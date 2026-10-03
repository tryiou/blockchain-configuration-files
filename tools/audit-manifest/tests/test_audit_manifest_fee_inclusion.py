#!/usr/bin/env python3
"""
Proof-first R9 regression test for the DOGECOIN fee-base defect.

CONFIRMED bug: CppSourceInspector.fee_constants() reads only the relay
minimum (DEFAULT_MIN_RELAY_TX_FEE) and ignores the miner block-inclusion
minimum (DEFAULT_BLOCK_MIN_TX_FEE). For split-policy coins (Dogecoin:
relay 100,000/kB vs inclusion 1,000,000/kB) the audit therefore derives
fees from the relay floor only. Live chain sampling (block 6390072,
Sept 2026) shows economical confirmed DOGE txs pay ~1000/byte — the
inclusion/wallet rate — while relay-derived params (150/byte) relay
but mine last. For atomic swaps with short HTLC locktimes that is a
slow-confirm risk the audit must not certify as PASS.

Fix contract (1.5x logic untouched): rate = max(relay, block-inclusion).
Equal-rate coins (BTC/LTC/DASH/...) must see zero behavior change.

This test must FAIL before the fix (rate == relay only) and PASS after.
"""
import importlib.util
import sys
from pathlib import Path

AUDIT_PATH = Path(__file__).resolve().parents[1] / "audit-manifest.py"
spec = importlib.util.spec_from_file_location("audit_manifest_fee_incl", str(AUDIT_PATH))
audit = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = audit
spec.loader.exec_module(audit)


def _make_split_policy_tree(tmp_path):
    """DOGE-like split policy: relay 100k, block-inclusion 1M (with C cast)."""
    pol = tmp_path / "src" / "policy"
    pol.mkdir(parents=True)
    (pol / "policy.h").write_text(
        "static const CAmount RECOMMENDED_MIN_TX_FEE = 1000000;\n"
        "static const CAmount DEFAULT_MIN_RELAY_TX_FEE = RECOMMENDED_MIN_TX_FEE / 10;\n"
        "static const unsigned int DEFAULT_BLOCK_MIN_TX_FEE = (unsigned int) RECOMMENDED_MIN_TX_FEE;\n",
        encoding="utf-8",
    )
    return tmp_path


def _make_equal_policy_tree(tmp_path):
    """BTC-like: relay == block == 1000. Fix must not change this case."""
    pol = tmp_path / "src" / "policy"
    pol.mkdir(parents=True)
    (pol / "policy.h").write_text(
        "static const unsigned int DEFAULT_MIN_RELAY_TX_FEE = 1000;\n"
        "static const unsigned int DEFAULT_BLOCK_MIN_TX_FEE = 1000;\n",
        encoding="utf-8",
    )
    return tmp_path


def test_split_policy_uses_max_relay_block(tmp_path):
    src = _make_split_policy_tree(tmp_path)
    rate, rate_ev, _, _ = audit.CppSourceInspector.fee_constants(src)
    assert rate == 1000000, (
        f"split-policy rate must be max(relay 100000, block 1000000) = 1000000, got {rate!r} ({rate_ev})"
    )
    assert "max(relay" in (rate_ev or ""), (
        f"evidence must mark the max(relay, block-inclusion) decision, got: {rate_ev!r}"
    )
    assert "src/policy/policy.h:3" in (rate_ev or ""), (
        f"evidence must cite the winning block-inclusion line 3, got: {rate_ev!r}"
    )


def test_equal_policy_unchanged(tmp_path):
    src = _make_equal_policy_tree(tmp_path)
    rate, rate_ev, _, _ = audit.CppSourceInspector.fee_constants(src)
    assert rate == 1000, f"equal-policy rate must stay 1000, got {rate!r} ({rate_ev})"


def test_brace_init_block_rate_resolves(tmp_path):
    """Brace-initialized inclusion (e.g. `{2000}`) must not be mangled."""
    pol = tmp_path / "src" / "policy"
    pol.mkdir(parents=True)
    (pol / "policy.h").write_text(
        "static const unsigned int DEFAULT_MIN_RELAY_TX_FEE = 1000;\n"
        "static const unsigned int DEFAULT_BLOCK_MIN_TX_FEE = {2000};\n",
        encoding="utf-8",
    )
    rate, rate_ev, _, _ = audit.CppSourceInspector.fee_constants(tmp_path)
    assert rate == 2000, f"brace-init block 2000 must win, got {rate!r} ({rate_ev})"


def test_relay_missing_evidence_has_no_none(tmp_path):
    """Relay absent + block present: rate from block, evidence names it."""
    pol = tmp_path / "src" / "policy"
    pol.mkdir(parents=True)
    (pol / "policy.h").write_text(
        "static const unsigned int DEFAULT_BLOCK_MIN_TX_FEE = 5000;\n",
        encoding="utf-8",
    )
    rate, rate_ev, _, _ = audit.CppSourceInspector.fee_constants(tmp_path)
    assert rate == 5000, f"block-only rate must be 5000, got {rate!r} ({rate_ev})"
    assert "None" not in (rate_ev or ""), f"evidence must not leak None: {rate_ev!r}"
    assert "relay not located" in (rate_ev or ""), f"evidence must say so: {rate_ev!r}"


def test_paren_init_and_wrapped_literal_resolve(tmp_path):
    """Direct-init `X(3000)` and wrapped `(4000)` must resolve, not vanish."""
    pol = tmp_path / "src" / "policy"
    pol.mkdir(parents=True)
    (pol / "policy.h").write_text(
        "static const unsigned int DEFAULT_MIN_RELAY_TX_FEE = 1000;\n"
        "static const unsigned int DEFAULT_BLOCK_MIN_TX_FEE(3000);\n",
        encoding="utf-8",
    )
    rate, _, _, _ = audit.CppSourceInspector.fee_constants(tmp_path)
    assert rate == 3000, f"paren-init block 3000 must win, got {rate!r}"
    (pol / "policy.h").write_text(
        "static const unsigned int DEFAULT_MIN_RELAY_TX_FEE = 1000;\n"
        "static const unsigned int DEFAULT_BLOCK_MIN_TX_FEE = (4000);\n",
        encoding="utf-8",
    )
    rate2, _, _, _ = audit.CppSourceInspector.fee_constants(tmp_path)
    assert rate2 == 4000, f"wrapped literal block 4000 must win, got {rate2!r}"


def test_recommended_fees_from_inclusion_base():
    # Strict-exact doctrine: rate 1M floor-model -> Min 452000 / FPB 1000.
    floor = audit.FeePolicy(rounding="floor", mempool="dynamic")
    rec_min, rec_fee = audit.recommended_fees(floor, 1000000)
    assert (rec_min, rec_fee) == (452000, 1000), f"got {(rec_min, rec_fee)}"
    # Old relay base for comparison (must NOT be the audit result for DOGE).
    old_min, old_fee = audit.recommended_fees(floor, 100000)
    assert (old_min, old_fee) == (45200, 100), f"got {(old_min, old_fee)}"
