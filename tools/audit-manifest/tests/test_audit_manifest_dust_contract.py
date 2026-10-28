#!/usr/bin/env python3
"""The DustAmount contract: one source-derived threshold per coin.

``DustAmount`` is the only definition of a coin's dust threshold, so the value
the audit validates and the value it writes must come from one computation.
These cases pin every gate shape the fleet actually has — per-size P2PKH, the
legacy 3x multiplier, a flat-amount ``IsDust``, a consensus minimum output
amount, and a source that disables dust — plus the refusal that keeps an
unprovable constant from becoming a fund-loss number.
"""

from pathlib import Path

import pytest

from audit_manifest.inspectors.common import CommonParamCheckers
from audit_manifest.inspectors.dust import (
    DUST_P2PKH_SIZE,
    DustKind,
    dust_at_size,
    expectation,
    has_segwit,
    is_static_dust_limit,
)
from audit_manifest.model import FeePolicy, ParamStatus

COIN = "AAA"


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _policy(rounding: str = "floor") -> FeePolicy:
    return FeePolicy(rounding=rounding, mempool="floor", dust_model="standard", kb_step=1000)


def _expect(tmp_path: Path, policy: FeePolicy | None = None, dust: int | None = 3000, rate: int | None = 1000):
    return expectation(
        src_dir=tmp_path,
        rate=rate,
        rate_ev="src/policy/policy.h:1",
        dust=dust,
        dust_ev="src/policy/policy.h:1",
        policy=policy if policy is not None else _policy(),
    )


def _verdict(tmp_path: Path, conf_value: str, **kwargs):
    verdict = CommonParamCheckers.check_dust(
        _coin(),
        tmp_path,
        {"DustAmount": conf_value},
        kwargs.get("rate", 1000),
        "src/validation.h:1",
        kwargs.get("dust", 3000),
        "src/policy/policy.h:1",
        kwargs.get("policy", _policy()),
    )
    return verdict[0], verdict[1], (verdict[2] if len(verdict) > 2 else None)


def _coin():
    from audit_manifest.model import ManifestCoin

    return ManifestCoin(ticker=COIN, ver_id="aaa--v1.0")


# --------------------------------------------------------------------------
# The gate shapes
# --------------------------------------------------------------------------


def test_p2pkh_gate_is_the_dust_relay_rate_at_spend_size(tmp_path):
    """182 bytes (34-byte output + 148-byte input) at 3000 sat/kB is 546."""
    got = _expect(tmp_path, dust=3000)
    assert got is not None
    assert got.value == 546 and got.kind is DustKind.P2PKH


def test_legacy_3x_multiplier_triples_the_gate(tmp_path):
    """A source that gates at 3*rate must not be read as a plain gate."""
    _write(tmp_path / "src" / "primitives" / "transaction.h", "return 3*minRelayTxFee.GetFee(nSize);\n")
    got = _expect(tmp_path, dust=1000)
    assert got is not None
    assert got.value == 3 * 1000 * DUST_P2PKH_SIZE // 1000 == 546


def test_flat_amount_isdust_uses_the_limit_verbatim(tmp_path):
    """Dogecoin's `IsDust(const CAmount)` compares the value to the limit."""
    _write(tmp_path / "src" / "primitives" / "transaction.h", "bool IsDust(const CAmount dustLimit) const\n")
    assert is_static_dust_limit(tmp_path) is True
    got = _expect(tmp_path, dust=1_000_000)
    assert got is not None
    assert got.value == 1_000_000 and got.kind is DustKind.STATIC


def test_consensus_min_output_floor_wins_over_the_dust_rate(tmp_path):
    """A daemon that rejects any output below MIN_TXOUT_AMOUNT has no smaller gate."""
    _write(
        tmp_path / "src" / "amount.h",
        "static const CAmount SUBCENT = 100;\nstatic const CAmount MIN_TX_FEE = SUBCENT;\n"
        "static const CAmount MIN_TXOUT_AMOUNT = MIN_TX_FEE;\n",
    )
    _write(
        tmp_path / "src" / "validation.cpp", "if (!txout.IsEmpty() && txout.nValue < MIN_TXOUT_AMOUNT) return false;\n"
    )
    got = _expect(tmp_path, dust=10)
    assert got is not None
    assert got.value == 100 and got.kind is DustKind.MIN_TXOUT
    assert "MIN_TXOUT_AMOUNT=100" in got.evidence


def test_dust_disabled_source_expects_zero(tmp_path):
    disabled = FeePolicy(rounding="floor", mempool="floor", dust_model="disabled", evidence=["IsDust false"])
    got = _expect(tmp_path, policy=disabled, dust=1000)
    assert got is not None
    assert got.value == 0 and got.kind is DustKind.DISABLED


def test_dust_disabled_source_still_honours_the_consensus_minimum(tmp_path):
    """Disabling the fee-rate rule must not switch off a consensus output floor.

    ``0`` means "no dust gate at all", so it is only correct when the daemon
    truly has none: a source that drops ``IsDust`` but still rejects outputs
    below ``MIN_TXOUT_AMOUNT`` must keep that floor.
    """
    _write(
        tmp_path / "src" / "amount.h",
        "static const CAmount SUBCENT = 100;\nstatic const CAmount MIN_TX_FEE = SUBCENT;\n"
        "static const CAmount MIN_TXOUT_AMOUNT = MIN_TX_FEE;\n",
    )
    _write(
        tmp_path / "src" / "validation.cpp", "if (!txout.IsEmpty() && txout.nValue < MIN_TXOUT_AMOUNT) return false;\n"
    )
    disabled = FeePolicy(rounding="floor", mempool="floor", dust_model="disabled", evidence=["IsDust false"])
    got = _expect(tmp_path, policy=disabled, dust=1000)
    assert got is not None
    assert got.value == 100 and got.kind is DustKind.MIN_TXOUT


def test_unprovable_constants_yield_no_expectation(tmp_path):
    """No dust constant and no relay rate must never become a number."""
    assert _expect(tmp_path, dust=None, rate=None) is None


def test_segwit_analogue_is_cited_not_substituted(tmp_path):
    """The P2PKH gate is the threshold; P2WPKH is context in the evidence."""
    _write(
        tmp_path / "src" / "policy" / "policy.cpp",
        "int WITNESS_SCALE_FACTOR;\nbool IsWitnessProgram(x);\n",
    )
    assert has_segwit(tmp_path) is True
    got = _expect(tmp_path, dust=3000)
    assert got is not None
    assert got.value == 546
    assert "P2WPKH 294 sat" in got.evidence


@pytest.mark.parametrize(
    ("rounding", "rate", "want"), [("floor", 3000, 546), ("ceil", 3000, 546), ("go_floor", 3000, 546)]
)
def test_rounding_models_agree_at_the_reference_rate(rounding, rate, want):
    assert dust_at_size(rate, DUST_P2PKH_SIZE, 1, _policy(rounding)) == want


def test_ceil_step_charges_one_step_per_started_kilobyte():
    """Verge: ONE_KILO_BYTE=999 and a flat 10,000 per step."""
    policy = FeePolicy(rounding="ceil_step", mempool="floor", kb_step=999, step_rate=10000)
    assert dust_at_size(10000, DUST_P2PKH_SIZE, 1, policy) == 10000


# --------------------------------------------------------------------------
# The checker: PASS/missing/wrong/refusal
# --------------------------------------------------------------------------


def test_checker_passes_on_the_source_derived_value(tmp_path):
    status, detail, fixable = _verdict(tmp_path, "546")
    assert status is ParamStatus.PASS, detail
    assert fixable is None


def test_checker_fails_on_a_missing_key(tmp_path):
    """A conf that omits DustAmount is a defect, not a placeholder."""
    status, detail, fixable = _verdict(tmp_path, "")
    assert status is ParamStatus.FAIL, detail
    assert "missing" in detail and fixable == "dust"


@pytest.mark.parametrize("raw", ["x", "-1"])
def test_checker_fails_on_unusable_values(tmp_path, raw):
    status, detail, fixable = _verdict(tmp_path, raw)
    assert status is ParamStatus.FAIL, detail
    assert fixable == "dust"


def test_checker_warns_and_authorizes_the_fix_on_a_wrong_value(tmp_path):
    for raw in ("0", "5460"):
        status, detail, fixable = _verdict(tmp_path, raw)
        assert status is ParamStatus.WARN, detail
        assert fixable == "dust"


def test_checker_accepts_zero_only_when_the_source_disables_dust(tmp_path):
    disabled = FeePolicy(rounding="floor", mempool="floor", dust_model="disabled", evidence=["IsDust false"])
    status, detail, fixable = _verdict(tmp_path, "0", policy=disabled, dust=None)
    assert status is ParamStatus.PASS, detail
    assert fixable is None
    status, detail, fixable = _verdict(tmp_path, "546", policy=disabled, dust=None)
    assert status is ParamStatus.WARN, detail
    assert fixable == "dust"


def test_checker_refuses_to_invent_a_value(tmp_path):
    status, detail, fixable = _verdict(tmp_path, "546", dust=None, rate=None)
    assert status is ParamStatus.UNRESOLVED, detail
    assert fixable is None, "an unprovable constant must not authorize a write"
