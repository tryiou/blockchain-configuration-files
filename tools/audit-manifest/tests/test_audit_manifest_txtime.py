#!/usr/bin/env python3
"""
Test for the CppSourceInspector.check_txtime guard regex.
It must handle
  std::string(CURRENT_CHAIN) == "infiniloop"
Bug: s*== fails because ')' between CURRENT_CHAIN and == breaks s*==
Fix: W*== allows ')' and other non-word chars.

Proof-first R9: this test must FAIL before fix and PASS after.
"""
import re
import tempfile
import unittest.mock as mock
from pathlib import Path

import audit_manifest as audit

CppSourceInspector = audit.CppSourceInspector
ManifestCoin = audit.ManifestCoin
ParamStatus = audit.ParamStatus
_CURRENT_CHAIN_CACHE = audit._CURRENT_CHAIN_CACHE


def _lynx_tree(tmp_path: Path) -> Path:
    """Hermetic source tree: what _current_chain parses plus a chain-gated
    nTime serialization guard — no real checkout, no skips.

    Intentionally parser-shaped: it pins the inspector's behavior, not
    drift in upstream source (the real checkout is not part of the suite).
    The leading BITCOIN_DAEMON_NAME decoy exercises the '_' filter that
    must skip daemon-name assignments.
    """
    (tmp_path / "autogen.sh").write_text(
        "BITCOIN_DAEMON_NAME = bitcoind\nNAME = lynx\n", encoding="utf-8"
    )
    prim = tmp_path / "src" / "primitives"
    prim.mkdir(parents=True)
    (prim / "transaction.h").write_text(
        "struct CTransaction {\n"
        "    const uint32_t nTime;\n"
        "    template<typename Stream> void Serialize(Stream& s) const {\n"
        "        if (std::string(CURRENT_CHAIN) == \"infiniloop\") {\n"
        "            s >> tx.nTime;\n"
        "        }\n"
        "    }\n"
        "};\n",
        encoding="utf-8",
    )
    return tmp_path


def test_current_chain_returns_lynx(tmp_path):
    # autogen.sh NAME=lynx is what the parser must pick up.
    src = _lynx_tree(tmp_path)
    _CURRENT_CHAIN_CACHE.clear()
    chain = CppSourceInspector._current_chain(src)
    assert chain == "lynx", f"expected 'lynx' from autogen.sh, got {chain!r}"


def test_guard_regex_handles_std_string_paren():
    ctx = 'if (std::string(CURRENT_CHAIN) == "infiniloop" && g_currentValidatingBlockHeight <= g_infiniloopTransitionHeight) {'
    # Fixed regex (W* allows ')' between CURRENT_CHAIN and ==)
    m = re.search(r"CURRENT_CHAIN\W*==\s*[\"']([^\"']+)[\"']", ctx)
    assert m is not None, "regex should match std::string(CURRENT_CHAIN) == \"infiniloop\""
    assert m.group(1) == "infiniloop"
    # Verify old buggy regex would FAIL (proof that bug existed)
    m_old = re.search(r"CURRENT_CHAIN\s*==\s*[\"']([^\"']+)[\"']", ctx)
    assert m_old is None, "old regex \\s*== should NOT match when ')' present — confirms bug"


def test_check_txtime_lynx_match_not_warn(tmp_path):
    src = _lynx_tree(tmp_path)
    _CURRENT_CHAIN_CACHE.clear()
    # Verify _current_chain first
    chain = CppSourceInspector._current_chain(src)
    assert chain == "lynx"

    coin = ManifestCoin(ticker="LYNX", ver_id="lynx--v28.0.0")
    # conf has TxWithTimeField=false which matches actual=false for lynx chain (nTime not serialized)
    status, detail = CppSourceInspector.check_txtime(coin, src, {"TxWithTimeField": "false"})
    # Expected: MATCH with detail naming the chain guard AND the polarity
    assert status == ParamStatus.MATCH, f"expected MATCH but got {status} detail: {detail}"
    assert 'CURRENT_CHAIN="lynx" == "infiniloop"' in detail, f"detail should name the chain guard, got: {detail}"
    assert "nTime is NOT serialized" in detail, f"detail should state the not-serialized polarity, got: {detail}"


# ---------------------------------------------------------------------------
# Polarity + case-insensitive CURRENT_CHAIN tests (plan 07)
# Proof-first: these must FAIL on old code (== only, case-sensitive) and PASS after fix.
# Synthetic transaction.h exercised via monkeypatched SourceReader.
# ---------------------------------------------------------------------------


def _synthetic_check_txtime(tmp_chain: str, guard_line: str, conf_val: str, src_dir_path=None):
    """Helper: create temp src with synthetic transaction.h guard_line, mock _current_chain."""
    import shutil
    tmp = Path(tempfile.mkdtemp())
    # create src/primitives/transaction.h
    (tmp / "src" / "primitives").mkdir(parents=True)
    # minimal transaction.h: member nTime + serialized guard + nTime field
    content = f"""
    // header
    const uint32_t nTime;
    {guard_line}
        s >> tx.nTime;
    uint32_t nTime{{0}};
    """
    (tmp / "src" / "primitives" / "transaction.h").write_text(content)
    # Also create dummy place for _current_chain if it would try to read autogen.sh – we mock it.
    with mock.patch.object(CppSourceInspector, "_current_chain", return_value=tmp_chain.lower()):
        coin = ManifestCoin(ticker="TEST", ver_id="test--v1.0.0")
        status, detail = CppSourceInspector.check_txtime(coin, tmp, {"TxWithTimeField": conf_val})
    shutil.rmtree(tmp, ignore_errors=True)
    return status, detail


def test_txtime_not_equal_guard_lynx_not_serialized():
    # CURRENT_CHAIN != "lynx" with current=lynx -> guard_holds = (lynx != lynx)=False -> not serialized -> Tx false MATCH
    status, detail = _synthetic_check_txtime("lynx", 'if (CURRENT_CHAIN != "lynx") {', "false")
    assert status == ParamStatus.MATCH, f"!= lynx with lynx should be NOT serialized -> MATCH for false, got {status} {detail}"
    assert "not serialized" in detail.lower() or "!=" in detail


def test_txtime_std_string_not_equal_infiniloop_with_infiniloop():
    # std::string(CURRENT_CHAIN) != "infiniloop" with current=infiniloop -> False -> not serialized
    status, detail = _synthetic_check_txtime("infiniloop", 'if (std::string(CURRENT_CHAIN) != "infiniloop") {', "false")
    assert status == ParamStatus.MATCH, f"!= infiniloop with infiniloop should be NOT serialized -> MATCH false, got {status} {detail}"


def test_txtime_case_mix_current_chain_equal_upper():
    # Current_Chain == "INFINILOOP" with mixed case, current lynx -> False -> not serialized
    status, detail = _synthetic_check_txtime("lynx", 'if (Current_Chain == "INFINILOOP") {', "false")
    assert status == ParamStatus.MATCH, f"case-insensitive == INFINILOOP with lynx should be NOT serialized, got {status} {detail}"


def test_txtime_single_quote_not_equal_case_mix():
    # current_chain != 'Infiniloop' single quotes, current infiniloop -> False -> not serialized
    status, detail = _synthetic_check_txtime("infiniloop", "if (current_chain != 'Infiniloop') {", "false")
    assert status == ParamStatus.MATCH, f"single-quote != Infiniloop with infiniloop should be NOT serialized, got {status} {detail}"


def test_txtime_equal_still_match_for_lynx():
    # regression: == still works, lynx vs infiniloop -> False -> false MATCH
    status, detail = _synthetic_check_txtime("lynx", 'if (std::string(CURRENT_CHAIN) == "infiniloop") {', "false")
    assert status == ParamStatus.MATCH, f"== infiniloop with lynx should still be NOT serialized, got {status} {detail}"


def test_txtime_not_equal_true_serialized():
    # != with lynx vs infiniloop -> True -> serialized -> true MATCH
    status, detail = _synthetic_check_txtime("lynx", 'if (CURRENT_CHAIN != "infiniloop") {', "true")
    # actual True, conf true -> MATCH or WARN if cond
    assert status in (ParamStatus.MATCH, ParamStatus.WARN), f"!= infiniloop with lynx should be serialized -> true MATCH/WARN, got {status} {detail}"


# ---------------------------------------------------------------------------
# btcd (Go) side of the same check: cite the struct field, not a comment
# ---------------------------------------------------------------------------

def _make_ntime_comment_tree(tmp_path):
    (tmp_path / "wire").mkdir(parents=True)
    (tmp_path / "wire" / "msgtx.go").write_text(
        "package wire\n\n// nTime is serialized for time-locked variants.\n\n"
        "const TxVersion = 1\n\ntype MsgTx struct {\n"
        "\tVersion int32\n\tnTime uint32\n\tLockTime uint32\n}\n",
        encoding="utf-8",
    )
    return tmp_path


def test_go_txtime_cites_struct_ntime_not_comment(tmp_path):
    # The comment "nTime is serialized ..." precedes the field in the file,
    # so the citation must point at the struct member's own line, not the
    # comment that mentions it first.
    src = _make_ntime_comment_tree(tmp_path)
    coin = ManifestCoin(ticker="HYPO", ver_id="hypo--v1", daemon_family="btcd")
    st, det = audit.BtcdSourceInspector.check_txtime(coin, src, {"TxWithTimeField": "true"})
    assert st == ParamStatus.PASS, f"expected PASS, got {st}: {det[:120]}"
    assert "wire/msgtx.go:9" in det, f"citation must be the struct nTime line 9, got: {det!r}"
