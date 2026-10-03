#!/usr/bin/env python3
"""
Proof-first tests for the strict-exact fee model.

Locked doctrine: REQUIRED MinTxFee/FeePerByte are the exact smallest values
clearing the coin daemon's real gate (no margins). fee_policy() detects the
per-coin GetFee rounding + mempool dynamics from source; chain_floor() encodes
each model; strict_fees() solves the exact minimum over the sweep sizes.

Family evidence (all from local source checkouts at BCF-supported tags):
- floor+dynamic: BLOCK v4.4.0 feerate.cpp (trunc + 1-sat guard)
- ceil+dynamic: BTC v22-final / DASH v23.1.8 (std::ceil)
- ceil_step flat: XVG v26.8 (ONE_KILO_BYTE=999, flat 10*CENT, neutered GetMinFee)
- fixed_steps: EMC v0.8.5emc (GetMinFee 100sat/10KiB, rate ignored)
- literal_flat: COLX v1.2.5 (literal 1*COIN, full-rate min charge)
- go_floor: LBC v0.22.120 (calcMinRequiredTxRelayFee, full-rate guard)
- dust disabled: FIRO v0.14.18.0 (IsDust always false)
"""
import importlib.util
import sys
from pathlib import Path

AUDIT_PATH = Path(__file__).resolve().parents[1] / "audit-manifest.py"
spec = importlib.util.spec_from_file_location("audit_manifest_fee_policy", str(AUDIT_PATH))
audit = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = audit
spec.loader.exec_module(audit)


def _write(tree: Path, rel: str, text: str) -> Path:
    p = tree / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")
    return tree


def _floor_tree(tree: Path) -> Path:
    _write(tree, "src/policy/feerate.cpp",
           "CAmount CFeeRate::GetFee(size_t nBytes_) const\n{\n"
           "    int64_t nSize = int64_t(nBytes_);\n"
           "    CAmount nFee = nSatoshisPerK * nSize / 1000;\n"
           "    if (nFee == 0 && nSize != 0) {\n"
           "        if (nSatoshisPerK > 0)\n"
           "            nFee = CAmount(1);\n"
           "    }\n    return nFee;\n}\n")
    _write(tree, "src/txmempool.cpp",
           "CFeeRate CTxMemPool::GetMinFee(size_t sizelimit) const {\n"
           "    LOCK(cs);\n"
           "    if (!blockSinceLastRollingFeeBump || rollingMinimumFeeRate == 0)\n"
           "        return CFeeRate(llround(rollingMinimumFeeRate));\n"
           "    return std::max(CFeeRate(llround(rollingMinimumFeeRate)), incrementalRelayFee);\n}\n")
    return tree


def _ceil_tree(tree: Path) -> Path:
    _write(tree, "src/policy/feerate.cpp",
           "CAmount CFeeRate::GetFee(uint32_t num_bytes) const\n{\n"
           "    const int64_t nSize{num_bytes};\n"
           "    CAmount nFee{static_cast<CAmount>(std::ceil(nSatoshisPerK * nSize / 1000.0))};\n"
           "    if (nFee == 0 && nSize != 0) {\n"
           "        if (nSatoshisPerK > 0) nFee = CAmount(1);\n"
           "    }\n    return nFee;\n}\n")
    _write(tree, "src/txmempool.cpp",
           "CFeeRate CTxMemPool::GetMinFee(size_t sizelimit) const {\n"
           "    if (!blockSinceLastRollingFeeBump || rollingMinimumFeeRate == 0)\n"
           "        return CFeeRate(llround(rollingMinimumFeeRate));\n"
           "    return std::max(CFeeRate(llround(rollingMinimumFeeRate)), incrementalRelayFee);\n}\n")
    return tree


def _verge_tree(tree: Path) -> Path:
    _write(tree, "src/policy/feerate.cpp",
           "const size_t ONE_KILO_BYTE = 999;\n"
           "CFeeRate::CFeeRate(const CAmount& nFeePaid, size_t nBytes_)\n{\n"
           "    if (nSize > 0)\n"
           "        nSatoshisPerK = 10 * CENT;\n"
           "    else\n        nSatoshisPerK = 0;\n}\n"
           "CAmount CFeeRate::GetFee(size_t nBytes_) const\n{\n"
           "    int64_t nCeiledSize = ceil(nSize / static_cast<float>(ONE_KILO_BYTE));\n"
           "    CAmount nFee = nSatoshisPerK * nCeiledSize;\n"
           "    return nFee;\n}\n")
    _write(tree, "src/amount.h",
           "static const CAmount COIN = 1000000;\nstatic const CAmount CENT = 10000;\n")
    _write(tree, "src/txmempool.cpp",
           "CFeeRate CTxMemPool::GetMinFee(size_t sizelimit) const {\n"
           "    return CFeeRate(10 * CENT);\n}\n")
    return tree


def _emc_tree(tree: Path) -> Path:
    _write(tree, "src/policy/feerate.cpp",
           "CAmount GetMinFee(size_t nBytes)\n{\n"
           "    CAmount nBaseFee = MIN_TX_FEE;\n"
           "    CAmount nMinFee = (1 + nBytes / (10 * 1024)) * nBaseFee;\n"
           "    return nMinFee;\n}\n"
           "CAmount CFeeRate::GetFee(size_t nBytes_) const\n{\n"
           "    // emercoin: return fixed fee\n"
           "    return GetMinFee(nBytes_);\n"
           "#if 0\n"
           "    CAmount nFee = nSatoshisPerK * nSize / 1000;\n"
           "#endif\n}\n")
    _write(tree, "src/amount.h",
           "static const CAmount COIN = 1000000;\nstatic const CAmount MIN_TX_FEE = 100;\n")
    return tree


def _colx_tree(tree: Path) -> Path:
    _write(tree, "src/amount.cpp",
           "CAmount CFeeRate::GetFee(size_t nBytes_) const\n{\n"
           "    CAmount nFee = nSatoshisPerK * nSize / 1000;\n"
           "    if (nFee == 0 && nSize != 0)\n"
           "        nFee = nSatoshisPerK;\n"
           "    return nFee;\n}\n")
    _write(tree, "src/main.cpp",
           "CAmount nMinRelayTxFee = 1 * COIN;\nCAmount GetMinRelayFee() { return nMinRelayTxFee; }\n")
    return tree


def _go_tree(tree: Path) -> Path:
    _write(tree, "mempool/policy.go",
           "DefaultMinRelayTxFee = btcutil.Amount(1000)\n"
           "func calcMinRequiredTxRelayFee(serializedSize int64, minRelayTxFee btcutil.Amount) int64 {\n"
           "    minFee := (serializedSize * int64(minRelayTxFee)) / 1000\n"
           "    if minFee == 0 && minRelayTxFee > 0 {\n"
           "        minFee = int64(minRelayTxFee)\n"
           "    }\n    return minFee\n}\n")
    return tree


def _firo_dust_tree(tree: Path) -> Path:
    _write(tree, "src/primitives/transaction.h",
           "bool IsDust(const CFeeRate &minRelayTxFee) const {\n"
           "//  return (nValue < GetDustThreshold(minRelayTxFee));\n"
           "    //firo: disable dust\n"
           "    return false;\n}\n")
    return _floor_tree(tree)


def test_detect_floor_dynamic(tmp_path):
    pol = audit.CppSourceInspector.fee_policy(_floor_tree(tmp_path))
    assert pol.rounding == "floor", pol.evidence
    assert pol.mempool == "dynamic", pol.evidence


def test_detect_ceil_dynamic(tmp_path):
    pol = audit.CppSourceInspector.fee_policy(_ceil_tree(tmp_path))
    assert pol.rounding == "ceil", pol.evidence
    assert pol.mempool == "dynamic", pol.evidence


def test_detect_verge_ceil_step_flat(tmp_path):
    pol = audit.CppSourceInspector.fee_policy(_verge_tree(tmp_path))
    assert pol.rounding == "ceil_step", pol.evidence
    assert pol.kb_step == 999, pol.evidence
    assert pol.step_rate == 100000, pol.evidence
    assert pol.mempool == "flat", pol.evidence


def test_detect_emc_fixed_steps(tmp_path):
    pol = audit.CppSourceInspector.fee_policy(_emc_tree(tmp_path))
    assert pol.rounding == "fixed_steps", pol.evidence
    assert pol.fixed_step_bytes == 10240, pol.evidence
    assert pol.fixed_step_fee == 100, pol.evidence


def test_detect_colx_floor_fullrate(tmp_path):
    # Real COLX v1.2.5 has GetFee in amount.cpp (floor + full-rate min charge).
    pol = audit.CppSourceInspector.fee_policy(_colx_tree(tmp_path))
    assert pol.rounding == "floor", pol.evidence
    assert pol.zero_guard == "full_rate", pol.evidence


def _uno_tree(tree: Path) -> Path:
    # UNO-style old stack: flat literal relay in main.cpp, no GetFee anywhere.
    _write(tree, "src/main.cpp",
           "static const unsigned int nMinRelayTxFee = 1000;\n"
           "CAmount GetMinRelayFee() { return nMinRelayTxFee; }\n")
    return tree


def test_detect_uno_literal_flat(tmp_path):
    pol = audit.CppSourceInspector.fee_policy(_uno_tree(tmp_path))
    assert pol.rounding == "literal_flat", pol.evidence
    assert pol.zero_guard == "full_rate", pol.evidence


def test_detect_go_fullrate_guard(tmp_path):
    pol = audit.BtcdSourceInspector.fee_policy(_go_tree(tmp_path))
    assert pol.rounding == "go_floor", pol.evidence
    assert pol.zero_guard == "full_rate", pol.evidence


def _abc_tree(tree: Path) -> Path:
    # Bitcoin ABC idiom: template<bool ceil> split; relay GetFee -> <false>.
    _write(tree, "src/amount.cpp", "static const CAmount COIN = 100000000;\n")
    _write(tree, "src/feerate.cpp",
           "template <bool ceil>\nstatic Amount GetFee(size_t nBytes_, Amount nSatoshisPerK) {\n"
           "    Amount nFee = nSize * nSatoshisPerK / 1000;\n"
           "    return nFee;\n}\n"
           "Amount CFeeRate::GetFee(size_t nBytes) const {\n"
           "    return ::GetFee<false>(nBytes, nSatoshisPerK);\n}\n"
           "Amount CFeeRate::GetFeeCeiling(size_t nBytes) const {\n"
           "    return ::GetFee<true>(nBytes, nSatoshisPerK);\n}\n")
    return tree


def test_detect_abc_split_floor(tmp_path):
    pol = audit.CppSourceInspector.fee_policy(_abc_tree(tmp_path))
    assert pol.rounding == "floor", pol.evidence
    assert any("GetFeeCeiling" in n for n in pol.notes), pol.notes


def test_detect_firo_dust_disabled(tmp_path):
    pol = audit.CppSourceInspector.fee_policy(_firo_dust_tree(tmp_path))
    assert pol.dust_model == "disabled", pol.evidence


def test_strict_floor_1000():
    pol = audit.FeePolicy(rounding="floor", mempool="dynamic")
    assert audit.recommended_fees(pol, 1000) == (452, 1)


def test_strict_ceil_1000():
    pol = audit.FeePolicy(rounding="ceil", mempool="dynamic")
    assert audit.recommended_fees(pol, 1000) == (452, 1)


def test_strict_verge_is_100000_200():
    pol = audit.FeePolicy(rounding="ceil_step", mempool="flat",
                          kb_step=999, step_rate=100000)
    assert audit.recommended_fees(pol, 100000) == (100000, 200)


def test_strict_emc_is_100_1():
    pol = audit.FeePolicy(rounding="fixed_steps", mempool="dynamic",
                          fixed_step_bytes=10240, fixed_step_fee=100)
    assert audit.recommended_fees(pol, 10) == (100, 1)


def test_strict_colx_literal():
    pol = audit.FeePolicy(rounding="floor", mempool="none",
                          zero_guard="full_rate")
    assert audit.recommended_fees(pol, 100000000) == (45200000, 100000)


def test_strict_doge_is_452000_1000():
    pol = audit.FeePolicy(rounding="floor", mempool="dynamic")
    assert audit.recommended_fees(pol, 1000000) == (452000, 1000)


def test_verge_dust_uses_relay_rate_not_step_rate(tmp_path):
    # Verge dust gate = dustRelayFee.GetFee(182) with the single-arg rate as
    # given (10000 -> 10000), NOT the neutralized 2-arg flat step_rate
    # (100000). Fee gate and dust gate legitimately use different sources.
    from types import SimpleNamespace
    coin = SimpleNamespace(ticker="XVG")
    pol = audit.CppSourceInspector.fee_policy(_verge_tree(tmp_path))
    st, det = audit.CommonParamCheckers.check_dust(
        coin, tmp_path, {"DustAmount": "0"}, 100000, "rev",
        10000, "src/policy/policy.h:51", pol)
    assert st == audit.ParamStatus.INFO, det
    assert "10000 sat" in det, det


def test_verge_old_conf_fails_new_passes(tmp_path):
    from types import SimpleNamespace
    coin = SimpleNamespace(ticker="XVG")
    pol = audit.CppSourceInspector.fee_policy(_verge_tree(tmp_path))
    st, det = audit.CommonParamCheckers.check_fees(
        coin, tmp_path, {"MinTxFee": "67800", "FeePerByte": "150"},
        100000, "src/validation.h:55", None, None, pol)
    assert st == audit.ParamStatus.FAIL, det
    assert "REQUIRED MinTxFee=100000 FeePerByte=200" in det, det
    st2, det2 = audit.CommonParamCheckers.check_fees(
        coin, tmp_path, {"MinTxFee": "100000", "FeePerByte": "200"},
        100000, "src/validation.h:55", None, None, pol)
    assert st2 == audit.ParamStatus.PASS, det2


def test_doge_current_conf_is_overpay_warn(tmp_path):
    from types import SimpleNamespace
    coin = SimpleNamespace(ticker="DOGE")
    pol = audit.FeePolicy(rounding="floor", mempool="dynamic")
    st, det = audit.CommonParamCheckers.check_fees(
        coin, tmp_path, {"MinTxFee": "678000", "FeePerByte": "1500"},
        1000000, "src/policy/policy.h:31", None, None, pol)
    assert st == audit.ParamStatus.WARN, det
    assert "REQUIRED MinTxFee=452000 FeePerByte=1000" in det, det


def test_unknown_rounding_is_fail_not_pass(tmp_path):
    from types import SimpleNamespace
    coin = SimpleNamespace(ticker="???")
    pol = audit.FeePolicy(rounding="unknown", evidence=("nothing parseable",))
    st, det = audit.CommonParamCheckers.check_fees(
        coin, tmp_path, {"MinTxFee": "1", "FeePerByte": "1"},
        1000, "ev", None, None, pol)
    assert st == audit.ParamStatus.FAIL, det
    assert "fee extraction failed" in det, det


def test_zero_rate_is_fail_not_pass(tmp_path):
    from types import SimpleNamespace
    coin = SimpleNamespace(ticker="???")
    pol = audit.FeePolicy(rounding="floor", mempool="dynamic")
    st, det = audit.CommonParamCheckers.check_fees(
        coin, tmp_path, {"MinTxFee": "0", "FeePerByte": "1"},
        0, "ev", None, None, pol)
    assert st == audit.ParamStatus.FAIL, det
