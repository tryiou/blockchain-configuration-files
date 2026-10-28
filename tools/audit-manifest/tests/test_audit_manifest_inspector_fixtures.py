#!/usr/bin/env python3
"""Table-driven inspector fixtures: the fund-loss and derivation branches.

``check_coin`` decides whether a conf's COIN matches the coin's own
source — the audit's named fund-loss path, whose three resolution legs
(vendor literal, module cache, in-tree 3-point pin) need branch-level
pinning. The txindex and dust checkers get the same treatment for the
branch families their single-case tests do not reach: source layouts,
fixable kinds, and the derivation cascades.

Every case builds a synthetic source tree in tmp_path — no network, no
git, same materialization pattern as the other inspector tests.
"""

import audit_manifest as audit
from audit_manifest.inspectors import common as common_mod
from audit_manifest.inspectors.btcd import BtcdSourceInspector
from audit_manifest.inspectors.common import CommonParamCheckers
from audit_manifest.inspectors.cpp import CppSourceInspector
from audit_manifest.model import FeePolicy

_BTCD = {"daemon_family": "btcd"}


def _coin(ticker: str) -> audit.ManifestCoin:
    return audit.ManifestCoin(ticker=ticker, ver_id=f"{ticker.lower()}--v1.0", **_BTCD)


def _btcd_free_coin() -> audit.ManifestCoin:
    return audit.ManifestCoin(ticker="HYPO", ver_id="hypo--v1.0", daemon_family="btc")


def _result(res):
    """(status, detail, fixable): checkers may return the 2-tuple."""
    st, det, *rest = res
    return st, det, (rest[0] if rest else None)


def _write(path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _vendor_tree(tmp_path, value: str) -> None:
    _write(
        tmp_path / "vendor" / "btcutil" / "amount.go",
        f"package btcutil\n\nconst SatoshiPerBitcoin = {value}\n",
    )


def _intree_tree(tmp_path, *, compress: bool, genesis: bool) -> None:
    if compress:
        _write(
            tmp_path / "blockchain" / "compress.go",
            "package blockchain\n\n// 100000000 = 1.0 BTC\n",
        )
    if genesis:
        _write(
            tmp_path / "chaincfg" / "genesis.go",
            "package chaincfg\n\n// premine 0x8e1bc9bf040000 units\n",
        )
    _write(
        tmp_path / "rpcserver.go",
        "package main\n\n// NewAmount and SatoshiPerBitcoin\n",
    )


def test_btcd_coin_bad_conf_shapes(tmp_path):
    """A conf COIN that is not a positive integer is FAIL, never a verdict."""
    for xc, why in (({"COIN": "abc"}, "non-numeric"), ({"COIN": "0"}, "zero"), ({"COIN": ""}, "empty")):
        st, det = BtcdSourceInspector.check_coin(_coin("HYPO"), tmp_path, xc)
        assert st == audit.ParamStatus.FAIL, f"COIN={xc['COIN']!r} ({why}) must FAIL, got {st}: {det[:120]}"


def test_btcd_coin_vendor_leg(tmp_path):
    """Leg (a): the vendored SatoshiPerBitcoin is byte-exact and wins."""
    _vendor_tree(tmp_path, "100000000")
    _intree_tree(tmp_path, compress=False, genesis=False)  # garbage in-tree must not matter
    lbc = _coin("LBC")

    st, det = BtcdSourceInspector.check_coin(lbc, tmp_path, {"COIN": "100000000"})
    assert st == audit.ParamStatus.PASS, f"vendor match must PASS, got {st}: {det[:120]}"
    assert "amount.go" in det, f"vendor evidence must cite the vendored file: {det[:120]}"

    st, det = BtcdSourceInspector.check_coin(lbc, tmp_path, {"COIN": "1000000"})
    assert st == audit.ParamStatus.WARN, f"vendor mismatch must WARN, got {st}: {det[:120]}"
    assert "fund-loss" in det, f"the mismatch must name the fund-loss risk: {det[:120]}"

    _vendor_tree(tmp_path, "1000000")  # a coin whose units really are 1e6
    st, det = BtcdSourceInspector.check_coin(lbc, tmp_path, {"COIN": "1000000"})
    assert st == audit.ParamStatus.PASS, f"underscore/quote-free vendor value must still match: {det[:120]}"


def test_btcd_coin_intree_pin_conjunction(tmp_path):
    """Leg (c): the 3-point pin needs its conjunction; genesis is LBC-scoped."""
    _intree_tree(tmp_path, compress=True, genesis=False)
    lbc, hypo = _coin("LBC"), _coin("HYPO")

    st, det = BtcdSourceInspector.check_coin(lbc, tmp_path, {"COIN": "100000000"})
    assert st == audit.ParamStatus.PASS, f"rpc+compress pin must PASS, got {st}: {det[:120]}"
    st, _ = BtcdSourceInspector.check_coin(hypo, tmp_path, {"COIN": "100000000"})
    assert st == audit.ParamStatus.PASS, "the pin is coin-agnostic, only genesis is scoped"

    st, det = BtcdSourceInspector.check_coin(lbc, tmp_path, {"COIN": "1000000"})
    assert st == audit.ParamStatus.WARN and "fund-loss" in det, f"pin mismatch must WARN: {det[:120]}"


def test_btcd_coin_intree_pin_incomplete(tmp_path):
    """Without compress.go, only LBC's genesis leg may complete the pin."""
    _intree_tree(tmp_path, compress=False, genesis=True)
    lbc, hypo = _coin("LBC"), _coin("HYPO")

    st, det = BtcdSourceInspector.check_coin(lbc, tmp_path, {"COIN": "100000000"})
    assert st == audit.ParamStatus.PASS, f"LBC genesis leg completes the pin, got {st}: {det[:120]}"
    assert "genesis.go" in det, f"the genesis leg must be cited: {det[:120]}"

    st, det = BtcdSourceInspector.check_coin(hypo, tmp_path, {"COIN": "100000000"})
    assert st == audit.ParamStatus.UNRESOLVED, f"non-LBC must not pass on genesis alone: {st}: {det[:120]}"
    assert "compress.go" in det, f"the attempt list must name the missing leg: {det[:120]}"

    # a fresh tree with neither leg: both attempts are reported
    bare = tmp_path / "bare"
    _intree_tree(bare, compress=False, genesis=False)
    st, det = BtcdSourceInspector.check_coin(lbc, bare, {"COIN": "100000000"})
    assert st == audit.ParamStatus.UNRESOLVED and "genesis.go" in det, (
        f"both legs missing must UNRESOLVED with both attempts: {det[:120]}"
    )


def test_cpp_txindex_absent_conf_variants(tmp_path):
    """txindex with no conf line: the verdict follows DEFAULT_TXINDEX."""
    cases = [
        ("src/index/txindex.h", "constexpr bool DEFAULT_TXINDEX{true};", audit.ParamStatus.INFO, "default=true"),
        ("src/validation.h", "static const bool DEFAULT_TXINDEX = false;", audit.ParamStatus.WARN, "txindex"),
        ("src/main.h", "bool DEFAULT_TXINDEX = true;", audit.ParamStatus.INFO, "default=true"),
    ]
    for i, (rel, src, want_status, want_detail) in enumerate(cases):
        case = tmp_path / f"case{i}"
        _write(case / rel, f"// header\n{src}\n")
        _write(case / "src/init.cpp", 'AddArg("-txindex", "maintain a tx index");\n')
        st, det = _result(CppSourceInspector.check_txindex(_btcd_free_coin(), case, {}))[:2]
        assert st == want_status, f"{rel}: want {want_status}, got {st}: {det[:120]}"
        assert want_detail in det, f"{rel}: detail must mention {want_detail!r}: {det[:120]}"


def test_cpp_txindex_legacy_fallbacks(tmp_path):
    """Forks without DEFAULT_TXINDEX resolve via fTxIndex / GetBoolArg."""
    _write(tmp_path / "src" / "txdb.cpp", "// init\nbool fTxIndex = true;\n")
    _write(tmp_path / "src" / "init.cpp", 'AddArg("-txindex", "x");\n')
    st, det = _result(CppSourceInspector.check_txindex(_btcd_free_coin(), tmp_path, {"txindex": "1"}))[:2]
    assert st == audit.ParamStatus.PASS, f"fTxIndex fallback + conf line must PASS, got {st}: {det[:120]}"
    assert "fTxIndex" in det, f"the fallback evidence must be cited: {det[:120]}"

    src = tmp_path / "src" / "txdb.cpp"
    src.write_text('bool g = GetBoolArg("-txindex", false);\n', encoding="utf-8")
    st, det = _result(CppSourceInspector.check_txindex(_btcd_free_coin(), tmp_path, {}))[:2]
    assert st == audit.ParamStatus.WARN, f"GetBoolArg default=false + no conf line must WARN, got {st}: {det[:120]}"
    assert "GetBoolArg-txindex" in det, f"the GetBoolArg evidence must be cited: {det[:120]}"


def test_cpp_txindex_unlocatable(tmp_path):
    """No constant, no registration: two distinct UNRESOLVED refusals."""
    st, det = CppSourceInspector.check_txindex(_btcd_free_coin(), tmp_path, {"txindex": "1"})
    assert st == audit.ParamStatus.UNRESOLVED and "DEFAULT_TXINDEX" in det, (
        f"missing constant must UNRESOLVED, got {st}: {det[:120]}"
    )
    _write(tmp_path / "src" / "validation.h", "bool DEFAULT_TXINDEX = true;\n")
    st, det = CppSourceInspector.check_txindex(_btcd_free_coin(), tmp_path, {"txindex": "1"})
    assert st == audit.ParamStatus.UNRESOLVED and "not registered" in det, (
        f"missing registration must UNRESOLVED, got {st}: {det[:120]}"
    )


def test_cpp_txindex_conf_verdicts(tmp_path):
    """With the conf line present: 1 PASSes, other values WARN, junk FAILs."""
    _write(tmp_path / "src" / "validation.h", "bool DEFAULT_TXINDEX = true;\n")
    _write(tmp_path / "src" / "init.cpp", 'AddArg("-txindex", "x");\n')
    check = CppSourceInspector.check_txindex
    coin = _btcd_free_coin()
    st, _ = check(coin, tmp_path, {"txindex": "1"})
    assert st == audit.ParamStatus.PASS, "txindex=1 is an explicit enable"
    st, det = check(coin, tmp_path, {"txindex": "0"})
    assert st == audit.ParamStatus.WARN and "XBridge needs index" in det, (
        f"txindex=0 must WARN with the reason: {det[:120]}"
    )
    st, _ = check(coin, tmp_path, {"txindex": "yes"})
    assert st == audit.ParamStatus.FAIL, "non-numeric txindex must FAIL"


def _btcd_free_coin() -> audit.ManifestCoin:
    return audit.ManifestCoin(ticker="HYPO", ver_id="hypo--v1.0", daemon_family="btc")


def _dust_policy(rounding: str, mempool: str = "floor") -> FeePolicy:
    return FeePolicy(rounding=rounding, mempool=mempool, dust_model="legacy", kb_step=1000)


def test_dust_derivation_cascades(tmp_path):
    """The dust gate derives per rounding model, with the 3x and segwit variants."""
    policy = _dust_policy("floor")
    dust_ev = "src/policy/policy.cpp:1 nDustRelayFee"
    dust = 1000  # sat/kB -> 182 sat at a 182-byte P2PKH spend

    # the source-derived value is the PASS
    st, det, fixable = _result(
        CommonParamCheckers.check_dust(
            _btcd_free_coin(), tmp_path, {"DustAmount": "182"}, 3000, "ev", dust, dust_ev, policy
        )
    )
    assert st == audit.ParamStatus.PASS and "effective threshold" in det, (
        f"the source-derived value must PASS, got {st}: {det[:120]}"
    )
    assert fixable is None, "a matching value needs no fix"

    # anything else — including the retired placeholder 0 — is the fixable WARN
    for wrong in ("0", "999999"):
        st, det, fixable = _result(
            CommonParamCheckers.check_dust(
                _btcd_free_coin(), tmp_path, {"DustAmount": wrong}, 3000, "ev", dust, dust_ev, policy
            )
        )
        assert st == audit.ParamStatus.WARN and fixable == "dust", (
            f"DustAmount={wrong} must WARN with fixable=dust, got {st}/{fixable}: {det[:120]}"
        )

    # the 3x multiplier branch: a policy.cpp that applies 3*dustRelayFee
    _write(
        tmp_path / "src" / "policy" / "policy.cpp",
        "CFeeRate dustRelayFee{3 * dustRelayFee};\n",
    )
    st, det, _ = _result(
        CommonParamCheckers.check_dust(
            _btcd_free_coin(), tmp_path, {"DustAmount": "546"}, 3000, "ev", dust, dust_ev, policy
        )
    )
    assert st == audit.ParamStatus.PASS and "P2PKH" in det, (
        f"the 3x factor must derive 3*182=546, got {st}: {det[:120]}"
    )

    # segwit branch: the same file proves a witness-aware IsDust → P2WPKH cited
    _write(
        tmp_path / "src" / "policy" / "policy.cpp",
        "int WITNESS_SCALE_FACTOR;\nbool IsWitnessProgram(x);\nCFeeRate d{3 * dustRelayFee};\n",
    )
    st, det, _ = _result(
        CommonParamCheckers.check_dust(
            _btcd_free_coin(), tmp_path, {"DustAmount": "546"}, 3000, "ev", dust, dust_ev, policy
        )
    )
    assert st == audit.ParamStatus.PASS and "P2WPKH" in det, (
        f"the segwit derivation must cite P2WPKH, got {st}: {det[:120]}"
    )


def test_dust_disabled_and_missing_models(tmp_path):
    """dust disabled upstream, and an unlocatable dust constant, are distinct verdicts."""
    disabled = FeePolicy(
        rounding="floor", mempool="floor", dust_model="disabled", kb_step=1000, evidence=["IsDust false"]
    )
    st, det, _ = _result(
        CommonParamCheckers.check_dust(
            _btcd_free_coin(), tmp_path, {"DustAmount": "0"}, None, None, None, None, disabled
        )
    )
    assert st == audit.ParamStatus.PASS and "disables dust" in det, (
        f"a source that disables dust must accept 0, got {st}: {det[:120]}"
    )
    st, det, fixable = _result(
        CommonParamCheckers.check_dust(
            _btcd_free_coin(), tmp_path, {"DustAmount": "1234"}, None, None, None, None, disabled
        )
    )
    assert st == audit.ParamStatus.WARN and fixable == "dust", (
        f"disabled dust + real value is the fixable WARN, got {st}/{fixable}: {det[:120]}"
    )
    legacy = _dust_policy("floor")
    st, det, _ = _result(
        CommonParamCheckers.check_dust(_btcd_free_coin(), tmp_path, {"DustAmount": "0"}, None, None, None, None, legacy)
    )
    assert st == audit.ParamStatus.UNRESOLVED and "not located" in det, (
        f"no dust constant anywhere must UNRESOLVED, got {st}: {det[:120]}"
    )
    st, det, _ = _result(
        CommonParamCheckers.check_dust(_btcd_free_coin(), tmp_path, {"DustAmount": "x"}, None, None, None, None, legacy)
    )
    assert st == audit.ParamStatus.FAIL and "non-numeric" in det, (
        f"a non-numeric conf value must FAIL, got {st}: {det[:120]}"
    )


def test_cpp_coin_resolution_legs(tmp_path):
    """cpp COIN: legacy/modern layouts, brace init, unresolvable, missing."""
    match_wc = {"COIN": "100000000"}
    bad_wc = {"COIN": "1000000"}

    def case(rel: str, body: str, sub: str):
        d = tmp_path / sub
        _write(d / rel, f"// amount\n{body}\n")
        return d

    # legacy layout, match and mismatch
    d = case("src/amount.h", "static const CAmount COIN = 100000000;", "legacy")
    st, det = _result(CppSourceInspector.check_coin(_btcd_free_coin(), d, match_wc))[:2]
    assert st == audit.ParamStatus.PASS, f"legacy amount.h match must PASS, got {st}: {det[:120]}"
    st, det = _result(CppSourceInspector.check_coin(_btcd_free_coin(), d, bad_wc))[:2]
    assert st == audit.ParamStatus.WARN and "fund-loss" in det, (
        f"legacy amount.h mismatch must WARN with the ratio: {det[:120]}"
    )

    # modern layout
    d = case("src/consensus/amount.h", "CAmount COIN = 100000000;", "modern")
    st, det = _result(CppSourceInspector.check_coin(_btcd_free_coin(), d, match_wc))[:2]
    assert st == audit.ParamStatus.PASS, f"modern layout must resolve, got {st}: {det[:120]}"

    # brace init (PART-style)
    d = case("src/amount.h", "CAmount COIN{100000000};", "brace")
    st, det = _result(CppSourceInspector.check_coin(_btcd_free_coin(), d, match_wc))[:2]
    assert st == audit.ParamStatus.PASS, f"brace init must resolve, got {st}: {det[:120]}"

    # an unresolvable expression is UNRESOLVED, never a guessed verdict
    d = case("src/amount.h", "CAmount COIN = SOME_EXTERNAL * 2;", "unresolved")
    st, det = _result(CppSourceInspector.check_coin(_btcd_free_coin(), d, match_wc))[:2]
    assert st == audit.ParamStatus.UNRESOLVED and "unresolvable" in det, (
        f"unresolvable expression must UNRESOLVED, got {st}: {det[:120]}"
    )

    # no layout at all
    d = tmp_path / "empty"
    d.mkdir()
    st, det = _result(CppSourceInspector.check_coin(_btcd_free_coin(), d, match_wc))[:2]
    assert st == audit.ParamStatus.UNRESOLVED and "layout differs" in det, (
        f"missing layout must UNRESOLVED, got {st}: {det[:120]}"
    )

    # bad conf shapes
    st, det = _result(CppSourceInspector.check_coin(_btcd_free_coin(), tmp_path, {"COIN": "x"}))[:2]
    assert st == audit.ParamStatus.FAIL and "non-numeric" in det, f"non-numeric COIN must FAIL, got {st}: {det[:120]}"
    st, _ = _result(CppSourceInspector.check_coin(_btcd_free_coin(), tmp_path, {"COIN": "0"}))[:2]
    assert st == audit.ParamStatus.FAIL, "COIN=0 is rejected by blocknet"


def test_cpp_port_match_and_mismatch(tmp_path):
    """cpp nDefaultPort: match, mismatch, and a conf with no port line."""
    src = "class CMainParams {\npublic:\n    int nDefaultPort = 9333;\n};\n"
    _write(tmp_path / "src" / "chainparams.cpp", src)
    args = (tmp_path,)
    kwargs = {"want_test": False, "repo_root": tmp_path}
    coin = _btcd_free_coin()

    st, det = _result(CppSourceInspector.check_port(coin, *args, {"port": "9333"}, **kwargs))[:2]
    assert st == audit.ParamStatus.MATCH, f"port match must MATCH, got {st}: {det[:120]}"
    st, det = _result(CppSourceInspector.check_port(coin, *args, {"port": "1234"}, **kwargs))[:2]
    assert st == audit.ParamStatus.WARN and "vs source" in det, f"port mismatch must WARN, got {st}: {det[:120]}"
    st, det = _result(CppSourceInspector.check_port(coin, *args, {}, **kwargs))[:2]
    assert st == audit.ParamStatus.UNRESOLVED and "no port" in det, (
        f"a conf with no port line must UNRESOLVED, got {st}: {det[:120]}"
    )

    # no chainparams anywhere
    empty = tmp_path / "empty"
    empty.mkdir()
    st, det = _result(CppSourceInspector.check_port(coin, empty, {"port": "9333"}, **kwargs))[:2]
    assert st == audit.ParamStatus.UNRESOLVED, f"no layout must UNRESOLVED, got {st}: {det[:120]}"


def test_fee_planner_dispatch_is_keyed_off_fixable(tmp_path):
    """check_fees' fixable kind is what authorizes the fee fix, not the message."""
    policy = FeePolicy(rounding="ceil_step", mempool="flat", dust_model="legacy", kb_step=999, step_rate=100000)
    # below the chain gate → FAIL + fixable fees
    st, det, fixable = _result(
        common_mod.CommonParamCheckers.check_fees(
            _btcd_free_coin(), tmp_path, {"MinTxFee": "0", "FeePerByte": "0"}, 1000, "ev", 1000, "ev", policy
        )
    )
    assert st == audit.ParamStatus.FAIL and fixable == "fees", (
        f"below-gate fees must FAIL with fixable=fees, got {st}/{fixable}: {det[:120]}"
    )
    # above the gate → WARN + fixable fees
    st, det, fixable = _result(
        common_mod.CommonParamCheckers.check_fees(
            _btcd_free_coin(), tmp_path, {"MinTxFee": "999999", "FeePerByte": "999999"}, 1000, "ev", 1000, "ev", policy
        )
    )
    assert st == audit.ParamStatus.WARN and fixable == "fees", (
        f"overpay must WARN with fixable=fees, got {st}/{fixable}: {det[:120]}"
    )
    # non-numeric → FAIL with no fixable
    st, det, fixable = _result(
        common_mod.CommonParamCheckers.check_fees(
            _btcd_free_coin(), tmp_path, {"MinTxFee": "abc", "FeePerByte": "1"}, 1000, "ev", 1000, "ev", policy
        )
    )
    assert st == audit.ParamStatus.FAIL and fixable is None, (
        f"non-numeric fees must FAIL without a fixable kind, got {st}/{fixable}: {det[:120]}"
    )
