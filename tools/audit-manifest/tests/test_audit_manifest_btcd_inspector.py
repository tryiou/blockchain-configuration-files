#!/usr/bin/env python3
"""
BtcdSourceInspector's own source rules.

btcd spells config fields in mixed case (defaultTxIndex in config.go) and
ships a pinned LBC genesis magic. Neither may leak into a verdict: a mixed
key still resolves, and the genesis pin stays scoped to LBC instead of
making every btcd coin look verified.
"""

import audit_manifest as audit


def test_btcd_txindex_mixed_case_key(tmp_path):
    cfg = tmp_path / "config.go"
    cfg.write_text("package main\n\ndefaultTxIndex = true\n", encoding="utf-8")
    coin = audit.ManifestCoin(ticker="HYPO", ver_id="hypo--v1", daemon_family="btcd")
    st, det = audit.BtcdSourceInspector.check_txindex(coin, tmp_path, {"TxIndex": "1"})
    assert st == audit.ParamStatus.PASS, f"mixed-case TxIndex=1 must PASS, got {st}: {det[:120]}"


def _make_genesis_only_tree(tmp_path):
    (tmp_path / "rpcserver.go").write_text(
        "package main\n\n// NewAmount creates coins.\n// SatoshiPerBitcoin used here.\n",
        encoding="utf-8",
    )
    chaincfg = tmp_path / "chaincfg"
    chaincfg.mkdir(parents=True)
    (chaincfg / "genesis.go").write_text(
        "package chaincfg\n\n// premine 0x8e1bc9bf040000 units\n",
        encoding="utf-8",
    )
    return tmp_path


def test_btcd_genesis_pin_scoped_to_lbc(tmp_path):
    src = _make_genesis_only_tree(tmp_path)
    xc = {"COIN": "100000000"}
    lbc = audit.ManifestCoin(ticker="LBC", ver_id="lbcd--v1", daemon_family="btcd")
    st_lbc, _ = audit.BtcdSourceInspector.check_coin(lbc, src, xc)
    assert st_lbc == audit.ParamStatus.PASS, f"LBC genesis pin must still PASS, got {st_lbc}"
    hypo = audit.ManifestCoin(ticker="HYPO", ver_id="hypo--v1", daemon_family="btcd")
    st_hypo, det = audit.BtcdSourceInspector.check_coin(hypo, src, xc)
    assert st_hypo == audit.ParamStatus.UNRESOLVED, (
        f"non-LBC coin must not PASS on LBC genesis magic alone, got {st_hypo}: {det[:120]}"
    )


# --- port / rpcport / prefixes / blocktime -----------------------------
# The WARN paths thread SourceReader.lineage_date; a coin whose conf does
# not exist under the given repo_root short-circuits before git, so these
# stay hermetic.


def _coin(ticker="HYPO"):
    return audit.ManifestCoin(ticker=ticker, ver_id=f"{ticker.lower()}--v1", daemon_family="btcd")


def test_btcd_port_match_and_fleet_reassignment(tmp_path):
    (tmp_path / "chaincfg").mkdir()
    (tmp_path / "chaincfg" / "params.go").write_text(
        'package chaincfg\n\nvar MainNetParams = Params{\n    DefaultPort: "9333",\n}\n', encoding="utf-8"
    )
    st, det = audit.BtcdSourceInspector.check_port(_coin(), tmp_path, {"port": "9333"}, tmp_path)
    assert st == audit.ParamStatus.MATCH, det
    assert "chaincfg/params.go:4" in det, det
    st_w, det_w = audit.BtcdSourceInspector.check_port(_coin(), tmp_path, {"port": "19444"}, tmp_path)
    assert st_w == audit.ParamStatus.WARN, det_w
    assert "[fleet-reassigned]" in det_w, det_w


def test_btcd_port_assignment_form_and_missing_inputs(tmp_path):
    (tmp_path / "chaincfg").mkdir()
    (tmp_path / "chaincfg" / "params.go").write_text(
        'package chaincfg\n\nvar MainNetParams = Params{\n    DefaultPort = "9333",\n}\n', encoding="utf-8"
    )
    st, det = audit.BtcdSourceInspector.check_port(_coin(), tmp_path, {"port": "9333"}, tmp_path)
    assert st == audit.ParamStatus.MATCH, f"the `DefaultPort =` spelling must parse, got {st}: {det}"
    st_e, det_e = audit.BtcdSourceInspector.check_port(_coin(), tmp_path, {}, tmp_path)
    assert st_e == audit.ParamStatus.UNRESOLVED and "no port=" in det_e, det_e
    no_params = tmp_path / "bare"
    no_params.mkdir()
    st_f, det_f = audit.BtcdSourceInspector.check_port(_coin(), no_params, {"port": "1"}, no_params)
    assert st_f == audit.ParamStatus.UNRESOLVED and "params.go not found" in det_f, det_f


def test_btcd_port_without_default_port_refuses_to_guess(tmp_path):
    (tmp_path / "chaincfg").mkdir()
    (tmp_path / "chaincfg" / "params.go").write_text(
        'package chaincfg\n\nvar MainNetParams = Params{\n    Name: "x",\n}\n', encoding="utf-8"
    )
    st, det = audit.BtcdSourceInspector.check_port(_coin(), tmp_path, {"port": "9333"}, tmp_path)
    assert st == audit.ParamStatus.UNRESOLVED and "DefaultPort not found" in det, det


def test_btcd_rpcport_default_comment_form(tmp_path):
    (tmp_path / "config.go").write_text(
        "package main\n\n// RPCListeners binds default port: 8334\nvar defaultRPCPort = 8334\n", encoding="utf-8"
    )
    st, det = audit.BtcdSourceInspector.check_rpcport(_coin(), tmp_path, {"rpcport": "8334"}, tmp_path)
    assert st == audit.ParamStatus.MATCH, det
    st_w, det_w = audit.BtcdSourceInspector.check_rpcport(_coin(), tmp_path, {"rpcport": "9999"}, tmp_path)
    assert st_w == audit.ParamStatus.WARN and "[fleet-reassigned]" in det_w, det_w
    st_u, det_u = audit.BtcdSourceInspector.check_rpcport(_coin(), tmp_path, {}, tmp_path)
    assert st_u == audit.ParamStatus.UNRESOLVED and "no rpcport=" in det_u, det_u


def test_btcd_rpcport_without_comment_is_unresolved(tmp_path):
    (tmp_path / "config.go").write_text("package main\n\nvar defaultRPCPort = 8334\n", encoding="utf-8")
    st, det = audit.BtcdSourceInspector.check_rpcport(_coin(), tmp_path, {"rpcport": "8334"}, tmp_path)
    assert st == audit.ParamStatus.UNRESOLVED and "not located" in det, det
    bare = tmp_path / "bare"
    bare.mkdir()
    st_f, det_f = audit.BtcdSourceInspector.check_rpcport(_coin(), bare, {"rpcport": "8334"}, bare)
    assert st_f == audit.ParamStatus.UNRESOLVED, det_f


def _prefix_tree(tmp_path):
    (tmp_path / "chaincfg").mkdir()
    (tmp_path / "chaincfg" / "params.go").write_text(
        "package chaincfg\n\nvar MainNetParams = Params{\n"
        "    PubKeyHashAddrID: 0x1e,\n    ScriptHashAddrID: 0x05,\n    PrivateKeyID: 0x9e,\n}\n"
        "var RegressionNetParams = Params{\n    PubKeyHashAddrID: 0x6f,\n}\n",
        encoding="utf-8",
    )
    return tmp_path


def test_btcd_prefixes_pass_warn_fail_rows(tmp_path):
    _prefix_tree(tmp_path)
    xc_ok = {"AddressPrefix": "30", "ScriptPrefix": "5", "SecretPrefix": "158"}
    st, det = audit.BtcdSourceInspector.check_prefixes(_coin(), tmp_path, xc_ok, tmp_path)
    assert st == audit.ParamStatus.PASS, det
    assert det.count("== source") == 3, det
    st_w, det_w = audit.BtcdSourceInspector.check_prefixes(_coin(), tmp_path, dict(xc_ok, ScriptPrefix="196"), tmp_path)
    assert st_w == audit.ParamStatus.WARN, det_w
    assert "ScriptPrefix: conf 196 vs source 5" in det_w, det_w
    st_f, det_f = audit.BtcdSourceInspector.check_prefixes(_coin(), tmp_path, dict(xc_ok, SecretPrefix="zz"), tmp_path)
    assert st_f == audit.ParamStatus.FAIL and "non-numeric" in det_f, det_f


def test_btcd_prefixes_missing_source_key_is_unresolved(tmp_path):
    (tmp_path / "chaincfg").mkdir()
    (tmp_path / "chaincfg" / "params.go").write_text(
        "package chaincfg\n\nvar MainNetParams = Params{\n    PubKeyHashAddrID: 30,\n}\n", encoding="utf-8"
    )
    st, det = audit.BtcdSourceInspector.check_prefixes(_coin(), tmp_path, {"AddressPrefix": "30"}, tmp_path)
    assert st == audit.ParamStatus.UNRESOLVED, det
    assert "ScriptPrefix: source not found" in det and "SecretPrefix: source not found" in det, det


def test_btcd_blocktime_match_and_drift(tmp_path):
    (tmp_path / "chaincfg").mkdir()
    (tmp_path / "chaincfg" / "params.go").write_text(
        "package chaincfg\n\nvar MainNetParams = Params{\n    TargetTimePerBlock: time.Second * 150,\n}\n",
        encoding="utf-8",
    )
    st, det = audit.BtcdSourceInspector.check_blocktime(_coin(), tmp_path, {"BlockTime": "150"}, tmp_path)
    assert st == audit.ParamStatus.PASS and "== TargetTimePerBlock" in det, det
    st_w, det_w = audit.BtcdSourceInspector.check_blocktime(_coin(), tmp_path, {"BlockTime": "600"}, tmp_path)
    assert st_w == audit.ParamStatus.WARN and "vs chaincfg" in det_w, det_w


def test_btcd_blocktime_duration_form_and_refusals(tmp_path):
    (tmp_path / "chaincfg").mkdir()
    (tmp_path / "chaincfg" / "params.go").write_text(
        "package chaincfg\n\nvar MainNetParams = Params{\n"
        "    TargetTimePerBlock: time.Duration(30 * time.Second),\n}\n",
        encoding="utf-8",
    )
    st, det = audit.BtcdSourceInspector.check_blocktime(_coin(), tmp_path, {"BlockTime": "30"}, tmp_path)
    assert st == audit.ParamStatus.PASS, det
    st_f, det_f = audit.BtcdSourceInspector.check_blocktime(_coin(), tmp_path, {"BlockTime": "abc"}, tmp_path)
    assert st_f == audit.ParamStatus.FAIL and "non-numeric" in det_f, det_f
    st_z, det_z = audit.BtcdSourceInspector.check_blocktime(_coin(), tmp_path, {"BlockTime": "0"}, tmp_path)
    assert st_z == audit.ParamStatus.FAIL and "rejected by blocknet" in det_z, det_z


def test_btcd_blocktime_without_target_time_is_unresolved(tmp_path):
    (tmp_path / "chaincfg").mkdir()
    (tmp_path / "chaincfg" / "params.go").write_text(
        'package chaincfg\n\nvar MainNetParams = Params{\n    Name: "x",\n}\n', encoding="utf-8"
    )
    st, det = audit.BtcdSourceInspector.check_blocktime(_coin(), tmp_path, {"BlockTime": "150"}, tmp_path)
    assert st == audit.ParamStatus.UNRESOLVED and "TargetTimePerBlock not found" in det, det


# --- txversion / txtime ------------------------------------------------


def test_btcd_txversion_bounds(tmp_path):
    (tmp_path / "wire").mkdir()
    (tmp_path / "wire" / "msgtx.go").write_text("package wire\n\nconst TxVersion = 2\n", encoding="utf-8")
    st, det = audit.BtcdSourceInspector.check_txversion(_coin(), tmp_path, {"TxVersion": "1"})
    assert st == audit.ParamStatus.PASS and "wire TxVersion 2" in det, det
    st_eq, _ = audit.BtcdSourceInspector.check_txversion(_coin(), tmp_path, {"TxVersion": "2"})
    assert st_eq == audit.ParamStatus.PASS
    st_over, det_over = audit.BtcdSourceInspector.check_txversion(_coin(), tmp_path, {"TxVersion": "3"})
    assert st_over == audit.ParamStatus.FAIL and "exceeds wire TxVersion" in det_over, det_over
    st_bad, det_bad = audit.BtcdSourceInspector.check_txversion(_coin(), tmp_path, {"TxVersion": "v2"})
    assert st_bad == audit.ParamStatus.FAIL and "non-numeric" in det_bad, det_bad
    bare = tmp_path / "bare"
    bare.mkdir()
    st_f, det_f = audit.BtcdSourceInspector.check_txversion(_coin(), bare, {"TxVersion": "1"})
    assert st_f == audit.ParamStatus.UNRESOLVED and "wire/msgtx.go not found" in det_f, det_f


def test_btcd_txversion_without_constant_is_unresolved(tmp_path):
    (tmp_path / "wire").mkdir()
    (tmp_path / "wire" / "msgtx.go").write_text("package wire\n\n// no version here\n", encoding="utf-8")
    st, det = audit.BtcdSourceInspector.check_txversion(_coin(), tmp_path, {"TxVersion": "1"})
    assert st == audit.ParamStatus.UNRESOLVED and "TxVersion not found" in det, det


def test_btcd_txtime_all_four_legs(tmp_path):
    (tmp_path / "wire").mkdir()
    (tmp_path / "wire" / "msgtx.go").write_text(
        "package wire\n\ntype MsgTx struct {\n    CachedHash *chainhash.Hash\n    Version int32\n"
        "    TxIn []*TxIn\n    TxOut []*TxOut\n    LockTime uint32\n    nTime int64\n}\n",
        encoding="utf-8",
    )
    st, det = audit.BtcdSourceInspector.check_txtime(_coin(), tmp_path, {"TxWithTimeField": "true"})
    assert st == audit.ParamStatus.PASS and "carries nTime" in det, det
    st_w, det_w = audit.BtcdSourceInspector.check_txtime(_coin(), tmp_path, {"TxWithTimeField": "false"})
    assert st_w == audit.ParamStatus.WARN and "wire-format mismatch risk" in det_w, det_w


def test_btcd_txtime_without_wire_field(tmp_path):
    (tmp_path / "wire").mkdir()
    (tmp_path / "wire" / "msgtx.go").write_text(
        "package wire\n\ntype MsgTx struct {\n    Version int32\n    TxIn []*TxIn\n    LockTime uint32\n}\n",
        encoding="utf-8",
    )
    st, det = audit.BtcdSourceInspector.check_txtime(_coin(), tmp_path, {"TxWithTimeField": "true"})
    assert st == audit.ParamStatus.WARN and "no nTime" in det, det
    st_ok, det_ok = audit.BtcdSourceInspector.check_txtime(_coin(), tmp_path, {"TxWithTimeField": "false"})
    assert st_ok == audit.ParamStatus.PASS and "no nTime field" in det_ok, det_ok
    bare = tmp_path / "bare"
    bare.mkdir()
    st_f, det_f = audit.BtcdSourceInspector.check_txtime(_coin(), bare, {"TxWithTimeField": "false"})
    assert st_f == audit.ParamStatus.UNRESOLVED and "wire/msgtx.go not found" in det_f, det_f


# --- txindex / addrtype / deprecatedrpc / structure ---------------------


def test_btcd_txindex_default_matrix(tmp_path):
    (tmp_path / "config.go").write_text("package main\n\ndefaultTxIndex = false\n", encoding="utf-8")
    coin = _coin()
    st_missing, det = audit.BtcdSourceInspector.check_txindex(coin, tmp_path, {})
    assert st_missing == audit.ParamStatus.WARN and "missing from conf" in det, det
    (tmp_path / "config.go").write_text("package main\n\ndefaultTxIndex = true\n", encoding="utf-8")
    st_info, det_info = audit.BtcdSourceInspector.check_txindex(coin, tmp_path, {})
    assert st_info == audit.ParamStatus.INFO and "upstream default=true" in det_info, det_info
    st_off, det_off = audit.BtcdSourceInspector.check_txindex(coin, tmp_path, {"txindex": "0"})
    assert st_off == audit.ParamStatus.WARN and "explicitly disabled" in det_off, det_off
    st_bad, det_bad = audit.BtcdSourceInspector.check_txindex(coin, tmp_path, {"txindex": "maybe"})
    assert st_bad == audit.ParamStatus.FAIL and "non-numeric" in det_bad, det_bad


def test_btcd_txindex_without_default_is_unresolved(tmp_path):
    (tmp_path / "config.go").write_text("package main\n\n// no default here\n", encoding="utf-8")
    st, det = audit.BtcdSourceInspector.check_txindex(_coin(), tmp_path, {"TxIndex": "1"})
    assert st == audit.ParamStatus.UNRESOLVED and "defaultTxIndex not found" in det, det
    bare = tmp_path / "bare"
    bare.mkdir()
    st_f, det_f = audit.BtcdSourceInspector.check_txindex(_coin(), bare, {"TxIndex": "1"})
    assert st_f == audit.ParamStatus.UNRESOLVED and "config.go not found" in det_f, det_f


def test_btcd_addrtype_and_deprecatedrpc_are_not_applicable():
    coin = _coin()
    st_skip, det_skip = audit.BtcdSourceInspector.check_addrtype(coin, None, {})
    assert st_skip == audit.ParamStatus.SKIP and det_skip == "not used", det_skip
    st_info, det_info = audit.BtcdSourceInspector.check_addrtype(coin, None, {"addresstype": "legacy"})
    assert st_info == audit.ParamStatus.INFO and "not applicable" in det_info, det_info
    st_unset, det_unset = audit.BtcdSourceInspector.check_deprecatedrpc(coin, None, {})
    assert st_unset == audit.ParamStatus.INFO and "not set" in det_unset, det_unset
    st_set, det_set = audit.BtcdSourceInspector.check_deprecatedrpc(coin, None, {"DeprecatedRpc": "1"})
    assert st_set == audit.ParamStatus.INFO and "not applicable" in det_set, det_set


def test_btcd_structure_conventions(tmp_path):
    coin = _coin()
    st, det = audit.BtcdSourceInspector.check_structure(coin, {}, {"Ip": "127.0.0.1"})
    assert st == audit.ParamStatus.PASS and "conventions hold" in det, det
    st_ip, det_ip = audit.BtcdSourceInspector.check_structure(coin, {}, {"Ip": "0.0.0.0"})  # noqa: S104  # fixture value for the Ip warning, not a bind
    assert st_ip == audit.ParamStatus.WARN and "Ip='0.0.0.0'" in det_ip, det_ip
    st_v, det_v = audit.BtcdSourceInspector.check_structure(coin, {}, {"Ip": "127.0.0.1", "JSONVersion": ""})
    assert st_v == audit.ParamStatus.INFO and "empty vestigial keys: JSONVersion" in det_v, det_v
    st_c, det_c = audit.BtcdSourceInspector.check_structure(coin, {"rpcuser": "u"}, {"Ip": "127.0.0.1"})
    assert st_c == audit.ParamStatus.INFO and "credentials shipped" in det_c, det_c


# --- fee constants / policy / go.mod legs -------------------------------


def test_btcd_fee_constants_from_policy(tmp_path):
    (tmp_path / "mempool").mkdir()
    (tmp_path / "mempool" / "policy.go").write_text(
        "package mempool\n\nvar DefaultMinRelayTxFee = btcutil.Amount(1000)\n", encoding="utf-8"
    )
    got = audit.BtcdSourceInspector.fee_constants(tmp_path)
    assert got[0] == 1000 and got[1] == "mempool/policy.go:3", got
    other = tmp_path / "policy_dir"
    (other / "policy").mkdir(parents=True)
    (other / "policy" / "policy.go").write_text(
        "package policy\n\nvar DefaultMinRelayTxFee = btcutil.Amount(2000)\n", encoding="utf-8"
    )
    got2 = audit.BtcdSourceInspector.fee_constants(other)
    assert got2[0] == 2000, got2


def test_btcd_fee_constants_absent_is_none(tmp_path):
    assert audit.BtcdSourceInspector.fee_constants(tmp_path) == (None, None, None, None)


def test_btcd_fee_policy_without_go_source_is_unknown(tmp_path):
    pol = audit.BtcdSourceInspector.fee_policy(tmp_path)
    assert pol.rounding == "unknown", pol.evidence
    assert pol.evidence == ("no Go fee policy found",), pol.evidence


def test_btcutil_module_pin_from_gomod():
    gomod = (
        "module github.com/lbc-fullcoin/lbcd\n\ngo 1.17\n\nrequire (\n"
        "    github.com/lbc-fullcoin/lbcutil v0.0.0-20210101000000-abcdefabcdef\n)\n"
    )
    assert audit.BtcdSourceInspector._btcutil_module(gomod) == (
        "github.com/lbc-fullcoin/lbcutil",
        "v0.0.0-20210101000000-abcdefabcdef",
    )
    assert audit.BtcdSourceInspector._btcutil_module("module x\n") is None


def test_vendor_coin_underscore_separators(tmp_path):
    vend = tmp_path / "vendor" / "github.com" / "btcsuite" / "btcd" / "btcutil"
    vend.mkdir(parents=True)
    (vend / "amount.go").write_text("package btcutil\n\nconst SatoshiPerBitcoin = 1_000_000_00\n", encoding="utf-8")
    got = audit.BtcdSourceInspector._vendor_coin(tmp_path)
    assert got == (100000000, "vendor/github.com/btcsuite/btcd/btcutil/amount.go:3"), got


def test_vendor_coin_absent(tmp_path):
    assert audit.BtcdSourceInspector._vendor_coin(tmp_path) is None


def test_intree_coin_pin_three_legs(tmp_path):
    (tmp_path / "rpcserver.go").write_text(
        'package main\n\nimport "btcutil"\n\n'
        "// SatoshiPerBitcoin: amounts go through btcutil.NewAmount\namount := btcutil.NewAmount(1)\n",
        encoding="utf-8",
    )
    (tmp_path / "blockchain").mkdir()
    (tmp_path / "blockchain" / "compress.go").write_text(
        "package blockchain\n\n// 100000000 satoshis per 1.0 BTC\n", encoding="utf-8"
    )
    coin = _coin()
    st, det = audit.BtcdSourceInspector._intree_coin_pin(coin, tmp_path, 100000000, None, None)
    assert st == audit.ParamStatus.PASS and "== source 100000000" in det, det
    st_w, det_w = audit.BtcdSourceInspector._intree_coin_pin(coin, tmp_path, 1000000, None, None)
    assert st_w == audit.ParamStatus.WARN and "fund-loss risk" in det_w, det_w


def test_intree_coin_pin_missing_legs_is_unresolved(tmp_path):
    bare = tmp_path / "bare"
    bare.mkdir()
    st, det = audit.BtcdSourceInspector._intree_coin_pin(_coin(), bare, 100000000, None, None)
    assert st == audit.ParamStatus.UNRESOLVED, det
    assert "rpcserver.go" in det and "compress.go" in det and "premine" in det, det


def test_check_coin_vendor_legs(tmp_path):
    (tmp_path / "vendor").mkdir()
    (tmp_path / "vendor" / "amount.go").write_text(
        "package x\n\nconst SatoshiPerBitcoin = 100000000\n", encoding="utf-8"
    )
    coin = _coin()
    st, det = audit.BtcdSourceInspector.check_coin(coin, tmp_path, {"COIN": "100000000"})
    assert st == audit.ParamStatus.PASS and "== source 100000000" in det, det
    st_w, det_w = audit.BtcdSourceInspector.check_coin(coin, tmp_path, {"COIN": "21000000"})
    assert st_w == audit.ParamStatus.WARN and "fund-loss risk" in det_w, det_w


def test_check_coin_refuses_bad_conf(tmp_path):
    st_nan, det_nan = audit.BtcdSourceInspector.check_coin(_coin(), tmp_path, {"COIN": "none"})
    assert st_nan == audit.ParamStatus.FAIL and "non-numeric" in det_nan, det_nan
    st_zero, det_zero = audit.BtcdSourceInspector.check_coin(_coin(), tmp_path, {"COIN": "0"})
    assert st_zero == audit.ParamStatus.FAIL and "rejected by blocknet" in det_zero, det_zero


def test_module_cache_coin_paths(tmp_path, monkeypatch):
    from audit_manifest import probe as probe_mod

    (tmp_path / "amount.go").write_text("package x\n\nconst SatoshiPerBitcoin = 100000000\n", encoding="utf-8")

    class _FakeProc:
        returncode = 0
        stdout = f"{tmp_path}\n"

    monkeypatch.setattr(probe_mod.SystemCommandRunner, "run", staticmethod(lambda *a, **k: _FakeProc()))
    got = audit.BtcdSourceInspector._module_cache_coin(tmp_path, "github.com/lbc-fullcoin/lbcutil", "v1.2.3")
    assert got == (100000000, "module-cache github.com/lbc-fullcoin/lbcutil@v1.2.3 amount.go"), got

    class _FailProc:
        returncode = 1
        stdout = ""

    monkeypatch.setattr(probe_mod.SystemCommandRunner, "run", staticmethod(lambda *a, **k: _FailProc()))
    assert audit.BtcdSourceInspector._module_cache_coin(tmp_path, "m", "v") is None
