#!/usr/bin/env python3
"""
BtcdSourceInspector's own source rules.

btcd spells config fields in mixed case (defaultTxIndex in config.go) and
ships a pinned LBC genesis magic. Neither may leak into a verdict: a mixed
key still resolves, and the genesis pin stays scoped to LBC instead of
making every btcd coin look verified.
"""
import importlib.util
import sys
from pathlib import Path

AUDIT_PATH = Path(__file__).resolve().parents[1] / "audit-manifest.py"
spec = importlib.util.spec_from_file_location("audit_manifest_btcdinsp", str(AUDIT_PATH))
audit = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = audit
spec.loader.exec_module(audit)


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
