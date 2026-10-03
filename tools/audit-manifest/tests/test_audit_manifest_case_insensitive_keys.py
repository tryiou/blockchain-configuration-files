#!/usr/bin/env python3
"""
Conf and source keys are matched case-insensitively.

Daemons spell the same key several ways across conf files and source
(TxIndex / txindex, AddressType / addressType), so a lookup that compares
case-sensitively reports the key as absent — which turns a check into SKIP
or an empty value instead of a verdict.
"""

import audit_manifest as audit


def test_conf_val_ci_case_insensitive():
    assert audit.conf_val_ci({"TxIndex": "1"}, "txindex") == "1"
    assert audit.conf_val_ci({"txindex": "0"}, "TXINDEX") == "0"
    assert audit.conf_val_ci({}, "txindex") == ""


def test_addrtype_mixed_case_key_detected(tmp_path):
    coin = audit.ManifestCoin(ticker="HYPO", ver_id="hypo--v1")
    st_cpp, _ = audit.CppSourceInspector.check_addrtype(coin, tmp_path, {"AddressType": "legacy"})
    assert st_cpp != audit.ParamStatus.SKIP, "mixed-case AddressType must be detected, got SKIP"
    btcd = audit.ManifestCoin(ticker="HYPO", ver_id="hypo--v1", daemon_family="btcd")
    st_go, _ = audit.BtcdSourceInspector.check_addrtype(btcd, tmp_path, {"ChangeType": "legacy"})
    assert st_go != audit.ParamStatus.SKIP, "mixed-case ChangeType must be detected, got SKIP"
