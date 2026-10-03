#!/usr/bin/env python3
"""
Fee-constant lookup must dispatch on the coin's daemon family.

fee_constants_for_coin() routes btcd-family coins through the Go inspector
(mempool/policy.go DefaultMinRelayTxFee) and everything else through the C++
inspector. A btcd coin must not take its relay rate from a C++ tree, and a
BTC coin must not resolve one out of a Go tree.
"""

import audit_manifest as audit


def _make_go_tree(tmp_path, amount=1000):
    mempool = tmp_path / "mempool"
    mempool.mkdir(parents=True)
    (mempool / "policy.go").write_text(
        f"package mempool\n\n// DefaultMinRelayTxFee is the minimum fee.\n"
        f"DefaultMinRelayTxFee = btcutil.Amount({amount})\n",
        encoding="utf-8",
    )
    return tmp_path


def test_fee_dispatch_uses_btcd_path_for_btcd_coin(tmp_path):
    src = _make_go_tree(tmp_path)
    btcd_coin = audit.ManifestCoin(ticker="LBC", ver_id="lbcd--v1", daemon_family="btcd")
    rate, rate_ev, dust, dust_ev = audit.fee_constants_for_coin(btcd_coin, src)
    assert rate == 1000, f"btcd path must resolve relay from mempool/policy.go, got {rate!r}"
    assert rate_ev.startswith("mempool/policy.go:"), f"citation file wrong: {rate_ev!r}"


def test_fee_dispatch_uses_cpp_path_for_btc_coin(tmp_path):
    src = _make_go_tree(tmp_path)
    btc_coin = audit.ManifestCoin(ticker="BTC", ver_id="bitcoin--v1", daemon_family="btc")
    rate, _, _, _ = audit.fee_constants_for_coin(btc_coin, src)
    assert rate is None, f"C++ path must find no relay in a Go tree, got {rate!r}"
