#!/usr/bin/env python3
"""
Proof-first R9 regression tests for coin-scaffold defects.

CONFIRMED bug 1 (live XVG v26.8 evidence): CppExpressionEvaluator.resolve_cexpr()
searches raw file text INCLUDING //-commented lines. Verge src/amount.h carries
a commented-out `// static const CAmount CENT = 1000000;` above the active
`static const CAmount CENT = 10000;`, so the relay resolves to 10*1000000 =
10,000,000 sat/kB instead of 100,000 — and the scaffold emits
MinTxFee=6780000/FeePerByte=15000, 100x above the correct 67800/150.
This test must FAIL before the fix (rate == 10000000) and PASS after (100000).

New behavior 2: CoinScaffolder.derive_identity() must read daemon + datadir
names from source (Makefile.am bin_PROGRAMS, GetDefaultDataDir) instead of
guessing from the ticker, so --apply output is committable without hand-edits.
"""

import audit_manifest as audit


def _make_verge_like_tree(tmp_path):
    """XVG-shaped: commented CENT above the active one; Verge daemon layout."""
    (tmp_path / "src").mkdir(parents=True)
    (tmp_path / "src" / "amount.h").write_text(
        "// static const CAmount CENT = 1000000;\n"
        "static const CAmount COIN = 100000000;\n"
        "static const CAmount CENT = 10000;\n",
        encoding="utf-8",
    )
    (tmp_path / "src" / "validation.h").write_text(
        "static const unsigned int DEFAULT_MIN_RELAY_TX_FEE = 10 * CENT;\n",
        encoding="utf-8",
    )
    (tmp_path / "src" / "Makefile.am").write_text(
        "/* license block spanning\n"
        "   multiple lines with bin_PROGRAMS mentioned inside */\n"
        "bin_PROGRAMS =\n"
        "bin_PROGRAMS += verged\n"
        "bin_PROGRAMS += verge-cli verge-tx\n"
        "check-symbols: $(bin_PROGRAMS)\n"
        "\t$(AM_V_at) READELF=$(READELF) < $(bin_PROGRAMS)\n",
        encoding="utf-8",
    )
    util = tmp_path / "src" / "util"
    util.mkdir(parents=True)
    (util / "system.cpp").write_text(
        "fs::path GetDefaultDataDir()\n"
        "{\n"
        "    // Mac: ~/Library/Application Support/VERGE\n"
        "    // Unix: ~/.verge\n"
        "#ifdef WIN32\n"
        '    return GetSpecialFolderPath(CSIDL_APPDATA) / "VERGE";\n'
        "#else\n"
        "#ifdef MAC_OSX\n"
        '    return pathRet / "Library/Application Support/VERGE";\n'
        "#else\n"
        '    return pathRet / ".VERGE";\n'
        "#endif\n"
        "#endif\n"
        "}\n",
        encoding="utf-8",
    )
    return tmp_path


def test_commented_cent_ignored(tmp_path):
    src = _make_verge_like_tree(tmp_path)
    rate, rate_ev, _, _ = audit.CppSourceInspector.fee_constants(src)
    assert rate == 100000, f"relay must resolve via ACTIVE CENT=10000 -> 10*10000=100000, got {rate!r} ({rate_ev})"


def test_derive_identity_from_source(tmp_path):
    src = _make_verge_like_tree(tmp_path)
    ident = audit.CoinScaffolder.derive_identity(src, "XVG")
    assert ident["daemon"] == "verged", f"daemon must be verged, got {ident!r}"
    assert ident["conf_name"] == "verge.conf", f"conf_name must be verge.conf, got {ident!r}"
    assert ident["dir_linux"] == "VERGE", f"linux dir must be VERGE, got {ident!r}"
    assert ident["dir_mac"] == "VERGE", f"mac dir must be VERGE, got {ident!r}"
    assert ident["dir_win"] == "VERGE", f"win dir must be VERGE, got {ident!r}"


VERGE_AMOUNT_H = """#include <stdint.h>
/** Amount in satoshis (Can be negative) */
typedef int64_t CAmount;

// static const CAmount COIN = 100000000;
// static const CAmount CENT = 1000000;
// Use peercoin standard
static const CAmount COIN = 1000000;
static const CAmount CENT = 10000;
"""


def test_coin_ignores_commented_definition(tmp_path):
    """CONFIRMED bug 2 (live XVG v26.8 evidence): the COIN regexes run on raw
    file text, so Verge's commented-out `// ... COIN = 100000000;` wins over
    the active `COIN = 1000000` (6 decimals, peercoin standard). The scaffold
    then emits COIN=100000000 and check_coin passes 1e8==1e8 — self-consistent
    wrongness, 100x fund-loss risk. Must resolve 1000000."""
    value, ev = audit.coin_value_from_amount_h(VERGE_AMOUNT_H, "src/amount.h", tmp_path)
    assert value == 1000000, f"COIN must resolve via ACTIVE definition -> 1000000, got {value!r} ({ev})"


def test_check_coin_passes_corrected_conf(tmp_path):
    src = tmp_path / "src"
    src.mkdir(parents=True)
    (src / "amount.h").write_text(VERGE_AMOUNT_H, encoding="utf-8")
    coin = audit.ManifestCoin(ticker="XVG", ver_id="verge--v26.8")
    status, msg = audit.CppSourceInspector.check_coin(coin, tmp_path, {"COIN": "1000000"})
    assert status == audit.ParamStatus.PASS, f"conf COIN=1000000 must match source 1000000, got {status!r} ({msg})"


def test_scaffold_plan_entries_carry_staged_contents():
    """P4: staged entries embed everything Apply needs, no /tmp chase."""
    from audit_manifest.scaffold import scaffold_plan_entries

    snippet = {"ticker": "NEW", "ver_id": "new--v1.0", "versions": ["v1.0.0"]}
    entries = scaffold_plan_entries(
        "NEW",
        "new--v1.0",
        "v1.0.0",
        "new--v1.0.conf",
        "new--v1.0.conf",
        "rpcuser=x\n",
        "Port=1\n",
        snippet,
        "manifest-latest.json",
    )
    assert [e["file"] for e in entries] == [
        "wallet-confs/new--v1.0.conf",
        "xbridge-confs/new--v1.0.conf",
        "manifest-latest.json",
    ]
    assert entries[0]["contents"] == "rpcuser=x\n"
    assert entries[1]["contents"] == "Port=1\n"
    assert entries[2]["snippet"] == snippet
    assert all(e["applied"] is False for e in entries)


def test_scaffold_proposal_prefers_free_source_ports():
    """Port proposals reuse source values exactly when free."""
    from audit_manifest.scaffold import propose_scaffold_ports

    assert propose_scaffold_ports(5000, 5001, {1000}, {2000}) == (5000, 5001)


def test_scaffold_proposal_moves_off_taken_ports():
    """Port proposals dodge occupied values instead of colliding."""
    from audit_manifest.scaffold import propose_scaffold_ports

    p2p, rpc = propose_scaffold_ports(5000, 5001, {5000}, {5001})
    assert (p2p, rpc) != (5000, 5001)
    assert p2p not in {5000} and rpc not in {5001}
    assert 1024 <= p2p <= 65535 and 1024 <= rpc <= 65535


def test_scaffold_proposal_gives_up_when_crowded_out():
    """No free pair anywhere is an explicit None, never a collision."""
    from audit_manifest.scaffold import propose_scaffold_ports

    used = set(range(1024, 65536))
    assert propose_scaffold_ports(5000, 5001, used, used) is None


def test_staging_dir_refuses_symlinks(tmp_path):
    """Staged files never land through a hijacked path."""
    from audit_manifest.scaffold import ensure_out_dir

    link = tmp_path / "link"
    link.symlink_to(tmp_path)
    assert ensure_out_dir(link) is not None
    assert ensure_out_dir(tmp_path / "fresh") is None
    assert (tmp_path / "fresh").is_dir()


def test_scaffold_applier_refuses_duplicates_and_collisions(tmp_path):
    """Staged apply refuses duplicates and taken ports, writes nothing."""
    from audit_manifest.apply_plan import apply_entries
    from audit_manifest.scaffold import scaffold_plan_entries

    (tmp_path / "manifest-latest.json").write_text(
        __import__("json").dumps(
            [
                {
                    "ticker": "AAA",
                    "ver_id": "a--v1.0",
                    "versions": ["v1.0.0"],
                    "wallet_conf": "aaa.conf",
                    "xbridge_conf": "aaa.conf",
                }
            ]
        )
    )
    (tmp_path / "wallet-confs").mkdir()
    (tmp_path / "xbridge-confs").mkdir()
    (tmp_path / "wallet-confs" / "aaa.conf").write_text("port=5000\nrpcport=5001\n")
    (tmp_path / "xbridge-confs" / "aaa.conf").write_text("Port=5001\n")
    dup_snippet = {
        "ticker": "AAA",
        "ver_id": "a--v1.0",
        "versions": ["v1.0.0"],
        "wallet_conf": "aaa.conf",
        "xbridge_conf": "aaa.conf",
    }
    dup = scaffold_plan_entries(
        "AAA",
        "a--v1.0",
        "v1.0.0",
        "aaa.conf",
        "aaa.conf",
        "port=6000\n",
        "Port=6000\n",
        dup_snippet,
        "manifest-latest.json",
    )
    assert all(e["applied"] is False for e in apply_entries(dup, tmp_path))
    clash_snippet = {
        "ticker": "NEW",
        "ver_id": "new--v1.0",
        "versions": ["v1.0.0"],
        "wallet_conf": "new--v1.0.conf",
        "xbridge_conf": "new--v1.0.conf",
    }
    clash = scaffold_plan_entries(
        "NEW",
        "new--v1.0",
        "v1.0.0",
        "new--v1.0.conf",
        "new--v1.0.conf",
        "port=5000\nrpcport=5001\n",
        "Port=5001\n",
        clash_snippet,
        "manifest-latest.json",
    )
    out = apply_entries(clash, tmp_path)
    assert all(e["applied"] is False for e in out)
    assert not (tmp_path / "wallet-confs" / "new--v1.0.conf").exists()


def test_scaffold_apply_routes_through_single_applier(tmp_path):
    """No dual path: staged entries apply via apply_entries only."""
    from audit_manifest.apply_plan import apply_entries
    from audit_manifest.scaffold import scaffold_plan_entries

    snippet = {
        "ticker": "NEW",
        "ver_id": "new--v1.0",
        "versions": ["v1.0.0"],
        "wallet_conf": "new--v1.0.conf",
        "xbridge_conf": "new--v1.0.conf",
    }
    (tmp_path / "manifest-latest.json").write_text(__import__("json").dumps([]))
    (tmp_path / "wallet-confs").mkdir()
    (tmp_path / "xbridge-confs").mkdir()
    entries = scaffold_plan_entries(
        "NEW",
        "new--v1.0",
        "v1.0.0",
        "new--v1.0.conf",
        "new--v1.0.conf",
        "rpcuser=x\nport=6000\nrpcport=6001\n",
        "Port=6001\n",
        snippet,
        "manifest-latest.json",
    )
    out = apply_entries(entries, tmp_path)
    assert all(e["applied"] for e in out)
    assert (tmp_path / "wallet-confs" / "new--v1.0.conf").is_file()
    assert (tmp_path / "xbridge-confs" / "new--v1.0.conf").is_file()
    tickers = [e["ticker"] for e in __import__("json").loads((tmp_path / "manifest-latest.json").read_text())]
    assert tickers == ["NEW"]


def _scaffold_args(tmp_path, *, apply):
    """Minimal args reaching the write stage without network."""
    import argparse as _ap

    return _ap.Namespace(
        repo_url="https://github.com/example/newcoin-core",
        scaffold_ticker="NEW",
        scaffold_tag="v1.0.0",
        scaffold_out_dir=str(tmp_path / "stage"),
        scaffold_name=None,
        apply=apply,
        dry_run=False,
        timeout=10,
    )


def _scaffold_params():
    """Complete extraction payload so run() reaches the write stage."""
    from audit_manifest.model import FeePolicy

    return {
        "port": (6000, "src/chainparams.cpp:1"),
        "rpcport": (6001, "src/chainparams.cpp:2"),
        "COIN": (100000000, "src/amount.h:1"),
        "BlockTime": (150, "src/chainparams.cpp:3"),
        "TxVersion": (1, "src/primitives/transaction.h:1"),
        "AddressPrefix": (0, "src/chainparams.cpp:4"),
        "ScriptPrefix": (5, "src/chainparams.cpp:5"),
        "SecretPrefix": (128, "src/chainparams.cpp:6"),
        "relay_rate": (1000, "src/validation.h:1"),
        "fee_policy": FeePolicy(rounding="floor", mempool="flat"),
        "_family": "btc",
    }


def test_scaffold_print_only_writes_nothing_to_repo(tmp_path, monkeypatch):
    """Print-only stages to out_dir; the repo stays untouched."""
    import json as _json
    from unittest import mock as _mock

    from audit_manifest.checkout import SourceCheckoutManager
    from audit_manifest.scaffold import CoinScaffolder

    (tmp_path / "manifest-latest.json").write_text(_json.dumps([]))
    (tmp_path / "wallet-confs").mkdir()
    (tmp_path / "xbridge-confs").mkdir()
    src = tmp_path / "src-tree"
    src.mkdir()
    monkeypatch.setattr(SourceCheckoutManager, "resolve_for", lambda self, ticker, url, tag, timeout: (src, "cloned"))
    with _mock.patch.object(CoinScaffolder, "extract_scaffold_params", return_value=_scaffold_params()):
        rc, _result = CoinScaffolder().run(_scaffold_args(tmp_path, apply=False), [], tmp_path)
    assert rc == 0
    assert (tmp_path / "stage" / "wallet-confs").is_dir()
    assert list((tmp_path / "wallet-confs").iterdir()) == []
    assert _json.loads((tmp_path / "manifest-latest.json").read_text()) == []


def test_scaffold_apply_writes_coin_through_applier(tmp_path, monkeypatch):
    """--apply lands wallet, xbridge and manifest entry as one coin."""
    import json as _json
    from unittest import mock as _mock

    from audit_manifest.checkout import SourceCheckoutManager
    from audit_manifest.scaffold import CoinScaffolder

    (tmp_path / "manifest-latest.json").write_text(_json.dumps([]))
    (tmp_path / "wallet-confs").mkdir()
    (tmp_path / "xbridge-confs").mkdir()
    src = tmp_path / "src-tree"
    src.mkdir()
    monkeypatch.setattr(SourceCheckoutManager, "resolve_for", lambda self, ticker, url, tag, timeout: (src, "cloned"))
    with _mock.patch.object(CoinScaffolder, "extract_scaffold_params", return_value=_scaffold_params()):
        rc, result = CoinScaffolder().run(_scaffold_args(tmp_path, apply=True), [], tmp_path)
    assert rc == 0
    assert result["applied"] is True
    assert (tmp_path / "wallet-confs" / "new--v1.0.0.conf").is_file()
    assert (tmp_path / "xbridge-confs" / "new--v1.0.0.conf").is_file()
    assert [e["ticker"] for e in _json.loads((tmp_path / "manifest-latest.json").read_text())] == ["NEW"]


def test_scaffold_apply_is_all_or_nothing_on_half_exists(tmp_path):
    """Half-present targets refuse before any write; no partial coin."""
    from audit_manifest.scaffold import scaffold_target_checks

    (tmp_path / "manifest-latest.json").write_text(__import__("json").dumps([]))
    (tmp_path / "wallet-confs").mkdir()
    (tmp_path / "xbridge-confs").mkdir()
    (tmp_path / "wallet-confs" / "new--v1.0.conf").write_text("existing\n")
    err = scaffold_target_checks("NEW", "new--v1.0.conf", "new--v1.0.conf", tmp_path)
    assert err is not None
    assert not (tmp_path / "xbridge-confs" / "new--v1.0.conf").exists()
    assert __import__("json").loads((tmp_path / "manifest-latest.json").read_text()) == []


def test_scaffold_proposal_treats_namespaces_as_one_domain():
    """A source p2p equal to any fleet rpc is taken, not free."""
    from audit_manifest.scaffold import propose_scaffold_ports

    got = propose_scaffold_ports(5000, 6000, {1000}, {5000})
    assert got != (5000, 6000)
    assert got[0] not in ({1000} | {5000}) and got[1] not in ({1000} | {5000})


def test_scaffold_detects_nTime_serialization_with_space(tmp_path):
    """R9 proof-first: `s >> tx.nTime;` must count as serialized.

    The scaffold's serialization regex carried `>>s*` (zero or more literal
    's') instead of `>>\\s*`, so the canonical `s >> tx.nTime;` form never
    matched and a scaffolded coin got TxWithTimeField=false from source that
    does serialize it. This test must FAIL before the fix and PASS after.
    """
    (tmp_path / "src" / "primitives").mkdir(parents=True)
    (tmp_path / "src" / "primitives" / "transaction.h").write_text(
        "class CTransaction {\n"
        "    ...\n"
        "    template <typename Stream, typename Operation>\n"
        "    inline void SerializationOp(Stream& s, Operation ser_action) {\n"
        "        s << tx.nVersion;\n"
        "        s >> tx.nTime;\n"
        "    }\n"
        "};\n",
        encoding="utf-8",
    )
    params = audit.CoinScaffolder().extract_scaffold_params(tmp_path)
    flag, _ev = params["TxWithTimeField"]
    assert flag is True, "s >> tx.nTime; is nTime serialization; the regex must see it"
