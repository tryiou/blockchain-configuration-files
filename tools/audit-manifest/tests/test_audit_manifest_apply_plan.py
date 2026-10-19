#!/usr/bin/env python3
"""Tests for the derive/apply split: plan halves never write, the applier
never derives, and both agree with the legacy fixers byte for byte.

Standard library + pytest only; no network, no Textual, no working tree.
"""

import json

import pytest

from audit_manifest.apply_plan import apply_entries
from audit_manifest.fixes import ConfigAutoFixer
from audit_manifest.model import ManifestCoin
from audit_manifest.ports import PortCollisionManager


def make_coin(**kw):
    base = {
        "ticker": "AAA",
        "ver_id": "aaa--v1.0",
        "wallet_conf": "aaa--v1.0.conf",
        "xbridge_conf": "aaa--v1.0.conf",
        "versions": ["v1.0.0"],
    }
    base.update(kw)
    return ManifestCoin(**base)


@pytest.fixture
def root(tmp_path):
    (tmp_path / "wallet-confs").mkdir()
    (tmp_path / "xbridge-confs").mkdir()
    (tmp_path / "wallet-confs" / "aaa--v1.0.conf").write_text(
        "rpcuser=x\nDustAmount=100\ndeprecatedrpc=wallet\n", encoding="utf-8"
    )
    (tmp_path / "xbridge-confs" / "aaa--v1.0.conf").write_text(
        "MinTxFee=0.1\nPort=9999\nDustAmount=100\n", encoding="utf-8"
    )
    return tmp_path


def snapshot(root):
    return {
        str(p.relative_to(root)): p.read_bytes()
        for p in sorted((root / "wallet-confs").glob("*")) + sorted((root / "xbridge-confs").glob("*"))
    }


def test_plan_halves_write_nothing(root):
    """P0-B: derivation leaves every byte untouched."""
    coin = make_coin()
    before = snapshot(root)
    ConfigAutoFixer.plan_missing_txindex(root, coin)
    ConfigAutoFixer.plan_normalize_dust(root, coin)
    ConfigAutoFixer.plan_remove_deprecatedrpc(root, coin)
    PortCollisionManager.plan_wallet_key(root / "wallet-confs" / "aaa--v1.0.conf", "rpcport", 8888, repo_root=root)
    assert snapshot(root) == before


def test_applier_appends_txindex_and_refuses_when_present(root):
    """P0-B: txindex applies once, then refuses as stale."""
    coin = make_coin()
    entries, _ = ConfigAutoFixer.plan_missing_txindex(root, coin)
    entry = entries[0]
    out = apply_entries([entry], root)
    assert out[0]["applied"] is True
    assert "txindex=1" in (root / "wallet-confs" / "aaa--v1.0.conf").read_text()
    out = apply_entries([entry], root)
    assert out[0]["applied"] is False


def test_applier_dust_replace_and_stale_refuse(root):
    """P0-B: dust rewrites the reviewed value, refuses a moved one."""
    coin = make_coin()
    entries, _ = ConfigAutoFixer.plan_normalize_dust(root, coin)
    entry = entries[0]
    assert entry["old"] == "100"
    out = apply_entries([entry], root)
    assert out[0]["applied"] is True
    assert "DustAmount=0" in (root / "xbridge-confs" / "aaa--v1.0.conf").read_text()
    out = apply_entries([entry], root)
    assert out[0]["applied"] is False


def test_applier_removes_deprecatedrpc(root):
    """P0-B: stale flag lines are removed, then refused when gone."""
    coin = make_coin()
    entries, _ = ConfigAutoFixer.plan_remove_deprecatedrpc(root, coin)
    entry = entries[0]
    assert entry["new"] is None
    out = apply_entries([entry], root)
    assert out[0]["applied"] is True
    assert "deprecatedrpc" not in (root / "wallet-confs" / "aaa--v1.0.conf").read_text()
    out = apply_entries([entry], root)
    assert out[0]["applied"] is False


def test_applier_refuses_grown_deprecatedrpc(root):
    """A file that gained matching lines is not what was reviewed."""
    coin = make_coin()
    entries, _ = ConfigAutoFixer.plan_remove_deprecatedrpc(root, coin)
    entry = entries[0]
    with (root / "wallet-confs" / "aaa--v1.0.conf").open("a", encoding="utf-8") as fh:
        fh.write("deprecatedrpc=newflag\n")
    out = apply_entries([entry], root)
    assert out[0]["applied"] is False


def test_applier_sets_port_and_refuses_mismatch(root):
    """P0-B: port rewrite verifies the reviewed old value first."""
    (root / "manifest-latest.json").write_text(
        json.dumps(
            [
                {
                    "ticker": "AAA",
                    "ver_id": "aaa--v1.0",
                    "versions": ["v1.0.0"],
                    "wallet_conf": "aaa--v1.0.conf",
                    "xbridge_conf": "aaa--v1.0.conf",
                }
            ]
        )
    )
    entries, _ = PortCollisionManager.plan_wallet_key(
        root / "xbridge-confs" / "aaa--v1.0.conf", "Port", 7777, repo_root=root
    )
    entry = entries[0]
    entry["coin"] = "AAA"
    out = apply_entries([entry], root)
    assert out[0]["applied"] is True
    out = apply_entries([dict(entry, old="1")], root)
    assert out[0]["applied"] is False


def test_fee_plan_emits_two_scalar_entries():
    """P0-B: the fee composite is two appliable single-key entries."""
    from audit_manifest.fixes import plan_fee_entries

    entries = plan_fee_entries("0.1", "5", "0.01", "1", "xbridge-confs/a.conf", ticker="AAA", ver_id="a--v1")
    assert [(e["key"], e["old"], e["new"]) for e in entries] == [("MinTxFee", "0.1", "0.01"), ("FeePerByte", "5", "1")]


def test_versions_append_applies_and_refuses_stale(tmp_path):
    """P0-B: version append verifies the reviewed old list."""
    manifest = [{"ticker": "AAA", "versions": ["v1.0.0"], "ver_id": "a--v1.0"}]
    (tmp_path / "manifest-latest.json").write_text(json.dumps(manifest))
    entry = {
        "action": "versions",
        "file": "manifest-latest.json",
        "key": "AAA.versions",
        "old": "v1.0.0",
        "new": "v1.0.0, v1.1.0",
        "reason": "t",
        "coin": "AAA",
        "ver_id": "a--v1.0",
        "applied": False,
    }
    out = apply_entries([entry], tmp_path)
    assert out[0]["applied"] is True
    assert json.loads((tmp_path / "manifest-latest.json").read_text())[0]["versions"] == ["v1.0.0", "v1.1.0"]
    out = apply_entries([entry], tmp_path)
    assert out[0]["applied"] is False


def test_versions_collapse_carries_machine_target(tmp_path):
    """P0-B: collapse entries store the tag the applier renames to."""
    import argparse

    from audit_manifest.fixes import plan_version_bumps

    manifest = [
        {
            "ticker": "AAA",
            "ver_id": "aaa--v1.0",
            "versions": ["v1.0.0"],
            "wallet_conf": "aaa--v1.0.conf",
            "xbridge_conf": "aaa--v1.0.conf",
        }
    ]
    (tmp_path / "manifest-latest.json").write_text(json.dumps(manifest))
    (tmp_path / "wallet-confs").mkdir()
    (tmp_path / "xbridge-confs").mkdir()
    (tmp_path / "wallet-confs" / "aaa--v1.0.conf").write_text("x=1\n")
    (tmp_path / "xbridge-confs" / "aaa--v1.0.conf").write_text("y=2\n")
    repos = {
        "https://example.invalid/r": {
            "status": "ALIVE",
            "newer_same": ["v1.1.0"],
            "newer_alt": [],
            "remote_latest": "v1.1.0",
            "entries": [{"ticker": "AAA"}],
        }
    }
    args = argparse.Namespace(update_versions=True, replace_versions=True, dry_run=True)
    tickers, plan = plan_version_bumps(args, tmp_path / "manifest-latest.json", repos, tmp_path)
    assert tickers == ["AAA"]
    main = next(e for e in plan if e["key"] == "AAA")
    assert main["target"] == "v1.1.0"
    assert main["old_ver_id"] == "aaa--v1.0"
    assert (tmp_path / "manifest-latest.json").read_text() == json.dumps(manifest)
    out = apply_entries(plan, tmp_path)
    assert all(e["applied"] for e in out)
    item = json.loads((tmp_path / "manifest-latest.json").read_text())[0]
    assert item["versions"] == ["v1.1.0"]
    assert (tmp_path / "wallet-confs" / "aaa--v1.1.0.conf").is_file()


def test_versions_collapse_removes_the_superseded_confs(tmp_path):
    """--replace-versions renames: the retired confs must not survive as orphans.

    The manifest is rewritten to the new conf names, so leaving the old confs
    behind orphans them on every collapse. The plan must carry each removal and
    the applier must drop the file once the manifest no longer names it.
    """
    import argparse

    from audit_manifest.fixes import plan_version_bumps

    manifest = [
        {
            "ticker": "AAA",
            "ver_id": "aaa--v1.0",
            "versions": ["v1.0.0"],
            "wallet_conf": "aaa--v1.0.conf",
            "xbridge_conf": "aaa--v1.0.conf",
        }
    ]
    (tmp_path / "manifest-latest.json").write_text(json.dumps(manifest))
    (tmp_path / "wallet-confs").mkdir()
    (tmp_path / "xbridge-confs").mkdir()
    (tmp_path / "wallet-confs" / "aaa--v1.0.conf").write_text("x=1\n")
    (tmp_path / "xbridge-confs" / "aaa--v1.0.conf").write_text("y=2\n")
    repos = {
        "https://example.invalid/r": {
            "status": "ALIVE",
            "newer_same": ["v1.1.0"],
            "newer_alt": [],
            "remote_latest": "v1.1.0",
            "entries": [{"ticker": "AAA"}],
        }
    }
    args = argparse.Namespace(update_versions=True, replace_versions=True, dry_run=True)
    _tickers, plan = plan_version_bumps(args, tmp_path / "manifest-latest.json", repos, tmp_path)
    removals = [e for e in plan if e["action"] == "versions" and e["key"] == "-"]
    assert len(removals) == 2, plan
    assert {e["file"] for e in removals} == {"wallet-confs/aaa--v1.0.conf", "xbridge-confs/aaa--v1.0.conf"}
    out = apply_entries(plan, tmp_path)
    assert all(e["applied"] for e in out), [e for e in out if not e["applied"]]
    assert (tmp_path / "wallet-confs" / "aaa--v1.1.0.conf").is_file()
    assert (tmp_path / "xbridge-confs" / "aaa--v1.1.0.conf").is_file()
    assert not (tmp_path / "wallet-confs" / "aaa--v1.0.conf").exists()
    assert not (tmp_path / "xbridge-confs" / "aaa--v1.0.conf").exists()


def test_superseded_removal_refuses_while_the_manifest_still_names_it(tmp_path):
    """A refused or skipped collapse must never orphan-delete a live conf.

    Removal is only safe once the manifest points elsewhere; while it still
    names the file the entry must refuse and leave the file in place.
    """
    (tmp_path / "wallet-confs").mkdir()
    (tmp_path / "wallet-confs" / "aaa--v1.0.conf").write_text("x=1\n")
    (tmp_path / "manifest-latest.json").write_text(
        json.dumps(
            [
                {
                    "ticker": "AAA",
                    "ver_id": "aaa--v1.0",
                    "versions": ["v1.0.0"],
                    "wallet_conf": "aaa--v1.0.conf",
                    "xbridge_conf": "aaa--v1.0.conf",
                }
            ]
        )
    )
    entry = {
        "action": "versions",
        "file": "wallet-confs/aaa--v1.0.conf",
        "key": "-",
        "old": "aaa--v1.0.conf",
        "new": None,
        "reason": "t",
        "coin": "AAA",
        "ver_id": "aaa--v1.0",
        "applied": False,
    }
    out = apply_entries([entry], tmp_path)
    assert out[0]["applied"] is False
    assert "still points at" in out[0]["error"]
    assert (tmp_path / "wallet-confs" / "aaa--v1.0.conf").is_file()


def test_superseded_removal_refuses_while_another_ticker_holds_the_conf(tmp_path):
    """A conf still named by a second manifest row must survive the collapse.

    Conf names embed ticker+version, so two rows sharing one is not expected
    today — but this applier deletes a file, so the gate must cover the whole
    fleet, not only the collapsing coin's own row.
    """
    (tmp_path / "wallet-confs").mkdir()
    (tmp_path / "wallet-confs" / "aaa--v1.0.conf").write_text("x=1\n")
    (tmp_path / "manifest-latest.json").write_text(
        json.dumps(
            [
                {
                    "ticker": "AAA",
                    "ver_id": "aaa--v1.1",
                    "versions": ["v1.1.0"],
                    "wallet_conf": "aaa--v1.1.conf",
                    "xbridge_conf": "aaa--v1.1.conf",
                },
                {
                    "ticker": "BBB",
                    "ver_id": "aaa--v1.0",
                    "versions": ["v1.0.0"],
                    "wallet_conf": "aaa--v1.0.conf",
                    "xbridge_conf": "aaa--v1.0.conf",
                },
            ]
        )
    )
    entry = {
        "action": "versions",
        "file": "wallet-confs/aaa--v1.0.conf",
        "key": "-",
        "old": "aaa--v1.0.conf",
        "new": None,
        "reason": "t",
        "coin": "AAA",
        "ver_id": "aaa--v1.1",
        "applied": False,
    }
    out = apply_entries([entry], tmp_path)
    assert out[0]["applied"] is False
    assert "is still named by BBB" in out[0]["error"]
    assert (tmp_path / "wallet-confs" / "aaa--v1.0.conf").is_file()


def test_superseded_removal_refuses_while_a_duplicate_row_names_the_conf(tmp_path):
    """A second row for the same ticker still blocks the unlink.

    The collapse rewrites only the first row it finds, so a duplicate ticker
    (hand-edited manifest) can leave the old conf named elsewhere. The holder
    scan must read every row, not skip rows that share the removal's coin.
    """
    (tmp_path / "wallet-confs").mkdir()
    (tmp_path / "wallet-confs" / "aaa--v1.0.conf").write_text("x=1\n")
    (tmp_path / "manifest-latest.json").write_text(
        json.dumps(
            [
                {
                    "ticker": "AAA",
                    "ver_id": "aaa--v1.1",
                    "versions": ["v1.1.0"],
                    "wallet_conf": "aaa--v1.1.conf",
                    "xbridge_conf": "aaa--v1.1.conf",
                },
                {
                    "ticker": "AAA",
                    "ver_id": "aaa--v1.0",
                    "versions": ["v1.0.0"],
                    "wallet_conf": "aaa--v1.0.conf",
                    "xbridge_conf": "aaa--v1.0.conf",
                },
            ]
        )
    )
    entry = {
        "action": "versions",
        "file": "wallet-confs/aaa--v1.0.conf",
        "key": "-",
        "old": "aaa--v1.0.conf",
        "new": None,
        "reason": "t",
        "coin": "AAA",
        "ver_id": "aaa--v1.1",
        "applied": False,
    }
    out = apply_entries([entry], tmp_path)
    assert out[0]["applied"] is False
    assert "still named by AAA" in out[0]["error"]
    assert (tmp_path / "wallet-confs" / "aaa--v1.0.conf").is_file()


def test_scaffold_entries_refused_without_staged_contents(tmp_path):
    """P0-B: contentless scaffold entries refuse instead of guessing."""
    entry = {
        "action": "scaffold",
        "file": "wallet-confs/new.conf",
        "key": "*",
        "old": None,
        "new": "generated",
        "reason": "t",
        "applied": False,
    }
    out = apply_entries([entry], tmp_path)
    assert out[0]["applied"] is False
    assert not (tmp_path / "wallet-confs" / "new.conf").exists()


def test_plan_apply_writes_exact_bytes(root):
    """P0-B: plan halves plus applier produce the exact expected tree."""
    coin = make_coin()
    planned = []
    for entries, _ in (
        ConfigAutoFixer.plan_missing_txindex(root, coin),
        ConfigAutoFixer.plan_normalize_dust(root, coin),
        ConfigAutoFixer.plan_remove_deprecatedrpc(root, coin),
    ):
        planned.extend(entries)
    out = apply_entries(planned, root)
    assert all(e["applied"] for e in out)
    wallet = (root / "wallet-confs" / "aaa--v1.0.conf").read_text()
    xbridge = (root / "xbridge-confs" / "aaa--v1.0.conf").read_text()
    assert wallet == "rpcuser=x\nDustAmount=100\ntxindex=1\n"
    assert xbridge == "MinTxFee=0.1\nPort=9999\nDustAmount=0\n"


def test_apply_plan_file_round_trip(tmp_path):
    """P0-B: the plan file comes back with applied flags."""
    from audit_manifest.apply_plan import apply_plan_file
    from audit_manifest.probe import SystemCommandRunner

    (tmp_path / "wallet-confs").mkdir()
    (tmp_path / "wallet-confs" / "a.conf").write_text("rpcuser=x\n")
    plan = [
        {
            "action": "txindex",
            "file": "wallet-confs/a.conf",
            "key": "txindex",
            "old": None,
            "new": "1",
            "reason": "t",
            "coin": "AAA",
            "applied": False,
        }
    ]
    path = tmp_path / "plan.json"
    path.write_text(json.dumps({"schema_version": 1, "plan": plan, "findings": []}))
    rc, out = apply_plan_file(path, tmp_path, SystemCommandRunner())
    assert rc == 0
    assert out[0]["applied"] is True
    assert json.loads(path.read_text())["plan"][0]["applied"] is True
    rc, out = apply_plan_file(path, tmp_path, SystemCommandRunner())
    assert rc == 1
    assert out[0]["applied"] is False


def test_apply_plan_cli_flag_is_offline(tmp_path, capsys):
    """P0-B: --apply-plan never probes, clones or fetches."""
    from audit_manifest import cli

    (tmp_path / "manifest-latest.json").write_text(
        json.dumps(
            [
                {
                    "ticker": "AAA",
                    "ver_id": "a--v1.0",
                    "versions": ["v1.0.0"],
                    "wallet_conf": "a.conf",
                    "xbridge_conf": "a.conf",
                }
            ]
        )
    )
    (tmp_path / "wallet-confs").mkdir()
    (tmp_path / "wallet-confs" / "a.conf").write_text("rpcuser=x\n")
    plan = [
        {
            "action": "txindex",
            "file": "wallet-confs/a.conf",
            "key": "txindex",
            "old": None,
            "new": "1",
            "reason": "t",
            "coin": "AAA",
            "applied": False,
        }
    ]
    path = tmp_path / "plan.json"
    path.write_text(json.dumps(plan))
    rc = cli.main(["--manifest", str(tmp_path / "manifest-latest.json"), "--apply-plan", str(path)])
    assert rc == 0
    assert "txindex=1" in (tmp_path / "wallet-confs" / "a.conf").read_text()


def test_scaffold_apply_writes_embedded_bytes(tmp_path):
    """P4: staged entries apply without re-derivation or /tmp reads."""
    (tmp_path / "manifest-latest.json").write_text(
        json.dumps(
            [
                {
                    "ticker": "AAA",
                    "ver_id": "aaa--v1.0",
                    "versions": ["v1.0.0"],
                    "wallet_conf": "aaa.conf",
                    "xbridge_conf": "aaa.conf",
                }
            ]
        )
    )
    snippet = {
        "ticker": "NEW",
        "ver_id": "new--v1.0",
        "versions": ["v1.0.0"],
        "wallet_conf": "new--v1.0.conf",
        "xbridge_conf": "new--v1.0.conf",
    }
    entries = [
        {
            "action": "scaffold",
            "file": "wallet-confs/new--v1.0.conf",
            "key": "*",
            "old": None,
            "new": "generated for NEW v1.0.0",
            "reason": "t",
            "coin": "NEW",
            "ver_id": "new--v1.0",
            "applied": False,
            "contents": "rpcuser=x\n",
        },
        {
            "action": "scaffold",
            "file": "xbridge-confs/new--v1.0.conf",
            "key": "*",
            "old": None,
            "new": "generated for NEW v1.0.0",
            "reason": "t",
            "coin": "NEW",
            "ver_id": "new--v1.0",
            "applied": False,
            "contents": "Port=1\n",
        },
        {
            "action": "scaffold",
            "file": "manifest-latest.json",
            "key": "NEW",
            "old": None,
            "new": "new--v1.0",
            "reason": "t",
            "coin": "NEW",
            "ver_id": "new--v1.0",
            "applied": False,
            "snippet": snippet,
        },
    ]
    out = apply_entries(entries, tmp_path)
    assert all(e["applied"] for e in out)
    assert (tmp_path / "wallet-confs" / "new--v1.0.conf").read_text() == "rpcuser=x\n"
    tickers = [e["ticker"] for e in json.loads((tmp_path / "manifest-latest.json").read_text())]
    assert tickers == ["AAA", "NEW"]


def _delist_tree(tmp_path):
    (tmp_path / "wallet-confs").mkdir(exist_ok=True)
    (tmp_path / "xbridge-confs").mkdir(exist_ok=True)
    (tmp_path / "autobuild" / "configs").mkdir(parents=True, exist_ok=True)
    (tmp_path / "wallet-confs" / "aaa.conf").write_text("rpcuser=x\n")
    (tmp_path / "xbridge-confs" / "aaa.conf").write_text("Port=1\n")
    (tmp_path / "wallet-confs" / "bbb.conf").write_text("rpcuser=y\n")
    (tmp_path / "autobuild" / "configs" / "aaa.base.j2").write_text("template\n")
    (tmp_path / "manifest-latest.json").write_text(
        json.dumps(
            [
                {
                    "ticker": "AAA",
                    "ver_id": "aaa--v1.0",
                    "versions": ["v1.0.0"],
                    "wallet_conf": "aaa.conf",
                    "xbridge_conf": "aaa.conf",
                },
                {
                    "ticker": "BBB",
                    "ver_id": "bbb--v2.0",
                    "versions": ["v2.0.0"],
                    "wallet_conf": "bbb.conf",
                    "xbridge_conf": "bbb.conf",
                },
            ]
        )
    )
    return tmp_path


def test_delist_plan_enumerates_coin_files(tmp_path):
    """P5: delist names the manifest entry plus every coin file."""
    from audit_manifest.fixes import plan_delist_entries
    from audit_manifest.model import ManifestCoin

    _delist_tree(tmp_path)
    coin = ManifestCoin(
        ticker="AAA", ver_id="aaa--v1.0", versions=["v1.0.0"], wallet_conf="aaa.conf", xbridge_conf="aaa.conf"
    )
    entries, note = plan_delist_entries(coin, tmp_path)
    assert [e["file"] for e in entries] == [
        "manifest-latest.json",
        "wallet-confs/aaa.conf",
        "xbridge-confs/aaa.conf",
        "autobuild/configs/aaa.base.j2",
    ]
    assert all(e["action"] == "delist" and e["applied"] is False for e in entries)
    assert note is None


def test_delist_plan_names_missing_files(tmp_path):
    """P5: absent files are noted omissions, never errors."""
    from audit_manifest.fixes import plan_delist_entries
    from audit_manifest.model import ManifestCoin

    _delist_tree(tmp_path)
    (tmp_path / "autobuild" / "configs" / "aaa.base.j2").unlink()
    coin = ManifestCoin(
        ticker="AAA", ver_id="aaa--v1.0", versions=["v1.0.0"], wallet_conf="aaa.conf", xbridge_conf="aaa.conf"
    )
    entries, note = plan_delist_entries(coin, tmp_path)
    assert len(entries) == 3
    assert note is not None and "aaa.base.j2" in note


def test_delist_apply_removes_exactly_listed_paths(tmp_path):
    """P5: delist deletes the coin and leaves siblings alone."""
    from audit_manifest.fixes import plan_delist_entries
    from audit_manifest.model import ManifestCoin

    _delist_tree(tmp_path)
    coin = ManifestCoin(
        ticker="AAA", ver_id="aaa--v1.0", versions=["v1.0.0"], wallet_conf="aaa.conf", xbridge_conf="aaa.conf"
    )
    entries, _ = plan_delist_entries(coin, tmp_path)
    out = apply_entries(entries, tmp_path)
    assert all(e["applied"] for e in out)
    assert [e["ticker"] for e in json.loads((tmp_path / "manifest-latest.json").read_text())] == ["BBB"]
    assert not (tmp_path / "wallet-confs" / "aaa.conf").exists()
    assert not (tmp_path / "autobuild" / "configs" / "aaa.base.j2").exists()
    assert (tmp_path / "wallet-confs" / "bbb.conf").is_file()


def test_applier_refuses_colliding_port(tmp_path):
    """Port writes never introduce a fleet collision."""
    (tmp_path / "manifest-latest.json").write_text(
        json.dumps(
            [
                {
                    "ticker": "AAA",
                    "ver_id": "aaa--v1.0",
                    "versions": ["v1.0.0"],
                    "wallet_conf": "aaa.conf",
                    "xbridge_conf": "aaa.conf",
                },
                {
                    "ticker": "BBB",
                    "ver_id": "bbb--v2.0",
                    "versions": ["v2.0.0"],
                    "wallet_conf": "bbb.conf",
                    "xbridge_conf": "bbb.conf",
                },
            ]
        )
    )
    (tmp_path / "wallet-confs").mkdir()
    (tmp_path / "xbridge-confs").mkdir()
    (tmp_path / "wallet-confs" / "aaa.conf").write_text("rpcuser=x\nrpcport=1000\n")
    (tmp_path / "wallet-confs" / "bbb.conf").write_text("rpcuser=y\nrpcport=8888\n")
    (tmp_path / "xbridge-confs" / "aaa.conf").write_text("Port=1\n")
    (tmp_path / "xbridge-confs" / "bbb.conf").write_text("Port=1\n")
    port_entry = {
        "action": "port",
        "file": "wallet-confs/aaa.conf",
        "key": "rpcport",
        "old": "1000",
        "new": "8888",
        "reason": "t",
        "coin": "AAA",
        "ver_id": "aaa--v1.0",
        "applied": False,
    }
    other = {
        "action": "txindex",
        "file": "wallet-confs/aaa.conf",
        "key": "txindex",
        "old": None,
        "new": "1",
        "reason": "t",
        "coin": "AAA",
        "ver_id": "aaa--v1.0",
        "applied": False,
    }
    out = apply_entries([port_entry, other], tmp_path)
    assert out[0]["applied"] is False
    assert "collides with BBB" in str(out[0].get("error", ""))
    assert out[1]["applied"] is True
    assert "rpcport=8888" not in (tmp_path / "wallet-confs" / "aaa.conf").read_text()


def test_applier_port_guard_ignores_test_sections(tmp_path):
    """The guard matches the detector: [test] ports are not collisions."""
    (tmp_path / "manifest-latest.json").write_text(
        json.dumps(
            [
                {
                    "ticker": "AAA",
                    "ver_id": "aaa--v1.0",
                    "versions": ["v1.0.0"],
                    "wallet_conf": "aaa.conf",
                    "xbridge_conf": "aaa.conf",
                },
                {
                    "ticker": "BBB",
                    "ver_id": "bbb--v2.0",
                    "versions": ["v2.0.0"],
                    "wallet_conf": "bbb.conf",
                    "xbridge_conf": "bbb.conf",
                },
            ]
        )
    )
    (tmp_path / "wallet-confs").mkdir()
    (tmp_path / "xbridge-confs").mkdir()
    (tmp_path / "wallet-confs" / "aaa.conf").write_text("rpcuser=x\nrpcport=1000\n")
    (tmp_path / "wallet-confs" / "bbb.conf").write_text("rpcuser=y\n[test]\nrpcport=8888\n")
    (tmp_path / "xbridge-confs" / "aaa.conf").write_text("Port=1\n")
    (tmp_path / "xbridge-confs" / "bbb.conf").write_text("Port=1\n")
    port_entry = {
        "action": "port",
        "file": "wallet-confs/aaa.conf",
        "key": "rpcport",
        "old": "1000",
        "new": "8888",
        "reason": "t",
        "coin": "AAA",
        "ver_id": "aaa--v1.0",
        "applied": False,
    }
    out = apply_entries([port_entry], tmp_path)
    assert out[0]["applied"] is True


def test_scaffold_apply_refuses_taken_ports(tmp_path):
    """Staged coins never land on occupied ports."""
    (tmp_path / "manifest-latest.json").write_text(
        json.dumps(
            [
                {
                    "ticker": "AAA",
                    "ver_id": "aaa--v1.0",
                    "versions": ["v1.0.0"],
                    "wallet_conf": "aaa.conf",
                    "xbridge_conf": "aaa.conf",
                }
            ]
        )
    )
    (tmp_path / "wallet-confs").mkdir()
    (tmp_path / "xbridge-confs").mkdir()
    (tmp_path / "wallet-confs" / "aaa.conf").write_text("rpcuser=x\nport=7777\n")
    (tmp_path / "xbridge-confs" / "aaa.conf").write_text("Port=7778\n")
    snippet = {
        "ticker": "NEW",
        "ver_id": "new--v1.0",
        "versions": ["v1.0.0"],
        "wallet_conf": "new--v1.0.conf",
        "xbridge_conf": "new--v1.0.conf",
    }
    entries = [
        {
            "action": "scaffold",
            "file": "wallet-confs/new--v1.0.conf",
            "key": "*",
            "old": None,
            "new": "generated",
            "reason": "t",
            "coin": "NEW",
            "ver_id": "new--v1.0",
            "applied": False,
            "contents": "rpcuser=z\nport=7777\nrpcport=7778\n",
        },
        {
            "action": "scaffold",
            "file": "manifest-latest.json",
            "key": "NEW",
            "old": None,
            "new": "new--v1.0",
            "reason": "t",
            "coin": "NEW",
            "ver_id": "new--v1.0",
            "applied": False,
            "snippet": snippet,
        },
    ]
    out = apply_entries(entries, tmp_path)
    assert all(e["applied"] is False for e in out)
    assert not (tmp_path / "wallet-confs" / "new--v1.0.conf").exists()
    assert [e["ticker"] for e in json.loads((tmp_path / "manifest-latest.json").read_text())] == ["AAA"]


def test_apply_refuses_absolute_and_parent_paths(tmp_path):
    """Reviewed entries cannot escape the repo root."""
    (tmp_path / "manifest-latest.json").write_text(
        json.dumps(
            [
                {
                    "ticker": "AAA",
                    "ver_id": "aaa--v1.0",
                    "versions": ["v1.0.0"],
                    "wallet_conf": "aaa.conf",
                    "xbridge_conf": "aaa.conf",
                }
            ]
        )
    )
    (tmp_path / "wallet-confs").mkdir()
    (tmp_path / "xbridge-confs").mkdir()
    (tmp_path / "wallet-confs" / "aaa.conf").write_text("rpcuser=x\n")
    evil = tmp_path.parent / "evil.json"
    entries = [
        {
            "action": "versions",
            "file": "/etc/manifest-latest.json",
            "key": "AAA.versions",
            "old": "v1.0.0",
            "new": "v1.0.0, v1.1.0",
            "reason": "t",
            "coin": "AAA",
            "applied": False,
        },
        {
            "action": "txindex",
            "file": "../../evil.json",
            "key": "txindex",
            "old": None,
            "new": "1",
            "reason": "t",
            "coin": "AAA",
            "applied": False,
        },
        {
            "action": "versions",
            "file": "wallet-confs/aaa.conf",
            "key": "*",
            "old": None,
            "new": "copy of ../../evil2.json",
            "reason": "t",
            "coin": "AAA",
            "applied": False,
        },
    ]
    out = apply_entries(entries, tmp_path)
    assert all(e["applied"] is False for e in out)
    assert not evil.exists()
    assert (tmp_path / "wallet-confs" / "aaa.conf").read_text() == "rpcuser=x\n"


def test_delist_dry_run_exits_zero(tmp_path):
    """P5: a delist preview is success, not a failure."""
    from audit_manifest import cli

    (tmp_path / "manifest-latest.json").write_text(
        json.dumps(
            [
                {
                    "ticker": "AAA",
                    "ver_id": "aaa--v1.0",
                    "versions": ["v1.0.0"],
                    "wallet_conf": "aaa.conf",
                    "xbridge_conf": "aaa.conf",
                }
            ]
        )
    )
    (tmp_path / "wallet-confs").mkdir()
    (tmp_path / "xbridge-confs").mkdir()
    (tmp_path / "wallet-confs" / "aaa.conf").write_text("rpcuser=x\n")
    rc = cli.main(["--manifest", str(tmp_path / "manifest-latest.json"), "--delist", "--ticker", "AAA", "--dry-run"])
    assert rc == 0
    assert (tmp_path / "wallet-confs" / "aaa.conf").is_file()


def test_delist_writes_the_named_manifest_and_nothing_else(tmp_path):
    """--manifest points the whole verb at one file; the sibling default is not touched.

    A candidate fleet file next to the production manifest must receive
    the splice itself: planning, applying, and the per-entry old-value
    verification all read the same file the CLI was pointed at.
    """
    from audit_manifest import cli

    (tmp_path / "wallet-confs").mkdir()
    (tmp_path / "xbridge-confs").mkdir()
    (tmp_path / "wallet-confs" / "aaa.conf").write_text("rpcuser=x\n")
    (tmp_path / "xbridge-confs" / "aaa.conf").write_text("Port=1\n")
    (tmp_path / "wallet-confs" / "bbb.conf").write_text("rpcuser=y\n")
    coin = {"ver_id": "aaa--v1.0", "versions": ["v1.0.0"], "wallet_conf": "aaa.conf", "xbridge_conf": "aaa.conf"}
    candidate = tmp_path / "manifest-candidate.json"
    candidate.write_text(
        json.dumps(
            [
                {"ticker": "AAA", **coin},
                {
                    "ticker": "BBB",
                    "ver_id": "bbb--v2.0",
                    "versions": ["v2.0.0"],
                    "wallet_conf": "bbb.conf",
                    "xbridge_conf": "bbb.conf",
                },
            ]
        )
    )
    # Same AAA ticker in the production file: a splice aimed at the wrong
    # manifest would still "succeed", silently editing the wrong fleet.
    (tmp_path / "manifest-latest.json").write_text(
        json.dumps(
            [
                {
                    "ticker": "AAA",
                    "ver_id": "aaa--v1.0",
                    "versions": ["v1.0.0"],
                    "wallet_conf": "aaa.conf",
                    "xbridge_conf": "aaa.conf",
                },
                {
                    "ticker": "ZZZ",
                    "ver_id": "zzz--v9.0",
                    "versions": ["v9.0.0"],
                    "wallet_conf": "zzz.conf",
                    "xbridge_conf": "zzz.conf",
                },
            ]
        )
    )

    rc = cli.main(["--manifest", str(candidate), "--delist", "--ticker", "AAA"])
    assert rc == 0
    assert [e["ticker"] for e in json.loads(candidate.read_text())] == ["BBB"]
    assert [e["ticker"] for e in json.loads((tmp_path / "manifest-latest.json").read_text())] == ["AAA", "ZZZ"]
    assert not (tmp_path / "wallet-confs" / "aaa.conf").exists()


def test_apply_plan_file_preserves_report_shape(tmp_path):
    """Pointing at a full report keeps its keys, not just the plan."""
    from audit_manifest.apply_plan import apply_plan_file
    from audit_manifest.probe import SystemCommandRunner

    (tmp_path / "manifest-latest.json").write_text(json.dumps([]))
    payload = {"schema_version": 1, "plan": [], "findings": [], "meta": {"verb": "plan-fix"}, "repos": {"u": {}}}
    path = tmp_path / "plan.json"
    path.write_text(json.dumps(payload))
    rc, _ = apply_plan_file(path, tmp_path, SystemCommandRunner())
    assert rc == 0
    kept = json.loads(path.read_text())
    assert kept["meta"] == {"verb": "plan-fix"}
    assert kept["repos"] == {"u": {}}


def test_apply_plan_file_counts_dropped_rows(tmp_path):
    """Unreadable rows refuse loudly instead of vanishing."""
    from audit_manifest.apply_plan import apply_plan_file
    from audit_manifest.probe import SystemCommandRunner

    (tmp_path / "manifest-latest.json").write_text(json.dumps([]))
    path = tmp_path / "plan.json"
    path.write_text(json.dumps({"schema_version": 1, "plan": ["junk", 42], "findings": []}))
    rc, out = apply_plan_file(path, tmp_path, SystemCommandRunner())
    assert rc == 1
    assert out == []


def test_conf_edits_stay_in_conf_dirs(tmp_path):
    """A reviewed entry cannot redirect a conf write elsewhere."""
    (tmp_path / "manifest-latest.json").write_text(json.dumps([]))
    (tmp_path / "wallet-confs").mkdir()
    entry = {
        "action": "txindex",
        "file": "manifest-latest.json",
        "key": "txindex",
        "old": None,
        "new": "1",
        "reason": "t",
        "coin": "AAA",
        "applied": False,
    }
    out = apply_entries([entry], tmp_path)
    assert out[0]["applied"] is False
    assert json.loads((tmp_path / "manifest-latest.json").read_text()) == []


def test_delist_deletes_only_coin_files(tmp_path):
    """Delist entries cannot reach outside their own file classes."""
    (tmp_path / "manifest-latest.json").write_text(
        json.dumps(
            [
                {
                    "ticker": "AAA",
                    "ver_id": "aaa--v1.0",
                    "versions": ["v1.0.0"],
                    "wallet_conf": "aaa.conf",
                    "xbridge_conf": "aaa.conf",
                }
            ]
        )
    )
    (tmp_path / "README.md").write_text("docs\n")
    entry = {
        "action": "delist",
        "file": "README.md",
        "key": "*",
        "old": None,
        "new": None,
        "reason": "t",
        "coin": "AAA",
        "applied": False,
    }
    out = apply_entries([entry], tmp_path)
    assert out[0]["applied"] is False
    assert (tmp_path / "README.md").is_file()


def test_fleet_holders_strip_inline_comments(tmp_path):
    """Holders match the detector: inline comments are not the port."""
    from audit_manifest.apply_plan import _fleet_port_holders

    (tmp_path / "manifest-latest.json").write_text(
        json.dumps(
            [
                {
                    "ticker": "AAA",
                    "ver_id": "aaa--v1.0",
                    "versions": ["v1.0.0"],
                    "wallet_conf": "aaa.conf",
                    "xbridge_conf": "aaa.conf",
                }
            ]
        )
    )
    (tmp_path / "wallet-confs").mkdir()
    (tmp_path / "xbridge-confs").mkdir()
    (tmp_path / "wallet-confs" / "aaa.conf").write_text("port=8333 # comment\nrpcport=8332\n")
    (tmp_path / "xbridge-confs" / "aaa.conf").write_text("Port=8332\n")
    holders = _fleet_port_holders(tmp_path)
    assert holders.get(("p2p", "8333")) == "AAA"


def test_deprecatedrpc_removal_preserves_unrelated_comments(root):
    """Removal deletes flag lines only, never comment lines."""
    coin = make_coin()
    (root / "wallet-confs" / "aaa--v1.0.conf").write_text(
        "rpcuser=x\n# Enable deprecated calls\ndeprecatedrpc=wallet\n", encoding="utf-8"
    )
    entries, _ = ConfigAutoFixer.plan_remove_deprecatedrpc(root, coin)
    out = apply_entries(entries, root)
    assert out[0]["applied"] is True
    assert "# Enable deprecated calls" in (root / "wallet-confs" / "aaa--v1.0.conf").read_text()


def test_scaffold_refuses_degenerate_port_pair(tmp_path):
    """A staged coin with port==rpcport cannot bind twice."""
    from audit_manifest.scaffold import scaffold_plan_entries

    snippet = {
        "ticker": "NEW",
        "ver_id": "new--v1.0",
        "versions": ["v1.0.0"],
        "wallet_conf": "new--v1.0.conf",
        "xbridge_conf": "new--v1.0.conf",
    }
    (tmp_path / "manifest-latest.json").write_text(json.dumps([]))
    (tmp_path / "wallet-confs").mkdir()
    (tmp_path / "xbridge-confs").mkdir()
    entries = scaffold_plan_entries(
        "NEW",
        "new--v1.0",
        "v1.0.0",
        "new--v1.0.conf",
        "new--v1.0.conf",
        "port=5000\nrpcport=5000\n",
        "Port=5000\n",
        snippet,
        "manifest-latest.json",
    )
    out = apply_entries(entries, tmp_path)
    assert all(e["applied"] is False for e in out)
    assert not (tmp_path / "wallet-confs" / "new--v1.0.conf").exists()


def test_norm_strips_semicolon_comments():
    """`;` trails are comments on port lines, like `#` and `//`."""
    from audit_manifest.util import norm_port_value

    assert norm_port_value("8333 ; comment") == "8333"


def test_scaffold_dict_manifest_refuses_everything(tmp_path):
    """A non-array manifest blocks the whole triple; nothing lands."""
    from audit_manifest.scaffold import scaffold_plan_entries

    snippet = {
        "ticker": "NEW",
        "ver_id": "new--v1.0",
        "versions": ["v1.0.0"],
        "wallet_conf": "new--v1.0.conf",
        "xbridge_conf": "new--v1.0.conf",
    }
    (tmp_path / "manifest-latest.json").write_text(json.dumps({"oops": True}))
    (tmp_path / "wallet-confs").mkdir()
    (tmp_path / "xbridge-confs").mkdir()
    entries = scaffold_plan_entries(
        "NEW",
        "new--v1.0",
        "v1.0.0",
        "new--v1.0.conf",
        "new--v1.0.conf",
        "port=6000\nrpcport=6001\n",
        "Port=6001\n",
        snippet,
        "manifest-latest.json",
    )
    out = apply_entries(entries, tmp_path)
    assert all(e["applied"] is False for e in out)
    assert not (tmp_path / "wallet-confs" / "new--v1.0.conf").exists()
    assert not (tmp_path / "xbridge-confs" / "new--v1.0.conf").exists()


def test_partial_scaffold_rolls_back_manifest_row(tmp_path):
    """A refused conf reverts the staged manifest row too."""
    from audit_manifest.scaffold import scaffold_plan_entries

    snippet = {
        "ticker": "NEW",
        "ver_id": "new--v1.0",
        "versions": ["v1.0.0"],
        "wallet_conf": "new--v1.0.conf",
        "xbridge_conf": "new--v1.0.conf",
    }
    (tmp_path / "manifest-latest.json").write_text(json.dumps([]))
    (tmp_path / "wallet-confs").mkdir()
    (tmp_path / "xbridge-confs").mkdir()
    entries = scaffold_plan_entries(
        "NEW",
        "new--v1.0",
        "v1.0.0",
        "new--v1.0.conf",
        "new--v1.0.conf",
        "port=6000\nrpcport=6001\n",
        "Port=6001\n",
        snippet,
        "manifest-latest.json",
    )
    del entries[0]["contents"]
    out = apply_entries(entries, tmp_path)
    assert all(e["applied"] is False for e in out)
    assert json.loads((tmp_path / "manifest-latest.json").read_text()) == []
    assert not (tmp_path / "xbridge-confs" / "new--v1.0.conf").exists()


def test_conf_write_refuses_symlinked_conf_dir(tmp_path):
    """A conf dir symlinked out of the repo must not receive writes."""
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "aaa.conf").write_text("rpcuser=x\n", encoding="utf-8")
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "manifest-latest.json").write_text(
        json.dumps(
            [
                {
                    "ticker": "AAA",
                    "ver_id": "aaa--v1.0",
                    "versions": ["v1.0.0"],
                    "wallet_conf": "aaa.conf",
                    "xbridge_conf": "aaa.conf",
                }
            ]
        )
    )
    (repo / "wallet-confs").symlink_to(outside, target_is_directory=True)
    (repo / "xbridge-confs").mkdir()
    entries = [
        {
            "action": "txindex",
            "file": "wallet-confs/aaa.conf",
            "key": "txindex",
            "old": None,
            "new": "1",
            "reason": "t",
            "coin": "AAA",
            "applied": False,
        }
    ]
    out = apply_entries(entries, repo)
    assert out[0]["applied"] is False
    assert (outside / "aaa.conf").read_text(encoding="utf-8") == "rpcuser=x\n"


def test_conf_edit_refuses_nested_conf_dir(tmp_path):
    """Conf edits stay at the top-level conf dirs, like delist paths."""
    (tmp_path / "manifest-latest.json").write_text(
        json.dumps(
            [
                {
                    "ticker": "AAA",
                    "ver_id": "aaa--v1.0",
                    "versions": ["v1.0.0"],
                    "wallet_conf": "aaa.conf",
                    "xbridge_conf": "aaa.conf",
                }
            ]
        )
    )
    nested = tmp_path / "sub" / "wallet-confs"
    nested.mkdir(parents=True)
    target = nested / "aaa.conf"
    target.write_text("rpcuser=x\n", encoding="utf-8")
    entries = [
        {
            "action": "txindex",
            "file": "sub/wallet-confs/aaa.conf",
            "key": "txindex",
            "old": None,
            "new": "1",
            "reason": "t",
            "coin": "AAA",
            "applied": False,
        }
    ]
    out = apply_entries(entries, tmp_path)
    assert out[0]["applied"] is False
    assert target.read_text(encoding="utf-8") == "rpcuser=x\n"


def test_apply_entries_can_skip_base_j2_regeneration(tmp_path, monkeypatch):
    """A batch caller that regenerates once itself must be able to opt out."""
    import audit_manifest.apply_plan as ap

    calls = []
    monkeypatch.setattr(ap, "regenerate_base_j2", lambda root, tickers, runner=None: calls.append(tickers))
    (tmp_path / "manifest-latest.json").write_text(json.dumps([]))
    (tmp_path / "wallet-confs").mkdir()
    entry = {
        "action": "txindex",
        "file": "wallet-confs/a.conf",
        "key": "txindex",
        "old": None,
        "new": "1",
        "reason": "t",
        "coin": "AAA",
        "applied": False,
    }
    (tmp_path / "wallet-confs" / "a.conf").write_text("rpcuser=x\n")
    out = apply_entries([entry], tmp_path, object(), regenerate=False)
    assert out[0]["applied"] is True
    assert calls == [], "regenerate=False must not spawn the j2 generator"


def test_regenerate_for_uses_applied_entries_only(tmp_path, monkeypatch):
    """The one-shot helper counts applied, j2-relevant actions — nothing else."""
    import audit_manifest.apply_plan as ap

    calls = []
    monkeypatch.setattr(ap, "regenerate_base_j2", lambda root, tickers, runner=None: calls.append(tickers))
    entries = [
        {"action": "txindex", "coin": "BBB", "applied": True},
        {"action": "fees", "coin": "AAA", "applied": True},
        {"action": "port", "coin": "AAA", "applied": False},
        {"action": "scaffold", "coin": "NEW", "applied": True},
        "junk",
    ]
    ap.regenerate_for(entries, tmp_path, object())
    assert calls == [["AAA", "BBB"]]


def test_writes_reach_disk_through_temp_and_replace(tmp_path, monkeypatch):
    """An interrupted write must never truncate a reviewed conf."""
    import os as _os

    import audit_manifest.apply_plan as ap

    replaced = []
    real_replace = _os.replace

    def spy(src, dst):
        replaced.append((str(src), str(dst)))
        return real_replace(src, dst)

    monkeypatch.setattr(ap.os, "replace", spy)
    (tmp_path / "manifest-latest.json").write_text(json.dumps([]))
    (tmp_path / "wallet-confs").mkdir()
    (tmp_path / "wallet-confs" / "a.conf").write_text("rpcuser=x\n")
    entry = {
        "action": "txindex",
        "file": "wallet-confs/a.conf",
        "key": "txindex",
        "old": None,
        "new": "1",
        "reason": "t",
        "coin": "AAA",
        "applied": False,
    }
    out = apply_entries([entry], tmp_path)
    assert out[0]["applied"] is True
    assert replaced, "the conf must land via a same-dir temp file + os.replace"
    assert replaced[0][0].endswith(".tmp")
    assert replaced[0][1].endswith("a.conf")
    assert not (tmp_path / "wallet-confs" / "a.conf.tmp").exists()


def test_txindex_plan_ignores_comment_mentions(tmp_path):
    """R9 proof-first: a comment mentioning txindex must not suppress the fix.

    plan_missing_txindex tested `"txindex" not in txt.lower()` — a wallet
    conf carrying `# txindex is managed elsewhere` looked like it already
    had the key and the fix was never planned. The applier checks key
    presence properly (_key_present); the planner must agree.

    Must FAIL before the fix (no entry planned for the comment-only conf)
    and PASS after.
    """
    (tmp_path / "wallet-confs").mkdir()
    (tmp_path / "xbridge-confs").mkdir()
    wconf = tmp_path / "wallet-confs" / "aaa--v1.0.conf"
    wconf.write_text("rpcuser=x\n# txindex is managed elsewhere\n", encoding="utf-8")
    entries, _note = ConfigAutoFixer.plan_missing_txindex(tmp_path, make_coin())
    assert entries, "a comment mentioning txindex is not a txindex= key"
    assert entries[0]["key"] == "txindex" and entries[0]["new"] == "1"
    # a real key still suppresses the plan
    wconf.write_text("rpcuser=x\ntxindex=0\n", encoding="utf-8")
    entries2, _ = ConfigAutoFixer.plan_missing_txindex(tmp_path, make_coin())
    assert entries2 == [], "txindex=0 is present: no plan needed"


def test_fix_dispatch_uses_the_structured_fixable_field(tmp_path):
    """R9 proof-first: fixers must key off `fixable`, not message substrings.

    The dispatch used to trigger on four substrings of other modules'
    user-facing messages ("ignored by blocknet loader", "overpay", …).
    Rewording any of those messages silently disabled the corresponding
    auto-fix with no test failing. The checker now attaches a structured
    `fixable` kind to the finding; the dispatch reads only that.

    Must FAIL before the fix (a fixable finding with a reworded message
    plans nothing) and PASS after.
    """
    import argparse

    from audit_manifest.fixes import apply_conf_fixes

    (tmp_path / "wallet-confs").mkdir()
    (tmp_path / "xbridge-confs").mkdir()
    (tmp_path / "wallet-confs" / "aaa--v1.0.conf").write_text("rpcuser=x\n", encoding="utf-8")
    (tmp_path / "xbridge-confs" / "aaa--v1.0.conf").write_text("MinTxFee=0.1\nDustAmount=100\n", encoding="utf-8")
    coin = make_coin()
    args = argparse.Namespace(write_config=True, fee_write=False, dry_run=True)
    param_results = {
        coin.ver_id: {
            "checks": [
                {
                    "id": "DUST",
                    "status": "WARN",
                    "fixable": "dust",
                    "detail": "totally reworded message that no longer contains the old trigger",
                },
            ]
        },
    }
    plan = apply_conf_fixes(args, [coin], param_results, tmp_path, None)
    assert plan and plan[0]["coin"] == "AAA", "fixable=dust must dispatch to the dust fixer"
    assert plan[0]["key"] == "DustAmount"
    # and the converse: no fixable, no dispatch, whatever the message says
    param_results[coin.ver_id]["checks"][0].pop("fixable")
    param_results[coin.ver_id]["checks"][0]["detail"] = "ignored by blocknet loader"
    plan2 = apply_conf_fixes(args, [coin], param_results, tmp_path, None)
    assert plan2 == [], "message text alone must never dispatch a fix"
