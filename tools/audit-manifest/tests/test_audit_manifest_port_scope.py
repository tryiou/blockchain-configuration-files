#!/usr/bin/env python3
"""
A --ticker-scoped port fix must still avoid every coin's ports.

Occupancy is a fleet fact: a narrowed run handed only the filtered
manifest could allocate a port an unticked coin holds. The detector
drives the real CLI (AAA+BBB collide; unticked CCC holds 9433/9432),
so it pins the wiring, not just the helper.
"""

import io
import json
from contextlib import redirect_stdout
from pathlib import Path

import audit_manifest as audit
import audit_manifest.checkout as checkout_mod


def _fleet_repo(tmp_path: Path) -> Path:
    """AAA+BBB collide on 9333/9332; unticked CCC holds 9433/9432.

    No versions on purpose: a tag would send param-check to the source
    checkout (a real ``git clone``), and this detector only needs the
    conf-file collisions — zero network, zero writes outside tmp_path.
    """
    (tmp_path / "wallet-confs").mkdir()
    (tmp_path / "xbridge-confs").mkdir()
    (tmp_path / "autobuild" / "configs").mkdir(parents=True)
    manifest = [
        {
            "ticker": ticker,
            "ver_id": f"{ticker.lower()}--v1",
            "versions": [],
            "wallet_conf": f"{ticker.lower()}.conf",
            "xbridge_conf": f"{ticker.lower()}.conf",
            "repo_url": f"https://example.invalid/{ticker.lower()}",
        }
        for ticker in ("AAA", "BBB", "CCC")
    ]
    manifest_path = tmp_path / "manifest-latest.json"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    for name, port, rpc in (
        ("aaa", 9333, 9332),
        ("bbb", 9333, 9332),
        ("ccc", 9433, 9432),
    ):
        (tmp_path / "wallet-confs" / f"{name}.conf").write_text(f"port={port}\nrpcport={rpc}\n", encoding="utf-8")
        (tmp_path / "xbridge-confs" / f"{name}.conf").write_text(f"Port={rpc}\n", encoding="utf-8")
    return manifest_path


def test_a_scoped_port_fix_never_allocates_an_unticked_coins_ports(tmp_path: Path, monkeypatch):
    manifest_path = _fleet_repo(tmp_path)
    report = tmp_path / "scoped-report.json"

    def _no_checkout(*args, **kwargs):
        raise AssertionError("a versions-less fixture must never checkout")

    monkeypatch.setattr(checkout_mod.SourceCheckoutManager, "resolve_source", _no_checkout)
    buf = io.StringIO()
    with redirect_stdout(buf):
        audit.main(
            [
                "--manifest",
                str(manifest_path),
                "--local-only",
                "--fix-ports",
                "--dry-run",
                "--ticker",
                "AAA,BBB",
                "--report",
                str(report),
            ]
        )
    payload = json.loads(report.read_text(encoding="utf-8"))
    planned = [entry for entry in payload.get("plan") or [] if entry.get("key") in ("port", "rpcport")]
    assert planned, "AAA and BBB collide on 9333/9332, so the scoped run must plan the loser's reassignment"
    held_by_unticked_ccc = {"9433", "9432"}
    for entry in planned:
        assert str(entry.get("new")) not in held_by_unticked_ccc, (
            f"{entry.get('coin')} {entry.get('key')} -> {entry.get('new')} "
            "is unticked CCC's port: port occupancy must be the fleet's, "
            "not the scope's"
        )


def test_crowded_out_loser_is_loud_never_silent(tmp_path, monkeypatch, caplog):
    """A loser with no free placement must warn, not vanish."""
    import argparse
    import logging
    from unittest import mock

    from audit_manifest.cli import load_manifest
    from audit_manifest.fixes import apply_port_fixes
    from audit_manifest.ports import PortCollisionManager

    manifest_path = _fleet_repo(tmp_path)
    manifest = load_manifest(manifest_path)
    args = argparse.Namespace(fix_ports=True, dry_run=True)
    with (
        mock.patch.object(PortCollisionManager, "find_free_pair", return_value=(None, None)),
        mock.patch.object(PortCollisionManager, "find_free_single", return_value=None),
        caplog.at_level(logging.WARNING),
    ):
        plan = apply_port_fixes(args, manifest, {}, tmp_path, None)
    assert plan == []
    assert any("crowded" in r.getMessage() or "exhaust" in r.getMessage() for r in caplog.records), (
        "an unplaceable loser must warn instead of silently skipping"
    )


def test_commented_loser_ports_still_plan_moves(tmp_path):
    """Detector/fixer agree on comments: a commented loser moves."""
    import argparse
    import json as _json

    from audit_manifest.cli import load_manifest
    from audit_manifest.fixes import apply_port_fixes

    (tmp_path / "wallet-confs").mkdir()
    (tmp_path / "xbridge-confs").mkdir()
    (tmp_path / "autobuild" / "configs").mkdir(parents=True)
    (tmp_path / "manifest-latest.json").write_text(
        _json.dumps(
            [
                {
                    "ticker": "AAA",
                    "ver_id": "aaa--v1",
                    "versions": [],
                    "wallet_conf": "aaa.conf",
                    "xbridge_conf": "aaa.conf",
                    "repo_url": "https://example.invalid/aaa",
                },
                {
                    "ticker": "BBB",
                    "ver_id": "bbb--v1",
                    "versions": [],
                    "wallet_conf": "bbb.conf",
                    "xbridge_conf": "bbb.conf",
                    "repo_url": "https://example.invalid/bbb",
                },
            ]
        )
    )
    (tmp_path / "wallet-confs" / "aaa.conf").write_text("port=9333 # keep\nrpcport=9332 # keep\n")
    (tmp_path / "xbridge-confs" / "aaa.conf").write_text("Port=9332\n")
    (tmp_path / "wallet-confs" / "bbb.conf").write_text("port=9333\nrpcport=9332\n")
    (tmp_path / "xbridge-confs" / "bbb.conf").write_text("Port=9332\n")
    manifest = load_manifest(tmp_path / "manifest-latest.json")
    args = argparse.Namespace(fix_ports=True, dry_run=True)
    plan = apply_port_fixes(args, manifest, {}, tmp_path, None)
    assert plan, "commented collision ports must plan the loser move, not skip"


def test_find_free_single_never_returns_the_port_it_moves_away_from():
    """A move back onto src is a no-op that leaves the collision standing."""
    from audit_manifest.ports import PortCollisionManager

    src = 50000
    crowded = set(range(50100, 65536))
    got = PortCollisionManager.find_free_single(src, crowded, crowded, exclude_self=src)
    assert got is not None
    assert got != src
    assert got not in crowded
