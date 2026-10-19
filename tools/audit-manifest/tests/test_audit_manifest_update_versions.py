#!/usr/bin/env python3
"""
Proof-first regression tests for --update-versions conf-name derivation
(review finding #2: new_xc was built from wc_prefix, so divergent
wallet/xbridge stems would mistarget the xbridge conf).

These must FAIL before the fix (build_update_version_names missing) and
PASS after the helper derives xc_prefix from old_xc.
"""

import audit_manifest as audit

build_names = audit.build_update_version_names


def test_identical_stems():
    ver_id, wc, xc = build_names(
        "DGB",
        "digibyte--v9.26.5",
        "digibyte--v9.26.5.conf",
        "digibyte--v9.26.5.conf",
        "v9.26.6",
    )
    assert ver_id == "digibyte--v9.26.6"
    assert wc == "digibyte--v9.26.6.conf"
    assert xc == "digibyte--v9.26.6.conf"


def test_divergent_stems_xbridge_keeps_own_prefix():
    # Old inline logic reused wc_prefix for new_xc -> "foo--v2.conf" (wrong).
    ver_id, wc, xc = build_names("HYPO", "hypo--v1", "foo--v1.conf", "bar--v1.conf", "v2")
    assert wc == "foo--v2.conf"
    assert xc == "bar--v2.conf", f"divergent xbridge stem mistargeted: {xc!r}"
    assert ver_id == "hypo--v2"


def test_lbc_special_case():
    ver_id, wc, xc = build_names("LBC", "lbcd--v0.22.120", "lbcd--v0.22.120.conf", "lbcd--v0.22.120.conf", "v0.22.121")
    assert (ver_id, wc, xc) == ("lbcd--v0.22.121", "lbcd--v0.22.121.conf", "lbcd--v0.22.121.conf")


def test_lbc_override_requires_exact_lbcd_stem():
    # Substring "lbcd" inside a longer stem must NOT trigger the lbcd override.
    ver_id, wc, xc = build_names("LBC", "mylbcd--v1", "mylbcd--v1.conf", "mylbcd--v1.conf", "v2")
    assert (ver_id, wc, xc) == ("mylbcd--v2", "mylbcd--v2.conf", "mylbcd--v2.conf")


def test_lbc_override_is_per_part():
    # Divergent xbridge stem under LBC ticker: wallet side takes lbcd
    # override, xbridge side keeps its own stem.
    _ver_id, wc, xc = build_names("LBC", "lbcd--v1", "lbcd--v1.conf", "other--v1.conf", "v2")
    assert wc == "lbcd--v2.conf"
    assert xc == "other--v2.conf", f"divergent xbridge stem must survive LBC override: {xc!r}"


def test_no_separator_falls_back_to_ticker():
    ver_id, wc, xc = build_names("DGB", "digibyte", "digibyte.conf", "digibyte.conf", "v9.26.6")
    assert ver_id == "dgb--v9.26.6"
    assert wc == "dgb--v9.26.6.conf"
    assert xc == "dgb--v9.26.6.conf"


def _firo_item():
    return {
        "ticker": "FIRO",
        "ver_id": "firo--v0.14.18.0",
        "versions": ["v0.14.18.0"],
        "wallet_conf": "firo--v0.14.18.0.conf",
        "xbridge_conf": "firo--v0.14.18.0.conf",
    }


def test_additive_bump_appends_and_keeps_confs():
    # Non-fork release: old version stays buildable, target appended,
    # ver_id + conf refs untouched (DOGE/BLOCK/SYS convention).
    item = _firo_item()
    changed = audit.apply_additive_bump(item, "v0.14.18.1")
    assert changed is True
    assert item["versions"] == ["v0.14.18.0", "v0.14.18.1"]
    assert item["ver_id"] == "firo--v0.14.18.0"
    assert item["wallet_conf"] == "firo--v0.14.18.0.conf"
    assert item["xbridge_conf"] == "firo--v0.14.18.0.conf"


def test_additive_bump_is_idempotent():
    item = _firo_item()
    assert audit.apply_additive_bump(item, "v0.14.18.1") is True
    assert audit.apply_additive_bump(item, "v0.14.18.1") is False
    assert item["versions"] == ["v0.14.18.0", "v0.14.18.1"]


def _probe_repos():
    return {
        "https://example.invalid/aaa": {
            "status": "ALIVE",
            "newer_same": ["v1.1.0"],
            "newer_alt": [],
            "remote_latest": "v1.1.0",
            "entries": [{"ticker": "AAA"}],
        }
    }


def test_versions_from_probe_slot_emits_bump_entries(tmp_path):
    """P2: version bumps derive from a probe report, never a live probe."""
    import argparse

    from audit_manifest.fixes import plan_version_bumps

    (tmp_path / "manifest-latest.json").write_text(
        __import__("json").dumps(
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
    args = argparse.Namespace(update_versions=True, replace_versions=False, dry_run=True)
    tickers, plan = plan_version_bumps(args, tmp_path / "manifest-latest.json", _probe_repos(), tmp_path)
    assert tickers == ["AAA"]
    assert plan[0]["key"] == "AAA.versions"
    assert plan[0]["new"] == "v1.0.0, v1.1.0"
    assert all(e["applied"] is False for e in plan)
    assert __import__("json").loads((tmp_path / "manifest-latest.json").read_text())[0]["versions"] == ["v1.0.0"]


def test_versions_from_unreadable_slot_notes_and_emits_none(tmp_path):
    """P2: a missing probe slot is a notice, never a guess."""
    from audit_manifest.fixes import read_probe_repos

    repos, note = read_probe_repos(tmp_path / "nope.json")
    assert repos == {}
    assert note is not None and "nope.json" in note


def test_hard_fork_repo_never_gets_bump_entry(tmp_path):
    """P2: mandatory-HF repos stay manual under --versions-from too."""
    import argparse

    from audit_manifest.fixes import plan_version_bumps

    (tmp_path / "manifest-latest.json").write_text(
        __import__("json").dumps(
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
    repos = _probe_repos()
    repos["https://example.invalid/aaa"]["changelog_mandatory"] = True
    args = argparse.Namespace(update_versions=True, replace_versions=False, dry_run=True)
    tickers, plan = plan_version_bumps(args, tmp_path / "manifest-latest.json", repos, tmp_path)
    assert tickers == [] and plan == []


def test_update_versions_applies_to_the_named_manifest(tmp_path):
    """--manifest points the whole update flow at one file.

    The additive bump must land in the manifest the CLI was pointed at,
    and the sibling default-named manifest must not be touched: the
    apply path threads the same file the planner named.
    """
    import json as _json

    from audit_manifest import cli

    (tmp_path / "wallet-confs").mkdir()
    (tmp_path / "xbridge-confs").mkdir()
    (tmp_path / "wallet-confs" / "aaa--v1.0.conf").write_text("rpcuser=x\n")
    (tmp_path / "xbridge-confs" / "aaa--v1.0.conf").write_text("Port=1\n")
    item = {
        "ticker": "AAA",
        "ver_id": "aaa--v1.0",
        "versions": ["v1.0.0"],
        "wallet_conf": "aaa--v1.0.conf",
        "xbridge_conf": "aaa--v1.0.conf",
    }
    candidate = tmp_path / "manifest-candidate.json"
    candidate.write_text(_json.dumps([dict(item)]))
    (tmp_path / "manifest-latest.json").write_text(_json.dumps([dict(item)]))
    probe = tmp_path / "probe.json"
    probe.write_text(_json.dumps({"repos": _probe_repos()}))

    rc = cli.main(
        [
            "--local-only",
            "--manifest",
            str(candidate),
            "--versions-from",
            str(probe),
            "--update-versions",
        ]
    )
    assert rc == 0
    assert _json.loads(candidate.read_text())[0]["versions"] == ["v1.0.0", "v1.1.0"]
    assert _json.loads((tmp_path / "manifest-latest.json").read_text())[0]["versions"] == ["v1.0.0"]


def test_update_versions_summary_reports_only_what_applied(tmp_path, capsys, monkeypatch):
    """A refused entry must not be claimed as bumped.

    The summary gates the follow-up lines (re-run --param-check, the
    superseded-confs-removed note), so it must come from what the applier
    actually wrote — not from what the planner intended.
    """
    import argparse

    from audit_manifest import fixes

    (tmp_path / "manifest-latest.json").write_text(
        __import__("json").dumps(
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
    # Every entry refused at apply time ("versions changed since planning"
    # is the real-world shape; the plan's flags are what the summary reads).
    monkeypatch.setattr(fixes, "apply_entries", lambda entries, *a, **k: entries)
    args = argparse.Namespace(update_versions=True, replace_versions=False, dry_run=False)
    fixes.apply_version_bumps(args, tmp_path / "manifest-latest.json", _probe_repos(), tmp_path, None)
    out = capsys.readouterr().out
    assert "bumped AAA to latest remote" not in out, out
    assert "refused AAA" in out, out


def test_replace_versions_summary_does_not_claim_a_refused_removal(tmp_path, capsys, monkeypatch):
    """A refused collapse must not be summarised as a bump or a completed rename.

    The conf copy carries the same coin as the manifest write, so an applied
    copy used to be enough to print "bumped AAA" even when the collapse that
    moves the manifest was refused. The summary must key on the manifest
    write, and it must not call the rename complete while the manifest still
    names the old conf.
    """
    import argparse

    from audit_manifest import fixes

    (tmp_path / "wallet-confs").mkdir()
    (tmp_path / "wallet-confs" / "aaa--v1.0.conf").write_text("x=1\n")
    (tmp_path / "manifest-latest.json").write_text(
        __import__("json").dumps(
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
    plan = [
        {
            "action": "versions",
            "file": "manifest-candidate.json",
            "key": "AAA",
            "old": "aaa--v1.0",
            "new": "aaa--v1.1",
            "reason": "t",
            "coin": "AAA",
            "ver_id": "aaa--v1.1",
            "target": "v1.1.0",
            "old_ver_id": "aaa--v1.0",
            "old_wallet_conf": "aaa--v1.0.conf",
            "old_xbridge_conf": "aaa--v1.0.conf",
            "applied": False,
        },
        {
            "action": "versions",
            "file": "wallet-confs/aaa--v1.1.conf",
            "key": "*",
            "old": None,
            "new": "copy of aaa--v1.0.conf",
            "reason": "t",
            "coin": "AAA",
            "ver_id": "aaa--v1.1",
            "applied": False,
        },
        {
            "action": "versions",
            "file": "wallet-confs/aaa--v1.0.conf",
            "key": "-",
            "old": "aaa--v1.0.conf",
            "new": None,
            "reason": "t",
            "coin": "AAA",
            "ver_id": "aaa--v1.1",
            "applied": False,
        },
    ]
    monkeypatch.setattr(fixes, "plan_version_bumps", lambda *a, **k: (["AAA"], plan))
    args = argparse.Namespace(update_versions=True, replace_versions=True, dry_run=False)
    fixes.apply_version_bumps(args, tmp_path / "manifest-latest.json", {}, tmp_path, None)
    out = capsys.readouterr().out
    assert "bumped AAA to latest remote" not in out, out
    assert "refused AAA: wallet-confs/aaa--v1.0.conf" in out, out
    assert "rename is complete" not in out, out
    assert (tmp_path / "wallet-confs" / "aaa--v1.0.conf").is_file()


def test_replace_versions_summary_reports_a_holder_refused_removal(tmp_path, capsys, monkeypatch):
    """A removal stopped by a second manifest row is reported, not glossed over.

    Here the collapse applies and the copy lands, so only the fleet-wide
    holder gate can stop the delete. The summary must still decline to call
    the rename complete, because the superseded conf is left on disk.
    """
    import argparse

    from audit_manifest import fixes

    (tmp_path / "wallet-confs").mkdir()
    (tmp_path / "wallet-confs" / "aaa--v1.0.conf").write_text("x=1\n")
    (tmp_path / "manifest-latest.json").write_text(
        __import__("json").dumps(
            [
                {
                    "ticker": "AAA",
                    "ver_id": "aaa--v1.0",
                    "versions": ["v1.0.0"],
                    "wallet_conf": "aaa--v1.0.conf",
                    "xbridge_conf": "aaa--v1.0.conf",
                },
                {
                    "ticker": "BBB",
                    "ver_id": "bbb--v1.0",
                    "versions": ["v1.0.0"],
                    "wallet_conf": "aaa--v1.0.conf",
                    "xbridge_conf": "bbb--v1.0.conf",
                },
            ]
        )
    )
    plan = [
        {
            "action": "versions",
            "file": "manifest-latest.json",
            "key": "AAA",
            "old": "aaa--v1.0",
            "new": "aaa--v1.1",
            "reason": "t",
            "coin": "AAA",
            "ver_id": "aaa--v1.1",
            "target": "v1.1.0",
            "old_ver_id": "aaa--v1.0",
            "old_wallet_conf": "aaa--v1.0.conf",
            "old_xbridge_conf": "aaa--v1.0.conf",
            "applied": False,
        },
        {
            "action": "versions",
            "file": "wallet-confs/aaa--v1.1.conf",
            "key": "*",
            "old": None,
            "new": "copy of aaa--v1.0.conf",
            "reason": "t",
            "coin": "AAA",
            "ver_id": "aaa--v1.1",
            "applied": False,
        },
        {
            "action": "versions",
            "file": "wallet-confs/aaa--v1.0.conf",
            "key": "-",
            "old": "aaa--v1.0.conf",
            "new": None,
            "reason": "t",
            "coin": "AAA",
            "ver_id": "aaa--v1.1",
            "applied": False,
        },
    ]
    monkeypatch.setattr(fixes, "plan_version_bumps", lambda *a, **k: (["AAA"], plan))
    args = argparse.Namespace(update_versions=True, replace_versions=True, dry_run=False)
    fixes.apply_version_bumps(args, tmp_path / "manifest-latest.json", {}, tmp_path, None)
    out = capsys.readouterr().out
    assert "copied" in out, out
    assert "refused AAA: wallet-confs/aaa--v1.0.conf" in out, out
    assert "still named by BBB" in out, out
    assert "rename is complete" not in out, out
    assert "superseded confs are still on disk" in out, out
    assert (tmp_path / "wallet-confs" / "aaa--v1.0.conf").is_file()


def test_replace_versions_summary_reports_a_completed_rename(tmp_path, capsys, monkeypatch):
    """A collapse that lands and drops its superseded confs says so.

    The mirror of the refusal cases: the manifest write applies and every
    planned removal applies, so the summary must claim the bump and the
    completed rename — pinning the positive side of both predicates.
    """
    import argparse

    from audit_manifest import fixes

    (tmp_path / "wallet-confs").mkdir()
    (tmp_path / "wallet-confs" / "aaa--v1.0.conf").write_text("x=1\n")
    (tmp_path / "manifest-latest.json").write_text(
        __import__("json").dumps(
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
    plan = [
        {
            "action": "versions",
            "file": "manifest-latest.json",
            "key": "AAA",
            "old": "aaa--v1.0",
            "new": "aaa--v1.1",
            "reason": "t",
            "coin": "AAA",
            "ver_id": "aaa--v1.1",
            "target": "v1.1.0",
            "old_ver_id": "aaa--v1.0",
            "old_wallet_conf": "aaa--v1.0.conf",
            "old_xbridge_conf": "aaa--v1.0.conf",
            "applied": False,
        },
        {
            "action": "versions",
            "file": "wallet-confs/aaa--v1.1.conf",
            "key": "*",
            "old": None,
            "new": "copy of aaa--v1.0.conf",
            "reason": "t",
            "coin": "AAA",
            "ver_id": "aaa--v1.1",
            "applied": False,
        },
        {
            "action": "versions",
            "file": "wallet-confs/aaa--v1.0.conf",
            "key": "-",
            "old": "aaa--v1.0.conf",
            "new": None,
            "reason": "t",
            "coin": "AAA",
            "ver_id": "aaa--v1.1",
            "applied": False,
        },
    ]
    monkeypatch.setattr(fixes, "plan_version_bumps", lambda *a, **k: (["AAA"], plan))
    args = argparse.Namespace(update_versions=True, replace_versions=True, dry_run=False)
    fixes.apply_version_bumps(args, tmp_path / "manifest-latest.json", {}, tmp_path, None)
    out = capsys.readouterr().out
    assert "bumped AAA to latest remote" in out, out
    assert "rename is complete" in out, out
    assert (tmp_path / "wallet-confs" / "aaa--v1.1.conf").is_file()
    assert not (tmp_path / "wallet-confs" / "aaa--v1.0.conf").exists()


def test_versions_from_flag_end_to_end_dry(tmp_path):
    """P2: --versions-from plans bumps offline with the tree untouched."""
    import json as _json

    from audit_manifest import cli

    (tmp_path / "manifest-latest.json").write_text(
        _json.dumps(
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
    (tmp_path / "wallet-confs").mkdir()
    (tmp_path / "xbridge-confs").mkdir()
    slot = tmp_path / "probe.json"
    slot.write_text(
        _json.dumps(
            {
                "repos": {
                    "https://example.invalid/aaa": {
                        "status": "ALIVE",
                        "newer_same": ["v1.1.0"],
                        "newer_alt": [],
                        "remote_latest": "v1.1.0",
                        "entries": [{"ticker": "AAA"}],
                    }
                }
            }
        )
    )
    report = tmp_path / "out.json"
    rc = cli.main(
        [
            "--manifest",
            str(tmp_path / "manifest-latest.json"),
            "--local-only",
            "--update-versions",
            "--dry-run",
            "--versions-from",
            str(slot),
            "--report",
            str(report),
        ]
    )
    assert rc == 0
    payload = _json.loads(report.read_text())
    assert payload["plan"][0]["key"] == "AAA.versions"
    assert _json.loads((tmp_path / "manifest-latest.json").read_text())[0]["versions"] == ["v1.0.0"]
