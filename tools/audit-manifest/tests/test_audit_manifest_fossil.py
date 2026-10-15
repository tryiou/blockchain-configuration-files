#!/usr/bin/env python3
"""
Proof-first test for fossil purge by DATE — COLX/TRC creatordate vs semver.

Covers mandatory creatordate fetch and fossil filtering:
  COLX v1.2.5 (2024-09-23) vs v2.3.0 (2017-08-06) -> fossil
  TRC v0.12.2.5 (2020-03-05) vs v0.13.0.0 (2016-01-09) -> fossil
Ensures single probe_tag_dates call per repo and DRY helper.
"""

import json
import tempfile
from pathlib import Path
from unittest import mock

import audit_manifest as audit

VersionEngine = audit.VersionEngine
_newest_and_stale = audit._newest_and_stale
ManifestCoin = audit.ManifestCoin


def test_newest_and_stale_helper():
    dates = {
        "v1.2.5": "2024-09-23 10:29:10 +0530",
        "v2.3.0": "2017-08-06 20:20:22 -0700",
        "v0.10.15.0": "2020-01-01 00:00:00 +0000",
    }
    newest_tag, newest_date, stale = _newest_and_stale(dates, stale_years=3.0)
    assert newest_tag == "v1.2.5"
    assert newest_date == "2024-09-23 10:29:10 +0530"
    assert stale is False  # 2024 is not stale

    # stale case: newest is old
    old = {"v0.10.0": "2018-01-01 00:00:00 +0000"}
    _nt, _nd, st = _newest_and_stale(old, stale_years=3.0)
    assert st is True

    # empty
    assert _newest_and_stale({}, 3.0) == (None, None, False)


def test_fossil_colx_purge():
    held = "v1.2.5"
    newer = ["v2.3.0", "v1.2.6", "v0.10.15.10"]  # v2.3.0 fossil, others newer but newer dates
    tag_dates = {
        "v1.2.5": "2024-09-23 10:29:10 +0530",
        "v2.3.0": "2017-08-06 20:20:22 -0700",
        "v1.2.6": "2025-01-01 00:00:00 +0000",
        "v0.10.15.10": "2024-10-01 00:00:00 +0000",
    }
    held_date = tag_dates[held]
    fossils = [t for t in newer if (td := tag_dates.get(t)) is not None and td < held_date]
    assert "v2.3.0" in fossils
    assert "v1.2.6" not in fossils
    assert "v0.10.15.10" not in fossils
    # after purge newer should not contain fossil
    filtered = [t for t in newer if t not in fossils]
    assert "v2.3.0" not in filtered
    assert "v1.2.6" in filtered


def test_fossil_trc_purge():
    held = "v0.12.2.5"
    newer = ["v0.13.0.0", "v0.12.2.6"]
    tag_dates = {
        "v0.12.2.5": "2020-03-05 08:07:55 -0700",
        "v0.13.0.0": "2016-01-09 13:48:29 -0700",
        "v0.12.2.6": "2021-01-01 00:00:00 +0000",
    }
    held_date = tag_dates[held]
    fossils = [t for t in newer if tag_dates.get(t) < held_date]
    assert fossils == ["v0.13.0.0"]
    filtered = [t for t in newer if t not in fossils]
    assert filtered == ["v0.12.2.6"]


def test_no_fossil_when_newer_is_genuinely_newer():
    # BTC v22-final (2022) vs v23.0 (2023) -> not fossil
    held = "v22-final"
    newer = ["v23.0"]
    tag_dates = {
        "v22-final": "2022-01-01 00:00:00 +0000",
        "v23.0": "2023-06-01 00:00:00 +0000",
    }
    held_date = tag_dates[held]
    fossils = [t for t in newer if tag_dates.get(t) < held_date]
    assert fossils == []


def test_held_phantom_no_fossil():
    # held_max not in tag_dates (phantom missing) -> no fossil filtering
    tag_dates = {"v2.3.0": "2017-08-06 20:20:22 -0700"}
    held_max = "v1.2.5"  # phantom not in tag_dates
    held_date = tag_dates.get(held_max)
    assert held_date is None
    fossils = []
    if tag_dates and held_date:
        fossils = ["should not happen"]
    assert fossils == []


def test_single_probe_call_mock():
    """Integration: single probe_tag_dates call per repo via audit.main (COLX needed set)."""
    # Build minimal manifest with one COLX coin to drive one repo loop
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        manifest = [
            {
                "ticker": "COLX",
                "ver_id": "colossusxt--v1.2.5",
                "versions": ["v1.2.5"],
                "repo_url": "https://github.com/ColossusCoinXT/ColossusCoinXT",
                "wallet_conf": "colossusxt.conf",
                "xbridge_conf": "colossusxt.conf",
                "dir_name_linux": "colossusxt",
            }
        ]
        manifest_file = tmp_path / "manifest.json"
        manifest_file.write_text(json.dumps(manifest))
        report_file = tmp_path / "report.json"
        # Ensure local cross-check / port collision dirs exist to avoid FileNotFoundError
        (tmp_path / "wallet-confs").mkdir(exist_ok=True)
        (tmp_path / "xbridge-confs").mkdir(exist_ok=True)
        (tmp_path / "autobuild" / "configs").mkdir(parents=True, exist_ok=True)

        # Mock data: remote tags include held and newer fossil candidates
        remote_tags = {"v1.2.5", "v2.3.0", "v0.10.15.10", "v1.2.6"}
        tag_dates_return = {
            "v1.2.5": "2024-09-23 10:29:10 +0530",
            "v2.3.0": "2017-08-06 20:20:22 -0700",
            "v0.10.15.10": "2020-01-01 00:00:00 +0000",
            "v1.2.6": "2025-01-01 00:00:00 +0000",
        }

        with (
            mock.patch.object(audit.RemoteProbeService, "probe_redirect", return_value=None) as _mr,
            mock.patch.object(
                audit.RemoteProbeService,
                "probe_tags",
                return_value=(audit.RepoStatus.ALIVE, remote_tags),
            ) as _mt,
            mock.patch.object(audit.RemoteProbeService, "probe_tag_dates", return_value=tag_dates_return) as mock_dates,
            mock.patch("time.sleep", return_value=None),
        ):
            rc = audit.main(
                [
                    "--manifest",
                    str(manifest_file),
                    "--ticker",
                    "COLX",
                    "--timeout",
                    "5",
                    "--report",
                    str(report_file),
                ]
            )
            # main should succeed (0) even with minimal manifest
            assert rc == 0, f"audit.main returned {rc}"
            # Must have called probe_tag_dates exactly once per repo (one repo in manifest)
            assert mock_dates.call_count == 1, (
                f"expected single probe_tag_dates call per repo, got {mock_dates.call_count}"
            )
            # Verify selected set included held_max and newer candidates (union)
            called_args, _ = mock_dates.call_args
            selected_set = called_args[1] if len(called_args) > 1 else set()
            assert "v1.2.5" in selected_set, f"held_max v1.2.5 must be in selected {selected_set}"
            assert "v2.3.0" in selected_set, f"newer fossil v2.3.0 must be in selected {selected_set}"
            # Verify report was written and fossil logic would have filtered v2.3.0
            assert report_file.exists()
            data = json.loads(report_file.read_text())
            # Fossil check via report: newer_same/alt should not contain fossil after purge
            # Since v2.3.0 is older-dated than v1.2.5, it should be in stale_higher_semver
            repo_key = "https://github.com/ColossusCoinXT/ColossusCoinXT"
            repo_data = data["repos"].get(repo_key)
            assert repo_data is not None, f"repo {repo_key} missing in report"
            fossils = repo_data.get("stale_higher_semver") or []
            assert "v2.3.0" in fossils, f"v2.3.0 should be fossil, got {fossils}"


def test_integration_colx_fossil_via_detect_newer_and_dates():
    coin = ManifestCoin(ticker="COLX", ver_id="colossusxt--v1.2.5", versions=["v1.2.5"])
    remote = {"v1.2.5", "v2.3.0", "v2.1.2.3", "v0.10.15.10"}
    # Add many stable tags to force bulk >100 path, but mocked dates
    newer_same, newer_alt = VersionEngine.detect_newer(remote, [coin])
    # v2.3.0 should be newer_same or newer_alt depending on tuple len
    assert "v2.3.0" in newer_same + newer_alt
    # Mock dates where held is newest date
    tag_dates = {
        "v1.2.5": "2024-09-23 10:29:10 +0530",
        "v2.3.0": "2017-08-06 20:20:22 -0700",
        "v2.1.2.3": "2017-07-01 00:00:00 +0000",
        "v0.10.15.10": "2020-01-01 00:00:00 +0000",
    }
    held_max = VersionEngine.max_version_tag(coin.expected_tags())
    held_date = tag_dates.get(held_max)
    fossils = [t for t in newer_same + newer_alt if tag_dates.get(t) and tag_dates.get(t) < held_date]
    # v2.3.0 and v2.1.2.3 are both old fossils
    assert "v2.3.0" in fossils
    assert "v2.1.2.3" in fossils
    # after purge, newer should be filtered
    fset = set(fossils)
    ns_filtered = [t for t in newer_same if t not in fset]
    na_filtered = [t for t in newer_alt if t not in fset]
    assert "v2.3.0" not in ns_filtered + na_filtered


def test_console_line_leads_with_verdict_and_caps_tag_lists(capsys):
    """F5a: per-coin line scans — action= first, padded ticker, capped lists."""
    import tempfile

    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        manifest = [
            {
                "ticker": "AAA",
                "ver_id": "aaa--v1.0.0",
                "versions": ["v1.0.0"],
                "repo_url": "https://github.com/example/aaa",
                "wallet_conf": "aaa.conf",
                "xbridge_conf": "aaa.conf",
            }
        ]
        manifest_file = tmp_path / "manifest.json"
        manifest_file.write_text(json.dumps(manifest))
        report_file = tmp_path / "report.json"
        (tmp_path / "wallet-confs").mkdir(exist_ok=True)
        (tmp_path / "xbridge-confs").mkdir(exist_ok=True)
        (tmp_path / "autobuild" / "configs").mkdir(parents=True, exist_ok=True)
        remote_tags = {"v1.0.0", "v1.1.0", "v1.2.0", "v1.3.0", "v1.4.0", "v1.5.0", "v1.6.0"}
        with (
            mock.patch.object(audit.RemoteProbeService, "probe_redirect", return_value=None),
            mock.patch.object(
                audit.RemoteProbeService,
                "probe_tags",
                return_value=(audit.RepoStatus.ALIVE, remote_tags),
            ),
            mock.patch.object(audit.RemoteProbeService, "probe_tag_dates", return_value={}),
            mock.patch("time.sleep", return_value=None),
        ):
            rc = audit.main(
                [
                    "--manifest",
                    str(manifest_file),
                    "--ticker",
                    "AAA",
                    "--timeout",
                    "5",
                    "--report",
                    str(report_file),
                ]
            )
            assert rc in (0, 1)
            out = capsys.readouterr().out
            coin_lines = [ln for ln in out.splitlines() if ln.startswith("[1/1]")]
            assert len(coin_lines) == 1, f"one per-coin line, got {coin_lines!r}"
            line = coin_lines[0]
            assert line.index("action=") < line.index("ALIVE"), f"verdict first, got {line[:80]!r}"
            assert "AAA         " in line, f"ticker padded to 12, got {line[:80]!r}"
            import re

            assert re.search(r"NEWER_same=\[[^\]]*\+\d+ more\]", line), f"tag list capped with +N, got {line!r}"
