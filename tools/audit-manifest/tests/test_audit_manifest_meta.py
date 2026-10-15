#!/usr/bin/env python3
"""
Report meta bake-in: the flags you pass must reach payload["meta"], and
payload["dirty"] must be present and None.

The run is real — audit-manifest.py is spawned as a subprocess and its report
is parsed — but it uses --local-only, because these assertions are about the
report contract rather than about probing. A live probe of one coin costs
~16s of GitHub traffic (216 tags plus the release-notes changelog), and the
meta fields under test are filled in from the command line either way.

Nothing here mutates the repository: no stash, no writes outside tmp_path.
"""

import json
import subprocess
import sys
from pathlib import Path

AUDIT_PATH = Path(__file__).resolve().parents[1] / "audit-manifest.py"

# <repo>/tools/audit-manifest/tests/<this file> -> <repo>
REPO_ROOT = Path(__file__).resolve().parents[3]

ARGS = [
    "--local-only",
    "--ticker",
    "DGB",
    "--timeout",
    "10",
    "--clone-timeout",
    "60",
    "--batch",
    "99/99",
]


def _run_audit(extra_args, report_path):
    cmd = [sys.executable, str(AUDIT_PATH), *extra_args, "--report", str(report_path)]
    return subprocess.run(cmd, capture_output=True, text=True, timeout=60, cwd=str(REPO_ROOT), check=False)


def test_meta_and_dirty_are_baked_into_the_report(tmp_path):
    report = tmp_path / "probe_meta.json"
    proc = _run_audit(ARGS, report)

    # Exit 0 or 1 depending on findings; 2 would mean the run itself failed.
    assert proc.returncode in (0, 1), (
        f"audit run failed rc={proc.returncode} stderr={proc.stderr[:500]} stdout={proc.stdout[:500]}"
    )
    assert report.exists(), "report not written"

    data = json.loads(report.read_text())
    assert "meta" in data, f"meta missing in report keys={list(data.keys())}"

    meta = data["meta"]
    assert meta.get("timeout") == 10, f"meta timeout expected 10 got {meta.get('timeout')}"
    assert meta.get("clone_timeout") == 60, f"meta clone_timeout expected 60 got {meta.get('clone_timeout')}"
    assert meta.get("batch") == "99/99", f"meta batch expected 99/99 got {meta.get('batch')}"
    assert meta.get("tickers") == "DGB", f"meta tickers expected 'DGB' got {meta.get('tickers')!r}"
    # Mandatory date fetch is automatic, so there is no opt-out flag to record.
    assert "no_tag_dates" not in meta, (
        f"no_tag_dates should be absent for mandatory fetch (clean no-op), got {meta.get('no_tag_dates')!r}"
    )
    # Guards the speed contract: if this ever stops being true, the test is
    # silently back on the network.
    assert meta.get("local_only") is True, f"this test must stay offline, got local_only={meta.get('local_only')!r}"

    # BCF dirty is intentionally ignored: we audit files on disk, not git
    # state, so the field is present and None whichever way the worktree looks.
    assert "dirty" in data, "dirty missing"
    assert data["dirty"] is None, f"dirty should be None (ignored), got {data['dirty']!r}"
