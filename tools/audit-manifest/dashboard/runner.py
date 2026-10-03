"""Subprocess mechanics: launch audit-manifest.py and capture its output.

This module knows nothing about verbs — it runs the command line it is
given; verb semantics (argv translation, envelope, exit codes, dispatch)
live in ``verbs``.
"""
from __future__ import annotations

import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Sequence

from . import paths
from .paths import DashboardError


def audit_command(argv: Sequence[str], report_path: Path) -> List[str]:
    return [sys.executable, str(paths.AUDIT_SCRIPT), *argv, "--report", str(report_path)]


def run_audit(cmd: Sequence[str], log_path: Path, max_seconds: int = 0) -> Dict[str, Any]:
    """Run audit-manifest.py synchronously, capturing its full console output.

    No timeout by default: the audit script already bounds every network
    call it makes, and killing it mid-run would discard work the caller is
    about to read. ``max_seconds`` is an explicit opt-in for callers that
    would rather have a bounded failure than an unbounded wait.
    """
    paths.CACHE_ROOT.mkdir(parents=True, exist_ok=True)
    started = time.monotonic()
    try:
        proc = subprocess.run(
            list(cmd),
            capture_output=True,
            text=True,
            timeout=max_seconds or None,
        )
    except OSError as exc:
        raise DashboardError(f"could not launch {paths.AUDIT_SCRIPT.name}: {exc}")
    except subprocess.TimeoutExpired:
        raise DashboardError(f"the audit run exceeded {max_seconds}s (--max-seconds)")

    duration = time.monotonic() - started
    out = proc.stdout or ""
    err = proc.stderr or ""
    log_path.write_text(out + ("\n--- stderr ---\n" + err if err else ""), encoding="utf-8")
    print(
        f"[audit] rc={proc.returncode} in {duration:.1f}s log={log_path}",
        file=paths.LOG_STREAM,
    )
    return {"returncode": proc.returncode, "duration": duration, "log": str(log_path)}
