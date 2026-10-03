"""Filesystem state: where reports live, and the seam tests redirect.

Every name in this module that describes *where* something is (or where a
human-readable line goes) is read at call time through ``paths.<name>``, so
a test can point the dashboard at a throwaway directory by patching
``dashboard.paths.<name>``. Nothing outside this module re-binds those
names: other modules do ``from . import paths`` and read ``paths.CACHE_ROOT``.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, Dict, Optional, Sequence, Tuple

HERE = Path(__file__).resolve().parent.parent
AUDIT_SCRIPT = HERE / "audit-manifest.py"
REPO_ROOT = HERE.parent.parent
DEFAULT_MANIFEST = REPO_ROOT / "manifest-latest.json"
CACHE_ROOT = REPO_ROOT / ".cache" / "audit-manifest"
LAST_REPORT = CACHE_ROOT / "last-run.json"
LAST_META = CACHE_ROOT / "last-run.meta.json"

# Every human-readable line goes to stderr; stdout is reserved for the envelope.
LOG_STREAM = sys.stderr

# Envelope contract version (see runner.build_envelope).
SCHEMA_VERSION = 1


class DashboardError(Exception):
    """A failure that is the caller's fault or an environment problem, not a bug.

    It lives at the bottom of the package because every layer raises it: the
    report plumbing (this module), the verb runner, the CLI and the TUI all
    surface it to their caller instead of swallowing it.
    """


def report_paths(verb: str, explicit: Optional[str]) -> Tuple[Path, Path, Path]:
    """Return (primary report, last-run copy, log) for a verb.

    Each verb keeps its own report so a cheap ``ports`` run cannot clobber
    the full audit an agent is about to read, while ``last-run.json`` is
    refreshed from whichever verb ran most recently so "the report" always
    resolves to something concrete.
    """
    if explicit:
        primary = Path(explicit).expanduser().resolve()
    else:
        primary = CACHE_ROOT / f"{verb}.json"
    return primary, LAST_REPORT, primary.with_suffix(".log")


def write_last_run_meta(verb: str, argv: Sequence[str], primary: Path,
                        log_path: Path, started_at: float, duration: float,
                        returncode: int) -> None:
    """Record what produced a report, next to it and as the most recent run."""
    payload = {
        "verb": verb,
        "argv": list(argv),
        "report": str(primary),
        "log": str(log_path),
        "started_at": started_at,
        "duration_seconds": round(duration, 3),
        "audit_exit_code": returncode,
    }
    CACHE_ROOT.mkdir(parents=True, exist_ok=True)
    text = json.dumps(payload, indent=2) + "\n"
    meta_path(primary).write_text(text, encoding="utf-8")
    LAST_META.write_text(text, encoding="utf-8")


def meta_path(report_path: Path) -> Path:
    """Sidecar recording when/why ``report_path`` was written."""
    return report_path.with_suffix(".meta.json")


def read_meta_for(report_path: Path) -> Dict[str, Any]:
    path = meta_path(report_path)
    if not path.is_file():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}


def read_json(path: Path) -> Any:
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        raise DashboardError(f"no such report: {path}")
    except OSError as exc:
        raise DashboardError(f"cannot read {path}: {exc}")
    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        raise DashboardError(f"{path} is not valid JSON: {exc}")


def read_last_run_meta() -> Dict[str, Any]:
    if not LAST_META.is_file():
        return {}
    try:
        return json.loads(LAST_META.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}


# Verbs whose report surveys the whole fleet. A cheap verb such as ports also
# refreshes last-run.json, so "whatever ran last" is not the same thing as
# "the fleet audit", and the Overview must not silently swap one for the other.
FLEET_REPORTS = ("findings.json", "audit.json")


def best_fleet_report() -> Optional[Path]:
    """Newest fleet-wide report on disk, falling back to whatever ran last."""
    candidates = [CACHE_ROOT / name for name in FLEET_REPORTS]
    existing = [p for p in candidates if p.is_file()]
    if existing:
        return max(existing, key=lambda p: p.stat().st_mtime)
    return LAST_REPORT if LAST_REPORT.is_file() else None
