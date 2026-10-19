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
from collections.abc import Sequence
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent.parent
AUDIT_SCRIPT = HERE / "audit-manifest.py"
REPO_ROOT = HERE.parent.parent
DEFAULT_MANIFEST_NAME = "manifest-latest.json"
DEFAULT_MANIFEST = REPO_ROOT / DEFAULT_MANIFEST_NAME
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


def report_paths(
    verb: str,
    explicit: str | None,
    tickers: str | None = None,
) -> tuple[Path, Path, Path]:
    """Return (primary report, last-run copy, log) for a verb.

    Each verb keeps its own report so a cheap ``ports`` run cannot clobber
    the full audit an agent is about to read, while ``last-run.json`` is
    refreshed from whichever verb ran most recently so "the report" always
    resolves to something concrete.

    A scoped run (tickers set) writes its own ``<verb>.scoped`` slot —
    log and sidecar follow by suffix — and never touches the fleet slot.
    An explicit path is the operator's own choice and stays verbatim.
    """
    if explicit:
        primary = Path(explicit).expanduser().resolve()
    elif tickers:
        primary = CACHE_ROOT / f"{verb}.scoped.json"
    else:
        primary = CACHE_ROOT / f"{verb}.json"
    return primary, LAST_REPORT, primary.with_suffix(".log")


# one field per recorded key
def write_last_run_meta(  # noqa: PLR0913, PLR0917
    verb: str,
    argv: Sequence[str],
    primary: Path,
    log_path: Path,
    started_at: float,
    duration: float,
    returncode: int,
) -> None:
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


def state_path() -> Path:
    """Where the TUI persists its scope (selection / filter / tab).

    Resolved at call time from ``CACHE_ROOT`` — not an import-time
    constant — so a test that redirects ``CACHE_ROOT`` redirects this
    file too, and the TUI never writes to the real cache during tests.
    """
    return CACHE_ROOT / "dashboard.json"


def read_meta_for(report_path: Path) -> dict[str, Any]:
    path = meta_path(report_path)
    if not path.is_file():
        return {}
    try:
        meta = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    # Same promise as read_last_run_meta: callers read keys off the
    # result, so a non-mapping lands on the empty default.
    return meta if isinstance(meta, dict) else {}


def read_json(path: Path) -> Any:
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError as exc:
        raise DashboardError(f"no such report: {path}") from exc
    except OSError as exc:
        raise DashboardError(f"cannot read {path}: {exc}") from exc
    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        raise DashboardError(f"{path} is not valid JSON: {exc}") from exc


def read_last_run_meta() -> dict[str, Any]:
    """The last run's metadata sidecar, or ``{}`` when there is none.

    Callers read keys off the result, so any non-mapping shape lands on
    the empty default, like an unreadable file.
    """
    if not LAST_META.is_file():
        return {}
    try:
        meta = json.loads(LAST_META.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return meta if isinstance(meta, dict) else {}


# Verbs whose report surveys the whole fleet. A cheap verb such as ports
# also refreshes last-run.json, so "ran last" and "fleet audit" differ.
# param-check belongs here: its findings are per-coin results (fees,
# ports, prefixes vs source), not a log transcript — the Findings tab
# merges every slot below, newest row wins per coin+check.
FLEET_REPORTS = ("findings.json", "audit.json", "param-check.json", "analyze.json")

# Fleet slots whose signal is a payload blob, not finding rows: their
# counts surface in the overview ledger (ports collisions, cross-check
# missing/orphans), never as table rows.
EXTRA_SLOTS = ("ports.json", "cross-check.json")


def _skip_in_fleet_pick(path: Path) -> bool:
    """Whether a report file is unusable as the fleet report.

    Scoped runs bake their raw ``--ticker`` string into ``meta.tickers``
    and are always skipped, as are files that cannot even be decoded (an
    older good file shows instead of a degrade-to-empty). A dict without
    a meta block reads as fleet, like every pre-scope file.
    """
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return True
    if not isinstance(payload, dict):
        return True
    meta = payload.get("meta")
    return isinstance(meta, dict) and bool(meta.get("tickers"))


def best_fleet_report() -> Path | None:
    """Newest fleet-wide report on disk, falling back to whatever ran last.

    Scoped-content files never present as the fleet — not even through
    the last-run fallback: with no fleet file on disk there is no fleet
    report to show.
    """
    candidates = [CACHE_ROOT / name for name in FLEET_REPORTS]
    existing = [p for p in candidates if p.is_file() and not _skip_in_fleet_pick(p)]
    if existing:
        return max(existing, key=lambda p: p.stat().st_mtime)
    if LAST_REPORT.is_file() and not _skip_in_fleet_pick(LAST_REPORT):
        return LAST_REPORT
    return None


def fleet_report_slots() -> list[tuple[str, dict[str, Any], float, dict[str, Any]]]:
    """Usable fleet finding-slots for the merged Findings view.

    One entry per slot: (file name, decoded payload, mtime, sidecar
    meta). Scoped slots never present as the fleet (same rule as the
    single pick); undecodable or wrong-shaped files drop out so an
    older good slot shows instead of a degrade-to-empty.
    """
    slots: list[tuple[str, dict[str, Any], float, dict[str, Any]]] = []
    for name in FLEET_REPORTS:
        path = CACHE_ROOT / name
        if not path.is_file() or _skip_in_fleet_pick(path):
            continue
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if not isinstance(payload, dict):
            continue
        slots.append((name, payload, path.stat().st_mtime, read_meta_for(path)))
    return slots


def fleet_extra_slots() -> dict[str, tuple[dict[str, Any], float, dict[str, Any]]]:
    """Decoded ports/cross-check fleet slots for the overview ledger.

    Their signal is a payload blob (collision map, missing/orphan
    lists), not finding rows, so they never join the merged table —
    but their counts and ages belong on the Report ledger next to the
    finding sources. Same scoped/corrupt guards as the finding slots.
    """
    extras: dict[str, tuple[dict[str, Any], float, dict[str, Any]]] = {}
    for name in EXTRA_SLOTS:
        path = CACHE_ROOT / name
        if not path.is_file() or _skip_in_fleet_pick(path):
            continue
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if isinstance(payload, dict):
            extras[name] = (payload, path.stat().st_mtime, read_meta_for(path))
    return extras
