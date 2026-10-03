"""The audit-manifest dashboard: a Textual TUI for humans and a
verb-per-task JSON interface for agents.

Importing this package never imports Textual: ``dashboard.widgets`` is
loaded only when the TUI actually starts (via ``_make_app``), so every
JSON verb runs on a bare interpreter. The executable ``dashboard.py``
next to this package is a thin entry that calls ``dashboard.cli.main``.
"""
from .app import _make_app
from .cli import build_parser, main, run_tui, split_raw
from .paths import DashboardError, SCHEMA_VERSION, best_fleet_report, meta_path, report_paths
from .runner import audit_command, run_audit
from .verbs import (
    VERBS,
    Verb,
    build_audit_argv,
    build_counts,
    build_envelope,
    decide_exit,
    default_opts,
    dispatch,
)

__all__ = [
    "DashboardError",
    "SCHEMA_VERSION",
    "VERBS",
    "Verb",
    "_make_app",
    "audit_command",
    "best_fleet_report",
    "build_audit_argv",
    "build_counts",
    "build_envelope",
    "build_parser",
    "decide_exit",
    "default_opts",
    "dispatch",
    "main",
    "meta_path",
    "report_paths",
    "run_audit",
    "run_tui",
    "split_raw",
]
