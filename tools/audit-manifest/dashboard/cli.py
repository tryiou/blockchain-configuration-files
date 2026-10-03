"""The JSON verb interface: argument parsing, usage text, and main().

Standard library only — Textual is imported inside ``run_tui``, and the
widgets module only after the dependency probe succeeds, so every
agent-facing path here runs on a bare interpreter.
"""
from __future__ import annotations

import argparse
import json
import sys
from typing import List, Optional, Sequence, Tuple

from . import paths
from .paths import DashboardError
from .verbs import VERBS, dispatch


def add_common_flags(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--tickers", default=None,
                        help="Comma-separated ticker filter, e.g. BTC,LTC")
    parser.add_argument("--timeout", type=int, default=30, help="Seconds per probe")
    parser.add_argument("--batch", default=None, help="Batch label recorded in report meta")
    parser.add_argument("--manifest", default=str(paths.DEFAULT_MANIFEST),
                        help="Path to manifest-latest.json")
    parser.add_argument("--report", default=None,
                        help="Report path (default .cache/audit-manifest/<verb>.json; "
                             "last-run.json is refreshed too)")
    parser.add_argument("--max-seconds", type=int, default=0,
                        help="Abort the audit after N seconds (0 = no limit)")
    parser.add_argument("--local-only", action="store_true",
                        help="Skip the repo probe (fast; loses liveness and tag findings)")
    parser.add_argument("--with-probe", action="store_true",
                        help="Force the repo probe on for verbs that default to local-only")
    parser.add_argument("--with-changelog", action="store_true",
                        help="Include changelog mandatory-HF probes (slower, more complete)")
    parser.add_argument("--param-check", action="store_true",
                        help="Add the source parameter audit to this run")
    parser.add_argument("--fees-only", action="store_true",
                        help="With --param-check, only FEES/DUST")
    parser.add_argument("--dry-run", action="store_true",
                        help="Compute writes without touching disk")
    parser.add_argument("--replace-versions", action="store_true",
                        help="With update-versions, collapse to the latest tag")
    parser.add_argument("--apply", action="store_true",
                        help="For scaffold: write the result into the repo")
    parser.add_argument("--repo-url", default=None, help="Repo URL for the scaffold verb")
    parser.add_argument("--scaffold-ticker", default=None)
    parser.add_argument("--scaffold-tag", default=None)
    parser.add_argument("--scaffold-name", default=None)
    parser.add_argument("--scaffold-out-dir", default=None)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="dashboard.py",
        description="Audit dashboard: a Textual TUI with no arguments, JSON verbs with one.",
        epilog="Everything after -- is passed to audit-manifest.py untouched.",
    )
    sub = parser.add_subparsers(dest="verb", metavar="VERB")
    for name, verb in VERBS.items():
        child = sub.add_parser(name, help=verb.summary, description=verb.summary)
        add_common_flags(child)
    return parser


def print_usage(stream) -> None:
    width = max(len(n) for n in VERBS)
    print("usage: dashboard.py            start the TUI (needs a TTY and textual)", file=stream)
    print("       dashboard.py <VERB> [flags] [-- raw audit flags]", file=stream)
    print("", file=stream)
    print("verbs:", file=stream)
    for name, verb in VERBS.items():
        print(f"  {name:<{width}}  {verb.summary}", file=stream)
    print("", file=stream)
    print("exit:  0 nothing to decide · 1 findings/planned writes · 2 error", file=stream)
    print("", file=stream)
    print("default modes: findings/audit probe the fleet; param-check, ports,",
          "cross-check,", file=stream)
    print("  plan-fix and apply-fix skip the probe (--local-only) for speed.",
          "Widen with", file=stream)
    print("  --with-probe or --with-changelog; narrow with --local-only.",
          file=stream)


def split_raw(argv: Sequence[str]) -> Tuple[List[str], List[str]]:
    """Split on the -- end-of-options marker before argparse sees it."""
    if "--" in argv:
        i = list(argv).index("--")
        return list(argv[:i]), list(argv[i + 1:])
    return list(argv), []


def run_tui() -> int:
    try:
        import textual  # noqa: F401
    except ImportError:
        print(
            "dashboard.py: the TUI needs Textual, which is an optional dependency.\n"
            f"  install it for this repo only:\n"
            f"    {sys.executable} -m pip install -r {paths.HERE / 'requirements.txt'}\n"
            "  the JSON verbs need nothing beyond the standard library:\n"
            "    dashboard.py --help",
            file=paths.LOG_STREAM,
        )
        return 2
    from .app import _make_app

    app = _make_app()
    app.run()
    return 0


def main(argv: Optional[Sequence[str]] = None) -> int:
    head, raw = split_raw(list(sys.argv[1:] if argv is None else argv))

    if not head:
        if sys.stdout.isatty() and sys.stdin.isatty():
            return run_tui()
        print_usage(paths.LOG_STREAM)
        print(
            "\ndashboard.py: no verb given and stdout is not a TTY, so the TUI "
            "cannot start.",
            file=paths.LOG_STREAM,
        )
        return 2

    if head[0] in ("-h", "--help"):
        print_usage(sys.stdout)
        return 0

    if head[0] not in VERBS:
        print(f"dashboard.py: unknown verb {head[0]!r}", file=paths.LOG_STREAM)
        print_usage(paths.LOG_STREAM)
        return 2

    parser = build_parser()
    try:
        opts = parser.parse_args(head)
    except SystemExit as exc:  # --help on a sub-verb, or a bad flag
        return int(exc.code or 0)
    opts.verb = head[0]

    try:
        envelope, code = dispatch(opts, raw)
    except DashboardError as exc:
        print(f"dashboard.py: {exc}", file=paths.LOG_STREAM)
        return 2

    json.dump(envelope, sys.stdout, indent=2)
    sys.stdout.write("\n")
    return code
