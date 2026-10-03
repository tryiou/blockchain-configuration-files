#!/usr/bin/env python3
"""Dashboard for audit-manifest: a Textual TUI for humans, and a
verb-per-task JSON interface for agents.

Two modes, chosen by how you invoke it:

    dashboard.py                  TUI when stdout is a TTY, otherwise
                                  usage on stderr and exit 2
    dashboard.py <verb> [...]     exactly one JSON object on stdout

Exit codes in verb mode:

    0   the verb finished and there is nothing left to decide
    1   the verb finished and surfaced something that does
        (findings, collisions, planned-but-not-applied writes)
    2   the verb could not complete (bad usage, the audit script failed,
        or its report could not be read)

stdout carries the JSON envelope and nothing else — every human-readable
line goes to stderr — so ``dashboard.py findings | jq`` always works.

Textual is imported only when the TUI actually starts, so every
agent-facing path stays standard-library-only.

Run ``dashboard.py --help`` for the verb list.
"""
from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import time
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List, NamedTuple, Optional, Sequence, Tuple

SCHEMA_VERSION = 1

HERE = Path(__file__).resolve().parent
AUDIT_SCRIPT = HERE / "audit-manifest.py"
REPO_ROOT = HERE.parent.parent
DEFAULT_MANIFEST = REPO_ROOT / "manifest-latest.json"
CACHE_ROOT = REPO_ROOT / ".cache" / "audit-manifest"
LAST_REPORT = CACHE_ROOT / "last-run.json"
LAST_META = CACHE_ROOT / "last-run.meta.json"

# Every human-readable line goes to stderr; stdout is reserved for the envelope.
LOG_STREAM = sys.stderr


class DashboardError(Exception):
    """A failure that is the caller's fault or an environment problem, not a bug."""


class Verb(NamedTuple):
    """One agent-facing task and how it maps onto audit-manifest.py.

    ``base`` is appended verbatim to the audit invocation. ``subject`` names
    the payload whose emptiness decides exit code 1: ``"plan"`` for verbs
    that describe writes, ``"findings"`` for everything else. ``write``
    marks verbs that modify the working tree (they report success rather
    than findings, unless they were run as a preview).
    """

    name: str
    summary: str
    base: Tuple[str, ...]
    subject: str
    write: bool = False
    informational: bool = False


VERBS: Dict[str, Verb] = {
    v.name: v
    for v in (
        Verb(
            "list",
            "List manifest entries without running an audit",
            (),
            "entries",
            informational=True,
        ),
        Verb(
            "audit",
            "Full fleet audit: probe every repo, cross-check confs, port matrix",
            (),
            "findings",
        ),
        Verb(
            "findings",
            "Aggregated findings, worst-first (probe, changelog probes skipped)",
            ("--no-changelog",),
            "findings",
        ),
        Verb(
            "param-check",
            "Fact-check confs against coin source, skipping the repo probe",
            ("--local-only", "--param-check"),
            "findings",
        ),
        Verb(
            "ports",
            "Fleet port-collision matrix only",
            ("--local-only",),
            "findings",
        ),
        Verb(
            "cross-check",
            "On-disk conf cross-check: missing and orphaned files",
            ("--local-only",),
            "findings",
        ),
        Verb(
            "plan-fix",
            "Preview every write the fix flags would make (dry-run)",
            ("--local-only", "--param-check", "--dry-run",
             "--write-config", "--fee-write", "--fix-ports"),
            "plan",
        ),
        Verb(
            "apply-fix",
            "Apply the conf and port fixes",
            ("--local-only", "--param-check",
             "--write-config", "--fee-write", "--fix-ports"),
            "plan",
            write=True,
        ),
        Verb(
            "update-versions",
            "Bump manifest versions to the latest upstream tag",
            ("--no-changelog", "--update-versions"),
            "plan",
            write=True,
        ),
        Verb(
            "scaffold",
            "Extract a new coin entry from a repo URL (needs --repo-url)",
            ("--scaffold",),
            "plan",
            write=True,
        ),
        Verb(
            "report",
            "Metadata, summary and counts for the most recent run",
            (),
            "report",
            informational=True,
        ),
    )
}


# ---------------------------------------------------------------------------
# Report plumbing
# ---------------------------------------------------------------------------

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


# ---------------------------------------------------------------------------
# Running the audit script
# ---------------------------------------------------------------------------

def build_audit_argv(opts: argparse.Namespace, raw: Sequence[str]) -> List[str]:
    """Translate a verb plus its flags into audit-manifest.py arguments."""
    verb = VERBS[opts.verb]

    argv: List[str] = ["--manifest", opts.manifest, "--timeout", str(opts.timeout)]
    if opts.tickers:
        argv += ["--ticker", opts.tickers]
    if opts.batch:
        argv += ["--batch", opts.batch]

    base = list(verb.base)

    # Mode switches. Each verb has one documented default mode; these widen
    # it in the direction the flag name implies and never narrow it silently.
    if opts.with_probe and "--local-only" in base:
        base.remove("--local-only")
    if opts.local_only and "--local-only" not in base:
        base.append("--local-only")
    if opts.with_changelog and "--no-changelog" in base:
        base.remove("--no-changelog")
    if opts.param_check and "--param-check" not in base:
        base.append("--param-check")
    if opts.fees_only:
        base.append("--fees-only")
    if opts.dry_run and "--dry-run" not in base:
        base.append("--dry-run")
    if opts.replace_versions:
        base.append("--replace-versions")

    if verb.name == "scaffold":
        if not opts.repo_url:
            raise DashboardError("the scaffold verb requires --repo-url <url>")
        argv += ["--repo-url", opts.repo_url]
        for flag, value in (
            ("--scaffold-ticker", opts.scaffold_ticker),
            ("--scaffold-tag", opts.scaffold_tag),
            ("--scaffold-name", opts.scaffold_name),
            ("--scaffold-out-dir", opts.scaffold_out_dir),
        ):
            if value:
                argv += [flag, value]
        if opts.apply:
            base.append("--apply")

    argv += base
    argv += list(raw)
    return argv


def audit_command(argv: Sequence[str], report_path: Path) -> List[str]:
    return [sys.executable, str(AUDIT_SCRIPT), *argv, "--report", str(report_path)]


def run_audit(cmd: Sequence[str], log_path: Path, max_seconds: int = 0) -> Dict[str, Any]:
    """Run audit-manifest.py synchronously, capturing its full console output.

    No timeout by default: the audit script already bounds every network
    call it makes, and killing it mid-run would discard work the caller is
    about to read. ``max_seconds`` is an explicit opt-in for callers that
    would rather have a bounded failure than an unbounded wait.
    """
    CACHE_ROOT.mkdir(parents=True, exist_ok=True)
    started = time.monotonic()
    try:
        proc = subprocess.run(
            list(cmd),
            capture_output=True,
            text=True,
            timeout=max_seconds or None,
        )
    except OSError as exc:
        raise DashboardError(f"could not launch {AUDIT_SCRIPT.name}: {exc}")
    except subprocess.TimeoutExpired:
        raise DashboardError(f"the audit run exceeded {max_seconds}s (--max-seconds)")

    duration = time.monotonic() - started
    out = proc.stdout or ""
    err = proc.stderr or ""
    log_path.write_text(out + ("\n--- stderr ---\n" + err if err else ""), encoding="utf-8")
    print(
        f"[audit] rc={proc.returncode} in {duration:.1f}s log={log_path}",
        file=LOG_STREAM,
    )
    return {"returncode": proc.returncode, "duration": duration, "log": str(log_path)}


# ---------------------------------------------------------------------------
# Envelope
# ---------------------------------------------------------------------------

def build_counts(findings: Sequence[Dict[str, Any]]) -> Dict[str, Any]:
    """Compact rollups an agent can branch on without walking the array."""
    by_coin = Counter(f["coin"] for f in findings if f.get("coin"))
    return {
        "total": len(findings),
        "by_severity": dict(Counter(f.get("severity") for f in findings)),
        "by_category": dict(Counter(f.get("category") for f in findings)),
        "by_coin": dict(sorted(by_coin.items(), key=lambda kv: (-kv[1], kv[0]))),
    }


def build_envelope(
    verb: Verb,
    report: Optional[Dict[str, Any]],
    argv: Sequence[str],
    started_at: Optional[float],
    duration: Optional[float],
    audit_exit: Optional[int],
    report_path: Optional[Path],
    log_path: Optional[Path],
    extra: Dict[str, Any],
    exit_code: int,
) -> Dict[str, Any]:
    findings = (report or {}).get("findings") or []
    plan = (report or {}).get("plan") or []
    age = (time.time() - started_at) if started_at else None

    envelope: Dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "verb": verb.name,
        "ok": exit_code != 2,
        "exit_code": exit_code,
        "counts": build_counts(findings),
        "plan_count": len(plan),
        "sources": {
            "report": str(report_path) if report_path else None,
            "log": str(log_path) if log_path else None,
            "argv": list(argv),
            "audit_exit_code": audit_exit,
            "duration_seconds": round(duration, 3) if duration is not None else None,
            "age_seconds": round(age, 1) if age is not None else None,
        },
    }
    if report is not None:
        envelope["summary"] = report.get("summary")
        envelope["meta"] = report.get("meta")
        envelope["report_schema_version"] = report.get("schema_version")
    envelope.update(extra)
    return envelope


def decide_exit(verb: Verb, opts: argparse.Namespace, payload: Sequence[Any]) -> int:
    """0 = nothing left to decide, 1 = something is. Errors are handled above.

    A write verb that really wrote returns 0: the work is done, so there is
    no pending decision. A write verb run with ``--dry-run``, and scaffold
    without ``--apply``, are previews and follow the data-verb rule instead.
    """
    if verb.informational:
        return 0
    if verb.write and not opts.dry_run:
        if verb.name != "scaffold" or opts.apply:
            return 0
    return 1 if payload else 0


# ---------------------------------------------------------------------------
# Verb implementations
# ---------------------------------------------------------------------------

def _entries_payload(opts: argparse.Namespace) -> Dict[str, Any]:
    manifest_path = Path(opts.manifest).expanduser()
    raw = read_json(manifest_path) if manifest_path.is_file() else []
    if not isinstance(raw, list):
        raise DashboardError(f"{manifest_path} does not contain a JSON array")
    entries = [
        {
            "ticker": e.get("ticker"),
            "ver_id": e.get("ver_id"),
            "versions": e.get("versions"),
            "wallet_conf": e.get("wallet_conf"),
            "xbridge_conf": e.get("xbridge_conf"),
            "repo_url": e.get("repo_url"),
        }
        for e in raw
        if isinstance(e, dict)
    ]
    return {"entries": entries, "manifest": str(manifest_path)}


def _param_rollup(report: Dict[str, Any]) -> Dict[str, Any]:
    """Per-coin status counts for param-check, without the full check blobs.

    The complete checks live in the report file; this rollup is what an
    agent needs to decide which coin to look at next.
    """
    rollup: Dict[str, Any] = {}
    for key, res in (report.get("param_check") or {}).items():
        if key.startswith("_") or not isinstance(res, dict):
            continue
        counts = Counter(
            c.get("status") for c in res.get("checks", []) if isinstance(c, dict)
        )
        rollup[key] = {
            "mode": res.get("mode"),
            "source": res.get("source"),
            "counts": {k: v for k, v in counts.items() if k},
        }
    return rollup


def _run_verb(opts: argparse.Namespace, raw: Sequence[str]) -> Tuple[Dict[str, Any], int]:
    verb = VERBS[opts.verb]
    argv = build_audit_argv(opts, raw)
    primary, last, log_path = report_paths(verb.name, opts.report)

    cmd = audit_command(argv, primary)
    started_at = time.time()
    result = run_audit(cmd, log_path, opts.max_seconds)

    # The audit script uses 2 only for "could not run"; 1 just means the
    # probe found dead/moved/unknown repos, which is a finding, not an error.
    if result["returncode"] == 2:
        raise DashboardError(f"audit-manifest.py exited 2 — see {log_path}")

    report = read_json(primary)

    CACHE_ROOT.mkdir(parents=True, exist_ok=True)
    if primary != last:
        shutil.copyfile(primary, last)
    write_last_run_meta(
        verb.name, cmd, primary, log_path, started_at, result["duration"], result["returncode"]
    )

    findings = report.get("findings") or []
    plan = report.get("plan") or []

    extra: Dict[str, Any] = {"findings": findings, "plan": plan}
    if verb.name in ("cross-check", "ports"):
        extra["local"] = report.get("local")
        extra["port_collisions"] = report.get("port_collisions")
    if verb.name == "param-check":
        extra["param_check"] = _param_rollup(report)
    if verb.name == "scaffold":
        extra["scaffold"] = report.get("scaffold")

    payload = plan if verb.subject == "plan" else findings
    code = decide_exit(verb, opts, payload)
    envelope = build_envelope(
        verb, report, cmd, started_at, result["duration"], result["returncode"],
        primary, log_path, extra, code,
    )
    return envelope, code


def _report_verb(opts: argparse.Namespace) -> Tuple[Dict[str, Any], int]:
    report = read_json(LAST_REPORT)
    meta = read_last_run_meta()
    verb = VERBS[opts.verb]
    findings = report.get("findings") or []
    plan = report.get("plan") or []
    extra = {
        "findings": findings,
        "plan": plan,
        "last_run": meta or None,
        "report_path": str(LAST_REPORT),
        "log_path": meta.get("log"),
    }
    envelope = build_envelope(
        verb, report, meta.get("argv", []), meta.get("started_at"),
        meta.get("duration_seconds"), meta.get("audit_exit_code"),
        Path(meta["report"]) if meta.get("report") else LAST_REPORT,
        Path(meta["log"]) if meta.get("log") else None, extra, 0,
    )
    return envelope, 0


def dispatch(opts: argparse.Namespace, raw: Sequence[str]) -> Tuple[Dict[str, Any], int]:
    verb = VERBS[opts.verb]
    if verb.name == "list":
        payload = _entries_payload(opts)
        envelope = build_envelope(
            verb, None, [], None, None, None, None, None, payload, 0
        )
        envelope["counts"] = dict(build_counts([]), total=len(payload["entries"]))
        return envelope, 0
    if verb.name == "report":
        return _report_verb(opts)
    return _run_verb(opts, raw)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def add_common_flags(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--tickers", default=None,
                        help="Comma-separated ticker filter, e.g. BTC,LTC")
    parser.add_argument("--timeout", type=int, default=30, help="Seconds per probe")
    parser.add_argument("--batch", default=None, help="Batch label recorded in report meta")
    parser.add_argument("--manifest", default=str(DEFAULT_MANIFEST),
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
            f"    {sys.executable} -m pip install -r {HERE / 'requirements.txt'}\n"
            "  the JSON verbs need nothing beyond the standard library:\n"
            "    dashboard.py --help",
            file=LOG_STREAM,
        )
        return 2
    app = _make_app()
    app.run()
    return 0


def default_opts(verb: str) -> argparse.Namespace:
    """Namespace with build_parser()'s defaults, for TUI-initiated runs."""
    return argparse.Namespace(
        verb=verb, tickers=None, timeout=30, batch=None,
        manifest=str(DEFAULT_MANIFEST), report=None, max_seconds=0,
        local_only=False, with_probe=False, with_changelog=False,
        param_check=False, fees_only=False, dry_run=False,
        replace_versions=False, apply=False, repo_url=None,
        scaffold_ticker=None, scaffold_tag=None, scaffold_name=None,
        scaffold_out_dir=None,
    )


def main(argv: Optional[Sequence[str]] = None) -> int:
    head, raw = split_raw(list(sys.argv[1:] if argv is None else argv))

    if not head:
        if sys.stdout.isatty() and sys.stdin.isatty():
            return run_tui()
        print_usage(LOG_STREAM)
        print(
            "\ndashboard.py: no verb given and stdout is not a TTY, so the TUI "
            "cannot start.",
            file=LOG_STREAM,
        )
        return 2

    if head[0] in ("-h", "--help"):
        print_usage(sys.stdout)
        return 0

    if head[0] not in VERBS:
        print(f"dashboard.py: unknown verb {head[0]!r}", file=LOG_STREAM)
        print_usage(LOG_STREAM)
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
        print(f"dashboard.py: {exc}", file=LOG_STREAM)
        return 2

    json.dump(envelope, sys.stdout, indent=2)
    sys.stdout.write("\n")
    return code


def _make_app():
    """Build the Textual application.

    Textual is imported here rather than at module scope so that every
    agent-facing path in this file runs on a bare interpreter.
    """
    import asyncio

    from textual import on, work
    from textual.app import App, ComposeResult
    from textual.binding import Binding
    from textual.containers import Horizontal, Vertical
    from textual.screen import ModalScreen
    from textual.widgets import (
        Button,
        DataTable,
        Footer,
        Header,
        Input,
        Label,
        OptionList,
        RichLog,
        Static,
        TabbedContent,
        TabPane,
    )
    from textual.widgets.option_list import Option

    class ConfirmScreen(ModalScreen[bool]):
        """Blocks the app until a write into the working tree is confirmed."""

        def __init__(self, title: str, body: str) -> None:
            super().__init__()
            self._title = title
            self._body = body

        def compose(self) -> ComposeResult:
            with Vertical(id="confirm-box"):
                yield Label(self._title, id="confirm-title")
                yield Static(self._body, id="confirm-body")
                with Horizontal(id="confirm-buttons"):
                    yield Button("Apply", variant="error", id="confirm-yes")
                    yield Button("Cancel", variant="primary", id="confirm-no")

        @on(Button.Pressed, "#confirm-yes")
        def yes(self) -> None:
            self.dismiss(True)

        @on(Button.Pressed, "#confirm-no")
        def no(self) -> None:
            self.dismiss(False)

        def on_key(self, event) -> None:
            if event.key == "escape":
                self.dismiss(False)

    class CommandPalette(ModalScreen[Optional[str]]):
        """Ctrl+P: pick a task by name. Escape dismisses without running."""

        def __init__(self, verbs: Dict[str, Verb]) -> None:
            super().__init__()
            self._verbs = verbs

        def compose(self) -> ComposeResult:
            with Vertical(classes="palette-box"):
                yield Input(placeholder="Run a task…", id="palette-input")
                yield OptionList(
                    *[Option(f"{v.name} — {v.summary}", v.name) for v in self._verbs.values()],
                    id="palette-list",
                )

        def on_mount(self) -> None:
            self.query_one("#palette-input", Input).focus()

        @on(Input.Submitted, "#palette-input")
        def submitted(self, event: Input.Submitted) -> None:
            value = event.value.strip()
            if value in self._verbs:
                self.dismiss(value)
            elif value:
                matches = [n for n in self._verbs if n.startswith(value)]
                if len(matches) == 1:
                    self.dismiss(matches[0])

        @on(OptionList.OptionSelected, "#palette-list")
        def selected(self, event: OptionList.OptionSelected) -> None:
            self.dismiss(str(event.option_id))

        def on_key(self, event) -> None:
            if event.key == "escape":
                self.dismiss(None)

    class DashboardApp(App):
        """Single screen: four tabs on the left, a detail pane on the right."""

        TITLE = "audit-manifest"
        SUB_TITLE = "dashboard"

        # Textual registers its own ctrl+p palette and replaces any binding on
        # that key with it, which would swallow the task picker this app
        # advertises in its footer and its Overview hint.
        ENABLE_COMMAND_PALETTE = False

        CSS = """
        Screen { layout: vertical; }
        #body { height: 1fr; }
        #tabs { width: 1fr; }
        #detail {
            width: 48;
            border-left: solid $accent;
            padding: 0 1;
            overflow-y: auto;
        }
        #findings-table, #plan-table { height: 1fr; }
        #run-log { height: 1fr; border: solid $accent; margin-top: 1; }
        #run-buttons, #write-buttons { height: auto; }
        #run-buttons Button { width: 100%; margin-bottom: 0; }
        #write-buttons Button { margin-right: 1; }
        .palette-box {
            width: 70; height: auto; max-height: 80%;
            border: thick $accent; background: $surface; padding: 1 2;
        }
        #confirm-box {
            width: 70; height: auto;
            border: thick $error; background: $surface; padding: 1 2;
        }
        #confirm-title { text-style: bold; color: $error; }
        #confirm-buttons { margin-top: 1; }
        #confirm-buttons Button { margin-right: 1; }
        .hint { color: $text-muted; }
        """

        BINDINGS = [
            Binding("ctrl+p", "palette", "Tasks"),
            Binding("ctrl+r", "refresh", "Refresh"),
            Binding("ctrl+d", "detail", "Detail"),
            Binding("ctrl+q", "quit", "Quit"),
        ]

        def __init__(self) -> None:
            super().__init__()
            self.findings: List[Dict[str, Any]] = []
            self.plan: List[Dict[str, Any]] = []
            self.report: Dict[str, Any] = {}
            self.report_meta: Dict[str, Any] = {}
            self.report_path: Optional[Path] = None

        # -- layout ----------------------------------------------------------
        def compose(self) -> ComposeResult:
            yield Header()
            with Horizontal(id="body"):
                with TabbedContent(id="tabs"):
                    with TabPane("Overview", id="tab-overview"):
                        yield Static("Loading…", id="overview")
                    with TabPane("Findings", id="tab-findings"):
                        yield DataTable(id="findings-table")
                    with TabPane("Run", id="tab-run"):
                        with Vertical(id="run-buttons"):
                            for name, verb in VERBS.items():
                                yield Button(
                                    f"{name} — {verb.summary}",
                                    id=f"run-{name}",
                                    variant="default",
                                )
                        yield RichLog(id="run-log", highlight=False, markup=False)
                    with TabPane("Write", id="tab-write"):
                        yield Static(
                            "No plan yet. Run plan-fix to preview the writes.",
                            id="write-status",
                            classes="hint",
                        )
                        with Horizontal(id="write-buttons"):
                            yield Button("Preview (plan-fix)", id="write-preview-plan",
                                         variant="primary")
                            yield Button("Show git diff", id="write-preview-diff",
                                         variant="default")
                            yield Button("Apply changes", id="write-apply", variant="error")
                        yield DataTable(id="plan-table")
                yield Static(
                    "[b]Detail[/b]\nSelect a finding or a planned write to inspect it here.",
                    id="detail",
                )
            yield Footer()

        def on_mount(self) -> None:
            findings_table = self.query_one("#findings-table", DataTable)
            findings_table.add_columns("Severity", "Category", "Coin", "ID", "File")
            findings_table.cursor_type = "row"
            plan_table = self.query_one("#plan-table", DataTable)
            plan_table.add_columns("Action", "File", "Key", "Old", "New", "Applied")
            plan_table.cursor_type = "row"
            # Deferred rather than run here: filling a DataTable posts
            # RowHighlighted for row 0, and that message must not overtake the
            # detail pane's own mount, which happens after the tables'.
            self.call_after_refresh(self.refresh_reports)

        # -- state -----------------------------------------------------------
        def refresh_reports(self) -> None:
            """Re-read the reports on disk. Never launches the audit itself."""
            self.report_path = best_fleet_report()
            self.report_meta = (
                read_meta_for(self.report_path)
                if self.report_path is not None
                else {}
            )
            self.report = {}
            if self.report_path is not None:
                try:
                    self.report = read_json(self.report_path)
                except DashboardError:
                    self.report = {}
            self.findings = list(self.report.get("findings") or [])
            plan_path = CACHE_ROOT / "plan-fix.json"
            self.plan = []
            if plan_path.is_file():
                try:
                    self.plan = list(read_json(plan_path).get("plan") or [])
                except DashboardError:
                    self.plan = []
            self.rebuild_overview()
            self.rebuild_findings()
            self.rebuild_write()

        def rebuild_overview(self) -> None:
            counts = build_counts(self.findings)
            summary = self.report.get("summary") or {}
            started = self.report_meta.get("started_at")
            age_txt = f"{time.time() - started:.0f}s ago" if started else "never"
            lines = [
                "[b]Fleet summary[/b]",
                f"  repos probed      {summary.get('repos_total', 0)}",
                f"  alive / dead      {summary.get('alive', 0)} / {summary.get('dead', 0)}",
                f"  moved / unknown   {summary.get('moved', 0)} / {summary.get('unknown', 0)}",
                f"  stale repos       {summary.get('stale', 0)}",
                "",
                "[b]Findings[/b]",
                f"  total             {counts['total']}",
            ]
            lines += [f"  {str(sev):<17} {n}" for sev, n in counts["by_severity"].items()]
            lines += [
                "",
                "[b]Report[/b]",
                f"  file              {self.report_path.name if self.report_path else '—'}",
                f"  last run          {age_txt}",
                f"  by verb           {self.report_meta.get('verb', '—')}",
                f"  planned writes    {len(self.plan)}",
                "",
                "Pick a task with Ctrl+P, or start one from the Run tab.",
            ]
            self.query_one("#overview", Static).update("\n".join(lines))

        def rebuild_findings(self) -> None:
            table = self.query_one("#findings-table", DataTable)
            table.clear()
            for i, f in enumerate(self.findings):
                table.add_row(
                    str(f.get("severity", "")),
                    str(f.get("category", "")),
                    str(f.get("coin") or ""),
                    str(f.get("id", "")),
                    str(f.get("file") or ""),
                    key=str(i),
                )

        def rebuild_write(self) -> None:
            table = self.query_one("#plan-table", DataTable)
            table.clear()
            status = self.query_one("#write-status", Static)
            if not self.plan:
                status.update("No plan yet. Run plan-fix to preview the writes.")
                status.add_class("hint")
                return
            applied = sum(1 for e in self.plan if e.get("applied"))
            status.update(
                f"{len(self.plan)} planned write(s), {applied} already applied. "
                "Show the git diff before applying."
            )
            status.remove_class("hint")
            for e in self.plan:
                table.add_row(
                    str(e.get("action", "")),
                    str(e.get("file", "")),
                    str(e.get("key", "")),
                    str(e.get("old"))[:60],
                    str(e.get("new"))[:60],
                    "yes" if e.get("applied") else "no",
                )

        # -- detail pane ------------------------------------------------------
        @on(DataTable.RowHighlighted, "#findings-table")
        def finding_highlighted(self, event: DataTable.RowHighlighted) -> None:
            row = self._row_index(event.row_key, len(self.findings))
            if row is not None:
                self.show_detail_finding(self.findings[row])

        @on(DataTable.RowHighlighted, "#plan-table")
        def plan_highlighted(self, event: DataTable.RowHighlighted) -> None:
            row = self._row_index(event.row_key, len(self.plan))
            if row is not None:
                self.show_detail_plan(self.plan[row])

        @staticmethod
        def _row_index(row_key, size: int) -> Optional[int]:
            if row_key is None or row_key.value is None:
                return None
            idx = str(row_key.value)
            if idx.isdigit() and int(idx) < size:
                return int(idx)
            return None

        def show_detail_finding(self, f: Dict[str, Any]) -> None:
            lines = [
                "[b]Finding[/b]",
                f"  severity  {f.get('severity')}",
                f"  category  {f.get('category')}",
                f"  coin      {f.get('coin')}",
                f"  ver_id    {f.get('ver_id')}",
                f"  id        {f.get('id')}",
                "",
                "[b]Detail[/b]",
                str(f.get("detail", "")),
                "",
                f"file: {f.get('file')}",
                f"line: {f.get('line')}",
            ]
            self.query_one("#detail", Static).update("\n".join(lines))

        def show_detail_plan(self, e: Dict[str, Any]) -> None:
            lines = [
                "[b]Planned write[/b]",
                f"  action    {e.get('action')}",
                f"  coin      {e.get('coin')}",
                f"  ver_id    {e.get('ver_id')}",
                "",
                f"file: {e.get('file')}",
                f"key:  {e.get('key')}",
                "",
                "[b]old[/b]",
                str(e.get("old")),
                "",
                "[b]new[/b]",
                str(e.get("new")),
                "",
                "[b]reason[/b]",
                str(e.get("reason")),
                "",
                f"evidence: {e.get('evidence')}",
                f"applied:  {e.get('applied')}",
            ]
            self.query_one("#detail", Static).update("\n".join(lines))

        # -- actions ---------------------------------------------------------
        def action_palette(self) -> None:
            def handle(result: Optional[str]) -> None:
                if result:
                    self.run_verb(result)

            self.push_screen(CommandPalette(VERBS), handle)

        def action_refresh(self) -> None:
            self.refresh_reports()

        def action_detail(self) -> None:
            self.query_one("#detail", Static).update(
                "[b]Detail[/b]\nSelect a finding or a planned write to inspect it here."
            )

        @on(Button.Pressed, "#write-preview-plan")
        def btn_preview_plan(self) -> None:
            self.run_verb("plan-fix")

        @on(Button.Pressed, "#write-preview-diff")
        def btn_preview_diff(self) -> None:
            self.show_git_diff()

        @on(Button.Pressed, "#write-apply")
        def btn_apply(self) -> None:
            self.confirm_apply()

        @on(Button.Pressed)
        def any_button(self, event: Button.Pressed) -> None:
            """Every Run-tab button is run-<verb>; the Write tab binds its own."""
            ident = event.button.id or ""
            if not ident.startswith("run-"):
                return
            name = ident[4:]
            if name in VERBS:
                self.run_verb(name)

        @work(exclusive=True, group="audit")
        async def run_verb(self, name: str) -> None:
            """Run a verb, streaming its console output into the Run tab."""
            if name not in VERBS:
                return
            log = self.query_one("#run-log", RichLog)
            opts = default_opts(name)
            try:
                argv = build_audit_argv(opts, [])
            except DashboardError as exc:
                log.write(f"ERROR: {exc}")
                return

            primary, _, log_path = report_paths(name, None)
            cmd = audit_command(argv, primary)
            log.write("$ " + " ".join(cmd))

            CACHE_ROOT.mkdir(parents=True, exist_ok=True)
            started_at = time.time()
            began = time.monotonic()
            lines: List[str] = []
            try:
                proc = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.STDOUT,
                )
            except OSError as exc:
                log.write(f"ERROR: could not launch the audit script: {exc}")
                return

            assert proc.stdout is not None
            while True:
                chunk = await proc.stdout.readline()
                if not chunk:
                    break
                line = chunk.decode("utf-8", "replace").rstrip("\n")
                lines.append(line)
                log.write(line)
            rc = await proc.wait()
            duration = time.monotonic() - began
            log_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

            if rc == 2:
                log.write(f"--- {name} failed rc=2, see {log_path} ---")
                return
            if primary.is_file():
                if primary != LAST_REPORT:
                    shutil.copyfile(primary, LAST_REPORT)
                write_last_run_meta(name, cmd, primary, log_path, started_at, duration, rc)
            log.write(f"--- {name} finished rc={rc} in {duration:.1f}s ---")
            self.refresh_reports()

        def confirm_apply(self) -> None:
            if not self.plan:
                self.query_one("#write-status", Static).update(
                    "Nothing to apply: run plan-fix first."
                )
                return
            files = sorted({str(e.get("file")) for e in self.plan})
            body = (
                f"{len(self.plan)} write(s) to {len(files)} file(s) in the working "
                "tree:\n\n  " + "\n  ".join(files[:12])
                + ("\n  …" if len(files) > 12 else "")
            )

            def handle(confirmed: Optional[bool]) -> None:
                if confirmed:
                    self.run_verb("apply-fix")

            self.push_screen(ConfirmScreen("Apply planned changes?", body), handle)

        def show_git_diff(self) -> None:
            """Show the real working-tree diff, so the preview is not a promise."""
            self.query_one("#tabs", TabbedContent).active = "tab-run"
            log = self.query_one("#run-log", RichLog)
            try:
                proc = subprocess.run(
                    ["git", "-C", str(REPO_ROOT), "diff", "--stat"],
                    capture_output=True, text=True, timeout=30,
                )
                stat = proc.stdout.strip() or "(working tree is clean)"
            except (OSError, subprocess.TimeoutExpired) as exc:
                stat = f"git diff failed: {exc}"
            log.write("--- git diff --stat ---")
            for line in stat.splitlines():
                log.write(line)

    # An instance, not the class: run_tui() calls app.run() with no
    # arguments, which is only valid once the app has been constructed.
    return DashboardApp()


if __name__ == "__main__":
    sys.exit(main())
