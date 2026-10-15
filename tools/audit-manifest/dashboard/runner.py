"""Subprocess mechanics: launch audit-manifest.py and capture its output.

This module knows nothing about verbs — it runs the command line it is
given; verb semantics (argv translation, envelope, exit codes, dispatch)
live in ``verbs``. What it does own is the child's environment and its
merged output stream: ``@@PROGRESS`` events are parsed here — an
independent implementation of the audit script's wire format, pinned by
tests on both sides, never by importing across the package boundary —
and surfaced as state on the ``LiveRun`` handle the TUI keeps.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import os
import subprocess
import sys
import time
from collections.abc import Sequence
from pathlib import Path
from typing import Any, Callable

from . import paths
from .paths import DashboardError

PROGRESS_PREFIX = "@@PROGRESS@@"

# How long a stopped child gets to exit on SIGTERM before it is killed.
_STOP_GRACE_SECONDS = 2.0


def audit_command(argv: Sequence[str], report_path: Path) -> list[str]:
    return [sys.executable, "-u", str(paths.AUDIT_SCRIPT), *argv, "--report", str(report_path)]


def wrap_command(cmd: Sequence[str], width: int) -> list[str]:
    tokens = [str(t) for t in cmd]
    if width <= 0:
        return ["$ " + " ".join(tokens)]
    lines: list[str] = []
    cur = "$ "
    for token in tokens:
        sep = "" if cur in ("$ ", "  ") else " "
        if len(cur) + len(sep) + len(token) <= width:
            cur = cur + sep + token
        else:
            if cur.strip():
                lines.append(cur)
            cur = "  " + token
    if cur.strip():
        lines.append(cur)
    return lines or ["$ " + " ".join(tokens)]


def child_env(verb: str | None = None) -> dict[str, str]:
    """The environment for an audit child, tagged with its verb.

    ``AUDIT_VERB`` is the only truthful channel for the task name: the
    audit side cannot derive it from flags (ports, cross-check and a
    local-only audit are flag-identical), and putting it in argv would
    perturb the report/envelope byte-compare. When no verb is named the
    variable is removed, so a stale value from this process's own
    environment cannot mislabel the child.
    """
    env = dict(os.environ)
    if verb:
        env["AUDIT_VERB"] = verb
    else:
        env.pop("AUDIT_VERB", None)
    return env


def parse_progress(line: str) -> dict[str, Any] | None:
    """Parse one ``@@PROGRESS@@`` line from the child's merged stream.

    Total by design: anything that is not a well-formed progress object —
    ordinary report lines, a truncated tail, a non-object payload — is
    "not an event" (``None``), never an error, so a mixed stream keeps
    flowing.
    """
    if not line.startswith(PROGRESS_PREFIX):
        return None
    try:
        payload = json.loads(line[len(PROGRESS_PREFIX) :].strip())
    except json.JSONDecodeError:
        return None
    return payload if isinstance(payload, dict) else None


def human_lines(lines: list[str]) -> list[str]:
    return [line for line in lines if not line.startswith(PROGRESS_PREFIX) or parse_progress(line) is None]


def run_audit(
    cmd: Sequence[str],
    log_path: Path,
    max_seconds: int = 0,
    verb: str | None = None,
) -> dict[str, Any]:
    """Run audit-manifest.py synchronously, capturing its full console output.

    No timeout by default: the audit script already bounds every network
    call it makes, and killing it mid-run would discard work the caller is
    about to read. ``max_seconds`` is an explicit opt-in for callers that
    would rather have a bounded failure than an unbounded wait. ``verb``
    tags the child's environment (see ``child_env``); it reaches the
    strip through the audit's own progress events, never the envelope
    or the report.
    """
    paths.CACHE_ROOT.mkdir(parents=True, exist_ok=True)
    started = time.monotonic()
    try:
        proc = subprocess.run(
            list(cmd),
            capture_output=True,
            text=True,
            timeout=max_seconds or None,
            env=child_env(verb),
            check=False,  # rc is reported to the caller, not raised here
        )
    except OSError as exc:
        raise DashboardError(f"could not launch {paths.AUDIT_SCRIPT.name}: {exc}") from exc
    except subprocess.TimeoutExpired as exc:
        raise DashboardError(f"the audit run exceeded {max_seconds}s (--max-seconds)") from exc

    duration = time.monotonic() - started
    out = proc.stdout or ""
    err = "".join(human_lines((proc.stderr or "").splitlines(keepends=True)))
    log_path.write_text(out + ("\n--- stderr ---\n" + err if err.strip() else ""), encoding="utf-8")
    print(
        f"[audit] rc={proc.returncode} in {duration:.1f}s log={log_path}",
        file=paths.LOG_STREAM,
    )
    return {"returncode": proc.returncode, "duration": duration, "log": str(log_path)}


def git_diff_stat() -> str:
    """``git diff --stat`` for the repo working tree, or a failure line."""
    try:
        proc = subprocess.run(
            ["git", "-C", str(paths.REPO_ROOT), "diff", "--stat"],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return f"git diff failed: {exc}"
    return proc.stdout.strip() or "(working tree is clean)"


class LiveRun:
    """Handle to one live audit child: full capture, phase state, stop.

    ``lines`` keeps every merged line — progress or not — for the strip;
    the log file keeps human lines. ``phase``/``event`` hold the latest
    parsed progress state for the UI. Call ``stop`` from a running event
    loop (it schedules the SIGKILL escalation).
    """

    def __init__(self, proc: asyncio.subprocess.Process) -> None:
        self.proc = proc
        self.lines: list[str] = []
        self.phase: str | None = None
        self._escalate_task: asyncio.Future[None] | None = None
        self.event: dict[str, Any] | None = None
        self.stopped = False

    def stop(self, *, announce: bool = True) -> None:
        """SIGTERM the child, escalating to SIGKILL past the grace period.

        Records the stop in the capture — unless ``announce=False``, for
        the worker's own orphan-reaping where "stopped by user" would be
        a lie. Idempotent; a no-op once the child has exited.
        """
        if self.stopped or self.proc.returncode is not None:
            return
        # The flag means "the user pressed Stop": the orphan-reaping call
        # (announce=False) terminates without claiming it.
        if announce:
            self.stopped = True
            self.lines.append("--- stopped by user ---\n")
        # returncode stays None until wait() is awaited, so a just-exited
        # child can still look alive here: never fail the reaping.
        with contextlib.suppress(ProcessLookupError):
            self.proc.terminate()
        # Keep a reference: an unreferenced task can be garbage-collected
        # before the SIGKILL escalation ever runs.
        self._escalate_task = asyncio.ensure_future(self._escalate())

    async def _escalate(self) -> None:
        try:
            await asyncio.wait_for(self.proc.wait(), _STOP_GRACE_SECONDS)
        except asyncio.TimeoutError:
            if self.proc.returncode is None:
                with contextlib.suppress(ProcessLookupError):
                    self.proc.kill()


async def spawn_audit(cmd: Sequence[str], verb: str | None = None) -> LiveRun:
    """Start audit-manifest.py with stdout+stderr merged into one stream.

    The merge is what makes ``@@PROGRESS@@`` lines arrive in the same
    pipe as the report: one ordered stream, one capture, no interleaving
    surprises between two file descriptors.
    """
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
            env=child_env(verb),
        )
    except OSError as exc:
        raise DashboardError(f"could not launch {paths.AUDIT_SCRIPT.name}: {exc}") from exc
    return LiveRun(proc)


async def stream_lines(
    run: LiveRun,
    on_line: Callable[[str], None] | None = None,
    on_progress: Callable[[dict[str, Any]], None] | None = None,
) -> int:
    """Drain the child's merged stream into the run's capture.

    Progress lines update ``run.phase``/``run.event`` and go to
    ``on_progress``; every other line goes to ``on_line`` (so machine
    lines never land in a human log view). Both callbacks are optional —
    the capture sees everything either way. Returns the child's exit
    code once the stream is done.
    """
    if run.proc.stdout is None:
        raise DashboardError("audit child has no piped stdout")
    while True:
        raw = await run.proc.stdout.readline()
        if not raw:
            break
        line = raw.decode("utf-8", "replace")
        run.lines.append(line)
        event = parse_progress(line)
        if event is not None:
            run.event = event
            # A phaseless event carries nothing to show: keep the last
            # known phase rather than wiping the strip.
            if event.get("phase") is not None:
                run.phase = event.get("phase")
            if on_progress is not None:
                on_progress(event)
        elif on_line is not None:
            on_line(line)
    return await run.proc.wait()
