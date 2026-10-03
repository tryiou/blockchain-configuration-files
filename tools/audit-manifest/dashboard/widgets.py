"""The Textual screens and the application itself.

This module imports Textual at module scope and must only be imported once
the TUI is actually starting (from ``app._make_app``); importing it on a
bare interpreter fails by design, which is what keeps every JSON verb
standard-library-only.
"""
from __future__ import annotations

import asyncio
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

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

from . import paths
from .paths import (
    DashboardError,
    best_fleet_report,
    read_json,
    read_meta_for,
    report_paths,
    write_last_run_meta,
)
from .runner import audit_command
from .verbs import VERBS, Verb, build_audit_argv, build_counts, default_opts


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
        plan_path = paths.CACHE_ROOT / "plan-fix.json"
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

        paths.CACHE_ROOT.mkdir(parents=True, exist_ok=True)
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
            if primary != paths.LAST_REPORT:
                shutil.copyfile(primary, paths.LAST_REPORT)
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
                ["git", "-C", str(paths.REPO_ROOT), "diff", "--stat"],
                capture_output=True, text=True, timeout=30,
            )
            stat = proc.stdout.strip() or "(working tree is clean)"
        except (OSError, subprocess.TimeoutExpired) as exc:
            stat = f"git diff failed: {exc}"
        log.write("--- git diff --stat ---")
        for line in stat.splitlines():
            log.write(line)
