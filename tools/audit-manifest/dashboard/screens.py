"""The two screens: pick the coin scope first, then work in the workspace.

The app opens on :class:`CoinsScreen`. The workspace underneath stays the
app's *default* screen, so ``app.query_one`` keeps reaching the tables
while the picker sits on top. Continue pops the picker; ``ctrl+o``
pushes it again.
"""

from __future__ import annotations

import contextlib
from pathlib import Path
from typing import Any, ClassVar

from rich.text import Text
from textual import on
from textual.app import ComposeResult, ScreenStackError
from textual.binding import Binding, BindingType
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.css.query import NoMatches
from textual.geometry import Size
from textual.screen import Screen
from textual.widgets import (
    Button,
    Checkbox,
    DataTable,
    Footer,
    Header,
    Input,
    RichLog,
    Static,
    TabbedContent,
    TabPane,
)

from . import paths
from .model import (
    _tags,
    _tickable,
    _worst_status,
    action_for,
    age_text,
    build_coin_rows,
    dict_list,
    filter_plan_to_scope,
    last_run_line,
    merge_fleet_findings,
    param_blob,
    pick_plan_source,
    pick_probe_report,
    resolve_plan_slot,
    resolve_slot_file,
    severity_rank,
    split_verdict,
    staged_open_entries,
    with_embedded_fallback,
)
from .paths import (
    DashboardError,
    fleet_extra_slots,
    fleet_report_slots,
    read_json,
)
from .verbs import BUTTON_ACTIONS, COST_LABELS, PALETTE_VERBS, build_counts, fleet_entries

# Severity → table-cell style, the same language as the detail pane's
# tokens (FAIL red, anything needing review yellow, the rest plain).
_SEV_STYLE = {"FAIL": "bold red", "REVIEW": "yellow", "UPGRADE": "yellow", "WARN": "yellow", "SKIP": "yellow"}


# Detail-card shaping: the key counts that separate a category card from
# a version card, the narrow-terminal width, below which layout adapts.
_MIN_CATEGORY_KEYS = 4
_MIN_VERSION_KEYS = 6
_NARROW_WIDTH = 160


def _sev_cell(severity: str) -> Text:
    """A styled Severity cell: color carries the rank, text stays exact."""
    return Text(str(severity), style=_SEV_STYLE.get(severity, ""))


class CoinsScreen(Screen):
    """Scope picker: every manifest coin, tick what the next task may touch.

    All-ticked (or fresh) persists as ``selection: null`` — the full
    fleet, no ``--ticker``. All / None / Invert act on the whole fleet,
    never the filtered view; Continue is the only commit, and it stays
    disabled at zero. Non-string tickers cannot be ticked and are
    skipped here.
    """

    def __init__(self) -> None:
        super().__init__()
        self.entries: list[dict[str, Any]] = [e for e in fleet_entries() if isinstance(e.get("ticker"), str)]
        findings = self._last_report_findings()
        self._status: dict[str, str] = {e["ticker"]: _worst_status(findings, e["ticker"]) for e in self.entries}

    BINDINGS: ClassVar[list[BindingType]] = [
        Binding("enter", "continue", "Continue"),
    ]

    def action_continue(self) -> None:
        """Enter continues like the Continue button (audit #3)."""
        if self.query_one("#coins-continue", Button).disabled:
            return
        self.app.action_continue()

    @on(Input.Submitted, "#coins-filter")
    def filter_submitted(self, event: Input.Submitted) -> None:
        """Enter in the filter continues too — the Input eats the key."""
        event.stop()
        self.action_continue()

    @staticmethod
    def _last_report_findings() -> list[dict[str, Any]]:
        """Findings of the merged fleet reports, for the status column."""
        rows, _summary = merge_fleet_findings(fleet_report_slots())
        return rows

    def compose(self) -> ComposeResult:
        yield Header()
        yield Static(
            "Tick coins to scope runs — filter only hides rows. "
            "All ticked = full fleet. Enter continues, Ctrl+O reopens.",
            id="coins-hint",
            classes="hint",
        )
        with Horizontal(id="coins-toolbar"):
            yield Input(
                placeholder="Filter display only — ticker or ver_id (does not scope runs)",
                id="coins-filter",
            )
            with Horizontal(id="coins-bulk"):
                yield Button("All", id="coins-all")
                yield Button("None", id="coins-none")
                yield Button("Invert", id="coins-invert")
        yield Static(
            "coin   conf · held tags · status",
            id="coins-columns",
            classes="hint",
        )
        with VerticalScroll(id="coins-list"):
            # Ids are row positions, never raw tickers: a ticker like
            # "A B" is no valid widget id, but the coin must still tick.
            for i, entry in enumerate(self.entries):
                ticker = entry["ticker"]
                with Horizontal(id=f"row-{i}", classes="coin-row"):
                    yield Checkbox(
                        ticker,
                        id=f"coin-{i}",
                        value=self._starts_ticked(ticker),
                    )
                    yield Static(self._info(entry), id=f"coin-info-{i}", classes="coin-info")
        with Horizontal(id="coins-footer"):
            yield Static("", id="coins-count")
            yield Button("Continue", id="coins-continue", variant="primary")
        yield Footer()

    def _starts_ticked(self, ticker: str) -> bool:
        selection = self.app.state.get("selection")
        return selection is None or ticker in selection

    def _info(self, entry: dict[str, Any]) -> str:
        versions_text = _tags(entry.get("versions"))
        status = self._status[entry["ticker"]]
        if status == "FAIL":
            token = f"[red]{status}[/]"
        elif status in ("WARN", "REVIEW", "UPGRADE", "SKIP"):
            token = f"[yellow]{status}[/]"
        else:
            token = status
        return f"{entry.get('ver_id') or '—'}   {versions_text}   {token}"

    def on_mount(self) -> None:
        # Re-applying is idempotent and covers Textual versions that do
        # not post Changed for a programmatic value.
        text = str(self.app.state.get("filter") or "")
        if text:
            self.query_one("#coins-filter", Input).value = text
        self._apply_filter(text)
        self._update_footer()

    @property
    def entry_count(self) -> int:
        return len(self.entries)

    def selected_tickers(self) -> list[str]:
        """The ticked tickers, fleet-wide — the filter never scopes a run."""
        ticked = []
        for cb in self.query("#coins-list Checkbox"):
            if cb.value and cb.id and cb.id.startswith("coin-"):
                ticked.append(self.entries[int(cb.id[len("coin-") :])]["ticker"])
        return ticked

    def _update_footer(self) -> None:
        checked = len(self.selected_tickers())
        if not self.entry_count:
            self.query_one("#coins-count", Static).update("No coins found in manifest-latest.json — fix the manifest")
            self.query_one("#coins-continue", Button).disabled = True
            return
        try:
            needle = str(self.query_one("#coins-filter", Input).value or "").strip()
        except NoMatches:
            needle = ""
        visible = checked
        with contextlib.suppress(NoMatches):
            visible = sum(1 for i in range(self.entry_count) if self.query_one(f"#row-{i}").display)
        if needle and visible == 0:
            self.query_one("#coins-count", Static).update(f"no coins match '{needle}' — clear the filter")
            self.query_one("#coins-continue", Button).disabled = checked == 0
            return
        if checked == 0:
            self.query_one("#coins-count", Static).update("Tick at least one coin to continue")
        elif checked == self.entry_count:
            self.query_one("#coins-count", Static).update(f"{checked} of {self.entry_count} ticked · full fleet")
        else:
            self.query_one("#coins-count", Static).update(f"{checked} of {self.entry_count} ticked")
        self.query_one("#coins-continue", Button).disabled = checked == 0

    def _apply_filter(self, text: str) -> None:
        needle = text.strip().lower()
        for i, entry in enumerate(self.entries):
            ticker = entry["ticker"]
            haystack = f"{ticker} {entry.get('ver_id') or ''}".lower()
            self.query_one(f"#row-{i}").display = not needle or needle in haystack
        self._update_footer()

    def _set_all(self, *, value: bool) -> None:
        for checkbox in self.query("#coins-list Checkbox"):
            checkbox.value = value
        self._update_footer()

    @on(Input.Changed, "#coins-filter")
    def filter_changed(self, event: Input.Changed) -> None:
        self.app.state["filter"] = event.value
        self._apply_filter(event.value)

    @on(Checkbox.Changed)
    def coin_toggled(self, event: Checkbox.Changed) -> None:
        if event.checkbox.id and event.checkbox.id.startswith("coin-"):
            self._update_footer()

    @on(Button.Pressed, "#coins-all")
    def all_pressed(self) -> None:
        self._set_all(value=True)

    @on(Button.Pressed, "#coins-none")
    def none_pressed(self) -> None:
        self._set_all(value=False)

    @on(Button.Pressed, "#coins-invert")
    def invert_pressed(self) -> None:
        for checkbox in self.query("#coins-list Checkbox"):
            checkbox.value = not checkbox.value
        self._update_footer()

    @on(Button.Pressed, "#coins-continue")
    def continue_pressed(self) -> None:
        self.app.action_continue()


def _fixed_plan_width(table: DataTable, keys: list, pad: int) -> int:
    """The non-flexible plan-column width budget (indices 0, 2, 5)."""
    return sum(
        2 * pad
        + (table.columns[keys[i]].content_width if table.columns[keys[i]].auto_width else table.columns[keys[i]].width)
        for i in (0, 2, 5)
    )


def _flex_plan_auto(table: DataTable, flex_cols: list, pad: int, fixed: int) -> None:
    """Expand flex columns to their natural width when the table has room."""
    changed = False
    for c in flex_cols:
        if not c.auto_width:
            c.auto_width = True
            changed = True
    if changed:
        total = fixed + sum(2 * pad + c.content_width for c in flex_cols)
        table.virtual_size = Size(total, table.virtual_size.height)
        table.refresh(layout=True)


def _flex_plan_shrink(table: DataTable, flex_cols: list, pad: int, fixed: int, avail: int) -> None:
    """Shrink flex columns into the available width, floor 6 per column."""
    budget = max(6, avail // 3 - 2 * pad)
    changed = False
    for c in flex_cols:
        want = max(min(c.content_width, budget), 6)
        if c.auto_width or c.width != want:
            c.width = want
            c.auto_width = False
            changed = True
    if changed:
        total = fixed + sum(2 * pad + c.width for c in flex_cols)
        table.virtual_size = Size(total, table.virtual_size.height)
        table.refresh(layout=True)


class WorkspaceScreen(Screen):
    """The workspace: owns the report data and every rendering of it.

    It is the app's default screen (see the module docstring), which is
    why app-level helpers reach its widgets through ``app.query_one``.
    """

    # Below this width the 48-col detail pane crushes the main column
    # (buttons truncate mid-phrase): the pane hides itself, and Ctrl+D
    # brings it back. A manual toggle always wins over later resizes.
    NARROW_COLS = 100
    LEDGER_ROWS = 17
    TASKS_ROWS = 15
    TABS_MIN = 10

    def __init__(self) -> None:
        super().__init__()
        self.findings: list[dict[str, Any]] = []
        # One row per coin for the Findings table + detail pane (built
        # from self.findings by build_coin_rows on every refresh).
        self.coins: list[dict[str, Any]] = []
        self.plan: list[dict[str, Any]] = []
        self.report: dict[str, Any] = {}
        self.report_meta: dict[str, Any] = {}
        self.report_path: Path | None = None
        # Merge provenance: sources[name] = {"total","shown","mtime"}.
        self.sources: dict[str, dict[str, Any]] = {}
        # Overview extras: ports/cross-check decoded slots.
        self.extras: dict[str, tuple] = {}
        # Per-coin param checks, keyed by ver_id (param-check.json blob).
        self.param_blob: dict[str, Any] = {}
        self.detail_auto = True

    def compose(self) -> ComposeResult:
        yield Header()
        with Horizontal(id="body"):
            with Vertical(id="main"):
                with VerticalScroll(id="overview-scroll"):
                    yield Static("Loading…", id="overview")
                with Vertical(id="task-groups"):
                    for aid in BUTTON_ACTIONS:
                        item = PALETTE_VERBS[aid]
                        yield Button(
                            f"\\[{COST_LABELS[item.cost]}] ▸ {aid} — {item.summary}",
                            id=f"act-{aid}",
                            variant="warning" if aid == "apply" else "default",
                        )
                with Horizontal(id="run-strip"):
                    yield Static("idle — pick a task (Ctrl+P)", id="run-phase")
                    yield Static("", id="run-elapsed")
                    yield Button("Stop", id="run-stop", variant="error", disabled=True)
                with TabbedContent(id="tabs"):
                    with TabPane("Findings", id="tab-findings"):
                        yield Static(
                            "No findings yet — run Analyze first.",
                            id="findings-status",
                            classes="hint",
                        )
                        yield DataTable(id="findings-table")
                    with TabPane("Plan", id="tab-plan"):
                        yield Static(
                            "No plan yet — run Plan to preview the writes.",
                            id="write-status",
                            classes="hint",
                        )
                        with Horizontal(id="write-buttons"):
                            yield Button("Preview (Plan)", id="write-preview-plan", variant="primary")
                            yield Button("Show git diff", id="write-preview-diff", variant="default")
                            yield Button("Apply changes", id="write-apply", variant="error")
                        yield DataTable(id="plan-table")
                    with TabPane("Log", id="tab-log"):
                        yield RichLog(id="run-log", highlight=False, markup=False, wrap=True)
            with VerticalScroll(id="detail-scroll"):
                yield Static(
                    "[b]Detail[/b]\nSelect a finding or a planned write to inspect it here.",
                    id="detail",
                )
        yield Footer()

    def on_mount(self) -> None:
        findings_table = self.query_one("#findings-table", DataTable)
        findings_table.add_columns("Severity", "Coin", "Change", "Reason")
        findings_table.cursor_type = "row"
        plan_table = self.query_one("#plan-table", DataTable)
        plan_table.add_columns("Action", "File", "Key", "Old", "New", "Applied")
        plan_table.cursor_type = "row"
        # Which row the detail pane shows ((kind, index) or None for the
        # hint): refresh validates it instead of leaving deleted text.
        self._detail: tuple | None = None
        # Deferred: filling a DataTable posts RowHighlighted for row 0,
        # which must not overtake the detail pane's own mount.
        self.query_one("#tabs", TabbedContent).active = f"tab-{self.app.state['tab']}"
        self.apply_narrow_default()
        self.apply_compact_default()
        # An untouched Log is a blank bordered box (audit #13): seed the
        # way in. Runs append below it; it never reads as run output.
        self.query_one("#run-log", RichLog).write("No output yet — pick a task (Ctrl+P)")
        self.call_after_refresh(self.refresh_reports)

    def apply_narrow_default(self) -> None:
        """Hide the detail pane on narrow terminals until asked for.

        Sticky by design: widening again does not restore the pane —
        Ctrl+D does. A hidden pane the operator never asked about is a
        surprise; a reappearing one after they arranged without it is too.
        """
        try:
            narrow = self.app.screen.size.width <= self.NARROW_COLS
        except Exception:
            return
        if narrow:
            self.query_one("#detail-scroll", VerticalScroll).display = False

    def apply_compact_default(self) -> None:
        try:
            h = self.app.screen.size.height
        except ScreenStackError:
            return
        compact = h - self.LEDGER_ROWS - self.TASKS_ROWS < self.TABS_MIN
        with contextlib.suppress(NoMatches):
            self.query_one("#overview-scroll", VerticalScroll).set_class(compact, "compact")
        try:
            body = h - 5
            ledger = max(6, min(self.LEDGER_ROWS, body * 18 // 100))
            tasks = max(6, min(self.TASKS_ROWS, body * 22 // 100))
            if compact:
                ledger = 5
            self.query_one("#overview-scroll", VerticalScroll).styles.max_height = ledger
            self.query_one("#task-groups").styles.max_height = tasks
        except NoMatches:
            pass

    def fit_detail(self) -> None:
        try:
            w = self.app.screen.size.width
        except ScreenStackError:
            return
        with contextlib.suppress(NoMatches):
            self.query_one("#detail-scroll", VerticalScroll).styles.width = min(48, max(24, w - 56))

    def _flex_findings(self) -> None:
        try:
            table = self.query_one("#findings-table", DataTable)
        except NoMatches:
            return
        try:
            keys = list(table.columns.keys())
            if len(keys) < _MIN_CATEGORY_KEYS:
                return
            if self.app.screen.size.width <= _NARROW_WIDTH:
                last = table.columns[keys[3]]
                if not last.auto_width:
                    last.auto_width = True
                    table.refresh(layout=True)
                return
            w = table.region.width
            if w <= 0:
                return
            fixed = sum(table.columns[k].width for k in keys[:3])
            last = table.columns[keys[3]]
            need = w - fixed - 10
            want = max(last.content_width, need)
            if want != last.width or last.auto_width:
                last.width = want
                last.auto_width = False
                table.refresh(layout=True)
        except NoMatches:
            pass

    def _flex_plan(self) -> None:
        try:
            table = self.query_one("#plan-table", DataTable)
        except Exception:
            return
        try:
            keys = list(table.columns.keys())
            if len(keys) < _MIN_VERSION_KEYS:
                return
            w = table.region.width
            if w <= 0:
                return
            pad = table.cell_padding
            fixed = _fixed_plan_width(table, keys, pad)
            flex_cols = [table.columns[keys[i]] for i in (1, 3, 4)]
            natural = fixed + sum(2 * pad + (c.content_width if c.auto_width else c.width) for c in flex_cols)
            if natural <= w:
                _flex_plan_auto(table, flex_cols, pad, fixed)
                return
            _flex_plan_shrink(table, flex_cols, pad, fixed, w - fixed - 4)
        except NoMatches:
            pass

    def on_resize(self, _event) -> None:
        if self.detail_auto:
            self.apply_narrow_default()
        self.apply_compact_default()
        self.fit_detail()
        self._flex_findings()
        self._flex_plan()

    @on(TabbedContent.TabActivated, "#tabs")
    def tab_activated(self, _event: TabbedContent.TabActivated) -> None:
        active = self.query_one("#tabs", TabbedContent).active
        if active.startswith("tab-"):
            self.app.state["tab"] = active[len("tab-") :]
        # Switching tabs must show the visible table's row: highlights
        # only fire on cursor moves, so without this the pane keeps the
        # other tab's text (or the hint) after a switch.
        if active == "tab-findings" and self.coins:
            row = self.query_one("#findings-table", DataTable).cursor_row
            if 0 <= row < len(self.coins):
                self._detail = ("finding", row)
                self.show_detail_coin(self.coins[row])
        elif active == "tab-plan" and self.plan:
            row = self.query_one("#plan-table", DataTable).cursor_row
            if 0 <= row < len(self.plan):
                self._detail = ("plan", row)
                self.show_detail_plan(self.plan[row])
            self._flex_plan()
        try:
            target = {
                "tab-findings": "#findings-table",
                "tab-plan": "#plan-table",
                "tab-log": "#run-log",
            }.get(active, "#tabs")
            widget = self.query_one(target)
            if widget.display and widget.region:
                widget.scroll_visible(animate=False, immediate=True)
        except NoMatches:
            pass

    # -- state -----------------------------------------------------------
    def refresh_reports(self) -> None:
        """Re-read the reports on disk. Never launches the audit itself."""
        slots = fleet_report_slots()
        self.findings, self.sources = merge_fleet_findings(slots)
        self.coins = build_coin_rows(self.findings)
        pick = pick_probe_report(slots)
        if pick is not None:
            name, self.report, _mtime, self.report_meta = pick
            self.report_path = paths.CACHE_ROOT / name
        else:
            self.report_path = None
            self.report_meta = {}
            self.report = {}
        self.param_blob = param_blob(slots)
        self.extras = with_embedded_fallback(fleet_extra_slots(), slots)
        selection = self.app.state.get("selection")
        tickable = _tickable(fleet_entries())
        plan_path, scoped, live = resolve_plan_slot(selection, tickable, paths.CACHE_ROOT)
        plan_path = pick_plan_source(plan_path, paths.CACHE_ROOT / "plan-fix.apply.json") or plan_path
        self.plan = []
        if plan_path.is_file():
            try:
                payload = read_json(plan_path)
            except DashboardError:
                payload = {}
            self.plan = dict_list(payload, "plan") if isinstance(payload, dict) else []
        self.plan = filter_plan_to_scope(self.plan, live, scoped=scoped)
        delist_path, delist_scoped, delist_live = resolve_slot_file(
            selection, tickable, paths.CACHE_ROOT, "delist.scoped.json", "delist.json"
        )
        for slot_path, scope_filter in (
            (paths.CACHE_ROOT / "scaffold.json", None),
            (delist_path, (delist_live, delist_scoped)),
        ):
            if slot_path.is_file():
                try:
                    slot_payload = read_json(slot_path)
                except DashboardError:
                    slot_payload = {}
                staged = staged_open_entries(slot_payload)
                if scope_filter is not None:
                    staged = filter_plan_to_scope(staged, scope_filter[0], scoped=scope_filter[1])
                self.plan = self.plan + staged
        self.rebuild_overview()
        self.rebuild_findings()
        self.rebuild_write()
        if self._detail is not None:
            kind, idx = self._detail
            rows = self.coins if kind == "finding" else self.plan
            if idx >= len(rows):
                # The highlighted row is gone: never show deleted text.
                self.reset_detail()

    def rebuild_overview(self) -> None:
        counts = build_counts(self.findings)
        summary = self.report.get("summary")
        if not isinstance(summary, dict):
            summary = {}
        started = self.report_meta.get("started_at")
        age_txt = age_text(started)
        selection = self.app.state.get("selection")
        if selection is None:
            # Full fleet — but only when a fleet exists. Fresh state over
            # an empty (broken) manifest is empty, never full.
            tickable = [e for e in fleet_entries() if isinstance(e.get("ticker"), str)]
            scope_txt = "full fleet" if tickable else "0 of 0 coins"
        else:
            # Same live count as the confirm dialogs: a delisted ticker
            # — or an explicit-full-list scope from an older state file —
            # must inflate neither number.
            tickable = [e for e in fleet_entries() if isinstance(e.get("ticker"), str)]
            fleet = {e["ticker"] for e in tickable}
            live = sorted({t for t in selection if t in fleet})
            scope_txt = "full fleet" if fleet and set(live) == fleet else f"{len(live)} of {len(tickable)} coins"
        lines = [
            "[b]Status[/b]",
            f"  scope             {scope_txt}",
            f"  last run          {self._last_run_text(age_txt)}",
            f"  planned writes    {len(self.plan)}",
            f"  sources           {self._source_names_text()}",
            "",
            "[b]Fleet summary[/b]",
            f"  repos probed {summary.get('repos_total', 0)} · "
            f"alive {summary.get('alive', 0)} / dead {summary.get('dead', 0)} · "
            f"stale {summary.get('stale', 0)}",
            f"  moved {summary.get('moved', 0)} / unknown {summary.get('unknown', 0)}",
            "",
            "[b]Findings[/b]",
            f"  total             {counts['total']}",
        ]
        lines += [f"  {sev!s:<17} {n}" for sev, n in counts["by_severity"].items()]
        lines += self._source_lines()
        lines += [
            "",
            "[b]Report[/b]",
            f"  file              {self.report_path.name if self.report_path else '—'}",
            f"  fleet             {age_txt} · by {self.report_meta.get('verb', '—')}",
            "",
            "Pick a task with Ctrl+P, or start one from the task groups.",
        ]
        self.query_one("#overview", Static).update("\n".join(lines))

    def _source_names_text(self) -> str:
        seen = [s for s in ("findings", "audit", "param-check") if f"{s}.json" in self.sources]
        seen += [s for s in ("ports", "cross-check") if f"{s}.json" in self.extras]
        return ", ".join(seen) if seen else "—"

    def _source_lines(self) -> list[str]:
        """One ledger line per fleet datum: finding slots with their row
        counts and ages, then the ports/cross-check blobs. Each datum has
        exactly one home — nothing is duplicated, missing slots leave no
        line (never a None or a zeroed phantom)."""
        lines = ["", "[b]Sources[/b]"]
        for name in ("findings.json", "audit.json", "param-check.json"):
            info = self.sources.get(name)
            if info is None:
                continue
            total = info["total"]
            noun = "finding" if total == 1 else "findings"
            lines.append(f"  {name:<15} {total} {noun} · {age_text(info['mtime'])}")
        if "ports.json" in self.extras:
            ports, _mtime, ports_meta = self.extras["ports.json"]
            collisions = ports.get("port_collisions")
            if isinstance(collisions, dict) and collisions:
                shown_ports = ", ".join(sorted(str(p) for p in collisions)[:4])
                lines.append(
                    f"  ports.json      {len(collisions)} collision(s) "
                    f"(port {shown_ports}) · {age_text(ports_meta.get('started_at'))}"
                )
            else:
                lines.append(f"  ports.json      no collisions · {age_text(ports_meta.get('started_at'))}")
        if "cross-check.json" in self.extras:
            cross, _mtime, cross_meta = self.extras["cross-check.json"]
            local = cross.get("local")
            if isinstance(local, dict):
                missing = sum(
                    len(entries)
                    for key in ("missing_wallet_conf", "missing_xbridge_conf", "missing_base_j2")
                    for entries in [local.get(key)]
                    if isinstance(entries, list)
                )
                orphans = local.get("orphans")
                orphaned = (
                    sum(len(entries) for entries in orphans.values() if isinstance(entries, list))
                    if isinstance(orphans, dict)
                    else 0
                )
                if missing or orphaned:
                    lines.append(
                        f"  cross-check.json missing {missing} · orphans {orphaned} "
                        f"· {age_text(cross_meta.get('started_at'))}"
                    )
                else:
                    lines.append(f"  cross-check.json clean · {age_text(cross_meta.get('started_at'))}")
        # a detail card needs more than its header before it renders
        return lines if len(lines) > 2 else []  # noqa: PLR2004

    def _last_run_text(self, age_txt: str) -> str:
        """The last-run row, never contradicting the fleet row above it.

        Meta absent + fleet report present (deleted sidecar, foreign
        cache) used to print "never" next to a fresh fleet age — two
        "last run" answers disagreeing on one screen.
        """
        line = last_run_line()
        if line != "never":
            return line
        if self.report_path is not None:
            return f"no run recorded — showing {self.report_path.name} ({age_txt})"
        return "never"

    def rebuild_findings(self) -> None:
        table = self.query_one("#findings-table", DataTable)
        table.clear()
        status = self.query_one("#findings-status", Static)
        if not self.coins:
            status.update("No findings yet — run Analyze first.")
            status.add_class("hint")
        else:
            names = sorted(name for name, info in self.sources.items() if info["shown"])
            status.update(f"{len(self.coins)} coin(s), worst first · from {', '.join(names)} · red FAIL, yellow review")
            status.remove_class("hint")
        for i, coin in enumerate(self.coins):
            table.add_row(
                _sev_cell(coin["severity"]),
                coin["coin"],
                coin["change"],
                coin["reason"],
                key=str(i),
            )
        self._flex_findings()

    def rebuild_write(self) -> None:
        table = self.query_one("#plan-table", DataTable)
        table.clear()
        status = self.query_one("#write-status", Static)
        # Dead buttons disable instead of scolding: a button that looks
        # live and then refuses is a trap next to a red Apply. The diff
        # button stays live — it reports on the working tree, not the plan.
        for btn in ("#write-preview-plan", "#write-apply"):
            self.query_one(btn, Button).disabled = not self.plan
        if not self.plan:
            scoped = self.app.state.get("selection") is not None
            status.update(
                "No plan under this scope — run Plan under this scope first."
                if scoped
                else "No plan yet — run Plan to preview the writes."
            )
            status.add_class("hint")
            return
        applied = sum(1 for e in self.plan if e.get("applied"))
        status.update(
            f"{len(self.plan)} planned write(s), {applied} already applied. Show the git diff before applying."
        )
        status.remove_class("hint")
        for i, e in enumerate(self.plan):
            old, new = e.get("old"), e.get("new")
            table.add_row(
                str(e.get("action", "")),
                str(e.get("file", "")),
                str(e.get("key", "")),
                # Null bounds are not the text "None" (the detail pane
                # omits nulls; a table cell shows the dash instead).
                str(old)[:60] if old is not None else "—",
                str(new)[:60] if new is not None else "—",
                "yes" if e.get("applied") else "no",
                key=str(i),
            )
        self._flex_plan()

    # -- detail pane ------------------------------------------------------
    @on(DataTable.RowHighlighted, "#findings-table")
    def finding_highlighted(self, event: DataTable.RowHighlighted) -> None:
        if self.query_one("#tabs", TabbedContent).active != "tab-findings":
            # The hidden table's refill must not author the detail pane.
            return
        row = self._row_index(event.row_key, len(self.coins))
        if row is not None:
            self._detail = ("finding", row)
            self.show_detail_coin(self.coins[row])

    @on(DataTable.RowHighlighted, "#plan-table")
    def plan_highlighted(self, event: DataTable.RowHighlighted) -> None:
        if self.query_one("#tabs", TabbedContent).active != "tab-plan":
            return
        row = self._row_index(event.row_key, len(self.plan))
        if row is not None:
            self._detail = ("plan", row)
            self.show_detail_plan(self.plan[row])

    @staticmethod
    def _row_index(row_key, size: int) -> int | None:
        if row_key is None or row_key.value is None:
            return None
        idx = str(row_key.value)
        if idx.isdigit() and int(idx) < size:
            return int(idx)
        return None

    def reset_detail(self) -> None:
        self._detail = None
        self.query_one("#detail", Static).update(
            "[b]Detail[/b]\nSelect a finding or a planned write to inspect it here."
        )

    # Statuses that need a human: everything else passing is a count,
    # never listed content. SKIP is absence of signal — it rides the
    # clear line with its id, never an attention entry (D27).
    _ATTENTION = ("FAIL", "WARN", "UNRESOLVED")
    _SEV_COLOR: ClassVar[dict[str, str]] = {
        "FAIL": "red",
        "WARN": "yellow",
        "SKIP": "yellow",
        "REVIEW": "yellow",
        "UPGRADE": "yellow",
    }

    @staticmethod
    def _status_token(status: str) -> str:
        color = WorkspaceScreen._SEV_COLOR.get(status or "")
        return f"[{color}]{status}[/]" if color else str(status or "?")

    @staticmethod
    def _verdict(detail: Any, severity: str) -> tuple:
        """Split a check text into (verdict, dim evidence) — see
        :func:`split_verdict`, the single implementation."""
        return split_verdict(detail, severity)

    def show_detail_coin(self, coin: dict[str, Any]) -> None:
        """The coin's verdict card: header verdict, attention entries,
        planned pointer, passing count. Budgets: header 1 line, each
        problem 2 (verdict + dim evidence), passes 1 line, pointer 1.
        A finding and its blob check merge on (id, ver_id) — one check
        renders once, finding text wins, blob adds only its source-ref.
        """
        ver_ids = []
        for row in coin["rows"]:
            ver_id = row.get("ver_id")
            if isinstance(ver_id, str) and ver_id not in ver_ids:
                ver_ids.append(ver_id)
        conf = ver_ids[0] if ver_ids else "—"
        count = coin["count"]
        noun = "finding" if count == 1 else "findings"
        lines = [
            f"[b]{coin['coin']} — {self._status_token(coin['severity'])} · {count} {noun} · {conf}[/]",
        ]
        attention, clear, skipped = self._attention_rows(coin, ver_ids)
        lines.extend(self._render_attention(attention))
        lines.extend(self._version_ride(coin, conf))
        lines.extend(self._footer_lines(coin, attention, clear, skipped))
        self.query_one("#detail", Static).update("\n".join(lines))

    def _attention_rows(self, coin: dict[str, Any], ver_ids: list[str]) -> tuple[list[tuple[Any, ...]], int, list[str]]:
        """Every check worth attention, merged finding-first, worst first.

        Findings (``coin["rows"]``) keep their ``(id, ver_id)`` slot — a
        blob check only fills slots no finding took, so one check renders
        once and finding text wins. The single blob pass also counts the
        passing checks and the no-signal ones, so the card never walks
        the blob twice. Rows carry
        ``(rank, status, id, ver_id, detail, file, line)``.
        """
        seen: set[tuple[Any, Any]] = set()
        attention: list[tuple[Any, ...]] = []
        for row in coin["rows"]:
            key = (row.get("id"), row.get("ver_id"))
            seen.add(key)
            attention.append(
                (
                    severity_rank(row.get("severity")),
                    str(row.get("severity") or "?"),
                    str(row.get("id") or "—"),
                    row.get("ver_id"),
                    str(row.get("detail") or ""),
                    row.get("file"),
                    row.get("line"),
                )
            )
        clear = 0
        skipped: list[str] = []
        for ver_id in ver_ids:
            entry = self.param_blob.get(ver_id)
            checks = entry.get("checks") if isinstance(entry, dict) else None
            if not isinstance(checks, list):
                continue
            for check in checks:
                if not isinstance(check, dict):
                    continue
                status = str(check.get("status") or "?")
                if (check.get("id"), ver_id) in seen:
                    continue
                if status in self._ATTENTION:
                    attention.append(
                        (
                            severity_rank(status),
                            status,
                            str(check.get("id") or "—"),
                            ver_id,
                            str(check.get("detail") or ""),
                            None,
                            None,
                        )
                    )
                elif status == "SKIP":
                    skipped.append(str(check.get("id") or "—"))
                elif status not in self._ATTENTION:
                    clear += 1
        attention.sort(key=lambda e: (e[0], e[2]))
        return attention, clear, skipped

    def _render_attention(self, attention: list[tuple[Any, ...]]) -> list[str]:
        """Two budgeted lines per problem: verdict, then dim action/evidence."""
        lines: list[str] = []
        for _rank, status, check_id, _ver, detail, file, line in attention:
            verdict, evidence = self._verdict(detail, status)
            if file is not None:
                evidence = f"{evidence} · file: {file}".strip(" ·") if evidence else f"file: {file}"
            if line is not None:
                evidence = f"{evidence} · line: {line}".strip(" ·") if evidence else f"line: {line}"
            lines.append(f"  {self._status_token(status)} {check_id} — {verdict}")
            action = action_for(check_id, status, detail)
            dim = f"→ {action}"
            if evidence:
                dim += f" · {evidence}"
            lines.append(f"    [dim]{dim}[/]")
        return lines

    def _version_ride(self, coin: dict[str, Any], conf: str) -> list[str]:
        """Hold vs upstream rides the coin card (D28) — its only renderer."""
        version = coin.get("version")
        versions = version.get("versions") if isinstance(version, dict) else None
        if not (isinstance(versions, dict) and versions):
            return []
        ours = versions.get("our_latest") or "—"
        remote = versions.get("remote_latest") or "—"
        vline = f"Version — we hold {ours} → upstream {remote}"
        newer = versions.get("newer_same")
        if isinstance(newer, list) and newer:
            vline += f" · newer same: {', '.join(str(v) for v in newer)}"
        vconf = version.get("ver_id") if isinstance(version, dict) else None
        if isinstance(vconf, str) and vconf != conf:
            # Multi-conf coin: this line reads another group's data —
            # say so, or it masquerades as the header's conf (R11).
            vline += f" · conf {vconf}"
        return [f"  [dim]{vline}[/]"]

    def _footer_lines(
        self,
        coin: dict[str, Any],
        attention: list[tuple[Any, ...]],
        clear: int,
        skipped: list[str],
    ) -> list[str]:
        """Planned-write pointer, pass count, skipped count — in that order."""
        lines: list[str] = []
        planned = sum(1 for e in self.plan if isinstance(e, dict) and e.get("coin") == coin["coin"])
        if planned:
            noun = "write" if planned == 1 else "writes"
            lines.append(f"  {planned} planned {noun} for {coin['coin']} — see Plan tab")
        elif any(status in ("FAIL", "WARN") for _, status, _, _, _, _, _ in attention):
            lines.append("  run Plan to preview writes")
        if clear:
            lines.append(f"  [dim]All clear — {clear} checks pass[/]")
        if skipped:
            ids = ", ".join(sorted(set(skipped)))
            n = len(skipped)
            noun = "check" if n == 1 else "checks"
            lines.append(f"  [dim]{n} skipped ({ids}) — no signal, not a problem[/]")
        return lines

    def show_detail_plan(self, e: dict[str, Any]) -> None:
        old, new = e.get("old"), e.get("new")
        lines = [
            "[b]Planned write[/b]",
            f"  action    {e.get('action')}",
            f"  coin      {e.get('coin')}",
        ]
        if e.get("ver_id"):
            lines.append(f"  conf      {e.get('ver_id')}")
        lines.append("")
        if e.get("file") is not None:
            lines.append(f"file: {e.get('file')}")
        if e.get("key") is not None:
            lines.append(f"key:  {e.get('key')}")
        lines += [
            "",
            "[b]old[/b]",
            # Null bounds are the dash, like the table cells — never
            # the string "None".
            str(old) if old is not None else "—",
            "",
            "[b]new[/b]",
            str(new) if new is not None else "—",
            "",
            "[b]reason[/b]",
            # A missing reason is the dash, never the string "None".
            str(e.get("reason")) if e.get("reason") is not None else "—",
            "",
            # Matches the table cell ("yes"/"no"), never Python True/False.
            f"evidence: {e.get('evidence') or '—'}",
            f"applied:  {'yes' if e.get('applied') else 'no'}",
        ]
        if isinstance(e.get("contents"), str):
            lines += ["", "[b]staged contents[/b]"]
            lines += [line.replace("[", "\\[") for line in e["contents"].splitlines()]
        if isinstance(e.get("snippet"), dict):
            lines += ["", "[b]staged manifest entry[/b]"]
            for k, v in e["snippet"].items():
                lines.append("  " + str(k) + ": " + str(v).replace("[", "\\["))
        self.query_one("#detail", Static).update("\n".join(lines))
