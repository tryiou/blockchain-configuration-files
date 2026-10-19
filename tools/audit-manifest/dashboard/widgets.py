"""The Textual application: the screen stack, the modals, the audit worker.

This module imports Textual at module scope and must only be imported once
the TUI is actually starting (from ``app._make_app``); importing it on a
bare interpreter fails by design, which is what keeps every JSON verb
standard-library-only.

The screen trees live in ``screens``; this module owns the app-level
glue: the screen stack (coins first, workspace underneath), the scope
decision (persisted selection → ``--ticker``), the confirm gates, and
the worker that runs a task and streams its output.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import shutil
import time
from pathlib import Path
from typing import Any, ClassVar, Optional

from textual import on, work
from textual.app import App, ComposeResult
from textual.binding import Binding, BindingType
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.screen import ModalScreen
from textual.widgets import (
    Button,
    Input,
    Label,
    OptionList,
    RichLog,
    Static,
    TabbedContent,
)
from textual.widgets.option_list import Option

# Module import, not names: tests point ``runner.audit_command`` at a
# recorder without touching the process table.
from . import paths, runner, state
from .model import (
    _FINDINGS_VERBS,
    _PLAN_VERBS,
    _finish_line,
    _strip_note,
    _tags,
    _tickable,
    apply_files,
    newest_probe_slot,
    scope_text,
    scoped_subset_for_apply,
    split_scope,
)
from .paths import DashboardError, read_last_run_meta, report_paths, write_last_run_meta
from .screens import CoinsScreen, WorkspaceScreen
from .verbs import (
    ACTION_RUN,
    COST_LABELS,
    PALETTE_VERBS,
    VERBS,
    Verb,
    build_audit_argv,
    default_opts,
    fleet_entries,
    parse_github_repo_url,
)

# Dialog/log shaping: how many tickers a scope preview names, how many
# files a summary lists, and the audit script's usage-error exit code.
_MAX_SCOPE_PREVIEW = 8
_MAX_FILE_PREVIEW = 12
_EXIT_USAGE = 2


class ConfirmScreen(ModalScreen[bool]):
    """Blocks the app until a scoped action into the working tree is confirmed.

    Red is reserved for writes: ``danger=True`` (apply, update-versions)
    renders Run as error-red; read-only confirms use primary so a safe
    preview never teaches users to ignore red. Cancel is always neutral.
    """

    def __init__(
        self,
        title: str,
        body: str,
        action: str = "Apply",
        *,
        danger: bool = False,
    ) -> None:
        super().__init__()
        self._title = title
        self._body = body
        self._action = action
        self._danger = danger

    def compose(self) -> ComposeResult:
        with Vertical(id="confirm-box", classes="danger" if self._danger else ""):
            yield Label(self._title, id="confirm-title", classes="danger" if self._danger else "")
            yield Static(self._body, id="confirm-body")
            with Horizontal(id="confirm-buttons"):
                yield Button(
                    self._action,
                    variant="error" if self._danger else "primary",
                    id="confirm-yes",
                )
                yield Button("Cancel", variant="default", id="confirm-no")

    def on_mount(self) -> None:
        # D29: Enter is always the safe exit — Cancel is focused on every
        # confirm, so a write needs an explicit Tab/click, never one keypress.
        self.query_one("#confirm-no", Button).focus()

    @on(Button.Pressed, "#confirm-yes")
    def yes(self) -> None:
        self.dismiss(True)  # noqa: FBT003  # modal result payload, positional by Textual's dismiss() API

    @on(Button.Pressed, "#confirm-no")
    def no(self) -> None:
        self.dismiss(False)  # noqa: FBT003  # modal result payload, positional by Textual's dismiss() API

    def on_key(self, event) -> None:
        if event.key == "escape":
            self.dismiss(False)  # noqa: FBT003  # modal result payload, positional by Textual's dismiss() API


class ScaffoldDialog(ModalScreen[Optional[str]]):
    """Ask for the coin's GitHub URL in-TUI (D21): no task may launch-to-fail."""

    def compose(self) -> ComposeResult:
        with Vertical(id="scaffold-box"):
            yield Label("New coin from a GitHub URL", id="scaffold-title")
            yield Static(
                "HTTPS GitHub repo URL, e.g. https://github.com/<org>/<coin>-core",
                id="scaffold-hint",
                classes="hint",
            )
            yield Input(
                placeholder="https://github.com/<org>/<repo>",
                id="scaffold-input",
            )
            yield Static("", id="scaffold-status")
            with Horizontal(id="scaffold-buttons"):
                yield Button("Run", variant="primary", id="scaffold-yes")
                yield Button("Cancel", variant="default", id="scaffold-no")

    def on_mount(self) -> None:
        self.query_one("#scaffold-input", Input).focus()

    @on(Button.Pressed, "#scaffold-yes")
    def yes(self) -> None:
        raw = self.query_one("#scaffold-input", Input).value
        url = parse_github_repo_url(raw)
        if url is None:
            self.query_one("#scaffold-status", Static).update(
                "ERROR: need https://github.com/<org>/<repo> — nothing was launched"
            )
            return
        self.dismiss(url)

    @on(Button.Pressed, "#scaffold-no")
    def no(self) -> None:
        self.dismiss(None)

    @on(Input.Submitted, "#scaffold-input")
    def submitted(self, _event: Input.Submitted) -> None:
        self.yes()

    def on_key(self, event) -> None:
        if event.key == "escape":
            self.dismiss(None)


class CommandPalette(ModalScreen[Optional[str]]):
    """Ctrl+P: pick a task by name. Escape dismisses without running."""

    def __init__(self, verbs: dict[str, Verb]) -> None:
        super().__init__()
        self._verbs = verbs

    def _matches(self, needle: str) -> list[str]:
        """Case-insensitive substring over names and summaries, in verb order."""
        n = needle.strip().lower()
        if not n:
            return list(self._verbs)
        return [name for name, verb in self._verbs.items() if n in name.lower() or n in verb.summary.lower()]

    def _rebuild_list(self, names: list[str]) -> None:
        lst = self.query_one("#palette-list", OptionList)
        lst.clear_options()
        for name in names:
            verb = self._verbs[name]
            lst.add_option(
                Option(
                    f"\\[{COST_LABELS[verb.cost]}] {verb.name} — {verb.summary}",
                    verb.name,
                )
            )

    def compose(self) -> ComposeResult:
        with Vertical(classes="palette-box"):
            yield Input(placeholder="Run a task…", id="palette-input")
            yield Static(
                f"{len(self._verbs)} tasks — type to filter · Enter runs, Esc cancels",
                id="palette-status",
                classes="hint",
            )
            yield OptionList(
                *[
                    Option(
                        f"\\[{COST_LABELS[v.cost]}] {v.name} — {v.summary}",
                        v.name,
                    )
                    for v in self._verbs.values()
                ],
                id="palette-list",
            )

    def on_mount(self) -> None:
        self.query_one("#palette-input", Input).focus()

    @on(Input.Changed, "#palette-input")
    def filter_changed(self, event: Input.Changed) -> None:
        value = event.value.strip()
        keys = " · Enter runs, Esc cancels"
        matches = self._matches(value)
        self._rebuild_list(matches)
        if not value:
            text = f"{len(self._verbs)} tasks — type to filter{keys}"
        else:
            lowered = value.lower()
            exact = [n for n in self._verbs if n.lower() == lowered]
            if exact:
                text = f"exact match: {exact[0]} — Enter runs it, Esc cancels"
            elif not matches:
                text = f"no match{keys}"
            elif len(matches) == 1:
                text = f"1 match: {matches[0]} — Enter runs it, Esc cancels"
            else:
                text = f"{len(matches)} matches, keep typing{keys}"
        self.query_one("#palette-status", Static).update(text)

    @on(Input.Submitted, "#palette-input")
    def submitted(self, event: Input.Submitted) -> None:
        value = event.value.strip()
        lowered = value.lower()
        exact = [n for n in self._verbs if n.lower() == lowered]
        if exact:
            self.dismiss(exact[0])
        elif value:
            matches = self._matches(value)
            if len(matches) == 1:
                self.dismiss(matches[0])
            else:
                # Stay open and say so: silence was the bug — a prefix
                # with 0 or 2+ matches must answer, not sit still.
                self.query_one("#palette-status", Static).update(
                    "no match · Enter runs, Esc cancels"
                    if not matches
                    else f"{len(matches)} matches, keep typing · Enter runs, Esc cancels"
                )

    @on(OptionList.OptionSelected, "#palette-list")
    def selected(self, event: OptionList.OptionSelected) -> None:
        self.dismiss(str(event.option_id))

    def on_key(self, event) -> None:
        if event.key == "escape":
            self.dismiss(None)


class DashboardApp(App):
    """Coins scope first; the workspace sits underneath it.

    The workspace is the *default* screen: Textual's ``app.query_one``
    searches the screen the app composed onto (the bottom of the stack),
    never one pushed on top of it, so keeping the workspace at the bottom
    is what lets app-level helpers and tests reach ``#findings-table``,
    ``#run-log`` and ``#detail`` while the coins picker is open. The
    picker is pushed over the workspace at mount; Continue pops it,
    ``ctrl+o`` pushes it again.
    """

    TITLE = "audit-manifest"
    SUB_TITLE = "dashboard"

    # Textual registers its own ctrl+p palette and replaces any binding on
    # that key with it, which would swallow the task picker this app
    # advertises in its footer and its Overview hint.
    ENABLE_COMMAND_PALETTE = False

    CSS = """
    Screen { layout: vertical; }
    ModalScreen { align: center middle; }
    #body { height: 1fr; }
    #main { width: 1fr; height: 1fr; overflow-y: auto; }
    #main > * { width: 100%; }
    #overview-scroll {
        height: auto;
        max-height: 17;
        overflow-y: auto;
        padding: 0 1;
    }
    #overview-scroll.compact { max-height: 5; }
    #overview { height: auto; width: 100%; }
    #task-groups { height: auto; overflow-y: auto; }
    #task-groups Button {
        width: 100%;
        margin-bottom: 0;
        height: 1;
        border: none;
        text-align: left;
        content-align: left middle;
        transition: background 0.1s;
    }
    #task-groups Button:hover { background: $panel-lighten-1; }
    #task-groups Button:focus { background: $panel-lighten-1; text-style: underline; }
    #tabs { height: 1fr; min-height: 8; }
    #tabs Tab { color: #a0a0a0; }
    #tabs Tab.-active { text-style: bold; color: $text; }
    #tabs Underline > .underline--bar { background: $accent; color: $accent; }
    #detail-scroll {
        width: 48;
        max-width: 48;
        height: 1fr;
        border-left: solid $accent;
        padding: 0 1;
    }
    #detail { width: 100%; height: auto; }
    #findings-table, #plan-table { height: 1fr; }
    #run-strip { height: auto; }
    #run-phase { width: 1fr; height: auto; content-align: left middle; }
    #run-elapsed { width: 10; content-align: right middle; }
    #run-stop { height: 1; border: none; min-width: 8; }
    #run-log { height: 1fr; border: solid $accent; margin-top: 1; }
    #write-buttons { height: 1; }
    #write-buttons Button { margin-right: 1; height: 1; border: none; }
    #coins-hint { height: auto; padding: 0 1; }
    #coins-columns { height: auto; padding: 0 1; }
    #coins-toolbar { height: auto; padding: 0 1; }
    #coins-toolbar Input { width: 1fr; }
    #coins-bulk { height: auto; }
    #coins-bulk Button { margin-left: 1; min-width: 10; }
    #coins-bulk #coins-all { margin-left: 0; }
    #coins-list { height: 1fr; }
    #coins-list Checkbox { border: none; height: 1; }
    .coin-row { height: auto; }
    .coin-info {
        width: 1fr;
        content-align: left middle;
        padding: 0 1;
    }
    #coins-footer { height: auto; padding: 0 1; }
    #coins-count { width: 1fr; content-align: left middle; }
    .palette-box {
        width: 90%; max-width: 110; height: auto; max-height: 80%;
        border: thick $accent; background: $surface; padding: 1 2;
    }
    #confirm-box {
        width: 90%; max-width: 70; height: auto;
        border: thick $accent; background: $surface; padding: 1 2;
    }
    #confirm-box.danger {
        border: thick $error;
    }
    #scaffold-box {
        width: 90%; max-width: 70; height: auto;
        border: thick $accent; background: $surface; padding: 1 2;
    }
    #scaffold-title { text-style: bold; }
    #scaffold-buttons { margin-top: 1; height: auto; }
    #scaffold-buttons Button { margin-right: 1; }
    #confirm-title { text-style: bold; color: $accent; }
    #confirm-title.danger { color: $error; }
    #confirm-buttons { margin-top: 1; height: auto; }
    #confirm-buttons Button { margin-right: 1; }
    .hint { color: $text-muted; }
    """

    BINDINGS: ClassVar[list[BindingType]] = [
        Binding("ctrl+p", "palette", "Tasks"),
        Binding("ctrl+o", "coins", "Coins"),
        Binding("ctrl+r", "refresh", "Refresh"),
        Binding("ctrl+d", "detail", "Detail"),
        Binding("ctrl+q", "quit", "Quit"),
    ]

    def __init__(self) -> None:
        super().__init__()
        # One screen instance: get_default_screen() must hand back the
        # screen the app composes onto, not a fresh one per query.
        self.workspace = WorkspaceScreen()
        self.state: dict[str, Any] = state.load()
        # Live audit child, ``None`` while idle; identity-guarded so a
        # cancelled predecessor can never clear its successor's handle.
        self.live_run: runner.LiveRun | None = None

    def get_default_screen(self) -> WorkspaceScreen:
        return self.workspace

    def on_mount(self) -> None:
        self.push_screen(CoinsScreen())

    async def action_quit(self) -> None:
        """Settle the live task, persist the scope, then quit.

        try/finally, not try/except: a failed save still surfaces, but
        it can never wedge the app open. Settling first keeps the
        worker's finally from racing the screen teardown.
        """
        run = self.live_run
        if run is not None:
            run.stop()
            self.workers.cancel_group(self, "audit")
            for _ in range(100):
                if self.live_run is None:
                    break
                await asyncio.sleep(0.05)
        try:
            state.save(self.state)
        finally:
            await super().action_quit()

    # -- the screen stack -------------------------------------------------
    def ensure_workspace(self) -> None:
        """Commit whatever is ticked, then land on the workspace.

        A task started while the picker is open must not disagree with
        the scope on screen, so the tick state is committed on entry.
        """
        if isinstance(self.screen, CoinsScreen):
            self.action_continue()

    def action_continue(self) -> None:
        """Leave the coins screen, committing the ticked coins as scope.

        Every coin ticked (the fresh state) commits the full fleet —
        ``selection: null``, no ``--ticker``. An empty selection can only
        arrive from the outside (Continue is disabled at zero); it is
        committed as-is and refused at run time, never silently widened.
        """
        coins = self.screen
        if not isinstance(coins, CoinsScreen):
            return
        checked = sorted(coins.selected_tickers())
        if not coins.entry_count or (checked and len(checked) == coins.entry_count):
            # All ticked — or nothing to tick — is the full fleet. The
            # empty case matters: committing [] would poison the next
            # start over a healthy manifest with an unticked scope.
            self.state["selection"] = None
        else:
            # Deduped like state.load: duplicate-ticker rows tick
            # independently but commit once.
            self.state["selection"] = list(dict.fromkeys(checked))
        self.pop_screen()
        # The workspace below still shows the pre-Continue scope: refresh
        # it with the committed one (runs recompute scope anyway, but the
        # overview and the Plan tab must not wait for Ctrl+R).
        self.workspace.refresh_reports()
        # A resize while the picker was on top went to the picker, not the
        # workspace (R11): re-apply the size defaults here, honoring a
        # manual detail toggle like on_resize does.
        self.workspace.apply_compact_default()
        self.workspace.fit_detail()
        if self.workspace.detail_auto:
            self.workspace.apply_narrow_default()

    def action_coins(self) -> None:
        """Ctrl+o: reopen the scope picker over the workspace."""
        if isinstance(self.screen, WorkspaceScreen):
            self.push_screen(CoinsScreen())

    # -- scope ------------------------------------------------------------
    def _scope_line(self) -> str | None:
        """``"2 of 3 coins"`` when the scope is narrowed, else ``None``.

        Counts only coins the manifest still lists — a delisted ticker
        in a persisted scope must not inflate the line.
        """
        return scope_text(self.state.get("selection"), _tickable(fleet_entries()))

    # -- actions ---------------------------------------------------------
    def action_palette(self) -> None:
        # Never stack a second modal over a confirmation or the palette
        # itself: confirming twice would launch two exclusive workers.
        # The picker is fine — a picked task commits its scope on entry.
        if isinstance(self.screen, ModalScreen):
            return

        def handle(result: str | None) -> None:
            if result:
                self.run_verb(result)

        self.push_screen(CommandPalette(PALETTE_VERBS), handle)

    def action_refresh(self) -> None:
        self.workspace.refresh_reports()
        if self.live_run is None:
            # Ctrl+R answers on the strip — the app's feedback organ —
            # so a refresh is never a silent no-op (audit #18).
            n = len(self.workspace.coins)
            self.query_one("#run-phase", Static).update(f"refreshed · {n} coin(s) with findings")

    def action_detail(self) -> None:
        """Ctrl+D toggles the detail pane: never wipes its content.

        The old binding cleared the pane, destroying the row the
        operator was reading. Toggling visibility keeps the content
        and gives narrow terminals their width back; pressing again
        restores it. A manual toggle disables the narrow auto-hide.
        The toggle targets the scroll wrapper: the inner Static grows
        with its content, so only the wrapper shows/hides the column.
        """
        detail = self.workspace.query_one("#detail-scroll", VerticalScroll)
        self.workspace.detail_auto = False
        detail.display = not detail.display
        if detail.display:
            self.workspace.fit_detail()

    # -- run strip (phase / elapsed / Stop, in tab-log) -------------------
    def _arm_strip(self, name: str) -> None:
        """Arm the strip as soon as the child exists."""
        self.query_one("#run-phase", Static).update(f"{name}…")
        self.query_one("#run-elapsed", Static).update("⏱ 00:00")
        self.query_one("#run-stop", Button).disabled = False

    def _disarm_strip(self, last: str | None = None) -> None:
        """Stand the strip down: Stop disabled, hint where to start next.

        ``last`` keeps the strip answering "what just happened" without
        scrolling the log: the idle hint plus the finished run's one-line
        result.
        """
        hint = "idle — pick a task (Ctrl+P)"
        if last:
            hint += f" · last {last}"
        self.query_one("#run-phase", Static).update(hint)
        self.query_one("#run-elapsed", Static).update("")
        self.query_one("#run-stop", Button).disabled = True

    def _show_progress(self, event: dict[str, Any]) -> None:
        """Mirror the newest progress event onto the strip.

        Progress lines never reach the RichLog; the pane keeps human
        output and the strip carries the machine state.
        """
        parts: list[str] = []
        phase = event.get("phase")
        if phase:
            parts.append(str(phase))
        if event.get("index") is not None and event.get("total") is not None:
            parts.append(f"{event['index']}/{event['total']}")
        if event.get("ticker"):
            parts.append(str(event["ticker"]))
        self.query_one("#run-phase", Static).update(" ".join(parts))

    @on(Button.Pressed, "#run-stop")
    def stop_run(self) -> None:
        """Stop the live task: terminate the child, then unwind its worker.

        ``stop()`` marks the capture and SIGTERMs the child; cancelling
        the worker group then unwinds ``_start_verb``, whose finally
        writes the log file and stands the strip down. Idle: a no-op.
        """
        run = self.live_run
        if run is None:
            return
        run.stop()
        self.workers.cancel_group(self, "audit")

    @on(Button.Pressed, "#write-preview-plan")
    def btn_preview_plan(self) -> None:
        self.run_verb("plan")

    @on(Button.Pressed, "#write-preview-diff")
    def btn_preview_diff(self) -> None:
        self.show_git_diff()

    @on(Button.Pressed, "#write-apply")
    def btn_apply(self) -> None:
        self.confirm_apply()

    @on(Button.Pressed)
    def any_button(self, event: Button.Pressed) -> None:
        """Every action button is act-<id>; other screens bind their own."""
        ident = event.button.id or ""
        if not ident.startswith("act-"):
            return
        name = ident[4:]
        if name in ACTION_RUN:
            self.run_verb(name)

    def run_verb(  # noqa: C901, PLR0911  # launch gate: one return per refusal path
        self,
        name: str,
        *,
        confirmed: bool = False,
    ) -> None:
        """Start a task: settle the scope, confirm, then work.

        Full fleet runs a read-only task immediately; a narrowed scope
        confirms its size plus what the scope does *not* narrow. Writes
        always confirm first — one modal, never two — and
        ``confirmed=True`` is those dialogs' re-entry past the gate.

        Informational verbs never reach the worker below (D20): local
        reads, no spawn, nothing for a scope gate to protect.
        """
        if name not in VERBS and name not in ACTION_RUN:
            return
        if self._busy_refusal():
            return
        self.ensure_workspace()
        verb_name, overrides = ACTION_RUN.get(name, (name, {}))
        if VERBS[verb_name].informational:
            self._run_informational(verb_name)
            return
        opts = default_opts(verb_name)
        for key, value in overrides.items():
            setattr(opts, key, value)
        if verb_name == "plan-fix" and name == "plan":
            slot = newest_probe_slot(paths.CACHE_ROOT)
            if slot is not None:
                opts.with_versions = True
                opts.versions_from = str(slot)
            else:
                self.query_one("#run-log", RichLog).write(
                    "--- plan: no probe data for version bumps — run Analyze first ---"
                )
        if verb_name == "scaffold":
            # D21: the TUI asks for the URL on screen — no task may
            # launch-to-fail for a missing flag. Scope never applies:
            # dialog before the scope block so no --ticker is ever built.
            def handle_scaffold(url: str | None) -> None:
                if url:
                    opts.repo_url = url
                    self._start_verb(opts)

            self.push_screen(ScaffoldDialog(), handle_scaffold)
            return
        tickable = _tickable(fleet_entries())
        if not tickable:
            # No fleet to run on (broken/empty manifest): refuse
            # regardless of scope shape — None selection included.
            self.query_one("#tabs", TabbedContent).active = "tab-log"
            self.query_one("#run-log", RichLog).write(
                "ERROR: no coins in the manifest — fix manifest-latest.json before running tasks"
            )
            return
        if verb_name == "delist" and self.state.get("selection") is None:
            self.query_one("#tabs", TabbedContent).active = "tab-log"
            self.query_one("#run-log", RichLog).write(
                "ERROR: delist needs ticked coins — pick a scope first, the full fleet is never a removal target"
            )
            return
        settled = self._settle_scope(tickable, opts)
        if settled is None:
            return
        selection, narrowed, total = settled
        if confirmed:
            self._confirmed_run(verb_name, opts)
            return
        self._confirm_then_run(name, verb_name, opts, selection, narrowed=narrowed, total=total)

    def _busy_refusal(self) -> bool:
        """Refuse a second launch, visibly, and say why. True when refused.

        The worker group is exclusive, so a second launch would cancel
        the live child — minutes of probe lost to one stray click. The
        refusal writes to the Log tab, wherever the operator was looking:
        a line on a hidden tab is a dead click.
        """
        if isinstance(self.screen, ModalScreen):
            # A second run never stacks over a confirmation or the
            # palette: confirming twice would queue two exclusive
            # workers. (Re-entry from a dismissed dialog lands on the
            # workspace, so the gate never blocks it.) Say so on the log,
            # since the task buttons stay enabled under the modal.
            self.query_one("#run-log", RichLog).write(
                "--- busy: an open dialog is waiting — confirm or cancel it first ---"
            )
            return True
        if self.live_run is not None:
            self.query_one("#tabs", TabbedContent).active = "tab-log"
            self.query_one("#run-log", RichLog).write("--- busy: a task is still running — Stop it first ---")
            return True
        return False

    def _settle_scope(
        self, tickable: list[dict[str, Any]], opts: argparse.Namespace
    ) -> tuple[list[str] | None, bool, int] | None:
        """Settle the ticked scope into ``opts``. None means already refused.

        Returns ``(selection, narrowed, total)``: selection is the
        operator's live-tick list (None when nothing is ticked), narrowed
        says the scope dropped manifest coins, total is the tickable
        fleet size the confirmations quote. A scope of all-dead ticks is
        a refusal, logged on the Log tab.
        """
        selection = self.state.get("selection")

        narrowed = False
        total = len(tickable)
        if selection is not None:
            fleet = {e["ticker"] for e in tickable}
            selection, narrowed = split_scope(selection, fleet)
            if not selection:
                self.query_one("#tabs", TabbedContent).active = "tab-log"
                self.query_one("#run-log", RichLog).write(
                    "ERROR: no coins are ticked — reopen the coins screen (ctrl+o) and pick a scope"
                )
                return None
            if narrowed:
                opts.tickers = ",".join(selection)
        return selection, narrowed, total

    def _confirmed_run(self, verb_name: str, opts: argparse.Namespace) -> None:
        """The confirmation dialogs' re-entry path past the gate.

        apply-fix re-enters with the reviewed plan file already on disk:
        the subset is re-scoped against the live ticks at confirmation
        time, so a coin unticked between preview and confirm is never
        written. Every other verb re-enters with its original opts.
        """
        if verb_name == "apply-fix":
            selection = self.state.get("selection")
            tickable = _tickable(fleet_entries())
            subset = scoped_subset_for_apply(self.workspace.plan, selection, {e["ticker"] for e in tickable})
            plan_path = paths.CACHE_ROOT / "plan-fix.apply.json"
            plan_path.write_text(json.dumps({"schema_version": 1, "plan": subset, "findings": []}), encoding="utf-8")
            opts = default_opts("apply-plan")
            opts.apply_plan = str(plan_path)
        self._start_verb(opts)

    def _confirm_then_run(  # noqa: PLR0913  # one input per confirmation branch, keyword-only flags at the call site
        self,
        name: str,
        verb_name: str,
        opts: argparse.Namespace,
        selection: list[str] | None,
        *,
        narrowed: bool,
        total: int,
    ) -> None:
        """One confirmation per launch: write risk, else narrowed scope.

        Full-fleet read-only runs never reach here — they start directly.
        Apply-fix keeps its single Plan-tab dialog as the write's one
        confirmation; a write verb builds its dialog from the verb
        itself, so a future write gets truthful copy, and scope is always
        shown — full fleet most of all, since that is the most dangerous
        shape.
        """
        verb = VERBS[verb_name]
        if verb.name == "apply-fix":
            # The Plan tab's dialog is this write's one confirmation.
            self.confirm_apply()
            return
        if verb.write:

            def handle_write(write_confirmed: bool | None) -> None:  # noqa: FBT001  # modal result payload, invoked positionally by push_screen
                if write_confirmed:
                    self._start_verb(opts)

            body = f"{verb.summary}.\nThis task writes to the working tree."
            scope = self._scope_line() or f"full fleet ({total} coins)"
            body += f"\n\nscope: {scope}"
            self.push_screen(
                ConfirmScreen(f"Run {name}?", body, action="Run", danger=True),
                handle_write,
            )
            return
        if narrowed and selection:
            # narrowed is only ever set for a non-None selection (see
            # _settle_scope), and the guard states it for readers and the
            # type checker alike.

            def handle(confirmed: bool | None) -> None:  # noqa: FBT001  # modal result payload, invoked positionally by push_screen
                if confirmed:
                    self._start_verb(opts)

            coins = ", ".join(sorted(selection)[:8])
            if len(selection) > _MAX_SCOPE_PREVIEW:
                coins += ", …"
            self.push_screen(
                ConfirmScreen(
                    f"Run {name} on {len(selection)} of {total} coins",
                    f"Coins: {coins}\n"
                    "Scope narrows probes and param-check; "
                    "cross-check and port matrix stay fleet-wide.",
                    action="Run",
                ),
                handle,
            )
            return
        self._start_verb(opts)

    def _run_informational(self, name: str) -> None:
        """Run an informational verb locally: a read, never a spawn (D20).

        ``list`` and ``report`` neither launch the audit script nor need
        the scope gate a real run passes through.
        """
        self.query_one("#tabs", TabbedContent).active = "tab-log"
        log = self.query_one("#run-log", RichLog)
        if name == "list":
            # Unfiltered on purpose: every row stays visible, falsy tickers
            # as "?", truthy non-strings raw (the picker still skips them).
            entries = fleet_entries()
            log.write(f"--- list: {len(entries)} entries (local read, no audit spawned) ---")
            for entry in entries:
                versions_text = _tags(entry.get("versions"))
                log.write(f"  {entry.get('ticker') or '?'}   {entry.get('ver_id') or '—'}   {versions_text}")
            self._disarm_strip(last=f"{name} · local read")
            return
        if name == "report":
            meta = read_last_run_meta()
            if not meta:
                log.write("--- report: no run recorded yet ---")
                self._disarm_strip(last="report · no run recorded")
                return
            log.write("--- report: last run (no audit spawned) ---")
            for key, value in meta.items():
                log.write(f"  {key:<18}{value}")
            self._disarm_strip(last="report · local read")
            return
        # A new informational verb must be named here, never fall through.
        log.write(f"ERROR: informational task {name} has no local handler")

    @work(exclusive=True, group="audit")
    async def _start_verb(self, opts: argparse.Namespace) -> None:
        """Run one task, streaming its console output into the Log pane.

        The RichLog gets human lines only; ``LiveRun.lines`` keeps the
        full capture in memory; the log file keeps human lines. The
        finally runs on success, failure and Stop alike: capture written, timer stopped,
        strip stood down, and a child still alive at cancel time is
        terminated, never orphaned.
        """
        name = opts.verb
        # A RichLog that was never laid out swallows its first lines.
        self.query_one("#tabs", TabbedContent).active = "tab-log"
        log = self.query_one("#run-log", RichLog)
        prepared = self._verb_command(opts, log)
        if prepared is None:
            return
        cmd, primary, log_path = prepared

        started_at = time.time()
        began = time.monotonic()
        run: runner.LiveRun | None = None
        timer = None
        note: str | None = None
        try:
            run = await self._spawn_verb_run(cmd, name, log, log_path)
            if run is None:
                return

            self.live_run = run
            self._arm_strip(name)
            started_mono = time.monotonic()

            def tick() -> None:
                """Per-run closure, so no run's timer ticks another's strip."""
                secs = int(time.monotonic() - started_mono)
                self.query_one("#run-elapsed", Static).update(f"⏱ {secs // 60:02d}:{secs % 60:02d}")

            timer = self.set_interval(1.0, tick)

            def on_display_line(line: str) -> None:
                # The capture keeps the trailing newline; RichLog would
                # render it as a blank row, so strip at the display edge.
                log.write(line.rstrip("\n"))

            rc = await runner.stream_lines(
                run,
                on_line=on_display_line,
                on_progress=self._show_progress,
            )
            note = self._settle_completion(
                name=name,
                cmd=cmd,
                primary=primary,
                log_path=log_path,
                opts=opts,
                run=run,
                rc=rc,
                started_at=started_at,
                duration=time.monotonic() - began,
                log=log,
            )
        finally:
            if timer is not None:
                timer.stop()
            if run is not None:
                note = self._finish_capture(run, name, log, log_path, note)

    def _finish_capture(
        self,
        run: runner.LiveRun,
        name: str,
        log: RichLog,
        log_path: Path,
        note: str | None,
    ) -> str | None:
        """Reap the child, write the human capture, stand the strip down.

        Runs on success, failure and Stop alike. The stopped/alive flags
        are snapshotted before the orphan-reaping ``stop()`` below, which
        marks the capture "stopped by user" — a claim only the Stop
        button may make; a worker unwound otherwise, with a child still
        alive, reports as interrupted instead. Returns the possibly-set
        note for the strip's last line.
        """
        was_stopped = run.stopped
        was_alive = run.proc.returncode is None
        if was_alive:
            # Cancelled mid-stream or racy: never leave it behind.
            run.stop(announce=False)
        if was_stopped:
            # The try-block's stopped path returns without a line,
            # and a cancelled worker never reaches it; the file
            # already carries stop()'s own marker.
            log.write(f"--- {name} stopped by user ---")
            if note is None:
                note = f"{name} stopped by user"
        elif was_alive:
            run.lines.append(f"--- {name} interrupted ---\n")
            log.write(f"--- {name} interrupted ---")
            if note is None:
                note = f"{name} interrupted"
        text = "".join(runner.human_lines(run.lines))
        try:
            log_path.write_text(
                text if text.endswith("\n") else text + "\n",
                encoding="utf-8",
            )
        except OSError as exc:
            # The pane already shows the run; say so there rather
            # than crashing the worker on a dead cache dir.
            log.write(f"ERROR: could not write {log_path.name}: {exc}")
        if self.live_run is run:
            self.live_run = None
            self._disarm_strip(last=note)
        return note

    def _verb_command(self, opts: argparse.Namespace, log: RichLog) -> tuple[list[str], Path, Path] | None:
        """Build the audit command and its report/log paths.

        Returns ``(cmd, primary, log_path)``, or None when argv could not
        be built — that error is already on the log. The wrapped command
        is echoed so the operator sees exactly what runs before output
        starts.
        """
        name = opts.verb
        try:
            argv = build_audit_argv(opts, [])
        except DashboardError as exc:
            log.write(f"ERROR: {exc}")
            return None
        primary, _, log_path = report_paths(name, None, tickers=getattr(opts, "tickers", None))
        cmd = runner.audit_command(argv, primary)
        for line in runner.wrap_command(cmd, log.region.width):
            log.write(line)
        return cmd, primary, log_path

    async def _spawn_verb_run(self, cmd: list[str], name: str, log: RichLog, log_path: Path) -> runner.LiveRun | None:
        """Spawn the audit child; None when it could not start.

        A launch failure writes the error to the log AND to the log file
        — the run's only trace when the child never existed. An unusable
        cache dir is a log-line-only failure.
        """
        try:
            paths.CACHE_ROOT.mkdir(parents=True, exist_ok=True)
            return await runner.spawn_audit(cmd, verb=name)
        except DashboardError as exc:
            line = f"ERROR: could not launch the audit script: {exc}"
            log.write(line)
            log_path.write_text(f"$ {' '.join(cmd)}\n{line}\n", encoding="utf-8")
            return None
        except OSError as exc:
            log.write(f"ERROR: cannot use the cache dir: {exc}")
            return None

    def _settle_completion(  # noqa: PLR0913  # the finished run's state, keyword-only at the call site
        self,
        *,
        name: str,
        cmd: list[str],
        primary: Path,
        log_path: Path,
        opts: argparse.Namespace,
        run: runner.LiveRun,
        rc: int,
        started_at: float,
        duration: float,
        log: RichLog,
    ) -> str:
        """Turn a finished child into state: promote, warn, or keep.

        Returns the strip note. Each early outcome — stopped, failed
        rc=2, a silent success that wrote no report — keeps last-run
        alone and re-shows the last good fleet state, because promoting a
        partial or absent report would present it as this run's.
        """
        if run.stopped:
            # Partial report: leave last-run alone and re-show the
            # last good fleet state instead of promoting the partial.
            self.workspace.refresh_reports()
            return f"{name} stopped by user"
        if rc == _EXIT_USAGE:
            log.write(f"--- {name} failed rc=2, see {log_path} ---")
            return f"{name} failed rc=2"
        if not primary.is_file():
            # The child exited 0/1 but left no report: claiming
            # "finished" would present the previous report as this
            # run's, so fail loud instead (the agent path raises
            # DashboardError on the same condition).
            log.write(
                f"ERROR: {name} exited rc={rc} but wrote no report "
                f"(expected {primary.name}) — showing previous results, "
                f"see {log_path.name}"
            )
            self.workspace.refresh_reports()
            return f"{name} wrote no report"
        if primary != paths.LAST_REPORT:
            shutil.copyfile(primary, paths.LAST_REPORT)
        write_last_run_meta(name, cmd, primary, log_path, started_at, duration, rc)
        self.workspace.refresh_reports()
        tickers = getattr(opts, "tickers", None)
        finish = _finish_line(name, tickers, primary)
        log.write(finish)
        note = _strip_note(name, tickers)
        if not tickers:
            # Fleet runs park the user where the results are; scoped
            # runs stay on the log — the fleet tabs deliberately do
            # not reflect them, and switching there would mislead.
            dest = None
            if name in _FINDINGS_VERBS:
                dest = "tab-findings"
            elif name in _PLAN_VERBS:
                dest = "tab-plan"
            if dest is not None:
                self.query_one("#tabs", TabbedContent).active = dest
        return note

    def confirm_apply(self) -> None:
        if not self.workspace.plan:
            # The message lives in the Plan pane; show that pane first.
            # The plan resolves by scope (fleet or scoped slot), so the
            # refusal names the run that would fill it.
            self.query_one("#tabs", TabbedContent).active = "tab-plan"
            scoped = self.state.get("selection") is not None
            self.workspace.query_one("#write-status", Static).update(
                "Nothing to apply under this scope: run Plan under this scope first."
                if scoped
                else "Nothing to apply: run Plan first."
            )
            return
        plan = self.workspace.plan
        selection = self.state.get("selection")
        fleet = {e["ticker"] for e in _tickable(fleet_entries())}
        subset = scoped_subset_for_apply(plan, selection, fleet)
        if not subset:
            # A scope with no planned writes confirms nothing: refuse
            # like the no-plan path instead of dialoguing a no-op.
            self.query_one("#tabs", TabbedContent).active = "tab-plan"
            self.workspace.query_one("#write-status", Static).update(
                "Nothing to apply under this scope: widen the scope or run Plan."
            )
            return
        files = apply_files(subset)
        body = (
            f"{len(subset)} write(s) to {len(files)} file(s) in the working "
            "tree:\n\n  " + "\n  ".join(files[:12]) + ("\n  …" if len(files) > _MAX_FILE_PREVIEW else "")
        )
        scope = self._scope_line()
        if scope is None:
            total = len(_tickable(fleet_entries()))
            scope = f"full fleet ({total} coins)"
        body += f"\n\nscope: {scope}"

        def handle(confirmed: bool | None) -> None:  # noqa: FBT001  # modal result payload, invoked positionally by push_screen
            if confirmed:
                # The dialog was the confirmation; this is the launch.
                self.run_verb("apply-fix", confirmed=True)

        self.push_screen(ConfirmScreen("Apply planned changes?", body, danger=True), handle)

    def show_git_diff(self) -> None:
        """Show the real working-tree diff, so the preview is not a promise."""
        self.query_one("#tabs", TabbedContent).active = "tab-log"
        log = self.query_one("#run-log", RichLog)
        stat = runner.git_diff_stat()
        log.write("--- git diff --stat ---")
        for line in stat.splitlines():
            log.write(line)
