#!/usr/bin/env python3
"""Pilot tests for the Textual TUI in dashboard.py.

These drive the real widgets — mount, tabs, tables, the command palette and
the confirm gate — against a synthetic cache so that no audit script is ever
launched and no report of the real repository is touched.

Textual is an optional dependency, so the whole module is skipped when it is
not installed (the workspace venv deliberately does not have it).
"""
import asyncio
import inspect
import json
import time
from pathlib import Path

import pytest

pytest.importorskip("textual")

from textual.widgets import (  # noqa: E402
    Button,
    DataTable,
    Input,
    RichLog,
    Static,
    TabbedContent,
)

import importlib.util  # noqa: E402
import sys  # noqa: E402

DASH_PATH = Path(__file__).resolve().parents[1] / "dashboard.py"
spec = importlib.util.spec_from_file_location("audit_manifest_dashboard_tui", str(DASH_PATH))
dash = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = dash
spec.loader.exec_module(dash)


# ---------------------------------------------------------------------------
# Harness
# ---------------------------------------------------------------------------

def run_app(app, body):
    """Drive one app to completion through Textual's own test runner."""
    async def scenario():
        async with app.run_test(size=(140, 42)) as pilot:
            # Let deferred mount callbacks (the first report load) land first,
            # so every body starts from a populated screen.
            await pilot.pause()
            await body(app, pilot)

    asyncio.run(scenario())


@pytest.fixture
def cache(tmp_path, monkeypatch):
    """Point every cache path at a throwaway directory."""
    root = tmp_path / "cache"
    root.mkdir()
    monkeypatch.setattr(dash, "CACHE_ROOT", root)
    monkeypatch.setattr(dash, "LAST_REPORT", root / "last-run.json")
    monkeypatch.setattr(dash, "LAST_META", root / "last-run.meta.json")
    return root


def write_report(root: Path, name: str, findings, plan, meta_verb=None):
    """Write a report plus its meta sidecar the way a completed run would."""
    payload = {
        "schema_version": 1,
        "summary": {
            "repos_total": 41, "alive": 39, "dead": 1,
            "moved": 0, "unknown": 1, "stale": 3,
        },
        "findings": list(findings),
        "plan": list(plan),
        "meta": {"local_only": False},
    }
    path = root / f"{name}.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    meta = {
        "verb": meta_verb or name,
        "argv": ["audit-manifest.py", "--report", str(path)],
        "report": str(path),
        "log": str(root / f"{name}.log"),
        "started_at": time.time() - 60,
        "duration_seconds": 107.5,
        "audit_exit_code": 1,
    }
    (root / f"{name}.meta.json").write_text(json.dumps(meta), encoding="utf-8")
    return path


def write_plan(root: Path, plan):
    """Write the plan-fix artefact the Write tab reads."""
    payload = {"schema_version": 1, "plan": list(plan), "findings": []}
    path = root / "plan-fix.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    (root / "plan-fix.meta.json").write_text(
        json.dumps({
            "verb": "plan-fix",
            "argv": ["audit-manifest.py", "--dry-run"],
            "report": str(path),
            "log": str(root / "plan-fix.log"),
            "started_at": time.time() - 60,
            "duration_seconds": 662.0,
            "audit_exit_code": 1,
        }),
        encoding="utf-8",
    )
    return path


FINDING = {
    "severity": "FAIL",
    "category": "local",
    "coin": "LYNX",
    "ver_id": "lynx--v1.0",
    "id": "MISSING-WALLET-CONF",
    "detail": "manifest points at wallet-confs/lynx--v1.0.conf but it is absent",
    "file": "wallet-confs/lynx--v1.0.conf",
    "line": None,
}

PLAN_ENTRY = {
    "action": "fees",
    "file": "wallet-confs/lynx--v1.0.conf",
    "key": "maxtxfee",
    "old": "0.1",
    "new": "0.2",
    "reason": "fee margin below the configured floor",
    "coin": "LYNX",
    "ver_id": "lynx--v1.0",
    "evidence": "wallet-confs/lynx--v1.0.conf:12",
    "applied": False,
}


def log_text(app) -> str:
    log = app.query_one("#run-log", RichLog)
    return "\n".join(str(line.text) for line in log.lines)


def screen_name(app) -> str:
    return type(app.screen).__name__


# DashboardApp is the App; its screen stack starts on Textual's default Screen,
# so a modal has been pushed exactly when the name is no longer this one.
DEFAULT_SCREEN = "Screen"


def record_run_verb(monkeypatch, app, sink):
    """Replace the worker with a recorder so nothing is ever executed."""
    monkeypatch.setattr(type(app), "run_verb", lambda self, name: sink.append(name))


# ---------------------------------------------------------------------------
# Mount / reading the cache
# ---------------------------------------------------------------------------

def test_the_tui_entrypoint_can_actually_start():
    """run_tui() does ``app = _make_app(); app.run()``.

    If _make_app() hands back the class instead of an instance, ``run()`` is
    still missing its ``self`` and the TUI dies with a TypeError before it
    ever draws a screen.
    """
    app = dash._make_app()
    assert not isinstance(app, type), "_make_app() must return an application instance"
    inspect.signature(app.run).bind()      # raises TypeError if self is unbound


def test_the_widget_tree_composes_without_raising(cache):
    """A bad Button variant kills compose, so the app never draws anything."""
    write_report(cache, "findings", [], [])

    app = dash._make_app()

    async def body(app, pilot):
        # If any widget were constructed with an invalid argument, run_test()
        # would already have raised (e.g. InvalidButtonVariant) before this.
        assert app.query_one("#run-list", Button)
        assert app.query_one("#write-apply", Button)
        assert app.query_one("#findings-table", DataTable)

    run_app(app, body)


def test_mount_reads_the_cached_fleet_report(cache):
    write_report(cache, "findings", [FINDING], [])

    app = dash._make_app()

    async def body(app, pilot):
        overview = str(app.query_one("#overview", Static).content)
        assert "findings.json" in overview
        assert "total             1" in overview
        assert "repos probed      41" in overview
        assert "60s ago" in overview        # age computed from the sidecar
        assert "by verb" in overview and "findings" in overview
        # Mounting must never start an audit run: once the Run tab has been
        # laid out (RichLog hides earlier writes until then), it is still empty.
        app.query_one("#tabs", TabbedContent).active = "tab-run"
        await pilot.pause()
        assert log_text(app) == ""

    run_app(app, body)


def test_overview_prefers_the_fleet_report_over_a_later_cheap_run(cache):
    # An old fleet report plus a newer last-run.json from a cheap verb.
    write_report(cache, "findings", [FINDING], [])
    (cache / "last-run.json").write_text(
        json.dumps({"schema_version": 1, "findings": [], "summary": {}}),
        encoding="utf-8",
    )

    app = dash._make_app()

    async def body(app, pilot):
        overview = str(app.query_one("#overview", Static).content)
        assert "findings.json" in overview
        assert "total             1" in overview

    run_app(app, body)


def test_findings_table_lists_every_finding(cache):
    write_report(cache, "findings", [FINDING, dict(FINDING, coin="DGB", severity="WARN")], [])

    app = dash._make_app()

    async def body(app, pilot):
        table = app.query_one("#findings-table", DataTable)
        assert table.row_count == 2
        assert list(table.get_row_at(0)[:2]) == ["FAIL", "local"]
        assert list(table.get_row_at(1)[:2]) == ["WARN", "local"]

    run_app(app, body)


def test_write_tab_starts_empty(cache):
    write_report(cache, "findings", [], [])

    app = dash._make_app()

    async def body(app, pilot):
        status = str(app.query_one("#write-status", Static).content)
        assert "No plan yet" in status
        assert "hint" in app.query_one("#write-status").classes
        assert app.query_one("#plan-table", DataTable).row_count == 0

    run_app(app, body)


def test_write_tab_lists_planned_writes(cache):
    write_report(cache, "findings", [], [])
    write_plan(cache, [PLAN_ENTRY, dict(PLAN_ENTRY, applied=True)])

    app = dash._make_app()

    async def body(app, pilot):
        status = str(app.query_one("#write-status", Static).content)
        assert "2 planned write(s)" in status
        assert "1 already applied" in status
        assert "hint" not in app.query_one("#write-status").classes
        table = app.query_one("#plan-table", DataTable)
        assert table.row_count == 2
        assert table.get_row_at(0)[-1] == "no"
        assert table.get_row_at(1)[-1] == "yes"

    run_app(app, body)


def test_refresh_picks_up_a_report_written_after_mount(cache):
    write_report(cache, "findings", [], [])

    app = dash._make_app()

    async def body(app, pilot):
        assert app.query_one("#findings-table", DataTable).row_count == 0
        write_report(cache, "findings", [FINDING], [])
        app.action_refresh()
        await pilot.pause()
        assert app.query_one("#findings-table", DataTable).row_count == 1

    run_app(app, body)


# ---------------------------------------------------------------------------
# Layout
# ---------------------------------------------------------------------------

def test_all_four_tabs_and_verb_buttons_are_present(cache):
    write_report(cache, "findings", [], [])

    app = dash._make_app()

    async def body(app, pilot):
        tabs = app.query_one("#tabs", TabbedContent)
        assert [pane.id for pane in tabs.query("TabPane")] == [
            "tab-overview", "tab-findings", "tab-run", "tab-write",
        ]
        for name in dash.VERBS:
            assert app.query(f"#run-{name}"), f"missing Run-tab button for {name}"
        assert app.query_one("#detail", Static)

    run_app(app, body)


def test_selecting_a_finding_fills_the_detail_pane(cache):
    write_report(cache, "findings", [FINDING], [])

    app = dash._make_app()

    async def body(app, pilot):
        app.query_one("#tabs", TabbedContent).active = "tab-findings"
        await pilot.pause()
        table = app.query_one("#findings-table", DataTable)
        table.focus()
        await pilot.press("down")
        await pilot.pause()
        detail = str(app.query_one("#detail", Static).content)
        assert "MISSING-WALLET-CONF" in detail
        assert FINDING["detail"] in detail

    run_app(app, body)


# ---------------------------------------------------------------------------
# Command palette
# ---------------------------------------------------------------------------

def test_control_p_opens_the_palette_and_escape_closes_it(cache, monkeypatch):
    write_report(cache, "findings", [], [])

    app = dash._make_app()

    async def body(app, pilot):
        await pilot.press("ctrl+p")
        await pilot.pause()
        assert screen_name(app) == "CommandPalette"
        assert app.screen.query_one("#palette-input", Input).has_focus

        await pilot.press("escape")
        await pilot.pause()
        assert screen_name(app) == DEFAULT_SCREEN

    run_app(app, body)


def test_palette_submits_the_chosen_verb(cache, monkeypatch):
    write_report(cache, "findings", [], [])
    app = dash._make_app()
    ran = []
    record_run_verb(monkeypatch, app, ran)

    async def body(app, pilot):
        await pilot.press("ctrl+p")
        await pilot.pause()
        app.screen.query_one("#palette-input", Input).value = "ports"
        await pilot.press("enter")
        await pilot.pause()
        assert ran == ["ports"], "palette selection did not reach run_verb"
        assert screen_name(app) == DEFAULT_SCREEN

    run_app(app, body)


def test_palette_ignores_an_unknown_task(cache, monkeypatch):
    write_report(cache, "findings", [], [])
    app = dash._make_app()
    ran = []
    record_run_verb(monkeypatch, app, ran)

    async def body(app, pilot):
        await pilot.press("ctrl+p")
        await pilot.pause()
        app.screen.query_one("#palette-input", Input).value = "frobnicate"
        await pilot.press("enter")
        await pilot.pause()
        assert ran == [], "an unknown task must not run"
        assert screen_name(app) == "CommandPalette"

    run_app(app, body)


def test_run_tab_buttons_route_to_their_verb(cache, monkeypatch):
    write_report(cache, "findings", [], [])
    app = dash._make_app()
    ran = []
    record_run_verb(monkeypatch, app, ran)

    async def body(app, pilot):
        for name in ("cross-check", "plan-fix"):
            app.query_one(f"#run-{name}", Button).press()
            await pilot.pause()
        assert ran == ["cross-check", "plan-fix"]

    run_app(app, body)


def test_scaffold_from_the_run_tab_stops_on_a_usage_error(cache):
    """The real worker must refuse before it can spawn anything."""
    write_report(cache, "findings", [], [])

    app = dash._make_app()

    async def body(app, pilot):
        # The Run tab must be laid out first: RichLog defers writes until it
        # knows its own size, so a log written from another tab is invisible.
        app.query_one("#tabs", TabbedContent).active = "tab-run"
        await pilot.pause()
        app.query_one("#run-scaffold", Button).press()
        await pilot.pause()
        await pilot.pause()
        assert "requires --repo-url" in log_text(app)
        assert "$" not in log_text(app), "the audit script was launched anyway"

    run_app(app, body)


# ---------------------------------------------------------------------------
# The confirm gate: no write happens without passing through it
# ---------------------------------------------------------------------------

def test_apply_without_a_plan_is_refused_and_opens_no_dialog(cache, monkeypatch):
    write_report(cache, "findings", [], [])
    app = dash._make_app()
    ran = []
    record_run_verb(monkeypatch, app, ran)

    async def body(app, pilot):
        app.query_one("#tabs", TabbedContent).active = "tab-write"
        await pilot.pause()
        app.query_one("#write-apply", Button).press()
        await pilot.pause()
        status = str(app.query_one("#write-status", Static).content)
        assert "Nothing to apply" in status
        assert screen_name(app) == DEFAULT_SCREEN
        assert ran == []

    run_app(app, body)


def test_apply_with_a_plan_requires_confirmation(cache, monkeypatch):
    write_report(cache, "findings", [], [])
    write_plan(cache, [PLAN_ENTRY])
    app = dash._make_app()
    ran = []
    record_run_verb(monkeypatch, app, ran)

    async def body(app, pilot):
        app.query_one("#tabs", TabbedContent).active = "tab-write"
        await pilot.pause()
        app.query_one("#write-apply", Button).press()
        await pilot.pause()
        assert screen_name(app) == "ConfirmScreen"
        assert "1 write(s)" in str(app.screen.query_one("#confirm-body").content)
        assert ran == [], "confirming must not be implicit"

        await pilot.press("escape")
        await pilot.pause()
        assert screen_name(app) == DEFAULT_SCREEN
        assert ran == [], "cancelling must not run the write"

    run_app(app, body)


def test_confirming_the_dialog_is_what_runs_the_write(cache, monkeypatch):
    write_report(cache, "findings", [], [])
    write_plan(cache, [PLAN_ENTRY])
    app = dash._make_app()
    ran = []
    record_run_verb(monkeypatch, app, ran)

    async def body(app, pilot):
        app.query_one("#tabs", TabbedContent).active = "tab-write"
        await pilot.pause()
        app.query_one("#write-apply", Button).press()
        await pilot.pause()
        assert screen_name(app) == "ConfirmScreen"
        app.screen.query_one("#confirm-yes", Button).press()
        await pilot.pause()
        assert ran == ["apply-fix"]
        assert screen_name(app) == DEFAULT_SCREEN

    run_app(app, body)


def test_preview_button_runs_the_dry_run_verb(cache, monkeypatch):
    write_report(cache, "findings", [], [])
    app = dash._make_app()
    ran = []
    record_run_verb(monkeypatch, app, ran)

    async def body(app, pilot):
        app.query_one("#tabs", TabbedContent).active = "tab-write"
        await pilot.pause()
        app.query_one("#write-preview-plan", Button).press()
        await pilot.pause()
        assert ran == ["plan-fix"], "the preview button must never apply"

    run_app(app, body)


# ---------------------------------------------------------------------------
# git diff preview
# ---------------------------------------------------------------------------

@pytest.mark.skipif(
    not (Path(__file__).resolve().parents[3] / ".git").exists(),
    reason="no git checkout to diff",
)
def test_show_git_diff_reports_the_real_working_tree(cache):
    write_report(cache, "findings", [], [])

    app = dash._make_app()

    async def body(app, pilot):
        app.query_one("#tabs", TabbedContent).active = "tab-run"
        await pilot.pause()          # let RichLog learn its size before writes
        app.query_one("#write-preview-diff", Button).press()
        await pilot.pause()
        await pilot.pause()
        assert app.query_one("#tabs", TabbedContent).active == "tab-run"
        assert "git diff --stat" in log_text(app)

    run_app(app, body)
