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
import re
import sys
import time
from pathlib import Path

import pytest

pytest.importorskip("textual")

from textual.widgets import (
    Button,
    Checkbox,
    DataTable,
    Input,
    RichLog,
    Static,
    TabbedContent,
)

import dashboard as dash

# ---------------------------------------------------------------------------
# Harness
# ---------------------------------------------------------------------------


def run_app(app, body, *, screen="workspace", size=(140, 42)):
    """Drive one app to completion through Textual's own test runner.

    ``screen="workspace"`` hands the body the workspace (the app starts on
    the coins screen, and Continue is the only door in); ``screen="coins"``
    leaves the initial scope picker up. ``size`` overrides the terminal
    geometry for narrow-terminal tests (default 140x42).
    """

    async def scenario():
        async with app.run_test(size=size) as pilot:
            # Let deferred mount callbacks (the first report load) land first,
            # so every body starts from a populated screen.
            await pilot.pause()
            if screen == "workspace":
                app.action_continue()
                await pilot.pause()
            await body(app, pilot)

    asyncio.run(scenario())


@pytest.fixture
def cache(tmp_path, monkeypatch):
    """Point every cache path at a throwaway directory."""
    root = tmp_path / "cache"
    root.mkdir()
    monkeypatch.setattr(dash.paths, "CACHE_ROOT", root)
    monkeypatch.setattr(dash.paths, "LAST_REPORT", root / "last-run.json")
    monkeypatch.setattr(dash.paths, "LAST_META", root / "last-run.meta.json")
    return root


def write_report(root: Path, name: str, findings, plan, meta_verb=None):
    """Write a report plus its meta sidecar the way a completed run would."""
    payload = {
        "schema_version": 1,
        "summary": {
            "repos_total": 41,
            "alive": 39,
            "dead": 1,
            "moved": 0,
            "unknown": 1,
            "stale": 3,
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
    """Write the plan-fix artefact the Plan tab reads."""
    payload = {"schema_version": 1, "plan": list(plan), "findings": []}
    path = root / "plan-fix.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    (root / "plan-fix.meta.json").write_text(
        json.dumps(
            {
                "verb": "plan-fix",
                "argv": ["audit-manifest.py", "--dry-run"],
                "report": str(path),
                "log": str(root / "plan-fix.log"),
                "started_at": time.time() - 60,
                "duration_seconds": 662.0,
                "audit_exit_code": 1,
            }
        ),
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

# A finding exactly as build_findings() emits a REPO-ACTION row: carries the
# versions block, and its file/line are genuinely null (no file to point at).
VERSION_FINDING = dict(
    FINDING,
    coin="AAA",
    ver_id="aaa--v1.0",
    category="version",
    id="REPO-ACTION",
    detail="repo ALIVE: newer same-series tags: v1.2.0",
    file=None,
    line=None,
    versions={
        "declared": ["v1.0.0"],
        "our_latest": "v1.0.0",
        "remote_latest": "v1.2.0",
        "newer_same": ["v1.2.0"],
        "newer_alt": [],
        "missing": [],
        "found": [],
        "tag_count": 3,
        "conf": "aaa--v1.0",
    },
)


def log_text(app) -> str:
    log = app.query_one("#run-log", RichLog)
    return "\n".join(str(line.text) for line in log.lines)


async def press_task(app, pilot, name: str) -> None:
    """Run a task with the Log pane laid out first.

    Lines written before the pane's first layout defer on a Resize
    that pilot scheduling sometimes never delivers, so content asserts
    flake 50/50 without this. Settling first makes every run's log
    deterministic; real operators always press with the UI settled.
    """
    app.query_one("#tabs", TabbedContent).active = "tab-log"
    assert await wait_until(
        pilot,
        lambda: app.query_one("#run-log", RichLog)._size_known,
        steps=100,
    ), "the log pane must lay out before a run starts"
    app.run_verb(name)


def screen_name(app) -> str:
    return type(app.screen).__name__


def detail_field(text: str, label: str):
    """The value on a ``<label>  <value>`` line of the detail pane.

    Tolerant of the renderer's padding (labels differ in length), but it
    pins the pairing: the value must sit on the same line as its label.
    """
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith(label + " "):
            return stripped[len(label) :].strip()
    return None


# The app opens on CoinsScreen; a modal returns to whichever screen pushed it.
DEFAULT_SCREEN = "CoinsScreen"


def record_run_verb(monkeypatch, app, sink):
    """Replace the worker with a recorder so nothing is ever executed."""
    # ``**_`` so the confirmation dialogs' confirmed=True re-entry is
    # recorded too — the recorder stands in for the whole method.
    monkeypatch.setattr(type(app), "run_verb", lambda self, name, **_: sink.append(name))


@pytest.fixture
def manifest(tmp_path, monkeypatch):
    """A three-coin manifest, so the coins screen and the scope logic are hermetic."""
    entries = [
        {
            "ticker": "AAA",
            "ver_id": "aaa--v1.0",
            "versions": ["v1.0.0"],
            "wallet_conf": "aaa.conf",
            "xbridge_conf": "aaa.conf",
            "repo_url": "https://example.invalid/aaa",
        },
        {
            "ticker": "BBB",
            "ver_id": "bbb--v2.0",
            "versions": ["v2.0.0", "v2.1.0"],
            "wallet_conf": "bbb.conf",
            "xbridge_conf": "bbb.conf",
            "repo_url": "https://example.invalid/bbb",
        },
        {
            "ticker": "CCC",
            "ver_id": "ccc--v3.0",
            "versions": [],
            "wallet_conf": "ccc.conf",
            "xbridge_conf": "ccc.conf",
            "repo_url": "https://example.invalid/ccc",
        },
    ]
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps(entries), encoding="utf-8")
    monkeypatch.setattr(dash.paths, "DEFAULT_MANIFEST", path)
    return entries


def seed_scope(cache, selection):
    """Persist a narrowed selection the way a previous session's Continue did."""
    scope = dash.state.defaults()
    scope["selection"] = selection
    dash.state.save(scope)


def record_audit_command(monkeypatch, captured):
    """Capture the next task's argv instead of launching the audit script."""

    def fake(argv, primary):
        captured.append(list(argv))
        return [sys.executable, "-c", "pass"]

    monkeypatch.setattr(dash.runner, "audit_command", fake)


async def wait_until(pilot, predicate, steps=150):
    """Give an async worker time to reach the next awaited milestone.

    Budget is ~5s: healthy conditions fire in well under a second, so
    anything slower is a product hang, not a slow CI box — fail fast
    instead of burning 11s per missed predicate.
    """
    for _ in range(steps):
        if predicate():
            return True
        await pilot.pause()
        await asyncio.sleep(0.01)
    return False


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
    inspect.signature(app.run).bind()  # raises TypeError if self is unbound


def test_the_widget_tree_composes_without_raising(cache):
    """A bad Button variant kills compose, so the app never draws anything."""
    write_report(cache, "findings", [], [])

    app = dash._make_app()

    async def body(app, pilot):
        # If any widget were constructed with an invalid argument, run_test()
        # would already have raised (e.g. InvalidButtonVariant) before this.
        for aid in ("analyze", "plan", "apply", "add-coin"):
            assert app.query_one(f"#act-{aid}", Button)
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
        assert "repos probed 41" in overview  # condensed Status-first layout (C1)
        assert re.search(r"\b6[0-5]s ago", overview)  # age computed from the sidecar
        assert "fleet" in overview and "findings" in overview
        # Mounting must never start an audit run: once the Log pane has been
        # laid out, it holds only the empty-state seed — no $, no run lines.
        app.query_one("#tabs", TabbedContent).active = "tab-log"
        await pilot.pause()
        text = log_text(app)
        assert "$" not in text and "done" not in text
        assert "Ctrl+P" in text, "the empty log seeds the way in (audit #13)"

    run_app(app, body, screen="coins")


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

    run_app(app, body, screen="coins")


def test_findings_table_lists_every_finding(cache):
    write_report(cache, "findings", [FINDING, dict(FINDING, coin="DGB", severity="WARN")], [])

    app = dash._make_app()

    async def body(app, pilot):
        table = app.query_one("#findings-table", DataTable)
        assert table.row_count == 2
        # Severity cells are styled Text (C2) — text stays exact, color
        # carries the rank — so compare their strings, not the objects.
        assert [str(c) for c in table.get_row_at(0)] == ["FAIL", "LYNX", "—", FINDING["detail"]]
        assert [str(c) for c in table.get_row_at(1)] == ["WARN", "DGB", "—", FINDING["detail"]]

    run_app(app, body)


def test_plan_tab_starts_empty(cache):
    write_report(cache, "findings", [], [])

    app = dash._make_app()

    async def body(app, pilot):
        status = str(app.query_one("#write-status", Static).content)
        assert "No plan yet" in status
        assert "hint" in app.query_one("#write-status").classes
        assert app.query_one("#plan-table", DataTable).row_count == 0

    run_app(app, body)


def test_plan_tab_lists_planned_writes(cache):
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


def test_a_wrong_shaped_report_json_lands_on_the_empty_default(cache):
    """A list where an object belongs lands on the ``{}`` default
    instead of raising AttributeError past the DashboardError guard."""
    write_report(cache, "findings", [], [])
    (cache / "findings.json").write_text("[1, 2]", encoding="utf-8")

    app = dash._make_app()

    async def body(app, pilot):
        assert app.workspace.report == {}, "a wrong-shaped report must land on the empty default"
        assert app.workspace.findings == []

    run_app(app, body)


def test_a_wrong_shaped_plan_json_lands_on_the_empty_plan(cache):
    write_report(cache, "findings", [], [])
    (cache / "plan-fix.json").write_text("[1, 2]", encoding="utf-8")

    app = dash._make_app()

    async def body(app, pilot):
        assert app.workspace.plan == [], "a wrong-shaped plan must land on the empty default"

    run_app(app, body)


def test_a_plan_array_of_strings_lands_on_the_empty_plan(cache):
    """Plan elements get the same element check as findings: strings
    where objects belong must land on the empty default instead of
    crashing rebuild_write's ``.get()`` calls at refresh time."""
    write_report(cache, "findings", [], [])
    write_plan(cache, ["x"])
    app = dash._make_app()

    async def body(app, pilot):
        assert app.workspace.plan == [], "string plan entries are not plan objects"
        assert app.query_one("#plan-table", DataTable).row_count == 0

    run_app(app, body)


def test_a_dict_shaped_plan_value_lands_on_the_empty_plan(cache):
    """A plan mapping is the wrong shape the same way: list() of a
    mapping yields its keys, and keys are strings, not plan objects."""
    write_report(cache, "findings", [], [])
    write_plan(cache, [])
    (cache / "plan-fix.json").write_text(
        json.dumps({"schema_version": 1, "plan": {"a": 1}, "findings": []}),
        encoding="utf-8",
    )
    app = dash._make_app()

    async def body(app, pilot):
        assert app.workspace.plan == [], "a plan mapping must land on the empty default"
        assert app.query_one("#plan-table", DataTable).row_count == 0

    run_app(app, body)


def test_a_non_dict_summary_renders_the_overview(cache):
    """A truthy non-dict summary must not reach the overview's ``.get()``
    calls: like every other report shape, it lands on the empty default."""
    write_report(cache, "findings", [], [])
    (cache / "findings.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "summary": [1, 2],
                "findings": [],
                "plan": [],
                "meta": {},
            }
        ),
        encoding="utf-8",
    )
    app = dash._make_app()

    async def body(app, pilot):
        overview = str(app.query_one("#overview", Static).content)
        assert "Fleet summary" in overview, "the overview must still render"

    run_app(app, body)


def test_a_findings_array_of_strings_lands_on_the_empty_findings(cache):
    """Non-object findings must not reach the table's ``.get()`` calls:
    strings where objects belong land on the empty default."""
    write_report(cache, "findings", ["x"], [])
    app = dash._make_app()

    async def body(app, pilot):
        assert app.workspace.findings == [], "string findings are not finding objects"
        assert app.query_one("#findings-table", DataTable).row_count == 0

    run_app(app, body)


def test_a_dict_shaped_findings_value_lands_on_the_empty_findings(cache):
    """A findings mapping is the wrong shape the same way: list() of a
    mapping yields its keys, and keys are strings, not finding objects."""
    write_report(cache, "findings", [], [])
    (cache / "findings.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "summary": {},
                "findings": {"a": 1},
                "plan": [],
                "meta": {},
            }
        ),
        encoding="utf-8",
    )
    app = dash._make_app()

    async def body(app, pilot):
        assert app.workspace.findings == [], "a findings mapping must land on the empty default"
        assert app.query_one("#findings-table", DataTable).row_count == 0

    run_app(app, body)


def test_a_broken_manifest_degrades_to_an_empty_fleet(cache, tmp_path, monkeypatch):
    """A non-array manifest raises in the agent reader; the TUI must
    degrade to an empty fleet — refusing loudly at run time — instead
    of crashing on startup."""
    bad = tmp_path / "manifest.json"
    bad.write_text('{"a": 1}', encoding="utf-8")
    monkeypatch.setattr(dash.paths, "DEFAULT_MANIFEST", bad)
    write_report(cache, "findings", [], [])
    app = dash._make_app()

    async def body(app, pilot):
        assert app.screen.query_one("#coins-continue", Button).disabled, "an empty fleet cannot be confirmed"
        app.action_continue()
        await pilot.pause()
        await press_task(app, pilot, "ports")
        await pilot.pause()
        assert "no coins in the manifest" in log_text(app)
        app.action_refresh()
        await pilot.pause()
        overview = str(app.query_one("#overview", Static).content)
        assert "0 of 0 coins" in overview, "an empty fleet is empty, not the full fleet"

    run_app(app, body, screen="coins")


# ---------------------------------------------------------------------------
# Layout
# ---------------------------------------------------------------------------


def test_the_workspace_is_four_actions_and_three_result_tabs(cache):
    write_report(cache, "findings", [], [])

    app = dash._make_app()

    async def body(app, pilot):
        assert screen_name(app) == "WorkspaceScreen"
        for aid in dash.verbs.BUTTON_ACTIONS:
            assert app.query_one(f"#act-{aid}", Button), f"missing action button for {aid}"
        for name in dash.VERBS:
            assert not app.query(f"#run-{name}"), f"verb button for {name} must be gone"
        tabs = app.query_one("#tabs", TabbedContent)
        assert [pane.id for pane in tabs.query("TabPane")] == [
            "tab-findings",
            "tab-plan",
            "tab-log",
        ]
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
# Findings columns / detail Version block / cost labels
# ---------------------------------------------------------------------------


def test_findings_columns_are_severity_coin_change_reason(cache):
    write_report(cache, "findings", [VERSION_FINDING, FINDING], [])

    app = dash._make_app()

    async def body(app, pilot):
        table = app.query_one("#findings-table", DataTable)
        assert [str(c.label) for c in table.ordered_columns] == [
            "Severity",
            "Coin",
            "Change",
            "Reason",
        ]
        upgraded = [str(c) for c in table.get_row_at(0)]
        assert upgraded == [
            "FAIL",
            "AAA",
            "v1.0.0 → v1.2.0",
            VERSION_FINDING["detail"],
        ], "Change is our_latest → remote_latest; Reason is the detail"
        plain = [str(c) for c in table.get_row_at(1)]
        assert plain[2] == "—", "a finding with no versions shows no change"
        assert plain[3] == FINDING["detail"]
        assert len(plain) == 4, "ID, category and file are detail-pane material now, not columns"

    run_app(app, body)


def test_detail_pane_renders_the_plan_entry(cache):
    write_report(cache, "findings", [VERSION_FINDING, FINDING], [])

    app = dash._make_app()

    async def body(app, pilot):
        workspace = app.workspace
        workspace.show_detail_plan(PLAN_ENTRY)
        planned = str(app.query_one("#detail", Static).content)
        assert "ver_id" not in planned
        assert detail_field(planned, "conf") == "lynx--v1.0"
        assert "line:" not in planned, "plan entries have no line to show"
        assert "file: wallet-confs/lynx--v1.0.conf" in planned

    run_app(app, body)


def test_every_action_row_carries_a_cost_label(cache):
    write_report(cache, "findings", [], [])

    app = dash._make_app()

    async def body(app, pilot):
        for aid in dash.verbs.BUTTON_ACTIONS:
            item = dash.verbs.PALETTE_VERBS[aid]
            label = str(app.query_one(f"#act-{aid}", Button).label)
            cost = dash.verbs.COST_LABELS[item.cost]
            assert label.startswith(f"[{cost}]"), (
                f"{aid} must lead with its cost class [{cost}] (truncation"
                f" eats the summary, never the safety tag), got {label!r}"
            )

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

    run_app(app, body, screen="coins")


def test_palette_submits_the_chosen_action(cache, monkeypatch):
    write_report(cache, "findings", [], [])
    app = dash._make_app()
    ran = []
    record_run_verb(monkeypatch, app, ran)

    async def body(app, pilot):
        await pilot.press("ctrl+p")
        await pilot.pause()
        app.screen.query_one("#palette-input", Input).value = "plan"
        await pilot.press("enter")
        await pilot.pause()
        assert ran == ["plan"], "palette selection did not reach run_verb"
        assert screen_name(app) == DEFAULT_SCREEN

    run_app(app, body, screen="coins")


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

    run_app(app, body, screen="coins")


def test_action_buttons_route_to_their_verbs(cache, monkeypatch):
    write_report(cache, "findings", [], [])
    app = dash._make_app()
    ran = []
    record_run_verb(monkeypatch, app, ran)

    async def body(app, pilot):
        for name in ("plan", "apply"):
            app.query_one(f"#act-{name}", Button).press()
            await pilot.pause()
        assert ran == ["plan", "apply"]

    run_app(app, body)


def test_scaffold_from_the_task_group_asks_for_a_url(cache):
    """D21: no task may launch-to-fail — scaffold asks on screen."""
    write_report(cache, "findings", [], [])

    app = dash._make_app()

    async def body(app, pilot):
        await press_task(app, pilot, "scaffold")
        await pilot.pause()
        assert screen_name(app) == "ScaffoldDialog", "scaffold must ask for the repo URL instead of failing"
        assert "$" not in log_text(app), "the audit script was launched anyway"
        await pilot.press("escape")
        await pilot.pause()
        assert screen_name(app) == "WorkspaceScreen"
        assert "$" not in log_text(app), "cancelling must not start the audit"

    run_app(app, body)


# ---------------------------------------------------------------------------
# D20: informational verbs are local reads, never a spawn
# ---------------------------------------------------------------------------


def test_list_row_reads_the_manifest_without_spawning(cache, monkeypatch, manifest):
    write_report(cache, "findings", [], [])
    captured = []
    record_audit_command(monkeypatch, captured)
    app = dash._make_app()

    async def body(app, pilot):
        app.query_one("#tabs", TabbedContent).active = "tab-log"
        await pilot.pause()
        await press_task(app, pilot, "list")
        await pilot.pause()
        text = log_text(app)
        assert "3 entries" in text, "list reads the manifest itself"
        assert "AAA" in text and "aaa--v1.0" in text, "each entry is listed"
        assert "$" not in text, "no audit command line was echoed"
        assert captured == [], "list must never spawn the audit script"

    run_app(app, body)


def test_report_row_dumps_the_last_run_meta_without_spawning(cache, monkeypatch):
    write_report(cache, "findings", [], [])
    captured = []
    record_audit_command(monkeypatch, captured)
    app = dash._make_app()

    async def body(app, pilot):
        app.query_one("#tabs", TabbedContent).active = "tab-log"
        await pilot.pause()
        await press_task(app, pilot, "report")
        await pilot.pause()
        assert "no run recorded yet" in log_text(app), "a fresh cache says so instead of running anything"

        (cache / "last-run.meta.json").write_text(
            json.dumps(
                {
                    "verb": "findings",
                    "argv": ["audit-manifest.py", "--no-changelog"],
                    "report": str(cache / "findings.json"),
                    "log": str(cache / "findings.log"),
                    "started_at": time.time() - 60,
                    "duration_seconds": 107.5,
                    "audit_exit_code": 1,
                }
            ),
            encoding="utf-8",
        )
        await press_task(app, pilot, "report")
        await pilot.pause()
        text = log_text(app)
        assert "last run" in text
        assert detail_field(text, "verb") == "findings"
        assert detail_field(text, "duration_seconds") == "107.5"
        assert detail_field(text, "audit_exit_code") == "1"
        assert captured == [], "report must never spawn the audit script"

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
        app.query_one("#tabs", TabbedContent).active = "tab-plan"
        await pilot.pause()
        # P4: the refusal is the disabled button itself — it cannot even
        # be pressed — with the status naming the producing task.
        assert app.query_one("#write-apply", Button).disabled, "Apply with no plan must not look live"
        status = str(app.query_one("#write-status", Static).content)
        assert "Plan" in status
        assert screen_name(app) == "WorkspaceScreen"
        assert ran == []

    run_app(app, body)


def test_an_empty_scope_refusal_is_visible_on_the_log_pane(cache):
    """A refusal written to the Log pane must show the Log pane."""
    write_report(cache, "findings", [], [])
    app = dash._make_app()

    async def body(app, pilot):
        app.state["selection"] = []
        app.query_one("#tabs", TabbedContent).active = "tab-findings"
        await pilot.pause()
        await press_task(app, pilot, "ports")
        await pilot.pause()
        assert app.query_one("#tabs", TabbedContent).active == "tab-log", (
            "the refusal is written into the Log pane, so it must be shown"
        )
        assert "no coins are ticked" in log_text(app)

    run_app(app, body)


def test_the_apply_row_refusal_opens_the_plan_pane(cache):
    """The Write group's apply row can be pressed from any pane, so its
    no-plan refusal must land where the message is written."""
    write_report(cache, "findings", [], [])
    app = dash._make_app()

    async def body(app, pilot):
        app.query_one("#tabs", TabbedContent).active = "tab-log"
        await pilot.pause()
        await press_task(app, pilot, "apply-fix")
        await pilot.pause()
        assert screen_name(app) == "WorkspaceScreen", "no plan opens no dialog"
        assert app.query_one("#tabs", TabbedContent).active == "tab-plan", (
            "the refusal is written into the Plan pane, so it must be shown"
        )
        status = str(app.query_one("#write-status", Static).content)
        assert "Nothing to apply" in status

    run_app(app, body)


def test_apply_with_a_plan_requires_confirmation(cache, monkeypatch):
    write_report(cache, "findings", [], [])
    write_plan(cache, [PLAN_ENTRY])
    app = dash._make_app()
    ran = []
    record_run_verb(monkeypatch, app, ran)

    async def body(app, pilot):
        app.query_one("#tabs", TabbedContent).active = "tab-plan"
        await pilot.pause()
        app.query_one("#write-apply", Button).press()
        await pilot.pause()
        assert screen_name(app) == "ConfirmScreen"
        assert "1 write(s)" in str(app.screen.query_one("#confirm-body").content)
        assert ran == [], "confirming must not be implicit"

        await pilot.press("escape")
        await pilot.pause()
        assert screen_name(app) == "WorkspaceScreen"
        assert ran == [], "cancelling must not run the write"

    run_app(app, body)


def test_confirming_the_dialog_is_what_runs_the_write(cache, monkeypatch):
    write_report(cache, "findings", [], [])
    write_plan(cache, [PLAN_ENTRY])
    app = dash._make_app()
    ran = []
    record_run_verb(monkeypatch, app, ran)

    async def body(app, pilot):
        app.query_one("#tabs", TabbedContent).active = "tab-plan"
        await pilot.pause()
        app.query_one("#write-apply", Button).press()
        await pilot.pause()
        assert screen_name(app) == "ConfirmScreen"
        app.screen.query_one("#confirm-yes", Button).press()
        await pilot.pause()
        assert ran == ["apply-fix"]
        assert screen_name(app) == "WorkspaceScreen"

    run_app(app, body)


def test_the_apply_task_row_opens_the_confirmation_instead_of_running(
    cache,
    manifest,
    monkeypatch,
):
    """The Write group's apply row must not bypass the Plan tab's dialog."""
    captured = []
    record_audit_command(monkeypatch, captured)
    seed_scope(cache, ["AAA", "BBB"])
    write_report(cache, "findings", [], [])
    # The entry's coin must be ticked: a scoped apply ignores the rest.
    write_plan(cache, [dict(PLAN_ENTRY, coin="AAA", ver_id="aaa--v1.0")])
    app = dash._make_app()

    async def body(app, pilot):
        await press_task(app, pilot, "apply-fix")
        await pilot.pause()
        assert screen_name(app) == "ConfirmScreen", "a write must never start without its confirmation"
        body_text = str(app.screen.query_one("#confirm-body").content)
        assert "1 write(s)" in body_text, "the dialog lists what would change"
        assert "2 of 3" in body_text, "the confirmation carries the scope"
        assert captured == [], "pressing the row must not spawn anything"

        app.screen.query_one("#confirm-yes", Button).press()
        assert await wait_until(pilot, lambda: len(captured) == 1), "confirming is what starts the write"
        assert "--apply-plan" in captured[0], "the confirmed run applies the reviewed file"
        assert captured[0][captured[0].index("--apply-plan") + 1].endswith("plan-fix.apply.json"), (
            "the confirmed subset travels in its own file"
        )
        assert screen_name(app) == "WorkspaceScreen"

    run_app(app, body)


def test_the_apply_dialog_counts_only_the_scoped_writes(
    cache,
    manifest,
    monkeypatch,
):
    """The confirmation must describe the run it confirms: a scoped
    apply only touches ticked coins, so the numbers are the scoped
    subset, not the whole plan.
    """
    captured = []
    record_audit_command(monkeypatch, captured)
    seed_scope(cache, ["AAA"])
    write_report(cache, "findings", [], [])
    write_plan(
        cache,
        [
            dict(PLAN_ENTRY, coin="AAA", ver_id="aaa--v1.0", file="wallet-confs/aaa.conf"),
            dict(PLAN_ENTRY, coin="AAA", ver_id="aaa--v1.0", file="wallet-confs/aaa-extra.conf"),
            dict(PLAN_ENTRY, coin="BBB", ver_id="bbb--v2.0", file="wallet-confs/bbb.conf"),
            dict(PLAN_ENTRY, coin="BBB", ver_id="bbb--v2.0", file="wallet-confs/bbb.conf", key="rpcport"),
            dict(PLAN_ENTRY, coin="CCC", ver_id="ccc--v3.0", file="wallet-confs/ccc.conf"),
        ],
    )
    app = dash._make_app()

    async def body(app, pilot):
        await press_task(app, pilot, "apply-fix")
        await pilot.pause()
        assert screen_name(app) == "ConfirmScreen"
        body_text = str(app.screen.query_one("#confirm-body").content)
        assert "2 write(s)" in body_text, "only AAA's two entries run under this scope, not the whole plan"
        assert "5 write(s)" not in body_text
        assert "1 of 3" in body_text, "the scope line says what was left out"

    run_app(app, body)


def test_the_apply_dialog_refuses_an_empty_scoped_subset(
    cache,
    manifest,
    monkeypatch,
):
    """A scope with no planned writes confirms nothing: refuse like the
    no-plan path instead of opening a "0 write(s)" dialog over a no-op."""
    captured = []
    record_audit_command(monkeypatch, captured)
    seed_scope(cache, ["AAA"])
    write_report(cache, "findings", [], [])
    write_plan(cache, [dict(PLAN_ENTRY, coin="BBB", ver_id="bbb--v2.0")])
    app = dash._make_app()

    async def body(app, pilot):
        app.query_one("#tabs", TabbedContent).active = "tab-plan"
        await pilot.pause()
        await press_task(app, pilot, "apply-fix")
        await pilot.pause()
        assert screen_name(app) == "WorkspaceScreen", "empty scope opens no dialog"
        status = str(app.query_one("#write-status", Static).content)
        assert "Nothing to apply" in status
        assert captured == [], "a refusal must not spawn anything"

    run_app(app, body)


def test_the_update_versions_task_row_requires_confirmation(cache, monkeypatch):
    """A manifest-writing task from its own row confirms before it runs."""
    captured = []
    record_audit_command(monkeypatch, captured)
    app = dash._make_app()

    async def body(app, pilot):
        await press_task(app, pilot, "update-versions")
        await pilot.pause()
        assert screen_name(app) == "ConfirmScreen", "pressing the row must open a confirmation, not a run"
        title = str(app.screen.query_one("#confirm-title").content)
        assert "update-versions" in title, "the dialog names the task"
        body_text = str(app.screen.query_one("#confirm-body").content)
        assert "latest tag" in body_text, "the dialog body comes from the task's own summary"
        assert captured == [], "pressing the row must not spawn anything"

        await pilot.press("escape")
        await pilot.pause()
        assert screen_name(app) == "WorkspaceScreen"
        assert captured == [], "cancelling must not start the write"

        await press_task(app, pilot, "update-versions")
        await pilot.pause()
        app.screen.query_one("#confirm-yes", Button).press()
        assert await wait_until(pilot, lambda: len(captured) == 1), "confirming is what starts the write"

    run_app(app, body)


def test_preview_button_runs_the_dry_run_verb(cache, monkeypatch):
    write_report(cache, "findings", [], [])
    write_plan(cache, [dict(PLAN_ENTRY)])
    app = dash._make_app()
    ran = []
    record_run_verb(monkeypatch, app, ran)

    async def body(app, pilot):
        app.query_one("#tabs", TabbedContent).active = "tab-plan"
        await pilot.pause()
        # A plan exists so the button is live (P4 disables it without one).
        assert not app.query_one("#write-preview-plan", Button).disabled
        app.query_one("#write-preview-plan", Button).press()
        await pilot.pause()
        assert ran == ["plan"], "the preview button must never apply"

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
        app.query_one("#tabs", TabbedContent).active = "tab-log"
        app.query_one("#tabs", TabbedContent).active = "tab-log"
        assert await wait_until(
            pilot,
            lambda: app.query_one("#run-log", RichLog)._size_known,
            steps=50,
        ), "the log pane must lay out before the diff lands"
        app.query_one("#write-preview-diff", Button).press()
        await pilot.pause()
        await pilot.pause()
        assert app.query_one("#tabs", TabbedContent).active == "tab-log", "the diff previews in the log tab"
        assert "git diff --stat" in log_text(app)

    run_app(app, body)


# ---------------------------------------------------------------------------
# Two screens: pick the scope first, run from the workspace
# ---------------------------------------------------------------------------


def test_the_coins_screen_lists_every_entry_with_its_last_known_status(cache, manifest):
    write_report(
        cache,
        "findings",
        [
            dict(FINDING, coin="AAA", severity="FAIL"),
            dict(FINDING, coin="AAA", severity="WARN", id="SECOND-CHECK", detail="a second check under warn"),
            dict(FINDING, coin="CCC", severity="WEIRD"),
            dict(FINDING, coin="CCC", severity="INFO"),
        ],
        [],
    )

    app = dash._make_app()

    async def body(app, pilot):
        assert screen_name(app) == "CoinsScreen", "the app opens on the scope picker"
        assert app.screen.query_one("#coin-0", Checkbox).value, "a fresh scope starts on the whole fleet"
        aaa = str(app.screen.query_one("#coin-info-0").content)
        assert "aaa--v1.0" in aaa and "v1.0.0" in aaa, "conf id and versions are listed"
        assert "FAIL" in aaa, "the worst known severity is the coin's status"
        bbb = str(app.screen.query_one("#coin-info-1").content)
        assert "v2.0.0" in bbb and "v2.1.0" in bbb, "every declared version is shown"
        assert "—" in bbb, "a coin that never reported has no status"
        ccc = str(app.screen.query_one("#coin-info-2").content)
        assert "INFO" in ccc, "an unranked severity must rank below a known one"
        assert "3 of 3" in str(app.screen.query_one("#coins-count").content)

    run_app(app, body, screen="coins")


def test_the_filter_and_bulk_buttons_reshape_the_selection(cache, manifest):
    app = dash._make_app()

    async def body(app, pilot):
        assert screen_name(app) == "CoinsScreen"
        app.screen.query_one("#coins-filter", Input).focus()
        await pilot.press("b", "b")
        await pilot.pause()
        assert app.state["filter"] == "bb", "the filter is part of the persisted scope"
        assert not app.screen.query_one("#row-0").display, "the filter hides misses"
        assert app.screen.query_one("#row-1").display, "and keeps hits"
        # Bulk buttons act on the whole fleet, not only the filtered view.
        app.screen.query_one("#coins-invert", Button).press()
        await pilot.pause()
        assert "Tick at least one coin" in str(app.screen.query_one("#coins-count").content), (
            "empty selection names the next action instead of a bare 0"
        )
        app.screen.query_one("#coins-all", Button).press()
        await pilot.pause()
        assert "3 of 3" in str(app.screen.query_one("#coins-count").content)
        app.screen.query_one("#coins-none", Button).press()
        await pilot.pause()
        assert "Tick at least one coin" in str(app.screen.query_one("#coins-count").content)
        assert app.screen.query_one("#coins-continue", Button).disabled, "an empty scope cannot be confirmed"

    run_app(app, body, screen="coins")


def test_continue_enters_the_workspace_and_ctrl_o_returns_to_the_coins(cache, manifest):
    app = dash._make_app()

    async def body(app, pilot):
        assert screen_name(app) == "CoinsScreen"
        app.screen.query_one("#coins-continue", Button).press()
        await pilot.pause()
        assert screen_name(app) == "WorkspaceScreen"
        assert app.state["selection"] is None, "all ticked means the full fleet"

        await pilot.press("ctrl+o")
        await pilot.pause()
        assert screen_name(app) == "CoinsScreen"
        app.screen.query_one("#coin-2", Checkbox).value = False
        await pilot.pause()
        app.screen.query_one("#coins-continue", Button).press()
        await pilot.pause()
        assert screen_name(app) == "WorkspaceScreen"
        assert app.state["selection"] == ["AAA", "BBB"], "Continue commits the ticked coins as the next run's scope"

        await pilot.press("ctrl+o")
        await pilot.pause()
        assert screen_name(app) == "CoinsScreen"
        await pilot.press("ctrl+o")
        await pilot.pause()
        assert screen_name(app) == "CoinsScreen", "ctrl+o on the coins screen is a no-op"

    run_app(app, body, screen="coins")


def test_a_narrowed_readonly_run_asks_for_confirmation_with_the_fleet_caveat(
    cache,
    manifest,
    monkeypatch,
):
    captured = []
    record_audit_command(monkeypatch, captured)
    seed_scope(cache, ["AAA", "BBB"])
    app = dash._make_app()

    async def body(app, pilot):
        assert screen_name(app) == "WorkspaceScreen"
        await press_task(app, pilot, "ports")
        await pilot.pause()
        assert screen_name(app) == "ConfirmScreen", "a narrowed run must confirm its scope"
        title = str(app.screen.query_one("#confirm-title").content)
        body_text = str(app.screen.query_one("#confirm-body").content)
        assert "Run ports on 2 of 3 coins" in title, "the confirm names the exact scope"
        assert "stay fleet-wide" in body_text, "the caveat must say what the scope does not narrow"
        await pilot.press("escape")
        await pilot.pause()
        assert screen_name(app) == "WorkspaceScreen"
        assert captured == [], "cancelling must not start the task"

    run_app(app, body)


def test_a_narrowed_write_confirmation_carries_the_scope(cache, manifest):
    seed_scope(cache, ["AAA", "BBB"])
    write_report(cache, "findings", [], [])
    write_plan(cache, [dict(PLAN_ENTRY, coin="AAA", ver_id="aaa--v1.0")])
    app = dash._make_app()

    async def body(app, pilot):
        app.query_one("#write-apply", Button).press()
        await pilot.pause()
        assert screen_name(app) == "ConfirmScreen"
        body_text = str(app.screen.query_one("#confirm-body").content)
        assert "1 write(s)" in body_text
        assert "2 of 3" in body_text, "a narrowed write must show its scope before it runs"

    run_app(app, body)


def test_a_narrowed_selection_narrows_the_argv_while_the_full_fleet_does_not(
    cache,
    manifest,
    monkeypatch,
):
    captured = []
    record_audit_command(monkeypatch, captured)
    app = dash._make_app()

    async def body(app, pilot):
        # Full fleet: the audit runs unmodified — no --ticker, no modal.
        await press_task(app, pilot, "ports")
        assert await wait_until(pilot, lambda: captured), "the task must reach the runner"
        assert "--ticker" not in captured[0], "the full fleet is not narrowed"

        # Narrowed scope: the ticked coins become the audit's --ticker filter.
        app.state["selection"] = ["AAA", "BBB"]
        await press_task(app, pilot, "ports")
        await pilot.pause()
        was_modal = screen_name(app) == "ConfirmScreen"
        if was_modal:
            app.screen.query_one("#confirm-yes", Button).press()
        assert await wait_until(pilot, lambda: len(captured) == 2), "the confirmed task must reach the runner"
        argv = captured[1]
        assert "--ticker" in argv, "a narrowed selection must narrow the audit argv"
        assert argv[argv.index("--ticker") + 1] == "AAA,BBB"
        assert was_modal, "a narrowed readonly run confirms its scope first"

    run_app(app, body)


def test_a_scope_naming_a_delisted_coin_runs_only_the_live_ones(
    cache,
    manifest,
    monkeypatch,
):
    """A delisted ticker counts for neither the dialog nor the argv."""
    captured = []
    record_audit_command(monkeypatch, captured)
    app = dash._make_app()

    async def body(app, pilot):
        app.state["selection"] = ["AAA", "GHOST"]
        await press_task(app, pilot, "ports")
        await pilot.pause()
        assert screen_name(app) == "ConfirmScreen", "a live coin is still ticked"
        title = str(app.screen.query_one("#confirm-title").content)
        assert "Run ports on 1 of 3 coins" in title, "a delisted coin must not count toward the scope"
        app.screen.query_one("#confirm-yes", Button).press()
        assert await wait_until(pilot, lambda: captured), "the confirmed task must reach the runner"
        assert "--ticker" in captured[0]
        assert captured[0][captured[0].index("--ticker") + 1] == "AAA", "a delisted coin must not reach the audit argv"

    run_app(app, body)


def test_the_overview_counts_only_live_coins(cache, manifest):
    """The overview scope line and the confirm dialogs must agree: a
    delisted ticker counts in neither.

    The ghost is set mid-session, past the picker: Continue heals a
    persisted ghost (no checkbox to tick it with), but state set while
    the workspace is up reaches the overview verbatim.
    """
    write_report(cache, "findings", [], [])
    app = dash._make_app()

    async def body(app, pilot):
        app.state["selection"] = ["AAA", "GHOST"]
        app.action_refresh()
        await pilot.pause()
        overview = str(app.query_one("#overview", Static).content)
        assert "1 of 3 coins" in overview, "a delisted coin must not count toward the overview scope"

    run_app(app, body)


def test_the_scope_dialog_ignores_untickable_entries(cache, tmp_path, monkeypatch):
    """Entries without a string ticker cannot be ticked — the picker
    skips them — so they must not inflate the dialog's fleet total."""
    entries = [
        {
            "ticker": "AAA",
            "ver_id": "aaa--v1.0",
            "versions": ["v1.0.0"],
            "wallet_conf": "aaa.conf",
            "xbridge_conf": "aaa.conf",
            "repo_url": "https://example.invalid/aaa",
        },
        {
            "ticker": "BBB",
            "ver_id": "bbb--v2.0",
            "versions": ["v2.0.0"],
            "wallet_conf": "bbb.conf",
            "xbridge_conf": "bbb.conf",
            "repo_url": "https://example.invalid/bbb",
        },
        {
            "ticker": 123,
            "ver_id": "bad--v9",
            "versions": [],
            "wallet_conf": "bad.conf",
            "xbridge_conf": "bad.conf",
            "repo_url": "https://example.invalid/bad",
        },
    ]
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps(entries), encoding="utf-8")
    monkeypatch.setattr(dash.paths, "DEFAULT_MANIFEST", path)
    seed_scope(cache, ["AAA"])
    write_report(cache, "findings", [], [])
    app = dash._make_app()

    async def body(app, pilot):
        await press_task(app, pilot, "ports")
        await pilot.pause()
        assert screen_name(app) == "ConfirmScreen"
        title = str(app.screen.query_one("#confirm-title").content)
        assert "Run ports on 1 of 2 coins" in title, "an untickable entry is not part of the fleet"

    run_app(app, body)


def test_the_list_dump_renders_string_versions_as_unknown(
    cache,
    tmp_path,
    monkeypatch,
):
    """Same corrupt input as the picker test: the local list dump must
    render "—", not join the string into characters."""
    entries = [
        {
            "ticker": "AAA",
            "ver_id": "aaa--v1.0",
            "versions": "v1.0.0",
            "wallet_conf": "aaa.conf",
            "xbridge_conf": "aaa.conf",
            "repo_url": "https://example.invalid/aaa",
        },
    ]
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps(entries), encoding="utf-8")
    monkeypatch.setattr(dash.paths, "DEFAULT_MANIFEST", path)
    app = dash._make_app()

    async def body(app, pilot):
        await press_task(app, pilot, "list")
        await pilot.pause()
        assert "aaa--v1.0   —" in log_text(app), "string versions must render as unknown in the list dump too"

    run_app(app, body)


def test_a_non_string_started_at_renders_as_never(cache):
    """The sidecar promises a dict, not field types: a wrong-typed
    started_at must degrade to "never", not TypeError the refresh."""
    write_report(cache, "findings", [], [])
    (cache / "findings.meta.json").write_text(
        json.dumps({"verb": "findings", "started_at": "bad"}),
        encoding="utf-8",
    )
    app = dash._make_app()

    async def body(app, pilot):
        app.action_refresh()
        await pilot.pause()
        overview = str(app.query_one("#overview", Static).content)
        assert "never" in overview, "a bad timestamp is no timestamp"

    run_app(app, body)


def test_a_boolean_started_at_renders_as_never(cache):
    """`True` is an `int` instance, so a bare isinstance check renders an
    age for it — the timestamp guard must exclude booleans."""
    write_report(cache, "findings", [], [])
    (cache / "findings.meta.json").write_text(
        json.dumps({"verb": "findings", "started_at": True}),
        encoding="utf-8",
    )
    app = dash._make_app()

    async def body(app, pilot):
        app.action_refresh()
        await pilot.pause()
        overview = str(app.query_one("#overview", Static).content)
        assert "never" in overview

    run_app(app, body)


def test_the_palette_does_not_stack_over_a_confirmation(
    cache,
    manifest,
    monkeypatch,
):
    """Ctrl+P over an open confirm must not stack a second modal:
    confirming twice would launch two exclusive workers."""
    captured = []
    record_audit_command(monkeypatch, captured)
    seed_scope(cache, ["AAA", "BBB"])
    write_report(cache, "findings", [], [])
    app = dash._make_app()

    async def body(app, pilot):
        await press_task(app, pilot, "ports")
        await pilot.pause()
        assert screen_name(app) == "ConfirmScreen"
        await pilot.press("ctrl+p")
        await pilot.pause()
        assert screen_name(app) == "ConfirmScreen", "the palette must not open over a confirmation"

    run_app(app, body)


def test_null_plan_bounds_render_as_dashes(cache):
    """The plan table cannot omit cells like the detail pane omits
    lines: null bounds render as "—", never the string "None"."""
    write_report(cache, "findings", [], [])
    write_plan(cache, [dict(PLAN_ENTRY, old=None, new=None)])
    app = dash._make_app()

    async def body(app, pilot):
        row = app.query_one("#plan-table", DataTable).get_row_at(0)
        assert row[3] == "—" and row[4] == "—", "null bounds are not the text None"

    run_app(app, body)


def test_the_plan_detail_pane_renders_null_bounds_as_dashes(cache):
    """The table renders null bounds as "—"; the detail pane must not
    show the string "None" for the same row."""
    write_report(cache, "findings", [], [])
    write_plan(cache, [dict(PLAN_ENTRY, old=None, new=None)])
    app = dash._make_app()

    async def body(app, pilot):
        app.query_one("#tabs", TabbedContent).active = "tab-plan"
        await pilot.pause()
        table = app.query_one("#plan-table", DataTable)
        table.focus()
        await pilot.press("down")
        await pilot.pause()
        detail = str(app.query_one("#detail", Static).content)
        assert "None" not in detail, "null bounds are not the text None"
        assert "—" in detail

    run_app(app, body)


def test_a_bare_object_finding_renders_no_none_headers(cache):
    """`[{}]` is a kept degraded state (matrix), so highlighting it must
    render dashes, never `severity  None`."""
    write_report(cache, "findings", [{}], [])
    app = dash._make_app()

    async def body(app, pilot):
        table = app.query_one("#findings-table", DataTable)
        table.focus()
        await pilot.press("down")
        await pilot.pause()
        detail = str(app.query_one("#detail", Static).content)
        assert "None" not in detail

    run_app(app, body)


def test_the_plan_detail_pane_renders_missing_evidence_as_a_dash(cache):
    """Most real entries pass no evidence: like every other null, it
    renders as "—", never "evidence: None"."""
    write_report(cache, "findings", [], [])
    write_plan(cache, [dict(PLAN_ENTRY, old=None, new=None, evidence=None)])
    app = dash._make_app()

    async def body(app, pilot):
        app.query_one("#tabs", TabbedContent).active = "tab-plan"
        await pilot.pause()
        table = app.query_one("#plan-table", DataTable)
        table.focus()
        await pilot.press("down")
        await pilot.pause()
        detail = str(app.query_one("#detail", Static).content)
        assert "evidence: None" not in detail
        assert "evidence: —" in detail

    run_app(app, body)


def test_continue_over_an_empty_fleet_commits_the_full_fleet(
    cache,
    tmp_path,
    monkeypatch,
):
    """Continuing with no coins to tick must persist the full fleet:
    committing [] would poison the next start over a healthy manifest
    with an unticked 0-of-N scope."""
    bad = tmp_path / "manifest.json"
    bad.write_text('{"a": 1}', encoding="utf-8")
    monkeypatch.setattr(dash.paths, "DEFAULT_MANIFEST", bad)
    app = dash._make_app()

    async def body(app, pilot):
        app.action_continue()
        await pilot.pause()
        assert app.state["selection"] is None, "an empty fleet has nothing to narrow"

    run_app(app, body, screen="coins")


def test_the_picker_lays_out_one_line_rows(cache, manifest):
    """Mounted rows must also paint: one line per coin, footer on screen.

    Two CSS traps broke this with zero test signal (tests only read the
    DOM): `Horizontal` defaults to `1fr` height, so an unpinned container
    eats the viewport; `ToggleButton`'s tall border makes each Checkbox
    three lines tall.
    """
    app = dash._make_app()

    async def body(app, pilot):
        row = app.screen.query_one("#row-0")
        assert row.region.height == 1, "a coin row is one line"
        footer = app.screen.query_one("#coins-footer")
        assert footer.region.y + footer.region.height <= 42, "the footer stays inside the viewport"

    run_app(app, body, screen="coins")


def test_continue_dedupes_duplicate_ticker_rows(cache, tmp_path, monkeypatch):
    """Duplicate-ticker rows tick independently but commit once: the
    stored scope must match what `state.load` would read back."""
    entries = [
        {
            "ticker": "AAA",
            "ver_id": "aaa--v1.0",
            "versions": ["v1.0.0"],
            "wallet_conf": "aaa.conf",
            "xbridge_conf": "aaa.conf",
            "repo_url": "https://example.invalid/aaa",
        },
        {
            "ticker": "AAA",
            "ver_id": "aaa--v2.0",
            "versions": ["v2.0.0"],
            "wallet_conf": "aaa2.conf",
            "xbridge_conf": "aaa2.conf",
            "repo_url": "https://example.invalid/aaa2",
        },
        {
            "ticker": "BBB",
            "ver_id": "bbb--v2.0",
            "versions": ["v2.0.0"],
            "wallet_conf": "bbb.conf",
            "xbridge_conf": "bbb.conf",
            "repo_url": "https://example.invalid/bbb",
        },
    ]
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps(entries), encoding="utf-8")
    monkeypatch.setattr(dash.paths, "DEFAULT_MANIFEST", path)
    app = dash._make_app()

    async def body(app, pilot):
        app.screen.query_one("#coin-2", Checkbox).value = False
        await pilot.pause()
        app.screen.query_one("#coins-continue", Button).press()
        await pilot.pause()
        assert app.state["selection"] == ["AAA"], "one ticker commits once"

    run_app(app, body, screen="coins")


def test_a_fresh_state_over_an_empty_fleet_is_not_the_full_fleet(
    cache,
    tmp_path,
    monkeypatch,
):
    """selection None means full fleet only when a fleet exists: over an
    empty (broken) manifest it must read as empty, not full."""
    bad = tmp_path / "manifest.json"
    bad.write_text('{"a": 1}', encoding="utf-8")
    monkeypatch.setattr(dash.paths, "DEFAULT_MANIFEST", bad)
    write_report(cache, "findings", [], [])
    app = dash._make_app()

    async def body(app, pilot):
        app.state["selection"] = None
        app.action_refresh()
        await pilot.pause()
        overview = str(app.query_one("#overview", Static).content)
        assert "0 of 0 coins" in overview

    run_app(app, body)


def test_a_ticker_that_is_no_valid_widget_id_still_ticks(
    cache,
    tmp_path,
    monkeypatch,
):
    """Widget ids come from row positions, never the raw ticker: a coin
    like "A B" must mount, tick and run instead of breaking compose."""
    entries = [
        {
            "ticker": "AAA",
            "ver_id": "aaa--v1.0",
            "versions": ["v1.0.0"],
            "wallet_conf": "aaa.conf",
            "xbridge_conf": "aaa.conf",
            "repo_url": "https://example.invalid/aaa",
        },
        {
            "ticker": "A B",
            "ver_id": "ab--v1.0",
            "versions": ["v1.0.0"],
            "wallet_conf": "ab.conf",
            "xbridge_conf": "ab.conf",
            "repo_url": "https://example.invalid/ab",
        },
    ]
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps(entries), encoding="utf-8")
    monkeypatch.setattr(dash.paths, "DEFAULT_MANIFEST", path)
    write_report(cache, "findings", [], [])
    app = dash._make_app()

    async def body(app, pilot):
        boxes = app.screen.query("#coins-list Checkbox")
        assert len(boxes) == 2, "both coins must mount"
        app.action_continue()
        await pilot.pause()
        assert app.state["selection"] is None, "all ticked is the full fleet"

    run_app(app, body, screen="coins")


def test_a_string_versions_value_renders_as_unknown(cache, tmp_path, monkeypatch):
    """A string where the versions list belongs must not join into
    characters: like every other wrong shape, it renders as unknown."""
    entries = [
        {
            "ticker": "AAA",
            "ver_id": "aaa--v1.0",
            "versions": "v1.0.0",
            "wallet_conf": "aaa.conf",
            "xbridge_conf": "aaa.conf",
            "repo_url": "https://example.invalid/aaa",
        },
    ]
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps(entries), encoding="utf-8")
    monkeypatch.setattr(dash.paths, "DEFAULT_MANIFEST", path)
    app = dash._make_app()

    async def body(app, pilot):
        info = str(app.screen.query_one("#coin-info-0").content)
        assert "aaa--v1.0   —" in info, (
            "a string versions value must render as unknown in its own slot, not join into characters"
        )

    run_app(app, body, screen="coins")


def test_an_explicit_full_list_scope_displays_as_the_full_fleet(
    cache,
    manifest,
    monkeypatch,
):
    """A persisted explicit-full-list scope (older dashboard.json) is the
    full fleet: no "N of N" line anywhere, no --ticker on the run."""
    captured = []
    record_audit_command(monkeypatch, captured)
    write_report(cache, "findings", [], [])
    app = dash._make_app()

    async def body(app, pilot):
        app.state["selection"] = ["AAA", "BBB", "CCC"]
        app.action_refresh()
        await pilot.pause()
        overview = str(app.query_one("#overview", Static).content)
        assert "full fleet" in overview
        assert "3 of 3 coins" not in overview
        await press_task(app, pilot, "ports")
        assert await wait_until(pilot, lambda: captured), "the task must run"
        assert "--ticker" not in captured[0], "the full fleet is not narrowed"

    run_app(app, body)


def test_scaffold_never_inherits_the_scope_tickers(
    cache,
    manifest,
    monkeypatch,
):
    """Scope cannot apply to a repo-URL verb: the dialog's launch carries
    the URL and no --ticker, whatever the picker holds."""
    write_report(cache, "findings", [], [])
    seed_scope(cache, ["AAA", "BBB"])
    app = dash._make_app()
    started = []
    monkeypatch.setattr(type(app), "_start_verb", lambda self, opts: started.append(opts))

    async def body(app, pilot):
        await press_task(app, pilot, "scaffold")
        await pilot.pause()
        assert screen_name(app) == "ScaffoldDialog"
        app.screen.query_one("#scaffold-input", Input).value = "https://github.com/example/coin-core"
        await pilot.pause()
        app.screen.query_one("#scaffold-yes", Button).press()
        await pilot.pause()
        assert started, "submitting the dialog must reach the worker"
        assert getattr(started[0], "tickers", None) is None, "scope must not leak into scaffold"
        assert started[0].repo_url == "https://github.com/example/coin-core"

    run_app(app, body)


# ---------------------------------------------------------------------------
# Run feedback: strip, phase label, Stop
# ---------------------------------------------------------------------------


def test_the_run_strip_exists_and_stands_down_while_idle(cache):
    app = dash._make_app()

    async def body(app, pilot):
        assert "Ctrl+P" in str(app.query_one("#run-phase", Static).content), "idle names the way to start a task"
        assert not str(app.query_one("#run-elapsed", Static).content)
        stop = app.query_one("#run-stop", Button)
        assert stop.disabled, "Stop is armed only while a task is live"

    run_app(app, body)


def test_the_stop_button_kills_a_live_child(cache, monkeypatch):
    # A real, sleeping child — not the audit — proves Stop reaches the
    # process itself, not just the UI around it.
    def sleeper(argv, report_path):
        return [sys.executable, "-c", "import time\nprint('alive', flush=True)\ntime.sleep(30)\n"]

    monkeypatch.setattr(dash.runner, "audit_command", sleeper)
    app = dash._make_app()

    async def body(app, pilot):
        await press_task(app, pilot, "ports")
        assert await wait_until(pilot, lambda: app.live_run is not None), "the app must keep a handle to the live child"
        run = app.live_run
        assert await wait_until(
            pilot,
            lambda: "⏱" in str(app.query_one("#run-elapsed", Static).content),
        ), "the elapsed timer runs while a task is live"
        assert not app.query_one("#run-stop", Button).disabled

        app.query_one("#run-stop", Button).press()
        assert await wait_until(pilot, lambda: run.proc.returncode is not None), (
            "Stop must terminate the child, not just hide it"
        )
        assert run.proc.returncode != 0
        log_path = cache / "ports.log"
        assert await wait_until(pilot, log_path.is_file), "the worker writes its capture on the way out"
        assert "stopped by user" in log_path.read_text(encoding="utf-8")
        assert await wait_until(
            pilot,
            lambda: app.query_one("#run-stop", Button).disabled,
        ), "the strip stands down when the run ends"

    run_app(app, body)


def test_only_stop_reports_a_run_as_user_stopped(cache, monkeypatch):
    """A second task never supersedes the live one; only Stop ends it.

    Supersedes test_a_run_cancelled_by_its_successor (removed): the old
    behavior — second launch cancels the first through the exclusive
    worker group — discarded minutes of probe per stray click, so the
    gate now refuses while live. The "only Stop says stopped" half of
    the old contract is preserved here.
    """

    def sleeper(argv, report_path):
        return [sys.executable, "-c", "import time\nprint('alive', flush=True)\ntime.sleep(30)\n"]

    monkeypatch.setattr(dash.runner, "audit_command", sleeper)
    app = dash._make_app()

    async def body(app, pilot):
        await press_task(app, pilot, "ports")
        assert await wait_until(pilot, lambda: app.live_run is not None), (
            "the first task must be live before the second is refused"
        )
        first = app.live_run
        await press_task(app, pilot, "cross-check")
        await pilot.pause()
        assert app.live_run is first, "a second task never kills the live one"
        assert "still running" in log_text(app), "the refusal says why"
        app.query_one("#run-stop", Button).press()
        assert await wait_until(pilot, lambda: app.live_run is None)
        log_path = cache / "ports.log"
        assert await wait_until(
            pilot,
            lambda: log_path.is_file() and "stopped by user" in log_path.read_text(encoding="utf-8"),
        ), "the stopped run writes its capture on the way out"
        assert first.stopped is True, "Stop marks the run it ended"

    run_app(app, body)


def test_the_phase_label_follows_progress_and_stays_out_of_the_log(cache, monkeypatch):
    # The child-output line is assembled at runtime so the ``$ <cmd>`` echo
    # in the log cannot satisfy it: only the child's own output contains it.
    child = (
        "import json, time\n"
        "print('@@PROGRESS@@ ' + json.dumps({'phase': 'param-check', 'index': 2,"
        " 'total': 5, 'ticker': 'LTC', 'verb': 'ports', 'ts': 1.0}), flush=True)\n"
        "print('hum' + 'an line', flush=True)\n"
        "time.sleep(0.5)\n"
    )
    monkeypatch.setattr(
        dash.runner,
        "audit_command",
        lambda argv, report_path: [sys.executable, "-c", child],
    )
    app = dash._make_app()

    async def body(app, pilot):
        await press_task(app, pilot, "ports")
        assert await wait_until(
            pilot,
            lambda: "param-check" in str(app.query_one("#run-phase", Static).content),
        ), "the phase label mirrors the newest progress event"
        phase = str(app.query_one("#run-phase", Static).content)
        assert "2/5" in phase and "LTC" in phase, "index/total and ticker are shown"
        assert await wait_until(pilot, lambda: "human line" in log_text(app)), "the child's own output reaches the log"
        assert await wait_until(pilot, lambda: app.query_one("#run-stop", Button).disabled), (
            "a run that exits on its own stands the strip down"
        )
        lines = log_text(app).splitlines()
        assert not any(line.startswith("@@PROGRESS@@") for line in lines), (
            "machine lines stay out of the RichLog — the capture keeps them"
        )
        assert "Ctrl+P" in str(app.query_one("#run-phase", Static).content)
        assert not str(app.query_one("#run-elapsed", Static).content)

    run_app(app, body)


def test_the_log_does_not_double_every_child_line(cache, monkeypatch):
    """A child line must land as exactly one row, not row + blank.

    stream_lines hands the display callback the capture's raw line —
    trailing newline kept, because the log file's join depends on it —
    while RichLog renders a trailing newline as a blank row. The
    newline is therefore the display adapter's to strip, not the
    runner's.
    """
    write_report(cache, "findings", [], [])

    def _writer(argv, report_path):
        # The stub must write the verb's report file: a child that exits
        # 0 without one is a loud ERROR since the missing-report fix, not
        # a finish. (One argv token per line: a literal newline inside -c
        # would land in the "$ cmd" echo, which is not what this is about.)
        code = (
            "import json; json.dump({'schema_version': 1, 'summary': {}, "
            "'findings': [], 'plan': [], 'meta': {}}, "
            f"open({str(report_path)!r}, 'w'));"
            "print('first line');print('second line')"
        )
        return [sys.executable, "-c", code]

    monkeypatch.setattr(dash.runner, "audit_command", _writer)
    app = dash._make_app()

    async def body(app, pilot):
        await press_task(app, pilot, "ports")
        assert await wait_until(pilot, lambda: "done" in log_text(app)), (
            "the run must be over before its rows are counted"
        )
        rows = log_text(app).splitlines()
        assert "first line" in rows and "second line" in rows, "the child's output reaches the log"
        assert "" not in rows, "a trailing newline must not double the row"

    run_app(app, body)


def test_a_long_command_line_wraps_instead_of_scrolling(cache):
    """The run's `$` echo carries absolute paths, far wider than the pane.

    With wrapping off (the widget default) that single line forces a
    horizontal scrollbar whose thumb parks at the left over empty text —
    it reads as a stuck loading bar. The log wraps instead, so every
    line is readable with vertical scrolling only.
    """
    write_report(cache, "findings", [], [])
    app = dash._make_app()

    async def body(app, pilot):
        app.query_one("#tabs", TabbedContent).active = "tab-log"
        await pilot.pause()
        log = app.query_one("#run-log", RichLog)
        assert log.wrap is True, "the log wraps long lines for display"
        assert log._size_known is True, "the pane must be laid out before the wrap is meaningful"
        log.write("$ " + "x" * 500)
        await pilot.pause()
        assert len(log.lines) > 3, "a 500-char line renders as wrapped rows, not one wide row"
        assert log.horizontal_scrollbar.display is False, "a wrapped line must not summon the horizontal scrollbar"

    run_app(app, body)


def test_the_run_strip_is_one_line(cache):
    """The strip carries one line of text (phase + elapsed) plus Stop.

    A default-height Button stretched it to three rows — two of them
    dead space squeezing the log, with Stop floating detached on what
    reads as the tab-bar row. The strip is one row; Stop is a flat
    one-line chip on it, still the same button (the kill test below
    proves it still stops a live child).
    """
    write_report(cache, "findings", [], [])
    app = dash._make_app()

    async def body(app, pilot):
        app.query_one("#tabs", TabbedContent).active = "tab-log"
        await pilot.pause()
        strip = app.query_one("#run-strip")
        stop = app.query_one("#run-stop", Button)
        assert strip.region.height == 1, "the strip costs the log one row"
        assert stop.region.height == 1, "Stop sits on the strip's row"

    run_app(app, body)


def test_a_second_launch_while_live_is_refused(cache, monkeypatch):
    """A stray click must never kill the running audit.

    The worker group is exclusive, so launching a second task cancels
    the first — minutes of probe gone with one misclick. The gate
    refuses while `live_run` is set and names the reason on the log.
    """
    monkeypatch.setattr(
        dash.runner,
        "audit_command",
        lambda argv, report_path: [
            sys.executable,
            "-c",
            "import time\nprint('alive', flush=True)\ntime.sleep(30)\n",
        ],
    )
    app = dash._make_app()

    async def body(app, pilot):
        await press_task(app, pilot, "ports")
        assert await wait_until(pilot, lambda: app.live_run is not None)
        first = app.live_run
        app.run_verb("cross-check")
        await pilot.pause()
        assert app.live_run is first, "the live run survives a second launch"
        assert "still running" in log_text(app), "the refusal says why"
        # Drain before teardown: abandoning a live worker panics the pilot.
        app.query_one("#run-stop", Button).press()
        assert await wait_until(pilot, lambda: app.live_run is None)

    run_app(app, body)


def test_a_finish_line_names_counts_destination_and_file(cache, monkeypatch):
    """`finished rc=1` tells the operator nothing; the finish line must.

    What ran, what it found, which file holds it, which tab shows it —
    so nobody has to discover the tabs alone, and `rc=1` (findings need
    review) stops reading as a crash.
    """
    payload = {
        "schema_version": 1,
        "summary": {},
        "meta": {},
        "findings": [
            {"severity": "WARN", "coin": "AAA", "category": "param", "id": "fee", "detail": "overpay"},
        ],
        "plan": [],
    }

    def writer(argv, report_path):
        code = f"import json; json.dump({payload!r}, open({str(report_path)!r}, 'w'));print('hello')"
        return [sys.executable, "-c", code]

    monkeypatch.setattr(dash.runner, "audit_command", writer)
    app = dash._make_app()

    async def body(app, pilot):
        await press_task(app, pilot, "findings")
        assert await wait_until(pilot, lambda: "done" in log_text(app)), "the run must finish before its line is read"
        text = log_text(app)
        assert "1 finding" in text, "the line counts what was found"
        assert "Findings tab" in text, "the line names the destination"
        assert "findings.json" in text, "the line names the file"
        assert "rc=" not in text, "exit codes are not operator language"
        assert app.query_one("#tabs", TabbedContent).active == "tab-findings", (
            "finish parks the user where the results are, not on the log"
        )

    run_app(app, body)


def test_the_idle_strip_hints_the_next_action(cache):
    """An empty strip reads as broken; idle must say what to do."""
    app = dash._make_app()

    async def body(app, pilot):
        phase = str(app.query_one("#run-phase", Static).content)
        assert "Ctrl+P" in phase, "idle names the way to start a task"

    run_app(app, body)


def test_the_overview_names_the_actual_last_run(cache, monkeypatch):
    """The Report block showed the fleet file's age as 'last run'.

    After a scoped run the fleet file is deliberately untouched, so its
    age is not the last action. The block keeps the fleet file line and
    adds the real last run (verb, scope, age, file) from last-run.meta.
    """
    write_report(cache, "findings", [], [])
    meta_path = cache / "plan-fix.scoped.meta.json"
    (cache / "plan-fix.scoped.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "summary": {},
                "findings": [],
                "plan": [{"action": "fees", "coin": "AAA"}],
                "meta": {"verb": "plan-fix", "tickers": "AAA"},
            }
        ),
        encoding="utf-8",
    )
    dash.paths.write_last_run_meta(
        "plan-fix",
        ["audit-manifest.py", "--ticker", "AAA", "--dry-run"],
        cache / "plan-fix.scoped.json",
        cache / "plan-fix.scoped.log",
        time.time() - 12,
        2.0,
        1,
    )
    assert meta_path.is_file()
    app = dash._make_app()

    async def body(app, pilot):
        overview = str(app.query_one("#overview", Static).content)
        assert "findings.json" in overview, "the fleet file line stays"
        assert "plan-fix" in overview, "the last run names its verb"
        assert "1 coin" in overview, "the last run names its scope"
        assert "plan-fix.scoped.json" in overview, "the last run names its file"

    run_app(app, body)


def test_the_detail_pane_belongs_to_the_active_tab(cache):
    """Rebuilding both tables let the hidden one steal the detail pane.

    With findings on screen and a plan on disk, the detail pane showed
    the plan write — the Findings tab's own row 0 never got a look in.
    Highlights only land from the visible table.
    """
    write_report(
        cache,
        "findings",
        [{"severity": "WARN", "coin": "AAA", "category": "param", "id": "fee", "detail": "overpay"}],
        [],
    )
    write_plan(
        cache,
        [{"action": "fees", "coin": "AAA", "file": "a.conf", "key": "k", "old": "1", "new": "2", "applied": False}],
    )
    app = dash._make_app()

    async def body(app, pilot):
        assert app.query_one("#tabs", TabbedContent).active == "tab-findings"
        await pilot.pause()
        await pilot.pause()
        detail = str(app.query_one("#detail", Static).content)
        assert "Planned write" not in detail, "the hidden plan table must not author the detail pane"

    run_app(app, body)


def test_the_detail_pane_drops_a_row_refresh_deleted(cache):
    """A refresh that empties the plan left the deleted write on screen."""
    write_report(cache, "findings", [], [])
    write_plan(
        cache,
        [
            {"action": "fees", "coin": "AAA", "file": "a.conf", "key": "k", "old": "1", "new": "2", "applied": False},
            {"action": "fees", "coin": "BBB", "file": "b.conf", "key": "k", "old": "1", "new": "2", "applied": False},
        ],
    )
    app = dash._make_app()

    async def body(app, pilot):
        app.query_one("#tabs", TabbedContent).active = "tab-plan"
        await pilot.pause()
        table = app.query_one("#plan-table", DataTable)
        table.focus()
        await pilot.press("down")
        await pilot.pause()
        assert "b.conf" in str(app.query_one("#detail", Static).content)
        (cache / "plan-fix.json").unlink()
        app.action_refresh()
        await pilot.pause()
        detail = str(app.query_one("#detail", Static).content)
        assert "b.conf" not in detail, "a deleted row must not linger"

    run_app(app, body)


# ---------------------------------------------------------------------------
# State persistence (selection / filter survive the app)
# ---------------------------------------------------------------------------


def test_state_round_trips_through_dashboard_json(cache, manifest):
    async def pick_and_quit(app, pilot):
        app.state["selection"] = ["AAA", "BBB"]
        app.state["filter"] = "aa"
        await pilot.press("ctrl+q")

    run_app(dash._make_app(), pick_and_quit)
    assert (cache / "dashboard.json").is_file(), "a graceful quit must persist the scope"

    restored = {}

    async def read_state(app, pilot):
        restored.update(app.state)

    run_app(dash._make_app(), read_state)
    assert restored["selection"] == ["AAA", "BBB"], "the next app must come up narrowed, on the coins its scope names"
    assert restored["filter"] == "aa"


def test_state_load_dedupes_the_selection(cache):
    """A hand-edited state file can repeat tickers; duplicates would
    inflate the scope line ("4 of 3") and the --ticker flag, so load
    keeps first occurrence order and drops the rest."""
    (cache / "dashboard.json").write_text(
        json.dumps(
            {
                "schema_version": dash.state.STATE_VERSION,
                "selection": ["AAA", "AAA", "BBB"],
                "filter": "",
                "tab": "findings",
            }
        ),
        encoding="utf-8",
    )
    assert dash.state.load()["selection"] == ["AAA", "BBB"]


# ---------------------------------------------------------------------------
# Production-grade UX iteration: hierarchy, feedback, confirms, dialog, keys
# ---------------------------------------------------------------------------


def test_write_rows_use_the_warning_variant(cache):
    """Only Apply stays filled; siblings stay outlined (D10)."""
    write_report(cache, "findings", [], [])
    app = dash._make_app()

    async def body(app, pilot):
        assert app.query_one("#act-apply", Button).variant == "warning"
        for aid in ("analyze", "plan", "add-coin"):
            assert app.query_one(f"#act-{aid}", Button).variant == "default", f"{aid} must stay flat"

    run_app(app, body)


def test_active_tab_is_bold(cache):
    """The active tab must be unmissable — sitting on Findings while a
    Log-streamed run finished is how operators conclude nothing ran."""
    write_report(cache, "findings", [], [])
    app = dash._make_app()

    async def body(app, pilot):
        tabs = list(app.query("Tab"))
        assert tabs, "the tab bar must exist"
        active = [t for t in tabs if t.has_class("-active")]
        assert len(active) == 1, "exactly one tab must read as active"

    run_app(app, body)


def test_palette_names_cost_and_answers_no_match(cache, monkeypatch):
    """The advertised fast path hides costs and sat silent on bad prefixes."""
    write_report(cache, "findings", [], [])
    app = dash._make_app()
    ran = []
    record_run_verb(monkeypatch, app, ran)

    async def body(app, pilot):
        await pilot.press("ctrl+p")
        await pilot.pause()
        status = app.screen.query_one("#palette-status", Static)
        assert "tasks" in str(status.content), "palette opens with a count"
        app.screen.query_one("#palette-input", Input).value = "frobnicate"
        await pilot.press("enter")
        await pilot.pause()
        await pilot.pause()
        assert "no match" in str(app.screen.query_one("#palette-status", Static).content), (
            "a dead prefix must answer instead of sitting silent"
        )
        assert ran == []
        assert screen_name(app) == "CommandPalette"
        await pilot.press("escape")
        await pilot.pause()

    run_app(app, body, screen="coins")


def test_empty_tables_name_the_producing_task(cache):
    """Blank tables read as broken; empty states name the next action."""
    write_report(cache, "findings", [], [])
    app = dash._make_app()

    async def body(app, pilot):
        status = str(app.query_one("#findings-status", Static).content)
        assert "Analyze" in status, "empty findings must name the producing action"
        assert "Plan" in str(app.query_one("#write-status", Static).content)

    run_app(app, body)


def test_narrowed_read_confirm_lists_the_coins(cache, manifest, monkeypatch):
    """A narrowed read confirms its exact size plus which coins."""
    write_report(cache, "findings", [], [])
    seed_scope(cache, ["AAA", "BBB"])
    app = dash._make_app()
    captured = []
    record_audit_command(monkeypatch, captured)

    async def body(app, pilot):
        await press_task(app, pilot, "ports")
        await pilot.pause()
        assert screen_name(app) == "ConfirmScreen"
        body_text = str(app.screen.query_one("#confirm-body", Static).content)
        assert "AAA" in body_text and "BBB" in body_text, "the dialog must list the coins it will touch"
        assert "fleet-wide" in body_text
        app.screen.query_one("#confirm-no", Button).press()
        await pilot.pause()
        assert captured == [], "cancelling must not start the run"

    run_app(app, body)


def test_full_fleet_write_dialog_shows_the_scope(cache, manifest, monkeypatch):
    """Full fleet is the most dangerous shape; the old dialog showed none."""
    write_report(cache, "findings", [], [])
    plan = [dict(PLAN_ENTRY, coin="AAA", file="a.conf")]
    write_plan(cache, plan)
    app = dash._make_app()
    captured = []
    record_audit_command(monkeypatch, captured)

    async def body(app, pilot):
        app.query_one("#write-apply", Button).press()
        await pilot.pause()
        assert screen_name(app) == "ConfirmScreen"
        body_text = str(app.screen.query_one("#confirm-body", Static).content)
        assert "full fleet" in body_text, "a full-fleet write must say so"
        assert "a.conf" in body_text, "the dialog must list the files"
        app.screen.query_one("#confirm-no", Button).press()
        await pilot.pause()
        assert captured == [], "cancelling must not start the run"

    run_app(app, body)


def test_scaffold_dialog_refuses_a_bad_url(cache, monkeypatch):
    """A non-GitHub string never launches; the dialog says why and stays."""
    write_report(cache, "findings", [], [])
    app = dash._make_app()
    captured = []
    record_audit_command(monkeypatch, captured)

    async def body(app, pilot):
        await press_task(app, pilot, "scaffold")
        await pilot.pause()
        assert screen_name(app) == "ScaffoldDialog"
        app.screen.query_one("#scaffold-input", Input).value = "not a url"
        await pilot.pause()
        app.screen.query_one("#scaffold-yes", Button).press()
        await pilot.pause()
        assert screen_name(app) == "ScaffoldDialog", "a bad URL must not dismiss the dialog"
        assert "github.com" in str(app.screen.query_one("#scaffold-status", Static).content).lower()
        assert captured == [], "nothing may spawn on a refused URL"
        await pilot.press("escape")
        await pilot.pause()

    run_app(app, body)


def test_ctrl_d_toggles_the_detail_pane(cache):
    """Ctrl+D hid content destruction behind a focus-looking key: it must
    toggle visibility and never wipe the row being read."""
    write_report(
        cache,
        "findings",
        [
            dict(FINDING, coin="AAA", severity="FAIL"),
        ],
        [],
    )
    app = dash._make_app()

    async def body(app, pilot):
        before = str(app.query_one("#detail", Static).content)
        assert "AAA" in before or "Finding" in before
        app.action_detail()
        await pilot.pause()
        from textual.containers import VerticalScroll

        assert app.query_one("#detail-scroll", VerticalScroll).display is False
        app.action_detail()
        await pilot.pause()
        assert app.query_one("#detail-scroll", VerticalScroll).display is True
        assert str(app.query_one("#detail", Static).content) == before, "toggling must never destroy the content"

    run_app(app, body)


def test_picker_header_states_scope_vs_filter(cache, manifest):
    """The scope-vs-filter trap gets its answer on the screen itself."""
    app = dash._make_app()

    async def body(app, pilot):
        hint = str(app.screen.query_one("#coins-hint", Static).content)
        assert "filter only hides" in hint
        assert "All ticked = full fleet" in hint

    run_app(app, body, screen="coins")


def test_zero_scope_names_the_next_action(cache, manifest):
    """Zero-selection is a grey button with no reason unless named."""
    app = dash._make_app()

    async def body(app, pilot):
        app.screen.query_one("#coins-none", Button).press()
        await pilot.pause()
        assert "Tick at least one coin" in str(app.screen.query_one("#coins-count", Static).content)
        assert app.screen.query_one("#coins-continue", Button).disabled

    run_app(app, body, screen="coins")


def test_strip_keeps_the_last_result(cache, monkeypatch):
    """After a run the strip answers 'what just happened' without scrolling."""
    payload = {
        "schema_version": 1,
        "summary": {},
        "meta": {},
        "findings": [
            {"severity": "WARN", "coin": "AAA", "category": "param", "id": "fee", "detail": "overpay"},
        ],
        "plan": [],
    }

    def writer(argv, report_path):
        code = f"import json; json.dump({payload!r}, open({str(report_path)!r}, 'w'));print('hello')"
        return [sys.executable, "-c", code]

    monkeypatch.setattr(dash.runner, "audit_command", writer)
    app = dash._make_app()

    async def body(app, pilot):
        await press_task(app, pilot, "findings")
        assert await wait_until(pilot, lambda: "done" in log_text(app)), "the run must finish before the strip is read"
        assert await wait_until(pilot, lambda: app.live_run is None)
        await pilot.pause()
        phase = str(app.query_one("#run-phase", Static).content)
        assert "Ctrl+P" in phase, "the idle hint must survive"
        assert "findings" in phase, "the strip must keep the last result"

    run_app(app, body)


def test_the_plan_detail_pane_renders_a_missing_reason_as_a_dash(cache):
    """Entries without a reason must not print the string "None" (seen on
    the Plan tab screenshot: a bare `reason / None` block)."""
    write_report(cache, "findings", [], [])
    entry = dict(PLAN_ENTRY)
    entry.pop("reason", None)
    write_plan(cache, [entry])
    app = dash._make_app()

    async def body(app, pilot):
        app.query_one("#tabs", TabbedContent).active = "tab-plan"
        await pilot.pause()
        table = app.query_one("#plan-table", DataTable)
        table.focus()
        await pilot.press("down")
        await pilot.pause()
        detail = str(app.query_one("#detail", Static).content)
        assert "\nNone\n" not in detail and not detail.endswith("\nNone")
        assert "applied:  no" in detail, "applied renders like the table cell"

    run_app(app, body)


# ---------------------------------------------------------------------------
# Audit follow-up P1-P8: strip hoist, red reservation, dead buttons,
# last-run unity, footer units
# ---------------------------------------------------------------------------


def test_strip_stays_visible_on_the_findings_tab_during_a_run(
    cache,
    monkeypatch,
):
    """The strip used to live inside the Log tab: switching to Findings
    mid-run lost phase/elapsed/Stop exactly when they matter most."""
    write_report(cache, "findings", [], [])
    monkeypatch.setattr(
        dash.runner,
        "audit_command",
        lambda argv, report_path: [
            sys.executable,
            "-c",
            "import time\nprint('alive', flush=True)\ntime.sleep(30)\n",
        ],
    )
    app = dash._make_app()

    async def body(app, pilot):
        await press_task(app, pilot, "ports")
        assert await wait_until(pilot, lambda: app.live_run is not None)
        app.query_one("#tabs", TabbedContent).active = "tab-findings"
        await pilot.pause()
        assert app.query_one("#run-stop", Button).display, "Stop must stay visible off the Log tab"
        assert "ports" in str(app.query_one("#run-phase", Static).content)
        app.query_one("#run-stop", Button).press()
        assert await wait_until(pilot, lambda: app.live_run is None)

    run_app(app, body)


def test_read_confirm_run_is_not_red_but_write_confirm_stays_red(
    cache,
    manifest,
    monkeypatch,
):
    """Red means 'writes to my tree': a scoped preview must not teach
    users to ignore it before Apply needs it to mean something."""
    write_report(cache, "findings", [], [])
    seed_scope(cache, ["AAA", "BBB"])
    write_plan(cache, [dict(PLAN_ENTRY, coin="AAA", ver_id="aaa--v1.0")])
    app = dash._make_app()
    captured = []
    record_audit_command(monkeypatch, captured)

    async def body(app, pilot):
        await press_task(app, pilot, "ports")
        await pilot.pause()
        assert screen_name(app) == "ConfirmScreen"
        assert app.screen.query_one("#confirm-yes", Button).variant == "primary"
        assert app.screen.query_one("#confirm-no", Button).variant == "default"
        await pilot.press("escape")
        await pilot.pause()
        app.query_one("#write-apply", Button).press()
        await pilot.pause()
        assert screen_name(app) == "ConfirmScreen"
        assert app.screen.query_one("#confirm-yes", Button).variant == "error", "the Apply confirm keeps its red"
        await pilot.press("escape")
        await pilot.pause()
        assert captured == []

    run_app(app, body)


def test_plan_buttons_disable_without_a_plan(cache):
    """Buttons that look live and then scold are a trap next to a red
    Apply: with no plan, Preview/Apply disable (diff stays live — it
    reports on the tree, not the plan)."""
    write_report(cache, "findings", [], [])
    app = dash._make_app()

    async def body(app, pilot):
        assert app.query_one("#write-preview-plan", Button).disabled
        assert app.query_one("#write-apply", Button).disabled
        assert not app.query_one("#write-preview-diff", Button).disabled

    run_app(app, body)


def test_last_run_unknown_names_the_shown_file(cache):
    """Meta absent + fleet report present printed 'never' next to a fresh
    fleet age — two last-run answers disagreeing on one screen."""
    write_report(cache, "findings", [], [])
    assert not (cache / "last-run.meta.json").exists()
    app = dash._make_app()

    async def body(app, pilot):
        overview = str(app.query_one("#overview", Static).content)
        assert "no run recorded — showing findings.json" in overview, (
            "the row must say which file is shown instead of bare never"
        )

    run_app(app, body)


def test_picker_footer_names_units(cache, manifest):
    """Bare '41 of 41' reads as visible-count; units say ticked + fleet."""
    app = dash._make_app()

    async def body(app, pilot):
        assert "ticked · full fleet" in str(app.screen.query_one("#coins-count", Static).content)

    run_app(app, body, screen="coins")


def test_narrow_terminal_hides_detail_until_asked(cache):
    """At 80 cols the 48-col pane crushes buttons mid-phrase: it hides
    itself, and Ctrl+D brings it back — a manual toggle that sticks."""
    write_report(cache, "findings", [], [])
    app = dash._make_app()

    async def body(app, pilot):
        from textual.containers import VerticalScroll

        assert app.query_one("#detail-scroll", VerticalScroll).display is False, (
            "narrow terminals start with the width reclaimed"
        )
        app.action_detail()
        await pilot.pause()
        assert app.query_one("#detail-scroll", VerticalScroll).display is True

    run_app(app, body, size=(80, 24))


# ---------------------------------------------------------------------------
# Fleet merge: version + param findings share one table, newest wins
# ---------------------------------------------------------------------------


def _slot(name, findings, mtime=100.0):
    return (name, {"schema_version": 1, "findings": findings}, mtime, {})


def _row(coin, category="version", fid="REPO-ACTION", ver="v1", **kw):
    base = {"severity": "WARN", "coin": coin, "category": category, "id": fid, "ver_id": ver, "detail": f"{coin} {fid}"}
    base.update(kw)
    return base


def test_merge_dedupes_audit_vs_findings_newest_wins():
    """audit + findings probe the same fleet: the same coin+check must
    render once, not twice — the newer report's row wins."""
    from dashboard.screens import merge_fleet_findings

    old = _row("BCH", detail="tags: v29.2.0")
    new = _row("BCH", detail="tags: v29.2.0, v29.3.0")
    rows, summary = merge_fleet_findings(
        [
            _slot("audit.json", [old], mtime=100.0),
            _slot("findings.json", [new], mtime=200.0),
        ]
    )
    assert len(rows) == 1, "one coin+check renders one row"
    assert rows[0]["detail"] == "tags: v29.2.0, v29.3.0"
    assert summary["findings.json"]["shown"] == 1
    assert summary["audit.json"]["shown"] == 0


def test_merge_keeps_param_rows_beside_version_rows():
    """Param ids (FEES/PORT) are disjoint from REPO-ACTION: they coexist,
    and the status names every contributing source."""
    from dashboard.screens import merge_fleet_findings

    rows, summary = merge_fleet_findings(
        [
            _slot("audit.json", [_row("BCH")], mtime=100.0),
            _slot(
                "param-check.json",
                [
                    _row("AGM", category="param", fid="FEES", ver="argoneum--v1", detail="overpay", versions=None),
                    _row(
                        "BCH", category="param", fid="PORT", ver="bitcoincash--v29", detail="port drift", versions=None
                    ),
                ],
                mtime=200.0,
            ),
        ]
    )
    assert len(rows) == 3
    assert {r["id"] for r in rows} == {"REPO-ACTION", "FEES", "PORT"}
    assert set(summary) == {"audit.json", "param-check.json"}


def test_merge_tie_prefers_later_slot_and_empty_degrades():
    """Same mtime: the later slot decides (deterministic, no flake).
    No slots: empty table, empty provenance — never an error."""
    from dashboard.screens import merge_fleet_findings

    rows, _s = merge_fleet_findings(
        [
            _slot("audit.json", [_row("BCH", detail="old")], mtime=100.0),
            _slot("findings.json", [_row("BCH", detail="new")], mtime=100.0),
        ]
    )
    assert len(rows) == 1 and rows[0]["detail"] == "new"
    rows, summary = merge_fleet_findings([])
    assert rows == [] and summary == {}


# ---------------------------------------------------------------------------
# Complete wiring: param-check/ports/cross-check surface in fleet views
# ---------------------------------------------------------------------------

PARAM_FINDING = {
    "severity": "WARN",
    "category": "param",
    "coin": "AGM",
    "ver_id": "argoneum--v1.0",
    "id": "FEES",
    "detail": "WARN overpay — got MinTxFee=678 FeePerByte=2",
    "file": None,
    "line": None,
    "versions": None,
}

WIRE_VERSION_FINDING = {
    "severity": "UPGRADE",
    "category": "version",
    "coin": "BCH",
    "ver_id": "bitcoincash--v29.1.0",
    "id": "REPO-ACTION",
    "detail": "repo ALIVE: newer same-series tags: v29.2.0",
    "file": None,
    "line": None,
    "versions": {
        "declared": ["v29.1.0"],
        "our_latest": "v29.1.0",
        "remote_latest": "v29.2.0",
        "newer_same": ["v29.2.0"],
        "newer_alt": [],
        "missing": [],
        "found": ["v29.1.0"],
        "tag_count": 20,
        "conf": "bitcoincash--v29.1.0",
    },
}


def _write_param_cache(root, findings, blob):
    payload = {"schema_version": 1, "summary": {}, "findings": findings, "plan": [], "meta": {}, "param_check": blob}
    path = root / "param-check.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    (root / "param-check.meta.json").write_text(
        json.dumps(
            {
                "verb": "param-check",
                "argv": [],
                "report": str(path),
                "log": str(root / "param-check.log"),
                "started_at": time.time() - 60,
                "duration_seconds": 5.0,
                "audit_exit_code": 1,
            }
        ),
        encoding="utf-8",
    )
    return path


def test_findings_table_merges_param_rows_beside_version_rows(cache):
    """A fleet param-check must reach the Findings tab next to the
    version rows — one row per coin, checks aggregated under it."""
    write_report(cache, "audit", [dict(WIRE_VERSION_FINDING)], [])
    _write_param_cache(cache, [dict(PARAM_FINDING)], {})
    app = dash._make_app()

    async def body(app, pilot):
        table = app.query_one("#findings-table", DataTable)
        assert table.row_count == 2, "BCH + AGM render one row each"
        status = str(app.query_one("#findings-status", Static).content)
        assert "audit" in status and "param-check" in status, "the status names every contributing source"

    run_app(app, body)


def test_coins_status_reflects_param_warn(cache, manifest):
    """The picker status column reads the merged set: a coin whose only
    signal is a param WARN must not show a clean dash."""
    write_report(cache, "audit", [], [])
    _write_param_cache(cache, [dict(PARAM_FINDING, coin="AAA")], {})
    app = dash._make_app()

    async def body(app, pilot):
        info = str(app.screen.query_one("#coin-info-0", Static).content)
        assert "WARN" in info, "AAA's param WARN reaches the picker"

    run_app(app, body, screen="coins")


def test_detail_param_block_lists_checks_failures_first(cache):
    """Selecting a coin aggregates its param checks into one entry per
    check: failures lead as entries, matches collapse to the clear
    count — no Param header, no duplicated finding text."""
    write_report(cache, "audit", [dict(WIRE_VERSION_FINDING)], [])
    blob = {
        ver_id: {
            "tag": "v",
            "source": "repos/X",
            "mode": "reused",
            "checks": [
                {"id": "PORT", "status": "MATCH", "detail": "wallet port ok"},
                {"id": "FEES", "status": "WARN", "detail": "overpay 2x"},
            ],
        }
        for ver_id in ("bitcoincash--v29.1.0", "argoneum--v1.0")
    }
    _write_param_cache(cache, [dict(PARAM_FINDING)], blob)
    app = dash._make_app()

    async def body(app, pilot):
        app.query_one("#tabs", TabbedContent).active = "tab-findings"
        await pilot.pause()
        table = app.query_one("#findings-table", DataTable)
        table.focus()
        await pilot.press("down")
        await pilot.pause()
        detail = str(app.query_one("#detail", Static).content)
        assert "overpay" in detail
        assert detail.index("overpay") < detail.index("All clear"), "failures lead, the clear count closes"
        assert "Param" not in detail, "no section headers — color sections"
        assert "wallet port ok" not in detail, "matches are a count, not content"

    run_app(app, body)


def test_detail_without_blob_entry_omits_param(cache):
    """A coin with no blob entry gets no Param section: the section
    stays out silently instead of an empty header."""
    write_report(cache, "audit", [dict(WIRE_VERSION_FINDING)], [])
    _write_param_cache(cache, [], {})
    app = dash._make_app()

    async def body(app, pilot):
        app.query_one("#tabs", TabbedContent).active = "tab-findings"
        await pilot.pause()
        table = app.query_one("#findings-table", DataTable)
        table.focus()
        await pilot.press("down")
        await pilot.pause()
        assert "Param" not in str(app.query_one("#detail", Static).content)

    run_app(app, body)


def test_overview_ledger_names_every_source(cache):
    """Each datum once: param counts, port collisions, cross-check
    missing/orphans each get a ledger line with an age."""
    import time as _time

    write_report(cache, "audit", [dict(WIRE_VERSION_FINDING)], [])
    _write_param_cache(cache, [dict(PARAM_FINDING)], {})
    (cache / "ports.json").write_text(
        json.dumps(
            {"schema_version": 1, "findings": [], "plan": [], "port_collisions": {"8333": ["AAA", "BBB"]}, "meta": {}}
        ),
        encoding="utf-8",
    )
    (cache / "ports.meta.json").write_text(
        json.dumps(
            {
                "verb": "ports",
                "argv": [],
                "report": str(cache / "ports.json"),
                "log": "",
                "started_at": _time.time() - 30,
                "duration_seconds": 1.0,
                "audit_exit_code": 0,
            }
        ),
        encoding="utf-8",
    )
    (cache / "cross-check.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "findings": [],
                "plan": [],
                "local": {
                    "missing_wallet_conf": ["zzz.conf"],
                    "missing_xbridge_conf": [],
                    "missing_base_j2": [],
                    "orphans": {"wallet-confs": [], "xbridge-confs": ["old.conf"]},
                },
                "meta": {},
            }
        ),
        encoding="utf-8",
    )
    (cache / "cross-check.meta.json").write_text(
        json.dumps(
            {
                "verb": "cross-check",
                "argv": [],
                "report": str(cache / "cross-check.json"),
                "log": "",
                "started_at": _time.time() - 30,
                "duration_seconds": 1.0,
                "audit_exit_code": 0,
            }
        ),
        encoding="utf-8",
    )
    app = dash._make_app()

    async def body(app, pilot):
        overview = str(app.query_one("#overview", Static).content)
        assert "param-check" in overview and "1" in overview
        assert "8333" in overview, "the collision ports surface in the ledger"
        assert "zzz.conf" in overview or "missing" in overview

    run_app(app, body)


def test_overview_omits_missing_slots(cache):
    """Absent slots leave no line: no 'None', no zeroed phantom rows."""
    write_report(cache, "audit", [dict(WIRE_VERSION_FINDING)], [])
    app = dash._make_app()

    async def body(app, pilot):
        overview = str(app.query_one("#overview", Static).content)
        assert "param-check" not in overview
        assert "ports" not in overview or "port" not in overview.replace("reported", "")

    run_app(app, body)


def test_finding_detail_points_at_planned_writes(cache):
    """The cross-link is a pointer, never duplicated content: N writes
    for this coin live on the Plan tab, the finding names the count."""
    write_report(cache, "audit", [dict(WIRE_VERSION_FINDING)], [])
    _write_param_cache(cache, [], {})
    write_plan(
        cache,
        [
            dict(PLAN_ENTRY, coin="BCH", ver_id="bitcoincash--v29.1.0"),
            dict(PLAN_ENTRY, coin="AGM", ver_id="argoneum--v1.0"),
        ],
    )
    app = dash._make_app()

    async def body(app, pilot):
        app.query_one("#tabs", TabbedContent).active = "tab-findings"
        await pilot.pause()
        table = app.query_one("#findings-table", DataTable)
        table.focus()
        await pilot.press("down")
        await pilot.pause()
        detail = str(app.query_one("#detail", Static).content)
        assert "1 planned write" in detail and "Plan tab" in detail

    run_app(app, body)


# ---------------------------------------------------------------------------
# One row per coin: findings aggregate, detail reads the coin report
# ---------------------------------------------------------------------------


def test_coin_rows_group_every_check_under_its_ticker():
    """BCH's version + param rows collapse to one BCH row; AGM stands
    alone. The table counts coins, not checks."""
    from dashboard.screens import build_coin_rows

    coins = build_coin_rows(
        [
            dict(WIRE_VERSION_FINDING),
            dict(
                PARAM_FINDING, coin="BCH", ver_id="bitcoincash--v29.1.0", id="PORT", detail="port drift", versions=None
            ),
            dict(PARAM_FINDING),
        ]
    )
    assert [c["coin"] for c in coins] == ["BCH", "AGM"]
    bch = next(c for c in coins if c["coin"] == "BCH")
    assert bch["count"] == 2
    assert bch["severity"] == "UPGRADE", "worst of UPGRADE + WARN wins"
    assert bch["change"] == "v29.1.0 → v29.2.0"
    assert bch["reason"].startswith("2 findings — ")


def test_coin_row_reason_is_verbatim_for_single_finding_coins():
    """A coin with one finding keeps today's look: no count prefix.

    Contract change (D4): the Reason is the short verdict, not the
    engine-verbatim detail — the table scans, the pane explains."""
    from dashboard.screens import build_coin_rows

    coins = build_coin_rows([dict(PARAM_FINDING)])
    assert coins[0]["reason"] == "overpay"
    assert coins[0]["change"] == "—", "param rows carry no version change"


def test_coin_rows_order_worst_first_then_ticker():
    """Worst band first, busiest coin first inside the band, ticker ties."""
    from dashboard.screens import build_coin_rows

    coins = build_coin_rows(
        [
            dict(PARAM_FINDING, coin="ZZZ"),
            dict(WIRE_VERSION_FINDING, coin="MMM", severity="FAIL"),
            dict(PARAM_FINDING, coin="AAA"),
        ]
    )
    assert [c["coin"] for c in coins] == ["MMM", "AAA", "ZZZ"]


def test_coin_rows_empty_degrades_to_empty():
    from dashboard.screens import build_coin_rows

    assert build_coin_rows([]) == []
    assert build_coin_rows([None, "x", 7]) == []


def test_param_check_finish_parks_on_the_findings_tab(cache, monkeypatch):
    """Param findings merge into the Findings table, so a fleet
    param-check parks there like audit/findings — never 'Log only'."""
    payload = {"schema_version": 1, "summary": {}, "meta": {}, "findings": [dict(PARAM_FINDING)], "plan": []}

    def writer(argv, report_path):
        code = f"import json; json.dump({payload!r}, open({str(report_path)!r}, 'w'));print('checked')"
        return [sys.executable, "-c", code]

    monkeypatch.setattr(dash.runner, "audit_command", writer)
    app = dash._make_app()

    async def body(app, pilot):
        await press_task(app, pilot, "param-check")
        assert await wait_until(pilot, lambda: "done" in log_text(app)), "the run must finish before parking is read"
        assert "Findings tab" in log_text(app)
        assert app.query_one("#tabs", TabbedContent).active == "tab-findings"
        assert app.query_one("#findings-table", DataTable).row_count == 1

    run_app(app, body)


def test_ports_finish_names_the_overview_counts(cache, monkeypatch):
    """Ports reports carry no finding rows: the finish line names the
    overview ledger counts (not 'Log only', not a phantom 'clean')."""
    payload = {
        "schema_version": 1,
        "summary": {},
        "meta": {},
        "findings": [],
        "plan": [],
        "port_collisions": {"8333": ["AAA", "BBB"]},
    }

    def writer(argv, report_path):
        code = f"import json; json.dump({payload!r}, open({str(report_path)!r}, 'w'));print('checked')"
        return [sys.executable, "-c", code]

    monkeypatch.setattr(dash.runner, "audit_command", writer)
    app = dash._make_app()

    async def body(app, pilot):
        await press_task(app, pilot, "ports")
        assert await wait_until(pilot, lambda: "done" in log_text(app))
        text = log_text(app)
        assert "overview" in text and "1 collision" in text
        assert "(Log only)" not in text

    run_app(app, body)


def test_detail_pane_scrolls_long_coin_reports(cache):
    """A coin with dozens of checks (SYS) overflows the pane: the excess
    must scroll inside it, not clip unreachable below the fold."""
    write_report(cache, "audit", [dict(WIRE_VERSION_FINDING)], [])
    blob = {
        "bitcoincash--v29.1.0": {
            "tag": "v",
            "source": "repos/X",
            "mode": "reused",
            "checks": [
                {"id": f"W{i:02d}", "status": "WARN", "detail": f"problem number {i} detail"} for i in range(40)
            ],
        }
    }
    _write_param_cache(cache, [], blob)
    app = dash._make_app()

    async def body(app, pilot):
        app.query_one("#tabs", TabbedContent).active = "tab-findings"
        await pilot.pause()
        table = app.query_one("#findings-table", DataTable)
        table.focus()
        await pilot.pause()
        from textual.containers import VerticalScroll

        scroller = app.query_one("#detail-scroll", VerticalScroll)
        inner = app.query_one("#detail", Static)
        assert inner.region.height > scroller.region.height, "long reports must overflow inside the scroller, not clip"
        assert scroller.is_scrollable, "the wrapper must offer a scrollbar"
        scroller.scroll_end(animate=False)
        await pilot.pause()
        assert scroller.scroll_y > 0, "the pane must actually travel to the end"

    run_app(app, body)


# ---------------------------------------------------------------------------
# Coin detail redesign: verdict-first, deduped, budgeted
# ---------------------------------------------------------------------------

SYS_FINDING = {
    "severity": "WARN",
    "category": "param",
    "coin": "SYS",
    "ver_id": "syscoin--v5.1.0",
    "id": "FEES",
    "detail": (
        "WARN overpay — got MinTxFee=678 FeePerByte=2 != REQUIRED MinTxFee=452 FeePerByte=1 (src/policy/policy.h:61)"
    ),
    "file": None,
    "line": None,
    "versions": None,
}

SYS_BLOB = {
    "syscoin--v5.1.0": {
        "tag": "v5.1.0",
        "source": "repos/SYS",
        "mode": "reused",
        "checks": [
            {"id": "FEES", "status": "WARN", "detail": "WARN overpay — got MinTxFee=678 (src/policy/policy.h:61)"},
            {"id": "PORT", "status": "MATCH", "detail": "wallet port ok"},
            {"id": "COIN", "status": "PASS", "detail": "COIN ok"},
            {"id": "DUST", "status": "INFO", "detail": "placeholder dust"},
        ],
    },
}


def _sys_app(cache):
    write_report(cache, "audit", [dict(SYS_FINDING)], [])
    _write_param_cache(cache, [dict(SYS_FINDING)], dict(SYS_BLOB))
    return dash._make_app()


def test_coin_detail_dedupes_finding_and_blob_check(cache):
    """The FEES finding IS its blob check restated: one entry, not two.
    No Findings/Param/Version block headers — severity color sections."""
    app = _sys_app(cache)

    async def body(app, pilot):
        app.workspace.show_detail_coin(app.workspace.coins[0])
        detail = str(app.query_one("#detail", Static).content)
        assert detail.count("overpay") == 1, "one check renders once"
        assert "[b]Findings[/b]" not in detail
        assert "[b]Param[/b]" not in detail
        assert "[b]Version[/b]" not in detail

    run_app(app, body)


def test_coin_detail_verdict_line_is_capped_with_dim_evidence(cache):
    """Verdict line ≈90 chars max; the remainder survives dimmed below."""
    app = _sys_app(cache)

    async def body(app, pilot):
        app.workspace.show_detail_coin(app.workspace.coins[0])
        detail = str(app.query_one("#detail", Static).content)
        verdict = next(ln for ln in detail.splitlines() if "FEES" in ln)
        plain = verdict.replace("[yellow]", "").replace("[/]", "")
        assert len(plain) <= 100, f"verdict must stay short, got {len(plain)}"
        assert "src/policy/policy.h" in detail, "evidence is kept, subordinated"
        assert "[dim]" in detail

    run_app(app, body)


def test_coin_detail_clear_line_counts_passes(cache):
    """Passing checks are a count line, never listed content."""
    app = _sys_app(cache)

    async def body(app, pilot):
        app.workspace.show_detail_coin(app.workspace.coins[0])
        detail = str(app.query_one("#detail", Static).content)
        assert "All clear — 3 checks pass" in detail
        assert "wallet port ok" not in detail
        assert "COIN ok" not in detail

    run_app(app, body)


def test_coin_detail_next_step_names_plan_fix(cache):
    """Actionable coins name the next step; pointer stays a pointer.

    Contract change (A4): a plan that already exists points at the Plan
    tab only — inviting another plan-fix run wastes minutes."""
    write_report(cache, "audit", [dict(SYS_FINDING)], [])
    _write_param_cache(cache, [dict(SYS_FINDING)], dict(SYS_BLOB))
    write_plan(cache, [dict(PLAN_ENTRY, coin="SYS", ver_id="syscoin--v5.1.0")])
    app = dash._make_app()

    async def body(app, pilot):
        app.workspace.show_detail_coin(app.workspace.coins[0])
        detail = str(app.query_one("#detail", Static).content)
        assert "see Plan tab" in detail

    run_app(app, body)


def test_coin_detail_colors_status_tokens(cache):
    """Severity color is the sectioning: red/yellow tokens, dim evidence."""
    app = _sys_app(cache)

    async def body(app, pilot):
        app.workspace.show_detail_coin(app.workspace.coins[0])
        detail = str(app.query_one("#detail", Static).content)
        assert "[yellow]" in detail, "WARN reads yellow"
        assert detail.startswith("[b]SYS — "), "bold header leads with the verdict"

    run_app(app, body)


# ---------------------------------------------------------------------------
# Phase A — safety & correctness (fact-checked audit #16, #8, #6, #5-pointer)
# ---------------------------------------------------------------------------


def test_confirm_focuses_cancel_for_both_variants(cache):
    """Enter must never execute a write: Cancel is focused, always (D29)."""
    from dashboard.widgets import ConfirmScreen

    app = dash._make_app()

    async def body(app, pilot):
        app.push_screen(ConfirmScreen("Apply?", "body", action="Apply", danger=True))
        await pilot.pause()
        await pilot.pause()
        assert app.screen.focused is not None
        assert app.screen.focused.id == "confirm-no", "danger: Enter = Cancel"
        app.pop_screen()
        await pilot.pause()
        app.push_screen(ConfirmScreen("Run?", "body", action="Run", danger=False))
        await pilot.pause()
        await pilot.pause()
        assert app.screen.focused.id == "confirm-no", "safe: Enter = Cancel too"

    run_app(app, body)


def test_confirm_chrome_follows_danger(cache):
    """Red chrome only when danger=True; safe confirms use accent (audit #8)."""
    from dashboard.widgets import ConfirmScreen

    app = dash._make_app()

    async def body(app, pilot):
        app.push_screen(ConfirmScreen("Run?", "body", danger=False))
        await pilot.pause()
        box = app.screen.query_one("#confirm-box")
        assert "danger" not in box.classes, "safe confirm must not wear red"
        app.pop_screen()
        await pilot.pause()
        app.push_screen(ConfirmScreen("Apply?", "body", danger=True))
        await pilot.pause()
        box = app.screen.query_one("#confirm-box")
        assert "danger" in box.classes, "write confirm must wear red"

    run_app(app, body)


def test_busy_refusal_switches_to_log(cache):
    """A refused second launch must be visible, not a dead click (audit #6)."""
    app = dash._make_app()

    async def body(app, pilot):
        app.query_one("#tabs", TabbedContent).active = "tab-findings"
        await pilot.pause()
        app.live_run = object()
        try:
            app.run_verb("ports")
            await pilot.pause()
            assert app.query_one("#tabs", TabbedContent).active == "tab-log"
            assert "still running" in log_text(app)
        finally:
            app.live_run = None

    run_app(app, body)


def test_plan_pointer_splits_existing_vs_missing_plan(cache):
    """Plan exists → 'see Plan tab' only; no plan + WARN → names plan-fix (A4)."""
    write_report(cache, "audit", [dict(SYS_FINDING)], [])
    _write_param_cache(cache, [dict(SYS_FINDING)], dict(SYS_BLOB))
    write_plan(cache, [dict(PLAN_ENTRY, coin="SYS", ver_id="syscoin--v5.1.0")])
    app = dash._make_app()

    async def body(app, pilot):
        app.workspace.show_detail_coin(app.workspace.coins[0])
        with_plan = str(app.query_one("#detail", Static).content)
        assert "see Plan tab" in with_plan
        assert "run Plan to preview" not in with_plan, "a plan already exists — inviting another run wastes minutes"
        app.workspace.plan = []
        app.workspace.show_detail_coin(app.workspace.coins[0])
        without = str(app.query_one("#detail", Static).content)
        assert "run Plan to preview" in without

    run_app(app, body)


# ---------------------------------------------------------------------------
# Phase B — navigation & fast feedback (audit #2, #3, #10, #18, #13, #14)
# ---------------------------------------------------------------------------


def test_palette_filters_case_insensitive_substring(cache, manifest):
    """Typing filters the option list, not just the status line (audit #2)."""
    from textual.widgets import OptionList

    from dashboard.widgets import CommandPalette

    app = dash._make_app()

    async def body(app, pilot):
        app.push_screen(CommandPalette(dash.verbs.VERBS))
        await pilot.pause()
        await pilot.pause()
        full = app.screen.query_one("#palette-list", OptionList).option_count
        assert full == len(dash.verbs.VERBS)
        app.screen.query_one("#palette-input", Input).value = "Audit"
        await pilot.pause()
        await pilot.pause()
        shown = app.screen.query_one("#palette-list", OptionList).option_count
        assert 0 < shown < full, "the list must shrink to the matches"
        status = str(app.screen.query_one("#palette-status", Static).content)
        assert "no match" not in status.lower()

    run_app(app, body, screen="coins")


def test_enter_continues_from_picker(cache, manifest):
    """Enter leaves the picker like Continue does (audit #3)."""
    app = dash._make_app()

    async def body(app, pilot):
        assert screen_name(app) == "CoinsScreen"
        await pilot.press("enter")
        await pilot.pause()
        assert screen_name(app) != "CoinsScreen", "Enter must continue"

    run_app(app, body, screen="coins")


def test_picker_shows_column_labels(cache, manifest):
    """The three picker columns are labeled, not guessed (audit #10)."""
    app = dash._make_app()

    async def body(app, pilot):
        labels = str(app.screen.query_one("#coins-columns", Static).content)
        assert "conf" in labels.lower()
        assert "status" in labels.lower()

    run_app(app, body, screen="coins")


def test_ctrl_r_acknowledges_refresh(cache):
    """Ctrl+R answers visibly on the strip (audit #18)."""
    write_report(cache, "findings", [], [])
    app = dash._make_app()

    async def body(app, pilot):
        app.action_refresh()
        await pilot.pause()
        phase = str(app.query_one("#run-phase", Static).content)
        assert "refreshed" in phase.lower()

    run_app(app, body)


def test_empty_log_seeds_a_hint(cache):
    """An untouched Log tab says how to start (audit #13)."""
    write_report(cache, "findings", [], [])
    app = dash._make_app()

    async def body(app, pilot):
        app.query_one("#tabs", TabbedContent).active = "tab-log"
        await pilot.pause()
        assert "Ctrl+P" in log_text(app), "empty log must name the way in"

    run_app(app, body)


def test_empty_manifest_names_the_manifest(cache, tmp_path, monkeypatch):
    """Broken manifest: the picker names the file, not ticking (audit #14)."""
    import json as _json

    empty = tmp_path / "manifest.json"
    empty.write_text(_json.dumps([]), encoding="utf-8")
    monkeypatch.setattr(dash.paths, "DEFAULT_MANIFEST", empty)
    app = dash._make_app()

    async def body(app, pilot):
        count = str(app.screen.query_one("#coins-count", Static).content)
        assert "manifest" in count.lower(), f"must name the manifest, got: {count!r}"
        assert app.screen.query_one("#coins-continue", Button).disabled

    run_app(app, body, screen="coins")


# ---------------------------------------------------------------------------
# Phase C — hierarchy & layout (audit #1, #7, #9, #4, #15, #17)
# ---------------------------------------------------------------------------


def test_overview_leads_with_status_not_ledger(cache):
    """Scope · last run · planned writes sit above the ledger (audit #1)."""
    write_report(cache, "findings", [FINDING], [])
    app = dash._make_app()

    async def body(app, pilot):
        overview = str(app.query_one("#overview", Static).content)
        assert overview.index("scope") < overview.index("Fleet summary")
        assert overview.index("planned writes") < overview.index("Fleet summary")
        assert overview.index("last run") < overview.index("Fleet summary")

    run_app(app, body)


def test_findings_severity_cells_carry_color(cache):
    """The table's Severity cells use the pane's red/yellow language (audit #7)."""
    from rich.text import Text

    write_report(cache, "findings", [FINDING], [])
    app = dash._make_app()

    async def body(app, pilot):
        table = app.query_one("#findings-table", DataTable)
        cell = next(iter(table.get_row_at(0)))
        assert isinstance(cell, Text), "severity must be styled text, not a plain string"
        assert "red" in str(cell.style).lower(), f"FAIL reads red, got {cell.style!r}"
        status = str(app.query_one("#findings-status", Static).content)
        assert "red" in status.lower() and "yellow" in status.lower(), "a one-line legend names the colors"

    run_app(app, body)


def test_short_terminal_keeps_tabs_on_screen(cache):
    """At 80x24 the tab bar is reachable, not below the fold (audit #9).

    Eleven task rows cannot all fit in 24 lines — the guarantee is the
    tab *bar* on-screen (tabs start above the footer) with the ledger
    compacted, so results are one click away, not invisible."""
    write_report(cache, "findings", [FINDING], [])
    app = dash._make_app()

    async def body(app, pilot):
        from textual.containers import VerticalScroll

        assert "compact" in app.query_one("#overview-scroll", VerticalScroll).classes
        tabs = app.query_one("#tabs")
        assert tabs.region.y < 24, f"tab bar must start on-screen, region={tabs.region}"

    run_app(app, body, size=(80, 24))


def test_task_rows_read_as_a_menu(cache):
    """Task rows carry a menu marker and a hover/focus bar (audit #4)."""
    write_report(cache, "findings", [], [])
    app = dash._make_app()

    async def body(app, pilot):
        label = str(app.query_one("#act-analyze", Button).label)
        assert "▸ analyze" in label, f"action rows read as a menu, got {label!r}"
        css = dash.widgets.DashboardApp.CSS
        assert ":hover" in css and ":focus" in css, "menu rows answer hover/focus"

    run_app(app, body)


def test_inactive_tabs_meet_contrast_and_palette_fits(cache):
    """Inactive tabs ≥4.5:1; palette box never clips cost tags (audit #15, #17)."""
    css = dash.widgets.DashboardApp.CSS
    assert "#a0a0a0" in css, "inactive tabs use an explicit ≥4.5:1 gray"
    assert "width: 90%" in css, "the palette box scales instead of clipping"


# ---------------------------------------------------------------------------
# Phase D — content language (audit #5; D27 plain verdicts + arrows, D28
# version wired in, D29 already landed, D30 landed in Phase C)
# ---------------------------------------------------------------------------


def test_coin_detail_entries_carry_action_arrows(cache):
    """Every attention entry names its action (D27)."""
    app = _sys_app(cache)

    async def body(app, pilot):
        app.workspace.show_detail_coin(app.workspace.coins[0])
        detail = str(app.query_one("#detail", Static).content)
        assert "→" in detail, "entries map to an action"
        assert "lower MinTxFee" in detail

    run_app(app, body)


def test_coin_detail_demotes_skip_to_the_clear_line(cache):
    """A skipped check is absence of signal, not an attention entry (D27)."""
    blob = {
        "syscoin--v5.1.0": {
            "tag": "v5.1.0",
            "source": "repos/SYS",
            "mode": "reused",
            "checks": [
                {"id": "ADDRTYPE", "status": "SKIP", "detail": "not used"},
            ],
        }
    }
    write_report(cache, "audit", [dict(SYS_FINDING)], [])
    _write_param_cache(cache, [dict(SYS_FINDING)], blob)
    app = dash._make_app()

    async def body(app, pilot):
        app.workspace.show_detail_coin(app.workspace.coins[0])
        detail = str(app.query_one("#detail", Static).content)
        assert "SKIP" not in detail, "skips never headline"
        assert "1 skipped (ADDRTYPE)" in detail

    run_app(app, body)


def test_coin_detail_quiet_upstream_needs_no_action(cache):
    """'No upstream release inside the staleness window' reads as no-action."""
    quiet = dict(
        VERSION_FINDING,
        severity="REVIEW",
        id="REPO-ACTION",
        detail="REVIEW no upstream release inside the staleness window",
    )
    write_report(cache, "audit", [quiet], [])
    app = dash._make_app()

    async def body(app, pilot):
        app.workspace.show_detail_coin(app.workspace.coins[0])
        detail = str(app.query_one("#detail", Static).content)
        assert "no action" in detail

    run_app(app, body)


def test_coin_detail_evidence_drops_model_parenthetical(cache):
    """Evidence keeps file:line, drops model gibberish (D27)."""
    gibberish = dict(
        FINDING,
        coin="AGM",
        ver_id="argoneum--v1.0",
        detail="fee below relay floor (2.00x, model floor/dynamic)",
        file="src/validation.cpp",
        line=61,
    )
    write_report(cache, "audit", [gibberish], [])
    app = dash._make_app()

    async def body(app, pilot):
        app.workspace.show_detail_coin(app.workspace.coins[0])
        detail = str(app.query_one("#detail", Static).content)
        assert "2.00x" not in detail and "model floor" not in detail
        assert "src/validation.cpp" in detail and "61" in detail

    run_app(app, body)


def test_coin_detail_header_is_bold_and_versions_wired(cache):
    """Bold verdict header; hold → upstream rides along (D28)."""
    write_report(cache, "audit", [dict(VERSION_FINDING)], [])
    app = dash._make_app()

    async def body(app, pilot):
        app.workspace.show_detail_coin(app.workspace.coins[0])
        detail = str(app.query_one("#detail", Static).content)
        assert detail.startswith("[b]"), "the verdict header leads bold"
        assert "we hold" in detail and "upstream" in detail, (
            "hold vs upstream answers in-pane (was dead show_detail_finding only)"
        )

    run_app(app, body)


def test_coin_row_reason_is_a_short_verdict():
    """The table's Reason column uses the short verdict (D4, contract change)."""
    from dashboard.screens import build_coin_rows

    coins = build_coin_rows([dict(PARAM_FINDING)])
    assert coins[0]["reason"] == "overpay", f"short verdict, not engine-verbatim, got {coins[0]['reason']!r}"


# ---------------------------------------------------------------------------
# R11 review notes (PASS-with-notes): table/detail color parity, version conf
# ---------------------------------------------------------------------------


def test_review_severity_colors_match_table_and_pane(cache):
    """REVIEW reads yellow in both places — one language (R11 note 1)."""
    from rich.text import Text

    quiet = dict(
        VERSION_FINDING,
        severity="REVIEW",
        id="REPO-ACTION",
        detail="REVIEW no upstream release inside the staleness window",
    )
    write_report(cache, "audit", [quiet], [])
    app = dash._make_app()

    async def body(app, pilot):
        cell = next(iter(app.query_one("#findings-table", DataTable).get_row_at(0)))
        assert isinstance(cell, Text) and "yellow" in str(cell.style).lower()
        app.workspace.show_detail_coin(app.workspace.coins[0])
        assert "[yellow]" in str(app.query_one("#detail", Static).content)

    run_app(app, body)


def test_version_line_names_its_conf_when_it_differs(cache):
    """Multi-conf coin: the hold/upstream line says which conf (R11 note 3)."""
    a = dict(VERSION_FINDING, coin="MMM", ver_id="mmm--v1.0", versions=None)
    b = dict(VERSION_FINDING, coin="MMM", ver_id="mmm--v2.0")
    write_report(cache, "audit", [a, b], [])
    app = dash._make_app()

    async def body(app, pilot):
        app.workspace.show_detail_coin(app.workspace.coins[0])
        detail = str(app.query_one("#detail", Static).content)
        assert "mmm--v2.0" in detail, "hold/upstream data from conf B must not masquerade as conf A"

    run_app(app, body)


# ---------------------------------------------------------------------------
# Round 2 Phase 1 — quick correctness (F9, F6, F11, F10) red-first
# ---------------------------------------------------------------------------


def test_split_verdict_keeps_citation_parens_balanced():
    """F9: a trailing (src/file:N) citation must survive with both parens."""
    from dashboard.screens import split_verdict

    _v, ev = split_verdict("WARN overpay — got MinTxFee=678 (src/policy/policy.h:61)", "WARN")
    assert "(src/policy/policy.h:61)" in ev, f"citation unbalanced, got {ev!r}"
    assert ev.count("(") == ev.count(")"), f"unbalanced parens in {ev!r}"


def test_confirm_dialog_is_centered_with_compact_buttons(cache):
    """F6: modal centered, button row hugs content (no 25 empty rows)."""
    from dashboard.widgets import ConfirmScreen

    app = dash._make_app()

    async def body(app, pilot):
        app.push_screen(ConfirmScreen("Apply 1 write?", "body", action="Apply", danger=True))
        await pilot.pause()
        await pilot.pause()
        box = app.screen.query_one("#confirm-box")
        btns = app.screen.query_one("#confirm-buttons")
        assert box.region.x > 0, f"box must not hug left edge, region={box.region}"
        assert box.region.y > 0, f"box must not hug top edge, region={box.region}"
        assert btns.region.height <= 3, f"button row must hug content, got h={btns.region.height}"
        assert box.region.height <= 14, f"box must hug content, got h={box.region.height}"

    run_app(app, body, size=(120, 36))


def test_picker_zero_filter_names_the_needle(cache, manifest):
    """F11: filtering to zero matches says so instead of a blank list."""
    app = dash._make_app()

    async def body(app, pilot):
        app.screen.query_one("#coins-filter", Input).value = "zzz-no-such-coin"
        await pilot.pause()
        await pilot.pause()
        count = str(app.screen.query_one("#coins-count", Static).content)
        assert "no coins match" in count.lower(), f"must name the miss, got {count!r}"
        assert "zzz-no-such-coin" in count, f"must name the needle, got {count!r}"

    run_app(app, body, screen="coins")


def test_picker_status_severity_carries_color(cache, manifest):
    """F10: picker status reads red/yellow like table + detail."""
    write_report(cache, "findings", [dict(FINDING, coin="AAA", severity="FAIL")], [])
    app = dash._make_app()

    async def body(app, pilot):
        info = str(app.screen.query_one("#coin-info-0", Static).content)
        assert "[red]" in info or "[yellow]" in info, f"severity must carry color markup, got {info!r}"

    run_app(app, body, screen="coins")


# ---------------------------------------------------------------------------
# Round 2 Phase 2 — hierarchy & range (F1, F2, F2b, F4) red-first
# ---------------------------------------------------------------------------


def test_overview_frame_scrolls_to_report(cache):
    """F1: the ledger frame scrolls — Report/hint reachable, not clipped."""
    from textual.containers import VerticalScroll

    write_report(cache, "findings", [FINDING], [])
    app = dash._make_app()

    async def body(app, pilot):
        frame = app.query_one("#overview-scroll", VerticalScroll)
        assert frame.max_scroll_y > 0, "a 27-line ledger in 17 rows must scroll"
        frame.scroll_end(animate=False)
        await pilot.pause()
        assert frame.scroll_y > 0, "scroll_end must travel to the Report block"

    run_app(app, body)


def test_tab_activation_brings_table_on_screen(cache):
    """F2: activating Findings at 80x24 scrolls the table into view."""
    write_report(cache, "findings", [FINDING], [])
    app = dash._make_app()

    async def body(app, pilot):
        app.query_one("#tabs", TabbedContent).active = "tab-findings"
        await pilot.pause()
        await pilot.pause()
        tbl = app.query_one("#findings-table", DataTable)
        assert tbl.region.y + tbl.region.height <= 24, f"table must be on-screen after activation, region={tbl.region}"

    run_app(app, body, size=(80, 24))


@pytest.mark.parametrize(
    "size",
    [
        (64, 24),
        (80, 24),
        (100, 30),
        (120, 40),
        (160, 48),
        (190, 44),
        (256, 64),
        (320, 90),
    ],
)
def test_range_tabs_table_log_visible(cache, size):
    """F2b: tabs bar, table and log on-screen at every size 64x24..320x90."""
    write_report(cache, "findings", [FINDING], [])
    app = dash._make_app()
    _W, H = size

    async def body(app, pilot):
        tabs = app.query_one("#tabs")
        assert tabs.region.y < H, f"tabs bar off-screen at {size}: {tabs.region}"
        app.query_one("#tabs", TabbedContent).active = "tab-findings"
        await pilot.pause()
        await pilot.pause()
        tbl = app.query_one("#findings-table", DataTable)
        assert tbl.region.y + tbl.region.height <= H, f"table off-screen at {size}: {tbl.region}"
        app.query_one("#tabs", TabbedContent).active = "tab-log"
        await pilot.pause()
        await pilot.pause()
        log = app.query_one("#run-log")
        assert log.region.y + log.region.height <= H, f"log off-screen at {size}: {log.region}"
        assert log.region.height >= 6, f"log starved at {size}: h={log.region.height}"

    run_app(app, body, size=size)


def test_detail_toggle_keeps_main_usable_at_80_cols(cache):
    """F4: ^d at 80 cols narrows the pane instead of crushing main."""
    write_report(cache, "findings", [], [])
    app = dash._make_app()

    async def body(app, pilot):
        app.action_detail()
        await pilot.pause()
        await pilot.pause()
        main_w = app.query_one("#main").region.width
        assert main_w >= 48, f"main must stay usable, got w={main_w}"

    run_app(app, body, size=(80, 24))


# ---------------------------------------------------------------------------
# Round 2 Phase 3 — feedback polish (F7, F8, F14) red-first
# ---------------------------------------------------------------------------


def test_strip_note_fits_a_narrow_strip():
    """F8: the strip note is short — counts live in the log line."""
    from dashboard.widgets import _strip_note

    cases = [
        ("findings", None),
        ("audit", "AAA,BBB"),
        ("ports", None),
        ("cross-check", None),
        ("plan-fix", None),
        ("update-versions", "AAA"),
    ]
    for name, tickers in cases:
        note = _strip_note(name, tickers)
        assert len(note) <= 34, f"{name}: strip note too long: {note!r}"


def test_disarm_strip_single_line_at_140(cache):
    """F8: idle hint + note fit #run-phase at 140 cols (no mid-sentence clip)."""
    from dashboard.widgets import _strip_note

    write_report(cache, "findings", [], [])
    app = dash._make_app()

    async def body(app, pilot):
        app._disarm_strip(last=_strip_note("findings", None))
        await pilot.pause()
        phase = app.query_one("#run-phase", Static)
        text = str(phase.content)
        assert len(text) <= phase.region.width, f"strip clips: {len(text)} chars in w={phase.region.width}: {text!r}"
        assert app.query_one("#run-strip").region.height == 1

    run_app(app, body, size=(140, 42))


def test_task_hover_visible_with_transition():
    """F14: hover is a visible surface change, not a 4% whisper."""
    from dashboard import widgets as _widgets

    css = _widgets.DashboardApp.CSS
    assert "transition" in css, "task rows must animate state changes"
    assert "$panel-lighten-1" in css, "hover must be a visible surface"


# ---------------------------------------------------------------------------
# Round 2 Phase 4 — CLI (F5b live seam) red-first
# ---------------------------------------------------------------------------


def test_live_log_file_drops_progress_events(cache, monkeypatch):
    """F5b: the run's saved log file is human — no machine lines."""
    write_report(cache, "findings", [], [])

    def _writer(argv, report_path):
        code = (
            "import json,sys; json.dump({'schema_version': 1, 'summary': {}, "
            "'findings': [], 'plan': [], 'meta': {}}, "
            f"open({str(report_path)!r}, 'w'));"
            'print(\'@@PROGRESS@@ {"phase": "probe", "index": 1}\', file=sys.stderr);'
            "print('human line')"
        )
        return [sys.executable, "-c", code]

    monkeypatch.setattr(dash.runner, "audit_command", _writer)
    app = dash._make_app()

    async def body(app, pilot):
        await press_task(app, pilot, "ports")
        assert await wait_until(pilot, lambda: "done" in log_text(app))
        text = (cache / "ports.log").read_text(encoding="utf-8")
        assert "human line" in text
        assert "@@PROGRESS@@" not in text, f"machine lines in log file: {text!r}"

    run_app(app, body)


# ---------------------------------------------------------------------------
# Round 2 remediation (R11 notes) red-first
# ---------------------------------------------------------------------------


def test_empty_manifest_beats_zero_filter(cache, tmp_path, monkeypatch):
    """Empty manifest + filter text names the manifest, not the needle."""
    import json as _json

    empty = tmp_path / "manifest.json"
    empty.write_text(_json.dumps([]), encoding="utf-8")
    monkeypatch.setattr(dash.paths, "DEFAULT_MANIFEST", empty)
    app = dash._make_app()

    async def body(app, pilot):
        app.screen.query_one("#coins-filter", Input).value = "zzz"
        await pilot.pause()
        await pilot.pause()
        count = str(app.screen.query_one("#coins-count", Static).content)
        assert "manifest" in count.lower(), f"manifest error wins, got {count!r}"

    run_app(app, body, screen="coins")


def test_palette_options_lead_with_cost_tag(cache):
    """Palette rows truncate like task rows — safety tag first."""
    from textual.widgets import OptionList

    from dashboard.widgets import CommandPalette

    app = dash._make_app()

    async def body(app, pilot):
        app.push_screen(CommandPalette(dash.verbs.VERBS))
        await pilot.pause()
        await pilot.pause()
        first = app.screen.query_one("#palette-list", OptionList).get_option_at_index(0)
        prompt = str(first.prompt).lstrip("\\")
        assert prompt.startswith("["), f"palette options lead with cost tag, got {first.prompt!r}"

    run_app(app, body, screen="coins")


def test_strip_wraps_instead_of_clipping_at_100(cache):
    """Below 140 cols the strip wraps — mid-sentence clip is gone."""
    from dashboard.widgets import _strip_note

    write_report(cache, "findings", [], [])
    app = dash._make_app()

    async def body(app, pilot):
        app._disarm_strip(last=_strip_note("findings", None))
        await pilot.pause()
        strip = app.query_one("#run-strip")
        text = str(app.query_one("#run-phase", Static).content)
        assert len(text) > app.query_one("#run-phase", Static).region.width
        assert strip.region.height == 2, f"long note wraps to 2 rows, strip={strip.region}"

    run_app(app, body, size=(64, 24))


def test_confirm_dialog_fits_a_64_col_terminal(cache):
    """D1: the write gate stays fully on-screen at 64 cols."""
    from dashboard.widgets import ConfirmScreen

    app = dash._make_app()

    async def body(app, pilot):
        app.push_screen(ConfirmScreen("Run update-versions on 2 coins?", "body", action="Run", danger=True))
        await pilot.pause()
        await pilot.pause()
        box = app.screen.query_one("#confirm-box")
        assert box.region.x + box.region.width <= 64
        assert box.region.x >= 1

    run_app(app, body, screen="coins", size=(64, 24))


def test_narrow_threshold_hides_detail_at_exactly_100(cache):
    """D5: at 100 cols the pane hides instead of truncating labels."""
    write_report(cache, "findings", [], [])
    app = dash._make_app()

    async def body(app, pilot):
        assert app.query_one("#detail-scroll").display is False

    run_app(app, body, size=(100, 30))


def test_read_verb_answers_on_the_strip(cache):
    """D6: a finished read leaves its name on the strip."""
    write_report(cache, "findings", [], [])
    app = dash._make_app()

    async def body(app, pilot):
        app.run_verb("list")
        await pilot.pause()
        await pilot.pause()
        text = str(app.query_one("#run-phase", Static).content)
        assert "list" in text
        assert "local read" in text

    run_app(app, body)


def test_compact_hook_lives_on_the_scroll_frame(cache):
    """D7: the scroll frame carries compact, never the inner Static."""
    write_report(cache, "findings", [], [])
    app = dash._make_app()

    async def body(app, pilot):
        from textual.containers import VerticalScroll

        frame = app.query_one("#overview-scroll", VerticalScroll)
        inner = app.query_one("#overview", Static)
        assert "compact" in frame.classes
        assert "compact" not in inner.classes

    run_app(app, body, size=(80, 24))


@pytest.mark.parametrize("size", [(160, 48), (190, 44), (256, 64), (320, 90)])
def test_results_get_the_majority_of_body_rows(cache, size):
    """D4: chrome capped at 40% of body on full-size terminals."""
    write_report(cache, "findings", [FINDING], [])
    app = dash._make_app()

    async def body(app, pilot):
        from textual.containers import VerticalScroll

        ov = app.query_one("#overview-scroll", VerticalScroll)
        tg = app.query_one("#task-groups")
        main = app.query_one("#main")
        tbl = app.query_one("#findings-table", DataTable)
        chrome = ov.region.height + tg.region.height
        assert chrome <= int(main.region.height * 0.40) + 1
        assert tbl.region.height >= 14

    run_app(app, body, size=size)


def test_only_apply_stays_filled_warning(cache):
    """D10: one filled primary; siblings stay outlined."""
    write_report(cache, "findings", [], [])
    app = dash._make_app()

    async def body(app, pilot):
        assert str(app.query_one("#act-apply", Button).variant) == "warning"
        for aid in ("analyze", "plan", "add-coin"):
            assert str(app.query_one(f"#act-{aid}", Button).variant) == "default"

    run_app(app, body)


def test_reason_column_flexes_at_320_cols(cache):
    """D9: wide terminals show wide reasons, not empty space."""
    write_report(cache, "findings", [FINDING], [])
    app = dash._make_app()

    async def body(app, pilot):
        tbl = app.query_one("#findings-table", DataTable)
        total = sum(c.width for c in tbl.columns.values())
        assert total >= int(tbl.region.width * 0.9)

    run_app(app, body, size=(320, 90))


@pytest.mark.parametrize("size", [(120, 40), (160, 48), (190, 44)])
def test_plan_applied_column_stays_visible(cache, size):
    """M1: the Applied answer never hides behind horizontal scroll."""
    long_text = "x" * 60
    write_plan(
        cache,
        [
            dict(
                PLAN_ENTRY,
                file="wallet-confs/very-long-coin-name-here--v22.0-final.conf",
                key="someverylongkeyname",
                old=long_text,
                new=long_text,
            )
        ],
    )
    app = dash._make_app()

    async def body(app, pilot):
        app.query_one("#tabs", TabbedContent).active = "tab-plan"
        tbl = app.query_one("#plan-table", DataTable)
        assert await wait_until(
            pilot,
            lambda: tbl.show_horizontal_scrollbar is False,
            steps=100,
        ), "the flex must settle before the scrollbar is read"

    run_app(app, body, size=size)


@pytest.mark.parametrize("size", [(64, 24), (190, 44), (160, 48), (320, 90)])
def test_four_actions_need_no_overflow_hint(cache, size):
    """P1: four rows always fit — the overflow hint is retired."""
    write_report(cache, "findings", [], [])
    app = dash._make_app()

    async def body(app, pilot):
        assert not app.query("#more-tasks"), "the hint element is gone"
        for aid in ("analyze", "plan", "apply", "add-coin"):
            btn = app.query_one(f"#act-{aid}", Button)
            assert btn.region.y + btn.region.height <= size[1]

    run_app(app, body, size=size)


@pytest.mark.parametrize("size", [(64, 24), (80, 24), (100, 30)])
def test_bulk_buttons_stay_on_screen(cache, size):
    """M3: All/None/Invert never clip off the picker toolbar."""
    write_report(cache, "findings", [], [])
    app = dash._make_app()

    async def body(app, pilot):
        for bid in ("#coins-all", "#coins-none", "#coins-invert"):
            btn = app.screen.query_one(bid, Button)
            assert btn.region.x + btn.region.width <= size[0]

    run_app(app, body, screen="coins", size=size)


def test_refresh_names_what_it_counted(cache):
    """m1: the refresh ack says findings rows, not fleet coins."""
    write_report(cache, "findings", [FINDING], [])
    app = dash._make_app()

    async def body(app, pilot):
        app.action_refresh()
        await pilot.pause()
        assert "with findings" in str(app.query_one("#run-phase", Static).content)

    run_app(app, body)


def test_equal_versions_read_as_current(cache):
    """m2: identical bounds show currency, not a no-op arrow."""
    finding = dict(VERSION_FINDING, versions=dict(VERSION_FINDING["versions"], remote_latest="v1.0.0"))
    write_report(cache, "findings", [finding], [])
    app = dash._make_app()

    async def body(app, pilot):
        row = app.query_one("#findings-table", DataTable).get_row_at(0)
        assert row[2] == "v1.0.0 (current)"

    run_app(app, body)


def test_focused_task_underlines(cache):
    """m4: keyboard focus is an underline, not bold-again."""
    write_report(cache, "findings", [], [])
    app = dash._make_app()

    async def body(app, pilot):
        btn = app.query_one("#act-analyze", Button)
        assert "underline" not in str(btn.styles.text_style)
        btn.focus()
        await pilot.pause()
        assert "underline" in str(btn.styles.text_style)

    run_app(app, body)


def test_sources_summary_sits_above_the_fold(cache):
    """m3: the trust line reads without scrolling the ledger."""
    write_report(cache, "findings", [FINDING], [])
    app = dash._make_app()

    async def body(app, pilot):
        lines = str(app.query_one("#overview", Static).content).splitlines()
        assert any("sources" in line.lower() for line in lines[:7])

    run_app(app, body, size=(190, 44))


def test_workspace_shows_four_actions(cache):
    """P1: Analyze/Plan/Apply/Add coin with cost tags first."""
    write_report(cache, "findings", [], [])
    app = dash._make_app()

    async def body(app, pilot):
        for aid in ("analyze", "plan", "apply", "add-coin"):
            btn = app.query_one(f"#act-{aid}", Button)
            assert str(btn.label).startswith("["), f"{aid} must lead with its cost class"
        assert str(app.query_one("#act-apply", Button).variant) == "warning"
        for aid in ("analyze", "plan", "add-coin"):
            assert str(app.query_one(f"#act-{aid}", Button).variant) == "default"

    run_app(app, body)


def test_palette_lists_action_variants(cache, monkeypatch):
    """P1: the palette offers depths plus the four intents."""
    write_report(cache, "findings", [], [])
    app = dash._make_app()
    ran = []
    record_run_verb(monkeypatch, app, ran)

    async def body(app, pilot):
        app.action_palette()
        await pilot.pause()
        status = app.screen.query_one("#palette-status", Static)
        assert str(status.content).startswith("8 tasks"), f"palette must offer 8 actions, got {str(status.content)!r}"
        app.screen.query_one("#palette-input", Input).value = "analyze-"
        await pilot.pause()
        assert "3 matches" in str(status.content)
        app.screen.query_one("#palette-input", Input).value = "plan"
        await pilot.pause()
        await pilot.press("enter")
        await pilot.pause()
        assert ran == ["plan"]

    run_app(app, body)


def test_analyze_depths_shape_argv(cache, monkeypatch):
    """P1: depth variants translate to probe/changelog/source flags."""
    write_report(cache, "findings", [], [])
    app = dash._make_app()

    async def body(app, pilot):
        app.query_one("#tabs", TabbedContent).active = "tab-log"
        assert await wait_until(
            pilot,
            lambda: app.query_one("#run-log", RichLog)._size_known,
            steps=100,
        )
        captured = []
        record_audit_command(monkeypatch, captured)
        app.run_verb("analyze-quick")
        assert await wait_until(pilot, lambda: bool(captured), steps=100)
        assert "--local-only" in captured[-1]
        assert "--param-check" not in captured[-1]

    run_app(app, body)


def test_plan_button_sets_versions_from(cache, monkeypatch):
    """P2: Plan consumes the newest probe slot for version bumps."""
    import json as _json

    write_report(cache, "findings", [], [])
    probe = cache / "audit.json"
    probe.write_text(_json.dumps({"repos": {"u": {}}, "meta": {}}))
    app = dash._make_app()

    async def body(app, pilot):
        app.query_one("#tabs", TabbedContent).active = "tab-log"
        assert await wait_until(
            pilot,
            lambda: app.query_one("#run-log", RichLog)._size_known,
            steps=100,
        )
        captured = []
        record_audit_command(monkeypatch, captured)
        app.run_verb("plan")
        assert await wait_until(pilot, lambda: bool(captured), steps=100)
        assert "--update-versions" in captured[-1]
        assert "--versions-from" in captured[-1]
        assert captured[-1][captured[-1].index("--versions-from") + 1].endswith("audit.json")

    run_app(app, body)


def test_plan_without_probe_slot_says_so(cache, monkeypatch, manifest):
    """P2: no probe data names Analyze instead of guessing versions."""
    write_report(cache, "findings", [], [])
    app = dash._make_app()

    async def body(app, pilot):
        app.query_one("#tabs", TabbedContent).active = "tab-log"
        assert await wait_until(
            pilot,
            lambda: app.query_one("#run-log", RichLog)._size_known,
            steps=100,
        )
        captured = []
        record_audit_command(monkeypatch, captured)
        app.run_verb("plan")
        assert await wait_until(pilot, lambda: bool(captured), steps=100)
        assert "--update-versions" not in captured[-1]
        assert "Analyze" in log_text(app)

    run_app(app, body)


def test_plan_view_merges_scaffold_entries(cache):
    """P4: staged new-coin proposals read in the Plan tab."""
    import json as _json

    write_plan(cache, [PLAN_ENTRY])
    entry = {
        "action": "scaffold",
        "file": "wallet-confs/new--v1.0.conf",
        "key": "*",
        "old": None,
        "new": "generated for NEW v1.0.0",
        "reason": "scaffold",
        "coin": "NEW",
        "ver_id": "new--v1.0",
        "applied": False,
        "contents": "rpcuser=x\n",
    }
    (cache / "scaffold.json").write_text(_json.dumps({"schema_version": 1, "plan": [entry], "findings": []}))
    app = dash._make_app()

    async def body(app, pilot):
        app.query_one("#tabs", TabbedContent).active = "tab-plan"
        await pilot.pause()
        rows = app.query_one("#plan-table", DataTable).row_count
        assert rows == 2

    run_app(app, body)


def test_delist_runs_scoped_preview(cache, monkeypatch, manifest):
    """P5: delist previews ticked coins, never the fleet."""
    seed_scope(cache, ["AAA"])
    write_report(cache, "findings", [], [])
    app = dash._make_app()

    async def body(app, pilot):
        app.query_one("#tabs", TabbedContent).active = "tab-log"
        assert await wait_until(
            pilot,
            lambda: app.query_one("#run-log", RichLog)._size_known,
            steps=100,
        )
        captured = []
        record_audit_command(monkeypatch, captured)
        app.run_verb("delist")
        await pilot.pause()
        assert screen_name(app) == "ConfirmScreen"
        app.screen.query_one("#confirm-yes", Button).press()
        assert await wait_until(pilot, lambda: bool(captured), steps=100)
        assert "--delist" in captured[-1]
        assert "--dry-run" in captured[-1]
        assert "AAA" in captured[-1][captured[-1].index("--ticker") + 1]

    run_app(app, body)


def test_delist_refuses_full_fleet(cache, monkeypatch):
    """P5: the fleet is never a removal target."""
    write_report(cache, "findings", [], [])
    app = dash._make_app()

    async def body(app, pilot):
        captured = []
        record_audit_command(monkeypatch, captured)
        app.run_verb("delist")
        await pilot.pause()
        await pilot.pause()
        assert captured == []
        assert "removal target" in log_text(app).replace("\n", " ")

    run_app(app, body)


def test_plan_view_merges_delist_entries(cache):
    """P5: delist previews read in the Plan tab."""
    import json as _json

    write_plan(cache, [PLAN_ENTRY])
    entry = {
        "action": "delist",
        "file": "wallet-confs/old.conf",
        "key": "*",
        "old": None,
        "new": None,
        "reason": "remove OLD",
        "coin": "OLD",
        "ver_id": "old--v1.0",
        "applied": False,
    }
    (cache / "delist.json").write_text(_json.dumps({"schema_version": 1, "plan": [entry], "findings": []}))
    app = dash._make_app()

    async def body(app, pilot):
        app.query_one("#tabs", TabbedContent).active = "tab-plan"
        await pilot.pause()
        assert app.query_one("#plan-table", DataTable).row_count == 2

    run_app(app, body)


def test_empty_states_name_actions(cache):
    """P6: empty states point at Analyze/Plan, not retired verbs."""
    write_report(cache, "findings", [], [])
    app = dash._make_app()

    async def body(app, pilot):
        assert "Analyze" in str(app.query_one("#findings-status", Static).content)
        assert "Plan" in str(app.query_one("#write-status", Static).content)

    run_app(app, body)


def test_apply_completion_shows_applied_counts(cache, monkeypatch):
    """P3: a finished Apply reports applied rows, never stale previews."""
    write_report(cache, "findings", [], [])
    write_plan(cache, [PLAN_ENTRY])
    app = dash._make_app()

    def _completing_child(argv, report_path):
        target = argv[argv.index("--apply-plan") + 1]
        code = (
            "import json;"
            f"p={target!r};payload=json.load(open(p));"
            "[e.__setitem__('applied', True) for e in payload['plan']];"
            "json.dump(payload, open(p, 'w'));"
            f"json.dump({{'schema_version': 1, 'plan': payload['plan'], 'findings': []}}, "
            f"open({str(report_path)!r}, 'w'));"
            "print('APPLY-PLAN: applied 1, refused 0')"
        )
        return [sys.executable, "-c", code]

    monkeypatch.setattr(dash.runner, "audit_command", _completing_child)

    async def body(app, pilot):
        app.query_one("#tabs", TabbedContent).active = "tab-log"
        assert await wait_until(
            pilot,
            lambda: app.query_one("#run-log", RichLog)._size_known,
            steps=100,
        )
        app.query_one("#tabs", TabbedContent).active = "tab-plan"
        await pilot.pause()
        app.query_one("#write-apply", Button).press()
        await pilot.pause()
        assert screen_name(app) == "ConfirmScreen"
        app.screen.query_one("#confirm-yes", Button).press()
        assert await wait_until(
            pilot,
            lambda: "applied 1, refused 0" in log_text(app),
            steps=100,
        ), "the finish line must count the applied file"
        assert "wrote no report" not in log_text(app)
        table = app.query_one("#plan-table", DataTable)
        assert table.get_row_at(0)[-1] == "yes"

    run_app(app, body)


def test_narrowed_view_hides_foreign_delist_rows(cache, manifest):
    """Delist previews obey scope like plan rows do."""
    import json as _json

    seed_scope(cache, ["AAA"])
    write_report(cache, "findings", [], [])
    write_plan(cache, [])
    entry = {
        "action": "delist",
        "file": "wallet-confs/old.conf",
        "key": "*",
        "old": None,
        "new": None,
        "reason": "remove OLD",
        "coin": "OLD",
        "ver_id": "old--v1.0",
        "applied": False,
    }
    (cache / "delist.json").write_text(_json.dumps({"schema_version": 1, "plan": [entry], "findings": []}))
    app = dash._make_app()

    async def body(app, pilot):
        app.query_one("#tabs", TabbedContent).active = "tab-plan"
        await pilot.pause()
        assert app.query_one("#plan-table", DataTable).row_count == 0

    run_app(app, body)


def test_narrowed_view_shows_scoped_delist_rows(cache, manifest):
    """A scoped delist preview reads in the Plan tab under its scope."""
    import json as _json

    seed_scope(cache, ["AAA"])
    write_report(cache, "findings", [], [])
    write_plan(cache, [])
    entry = {
        "action": "delist",
        "file": "wallet-confs/aaa.conf",
        "key": "*",
        "old": None,
        "new": None,
        "reason": "remove AAA",
        "coin": "AAA",
        "ver_id": "aaa--v1.0",
        "applied": False,
    }
    (cache / "delist.scoped.json").write_text(_json.dumps({"schema_version": 1, "plan": [entry], "findings": []}))
    app = dash._make_app()

    async def body(app, pilot):
        app.query_one("#tabs", TabbedContent).active = "tab-plan"
        await pilot.pause()
        assert app.query_one("#plan-table", DataTable).row_count == 1

    run_app(app, body)


def test_plan_detail_renders_staged_file(cache):
    """P4: the detail pane shows staged contents, not just the file name."""
    import json as _json

    write_plan(cache, [])
    entry = {
        "action": "scaffold",
        "file": "wallet-confs/new--v1.0.conf",
        "key": "*",
        "old": None,
        "new": "generated for NEW v1.0.0",
        "reason": "scaffold",
        "coin": "NEW",
        "ver_id": "new--v1.0",
        "applied": False,
        "contents": "rpcuser=x\ntxindex=1\n",
    }
    (cache / "scaffold.json").write_text(_json.dumps({"schema_version": 1, "plan": [entry], "findings": []}))
    app = dash._make_app()

    async def body(app, pilot):
        app.query_one("#tabs", TabbedContent).active = "tab-plan"
        await pilot.pause()
        await pilot.pause()
        table = app.query_one("#plan-table", DataTable)
        table.focus()
        await pilot.press("down")
        await pilot.pause()
        detail = str(app.query_one("#detail", Static).content)
        assert "rpcuser=x" in detail

    run_app(app, body)
