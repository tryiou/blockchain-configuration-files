#!/usr/bin/env python3
"""Scoped runs write scope-separated cache files; fleet files stay fleet.

A narrowed run used to overwrite the very files the fleet views read
(``findings.json``, ``plan-fix.json`` …), so widening the scope
afterwards presented scoped data as the fleet and destroyed the fleet
report. Now a scoped run writes ``<verb>.scoped.json`` (+ log/meta by
suffix) and never touches the fleet slot:

* ``report_paths`` derives the slot from the tickers, fleet or scoped;
* ``best_fleet_report`` only ever picks tickers-less reports, so the
  overview, the status column and the findings table stay fleet-wide;
* refresh and the apply dialog resolve the plan file by current scope.

Fixtures are local (versions-less manifest, conf-file collisions only):
no probe, no checkout, zero network.
"""

import json
import os
import sys
import time
from pathlib import Path

import pytest

pytest.importorskip("textual")

from test_dashboard_tui import (
    PLAN_ENTRY,
    log_text,
    press_task,
    record_audit_command,
    run_app,
    screen_name,
    seed_scope,
    wait_until,
    write_plan,
    write_report,
)
from textual.widgets import Button, Checkbox, DataTable, Static, TabbedContent

import dashboard as dash


@pytest.fixture
def cache(tmp_path, monkeypatch):
    """Point every cache path at a throwaway directory."""
    root = tmp_path / "cache"
    root.mkdir()
    monkeypatch.setattr(dash.paths, "CACHE_ROOT", root)
    monkeypatch.setattr(dash.paths, "LAST_REPORT", root / "last-run.json")
    monkeypatch.setattr(dash.paths, "LAST_META", root / "last-run.meta.json")
    return root


@pytest.fixture
def manifest(tmp_path, monkeypatch):
    """A three-coin manifest, so scope math is hermetic."""
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


def test_scoped_runs_use_their_own_report_slot(tmp_path, monkeypatch):
    """The slot derives from the tickers: fleet and scoped runs of one
    verb must never share a primary, log, or sidecar."""
    monkeypatch.setattr(dash.paths, "CACHE_ROOT", tmp_path)
    monkeypatch.setattr(dash.paths, "LAST_REPORT", tmp_path / "last-run.json")
    monkeypatch.setattr(dash.paths, "LAST_META", tmp_path / "last-run.meta.json")

    fleet = dash.paths.report_paths("findings", None)
    scoped = dash.paths.report_paths("findings", None, tickers="AAA,BBB")

    assert fleet[0].name == "findings.json"
    assert scoped[0].name == "findings.scoped.json"
    assert scoped[2].name == "findings.scoped.log"
    assert dash.paths.meta_path(scoped[0]).name == "findings.scoped.meta.json"
    assert fleet[1] == scoped[1], "last-run still means whatever ran last"


def test_best_fleet_report_prefers_fleet_over_newer_scoped(tmp_path, monkeypatch):
    """Newest-by-mtime is not enough: a newer scoped-content report —
    the legacy clobber world — must never present as the fleet."""
    monkeypatch.setattr(dash.paths, "CACHE_ROOT", tmp_path)
    monkeypatch.setattr(dash.paths, "LAST_REPORT", tmp_path / "last-run.json")
    monkeypatch.setattr(dash.paths, "LAST_META", tmp_path / "last-run.meta.json")
    fleet = tmp_path / "audit.json"
    fleet.write_text(json.dumps({"findings": [], "meta": {}}), encoding="utf-8")
    old = time.time() - 60
    os.utime(fleet, (old, old))
    scoped = tmp_path / "findings.json"
    scoped.write_text(
        json.dumps({"findings": [{"coin": "AAA"}], "meta": {"tickers": "AAA"}}),
        encoding="utf-8",
    )
    assert dash.paths.best_fleet_report() == fleet


def test_best_fleet_report_skips_a_scoped_last_run_fallback(tmp_path, monkeypatch):
    """The last-run fallback gets the same scope check: with no fleet
    file on disk, a scoped last run is not a fleet report."""
    monkeypatch.setattr(dash.paths, "CACHE_ROOT", tmp_path)
    last = tmp_path / "last-run.json"
    monkeypatch.setattr(dash.paths, "LAST_REPORT", last)
    monkeypatch.setattr(dash.paths, "LAST_META", tmp_path / "last-run.meta.json")
    last.write_text(
        json.dumps({"findings": [{"coin": "AAA"}], "meta": {"tickers": "AAA"}}),
        encoding="utf-8",
    )
    assert dash.paths.best_fleet_report() is None


def _scoped_repo(tmp_path: Path) -> Path:
    """AAA+BBB collide on 9333/9332; unticked CCC holds 9433/9432.

    Versions-less on purpose (no checkout, no network); the port
    allocator reads conf files only.
    """
    (tmp_path / "wallet-confs").mkdir()
    (tmp_path / "xbridge-confs").mkdir()
    (tmp_path / "autobuild" / "configs").mkdir(parents=True)
    manifest = [
        {
            "ticker": ticker,
            "ver_id": f"{ticker.lower()}--v1",
            "versions": [],
            "wallet_conf": f"{ticker.lower()}.conf",
            "xbridge_conf": f"{ticker.lower()}.conf",
            "repo_url": f"https://example.invalid/{ticker.lower()}",
        }
        for ticker in ("AAA", "BBB", "CCC")
    ]
    manifest_path = tmp_path / "manifest-latest.json"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    for name, port, rpc in (
        ("aaa", 9333, 9332),
        ("bbb", 9333, 9332),
        ("ccc", 9433, 9432),
    ):
        (tmp_path / "wallet-confs" / f"{name}.conf").write_text(f"port={port}\nrpcport={rpc}\n", encoding="utf-8")
        (tmp_path / "xbridge-confs" / f"{name}.conf").write_text(f"Port={rpc}\n", encoding="utf-8")
    return manifest_path


def test_a_scoped_plan_fix_leaves_the_fleet_plan_alone(cache, tmp_path, capsys):
    """End to end through the real agent path: a narrowed plan-fix must
    write the scoped slot and leave no fleet plan behind."""
    manifest_path = _scoped_repo(tmp_path)
    code = dash.main(
        [
            "plan-fix",
            "--manifest",
            str(manifest_path),
            "--local-only",
            "--dry-run",
            "--tickers",
            "AAA,BBB",
        ]
    )
    assert code in (0, 1), "the run itself must succeed for the files to mean anything"
    out = capsys.readouterr().out
    envelope = json.loads(out) if out.strip() else {}
    assert not (cache / "plan-fix.json").is_file(), "a scoped run must never create the fleet plan"
    scoped = cache / "plan-fix.scoped.json"
    assert scoped.is_file(), "the scoped run lands in the scoped slot"
    payload = json.loads(scoped.read_text(encoding="utf-8"))
    assert envelope.get("sources", {}).get("report", "").endswith("plan-fix.scoped.json")
    assert payload.get("meta", {}).get("tickers") == "AAA,BBB"
    planned = [entry for entry in payload.get("plan") or [] if entry.get("key") in ("port", "rpcport")]
    assert planned, "the scoped run still plans the AAA/BBB reassignment"
    for entry in planned:
        assert str(entry.get("new")) not in {"9433", "9432"}, "unticked CCC's ports stay out even in the scoped slot"


def test_newer_scoped_files_never_leak_into_fleet_views(cache):
    """Pin: whatever a scoped run leaves behind, the fleet views
    (findings table here) read the fleet slot only."""
    write_report(
        cache,
        "findings",
        [
            dict(
                PLAN_ENTRY,
                severity="FAIL",
                coin="AAA",
                id="X",
                detail="fleet",
                file=None,
                line=None,
                key=None,
                old=None,
                new=None,
                reason=None,
                evidence=None,
                versions=None,
                ver_id="aaa--v1.0",
            ),
        ],
        [],
    )
    scoped = cache / "findings.scoped.json"
    scoped.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "summary": {},
                "findings": [dict(PLAN_ENTRY, severity="FAIL", coin="BBB")],
                "plan": [],
                "meta": {"tickers": "BBB"},
            }
        ),
        encoding="utf-8",
    )
    now = time.time()
    os.utime(scoped, (now + 60, now + 60))
    app = dash._make_app()

    async def body(app, pilot):
        table = app.query_one("#findings-table", DataTable)
        assert table.row_count == 1
        assert table.get_row_at(0)[1] == "AAA", "the scoped file must not leak in"

    run_app(app, body)


def _write_scoped_plan(root: Path, plan):
    path = root / "plan-fix.scoped.json"
    path.write_text(
        json.dumps({"schema_version": 1, "plan": list(plan), "findings": []}),
        encoding="utf-8",
    )
    return path


def test_the_apply_dialog_reads_the_scoped_plan_when_narrowed(
    cache,
    manifest,
    monkeypatch,
):
    """Narrowed scope resolves the scoped plan: the dialog counts it,
    never the fleet file beside it."""
    captured = []
    record_audit_command(monkeypatch, captured)
    seed_scope(cache, ["AAA"])
    write_report(cache, "findings", [], [])
    write_plan(
        cache,
        [
            dict(PLAN_ENTRY, coin="BBB", ver_id="bbb--v2.0"),
            dict(PLAN_ENTRY, coin="BBB", ver_id="bbb--v2.0", key="rpcport"),
            dict(PLAN_ENTRY, coin="CCC", ver_id="ccc--v3.0"),
        ],
    )
    _write_scoped_plan(
        cache,
        [
            dict(PLAN_ENTRY, coin="AAA", ver_id="aaa--v1.0"),
            dict(PLAN_ENTRY, coin="AAA", ver_id="aaa--v1.0", key="rpcport"),
        ],
    )
    app = dash._make_app()

    async def body(app, pilot):
        await press_task(app, pilot, "apply-fix")
        await pilot.pause()
        assert screen_name(app) == "ConfirmScreen"
        body_text = str(app.screen.query_one("#confirm-body").content)
        assert "2 write(s)" in body_text, "the dialog counts the scoped plan"
        assert "3 write(s)" not in body_text, "the fleet plan must not leak in"

    run_app(app, body)


def test_the_apply_dialog_falls_back_to_the_fleet_plan_when_narrowed(
    cache,
    manifest,
    monkeypatch,
):
    """Full-plan-then-narrow keeps working: with no scoped file, the
    dialog counts the fleet plan filtered to the scope — a labeled
    subset, never a silent whole."""
    captured = []
    record_audit_command(monkeypatch, captured)
    seed_scope(cache, ["AAA"])
    write_report(cache, "findings", [], [])
    write_plan(
        cache,
        [
            dict(PLAN_ENTRY, coin="AAA", ver_id="aaa--v1.0"),
            dict(PLAN_ENTRY, coin="BBB", ver_id="bbb--v2.0"),
        ],
    )
    app = dash._make_app()

    async def body(app, pilot):
        await press_task(app, pilot, "apply-fix")
        await pilot.pause()
        assert screen_name(app) == "ConfirmScreen"
        body_text = str(app.screen.query_one("#confirm-body").content)
        assert "1 write(s)" in body_text, "the dialog counts the scoped subset"
        assert "1 of 3" in body_text

    run_app(app, body)


def test_a_run_with_no_fleet_refuses_even_without_a_scope(
    cache,
    tmp_path,
    monkeypatch,
):
    """selection None means full fleet — but only when a fleet exists.
    Over an empty (broken) manifest the run gate must refuse exactly
    like the empty-scope path instead of launching."""
    bad = tmp_path / "manifest.json"
    bad.write_text('{"a": 1}', encoding="utf-8")
    monkeypatch.setattr(dash.paths, "DEFAULT_MANIFEST", bad)
    write_report(cache, "findings", [], [])
    captured = []
    record_audit_command(monkeypatch, captured)
    app = dash._make_app()

    async def body(app, pilot):
        app.state["selection"] = None
        await press_task(app, pilot, "ports")
        await pilot.pause()
        assert captured == [], "no fleet means no run"
        assert "no coins" in log_text(app)

    run_app(app, body)


def test_a_second_run_never_stacks_over_a_confirmation(
    cache,
    manifest,
    monkeypatch,
):
    """A rapid double-run must not stack two confirms: confirming both
    would queue two exclusive workers, the second cancelling the first."""
    captured = []
    record_audit_command(monkeypatch, captured)
    seed_scope(cache, ["AAA", "BBB"])
    write_report(cache, "findings", [], [])
    app = dash._make_app()

    async def body(app, pilot):
        # The Log pane must be laid out first: RichLog defers writes
        # until it knows its own size, so the busy line would otherwise
        # sit invisible in the deferred queue.
        app.query_one("#tabs", TabbedContent).active = "tab-log"
        await pilot.pause()
        await press_task(app, pilot, "ports")
        await pilot.pause()
        assert screen_name(app) == "ConfirmScreen"
        app.run_verb("ports")
        await pilot.pause()
        assert len(app.screen_stack) == 2, "the second run must be ignored"
        assert "open dialog" in log_text(app), "an ignored run still says why on the log"

    run_app(app, body)


def test_the_newer_plan_wins_regardless_of_slot(cache, manifest, monkeypatch):
    """Scoped slot preferred, not frozen: a fleet plan-fix after a scoped
    one is the fresher preview, so the narrowed view follows it."""
    captured = []
    record_audit_command(monkeypatch, captured)
    seed_scope(cache, ["AAA"])
    write_report(cache, "findings", [], [])
    _write_scoped_plan(
        cache,
        [
            dict(PLAN_ENTRY, coin="AAA", ver_id="aaa--v1.0"),
            dict(PLAN_ENTRY, coin="AAA", ver_id="aaa--v1.0", key="rpcport"),
        ],
    )
    write_plan(cache, [dict(PLAN_ENTRY, coin="AAA", ver_id="aaa--v1.0")])
    now = time.time()
    os.utime(cache / "plan-fix.scoped.json", (now - 60, now - 60))
    app = dash._make_app()

    async def body(app, pilot):
        await press_task(app, pilot, "apply-fix")
        await pilot.pause()
        assert screen_name(app) == "ConfirmScreen"
        body_text = str(app.screen.query_one("#confirm-body").content)
        assert "1 write(s)" in body_text, "the fresher fleet plan rules"

    run_app(app, body)


def test_continue_refreshes_the_plan_view_to_the_new_scope(
    cache,
    manifest,
    monkeypatch,
):
    """Committing a narrower scope must refresh the workspace with it:
    the Plan tab and the overview must not show the pre-Continue scope
    until the next Ctrl+R or task."""
    write_report(cache, "findings", [], [])
    write_plan(
        cache,
        [
            dict(PLAN_ENTRY, coin="AAA", ver_id="aaa--v1.0", file="wallet-confs/aaa.conf"),
            dict(PLAN_ENTRY, coin="BBB", ver_id="bbb--v2.0", file="wallet-confs/bbb.conf"),
        ],
    )
    app = dash._make_app()

    async def body(app, pilot):
        app.screen.query_one("#coin-1", Checkbox).value = False
        app.screen.query_one("#coin-2", Checkbox).value = False
        await pilot.pause()
        app.screen.query_one("#coins-continue", Button).press()
        await pilot.pause()
        assert screen_name(app) == "WorkspaceScreen"
        table = app.query_one("#plan-table", DataTable)
        assert table.row_count == 1, "the narrowed view follows the commit"
        assert table.get_row_at(0)[1] == "wallet-confs/aaa.conf"
        overview = str(app.query_one("#overview", Static).content)
        assert "1 of 3 coins" in overview

    run_app(app, body, screen="coins")


def test_the_apply_dialog_lists_no_none_file(cache, manifest, monkeypatch):
    """A plan entry without a file is still counted, but the file list
    must not render the string "None" for it."""
    captured = []
    record_audit_command(monkeypatch, captured)
    seed_scope(cache, ["AAA"])
    write_report(cache, "findings", [], [])
    write_plan(cache, [dict(PLAN_ENTRY, coin="AAA", ver_id="aaa--v1.0", file=None)])
    app = dash._make_app()

    async def body(app, pilot):
        await press_task(app, pilot, "apply-fix")
        await pilot.pause()
        assert screen_name(app) == "ConfirmScreen"
        body_text = str(app.screen.query_one("#confirm-body").content)
        assert "1 write(s)" in body_text, "a file-less entry still counts"
        assert "None" not in body_text

    run_app(app, body)


def test_a_launch_failure_still_writes_its_log_file(cache, monkeypatch):
    """A run that never spawns must still leave forensics: the log file
    carries the command and the error, not just the RichLog."""

    def _no_spawn(cmd, verb=None):
        raise dash.paths.DashboardError("boom")

    monkeypatch.setattr(dash.runner, "spawn_audit", _no_spawn)
    app = dash._make_app()

    async def body(app, pilot):
        await press_task(app, pilot, "ports")
        await pilot.pause()
        await pilot.pause()
        log_path = cache / "ports.log"
        assert log_path.is_file(), "even a stillborn run leaves a log file"
        text = log_path.read_text(encoding="utf-8")
        assert "boom" in text

    run_app(app, body)


def test_a_dead_cache_dir_cannot_leak_the_live_handle(cache, monkeypatch):
    """If the log file cannot be written, the worker reports on the pane
    and still stands the strip down — never crashing, never leaking."""

    def sleeper(argv, report_path):
        return [sys.executable, "-c", "import time\nprint('alive', flush=True)\ntime.sleep(30)\n"]

    monkeypatch.setattr(dash.runner, "audit_command", sleeper)
    real_write = Path.write_text

    def _fail_logs(self, data="", *args, **kwargs):
        if str(self).endswith(".log"):
            raise OSError("disk full (test)")
        return real_write(self, data, *args, **kwargs)

    monkeypatch.setattr(Path, "write_text", _fail_logs)
    app = dash._make_app()

    async def body(app, pilot):
        await press_task(app, pilot, "ports")
        assert await wait_until(pilot, lambda: app.live_run is not None)
        app.query_one("#run-stop", Button).press()
        assert await wait_until(pilot, lambda: app.query_one("#run-stop", Button).disabled), (
            "the strip stands down even when the log write fails"
        )
        assert "could not write ports.log" in log_text(app)

    run_app(app, body)


def test_the_narrowed_plan_view_shows_only_scoped_rows(
    cache,
    manifest,
    monkeypatch,
):
    """The Plan tab must agree with the Apply dialog: under a narrowed
    scope it lists the scoped subset, not the whole fleet file."""
    seed_scope(cache, ["AAA"])
    write_report(cache, "findings", [], [])
    write_plan(
        cache,
        [
            dict(PLAN_ENTRY, coin="AAA", ver_id="aaa--v1.0", file="wallet-confs/aaa.conf"),
            dict(PLAN_ENTRY, coin="BBB", ver_id="bbb--v2.0", file="wallet-confs/bbb.conf"),
        ],
    )
    app = dash._make_app()

    async def body(app, pilot):
        table = app.query_one("#plan-table", DataTable)
        assert table.row_count == 1, "out-of-scope rows are not displayed"
        assert table.get_row_at(0)[1] == "wallet-confs/aaa.conf"
        overview = str(app.query_one("#overview", Static).content)
        assert "planned writes    1" in overview

    run_app(app, body)


def test_a_raw_ticker_passthrough_still_uses_the_scoped_slot(
    cache,
    tmp_path,
    capsys,
):
    """Scope smuggled past `--` (`dashboard.py plan-fix -- --ticker X`)
    still scopes the run, so it must land in the scoped slot — argv
    itself passes through verbatim, only the slot decision reads it."""
    manifest_path = _scoped_repo(tmp_path)
    code = dash.main(
        [
            "plan-fix",
            "--manifest",
            str(manifest_path),
            "--local-only",
            "--dry-run",
            "--",
            "--ticker",
            "AAA,BBB",
        ]
    )
    assert code in (0, 1), "the run itself must succeed for the files to mean anything"
    assert not (cache / "plan-fix.json").is_file(), (
        "a scoped run must never create the fleet plan, however the scope arrived"
    )
    assert (cache / "plan-fix.scoped.json").is_file()


def test_duplicate_tickers_never_inflate_the_scope(
    cache,
    manifest,
    monkeypatch,
):
    """Duplicates reach state only by surgery (load dedupes, the picker
    ticks once), but every scope consumer must still count them once."""
    captured = []
    record_audit_command(monkeypatch, captured)
    write_report(cache, "findings", [], [])
    app = dash._make_app()

    async def body(app, pilot):
        app.state["selection"] = ["AAA", "AAA", "BBB"]
        await press_task(app, pilot, "ports")
        await pilot.pause()
        assert screen_name(app) == "ConfirmScreen"
        title = str(app.screen.query_one("#confirm-title").content)
        assert "Run ports on 2 of 3 coins" in title, "duplicates count once"
        app.screen.query_one("#confirm-yes", Button).press()
        assert await wait_until(pilot, lambda: captured), "the run must start"
        assert captured[0][captured[0].index("--ticker") + 1] == "AAA,BBB"

    run_app(app, body)
