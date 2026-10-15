#!/usr/bin/env python3
"""Corruption matrix: every dashboard reader against every wrong shape.

Static reviewers sample; this file executes. Each case feeds one
malformed input to one ingestion point — missing file, invalid JSON,
null/bool/number/string/list/dict in every slot — and asserts the
dashboard degrades to its documented default instead of raising.

Ingestion points covered: manifest read (fleet + picker), report and
plan reads (top-level and elements), summary, sidecar fields,
state file, fleet-report pick, and the dashboard CLI surface.
"""

import json
import os
import sys
import time
from pathlib import Path

import pytest

pytest.importorskip("textual")

from test_dashboard_tui import run_app, write_report
from textual.widgets import DataTable, Static

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


def _report(cache: Path, *, findings=None, summary=None, plan=None):
    payload = {
        "schema_version": 1,
        "summary": {"repos_total": 0, "alive": 0, "dead": 0, "moved": 0, "unknown": 0, "stale": 0}
        if summary is None
        else summary,
        "findings": [] if findings is None else findings,
        "plan": [] if plan is None else plan,
        "meta": {},
    }
    (cache / "findings.json").write_text(json.dumps(payload), encoding="utf-8")


def _meta(cache: Path, **fields):
    meta = {
        "verb": "findings",
        "argv": ["audit-manifest.py"],
        "report": str(cache / "findings.json"),
        "log": str(cache / "findings.log"),
        "started_at": time.time() - 60,
        "duration_seconds": 1.0,
        "audit_exit_code": 0,
    }
    meta.update(fields)
    (cache / "findings.meta.json").write_text(json.dumps(meta), encoding="utf-8")


def _overview(app) -> str:
    app.action_refresh()
    return str(app.query_one("#overview", Static).content)


# ---------------------------------------------------------------------------
# Findings shapes through a full refresh
# ---------------------------------------------------------------------------

FINDING = {
    "severity": "FAIL",
    "category": "local",
    "coin": "AAA",
    "ver_id": "aaa--v1.0",
    "id": "X",
    "detail": "d",
}


@pytest.mark.parametrize(
    "findings,expected",
    [
        pytest.param(None, [], id="null"),
        pytest.param({"a": 1}, [], id="mapping"),
        pytest.param(["x"], [], id="strings"),
        pytest.param([{}], [{}], id="empty-object-kept"),
        pytest.param("str", [], id="string"),
        pytest.param(42, [], id="number"),
        pytest.param(True, [], id="boolean"),
        pytest.param([FINDING], [FINDING], id="healthy"),
        pytest.param(
            [{"coin": "AAA", "severity": "FAIL"}, {"coin": 123, "severity": "FAIL"}],
            [{"coin": "AAA", "severity": "FAIL"}, {"coin": 123, "severity": "FAIL"}],
            id="mixed-type-coins",
        ),
    ],
    ids=str,
)
def test_refresh_survives_any_findings_shape(cache, findings, expected):
    _report(cache, findings=findings)
    _meta(cache)
    app = dash._make_app()

    async def body(app, pilot):
        assert app.workspace.findings == expected
        assert "Fleet summary" in str(app.query_one("#overview", Static).content)
        assert app.query_one("#findings-table", DataTable).row_count == len(expected)

    run_app(app, body)


# ---------------------------------------------------------------------------
# Summary / plan / sidecar shapes through a full refresh
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("summary", [[1, 2], "str", 5, None, True], ids=str)
def test_refresh_survives_any_summary_shape(cache, summary):
    _report(cache, summary=summary)
    _meta(cache)
    app = dash._make_app()

    async def body(app, pilot):
        overview = _overview(app)
        assert "Fleet summary" in overview
        assert "repos probed 0" in overview  # condensed Status-first layout (C1)

    run_app(app, body)


@pytest.mark.parametrize(
    "plan,expected",
    [
        pytest.param(None, [], id="null"),
        pytest.param({"a": 1}, [], id="mapping"),
        pytest.param(["x"], [], id="strings"),
        pytest.param([{}], [{}], id="empty-object-kept"),
        pytest.param("str", [], id="string"),
        pytest.param(42, [], id="number"),
    ],
    ids=str,
)
def test_refresh_survives_any_plan_shape(cache, plan, expected):
    _report(cache)
    _meta(cache)
    (cache / "plan-fix.json").write_text(
        json.dumps({"schema_version": 1, "plan": plan, "findings": []}),
        encoding="utf-8",
    )
    app = dash._make_app()

    async def body(app, pilot):
        assert app.workspace.plan == expected

    run_app(app, body)


@pytest.mark.parametrize("started_at", ["bad", True, 5, None], ids=str)
def test_refresh_survives_any_started_at_shape(cache, started_at):
    _report(cache)
    _meta(cache, started_at=started_at)
    app = dash._make_app()

    async def body(app, pilot):
        overview = _overview(app)
        assert "last run" in overview

    run_app(app, body)


# ---------------------------------------------------------------------------
# Manifest shapes through boot and scope math
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "raw,expected_ticks",
    [
        pytest.param('{"a": 1}', 0, id="mapping"),
        pytest.param("[1, 2]", 0, id="non-object-rows"),
        pytest.param('[{"ticker": 123}]', 0, id="non-string-ticker"),
        pytest.param('[{"ticker": "AAA"}, "x"]', 1, id="mixed-rows"),
        pytest.param("null", 0, id="null"),
    ],
    ids=str,
)
def test_boot_survives_any_manifest_shape(cache, tmp_path, monkeypatch, raw, expected_ticks):
    manifest = tmp_path / "manifest.json"
    manifest.write_text(raw, encoding="utf-8")
    monkeypatch.setattr(dash.paths, "DEFAULT_MANIFEST", manifest)
    write_report(cache, "findings", [], [])
    app = dash._make_app()

    async def body(app, pilot):
        boxes = app.screen.query("#coins-list Checkbox")
        assert len(boxes) == expected_ticks

    run_app(app, body, screen="coins")


# ---------------------------------------------------------------------------
# State-file shapes through load
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "patch,expected",
    [
        pytest.param({"selection": ["AAA", "AAA"]}, ["AAA"], id="duplicates"),
        pytest.param({"selection": "AAA"}, None, id="non-list-selection"),
        pytest.param({"selection": [1]}, None, id="non-string-selection"),
        pytest.param({"selection": None}, None, id="explicit-null"),
        pytest.param({"tab": "nope"}, "findings", id="unknown-tab-falls-back"),
        pytest.param(
            {"schema_version": -1, "selection": ["AAA"]},
            None,
            id="unknown-schema-resets",
        ),
    ],
    ids=str,
)
def test_state_load_survives_any_shape(cache, patch, expected):
    payload = {"schema_version": dash.state.STATE_VERSION}
    payload.update(patch)
    (cache / "dashboard.json").write_text(json.dumps(payload), encoding="utf-8")
    if "selection" in patch:
        assert dash.state.load()["selection"] == expected
    else:
        assert dash.state.load()["tab"] == expected
    assert dash.state.load()["filter"] == ""


@pytest.mark.parametrize("raw", ["[1, 2]", "null", "{oops"], ids=str)
def test_state_load_survives_non_mapping_files(cache, raw):
    (cache / "dashboard.json").write_text(raw, encoding="utf-8")
    scope = dash.state.load()
    assert scope["selection"] is None
    assert scope["tab"] == "findings"
    assert scope["filter"] == ""


# ---------------------------------------------------------------------------
# Fleet-report pick shapes
# ---------------------------------------------------------------------------


def test_best_fleet_report_survives_corrupt_candidates(tmp_path, monkeypatch):
    """An unreadable candidate proves nothing either way: it must not
    crash the pick, and a readable fleet file still wins."""
    monkeypatch.setattr(dash.paths, "CACHE_ROOT", tmp_path)
    monkeypatch.setattr(dash.paths, "LAST_REPORT", tmp_path / "last-run.json")
    monkeypatch.setattr(dash.paths, "LAST_META", tmp_path / "last-run.meta.json")
    bad = tmp_path / "findings.json"
    bad.write_text("{oops", encoding="utf-8")
    good = tmp_path / "audit.json"
    good.write_text(json.dumps({"findings": [], "meta": {}}), encoding="utf-8")
    old = time.time() - 60
    os.utime(good, (old, old))
    assert dash.paths.best_fleet_report() == good


# ---------------------------------------------------------------------------
# CLI surface shapes (loud refusal, never a traceback)
# ---------------------------------------------------------------------------


def test_cli_list_with_broken_manifest_is_exit_2_not_traceback(
    capsys,
    tmp_path,
    monkeypatch,
):
    monkeypatch.setattr(dash.paths, "LOG_STREAM", sys.stderr)
    bad = tmp_path / "manifest.json"
    bad.write_text('{"a": 1}', encoding="utf-8")
    assert dash.main(["list", "--manifest", str(bad)]) == 2
    assert "Traceback" not in capsys.readouterr().err
