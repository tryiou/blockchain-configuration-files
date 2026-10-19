#!/usr/bin/env python3
"""Contract tests for dashboard.py's own surface.

Scope is deliberately narrow: these cover what this file promises its
callers — the CLI shape, exit codes, the JSON envelope, the verb table,
the report plumbing, and the runner's child-stream handling (progress
parsing, child environment, live streaming and stop). The audit script's
behaviour is owned by test_audit_manifest*.py and is NOT re-tested here;
nothing in this module runs audit-manifest.py (importing its progress
module to pin the wire format launches no subprocess).

Standard library + pytest only, so this file runs under the workspace venv
next to the audit suite (Textual is not installed there).
"""

import asyncio
import json
import subprocess
import sys
from pathlib import Path

import pytest

import dashboard as dash

DASH_PATH = Path(__file__).resolve().parents[1] / "dashboard.py"


def test_default_manifest_name_matches_the_engine():
    """The dashboard and the engine must name the default manifest alike.

    Plan entries and appliers compare the manifest's repo-relative name,
    so a dashboard that drifted from the engine's spelling would silently
    misroute every manifest entry the dashboard launches a run for.
    """
    from audit_manifest.constants import DEFAULT_MANIFEST_NAME

    assert dash.paths.DEFAULT_MANIFEST_NAME == DEFAULT_MANIFEST_NAME
    assert dash.paths.DEFAULT_MANIFEST.name == DEFAULT_MANIFEST_NAME


def test_last_run_scope_reads_a_flag_looking_ticker_as_no_coins():
    """`--ticker --report` is a scope the engine matches no coin to.

    argparse consumes the next token verbatim, so the scope line must not
    count the mis-consumed flag as a coin. The slot decision keeps the
    faithful string — the engine would run the same scope — but the
    display says the truth.
    """
    assert dash.model._last_run_scope(["--ticker", "AAA,BBB"]) == "2 coins"
    assert dash.model._last_run_scope(["--ticker", "AAA"]) == "1 coin"
    assert dash.model._last_run_scope(["--ticker", "--report"]) == "scope matched no coins"
    assert dash.model._last_run_scope(["--local-only"]) == "full fleet"
    # The slot-facing read stays faithful to the engine's own parse.
    assert dash.model.argv_tickers(["--ticker", "--report"]) == "--report"


# ---------------------------------------------------------------------------
# Subprocess-level CLI contract
# ---------------------------------------------------------------------------


def run_cli(*args, stdin_null=True):
    return subprocess.run(
        [sys.executable, str(DASH_PATH), *args],
        capture_output=True,
        text=True,
        stdin=subprocess.DEVNULL if stdin_null else None,
        check=False,
    )


def test_help_exits_zero_and_lists_verbs_on_stdout():
    res = run_cli("--help")
    assert res.returncode == 0
    assert "verbs:" in res.stdout
    for name in dash.VERBS:
        assert name in res.stdout


def test_no_verb_without_a_tty_exits_2_with_stdout_empty():
    # stdout is a pipe here, so the TUI must not even be attempted.
    res = run_cli()
    assert res.returncode == 2
    assert res.stdout == ""
    assert "not a TTY" in res.stderr


def test_unknown_verb_exits_2_with_stdout_empty():
    res = run_cli("frobnicate")
    assert res.returncode == 2
    assert res.stdout == ""
    assert "unknown verb" in res.stderr


def test_list_verb_is_pure_json_on_stdout():
    res = run_cli("list")
    assert res.returncode == 0
    envelope = json.loads(res.stdout)  # fails if anything but JSON leaked
    assert envelope["schema_version"] == dash.SCHEMA_VERSION
    assert envelope["verb"] == "list"
    assert envelope["ok"] is True
    assert envelope["counts"]["total"] == len(envelope["entries"])
    assert res.stderr == ""


def test_importing_dashboard_never_imports_textual():
    code = (
        "import importlib.util, sys\n"
        f"sys.path.insert(0, {str(DASH_PATH.parent)!r})\n"
        f"spec = importlib.util.spec_from_file_location('d', {str(DASH_PATH)!r})\n"
        "mod = importlib.util.module_from_spec(spec)\n"
        "spec.loader.exec_module(mod)\n"
        "print('textual' in sys.modules)\n"
    )
    res = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, check=False)
    assert res.returncode == 0, res.stderr
    assert res.stdout.strip() == "False", "importing dashboard pulled in Textual"


def test_tui_without_textual_fails_with_an_install_hint(capsys, monkeypatch):
    """run_tui() must explain the missing optional dependency and exit 2.

    The absence is simulated rather than assumed: a ``None`` entry in
    ``sys.modules`` makes any later import of that name raise ImportError,
    so this branch is exercised whether or not Textual happens to be
    installed in the interpreter running the suite.
    """
    monkeypatch.setattr(dash.paths, "LOG_STREAM", sys.stderr)
    monkeypatch.setitem(sys.modules, "textual", None)
    assert dash.run_tui() == 2
    err = capsys.readouterr().err
    assert "optional dependency" in err
    assert "requirements.txt" in err


# ---------------------------------------------------------------------------
# Verb translation (in-process: no audit script is executed)
# ---------------------------------------------------------------------------


def test_split_raw_stops_at_the_double_dash():
    head, raw = dash.split_raw(["ports", "--tickers", "LTC", "--", "--fees-only"])
    assert head == ["ports", "--tickers", "LTC"]
    assert raw == ["--fees-only"]


def test_raw_passthrough_reaches_the_audit_argv_last():
    head, raw = dash.split_raw(["cross-check", "--", "--strict-per-version", "--fees-only"])
    opts = dash.build_parser().parse_args(head)
    argv = dash.build_audit_argv(opts, raw)
    assert argv[-2:] == ["--strict-per-version", "--fees-only"]
    # ...and the verb's own mode still precedes the passthrough.
    assert "--local-only" in argv[: -len(raw)]


def test_verb_default_modes_are_never_narrowed_silently():
    cases = {
        "findings": ["--no-changelog"],
        "param-check": ["--local-only", "--param-check"],
        "ports": ["--local-only"],
        "cross-check": ["--local-only"],
        "plan-fix": ["--local-only", "--param-check", "--dry-run", "--write-config", "--fee-write", "--fix-ports"],
        "apply-fix": ["--local-only", "--param-check", "--write-config", "--fee-write", "--fix-ports"],
    }
    for verb, expected in cases.items():
        opts = dash.default_opts(verb)
        argv = dash.build_audit_argv(opts, [])
        for flag in expected:
            assert flag in argv, f"{verb} lost its default flag {flag}"


def test_apply_fix_is_a_write_and_plan_fix_is_a_dry_run():
    opts = dash.default_opts("plan-fix")
    argv = dash.build_audit_argv(opts, [])
    assert "--dry-run" in argv
    argv = dash.build_audit_argv(dash.default_opts("apply-fix"), [])
    assert "--dry-run" not in argv


def test_with_probe_widens_a_local_only_verb():
    opts = dash.default_opts("ports")
    opts.with_probe = True
    argv = dash.build_audit_argv(opts, [])
    assert "--local-only" not in argv


def test_scaffold_without_repo_url_is_a_usage_error():
    # Raised before any subprocess exists, so this is a pure contract check.
    opts = dash.default_opts("scaffold")
    with pytest.raises(dash.DashboardError, match="--repo-url"):
        dash.build_audit_argv(opts, [])


def test_every_verb_declares_a_documented_cost_class():
    """Each verb's cost class is what its task row advertises to the operator."""
    assert {name: verb.cost for name, verb in dash.VERBS.items()} == {
        "list": "local",
        "report": "local",
        "cross-check": "local",
        "ports": "local",
        "findings": "network",
        "audit": "network",
        "analyze": "network",
        "update-versions": "network",
        "scaffold": "network",
        "param-check": "heavy",
        "plan-fix": "heavy",
        "apply-fix": "heavy",
        "apply-plan": "local",
        "delist": "local",
    }
    assert set(dash.verbs.COST_LABELS) == {"local", "network", "heavy"}
    for verb in dash.VERBS.values():
        assert verb.cost in dash.verbs.COST_LABELS, f"{verb.name} has no display label for class {verb.cost}"


def test_task_rows_tell_the_operator_where_results_land():
    """Every task label names its destination: Log, overview, Findings
    tab, Plan tab. Ports/cross-check surface in the overview ledger
    (their reports carry no finding rows); reads stay Log-only."""
    for name in ("list", "report"):
        assert "Log" in dash.VERBS[name].summary, f"{name} must name the Log"
    for name in ("cross-check", "ports"):
        assert "overview" in dash.VERBS[name].summary, f"{name} must name the overview ledger"
    for name in ("findings", "audit", "param-check"):
        assert "Findings tab" in dash.VERBS[name].summary
    assert "Plan tab" in dash.VERBS["plan-fix"].summary
    for name in ("apply-fix", "update-versions", "scaffold"):
        assert dash.VERBS[name].summary.startswith("WRITE:"), f"{name} must shout that it writes"


def test_heavy_cost_promises_no_minutes():
    """A public label cannot keep another box's number — slow, not ~Nm."""
    assert dash.verbs.COST_LABELS["heavy"] == "network (slow)"


def test_github_url_validation_is_strict():
    good = dash.verbs.parse_github_repo_url
    assert good("https://github.com/org/coin-core") == "https://github.com/org/coin-core"
    assert good("https://github.com/org/coin-core.git") == "https://github.com/org/coin-core"
    assert good("  https://github.com/org/coin-core/  ") == "https://github.com/org/coin-core"
    for bad in (
        "",
        "   ",
        "https://github.com/org",
        "http://github.com/org/coin-core",
        "https://gitlab.com/org/coin-core",
        "https://github.com//coin-core",
        "not a url",
    ):
        assert good(bad) is None, f"{bad!r} must be refused"


# ---------------------------------------------------------------------------
# Exit codes
# ---------------------------------------------------------------------------


def test_informational_verbs_always_exit_zero():
    for name in ("list", "report"):
        verb = dash.VERBS[name]
        assert dash.decide_exit(verb, dash.default_opts(name), [{"x": 1}]) == 0


def test_data_verb_exit_reflects_whether_there_is_something_to_decide():
    verb = dash.VERBS["ports"]
    assert dash.decide_exit(verb, dash.default_opts("ports"), [{"x": 1}]) == 1
    assert dash.decide_exit(verb, dash.default_opts("ports"), []) == 0


def test_apply_plan_exit_reflects_refusals():
    """A partial apply is a pending decision, not success."""
    verb = dash.VERBS["apply-plan"]
    opts = dash.default_opts("apply-plan")
    assert dash.decide_exit(verb, opts, [{"applied": True}]) == 0
    assert dash.decide_exit(verb, opts, [{"applied": True}, {"applied": False}]) == 1
    assert dash.decide_exit(verb, opts, []) == 0


def test_write_verb_that_really_wrote_is_not_a_pending_decision():
    verb = dash.VERBS["apply-fix"]
    opts = dash.default_opts("apply-fix")
    assert dash.decide_exit(verb, opts, [{"applied": True}]) == 0


def test_write_verb_run_as_a_preview_follows_the_data_verb_rule():
    verb = dash.VERBS["apply-fix"]
    opts = dash.default_opts("apply-fix")
    opts.dry_run = True
    assert dash.decide_exit(verb, opts, [{"applied": False}]) == 1
    assert dash.decide_exit(verb, opts, []) == 0


def test_scaffold_without_apply_is_a_preview():
    verb = dash.VERBS["scaffold"]
    opts = dash.default_opts("scaffold")
    opts.repo_url = "https://example.invalid/repo.git"
    assert dash.decide_exit(verb, opts, [{"applied": False}]) == 1
    opts.apply = True
    assert dash.decide_exit(verb, opts, [{"applied": True}]) == 0


def test_live_write_with_an_empty_plan_needs_a_clean_engine_exit():
    """An empty plan is "nothing to decide" only when the engine exited clean.

    A write verb that planned no rows but whose run failed refused before it
    could do anything (unresolvable source, a refused target) — that is still
    a pending decision, not success.
    """
    verb = dash.VERBS["apply-fix"]
    opts = dash.default_opts("apply-fix")
    assert dash.decide_exit(verb, opts, [], audit_exit=0) == 0
    assert dash.decide_exit(verb, opts, [], audit_exit=1) == 1


def test_live_write_that_refused_before_planning_exits_1(capsys, tmp_path, monkeypatch):
    """``scaffold --apply`` that fails with an empty plan must not read as success.

    The engine can refuse before deriving a single entry (an unresolvable fee
    source), exiting non-zero with an empty plan. The envelope must report the
    pending decision (exit 1), never the success code.
    """
    monkeypatch.setattr(dash.paths, "LOG_STREAM", sys.stderr)
    monkeypatch.setattr(dash.paths, "CACHE_ROOT", tmp_path)
    monkeypatch.setattr(dash.paths, "LAST_REPORT", tmp_path / "last-run.json")
    monkeypatch.setattr(dash.paths, "LAST_META", tmp_path / "last-run.meta.json")

    def _refused(cmd, log_path, *_args, **_kwargs):
        report = Path(cmd[cmd.index("--report") + 1])
        report.write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "findings": [],
                    "plan": [],
                    "scaffold": {"mode": "scaffold", "applied": False, "error": "fee source unresolvable"},
                    "meta": {},
                    "summary": {},
                }
            ),
            encoding="utf-8",
        )
        return {"returncode": 1, "duration": 0.0, "log": str(log_path)}

    monkeypatch.setattr(dash.runner, "run_audit", _refused)
    assert dash.main(["scaffold", "--repo-url", "https://example.invalid/aaa", "--apply"]) == 1
    assert "Traceback" not in capsys.readouterr().err


# ---------------------------------------------------------------------------
# Envelope
# ---------------------------------------------------------------------------


def _envelope(exit_code=1, findings=(), plan=()):
    verb = dash.VERBS["ports"]
    report = {"findings": list(findings), "plan": list(plan), "summary": {}, "meta": {}, "schema_version": 1}
    return dash.build_envelope(
        dash.verbs.EnvelopeInputs(
            verb=verb,
            report=report,
            argv=["audit-manifest.py"],
            started_at=None,
            duration=None,
            audit_exit=None,
            report_path=None,
            log_path=None,
            extra={"findings": list(findings), "plan": list(plan)},
            exit_code=exit_code,
        )
    )


def test_envelope_shape_is_stable():
    env = _envelope(exit_code=1, findings=[{"severity": "FAIL", "coin": "X", "category": "c"}])
    assert env["schema_version"] == dash.SCHEMA_VERSION
    assert env["verb"] == "ports"
    assert env["exit_code"] == 1
    assert env["ok"] is True
    assert env["counts"]["total"] == 1
    assert env["counts"]["by_coin"] == {"X": 1}
    assert env["plan_count"] == 0
    assert set(env["sources"]) == {"report", "log", "argv", "audit_exit_code", "duration_seconds", "age_seconds"}


def test_envelope_ok_is_false_only_for_a_failed_run():
    assert _envelope(exit_code=0)["ok"] is True
    assert _envelope(exit_code=1)["ok"] is True
    assert _envelope(exit_code=2)["ok"] is False


def test_envelope_preserves_the_versions_block():
    """The envelope relays findings verbatim — the block survives."""
    block = {
        "declared": ["v1.0.0"],
        "our_latest": "v1.0.0",
        "remote_latest": "v2.0.0",
        "newer_same": ["v2.0.0"],
        "newer_alt": [],
        "missing": [],
        "found": ["v1.0.0"],
        "tag_count": 3,
        "conf": "x--v1.0.0",
    }
    env = _envelope(
        exit_code=1,
        findings=[
            {"severity": "UPGRADE", "coin": "X", "category": "version", "id": "REPO-ACTION", "versions": block},
        ],
    )
    assert env["findings"][0]["versions"] == block
    assert env["counts"]["total"] == 1


# ---------------------------------------------------------------------------
# Report plumbing
# ---------------------------------------------------------------------------


def test_each_verb_gets_its_own_report_file(tmp_path):
    primary, last, log = dash.report_paths("plan-fix", None)
    assert primary.name == "plan-fix.json"
    assert primary.parent == dash.paths.CACHE_ROOT
    assert last == dash.paths.LAST_REPORT
    assert log.name == "plan-fix.log"


def test_an_explicit_report_path_redirects_primary_and_log(tmp_path):
    target = tmp_path / "custom.json"
    primary, last, log = dash.report_paths("findings", str(target))
    assert primary == target
    assert last == dash.paths.LAST_REPORT
    assert log == tmp_path / "custom.log"


def test_meta_sidecar_is_named_after_its_report(tmp_path):
    assert dash.meta_path(tmp_path / "findings.json") == tmp_path / "findings.meta.json"


def test_best_fleet_report_prefers_a_fleet_report_over_the_last_run(tmp_path, monkeypatch):
    import os

    monkeypatch.setattr(dash.paths, "CACHE_ROOT", tmp_path)
    monkeypatch.setattr(dash.paths, "LAST_REPORT", tmp_path / "last-run.json")
    base = 1_700_000_000.0

    def stamp(name, when):
        path = tmp_path / name
        path.write_text("{}")
        os.utime(path, (when, when))
        return path

    assert dash.best_fleet_report() is None

    # Written oldest first: last-run, then the fleet reports.
    last = stamp("last-run.json", base)
    assert dash.best_fleet_report() == last, "last-run should be the fallback"

    findings = stamp("findings.json", base + 10)
    assert dash.best_fleet_report() == findings, (
        "a cheap verb refreshing last-run.json must not displace the fleet report"
    )

    audit = stamp("audit.json", base + 5)
    assert dash.best_fleet_report() == findings, "the newest fleet report wins"

    os.utime(audit, (base + 20, base + 20))
    assert dash.best_fleet_report() == audit


def test_report_verb_without_a_prior_run_is_an_error(capsys, monkeypatch, tmp_path):
    monkeypatch.setattr(dash.paths, "LOG_STREAM", sys.stderr)
    monkeypatch.setattr(dash.paths, "LAST_REPORT", tmp_path / "last-run.json")
    monkeypatch.setattr(dash.paths, "LAST_META", tmp_path / "last-run.meta.json")
    assert dash.main(["report"]) == 2
    out = capsys.readouterr()
    assert out.out == ""
    assert "no such report" in out.err


def test_last_run_meta_is_never_a_non_dict(tmp_path, monkeypatch):
    """A valid-JSON sidecar of the wrong shape is as broken as corrupt JSON.

    read_last_run_meta() promises a mapping; every caller (the envelope,
    the TUI's report dump) reads keys off the result, so anything else —
    a list, a string — must land on the same empty default as a file
    that cannot be read at all.
    """
    meta = tmp_path / "last-run.meta.json"
    meta.write_text("[1, 2]", encoding="utf-8")
    monkeypatch.setattr(dash.paths, "LAST_META", meta)
    assert dash.paths.read_last_run_meta() == {}


def test_read_meta_for_is_never_a_non_dict(tmp_path):
    """Like read_last_run_meta: callers read keys off the result, so a
    non-mapping sidecar lands on the empty default."""
    report = tmp_path / "findings.json"
    report.write_text("{}", encoding="utf-8")
    (tmp_path / "findings.meta.json").write_text("[1, 2]", encoding="utf-8")
    assert dash.paths.read_meta_for(report) == {}


def test_fleet_entries_is_empty_on_a_broken_manifest(tmp_path, monkeypatch):
    """The agent reader raises on a non-array manifest; the TUI helper
    degrades to an empty fleet instead of crashing the screens."""
    bad = tmp_path / "manifest.json"
    bad.write_text('{"a": 1}', encoding="utf-8")
    monkeypatch.setattr(dash.paths, "DEFAULT_MANIFEST", bad)
    assert dash.verbs.fleet_entries() == []


def test_list_verb_applies_the_tickers_filter(capsys):
    """`list --tickers` must narrow: silently returning the full fleet
    for a narrowed agent request misleads."""
    assert dash.main(["list", "--tickers", "BTC"]) == 0
    out = capsys.readouterr().out
    envelope = json.loads(out)
    tickers = [e.get("ticker") for e in envelope["entries"]]
    assert tickers == ["BTC"], "the filter names the only row returned"


def test_list_tickers_matches_an_untickable_row_explicitly(capsys, tmp_path, monkeypatch):
    """Pinned divergence: the agent `list` matches tickers as strings, so
    `--tickers 123` finds an int-ticker row the picker (string tickers
    only) will never tick. Documented here so the difference stays a
    decision, not drift."""
    manifest = tmp_path / "manifest.json"
    manifest.write_text(
        json.dumps(
            [
                {
                    "ticker": 123,
                    "ver_id": "x--v1",
                    "versions": [],
                    "wallet_conf": "x.conf",
                    "xbridge_conf": "x.conf",
                    "repo_url": "https://example.invalid/x",
                },
            ]
        ),
        encoding="utf-8",
    )
    assert dash.main(["list", "--manifest", str(manifest), "--tickers", "123"]) == 0
    out = capsys.readouterr().out
    envelope = json.loads(out)
    assert [e.get("ticker") for e in envelope["entries"]] == [123]


def test_report_verb_rejects_tickers(capsys, tmp_path, monkeypatch):
    """`report` describes the last run — a coin filter is meaningless on
    it, so it must refuse loudly instead of ignoring the flag."""
    monkeypatch.setattr(dash.paths, "LOG_STREAM", sys.stderr)
    monkeypatch.setattr(dash.paths, "CACHE_ROOT", tmp_path)
    monkeypatch.setattr(dash.paths, "LAST_REPORT", tmp_path / "last-run.json")
    monkeypatch.setattr(dash.paths, "LAST_META", tmp_path / "last-run.meta.json")
    (tmp_path / "last-run.json").write_text(
        json.dumps({"schema_version": 1, "findings": [], "plan": [], "meta": {}}),
        encoding="utf-8",
    )
    (tmp_path / "last-run.meta.json").write_text(
        json.dumps({"verb": "findings", "argv": [], "report": "", "log": ""}),
        encoding="utf-8",
    )
    assert dash.main(["report", "--tickers", "BTC"]) == 2
    err = capsys.readouterr().err
    assert "tickers" in err, "the refusal must name the offending flag"


def test_report_verb_on_a_corrupt_last_run_is_exit_2(capsys, tmp_path, monkeypatch):
    """A hand-corrupted last-run report must read as a clean usage-level
    error, not an AttributeError traceback out of the envelope build."""
    monkeypatch.setattr(dash.paths, "LOG_STREAM", sys.stderr)
    monkeypatch.setattr(dash.paths, "CACHE_ROOT", tmp_path)
    monkeypatch.setattr(dash.paths, "LAST_REPORT", tmp_path / "last-run.json")
    monkeypatch.setattr(dash.paths, "LAST_META", tmp_path / "last-run.meta.json")
    (tmp_path / "last-run.json").write_text(
        json.dumps({"schema_version": 1, "findings": ["x"], "plan": [], "meta": {}}),
        encoding="utf-8",
    )
    assert dash.main(["report"]) == 2
    err = capsys.readouterr().err
    assert "Traceback" not in err
    assert "corrupt" in err.lower()


def test_scaffold_verb_rejects_tickers(capsys, monkeypatch):
    """Scope never applies to a repo-URL verb: like `report`, scaffold
    must refuse `--tickers` loudly instead of ignoring it by ordering."""
    monkeypatch.setattr(dash.paths, "LOG_STREAM", sys.stderr)

    def _no_spawn(*args, **kwargs):
        raise AssertionError("a refused verb must never spawn the audit")

    monkeypatch.setattr(dash.runner, "run_audit", _no_spawn)
    assert (
        dash.main(
            [
                "scaffold",
                "--tickers",
                "AAA",
                "--repo-url",
                "https://example.invalid/aaa",
            ]
        )
        == 2
    )
    err = capsys.readouterr().err
    assert "tickers" in err, "the refusal must name the offending flag"


# ---------------------------------------------------------------------------
# Runner: the child stream (progress parsing, env, streaming, stop)
# ---------------------------------------------------------------------------
def test_progress_parser_accepts_a_real_emitted_line_and_ignores_noise(capsys, monkeypatch):
    # The line format is a wire contract between two independently written
    # parsers; this test crosses it on purpose by feeding the audit
    # script's own emitter output into the dashboard's parser.
    monkeypatch.delenv("AUDIT_VERB", raising=False)
    import audit_manifest.progress as audit_progress

    audit_progress.emit("probe", index=1, total=2, ticker="AAA")
    line = capsys.readouterr().err.splitlines()[0]

    evt = dash.runner.parse_progress(line)
    assert evt is not None
    assert evt["phase"] == "probe"
    assert (evt["index"], evt["total"], evt["ticker"]) == (1, 2, "AAA")
    assert evt["verb"] is None

    assert dash.runner.parse_progress("Probing 2 distinct repos...\n") is None
    assert dash.runner.parse_progress("@@PROGRESS@@ {truncated") is None
    assert dash.runner.parse_progress("@@PROGRESS@@ [1, 2]") is None


def test_child_env_carries_the_verb_and_keeps_the_parent_environment(monkeypatch):
    import os

    monkeypatch.setenv("AUDIT_VERB", "stale")
    monkeypatch.setenv("SOME_PARENT_VAR", "kept")

    env = dash.runner.child_env("ports")
    assert env["AUDIT_VERB"] == "ports"
    assert env["SOME_PARENT_VAR"] == "kept"
    assert env.get("PATH") == os.environ.get("PATH")

    assert "AUDIT_VERB" not in dash.runner.child_env(None), "a spawn that names no verb must not inherit a stale verb"


def test_stream_lines_separates_progress_events_from_display_lines():
    # The child prints one @@PROGRESS@@ line (verb read from the env the
    # spawn must have set) and one human line; the display callback must
    # see only the human one while the capture keeps both.
    child = (
        "import json, os, time\n"
        "print('@@PROGRESS@@ ' + json.dumps({"
        "'phase': 'param-check', 'index': 2, 'total': 3, 'ticker': 'LTC', "
        "'tag': 'v1.0.0', 'verb': os.environ.get('AUDIT_VERB'), 'ts': 1.0}))\n"
        "print('human line')\n"
        "time.sleep(0.05)\n"
    )

    async def scenario():
        run = await dash.runner.spawn_audit([sys.executable, "-c", child], verb="param-check")
        display, events = [], []
        rc = await dash.runner.stream_lines(run, on_line=display.append, on_progress=events.append)
        return run, display, events, rc

    run, display, events, rc = asyncio.run(scenario())

    assert rc == 0
    assert display == ["human line\n"], "progress lines are machine state, not log text"
    assert [e["phase"] for e in events] == ["param-check"]
    assert (events[0]["index"], events[0]["total"]) == (2, 3)
    assert events[0]["verb"] == "param-check", "the spawn's env must reach the child"
    assert run.phase == "param-check"
    assert len(run.lines) == 2, "the capture keeps every line, event or not"


def test_a_phaseless_progress_event_keeps_the_last_phase():
    """A progress event without a phase key must not wipe the strip's
    phase: only hand-crafted lines omit it (emit always sends one)."""
    child = (
        "import json\n"
        "print('@@PROGRESS@@ ' + json.dumps({'phase': 'param-check', 'index': 1,"
        " 'total': 2, 'ticker': 'AAA', 'verb': 'x', 'ts': 1.0}))\n"
        "print('@@PROGRESS@@ ' + json.dumps({'index': 2,"
        " 'total': 2, 'ticker': 'BBB', 'verb': 'x', 'ts': 2.0}))\n"
    )

    async def scenario():
        run = await dash.runner.spawn_audit([sys.executable, "-c", child])
        rc = await dash.runner.stream_lines(run)
        return run, rc

    run, rc = asyncio.run(scenario())

    assert rc == 0
    assert run.phase == "param-check", "a phaseless event carries no phase to show"


def test_stream_lines_refuses_an_unpiped_child():
    """stream_lines assumes a piped stdout; a None stream must fail as a
    DashboardError, not an AttributeError inside the worker."""

    class _Unpiped:
        stdout = None
        returncode = 0

    async def scenario():
        run = dash.runner.LiveRun(_Unpiped())
        with pytest.raises(dash.paths.DashboardError):
            await dash.runner.stream_lines(run)

    asyncio.run(scenario())


def test_live_run_stop_terminates_the_child():
    async def scenario():
        run = await dash.runner.spawn_audit(
            [sys.executable, "-c", "import time\nprint('alive', flush=True)\ntime.sleep(30)\n"],
            verb="ports",
        )
        # The first line proves the child is up before we pull the plug.
        await asyncio.wait_for(run.proc.stdout.readline(), 10)
        run.stop()
        rc = await asyncio.wait_for(run.proc.wait(), 10)
        await asyncio.sleep(0.05)  # let the fire-and-forget kill watcher observe the exit
        return run, rc

    run, rc = asyncio.run(scenario())

    assert run.stopped
    assert rc != 0, "a stopped child must not look like a clean exit"
    assert any("--- stopped by user ---" in ln for ln in run.lines)


# ---------------------------------------------------------------------------
# State: dashboard.json scope persistence (selection / filter / tab)
# ---------------------------------------------------------------------------


def test_state_round_trips_selection_filter_and_tab(tmp_path, monkeypatch):
    monkeypatch.setattr(dash.paths, "CACHE_ROOT", tmp_path)

    assert dash.state.load() == dash.state.defaults(), "a missing file is the defaults"

    scope = dash.state.defaults()
    scope["selection"] = ["BTC", "LTC"]
    scope["filter"] = "lt"
    scope["tab"] = "plan"
    dash.state.save(scope)

    assert (tmp_path / "dashboard.json").is_file()
    assert dash.state.load() == scope


def test_state_falls_back_on_unusable_content(tmp_path, monkeypatch):
    import json as _json

    monkeypatch.setattr(dash.paths, "CACHE_ROOT", tmp_path)
    path = tmp_path / "dashboard.json"
    defaults = dash.state.defaults()

    path.write_text("{not json", encoding="utf-8")
    assert dash.state.load() == defaults, "corrupt JSON is the defaults, never an error"

    path.write_text(_json.dumps({"schema_version": 99, "selection": ["X"]}), encoding="utf-8")
    assert dash.state.load() == defaults, "an unknown schema_version must not be trusted"

    path.write_text(
        _json.dumps(
            {
                "schema_version": 1,
                "selection": "BTC",
                "filter": 7,
                "tab": "nope",
            }
        ),
        encoding="utf-8",
    )
    loaded = dash.state.load()
    assert loaded["selection"] is None, "a non-list selection is not a selection"
    assert loaded["filter"] == "", "a non-string filter is not a filter"
    assert loaded["tab"] == "findings", "an unknown tab falls back to the default tab"


# ---------------------------------------------------------------------------
# Fleet slots: findings merge sources + overview extras (param-check wiring)
# ---------------------------------------------------------------------------


def _slot_payload(findings=(), tickers=None):
    import json as _json

    meta = {}
    if tickers is not None:
        meta = {"tickers": tickers}
    return _json.dumps({"schema_version": 1, "findings": list(findings), "plan": [], "meta": meta})


def test_param_check_joins_the_fleet_pick(tmp_path, monkeypatch):
    """A fleet param-check run must be pickable as fleet content: today
    FLEET_REPORTS names only findings/audit, so its 54 WARN stay invisible."""
    monkeypatch.setattr(dash.paths, "CACHE_ROOT", tmp_path)
    (tmp_path / "param-check.json").write_text(_slot_payload([{"severity": "WARN"}]), encoding="utf-8")
    names = [name for name, _payload, _mtime, _meta in dash.paths.fleet_report_slots()]
    assert "param-check.json" in names


def test_fleet_slots_skip_scoped_and_corrupt(tmp_path, monkeypatch):
    """Scoped slots never present as the fleet; undecodable files degrade
    to the older good slot instead of crashing the pick."""
    monkeypatch.setattr(dash.paths, "CACHE_ROOT", tmp_path)
    (tmp_path / "audit.json").write_text(_slot_payload([{"severity": "FAIL"}]), encoding="utf-8")
    (tmp_path / "param-check.scoped.json").write_text(
        _slot_payload([{"severity": "WARN"}], tickers="AAA"), encoding="utf-8"
    )
    (tmp_path / "findings.json").write_text("{not json", encoding="utf-8")
    names = [name for name, _payload, _mtime, _meta in dash.paths.fleet_report_slots()]
    assert "audit.json" in names
    assert "param-check.scoped.json" not in names
    assert "findings.json" not in names


def test_extra_slots_decode_guarded(tmp_path, monkeypatch):
    """ports/cross-check slots decode for the overview ledger; a corrupt
    file drops out instead of breaking refresh."""
    import json as _json

    monkeypatch.setattr(dash.paths, "CACHE_ROOT", tmp_path)
    (tmp_path / "ports.json").write_text(_json.dumps({"port_collisions": {"8333": ["AAA", "BBB"]}}), encoding="utf-8")
    (tmp_path / "cross-check.json").write_text("{not json", encoding="utf-8")
    extras = dash.paths.fleet_extra_slots()
    assert set(extras) == {"ports.json"}
    assert extras["ports.json"][0]["port_collisions"] == {"8333": ["AAA", "BBB"]}


def test_run_audit_log_file_drops_progress_events(tmp_path, monkeypatch):
    """F5b: the saved log is human — machine events never land in the file."""
    import sys as _sys

    monkeypatch.setattr(dash.paths, "CACHE_ROOT", tmp_path)
    monkeypatch.setattr(dash.paths, "LOG_STREAM", _sys.stderr)
    log_path = tmp_path / "findings.log"
    cmd = [
        _sys.executable,
        "-c",
        'import sys; print(\'human line\'); print(\'@@PROGRESS@@ {"phase": "probe", "index": 1}\', file=sys.stderr)',
    ]
    dash.runner.run_audit(cmd, log_path)
    text = log_path.read_text(encoding="utf-8")
    assert "human line" in text
    assert "@@PROGRESS@@" not in text


def test_help_names_examples():
    """F12: audit-manifest.py --help ends with copy-paste examples."""
    import audit_manifest as _audit

    text = _audit.build_arg_parser().format_help()
    assert "example" in text.lower(), "help must carry examples"
    assert "--ticker" in text


def test_human_lines_keeps_malformed_progress():
    """Only valid progress events leave the log — a truncated machine
    line is pane-visible evidence, so the file must keep it too."""
    assert dash.runner.human_lines(["@@PROGRESS@@ {truncated", "human"]) == ["@@PROGRESS@@ {truncated", "human"]
    assert dash.runner.human_lines(['@@PROGRESS@@ {"phase": "probe"}', "human"]) == ["human"]


def test_audit_command_spawns_unbuffered(tmp_path):
    """D3: the child streams human lines, never bursts."""
    cmd = dash.runner.audit_command(["--ticker", "AAA"], tmp_path / "r.json")
    assert cmd[1] == "-u"


def test_early_closed_stdout_exits_zero_silent():
    """D2: a consumer that stops reading is success, not a crash."""
    import subprocess as _sp

    proc = _sp.Popen([sys.executable, str(DASH_PATH), "list"], stdout=_sp.PIPE, stderr=_sp.PIPE)
    try:
        proc.stdout.read(10)
        proc.stdout.close()
        _, err = proc.communicate(timeout=30)
    finally:
        if proc.poll() is None:
            proc.kill()
    assert proc.returncode == 0
    assert "BrokenPipeError" not in err.decode()


def test_engine_help_is_sectioned():
    """D8: engine help groups flags instead of a flat wall."""
    import audit_manifest as _am

    text = _am.build_arg_parser().format_help().lower()
    for section in ("scope", "probe", "write", "output"):
        assert section in text


def test_usage_names_the_always_zero_verbs():
    """n1: list/report exit 0 is written down, not tribal knowledge."""
    res = run_cli()
    assert "list and report" in res.stderr
    assert "always exit 0" in res.stderr


def test_command_wrap_breaks_on_spaces_only():
    """n2: the log echo folds at token bounds, never mid-path."""
    cmd = [
        "/venv/bin/python",
        "-u",
        "/repo/audit-manifest.py",
        "--report",
        "/cache/audit-manifest/plan-fix.scoped.json",
        "--tickers",
        "AAA,BBB,CCC",
    ]
    lines = dash.runner.wrap_command(cmd, 80)
    assert all(len(line) <= 80 for line in lines)
    assert lines[0].startswith("$ ")
    assert " ".join(line.strip() for line in lines)[2:] == " ".join(cmd)


def test_model_imports_without_textual():
    """P0-A: fleet-data logic lives in a Textual-free module."""
    from dashboard import model

    assert callable(model.merge_fleet_findings)
    assert callable(model.build_coin_rows)


def test_model_merge_newest_row_wins():
    """P0-A: the merge keeps the later slot's row per coin+check."""
    from dashboard.model import merge_fleet_findings

    old = {"coin": "AAA", "category": "fee", "id": "floor", "ver_id": "a--v1", "severity": "WARN", "detail": "old"}
    new = dict(old, severity="FAIL", detail="new")
    rows, summary = merge_fleet_findings(
        [
            ("findings.json", {"findings": [old]}, 100.0, {}),
            ("audit.json", {"findings": [new]}, 200.0, {}),
        ]
    )
    assert len(rows) == 1
    assert rows[0]["detail"] == "new"
    assert summary["findings.json"] == {"total": 1, "shown": 0, "mtime": 100.0}
    assert summary["audit.json"]["shown"] == 1


def test_model_coin_rows_order_worst_first():
    """P0-A: worst band first; worst severity shown per row."""
    from dashboard.model import build_coin_rows

    coins = build_coin_rows(
        [
            {"coin": "BBB", "severity": "WARN", "detail": "w", "versions": None},
            {"coin": "AAA", "severity": "FAIL", "detail": "f", "versions": None},
        ]
    )
    assert [c["coin"] for c in coins] == ["AAA", "BBB"]
    assert coins[0]["severity"] == "FAIL"


def test_model_scope_text_vectors():
    """P0-A: scope line counts live coins, never delisted ones."""
    from dashboard.model import scope_text

    tickable = [{"ticker": "AAA"}, {"ticker": "BBB"}, {"ticker": "CCC"}]
    assert scope_text(None, tickable) is None
    assert scope_text(None, []) == "0 of 0 coins"
    assert scope_text(["AAA"], tickable) == "1 of 3 coins"
    assert scope_text(["AAA", "ZZZ"], tickable) == "1 of 3 coins"
    assert scope_text(["AAA", "BBB", "CCC"], tickable) is None


def test_model_split_scope_vectors():
    """P0-A: narrowed runs name live tickers only."""
    from dashboard.model import split_scope

    assert split_scope(None, {"AAA"}) == (None, False)
    assert split_scope(["AAA", "ZZZ"], {"AAA", "BBB"}) == (["AAA"], True)
    assert split_scope(["AAA", "BBB"], {"AAA", "BBB"}) == (["AAA", "BBB"], False)


def test_model_plan_slot_prefers_scoped(tmp_path):
    """P0-A: a narrowed scope resolves the scoped plan slot."""
    from dashboard.model import resolve_plan_slot

    fleet = tmp_path / "plan-fix.json"
    fleet.write_text('{"plan": []}')
    scoped = tmp_path / "plan-fix.scoped.json"
    scoped.write_text('{"plan": []}')
    tickable = [{"ticker": "AAA"}, {"ticker": "BBB"}]
    path, is_scoped, live = resolve_plan_slot(["AAA"], tickable, tmp_path)
    assert path == scoped
    assert is_scoped is True
    assert live == ["AAA"]
    path, is_scoped, _ = resolve_plan_slot(None, tickable, tmp_path)
    assert path == fleet
    assert is_scoped is False


def test_model_plan_slot_missing_defaults_to_fleet(tmp_path):
    """P0-A: no plan file on disk still resolves a path."""
    from dashboard.model import resolve_plan_slot

    path, is_scoped, _ = resolve_plan_slot(None, [{"ticker": "AAA"}], tmp_path)
    assert path == tmp_path / "plan-fix.json"
    assert is_scoped is False


def test_model_filter_and_subset_agree():
    """P0-A: narrowed views and the apply dialog count the same rows."""
    from dashboard.model import filter_plan_to_scope, scoped_subset_for_apply

    plan = [{"coin": "AAA"}, {"coin": "BBB"}, {"noid": 1}]
    assert filter_plan_to_scope(plan, ["AAA"], scoped=True) == [{"coin": "AAA"}]
    assert filter_plan_to_scope(plan, [], scoped=False) == plan
    assert scoped_subset_for_apply(plan, None, {"AAA"}) == plan
    assert scoped_subset_for_apply(plan, ["AAA", "ZZZ"], {"AAA", "BBB"}) == [{"coin": "AAA"}]


def test_model_probe_pick_prefers_probed():
    """P0-A: the fleet summary comes from a probe slot, not a zeroed one."""
    from dashboard.model import pick_probe_report

    zeroed = ("param-check.json", {"summary": {"repos_total": 0}}, 200.0, {})
    probed = ("audit.json", {"summary": {"repos_total": 41}}, 100.0, {})
    assert pick_probe_report([zeroed, probed])[0] == "audit.json"
    assert pick_probe_report([zeroed])[0] == "param-check.json"
    assert pick_probe_report([]) is None


def test_model_strip_and_finish_lines(tmp_path):
    """P0-A: strip notes name the destination, finish lines the counts."""
    from dashboard.model import _finish_line, _strip_note

    assert _strip_note("ports", "AAA,BBB") == "ports (2 coins) → log"
    assert _strip_note("ports", None) == "ports → overview"
    report = tmp_path / "ports.json"
    report.write_text('{"port_collisions": {"1": []}}')
    assert "1 collision" in _finish_line("ports", None, report)


def test_analyze_verb_reports_to_own_slot():
    """P1: analyze is a real verb with its own report slot."""
    assert "analyze" in dash.VERBS
    opts = dash.default_opts("analyze")
    argv = dash.build_audit_argv(opts, [])
    assert "--local-only" not in argv
    assert "--no-changelog" in argv
    opts2 = dash.default_opts("analyze")
    opts2.local_only = True
    assert "--local-only" in dash.build_audit_argv(opts2, [])
    opts3 = dash.default_opts("analyze")
    opts3.with_changelog = True
    assert "--no-changelog" not in dash.build_audit_argv(opts3, [])
    primary, _, _ = dash.paths.report_paths("analyze", None)
    assert primary.name == "analyze.json"


def test_analyze_slot_merges_like_other_probes():
    """P1: analyze.json rows join the merged findings with provenance."""
    from dashboard.model import merge_fleet_findings

    row = {
        "coin": "AAA",
        "category": "fee",
        "id": "floor",
        "ver_id": "a--v1",
        "severity": "FAIL",
        "detail": "fee below relay floor",
    }
    rows, summary = merge_fleet_findings([("analyze.json", {"findings": [row]}, 300.0, {})])
    assert len(rows) == 1
    assert summary["analyze.json"] == {"total": 1, "shown": 1, "mtime": 300.0}


def test_embedded_sections_fill_missing_extra_slots():
    """P1: fresh probe data covers ports/cross-check with no dedicated run."""
    from dashboard.model import with_embedded_fallback

    payload = {"port_collisions": {"1": []}, "local": {"missing_wallet_conf": []}}
    extras = with_embedded_fallback({}, [("analyze.json", payload, 300.0, {"started_at": 290.0})])
    assert "ports.json" in extras
    assert "cross-check.json" in extras
    assert extras["ports.json"][0]["port_collisions"] == {"1": []}


def test_embedded_fallback_prefers_newer_probe():
    """Two probe reports with embedded sections do not crash the merge."""
    from dashboard.model import with_embedded_fallback

    old = {"port_collisions": {"1": []}, "local": {}}
    new = {"port_collisions": {"2": []}, "local": {}}
    extras = with_embedded_fallback(
        {},
        [
            ("audit.json", old, 100.0, {}),
            ("analyze.json", new, 300.0, {}),
        ],
    )
    assert extras["ports.json"][0]["port_collisions"] == {"2": []}


def test_embedded_fallback_yields_to_dedicated_slots():
    """P1: an explicit ports run is never shadowed by embedded data."""
    from dashboard.model import with_embedded_fallback

    dedicated = ({"port_collisions": {"2": []}}, 400.0, {})
    embedded = {"port_collisions": {"1": []}, "local": {}}
    extras = with_embedded_fallback({"ports.json": dedicated}, [("analyze.json", embedded, 300.0, {})])
    assert extras["ports.json"][0]["port_collisions"] == {"2": []}
    assert "cross-check.json" in extras


def test_scaffold_entries_bypass_scope_filter():
    """P4: staged new-coin rows are proposals, never scope-filtered."""
    from dashboard.model import filter_plan_to_scope, scoped_subset_for_apply

    plan = [
        {"coin": "AAA", "action": "fees"},
        {"coin": "NEW", "action": "scaffold"},
        {"coin": "OLD", "action": "delist"},
    ]
    assert filter_plan_to_scope(plan, ["AAA"], scoped=True) == plan[:2]
    assert scoped_subset_for_apply(plan, ["AAA"], {"AAA", "BBB"}) == plan[:2]


def test_delist_slot_resolves_like_plan_slots(tmp_path):
    """Delist previews resolve newest-first, scoped or fleet."""
    import json as _json

    from dashboard.model import resolve_slot_file

    tickable = [{"ticker": "AAA"}, {"ticker": "BBB"}]
    (tmp_path / "delist.json").write_text(_json.dumps({"plan": []}))
    (tmp_path / "delist.scoped.json").write_text(_json.dumps({"plan": []}))
    path, scoped, live = resolve_slot_file(["AAA"], tickable, tmp_path, "delist.scoped.json", "delist.json")
    assert path == tmp_path / "delist.scoped.json"
    assert scoped is True
    assert live == ["AAA"]
    path, scoped, _ = resolve_slot_file(None, tickable, tmp_path, "delist.scoped.json", "delist.json")
    assert path == tmp_path / "delist.json"
    assert scoped is False


def test_applied_plan_wins_when_newer(tmp_path):
    """The confirmed set rules the Plan tab until a fresher preview lands."""
    import os as _os
    import time as _time

    from dashboard.model import pick_plan_source

    preview = tmp_path / "plan-fix.json"
    preview.write_text("{}")
    applied = tmp_path / "plan-fix.apply.json"
    applied.write_text("{}")
    now = _time.time()
    _os.utime(preview, (now - 60, now - 60))
    assert pick_plan_source(preview, applied) == applied
    _os.utime(applied, (now - 120, now - 120))
    assert pick_plan_source(preview, applied) == preview
    assert pick_plan_source(preview, tmp_path / "missing") == preview
    assert pick_plan_source(None, applied) == applied
    assert pick_plan_source(None, None) is None


def test_apply_plan_envelope_reads_rewritten_plan(tmp_path, monkeypatch):
    """P3: the Apply envelope reports the file the engine rewrote."""
    import json as _json

    monkeypatch.setattr(dash.paths, "CACHE_ROOT", tmp_path)
    monkeypatch.setattr(dash.runner, "run_audit", lambda *a, **k: {"returncode": 0, "duration": 0.1, "lines": []})
    plan = [
        {
            "action": "txindex",
            "file": "wallet-confs/a.conf",
            "key": "txindex",
            "old": None,
            "new": "1",
            "reason": "t",
            "coin": "AAA",
            "ver_id": "a--v1.0",
            "applied": True,
        }
    ]
    target = tmp_path / "plan-fix.json"
    target.write_text(_json.dumps({"schema_version": 1, "plan": plan, "findings": []}))
    opts = dash.default_opts("apply-plan")
    opts.apply_plan = str(target)
    envelope, code = dash.dispatch(opts, [])
    assert code == 0
    assert envelope["plan"][0]["applied"] is True
    assert envelope["verb"] == "apply-plan"


def test_apply_finish_names_next_step(tmp_path):
    """P3: Apply tells the operator what the tool cannot do itself."""
    import json as _json

    from dashboard.model import _finish_line

    report = tmp_path / "apply-plan.json"
    report.write_text(_json.dumps({"plan": [{"action": "txindex", "file": "f", "key": "k", "severity": "FAIL"}]}))
    line = _finish_line("apply-plan", None, report)
    assert "Plan tab" in line
    assert "git diff" in line


def test_apply_finish_counts_refusals(tmp_path):
    """A partial apply reports its refusals, never a clean bill."""
    import json as _json

    from dashboard.model import _finish_line

    report = tmp_path / "apply-plan.json"
    report.write_text(
        _json.dumps({"plan": [{"action": "txindex", "applied": True}, {"action": "port", "applied": False}]})
    )
    line = _finish_line("apply-plan", None, report)
    assert "applied 1, refused 1" in line


def test_apply_finish_tolerates_list_reports(tmp_path):
    """A bare-list plan file reads like an envelope for counting."""
    import json as _json

    from dashboard.model import _finish_line, staged_open_entries

    report = tmp_path / "apply-plan.json"
    report.write_text(_json.dumps([{"action": "txindex", "applied": True}]))
    assert "applied 1, refused 0" in _finish_line("apply-plan", None, report)
    assert staged_open_entries([{"action": "scaffold", "applied": False}]) != []


def test_with_versions_flag_adds_update_versions():
    """P2: version planning is opt-in, never a silent default."""
    opts = dash.default_opts("plan-fix")
    assert "--update-versions" not in dash.build_audit_argv(opts, [])
    opts.with_versions = True
    assert "--update-versions" in dash.build_audit_argv(opts, [])
    opts.versions_from = "versions.json"
    assert "--versions-from" in dash.build_audit_argv(opts, [])


def test_apply_plan_verb_translates_to_engine_flag(tmp_path):
    """P3: Apply runs the reviewed file, never re-derives."""
    opts = dash.default_opts("apply-plan")
    opts.apply_plan = str(tmp_path / "plan.json")
    argv = dash.build_audit_argv(opts, [])
    assert argv[argv.index("--apply-plan") + 1].endswith("plan.json")
    assert "--ticker" not in argv
    with pytest.raises(dash.DashboardError):
        dash.build_audit_argv(dash.default_opts("apply-plan"), [])


def test_newest_probe_slot_prefers_probe_reports(tmp_path):
    """P2: version input is the newest probe slot, scoped never."""
    import json as _json

    from dashboard.model import newest_probe_slot

    for name in ("param-check.json", "findings.json"):
        (tmp_path / name).write_text(_json.dumps({"repos": {"u": {}}, "meta": {}}))
    assert newest_probe_slot(tmp_path).name == "findings.json"
    (tmp_path / "findings.scoped.json").write_text(_json.dumps({"repos": {"u": {}}}))
    assert newest_probe_slot(tmp_path).name == "findings.json"
    assert newest_probe_slot(tmp_path / "empty") is None


def test_delist_verb_is_preview_only():
    """P5: delist plans removals; only Apply deletes."""
    assert "delist" in dash.VERBS
    assert dash.VERBS["delist"].cost == "local"
    opts = dash.default_opts("delist")
    argv = dash.build_audit_argv(opts, [])
    assert "--delist" in argv
    assert "--dry-run" in argv


def test_verb_partition_covers_every_verb_once():
    """GROUPS stays a true partition as verbs are added."""
    grouped = [n for names in dash.verbs.GROUPS.values() for n in names]
    assert sorted(grouped) == sorted(dash.VERBS)
    assert len(grouped) == len(set(grouped))


def test_model_coin_rows_order_severity_count_coin():
    """Worst band first, busiest coin first inside the band, ticker ties."""
    from dashboard.model import build_coin_rows

    coins = build_coin_rows(
        [
            {"coin": "AAA", "severity": "WARN", "detail": "w", "versions": None},
            {"coin": "MMM", "severity": "WARN", "detail": "w", "versions": None},
            {"coin": "MMM", "severity": "WARN", "detail": "w2", "versions": None},
            {"coin": "MMM", "severity": "WARN", "detail": "w3", "versions": None},
            {"coin": "ZZZ", "severity": "FAIL", "detail": "f", "versions": None},
        ]
    )
    assert [(c["coin"], c["count"]) for c in coins] == [("ZZZ", 1), ("MMM", 3), ("AAA", 1)]


def test_no_write_verb_disables_the_mandatory_hardfork_gate():
    """R9 proof-first for the update-versions gate defect.

    pipeline.py computes changelog_mandatory only inside the changelog
    path, so a --no-changelog verb base makes should_skip_version_bump()
    — the mandatory-hard-fork refusal — a permanent no-op for that verb:
    the dashboard could auto-bump exactly the repos the engine refuses to
    certify. A write verb must leave the gate live.

    Must FAIL before the fix (update-versions carries --no-changelog)
    and PASS after.
    """
    for name in dash.verbs.GROUPS["Write"]:
        base = dash.VERBS[name].base
        assert "--no-changelog" not in base, (
            f"{name} is a write verb: --no-changelog in its base disables "
            "should_skip_version_bump (changelog_mandatory is only computed "
            "when the changelog path runs)"
        )
