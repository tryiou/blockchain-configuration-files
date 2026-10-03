#!/usr/bin/env python3
"""Contract tests for dashboard.py's own surface.

Scope is deliberately narrow: these cover what this file promises its
callers — the CLI shape, exit codes, the JSON envelope, the verb table and
the report plumbing. The audit script's behaviour is owned by
test_audit_manifest*.py and is NOT re-tested here; nothing in this module
runs audit-manifest.py.

Standard library + pytest only, so this file runs under the workspace venv
next to the audit suite (Textual is not installed there).
"""
import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest

DASH_PATH = Path(__file__).resolve().parents[1] / "dashboard.py"
spec = importlib.util.spec_from_file_location("audit_manifest_dashboard", str(DASH_PATH))
dash = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = dash
spec.loader.exec_module(dash)


# ---------------------------------------------------------------------------
# Subprocess-level CLI contract
# ---------------------------------------------------------------------------

def run_cli(*args, stdin_null=True):
    return subprocess.run(
        [sys.executable, str(DASH_PATH), *args],
        capture_output=True,
        text=True,
        stdin=subprocess.DEVNULL if stdin_null else None,
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
    envelope = json.loads(res.stdout)          # fails if anything but JSON leaked
    assert envelope["schema_version"] == dash.SCHEMA_VERSION
    assert envelope["verb"] == "list"
    assert envelope["ok"] is True
    assert envelope["counts"]["total"] == len(envelope["entries"])
    assert res.stderr == ""


def test_importing_dashboard_never_imports_textual():
    code = (
        "import importlib.util, sys\n"
        f"spec = importlib.util.spec_from_file_location('d', {str(DASH_PATH)!r})\n"
        "mod = importlib.util.module_from_spec(spec)\n"
        "spec.loader.exec_module(mod)\n"
        "print('textual' in sys.modules)\n"
    )
    res = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True)
    assert res.returncode == 0, res.stderr
    assert res.stdout.strip() == "False", "importing dashboard pulled in Textual"


def test_tui_without_textual_fails_with_an_install_hint(capsys, monkeypatch):
    """run_tui() must explain the missing optional dependency and exit 2.

    The absence is simulated rather than assumed: a ``None`` entry in
    ``sys.modules`` makes any later import of that name raise ImportError,
    so this branch is exercised whether or not Textual happens to be
    installed in the interpreter running the suite.
    """
    monkeypatch.setattr(dash, "LOG_STREAM", sys.stderr)
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
        "plan-fix": ["--local-only", "--param-check", "--dry-run",
                     "--write-config", "--fee-write", "--fix-ports"],
        "apply-fix": ["--local-only", "--param-check",
                      "--write-config", "--fee-write", "--fix-ports"],
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


# ---------------------------------------------------------------------------
# Envelope
# ---------------------------------------------------------------------------

def _envelope(exit_code=1, findings=(), plan=()):
    verb = dash.VERBS["ports"]
    report = {"findings": list(findings), "plan": list(plan), "summary": {},
              "meta": {}, "schema_version": 1}
    return dash.build_envelope(
        verb, report, ["audit-manifest.py"], None, None, None, None, None,
        {"findings": list(findings), "plan": list(plan)}, exit_code,
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
    assert set(env["sources"]) == {"report", "log", "argv", "audit_exit_code",
                                   "duration_seconds", "age_seconds"}


def test_envelope_ok_is_false_only_for_a_failed_run():
    assert _envelope(exit_code=0)["ok"] is True
    assert _envelope(exit_code=1)["ok"] is True
    assert _envelope(exit_code=2)["ok"] is False


# ---------------------------------------------------------------------------
# Report plumbing
# ---------------------------------------------------------------------------

def test_each_verb_gets_its_own_report_file(tmp_path):
    primary, last, log = dash.report_paths("plan-fix", None)
    assert primary.name == "plan-fix.json"
    assert primary.parent == dash.CACHE_ROOT
    assert last == dash.LAST_REPORT
    assert log.name == "plan-fix.log"


def test_an_explicit_report_path_redirects_primary_and_log(tmp_path):
    target = tmp_path / "custom.json"
    primary, last, log = dash.report_paths("findings", str(target))
    assert primary == target
    assert last == dash.LAST_REPORT
    assert log == tmp_path / "custom.log"


def test_meta_sidecar_is_named_after_its_report(tmp_path):
    assert dash.meta_path(tmp_path / "findings.json") == tmp_path / "findings.meta.json"


def test_best_fleet_report_prefers_a_fleet_report_over_the_last_run(tmp_path, monkeypatch):
    import os

    monkeypatch.setattr(dash, "CACHE_ROOT", tmp_path)
    monkeypatch.setattr(dash, "LAST_REPORT", tmp_path / "last-run.json")
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
    monkeypatch.setattr(dash, "LOG_STREAM", sys.stderr)
    monkeypatch.setattr(dash, "LAST_REPORT", tmp_path / "last-run.json")
    monkeypatch.setattr(dash, "LAST_META", tmp_path / "last-run.meta.json")
    assert dash.main(["report"]) == 2
    out = capsys.readouterr()
    assert out.out == ""
    assert "no such report" in out.err
