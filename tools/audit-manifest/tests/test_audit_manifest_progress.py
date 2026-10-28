#!/usr/bin/env python3
"""``@@PROGRESS@@`` machine events on stderr — format and seam wiring.

Stdout is the human report; stderr carries one prefixed JSON object per
line for watchers. Contract pinned here:

* ``emit`` writes exactly one parseable JSON line per event to stderr and
  NEVER touches stdout — the A/B byte-compare depends on that;
* keys are exactly ``phase,index,total,ticker,tag,verb,ts``; ``verb`` comes
  from ``AUDIT_VERB`` (set by the dashboard on spawn, ``null``
  standalone);
* ``parse`` is total: ordinary lines, truncated JSON, and non-object JSON
  return ``None`` instead of raising;
* every orchestration seam emits: probe (per repo), param-check (per coin),
  conf-fixes (per conf file), scaffold (per stage).

Fixtures are local: fake probe service, fake audit engine, local ``git
init`` origin — zero network, zero writes outside ``tmp_path``.
"""

import argparse
import io
import json
import os
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import audit_manifest as audit
import audit_manifest.checkout as checkout_mod
import audit_manifest.pipeline as pipeline_mod
from audit_manifest.fixes import apply_conf_fixes
from audit_manifest.model import FeePolicy, RepoStatus
from audit_manifest.probe import SystemCommandRunner
from audit_manifest.progress import PREFIX, emit, parse

# ---------------------------------------------------------------------------
# Harness
# ---------------------------------------------------------------------------

_GIT_ENV = {
    **os.environ,
    "GIT_AUTHOR_NAME": "fixture",
    "GIT_AUTHOR_EMAIL": "fixture@example.invalid",
    "GIT_COMMITTER_NAME": "fixture",
    "GIT_COMMITTER_EMAIL": "fixture@example.invalid",
    # Neutralize the host's git config so the suite is hermetic even on a
    # machine with commit.gpgsign, status.showUntrackedFiles, templates …
    "GIT_CONFIG_GLOBAL": "/dev/null",
    "GIT_CONFIG_SYSTEM": "/dev/null",
    "GIT_CONFIG_NOSYSTEM": "1",
}


def _git(*args: str, cwd: str = "") -> subprocess.CompletedProcess:
    proc = subprocess.run(
        ["git", *args],
        cwd=cwd or None,
        env=_GIT_ENV,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert proc.returncode == 0, f"git {' '.join(args)} failed: {proc.stderr}"
    return proc


def _make_origin(root: Path, *tags: str) -> Path:
    """Local origin repo: one commit per tag, so tags point at real history."""
    origin = root / "origin"
    if not origin.exists():
        _git("init", "-q", str(origin))
    for tag in tags:
        (origin / "README.md").write_text(f"{tag}\n", encoding="utf-8")
        _git("add", "-A", cwd=str(origin))
        _git("commit", "-q", "-m", tag, cwd=str(origin))
        _git("tag", tag, cwd=str(origin))
    return origin


def _events(capsys) -> list:
    """Every ``@@PROGRESS@@`` payload captured on stderr, in order.

    Reads the capture buffer exactly once — call it once per test and keep
    the result.
    """
    err = capsys.readouterr().err
    return [parse(line) for line in err.splitlines() if line.startswith(PREFIX)]


def _payload(line: str) -> dict:
    """The JSON object of a single raw ``@@PROGRESS@@`` line."""
    assert line.startswith(PREFIX), f"not a progress line: {line!r}"
    return json.loads(line[len(PREFIX) :])


# ---------------------------------------------------------------------------
# Unit: format, channels, totality, verb plumbing
# ---------------------------------------------------------------------------


def test_progress_line_is_parseable_json_on_stderr(capsys):
    emit("probe", index=2, total=5, ticker="BTC", tag="v1.0.0")

    captured = capsys.readouterr()
    assert captured.out == "", "stdout is the report channel and must stay empty"
    lines = [ln for ln in captured.err.splitlines() if ln.startswith(PREFIX)]
    assert len(lines) == 1, "exactly one line per event, never a stream"

    payload = _payload(lines[0])
    assert set(payload) == {"phase", "index", "total", "ticker", "tag", "verb", "ts"}
    assert payload["phase"] == "probe"
    assert payload["index"] == 2
    assert payload["total"] == 5
    assert payload["ticker"] == "BTC"
    assert payload["tag"] == "v1.0.0"
    assert payload["verb"] is None, "a standalone run carries no verb"
    assert isinstance(payload["ts"], float)


def test_progress_never_writes_to_stdout(capsys):
    emit("param-check", index=1, total=1, ticker="LTC")

    captured = capsys.readouterr()
    assert captured.out == "", "the A/B byte-compare owns stdout"
    assert captured.err.strip() != "", "the event itself must arrive on stderr"


def test_parse_is_total_on_ordinary_and_garbled_lines():
    assert parse("Probing 41 distinct repos from manifest-latest.json...\n") is None
    assert parse("") is None
    assert parse(f"{PREFIX} {{truncated") is None
    assert parse(f"{PREFIX} [1, 2]") is None, "non-object payloads are not events"
    assert parse(f"{PREFIX} {{}}") == {}
    assert parse(f'{PREFIX} {{"phase": "probe", "index": null}}') == {
        "phase": "probe",
        "index": None,
    }


def test_verb_comes_from_the_audit_verb_env(monkeypatch, capsys):
    monkeypatch.setenv("AUDIT_VERB", "param-check")
    emit("param-check")
    payload = _payload(capsys.readouterr().err.splitlines()[0])
    assert payload["verb"] == "param-check"

    monkeypatch.delenv("AUDIT_VERB")
    emit("probe")
    payload = _payload(capsys.readouterr().err.splitlines()[0])
    assert payload["verb"] is None


# ---------------------------------------------------------------------------
# Seam: probe — one event per distinct repo
# ---------------------------------------------------------------------------


class _DeadProbe:
    """Enough of RemoteProbeService for audit_repos: repo dead, no tags."""

    def probe_redirect(self, url, timeout):
        return None

    def probe_tags(self, url, timeout):
        return (RepoStatus.DEAD, None)


def test_probe_seam_emits_one_event_per_repo(capsys, tmp_path):
    args = argparse.Namespace(timeout=10, top_tags=50, stale_years=6, no_changelog=True, sleep=0)
    manifest = [
        audit.ManifestCoin(
            ticker="AAA", ver_id="aaa--v1.0.0", versions=["v1.0.0"], repo_url="https://example.invalid/aaa/aaa"
        ),
        audit.ManifestCoin(
            ticker="BBB", ver_id="bbb--v1.0.0", versions=["v1.0.0"], repo_url="https://example.invalid/bbb/bbb"
        ),
        # Same repo as AAA: repos are deduplicated before the loop, so this
        # coin must fold into AAA's event, not add a third one.
        audit.ManifestCoin(
            ticker="CCC", ver_id="ccc--v1.0.0", versions=["v1.0.0"], repo_url="https://example.invalid/aaa/aaa"
        ),
    ]

    pipeline_mod.audit_repos(args, manifest, tmp_path / "manifest-latest.json", _DeadProbe())

    probes = [e for e in _events(capsys) if e["phase"] == "probe"]
    assert len(probes) == 2, "one event per distinct repo, not per coin"
    assert [e["index"] for e in probes] == [1, 2]
    assert [e["total"] for e in probes] == [2, 2]
    assert [e["ticker"] for e in probes] == ["AAA,CCC", "BBB"]
    assert all(e["verb"] is None for e in probes)


# ---------------------------------------------------------------------------
# Seam: param-check — one event per coin, entry tag from `versions`
# ---------------------------------------------------------------------------


class _FakeParamEngine:
    """Audit engine stand-in: every coin lands in the skipped branch."""

    def __init__(self, manager=None):
        self.manager = manager

    def audit_coin_all_versions(self, coin, repo_root, timeout, strict=False, fees_only=False):
        return SimpleNamespace(
            tag="v0.0.0",
            mode="skipped-test",
            per_version=[],
            to_dict=lambda: {"mode": "skipped-test", "tag": "v0.0.0"},
        )


def test_param_seam_emits_one_event_per_coin(capsys, tmp_path, monkeypatch):
    monkeypatch.setattr(pipeline_mod, "ParamAuditEngine", _FakeParamEngine)
    args = argparse.Namespace(
        param_check=True,
        strict_per_version=False,
        fees_only=False,
        timeout=10,
        sleep=0,
    )
    manifest = [
        audit.ManifestCoin(ticker="AAA", ver_id="aaa--v1", versions=["v1.0.0", "v1.2.0"]),
        audit.ManifestCoin(ticker="BBB", ver_id="bbb--v1", versions=[]),
    ]
    fleet_maps = {"p2p": {}, "rpc": {}, "xbridge": {}, "test_p2p": {}, "test_rpc": {}}

    result = pipeline_mod.audit_params(
        args,
        manifest,
        tmp_path,
        fleet_maps,
        {},
        SystemCommandRunner(),
    )

    events = [e for e in _events(capsys) if e["phase"] == "param-check"]
    assert len(events) == 2
    assert (events[0]["index"], events[0]["total"]) == (1, 2)
    assert events[0]["ticker"] == "AAA"
    assert events[0]["tag"] == "v1.2.0", "event tag mirrors the engine's entry tag"
    assert events[1]["ticker"] == "BBB"
    assert events[1]["tag"] is None, "a coin with no declared versions has no tag"
    assert set(result) == {"aaa--v1", "bbb--v1"}


# ---------------------------------------------------------------------------
# Seam: conf-fixes — one event per conf file, metadata keys excluded
# ---------------------------------------------------------------------------


def test_conf_fixes_seam_emits_one_event_per_conf_file(capsys, tmp_path):
    args = argparse.Namespace(write_config=True, fee_write=False, dry_run=True)
    manifest = [audit.ManifestCoin(ticker="XXX", ver_id="xxx--v1")]
    param_results = {"_meta": {"checks": []}, "xxx--v1": {"checks": []}}

    plan = apply_conf_fixes(args, manifest, param_results, tmp_path, SystemCommandRunner())

    events = [e for e in _events(capsys) if e["phase"] == "conf-fixes"]
    assert len(events) == 1, "underscore keys are metadata, not conf files"
    assert (events[0]["index"], events[0]["total"], events[0]["ticker"]) == (1, 1, "XXX")
    assert plan == [], "a check-free result must not fake writes"


def test_conf_fixes_seam_skips_keys_without_a_manifest_coin(capsys, tmp_path):
    """Keys no manifest coin answers must not inflate the progress total.

    A manifest edited mid-run can leave a param_results key unmatched;
    skipping it without emitting stalls the strip short of total/total,
    so unmatched keys are dropped before the loop instead.
    """
    args = argparse.Namespace(write_config=True, fee_write=False, dry_run=True)
    manifest = [audit.ManifestCoin(ticker="XXX", ver_id="xxx--v1")]
    param_results = {"GHOST": {"checks": []}, "xxx--v1": {"checks": []}}

    plan = apply_conf_fixes(args, manifest, param_results, tmp_path, SystemCommandRunner())

    events = [e for e in _events(capsys) if e["phase"] == "conf-fixes"]
    assert [(e["index"], e["total"]) for e in events] == [(1, 1)]
    assert plan == []


def test_emit_never_fails_a_run_on_a_broken_stderr(capsys, monkeypatch):
    """Progress is advisory telemetry: a dead stderr must not take down
    the run it announces (the parser side is already total)."""
    import audit_manifest.progress as audit_progress

    closed = io.StringIO()
    closed.close()
    monkeypatch.setattr(sys, "stderr", closed)
    audit_progress.emit("probe", index=1, total=1, ticker="AAA")


# ---------------------------------------------------------------------------
# Seam: scaffold — stage events
# ---------------------------------------------------------------------------


class _ProbeWithTags:
    """probe_tags answerable without the network: one stable tag."""

    def probe_tags(self, url, timeout):
        return (RepoStatus.ALIVE, {"v1.0.0"})


def _scaffold_args(origin: Path, tmp_path: Path, tag) -> argparse.Namespace:
    return argparse.Namespace(
        repo_url=origin.as_uri(),
        scaffold_ticker="TST",
        scaffold_tag=tag,
        scaffold_name=None,
        scaffold_out_dir=str(tmp_path / "out"),
        apply=False,
        dry_run=False,
        timeout=10,
    )


def test_scaffold_stages_emit_progress_events(tmp_path, capsys, monkeypatch):
    """probe/resolve/extract/ports fire on a real (unmodified) run.

    The run ends at the fee-source guard — a README-only fixture origin has
    no relay constants — which is fine: every stage before that guard must
    have reported.
    """
    monkeypatch.setattr(checkout_mod, "CACHE_ROOT", tmp_path / "cache")
    origin = _make_origin(tmp_path, "v1.0.0")
    args = _scaffold_args(origin, tmp_path, tag=None)

    code, result = audit.CoinScaffolder(probe_service=_ProbeWithTags()).run(args, [], tmp_path)

    events = _events(capsys)
    stages = [e["phase"] for e in events]
    assert "scaffold-probe" in stages, "auto-detected tag means the probe stage ran"
    assert "scaffold-resolve" in stages
    assert "scaffold-extract" in stages
    assert "scaffold-ports" in stages
    assert all(e["ticker"] == "TST" for e in events)
    assert code == 1
    assert "fee source unresolvable" in str(result["error"])


def test_scaffold_write_stage_emits_event(tmp_path, capsys, monkeypatch):
    """The final stage reports when the run completes all the way to write."""
    monkeypatch.setattr(checkout_mod, "CACHE_ROOT", tmp_path / "cache")
    origin = _make_origin(tmp_path, "v1.0.0")

    def _fake_extract(self, src_dir, want_test=False):
        return {
            "port": (12345, "fixture"),
            "rpcport": (12346, "fixture"),
            "COIN": (100000000, "fixture"),
            "BlockTime": (60, "fixture"),
            "TxVersion": (1, "fixture"),
            "AddressPrefix": (0, "fixture"),
            "ScriptPrefix": (0, "fixture"),
            "SecretPrefix": (0, "fixture"),
            "relay_rate": (100000, "fixture"),
            "dust_amount": (546, "fixture"),
            "fee_policy": FeePolicy(rounding="floor", mempool="flat"),
        }

    monkeypatch.setattr(audit.CoinScaffolder, "extract_scaffold_params", _fake_extract)
    args = _scaffold_args(origin, tmp_path, tag="v1.0.0")

    code, result = audit.CoinScaffolder().run(args, [], tmp_path)

    stages = [e["phase"] for e in _events(capsys)]
    assert stages == ["scaffold-resolve", "scaffold-extract", "scaffold-ports", "scaffold-write"], (
        "a completed run reports every stage exactly once, in order"
    )
    assert code == 0 and result["error"] is None
