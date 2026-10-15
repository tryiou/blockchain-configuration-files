#!/usr/bin/env python3
"""
GitHub release probing must fail closed.

probe_github_release() asks curl for a body plus a trailing HTTP status code.
A transport failure (nonzero return code) or an exit of 0 with no status line
is not an HTTP 200: the probe returns None so callers report the release as
unreachable instead of quoting notes that were never fetched.
"""

import subprocess

import audit_manifest as audit


class _StubRunner:
    def __init__(self, stdout, returncode):
        self._stdout = stdout
        self._rc = returncode

    def run(self, cmd, timeout, retries=2, env_extra=None, cwd=None):
        return subprocess.CompletedProcess(cmd, self._rc, self._stdout, "")


def test_github_release_rejects_transport_failure():
    svc = audit.RemoteProbeService(runner=_StubRunner('{"body": "notes"}', 7))
    assert svc.probe_github_release("https://github.com/o/r", "v1", 10) is None


def test_github_release_rejects_missing_code_line():
    # rc=0 but stdout carries no curl -w code line: fail closed, not 200.
    svc = audit.RemoteProbeService(runner=_StubRunner('{"body": "notes"}', 0))
    assert svc.probe_github_release("https://github.com/o/r", "v1", 10) is None


def test_github_release_accepts_http_200():
    svc = audit.RemoteProbeService(runner=_StubRunner('{"body": "notes"}\n200', 0))
    assert svc.probe_github_release("https://github.com/o/r", "v1", 10) == "notes"


def test_github_release_rate_limit_warns_loudly(caplog):
    """429/403 degrades to None but warns; never silent."""
    import logging

    svc = audit.RemoteProbeService(runner=_StubRunner('{"message": "limited"}\n429', 0))
    with caplog.at_level(logging.WARNING):
        assert svc.probe_github_release("https://github.com/o/r", "v1", 10) is None
    assert any("429" in r.getMessage() or "rate" in r.getMessage().lower() for r in caplog.records)


class _CmdStubRunner:
    """Answers per git subcommand and records every argv it was handed."""

    def __init__(self):
        self.commands = []

    def run(self, cmd, timeout, retries=2, env_extra=None, cwd=None):
        self.commands.append(list(cmd))
        if "init" in cmd or "fetch" in cmd:
            return subprocess.CompletedProcess(cmd, 0, "", "")
        if "for-each-ref" in cmd:
            out = "refs/tags/v1.0.0 2024-01-02T03:04:05+00:00\nrefs/tags/v2.0.0 2024-06-07T08:09:10+00:00\n"
            return subprocess.CompletedProcess(cmd, 0, out, "")
        return subprocess.CompletedProcess(cmd, 1, "", "")


def test_probe_tag_dates_batches_selected_tags_into_one_fetch():
    """The one-fetch batching must build ``+refs/tags/<t>`` refspecs.

    Regression guard: inlining the fetch argument list dropped the refspecs
    assignment, so every batched tag-date probe died with NameError.
    """
    runner = _CmdStubRunner()
    svc = audit.RemoteProbeService(runner=runner)
    dates = svc.probe_tag_dates("https://github.com/o/r", {"v1.0.0", "v2.0.0"}, 10)
    fetch = next(c for c in runner.commands if "fetch" in c)
    assert "+refs/tags/v1.0.0:refs/tags/v1.0.0" in fetch
    assert "+refs/tags/v2.0.0:refs/tags/v2.0.0" in fetch
    assert dates == {
        "v1.0.0": "2024-01-02T03:04:05+00:00",
        "v2.0.0": "2024-06-07T08:09:10+00:00",
    }
