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
