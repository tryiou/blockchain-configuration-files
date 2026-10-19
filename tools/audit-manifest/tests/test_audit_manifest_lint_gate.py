#!/usr/bin/env python3
"""The lint gate this suite ships must actually gate.

``ruff.toml`` selects a strict rule set and declares a mccabe complexity
budget. A selector typo — ``C4`` (flake8-comprehensions) where ``C90``
(mccabe) was meant — leaves the budget inert: ``ruff check`` reports
"All checks passed" while ``[lint.mccabe] max-complexity`` never fires.
These tests run the same ruff the suite runs and pin all three halves:
the shipped config is green over the tool source, its complexity budget
is reachable by a function that busts it, and the tree stays
``ruff format`` clean.
"""

import importlib.util
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

TOOL_DIR = Path(__file__).resolve().parents[1]
REPO_ROOT = TOOL_DIR.parents[1]

_SKIP_WITHOUT_RUFF = pytest.mark.skipif(
    importlib.util.find_spec("ruff") is None, reason="ruff not installed in this environment"
)

_SKIP_WITHOUT_MYPY = pytest.mark.skipif(
    importlib.util.find_spec("mypy") is None, reason="mypy not installed in this environment"
)

# The dashboard's Textual screens declare attributes the framework sets
# after construction (App.state, widget .value, action_* handlers), which
# mypy cannot see from the annotations alone. Those findings are the
# documented baseline: the engine types clean, and any dashboard finding
# OUTSIDE this set fails the gate. Shrinking the baseline is deliberate.
_TEXTUAL_DYNAMICS_BASELINE = {"dashboard/screens.py": 13}

# One decision point more than the budget ruff.toml declares, so the shipped
# config must flag it by rule code, not by anything about the function body.
_COMPLEXITY_PROBE = """\
def probe(first, second, third, fourth, fifth, sixth, seventh, eighth, ninth, tenth, eleventh):
    if first:
        return 1
    if second:
        return 2
    if third:
        return 3
    if fourth:
        return 4
    if fifth:
        return 5
    if sixth:
        return 6
    if seventh:
        return 7
    if eighth:
        return 8
    if ninth:
        return 9
    if tenth:
        return 10
    if eleventh:
        return 11
    return 0
"""


def _ruff(*argv: str, cwd: Path) -> "subprocess.CompletedProcess[str]":
    return subprocess.run(
        [sys.executable, "-m", "ruff", "check", *argv],
        check=False,
        capture_output=True,
        text=True,
        cwd=str(cwd),
    )


@_SKIP_WITHOUT_RUFF
def test_shipped_lint_config_is_green():
    proc = _ruff(str(TOOL_DIR.relative_to(REPO_ROOT)), cwd=REPO_ROOT)
    assert proc.returncode == 0, proc.stdout + proc.stderr


@_SKIP_WITHOUT_RUFF
def test_complexity_budget_is_reachable_by_mccabe(tmp_path: Path):
    """The declared mccabe budget must fire on a function that busts it.

    This pins the behaviour, not the selector text: with the shipped config
    applied, a function beyond ``max-complexity`` must be reported as C901.
    The ``C4`` prefix selects flake8-comprehensions instead and would leave
    the budget inert while everything else stayed green.
    """
    shutil.copy(TOOL_DIR / "ruff.toml", tmp_path / "ruff.toml")
    (tmp_path / "_complexity_probe.py").write_text(_COMPLEXITY_PROBE, encoding="utf-8")
    proc = _ruff(str(tmp_path), cwd=tmp_path)
    assert "C901" in proc.stdout, (
        "the shipped ruff.toml did not flag a function beyond its mccabe budget; "
        "the complexity rule is selected by the C90 prefix, not C4\n" + proc.stdout
    )


@_SKIP_WITHOUT_RUFF
def test_source_is_ruff_format_clean():
    """The suite is standardized by `ruff format`; drift must fail here, not in review."""
    proc = subprocess.run(
        [sys.executable, "-m", "ruff", "format", "--check", str(TOOL_DIR.relative_to(REPO_ROOT))],
        check=False,
        capture_output=True,
        text=True,
        cwd=str(REPO_ROOT),
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr


def _mypy(*targets: str) -> "subprocess.CompletedProcess[str]":
    return subprocess.run(
        [sys.executable, "-m", "mypy", *targets],
        check=False,
        capture_output=True,
        text=True,
        cwd=str(TOOL_DIR),
    )


@_SKIP_WITHOUT_MYPY
def test_engine_type_checks_clean():
    """audit_manifest/ must pass mypy with zero findings.

    The engine carries the fund-loss math and every conf/manifest write, so
    its annotations are load-bearing: a wrong return type, a mis-typed call
    or an unguarded Optional must be visible here, not only in review.
    """
    proc = _mypy("audit_manifest")
    assert proc.returncode == 0, proc.stdout + proc.stderr


@_SKIP_WITHOUT_MYPY
def test_dashboard_stays_at_the_documented_mypy_baseline():
    """Dashboard findings may only be the Textual-dynamics class, counted.

    A new finding moves the per-file counts and fails here, so the
    baseline shrinks only by deliberate edit — never by a regression
    quietly replacing a known one.
    """
    proc = _mypy("dashboard")
    counts: dict[str, int] = {}
    for line in proc.stdout.splitlines():
        if ": error:" in line:
            path = line.split(":", 1)[0]
            counts[path] = counts.get(path, 0) + 1
    assert counts == _TEXTUAL_DYNAMICS_BASELINE, (
        "dashboard mypy findings drifted from the documented Textual-dynamics baseline "
        f"{_TEXTUAL_DYNAMICS_BASELINE} (got {counts}); fix the new findings or update the "
        "baseline deliberately\n" + proc.stdout
    )
