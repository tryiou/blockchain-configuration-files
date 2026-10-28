#!/usr/bin/env python3
"""The DustAmount write path: flag scoping and the conf/template contract.

``DustAmount`` lives in two files that render into each other: the conf the
daemons read, and the ``autobuild/configs/<ticker>.base.j2`` template that
rewrites that conf on the next fleet render. A write that lands in one and not
the other is silently reverted later, so the write path has to prove both.
These cases pin the flag scoping (a dust run must not reassign ports) and the
half-write failures that used to be log lines.
"""

import argparse
import json

import pytest

from audit_manifest import apply_plan as ap
from audit_manifest import fixes
from audit_manifest.apply_plan import RegenerationError, apply_entries
from audit_manifest.fixes import ConfigAutoFixer
from audit_manifest.inspectors.dust import DustExpectation, DustKind
from audit_manifest.model import ManifestCoin


def _coin() -> ManifestCoin:
    return ManifestCoin(
        ticker="AAA",
        ver_id="aaa--v1.0",
        wallet_conf="aaa--v1.0.conf",
        xbridge_conf="aaa--v1.0.conf",
        versions=["v1.0.0"],
    )


@pytest.fixture
def repo(tmp_path):
    (tmp_path / "wallet-confs").mkdir()
    (tmp_path / "xbridge-confs").mkdir()
    (tmp_path / "autobuild" / "configs").mkdir(parents=True)
    (tmp_path / "autobuild" / "utils").mkdir(parents=True)
    (tmp_path / "autobuild" / "utils" / "create-j2-confs.py").write_text("", encoding="utf-8")
    (tmp_path / "wallet-confs" / "aaa--v1.0.conf").write_text("rpcuser=x\n", encoding="utf-8")
    (tmp_path / "xbridge-confs" / "aaa--v1.0.conf").write_text("rpcuser=x\nDustAmount=0\nPort=9999\n", encoding="utf-8")
    (tmp_path / "autobuild" / "configs" / "aaa.base.j2").write_text(
        json.dumps({"AAA": {"DustAmount": "0", "Port": "9999"}}), encoding="utf-8"
    )
    return tmp_path


def _pin_dust(monkeypatch, value: int) -> None:
    monkeypatch.setattr(
        ConfigAutoFixer,
        "_resolve_source_for_fix",
        staticmethod(lambda coin, label: __import__("pathlib").Path("/nonexistent")),
    )
    monkeypatch.setattr(fixes, "fee_constants_for_coin", lambda coin, src: (1000, "ev", 3000, "dev"))
    monkeypatch.setattr(fixes, "fee_policy_for_coin", lambda coin, src: None)
    monkeypatch.setattr(
        fixes,
        "expectation",
        lambda **_kw: DustExpectation(value, "src/policy/policy.h:1 -> P2PKH", DustKind.P2PKH),
    )


def _results(fixable: str = "dust", check_id: str = "DUST") -> dict:
    return {"aaa--v1.0": {"checks": [{"id": check_id, "status": "WARN", "fixable": fixable, "detail": "d"}]}}


# --------------------------------------------------------------------------
# Flag scoping
# --------------------------------------------------------------------------


def test_dust_write_plans_only_dust(repo, monkeypatch):
    """--dust-write must never drag txindex or port rewrites into the plan."""
    _pin_dust(monkeypatch, 546)
    args = argparse.Namespace(write_config=False, dust_write=True, fee_write=False, dry_run=True)
    plan = fixes.apply_conf_fixes(args, [_coin()], _results(), repo, None)
    assert [e["action"] for e in plan] == ["dust"], plan


def test_write_config_still_plans_dust(repo, monkeypatch):
    """--write-config keeps ownership of the conf-hygiene kinds, dust included."""
    _pin_dust(monkeypatch, 546)
    args = argparse.Namespace(write_config=True, dust_write=False, fee_write=False, dry_run=True)
    plan = fixes.apply_conf_fixes(args, [_coin()], _results(), repo, None)
    assert [e["action"] for e in plan] == ["dust"], plan


def test_fee_write_never_plans_dust(repo, monkeypatch):
    _pin_dust(monkeypatch, 546)
    args = argparse.Namespace(write_config=False, dust_write=False, fee_write=True, dry_run=True)
    plan = fixes.apply_conf_fixes(args, [_coin()], _results(), repo, None)
    assert plan == []


def test_dust_only_flag_does_not_imply_fix_ports():
    """A dust campaign that silently reassigned fleet ports would be a different change."""
    from audit_manifest.cli import apply_flag_implications

    args = argparse.Namespace(write_config=False, dust_write=True, fee_write=False, fix_ports=False, param_check=False)
    apply_flag_implications(args, emit=lambda *_a, **_k: None)
    assert args.param_check is True
    assert args.fix_ports is False


def test_dust_write_implies_param_check():
    from audit_manifest.cli import apply_flag_implications

    args = argparse.Namespace(write_config=False, dust_write=True, fee_write=False, fix_ports=False, param_check=False)
    apply_flag_implications(args, emit=lambda *_a, **_k: None)
    assert args.param_check is True


# --------------------------------------------------------------------------
# The conf/template contract
# --------------------------------------------------------------------------


class _FailingRunner:
    """A create-j2-confs stand-in that reports a non-zero exit."""

    @staticmethod
    def run(*_a, **_k):
        return _Completed(returncode=1, stderr="boom")


def test_dust_write_lands_in_conf_and_template(repo, monkeypatch):
    """The reviewed value must reach both files in one apply."""
    _pin_dust(monkeypatch, 5460)
    entries, _note = ConfigAutoFixer.plan_configure_dust(repo, _coin())
    out = apply_entries(entries, repo, runner=_Runner(repo, mirrored="5460"))
    assert out[0]["applied"] is True
    assert "DustAmount=5460" in (repo / "xbridge-confs" / "aaa--v1.0.conf").read_text()
    assert json.loads((repo / "autobuild" / "configs" / "aaa.base.j2").read_text())["AAA"]["DustAmount"] == "5460"


def test_a_stale_template_refuses_the_write(repo, monkeypatch):
    """A template that did not pick up the value is a half-applied run, not a success."""
    _pin_dust(monkeypatch, 5460)
    entries, _note = ConfigAutoFixer.plan_configure_dust(repo, _coin())
    with pytest.raises(RegenerationError, match="did not pick up DustAmount=5460"):
        apply_entries(entries, repo, runner=_Runner(repo, mirrored="0"))


def test_a_failed_regeneration_raises_instead_of_warning(repo):
    """The generator's exit code used to be a log line; a half-written tree must fail."""
    with pytest.raises(RegenerationError, match=r"regeneration failed for AAA"):
        ap.regenerate_base_j2(repo, ["AAA"], _FailingRunner())


def test_a_timed_out_regeneration_raises(repo):
    """A runner that reports no result at all is a failure, not a skip."""

    class _TimedOut:
        @staticmethod
        def run(*_a, **_k):
            return None

    with pytest.raises(RegenerationError, match=r"timeout"):
        ap.regenerate_base_j2(repo, ["AAA"], _TimedOut())


def test_a_missing_generator_with_a_template_layer_raises(repo):
    """A repo that has templates but no generator cannot mirror the write."""
    (repo / "autobuild" / "utils" / "create-j2-confs.py").unlink()
    with pytest.raises(RegenerationError, match=r"create-j2-confs\.py missing"):
        ap.regenerate_base_j2(repo, ["AAA"], object())


def test_a_repo_without_a_template_layer_is_a_no_op(tmp_path):
    """A bare conf-only repo has nothing to keep in sync."""
    ap.regenerate_base_j2(tmp_path, ["AAA"], object())


class _Runner:
    """A create-j2-confs stand-in: rewrites the template from the conf value."""

    def __init__(self, repo, mirrored: str) -> None:
        self.repo = repo
        self.mirrored = mirrored

    def run(self, _cmd, **_kwargs):
        (self.repo / "autobuild" / "configs" / "aaa.base.j2").write_text(
            json.dumps({"AAA": {"DustAmount": self.mirrored, "Port": "9999"}}), encoding="utf-8"
        )
        return _Completed()


class _Completed:
    """The subprocess.CompletedProcess shape the runner contract returns."""

    def __init__(self, returncode: int = 0, stdout: str = "", stderr: str = "") -> None:
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def test_scaffold_apply_mirrors_the_conf_into_the_template(repo, monkeypatch):
    """A new coin's conf is not written unless its template carries the same value.

    ``--scaffold --apply`` is a conf write like any other: skipping the
    regeneration would leave the new coin's ``DustAmount`` in a conf that the
    next fleet render silently overwrites from a template that never got it.
    """
    from audit_manifest import scaffold as sc

    runner = _NewCoinRunner(repo)
    calls = []
    monkeypatch.setattr(sc, "apply_entries", _spy_apply_entries(calls, runner))
    (repo / "manifest-latest.json").write_text(
        json.dumps(
            [
                {
                    "ticker": "AAA",
                    "ver_id": "aaa--v1.0",
                    "versions": ["v1.0.0"],
                    "wallet_conf": "aaa--v1.0.conf",
                    "xbridge_conf": "aaa--v1.0.conf",
                }
            ]
        ),
        encoding="utf-8",
    )
    plan = [
        {
            "action": "scaffold",
            "file": "xbridge-confs/new--v1.0.conf",
            "key": "*",
            "old": None,
            "new": "generated",
            "reason": "t",
            "coin": "NEW",
            "ver_id": "new--v1.0",
            "applied": False,
            "contents": "DustAmount=5460\nPort=1\n",
        }
    ]
    args = argparse.Namespace(apply=True, dry_run=False)
    result: dict = {}
    rc = sc.CoinScaffolder(runner=runner)._apply_scaffold(
        args=args,
        plan=plan,
        repo_root=repo,
        ticker="NEW",
        wallet_name="new--v1.0.conf",
        xbridge_name="new--v1.0.conf",
        out_dir=repo,
        result=result,
    )
    assert rc is None, result
    assert calls == [runner], "the scaffold write must hand apply_entries a runner so base.j2 is regenerated"


class _NewCoinRunner:
    """A create-j2-confs stand-in for a brand-new ticker."""

    def __init__(self, repo) -> None:
        self.repo = repo

    def run(self, _cmd, **_kwargs):
        (self.repo / "autobuild" / "configs" / "new.base.j2").write_text(
            json.dumps({"NEW": {"DustAmount": "5460", "Port": "1"}}), encoding="utf-8"
        )
        return _Completed()


def _spy_apply_entries(calls, runner):
    """Record the runner the scaffold passed, then apply the plan for real."""

    def _spy(entries, repo_root, runner_arg=None, **_kwargs):
        calls.append(runner_arg)
        return ap.apply_entries(entries, repo_root, runner_arg if runner_arg is not None else runner)

    return _spy


def test_a_checked_kind_with_no_planner_plans_nothing(repo, monkeypatch):
    """A checker may name a kind the table has no planner for; that is a no-op, not a crash."""
    _pin_dust(monkeypatch, 546)
    args = argparse.Namespace(write_config=True, dust_write=False, fee_write=False, dry_run=True)
    plan = fixes.apply_conf_fixes(args, [_coin()], _results(fixable="not-a-kind"), repo, None)
    assert plan == []


def test_a_broken_resolver_is_not_hidden_as_a_skipped_coin(repo, monkeypatch):
    """An unusable ticker is data; a bug in the resolver is a crash, not a note."""

    def _boom(*_a, **_k):
        raise AttributeError("resolve_for lost an attribute")

    monkeypatch.setattr(fixes.SourceCheckoutManager, "resolve_source", _boom, raising=True)
    with pytest.raises(AttributeError, match="lost an attribute"):
        ConfigAutoFixer._resolve_source_for_fix(_coin(), "FIX-DUST")


def test_fee_write_keeps_its_precedence(repo, monkeypatch):
    """--fee-write still means fee margins only, whatever else is passed."""
    _pin_dust(monkeypatch, 546)
    args = argparse.Namespace(write_config=True, dust_write=True, fee_write=True, dry_run=True)
    plan = fixes.apply_conf_fixes(args, [_coin()], _results(), repo, None)
    assert plan == [], "fee-write must not start planning conf hygiene or dust"
