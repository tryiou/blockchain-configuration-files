#!/usr/bin/env python3
"""
Proof-first regression tests for write flags implying --param-check.

--write-config, --fee-write and --fix-ports all read `param_results`, which
main() only populates inside `if args.param_check`. Passing any of them
without --param-check therefore did nothing at all: no PARAM CHECK section,
no fixes, no error, and an exit code derived from a probe-only summary. The
failure was silent, so the end-to-end test below is the detector: it must
show the param block running when only a write flag was asked for.
"""

import io
from contextlib import redirect_stdout
from pathlib import Path

import pytest

import audit_manifest as audit

WRITE_FLAGS_NEEDING_PARAM = ("--write-config", "--dust-write", "--fee-write", "--fix-ports")


def _args(*argv: str):
    return audit.build_arg_parser().parse_args(list(argv))


def _empty_repo(tmp_path: Path) -> Path:
    """A repo shaped like the real one but with no coins, so nothing probes."""
    (tmp_path / "wallet-confs").mkdir()
    (tmp_path / "xbridge-confs").mkdir()
    (tmp_path / "autobuild" / "configs").mkdir(parents=True)
    manifest = tmp_path / "manifest-latest.json"
    manifest.write_text("[]", encoding="utf-8")
    return manifest


def _run(argv) -> str:
    buf = io.StringIO()
    with redirect_stdout(buf):
        audit.main(argv)
    return buf.getvalue()


@pytest.mark.parametrize("flag", WRITE_FLAGS_NEEDING_PARAM)
def test_write_flag_turns_on_param_check(flag: str):
    args = _args(flag)
    assert args.param_check is False, "sanity: the flag alone does not set it"
    audit.apply_flag_implications(args)
    assert args.param_check is True, f"{flag} cannot act without --param-check, so it must imply it"


def test_implication_note_names_the_implying_flag(tmp_path: Path):
    manifest = _empty_repo(tmp_path)
    out = _run(["--manifest", str(manifest), "--local-only", "--fix-ports"])
    noted = [ln for ln in out.splitlines() if "implies" in ln]
    assert noted, "the implication must be reported, not silent"
    assert "--fix-ports" in noted[0] and "--param-check" in noted[0], noted[0]


def test_write_flag_runs_param_block_without_explicit_flag(tmp_path: Path):
    manifest = _empty_repo(tmp_path)
    out = _run(["--manifest", str(manifest), "--local-only", "--write-config"])
    assert "=== PARAM CHECK ===" in out, (
        "--write-config without --param-check silently skipped the only step "
        "that produces the input --write-config reads"
    )


def test_fee_write_runs_param_block_without_explicit_flag(tmp_path: Path):
    manifest = _empty_repo(tmp_path)
    out = _run(["--manifest", str(manifest), "--local-only", "--fee-write"])
    assert "=== PARAM CHECK ===" in out, "--fee-write must trigger param-check"


def test_update_versions_does_not_imply_param_check():
    """--update-versions works off the probe, so it must not drag in param-check."""
    args = _args("--update-versions")
    audit.apply_flag_implications(args)
    assert args.param_check is False


def test_read_only_run_stays_out_of_param_check(tmp_path: Path):
    """A plain read-only run must remain exactly what it is today."""
    manifest = _empty_repo(tmp_path)
    out = _run(["--manifest", str(manifest), "--local-only"])
    assert "=== PARAM CHECK ===" not in out
    assert "implies" not in out


def _colliding_repo(tmp_path: Path) -> Path:
    (tmp_path / "wallet-confs").mkdir()
    (tmp_path / "xbridge-confs").mkdir()
    (tmp_path / "autobuild" / "configs").mkdir(parents=True)
    for ticker, port in (("AAA", 1111), ("BBB", 1111)):
        (tmp_path / "wallet-confs" / f"{ticker.lower()}.conf").write_text(
            f"rpcuser=x\nport={port}\nrpcport={port + 1}\n", encoding="utf-8"
        )
        (tmp_path / "xbridge-confs" / f"{ticker.lower()}.conf").write_text(f"Port={port + 1}\n", encoding="utf-8")
    manifest = tmp_path / "manifest-latest.json"
    manifest.write_text(
        __import__("json").dumps(
            [
                {
                    "ticker": t,
                    "ver_id": f"{t.lower()}--v1.0",
                    "versions": ["v1.0.0"],
                    "wallet_conf": f"{t.lower()}.conf",
                    "xbridge_conf": f"{t.lower()}.conf",
                }
                for t in ("AAA", "BBB")
            ]
        ),
        encoding="utf-8",
    )
    return manifest


def test_plan_flow_implies_fix_ports():
    """Port checks are not optional in plan/write flows."""
    for argv in (("--write-config", "--dry-run"), ("--fee-write",)):
        args = _args(*argv)
        assert args.fix_ports is False, "sanity: the flow alone does not set it"
        audit.apply_flag_implications(args)
        assert args.fix_ports is True, f"{argv} plans or writes, so port checks must ride along"


def test_bare_dry_run_stays_cheap():
    """A dry run with nothing to plan implies nothing heavy."""
    args = _args("--dry-run")
    audit.apply_flag_implications(args)
    assert args.fix_ports is False
    assert args.param_check is False


def test_implication_note_names_fix_ports(tmp_path: Path):
    """The port implication is reported, not silent."""
    manifest = _empty_repo(tmp_path)
    out = _run(["--manifest", str(manifest), "--local-only", "--write-config", "--dry-run"])
    noted = [ln for ln in out.splitlines() if "implies --fix-ports" in ln]
    assert noted, "the port implication must be reported, not silent"


def test_dry_run_plan_includes_port_fixes(tmp_path: Path):
    """A preview without --fix-ports still plans the collision moves."""
    import json as _json

    manifest = _colliding_repo(tmp_path)
    report = tmp_path / "out.json"
    out = _run(["--manifest", str(manifest), "--local-only", "--write-config", "--dry-run", "--report", str(report)])
    assert "--fix-ports" in out, "the implication must be visible"
    plan = _json.loads(report.read_text())["plan"]
    assert any(e.get("action") == "port" for e in plan), (
        "colliding ports must be planned even when --fix-ports was not typed"
    )


def test_dry_run_chains_ports_into_param_check(tmp_path: Path):
    """A port implication without param input plans nothing silently."""
    manifest = _empty_repo(tmp_path)
    out = _run(["--manifest", str(manifest), "--local-only", "--write-config", "--dry-run"])
    assert "implies --fix-ports" in out
    assert "implies --param-check" in out


def test_apply_plan_dry_run_touches_nothing(tmp_path: Path):
    """--apply-plan --dry-run previews; conf, plan file and tree stay byte-identical."""
    import json as _json

    manifest = _empty_repo(tmp_path)
    conf = tmp_path / "wallet-confs" / "a.conf"
    conf.write_text("rpcuser=x\n", encoding="utf-8")
    plan = [
        {
            "action": "txindex",
            "file": "wallet-confs/a.conf",
            "key": "txindex",
            "old": None,
            "new": "1",
            "reason": "t",
            "coin": "AAA",
            "applied": False,
        }
    ]
    path = tmp_path / "plan.json"
    path.write_text(_json.dumps(plan), encoding="utf-8")
    plan_before = path.read_text(encoding="utf-8")
    out = _run(["--manifest", str(manifest), "--apply-plan", str(path), "--dry-run"])
    assert conf.read_text(encoding="utf-8") == "rpcuser=x\n", "dry-run must not write the conf"
    assert path.read_text(encoding="utf-8") == plan_before, "dry-run must not rewrite the plan"
    assert "dry-run" in out.lower(), "the preview must announce itself"


def test_main_regenerates_base_j2_exactly_once(tmp_path: Path):
    """Conf, port and version fixes share one j2 regeneration at the end."""
    from unittest import mock as _mock

    import audit_manifest.apply_plan as ap
    from audit_manifest import cli

    manifest = _empty_repo(tmp_path)
    applied = {
        "action": "txindex",
        "file": "wallet-confs/a.conf",
        "key": "txindex",
        "old": None,
        "new": "1",
        "reason": "t",
        "coin": "AAA",
        "applied": True,
    }
    calls = []
    with (
        _mock.patch.object(cli, "apply_conf_fixes", return_value=[applied]),
        _mock.patch.object(cli, "apply_port_fixes", return_value=[]),
        _mock.patch.object(cli, "apply_version_bumps", return_value=[]),
        _mock.patch.object(ap, "regenerate_base_j2", lambda root, tickers, runner=None: calls.append(tickers)),
    ):
        _run(["--manifest", str(manifest), "--local-only", "--write-config"])
    assert calls == [["AAA"]], "exactly one regeneration, with the union of touched coins"


def test_apply_plan_dry_run_reports_every_entry_unapplied(tmp_path: Path):
    """Preview rows carry applied=false even when the plan file was applied before."""
    import json as _json

    manifest = _empty_repo(tmp_path)
    conf = tmp_path / "wallet-confs" / "a.conf"
    conf.write_text("rpcuser=x\n", encoding="utf-8")
    plan = [
        {
            "action": "txindex",
            "file": "wallet-confs/a.conf",
            "key": "txindex",
            "old": None,
            "new": "1",
            "reason": "t",
            "coin": "AAA",
            "applied": True,
        }
    ]
    path = tmp_path / "plan.json"
    path.write_text(_json.dumps(plan), encoding="utf-8")
    report = tmp_path / "report.json"
    _run(["--manifest", str(manifest), "--apply-plan", str(path), "--dry-run", "--report", str(report)])
    entries = _json.loads(report.read_text(encoding="utf-8"))["plan"]
    assert entries and all(e.get("applied") is False for e in entries)
    assert conf.read_text(encoding="utf-8") == "rpcuser=x\n"
