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

WRITE_FLAGS_NEEDING_PARAM = ("--write-config", "--fee-write", "--fix-ports")


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
    assert args.param_check is True, (
        f"{flag} cannot act without --param-check, so it must imply it"
    )


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
