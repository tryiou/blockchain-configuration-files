#!/usr/bin/env python3
"""Manifest entries are validated at load: exit 2, never a traceback.

`from_dict` is total by construction (defaults + `list(...)`), so
wrong-typed fields used to sail through loading and crash deep in the
run — `c.ticker.upper()` on an int with `--ticker`, `parse_version`
on non-string versions. A corrupt manifest is an operator error and
must read as one: which entry, which field, exit code 2.

Validation fires at load, so every verb (and the dashboard paths that
spawn them) is covered; healthy manifests are untouched.
"""

import io
import json
from contextlib import redirect_stdout
from pathlib import Path

import audit_manifest as audit


def _manifest(tmp_path: Path, entry: dict) -> Path:
    (tmp_path / "wallet-confs").mkdir(exist_ok=True)
    (tmp_path / "xbridge-confs").mkdir(exist_ok=True)
    (tmp_path / "autobuild" / "configs").mkdir(parents=True, exist_ok=True)
    (tmp_path / "wallet-confs" / "aaa.conf").write_text("port=9333\n", encoding="utf-8")
    (tmp_path / "xbridge-confs" / "aaa.conf").write_text("Port=9332\n", encoding="utf-8")
    path = tmp_path / "manifest-latest.json"
    path.write_text(json.dumps([entry]), encoding="utf-8")
    return path


def _base_entry(**overrides) -> dict:
    entry = {
        "ticker": "AAA",
        "ver_id": "aaa--v1",
        "versions": [],
        "wallet_conf": "aaa.conf",
        "xbridge_conf": "aaa.conf",
        "repo_url": "https://example.invalid/aaa",
    }
    entry.update(overrides)
    return entry


def _run(argv, tmp_path: Path):
    buf = io.StringIO()
    with redirect_stdout(buf):
        code = audit.main(argv)
    return code, buf.getvalue()


def test_a_non_string_ticker_is_exit_2_not_traceback(tmp_path: Path, capsys):
    manifest = _manifest(tmp_path, _base_entry(ticker=123))
    code, _ = _run(
        [
            "--manifest",
            str(manifest),
            "--local-only",
            "--param-check",
            "--ticker",
            "AAA",
        ],
        tmp_path,
    )
    err = capsys.readouterr().err
    assert code == 2
    assert "Traceback" not in err, "a corrupt manifest must read as an error"
    assert "ticker" in _.lower(), "the error must name the bad field"


def test_string_versions_are_exit_2_not_traceback(tmp_path: Path, capsys):
    manifest = _manifest(tmp_path, _base_entry(versions="v1.0.0"))
    code, _ = _run(["--manifest", str(manifest), "--local-only", "--param-check"], tmp_path)
    err = capsys.readouterr().err
    assert code == 2
    assert "Traceback" not in err


def test_non_string_version_elements_are_exit_2_not_traceback(tmp_path: Path, capsys):
    manifest = _manifest(tmp_path, _base_entry(versions=["v1.0.0", None]))
    code, _ = _run(["--manifest", str(manifest), "--local-only", "--param-check"], tmp_path)
    err = capsys.readouterr().err
    assert code == 2
    assert "Traceback" not in err


def test_a_healthy_manifest_still_loads(tmp_path: Path, capsys):
    manifest = _manifest(tmp_path, _base_entry())
    code, _ = _run(["--manifest", str(manifest), "--local-only", "--param-check"], tmp_path)
    assert code in (0, 1), "validation must not reject healthy manifests"
    assert "Traceback" not in capsys.readouterr().err


def test_missing_conf_dirs_are_exit_2_not_traceback(tmp_path: Path, capsys):
    path = tmp_path / "manifest-latest.json"
    path.write_text(json.dumps([_base_entry()]), encoding="utf-8")
    code, out = _run(["--manifest", str(path), "--local-only", "--param-check"], tmp_path)
    err = capsys.readouterr().err
    assert code == 2, "a --manifest outside the repo root is a usage error"
    assert "Traceback" not in err, "the run must fail as an error, not a crash"
    assert "wallet-confs" in out, "the error must name what is missing"


def test_non_string_conf_fields_are_exit_2_not_traceback(tmp_path: Path, capsys):
    """R9 proof-first for the partial-validation bug.

    load_manifest only type-checked `ticker` and `versions`; every other
    string field reached ManifestCoin.from_dict unchecked, so a wrong-typed
    wallet_conf crashed the LOCAL CROSS-CHECK with
    AttributeError: 'int' object has no attribute 'removesuffix'
    (localcheck.py) instead of the documented exit 2 with a named field.
    Same for repo_url (probe.py url.rstrip) and ver_id.

    This test must FAIL before the fix (AttributeError traceback, exit 1)
    and PASS after (exit 2, field named, no traceback).
    """
    for field, bad in [
        ("wallet_conf", 123),
        ("xbridge_conf", None),
        ("repo_url", ["x"]),
        ("ver_id", 7),
        ("daemon_family", 5),
        ("dir_name_linux", {}),
    ]:
        manifest = _manifest(tmp_path, _base_entry(**{field: bad}))
        code, out = _run(["--manifest", str(manifest), "--local-only"], tmp_path)
        err = capsys.readouterr().err
        assert code == 2, f"{field}={bad!r} must be an operator error (exit 2), got {code}"
        assert "Traceback" not in err, f"{field}={bad!r} must not crash with a traceback"
        assert field in (out + err), f"the error must name the bad field: {field}"
