#!/usr/bin/env python3
"""Direct tests for ManifestCrossChecker (the LOCAL CROSS-CHECK feature).

The cross-checker had no direct tests: the whole feature was covered only
by whatever integration path happened to reach it, and a wrong-typed
wallet_conf crashed it with an AttributeError (see the manifest-validation
proof-first test). These pin the contract deterministically against a
tmp_path repo.
"""

import json
from pathlib import Path

from audit_manifest.localcheck import ManifestCrossChecker, crosscheck_local
from audit_manifest.model import ManifestCoin


def _repo(tmp_path: Path, *, wallet=True, xbridge=True, j2=True) -> Path:
    (tmp_path / "wallet-confs").mkdir(exist_ok=True)
    (tmp_path / "xbridge-confs").mkdir(exist_ok=True)
    (tmp_path / "autobuild" / "configs").mkdir(parents=True, exist_ok=True)
    if wallet:
        (tmp_path / "wallet-confs" / "aaa--v1.0.conf").write_text("port=9333\n", encoding="utf-8")
    if xbridge:
        (tmp_path / "xbridge-confs" / "aaa--v1.0.conf").write_text("Port=9332\n", encoding="utf-8")
    if j2:
        (tmp_path / "autobuild" / "configs" / "aaa.base.j2").write_text(
            json.dumps({"AAA": {"versions": {}}}), encoding="utf-8"
        )
    manifest = tmp_path / "manifest-latest.json"
    manifest.write_text(json.dumps([]), encoding="utf-8")
    return manifest


def _coin(**kw) -> ManifestCoin:
    base = {
        "ticker": "AAA",
        "ver_id": "aaa--v1.0",
        "versions": ["v1.0.0"],
        "wallet_conf": "aaa--v1.0.conf",
        "xbridge_conf": "aaa--v1.0.conf",
        "repo_url": "https://example.invalid/aaa",
    }
    base.update(kw)
    return ManifestCoin.from_dict(base)


def test_missing_conf_pair_is_reported_per_field(tmp_path: Path):
    manifest = _repo(tmp_path, wallet=False, xbridge=False)
    out = ManifestCrossChecker.local_crosscheck(manifest, [_coin()])
    assert out["missing_wallet_conf"] == [("AAA", "aaa--v1.0", "aaa--v1.0.conf")]
    assert out["missing_xbridge_conf"] == [("AAA", "aaa--v1.0", "aaa--v1.0.conf")]


def test_missing_base_j2_is_reported(tmp_path: Path):
    manifest = _repo(tmp_path, j2=False)
    out = ManifestCrossChecker.local_crosscheck(manifest, [_coin()])
    assert out["missing_base_j2"] == ["AAA"]


def test_missing_base_j2_message_names_the_lowercase_template(tmp_path: Path, capsys):
    """The line must name the template the check actually looked for.

    base.j2 files are lowercase, so printing the ticker names a file that does
    not exist on a case-sensitive filesystem and sends the operator hunting.
    """
    manifest = _repo(tmp_path, j2=False)
    crosscheck_local(manifest, [_coin()])
    out = capsys.readouterr().out
    assert "aaa.base.j2" in out
    assert "AAA.base.j2" not in out


def test_orphan_confs_are_informational(tmp_path: Path):
    manifest = _repo(tmp_path)
    (tmp_path / "wallet-confs" / "ghost--v9.conf").write_text("port=1\n", encoding="utf-8")
    out = ManifestCrossChecker.local_crosscheck(manifest, [_coin()])
    assert out["orphans"]["wallet-confs"] == ["ghost--v9"]
    assert out["orphans"]["xbridge-confs"] == []


def test_version_scoped_conf_pairs_are_expected(tmp_path: Path):
    """A per-version conf pair in base.j2 is not an orphan."""
    manifest = _repo(tmp_path)
    (tmp_path / "autobuild" / "configs" / "aaa.base.j2").write_text(
        json.dumps(
            {"AAA": {"versions": {"v0.9": {"wallet_conf": "aaa--v0.9.conf", "xbridge_conf": "aaa--v0.9.conf"}}}}
        ),
        encoding="utf-8",
    )
    (tmp_path / "wallet-confs" / "aaa--v0.9.conf").write_text("port=1\n", encoding="utf-8")
    (tmp_path / "xbridge-confs" / "aaa--v0.9.conf").write_text("Port=2\n", encoding="utf-8")
    coin = _coin(versions=["v1.0.0", "v0.9"])
    out = ManifestCrossChecker.local_crosscheck(manifest, [coin])
    assert out["orphans"]["wallet-confs"] == []
    assert out["orphans"]["xbridge-confs"] == []
    pair = ManifestCrossChecker.conf_pair_for_version(coin, "v0.9", tmp_path)
    assert pair == ("aaa--v0.9.conf", "aaa--v0.9.conf")


def test_base_j2_version_map_is_empty_for_missing_or_broken_files(tmp_path: Path):
    assert ManifestCrossChecker.base_j2_version_map("AAA", tmp_path) == {}
    (tmp_path / "autobuild" / "configs").mkdir(parents=True)
    (tmp_path / "autobuild" / "configs" / "aaa.base.j2").write_text("{not json", encoding="utf-8")
    assert ManifestCrossChecker.base_j2_version_map("AAA", tmp_path) == {}


def test_crosscheck_local_end_to_end_prints_and_returns(tmp_path: Path, capsys):
    manifest = _repo(tmp_path)
    out = crosscheck_local(manifest, [_coin()])
    printed = capsys.readouterr().out
    assert "=== LOCAL CROSS-CHECK ===" in printed
    assert "missing wallet_conf: none" in printed
    assert out["orphans"]["wallet-confs"] == []
