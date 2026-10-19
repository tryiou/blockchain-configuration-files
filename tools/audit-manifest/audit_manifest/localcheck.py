"""Local cross-check: manifest entries vs the conf/base.j2 files on disk.

Pure filesystem validation — no network, no source checkouts. Detects missing
conf pairs, missing base.j2 templates, and orphan conf files that no manifest
entry references.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .checkout import SourceReader
from .model import ManifestCoin
from .reporting import report_line


class ManifestCrossChecker:
    """Validates local configuration files against manifest specifications."""

    @staticmethod
    def base_j2_version_map(ticker: str, repo_root: Path) -> dict[str, Any]:
        try:
            path = repo_root / "autobuild" / "configs" / f"{ticker.lower()}.base.j2"
            txt = SourceReader.slurp(path)
            if txt is None:
                return {}
            data = json.loads(txt)
            entry = data.get(ticker) or data.get(ticker.upper()) or data.get(ticker.lower())
            if entry is None and len(data) == 1:
                entry = next(iter(data.values()))
            if not entry:
                return {}
            vers = entry.get("versions") or {}
            return vers if isinstance(vers, dict) else {}
        except Exception:
            # A malformed or non-object base.j2 has no version map to
            # read; {} means "no local version resolution", never an
            # audit crash over a template file.
            return {}

    @classmethod
    def conf_pair_for_version(cls, coin: ManifestCoin, version: str, repo_root: Path) -> tuple[str, str]:
        m = cls.base_j2_version_map(coin.ticker, repo_root)
        vd = m.get(version)
        if vd and vd.get("wallet_conf") and vd.get("xbridge_conf"):
            return vd.get("wallet_conf"), vd.get("xbridge_conf")
        return coin.wallet_conf, coin.xbridge_conf

    @classmethod
    def local_crosscheck(cls, manifest_path: Path, manifest: list[ManifestCoin]) -> dict[str, Any]:
        repo_root = manifest_path.parent
        wc_dir = repo_root / "wallet-confs"
        xc_dir = repo_root / "xbridge-confs"
        j2_dir = repo_root / "autobuild" / "configs"

        expected: set[str] = set()
        missing_wallet: list[tuple[str, str, str]] = []
        missing_xbridge: list[tuple[str, str, str]] = []
        missing_j2: list[str] = []

        for e in manifest:
            ver_id = e.ver_id
            prefix = ver_id.rsplit("--", 1)[0] if "--" in ver_id else None
            expected.add(ver_id)
            for v in e.versions:
                if prefix:
                    expected.add(f"{prefix}--{v}")
            wc = e.wallet_conf
            xc = e.xbridge_conf
            expected.add(wc.removesuffix(".conf"))
            expected.add(xc.removesuffix(".conf"))

            if wc and not (wc_dir / wc).is_file():
                missing_wallet.append((e.ticker, ver_id, wc))
            if xc and not (xc_dir / xc).is_file():
                missing_xbridge.append((e.ticker, ver_id, xc))

            ticker_j2 = j2_dir / f"{(e.ticker or '').lower()}.base.j2"
            if not ticker_j2.is_file():
                missing_j2.append(e.ticker)

        expected_lower = {s.lower() for s in expected if s}
        orphans: dict[str, list[str]] = {}
        for dname in ("wallet-confs", "xbridge-confs"):
            full = repo_root / dname
            stems = [f.stem for f in full.iterdir() if f.is_file() and f.suffix == ".conf"]
            orphans[dname] = sorted(f for f in stems if f.lower() not in expected_lower and not f.endswith(".conf.tmp"))

        return {
            "missing_wallet_conf": missing_wallet,
            "missing_xbridge_conf": missing_xbridge,
            "missing_base_j2": missing_j2,
            "orphans": orphans,
        }


def crosscheck_local(manifest_path: Path, full_manifest: list[ManifestCoin]) -> dict[str, Any]:
    """Print and return the on-disk conf cross-check. No network involved."""
    report_line("\n=== LOCAL CROSS-CHECK ===")
    local = ManifestCrossChecker.local_crosscheck(manifest_path, full_manifest)
    if not local["missing_wallet_conf"]:
        report_line("  missing wallet_conf: none")
    for ticker, ver_id, wc in local["missing_wallet_conf"]:
        report_line(f"  missing wallet_conf: {ticker} {ver_id} -> {wc}")
    if not local["missing_xbridge_conf"]:
        report_line("  missing xbridge_conf: none")
    for ticker, ver_id, xc in local["missing_xbridge_conf"]:
        report_line(f"  missing xbridge_conf: {ticker} {ver_id} -> {xc}")
    if not local["missing_base_j2"]:
        report_line("  missing base.j2: none")
    for ticker in sorted(set(local["missing_base_j2"])):
        report_line(f"  missing base.j2: {(ticker or '').lower()}.base.j2")
    for dname, orphs in local["orphans"].items():
        if not orphs:
            report_line(f"  orphan {dname}: none")
        else:
            report_line(f"  orphan {dname} (informational, {len(orphs)}):")
            report_line(f"    {', '.join(o + '.conf' for o in orphs)}")
    return local
