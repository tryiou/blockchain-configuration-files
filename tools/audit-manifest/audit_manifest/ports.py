"""Fleet port collision registry: detect, reallocate, and persist port moves.

Port facts are collected wallet-wide (P2P/RPC/xbridge, main + [test]) and
reallocation picks the nearest free offset while preserving the P2P→RPC delta
so a coin keeps a predictable pair.
"""

from __future__ import annotations

import argparse
import re
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from .checkout import SourceReader
from .constants import logger
from .model import ManifestCoin
from .reporting import report_line
from .util import norm_port_value, plan_entry, repo_relative


class PortCollisionManager:
    """Detects and reallocates colliding P2P and RPC ports across the entire fleet."""

    @staticmethod
    def collect_port_collisions(manifest: List[ManifestCoin], repo_root: Path) -> Dict[str, Dict[int, List[str]]]:
        p2p: Dict[int, List[str]] = defaultdict(list)
        rpc: Dict[int, List[str]] = defaultdict(list)
        xbp: Dict[int, List[str]] = defaultdict(list)
        test_p2p: Dict[int, List[str]] = defaultdict(list)
        test_rpc: Dict[int, List[str]] = defaultdict(list)

        for coin in manifest:
            ticker = coin.ticker or "?"
            wpath = repo_root / "wallet-confs" / coin.wallet_conf
            secs = SourceReader.parse_conf_sections(wpath)
            top = secs.get("", {})
            test_sec = secs.get("test", {})

            for key, mp in (("port", p2p), ("rpcport", rpc)):
                raw = top.get(key, "")
                v = norm_port_value(raw)
                if v.isdigit():
                    mp[int(v)].append(ticker)

            xpath = repo_root / "xbridge-confs" / coin.xbridge_conf
            xc = SourceReader.parse_conf(xpath)
            xv = norm_port_value(xc.get("Port", ""))
            if xv.isdigit():
                xbp[int(xv)].append(ticker)

            for key, mp in (("port", test_p2p), ("rpcport", test_rpc)):
                raw = test_sec.get(key, "") if test_sec else ""
                v = norm_port_value(raw)
                if v and v.isdigit():
                    mp[int(v)].append(ticker)

        return {
            "p2p": dict(p2p),
            "rpc": dict(rpc),
            "xbridge": dict(xbp),
            "test_p2p": dict(test_p2p),
            "test_rpc": dict(test_rpc),
        }

    @staticmethod
    def write_wallet_key(
        wpath: Path,
        key: str,
        new_val: int,
        dry_run: bool = False,
        repo_root: Optional[Path] = None,
    ) -> Dict[str, Any]:
        try:
            txt = SourceReader.slurp(wpath)
            if txt is None:
                return {}
            lines = txt.splitlines()
            out: List[str] = []
            in_test = False
            replaced = False
            old_val: Optional[str] = None
            for line in lines:
                stripped = line.strip()
                if stripped.lower().startswith("[test]"):
                    in_test = True
                elif stripped.startswith("[") and stripped.endswith("]"):
                    in_test = False
                if not in_test and not replaced and re.match(rf"^\s*{re.escape(key)}\s*=", line, flags=re.I):
                    old_val = line.split("=", 1)[1].strip() if "=" in line else None
                    out.append(f"{key}={new_val}")
                    replaced = True
                else:
                    out.append(line)
            if not replaced:
                out.append(f"{key}={new_val}")
            if not dry_run:
                wpath.write_text("\n".join(out) + "\n", encoding="utf-8")
            return plan_entry(
                repo_relative(wpath, repo_root), key, old_val, str(new_val),
                f"reassign {key} to a free port",
                "port", applied=not dry_run,
            )
        except OSError as e:
            logger.error("Failed writing wallet key to %s: %s", wpath, e)
            return {}

    @staticmethod
    def write_xbridge_port(
        xpath: Path,
        new_val: int,
        dry_run: bool = False,
        repo_root: Optional[Path] = None,
    ) -> Dict[str, Any]:
        try:
            txt = SourceReader.slurp(xpath)
            if txt is None:
                return {}
            lines = txt.splitlines()
            out: List[str] = []
            replaced = False
            old_val: Optional[str] = None
            for line in lines:
                if not replaced and re.match(r"^\s*Port\s*=", line, flags=re.I):
                    old_val = line.split("=", 1)[1].strip() if "=" in line else None
                    out.append(f"Port={new_val}")
                    replaced = True
                else:
                    out.append(line)
            if not replaced:
                out.append(f"Port={new_val}")
            if not dry_run:
                xpath.write_text("\n".join(out) + "\n", encoding="utf-8")
            return plan_entry(
                repo_relative(xpath, repo_root), "Port", old_val, str(new_val),
                "reassign xbridge Port to match the new wallet rpcport",
                "port", applied=not dry_run,
            )
        except OSError as e:
            logger.error("Failed writing xbridge port to %s: %s", xpath, e)
            return {}

    @staticmethod
    def find_free_single(src: int, used_p2p: Set[int], used_rpc: Set[int], exclude_self: Optional[int] = None) -> Optional[int]:
        used = used_p2p | used_rpc
        if exclude_self is not None:
            used = set(used) - {exclude_self}
        for off in range(100, 50000):
            cand = src + off
            if 1024 <= cand <= 65535 and cand not in used:
                return cand
        for cand in range(50000, 65535):
            if cand not in used:
                return cand
        return None

    @staticmethod
    def find_free_pair(src_p2p: int, src_rpc: int, used_p2p: Set[int], used_rpc: Set[int]) -> Tuple[Optional[int], Optional[int]]:
        used = used_p2p | used_rpc
        delta = src_rpc - src_p2p if src_rpc != src_p2p else 1
        for off in range(100, 50000):
            cand_p2p = src_p2p + off
            cand_rpc = cand_p2p + delta
            if 1024 <= cand_p2p <= 65535 and 1024 <= cand_rpc <= 65535:
                if cand_p2p not in used and cand_rpc not in used and cand_p2p != cand_rpc:
                    return cand_p2p, cand_rpc
        for cand_p2p in range(50000, 65534):
            cand_rpc = cand_p2p + delta
            if cand_rpc <= 65535 and cand_p2p not in used and cand_rpc not in used and cand_p2p != cand_rpc:
                return cand_p2p, cand_rpc
        return None, None


def collect_port_matrix(
    args: argparse.Namespace,
    full_manifest: List[ManifestCoin],
    repo_root: Path,
) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """Build the fleet port-collision matrix and print the fleet report.

    Always computed for the full fleet, never filtered by --ticker, so a
    filtered run still sees collisions against coins it did not select.
    """
    # Fleet Port Collision Matrix (always full fleet, report-only, like v1)
    fleet_maps = PortCollisionManager.collect_port_collisions(full_manifest, repo_root)
    fleet_summary = {k: {p: sorted(ts) for p, ts in v.items() if len(ts) > 1} for k, v in fleet_maps.items()}
    fleet_summary = {k: v for k, v in fleet_summary.items() if v}

    if not args.param_check:
        if fleet_summary:
            report_line("\n=== PORT COLLISIONS (fleet) ===")
            for kind in ("p2p", "rpc", "xbridge", "test_p2p", "test_rpc"):
                dup = fleet_summary.get(kind)
                if not dup:
                    continue
                label = {"p2p": "P2P", "rpc": "RPC", "xbridge": "XBRIDGE", "test_p2p": "TEST-P2P", "test_rpc": "TEST-RPC"}[kind]
                for port in sorted(dup):
                    report_line(f"  {label} {port} : {', '.join(dup[port])}")
        else:
            report_line("\n=== PORT COLLISIONS (fleet) ===  none")
    return fleet_maps, fleet_summary
