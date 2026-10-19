"""Fleet port collision registry: detect, reallocate, and persist port moves.

Port facts are collected wallet-wide (P2P/RPC/xbridge, main + [test]) and
reallocation picks the nearest free offset while preserving the P2P→RPC delta
so a coin keeps a predictable pair. Allocation merges namespaces into one
used set: one host, one TCP domain, so a main port never lands on any coin's
test port and p2p never lands on any rpc.
"""

from __future__ import annotations

import argparse
import re
from collections import defaultdict
from pathlib import Path
from typing import Any

from .checkout import SourceReader
from .constants import logger
from .model import ManifestCoin
from .reporting import report_line
from .util import iter_conf_lines, norm_port_value, plan_entry, repo_relative

# Privileged-port floor and ceiling for reassignment candidates. The
# near-source walk keeps a coin's port neighbourhood first and only then
# falls back to the whole range; the pair search stops one short of the
# ceiling so a +1 delta peer still fits.
_PORT_MIN = 1024
_PORT_MAX = 65535
_NEAR_OFFSET_START = 100
_NEAR_OFFSET_LIMIT = 50000
_PAIR_SEARCH_MAX = _PORT_MAX - 1

# The port namespaces the fleet tracks, in report order, and their labels.
PORT_KINDS: tuple[str, ...] = ("p2p", "rpc", "xbridge", "test_p2p", "test_rpc")
PORT_LABEL: dict[str, str] = {
    "p2p": "P2P",
    "rpc": "RPC",
    "xbridge": "XBRIDGE",
    "test_p2p": "TEST-P2P",
    "test_rpc": "TEST-RPC",
}


class PortCollisionManager:
    """Detects and reallocates colliding P2P and RPC ports across the entire fleet."""

    @staticmethod
    def collect_port_collisions(manifest: list[ManifestCoin], repo_root: Path) -> dict[str, dict[int, list[str]]]:
        p2p: dict[int, list[str]] = defaultdict(list)
        rpc: dict[int, list[str]] = defaultdict(list)
        xbp: dict[int, list[str]] = defaultdict(list)
        test_p2p: dict[int, list[str]] = defaultdict(list)
        test_rpc: dict[int, list[str]] = defaultdict(list)

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
    def plan_wallet_key(
        wpath: Path,
        key: str,
        new_val: int,
        repo_root: Path | None = None,
    ) -> tuple[list[dict[str, Any]], str | None]:
        try:
            txt = SourceReader.slurp(wpath)
            if txt is None:
                return [], None
            old_val: str | None = None
            for _lineno, line, in_test in iter_conf_lines(txt):
                if not in_test and re.match(rf"^\s*{re.escape(key)}\s*=", line, flags=re.I):
                    old_val = line.split("=", 1)[1].strip() if "=" in line else None
                    break
            return [
                plan_entry(
                    repo_relative(wpath, repo_root),
                    key,
                    old_val,
                    str(new_val),
                    f"reassign {key} to a free port",
                    "port",
                    applied=False,
                )
            ], None
        except OSError as e:
            logger.error("Failed reading wallet key from %s: %s", wpath, e)
            return [], None

    @staticmethod
    def plan_xbridge_port(
        xpath: Path,
        new_val: int,
        repo_root: Path | None = None,
    ) -> tuple[list[dict[str, Any]], str | None]:
        try:
            txt = SourceReader.slurp(xpath)
            if txt is None:
                return [], None
            old_val: str | None = None
            for line in txt.splitlines():
                if re.match(r"^\s*Port\s*=", line, flags=re.I):
                    old_val = line.split("=", 1)[1].strip() if "=" in line else None
                    break
            return [
                plan_entry(
                    repo_relative(xpath, repo_root),
                    "Port",
                    old_val,
                    str(new_val),
                    "reassign xbridge Port to match the new wallet rpcport",
                    "port",
                    applied=False,
                )
            ], None
        except OSError as e:
            logger.error("Failed reading xbridge Port from %s: %s", xpath, e)
            return [], None

    @staticmethod
    def find_free_single(
        src: int,
        used_p2p: set[int],
        used_rpc: set[int],
        exclude_self: int | None = None,
    ) -> int | None:
        used = used_p2p | used_rpc
        if exclude_self is not None:
            used = set(used) - {exclude_self}
        for off in range(_NEAR_OFFSET_START, _NEAR_OFFSET_LIMIT):
            cand = src + off
            if _PORT_MIN <= cand <= _PORT_MAX and cand not in used:
                return cand
        for cand in range(_NEAR_OFFSET_LIMIT, _PORT_MAX):
            if cand != src and cand not in used:
                return cand
        return None

    @staticmethod
    def find_free_pair(
        src_p2p: int,
        src_rpc: int,
        used_p2p: set[int],
        used_rpc: set[int],
    ) -> tuple[int | None, int | None]:
        used = used_p2p | used_rpc
        delta = src_rpc - src_p2p if src_rpc != src_p2p else 1
        for off in range(_NEAR_OFFSET_START, _NEAR_OFFSET_LIMIT):
            cand_p2p = src_p2p + off
            cand_rpc = cand_p2p + delta
            if (
                _PORT_MIN <= cand_p2p <= _PORT_MAX
                and _PORT_MIN <= cand_rpc <= _PORT_MAX
                and cand_p2p not in used
                and cand_rpc not in used
                and cand_p2p != cand_rpc
            ):
                return cand_p2p, cand_rpc
        for cand_p2p in range(_NEAR_OFFSET_LIMIT, _PAIR_SEARCH_MAX):
            cand_rpc = cand_p2p + delta
            if cand_rpc <= _PORT_MAX and cand_p2p not in used and cand_rpc not in used and cand_p2p != cand_rpc:
                return cand_p2p, cand_rpc
        return None, None


def collect_port_matrix(
    args: argparse.Namespace,
    full_manifest: list[ManifestCoin],
    repo_root: Path,
) -> tuple[dict[str, Any], dict[str, Any]]:
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
            for kind in PORT_KINDS:
                dup = fleet_summary.get(kind)
                if not dup:
                    continue
                label = PORT_LABEL[kind]
                for port in sorted(dup):
                    report_line(f"  {label} {port} : {', '.join(dup[port])}")
        else:
            report_line("\n=== PORT COLLISIONS (fleet) ===  none")
    return fleet_maps, fleet_summary
