"""Report payload assembly: findings, the JSON envelope, and its writer.

``build_findings`` flattens every actionable signal into one severity-ordered
array using the two scales the tool already defines (``ActionType`` for repo
state, ``ParamStatus`` for checks) — no third scale is introduced.
"""

from __future__ import annotations

import argparse
import json
from typing import Any, Dict, List, Optional, Tuple

from .model import (
    ACTION_SEVERITY,
    PARAM_STATUS_PRECEDENCE,
    ActionType,
    ManifestCoin,
    ParamStatus,
)
from .reporting import report_line

# findings[] only carries statuses that ask a human to act. PASS/MATCH/SKIP
# stay inside param_check — surfacing them would restate the whole fleet.
FINDING_PARAM_STATUSES: Tuple[ParamStatus, ...] = (
    ParamStatus.FAIL,
    ParamStatus.BROKEN,
    ParamStatus.CONFLICT,
    ParamStatus.DIFFERS,
    ParamStatus.WARN,
    ParamStatus.UNRESOLVED,
)

# Kind -> (stable id, conf template, conf key label). The xbridge namespace is
# its own file; the two [test] namespaces live in the wallet conf's test section.
PORT_FINDING_KINDS: Dict[str, Tuple[str, str, str]] = {
    "p2p": ("P2P-COLLISION", "wallet-confs/{}", "port"),
    "rpc": ("RPC-COLLISION", "wallet-confs/{}", "rpcport"),
    "xbridge": ("XBRIDGE-COLLISION", "xbridge-confs/{}", "Port"),
    "test_p2p": ("TEST-P2P-COLLISION", "wallet-confs/{}", "[test] port"),
    "test_rpc": ("TEST-RPC-COLLISION", "wallet-confs/{}", "[test] rpcport"),
}


def build_findings(
    full_manifest: List[ManifestCoin],
    report_repos: Dict[str, Any],
    local: Dict[str, Any],
    fleet_summary: Dict[str, Any],
    param_results: Optional[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """Flatten every actionable signal into one severity-ordered array.

    Severity values come from the two scales this module already defines —
    ``ActionType`` for repository state and ``ParamStatus`` for checks. Their
    vocabularies do not overlap, so a value names its own scale unambiguously
    and no third scale is introduced. Ordering follows the order this tool
    already prints its sections in (repository state, then local/port/check
    findings), and within each group worst-first by that scale's own table.

    Deliberately non-redundant: one finding per non-OK manifest entry, one per
    local defect, one per colliding port per coin, one per actionable check.
    ``--param-check`` re-derives the same port collisions as ``*-COLLISION``
    checks, so those ids are skipped here rather than reported twice; they
    remain available under ``param_check``.

    ``file``/``line`` are nullable: local and port findings know their conf
    path outright, while check evidence (``src/validation.h:123``, or a conf
    ref via ``_conf_key_line``) lives inside ``detail`` as prose and is left
    there rather than parsed back out.
    """
    findings: List[Dict[str, Any]] = []

    def add(
        severity: str,
        category: str,
        coin: Optional[str],
        ver_id: Optional[str],
        fid: str,
        detail: str,
        file: Optional[str] = None,
        line: Optional[int] = None,
        versions: Optional[Dict[str, Any]] = None,
    ) -> None:
        findings.append({
            "severity": severity,
            "category": category,
            "coin": coin,
            "ver_id": ver_id,
            "id": fid,
            "detail": detail,
            "file": file,
            "line": line,
            # Always present: the versions block for REPO-ACTION findings,
            # null everywhere else (see README — stable key, stable shape).
            "versions": versions,
        })

    # --- repository state: one finding per non-OK manifest entry -------------
    # classify_action already folds dead/moved/unknown, missing tags, newer
    # tags and staleness into a single per-entry action, so the entry itself
    # is the unit. Coins sharing a repo each get their own row because each
    # one needs its own decision.
    for rdata in report_repos.values():
        status = rdata.get("status", "?")
        for entry in rdata.get("entries", []):
            action = entry.get("action")
            if action is None or action == ActionType.OK:
                continue
            bits: List[str] = []
            if entry.get("missing"):
                bits.append("missing tags: " + ", ".join(entry["missing"]))
            if rdata.get("newer_same"):
                bits.append("newer same-series tags: " + ", ".join(rdata["newer_same"]))
            if rdata.get("newer_alt"):
                bits.append("newer alternate-series tags: " + ", ".join(rdata["newer_alt"]))
            if rdata.get("stale"):
                bits.append("no upstream release inside the staleness window")
            if entry.get("changelog_mandatory"):
                quote = entry.get("changelog_quote") or "mandatory hard fork"
                bits.append(f'changelog mandates a hard fork: "{quote}"')
            detail = f"repo {status}" + (": " + "; ".join(bits) if bits else "")
            if entry.get("changelog_mandatory"):
                category = "changelog"
            elif action in (ActionType.DEAD, ActionType.MOVED, ActionType.UNKNOWN):
                category = "liveness"
            else:
                category = "version"
            versions_block: Dict[str, Any] = {
                # List keys are defaulted so the README contract holds even
                # for sparse entries: lists are never null, they are [] when
                # there is nothing to report.
                "declared": entry.get("versions") or [],
                "our_latest": entry.get("our_latest"),
                "remote_latest": rdata.get("remote_latest"),
                "newer_same": rdata.get("newer_same") or [],
                "newer_alt": rdata.get("newer_alt") or [],
                "missing": entry.get("missing") or [],
                "found": entry.get("found") or [],
                "tag_count": rdata.get("tag_count"),
                "conf": entry.get("ver_id"),
            }
            add(
                str(action.value if isinstance(action, ActionType) else action),
                category,
                entry.get("ticker"),
                entry.get("ver_id"),
                "REPO-ACTION",
                detail,
                versions=versions_block,
            )

    # --- local cross-check ---------------------------------------------------
    for ticker, ver_id, wc in local.get("missing_wallet_conf", []):
        add("FAIL", "local", ticker, ver_id, "MISSING-WALLET-CONF",
            f"manifest points at wallet-confs/{wc} but the file does not exist",
            file=f"wallet-confs/{wc}")
    for ticker, ver_id, xc in local.get("missing_xbridge_conf", []):
        add("FAIL", "local", ticker, ver_id, "MISSING-XBRIDGE-CONF",
            f"manifest points at xbridge-confs/{xc} but the file does not exist",
            file=f"xbridge-confs/{xc}")
    for ticker in sorted(set(local.get("missing_base_j2", []))):
        add("WARN", "local", ticker, None, "MISSING-BASE-J2",
            f"autobuild/configs/{ticker}.base.j2 does not exist",
            file=f"autobuild/configs/{ticker}.base.j2")
    for dname, orphs in (local.get("orphans") or {}).items():
        for stem in sorted(set(orphs)):
            add("INFO", "local", None, None, "ORPHAN-CONF",
                f"{dname}/{stem}.conf is not referenced by the manifest "
                f"(informational)", file=f"{dname}/{stem}.conf")

    # --- fleet port matrix ---------------------------------------------------
    # One finding per colliding port per coin so coin/file are exact; the
    # matrix is fleet-wide even when --ticker narrowed the run.
    by_ticker: Dict[str, ManifestCoin] = {}
    for c in full_manifest:
        by_ticker.setdefault(c.ticker or "", c)
    for kind in ("p2p", "rpc", "xbridge", "test_p2p", "test_rpc"):
        fid, conf_tpl, key_label = PORT_FINDING_KINDS[kind]
        for port, tickers in sorted((fleet_summary.get(kind) or {}).items()):
            for t in sorted(tickers):
                coin = by_ticker.get(t)
                conf = conf_tpl.format(coin.wallet_conf) if coin and coin.wallet_conf else None
                others = sorted(x for x in tickers if x != t)
                add(
                    ParamStatus.CONFLICT.value, "port", t,
                    coin.ver_id if coin else None, fid,
                    f"{key_label}={port} is claimed by {', '.join(tickers)}"
                    + (f" (also {', '.join(others)})" if others else ""),
                    file=conf,
                )

    # --- parameter checks ----------------------------------------------------
    by_ver_id: Dict[str, ManifestCoin] = {c.ver_id: c for c in full_manifest if c.ver_id}
    for key, res in (param_results or {}).items():
        if key.startswith("_") or not isinstance(res, dict):
            continue
        coin = by_ver_id.get(key) or by_ticker.get(key)
        for chk in res.get("checks", []):
            cid = chk.get("id", "")
            if cid.endswith("-COLLISION"):
                continue  # already emitted from the fleet matrix above
            try:
                status = ParamStatus(chk.get("status"))
            except ValueError:
                continue
            if status not in FINDING_PARAM_STATUSES:
                continue
            add(
                status.value, "param",
                coin.ticker if coin else None,
                coin.ver_id if coin else None,
                cid, chk.get("detail", ""),
            )

    def _sort_key(f: Dict[str, Any]) -> Tuple[int, int, str, str, str]:
        sev = f["severity"]
        tie = (f["category"], f["coin"] or "", f["id"])
        if sev in ACTION_SEVERITY:  # repository-state group, worst first
            return (0, -ACTION_SEVERITY[ActionType(sev)], *tie)
        try:  # check group, worst first by PARAM_STATUS_PRECEDENCE
            return (1, -PARAM_STATUS_PRECEDENCE.index(ParamStatus(sev)), *tie)
        except ValueError:
            return (2, 0, *tie)

    findings.sort(key=_sort_key)
    return findings


def build_report(
    full_manifest: List[ManifestCoin],
    args: argparse.Namespace,
    report_repos: Dict[str, Any],
    summary: Dict[str, int],
    action_summary: Dict[ActionType, List[str]],
    local: Dict[str, Any],
    fleet_summary: Dict[str, Any],
    fleet_maps: Dict[str, Any],
    param_results: Optional[Dict[str, Any]],
    plan: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """Assemble the JSON report payload.

    Additive by contract: existing keys are never dropped or renamed, so
    anything reading today's reports keeps working. ``schema_version`` only
    increments if that contract breaks.
    """
    payload = {
        "schema_version": 1,
        "repos": report_repos,
        "summary": summary,
        "actions": {k.value: v for k, v in action_summary.items()},
        "local": local,
        "port_collisions": fleet_summary,
        "port_collision_maps": fleet_maps,
        "findings": build_findings(
            full_manifest, report_repos, local, fleet_summary, param_results
        ),
        "plan": plan,
    }
    if param_results is not None:
        payload["param_check"] = param_results
    # bake-in meta (dirty intentionally ignored: we audit files on disk, not git state)
    payload["meta"] = {
        "timeout": args.timeout,
        "clone_timeout": args.clone_timeout,
        "batch": getattr(args, "batch", None),
        "tickers": args.ticker,
        "local_only": bool(getattr(args, "local_only", False)),
    }
    payload["dirty"] = None
    return payload


def write_report(payload: Dict[str, Any], report_path: str) -> None:
    """Write the report payload as pretty-printed JSON."""
    with open(report_path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2)
    report_line(f"\nJSON report written to {report_path}")


def empty_summary() -> Dict[str, int]:
    """Zeroed probe summary for runs that never probe (--local-only).

    Keeps every key the normal path produces so report readers can index the
    same shape unconditionally; ``meta.local_only`` marks the difference.
    """
    return {
        "repos_total": 0,
        "alive": 0, "moved": 0, "dead": 0, "unknown": 0, "error": 0,
        "dead_tags": 0, "stale": 0,
    }
