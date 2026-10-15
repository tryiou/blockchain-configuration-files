"""Report payload assembly: findings, the JSON envelope, and its writer.

``build_findings`` flattens every actionable signal into one severity-ordered
array using the two scales the tool already defines (``ActionType`` for repo
state, ``ParamStatus`` for checks) — no third scale is introduced.
"""

from __future__ import annotations

import argparse
import json
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from .model import (
    ACTION_SEVERITY,
    PARAM_STATUS_PRECEDENCE,
    ActionType,
    ManifestCoin,
    ParamStatus,
)
from .ports import PORT_KINDS
from .reporting import report_line

# findings[] only carries statuses that ask a human to act. PASS/MATCH/SKIP
# stay inside param_check — surfacing them would restate the whole fleet.
FINDING_PARAM_STATUSES: tuple[ParamStatus, ...] = (
    ParamStatus.FAIL,
    ParamStatus.BROKEN,
    ParamStatus.CONFLICT,
    ParamStatus.DIFFERS,
    ParamStatus.WARN,
    ParamStatus.UNRESOLVED,
)

# Kind -> (stable id, conf template, conf key label). The xbridge namespace is
# its own file; the two [test] namespaces live in the wallet conf's test section.
PORT_FINDING_KINDS: dict[str, tuple[str, str, str]] = {
    "p2p": ("P2P-COLLISION", "wallet-confs/{}", "port"),
    "rpc": ("RPC-COLLISION", "wallet-confs/{}", "rpcport"),
    "xbridge": ("XBRIDGE-COLLISION", "xbridge-confs/{}", "Port"),
    "test_p2p": ("TEST-P2P-COLLISION", "wallet-confs/{}", "[test] port"),
    "test_rpc": ("TEST-RPC-COLLISION", "wallet-confs/{}", "[test] rpcport"),
}


def _by_ticker(full_manifest: list[ManifestCoin]) -> dict[str, ManifestCoin]:
    """Ticker -> first manifest coin with that ticker (coins can share one)."""
    by_ticker: dict[str, ManifestCoin] = {}
    for c in full_manifest:
        by_ticker.setdefault(c.ticker or "", c)
    return by_ticker


def _repo_findings(report_repos: dict[str, Any], add: Callable[..., None]) -> None:
    """Repository state: one finding per non-OK manifest entry."""
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
            bits, category = _repo_finding_bits(rdata, entry, action)
            detail = f"repo {status}" + (": " + "; ".join(bits) if bits else "")
            versions_block: dict[str, Any] = {
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


def _repo_finding_bits(rdata: dict[str, Any], entry: dict[str, Any], action: Any) -> tuple[list[str], str]:
    """The detail fragments and category for one non-OK repo entry."""
    bits: list[str] = []
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
    if entry.get("changelog_mandatory"):
        category = "changelog"
    elif action in (ActionType.DEAD, ActionType.MOVED, ActionType.UNKNOWN):
        category = "liveness"
    else:
        category = "version"
    return bits, category


def _local_findings(local: dict[str, Any], add: Callable[..., None]) -> None:
    """Local cross-check: missing confs, missing templates, orphans."""
    # --- local cross-check ---------------------------------------------------
    for ticker, ver_id, wc in local.get("missing_wallet_conf", []):
        add(
            "FAIL",
            "local",
            ticker,
            ver_id,
            "MISSING-WALLET-CONF",
            f"manifest points at wallet-confs/{wc} but the file does not exist",
            file=f"wallet-confs/{wc}",
        )
    for ticker, ver_id, xc in local.get("missing_xbridge_conf", []):
        add(
            "FAIL",
            "local",
            ticker,
            ver_id,
            "MISSING-XBRIDGE-CONF",
            f"manifest points at xbridge-confs/{xc} but the file does not exist",
            file=f"xbridge-confs/{xc}",
        )
    for ticker in sorted(set(local.get("missing_base_j2", []))):
        add(
            "WARN",
            "local",
            ticker,
            None,
            "MISSING-BASE-J2",
            f"autobuild/configs/{ticker}.base.j2 does not exist",
            file=f"autobuild/configs/{ticker}.base.j2",
        )
    for dname, orphs in (local.get("orphans") or {}).items():
        for stem in sorted(set(orphs)):
            add(
                "INFO",
                "local",
                None,
                None,
                "ORPHAN-CONF",
                f"{dname}/{stem}.conf is not referenced by the manifest (informational)",
                file=f"{dname}/{stem}.conf",
            )


def _port_findings(full_manifest: list[ManifestCoin], fleet_summary: dict[str, Any], add: Callable[..., None]) -> None:
    """Fleet port matrix: one finding per colliding port per coin."""
    # --- fleet port matrix ---------------------------------------------------
    # One finding per colliding port per coin so coin/file are exact; the
    # matrix is fleet-wide even when --ticker narrowed the run.
    by_ticker = _by_ticker(full_manifest)
    for kind in PORT_KINDS:
        fid, conf_tpl, key_label = PORT_FINDING_KINDS[kind]
        for port, tickers in sorted((fleet_summary.get(kind) or {}).items()):
            for t in sorted(tickers):
                coin = by_ticker.get(t)
                conf = conf_tpl.format(coin.wallet_conf) if coin and coin.wallet_conf else None
                others = sorted(x for x in tickers if x != t)
                add(
                    ParamStatus.CONFLICT.value,
                    "port",
                    t,
                    coin.ver_id if coin else None,
                    fid,
                    f"{key_label}={port} is claimed by {', '.join(tickers)}"
                    + (f" (also {', '.join(others)})" if others else ""),
                    file=conf,
                )


def _param_findings(
    param_results: dict[str, Any] | None, full_manifest: list[ManifestCoin], add: Callable[..., None]
) -> None:
    """Parameter checks: one finding per actionable check."""
    # --- parameter checks ----------------------------------------------------
    by_ver_id: dict[str, ManifestCoin] = {c.ver_id: c for c in full_manifest if c.ver_id}
    by_ticker = _by_ticker(full_manifest)
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
                status.value,
                "param",
                coin.ticker if coin else None,
                coin.ver_id if coin else None,
                cid,
                chk.get("detail", ""),
            )


def _findings_sort_key(f: dict[str, Any]) -> tuple[int, int, str, str, str]:
    sev = f["severity"]
    tie = (f["category"], f["coin"] or "", f["id"])
    if sev in ACTION_SEVERITY:  # repository-state group, worst first
        return (0, -ACTION_SEVERITY[ActionType(sev)], *tie)
    try:  # check group, worst first by PARAM_STATUS_PRECEDENCE
        return (1, -PARAM_STATUS_PRECEDENCE.index(ParamStatus(sev)), *tie)
    except ValueError:
        return (2, 0, *tie)


def build_findings(
    full_manifest: list[ManifestCoin],
    report_repos: dict[str, Any],
    local: dict[str, Any],
    fleet_summary: dict[str, Any],
    param_results: dict[str, Any] | None,
) -> list[dict[str, Any]]:
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
    findings: list[dict[str, Any]] = []

    def add(  # noqa: PLR0913, PLR0917  # the finding schema verbatim: one field per report column, all optional behind `detail`
        severity: str,
        category: str,
        coin: str | None,
        ver_id: str | None,
        fid: str,
        detail: str,
        file: str | None = None,
        line: int | None = None,
        versions: dict[str, Any] | None = None,
    ) -> None:
        findings.append(
            {
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
            }
        )

    _repo_findings(report_repos, add)
    _local_findings(local, add)
    _port_findings(full_manifest, fleet_summary, add)
    _param_findings(param_results, full_manifest, add)

    findings.sort(key=_findings_sort_key)
    return findings


@dataclass
class ReportInputs:
    """Everything :func:`build_report` needs, named.

    The report assembles sections from up to ten sources; a positional
    call of ``{}, empty_summary(), defaultdict(list), {}`` at a call site
    is unreadable and silently mis-orderable. Fleet sections default
    empty because scaffold/delist/apply-plan runs produce no fleet data.
    """

    full_manifest: list[ManifestCoin]
    args: argparse.Namespace
    report_repos: dict[str, Any] = field(default_factory=dict)
    summary: dict[str, int] = field(default_factory=dict)
    action_summary: dict[ActionType, list[str]] = field(default_factory=lambda: defaultdict(list))
    local: dict[str, Any] = field(default_factory=dict)
    fleet_summary: dict[str, Any] = field(default_factory=dict)
    fleet_maps: dict[str, Any] = field(default_factory=dict)
    param_results: dict[str, Any] | None = None
    plan: list[dict[str, Any]] = field(default_factory=list)


def build_report(inp: ReportInputs) -> dict[str, Any]:
    """Assemble the JSON report payload.

    Additive by contract: existing keys are never dropped or renamed, so
    anything reading today's reports keeps working. ``schema_version`` only
    increments if that contract breaks.
    """
    payload = {
        "schema_version": 1,
        "repos": inp.report_repos,
        "summary": inp.summary,
        "actions": {k.value: v for k, v in inp.action_summary.items()},
        "local": inp.local,
        "port_collisions": inp.fleet_summary,
        "port_collision_maps": inp.fleet_maps,
        "findings": build_findings(
            inp.full_manifest,
            inp.report_repos,
            inp.local,
            inp.fleet_summary,
            inp.param_results,
        ),
        "plan": inp.plan,
    }
    if inp.param_results is not None:
        payload["param_check"] = inp.param_results
    # bake-in meta (dirty intentionally ignored: we audit files on disk, not git state)
    payload["meta"] = {
        "timeout": inp.args.timeout,
        "clone_timeout": inp.args.clone_timeout,
        "batch": getattr(inp.args, "batch", None),
        "tickers": inp.args.ticker,
        "local_only": bool(getattr(inp.args, "local_only", False)),
    }
    payload["dirty"] = None
    return payload


def write_report(payload: dict[str, Any], report_path: str) -> None:
    """Write the report payload as pretty-printed JSON."""
    with Path(report_path).open("w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2)
    report_line(f"\nJSON report written to {report_path}")


def empty_summary() -> dict[str, int]:
    """Zeroed probe summary for runs that never probe (--local-only).

    Keeps every key the normal path produces so report readers can index the
    same shape unconditionally; ``meta.local_only`` marks the difference.
    """
    return {
        "repos_total": 0,
        "alive": 0,
        "moved": 0,
        "dead": 0,
        "unknown": 0,
        "error": 0,
        "dead_tags": 0,
        "stale": 0,
    }
