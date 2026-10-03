"""Top-level audit orchestration: remote repo probe pass and param-check pass.

``audit_repos`` drives the fleet probe (redirects, tags, dates, changelog,
triage) and prints progress as it goes; ``audit_params`` drives per-coin
param fact-checking. Both return exactly the structures the JSON report needs.
"""

from __future__ import annotations

import argparse
import datetime
import time
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from .checkout import SourceCheckoutManager, SourceReader
from .constants import CACHE_ROOT
from .model import (
    ACTION_SEVERITY,
    STATUS_MARKERS,
    ActionType,
    CheckFinding,
    ManifestCoin,
    ParamStatus,
    RepoStatus,
)
from .params import ParamAuditEngine
from .probe import RemoteProbeService, SystemCommandRunner
from .reporting import report_line
from .util import _detect_mandatory_hf, entry_changelog_quote, norm_port_value
from .versioning import VersionEngine, _newest_and_stale, action_reason, classify_action


def audit_repos(
    args: argparse.Namespace,
    manifest: List[ManifestCoin],
    manifest_path: Path,
    probe_service: RemoteProbeService,
) -> Tuple[Dict[str, Any], Dict[str, int], Dict[ActionType, List[str]]]:
    """Probe every distinct repo in the manifest and print the fleet sections.

    Prints one line per repo as it goes (so a multi-minute run stays
    observable), then the SUMMARY and ACTION SUMMARY blocks. Returns exactly
    the three structures the JSON report needs.
    """
    repos: Dict[str, List[ManifestCoin]] = defaultdict(list)
    for coin in manifest:
        if coin.repo_url:
            repos[coin.repo_url].append(coin)

    report_repos: Dict[str, Any] = {}
    action_summary: Dict[ActionType, List[str]] = defaultdict(list)
    summary: Dict[str, int] = {
        "repos_total": len(repos),
        "alive": 0, "moved": 0, "dead": 0, "unknown": 0, "error": 0,
        "dead_tags": 0, "stale": 0,
    }

    report_line(f"Probing {len(repos)} distinct repos from {manifest_path}...\n")

    for idx, url in enumerate(sorted(repos), 1):
        coins = repos[url]
        tickers_label = ",".join(sorted({c.ticker or "?" for c in coins}))
        new_home = probe_service.probe_redirect(url, args.timeout)
        status, tags = probe_service.probe_tags(url, args.timeout)
        if status == RepoStatus.ALIVE and new_home:
            status = RepoStatus.MOVED

        summary[status.value.lower()] += 1

        entries: List[Dict[str, Any]] = []
        for coin in coins:
            expected = coin.expected_tags()
            # Exact string match only — no canonical v handling:
            # FOUND iff byte-equal to a remote tag from git ls-remote.
            # Phantom v-prefix tags (e.g. MRX "v4.2.0.1" vs remote "4.2.0.1")
            # intentionally remain MISSING and drive REVIEW — this is the
            # correct manifest-inconsistency signal, not a detector bug.
            missing = [t for t in expected if tags is not None and t not in tags] if tags is not None else expected
            found = [t for t in expected if t not in missing]
            entries.append({
                "ticker": coin.ticker,
                "ver_id": coin.ver_id,
                "versions": coin.versions,
                "expected_tags": expected,
                "found": found,
                "missing": missing,
                "our_latest": VersionEngine.max_version_tag(expected),
                "remote_latest": VersionEngine.max_version_tag(VersionEngine.stable_tags(tags)) if tags else None,
            })
            summary["dead_tags"] += len(missing)

        newer_same, newer_alt = VersionEngine.detect_newer(tags, coins)

        tag_dates: Dict[str, str] = {}
        newest_tag: Optional[str] = None
        newest_date: Optional[str] = None
        stale = False
        held_max_name = VersionEngine.max_version_tag([t for c in coins for t in c.expected_tags()])
        fossils: List[str] = []

        # Mandatory fossil/stale date fetch — single round-trip per repo (unified).
        # Needed set for fossil decision: held_max + newer candidates filtered to existing tags.
        if status in (RepoStatus.ALIVE, RepoStatus.MOVED) and tags is not None:
            needed: Set[str] = set()
            if held_max_name and held_max_name in tags:
                needed.add(held_max_name)
            for t in newer_same + newer_alt:
                if t in tags:
                    needed.add(t)
            # Stale bulk set (held_present + top stable tags) — union with needed for one fetch.
            held = set()
            for c in coins:
                held.update(c.expected_tags())
            held_present = held & tags
            rest = [t for t in tags - held_present if not VersionEngine.is_prerelease(t) and VersionEngine.parse_version(t) is not None]
            if len(rest) <= 100:
                bulk = held_present | set(rest)
            else:
                rest.sort(key=lambda t: VersionEngine.parse_version(t) or (), reverse=True)
                bulk = held_present | set(rest[:args.top_tags])
            selected = needed | bulk
            if selected:
                fetched = probe_service.probe_tag_dates(url, selected, args.timeout)
                if fetched:
                    tag_dates.update(fetched)
            newest_tag, newest_date, stale = _newest_and_stale(tag_dates, args.stale_years)

        # Fossil purge: higher semver but older date than held_max — not real upgrades.
        held_date = tag_dates.get(held_max_name) if held_max_name else None
        if tag_dates and held_date:
            fossils = [t for t in newer_same + newer_alt if (td := tag_dates.get(t)) is not None and td < held_date]
            if fossils:
                fset = set(fossils)
                newer_same = [t for t in newer_same if t not in fset]
                newer_alt = [t for t in newer_alt if t not in fset]

        # Changelog extraction for interval (our_latest_exclusive < tag <= remote_latest) — bounded, cached, rate-limit aware
        changelog_findings: List[Dict[str, Any]] = []
        changelog_mandatory = False
        if not args.no_changelog and status in (RepoStatus.ALIVE, RepoStatus.MOVED) and tags is not None and (newer_same or newer_alt):
            changelog_candidates = newer_same + newer_alt
            # Cap to 5 most recent by version to avoid GH spam and keep fast
            if len(changelog_candidates) > 5:
                changelog_candidates = sorted(
                    changelog_candidates, key=lambda t: VersionEngine.parse_version(t) or (), reverse=True
                )[:5]
                changelog_candidates = sorted(changelog_candidates, key=lambda t: VersionEngine.parse_version(t) or ())
            for tag in changelog_candidates:
                res = probe_service.probe_changelog(url, tag, args.timeout, CACHE_ROOT)
                if res is None:
                    continue
                src, txt = res
                quote = _detect_mandatory_hf(txt)
                if quote:
                    changelog_mandatory = True
                    changelog_findings.append(
                        {"tag": tag, "source": src, "quote": quote, "mandatory": True, "text_snippet": txt[:800]}
                    )
                # small inter-tag sleep to avoid spam, fast as possible
                time.sleep(0.05)

        for entry in entries:
            act = classify_action(status, entry["missing"], newer_same, newer_alt, stale)
            # Mandatory HF escalates UPGRADE -> REVIEW (manual replacement required)
            if changelog_mandatory and act == ActionType.UPGRADE:
                act = ActionType.REVIEW
            entry["action"] = act
            if changelog_mandatory:
                entry["changelog_mandatory"] = True
                entry["changelog_quote"] = entry_changelog_quote(changelog_findings, newer_same, newer_alt)

        report_repos[url] = {
            "status": status.value,
            "new_home": new_home,
            "tag_count": len(tags) if tags is not None else None,
            "newer_same": newer_same,
            "newer_alt": newer_alt,
            "remote_latest": VersionEngine.max_version_tag(VersionEngine.stable_tags(tags)) if tags else None,
            "tag_dates": tag_dates,
            "stale_higher_semver": fossils,
            "newest_tag": newest_tag,
            "newest_tag_date": newest_date,
            "stale": stale,
            "entries": entries,
            "changelog": changelog_findings,
            "changelog_mandatory": changelog_mandatory,
        }
        if stale:
            summary["stale"] += 1

        missing_list = [f"{e['ticker']}:{t}" for e in entries for t in e["missing"]]
        miss = f"  missing_tags=[{', '.join(missing_list)}]" if missing_list else ""
        newer_line = ""
        if newer_same:
            newer_line += f"  NEWER_same=[{', '.join(newer_same)}]"
        if newer_alt:
            newer_line += f"  NEWER_alt=[{', '.join(newer_alt)}]"
        if fossils:
            newer_line += f"  FOSSIL_higher_semver=[{', '.join(fossils)}] (older-dated than our tag - not upgrades)"

        held_max = VersionEngine.max_version_tag([t for c in coins for t in c.expected_tags()])
        remote_latest = VersionEngine.max_version_tag(VersionEngine.stable_tags(tags)) if tags else None
        remote_latest_date = tag_dates.get(remote_latest, "")[:10] if remote_latest else ""

        newest_line = ""
        if newest_tag:
            if newest_tag == remote_latest:
                newest_line += f"  upstream_date_newest={newest_tag} (=upstream_semver_max) ({newest_date[:10]})"
            else:
                newest_line += f"  upstream_date_newest={newest_tag} ({newest_date[:10]})"

        version_line = ""
        if remote_latest:
            version_line += f"  held_max={held_max}  upstream_semver_max={remote_latest}" + (f" ({remote_latest_date})" if remote_latest_date else "")
            if held_max and held_max == remote_latest:
                version_line += " (=held, up-to-date by version)"

        stale_line = ""
        if stale and newest_date:
            try:
                nd2 = datetime.datetime.strptime(newest_date, "%Y-%m-%d %H:%M:%S %z")
                age_y = (datetime.datetime.now(nd2.tzinfo) - nd2).days / 365.25
                stale_line = f"  INACTIVE ({age_y:.1f}y since {newest_date[:10]} >{args.stale_years:.1f}y threshold)"
            except Exception:
                stale_line = f"  INACTIVE (>{args.stale_years:.1f}y since {newest_date[:10]})"
        elif stale:
            stale_line = f"  INACTIVE (>{args.stale_years:.1f}y)"

        repo_action = ActionType.OK
        for e in entries:
            sev = ACTION_SEVERITY[e["action"]]
            if sev > ACTION_SEVERITY[repo_action]:
                repo_action = e["action"]

        changelog_line = ""
        if changelog_mandatory:
            q = changelog_findings[0]["quote"] if changelog_findings else "mandatory hard fork"
            src = changelog_findings[0]["source"] if changelog_findings else "unknown"
            tag = changelog_findings[0]["tag"] if changelog_findings else "?"
            changelog_line = f"  CHANGELOG_MANDATORY_HF={tag} \"{q}\" (src:{src}) !! MANUAL REVIEW required (old versions must be dropped)"

        action_line = f"  action={repo_action.value}"
        if changelog_mandatory and repo_action == ActionType.REVIEW:
            action_line += " (escalated from UPGRADE due to mandatory HF)"
        action_summary[repo_action].append(
            f"{tickers_label}  ({action_reason(repo_action, status, missing_list, newer_same, newer_alt, stale, new_home)})"
            + (f" [mandatory HF {changelog_findings[0]['tag'] if changelog_findings else '?'}]" if changelog_mandatory else "")
        )

        report_line(
            f"[{idx}/{len(repos)}] {status.value:8} {tickers_label:12} {url}"
            f"{(' -> ' + new_home) if new_home else ''}"
            f"{('  tags=%d' % len(tags)) if tags is not None else ''}"
            f"{miss}{newer_line}{version_line}{newest_line}{stale_line}{changelog_line}{action_line}"
        )
        if changelog_mandatory:
            for cf in changelog_findings:
                report_line(f"    !! CHANGELOG {cf['tag']} ({cf['source']}): \"{cf['quote']}\"")
        time.sleep(args.sleep)

    report_line("\n=== SUMMARY ===")
    for key in ("repos_total", "alive", "moved", "dead", "unknown", "error", "dead_tags", "stale"):
        report_line(f"  {key}: {summary[key]}")

    report_line("\n=== ACTION SUMMARY ===")
    for act in (ActionType.DEAD, ActionType.MOVED, ActionType.UNKNOWN, ActionType.UPGRADE, ActionType.REVIEW, ActionType.OK):
        lines = action_summary.get(act)
        if lines:
            report_line(f"  {act.value} ({len(lines)}):")
            for line in lines:
                report_line(f"    {line}")

    return report_repos, summary, action_summary


def audit_params(
    args: argparse.Namespace,
    manifest: List[ManifestCoin],
    repo_root: Path,
    fleet_maps: Dict[str, Any],
    fleet_summary: Dict[str, Any],
    runner: SystemCommandRunner,
) -> Optional[Dict[str, Any]]:
    """Run --param-check across the manifest and print the PARAM CHECK section.

    Returns None when --param-check was not requested; callers treat None as
    "no findings available" and must not run any write step off it.
    """
    param_results: Optional[Dict[str, Any]] = None
    if args.param_check:
        report_line("\n=== PARAM CHECK ===")
        if args.strict_per_version:
            report_line("  strict-per-version: worst per-version status bubbles to entry")

        checkout_manager = SourceCheckoutManager(CACHE_ROOT, runner)
        audit_engine = ParamAuditEngine(checkout_manager)
        param_results = {}
        total_fail = 0

        for idx, coin in enumerate(manifest, 1):
            res = audit_engine.audit_coin_all_versions(coin, repo_root, args.timeout, strict=args.strict_per_version, fees_only=args.fees_only)

            if not res.mode.startswith(("skipped", "no-", "clone-")):
                wpath = repo_root / "wallet-confs" / coin.wallet_conf
                secs = SourceReader.parse_conf_sections(wpath)
                top = secs.get("", {})
                test_sec = secs.get("test", {})

                for kind, key, cid in (("p2p", "port", "P2P-COLLISION"), ("rpc", "rpcport", "RPC-COLLISION")):
                    v = norm_port_value(top.get(key, ""))
                    if v.isdigit():
                        p = int(v)
                        peers = fleet_maps[kind].get(p, [])
                        if len(peers) > 1:
                            others = sorted(t for t in peers if t != coin.ticker)
                            since = SourceReader.lineage_date(repo_root, f"wallet-confs/{coin.wallet_conf}", key)
                            lin = f"; value present since {since}" if since else ""
                            label = "P2P" if kind == "p2p" else "RPC"
                            detail = f"wallet {label} port={p} shared with: {', '.join(others)} (duplicate {kind} port){lin}"
                            res.checks.append(CheckFinding(id=cid, status=ParamStatus.CONFLICT, detail=detail))
                            res.conflict += 1

                xpath = repo_root / "xbridge-confs" / coin.xbridge_conf
                xc_tmp = SourceReader.parse_conf(xpath)
                xv = norm_port_value(xc_tmp.get("Port", ""))
                if xv.isdigit():
                    p = int(xv)
                    peers = fleet_maps["xbridge"].get(p, [])
                    if len(peers) > 1:
                        others = sorted(t for t in peers if t != coin.ticker)
                        detail = f"xbridge Port={p} shared with: {', '.join(others)} (duplicate xbridge port)"
                        res.checks.append(CheckFinding(id="XBRIDGE-COLLISION", status=ParamStatus.CONFLICT, detail=detail))
                        res.conflict += 1

                for kind, key, cid in (("test_p2p", "port", "TEST-P2P-COLLISION"), ("test_rpc", "rpcport", "TEST-RPC-COLLISION")):
                    v = norm_port_value(test_sec.get(key, "") if test_sec else "")
                    if v and v.isdigit():
                        p = int(v)
                        peers = fleet_maps[kind].get(p, [])
                        if len(peers) > 1:
                            others = sorted(t for t in peers if t != coin.ticker)
                            label = "P2P" if "p2p" in kind else "RPC"
                            detail = f"[test] {label} port={p} shared with: {', '.join(others)} (duplicate test {kind} port)"
                            res.checks.append(CheckFinding(id=cid, status=ParamStatus.CONFLICT, detail=detail))
                            res.conflict += 1

            key_name = coin.ver_id or coin.ticker
            orig_key = key_name
            suffix = 1
            while key_name in param_results:
                suffix += 1
                key_name = f"{orig_key}_{suffix}"
            param_results[key_name] = res.to_dict()

            if res.mode.startswith(("skipped", "no-", "clone-")):
                report_line(f"[{idx}/{len(manifest)}] {coin.ticker} ({coin.ver_id}) tag={res.tag} src=- ({res.mode})")
                for pv in res.per_version:
                    if pv.get("mode", "").startswith(("clone-", "no-")):
                        report_line(f"    -- {pv.get('version', ''):<12} wallet={pv.get('wallet_conf')} xbridge={pv.get('xbridge_conf')} ({pv.get('mode')})")
                continue

            src_base = Path(res.source).name if res.source else "-"
            report_line(
                f"[{idx}/{len(manifest)}] {coin.ticker} ({coin.ver_id}) tag={res.tag} src={src_base} : "
                f"FAIL={res.fail} DIFFERS={res.differs} WARN={res.warn} UNRESOLVED={res.unresolved} ({res.mode})"
            )
            for chk in res.checks:
                marker = STATUS_MARKERS.get(chk.status, "??")
                report_line(f"    {marker} {chk.id:<18} {chk.detail}")

            if len(res.per_version) > 1 or (len(res.per_version) == 1 and res.per_version[0]["version"] != res.tag):
                for pv in res.per_version:
                    pv_src = Path(pv["source"]).name if pv.get("source") else "-"
                    report_line(
                        f"    -> {pv['version']:<12} wallet={pv.get('wallet_conf')} xbridge={pv.get('xbridge_conf')} "
                        f"src={pv_src} : FAIL={pv.get('fail', 0)} DIFFERS={pv.get('differs', 0)} WARN={pv.get('warn', 0)} ({pv.get('mode', '')})"
                    )
                    if pv.get("fail", 0) or pv.get("differs", 0) or pv.get("warn", 0) or pv.get("unresolved", 0):
                        for chk_dict in pv.get("checks", []):
                            st_enum = ParamStatus(chk_dict["status"])
                            if st_enum in (ParamStatus.FAIL, ParamStatus.BROKEN, ParamStatus.DIFFERS, ParamStatus.WARN, ParamStatus.UNRESOLVED, ParamStatus.CONFLICT):
                                marker = STATUS_MARKERS.get(st_enum, "??")
                                report_line(f"       {marker} {chk_dict['id']:<18} {chk_dict['detail']}")

            total_fail += res.fail
            time.sleep(args.sleep * 0.2)

        total_differs = sum(v.get("differs", 0) for k, v in param_results.items() if not k.startswith("_") and isinstance(v, dict))
        total_warn = sum(v.get("warn", 0) for k, v in param_results.items() if not k.startswith("_") and isinstance(v, dict))
        total_unresolved = sum(v.get("unresolved", 0) for k, v in param_results.items() if not k.startswith("_") and isinstance(v, dict))
        total_conflicts = sum(v.get("conflict", 0) for k, v in param_results.items() if not k.startswith("_") and isinstance(v, dict))
        pv_fail = sum(pv.get("fail", 0) for k, v in param_results.items() if isinstance(v, dict) for pv in v.get("per_version", []))

        if fleet_summary:
            param_results["_collisions"] = fleet_summary
            param_results["_collision_maps"] = fleet_maps
            report_line("\n=== PORT COLLISIONS ===")
            for kind in ("p2p", "rpc", "xbridge", "test_p2p", "test_rpc"):
                dup = fleet_summary.get(kind)
                if not dup:
                    continue
                label = {"p2p": "P2P", "rpc": "RPC", "xbridge": "XBRIDGE", "test_p2p": "TEST-P2P", "test_rpc": "TEST-RPC"}[kind]
                for port in sorted(dup):
                    report_line(f"  {label} {port} : {', '.join(dup[port])}")
            report_line(f"  ({total_conflicts} distinct conflict rows injected)")
        else:
            report_line("\n=== PORT COLLISIONS ===  none")

        valid_entry_count = len([k for k in param_results if not k.startswith("_")])
        report_line(
            f"PARAM CHECK SUMMARY: {valid_entry_count} coins | {total_fail} objective-fail | "
            f"{total_differs} differs-from-source | {total_warn} warn | {total_unresolved} unresolved | "
            f"{total_conflicts} conflicts | per-version fails {pv_fail} | {'strict-bubble' if args.strict_per_version else 'report-only'}"
        )
    return param_results
