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
from dataclasses import dataclass
from pathlib import Path
from typing import Any, NamedTuple

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
from .params import ParamAuditEngine, ParamAuditResult
from .ports import PORT_KINDS, PORT_LABEL
from .probe import RemoteProbeService, SystemCommandRunner
from .progress import emit
from .reporting import report_line
from .util import _detect_mandatory_hf, entry_changelog_quote, norm_port_value
from .versioning import VersionEngine, _newest_and_stale, action_reason, classify_action

# Report-line shaping limits: how much of a list the console shows before
# it caps, and how many tags a changelog probe may fetch per repo.
_MAX_CAPPED_ITEMS = 3
_MAX_TAG_LIST = 100
_MAX_CHANGELOG_TAGS = 5


def _capped(items: list[str]) -> str:
    if len(items) > _MAX_CAPPED_ITEMS:
        return f"{', '.join(items[:_MAX_CAPPED_ITEMS])} +{len(items) - _MAX_CAPPED_ITEMS} more"
    return ", ".join(items)


def _repo_entries(coins: list[ManifestCoin], tags: set[str] | None, summary: dict[str, int]) -> list[dict[str, Any]]:
    """Per-coin expected/found/missing rows for one repo.

    Exact string match only — no canonical v handling: FOUND iff
    byte-equal to a remote tag from git ls-remote; a declared version
    that does not exist upstream stays MISSING and drives REVIEW.
    """
    entries: list[dict[str, Any]] = []
    for coin in coins:
        expected = coin.expected_tags()
        missing = [t for t in expected if t not in tags] if tags is not None else expected
        found = [t for t in expected if t not in missing]
        entries.append(
            {
                "ticker": coin.ticker,
                "ver_id": coin.ver_id,
                "versions": coin.versions,
                "expected_tags": expected,
                "found": found,
                "missing": missing,
                "our_latest": VersionEngine.max_version_tag(expected),
                "remote_latest": VersionEngine.max_version_tag(VersionEngine.stable_tags(tags)) if tags else None,
            }
        )
        summary["dead_tags"] += len(missing)
    return entries


def _selected_tags_for_dates(  # noqa: PLR0913  # probe inputs, keyword-only at the call site
    *,
    coins: list[ManifestCoin],
    tags: set[str],
    newer_same: list[str],
    newer_alt: list[str],
    held_max_name: str | None,
    top_tags: int,
) -> set[str]:
    """The tag set whose dates the fossil/stale decision needs — one fetch.

    The held tag plus the date-relevant candidates, unioned with the
    stale bulk set (held-present plus top stable tags, capped at
    ``top_tags`` when the tail is long).
    """
    needed: set[str] = set()
    if held_max_name and held_max_name in tags:
        needed.add(held_max_name)
    for t in newer_same + newer_alt:
        if t in tags:
            needed.add(t)
    held_present: set[str] = set()
    for c in coins:
        held_present.update(c.expected_tags())
    held_present &= tags
    rest = [
        t
        for t in tags - held_present
        if not VersionEngine.is_prerelease(t) and VersionEngine.parse_version(t) is not None
    ]
    if len(rest) <= _MAX_TAG_LIST:
        bulk = held_present | set(rest)
    else:
        rest.sort(key=lambda t: VersionEngine.parse_version(t) or (), reverse=True)
        bulk = held_present | set(rest[:top_tags])
    return needed | bulk


def _purge_fossils(
    tag_dates: dict[str, str],
    held_max_name: str | None,
    newer_same: list[str],
    newer_alt: list[str],
) -> tuple[list[str], list[str], list[str]]:
    """Fossil purge: higher semver but older-dated than held_max — not real upgrades.

    Returns ``(fossils, newer_same, newer_alt)`` with the fossils removed
    from the candidate lists so they cannot drive an UPGRADE action.
    """
    held_date = tag_dates.get(held_max_name) if held_max_name else None
    if not (tag_dates and held_date):
        return [], newer_same, newer_alt
    fossils = [t for t in newer_same + newer_alt if (td := tag_dates.get(t)) is not None and td < held_date]
    fset = set(fossils)
    return (
        fossils,
        [t for t in newer_same if t not in fset],
        [t for t in newer_alt if t not in fset],
    )


def _probe_changelogs(  # noqa: PLR0913  # probe inputs, keyword-only at the call site
    *,
    url: str,
    args: argparse.Namespace,
    status: RepoStatus,
    tags: set[str] | None,
    newer_same: list[str],
    newer_alt: list[str],
    probe_service: RemoteProbeService,
) -> tuple[list[dict[str, Any]], bool]:
    """Changelog extraction for the interval (our_latest_exclusive < tag <= remote_latest).

    Bounded to the 5 most recent candidates, cached, rate-limit aware.
    Returns ``(findings, mandatory)``.
    """
    if (
        args.no_changelog
        or status not in (RepoStatus.ALIVE, RepoStatus.MOVED)
        or tags is None
        or not (newer_same or newer_alt)
    ):
        return [], False
    changelog_candidates = newer_same + newer_alt
    # Cap to 5 most recent by version to avoid GH spam and keep fast
    if len(changelog_candidates) > _MAX_CHANGELOG_TAGS:
        changelog_candidates = sorted(
            changelog_candidates, key=lambda t: VersionEngine.parse_version(t) or (), reverse=True
        )[:5]
        changelog_candidates = sorted(changelog_candidates, key=lambda t: VersionEngine.parse_version(t) or ())
    changelog_findings: list[dict[str, Any]] = []
    changelog_mandatory = False
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
    return changelog_findings, changelog_mandatory


def _classify_entries(  # noqa: PLR0913  # one input per classification fact
    entries: list[dict[str, Any]],
    status: RepoStatus,
    newer_same: list[str],
    newer_alt: list[str],
    *,
    stale: bool,
    changelog_mandatory: bool,
    changelog_findings: list[dict[str, Any]],
) -> None:
    """Fold per-entry action; a mandatory HF escalates UPGRADE -> REVIEW."""
    for entry in entries:
        act = classify_action(status, entry["missing"], newer_same, newer_alt, stale=stale)
        if changelog_mandatory and act == ActionType.UPGRADE:
            act = ActionType.REVIEW
        entry["action"] = act
        if changelog_mandatory:
            entry["changelog_mandatory"] = True
            entry["changelog_quote"] = entry_changelog_quote(changelog_findings, newer_same, newer_alt)


@dataclass
class _RepoTagFacts:
    """The probe state one repo's report line is rendered from."""

    newer_same: list[str]
    newer_alt: list[str]
    fossils: list[str]
    tags: set[str] | None
    tag_dates: dict[str, str]
    newest_tag: str | None
    newest_date: str | None
    stale: bool
    coins: list[ManifestCoin]
    args: argparse.Namespace


def _repo_lines(entries: list[dict[str, Any]], facts: _RepoTagFacts) -> dict[str, Any]:
    """The per-repo report-line fragments (missing/newer/version/newest/stale)."""
    missing_list = [f"{e['ticker']}:{t}" for e in entries for t in e["missing"]]
    miss = f"  missing_tags=[{_capped(missing_list)}]" if missing_list else ""
    newer_line = ""
    if facts.newer_same:
        newer_line += f"  NEWER_same=[{_capped(facts.newer_same)}]"
    if facts.newer_alt:
        newer_line += f"  NEWER_alt=[{_capped(facts.newer_alt)}]"
    if facts.fossils:
        newer_line += f"  FOSSIL_higher_semver=[{_capped(facts.fossils)}] (older-dated than our tag - not upgrades)"

    held_max = VersionEngine.max_version_tag([t for c in facts.coins for t in c.expected_tags()])
    remote_latest = VersionEngine.max_version_tag(VersionEngine.stable_tags(facts.tags)) if facts.tags else None
    remote_latest_date = facts.tag_dates.get(remote_latest, "")[:10] if remote_latest else ""

    version_line = ""
    if remote_latest:
        version_line += (f"  held_max={held_max}  upstream_semver_max={remote_latest}") + (
            f" ({remote_latest_date})" if remote_latest_date else ""
        )
        if held_max and held_max == remote_latest:
            version_line += " (=held, up-to-date by version)"

    return {
        "missing_list": missing_list,
        "miss": miss,
        "newer_line": newer_line,
        "version_line": version_line,
        "newest_line": _newest_line(facts, remote_latest),
        "stale_line": _stale_line(facts),
    }


def _newest_line(facts: _RepoTagFacts, remote_latest: str | None) -> str:
    """The upstream_date_newest fragment, noting when newest == semver max."""
    if not facts.newest_tag or not facts.newest_date:
        # A newest tag with no parseable date renders no date fragment
        # rather than slicing None.
        return ""
    if facts.newest_tag == remote_latest:
        return f"  upstream_date_newest={facts.newest_tag} (=upstream_semver_max) ({facts.newest_date[:10]})"
    return f"  upstream_date_newest={facts.newest_tag} ({facts.newest_date[:10]})"


def _stale_line(facts: _RepoTagFacts) -> str:
    """The INACTIVE fragment for a stale repo, with measured age when the date parses."""
    if not facts.stale:
        return ""
    if not facts.newest_date:
        return f"  INACTIVE (>{facts.args.stale_years:.1f}y)"
    try:
        nd2 = datetime.datetime.strptime(facts.newest_date, "%Y-%m-%d %H:%M:%S %z")
        age_y = (datetime.datetime.now(nd2.tzinfo) - nd2).days / 365.25
        return f"  INACTIVE ({age_y:.1f}y since {facts.newest_date[:10]} >{facts.args.stale_years:.1f}y threshold)"
    except Exception:
        return f"  INACTIVE (>{facts.args.stale_years:.1f}y since {facts.newest_date[:10]})"


class _RepoProbe(NamedTuple):
    """Every network result for one repo, before entry classification."""

    status: RepoStatus
    new_home: str | None
    facts: _RepoTagFacts
    changelog_findings: list[dict[str, Any]]
    changelog_mandatory: bool


def _probe_repo(
    url: str, coins: list[ManifestCoin], args: argparse.Namespace, probe_service: RemoteProbeService
) -> _RepoProbe:
    """Every network probe for one repo: redirect, tags, dates, changelog."""
    new_home = probe_service.probe_redirect(url, args.timeout)
    status, tags = probe_service.probe_tags(url, args.timeout)
    if status == RepoStatus.ALIVE and new_home:
        status = RepoStatus.MOVED

    newer_same, newer_alt = VersionEngine.detect_newer(tags, coins)
    tag_dates: dict[str, str] = {}
    newest_tag: str | None = None
    newest_date: str | None = None
    stale = False
    held_max_name = VersionEngine.max_version_tag([t for c in coins for t in c.expected_tags()])
    fossils: list[str] = []

    # Mandatory fossil/stale date fetch — single round-trip per repo (unified).
    if status in (RepoStatus.ALIVE, RepoStatus.MOVED) and tags is not None:
        selected = _selected_tags_for_dates(
            coins=coins,
            tags=tags,
            newer_same=newer_same,
            newer_alt=newer_alt,
            held_max_name=held_max_name,
            top_tags=args.top_tags,
        )
        if selected:
            fetched = probe_service.probe_tag_dates(url, selected, args.timeout)
            if fetched:
                tag_dates.update(fetched)
        newest_tag, newest_date, stale = _newest_and_stale(tag_dates, args.stale_years)

    fossils, newer_same, newer_alt = _purge_fossils(tag_dates, held_max_name, newer_same, newer_alt)

    changelog_findings, changelog_mandatory = _probe_changelogs(
        url=url,
        args=args,
        status=status,
        tags=tags,
        newer_same=newer_same,
        newer_alt=newer_alt,
        probe_service=probe_service,
    )
    facts = _RepoTagFacts(
        newer_same=newer_same,
        newer_alt=newer_alt,
        fossils=fossils,
        tags=tags,
        tag_dates=tag_dates,
        newest_tag=newest_tag,
        newest_date=newest_date,
        stale=stale,
        coins=coins,
        args=args,
    )
    return _RepoProbe(status, new_home, facts, changelog_findings, changelog_mandatory)


def _repo_report_row(probe: _RepoProbe, entries: list[dict[str, Any]]) -> dict[str, Any]:
    """The per-repo JSON row: status, tag facts, stale flags, entries."""
    facts = probe.facts
    return {
        "status": probe.status.value,
        "new_home": probe.new_home,
        "tag_count": len(facts.tags) if facts.tags is not None else None,
        "newer_same": facts.newer_same,
        "newer_alt": facts.newer_alt,
        "remote_latest": VersionEngine.max_version_tag(VersionEngine.stable_tags(facts.tags)) if facts.tags else None,
        "tag_dates": facts.tag_dates,
        "stale_higher_semver": facts.fossils,
        "newest_tag": facts.newest_tag,
        "newest_tag_date": facts.newest_date,
        "stale": facts.stale,
        "entries": entries,
        "changelog": probe.changelog_findings,
        "changelog_mandatory": probe.changelog_mandatory,
    }


def _repo_action(entries: list[dict[str, Any]]) -> ActionType:
    """The worst action across one repo's entries."""
    repo_action = ActionType.OK
    for e in entries:
        sev = ACTION_SEVERITY[e["action"]]
        if sev > ACTION_SEVERITY[repo_action]:
            repo_action = e["action"]
    return repo_action


def _note_repo_action(
    action_summary: dict[ActionType, list[str]],
    repo_action: ActionType,
    entries: list[dict[str, Any]],
    probe: _RepoProbe,
    tickers_label: str,
) -> None:
    """Record one repo's ACTION SUMMARY entry (the escalated REVIEW case)."""
    facts = probe.facts
    reason = action_reason(
        repo_action,
        [f"{e['ticker']}:{t}" for e in entries for t in e["missing"]],
        facts.newer_same,
        facts.newer_alt,
        stale=facts.stale,
        new_home=probe.new_home,
    )
    action_summary[repo_action].append(
        f"{tickers_label}  ({reason})"
        + f" [mandatory HF {probe.changelog_findings[0]['tag'] if probe.changelog_findings else '?'}]"
    )


def _print_repo_row(  # noqa: PLR0913, PLR0917  # one input per rendered fragment
    idx: int,
    total: int,
    url: str,
    probe: _RepoProbe,
    tickers_label: str,
    repo_action: ActionType,
    frag: dict[str, str],
    *,
    escalated: bool,
) -> None:
    """The one console line per repo plus its changelog detail lines."""
    facts = probe.facts
    verdict = f"action={repo_action.value}"
    if escalated:
        verdict += " (escalated from UPGRADE due to mandatory HF)"
    changelog_line = ""
    if probe.changelog_mandatory:
        q = probe.changelog_findings[0]["quote"] if probe.changelog_findings else "mandatory hard fork"
        src = probe.changelog_findings[0]["source"] if probe.changelog_findings else "unknown"
        tag = probe.changelog_findings[0]["tag"] if probe.changelog_findings else "?"
        changelog_line = (
            f'  CHANGELOG_MANDATORY_HF={tag} "{q}" (src:{src}) !! MANUAL REVIEW required (old versions must be dropped)'
        )
    tags_suffix = f"  tags={len(facts.tags)}" if facts.tags is not None else ""
    report_line(
        f"[{idx}/{total}] {verdict} {probe.status.value:8} {tickers_label:12} {url}"
        f"{(' -> ' + probe.new_home) if probe.new_home else ''}"
        f"{tags_suffix}"
        f"{frag['miss']}{frag['newer_line']}{frag['version_line']}{frag['newest_line']}"
        f"{frag['stale_line']}{changelog_line}"
    )
    if probe.changelog_mandatory:
        for cf in probe.changelog_findings:
            report_line(f'    !! CHANGELOG {cf["tag"]} ({cf["source"]}): "{cf["quote"]}"')


def audit_repos(
    args: argparse.Namespace,
    manifest: list[ManifestCoin],
    manifest_path: Path,
    probe_service: RemoteProbeService,
) -> tuple[dict[str, Any], dict[str, int], dict[ActionType, list[str]]]:
    """Probe every distinct repo in the manifest and print the fleet sections.

    Prints one line per repo as it goes (so a multi-minute run stays
    observable), then the SUMMARY and ACTION SUMMARY blocks. Returns exactly
    the three structures the JSON report needs.
    """
    repos: dict[str, list[ManifestCoin]] = defaultdict(list)
    for coin in manifest:
        if coin.repo_url:
            repos[coin.repo_url].append(coin)

    report_repos: dict[str, Any] = {}
    action_summary: dict[ActionType, list[str]] = defaultdict(list)
    summary: dict[str, int] = {
        "repos_total": len(repos),
        "alive": 0,
        "moved": 0,
        "dead": 0,
        "unknown": 0,
        "error": 0,
        "dead_tags": 0,
        "stale": 0,
    }

    report_line(f"Probing {len(repos)} distinct repos from {manifest_path}...\n")

    for idx, url in enumerate(sorted(repos), 1):
        coins = repos[url]
        tickers_label = ",".join(sorted({c.ticker or "?" for c in coins}))
        emit("probe", index=idx, total=len(repos), ticker=tickers_label)
        probe = _probe_repo(url, coins, args, probe_service)
        summary[probe.status.value.lower()] += 1

        entries = _repo_entries(coins, probe.facts.tags, summary)
        _classify_entries(
            entries,
            probe.status,
            probe.facts.newer_same,
            probe.facts.newer_alt,
            stale=probe.facts.stale,
            changelog_mandatory=probe.changelog_mandatory,
            changelog_findings=probe.changelog_findings,
        )
        report_repos[url] = _repo_report_row(probe, entries)
        if probe.facts.stale:
            summary["stale"] += 1

        repo_action = _repo_action(entries)
        escalated = probe.changelog_mandatory and repo_action == ActionType.REVIEW
        if escalated:
            _note_repo_action(action_summary, repo_action, entries, probe, tickers_label)

        frag = _repo_lines(entries, probe.facts)
        _print_repo_row(idx, len(repos), url, probe, tickers_label, repo_action, frag, escalated=escalated)
        time.sleep(args.sleep)

    report_line("\n=== SUMMARY ===")
    for key in ("repos_total", "alive", "moved", "dead", "unknown", "error", "dead_tags", "stale"):
        report_line(f"  {key}: {summary[key]}")

    report_line("\n=== ACTION SUMMARY ===")
    for act in (
        ActionType.DEAD,
        ActionType.MOVED,
        ActionType.UNKNOWN,
        ActionType.UPGRADE,
        ActionType.REVIEW,
        ActionType.OK,
    ):
        lines = action_summary.get(act)
        if lines:
            report_line(f"  {act.value} ({len(lines)}):")
            for line in lines:
                report_line(f"    {line}")

    return report_repos, summary, action_summary


def _param_total(param_results: dict[str, Any], field: str) -> int:
    """Sum one count field across the per-coin rows; meta keys excluded.

    The ``_``-prefixed rows are collision metadata, not coin rows, so
    every summary total folds the same way.
    """
    return sum(v.get(field, 0) for k, v in param_results.items() if not k.startswith("_") and isinstance(v, dict))


def _inject_collision_checks(
    res: ParamAuditResult,
    coin: ManifestCoin,
    repo_root: Path,
    fleet_maps: dict[str, Any],
) -> None:
    """Re-derive this coin's fleet port collisions as CONFLICT checks.

    --param-check re-derives the same collisions the port matrix found, so
    the checks (and the --write-config fixers) see them per coin.
    """
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

    for kind, key, cid, label in (
        ("test_p2p", "port", "TEST-P2P-COLLISION", "P2P"),
        ("test_rpc", "rpcport", "TEST-RPC-COLLISION", "RPC"),
    ):
        v = norm_port_value(test_sec.get(key, "") if test_sec else "")
        if v and v.isdigit():
            p = int(v)
            peers = fleet_maps[kind].get(p, [])
            if len(peers) > 1:
                others = sorted(t for t in peers if t != coin.ticker)
                detail = f"[test] {label} port={p} shared with: {', '.join(others)} (duplicate test {kind} port)"
                res.checks.append(CheckFinding(id=cid, status=ParamStatus.CONFLICT, detail=detail))
                res.conflict += 1


def _unique_result_key(param_results: dict[str, Any], coin: ManifestCoin) -> str:
    """ver_id (or ticker) key, suffixed on collision so no entry is lost."""
    key_name = coin.ver_id or coin.ticker
    orig_key = key_name
    suffix = 1
    while key_name in param_results:
        suffix += 1
        key_name = f"{orig_key}_{suffix}"
    return key_name


def _print_param_coin_result(idx: int, total: int, coin: ManifestCoin, res: ParamAuditResult) -> None:
    """The per-coin PARAM CHECK block: one status line, then attention checks."""
    if res.mode.startswith(("skipped", "no-", "clone-", "fetch-")):
        report_line(f"[{idx}/{total}] {coin.ticker} ({coin.ver_id}) tag={res.tag} src=- ({res.mode})")
        for pv in res.per_version:
            if pv.get("mode", "").startswith(("clone-", "fetch-", "no-")):
                report_line(
                    f"    -- {pv.get('version', ''):<12} wallet={pv.get('wallet_conf')} "
                    f"xbridge={pv.get('xbridge_conf')} ({pv.get('mode')})"
                )
        return
    src_base = Path(res.source).name if res.source else "-"
    report_line(
        f"[{idx}/{total}] {coin.ticker} ({coin.ver_id}) tag={res.tag} src={src_base} : "
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
                f"src={pv_src} : FAIL={pv.get('fail', 0)} DIFFERS={pv.get('differs', 0)} "
                f"WARN={pv.get('warn', 0)} ({pv.get('mode', '')})"
            )
            if pv.get("fail", 0) or pv.get("differs", 0) or pv.get("warn", 0) or pv.get("unresolved", 0):
                for chk_dict in pv.get("checks", []):
                    st_enum = ParamStatus(chk_dict["status"])
                    if st_enum in (
                        ParamStatus.FAIL,
                        ParamStatus.BROKEN,
                        ParamStatus.DIFFERS,
                        ParamStatus.WARN,
                        ParamStatus.UNRESOLVED,
                        ParamStatus.CONFLICT,
                    ):
                        marker = STATUS_MARKERS.get(st_enum, "??")
                        report_line(f"       {marker} {chk_dict['id']:<18} {chk_dict['detail']}")


def _print_collision_section(fleet_summary: dict[str, Any], total_conflicts: int) -> None:
    """The PORT COLLISIONS section from the fleet summary."""
    report_line("\n=== PORT COLLISIONS ===")
    for kind in PORT_KINDS:
        dup = fleet_summary.get(kind)
        if not dup:
            continue
        label = PORT_LABEL[kind]
        for port in sorted(dup):
            report_line(f"  {label} {port} : {', '.join(dup[port])}")
    report_line(f"  ({total_conflicts} distinct conflict rows injected)")


def audit_params(  # noqa: PLR0913, PLR0917  # one input per audit stage
    args: argparse.Namespace,
    manifest: list[ManifestCoin],
    repo_root: Path,
    fleet_maps: dict[str, Any],
    fleet_summary: dict[str, Any],
    runner: SystemCommandRunner,
) -> dict[str, Any] | None:
    """Run --param-check across the manifest and print the PARAM CHECK section.

    Returns None when --param-check was not requested; callers treat None as
    "no findings available" and must not run any write step off it.
    """
    param_results: dict[str, Any] | None = None
    if args.param_check:
        report_line("\n=== PARAM CHECK ===")
        if args.strict_per_version:
            report_line("  strict-per-version: worst per-version status bubbles to entry")

        checkout_manager = SourceCheckoutManager(runner=runner)
        audit_engine = ParamAuditEngine(checkout_manager)
        param_results = {}
        total_fail = 0

        for idx, coin in enumerate(manifest, 1):
            # Mirrors the engine's entry-tag choice (params.audit_coin_all_versions):
            # the event names the tag the audit is about to work on, not versions[0].
            # Mirror-exact deliberately, corrupt input included: a string
            # `versions` char-splits the same way on both sides, so the
            # event never disagrees with the run it announces.
            emit(
                "param-check",
                index=idx,
                total=len(manifest),
                ticker=coin.ticker,
                tag=VersionEngine.max_version_tag(set(coin.versions)) if coin.versions else None,
            )
            res = audit_engine.audit_coin_all_versions(
                coin,
                repo_root,
                args.timeout,
                strict=args.strict_per_version,
                fees_only=args.fees_only,
            )

            skipped = res.mode.startswith(("skipped", "no-", "clone-", "fetch-"))
            if not skipped:
                _inject_collision_checks(res, coin, repo_root, fleet_maps)
            param_results[_unique_result_key(param_results, coin)] = res.to_dict()
            _print_param_coin_result(idx, len(manifest), coin, res)
            if skipped:
                # A coin with no resolved source has no counts to fold in.
                continue

            total_fail += res.fail
            time.sleep(args.sleep * 0.2)

        total_differs = _param_total(param_results, "differs")
        total_warn = _param_total(param_results, "warn")
        total_unresolved = _param_total(param_results, "unresolved")
        total_conflicts = _param_total(param_results, "conflict")
        pv_fail = sum(
            pv.get("fail", 0)
            for k, v in param_results.items()
            if isinstance(v, dict)
            for pv in v.get("per_version", [])
        )

        if fleet_summary:
            param_results["_collisions"] = fleet_summary
            param_results["_collision_maps"] = fleet_maps
            _print_collision_section(fleet_summary, total_conflicts)
        else:
            report_line("\n=== PORT COLLISIONS ===  none")

        valid_entry_count = len([k for k in param_results if not k.startswith("_")])
        report_line(
            f"PARAM CHECK SUMMARY: {valid_entry_count} coins | {total_fail} objective-fail | "
            f"{total_differs} differs-from-source | {total_warn} warn | {total_unresolved} unresolved | "
            f"{total_conflicts} conflicts | per-version fails {pv_fail} | "
            f"{'strict-bubble' if args.strict_per_version else 'report-only'}"
        )
    return param_results
