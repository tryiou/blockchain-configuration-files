"""Fleet-data shaping for the dashboard: merge, rows, scope and plan math.

Standard library only — Textual is never imported here, so the JSON-verb
paths and the contract suite use this directly while ``screens`` and
``widgets`` import it for rendering. Anything that touches a widget
stays in those modules; everything here is pure data in, data out,
except ``resolve_plan_slot`` which stats the cache directory it is
given (callers pass ``paths.CACHE_ROOT`` in production, a throwaway
directory in tests).
"""

from __future__ import annotations

import json
import re
import time
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from .paths import read_last_run_meta

SEVERITY_RANK = ("FAIL", "REVIEW", "UPGRADE", "WARN", "INFO")


def severity_rank(severity: Any) -> int:
    """Worst first: unranked severities sit below every known one, so an
    unknown label can never outrank a FAIL."""
    return SEVERITY_RANK.index(severity) if severity in SEVERITY_RANK else len(SEVERITY_RANK)


def split_verdict(detail: Any, severity: Any) -> tuple:
    """Split a check text into (verdict ≤ ~90 chars, dim evidence).

    The verdict is the first clause — findings restate their own
    severity up front ("WARN overpay — got …"), so that prefix is
    stripped, not echoed next to the colored token. The remainder
    survives verbatim as evidence, except a bare model parenthetical:
    when the cut falls on "(" and the remainder carries no source ref,
    it is model gibberish ("2.00x, model floor/dynamic"), not evidence,
    and is dropped — file:line refs still append below. Subordinated,
    never deleted: anything with a source marker is kept.
    """
    sev = str(severity or "")
    text = str(detail or "")
    prefix = f"{sev} " if sev else ""
    if prefix and text.startswith(prefix):
        text = text[len(prefix) :]
    cut = len(text)
    cut_sep = ""
    for sep in ("—", "(", ";"):
        i = text.find(sep)
        if i > 0 and i < cut:
            cut, cut_sep = i, sep
    verdict = text[:cut].strip()[:90].rstrip()
    remainder = text[cut:].strip(" —;")
    if cut_sep == "(" and not re.search(r"src/|\.cpp|\.h\b|:\d+", remainder):
        remainder = ""
    return verdict or text.strip()[:90], _trim_evidence(remainder)


def _trim_evidence(evidence: str) -> str:
    """Drop model parentheticals from evidence, keep source refs (D27)."""

    def keep(match: re.Match) -> str:
        group = match.group(0)
        if re.search(r"src/|\.cpp|\.h\b|:\d+", group):
            return group
        return ""

    return " ".join(re.sub(r"\([^)]*\)", keep, evidence).split())


def action_for(  # noqa: PLR0911  # advice table: one return per (check, status) pair
    check_id: Any,
    status: Any,
    detail: Any,
) -> str:
    """Plain action mapping per check (D27): specific advice wins, the
    status falls back. Every entry renders an arrow + an imperative, so
    a stranger knows what to do — or that there is nothing to do.

    Dispatch keys off the structured (check id, status); message text is
    human-facing. The one exception is the stale-repo case: no structured
    staleness flag reaches the finding today, so it still reads its own
    detail — the only prose-gated branch, and the reason for the finding
    schema to grow a field.
    """
    cid = str(check_id or "")
    sev = str(status or "")
    if cid == "FEES":
        if sev == "FAIL":
            return "meet the relay floor — must fix"
        if sev == "WARN":
            return "lower MinTxFee — safe but wasteful"
    if cid == "PORT":
        return "align the port — must fix"
    if cid == "REPO-ACTION" and "staleness window" in str(detail or ""):
        return "no action — upstream quiet"
    if sev == "FAIL":
        return "investigate — must fix"
    if sev == "WARN":
        return "decide — needs review"
    if sev == "UNRESOLVED":
        return "inspect — needs investigation"
    if sev == "UPGRADE":
        return "review update-versions — newer tags available"
    return "no action"


def _worst_status(findings: list[dict[str, Any]], ticker: str) -> str:
    """The coin's last-known status, or ``—`` if it never reported."""
    severities = [str(f.get("severity", "")) for f in findings if f.get("coin") == ticker]
    if not severities:
        return "—"

    return min(severities, key=severity_rank)


def _change(finding: dict[str, Any]) -> str:
    """``our_latest → remote_latest``; ``ours (current)`` when equal; ``—`` when either side is missing."""
    versions = finding.get("versions")
    if not isinstance(versions, dict):
        return "—"
    ours, remote = versions.get("our_latest"), versions.get("remote_latest")
    if ours and remote:
        if ours == remote:
            return f"{ours} (current)"
        return f"{ours} → {remote}"
    return "—"


def _tags(value: Any) -> str:
    """A tag list joined for reading, or an em dash when it is empty."""
    if isinstance(value, (list, tuple)) and value:
        return ", ".join(str(v) for v in value)
    return "—"


def argv_tickers(raw: Sequence[str]) -> str | None:
    """The ``--ticker`` value in an argv list, either spelling.

    The last occurrence wins, mirroring how the engine's own parser
    resolves a repeated flag. Both the cache-slot decision and the
    last-run scope line read this, so a smuggled ``--ticker`` scopes the
    run identically however it arrived.
    """
    tickers: str | None = None
    args = list(raw)
    i = 0
    while i < len(args):
        arg = args[i]
        if arg == "--ticker" and i + 1 < len(args):
            tickers = args[i + 1]
            i += 2
        elif arg.startswith("--ticker="):
            tickers = arg.split("=", 1)[1]
            i += 1
        else:
            i += 1
    return tickers


def _last_run_scope(argv: Any) -> str:
    """Scope of the last run from its recorded argv: full fleet, or N coins."""
    args = argv if isinstance(argv, list) else []
    raw = argv_tickers(args)
    if not raw:
        return "full fleet"
    tickers = [t for t in raw.split(",") if t.strip()]
    if not tickers:
        return "full fleet"
    # argparse consumes the token after --ticker verbatim, so a
    # flag-looking value is a mis-scoped run the engine matches no coin
    # to; counting it as a coin would overstate the scope.
    if any(t.startswith("-") for t in tickers):
        return "scope matched no coins"
    n = len(tickers)
    return f"{n} coin{'s' if n != 1 else ''}"


def last_run_line() -> str:
    """The actual last run (verb, scope, age, file) from last-run.meta.

    The fleet file above is deliberately untouched by scoped runs, so
    its age is not the last action — this line is. When the meta is
    absent the caller (rebuild_overview) says which file is shown
    instead of printing a bare "never" next to a fresh fleet age.
    """
    last = read_last_run_meta()
    if not last:
        return "never"
    started = last.get("started_at")
    age = (
        f"{time.time() - started:.0f}s ago"
        if isinstance(started, (int, float)) and not isinstance(started, bool)
        else "never"
    )
    verb = str(last.get("verb") or "—")
    report = last.get("report")
    name = Path(report).name if isinstance(report, str) and report else "—"
    return f"{verb} · {_last_run_scope(last.get('argv'))} · {age} → {name}"


def dict_list(payload: dict[str, Any], key: str) -> list[dict[str, Any]]:
    """Elements of ``payload[key]`` the UI can read keys off: only
    objects survive, anything else lands on the empty default."""
    items = payload.get(key)
    if not isinstance(items, list):
        return []
    return [e for e in items if isinstance(e, dict)]


def _merge_key(finding: dict[str, Any]) -> tuple:
    """One row per coin+check: audit and findings probe the same fleet,
    so the same check would otherwise render twice. Corrupt key types
    stringify (like the counts rollup) instead of raising."""
    return tuple(str(finding.get(k) or "") for k in ("coin", "category", "id", "ver_id"))


def merge_fleet_findings(
    slots: list[tuple],
) -> tuple:
    """Union one table from every fleet finding-slot, newest row wins.

    ``slots`` is :func:`paths.fleet_report_slots` output — (name,
    payload, mtime, meta). Returns (rows, summary) where ``rows`` keeps
    the winning dicts verbatim (table/detail code paths unchanged) and
    ``summary[name]`` is ``{"total", "shown", "mtime"}`` for the ledger
    and the provenance suffix. Ties prefer the later slot, so the merge
    is deterministic under identical mtimes (callers pass slots in
    ``FLEET_REPORTS`` order).
    """
    best: dict[tuple, tuple] = {}
    totals: dict[str, int] = {}
    mtimes: dict[str, float] = {}
    for name, payload, mtime, _meta in slots:
        rows = dict_list(payload, "findings") if isinstance(payload, dict) else []
        totals[name] = len(rows)
        mtimes[name] = mtime
        for row in rows:
            key = _merge_key(row)
            if key not in best or mtime >= best[key][1]:
                best[key] = (row, mtime, name)
    rows = [row for _key, (row, _mtime, _name) in best.items()]
    shown: dict[str, int] = dict.fromkeys(totals, 0)
    for _key, (_row, _mtime, name) in best.items():
        shown[name] += 1
    summary = {name: {"total": totals[name], "shown": shown[name], "mtime": mtimes[name]} for name in totals}
    return rows, summary


def build_coin_rows(merged: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """One row per coin: every finding for the coin aggregates here, and
    the detail pane reads the full coin report from the row.

    Each row is ``{"coin", "severity" (worst), "change", "reason",
    "count", "rows", "version"}``. ``reason`` is the worst finding's
    detail verbatim for single-finding coins, ``"N findings — <worst>"``
    otherwise. ``version`` is the first finding with a non-empty
    versions block, or None. Rows order worst severity first, then
    finding count desc, then ticker alpha, so the busiest problem
    coins read first and ties stay deterministic.
    A missing coin reads as "—", never an error.
    """
    groups: dict[str, list[dict[str, Any]]] = {}
    for row in merged:
        if not isinstance(row, dict):
            continue
        coin = str(row.get("coin") or "—")
        groups.setdefault(coin, []).append(row)
    worst_of: dict[str, dict[str, Any]] = {
        coin: min(rows, key=lambda r: severity_rank(r.get("severity"))) for coin, rows in groups.items()
    }
    coins = []
    for coin in sorted(
        groups,
        key=lambda c: (severity_rank(worst_of[c].get("severity")), -len(groups[c]), c),
    ):
        rows = groups[coin]
        worst = worst_of[coin]
        change = "—"
        version = None
        for row in rows:
            versions = row.get("versions")
            if isinstance(versions, dict) and versions:
                if version is None:
                    version = row
                candidate = _change(row)
                if candidate != "—":
                    change = candidate
                    break
        detail = str(worst.get("detail") or "")
        verdict, _evidence = split_verdict(detail, worst.get("severity"))
        reason = verdict if len(rows) == 1 else f"{len(rows)} findings — {verdict}"
        coins.append(
            {
                "coin": coin,
                "severity": str(worst.get("severity") or ""),
                "change": change,
                "reason": reason,
                "count": len(rows),
                "rows": rows,
                "version": version,
            }
        )
    return coins


def _probe_total(payload: dict[str, Any]) -> int:
    """Repos probed by a probe report, else 0 (param-check summaries are
    zeroed by contract — they must never read as the fleet summary)."""
    if not isinstance(payload, dict):
        return 0
    summary = payload.get("summary")
    total = summary.get("repos_total") if isinstance(summary, dict) else None
    return total if isinstance(total, int) and not isinstance(total, bool) else 0


def age_text(started: Any) -> str:
    """Seconds-ago for a sidecar timestamp, or "never" for anything else
    (bools excluded explicitly — True is an int instance)."""
    if isinstance(started, (int, float)) and not isinstance(started, bool):
        return f"{time.time() - started:.0f}s ago"
    return "never"


def pick_probe_report(slots: list[tuple]) -> tuple | None:
    """Newest probe slot for the fleet summary, else newest slot overall."""
    probed = [s for s in slots if _probe_total(s[1])]
    if probed:
        return max(probed, key=lambda s: s[2])
    if slots:
        return max(slots, key=lambda s: s[2])
    return None


def newest_probe_slot(cache_root: Path) -> Path | None:
    """Newest probe slot carrying version data, if any."""
    best: Path | None = None
    best_mtime = -1.0
    for name in ("findings.json", "audit.json", "analyze.json"):
        path = cache_root / name
        if not path.is_file():
            continue
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if not isinstance(payload, dict):
            continue
        meta = payload.get("meta")
        if isinstance(meta, dict) and meta.get("tickers"):
            continue
        if not isinstance(payload.get("repos"), dict) or not payload["repos"]:
            continue
        try:
            mtime = path.stat().st_mtime
        except OSError:
            continue
        if mtime > best_mtime:
            best, best_mtime = path, mtime
    return best


def param_blob(slots: list[tuple]) -> dict[str, Any]:
    """Per-coin param checks from the param-check slot, keyed by ver_id."""
    for name, payload, _mtime, _meta in slots:
        if name == "param-check.json":
            blob = payload.get("param_check")
            if isinstance(blob, dict):
                return blob
            break
    return {}


def with_embedded_fallback(extras: dict[str, tuple], slots: list[tuple]) -> dict[str, tuple]:
    """Fill missing extra slots from the newest probe report carrying them.

    Every probe persists its local cross-check and port matrix beside
    its findings, so a dedicated ports/cross-check run is not required
    before the overview names them. An explicit slot is never replaced:
    only gaps are filled, and the ledger ages keep the source honest.
    """
    out = dict(extras)
    for name, section in (("ports.json", "port_collisions"), ("cross-check.json", "local")):
        if name in out:
            continue
        best = None
        for _slot_name, payload, mtime, meta in slots:
            if not isinstance(payload, dict) or section not in payload:
                continue
            if best is None or mtime > best[1]:
                best = (payload, mtime, meta)
        if best is not None:
            out[name] = best
    return out


def _tickable(entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Entries the picker can tick: it skips non-string tickers, so scope
    math must not count them either."""
    return [e for e in entries if isinstance(e.get("ticker"), str)]


def live_tickers(selection: list[str] | None, fleet: Any) -> list[str]:
    """Ticked coins the manifest still lists, sorted and deduped."""
    if selection is None:
        return []
    return sorted({t for t in selection if t in fleet})


def split_scope(selection: list[str] | None, fleet: Any) -> tuple:
    """Live tickers plus whether the run narrows to them."""
    if selection is None:
        return None, False
    live = live_tickers(selection, fleet)
    return live, (not fleet or set(live) != set(fleet))


def scope_text(selection: list[str] | None, tickable: list[dict[str, Any]]) -> str | None:
    """``"N of M coins"`` when narrowed, else ``None`` for full fleet."""
    if selection is None:
        return None if tickable else "0 of 0 coins"
    fleet = {e["ticker"] for e in tickable}
    live = sorted({t for t in selection if t in fleet})
    if fleet and set(live) == fleet:
        return None
    return f"{len(live)} of {len(fleet) or len(tickable)} coins"


def resolve_slot_file(
    selection: list[str] | None,
    tickable: list[dict[str, Any]],
    cache_root: Path,
    scoped_name: str,
    fleet_name: str,
) -> tuple:
    """Report file for the scope: the scoped slot when narrowed, else fleet."""
    fleet = {e["ticker"] for e in tickable}
    live = [] if selection is None else sorted({t for t in selection if t in fleet})
    scoped = selection is not None and (not fleet or set(live) != fleet)
    names = [scoped_name, fleet_name] if scoped else [fleet_name]
    existing = [cache_root / name for name in names if (cache_root / name).is_file()]
    plan_path = max(existing, key=lambda p: p.stat().st_mtime) if existing else cache_root / names[0]
    return plan_path, scoped, live


def pick_plan_source(resolved: Path | None, applied: Path | None) -> Path | None:
    """Plan file to display: the applied set wins when strictly newer."""
    if applied is not None and applied.is_file():
        if resolved is None or not resolved.is_file():
            return applied
        try:
            if applied.stat().st_mtime > resolved.stat().st_mtime:
                return applied
        except OSError:
            return resolved
    return resolved


def resolve_plan_slot(
    selection: list[str] | None,
    tickable: list[dict[str, Any]],
    cache_root: Path,
) -> tuple:
    """Plan file for the scope plus whether the scope narrows it."""
    return resolve_slot_file(selection, tickable, cache_root, "plan-fix.scoped.json", "plan-fix.json")


def filter_plan_to_scope(plan: list[dict[str, Any]], live: list[str], *, scoped: bool) -> list[dict[str, Any]]:
    """Narrowed views show only rows the scope will touch."""
    if scoped:
        return [e for e in plan if e.get("coin") in live or e.get("action") == "scaffold"]
    return plan


def scoped_subset_for_apply(
    plan: list[dict[str, Any]], selection: list[str] | None, fleet: Any
) -> list[dict[str, Any]]:
    """Entries the apply run will actually perform under the scope."""
    if selection is None:
        return list(plan)
    live = set(selection) & set(fleet)
    return [e for e in plan if e.get("coin") in live or e.get("action") == "scaffold"]


def staged_open_entries(payload: Any) -> list[dict[str, Any]]:
    """Unapplied staged entries from a scaffold/delist report, if any."""
    plan = payload if isinstance(payload, list) else payload.get("plan") if isinstance(payload, dict) else None
    if not isinstance(plan, list):
        return []
    return [
        e for e in plan if isinstance(e, dict) and e.get("action") in ("scaffold", "delist") and not e.get("applied")
    ]


def apply_files(entries: list[dict[str, Any]]) -> list[str]:
    """Sorted files the entries touch, for the confirm dialog."""
    return sorted({str(f) for f in (e.get("file") for e in entries) if f is not None})


_FINDINGS_VERBS = ("audit", "findings", "param-check", "analyze")
_PLAN_VERBS = ("plan-fix", "apply-fix", "update-versions", "scaffold", "apply-plan", "delist")


def _read_report(primary: Path) -> tuple[dict[str, Any], list[dict[str, Any]], list[dict[str, Any]]]:
    """Report JSON sanitized to ``(report, finding rows, plan rows)``.

    A missing or unreadable report is an empty one, and non-dict rows are
    dropped: the finish line is operator language, never a traceback.
    """
    try:
        report = json.loads(primary.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        report = {}
    if not isinstance(report, dict):
        report = {}
    raw_findings = report.get("findings")
    findings = [f for f in raw_findings if isinstance(f, dict)] if isinstance(raw_findings, list) else []
    raw_plan = report.get("plan")
    plan = [p for p in raw_plan if isinstance(p, dict)] if isinstance(raw_plan, list) else []
    return report, findings, plan


def _counts_ports(report: dict[str, Any]) -> str:
    """Port-matrix verbs report distinct collision rows, not findings."""
    collisions = report.get("port_collisions")
    n = len(collisions) if isinstance(collisions, dict) else 0
    return f"{n} collision{'s' if n != 1 else ''}" if n else "no collisions"


def cross_check_counts(local: dict[str, Any]) -> tuple[int, int]:
    """(missing, orphaned) counts from a cross-check report's local slot.

    The cross-check verb and the overview ledger both show these two
    buckets; one implementation keeps the numbers identical.
    """
    missing = sum(
        len(entries)
        for key in ("missing_wallet_conf", "missing_xbridge_conf", "missing_base_j2")
        for entries in [local.get(key)]
        if isinstance(entries, list)
    )
    orphans = local.get("orphans")
    orphaned = (
        sum(len(entries) for entries in orphans.values() if isinstance(entries, list))
        if isinstance(orphans, dict)
        else 0
    )
    return missing, orphaned


def _counts_cross_check(report: dict[str, Any]) -> str:
    """Cross-check reports its two local-consistency buckets."""
    local = report.get("local")
    missing, orphaned = cross_check_counts(local) if isinstance(local, dict) else (0, 0)
    return f"missing {missing} · orphans {orphaned}" if missing or orphaned else "clean, nothing to decide"


def _counts_findings(findings: list[dict[str, Any]]) -> str:
    """Findings count with the severity breakdown, worst bucket first."""
    by_sev: dict[str, int] = {}
    for found in findings:
        sev = str(found.get("severity") or "?")
        by_sev[sev] = by_sev.get(sev, 0) + 1
    breakdown = ", ".join(f"{count} {sev}" for sev, count in sorted(by_sev.items()))
    return f"{len(findings)} finding{'s' if len(findings) != 1 else ''} ({breakdown})"


def _counts_plan(plan: list[dict[str, Any]]) -> str:
    return f"{len(plan)} planned write{'s' if len(plan) != 1 else ''}"


# Verbs whose count comes from their own report section rather than
# findings/plan; every other verb falls through to findings-then-plan.
_VERB_COUNTS = {
    "ports": _counts_ports,
    "cross-check": _counts_cross_check,
}


def _verb_counts(
    name: str,
    report: dict[str, Any],
    findings: list[dict[str, Any]],
    plan: list[dict[str, Any]],
) -> str:
    counter = _VERB_COUNTS.get(name)
    if counter is not None:
        return counter(report)
    if findings:
        return _counts_findings(findings)
    if plan:
        return _counts_plan(plan)
    return "clean, nothing to decide"


def _applied_refused(primary: Path) -> tuple[int, int]:
    """``(applied, total)`` plan rows in the report, for apply-plan only."""
    try:
        loaded = json.loads(primary.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        loaded = {}
    rows = loaded.get("plan") if isinstance(loaded, dict) else loaded
    if not isinstance(rows, list):
        return 0, 0
    done = sum(1 for r in rows if isinstance(r, dict) and r.get("applied"))
    total = sum(1 for r in rows if isinstance(r, dict))
    return done, total


def _destination_line(name: str, primary: Path, counts: str) -> str:
    """Where the run's output went: a named data tab, or the log only."""
    if name in _FINDINGS_VERBS:
        return f"--- {name} done: {counts} → Findings tab · {primary.name} ---"
    if name in _PLAN_VERBS:
        line = f"--- {name} done: {counts} → Plan tab · {primary.name} ---"
        if name == "apply-plan":
            done, total = _applied_refused(primary)
            if total:
                line = line.replace(counts, f"applied {done}, refused {total - done}", 1)
            line += " — next: regenerate rendered confs (autobuild) and review git diff"
        return line
    if name in ("ports", "cross-check"):
        return f"--- {name} done: {counts} → overview · {primary.name} ---"
    return f"--- {name} done: {counts} → {primary.name} (Log only) ---"


def _finish_line(name: str, tickers: str | None, primary: Path) -> str:
    """One human finish line: what ran, what it found, where it went.

    Exit codes are not operator language: rc 0 and 1 both land here as
    "done" with counts. A scoped run names its slot and says the fleet
    views are unchanged; a fleet run with a data tab names it.
    """
    report, findings, plan = _read_report(primary)
    counts = _verb_counts(name, report, findings, plan)
    if tickers:
        n = len([t for t in tickers.split(",") if t.strip()])
        scope = f"{n} coin{'s' if n != 1 else ''}"
        return f"--- {name} done ({scope}): {counts} → {primary.name} — fleet views unchanged ---"
    return _destination_line(name, primary, counts)


def _strip_note(name: str, tickers: str | None) -> str:
    if tickers:
        n = len([t for t in tickers.split(",") if t.strip()])
        return f"{name} ({n} coin{'s' if n != 1 else ''}) → log"
    dest = (
        "Findings tab"
        if name in _FINDINGS_VERBS
        else "Plan tab"
        if name in _PLAN_VERBS
        else "overview"
        if name in ("ports", "cross-check")
        else "Log"
    )
    return f"{name} → {dest}"
