"""Plan derivation and application for config fixes, ports and versions.

Derivation never writes: every ``plan_*`` helper reads the tree and
returns ``(entries, note)`` with ``applied=False``. Application never
derives: ``apply_plan.apply_entries`` executes reviewed entries with
per-entry ``old`` verification. The ``apply_*`` aggregators below keep
their names and signatures and compose the two halves, so reports,
console text and exit codes are unchanged in both modes.
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any, Callable, NamedTuple

from .apply_plan import apply_entries, key_present, manifest_target
from .checkout import SourceCheckoutManager, SourceReader
from .constants import FEE_REF_SIZE, logger
from .model import ManifestCoin, chain_floor, recommended_fees
from .params import fee_constants_for_coin, fee_policy_for_coin
from .ports import PortCollisionManager
from .probe import SystemCommandRunner
from .progress import emit
from .reporting import report_line
from .util import norm_port_value, plan_entry, repo_relative
from .versioning import (
    VersionEngine,
    apply_additive_bump,
    build_update_version_names,
    should_skip_version_bump,
)


class ConfigAutoFixer:
    """Applies safe in-place fixes to wallet/XBridge configuration files."""

    @staticmethod
    def plan_missing_txindex(repo_root: Path, coin: ManifestCoin) -> tuple[list[dict[str, Any]], str | None]:
        wpath = repo_root / "wallet-confs" / coin.wallet_conf
        try:
            txt = SourceReader.slurp(wpath)
            if txt is None:
                return [], None
            if not key_present(txt, "txindex", section_aware=False):
                return [
                    plan_entry(
                        repo_relative(wpath, repo_root),
                        "txindex",
                        None,
                        "1",
                        "txindex absent from the wallet conf",
                        "txindex",
                        coin=coin.ticker,
                        ver_id=coin.ver_id,
                        applied=False,
                    )
                ], f"PLAN {coin.ticker}: would write txindex=1 to {wpath}"
        except OSError as e:
            logger.error("Failed reading txindex state from %s: %s", wpath, e)
        return [], None

    @staticmethod
    def plan_normalize_dust(repo_root: Path, coin: ManifestCoin) -> tuple[list[dict[str, Any]], str | None]:
        xpath = repo_root / "xbridge-confs" / coin.xbridge_conf
        try:
            txt = SourceReader.slurp(xpath)
            if txt is None:
                return [], None
            old_val: str | None = None
            for line in txt.splitlines():
                if re.match(r"^\s*DustAmount\s*=", line, flags=re.I):
                    old_val = line.split("=", 1)[1].strip() if "=" in line else None
                    break
            return [
                plan_entry(
                    repo_relative(xpath, repo_root),
                    "DustAmount",
                    old_val,
                    "0",
                    "dust placeholder is ignored by the blocknet loader",
                    "dust",
                    coin=coin.ticker,
                    ver_id=coin.ver_id,
                    applied=False,
                )
            ], f"PLAN {coin.ticker}: would normalize DustAmount in {xpath}"
        except OSError as e:
            logger.error("Failed reading DustAmount state from %s: %s", xpath, e)
        return [], None

    @staticmethod
    def plan_remove_deprecatedrpc(repo_root: Path, coin: ManifestCoin) -> tuple[list[dict[str, Any]], str | None]:
        wpath = repo_root / "wallet-confs" / coin.wallet_conf
        try:
            txt = SourceReader.slurp(wpath)
            if txt is None:
                return [], None
            removed_lines = [
                line.strip() for line in txt.splitlines() if re.match(r"^\s*deprecatedrpc\s*=", line, flags=re.I)
            ]
            if removed_lines:
                return [
                    plan_entry(
                        repo_relative(wpath, repo_root),
                        "deprecatedrpc",
                        ", ".join(removed_lines),
                        None,
                        "deprecatedrpc flag does nothing upstream",
                        "deprecatedrpc",
                        coin=coin.ticker,
                        ver_id=coin.ver_id,
                        applied=False,
                    )
                ], f"PLAN {coin.ticker}: would remove {len(removed_lines)} stale deprecatedrpc line(s) from {wpath}"
        except OSError as e:
            logger.error("Failed reading deprecatedrpc state from %s: %s", wpath, e)
        return [], None

    @staticmethod
    def plan_fee_margin(  # noqa: C901, PLR0911  # fee planner: each return is a distinct resolve/parse refusal, logged before it
        repo_root: Path, coin: ManifestCoin
    ) -> tuple[list[dict[str, Any]], str | None]:
        try:
            mgr = SourceCheckoutManager()
            tag = VersionEngine.max_version_tag(set(coin.versions)) if coin.versions else ""
            if not tag:
                logger.warning("FIX-FEES %s: no declared versions, cannot resolve source", coin.ticker)
                return [], None
            try:
                src_dir, mode = mgr.resolve_source(coin, tag, timeout=60)
            except ValueError as exc:
                # Same contract as param-check: an unusable ticker is
                # data, not a crash — name it as such instead of the
                # generic failure line below.
                logger.error("FIX-FEES %s: %s", coin.ticker, exc)
                return [], None
            if not src_dir or mode.startswith(("clone-", "fetch-", "no-")):
                logger.warning("FIX-FEES %s: cannot resolve source for %s", coin.ticker, tag)
                return [], None
            rate, rate_ev, _, _ = fee_constants_for_coin(coin, src_dir)
            policy = fee_policy_for_coin(coin, src_dir)
            if policy.rounding == "unknown":
                logger.warning("FIX-FEES %s: fee policy not parseable (%s)", coin.ticker, "; ".join(policy.evidence))
                return [], None
            if rate is None or rate == 0:
                logger.warning("FIX-FEES %s: relay not found", coin.ticker)
                return [], None
            rec_min, fpb = recommended_fees(policy, rate)
            target_fee = rec_min
            floor_452 = chain_floor(policy, rate, FEE_REF_SIZE)
            xpath = repo_root / "xbridge-confs" / coin.xbridge_conf
            txt = SourceReader.slurp(xpath)
            if txt is None:
                return [], None
            old_mtf: str | None = None
            old_fpb: str | None = None
            for line in txt.splitlines():
                if re.match(r"^\s*MinTxFee\s*=", line, flags=re.I):
                    old_mtf = line.split("=", 1)[1].strip() if "=" in line else None
                elif re.match(r"^\s*FeePerByte\s*=", line, flags=re.I):
                    old_fpb = line.split("=", 1)[1].strip() if "=" in line else None
            return plan_fee_entries(
                old_mtf,
                old_fpb,
                target_fee,
                fpb,
                repo_relative(xpath, repo_root),
                coin.ticker,
                coin.ver_id,
                rate_ev,
            ), (
                f"PLAN-FEES {coin.ticker}: would set MinTxFee={target_fee} "
                f"FeePerByte={fpb} (rate {rate} floor452 {floor_452} "
                f"model {policy.rounding} {rate_ev or ''}"
            )
        except Exception as e:
            logger.error("FIX-FEES %s failed: %s", coin.ticker, e)
            return [], None


def plan_fee_entries(  # noqa: PLR0913, PLR0917  # plan-entry schema family: one field per plan column
    old_mtf: str | None,
    old_fpb: str | None,
    target_fee: int,
    fpb: int,
    file_rel: str,
    ticker: str,
    ver_id: str,
    evidence: str | None = None,
) -> list[dict[str, Any]]:
    """Two scalar fee entries from one composite derivation."""
    return [
        plan_entry(
            file_rel,
            "MinTxFee",
            old_mtf,
            target_fee,
            "rewrite fees to the strict chain gates from source",
            "fees",
            coin=ticker,
            ver_id=ver_id,
            evidence=evidence,
            applied=False,
        ),
        plan_entry(
            file_rel,
            "FeePerByte",
            old_fpb,
            fpb,
            "rewrite fees to the strict chain gates from source",
            "fees",
            coin=ticker,
            ver_id=ver_id,
            evidence=evidence,
            applied=False,
        ),
    ]


def _conf_fix_work_items(
    param_results: dict[str, Any], manifest: list[ManifestCoin]
) -> list[tuple[str, dict[str, Any], ManifestCoin]]:
    """``(key, result, coin)`` for every real result file a manifest coin answers.

    Metadata keys ("_collisions" …) are not conf files and are filtered so
    the progress total counts real files; keys no manifest coin answers (a
    manifest edited mid-run) are dropped so the index stays dense.
    """
    work: list[tuple[str, dict[str, Any], ManifestCoin]] = []
    for key, res_dict in param_results.items():
        if key.startswith("_"):
            continue
        coin = next((c for c in manifest if key in {c.ver_id, c.ticker}), None)
        if coin is not None:
            work.append((key, res_dict, coin))
    return work


# One table: the `fixable` kind a checker attaches -> the planner it authorizes.
_FIXABLE_PLANNERS = {
    "txindex": ConfigAutoFixer.plan_missing_txindex,
    "dust": ConfigAutoFixer.plan_normalize_dust,
    "deprecatedrpc": ConfigAutoFixer.plan_remove_deprecatedrpc,
    "fees": ConfigAutoFixer.plan_fee_margin,
}


def _execute_plan(
    plan: list[dict[str, Any]],
    repo_root: Path,
    runner: SystemCommandRunner,
    prefix: str,
    manifest_path: Path | None = None,
) -> None:
    """Execute the reviewed entries, then report per-entry refusals."""
    apply_entries(plan, repo_root, runner, regenerate=False, manifest_path=manifest_path)
    for e in plan:
        if not e.get("applied"):
            report_line(f"{prefix}refused {e.get('coin')}: {e.get('file')} {e.get('key')} — {e.get('error')}")


def apply_conf_fixes(  # noqa: PLR0913, PLR0917  # fix-aggregator inputs: one per fix knob
    args: argparse.Namespace,
    manifest: list[ManifestCoin],
    param_results: dict[str, Any] | None,
    repo_root: Path,
    runner: SystemCommandRunner,
    manifest_path: Path | None = None,
) -> list[dict[str, Any]]:
    """Derive --write-config / --fee-write fixes from param findings.

    Returns the plan entries. Derivation never writes: entries come
    back with ``applied=False`` and the optional note carries the
    preview line. Under ``--dry-run`` the notes print and nothing else
    happens; otherwise ``apply_plan`` executes the reviewed entries.
    """
    dry_run = bool(getattr(args, "dry_run", False))
    plan: list[dict[str, Any]] = []
    if not ((args.write_config or args.fee_write) and param_results is not None):
        return plan

    work = _conf_fix_work_items(param_results, manifest)
    for idx, (_key, res_dict, coin) in enumerate(work, 1):
        emit("conf-fixes", index=idx, total=len(work), ticker=coin.ticker)
        for chk_dict in res_dict.get("checks", []):
            if args.fee_write and chk_dict["id"] != "FEES":
                continue
            # Dispatch keys off the checker-attached `fixable` kind only.
            # Message text is human-facing and must never gate behavior.
            planner = _FIXABLE_PLANNERS.get(chk_dict.get("fixable"))
            if planner is None:
                continue
            entries, note = planner(repo_root, coin)
            if dry_run and note:
                report_line(note)
            for entry in entries:
                if entry:
                    plan.append(entry)

    if dry_run:
        return plan
    _execute_plan(plan, repo_root, runner, "  ", manifest_path)
    return plan


def _reassign_single_port(  # noqa: PLR0913  # reassignment inputs, keyword-only at the call site
    *,
    coin: ManifestCoin,
    repo_root: Path,
    used_p2p: set[int],
    used_rpc: set[int],
    verb: str,
    fixed_ports: list[str],
    record: Callable[[list[dict[str, Any]], ManifestCoin], None],
    kind: str,
    key: str,
    used: set[int],
    plan_calls: Callable[..., tuple],
) -> tuple[int, int] | None:
    """Reassign one coin's single port to the nearest free candidate.

    Returns ``(src, cand)`` on success — the caller logs the exact move,
    since the p2p and rpc families report different detail — and None when
    the collision stays (unparseable conf, or no free port near source).
    """
    t = coin.ticker
    wpath = repo_root / "wallet-confs" / coin.wallet_conf
    top = SourceReader.parse_conf_sections(wpath).get("", {})
    try:
        src = int(norm_port_value(top.get(key, "0")))
    except ValueError:
        logger.warning("%s %s: unparseable %s port — collision stays", verb, t, kind)
        report_line(f"  unparseable {kind} port {t}: collision stays")
        return None
    cand = PortCollisionManager.find_free_single(src, used_p2p, used_rpc, exclude_self=src)
    if not cand:
        logger.warning("%s %s: crowded out, no free %s near %s — collision stays", verb, t, kind, src)
        report_line(f"  crowded out {t}: no free {kind} near {src} — collision stays")
        return None
    for entries, _ in plan_calls(cand):
        record(entries, coin)
    used.add(cand)
    fixed_ports.append(t)
    return src, cand


def _port_losers_by_lineage(
    occupancy: list[ManifestCoin],
    repo_root: Path,
    collisions: dict[int, list[str]],
    *,
    kind: str,
    key: str,
) -> set[str]:
    """Earliest-lineage survivor per duplicated port; the rest are losers.

    ``kind``/``key`` label the port family and the conf key ("p2p"/"port",
    "rpc"/"rpcport"). An unknown lineage date sorts last, so a conf that
    cannot prove it was first never wins the port.
    """
    losers: set[str] = set()
    for port, tickers in collisions.items():
        dated = []
        for t in tickers:
            c = next((item for item in occupancy if item.ticker == t), None)
            d = SourceReader.lineage_date(repo_root, f"wallet-confs/{c.wallet_conf}", key) if c else None
            dated.append((d or "9999-99-99", t))
        dated.sort()
        keep = dated[0][1]
        losers_t = [t for _, t in dated[1:]]
        logger.info("%s %s: keep %s (%s), reassign %s", kind, port, keep, dated[0][0], ", ".join(losers_t))
        losers.update(losers_t)
    return losers


class _PortFixState(NamedTuple):
    """Everything the loser loops need: occupancy, used sets, loser sets."""

    used_p2p: set[int]
    used_rpc: set[int]
    p2p_losers: set[str]
    rpc_losers: set[str]


def _port_fix_state(occupancy: list[ManifestCoin], repo_root: Path) -> _PortFixState:
    """Used-port sets and lineage losers from the fleet's collisions."""
    coll_maps = PortCollisionManager.collect_port_collisions(occupancy, repo_root)
    used_p2p = set(coll_maps["p2p"].keys()) | set(coll_maps["test_p2p"].keys())
    used_rpc = set(coll_maps["rpc"].keys()) | set(coll_maps["test_rpc"].keys()) | set(coll_maps["xbridge"].keys())
    dup_p2p = {p: ts for p, ts in coll_maps["p2p"].items() if len(ts) > 1}
    dup_rpc = {p: ts for p, ts in coll_maps["rpc"].items() if len(ts) > 1}
    p2p_losers = _port_losers_by_lineage(occupancy, repo_root, dup_p2p, kind="p2p", key="port")
    rpc_losers = _port_losers_by_lineage(occupancy, repo_root, dup_rpc, kind="rpc", key="rpcport")
    return _PortFixState(used_p2p, used_rpc, p2p_losers, rpc_losers)


def _reassign_paired_loser(  # noqa: PLR0913, PLR0917  # one input per reassignment axis
    state: _PortFixState,
    ticker: str,
    coin: ManifestCoin,
    repo_root: Path,
    verb: str,
    record: Callable[[list[dict[str, Any]], ManifestCoin], None],
    fixed_ports: list[str],
) -> None:
    """Move one p2p+rpc paired loser to a free pair near its own ports."""
    wpath = repo_root / "wallet-confs" / coin.wallet_conf
    xpath = repo_root / "xbridge-confs" / coin.xbridge_conf
    top = SourceReader.parse_conf_sections(wpath).get("", {})
    try:
        src_p2p = int(norm_port_value(top.get("port", "0")))
        src_rpc = int(norm_port_value(top.get("rpcport", "0")))
    except ValueError:
        logger.warning("%s %s: unparseable ports — collision stays", verb, ticker)
        report_line(f"  unparseable ports {ticker}: collision stays")
        return

    cand_p2p, cand_rpc = PortCollisionManager.find_free_pair(src_p2p, src_rpc, state.used_p2p, state.used_rpc)
    if not (cand_p2p and cand_rpc):
        logger.warning(
            "%s %s: crowded out, no free p2p/rpc pair near %s/%s — collision stays", verb, ticker, src_p2p, src_rpc
        )
        report_line(f"  crowded out {ticker}: no free p2p/rpc pair near {src_p2p}/{src_rpc} — collision stays")
        return

    logger.info("%s %s: p2p %s->%s rpc %s->%s paired", verb, ticker, src_p2p, cand_p2p, src_rpc, cand_rpc)
    for entries, _ in (
        PortCollisionManager.plan_wallet_key(wpath, "port", cand_p2p, repo_root=repo_root),
        PortCollisionManager.plan_wallet_key(wpath, "rpcport", cand_rpc, repo_root=repo_root),
        PortCollisionManager.plan_xbridge_port(xpath, cand_rpc, repo_root=repo_root),
    ):
        record(entries, coin)
    state.used_p2p.add(cand_p2p)
    state.used_rpc.add(cand_rpc)
    fixed_ports.append(ticker)


def _reassign_single_losers(  # noqa: PLR0913, PLR0917  # one input per reassignment axis
    state: _PortFixState,
    manifest: list[ManifestCoin],
    repo_root: Path,
    verb: str,
    record: Callable[[list[dict[str, Any]], ManifestCoin], None],
    fixed_ports: list[str],
) -> None:
    """Walk both single-port loser families (p2p, then rpc)."""
    paired = state.p2p_losers & state.rpc_losers
    for kind, key, used, losers in (
        ("p2p", "port", state.used_p2p, state.p2p_losers - paired),
        ("rpc", "rpcport", state.used_rpc, state.rpc_losers - paired),
    ):
        for t in sorted(losers):
            if t in fixed_ports:
                continue
            c = next((item for item in manifest if item.ticker == t), None)
            if not c:
                continue
            _reassign_single_loser(state, t, c, repo_root, verb, record, fixed_ports, kind=kind, key=key, used=used)


def _reassign_single_loser(  # noqa: PLR0913, PLR0917  # one input per reassignment axis
    state: _PortFixState,
    ticker: str,
    coin: ManifestCoin,
    repo_root: Path,
    verb: str,
    record: Callable[[list[dict[str, Any]], ManifestCoin], None],
    fixed_ports: list[str],
    *,
    kind: str,
    key: str,
    used: set[int],
) -> None:
    """Move one single-port loser (p2p or rpc family) to the nearest free port."""
    wpath = repo_root / "wallet-confs" / coin.wallet_conf
    xpath = repo_root / "xbridge-confs" / coin.xbridge_conf
    plan_calls: Callable[..., tuple]
    if kind == "p2p":
        plan_calls = lambda cand, wpath=wpath: (  # noqa: E731
            PortCollisionManager.plan_wallet_key(wpath, key, cand, repo_root=repo_root),
        )
    else:
        plan_calls = lambda cand, wpath=wpath, xpath=xpath: (  # noqa: E731
            PortCollisionManager.plan_wallet_key(wpath, key, cand, repo_root=repo_root),
            PortCollisionManager.plan_xbridge_port(xpath, cand, repo_root=repo_root),
        )
    moved = _reassign_single_port(
        coin=coin,
        repo_root=repo_root,
        used_p2p=state.used_p2p,
        used_rpc=state.used_rpc,
        verb=verb,
        fixed_ports=fixed_ports,
        record=record,
        kind=kind,
        key=key,
        used=used,
        plan_calls=plan_calls,
    )
    if moved and kind == "p2p":
        logger.info("%s %s: p2p %s->%s", verb, ticker, moved[0], moved[1])
    elif moved:
        logger.info("%s %s: rpc %s->%s xbridge Port->%s", verb, ticker, moved[0], moved[1], moved[1])


def apply_port_fixes(  # noqa: PLR0913, PLR0917  # fix inputs: one per fix knob
    args: argparse.Namespace,
    manifest: list[ManifestCoin],
    param_results: dict[str, Any] | None,
    repo_root: Path,
    runner: SystemCommandRunner,
    fleet_manifest: list[ManifestCoin] | None = None,
    manifest_path: Path | None = None,
) -> list[dict[str, Any]]:
    """Apply --fix-ports reallocation (earliest lineage survives).

    Returns the plan entries. The candidate ports are
    chosen identically in dry-run mode and fed back into the used-sets, so a
    preview shows exactly the assignments a real run would make.

    Port occupancy is a fleet fact, not a scope fact: ``fleet_manifest``
    (the unfiltered fleet, when the caller has one) decides which ports
    look taken, so a ``--ticker``-scoped run never hands a coin a port
    that an unselected coin already holds — the same principle the port
    matrix states for itself. Writes stay scoped to ``manifest``: a
    fleet member outside the scope can hold a port but is never edited.
    Without a fleet manifest the caller's manifest *is* the fleet.
    """
    dry_run = bool(getattr(args, "dry_run", False))
    verb = "PLAN" if dry_run else "FIX"
    fixed_ports: list[str] = []
    plan: list[dict[str, Any]] = []

    def record(entries: list[dict[str, Any]], coin: ManifestCoin) -> None:
        for e in entries:
            if e:
                e["coin"] = coin.ticker
                e["ver_id"] = coin.ver_id
                plan.append(e)

    if args.fix_ports and param_results is not None:
        logger.info(
            "FIX-PORTS: earliest lineage survivor, paired scan reallocation%s",
            " (dry-run, nothing written)" if dry_run else "",
        )
        # Occupancy and keep/loser lineage are fleet facts (see the
        # docstring); writes stay scoped: the loops below resolve coins
        # in `manifest`, so an out-of-scope member is never edited.
        occupancy = fleet_manifest if fleet_manifest is not None else manifest
        state = _port_fix_state(occupancy, repo_root)

        for t in sorted(state.p2p_losers & state.rpc_losers):
            c = next((item for item in manifest if item.ticker == t), None)
            if not c:
                continue
            _reassign_paired_loser(state, t, c, repo_root, verb, record, fixed_ports)

        _reassign_single_losers(state, manifest, repo_root, verb, record, fixed_ports)

        if dry_run:
            return plan
        _execute_plan(plan, repo_root, runner, "  ", manifest_path)
        return plan

    return plan


def read_probe_repos(path: Path) -> tuple[dict[str, Any], str | None]:
    """Repos section of a probe report for --versions-from.

    Returns ``(repos, note)``: an unreadable or wrong-shaped slot
    yields ``({}, note)`` with the notice text, never guessed data.
    """
    try:
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}, f"NOTE: --versions-from {path} unreadable — version bumps skipped"
    repos = payload.get("repos") if isinstance(payload, dict) else None
    if not isinstance(repos, dict):
        return {}, f"NOTE: --versions-from {path} carries no repos section — version bumps skipped"
    return repos, None


def plan_delist_entries(
    coin: ManifestCoin,
    repo_root: Path,
    manifest_path: Path | None = None,
) -> tuple[list[dict[str, Any]], str | None]:
    """Removal entries for one coin: manifest splice plus every coin file."""
    manifest_rel = repo_relative(manifest_target(repo_root, manifest_path), repo_root)
    entries: list[dict[str, Any]] = [
        plan_entry(
            manifest_rel,
            coin.ticker,
            coin.ver_id,
            None,
            f"remove {coin.ticker} from the fleet",
            "delist",
            coin=coin.ticker,
            ver_id=coin.ver_id,
            applied=False,
        )
    ]
    missing: list[str] = []
    for rel in (
        f"wallet-confs/{coin.wallet_conf}",
        f"xbridge-confs/{coin.xbridge_conf}",
        f"autobuild/configs/{(coin.ticker or '').lower()}.base.j2",
    ):
        if (repo_root / rel).is_file():
            entries.append(
                plan_entry(
                    rel,
                    "*",
                    None,
                    None,
                    f"remove {coin.ticker} {rel}",
                    "delist",
                    coin=coin.ticker,
                    ver_id=coin.ver_id,
                    applied=False,
                )
            )
        else:
            missing.append(rel)
    note = None
    if missing:
        note = f"NOTE: delist {coin.ticker}: {', '.join(missing)} absent — nothing to remove there"
    return entries, note


def _collapse_plan_entries(
    item: dict[str, Any], ticker: str, target: str, repo_root: Path, manifest_path: Path | None = None
) -> tuple[list[dict[str, Any]], list[str]]:
    """Collapse one manifest item to target: rename confs, copy them forward.

    Returns (plan entries, report lines). The collapse entry is always
    first; each conf copy follows only when the target does not exist
    yet, and an existing target is reported rather than overwritten. Once
    the conf is copied its superseded original is planned for removal, so
    the rename completes instead of leaving an orphan behind.
    """
    old_ver_id = item.get("ver_id", "")
    old_wc = item.get("wallet_conf", "")
    old_xc = item.get("xbridge_conf", "")
    new_ver_id, new_wc, new_xc = build_update_version_names(ticker, old_ver_id, old_wc, old_xc, target)
    entries: list[dict[str, Any]] = []
    collapse = plan_entry(
        repo_relative(manifest_target(repo_root, manifest_path), repo_root),
        f"{ticker}",
        f"{old_ver_id} ({old_wc}, {old_xc})",
        f"{new_ver_id} ({new_wc}, {new_xc})",
        f"collapse versions to {target} and rename confs",
        "versions",
        coin=ticker,
        ver_id=new_ver_id,
        applied=False,
    )
    collapse["target"] = target
    collapse["old_ver_id"] = old_ver_id
    collapse["old_wallet_conf"] = old_wc
    collapse["old_xbridge_conf"] = old_xc
    entries.append(collapse)
    notes: list[str] = []
    old_w_path = repo_root / "wallet-confs" / old_wc
    new_w_path = repo_root / "wallet-confs" / new_wc
    old_x_path = repo_root / "xbridge-confs" / old_xc
    new_x_path = repo_root / "xbridge-confs" / new_xc
    for src_p, dst_p, label in (
        (old_w_path, new_w_path, "wallet"),
        (old_x_path, new_x_path, "xbridge"),
    ):
        if src_p.is_file() and not dst_p.is_file():
            entries.append(
                plan_entry(
                    repo_relative(dst_p, repo_root),
                    "*",
                    None,
                    f"copy of {src_p.name}",
                    f"copy {label} conf forward for the new version",
                    "versions",
                    coin=ticker,
                    ver_id=new_ver_id,
                    applied=False,
                )
            )
        elif dst_p.is_file():
            notes.append(
                f"  UPDATE-VERSIONS {ticker}: target {dst_p.name} already exists — kept as-is (verify content)"
            )
        if src_p.is_file() and src_p != dst_p:
            entries.append(
                plan_entry(
                    repo_relative(src_p, repo_root),
                    "-",
                    src_p.name,
                    None,
                    f"remove superseded {label} conf after the rename",
                    "versions",
                    coin=ticker,
                    ver_id=new_ver_id,
                    applied=False,
                )
            )
    return entries, notes


def plan_version_bumps(  # noqa: C901, PLR0912  # deep derivation nest: additive and replace branches share loop state
    args: argparse.Namespace,
    manifest_path: Path,
    report_repos: dict[str, Any],
    repo_root: Path,
) -> tuple[list[str], list[dict[str, Any]]]:
    """Derive --update-versions / --replace-versions entries; writes nothing.

    Returns ``(tickers bumped, plan entries)``. Manifest and conf
    mutations are computed against in-memory copies only. Lines that
    read identically in both modes print here; mode-dependent lines
    belong to the caller (dry summary) and the applier (copies).
    """
    updated_tickers: list[str] = []
    plan: list[dict[str, Any]] = []
    if args.update_versions:
        try:
            raw_text = SourceReader.slurp(manifest_path)
            if raw_text:
                raw_manifest = json.loads(raw_text)
                for _url, rdata in report_repos.items():
                    if rdata.get("status") not in ("ALIVE", "MOVED"):
                        continue
                    if should_skip_version_bump(rdata):
                        skipped = sorted({e.get("ticker", "?") for e in rdata.get("entries", [])})
                        report_line(
                            f"  UPDATE-VERSIONS skip {', '.join(skipped)}: mandatory hard fork — manual "
                            f"replacement required"
                        )
                        continue
                    if not rdata.get("newer_same") and not rdata.get("newer_alt"):
                        continue
                    target = rdata.get("remote_latest")
                    if not target:
                        continue
                    for entry in rdata.get("entries", []):
                        ticker = entry.get("ticker")
                        if not ticker:
                            continue
                        for item in raw_manifest:
                            if item.get("ticker") != ticker:
                                continue
                            old_versions = list(item.get("versions") or [])
                            if not args.replace_versions:
                                if apply_additive_bump(item, target):
                                    report_line(
                                        f"  UPDATE-VERSIONS {ticker}: appended {target} (kept "
                                        f"{item.get('ver_id', '')} confs)"
                                    )
                                    updated_tickers.append(ticker)
                                    plan.append(
                                        plan_entry(
                                            repo_relative(manifest_target(repo_root, manifest_path), repo_root),
                                            f"{ticker}.versions",
                                            ", ".join(old_versions),
                                            ", ".join(item.get("versions") or []),
                                            f"append latest upstream tag {target}; existing versions stay buildable",
                                            "versions",
                                            coin=ticker,
                                            ver_id=item.get("ver_id"),
                                            applied=False,
                                        )
                                    )
                                continue
                            if (
                                target in old_versions
                                and len(old_versions) == 1
                                and item.get("ver_id", "").endswith(target)
                            ):
                                continue
                            collapse_entries, collapse_notes = _collapse_plan_entries(
                                item, ticker, target, repo_root, manifest_path
                            )
                            plan.extend(collapse_entries)
                            for note in collapse_notes:
                                report_line(note)
                            updated_tickers.append(ticker)
        except Exception as e:
            logger.error("UPDATE-VERSIONS failed: %s", e)
    return updated_tickers, plan


def apply_version_bumps(
    args: argparse.Namespace,
    manifest_path: Path,
    report_repos: dict[str, Any],
    repo_root: Path,
    runner: SystemCommandRunner,
) -> list[dict[str, Any]]:
    """Preview or apply --update-versions / --replace-versions.

    Returns the plan entries. Derivation never writes; under
    ``--dry-run`` the planned copies print and nothing else happens,
    otherwise the applier executes the reviewed entries.
    """
    dry_run = bool(getattr(args, "dry_run", False))
    verb = "would bump" if dry_run else "bumped"
    updated_tickers, plan = plan_version_bumps(args, manifest_path, report_repos, repo_root)
    if dry_run:
        for e in plan:
            if e.get("action") == "versions" and e.get("key") == "*":
                rel = str(e.get("file") or "")
                label = "wallet" if rel.startswith("wallet-confs") else "xbridge"
                report_line(
                    f"  UPDATE-VERSIONS {e.get('coin')}: {label} conf "
                    f"{str(e.get('new') or '')[len('copy of ') :]} -> {Path(rel).name} (planned)"
                )
            elif e.get("action") == "versions" and e.get("key") == "-":
                rel = str(e.get("file") or "")
                report_line(f"  UPDATE-VERSIONS {e.get('coin')}: remove superseded conf {Path(rel).name} (planned)")
        if updated_tickers:
            report_line(f"\nUPDATE-VERSIONS: {verb} {', '.join(sorted(set(updated_tickers)))} to latest remote")
            report_line("UPDATE-VERSIONS: dry-run — manifest and confs left untouched")
        return plan
    _execute_plan(plan, repo_root, runner, "  UPDATE-VERSIONS ", manifest_path)
    # The summary gates the operator follow-up below, so it reports what the
    # applier actually wrote. Only the entry that writes this run's manifest
    # proves a coin moved: the conf copy and the superseded-conf removal carry
    # the same coin but are side effects, so a refused collapse — or a plan
    # aimed at another manifest — is never a bumped coin.
    manifest_rel = repo_relative(manifest_target(repo_root, manifest_path), repo_root)
    bumped = sorted(
        {str(e.get("coin")) for e in plan if e.get("applied") and e.get("coin") and e.get("file") == manifest_rel}
    )
    if bumped:
        report_line(f"\nUPDATE-VERSIONS: {verb} {', '.join(bumped)} to latest remote")
        if args.replace_versions:
            report_line(
                "UPDATE-VERSIONS: confs copied verbatim — re-run --param-check for bumped tickers (relay/fees "
                "are per-tag;"
            )
            report_line(
                "  changelog probe covers the 5 newest tags only, so an older mandatory HF needs manual review)"
            )
            removals = [e for e in plan if e.get("action") == "versions" and e.get("key") == "-"]
            still_on_disk = [
                e for e in removals if not e.get("applied") and (repo_root / str(e.get("file") or "")).is_file()
            ]
            if still_on_disk:
                report_line("UPDATE-VERSIONS: superseded confs are still on disk — see the refusals above")
            elif removals and all(e.get("applied") for e in removals):
                report_line(
                    "UPDATE-VERSIONS: superseded old conf files are gone — the rename is complete "
                    "(git history keeps the previous conf)"
                )
        else:
            report_line(
                "UPDATE-VERSIONS: old versions kept buildable on existing confs — "
                "re-run --param-check for bumped tickers (relay/fees are per-tag)"
            )
    return plan
