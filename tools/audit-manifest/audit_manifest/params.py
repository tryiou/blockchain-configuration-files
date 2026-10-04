"""Param fact-check engine: runs every checker against verified source trees.

``ParamAuditEngine`` resolves the checkout per tag, dispatches the family-
appropriate checks (C++ vs btcd), and aggregates counts. The two fee dispatch
helpers are the single place that routes to the right inspector.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

from .checkout import SourceCheckoutManager, SourceReader
from .constants import logger
from .inspectors import (
    BtcdSourceInspector,
    CommonParamCheckers,
    CppSourceInspector,
)
from .model import (
    PARAM_STATUS_PRECEDENCE,
    CheckFinding,
    FeePolicy,
    ManifestCoin,
    ParamAuditResult,
    ParamStatus,
)
from .localcheck import ManifestCrossChecker
from .versioning import VersionEngine


def fee_constants_for_coin(
    coin: ManifestCoin, src_dir: Path
) -> Tuple[Optional[int], Optional[str], Optional[int], Optional[str]]:
    """Relay/dust constants via the coin's own layout (Go btcd vs C++)."""
    if coin.is_btcd:
        return BtcdSourceInspector.fee_constants(src_dir)
    return CppSourceInspector.fee_constants(src_dir)


def fee_policy_for_coin(coin: ManifestCoin, src_dir: Path) -> FeePolicy:
    """Fee behavior via the coin's own layout (Go btcd vs C++)."""
    if coin.is_btcd:
        return BtcdSourceInspector.fee_policy(src_dir)
    return CppSourceInspector.fee_policy(src_dir)


class ParamAuditEngine:
    """Executes rule-based parameter validation passes against verified source trees."""

    def __init__(self, checkout_manager: SourceCheckoutManager):
        self.checkout_manager = checkout_manager

    def audit_version(
        self,
        coin: ManifestCoin,
        repo_root: Path,
        version_tag: str,
        wallet_conf: str,
        xbridge_conf: str,
        timeout: int,
        fees_only: bool = False,
    ) -> ParamAuditResult:
        shard = ManifestCoin(
            ticker=coin.ticker,
            ver_id=coin.ver_id,
            blockchain=coin.blockchain,
            repo_url=coin.repo_url,
            versions=[version_tag],
            wallet_conf=wallet_conf,
            xbridge_conf=xbridge_conf,
            daemon_family=coin.daemon_family,
            daemon_stem=coin.daemon_stem,
        )

        src_dir, mode = self.checkout_manager.resolve_source(shard, version_tag, timeout)
        if src_dir is None:
            return ParamAuditResult(
                tag=version_tag,
                source=None,
                mode=mode,
                version=version_tag,
                wallet_conf=wallet_conf,
                xbridge_conf=xbridge_conf,
            )

        wsecs = SourceReader.parse_conf_sections(repo_root / "wallet-confs" / wallet_conf)
        top = wsecs.get("", {})
        test = wsecs.get("test", {})
        want_test = bool(test) or top.get("testnet", "").strip() == "1"
        wc = dict(top)
        if want_test:
            wc.update(test)
            wc["_has_test_section"] = "true"

        xc = SourceReader.parse_conf(repo_root / "xbridge-confs" / xbridge_conf)
        is_btcd = shard.is_btcd

        if is_btcd:
            rate, rate_ev, dust, dust_ev = BtcdSourceInspector.fee_constants(src_dir)
        else:
            rate, rate_ev, dust, dust_ev = CppSourceInspector.fee_constants(src_dir)
        policy = fee_policy_for_coin(shard, src_dir) if src_dir else None

        checks: List[CheckFinding] = []

        def add_check(cid: str, func: Callable[..., Tuple[ParamStatus, str]], *args: Any) -> None:
            try:
                st, det = func(*args)
            except Exception as exc:
                logger.exception("Checker %s failed for %s @ %s", cid, coin.ticker, version_tag)
                msg = str(exc).lower()
                st = ParamStatus.FAIL if ("not found" in msg or "no such file" in msg) else ParamStatus.WARN
                det = f"checker error: {exc}"
            checks.append(CheckFinding(id=cid, status=st, detail=det))

        if is_btcd:
            add_check("PORT", BtcdSourceInspector.check_port, shard, src_dir, wc, repo_root)
            add_check("RPCPORT-SOURCE", BtcdSourceInspector.check_rpcport, shard, src_dir, wc, repo_root)
            add_check("RPCPORT-XBRIDGE", CommonParamCheckers.check_rpcport_xbridge, shard, wc, xc, repo_root)
            add_check("PREFIXES", BtcdSourceInspector.check_prefixes, shard, src_dir, xc, repo_root)
            add_check("COIN", BtcdSourceInspector.check_coin, shard, src_dir, xc)
            add_check("TXVERSION", BtcdSourceInspector.check_txversion, shard, src_dir, xc)
            add_check("BLOCKTIME", BtcdSourceInspector.check_blocktime, shard, src_dir, xc, repo_root)
            add_check("FEES", CommonParamCheckers.check_fees, shard, src_dir, xc, rate, rate_ev, dust, dust_ev, policy)
            add_check("DUST", CommonParamCheckers.check_dust, shard, src_dir, xc, rate, rate_ev, dust, dust_ev, policy)
            add_check("DEPRECATEDRPC", BtcdSourceInspector.check_deprecatedrpc, shard, src_dir, wc)
            add_check("TXTIME", BtcdSourceInspector.check_txtime, shard, src_dir, xc)
            add_check("TXINDEX", BtcdSourceInspector.check_txindex, shard, src_dir, wc)
            add_check("ADDRTYPE", BtcdSourceInspector.check_addrtype, shard, src_dir, wc)
            add_check("CONFIRM", CommonParamCheckers.check_confirmations, shard, xc)
            add_check("METHOD", CommonParamCheckers.check_method, shard, xc)
            add_check("STRUCT", BtcdSourceInspector.check_structure, shard, wc, xc)
        else:
            add_check("PORT", CppSourceInspector.check_port, shard, src_dir, wc, want_test, repo_root)
            add_check("RPCPORT-SOURCE", CppSourceInspector.check_rpcport_source, shard, src_dir, wc, want_test, repo_root)
            add_check("RPCPORT-XBRIDGE", CommonParamCheckers.check_rpcport_xbridge, shard, wc, xc, repo_root)
            add_check("PREFIXES", CppSourceInspector.check_prefixes, shard, src_dir, xc, want_test, repo_root)
            add_check("COIN", CppSourceInspector.check_coin, shard, src_dir, xc)
            add_check("TXVERSION", CppSourceInspector.check_txversion, shard, src_dir, xc)
            add_check("BLOCKTIME", CppSourceInspector.check_blocktime, shard, src_dir, xc, want_test, repo_root)
            add_check("FEES", CommonParamCheckers.check_fees, shard, src_dir, xc, rate, rate_ev, dust, dust_ev, policy)
            add_check("DUST", CommonParamCheckers.check_dust, shard, src_dir, xc, rate, rate_ev, dust, dust_ev, policy)
            add_check("DEPRECATEDRPC", CppSourceInspector.check_deprecatedrpc, shard, src_dir, wc, repo_root)
            add_check("TXTIME", CppSourceInspector.check_txtime, shard, src_dir, xc)
            add_check("TXINDEX", CppSourceInspector.check_txindex, shard, src_dir, wc)
            add_check("ADDRTYPE", CppSourceInspector.check_addrtype, shard, src_dir, wc)
            add_check("CONFIRM", CommonParamCheckers.check_confirmations, shard, xc)
            add_check("METHOD", CommonParamCheckers.check_method, shard, xc)
            add_check("STRUCT", CommonParamCheckers.check_structure, shard, wc, xc)

        if fees_only:
            checks = [c for c in checks if c.id in ("FEES", "DUST")]

        nf = sum(1 for c in checks if c.status in (ParamStatus.FAIL, ParamStatus.BROKEN))
        nd = sum(1 for c in checks if c.status == ParamStatus.DIFFERS)
        nw = sum(1 for c in checks if c.status == ParamStatus.WARN)
        nu = sum(1 for c in checks if c.status == ParamStatus.UNRESOLVED)

        return ParamAuditResult(
            tag=version_tag,
            source=str(src_dir),
            mode=mode,
            checks=checks,
            fail=nf,
            differs=nd,
            warn=nw,
            unresolved=nu,
            version=version_tag,
            wallet_conf=wallet_conf,
            xbridge_conf=xbridge_conf,
        )

    def audit_coin_all_versions(
        self,
        coin: ManifestCoin,
        repo_root: Path,
        timeout: int,
        strict: bool = False,
        fees_only: bool = False,
    ) -> ParamAuditResult:
        all_tags = coin.expected_tags()
        entry_tag = VersionEngine.max_version_tag(set(coin.versions)) if coin.versions else None

        if not entry_tag:
            return ParamAuditResult(tag=None, source=None, mode="no-tag")

        entry_res = self.audit_version(coin, repo_root, entry_tag, coin.wallet_conf, coin.xbridge_conf, timeout, fees_only=fees_only)

        per_version_results: List[Dict[str, Any]] = []
        seen_tags: Set[str] = set()

        for v in all_tags:
            if v in seen_tags:
                continue
            seen_tags.add(v)

            wc, xc = ManifestCrossChecker.conf_pair_for_version(coin, v, repo_root)
            if v == entry_tag and wc == coin.wallet_conf and xc == coin.xbridge_conf:
                pv_dict = entry_res.to_dict()
                pv_dict["version"] = v
                pv_dict["wallet_conf"] = wc
                pv_dict["xbridge_conf"] = xc
                per_version_results.append(pv_dict)
            else:
                pv = self.audit_version(coin, repo_root, v, wc, xc, timeout, fees_only=fees_only)
                per_version_results.append(pv.to_dict())

        # Check for reuse-drift (multiple versions share one conf file, but source constants diverged)
        # If sharing is clean (no DIFFERS across the per-version fact-checks), emit a
        # clarity INFO instead of staying silent. INFO does not increment warn
        # counters and does not bubble under --strict-per-version (only WARN/FAIL bubble).
        # Per-version clone/fact-check loop above stays intact — every tag is still
        # individually checked via conf_pair_for_version.
        if len(all_tags) > 1:
            uniq_wc = {p["wallet_conf"] for p in per_version_results}
            uniq_xc = {p["xbridge_conf"] for p in per_version_results}
            if len(uniq_wc) == 1 or len(uniq_xc) == 1:
                any_differs = any(p.get("differs", 0) > 0 for p in per_version_results)
                if any_differs:
                    differs_by_version = ", ".join(
                        f"{p['version']}:{p['differs']}DIFFERS"
                        for p in per_version_results
                        if p.get('differs')
                    )
                    detail = (
                        f"reuse hides drift: {len(all_tags)} versions share conf pair "
                        f"{next(iter(uniq_wc))} / {next(iter(uniq_xc))} but source constants diverged "
                        f"(per-version DIFFERS: {differs_by_version})"
                    )
                    entry_res.checks.append(CheckFinding(id="REUSE-DRIFT", status=ParamStatus.WARN, detail=detail))
                    entry_res.warn += 1
                else:
                    detail = (
                        f"{len(all_tags)} versions share conf pair {next(iter(uniq_wc))} / {next(iter(uniq_xc))} — per-version fact-check clean"
                    )
                    entry_res.checks.append(CheckFinding(id="SHARED-CONF", status=ParamStatus.INFO, detail=detail))

        if strict:
            worst_pv: Optional[ParamStatus] = None
            for pv in per_version_results:
                for chk in pv.get("checks", []):
                    st = ParamStatus(chk["status"])
                    if worst_pv is None or PARAM_STATUS_PRECEDENCE.index(st) < PARAM_STATUS_PRECEDENCE.index(worst_pv):
                        worst_pv = st

            # INFO/SKIP/PASS/MATCH never bubble — only WARN/FAIL (and DIFFERS/CONFLICT/BROKEN/UNRESOLVED) bubble per spec
            if worst_pv in (ParamStatus.INFO, ParamStatus.SKIP, ParamStatus.PASS, ParamStatus.MATCH):
                worst_pv = None

            entry_worst: Optional[ParamStatus] = None
            for chk in entry_res.checks:
                if entry_worst is None or PARAM_STATUS_PRECEDENCE.index(chk.status) < PARAM_STATUS_PRECEDENCE.index(entry_worst):
                    entry_worst = chk.status

            if worst_pv and entry_worst and PARAM_STATUS_PRECEDENCE.index(worst_pv) < PARAM_STATUS_PRECEDENCE.index(entry_worst):
                entry_res.checks.append(
                    CheckFinding(
                        id="STRICT-BUBBLE",
                        status=worst_pv,
                        detail=f"strict-per-version: worst per-version {worst_pv.value} bubbles to entry (was {entry_worst.value})",
                    )
                )
                if worst_pv in (ParamStatus.FAIL, ParamStatus.BROKEN):
                    entry_res.fail += 1
                elif worst_pv == ParamStatus.DIFFERS:
                    entry_res.differs += 1
                elif worst_pv == ParamStatus.WARN:
                    entry_res.warn += 1

        entry_res.per_version = per_version_results
        return entry_res
