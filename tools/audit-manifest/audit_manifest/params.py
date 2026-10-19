"""Param fact-check engine: runs every checker against verified source trees.

``ParamAuditEngine`` resolves the checkout per tag, dispatches the family-
appropriate checks (C++ vs btcd), and aggregates counts. The two fee dispatch
helpers are the single place that routes to the right inspector.
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Any, NamedTuple

from .checkout import SourceCheckoutManager, SourceReader
from .constants import logger
from .inspectors import (
    BtcdSourceInspector,
    CommonParamCheckers,
    CppSourceInspector,
)
from .localcheck import ManifestCrossChecker
from .model import (
    PARAM_STATUS_PRECEDENCE,
    CheckFinding,
    CheckResult,
    FeePolicy,
    ManifestCoin,
    ParamAuditResult,
    ParamStatus,
    max_status,
)
from .versioning import VersionEngine


def fee_constants_for_coin(coin: ManifestCoin, src_dir: Path) -> tuple[int | None, str | None, int | None, str | None]:
    """Relay/dust constants via the coin's own layout (Go btcd vs C++)."""
    if coin.is_btcd:
        return BtcdSourceInspector.fee_constants(src_dir)
    return CppSourceInspector.fee_constants(src_dir)


def fee_policy_for_coin(coin: ManifestCoin, src_dir: Path) -> FeePolicy:
    """Fee behavior via the coin's own layout (Go btcd vs C++)."""
    if coin.is_btcd:
        return BtcdSourceInspector.fee_policy(src_dir)
    return CppSourceInspector.fee_policy(src_dir)


class _CheckCtx(NamedTuple):
    """Everything the checker tables read beyond their per-check arguments."""

    shard: ManifestCoin
    src_dir: Path
    wc: dict[str, str]
    xc: dict[str, str]
    repo_root: Path
    want_test: bool
    rate: int | None
    rate_ev: str | None
    dust: int | None
    dust_ev: str | None
    policy: FeePolicy


def _run_checker(  # noqa: PLR0913, PLR0917  # dispatch signature: one slot per ingredient of a checker call
    cid: str,
    func: Callable[..., Any],
    coin: ManifestCoin,
    version_tag: str,
    checks: list[CheckFinding],
    args: tuple[Any, ...],
    kwargs: dict[str, Any],
) -> None:
    """Run one checker and append its finding, degrading a crash to a row.

    Checker contract: ``(status, detail)`` or ``(status, detail, fixable
    kind)``. A checker that raises never aborts the version — it becomes
    a FAIL/WARN row naming the exception, so a broken checker is visible
    in the report instead of silently dropping a check.
    """
    fixable: str | None = None
    try:
        st, det, fixable = CheckResult(*func(*args, **kwargs))
    except Exception as exc:
        logger.exception("Checker %s failed for %s @ %s", cid, coin.ticker, version_tag)
        msg = str(exc).lower()
        st = ParamStatus.FAIL if ("not found" in msg or "no such file" in msg) else ParamStatus.WARN
        det = f"checker error: {exc}"
    checks.append(CheckFinding(id=cid, status=st, detail=det, fixable=fixable))


class ParamAuditEngine:
    """Executes rule-based parameter validation passes against verified source trees."""

    def __init__(self, checkout_manager: SourceCheckoutManager):
        self.checkout_manager = checkout_manager

    def _resolve_version_source(self, shard: ManifestCoin, version_tag: str, timeout: int) -> tuple[Path | None, str]:
        """The checkout for one shard, degrading a bad ticker to no-source.

        Returns ``(src_dir, mode)``; ``src_dir is None`` carries the mode
        that explains why, so the caller can emit the structured row.
        """
        try:
            return self.checkout_manager.resolve_source(shard, version_tag, timeout)
        except ValueError as exc:
            # Malformed manifest ticker: degrade this one entry to a
            # structured no-source row instead of aborting the whole run.
            logger.error("PARAM-CHECK %s @ %s: %s", shard.ticker or "?", version_tag, exc)
            return None, "no-valid-ticker"

    @staticmethod
    def _conf_views(
        repo_root: Path, wallet_conf: str, xbridge_conf: str
    ) -> tuple[dict[str, str], dict[str, str], bool]:
        """(wallet conf flat dict, xbridge conf dict, want_test flag).

        A testnet-section wallet conf folds its ``[test]`` keys over the
        top level and flags itself, so every checker reads one dict.
        """
        wsecs = SourceReader.parse_conf_sections(repo_root / "wallet-confs" / wallet_conf)
        top = wsecs.get("", {})
        test = wsecs.get("test", {})
        want_test = bool(test) or top.get("testnet", "").strip() == "1"
        wc = dict(top)
        if want_test:
            wc.update(test)
            wc["_has_test_section"] = "true"
        xc = SourceReader.parse_conf(repo_root / "xbridge-confs" / xbridge_conf)
        return wc, xc, want_test

    # dispatch orchestrator: resolve, parse, then the family's checker table
    def audit_version(  # noqa: PLR0913, PLR0917  # result-row inputs, keyword-only at the call site
        self,
        coin: ManifestCoin,
        repo_root: Path,
        version_tag: str,
        wallet_conf: str,
        xbridge_conf: str,
        timeout: int,
        *,
        fees_only: bool = False,
    ) -> ParamAuditResult:
        shard = self._shard_for_version(coin, version_tag, wallet_conf, xbridge_conf)
        src_dir, mode = self._resolve_version_source(shard, version_tag, timeout)
        if src_dir is None:
            return ParamAuditResult(
                tag=version_tag,
                source=None,
                mode=mode,
                version=version_tag,
                wallet_conf=wallet_conf,
                xbridge_conf=xbridge_conf,
            )

        wc, xc, want_test = self._conf_views(repo_root, wallet_conf, xbridge_conf)
        if shard.is_btcd:
            rate, rate_ev, dust, dust_ev = BtcdSourceInspector.fee_constants(src_dir)
        else:
            rate, rate_ev, dust, dust_ev = CppSourceInspector.fee_constants(src_dir)
        policy = fee_policy_for_coin(shard, src_dir)
        ctx = _CheckCtx(
            shard=shard,
            src_dir=src_dir,
            wc=wc,
            xc=xc,
            repo_root=repo_root,
            want_test=want_test,
            rate=rate,
            rate_ev=rate_ev,
            dust=dust,
            dust_ev=dust_ev,
            policy=policy,
        )

        if shard.is_btcd:
            checks = self._checks_btcd(coin, version_tag, ctx)
        else:
            checks = self._checks_cpp(coin, version_tag, ctx)

        if fees_only:
            checks = [c for c in checks if c.id in ("FEES", "DUST")]

        return ParamAuditEngine._version_result(
            version_tag=version_tag,
            src_dir=src_dir,
            mode=mode,
            checks=checks,
            wallet_conf=wallet_conf,
            xbridge_conf=xbridge_conf,
        )

    def _checks_btcd(self, coin: ManifestCoin, version_tag: str, ctx: _CheckCtx) -> list[CheckFinding]:
        """The Go-family checker table, in the order the report lists it."""
        btcd, common = BtcdSourceInspector, CommonParamCheckers
        s, w, x, r = ctx.shard, ctx.wc, ctx.xc, ctx.repo_root
        t = (s, ctx.src_dir)
        lines: tuple[tuple[str, Any, tuple[Any, ...], dict[str, Any]], ...] = (
            ("PORT", btcd.check_port, (*t, w, r), {}),
            ("RPCPORT-SOURCE", btcd.check_rpcport, (*t, w, r), {}),
            ("RPCPORT-XBRIDGE", common.check_rpcport_xbridge, (s, w, x, r), {}),
            ("PREFIXES", btcd.check_prefixes, (s, ctx.src_dir, x, r), {}),
            ("COIN", btcd.check_coin, (*t, x), {}),
            ("TXVERSION", btcd.check_txversion, (*t, x), {}),
            ("BLOCKTIME", btcd.check_blocktime, (s, ctx.src_dir, x, r), {}),
            (
                "FEES",
                common.check_fees,
                (s, ctx.src_dir, x, ctx.rate, ctx.rate_ev, ctx.dust, ctx.dust_ev, ctx.policy),
                {},
            ),
            (
                "DUST",
                common.check_dust,
                (s, ctx.src_dir, x, ctx.rate, ctx.rate_ev, ctx.dust, ctx.dust_ev, ctx.policy),
                {},
            ),
            ("DEPRECATEDRPC", btcd.check_deprecatedrpc, (*t, w), {}),
            ("TXTIME", btcd.check_txtime, (*t, x), {}),
            ("TXINDEX", btcd.check_txindex, (*t, w), {}),
            ("ADDRTYPE", btcd.check_addrtype, (*t, w), {}),
            ("CONFIRM", common.check_confirmations, (s, x), {}),
            ("METHOD", common.check_method, (s, x), {}),
            ("STRUCT", btcd.check_structure, (s, w, x), {}),
        )
        out: list[CheckFinding] = []
        for cid, func, args, kwargs in lines:
            _run_checker(cid, func, coin, version_tag, out, args, kwargs)
        return out

    def _checks_cpp(self, coin: ManifestCoin, version_tag: str, ctx: _CheckCtx) -> list[CheckFinding]:
        """The C++-family checker table, in the order the report lists it."""
        cpp, common = CppSourceInspector, CommonParamCheckers
        s, w, x, r = ctx.shard, ctx.wc, ctx.xc, ctx.repo_root
        t = (s, ctx.src_dir)
        want = {"want_test": ctx.want_test, "repo_root": r}
        lines: tuple[tuple[str, Any, tuple[Any, ...], dict[str, Any]], ...] = (
            ("PORT", cpp.check_port, (*t, w), want),
            ("RPCPORT-SOURCE", cpp.check_rpcport_source, (*t, w), want),
            ("RPCPORT-XBRIDGE", common.check_rpcport_xbridge, (s, w, x, r), {}),
            ("PREFIXES", cpp.check_prefixes, (*t, x), want),
            ("COIN", cpp.check_coin, (*t, x), {}),
            ("TXVERSION", cpp.check_txversion, (*t, x), {}),
            ("BLOCKTIME", cpp.check_blocktime, (*t, x), want),
            (
                "FEES",
                common.check_fees,
                (s, ctx.src_dir, x, ctx.rate, ctx.rate_ev, ctx.dust, ctx.dust_ev, ctx.policy),
                {},
            ),
            (
                "DUST",
                common.check_dust,
                (s, ctx.src_dir, x, ctx.rate, ctx.rate_ev, ctx.dust, ctx.dust_ev, ctx.policy),
                {},
            ),
            ("DEPRECATEDRPC", cpp.check_deprecatedrpc, (*t, w, r), {}),
            ("TXTIME", cpp.check_txtime, (*t, x), {}),
            ("TXINDEX", cpp.check_txindex, (*t, w), {}),
            ("ADDRTYPE", cpp.check_addrtype, (*t, w), {}),
            ("CONFIRM", common.check_confirmations, (s, x), {}),
            ("METHOD", common.check_method, (s, x), {}),
            ("STRUCT", common.check_structure, (s, w, x), {}),
        )
        out: list[CheckFinding] = []
        for cid, func, args, kwargs in lines:
            _run_checker(cid, func, coin, version_tag, out, args, kwargs)
        return out

    @staticmethod
    def _shard_for_version(coin: ManifestCoin, version_tag: str, wallet_conf: str, xbridge_conf: str) -> ManifestCoin:
        """The same coin scoped to one version tag and its conf pair."""
        return ManifestCoin(
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

    @staticmethod
    def _version_result(  # noqa: PLR0913  # the result row's fields, keyword-only at the call site
        *,
        version_tag: str,
        src_dir: Path,
        mode: str,
        checks: list[CheckFinding],
        wallet_conf: str,
        xbridge_conf: str,
    ) -> ParamAuditResult:
        """Counts per attention status, then the row for this version."""
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
        *,
        strict: bool = False,
        fees_only: bool = False,
    ) -> ParamAuditResult:
        all_tags = coin.expected_tags()
        entry_tag = VersionEngine.max_version_tag(set(coin.versions)) if coin.versions else None

        if not entry_tag:
            return ParamAuditResult(tag=None, source=None, mode="no-tag")

        entry_res = self.audit_version(
            coin,
            repo_root,
            entry_tag,
            coin.wallet_conf,
            coin.xbridge_conf,
            timeout,
            fees_only=fees_only,
        )

        per_version_results: list[dict[str, Any]] = []
        seen_tags: set[str] = set()

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

        if len(all_tags) > 1:
            _reuse_conf_checks(entry_res, per_version_results, all_tags)

        if strict:
            _apply_strict_bubble(entry_res, per_version_results)

        entry_res.per_version = per_version_results
        return entry_res


def _reuse_conf_checks(
    entry_res: ParamAuditResult, per_version_results: list[dict[str, Any]], all_tags: list[str]
) -> None:
    """Reuse-drift: shared conf pair, diverged source constants.

    If sharing is clean (no DIFFERS across the per-version fact-checks),
    emit a clarity INFO instead of staying silent. INFO does not
    increment warn counters and does not bubble under
    --strict-per-version (only WARN/FAIL bubble).
    """
    # Check for reuse-drift (multiple versions share one conf file, but source constants diverged)
    # If sharing is clean (no DIFFERS across the per-version fact-checks), emit a
    # clarity INFO instead of staying silent. INFO does not increment warn
    # counters and does not bubble under --strict-per-version (only WARN/FAIL bubble).
    # Per-version clone/fact-check loop above stays intact — every tag is still
    # individually checked via conf_pair_for_version.
    uniq_wc = {p["wallet_conf"] for p in per_version_results}
    uniq_xc = {p["xbridge_conf"] for p in per_version_results}
    if len(uniq_wc) == 1 or len(uniq_xc) == 1:
        any_differs = any(p.get("differs", 0) > 0 for p in per_version_results)
        if any_differs:
            differs_by_version = ", ".join(
                f"{p['version']}:{p['differs']}DIFFERS" for p in per_version_results if p.get("differs")
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
                f"{len(all_tags)} versions share conf pair {next(iter(uniq_wc))} / "
                f"{next(iter(uniq_xc))} — per-version fact-check clean"
            )
            entry_res.checks.append(CheckFinding(id="SHARED-CONF", status=ParamStatus.INFO, detail=detail))


def _apply_strict_bubble(entry_res: ParamAuditResult, per_version_results: list[dict[str, Any]]) -> None:
    """--strict-per-version: worst per-version status bubbles to the entry."""
    worst_pv = _worst_per_version_status(per_version_results)

    # INFO/SKIP/PASS/MATCH never bubble — only WARN/FAIL (and DIFFERS/CONFLICT/BROKEN/UNRESOLVED) bubble per spec
    if worst_pv in (ParamStatus.INFO, ParamStatus.SKIP, ParamStatus.PASS, ParamStatus.MATCH):
        worst_pv = None

    entry_worst = _worst_finding_status(entry_res.checks)

    if (
        worst_pv
        and entry_worst
        and PARAM_STATUS_PRECEDENCE.index(worst_pv) < PARAM_STATUS_PRECEDENCE.index(entry_worst)
    ):
        entry_res.checks.append(
            CheckFinding(
                id="STRICT-BUBBLE",
                status=worst_pv,
                detail=(
                    f"strict-per-version: worst per-version {worst_pv.value} bubbles to entry (was {entry_worst.value})"
                ),
            )
        )
        if worst_pv in (ParamStatus.FAIL, ParamStatus.BROKEN):
            entry_res.fail += 1
        elif worst_pv == ParamStatus.DIFFERS:
            entry_res.differs += 1
        elif worst_pv == ParamStatus.WARN:
            entry_res.warn += 1


def _worst_per_version_status(per_version_results: list[dict[str, Any]]) -> ParamStatus | None:
    """Worst status across every per-version fact-check, None when there is none."""
    worst: ParamStatus | None = None
    for pv in per_version_results:
        for chk in pv.get("checks", []):
            st = ParamStatus(chk["status"])
            worst = st if worst is None else max_status(worst, st)
    return worst


def _worst_finding_status(checks: list[CheckFinding]) -> ParamStatus | None:
    """Worst status across one finding list, None when empty."""
    worst: ParamStatus | None = None
    for chk in checks:
        worst = chk.status if worst is None else max_status(worst, chk.status)
    return worst
