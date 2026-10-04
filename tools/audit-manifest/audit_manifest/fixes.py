"""Write paths: config auto-fixes, port reallocation, and manifest version bumps.

Every function here returns ``(tickers touched, plan entries)`` (or just plan
entries) computed by the SAME code whether or not ``--dry-run`` is set — the
only difference is ``applied`` and whether bytes reach disk, so a preview can
never disagree with the apply it previews.
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from .checkout import SourceCheckoutManager, SourceReader
from .constants import FEE_REF_SIZE, logger
from .model import ManifestCoin, ParamStatus, chain_floor, recommended_fees
from .params import fee_constants_for_coin, fee_policy_for_coin
from .ports import PortCollisionManager
from .probe import SystemCommandRunner
from .reporting import report_line
from .util import plan_entry, repo_relative
from .versioning import (
    apply_additive_bump,
    build_update_version_names,
    should_skip_version_bump,
)


class ConfigAutoFixer:
    """Applies safe in-place fixes to wallet/XBridge configuration files."""

    @staticmethod
    def fix_missing_txindex(repo_root: Path, coin: ManifestCoin, dry_run: bool = False) -> Dict[str, Any]:
        wpath = repo_root / "wallet-confs" / coin.wallet_conf
        try:
            txt = SourceReader.slurp(wpath)
            if txt is None:
                return {}
            if "txindex" not in txt.lower():
                if dry_run:
                    logger.info("PLAN %s: would write txindex=1 to %s", coin.ticker, wpath)
                else:
                    with open(wpath, "a", encoding="utf-8") as fh:
                        if not txt.endswith("\n"):
                            fh.write("\n")
                        fh.write("txindex=1\n")
                    logger.info("FIX %s: wrote txindex=1 to %s", coin.ticker, wpath)
                return plan_entry(
                    repo_relative(wpath, repo_root), "txindex", None, "1",
                    "txindex absent from the wallet conf",
                    "txindex", coin=coin.ticker, ver_id=coin.ver_id,
                    applied=not dry_run,
                )
        except OSError as e:
            logger.error("Failed writing txindex to %s: %s", wpath, e)
        return {}

    @staticmethod
    def normalize_dust_amount(repo_root: Path, coin: ManifestCoin, dry_run: bool = False) -> Dict[str, Any]:
        xpath = repo_root / "xbridge-confs" / coin.xbridge_conf
        try:
            txt = SourceReader.slurp(xpath)
            if txt is None:
                return {}
            lines = txt.splitlines()
            out: List[str] = []
            replaced = False
            old_val: Optional[str] = None
            for line in lines:
                if not replaced and re.match(r"^\s*DustAmount\s*=", line, flags=re.I):
                    old_val = line.split("=", 1)[1].strip() if "=" in line else None
                    out.append("DustAmount=0")
                    replaced = True
                else:
                    out.append(line)
            if not replaced:
                out.append("DustAmount=0")
            if dry_run:
                logger.info("PLAN %s: would normalize DustAmount in %s", coin.ticker, xpath)
            else:
                xpath.write_text("\n".join(out) + "\n", encoding="utf-8")
                logger.info("FIX %s: normalized DustAmount=0 in %s", coin.ticker, xpath)
            return plan_entry(
                repo_relative(xpath, repo_root), "DustAmount", old_val, "0",
                "dust placeholder is ignored by the blocknet loader",
                "dust", coin=coin.ticker, ver_id=coin.ver_id, applied=not dry_run,
            )
        except OSError as e:
            logger.error("Failed normalizing DustAmount in %s: %s", xpath, e)
        return {}

    @staticmethod
    def remove_stale_deprecatedrpc(repo_root: Path, coin: ManifestCoin, dry_run: bool = False) -> Dict[str, Any]:
        wpath = repo_root / "wallet-confs" / coin.wallet_conf
        try:
            txt = SourceReader.slurp(wpath)
            if txt is None:
                return {}
            lines = txt.splitlines()
            out_lines: List[str] = []
            removed_lines: List[str] = []
            for line in lines:
                if re.match(r"^\s*deprecatedrpc\s*=", line, flags=re.I):
                    removed_lines.append(line.strip())
                    continue
                out_lines.append(line)

            removed = len(removed_lines)
            if removed and any("# Enable deprecated calls" in x for x in lines):
                if not any(re.match(r"^\s*deprecatedrpc\s*=", x, flags=re.I) for x in out_lines):
                    out_lines = [x for x in out_lines if "# Enable deprecated calls" not in x]

            if removed:
                if dry_run:
                    logger.info("PLAN %s: would remove %d stale deprecatedrpc line(s) from %s",
                                coin.ticker, removed, wpath)
                else:
                    wpath.write_text("\n".join(out_lines) + "\n", encoding="utf-8")
                    logger.info("FIX %s: removed stale deprecatedrpc from %s", coin.ticker, wpath)
                return plan_entry(
                    repo_relative(wpath, repo_root), "deprecatedrpc",
                    ", ".join(removed_lines), None,
                    "deprecatedrpc flag does nothing upstream",
                    "deprecatedrpc", coin=coin.ticker, ver_id=coin.ver_id,
                    applied=not dry_run,
                )
        except OSError as e:
            logger.error("Failed removing deprecatedrpc from %s: %s", wpath, e)
        return {}

    @staticmethod
    def fix_fee_margin(repo_root: Path, coin: ManifestCoin, dry_run: bool = False) -> Dict[str, Any]:
        """Fix FEES to strict-exact chain gates by updating MinTxFee/FeePerByte in xbridge conf."""
        try:
            # Resolve source to get rate + fee policy
            mgr = SourceCheckoutManager()
            # Use coin's first version tag for source resolution
            tag = coin.versions[0] if coin.versions else ""
            if not tag:
                logger.warning("FIX-FEES %s: no declared versions, cannot resolve source", coin.ticker)
                return {}
            src_dir, mode = mgr.resolve_source(coin, tag, timeout=60)
            if not src_dir or mode.startswith(("clone-", "no-")):
                logger.warning("FIX-FEES %s: cannot resolve source for %s", coin.ticker, tag)
                return {}
            rate, rate_ev, _, _ = fee_constants_for_coin(coin, src_dir)
            policy = fee_policy_for_coin(coin, src_dir)
            if policy.rounding == "unknown":
                logger.warning("FIX-FEES %s: fee policy not parseable (%s)", coin.ticker, "; ".join(policy.evidence))
                return {}
            if rate is None or rate == 0:
                logger.warning("FIX-FEES %s: relay not found", coin.ticker)
                return {}
            recMin, fpb = recommended_fees(policy, rate)
            target_fee = recMin
            floor_452 = chain_floor(policy, rate, FEE_REF_SIZE)
            xpath = repo_root / "xbridge-confs" / coin.xbridge_conf
            txt = SourceReader.slurp(xpath)
            if txt is None:
                return {}
            lines = txt.splitlines()
            out = []
            has_mtf = False
            has_fpb = False
            old_mtf: Optional[str] = None
            old_fpb: Optional[str] = None
            for line in lines:
                if re.match(r"^\s*MinTxFee\s*=", line, flags=re.I):
                    old_mtf = line.split("=", 1)[1].strip() if "=" in line else None
                    out.append(f"MinTxFee={target_fee}")
                    has_mtf = True
                elif re.match(r"^\s*FeePerByte\s*=", line, flags=re.I):
                    old_fpb = line.split("=", 1)[1].strip() if "=" in line else None
                    out.append(f"FeePerByte={fpb}")
                    has_fpb = True
                else:
                    out.append(line)
            if not has_mtf:
                out.append(f"MinTxFee={target_fee}")
            if not has_fpb:
                out.append(f"FeePerByte={fpb}")
            if dry_run:
                logger.info("PLAN-FEES %s: would set MinTxFee=%s FeePerByte=%s (rate %s floor452 %s model %s) %s",
                            coin.ticker, target_fee, fpb, rate, floor_452, policy.rounding, rate_ev or "")
            else:
                xpath.write_text("\n".join(out) + "\n", encoding="utf-8")
                logger.info("FIX-FEES %s: set MinTxFee=%s FeePerByte=%s (rate %s floor452 %s model %s) %s", coin.ticker, target_fee, fpb, rate, floor_452, policy.rounding, rate_ev or "")
            return plan_entry(
                repo_relative(xpath, repo_root), "MinTxFee/FeePerByte",
                f"MinTxFee={old_mtf} FeePerByte={old_fpb}",
                f"MinTxFee={target_fee} FeePerByte={fpb}",
                "rewrite fees to the strict chain gates from source",
                "fees", coin=coin.ticker, ver_id=coin.ver_id,
                evidence=rate_ev, applied=not dry_run,
            )
        except Exception as e:
            logger.error("FIX-FEES %s failed: %s", coin.ticker if 'coin' in locals() else "?", e)
            return {}

    @staticmethod
    def regenerate_base_j2(repo_root: Path, tickers: List[str], runner: SystemCommandRunner = SystemCommandRunner()) -> None:
        utils_dir = repo_root / "autobuild" / "utils"
        script = utils_dir / "create-j2-confs.py"
        if not script.is_file():
            logger.warning("create-j2-confs.py not found at %s", script)
            return

        for t in tickers:
            logger.info("Regenerating base.j2 for %s ...", t)
            res = runner.run(
                ["python3", str(script), "--coins", t],
                timeout=60,
                cwd=utils_dir,
                env_extra={"PYTHONUNBUFFERED": "1"},
            )
            if res and res.returncode == 0:
                logger.info("Regenerated base.j2 successfully for %s", t)
            else:
                logger.error("Failed regenerating base.j2 for %s: %s", t, res.stderr if res else "timeout")


def apply_conf_fixes(
    args: argparse.Namespace,
    manifest: List[ManifestCoin],
    param_results: Optional[Dict[str, Any]],
    repo_root: Path,
    runner: SystemCommandRunner,
) -> Tuple[List[str], List[Dict[str, Any]]]:
    """Apply --write-config / --fee-write fixes derived from param findings.

    Returns ``(tickers touched, plan entries)``. Under ``--dry-run`` the same
    code computes every entry with ``applied=False`` and writes nothing, so
    the preview and the apply cannot disagree about what would change.
    """
    dry_run = bool(getattr(args, "dry_run", False))
    fixed_tickers: List[str] = []
    plan: List[Dict[str, Any]] = []
    if (args.write_config or args.fee_write) and param_results is not None:
        for ver_id_key, res_dict in param_results.items():
            if ver_id_key.startswith("_"):
                continue
            coin = next((c for c in manifest if c.ver_id == ver_id_key or c.ticker == ver_id_key), None)
            if not coin:
                continue
            for chk_dict in res_dict.get("checks", []):
                cid = chk_dict["id"]
                cst = chk_dict["status"]
                cdet = chk_dict["detail"]
                if args.fee_write and cid != "FEES":
                    continue
                entry: Dict[str, Any] = {}
                if cid == "TXINDEX" and "txindex missing from conf while DEFAULT_TXINDEX=false" in cdet:
                    entry = ConfigAutoFixer.fix_missing_txindex(repo_root, coin, dry_run=dry_run)
                elif cid == "DUST" and cst == ParamStatus.WARN.value and "ignored by blocknet loader" in cdet:
                    entry = ConfigAutoFixer.normalize_dust_amount(repo_root, coin, dry_run=dry_run)
                elif cid == "DEPRECATEDRPC" and cst == ParamStatus.WARN.value and "stale, flag does nothing" in cdet:
                    entry = ConfigAutoFixer.remove_stale_deprecatedrpc(repo_root, coin, dry_run=dry_run)
                elif cid == "FEES" and (cst == ParamStatus.FAIL.value or (cst == ParamStatus.WARN.value and "overpay" in cdet)):
                    # FAIL (below strict chain gate) or overpay-WARN: rewrite to strict-exact.
                    entry = ConfigAutoFixer.fix_fee_margin(repo_root, coin, dry_run=dry_run)
                if entry:
                    plan.append(entry)
                    if coin.ticker not in fixed_tickers:
                        fixed_tickers.append(coin.ticker)

        if fixed_tickers and not dry_run:
            ConfigAutoFixer.regenerate_base_j2(repo_root, fixed_tickers, runner)

    return fixed_tickers, plan


def apply_port_fixes(
    args: argparse.Namespace,
    manifest: List[ManifestCoin],
    param_results: Optional[Dict[str, Any]],
    repo_root: Path,
    runner: SystemCommandRunner,
) -> Tuple[List[str], List[Dict[str, Any]]]:
    """Apply --fix-ports reallocation (earliest lineage survives).

    Returns ``(tickers touched, plan entries)``. The candidate ports are
    chosen identically in dry-run mode and fed back into the used-sets, so a
    preview shows exactly the assignments a real run would make.
    """
    dry_run = bool(getattr(args, "dry_run", False))
    verb = "PLAN" if dry_run else "FIX"
    fixed_ports: List[str] = []
    plan: List[Dict[str, Any]] = []

    def record(entries: List[Dict[str, Any]], coin: ManifestCoin) -> None:
        for e in entries:
            if e:
                e["coin"] = coin.ticker
                e["ver_id"] = coin.ver_id
                plan.append(e)

    if args.fix_ports and param_results is not None:
        logger.info("FIX-PORTS: earliest lineage survivor, paired scan reallocation%s",
                    " (dry-run, nothing written)" if dry_run else "")
        coll_maps = PortCollisionManager.collect_port_collisions(manifest, repo_root)
        used_p2p = set(coll_maps["p2p"].keys()) | set(coll_maps["test_p2p"].keys())
        used_rpc = set(coll_maps["rpc"].keys()) | set(coll_maps["test_rpc"].keys()) | set(coll_maps["xbridge"].keys())

        dup_p2p = {p: ts for p, ts in coll_maps["p2p"].items() if len(ts) > 1}
        dup_rpc = {p: ts for p, ts in coll_maps["rpc"].items() if len(ts) > 1}

        p2p_losers: Set[str] = set()
        rpc_losers: Set[str] = set()

        for port, tickers in dup_p2p.items():
            dated = []
            for t in tickers:
                c = next((item for item in manifest if item.ticker == t), None)
                d = SourceReader.lineage_date(repo_root, f"wallet-confs/{c.wallet_conf}", "port") if c else None
                dated.append((d or "9999-99-99", t))
            dated.sort()
            keep = dated[0][1]
            losers = [t for _, t in dated[1:]]
            logger.info("p2p %s: keep %s (%s), reassign %s", port, keep, dated[0][0], ", ".join(losers))
            p2p_losers.update(losers)

        for port, tickers in dup_rpc.items():
            dated = []
            for t in tickers:
                c = next((item for item in manifest if item.ticker == t), None)
                d = SourceReader.lineage_date(repo_root, f"wallet-confs/{c.wallet_conf}", "rpcport") if c else None
                dated.append((d or "9999-99-99", t))
            dated.sort()
            keep = dated[0][1]
            losers = [t for _, t in dated[1:]]
            logger.info("rpc %s: keep %s (%s), reassign %s", port, keep, dated[0][0], ", ".join(losers))
            rpc_losers.update(losers)

        paired_losers = p2p_losers & rpc_losers

        for t in sorted(paired_losers):
            c = next((item for item in manifest if item.ticker == t), None)
            if not c:
                continue
            wpath = repo_root / "wallet-confs" / c.wallet_conf
            xpath = repo_root / "xbridge-confs" / c.xbridge_conf
            secs = SourceReader.parse_conf_sections(wpath)
            top = secs.get("", {})
            try:
                src_p2p = int(top.get("port", "0").strip())
                src_rpc = int(top.get("rpcport", "0").strip())
            except ValueError:
                continue

            cand_p2p, cand_rpc = PortCollisionManager.find_free_pair(src_p2p, src_rpc, used_p2p, used_rpc)
            if cand_p2p and cand_rpc:
                logger.info("%s %s: p2p %s->%s rpc %s->%s paired", verb, t, src_p2p, cand_p2p, src_rpc, cand_rpc)
                record([
                    PortCollisionManager.write_wallet_key(wpath, "port", cand_p2p, dry_run=dry_run, repo_root=repo_root),
                    PortCollisionManager.write_wallet_key(wpath, "rpcport", cand_rpc, dry_run=dry_run, repo_root=repo_root),
                    PortCollisionManager.write_xbridge_port(xpath, cand_rpc, dry_run=dry_run, repo_root=repo_root),
                ], c)
                used_p2p.add(cand_p2p)
                used_rpc.add(cand_rpc)
                fixed_ports.append(t)

        for t in sorted(p2p_losers - paired_losers):
            c = next((item for item in manifest if item.ticker == t), None)
            if not c or t in fixed_ports:
                continue
            wpath = repo_root / "wallet-confs" / c.wallet_conf
            secs = SourceReader.parse_conf_sections(wpath)
            top = secs.get("", {})
            try:
                src = int(top.get("port", "0").strip())
            except ValueError:
                continue
            cand = PortCollisionManager.find_free_single(src, used_p2p, used_rpc, exclude_self=src)
            if cand:
                logger.info("%s %s: p2p %s->%s", verb, t, src, cand)
                record([
                    PortCollisionManager.write_wallet_key(wpath, "port", cand, dry_run=dry_run, repo_root=repo_root),
                ], c)
                used_p2p.add(cand)
                fixed_ports.append(t)

        for t in sorted(rpc_losers - paired_losers):
            if t in fixed_ports:
                continue
            c = next((item for item in manifest if item.ticker == t), None)
            if not c:
                continue
            wpath = repo_root / "wallet-confs" / c.wallet_conf
            xpath = repo_root / "xbridge-confs" / c.xbridge_conf
            secs = SourceReader.parse_conf_sections(wpath)
            top = secs.get("", {})
            try:
                src = int(top.get("rpcport", "0").strip())
            except ValueError:
                continue
            cand = PortCollisionManager.find_free_single(src, used_p2p, used_rpc, exclude_self=src)
            if cand:
                logger.info("%s %s: rpc %s->%s xbridge Port->%s", verb, t, src, cand, cand)
                record([
                    PortCollisionManager.write_wallet_key(wpath, "rpcport", cand, dry_run=dry_run, repo_root=repo_root),
                    PortCollisionManager.write_xbridge_port(xpath, cand, dry_run=dry_run, repo_root=repo_root),
                ], c)
                used_rpc.add(cand)
                fixed_ports.append(t)

        if fixed_ports and not dry_run:
            ConfigAutoFixer.regenerate_base_j2(repo_root, sorted(set(fixed_ports)), runner)

    return fixed_ports, plan


def apply_version_bumps(
    args: argparse.Namespace,
    manifest_path: Path,
    report_repos: Dict[str, Any],
    repo_root: Path,
    runner: SystemCommandRunner,
) -> Tuple[List[str], List[Dict[str, Any]]]:
    """Apply --update-versions / --replace-versions to manifest-latest.json.

    Returns ``(tickers bumped, plan entries)``. The manifest and conf
    mutations are computed in memory either way; ``--dry-run`` only stops them
    from reaching disk, so the preview is the exact diff apply would write.
    """
    dry_run = bool(getattr(args, "dry_run", False))
    verb = "would bump" if dry_run else "bumped"
    updated_tickers: List[str] = []
    plan: List[Dict[str, Any]] = []
    if args.update_versions:
        # Batch manifest version bump to latest remote for UPGRADE/REVIEW coins
        # Handles both newer_same and newer_alt (e.g. NMC nc0.20.0 -> nc31.1 rebrand)
        try:
            raw_text = SourceReader.slurp(manifest_path)
            if raw_text:
                raw_manifest = json.loads(raw_text)
                for url, rdata in report_repos.items():
                    if rdata.get("status") not in ("ALIVE", "MOVED"):
                        continue
                    if should_skip_version_bump(rdata):
                        skipped = sorted({e.get("ticker", "?") for e in rdata.get("entries", [])})
                        report_line(f"  UPDATE-VERSIONS skip {', '.join(skipped)}: mandatory hard fork — manual replacement required")
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
                                    report_line(f"  UPDATE-VERSIONS {ticker}: appended {target} (kept {item.get('ver_id', '')} confs)")
                                    updated_tickers.append(ticker)
                                    plan.append(plan_entry(
                                        "manifest-latest.json", f"{ticker}.versions",
                                        ", ".join(old_versions),
                                        ", ".join(item.get("versions") or []),
                                        f"append latest upstream tag {target}; existing versions stay buildable",
                                        "versions", coin=ticker,
                                        ver_id=item.get("ver_id"), applied=not dry_run,
                                    ))
                                continue
                            if target in old_versions and len(old_versions) == 1 and item.get("ver_id", "").endswith(target):
                                continue
                            old_ver_id = item.get("ver_id", "")
                            old_wc = item.get("wallet_conf", "")
                            old_xc = item.get("xbridge_conf", "")
                            new_ver_id, new_wc, new_xc = build_update_version_names(
                                ticker, old_ver_id, old_wc, old_xc, target
                            )
                            item["ver_id"] = new_ver_id
                            item["versions"] = [target]
                            item["wallet_conf"] = new_wc
                            item["xbridge_conf"] = new_xc
                            updated_tickers.append(ticker)
                            plan.append(plan_entry(
                                "manifest-latest.json", f"{ticker}",
                                f"{old_ver_id} ({old_wc}, {old_xc})",
                                f"{new_ver_id} ({new_wc}, {new_xc})",
                                f"collapse versions to {target} and rename confs",
                                "versions", coin=ticker, ver_id=new_ver_id,
                                applied=not dry_run,
                            ))
                            old_w_path = repo_root / "wallet-confs" / old_wc
                            new_w_path = repo_root / "wallet-confs" / new_wc
                            old_x_path = repo_root / "xbridge-confs" / old_xc
                            new_x_path = repo_root / "xbridge-confs" / new_xc
                            try:
                                for src_p, dst_p, label in (
                                    (old_w_path, new_w_path, "wallet"),
                                    (old_x_path, new_x_path, "xbridge"),
                                ):
                                    if src_p.is_file() and not dst_p.is_file():
                                        if not dry_run:
                                            shutil.copy2(src_p, dst_p)
                                        report_line(f"  UPDATE-VERSIONS {ticker}: {label} conf {src_p.name} -> {dst_p.name}"
                                                    + (" (planned)" if dry_run else " (copied)"))
                                        plan.append(plan_entry(
                                            repo_relative(dst_p, repo_root), "*",
                                            None, f"copy of {src_p.name}",
                                            f"copy {label} conf forward for the new version",
                                            "versions", coin=ticker, ver_id=new_ver_id,
                                            applied=not dry_run,
                                        ))
                                    elif dst_p.is_file():
                                        report_line(f"  UPDATE-VERSIONS {ticker}: target {dst_p.name} already exists — kept as-is (verify content)")
                            except Exception as e:
                                logger.warning("copy conf failed for %s: %s", ticker, e)
                if updated_tickers:
                    if not dry_run:
                        manifest_path.write_text(json.dumps(raw_manifest, indent=2) + "\n", encoding="utf-8")
                    report_line(f"\nUPDATE-VERSIONS: {verb} {', '.join(sorted(set(updated_tickers)))} to latest remote")
                    if dry_run:
                        report_line("UPDATE-VERSIONS: dry-run — manifest and confs left untouched")
                    elif args.replace_versions:
                        report_line("UPDATE-VERSIONS: confs copied verbatim — re-run --param-check for bumped tickers (relay/fees are per-tag;")
                        report_line("  changelog probe covers the 5 newest tags only, so an older mandatory HF needs manual review)")
                        report_line("UPDATE-VERSIONS: superseded old conf files are left on disk — git rm them in blockchain-configuration-files once verified")
                    else:
                        report_line("UPDATE-VERSIONS: old versions kept buildable on existing confs — re-run --param-check for bumped tickers (relay/fees are per-tag)")
                    if not dry_run:
                        try:
                            ConfigAutoFixer.regenerate_base_j2(repo_root, sorted(set(updated_tickers)), runner)
                        except Exception as e:
                            logger.warning("regenerate base.j2 failed: %s", e)
        except Exception as e:
            logger.error("UPDATE-VERSIONS failed: %s", e)

    return updated_tickers, plan
