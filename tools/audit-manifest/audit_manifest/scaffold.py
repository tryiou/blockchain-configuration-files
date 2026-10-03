"""Coin scaffolding: extract fleet facts from a fresh clone and emit confs.

``CoinScaffolder.run`` probes the repo, shallow-clones the chosen tag into
scratch, extracts ports/prefixes/fees from source, picks collision-free ports
against the live fleet, and writes (or prints) the new wallet/xbridge conf
pair plus a manifest snippet. Every user-facing line goes through
:func:`report_line`.
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
from pathlib import Path
from typing import Any, Dict, List, Tuple

from .constants import CACHE_ROOT
from .inspectors import BtcdSourceInspector, CppSourceInspector
from .model import ManifestCoin, RepoStatus, recommended_fees
from .ports import PortCollisionManager
from .probe import RemoteProbeService, SystemCommandRunner
from .reporting import report_line
from .util import _safe_arith_float, plan_entry
from .versioning import VersionEngine
from .checkout import SourceReader


class CoinScaffolder:
    """Automates repository cloning, parameter extraction, and template emission for new coins."""

    def __init__(self, runner: SystemCommandRunner = SystemCommandRunner(), probe_service: RemoteProbeService = RemoteProbeService()):
        self.runner = runner
        self.probe_service = probe_service

    @staticmethod
    def derive_ticker(repo_url: str) -> str:
        base = repo_url.rstrip("/").removesuffix(".git").split("/")[-1] if repo_url else "COIN"
        base = re.sub(r"[-_]?core$", "", base, flags=re.I)
        base = re.sub(r"[-_]?project$", "", base, flags=re.I)
        base = re.sub(r"[^A-Za-z0-9]", "", base)
        return (base[:8] or "COIN").upper()

    @staticmethod
    def derive_identity(src_dir: Path, ticker: str) -> Dict[str, str]:
        """Read daemon + datadir names from source so --apply needs no hand-edits.

        conf_name follows the fleet rule `<stem>.conf` where `<stem>d` is the
        daemon (verged -> verge.conf); datadirs come from GetDefaultDataDir
        (Unix `~/.<linux>`, Mac/Win `<Name>`). Anything unresolvable falls back
        to the old ticker guesses. Display name (blockchain/Title) is NOT
        derivable from source — callers pass --scaffold-name for it.
        """
        stem = ticker.lower()
        dir_linux, dir_mac, dir_win = stem, ticker.upper(), ticker.upper()
        daemon = None
        mk = SourceReader.slurp(src_dir / "src" / "Makefile.am")
        if mk:
            toks: list = []
            for line in mk.splitlines():
                # Make comments are `#`-to-EOL: skip them WITHOUT the C
                # strip_comments() helper, whose /*...*/ pattern can pair
                # across a whole Makefile and eat the bin_PROGRAMS lines.
                # Also skip make-variable expansions ($(bin_PROGRAMS) in
                # check-* recipes) — only literal program names count.
                s = line.strip()
                if not s or s.startswith("#") or "$" in s:
                    continue
                if "bin_PROGRAMS" not in s:
                    continue
                rhs = s.split("=", 1)[1] if "=" in s else ""
                toks += rhs.split()
            for tok in toks:
                tok = tok.strip().strip("\\")
                if tok.endswith("d") and len(tok) > 1 and "-" not in tok and "_" not in tok:
                    daemon = tok
                    break
        if daemon:
            stem = daemon[:-1]
        syscpp = SourceReader.slurp(src_dir / "src" / "util" / "system.cpp")
        if syscpp:
            m = re.search(r"GetDefaultDataDir\(\).*?return\s+pathRet\s*/\s*\"\.([^\"]+)\"", syscpp, flags=re.S)
            if m:
                dir_linux = m.group(1)
            m = re.search(r"Library/Application Support/([A-Za-z0-9_]+)", syscpp)
            if m:
                dir_mac = m.group(1)
            m = re.search(r"GetSpecialFolderPath\(CSIDL_APPDATA\)\s*/\s*\"([^\"]+)\"", syscpp)
            if m:
                dir_win = m.group(1)
        return {
            "daemon": daemon or (stem + "d"),
            "stem": stem,
            "conf_name": f"{stem}.conf",
            "dir_linux": dir_linux,
            "dir_mac": dir_mac,
            "dir_win": dir_win,
        }

    def extract_scaffold_params(self, src_dir: Path, want_test: bool = False) -> Dict[str, Any]:
        out: Dict[str, Any] = {}
        txt = SourceReader.slurp(src_dir / "src/chainparams.cpp")
        if txt is not None:
            s, e = CppSourceInspector.mainnet_slice(txt, want_test)
            m, ln = CppSourceInspector.regex_in_block(txt, s, e, r"\bnDefaultPort\s*=\s*(\d+)")
            if m:
                out["port"] = (int(m.group(1)), f"src/chainparams.cpp:{ln}")

        txt2 = SourceReader.slurp(src_dir / "src/chainparamsbase.cpp")
        if txt2 is not None:
            m = re.search(r"nRPCPort\s*=\s*(\d+)", txt2)
            if m:
                out["rpcport"] = (int(m.group(1)), f"src/chainparamsbase.cpp:{txt2[:m.start()].count(chr(10)) + 1}")
            else:
                tm = re.search(r'CBaseChainParams[^"]*"[^"]*",\s*(\d+)', txt2)
                if tm:
                    out["rpcport"] = (int(tm.group(1)), f"src/chainparamsbase.cpp:{txt2[:tm.start()].count(chr(10)) + 1}")

        if txt is not None:
            s, e = CppSourceInspector.mainnet_slice(txt, want_test)
            chain_tmp = CppSourceInspector._current_chain(src_dir)
            for ckey, pkey in (("AddressPrefix", "PUBKEY_ADDRESS"), ("ScriptPrefix", "SCRIPT_ADDRESS"), ("SecretPrefix", "SECRET_KEY")):
                v, ln = CppSourceInspector.prefix_value(txt, s, e, pkey, chain_tmp)
                if v is not None:
                    out[ckey] = (v, f"src/chainparams.cpp:{ln}")
            v2, ln2 = CppSourceInspector.prefix_value(txt, s, e, "SCRIPT_ADDRESS2", chain_tmp)
            if v2 is not None:
                out["ScriptAddress2"] = (v2, f"src/chainparams.cpp:{ln2}")

        for _rel in ("src/amount.h", "src/consensus/amount.h"):
            atxt = SourceReader.slurp_src(src_dir, _rel) or SourceReader.slurp(src_dir / _rel)
            if atxt is None:
                continue
            v, ev = CppSourceInspector.coin_value_from_amount_h(atxt, _rel, src_dir)
            if v is None:
                continue
            out["COIN"] = (v, ev)
            break

        if txt is not None:
            s, e = CppSourceInspector.mainnet_slice(txt, want_test)
            m2, ln2 = CppSourceInspector.regex_in_block(txt, s, e, r"(?:nPowTargetSpacing|nTargetSpacing|nStakeTargetSpacing)\s*=\s*([\d.]+(?:\s*\*\s*[\d.]+)?)")
            if m2:
                _bt = _safe_arith_float(m2.group(1))
                if _bt is not None:
                    out["BlockTime"] = (int(float(_bt)), f"src/chainparams.cpp:{ln2}")

        ttxt = SourceReader.slurp(src_dir / "src/primitives/transaction.h")
        if ttxt is not None:
            m_cur = re.search(r"CURRENT_VERSION\s*=\s*(-?\d+)", ttxt)
            cur = int(m_cur.group(1)) if m_cur else 1
            m_mx = re.search(r"MAX_STANDARD_VERSION\s*=\s*(-?\d+)", ttxt)
            mx = int(m_mx.group(1)) if m_mx else cur
            out["TxVersion"] = (cur, f"src/primitives/transaction.h CURRENT={cur} MAX={mx}")

        rate, rate_ev, dust, dust_ev = CppSourceInspector.fee_constants(src_dir)
        if rate is not None:
            out["relay_rate"] = (rate, rate_ev)
        if dust is not None:
            out["dust_rate"] = (dust, dust_ev)
        is_go_tree = (src_dir / "go.mod").exists() and SourceReader.slurp(
            src_dir / "src/chainparams.cpp") is None
        out["fee_policy"] = (BtcdSourceInspector.fee_policy(src_dir)
                             if is_go_tree else CppSourceInspector.fee_policy(src_dir))

        vtxt = SourceReader.slurp(src_dir / "src/validation.h")
        if vtxt is not None:
            m = re.search(r"DEFAULT_TXINDEX\s*=\s*(true|false)", vtxt)
            if m:
                out["DEFAULT_TXINDEX"] = (m.group(1) == "true", f"src/validation.h:{vtxt[:m.start()].count(chr(10)) + 1}")

        if ttxt is not None:
            txt_stripped = SourceReader.strip_comments(ttxt)
            member = re.search(r"(?:const\s+)?(?:unsigned\s+|u?int\d*_t\s+)nTime\s*;", txt_stripped)
            serialized = re.search(r">>s*(?:tx\.)?nTime\b", txt_stripped) or re.search(r"READWRITE\([^)]*\bnTime\b", txt_stripped)
            has_ntime = bool(member or serialized)
            out["TxWithTimeField"] = (has_ntime, f"src/primitives/transaction.h nTime {'serialized' if has_ntime else 'not serialized'}")

        itxt = ""
        for rel in ("src/init.cpp", "src/wallet/init.cpp"):
            t = SourceReader.slurp(src_dir / rel)
            if t:
                itxt += t
        out["_addresstype_registered"] = '"-addresstype"' in itxt

        if "ScriptPrefix" in out and "ScriptAddress2" in out:
            sa = out["ScriptPrefix"][0]
            sa2 = out["ScriptAddress2"][0]
            minted, ev = CppSourceInspector.minted_script_prefix(src_dir, sa, sa2)
            if minted is not None and minted != sa:
                out["ScriptPrefix"] = (minted, f"{ev} (minted, raw P2SH={sa} decode-compat={sa2})")

        out["_family"] = "btcd" if (txt is None and (src_dir / "go.mod").exists()) else "btc"
        return out

    def run(
        self, args: argparse.Namespace, manifest: List[ManifestCoin], repo_root: Path
    ) -> Tuple[int, Dict[str, Any]]:
        # Envelope handed back to main() for --report. Scaffold runs no audit,
        # so repos/local/findings stay empty and the substance is plan[] plus
        # the extracted scaffold payload below.
        plan: List[Dict[str, Any]] = []
        result: Dict[str, Any] = {
            "mode": "scaffold", "plan": plan, "applied": False, "error": None,
        }
        repo_url = args.repo_url
        if not repo_url:
            report_line("ERROR: --scaffold requires --repo-url <url>")
            result["error"] = "--scaffold requires --repo-url <url>"
            return 2, result
        # Fleet convention is bare repo URLs (no trailing .git): normalize the
        # input so --apply output matches, instead of flagging our own entry
        # MOVED on the next audit pass.
        repo_url = repo_url.rstrip("/").removesuffix(".git")

        ticker = (args.scaffold_ticker or self.derive_ticker(repo_url)).upper()
        tag = args.scaffold_tag
        if not tag:
            report_line(f"Probing tags for {repo_url} ...")
            status, tags = self.probe_service.probe_tags(repo_url, args.timeout)
            if status != RepoStatus.ALIVE or not tags:
                report_line(f"ERROR: could not probe tags (status {status.value})")
                result["error"] = f"could not probe tags (status {status.value})"
                return 1, result
            stable = VersionEngine.stable_tags(tags)
            tag = VersionEngine.max_version_tag(stable)
            if not tag:
                report_line("ERROR: no stable tag found")
                result["error"] = "no stable tag found"
                return 1, result
            report_line(f"Auto-detected tag: {tag}")
        else:
            report_line(f"Using supplied tag: {tag}")

        report_line(f"Ticker: {ticker}")
        tmp_root = CACHE_ROOT
        tmp_root.mkdir(parents=True, exist_ok=True)
        target = tmp_root / f"scaffold_{ticker.lower()}_check"
        shutil.rmtree(target, ignore_errors=True)

        report_line(f"Cloning {repo_url} @ {tag} ...")
        proc = self.runner.run(
            ["git", "clone", "-q", "--depth", "1", "--branch", tag, repo_url, str(target)],
            max(args.timeout, 60),
            env_extra={"GIT_TERMINAL_PROMPT": "0"},
        )
        if proc is None or proc.returncode != 0 or not target.is_dir():
            report_line(f"ERROR: clone failed for {repo_url} @ {tag}")
            shutil.rmtree(target, ignore_errors=True)
            result["error"] = f"clone failed for {repo_url} @ {tag}"
            return 1, result

        want_test = ticker.upper() in ("TBLOCK", "TSYS", "TPIVX", "TBTC", "TBCH")
        params = self.extract_scaffold_params(target, want_test)

        fleet = PortCollisionManager.collect_port_collisions(manifest, repo_root)
        used_p2p = set(fleet["p2p"].keys()) | set(fleet["test_p2p"].keys())
        used_rpc = set(fleet["rpc"].keys()) | set(fleet["test_rpc"].keys()) | set(fleet["xbridge"].keys())

        src_port = params.get("port", (8333, "fallback"))[0]
        src_rpc = params.get("rpcport", (8332, "fallback"))[0]

        p2p, rpc = src_port, src_rpc
        if p2p in used_p2p or rpc in used_rpc:
            pair_p2p, pair_rpc = PortCollisionManager.find_free_pair(src_port, src_rpc, used_p2p, used_rpc)
            if pair_p2p and pair_rpc:
                p2p, rpc = pair_p2p, pair_rpc
                report_line(f"Port collision: source p2p {src_port} rpc {src_rpc} -> proposing free p2p {p2p} rpc {rpc}")
        else:
            report_line(f"Ports p2p {p2p} rpc {rpc} are free (no collision)")

        coin_val = params.get("COIN", (100000000, "fallback"))[0]
        blocktime = params.get("BlockTime", (150, "fallback"))[0]
        txver = params.get("TxVersion", (1, ""))[0]
        prefixes = {
            "AddressPrefix": params.get("AddressPrefix", (0, ""))[0],
            "ScriptPrefix": params.get("ScriptPrefix", (5, ""))[0],
            "SecretPrefix": params.get("SecretPrefix", (128, ""))[0],
        }

        relay_entry = params.get("relay_rate")
        fee_policy = params.get("fee_policy")
        if relay_entry is None or relay_entry[0] in (None, 0) or fee_policy is None \
                or fee_policy.rounding == "unknown":
            report_line("ERROR: fee source unresolvable — refusing silent defaults "
                        "(no MinTxFee/FeePerByte emitted). Provide a source tree with "
                        "parseable relay/inclusion constants and GetFee body.")
            result["error"] = "fee source unresolvable — refusing silent defaults"
            return 1, result
        relay = relay_entry[0]
        mtf, fpb = recommended_fees(fee_policy, relay)

        title = getattr(args, "scaffold_name", None) or ticker.title()
        ident = CoinScaffolder.derive_identity(target, ticker)
        report_line(f"Identity: daemon {ident['daemon']} conf {ident['conf_name']} "
                    f"dirs {ident['dir_linux']}/{ident['dir_mac']}/{ident['dir_win']}")
        family = params.get("_family", "btc")
        addreg = params.get("_addresstype_registered", False)
        tx_with_time = params.get("TxWithTimeField", (False, ""))[0]

        # Generate wallet conf
        w_lines = [
            "server=1", "listen=1", "rpcuser=", "rpcpassword=",
            "rpcallowip=127.0.0.1", f"port={p2p}", f"rpcport={rpc}", "txindex=1", "",
        ]
        if addreg:
            w_lines += ["# Legacy addresses must be used", "addresstype=legacy", "changetype=legacy", ""]
        w_lines += ["# Enable rpcserialversion", "rpcserialversion=1", ""]
        wallet_txt = "\n".join(w_lines)

        # Generate XBridge conf
        x_lines = [
            f"[{ticker}]", f"Title={title}", "Address=", "Ip=127.0.0.1", f"Port={rpc}",
            "Username=", "Password=",
            f"AddressPrefix={prefixes.get('AddressPrefix', 0)}",
            f"ScriptPrefix={prefixes.get('ScriptPrefix', 5)}",
            f"SecretPrefix={prefixes.get('SecretPrefix', 128)}",
            f"COIN={coin_val}", "MinimumAmount=0", f"TxVersion={txver}", "DustAmount=0",
            "CreateTxMethod=BTC", "GetNewKeySupported=false", "ImportWithNoScanSupported=false",
            f"MinTxFee={mtf}", f"BlockTime={blocktime}", f"FeePerByte={fpb}", "Confirmations=0", "",
        ]
        if tx_with_time:
            x_lines.insert(12, "TxWithTimeField=true")
        xbridge_txt = "\n".join(x_lines)

        ver_id = f"{ident['stem']}--{tag}"
        wallet_name = f"{ver_id}.conf"
        xbridge_name = f"{ver_id}.conf"

        out_dir = Path(args.scaffold_out_dir) if args.scaffold_out_dir else Path(f"/tmp/newcoin_{ticker.lower()}")
        (out_dir / "wallet-confs").mkdir(parents=True, exist_ok=True)
        (out_dir / "xbridge-confs").mkdir(parents=True, exist_ok=True)

        wpath = out_dir / "wallet-confs" / wallet_name
        xpath = out_dir / "xbridge-confs" / xbridge_name
        wpath.write_text(wallet_txt, encoding="utf-8")
        xpath.write_text(xbridge_txt, encoding="utf-8")

        manifest_snippet = {
            "blockchain": title,
            "ticker": ticker,
            "ver_id": ver_id,
            "ver_name": f"{title} {tag}",
            "conf_name": ident["conf_name"],
            "dir_name_linux": ident["dir_linux"],
            "dir_name_mac": ident["dir_mac"],
            "dir_name_win": ident["dir_win"],
            "repo_url": repo_url,
            "versions": [tag],
            "wallet_conf": wallet_name,
            "xbridge_conf": xbridge_name,
            "daemon_family": family if family == "btcd" else "btc",
        }
        snippet_path = out_dir / "manifest_snippet.json"
        snippet_path.write_text(json.dumps(manifest_snippet, indent=2) + "\n", encoding="utf-8")

        report_line("\n=== SCAFFOLD EXTRACT (file:line) ===")
        for k in ("port", "rpcport", "AddressPrefix", "ScriptPrefix", "SecretPrefix", "COIN", "BlockTime", "TxVersion", "relay_rate"):
            if k in params:
                report_line(f"  {k} = {params[k][0]} ({params[k][1]})")
        report_line(f"  family = {params.get('_family', 'btc')}")

        report_line(f"\n=== GENERATED wallet-confs/{wallet_name} ===")
        report_line(wallet_txt)
        report_line(f"=== GENERATED xbridge-confs/{xbridge_name} ===")
        report_line(xbridge_txt)
        report_line(f"=== MANIFEST SNIPPET ({snippet_path}) ===")
        report_line(json.dumps(manifest_snippet, indent=2))

        # Record what a --apply run would put into the repo. It is recorded
        # whether or not the write happens, so an agent can read the target
        # file list before deciding to apply, and audit it afterwards.
        dry_run = bool(getattr(args, "dry_run", False))
        will_apply = bool(args.apply) and not dry_run
        for target_file, reason in (
            (f"wallet-confs/{wallet_name}", "scaffold: write the extracted wallet conf into the repo"),
            (f"xbridge-confs/{xbridge_name}", "scaffold: write the extracted xbridge conf into the repo"),
            ("manifest-latest.json", "scaffold: append the new manifest entry"),
        ):
            plan.append(plan_entry(
                target_file,
                ticker if target_file == "manifest-latest.json" else "*",
                None,
                ver_id if target_file == "manifest-latest.json" else f"generated for {ticker} {tag}",
                reason,
                "scaffold", coin=ticker, ver_id=ver_id, applied=will_apply,
            ))
        result.update({
            "ticker": ticker,
            "tag": tag,
            "ver_id": ver_id,
            "repo_url": repo_url,
            "wallet_conf": wallet_name,
            "xbridge_conf": xbridge_name,
            "out_dir": str(out_dir),
            "ports": {"p2p": p2p, "rpc": rpc},
            "identity": ident,
            "manifest_snippet": manifest_snippet,
            "applied": False,
        })

        if args.apply and dry_run:
            report_line(f"Dry-run: would write {repo_root / 'wallet-confs' / wallet_name} and "
                        f"{repo_root / 'xbridge-confs' / xbridge_name} and patch manifest-latest.json "
                        f"(suppressed by --dry-run)")
        elif args.apply:
            real_w = repo_root / "wallet-confs" / wallet_name
            real_x = repo_root / "xbridge-confs" / xbridge_name
            if real_w.exists() or real_x.exists():
                report_line(f"ERROR: --apply target already exists: {real_w} or {real_x}")
                result["error"] = f"--apply target already exists: {real_w} or {real_x}"
                return 1, result
            shutil.copy(wpath, real_w)
            shutil.copy(xpath, real_x)

            mpath = repo_root / "manifest-latest.json"
            raw_manifest = json.loads(SourceReader.slurp(mpath) or "[]")
            raw_manifest.append(manifest_snippet)
            raw_manifest.sort(key=lambda x: x.get("ticker", ""))
            mpath.write_text(json.dumps(raw_manifest, indent=2) + "\n", encoding="utf-8")
            report_line(f"Applied: wrote {real_w} and {real_x} and patched manifest ({len(raw_manifest)} entries now)")
            report_line(f"Next: run create-j2-confs.py --coins {ticker} and validate in-memory render")
            result["applied"] = True
            for e in plan:
                e["applied"] = True
        else:
            report_line(f"Print-only (no --apply): files under {out_dir} (not in repo)")

        report_line(f"Source clone kept at {target} for inspection")
        return 0, result
