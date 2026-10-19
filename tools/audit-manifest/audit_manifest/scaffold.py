"""Coin scaffolding: extract fleet facts from a fresh clone and emit confs.

``CoinScaffolder.run`` probes the repo, resolves the chosen tag through
the shared per-coin checkout (cloned, reused or fetched), extracts
ports/prefixes/fees from source, picks collision-free ports
against the live fleet, and writes (or prints) the new wallet/xbridge conf
pair plus a manifest snippet. Every user-facing line goes through
:func:`report_line`.
"""

from __future__ import annotations

import argparse
import json
import re
import tempfile
from pathlib import Path
from typing import Any

from .apply_plan import apply_entries, manifest_target
from .checkout import (
    SourceCheckoutManager,
    SourceReader,
    canonical_repo_url,
    repo_checkout_dir,
)
from .inspectors import (
    BtcdSourceInspector,
    CppSourceInspector,
    coin_value_from_amount_h,
    current_chain,
    mainnet_slice,
    regex_in_block,
)
from .inspectors.base import NTIME_SERIALIZED_RE, line_of
from .model import ManifestCoin, RepoStatus, recommended_fees
from .ports import PortCollisionManager
from .probe import RemoteProbeService, SystemCommandRunner
from .progress import emit
from .reporting import report_line
from .util import _safe_arith_float, plan_entry, repo_relative
from .versioning import VersionEngine

# Coins whose scaffolded network IS the testnet. There is no reliable
# in-source signal for operator intent, so this tuple is the single
# place to extend; an explicit --testnet scaffold flag is the long-term
# replacement (see tools/audit-manifest/README.md, scaffold section).
_TESTNET_TICKERS = ("TBLOCK", "TSYS", "TPIVX", "TBTC", "TBCH")


def ensure_out_dir(path: Path) -> str | None:
    """Create the staging dir, refusing symlink hijacks."""
    if path.is_symlink():
        return f"refusing symlink staging dir: {path}"
    # 0700: staging holds generated confs (rpcuser placeholders, derived params).
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    return None


def scaffold_target_checks(
    ticker: str,
    wallet_name: str,
    xbridge_name: str,
    repo_root: Path,
    manifest_path: Path | None = None,
) -> str | None:
    """Upfront all-or-nothing gate: no partial coin ever lands."""
    real_w = repo_root / "wallet-confs" / wallet_name
    real_x = repo_root / "xbridge-confs" / xbridge_name
    if real_w.exists() or real_x.exists():
        return f"--apply target already exists: {real_w} or {real_x}"
    try:
        raw = json.loads(manifest_target(repo_root, manifest_path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return "--apply manifest unreadable"
    if not isinstance(raw, list):
        return "--apply manifest is not an array"
    if any(isinstance(e, dict) and e.get("ticker") == ticker for e in raw):
        return f"--apply {ticker} already in the manifest"
    return None


def propose_scaffold_ports(
    src_port: int,
    src_rpc: int,
    used_p2p: set[int],
    used_rpc: set[int],
) -> tuple[int, int] | None:
    """Free p2p/rpc pair, preferring source values; None when crowded out."""
    used = used_p2p | used_rpc
    if src_port not in used and src_rpc not in used and src_port != src_rpc:
        return src_port, src_rpc
    pair_p2p, pair_rpc = PortCollisionManager.find_free_pair(src_port, src_rpc, used_p2p, used_rpc)
    if pair_p2p and pair_rpc:
        return pair_p2p, pair_rpc
    return None


def scaffold_plan_entries(  # noqa: PLR0913, PLR0917  # scaffold plan-entry schema family: one field per plan column
    ticker: str,
    ver_id: str,
    tag: str,
    wallet_name: str,
    xbridge_name: str,
    wallet_txt: str,
    xbridge_txt: str,
    manifest_snippet: dict[str, Any],
    manifest_rel: str,
) -> list[dict[str, Any]]:
    """Staged entries embed everything Apply needs: file bytes inline."""
    entries = [
        plan_entry(
            f"wallet-confs/{wallet_name}",
            "*",
            None,
            f"generated for {ticker} {tag}",
            "scaffold: write the extracted wallet conf into the repo",
            "scaffold",
            coin=ticker,
            ver_id=ver_id,
            applied=False,
        ),
        plan_entry(
            f"xbridge-confs/{xbridge_name}",
            "*",
            None,
            f"generated for {ticker} {tag}",
            "scaffold: write the extracted xbridge conf into the repo",
            "scaffold",
            coin=ticker,
            ver_id=ver_id,
            applied=False,
        ),
        plan_entry(
            manifest_rel,
            ticker,
            None,
            ver_id,
            "scaffold: append the new manifest entry",
            "scaffold",
            coin=ticker,
            ver_id=ver_id,
            applied=False,
        ),
    ]
    entries[0]["contents"] = wallet_txt
    entries[1]["contents"] = xbridge_txt
    entries[2]["snippet"] = manifest_snippet
    return entries


def _scaffold_ports(txt: str | None, txt2: str | None, *, want_test: bool) -> dict[str, Any]:
    """p2p port from chainparams.cpp, rpcport from chainparamsbase.cpp."""
    out: dict[str, Any] = {}
    if txt is not None:
        s, e = mainnet_slice(txt, want_test=want_test)
        m, ln = regex_in_block(txt, s, e, r"\bnDefaultPort\s*=\s*(\d+)")
        if m:
            out["port"] = (int(m.group(1)), f"src/chainparams.cpp:{ln}")
    if txt2 is not None:
        m = re.search(r"nRPCPort\s*=\s*(\d+)", txt2)
        if m:
            out["rpcport"] = (int(m.group(1)), f"src/chainparamsbase.cpp:{line_of(txt2, m)}")
        else:
            tm = re.search(r'CBaseChainParams[^"]*"[^"]*",\s*(\d+)', txt2)
            if tm:
                out["rpcport"] = (int(tm.group(1)), f"src/chainparamsbase.cpp:{line_of(txt2, tm)}")
    return out


def _scaffold_prefixes(txt: str | None, *, want_test: bool, src_dir: Path) -> dict[str, Any]:
    """Base58 prefixes from the mainnet slice, honoring CURRENT_CHAIN gating."""
    out: dict[str, Any] = {}
    if txt is None:
        return out
    s, e = mainnet_slice(txt, want_test=want_test)
    chain_tmp = current_chain(src_dir)
    for ckey, pkey in (
        ("AddressPrefix", "PUBKEY_ADDRESS"),
        ("ScriptPrefix", "SCRIPT_ADDRESS"),
        ("SecretPrefix", "SECRET_KEY"),
    ):
        v, ln = CppSourceInspector.prefix_value(txt, s, e, pkey, chain_tmp)
        if v is not None:
            out[ckey] = (v, f"src/chainparams.cpp:{ln}")
    v2, ln2 = CppSourceInspector.prefix_value(txt, s, e, "SCRIPT_ADDRESS2", chain_tmp)
    if v2 is not None:
        out["ScriptAddress2"] = (v2, f"src/chainparams.cpp:{ln2}")
    return out


def _scaffold_coin_value(src_dir: Path) -> dict[str, Any]:
    """COIN from amount.h (CAmount CENT), wrapper-aware."""
    for rel in ("src/amount.h", "src/consensus/amount.h"):
        atxt = SourceReader.read_src(src_dir, rel)
        if atxt is None:
            continue
        v, ev = coin_value_from_amount_h(atxt, rel, src_dir)
        if v is None:
            continue
        return {"COIN": (v, ev)}
    return {}


def _scaffold_block_time(txt: str | None, *, want_test: bool) -> dict[str, Any]:
    """Effective target spacing from the mainnet slice."""
    if txt is None:
        return {}
    s, e = mainnet_slice(txt, want_test=want_test)
    m2, ln2 = regex_in_block(
        txt,
        s,
        e,
        r"(?:nPowTargetSpacing|nTargetSpacing|nStakeTargetSpacing)"
        r"\s*=\s*([\d.]+(?:\s*\*\s*[\d.]+)?)",
    )
    if not m2:
        return {}
    _bt = _safe_arith_float(m2.group(1))
    if _bt is None:
        return {}
    return {"BlockTime": (int(float(_bt)), f"src/chainparams.cpp:{ln2}")}


def _scaffold_tx_wire(ttxt: str | None, src_dir: Path) -> dict[str, Any]:
    """TxVersion, nTime serialization and DEFAULT_TXINDEX."""
    out: dict[str, Any] = {}
    if ttxt is not None:
        m_cur = re.search(r"CURRENT_VERSION\s*=\s*(-?\d+)", ttxt)
        cur = int(m_cur.group(1)) if m_cur else 1
        m_mx = re.search(r"MAX_STANDARD_VERSION\s*=\s*(-?\d+)", ttxt)
        mx = int(m_mx.group(1)) if m_mx else cur
        out["TxVersion"] = (cur, f"src/primitives/transaction.h CURRENT={cur} MAX={mx}")

        txt_stripped = SourceReader.strip_comments(ttxt)
        member = re.search(r"(?:const\s+)?(?:unsigned\s+|u?int\d*_t\s+)nTime\s*;", txt_stripped)
        serialized = NTIME_SERIALIZED_RE.search(txt_stripped) or re.search(r"READWRITE\([^)]*\bnTime\b", txt_stripped)
        has_ntime = bool(member or serialized)
        out["TxWithTimeField"] = (
            has_ntime,
            f"src/primitives/transaction.h nTime {'serialized' if has_ntime else 'not serialized'}",
        )

    vtxt = SourceReader.slurp(src_dir / "src/validation.h")
    if vtxt is not None:
        m = re.search(r"DEFAULT_TXINDEX\s*=\s*(true|false)", vtxt)
        if m:
            out["DEFAULT_TXINDEX"] = (m.group(1) == "true", f"src/validation.h:{line_of(vtxt, m)}")
    return out


def _scaffold_fees(src_dir: Path) -> dict[str, Any]:
    """Relay/dust rates, fee policy and the Go-tree (btcd) signal."""
    out: dict[str, Any] = {}
    rate, rate_ev, dust, dust_ev = CppSourceInspector.fee_constants(src_dir)
    if rate is not None:
        out["relay_rate"] = (rate, rate_ev)
    if dust is not None:
        out["dust_rate"] = (dust, dust_ev)
    is_go_tree = (src_dir / "go.mod").exists() and SourceReader.slurp(src_dir / "src/chainparams.cpp") is None
    out["fee_policy"] = (
        BtcdSourceInspector.fee_policy(src_dir) if is_go_tree else CppSourceInspector.fee_policy(src_dir)
    )
    return out


def _scaffold_addresstype(src_dir: Path) -> bool:
    """Whether the daemon registers -addresstype (legacy-address signal)."""
    itxt = ""
    for rel in ("src/init.cpp", "src/wallet/init.cpp"):
        t = SourceReader.slurp(src_dir / rel)
        if t:
            itxt += t
    return '"-addresstype"' in itxt


def _daemon_from_makefile(mk: str) -> str | None:
    """The literal bin_PROGRAMS daemon name from a Makefile.am, else None."""
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
    for raw_tok in toks:
        tok = raw_tok.strip().strip("\\")
        if tok.endswith("d") and len(tok) > 1 and "-" not in tok and "_" not in tok:
            return tok
    return None


class CoinScaffolder:
    """Automates repository cloning, parameter extraction, and template emission for new coins."""

    def __init__(self, runner: SystemCommandRunner | None = None, probe_service: RemoteProbeService | None = None):
        self.runner = runner or SystemCommandRunner()
        self.probe_service = probe_service or RemoteProbeService()

    @staticmethod
    def derive_ticker(repo_url: str) -> str:
        base = repo_url.rstrip("/").removesuffix(".git").split("/")[-1] if repo_url else "COIN"
        base = re.sub(r"[-_]?core$", "", base, flags=re.I)
        base = re.sub(r"[-_]?project$", "", base, flags=re.I)
        base = re.sub(r"[^A-Za-z0-9]", "", base)
        return (base[:8] or "COIN").upper()

    @staticmethod
    def derive_identity(src_dir: Path, ticker: str) -> dict[str, str]:
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
            daemon = _daemon_from_makefile(mk)
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

    def extract_scaffold_params(self, src_dir: Path, *, want_test: bool = False) -> dict[str, Any]:
        """Pull every scaffoldable parameter out of the source tree.

        Each entry is ``(value, evidence)`` so the generated conf can cite
        where the number came from; ``_``-prefixed entries are internal
        flags the generator reads.
        """
        txt = SourceReader.slurp(src_dir / "src/chainparams.cpp")
        txt2 = SourceReader.slurp(src_dir / "src/chainparamsbase.cpp")
        ttxt = SourceReader.slurp(src_dir / "src/primitives/transaction.h")

        out: dict[str, Any] = {}
        out.update(_scaffold_ports(txt, txt2, want_test=want_test))
        out.update(_scaffold_prefixes(txt, want_test=want_test, src_dir=src_dir))
        out.update(_scaffold_coin_value(src_dir))
        out.update(_scaffold_block_time(txt, want_test=want_test))
        out.update(_scaffold_tx_wire(ttxt, src_dir))
        out.update(_scaffold_fees(src_dir))
        out["_addresstype_registered"] = _scaffold_addresstype(src_dir)

        if "ScriptPrefix" in out and "ScriptAddress2" in out:
            sa = out["ScriptPrefix"][0]
            sa2 = out["ScriptAddress2"][0]
            minted, ev = CppSourceInspector.minted_script_prefix(src_dir, sa, sa2)
            if minted is not None and minted != sa:
                out["ScriptPrefix"] = (minted, f"{ev} (minted, raw P2SH={sa} decode-compat={sa2})")

        out["_family"] = "btcd" if (txt is None and (src_dir / "go.mod").exists()) else "btc"
        return out

    def _propose_scaffold_ports(
        self, params: dict[str, Any], manifest: list[ManifestCoin], repo_root: Path
    ) -> tuple[tuple[int, int] | None, int, int]:
        """Resolve a free p2p/rpc pair for the new coin against the fleet.

        Returns ``(proposed_pair_or_None, source_port, source_rpc)``.
        """
        fleet = PortCollisionManager.collect_port_collisions(manifest, repo_root)
        used_p2p = set(fleet["p2p"].keys()) | set(fleet["test_p2p"].keys())
        used_rpc = set(fleet["rpc"].keys()) | set(fleet["test_rpc"].keys()) | set(fleet["xbridge"].keys())
        src_port = params.get("port", (8333, "fallback"))[0]
        src_rpc = params.get("rpcport", (8332, "fallback"))[0]
        proposed = propose_scaffold_ports(src_port, src_rpc, used_p2p, used_rpc)
        return proposed, src_port, src_rpc

    def _generate_conf_pair(  # noqa: PLR0913  # one input per conf field, keyword-only at the call site
        self,
        *,
        params: dict[str, Any],
        ticker: str,
        title: str,
        p2p: int,
        rpc: int,
        mtf: int,
        fpb: int,
        conventional: list[str],
    ) -> tuple[str, str]:
        """Render the wallet + xbridge conf pair from the extracted params.

        Params carry ``(value, evidence)`` when parsed from source; an
        evidence of "fallback" marks a conventional default — never a
        parsed value — and is appended to ``conventional``, which the
        caller reports and the generated conf comments, so no silent
        defaults.
        """
        addreg = params.get("_addresstype_registered", False)
        tx_with_time = params.get("TxWithTimeField", (False, ""))[0]

        def _param(key: str, default: Any) -> Any:
            value, ev = params.get(key, (default, "fallback"))
            if ev == "fallback":
                conventional.append(f"{key}={value}")
            return value

        prefixes = {
            "AddressPrefix": _param("AddressPrefix", 0),
            "ScriptPrefix": _param("ScriptPrefix", 5),
            "SecretPrefix": _param("SecretPrefix", 128),
        }
        coin_val = _param("COIN", 100000000)
        blocktime = _param("BlockTime", 150)
        txver = _param("TxVersion", 1)

        # Generate wallet conf
        w_lines = [
            "server=1",
            "listen=1",
            "rpcuser=",
            "rpcpassword=",
            "rpcallowip=127.0.0.1",
            f"port={p2p}",
            f"rpcport={rpc}",
            "txindex=1",
            "",
        ]
        if addreg:
            w_lines += ["# Legacy addresses must be used", "addresstype=legacy", "changetype=legacy", ""]
        w_lines += ["# Enable rpcserialversion", "rpcserialversion=1", ""]
        wallet_txt = "\n".join(w_lines)

        # Generate XBridge conf
        x_lines = [
            f"[{ticker}]",
            f"Title={title}",
            "Address=",
            "Ip=127.0.0.1",
            f"Port={rpc}",
            "Username=",
            "Password=",
        ]
        if conventional:
            x_lines.append("# conventional defaults, NOT parsed from source: " + ", ".join(conventional))
        x_lines += [
            f"AddressPrefix={prefixes.get('AddressPrefix', 0)}",
            f"ScriptPrefix={prefixes.get('ScriptPrefix', 5)}",
            f"SecretPrefix={prefixes.get('SecretPrefix', 128)}",
            f"COIN={coin_val}",
            "MinimumAmount=0",
            f"TxVersion={txver}",
            "DustAmount=0",
            "CreateTxMethod=BTC",
            "GetNewKeySupported=false",
            "ImportWithNoScanSupported=false",
            f"MinTxFee={mtf}",
            f"BlockTime={blocktime}",
            f"FeePerByte={fpb}",
            "Confirmations=0",
            "",
        ]
        if tx_with_time:
            # Anchor by value (immediately before TxVersion), not by a magic list index.
            x_lines.insert(x_lines.index(f"TxVersion={txver}"), "TxWithTimeField=true")
        xbridge_txt = "\n".join(x_lines)
        return wallet_txt, xbridge_txt

    def _stage_scaffold_outputs(  # noqa: PLR0913, PLR0917  # staging inputs: one per output artifact
        self,
        out_dir: Path,
        wallet_name: str,
        xbridge_name: str,
        wallet_txt: str,
        xbridge_txt: str,
        manifest_snippet: dict[str, Any],
    ) -> tuple[Path, Path, Path]:
        """Write the staged conf pair and manifest snippet under ``out_dir``."""
        (out_dir / "wallet-confs").mkdir(parents=True, exist_ok=True)
        (out_dir / "xbridge-confs").mkdir(parents=True, exist_ok=True)
        wpath = out_dir / "wallet-confs" / wallet_name
        xpath = out_dir / "xbridge-confs" / xbridge_name
        wpath.write_text(wallet_txt, encoding="utf-8")
        xpath.write_text(xbridge_txt, encoding="utf-8")
        snippet_path = out_dir / "manifest_snippet.json"
        snippet_path.write_text(json.dumps(manifest_snippet, indent=2) + "\n", encoding="utf-8")
        return wpath, xpath, snippet_path

    def _apply_scaffold(  # noqa: PLR0913  # write-path inputs, keyword-only at the call site
        self,
        *,
        args: argparse.Namespace,
        plan: list[dict[str, Any]],
        repo_root: Path,
        ticker: str,
        wallet_name: str,
        xbridge_name: str,
        out_dir: Path,
        result: dict[str, Any],
        manifest_path: Path | None = None,
    ) -> int | None:
        """Run the --apply write path behind the all-or-nothing gate.

        Returns None when the verb was print-only (caller continues), an
        exit code when the run is over.
        """
        manifest = manifest_target(repo_root, manifest_path)
        manifest_rel = repo_relative(manifest, repo_root)
        dry_run = bool(getattr(args, "dry_run", False))
        if args.apply and dry_run:
            report_line(
                f"Dry-run: would write {repo_root / 'wallet-confs' / wallet_name} and "
                f"{repo_root / 'xbridge-confs' / xbridge_name} and patch {manifest_rel} "
                f"(suppressed by --dry-run)"
            )
        elif args.apply:
            gate = scaffold_target_checks(ticker, wallet_name, xbridge_name, repo_root, manifest)
            if gate is not None:
                report_line(f"ERROR: {gate}")
                result["error"] = gate
                return 1
            out = apply_entries(plan, repo_root, manifest_path=manifest)
            refused = [e for e in out if not e.get("applied")]
            for e in refused:
                report_line(f"  refused {e.get('coin')}: {e.get('file')} — {e.get('error')}")
            if refused:
                result["error"] = refused[0].get("error")
                return 1
            try:
                raw = json.loads(manifest.read_text(encoding="utf-8"))
                raw_count = len(raw) if isinstance(raw, list) else 0
            except (OSError, ValueError):
                raw_count = 0
            report_line(
                f"Applied: wrote {repo_root / 'wallet-confs' / wallet_name} and "
                f"{repo_root / 'xbridge-confs' / xbridge_name} and patched manifest ({raw_count} entries now)"
            )
            report_line(f"Next: run create-j2-confs.py --coins {ticker} and validate in-memory render")
            result["applied"] = True
        else:
            report_line(f"Print-only (no --apply): files under {out_dir} (not in repo)")
        return None

    def _scaffold_prelude(self, args: argparse.Namespace, result: dict[str, Any]) -> tuple[str | None, str | None, int]:
        """Validate the scaffold inputs; normalize the repo URL.

        Returns ``(repo_url, ticker, exit_code)``; exit_code is 0 when both
        are usable. The URL is normalized to the fleet convention (no
        trailing .git) so --apply output matches instead of flagging our
        own entry MOVED on the next audit pass — the same helper the reuse
        gate compares with, so the two flows never disagree about URL
        identity. The ticker is validated against the checkout-path
        contract before any I/O so the usage error is structured (exit 2 +
        envelope), not a traceback.
        """
        repo_url = args.repo_url
        if not repo_url:
            report_line("ERROR: --scaffold requires --repo-url <url>")
            result["error"] = "--scaffold requires --repo-url <url>"
            return None, None, 2
        repo_url = canonical_repo_url(repo_url)

        ticker = (args.scaffold_ticker or self.derive_ticker(repo_url)).upper()
        try:
            repo_checkout_dir(ticker)
        except ValueError as exc:
            report_line(f"ERROR: {exc}")
            result["error"] = str(exc)
            return repo_url, None, 2
        return repo_url, ticker, 0

    def _print_scaffold_report(  # noqa: PLR0913, PLR0917  # report inputs: one per block it prints
        self,
        params: dict[str, Any],
        wallet_name: str,
        xbridge_name: str,
        wallet_txt: str,
        xbridge_txt: str,
        manifest_snippet: dict[str, Any],
        snippet_path: Path,
    ) -> None:
        """Print the extract, both generated confs and the manifest snippet."""
        report_line("\n=== SCAFFOLD EXTRACT (file:line) ===")
        for k in (
            "port",
            "rpcport",
            "AddressPrefix",
            "ScriptPrefix",
            "SecretPrefix",
            "COIN",
            "BlockTime",
            "TxVersion",
            "relay_rate",
        ):
            if k in params:
                report_line(f"  {k} = {params[k][0]} ({params[k][1]})")
        report_line(f"  family = {params.get('_family', 'btc')}")

        report_line(f"\n=== GENERATED wallet-confs/{wallet_name} ===")
        report_line(wallet_txt)
        report_line(f"=== GENERATED xbridge-confs/{xbridge_name} ===")
        report_line(xbridge_txt)
        report_line(f"=== MANIFEST SNIPPET ({snippet_path}) ===")
        report_line(json.dumps(manifest_snippet, indent=2))

    def _resolve_scaffold_tag(
        self, args: argparse.Namespace, ticker: str, repo_url: str
    ) -> tuple[str | None, int, str | None]:
        """Resolve the tag to scaffold: --scaffold-tag or the newest stable.

        Returns ``(tag_or_None, exit_code, error_or_None)``.
        """
        tag = args.scaffold_tag
        if tag:
            report_line(f"Using supplied tag: {tag}")
            return tag, 0, None
        emit("scaffold-probe", ticker=ticker)
        report_line(f"Probing tags for {repo_url} ...")
        status, tags = self.probe_service.probe_tags(repo_url, args.timeout)
        if status != RepoStatus.ALIVE or not tags:
            err = f"could not probe tags (status {status.value})"
            report_line(f"ERROR: {err}")
            return None, 1, err
        stable = VersionEngine.stable_tags(tags)
        tag = VersionEngine.max_version_tag(stable)
        if not tag:
            report_line("ERROR: no stable tag found")
            return None, 1, "no stable tag found"
        report_line(f"Auto-detected tag: {tag}")
        return tag, 0, None

    def _resolve_scaffold_source(
        self,
        ticker: str,
        repo_url: str,
        tag: str,
        args: argparse.Namespace,
        result: dict[str, Any],
    ) -> tuple[Path | None, int]:
        """Resolve the local source checkout for the tag. Returns (path, rc)."""
        emit("scaffold-resolve", ticker=ticker)
        report_line(f"Resolving {repo_url} @ {tag} ...")
        target, mode = SourceCheckoutManager(runner=self.runner).resolve_for(
            ticker, repo_url, tag, max(args.timeout, 60)
        )
        if target is None:
            err = f"source resolution failed for {repo_url} @ {tag} ({mode})"
            report_line(f"ERROR: {err}")
            result["error"] = err
            return None, 1
        if mode == "reused":
            report_line(f"Reusing existing checkout for {ticker} @ {tag}")
        elif mode == "fetched":
            report_line(f"Fetched {tag} into the existing checkout for {ticker}")
        elif mode == "cloned":
            report_line(f"Cloned {tag} into {target}")
        return target, 0

    def _propose_and_report_ports(
        self,
        ticker: str,
        params: dict[str, Any],
        manifest: list[ManifestCoin],
        repo_root: Path,
        result: dict[str, Any],
    ) -> tuple[int, int] | None:
        """Propose a free p2p/rpc pair and report the choice.

        Returns the pair, or None when the fleet is crowded out (the
        refusal line is already reported and ``result`` carries it).
        """
        emit("scaffold-ports", ticker=ticker)
        proposed, src_port, src_rpc = self._propose_scaffold_ports(params, manifest, repo_root)
        if proposed is None:
            report_line(f"ERROR: no free p2p/rpc pair near source {src_port}/{src_rpc} — fleet is crowded out")
            result["error"] = f"no free p2p/rpc pair near source {src_port}/{src_rpc}"
            return None
        p2p, rpc = proposed
        if (p2p, rpc) != (src_port, src_rpc):
            report_line(f"Port collision: source p2p {src_port} rpc {src_rpc} -> proposing free p2p {p2p} rpc {rpc}")
        else:
            report_line(f"Ports p2p {p2p} rpc {rpc} are free (no collision)")
        return p2p, rpc

    def _fee_gate(self, params: dict[str, Any], result: dict[str, Any]) -> tuple[int, int] | None:
        """(MinTxFee, FeePerByte) from the resolved fee policy.

        No MinTxFee/FeePerByte may ever be a silent default, so an
        unresolvable fee source refuses the whole scaffold before any
        conf generation; the refusal line is reported and ``result``
        carries it.
        """
        relay_entry = params.get("relay_rate")
        fee_policy = params.get("fee_policy")
        if relay_entry is None or relay_entry[0] in (None, 0) or fee_policy is None or fee_policy.rounding == "unknown":
            report_line(
                "ERROR: fee source unresolvable — refusing silent defaults "
                "(no MinTxFee/FeePerByte emitted). Provide a source tree with "
                "parseable relay/inclusion constants and GetFee body."
            )
            result["error"] = "fee source unresolvable — refusing silent defaults"
            return None
        return recommended_fees(fee_policy, relay_entry[0])

    def _scaffold_identity(self, target: Path, ticker: str, tag: str, args: argparse.Namespace) -> dict[str, Any]:
        """Identity, ver_id and the conventional conf names for this coin."""
        title = getattr(args, "scaffold_name", None) or ticker.title()
        ident = CoinScaffolder.derive_identity(target, ticker)
        report_line(
            f"Identity: daemon {ident['daemon']} conf {ident['conf_name']} "
            f"dirs {ident['dir_linux']}/{ident['dir_mac']}/{ident['dir_win']}"
        )
        ver_id = f"{ident['stem']}--{tag}"
        return {
            "title": title,
            "ident": ident,
            "ver_id": ver_id,
            "wallet_name": f"{ver_id}.conf",
            "xbridge_name": f"{ver_id}.conf",
        }

    def run(  # noqa: PLR0911  # a CLI verb: each failure path returns its structured (rc, envelope); stages are named helpers below
        self, args: argparse.Namespace, manifest: list[ManifestCoin], repo_root: Path, manifest_path: Path | None = None
    ) -> tuple[int, dict[str, Any]]:
        # Envelope handed back to main() for --report. Scaffold runs no audit,
        # so repos/local/findings stay empty and the substance is plan[] plus
        # the extracted scaffold payload below.
        plan: list[dict[str, Any]] = []
        result: dict[str, Any] = {
            "mode": "scaffold",
            "plan": plan,
            "applied": False,
            "error": None,
        }
        repo_url, ticker, rc = self._scaffold_prelude(args, result)
        if rc or repo_url is None or ticker is None:
            # rc==0 guarantees both are set (the prelude's contract); the
            # None arms exist only on its refusal paths.
            return rc, result
        tag, rc, tag_err = self._resolve_scaffold_tag(args, ticker, repo_url)
        if tag is None:
            result["error"] = tag_err
            return rc, result

        report_line(f"Ticker: {ticker}")
        target, rc = self._resolve_scaffold_source(ticker, repo_url, tag, args, result)
        if target is None:
            return rc, result

        want_test = ticker.upper() in _TESTNET_TICKERS
        emit("scaffold-extract", ticker=ticker)
        params = self.extract_scaffold_params(target, want_test=want_test)

        pair = self._propose_and_report_ports(ticker, params, manifest, repo_root, result)
        if pair is None:
            return 1, result
        p2p, rpc = pair

        fees = self._fee_gate(params, result)
        if fees is None:
            return 1, result
        mtf, fpb = fees

        # Conventional (unparsed) defaults are marked inside the generator
        # and reported below — matching the fee refusal above: no silent
        # defaults.
        conventional: list[str] = []

        ident_map = self._scaffold_identity(target, ticker, tag, args)
        title = ident_map["title"]
        ident = ident_map["ident"]
        ver_id = ident_map["ver_id"]
        wallet_name = ident_map["wallet_name"]
        xbridge_name = ident_map["xbridge_name"]
        family = params.get("_family", "btc")

        wallet_txt, xbridge_txt = self._generate_conf_pair(
            params=params,
            ticker=ticker,
            title=title,
            p2p=p2p,
            rpc=rpc,
            mtf=mtf,
            fpb=fpb,
            conventional=conventional,
        )
        if conventional:
            report_line("NOTE: conventional defaults used (not parsed from source): " + ", ".join(conventional))

        emit("scaffold-write", ticker=ticker)
        out_dir = (
            Path(args.scaffold_out_dir)
            if args.scaffold_out_dir
            else Path(tempfile.gettempdir(), f"newcoin_{ticker.lower()}")
        )
        out_dir_error = ensure_out_dir(out_dir)
        if out_dir_error is not None:
            report_line(f"ERROR: {out_dir_error}")
            result["error"] = out_dir_error
            return 1, result
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
        _wpath, _xpath, snippet_path = self._stage_scaffold_outputs(
            out_dir,
            wallet_name,
            xbridge_name,
            wallet_txt,
            xbridge_txt,
            manifest_snippet,
        )

        self._print_scaffold_report(
            params,
            wallet_name,
            xbridge_name,
            wallet_txt,
            xbridge_txt,
            manifest_snippet,
            snippet_path,
        )

        # Record what a --apply run would put into the repo. It is recorded
        # whether or not the write happens, so an agent can read the target
        # file list before deciding to apply, and audit it afterwards.
        plan.extend(
            scaffold_plan_entries(
                ticker,
                ver_id,
                tag,
                wallet_name,
                xbridge_name,
                wallet_txt,
                xbridge_txt,
                manifest_snippet,
                repo_relative(manifest_target(repo_root, manifest_path), repo_root),
            )
        )
        result.update(
            {
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
            }
        )

        applied_rc = self._apply_scaffold(
            args=args,
            plan=plan,
            repo_root=repo_root,
            ticker=ticker,
            wallet_name=wallet_name,
            xbridge_name=xbridge_name,
            out_dir=out_dir,
            result=result,
            manifest_path=manifest_path,
        )
        if applied_rc is not None:
            return applied_rc, result

        report_line(f"Source checkout kept at {target} for inspection (a later pass may switch it)")
        return 0, result
