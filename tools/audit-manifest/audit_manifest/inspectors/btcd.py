"""BtcdSourceInspector: fact-checks Go-based btcd family repositories.

Reads ``chaincfg/params.go``, ``config.go``, ``wire/msgtx.go`` and the Go
module graph. The COIN check resolves offline-first: vendor tree, then the
local module cache (GOPROXY=off), then an in-tree 3-point pin.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from ..checkout import SourceReader
from ..model import FeePolicy, ManifestCoin, ParamStatus, max_status
from ..probe import SystemCommandRunner
from ..util import conf_val_ci


class BtcdSourceInspector:
    """Fact-checks Go-based btcd family repositories (chaincfg/params.go, config.go)."""

    @staticmethod
    def fee_constants(src_dir: Path) -> Tuple[Optional[int], Optional[str], Optional[int], Optional[str]]:
        for rel in ("mempool/policy.go", "policy/policy.go"):
            txt = SourceReader.slurp(src_dir / rel)
            if txt is None:
                continue
            m = re.search(r"DefaultMinRelayTxFee\s*=\s*.*Amount\s*\(\s*(\d+)\s*\)", txt)
            if m:
                try:
                    return int(m.group(1)), f"{rel}:{txt[:m.start()].count(chr(10)) + 1}", None, None
                except ValueError:
                    pass
        return None, None, None, None

    @staticmethod
    def fee_policy(src_dir: Path) -> FeePolicy:
        """Go btcd-lineage policy: floor math with FULL-RATE zero guard
        (calcMinRequiredTxRelayFee: truncated 0 -> full minRelayTxFee)."""
        ev: List[str] = []
        notes: List[str] = []
        for rel in ("mempool/policy.go", "policy/policy.go"):
            txt = SourceReader.slurp(src_dir / rel)
            if txt is None:
                continue
            if "calcMinRequiredTxRelayFee" in txt or "DefaultMinRelayTxFee" in txt:
                ev.append(f"{rel}:btcd floor, full-rate zero guard")
                if "dust" in txt.lower():
                    ev.append(f"{rel}:dust paths present")
                return FeePolicy(
                    rounding="go_floor", mempool="dynamic",
                    zero_guard="full_rate", dust_model="standard",
                    notes=tuple(notes), evidence=tuple(ev),
                )
        return FeePolicy(rounding="unknown", mempool="unknown", evidence=("no Go fee policy found",))

    @staticmethod
    def check_port(coin: ManifestCoin, src_dir: Path, wc: Dict[str, str], repo_root: Path) -> Tuple[ParamStatus, str]:
        txt = SourceReader.slurp(src_dir / "chaincfg/params.go")
        if txt is None:
            return ParamStatus.UNRESOLVED, "btcd layout: chaincfg/params.go not found"
        m = re.search(r'DefaultPort\s*:\s*"(\d+)"', txt) or re.search(r'DefaultPort\s*=\s*"(\d+)"', txt)
        if m is None:
            return ParamStatus.UNRESOLVED, "DefaultPort not found in chaincfg/params.go"
        want = int(m.group(1))
        try:
            got = int(wc.get("port", ""))
        except ValueError:
            return ParamStatus.UNRESOLVED, "wallet conf has no port= line"
        if got == want:
            return ParamStatus.MATCH, f"wallet port={got} == source DefaultPort={want} (chaincfg/params.go:{txt[:m.start()].count(chr(10)) + 1})"
        since = SourceReader.lineage_date(repo_root, f"wallet-confs/{coin.wallet_conf}", "port")
        lin = f"; value present since {since}" if since else ""
        return ParamStatus.WARN, f"wallet port={got} vs source DefaultPort={want} (chaincfg/params.go:{txt[:m.start()].count(chr(10)) + 1}){lin} [fleet-reassigned]"

    @staticmethod
    def check_rpcport(coin: ManifestCoin, src_dir: Path, wc: Dict[str, str], repo_root: Path) -> Tuple[ParamStatus, str]:
        txt = SourceReader.slurp(src_dir / "config.go")
        if txt is not None:
            m = re.search(r"RPCListeners.*default port:\s*(\d+)", txt)
            if m:
                want = int(m.group(1))
                want_ev = f"config.go:{txt[:m.start()].count(chr(10)) + 1}"
                try:
                    got = int(wc.get("rpcport", ""))
                except ValueError:
                    return ParamStatus.UNRESOLVED, f"wallet conf has no rpcport= line (source {want_ev})"
                if got == want:
                    return ParamStatus.MATCH, f"wallet rpcport={got} == source default ({want_ev})"
                since = SourceReader.lineage_date(repo_root, f"wallet-confs/{coin.wallet_conf}", "rpcport")
                lin = f"; value present since {since}" if since else ""
                return ParamStatus.WARN, f"wallet rpcport={got} vs source default {want} ({want_ev}){lin} [fleet-reassigned]"
        return ParamStatus.UNRESOLVED, "btcd RPC port not located in config.go"

    @staticmethod
    def check_prefixes(coin: ManifestCoin, src_dir: Path, xc: Dict[str, str], repo_root: Path) -> Tuple[ParamStatus, str]:
        txt = SourceReader.slurp(src_dir / "chaincfg/params.go")
        if txt is None:
            return ParamStatus.UNRESOLVED, "btcd layout: chaincfg/params.go not found"

        m_main = re.search(r"MainNetParams\s*=\s*Params\s*\{", txt) or re.search(r"Params\s*\{", txt)
        if m_main is None:
            return ParamStatus.UNRESOLVED, "MainNetParams not found"
        start = m_main.start()
        m_next = re.search(r"\nvar\s+\w+Params\s*=\s*Params\s*\{", txt[start + 10:])
        end = start + 10 + m_next.start() if m_next else start + 20000
        block = txt[start:end]

        wants: Dict[str, Tuple[int, int]] = {}
        for key, pat in (
            ("AddressPrefix", r"PubKeyHashAddrID\s*:\s*(0x[0-9a-fA-F]+|\d+)"),
            ("ScriptPrefix", r"ScriptHashAddrID\s*:\s*(0x[0-9a-fA-F]+|\d+)"),
            ("SecretPrefix", r"PrivateKeyID\s*:\s*(0x[0-9a-fA-F]+|\d+)"),
        ):
            mm = re.search(pat, block)
            if mm:
                raw = mm.group(1)
                try:
                    val = int(raw, 16) if raw.lower().startswith("0x") else int(raw)
                    wants[key] = (val, txt[:start].count("\n") + block[:mm.start()].count("\n") + 1)
                except ValueError:
                    continue

        rows: List[str] = []
        worst = ParamStatus.PASS
        for ckey in ("AddressPrefix", "ScriptPrefix", "SecretPrefix"):
            if ckey not in wants:
                rows.append(f"{ckey}: source not found in chaincfg/params.go (UNRESOLVED)")
                worst = max_status(worst, ParamStatus.UNRESOLVED)
                continue
            want, ln = wants[ckey]
            conf_v = xc.get(ckey, "")
            try:
                conf_n = int(conf_v)
            except ValueError:
                rows.append(f"{ckey}: conf {conf_v!r} non-numeric vs {want} (chaincfg/params.go:{ln})")
                worst = max_status(worst, ParamStatus.FAIL)
                continue
            if conf_n == want:
                rows.append(f"{ckey}: {conf_n} == source (chaincfg/params.go:{ln})")
            else:
                worst = max_status(worst, ParamStatus.WARN)
                rows.append(f"{ckey}: conf {conf_n} vs source {want} (chaincfg/params.go:{ln})")

        return worst, "; ".join(rows) if rows else "no prefixes checked"

    @staticmethod
    def check_blocktime(coin: ManifestCoin, src_dir: Path, xc: Dict[str, str], repo_root: Path) -> Tuple[ParamStatus, str]:
        try:
            bt = int(xc.get("BlockTime", ""))
        except ValueError:
            return ParamStatus.FAIL, "BlockTime non-numeric"
        if bt == 0:
            return ParamStatus.FAIL, "BlockTime=0 rejected by blocknet"

        txt = SourceReader.slurp(src_dir / "chaincfg/params.go")
        if txt is None:
            return ParamStatus.UNRESOLVED, "btcd layout: chaincfg/params.go not found"

        m = (
            re.search(r"TargetTimePerBlock\s*:\s*time\.Second\s*\*\s*(\d+)", txt)
            or re.search(r"TargetTimePerBlock\s*:\s*time\.Duration\s*\(?\s*(\d+)\s*\*", txt)
            or re.search(r"TargetTimePerBlock[^:]*:\s*[^,\n]*?(\d+)\s*,?\s*//\s*(\d+)\s*seconds", txt)
        )
        if m is None:
            return ParamStatus.UNRESOLVED, "TargetTimePerBlock not found in chaincfg/params.go"
        try:
            want = int(m.group(1))
        except ValueError:
            return ParamStatus.UNRESOLVED, f"TargetTimePerBlock unparsable: {m.group(1)!r}"

        ln = txt[:m.start()].count("\n") + 1
        if want == bt:
            return ParamStatus.PASS, f"BlockTime={bt} == TargetTimePerBlock {want}s (chaincfg/params.go:{ln})"
        since = SourceReader.lineage_date(repo_root, f"xbridge-confs/{coin.xbridge_conf}", "BlockTime")
        lin = f"; value present since {since}" if since else ""
        return ParamStatus.WARN, f"BlockTime={bt} vs chaincfg TargetTimePerBlock {want}s (chaincfg/params.go:{ln}){lin}"

    @staticmethod
    def check_coin(coin: ManifestCoin, src_dir: Path, xc: Dict[str, str]) -> Tuple[ParamStatus, str]:
        """Go-coin COIN (satoshis per coin) — offline-first, no network fetch.

        Resolution order:
          (a) vendor/**/amount.go literal SatoshiPerBitcoin (byte-exact build dep)
          (b) local module cache (GOPROXY=off go list, cache-only, pinned by go.mod)
          (c) in-tree 3-point pin: rpcserver NewAmount usage + compress 1 BTC
              literal + genesis premine arithmetic (always available on shallow clone).
              Heuristic fallback, not byte-exact: conjunction required, genesis leg LBC-scoped.
        """
        try:
            conf_n = int(xc.get("COIN", ""))
        except ValueError:
            return ParamStatus.FAIL, f"COIN={xc.get('COIN', '')!r} non-numeric"
        if conf_n == 0:
            return ParamStatus.FAIL, "COIN=0 rejected by blocknet (xbridgeapp.cpp:1005)"

        # (a) vendor tree in clone
        try:
            for cand in sorted(src_dir.glob("vendor/**/amount*.go")):
                txt = SourceReader.slurp(cand)
                if not txt:
                    continue
                m = re.search(r"SatoshiPerBitcoin\s*=\s*(\d[\d'_]*)", txt)
                if m:
                    try:
                        src_n = int(m.group(1).replace("'", "").replace("_", ""))
                    except ValueError:
                        continue
                    rel = str(cand.relative_to(src_dir))
                    ln = txt[:m.start()].count("\n") + 1
                    if src_n != conf_n:
                        return ParamStatus.WARN, (
                            f"COIN={conf_n} vs source {src_n} ({rel}:{ln}) — CTxOut(amount*COIN) off, fund-loss risk"
                        )
                    return ParamStatus.PASS, f"COIN={conf_n} == source {src_n} ({rel}:{ln})"
        except OSError:
            pass

        # Identify module path + pinned version from go.mod (no network)
        mod_path = None
        mod_ver = None
        gomod = SourceReader.slurp(src_dir / "go.mod")
        if gomod is not None:
            for line in gomod.splitlines():
                mm = re.match(r"\s*(?:require\s+)?(github\.com/\S+)\s+(v\S+)", line)
                if mm and ("lbcutil" in mm.group(1) or "btcutil" in mm.group(1)):
                    mod_path, mod_ver = mm.group(1), mm.group(2)
                    break
            if mod_path is None:
                for mm in re.finditer(r"(github\.com/\S+)\s+(v\S+)", gomod):
                    if "lbcutil" in mm.group(1) or "btcutil" in mm.group(1):
                        mod_path, mod_ver = mm.group(1), mm.group(2)
                        break

        # (b) local module cache, cache-only (GOPROXY=off, no fetch).
        # Routed via SystemCommandRunner for uniform retry/timeout handling.
        if mod_path and mod_ver:
            pr = SystemCommandRunner.run(
                ["go", "list", "-m", "-f", "{{.Dir}}", mod_path],
                timeout=15,
                env_extra={"GOPROXY": "off", "GOFLAGS": "-mod=mod"},
                cwd=str(src_dir),
            )
            if pr is not None and pr.returncode == 0:
                try:
                    mod_dir = (pr.stdout or "").strip().splitlines()
                    if mod_dir and Path(mod_dir[0]).is_dir():
                        atxt = SourceReader.slurp(Path(mod_dir[0]) / "amount.go")
                        if atxt is not None:
                            m = re.search(r"SatoshiPerBitcoin\s*=\s*(\d[\d'_]*)", atxt)
                            if m:
                                try:
                                    src_n = int(m.group(1).replace("'", "").replace("_", ""))
                                except ValueError:
                                    src_n = None
                                if src_n is not None:
                                    ev = f"module-cache {mod_path}@{mod_ver} amount.go"
                                    if src_n != conf_n:
                                        return ParamStatus.WARN, (
                                            f"COIN={conf_n} vs source {src_n} ({ev}) — fund-loss risk"
                                        )
                                    return ParamStatus.PASS, f"COIN={conf_n} == source {src_n} ({ev})"
                except (OSError, subprocess.SubprocessError):
                    pass

        # (c) in-tree 3-point pin — always available on shallow clone
        rpc = SourceReader.slurp(src_dir / "rpcserver.go")
        rpc_ln = None
        if rpc is not None:
            m_use = re.search(r"NewAmount|MaxSatoshi", rpc)
            m_sat = re.search(r"SatoshiPerBitcoin", rpc)
            if m_use is not None and m_sat is not None:
                rpc_ln = rpc[:min(m_use.start(), m_sat.start())].count(chr(10)) + 1
        has_use = rpc_ln is not None
        comp = SourceReader.slurp(src_dir / "blockchain/compress.go")
        has_one_btc = False
        comp_ev = ""
        if comp is not None:
            m = re.search(r"100000000[^/\n]*1\.0+\s*BTC|1\.0+\s*BTC[^\n]*100000000", comp)
            if m is None:
                m = re.search(r"\b100000000\b", comp)
            if m:
                has_one_btc = True
                comp_ev = f"blockchain/compress.go:{comp[:m.start()].count(chr(10)) + 1}"
        gen = SourceReader.slurp(src_dir / "chaincfg/genesis.go")
        gen_ln = None
        if gen is not None:
            m_gen = re.search(r"0x8e1bc9bf040000", gen.lower())
            if m_gen:
                gen_ln = gen[:m_gen.start()].count("\n") + 1
        # Genesis premine arithmetic is LBC-specific evidence — it must not
        # certify a non-LBC btcd coin on its own.
        has_gen = gen_ln is not None and coin.ticker == "LBC"
        if has_use and (has_one_btc or has_gen):
            ev_bits = [f"rpcserver.go:{rpc_ln} NewAmount*SatoshiPerBitcoin"]
            if has_one_btc:
                ev_bits.append(comp_ev or "blockchain/compress.go:100000000=1 BTC")
            if has_gen:
                ev_bits.append(f"chaincfg/genesis.go:{gen_ln} 0x8e1bc9bf040000=400M*COIN")
            if mod_path and mod_ver:
                ev_bits.append(f"{mod_path}@{mod_ver}")
            ev = " + ".join(ev_bits)
            if conf_n != 100000000:
                return ParamStatus.WARN, (
                    f"COIN={conf_n} vs source 100000000 ({ev}) — CTxOut(amount*COIN) off, fund-loss risk"
                )
            return ParamStatus.PASS, f"COIN={conf_n} == source 100000000 ({ev})"
        attempted = []
        if not has_use:
            attempted.append("rpcserver.go:NewAmount*SatoshiPerBitcoin not found")
        if not has_one_btc:
            attempted.append("blockchain/compress.go:100000000=1 BTC not found")
        if not has_gen:
            attempted.append("chaincfg/genesis.go:premine pin not found")
        return ParamStatus.UNRESOLVED, f"Go COIN not located — {'; '.join(attempted)}"

    @staticmethod
    def check_txversion(coin: ManifestCoin, src_dir: Path, xc: Dict[str, str]) -> Tuple[ParamStatus, str]:
        txt = SourceReader.slurp(src_dir / "wire/msgtx.go")
        if txt is None:
            return ParamStatus.UNRESOLVED, "btcd layout: wire/msgtx.go not found"
        m = re.search(r"TxVersion\s*=\s*(\d+)", txt)
        if m is None:
            return ParamStatus.UNRESOLVED, "TxVersion not found in wire/msgtx.go"
        bound = int(m.group(1))
        ln = txt[:m.start()].count("\n") + 1
        try:
            tv = int(xc.get("TxVersion", ""))
        except ValueError:
            return ParamStatus.FAIL, "TxVersion non-numeric"
        if tv > bound:
            return ParamStatus.FAIL, f"TxVersion={tv} exceeds wire TxVersion {bound} (wire/msgtx.go:{ln})"
        return ParamStatus.PASS, f"TxVersion={tv} <= wire TxVersion {bound} (wire/msgtx.go:{ln})"

    @staticmethod
    def check_txtime(coin: ManifestCoin, src_dir: Path, xc: Dict[str, str]) -> Tuple[ParamStatus, str]:
        txt = SourceReader.slurp(src_dir / "wire/msgtx.go")
        if txt is None:
            return ParamStatus.UNRESOLVED, "btcd layout: wire/msgtx.go not found"
        m = re.search(r"type\s+MsgTx\s+struct\s*\{(.*?)\}", txt, flags=re.S)
        block = m.group(1) if m else ""
        struct_ln = txt[:m.start()].count("\n") + 1 if m else 1
        has_ntime = bool(re.search(r"\bnTime\b", block))
        raw = xc.get("TxWithTimeField", "").strip().lower()
        conf_v = raw in ("1", "true", "yes")
        if has_ntime:
            ln = struct_ln + block[:block.find("nTime")].count("\n")
            if conf_v:
                return ParamStatus.PASS, f"TxWithTimeField=true and MsgTx carries nTime (wire/msgtx.go:{ln})"
            return ParamStatus.WARN, f"TxWithTimeField=false while MsgTx carries nTime (wire/msgtx.go:{ln}) — wire-format mismatch risk"
        if conf_v:
            return ParamStatus.WARN, f"TxWithTimeField=true while wire MsgTx has no nTime field (wire/msgtx.go:{struct_ln} Version/TxIn/TxOut/LockTime only) — wire-format mismatch risk"
        return ParamStatus.PASS, f"TxWithTimeField=false and wire MsgTx has no nTime field (wire/msgtx.go:{struct_ln})"

    @staticmethod
    def check_txindex(coin: ManifestCoin, src_dir: Path, wc: Dict[str, str]) -> Tuple[ParamStatus, str]:
        txt = SourceReader.slurp(src_dir / "config.go")
        if txt is None:
            return ParamStatus.UNRESOLVED, "btcd layout: config.go not found"
        m = re.search(r"defaultTxIndex\s*=\s*(true|false)", txt)
        if m is None:
            return ParamStatus.UNRESOLVED, "defaultTxIndex not found in config.go"
        dflt = m.group(1) == "true"
        ev = f"config.go:{txt[:m.start()].count(chr(10)) + 1}"
        has_line = "txindex" in {k.split(".")[0].lower() for k in wc}
        if not has_line and dflt is False:
            return ParamStatus.WARN, f"txindex missing from conf while defaultTxIndex=false ({ev})"
        if not has_line and dflt:
            return ParamStatus.INFO, f"txindex relies on upstream default=true ({ev})"
        try:
            got = int(str(conf_val_ci(wc, "txindex")).strip())
        except ValueError:
            return ParamStatus.FAIL, f"txindex={conf_val_ci(wc, 'txindex')!r} non-numeric ({ev})"
        if got == 1:
            return ParamStatus.PASS, f"txindex=1 explicitly enabled ({ev})"
        return ParamStatus.WARN, f"txindex={got} explicitly disabled while XBridge needs index ({ev})"

    @staticmethod
    def check_addrtype(coin: ManifestCoin, src_dir: Path, wc: Dict[str, str]) -> Tuple[ParamStatus, str]:
        lowered = {k.lower() for k in wc}
        keys = [k for k in ("addresstype", "changetype") if k in lowered]
        if not keys:
            return ParamStatus.SKIP, "not used"
        return ParamStatus.INFO, "btcd layout – addresstype not applicable (no C++ -addresstype flag)"

    @staticmethod
    def check_deprecatedrpc(coin: ManifestCoin, src_dir: Path, wc: Dict[str, str]) -> Tuple[ParamStatus, str]:
        raw = (conf_val_ci(wc, "deprecatedrpc") or "").strip()
        if not raw:
            return ParamStatus.INFO, "deprecatedrpc not set"
        return ParamStatus.INFO, "btcd layout – deprecatedrpc not applicable (no C++ IsDeprecatedRPCEnabled)"

    @staticmethod
    def check_structure(coin: ManifestCoin, wc: Dict[str, str], xc: Dict[str, str]) -> Tuple[ParamStatus, str]:
        msgs: List[str] = []
        status = ParamStatus.PASS
        if xc.get("Ip", "") != "127.0.0.1":
            status = max_status(status, ParamStatus.WARN)
            msgs.append(f"Ip={xc.get('Ip')!r}")
        vestigial = [k for k in ("CashAddrPrefix", "ContentType", "JSONVersion") if xc.get(k, None) == ""]
        if vestigial:
            status = max_status(status, ParamStatus.INFO)
            msgs.append(f"empty vestigial keys: {','.join(vestigial)}")
        if wc.get("rpcuser") or wc.get("rpcpassword"):
            status = max_status(status, ParamStatus.INFO)
            msgs.append("credentials shipped in committed conf")
        compat = "Title/Address/MinimumAmount/GetNewKeySupported/ImportWithNoScanSupported compat-only"
        if not msgs:
            return status, f"conventions hold (btcd: rpcallowip absent by design; {compat})"
        return status, "; ".join(msgs) + f"; {compat}"
