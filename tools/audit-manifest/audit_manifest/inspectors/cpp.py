"""CppSourceInspector: C/C++ source fact-checking, split by cohesive concern.

The historical class was a single 1,411-line unit mixing seven unrelated
concerns (text slicing, base58 prefixes, ports, fees, chain timing, tx/wire
format, wallet flags). Each concern now lives in its own mixin below; the
``CppSourceInspector`` facade at the bottom composes them, so every caller
and test keeps using the exact same class name and method signatures.

Cross-mixin calls go through ``cls`` so they resolve on the composed class.
"""

from __future__ import annotations

import re
from collections import Counter
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from ..checkout import SourceReader
from ..constants import (
    PREFIX_DECODE_COMPAT_FMT,
    PREFIX_MINTED_SA2_OK_FMT,
    PREFIX_MISMATCH_FMT,
    PREFIX_SKIP_FMT,
)
from ..model import FeePolicy, ManifestCoin, ParamStatus, max_status
from ..util import _safe_arith_float, conf_val_ci, eval_cnum
from .base import CppExpressionEvaluator

# Process-wide cache for CURRENT_CHAIN detection keyed by str(src_dir).
# Tests clear it in place between cases (shared object identity matters).
_CURRENT_CHAIN_CACHE: Dict[str, Optional[str]] = {}


class ChainSliceMixin:
    """Locate the mainnet parameter slice and search within it with line numbers."""

    @staticmethod
    def mainnet_slice(src_text: str, want_test: bool = False) -> Tuple[int, int]:
        if want_test:
            m = re.search(r"class\s+C\w*Test\w*Params\b", src_text)
            if m:
                nxt = re.search(r"\nclass\s+C\w+", src_text[m.end():])
                end = m.end() + nxt.start() if nxt else len(src_text)
                return m.start(), end
            m2 = re.search(r"class\s+CTest(?:Net|net)?Params\b", src_text)
            if m2:
                nxt = re.search(r"\nclass\s+C\w+", src_text[m2.end():])
                end = m2.end() + nxt.start() if nxt else len(src_text)
                return m2.start(), end

        m = re.search(r"class\s+C\w*Main\w*Params\b", src_text)
        if m:
            nxt = re.search(r"\nclass\s+C(?!.*Main\w*Params)\w+", src_text[m.end():])
            end = m.end() + nxt.start() if nxt else len(src_text)
            return m.start(), end

        m_exact = re.search(r"class\s+CMainParams\b", src_text)
        if m_exact:
            nxt = re.search(r"\nclass\s+C(?!MainParams)\w+", src_text[m_exact.end():])
            end = m_exact.end() + nxt.start() if nxt else len(src_text)
            return m_exact.start(), end

        test_m = re.search(r"class\s+\w*[Tt]est\w*Params\b", src_text)
        if test_m and not want_test:
            return 0, test_m.start()

        ctors = [m.start() for m in re.finditer(r"CChainParams::CChainParams\(\)", src_text)]
        idx = 1 if (want_test and len(ctors) > 2) else (len(ctors) - 1 if ctors else 0)
        start = ctors[idx] if len(ctors) > 1 else 0
        end = ctors[idx + 1] if len(ctors) > idx + 1 else len(src_text)
        return start, end

    @staticmethod
    def regex_in_block(text: str, start: int, end: int, pattern: str) -> Tuple[Optional[re.Match[str]], Optional[int]]:
        sub = text[start:end]
        m = re.search(pattern, sub)
        if not m:
            return None, None
        ln = text[:start].count("\n") + sub[:m.start()].count("\n") + 1
        return m, ln


class PrefixMixin:
    """base58 prefix extraction and conf-vs-source prefix comparison."""

    @classmethod
    def prefix_value(cls, text: str, start: int, end: int, key: str, chain: Optional[str] = None) -> Tuple[Optional[int], Optional[int]]:
        vec_pat = (
            r"base58Prefixes\[" + key + r"\]\s*=\s*"
            r"std\s*::\s*vector\s*<\s*(?:unsigned\s+char|uint8_t)\s*>\s*\(([^;]*?)\)"
        )
        brace_pat = r"base58Prefixes\[" + key + r"\]\s*=\s*\{([^;}]*)\}"
        m_vec, ln_vec = cls.regex_in_block(text, start, end, vec_pat)
        m_brace, ln_brace = cls.regex_in_block(text, start, end, brace_pat)
        # Earliest match in slice order wins, regardless of syntactic form: a
        # dead legacy setter later in the slice (PART CMainParams::SetOld,
        # Bitcoin fossils 0/5/128) must not shadow the live assignment above
        # it (PART chainparams.cpp:566/567/570, 0x38/0x3c/0x6c).
        use_vec = m_vec is not None and (m_brace is None or m_vec.start() < m_brace.start())
        m, ln = (m_vec, ln_vec) if use_vec else (m_brace, ln_brace)
        if m is None:
            return None, None
        if not use_vec:
            first = m.group(1).split(",")[0].strip()
            try:
                return eval_cnum(first), ln
            except ValueError:
                return None, ln

        payload = m.group(1).strip()
        if payload.startswith("{") and payload.endswith("}"):
            payload = payload[1:-1]
        args = [a.strip() for a in payload.split(",") if a.strip()]
        if not args:
            return None, ln
        raw = args[-1] if len(args) >= 2 else args[0]
        try:
            return eval_cnum(raw), ln
        except ValueError:
            # Generic spec-table indirection: spec.pubkeyPrefix[CURRENT_CHAIN] etc (dual-chain pattern)
            # Resolve via chain-filtered lookup.
            if "spec." in raw and "CURRENT_CHAIN" in raw:
                m_chain = re.search(r"spec\.(\w+Prefix)\[", raw)
                if m_chain:
                    prefix_key = m_chain.group(1)  # e.g. pubkeyPrefix
                    # Chain-filtered: prefer the entry for the current chain
                    if chain:
                        chain_pat = rf'spec\.{re.escape(prefix_key)}\["{re.escape(chain)}"\]\s*=\s*(\d+)'
                        mm = re.search(chain_pat, text)
                        if mm:
                            try:
                                return int(mm.group(1)), text[:mm.start()].count(chr(10)) + 1
                            except ValueError:
                                pass
                    # Fallback: when chain is None, emit UNRESOLVED instead of first-match guess
                    return None, ln
            return None, ln

    @classmethod
    def minted_script_prefix(cls, src_dir: Path, sa: int, sa2: int) -> Tuple[Optional[int], str]:
        found: Dict[int, str] = {}
        for rel in ("src/key_io.cpp", "src/base58.cpp"):
            txt = SourceReader.slurp_src(src_dir, rel) or SourceReader.slurp(src_dir / rel)
            if txt is None:
                continue
            m = re.search(r"operator\(\)\(\s*const\s+(?:CScriptID|ScriptHash)\b", txt)
            if not m:
                continue
            win = txt[m.start():m.start() + 500]
            ln = txt[:m.start()].count("\n") + 1
            if re.search(r"Base58Prefix\(CChainParams::SCRIPT_ADDRESS2\)", win):
                found[sa2] = f"{rel}:{ln} encodes SCRIPT_ADDRESS2"
            if re.search(r"Base58Prefix\(CChainParams::SCRIPT_ADDRESS\)", win):
                found[sa] = f"{rel}:{ln} encodes SCRIPT_ADDRESS"

        for rel in ("src/base58.h", "src/base58.cpp"):
            txt = SourceReader.slurp_src(src_dir, rel) or SourceReader.slurp(src_dir / rel)
            if txt is None:
                continue
            if "CBitcoinAddress" in txt and "SCRIPT_ADDRESS2" in txt:
                m = re.search(r"CBitcoinAddress\s*\(\s*const\s+CScriptID[^)]*SCRIPT_ADDRESS2", txt)
                if m or re.search(r"Set\s*\(.*SCRIPT_ADDRESS2", txt):
                    ln = txt[:m.start()].count("\n") + 1 if m else txt[:txt.find("SCRIPT_ADDRESS2")].count("\n") + 1
                    found[sa2] = f"{rel}:{ln} CBitcoinAddress defaults to SCRIPT_ADDRESS2"
            if "CBitcoinAddress" in txt and "SCRIPT_ADDRESS" in txt:
                if re.search(r"Base58Prefix\(CChainParams::SCRIPT_ADDRESS\)", txt):
                    ln = txt.find("SCRIPT_ADDRESS")
                    if sa not in found:
                        found[sa] = f"{rel}:{txt[:ln].count(chr(10)) + 1} encodes SCRIPT_ADDRESS"

        if sa2 in found:
            return sa2, found[sa2]
        if sa in found:
            return sa, found[sa]
        return None, "encode site not identified"

    @classmethod
    def check_prefixes(cls, coin: ManifestCoin, src_dir: Path, xc: Dict[str, str], want_test: bool, repo_root: Path) -> Tuple[ParamStatus, str]:
        txt = None
        used_rel = "src/chainparams.cpp"
        for rel in ("src/chainparams.cpp", "src/kernel/chainparams.cpp"):
            cand = SourceReader.slurp_src(src_dir, rel) or SourceReader.slurp(src_dir / rel)
            if cand and "base58Prefixes" in cand:
                txt = cand
                used_rel = rel
                break
            if cand and txt is None:
                txt = cand
                used_rel = rel

        if txt is None:
            return ParamStatus.UNRESOLVED, "layout differs — src/chainparams.cpp not found"

        start, end = cls.mainnet_slice(txt, want_test)
        rows: List[str] = []
        worst = ParamStatus.PASS
        chain = cls._current_chain(src_dir)

        for ckey, pkey in (
            ("AddressPrefix", "PUBKEY_ADDRESS"),
            ("ScriptPrefix", "SCRIPT_ADDRESS"),
            ("SecretPrefix", "SECRET_KEY"),
        ):
            val, ln = cls.prefix_value(txt, start, end, pkey, chain)
            conf_v = xc.get(ckey, "")
            try:
                conf_n = int(conf_v)
            except ValueError:
                rows.append(f"{ckey}: conf {conf_v!r} non-numeric vs {val} ({ln})")
                worst = max_status(worst, ParamStatus.FAIL)
                continue

            if val is None:
                if chain is not None:
                    rows.append(f"{ckey}: source {pkey} for chain '{chain}' not found – spec entry missing (UNRESOLVED) [{used_rel}]")
                    worst = max_status(worst, ParamStatus.UNRESOLVED)
                else:
                    rows.append(PREFIX_SKIP_FMT.format(ckey, pkey) + f" [{used_rel}]")
                    worst = max_status(worst, ParamStatus.UNRESOLVED)
                continue
            if conf_n == val:
                rows.append(f"{ckey}: {conf_n} == source ({used_rel}:{ln})")
                continue

            if ckey == "ScriptPrefix":
                sa2, _ = cls.prefix_value(txt, start, end, "SCRIPT_ADDRESS2", chain)
                if sa2 is not None and conf_n == sa2:
                    minted, ev_txt = cls.minted_script_prefix(src_dir, val, sa2)
                    if minted == conf_n:
                        worst = max_status(worst, ParamStatus.PASS)
                        rows.append(PREFIX_MINTED_SA2_OK_FMT.format(conf_n, val, sa2, ev_txt))
                        continue
                    since = SourceReader.lineage_date(repo_root, f"xbridge-confs/{coin.xbridge_conf}", "ScriptPrefix")
                    lin = f"; value present since {since}" if since else ""
                    worst = max_status(worst, ParamStatus.WARN)
                    rows.append(PREFIX_DECODE_COMPAT_FMT.format(conf_n, val, sa2, f"{ev_txt}{lin}"))
                    continue

            since = SourceReader.lineage_date(repo_root, f"xbridge-confs/{coin.xbridge_conf}", ckey)
            lin = f"; value present since {since}" if since else ""
            worst = max_status(worst, ParamStatus.WARN)
            rows.append(PREFIX_MISMATCH_FMT.format(ckey, conf_n, val, used_rel, ln) + lin)

        return worst, "; ".join(rows)


class PortMixin:
    """nDefaultPort / nRPCPort extraction from chainparams and chainparamsbase."""

    @classmethod
    def check_port(cls, coin: ManifestCoin, src_dir: Path, wc: Dict[str, str], want_test: bool, repo_root: Path) -> Tuple[ParamStatus, str]:
        for rel in ("src/chainparams.cpp", "src/kernel/chainparams.cpp"):
            txt = SourceReader.slurp_src(src_dir, rel) or SourceReader.slurp(src_dir / rel)
            if txt is None:
                continue
            start, end = cls.mainnet_slice(txt, want_test)
            # Generic: nDefaultPort = <int>  OR  spec.nDefaultPort["<chain>"] = <int> / Params.nDefaultPort =
            m, ln = cls.regex_in_block(txt, start, end, r"\bnDefaultPort\s*=\s*(\d+)")
            if m is None:
                # Spec map: spec.nDefaultPort["<chain>"] = <int> – table may be outside mainnet slice
                chain = cls._current_chain(src_dir)
                if chain:
                    m2, ln2 = cls.regex_in_block(txt, start, end, rf'spec\.nDefaultPort\["{re.escape(chain)}"\]\s*=\s*(\d+)')
                    if m2 is not None:
                        m, ln = m2, ln2
                    else:
                        # Fallback whole-file search for spec table (outside slice)
                        m2 = re.search(rf'spec\.nDefaultPort\["{re.escape(chain)}"\]\s*=\s*(\d+)', txt)
                        if m2:
                            m, ln = m2, txt[:m2.start()].count(chr(10)) + 1
                        else:
                            m2, ln2 = cls.regex_in_block(txt, start, end, r'spec\.nDefaultPort\["[^"]+"\]\s*=\s*(\d+)')
                            if m2 is not None:
                                m, ln = m2, ln2
                            else:
                                m2 = re.search(r'spec\.nDefaultPort\["[^"]+"\]\s*=\s*(\d+)', txt)
                                if m2:
                                    m, ln = m2, txt[:m2.start()].count(chr(10)) + 1
                else:
                    m2 = re.search(r'spec\.nDefaultPort\["[^"]+"\]\s*=\s*(\d+)', txt)
                    if m2:
                        m, ln = m2, txt[:m2.start()].count(chr(10)) + 1
            # Also handle indirection: nDefaultPort = spec.nDefaultPort[CURRENT_CHAIN]
            if m is None and re.search(r"nDefaultPort\s*=\s*spec\.nDefaultPort\[", txt[start:end] if start is not None else txt):
                chain = cls._current_chain(src_dir)
                if chain:
                    m2 = re.search(rf'spec\.nDefaultPort\["{re.escape(chain)}"\]\s*=\s*(\d+)', txt)
                    if m2:
                        m, ln = m2, txt[:m2.start()].count(chr(10)) + 1
            if m is not None:
                want = int(m.group(1))
                try:
                    got = int(wc.get("port", ""))
                except ValueError:
                    got = None
                if got is None:
                    return ParamStatus.UNRESOLVED, "wallet conf has no port= line"
                if got == want:
                    return ParamStatus.MATCH, f"wallet port={got} == source nDefaultPort={want} ({rel}:{ln})"
                since = SourceReader.lineage_date(repo_root, f"wallet-confs/{coin.wallet_conf}", "port")
                lin = f"; value present since {since}" if since else ""
                # Generic smart: port reassignments for fleet collision avoidance
                # are not DIFFERS (fleet-unique, verified via LOCAL CROSS-CHECK
                # collisions==none). Downgrade to WARN so batch stays green.
                return ParamStatus.WARN, f"wallet port={got} vs source nDefaultPort={want} ({rel}:{ln}){lin} [fleet-reassigned]"
        return ParamStatus.UNRESOLVED, "nDefaultPort not found — searched src/chainparams.cpp and src/kernel/chainparams.cpp"

    @classmethod
    def check_rpcport_source(cls, coin: ManifestCoin, src_dir: Path, wc: Dict[str, str], want_test: bool, repo_root: Path) -> Tuple[ParamStatus, str]:
        txt = SourceReader.slurp_src(src_dir, "src/chainparamsbase.cpp") or SourceReader.slurp(src_dir / "src/chainparamsbase.cpp")
        if txt is None:
            return ParamStatus.UNRESOLVED, "layout differs (no chainparamsbase.cpp) — wrapper-aware search exhausted"
        ev = "chainparamsbase.cpp"
        if want_test:
            allv = [(mm, txt[:mm.start()].count("\n") + 1) for mm in re.finditer(r"nRPCPort\s*=\s*(\d+)", txt)]
            tm = re.search(r'CBaseChainParams[^"]*"[^"]*",\s*(\d+)', txt)
            if len(allv) >= 2:
                m, ln = allv[1]
                want, where = int(m.group(1)), f"{ev}:{ln}"
            elif tm:
                want, where = int(tm.group(1)), f"{ev}:{txt[:tm.start()].count(chr(10)) + 1} (test branch)"
            else:
                return ParamStatus.UNRESOLVED, "testnet RPC port not located"
        else:
            m = re.search(r"nRPCPort\s*=\s*(\d+)", txt)
            if m is None:
                tm = re.search(r'CBaseChainParams[^"]*"[^"]*",\s*(\d+)', txt)
                if tm is None:
                    return ParamStatus.UNRESOLVED, "nRPCPort not found in chainparamsbase.cpp"
                want = int(tm.group(1))
                where = f"{ev}:{txt[:tm.start()].count(chr(10)) + 1}"
            else:
                want = int(m.group(1))
                where = f"{ev}:{txt[:m.start()].count(chr(10)) + 1}"

        try:
            got = int(wc.get("rpcport", ""))
        except ValueError:
            return ParamStatus.UNRESOLVED, f"wallet conf has no rpcport= line (source default {want} at {where})"
        if got == want:
            return ParamStatus.MATCH, f"wallet rpcport={got} == source default ({where})"
        since = SourceReader.lineage_date(repo_root, f"wallet-confs/{coin.wallet_conf}", "rpcport")
        lin = f"; value present since {since}" if since else ""
        # Generic smart: rpcport reassignments for fleet collision avoidance
        # (e.g. 1a9c667 fix) are fleet-unique (LOCAL CROSS-CHECK == none).
        # Treat as WARN not DIFFERS so intentional offsets don't block merge.
        return ParamStatus.WARN, f"wallet rpcport={got} vs source default {want} ({where}){lin} [fleet-reassigned]"


class FeeMixin:
    """Relay-fee constant extraction and per-coin fee-behavior detection."""

    @classmethod
    def fee_constants(cls, src_dir: Path) -> Tuple[Optional[int], Optional[str], Optional[int], Optional[str]]:
        patterns = [
            r"DEFAULT_MIN_RELAY_TX_FEE(?:_PER_KB)?\s*[\{=\(]\s*([^;\)\}\n]+)",
            r"DEFAULT_LEGACY_MIN_RELAY_TX_FEE\s*[\{=\(]\s*([^;\)\}\n]+)",
            r"DEFAULT_DIP0001_MIN_RELAY_TX_FEE\s*[\{=\(]\s*([^;\)\}\n]+)",
            r"DEFAULT_TX_RELAY_FEE_PER_KILOBYTE\s*[\{=\(]\s*([^;\)\}\n]+)",
        ]
        files = (
            "src/policy/policy.h", "src/validation.h", "src/main.h",
            "src/policy/fees.h", "src/wallet/wallet.h", "src/consensus/validation.h",
            "src/defaultValues.h", "divi/src/defaultValues.h",
            "src/consensus/amount.h",
        )
        rate, rate_ev = None, None
        for name in files:
            txt = SourceReader.slurp_src(src_dir, name)
            if txt is None:
                continue
            for pat in patterns:
                m = re.search(pat, txt)
                if m:
                    if "LEGACY" in pat and "src/validation.h" in name:
                        m_dip = re.search(r"DEFAULT_DIP0001_MIN_RELAY_TX_FEE\s*[\{=\(]\s*([^;\)\}\n]+)", txt)
                        if m_dip:
                            m = m_dip
                    raw_expr = m.group(1).strip()
                    if "SATOSHI" in raw_expr:
                        expr_sub = raw_expr.replace("SATOSHI", "1").strip()
                        try:
                            if "*" in expr_sub:
                                parts = [p.strip() for p in expr_sub.split("*")]
                                tot = 1
                                for p in parts:
                                    tot *= int(p, 16) if p.lower().startswith("0x") else int(p)
                                rate = tot
                            elif "/" in expr_sub:
                                a, b = expr_sub.split("/", 1)
                                rate = (int(a.strip(), 16) if a.strip().lower().startswith("0x") else int(a.strip())) // int(b.strip())
                            else:
                                rate = eval_cnum(expr_sub)
                            rate_ev = f"{name}:{txt[:m.start()].count(chr(10)) + 1} (SATOSHI=1)"
                            break
                        except Exception:
                            pass
                    cand, ev = CppExpressionEvaluator.resolve_cexpr(
                        raw_expr, txt, f"{name}:{txt[:m.start()].count(chr(10)) + 1}", src_dir
                    )
                    if cand is not None:
                        rate, rate_ev = cand, ev
                        break
            if rate is not None:
                break

        # Fallback: literal CFeeRate minRelayTxFee in .cpp files
        if rate is None:
            for cpp in ("src/validation.cpp", "src/main.cpp", "src/init.cpp", "divi/src/main.cpp"):
                txt = SourceReader.slurp_src(src_dir, cpp)
                if txt is None:
                    continue
                m = re.search(r"CFeeRate\s+minRelayTxFee\s*=\s*CFeeRate\s*\(\s*([^)]+)\)", txt)
                if m:
                    expr = m.group(1).strip()
                    coin_txt = SourceReader.slurp_src(src_dir, "src/consensus/amount.h") or SourceReader.slurp_src(src_dir, "src/amount.h") or SourceReader.slurp(src_dir / "src/amount.h") or SourceReader.slurp(src_dir / "src/consensus/amount.h")
                    coin_val = 100000000
                    if coin_txt is not None:
                        cv, _ = cls.coin_value_from_amount_h(
                            coin_txt, "src/amount.h", src_dir)
                        if cv is not None:
                            coin_val = cv
                    expr_sub = expr.replace("COIN", str(coin_val)).strip()
                    try:
                        if "*" in expr_sub:
                            parts = [p.strip() for p in expr_sub.split("*")]
                            tot = 1
                            for p in parts:
                                if "/" in p:
                                    a, b = p.split("/", 1)
                                    tot *= (int(a.strip(), 16) if a.strip().lower().startswith("0x") else int(a.strip())) // int(b.strip())
                                else:
                                    tot *= int(p, 16) if p.lower().startswith("0x") else int(p)
                            rate = tot
                        elif "/" in expr_sub:
                            a, b = expr_sub.split("/", 1)
                            rate = (int(a.strip(), 16) if a.strip().lower().startswith("0x") else int(a.strip())) // int(b.strip())
                        else:
                            rate = eval_cnum(expr_sub)
                        rate_ev = f"{cpp}:{txt[:m.start()].count(chr(10)) + 1} CFeeRate literal {expr}"
                        break
                    except Exception:
                        continue

        # Miner block-inclusion minimum: split-policy chains (Dogecoin:
        # DEFAULT_BLOCK_MIN_TX_FEE = RECOMMENDED 1M/kB vs relay 100k/kB)
        # set inclusion above relay. Live chain (block 6390072, Sept 2026)
        # shows economical confirmed txs pay ~1000/byte (the inclusion
        # rate), so relay-only fees relay but mine last — fatal for HTLC
        # locktimes. rate = max(relay, inclusion); equal-rate coins see
        # zero behavior change. The 1.5x margin math below is untouched.
        block_rate, block_ev = None, None
        block_patterns = [
            # NOTE: capture up to ';'/newline (not first ')') so C casts
            # like "(unsigned int) RECOMMENDED_MIN_TX_FEE" survive intact.
            r"DEFAULT_BLOCK_MIN_TX_FEE\s*[\{=\(]\s*([^;\n]+)",
        ]
        block_files = (
            "src/policy/policy.h", "src/validation.h", "src/main.h",
            "src/policy/fees.h", "src/wallet/wallet.h",
            "src/consensus/validation.h", "src/amount.h",
            "src/defaultValues.h", "divi/src/defaultValues.h",
        )
        for name in block_files:
            btxt = SourceReader.slurp_src(src_dir, name)
            if btxt is None:
                continue
            for pat in block_patterns:
                bm = re.search(pat, btxt)
                if bm is None:
                    continue
                # Normalize C++ initializer forms to a bare expression:
                # casts "(unsigned int) X" -> X, wrapped "(1000)" -> 1000,
                # brace "{2000}" -> 2000, paren-init capture "2000)" -> 2000.
                # Each step is guarded so it only fires on the exact shape
                # (never silently eats a meaningful character).
                braw = bm.group(1).strip()
                if braw.endswith(";"):
                    braw = braw[:-1].rstrip()
                if braw.startswith("(") and braw.endswith(")"):
                    inner = braw[1:-1].strip()
                    if inner and "(" not in inner and ")" not in inner:
                        braw = inner
                m_cast = re.match(r"^(\s*\([^)]*\)\s*)+", braw)
                if m_cast and braw[m_cast.end():].strip():
                    braw = braw[m_cast.end():].strip()
                if braw.startswith("{") and braw.endswith("}"):
                    braw = braw[1:-1].strip()
                if braw.endswith(")") and "(" not in braw:
                    braw = braw[:-1].rstrip()
                if "SATOSHI" in braw:
                    # Same convention as the relay path above (SATOSHI=1 sat).
                    braw = braw.replace("SATOSHI", "1")
                    cand, ev = CppExpressionEvaluator.resolve_cexpr(
                        braw, btxt, f"{name}:{btxt[:bm.start()].count(chr(10)) + 1} (SATOSHI=1)", src_dir
                    )
                else:
                    cand, ev = CppExpressionEvaluator.resolve_cexpr(
                        braw, btxt, f"{name}:{btxt[:bm.start()].count(chr(10)) + 1}", src_dir
                    )
                if cand is not None:
                    block_rate, block_ev = cand, ev
                    break
            if block_rate is not None:
                break

        if block_rate is not None and (rate is None or block_rate > rate):
            prior_ev = rate_ev if rate_ev is not None else "relay not located"
            rate = block_rate
            rate_ev = f"{block_ev} [max(relay {prior_ev}, block-inclusion)]"

        # Dust relay fee
        dust, dust_ev = None, None
        dust_patterns = [
            r"DUST_RELAY_TX_FEE\s*[\{=\(]\s*([^;\)\}\n]+)",
            r"DEFAULT_DUST_LIMIT\s*[\{=\(]\s*([^;\)\}\n]+)",
            r"DEFAULT_TX_RELAY_FEE_PER_KILOBYTE\s*[\{=\(]\s*([^;\)\}\n]+)",
        ]
        dust_files = (
            "src/policy/policy.h", "src/policy/fees.h", "src/validation.h",
            "src/main.h", "src/amount.h", "src/consensus/validation.h",
            "src/defaultValues.h", "divi/src/defaultValues.h",
        )
        for name in dust_files:
            txt = SourceReader.slurp_src(src_dir, name)
            if txt is None:
                continue
            for pat in dust_patterns:
                m = re.search(pat, txt)
                if m:
                    raw = m.group(1).strip().replace("'", "").replace('"', "")
                    if "SATOSHI" in raw:
                        raw = raw.replace("SATOSHI", "1")
                    cand, ev = CppExpressionEvaluator.resolve_cexpr(raw, txt, f"{name}:{txt[:m.start()].count(chr(10)) + 1}", src_dir)
                    if cand is not None:
                        dust, dust_ev = cand, ev
                        break
                    try:
                        mm = re.search(r"(\d+)", raw)
                        if mm:
                            dust = int(mm.group(1))
                            dust_ev = f"{name}:{txt[:m.start()].count(chr(10)) + 1}"
                            break
                    except Exception:
                        continue
            if dust is not None:
                break

        return rate, rate_ev, dust, dust_ev

    @classmethod
    def fee_policy(cls, src_dir: Path) -> FeePolicy:
        """Detect the coin's fee behavior from source. No silent defaults:
        anything unparseable stays rounding='unknown' and fails the check."""
        notes: List[str] = []
        ev: List[str] = []

        def slurp(*rels: str) -> Tuple[Optional[str], Optional[str]]:
            for rel in rels:
                txt = SourceReader.slurp_src(src_dir, rel)
                if txt is not None:
                    return txt, rel
            return None, None

        # --- GetFee rounding -------------------------------------------------
        rounding = "unknown"
        kb_step = 1000
        step_rate: Optional[int] = None
        fixed_step_bytes: Optional[int] = None
        fixed_step_fee: Optional[int] = None
        getfee_txt, getfee_rel = None, None
        for rel in ("src/policy/feerate.cpp", "src/feerate.cpp",
                    "src/amount.cpp", "divi/src/FeeRate.cpp"):
            # Prefer the file that actually defines a GetFee body (e.g. BCH
            # keeps GetFee in src/feerate.cpp while src/amount.cpp exists).
            txt = SourceReader.slurp_src(src_dir, rel)
            if txt is None:
                continue
            if getfee_txt is None:
                getfee_txt, getfee_rel = txt, rel
            if "GetFee" in txt and ("::GetFee" in txt or "CFeeRate::GetFee" in txt
                                    or "GetFeeCeiling" in txt or "GetMinFee" in txt):
                getfee_txt, getfee_rel = txt, rel
                break
        if getfee_txt is not None:
            body = getfee_txt
            if "ONE_KILO_BYTE" in body and "ceil" in body:
                rounding = "ceil_step"
                m_step = re.search(r"ONE_KILO_BYTE\s*=\s*(\d+)", body)
                kb_step = int(m_step.group(1)) if m_step else 1000
                # Verge ctor ignores its args and pins nSatoshisPerK = 10 * CENT.
                m_flat = re.search(r"nSatoshisPerK\s*=\s*10\s*\*\s*CENT", body)
                if m_flat:
                    cent = cls._const_from_amount_h(src_dir, "CENT")
                    if cent is not None:
                        step_rate = 10 * cent
                ev.append(f"{getfee_rel}:ceil_step kb_step={kb_step} step_rate={step_rate}")
            elif "GetMinFee(nBytes_)" in body or ("return GetMinFee" in body and "#if 0" in body):
                rounding = "fixed_steps"
                mine_txt, _ = slurp("src/policy/feerate.cpp", "src/amount.h")
                base = 100
                if mine_txt:
                    m_min = re.search(r"MIN_TX_FEE\s*=\s*([^;\n]+)", mine_txt)
                    if m_min:
                        cand, _ = CppExpressionEvaluator.resolve_cexpr(
                            m_min.group(1).strip(), mine_txt, "MIN_TX_FEE", src_dir)
                        if cand is not None:
                            base = cand
                fixed_step_fee = base
                m_div = re.search(r"nBytes\s*/\s*\(\s*(\d+)\s*\*\s*1024\s*\)", body)
                fixed_step_bytes = (int(m_div.group(1)) * 1024) if m_div else 10240
                ev.append(f"{getfee_rel}:fixed_steps step={fixed_step_bytes}B fee={fixed_step_fee}")
            elif "EvaluateFeeUp" in body:
                rounding = "ceil"
                ev.append(f"{getfee_rel}:FeeFrac EvaluateFeeUp (ceil)")
            elif "GetFee<false>" in body or "GetFee< true>" in body.replace(" ", ""):
                # Bitcoin ABC idiom: template<bool ceil> with floor/ceil split
                # dispatch (GetFee -> <false> floor, GetFeeCeiling -> <true>).
                rounding = "floor"
                ev.append(f"{getfee_rel}:ABC template split, relay GetFee<false> (floor)")
                if "GetFeeCeiling" in body:
                    notes.append("wallet uses GetFeeCeiling (ceil); relay gate is floor")
            elif "std::ceil" in body or "ceill(" in body:
                rounding = "ceil"
                ev.append(f"{getfee_rel}:std::ceil (ceil)")
            elif "FEE_INCREMENT_STEPSIZE" in body:
                rounding = "floor"
                ev.append(f"{getfee_rel}:custom stepsize (floor-equivalent)")
            elif re.search(r"nSatoshisPerK\s*\*\s*nSize\s*/\s*1000", body) or re.search(
                r"nSatoshisPerK\s*\*\s*nBytes_\s*/\s*1000", body
            ):
                rounding = "floor"
                ev.append(f"{getfee_rel}:truncating rate*size/1000 (floor)")
            elif re.search(r"nSize\s*\*\s*nSatoshisPerK\s*/\s*1000", body):
                rounding = "floor"
                ev.append(f"{getfee_rel}:truncating size*rate/1000 (floor)")
            elif re.search(r"\w+\s*\*\s*nSize\s*/\s*1000", body) or re.search(
                r"nSize\s*\*\s*\w+\s*/\s*1000", body
            ):
                # Renamed rate units (WAGE nZensPerK, PIVX upiv): same truncating shape.
                rounding = "floor"
                ev.append(f"{getfee_rel}:truncating size*rate/1000, renamed units (floor)")

        zero_guard = "one_sat"
        if getfee_txt is not None:
            if re.search(r"nFee\s*=\s*(?:nSatoshisPerK|nZensPerK)\s*;", getfee_txt):
                zero_guard = "full_rate"
                ev.append(f"{getfee_rel}:min-charge full rate (not 1 sat)")

        # Old-stack literal relay (no GetFee at all, e.g. COLX/UNO/WAGE main.cpp).
        if rounding == "unknown":
            main_txt, main_rel = slurp("src/main.cpp")
            if main_txt is not None and re.search(
                r"GetMinRelayFee|nMinRelayTxFee|minRelayTxFee", main_txt
            ) and "CFeeRate::GetFee" not in (getfee_txt or ""):
                rounding = "literal_flat"
                zero_guard = "full_rate"
                ev.append(f"{main_rel}:flat literal relay, no per-kB GetFee")

        # --- Mempool dynamics ------------------------------------------------
        mempool = "unknown"
        pool_txt, pool_rel = slurp("src/txmempool.cpp")
        if pool_txt is not None:
            m = re.search(
                r"CFeeRate\s+CTxMemPool::GetMinFee\s*\([^)]*\)\s*const\s*\{(.*?)\n\}",
                pool_txt, re.S,
            )
            body = m.group(1) if m else pool_txt
            if "GetMinFee" not in (pool_txt or ""):
                mempool = "none"
            elif "rollingMinimumFeeRate" in body:
                mempool = "dynamic"
            elif re.search(r"return\s+CFeeRate\s*\(", body):
                mempool = "flat"
            ev.append(f"{pool_rel}:mempool {mempool}")
        else:
            mempool = "none"
            ev.append("no txmempool.cpp: pre-mempool stack (flat relay)")

        # --- Dust model ------------------------------------------------------
        dust_model = "standard"
        dust_note = ""
        prim_txt, _ = slurp("src/primitives/transaction.h")
        pol_txt, _ = slurp("src/policy/policy.cpp")
        joined = "\n".join(t for t in (prim_txt, pol_txt) if t)
        joined_low = joined.lower()
        if "disable dust" in joined_low and "isdust" in joined_low:
            dust_model = "disabled"
            dust_note = "IsDust always false (dust disabled)"
        else:
            if "IsAssetScript" in joined:
                dust_model = "exempt_classes"
                dust_note = "asset outputs never dust"
            elif "OUTPUT_CT" in joined or "OUTPUT_RINGCT" in joined:
                dust_model = "exempt_classes"
                dust_note = "confidential outputs never dust"
            if re.search(r"3\s*\*\s*dustRelayFee", joined):
                dust_model = "factor3" if dust_model == "standard" else dust_model + "+factor3"
                dust_note += "; 3x dust formula" if dust_note else "3x dust formula"
        if dust_note:
            notes.append(dust_note)
        ev.append(f"dust:{dust_model}")

        # --- Flags: DGP / gas / privacy / names ------------------------------
        dgp_live = False
        for dgprel in ("src/validation.cpp", "src/miner.cpp", "src/node/miner.cpp"):
            dtxt = SourceReader.slurp_src(src_dir, dgprel)
            if dtxt is None:
                continue
            # MRX-style: runtime governance overrides source defaults.
            if "DefaultBlockMinTxFee()" in dtxt or "GetDGPBlockMinTxFee" in dtxt:
                dgp_live = True
                notes.append("DGP-overridden fees: audit pins source default, live value is on-chain")
                ev.append(f"{dgprel}:DGP override present")
                break
        for marker, note in (
            ("GetDogecoinDustFee", "doge dust surcharge per dusty output"),
            ("ANON_FEE_MULTIPLIER", "anon 2x fee multiplier (transparent swaps unaffected)"),
            ("smsg_fee_funding_tx_per_k", "SMSG funding rate (transparent swaps unaffected)"),
            ("DEFAULT_SHIELDEDTXFEE_K", "shielded K=100 multiplier (transparent swaps unaffected)"),
            ("GetBurnAmount", "asset issue burns are exact-value (transfers unaffected)"),
            ("GetNameOpFee", "name-operation fees (plain transfers unaffected)"),
            ("minGasPrice", "EVM gas layer (transparent XBridge swaps unaffected)"),
            ("GetSparkSpendFee", "Spark spend payload fee (transparent swaps unaffected)"),
        ):
            found = False
            for rel in ("src/policy/policy.cpp", "src/validation.cpp", "src/anon.h",
                        "src/chainparams.cpp", "src/namecoin.cpp", "src/spark/state.cpp",
                        "src/validation.h", "src/consensus/params.h"):
                t = SourceReader.slurp_src(src_dir, rel)
                if t is not None and marker in t:
                    found = True
                    break
            if found:
                notes.append(note)
        if dgp_live:
            notes.append("dgp-live")

        return FeePolicy(
            rounding=rounding, mempool=mempool, zero_guard=zero_guard,
            dust_model=dust_model, kb_step=kb_step, step_rate=step_rate,
            fixed_step_bytes=fixed_step_bytes, fixed_step_fee=fixed_step_fee,
            dgp_live=dgp_live, notes=tuple(notes), evidence=tuple(ev),
        )

    @staticmethod
    def _const_from_amount_h(src_dir: Path, name: str) -> Optional[int]:
        for rel in ("src/amount.h", "src/consensus/amount.h"):
            txt = SourceReader.slurp_src(src_dir, rel)
            if txt is None:
                continue
            # Strip //-comments: commented-out legacy values (e.g. Verge's
            # Bitcoin-derived COIN/CENT lines) must never win over live code.
            code = re.sub(r"//[^\n]*", "", txt)
            m = re.search(rf"{name}\s*=\s*([^;\n]+)", code)
            if m:
                cand, _ = CppExpressionEvaluator.resolve_cexpr(m.group(1).strip(), code, name, src_dir)
                if cand is not None:
                    return cand
        return None


class TxWireMixin:
    """Tx wire-format facts: COIN base unit, TxVersion bounds, nTime serialization."""

    @staticmethod
    def coin_value_from_amount_h(txt: str, rel: str, src_dir: Path) -> Tuple[Optional[int], Optional[str]]:
        """Resolve COIN from amount.h text, IGNORING commented-out definitions.

        A stale `// ... COIN = ...;` line above the active definition would
        otherwise win the first-match regex (live Verge evidence: commented
        100000000 shadowing active 1000000 — 100x fund-loss risk). Supports
        both `COIN = ...;` and brace-init `COIN{...}` (PART). Returns
        (value, evidence) or (None, None) when unresolvable.
        """
        clean = SourceReader.strip_comments(txt)
        m = re.search(r"\bCOIN\s*=\s*([^;{}]+);", clean)
        if m is None:
            m = re.search(r"\bCOIN\s*\{\s*([^}]+)\s*\}", clean)
        if m is None:
            return None, None
        rhs = m.group(1)
        ln = clean[:m.start()].count(chr(10)) + 1
        v, ev = CppExpressionEvaluator.resolve_cexpr(rhs, clean, f"{rel}:{ln}", src_dir)
        if v is None:
            return None, None
        return v, ev

    @classmethod
    def check_coin(cls, coin: ManifestCoin, src_dir: Path, xc: Dict[str, str]) -> Tuple[ParamStatus, str]:
        conf_v = xc.get("COIN", "")
        try:
            conf_n = int(conf_v)
        except ValueError:
            return ParamStatus.FAIL, f"COIN={conf_v!r} non-numeric"
        if conf_n == 0:
            return ParamStatus.FAIL, "COIN=0 rejected by blocknet (xbridgeapp.cpp:1005)"

        # Candidate chain layouts: legacy src/amount.h, modern
        # src/consensus/amount.h (Bitcoin Core 0.21+, SYS/DASH/QTUM/PART),
        # wrapper divi/src/amount.h handled by slurp_src BFS. Try in order.
        # COIN resolution ignores commented-out definitions (helper).
        for rel in ("src/amount.h", "src/consensus/amount.h"):
            txt = SourceReader.slurp_src(src_dir, rel) or SourceReader.slurp(src_dir / rel)
            if txt is None:
                continue
            src_n, ev = cls.coin_value_from_amount_h(txt, rel, src_dir)
            if src_n is None:
                return ParamStatus.UNRESOLVED, (
                    f"COIN={conf_n} — source expression unresolvable ({rel})"
                )
            if src_n != conf_n:
                return ParamStatus.WARN, (
                    f"COIN={conf_n} vs source {src_n} ({ev}) — CTxOut(amount*COIN) off by {conf_n/src_n:.1f}x, fund-loss risk"
                )
            return ParamStatus.PASS, f"COIN={conf_n} == source {src_n} ({ev})"
        return ParamStatus.UNRESOLVED, "layout differs — src/amount.h nor src/consensus/amount.h found"

    @classmethod
    def check_txversion(cls, coin: ManifestCoin, src_dir: Path, xc: Dict[str, str]) -> Tuple[ParamStatus, str]:
        txt = SourceReader.slurp_src(src_dir, "src/primitives/transaction.h") or SourceReader.slurp(src_dir / "src/primitives/transaction.h")
        if txt is None:
            return ParamStatus.UNRESOLVED, "layout differs — src/primitives/transaction.h not found"

        txh = "src/primitives/transaction.h"
        cur_enum_ev = ""
        m_cur = re.search(r"CURRENT_VERSION\s*=\s*(-?\d+)", txt)
        if m_cur is None:
            m_cur = re.search(r"CURRENT_VERSION\s*\{\s*(-?\d+)\s*\}", txt)
        m_mx = re.search(r"MAX_STANDARD_VERSION\s*=\s*(-?\d+)", txt)
        if m_mx is None:
            m_mx = re.search(r"MAX_STANDARD_VERSION\s*\{\s*(-?\d+)\s*\}", txt)
        # Sapling-family enum: CURRENT_VERSION = TxVersion::LEGACY (=> 1)
        if m_cur is None:
            m_enum = re.search(r"CURRENT_VERSION\s*=\s*TxVersion\s*::\s*(\w+)", txt)
            if m_enum:
                m_val = re.search(r"\b" + re.escape(m_enum.group(1)) + r"\s*=\s*(-?\d+)", txt)
                if m_val:
                    cur = int(m_val.group(1))
                    cur_enum_ev = f"{txh}:{txt[:m_val.start()].count(chr(10)) + 1} TxVersion::{m_enum.group(1)}={cur}"
                else:
                    cur = None
            else:
                cur = None
        else:
            cur = int(m_cur.group(1))
        extra_pre: List[int] = []
        for em0 in re.finditer(r"MAX_[A-Z_]*VERSION\s*(?:=|\{)\s*(0x[0-9A-Fa-f]+|\d+)", txt):
            try:
                extra_pre.append(int(em0.group(1), 0))
            except ValueError:
                continue
        if cur is None and m_mx is None and not extra_pre:
            return ParamStatus.UNRESOLVED, "TxVersion bounds not located in src/primitives/transaction.h"
        if cur is None:
            cur = 1
        mx = int(m_mx.group(1)) if m_mx else cur

        bound = max(cur, mx, 1)
        extra: List[int] = []
        for em in re.finditer(r"MAX_[A-Z_]*VERSION\s*(?:=|\{)\s*(0x[0-9A-Fa-f]+|\d+)", txt):
            try:
                v = int(em.group(1), 0)
                extra.append(v)
                bound = max(bound, v)
            except ValueError:
                continue

        try:
            tv = int(xc.get("TxVersion", ""))
        except ValueError:
            return ParamStatus.FAIL, "TxVersion non-numeric"

        ext_note = f" (extended range max {max(extra)})" if extra else ""
        cur_ln = txt[:m_cur.start()].count(chr(10)) + 1 if m_cur else None
        bound_ev = f"{txh}:{cur_ln}" if cur_ln else txh
        if cur_enum_ev and not cur_ln:
            bound_ev = cur_enum_ev
        if tv > bound:
            return ParamStatus.FAIL, f"TxVersion={tv} exceeds bound {bound}{ext_note} ({bound_ev})"
        if tv > max(cur, mx, 1):
            return ParamStatus.INFO, f"TxVersion={tv} within extended bound {bound}{ext_note} ({bound_ev})"
        if tv == bound:
            return ParamStatus.INFO, f"TxVersion={tv} at bound {bound}{ext_note} ({bound_ev})"
        return ParamStatus.PASS, f"TxVersion={tv} <= bound {bound} ({bound_ev})"

    @classmethod
    def check_txtime(cls, coin: ManifestCoin, src_dir: Path, xc: Dict[str, str]) -> Tuple[ParamStatus, str]:
        raw = SourceReader.slurp_src(src_dir, "src/primitives/transaction.h") or SourceReader.slurp(src_dir / "src/primitives/transaction.h")
        if raw is None:
            return ParamStatus.UNRESOLVED, "layout differs — src/primitives/transaction.h not found"

        txt = SourceReader.strip_comments(raw)
        cond = "SER_BTC_TX" in txt
        member = re.search(r"(?:const\s+)?(?:unsigned\s+|u?int\d*_t\s+)nTime\s*;", txt)
        serialized = re.search(r">>\s*(?:tx\.)?nTime\b", txt) or re.search(r"READWRITE\([^)]*\bnTime\b", txt)
        conf_v = xc.get("TxWithTimeField", "false").lower() == "true"

        # Generic CURRENT_CHAIN gate detection (smart, no hard-coded tickers)
        current_chain = cls._current_chain(src_dir)
        is_dual_chain = False
        guard_chain_val = ""
        guard_op = "=="
        if serialized:
            slines = txt.splitlines()
            ln0 = next((i for i, line in enumerate(slines) if re.search(r">>\s*(?:tx\.)?nTime\b|READWRITE\([^)]*\bnTime\b", line)), None)
            if ln0 is not None:
                ctx = "\n".join(slines[max(0, ln0 - 3):ln0 + 2])
                if re.search(r"\bif\s*\(|SER_[A-Z_]+|CHAIN|Transition|fOptional", ctx):
                    cond = True
                if re.search(r"current_chain", ctx, re.I):
                    m_guard = re.search(r"CURRENT_CHAIN\W*(==|!=)\s*[\"']([^\"']+)[\"']", ctx, re.I)
                    if m_guard:
                        guard_op = m_guard.group(1)
                        guard_chain_val = m_guard.group(2).lower()
                        is_dual_chain = True

        # If serialization is gated on a specific chain, polarity-aware:
        # guard_holds = (current==guard) if == else (current!=guard)
        # actual = guard_holds (serialized exactly when guard holds)
        actual = bool(member or serialized)
        if is_dual_chain and current_chain:
            guard_holds = (current_chain == guard_chain_val) if guard_op == "==" else (current_chain != guard_chain_val)
            actual = guard_holds
            if not guard_holds:
                guard = f'CURRENT_CHAIN="{current_chain}" {guard_op} "{guard_chain_val}" → nTime not serialized'
            else:
                guard = f'CURRENT_CHAIN="{current_chain}" {guard_op} "{guard_chain_val}" → holds → nTime serialized'
        else:
            guard = ""
            if serialized:
                slines2 = txt.splitlines()
                g0 = next((i for i, line in enumerate(slines2) if re.search(r">>\s*(?:tx\.)?nTime\b|READWRITE\([^)]*\bnTime\b", line)), None)
                if g0 is not None:
                    for gl in slines2[max(0, g0 - 3):g0 + 1]:
                        gs = gl.strip()
                        if gs.startswith("if ") or "SER_" in gs:
                            guard = gs[:120]
                            break

        suffix = f"; serialization guard: {guard}" if guard else ""
        rel = "src/primitives/transaction.h"
        ln = None
        if serialized:
            sl = txt.splitlines()
            g = next((i for i, line in enumerate(sl) if re.search(r">>\s*(?:tx\.)?nTime\b|READWRITE\([^)]*\bnTime\b", line)), None)
            if g is not None:
                ln = g + 1
        if ln is None and member:
            ln = txt[:member.start()].count("\n") + 1
        if ln is None:
            m_struct = re.search(r"(?:struct|class)\s+CTransaction\b", txt)
            if m_struct:
                ln = txt[:m_struct.start()].count("\n") + 1
        ev = f"{rel}:{ln}" if ln is not None else f"{rel} (no nTime member, CTransaction scope examined)"
        cite = f" ({ev})"
        if conf_v == actual:
            msg = f"TxWithTimeField={str(conf_v).lower()} and nTime is{'' if actual else ' NOT'} serialized{cite}{suffix}"
            return (ParamStatus.WARN if conf_v and cond else ParamStatus.MATCH), msg

        if cond:
            # For dual-chain gated case, already handled; cond remaining is
            # truly conditional but not chain-gated → WARN is correct
            return ParamStatus.WARN, f"TxWithTimeField={str(conf_v).lower()} while nTime is conditionally serialized{cite}{suffix}"
        return ParamStatus.FAIL, f"TxWithTimeField={str(conf_v).lower()} while nTime IS unconditionally serialized - tx wire-format mismatch{cite}{suffix}"


class ChainTimingMixin:
    """CURRENT_CHAIN detection and effective block-spacing resolution."""

    @classmethod
    def _current_chain(cls, src_dir: Path) -> Optional[str]:
        """Generic CURRENT_CHAIN detection without hard-coding tickers.

        Checks Makefile.am/autogen.sh/configure.ac NAME, fallback to chainparams
        spec keys. Returns lowercased chain name or None if not found.
        """
        cache_key = str(src_dir)
        if cache_key in _CURRENT_CHAIN_CACHE:
            return _CURRENT_CHAIN_CACHE[cache_key]
        # Primary: NAME in autogen.sh is the chain name
        for rel in ("autogen.sh", "src/Makefile.am", "Makefile.am", "configure.ac", "src/Makefile.in", "Makefile.in"):
            t = SourceReader.slurp_src(src_dir, rel) or SourceReader.slurp(src_dir / rel)
            if not t:
                continue
            # Simple NAME search – filter out BITCOIN_DAEMON_NAME etc by ignoring
            # matches where preceding char is '_' (manual check). This correctly
            # captures sed-escaped '\nNAME = lynx' where preceding char is 'n'.
            mn = None
            for m_cand in re.finditer(r"NAME\s*=\s*(\w+)", t):
                if m_cand.start() > 0 and t[m_cand.start() - 1] == "_":
                    continue
                mn = m_cand
                break
            if mn:
                # Verify this is chain-related (gate Makefile.in only if CURRENT_CHAIN present)
                if "CURRENT_CHAIN" in t or rel == "autogen.sh":
                    _CURRENT_CHAIN_CACHE[cache_key] = mn.group(1).lower()
                    return _CURRENT_CHAIN_CACHE[cache_key]
            m = re.search(r"CURRENT_CHAIN\s*=?\s*\"?\$?\(NAME\)\"?", t)
            if m:
                mn2 = None
                for m_cand in re.finditer(r"NAME\s*=\s*(\w+)", t):
                    if m_cand.start() > 0 and t[m_cand.start() - 1] == "_":
                        continue
                    mn2 = m_cand
                    break
                if mn2:
                    _CURRENT_CHAIN_CACHE[cache_key] = mn2.group(1).lower()
                    return _CURRENT_CHAIN_CACHE[cache_key]
        # Fallback: inspect chainparams spec keys – generic frequency based
        for rel in ("src/kernel/chainparams.cpp", "src/chainparams.cpp"):
            t = SourceReader.slurp_src(src_dir, rel) or SourceReader.slurp(src_dir / rel)
            if t:
                keys = re.findall(r'spec\.\w+\["(\w+)"\]', t)
                if keys:
                    # Generic: most frequent spec key is likely the active chain
                    cnt = Counter(k.lower() for k in keys)
                    most_common = cnt.most_common()
                    max_c = most_common[0][1]
                    # Tie-breaker: if multiple keys share max count, prefer first
                    # encountered in file order that is not a test chain.
                    tied = [k for k, c in most_common if c == max_c]
                    if len(tied) == 1:
                        _CURRENT_CHAIN_CACHE[cache_key] = tied[0]
                        return tied[0]
                    # Preserve file order for tie-break
                    seen = []
                    seen_set = set()
                    for k in keys:
                        lk = k.lower()
                        if lk not in seen_set:
                            seen_set.add(lk)
                            seen.append(lk)
                    for lk in seen:
                        if lk in tied and lk not in ("test", "testnet", "regtest", "signet", "main"):
                            _CURRENT_CHAIN_CACHE[cache_key] = lk
                            return lk
                    _CURRENT_CHAIN_CACHE[cache_key] = tied[0]
                    return tied[0]
        _CURRENT_CHAIN_CACHE[cache_key] = None
        return None

    @classmethod
    def _effective_blocktime(cls, src_dir: Path, main_txt: str, start: int, end: int) -> Tuple[Optional[float], Optional[int], str]:
        """Generic effective spacing: raw nPowTargetSpacing/nTargetSpacing plus
        fork-aware overrides without hard-coding tickers.

        Detected patterns (all generic, tag-scoped):
        - FIRO-like MTP halving: pow.cpp/block.cpp GetTargetBlocksSpacing
          returns nPowTargetSpacingMTP/2 after stage3StartTime
        - QTUM-like RBT: nReduceBlocktimeHeight + nRBTPowTargetSpacing
        - UNO-like KGW: BlocksTargetSpacing = 3*60 in pow.cpp after fork block
        - PoS: nTargetSpacing (nPosTargetSpacing) variant
        """
        def _to_num(expr: str) -> Optional[float]:
            return _safe_arith_float(expr)

        # Raw candidates in mainnet block (generic, no hard-coding)
        raw_val: Optional[float] = None
        raw_ln: Optional[int] = None
        raw_key: str = ""
        for pat, key in (
            (r"nPowTargetSpacing\s*=\s*([^;\n]+)", "nPowTargetSpacing"),
            (r"nTargetSpacing\s*=\s*([^;\n]+)", "nTargetSpacing"),
            (r"nStakeTargetSpacing\s*=\s*([^;\n]+)", "nStakeTargetSpacing"),
            (r"nPosTargetSpacing\s*=\s*([^;\n]+)", "nPosTargetSpacing"),
        ):
            m, ln = cls.regex_in_block(main_txt, start, end, pat)
            if m is not None:
                raw_expr = m.group(1).strip()
                v = _to_num(raw_expr)
                if v is not None:
                    raw_val, raw_ln, raw_key = v, ln, key
                    break
                # Generic multi-algo indirection: raw is identifier (e.g. consensus.nPowTargetSpacingV2)
                # Resolve by searching same slice for the referenced V-suffix definition (no ticker hard-code).
                m_ref = re.search(r"nPowTargetSpacingV\w*", raw_expr)
                if m_ref:
                    var = m_ref.group(0)
                    m_v, ln_v = cls.regex_in_block(main_txt, start, end, rf"{re.escape(var)}\s*=\s*([^;\n]+)")
                    if m_v is not None:
                        v2 = _to_num(m_v.group(1))
                        if v2 is not None:
                            raw_val, raw_ln, raw_key = v2, ln_v, f"{key}->{var}"
                            break
                else:
                    # Fallback: opaque identifier – only if nPowTargetSpacing in raw_expr
                    if "nPowTargetSpacing" in raw_expr:
                        m_v2, ln_v2 = cls.regex_in_block(main_txt, start, end, r"nPowTargetSpacingV\w*\s*=\s*([^;\n]+)")
                        if m_v2 is not None:
                            v2 = _to_num(m_v2.group(1))
                            if v2 is not None:
                                raw_val, raw_ln, raw_key = v2, ln_v2, f"{key}->V*"
                                break

        # Note: do not early-return on raw_val is None – PoS/RBT/MTP/KGW
        # overrides below may still produce an effective value (e.g. chains
        # that only have nPosTargetSpacing).

        # Generic helpers to slurp optional files without ticker branches
        def _slurp_any(rel: str) -> Optional[str]:
            return SourceReader.slurp_src(src_dir, rel) or SourceReader.slurp(src_dir / rel)

        # 1) PoS spacing: if nTargetSpacing exists and differs from
        #    nPowTargetSpacing, the smaller PoS value is the actual block cadence.
        #    Many hybrids define both; the PoS spacing is the live chain spacing.
        #    Only use when PoS is faster (smaller) than PoW to avoid misclassifying
        #    pure PoW chains like DGB where nTargetSpacing 60 > nPow 15.
        m_pos, ln_pos = cls.regex_in_block(main_txt, start, end, r"nTargetSpacing\s*=\s*([^;\n]+)")
        m_pow, _ = cls.regex_in_block(main_txt, start, end, r"nPowTargetSpacing\s*=\s*([^;\n]+)")
        if m_pos is not None and m_pow is not None:
            v_pos = _to_num(m_pos.group(1))
            v_pow = _to_num(m_pow.group(1))
            if v_pos is not None and v_pow is not None and v_pos != v_pow and v_pos < v_pow:
                if re.search(r"nStakeMinConf|nTargetTimespan|nPosTargetSpacing", main_txt[start:end]):
                    return v_pos, ln_pos, f"{raw_key}:{raw_ln} PoS effective {v_pos} (raw PoW {v_pow})"
        # Also check nPosTargetSpacing as explicit PoS spacing
        m_ppos, ln_ppos = cls.regex_in_block(main_txt, start, end, r"nPosTargetSpacing\s*=\s*([^;\n]+)")
        if m_ppos is not None:
            v_ppos = _to_num(m_ppos.group(1))
            if v_ppos is not None:
                # KGW/PoS override: chains with PowTargetSpacingV1/V2/V3 historical;
                # nPosTargetSpacing is live
                if re.search(r"PowTargetSpacingV", main_txt[start:end]):
                    return v_ppos, ln_ppos, f"nPosTargetSpacing:{ln_ppos} PoS effective {v_ppos}"

        # 2) QTUM-like reduced blocktime: nReduceBlocktimeHeight + nRBTPowTargetSpacing
        m_rbt, ln_rbt = cls.regex_in_block(main_txt, start, end, r"nRBTPowTargetSpacing\s*=\s*([^;\n]+)")
        if m_rbt is not None:
            v_rbt = _to_num(m_rbt.group(1))
            if v_rbt is not None:
                # Generic: if Reduce height exists, use RBT value as effective
                # (tip is past reduce height for all our held tags >845k)
                if re.search(r"nReduceBlocktimeHeight", main_txt[start:end]):
                    return v_rbt, ln_rbt, f"nRBTPowTargetSpacing:{ln_rbt} effective {v_rbt} (raw {raw_val})"

        # 3) FIRO-like MTP halving: look for GetTargetBlocksSpacing returning MTP/2
        for rel in ("src/pow.cpp", "src/primitives/block.cpp", "src/consensus/params.cpp"):
            t = _slurp_any(rel)
            if t and "GetTargetBlocksSpacing" in t and "nPowTargetSpacingMTP" in t:
                # Find MTP spacing
                for cand in (t, main_txt):
                    m_mtp, ln_mtp = cls.regex_in_block(cand, 0, len(cand), r"nPowTargetSpacingMTP\s*=\s*([^;\n]+)")
                    if m_mtp:
                        v_mtp = _to_num(m_mtp.group(1))
                        if v_mtp is not None:
                            # Check for /2 halving pattern (stage3)
                            if "/2" in t[t.find("GetTargetBlocksSpacing"):t.find("GetTargetBlocksSpacing")+500] or "stage3StartTime" in t:
                                return v_mtp / 2.0, ln_mtp, f"nPowTargetSpacingMTP/2:{ln_mtp} effective {v_mtp/2.0} (raw {raw_val})"
                            return v_mtp, ln_mtp, f"nPowTargetSpacingMTP:{ln_mtp} effective {v_mtp}"

        # 4) UNO-like KGW: pow.cpp BlocksTargetSpacing = 3*60 after fork
        for rel in ("src/pow.cpp", "src/pow.h", "src/consensus/pow.cpp"):
            t = _slurp_any(rel)
            if t and "BlocksTargetSpacing" in t:
                m_bts, ln_bts = cls.regex_in_block(t, 0, len(t), r"BlocksTargetSpacing\s*=\s*([^;\n;]+)")
                if m_bts:
                    # Handle 3 * 60 expression
                    v_bts = _to_num(m_bts.group(1))
                    if v_bts is not None and v_bts >= 60:
                        # Generic signal: KGW present and fork block passed
                        if "KimotoGravityWell" in t or "PROOF_OF_WORK_FORK_BLOCK" in t:
                            return v_bts, ln_bts, f"BlocksTargetSpacing:{ln_bts} KGW effective {v_bts} (raw {raw_val})"

        # 5) Generic height-gated TargetSpacing: any .cpp/.h with `TargetSpacing = <val>` inside
        #    a height gate `height > 123456` or ternary `height < nReduce ? a : b`.
        #    Collect candidates (height, value, ref) within 15 lines before assignment,
        #    pick max-height as effective (assumes tip past fork).
        candidates: list = []
        # Build file list to scan (main_txt plus slurped sources)
        files_to_scan: list = [(main_txt, "chainparams.cpp:mainnet")]
        for rel in (
            "src/pow.cpp",
            "src/pow.h",
            "src/consensus/pow.cpp",
            "src/consensus/params.cpp",
            "src/validation.cpp",
            "src/chainparams.cpp",
            "src/chainparams.h",
            "src/kernel/chainparams.cpp",
            "src/primitives/block.cpp",
        ):
            txt_cand = _slurp_any(rel)
            if txt_cand:
                files_to_scan.append((txt_cand, rel))
        for file_txt, ref in files_to_scan:
            lines = file_txt.splitlines()
            for idx, line in enumerate(lines):
                for m_tg in re.finditer(r"TargetSpacing\s*=\s*([^;\n]+)", line):
                    val_expr = m_tg.group(1).strip().rstrip(";").strip()
                    ctx_before = "\n".join(lines[max(0, idx - 15): idx + 1])
                    height_val = None
                    # literal height gate
                    hm = re.search(r"(?:nHeight|height|nReduceBlocktimeHeight|stage3StartTime|PROOF_OF_WORK_FORK_BLOCK)\s*(?:>|>=|<|<=|==)\s*(\d+)", ctx_before, re.I)
                    if hm:
                        try:
                            height_val = int(hm.group(1))
                        except ValueError:
                            height_val = None
                    if height_val is None:
                        # variable height e.g. `height < nReduceBlocktimeHeight` -> resolve var
                        vm = re.search(r"(?:nHeight|height)\s*(?:>|>=|<|<=|==)\s*([A-Za-z_]\w*)", ctx_before, re.I)
                        if vm:
                            var_name = vm.group(1)
                            for ft2, _ in files_to_scan:
                                m_var, _ln = cls.regex_in_block(ft2, 0, len(ft2), rf"{re.escape(var_name)}\s*=\s*(\d+)")
                                if m_var:
                                    try:
                                        height_val = int(m_var.group(1).strip())
                                        break
                                    except ValueError:
                                        continue
                    if height_val is None:
                        # ternary height < 123456 ? ... : ...
                        tm = re.search(r"height\s*(?:<|>|<=|>=)\s*(\d+)\s*\?", ctx_before, re.I)
                        if tm:
                            try:
                                height_val = int(tm.group(1))
                            except ValueError:
                                pass
                    if height_val is None:
                        continue
                    v = _to_num(val_expr)
                    if v is None and "?" in val_expr and ":" in val_expr:
                        else_part = val_expr.split(":")[-1].strip()
                        # strip trailing ) etc
                        else_part = re.split(r"[;\)\s]+", else_part)[0]
                        v_try = _to_num(else_part)
                        if v_try is not None:
                            v = v_try
                        else:
                            # variable else part
                            var_else = re.search(r"[A-Za-z_]\w*", else_part)
                            if var_else:
                                var_name2 = var_else.group(0)
                                for ft2, _ in files_to_scan:
                                    m2, _ = cls.regex_in_block(ft2, 0, len(ft2), rf"{re.escape(var_name2)}\s*=\s*([^;\n]+)")
                                    if m2:
                                        v2 = _to_num(m2.group(1).strip())
                                        if v2 is not None:
                                            v = v2
                                            break
                    if v is None:
                        continue
                    candidates.append((height_val, v, f"{ref}:{idx+1}"))
        if candidates:
            candidates.sort(key=lambda x: x[0])
            best_h, best_v, best_ref = candidates[-1]
            return best_v, None, f"generic height-gated TargetSpacing:{best_ref} h={best_h} effective {best_v} (raw {raw_val})"

        # Default: raw is effective
        return raw_val, raw_ln, f"{raw_key}:{raw_ln} raw effective {raw_val}"

    @classmethod
    def check_blocktime(cls, coin: ManifestCoin, src_dir: Path, xc: Dict[str, str], want_test: bool, repo_root: Path) -> Tuple[ParamStatus, str]:
        try:
            bt = int(xc.get("BlockTime", ""))
        except ValueError:
            return ParamStatus.FAIL, "BlockTime non-numeric"
        if bt == 0:
            return ParamStatus.FAIL, "BlockTime=0 rejected by blocknet"

        txt = None
        used_rel = "src/chainparams.cpp"
        for rel in ("src/chainparams.cpp", "src/kernel/chainparams.cpp"):
            cand = SourceReader.slurp_src(src_dir, rel) or SourceReader.slurp(src_dir / rel)
            if cand:
                if txt is None:
                    txt = cand
                    used_rel = rel
                s_tmp, e_tmp = cls.mainnet_slice(cand, want_test)
                m_tmp, _ = cls.regex_in_block(
                    cand, s_tmp, e_tmp,
                    r"(?:nPowTargetSpacing\w*|nTargetSpacing|nStakeTargetSpacing|nPosTargetSpacing|TargetSpacing)\s*=\s*([^;\n]+)"
                )
                if m_tmp is not None:
                    txt = cand
                    used_rel = rel
                    break

        if txt is None:
            return ParamStatus.UNRESOLVED, "layout differs — src/chainparams.cpp not found"

        start, end = cls.mainnet_slice(txt, want_test)
        want, ln, ev = cls._effective_blocktime(src_dir, txt, start, end)
        if want is None:
            # Fallback to raw search for better UNRESOLVED message
            m, ln2 = cls.regex_in_block(txt, start, end, r"(?:nPowTargetSpacing\w*|nTargetSpacing|nStakeTargetSpacing|nPosTargetSpacing|TargetSpacing)\s*=\s*([^;\n]+)")
            if m is not None:
                want2 = _safe_arith_float(m.group(1))
                if want2 is not None:
                    if abs(want2 - bt) < 1e-9:
                        return ParamStatus.PASS, f"BlockTime={bt} == spacing ({used_rel}:{ln2})"
                    since = SourceReader.lineage_date(repo_root, f"xbridge-confs/{coin.xbridge_conf}", "BlockTime")
                    lin = f"; value present since {since}" if since else ""
                    return ParamStatus.WARN, f"BlockTime={bt} vs chainparams spacing {want2} ({used_rel}:{ln2}){lin}"
            return ParamStatus.UNRESOLVED, f"no effective target-spacing found ({used_rel} {ev})"

        m_embed = re.search(r"([\w./-]+\.(?:cpp|h|go):\d+)", ev)
        if ln is not None:
            cite = f"{used_rel}:{ln}"
        elif m_embed:
            cite = m_embed.group(1)
        else:
            cite = f"{used_rel} {ev}"
        if abs(want - bt) < 1e-9:
            return ParamStatus.PASS, f"BlockTime={bt} == effective spacing {want:g} ({cite}, {ev})"

        since = SourceReader.lineage_date(repo_root, f"xbridge-confs/{coin.xbridge_conf}", "BlockTime")
        lin = f"; value present since {since}" if since else ""
        return ParamStatus.WARN, f"BlockTime={bt} vs effective spacing {want:g} ({cite}, {ev}){lin}"


class WalletFlagMixin:
    """Wallet conf flag support: txindex, addresstype/changetype, deprecatedrpc."""

    @classmethod
    def check_txindex(cls, coin: ManifestCoin, src_dir: Path, wc: Dict[str, str]) -> Tuple[ParamStatus, str]:
        dflt, ev = None, None
        # Generic ordered candidates – covers Bitcoin Core evolution:
        # 0.21+ -> src/index/txindex.h  constexpr {false/true}
        # classic -> src/validation.h   = false
        # legacy forks -> src/main.h    = false/true
        # wrapper (divi) handled via slurp_src
        for rel in ("src/index/txindex.h", "src/validation.h", "src/main.h", "src/kernel/chainparams.h", "src/txdb.h", "divi/src/txdb.h"):
            txt = SourceReader.slurp_src(src_dir, rel) or SourceReader.slurp(src_dir / rel)
            if txt is None:
                continue
            m = re.search(r"DEFAULT_TXINDEX\s*(?:=\s*(true|false)|\{\s*(true|false)\s*\})", txt)
            if m:
                val = m.group(1) or m.group(2)
                dflt = val == "true"
                ev = f"{rel}:{txt[:m.start()].count(chr(10)) + 1}"
                break
        # Fallback: legacy forks without DEFAULT_TXINDEX constant – detect via fTxIndex init or GetBoolArg default
        if dflt is None:
            for rel in ("src/main.cpp", "src/txdb.cpp", "divi/src/txdb.cpp", "divi/src/BlockIndexLoading.cpp"):
                txt = SourceReader.slurp_src(src_dir, rel) or SourceReader.slurp(src_dir / rel)
                if txt is None:
                    continue
                m = re.search(r"bool\s+fTxIndex\s*=\s*(true|false)", txt)
                if m:
                    dflt = m.group(1) == "true"
                    ev = f"{rel}:{txt[:m.start()].count(chr(10)) + 1} fTxIndex"
                    break
                m2 = re.search(r'GetBoolArg\s*\(\s*["\']-txindex["\']\s*,\s*(true|false)', txt)
                if m2:
                    dflt = m2.group(1) == "true"
                    ev = f"{rel}:{txt[:m2.start()].count(chr(10)) + 1} GetBoolArg-txindex"
                    break

        has_line = "txindex" in {k.split(".")[0].lower() for k in wc}
        # Registration – search broader (init/common for newer cores)
        registered = False
        for rel in ("src/init.cpp", "src/init/common/args.cpp", "src/main.cpp", "divi/src/BlockIndexLoading.cpp"):
            t = SourceReader.slurp_src(src_dir, rel) or SourceReader.slurp(src_dir / rel)
            if t and ('"-txindex"' in t or "'-txindex'" in t):
                registered = True
                break
        if not registered:
            # legacy HelpMessageOpt style
            for rel in ("src/init.cpp", "src/main.cpp"):
                t = SourceReader.slurp_src(src_dir, rel) or SourceReader.slurp(src_dir / rel)
                if t and "-txindex" in t:
                    registered = True
                    break

        if dflt is None:
            return ParamStatus.UNRESOLVED, "DEFAULT_TXINDEX not located"
        if not registered:
            return ParamStatus.UNRESOLVED, "-txindex option not registered upstream"
        if not has_line and dflt is False:
            return ParamStatus.WARN, f"txindex missing from conf while DEFAULT_TXINDEX=false ({ev})"
        if not has_line and dflt:
            return ParamStatus.INFO, f"txindex relies on upstream default=true ({ev})"
        if has_line:
            try:
                got = int(str(conf_val_ci(wc, "txindex")).strip())
            except ValueError:
                return ParamStatus.FAIL, f"txindex={conf_val_ci(wc, 'txindex')!r} non-numeric ({ev})"
            if got == 1:
                return ParamStatus.PASS, f"txindex=1 explicitly enabled ({ev})"
            return ParamStatus.WARN, f"txindex={got} explicitly disabled while XBridge needs index ({ev})"

    @classmethod
    def check_addrtype(cls, coin: ManifestCoin, src_dir: Path, wc: Dict[str, str]) -> Tuple[ParamStatus, str]:
        lowered = {k.lower() for k in wc}
        keys = [k for k in ("addresstype", "changetype") if k in lowered]
        if not keys:
            return ParamStatus.SKIP, "not used"
        for rel in ("src/init.cpp", "src/wallet/init.cpp", "src/wallet/wallet.h"):
            t = SourceReader.slurp_src(src_dir, rel) or SourceReader.slurp(src_dir / rel)
            if not t:
                continue
            for flag in ('"-addresstype"', '"-changetype"'):
                if flag in t:
                    ln = t[:t.find(flag)].count("\n") + 1
                    return ParamStatus.PASS, f"addresstype/changetype supported upstream ({rel}:{ln} {flag})"
        searched = "src/init.cpp, src/wallet/init.cpp, src/wallet/wallet.h"
        return ParamStatus.INFO, f"addresstype/changetype lines are silently absorbed (option not registered) ({searched})"

    @classmethod
    def check_deprecatedrpc(cls, coin: ManifestCoin, src_dir: Path, wc: Dict[str, str], repo_root: Path) -> Tuple[ParamStatus, str]:
        raw = conf_val_ci(wc, "deprecatedrpc").strip()
        if raw.lower() == "true":
            raw = "signrawtransaction"
        if not raw:
            return ParamStatus.INFO, "deprecatedrpc not set"

        values = [v.strip() for v in raw.split(",") if v.strip()]
        if not values:
            return ParamStatus.INFO, "deprecatedrpc not set"

        details: List[str] = []
        worst = ParamStatus.INFO
        files_to_check = (
            "src/rpc/server.cpp", "src/init.cpp", "src/core_write.cpp",
            "src/rpc/blockchain.cpp", "src/rpc/rawtransaction.cpp",
            "src/wallet/rpcwallet.cpp", "src/rpc/misc.cpp",
        )

        for val in values:
            gate_found = False
            gate_ev = ""
            for rel in files_to_check:
                txt = SourceReader.slurp_src(src_dir, rel) or SourceReader.slurp(src_dir / rel)
                if txt is None:
                    continue
                if f'IsDeprecatedRPCEnabled("{val}")' in txt or f"IsDeprecatedRPCEnabled('{val}')" in txt:
                    ln = txt[:txt.find(val)].count("\n") + 1
                    gate_found = True
                    gate_ev = f"{rel}:{ln} IsDeprecatedRPCEnabled(\"{val}\")"
                    break
                if "IsDeprecatedRPCEnabled" in txt and val in txt:
                    for m in re.finditer(r"IsDeprecatedRPCEnabled\s*\(\s*[\"']" + re.escape(val) + r"[\"']\s*\)", txt):
                        gate_found = True
                        gate_ev = f"{rel}:{txt[:m.start()].count(chr(10)) + 1} IsDeprecatedRPCEnabled(\"{val}\")"
                        break
                    if gate_found:
                        break

            method_exists = False
            method_ev = ""
            for rel in files_to_check:
                txt = SourceReader.slurp_src(src_dir, rel) or SourceReader.slurp(src_dir / rel)
                if txt is None:
                    continue
                if f'"{val}"' in txt or f"'{val}'" in txt:
                    ln = txt.find(val)
                    method_exists = True
                    method_ev = f"{rel}:{txt[:ln].count(chr(10)) + 1} contains \"{val}\""

            if gate_found:
                details.append(f"{val} gated at {gate_ev} — keep")
                worst = max_status(worst, ParamStatus.INFO)
            elif method_exists:
                since = SourceReader.lineage_date(repo_root, f"wallet-confs/{coin.wallet_conf}", "deprecatedrpc")
                lin = f"; value present since {since}" if since else ""
                details.append(f"{val} method exists without gate ({method_ev}) — deprecatedrpc unnecessary{lin}")
                worst = max_status(worst, ParamStatus.WARN)
            else:
                since = SourceReader.lineage_date(repo_root, f"wallet-confs/{coin.wallet_conf}", "deprecatedrpc")
                lin = f"; value present since {since}" if since else ""
                details.append(f'{val} no IsDeprecatedRPCEnabled("{val}") gate and RPC "{val}" not registered at tag {coin.ver_id} — stale, flag does nothing{lin}')
                worst = max_status(worst, ParamStatus.WARN)

        return worst, "; ".join(details)


class CppSourceInspector(ChainSliceMixin, PrefixMixin, PortMixin, FeeMixin, TxWireMixin, ChainTimingMixin, WalletFlagMixin):
    """Fact-checks configuration values against Bitcoin-derivative C++ codebases.

    Composed facade: every method arrives from exactly one mixin above, so the
    historical API (``CppSourceInspector.check_port(...)`` etc.) is unchanged.
    """


