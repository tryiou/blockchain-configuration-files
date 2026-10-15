"""CppSourceInspector: C/C++ source fact-checking, split by cohesive concern.

The historical class was a single 1,411-line unit mixing seven unrelated
concerns (base58 prefixes, ports, fees, chain timing, tx/wire format,
wallet flags). Each concern now lives in its own mixin below; the
``CppSourceInspector`` facade at the bottom composes them, so every caller
and test keeps using the exact same class name and method signatures.

The scanners the mixins share (``mainnet_slice``, ``regex_in_block``,
``coin_value_from_amount_h``, ``current_chain``) are module-level
functions, so no cross-mixin dispatch is needed.
"""

from __future__ import annotations

import contextlib
import re
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import NamedTuple

from ..checkout import SourceReader
from ..constants import (
    PREFIX_DECODE_COMPAT_FMT,
    PREFIX_MINTED_SA2_OK_FMT,
    PREFIX_MISMATCH_FMT,
    PREFIX_SKIP_FMT,
    logger,
)
from ..model import CheckerTuple, FeePolicy, ManifestCoin, ParamStatus, max_status
from ..probe import SystemCommandRunner
from ..util import _safe_arith_float, conf_val_ci, eval_cnum
from .base import (
    NTIME_SERIALIZED_OR_RW_RE,
    NTIME_SERIALIZED_RE,
    CppExpressionEvaluator,
)

# Process-wide cache for CURRENT_CHAIN detection keyed by the checkout
# path AND its HEAD: the tool keeps ONE folder per coin and switches
# tags inside it, so the path alone no longer identifies the tree being
# read. Tests clear it in place between cases (shared object identity
# matters).
_CURRENT_CHAIN_CACHE: dict[str, str | None] = {}


def _chain_cached(key: str) -> tuple[bool, str | None]:
    """(hit, value) for one cache key; the dict stays clearable in place."""
    if key in _CURRENT_CHAIN_CACHE:
        return True, _CURRENT_CHAIN_CACHE[key]
    return False, None


def _chain_cache_put(key: str, value: str | None) -> None:
    """The single write into the chain cache."""
    _CURRENT_CHAIN_CACHE[key] = value


# Fee/blocktime shape constants: the float tolerance two source constants
# compare equal at, and the smallest spacing a KGW fork override may claim.
_FLOAT_TOLERANCE = 1e-9
_KGW_MIN_SPACING = 60
# mainnet-slice ctor selection: more than this many candidates means a
# testnet ctor set, and the test ctor sits second.
_MULTI_CTOR_THRESHOLD = 2


def _src_head(src_dir: Path) -> str | None:
    """HEAD commit of ``src_dir``, or ``None`` when the tree has no identity.

    Part of the cache key: a tag switch in place must invalidate the
    chain name that was read for the previous tag. ``None`` (non-git
    fixture tree, or git itself unavailable) means "never cache" rather
    than a shared sentinel that every tree would collide on. The call
    goes through the shared runner, which logs exceptions and timeouts;
    a plain non-zero exit (a non-git fixture tree) yields ``None``
    quietly.
    """
    proc = SystemCommandRunner.run(["git", "-C", str(src_dir), "rev-parse", "HEAD"], 30)
    if proc is not None and proc.returncode == 0 and proc.stdout.strip():
        return proc.stdout.strip()
    return None


def _src_dirty(src_dir: Path) -> bool | None:
    """True when tracked files have uncommitted edits, False when clean."""
    proc = SystemCommandRunner.run(["git", "-C", str(src_dir), "status", "--porcelain", "--untracked-files=no"], 30)
    if proc is None or proc.returncode != 0:
        return None
    return bool(proc.stdout.strip())


# Shared source scanners used across the mixins below.


def mainnet_slice(src_text: str, *, want_test: bool = False) -> tuple[int, int]:
    if want_test:
        m = re.search(r"class\s+C\w*Test\w*Params\b", src_text)
        if m:
            nxt = re.search(r"\nclass\s+C\w+", src_text[m.end() :])
            end = m.end() + nxt.start() if nxt else len(src_text)
            return m.start(), end
        m2 = re.search(r"class\s+CTest(?:Net|net)?Params\b", src_text)
        if m2:
            nxt = re.search(r"\nclass\s+C\w+", src_text[m2.end() :])
            end = m2.end() + nxt.start() if nxt else len(src_text)
            return m2.start(), end

    m = re.search(r"class\s+C\w*Main\w*Params\b", src_text)
    if m:
        nxt = re.search(r"\nclass\s+C(?!.*Main\w*Params)\w+", src_text[m.end() :])
        end = m.end() + nxt.start() if nxt else len(src_text)
        return m.start(), end

    m_exact = re.search(r"class\s+CMainParams\b", src_text)
    if m_exact:
        nxt = re.search(r"\nclass\s+C(?!MainParams)\w+", src_text[m_exact.end() :])
        end = m_exact.end() + nxt.start() if nxt else len(src_text)
        return m_exact.start(), end

    test_m = re.search(r"class\s+\w*[Tt]est\w*Params\b", src_text)
    if test_m and not want_test:
        return 0, test_m.start()

    ctors = [m.start() for m in re.finditer(r"CChainParams::CChainParams\(\)", src_text)]
    idx = 1 if (want_test and len(ctors) > _MULTI_CTOR_THRESHOLD) else (len(ctors) - 1 if ctors else 0)
    start = ctors[idx] if len(ctors) > 1 else 0
    end = ctors[idx + 1] if len(ctors) > idx + 1 else len(src_text)
    return start, end


def regex_in_block(text: str, start: int, end: int, pattern: str) -> tuple[re.Match[str] | None, int | None]:
    sub = text[start:end]
    m = re.search(pattern, sub)
    if not m:
        return None, None
    ln = text[:start].count("\n") + sub[: m.start()].count("\n") + 1
    return m, ln


class PrefixMixin:
    """base58 prefix extraction and conf-vs-source prefix comparison."""

    @classmethod
    def prefix_value(  # noqa: C901, PLR0911  # pattern-matcher: one branch per known source marker
        cls,
        text: str,
        start: int,
        end: int,
        key: str,
        chain: str | None = None,
    ) -> tuple[int | None, int | None]:
        vec_pat = (
            r"base58Prefixes\[" + key + r"\]\s*=\s*"
            r"std\s*::\s*vector\s*<\s*(?:unsigned\s+char|uint8_t)\s*>\s*\(([^;]*?)\)"
        )
        brace_pat = r"base58Prefixes\[" + key + r"\]\s*=\s*\{([^;}]*)\}"
        m_vec, ln_vec = regex_in_block(text, start, end, vec_pat)
        m_brace, ln_brace = regex_in_block(text, start, end, brace_pat)
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
        # ctor arity: the two-argument form carries (nBits, nProof)
        raw = args[-1] if len(args) >= 2 else args[0]  # noqa: PLR2004
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
                                return int(mm.group(1)), text[: mm.start()].count(chr(10)) + 1
                            except ValueError:
                                pass
                    # Fallback: when chain is None, emit UNRESOLVED instead of first-match guess
                    return None, ln
            return None, ln

    @classmethod
    def minted_script_prefix(  # noqa: C901, PLR0912  # pattern-matcher: one branch per known source marker
        cls,
        src_dir: Path,
        sa: int,
        sa2: int,
    ) -> tuple[int | None, str]:
        found: dict[int, str] = {}
        for rel in ("src/key_io.cpp", "src/base58.cpp"):
            txt = SourceReader.slurp_src(src_dir, rel) or SourceReader.slurp(src_dir / rel)
            if txt is None:
                continue
            m = re.search(r"operator\(\)\(\s*const\s+(?:CScriptID|ScriptHash)\b", txt)
            if not m:
                continue
            win = txt[m.start() : m.start() + 500]
            ln = txt[: m.start()].count("\n") + 1
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
                    ln = txt[: m.start()].count("\n") + 1 if m else txt[: txt.find("SCRIPT_ADDRESS2")].count("\n") + 1
                    found[sa2] = f"{rel}:{ln} CBitcoinAddress defaults to SCRIPT_ADDRESS2"
            if (
                "CBitcoinAddress" in txt
                and "SCRIPT_ADDRESS" in txt
                and re.search(r"Base58Prefix\(CChainParams::SCRIPT_ADDRESS\)", txt)
            ):
                ln = txt.find("SCRIPT_ADDRESS")
                if sa not in found:
                    found[sa] = f"{rel}:{txt[:ln].count(chr(10)) + 1} encodes SCRIPT_ADDRESS"

        if sa2 in found:
            return sa2, found[sa2]
        if sa in found:
            return sa, found[sa]
        return None, "encode site not identified"

    @classmethod
    def check_prefixes(  # noqa: C901, PLR0915, PLR0912  # pattern-matcher: one branch per known source marker
        cls, coin: ManifestCoin, src_dir: Path, xc: dict[str, str], *, want_test: bool, repo_root: Path
    ) -> tuple[ParamStatus, str]:
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

        start, end = mainnet_slice(txt, want_test=want_test)
        rows: list[str] = []
        worst = ParamStatus.PASS
        chain = current_chain(src_dir)

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
                    rows.append(
                        f"{ckey}: source {pkey} for chain '{chain}' not found - spec entry missing "
                        f"(UNRESOLVED) [{used_rel}]"
                    )
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
    def check_port(  # noqa: C901, PLR0912  # pattern-matcher: one branch per known source marker
        cls,
        coin: ManifestCoin,
        src_dir: Path,
        wc: dict[str, str],
        *,
        want_test: bool,
        repo_root: Path,
    ) -> tuple[ParamStatus, str]:
        for rel in ("src/chainparams.cpp", "src/kernel/chainparams.cpp"):
            txt = SourceReader.slurp_src(src_dir, rel) or SourceReader.slurp(src_dir / rel)
            if txt is None:
                continue
            start, end = mainnet_slice(txt, want_test=want_test)
            # Generic: nDefaultPort = <int>  OR  spec.nDefaultPort["<chain>"] = <int> / Params.nDefaultPort =
            m, ln = regex_in_block(txt, start, end, r"\bnDefaultPort\s*=\s*(\d+)")
            if m is None:
                # Spec map: spec.nDefaultPort["<chain>"] = <int> - table may be outside mainnet slice
                chain = current_chain(src_dir)
                if chain:
                    m2, ln2 = regex_in_block(
                        txt,
                        start,
                        end,
                        rf'spec\.nDefaultPort\["{re.escape(chain)}"\]\s*=\s*(\d+)',
                    )
                    if m2 is not None:
                        m, ln = m2, ln2
                    else:
                        # Fallback whole-file search for spec table (outside slice)
                        m2 = re.search(rf'spec\.nDefaultPort\["{re.escape(chain)}"\]\s*=\s*(\d+)', txt)
                        if m2:
                            m, ln = m2, txt[: m2.start()].count(chr(10)) + 1
                        else:
                            m2, ln2 = regex_in_block(txt, start, end, r'spec\.nDefaultPort\["[^"]+"\]\s*=\s*(\d+)')
                            if m2 is not None:
                                m, ln = m2, ln2
                            else:
                                m2 = re.search(r'spec\.nDefaultPort\["[^"]+"\]\s*=\s*(\d+)', txt)
                                if m2:
                                    m, ln = m2, txt[: m2.start()].count(chr(10)) + 1
                else:
                    m2 = re.search(r'spec\.nDefaultPort\["[^"]+"\]\s*=\s*(\d+)', txt)
                    if m2:
                        m, ln = m2, txt[: m2.start()].count(chr(10)) + 1
            # Also handle indirection: nDefaultPort = spec.nDefaultPort[CURRENT_CHAIN]
            if m is None and re.search(
                r"nDefaultPort\s*=\s*spec\.nDefaultPort\[",
                txt[start:end] if start is not None else txt,
            ):
                chain = current_chain(src_dir)
                if chain:
                    m2 = re.search(rf'spec\.nDefaultPort\["{re.escape(chain)}"\]\s*=\s*(\d+)', txt)
                    if m2:
                        m, ln = m2, txt[: m2.start()].count(chr(10)) + 1
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
                return ParamStatus.WARN, (
                    f"wallet port={got} vs source nDefaultPort={want} ({rel}:{ln}){lin} [fleet-reassigned]"
                )
        return ParamStatus.UNRESOLVED, (
            "nDefaultPort not found — searched src/chainparams.cpp and src/kernel/chainparams.cpp"
        )

    @classmethod
    def check_rpcport_source(
        cls,
        coin: ManifestCoin,
        src_dir: Path,
        wc: dict[str, str],
        *,
        want_test: bool,
        repo_root: Path,
    ) -> tuple[ParamStatus, str]:
        txt = SourceReader.slurp_src(src_dir, "src/chainparamsbase.cpp") or SourceReader.slurp(
            src_dir / "src/chainparamsbase.cpp"
        )
        if txt is None:
            return ParamStatus.UNRESOLVED, "layout differs (no chainparamsbase.cpp) — wrapper-aware search exhausted"
        ev = "chainparamsbase.cpp"
        if want_test:
            allv = [(mm, txt[: mm.start()].count("\n") + 1) for mm in re.finditer(r"nRPCPort\s*=\s*(\d+)", txt)]
            tm = re.search(r'CBaseChainParams[^"]*"[^"]*",\s*(\d+)', txt)
            if len(allv) >= 2:  # noqa: PLR2004  # testnet RPC arity: the second definition is the test value
                m, ln = allv[1]
                want, where = int(m.group(1)), f"{ev}:{ln}"
            elif tm:
                want, where = int(tm.group(1)), f"{ev}:{txt[: tm.start()].count(chr(10)) + 1} (test branch)"
            else:
                return ParamStatus.UNRESOLVED, "testnet RPC port not located"
        else:
            mm = re.search(r"nRPCPort\s*=\s*(\d+)", txt)
            if mm is None:
                tm = re.search(r'CBaseChainParams[^"]*"[^"]*",\s*(\d+)', txt)
                if tm is None:
                    return ParamStatus.UNRESOLVED, "nRPCPort not found in chainparamsbase.cpp"
                want = int(tm.group(1))
                where = f"{ev}:{txt[: tm.start()].count(chr(10)) + 1}"
            else:
                want = int(mm.group(1))
                where = f"{ev}:{txt[: mm.start()].count(chr(10)) + 1}"

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


# initializer-normalization cascade: one step per C++ form
def _block_inclusion_rate(src_dir: Path) -> tuple[int | None, str | None]:  # noqa: C901, PLR0912
    """DEFAULT_BLOCK_MIN_TX_FEE — the miner inclusion floor, when above relay.

    C++ initializer forms are normalized to a bare expression before
    evaluation: casts "(unsigned int) X" -> X, wrapped "(1000)" -> 1000,
    brace "{2000}" -> 2000, paren-init capture "2000)" -> 2000. Each step
    is guarded so it only fires on the exact shape (never silently eats a
    meaningful character).
    """
    block_patterns = [
        # NOTE: capture up to ';'/newline (not first ')') so C casts
        # like "(unsigned int) RECOMMENDED_MIN_TX_FEE" survive intact.
        r"DEFAULT_BLOCK_MIN_TX_FEE\s*[\{=\(]\s*([^;\n]+)",
    ]
    block_files = (
        "src/policy/policy.h",
        "src/validation.h",
        "src/main.h",
        "src/policy/fees.h",
        "src/wallet/wallet.h",
        "src/consensus/validation.h",
        "src/amount.h",
        "src/defaultValues.h",
        "divi/src/defaultValues.h",
    )
    for name in block_files:
        btxt = SourceReader.slurp_src(src_dir, name)
        if btxt is None:
            continue
        for pat in block_patterns:
            bm = re.search(pat, btxt)
            if bm is None:
                continue
            braw = bm.group(1).strip()
            if braw.endswith(";"):
                braw = braw[:-1].rstrip()
            if braw.startswith("(") and braw.endswith(")"):
                inner = braw[1:-1].strip()
                if inner and "(" not in inner and ")" not in inner:
                    braw = inner
            m_cast = re.match(r"^(\s*\([^)]*\)\s*)+", braw)
            if m_cast and braw[m_cast.end() :].strip():
                braw = braw[m_cast.end() :].strip()
            if braw.startswith("{") and braw.endswith("}"):
                braw = braw[1:-1].strip()
            if braw.endswith(")") and "(" not in braw:
                braw = braw[:-1].rstrip()
            if "SATOSHI" in braw:
                # Same convention as the relay path (SATOSHI=1 sat).
                braw = braw.replace("SATOSHI", "1")
                cand, ev = CppExpressionEvaluator.resolve_cexpr(
                    braw, btxt, f"{name}:{btxt[: bm.start()].count(chr(10)) + 1} (SATOSHI=1)", src_dir
                )
            else:
                cand, ev = CppExpressionEvaluator.resolve_cexpr(
                    braw, btxt, f"{name}:{btxt[: bm.start()].count(chr(10)) + 1}", src_dir
                )
            if cand is not None:
                return cand, ev
    return None, None


def _dust_relay_rate(src_dir: Path) -> tuple[int | None, str | None]:
    """DUST_RELAY_TX_FEE-family constants for the dust limit."""
    dust_patterns = [
        r"DUST_RELAY_TX_FEE\s*[\{=\(]\s*([^;\)\}\n]+)",
        r"DEFAULT_DUST_LIMIT\s*[\{=\(]\s*([^;\)\}\n]+)",
        r"DEFAULT_TX_RELAY_FEE_PER_KILOBYTE\s*[\{=\(]\s*([^;\)\}\n]+)",
    ]
    dust_files = (
        "src/policy/policy.h",
        "src/policy/fees.h",
        "src/validation.h",
        "src/main.h",
        "src/amount.h",
        "src/consensus/validation.h",
        "src/defaultValues.h",
        "divi/src/defaultValues.h",
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
                cand, ev = CppExpressionEvaluator.resolve_cexpr(
                    raw,
                    txt,
                    f"{name}:{txt[: m.start()].count(chr(10)) + 1}",
                    src_dir,
                )
                if cand is not None:
                    return cand, ev
                try:
                    mm = re.search(r"(\d+)", raw)
                    if mm:
                        return int(mm.group(1)), f"{name}:{txt[: m.start()].count(chr(10)) + 1}"
                except (ValueError, TypeError) as e:
                    logger.debug("dust marker %s not parseable: %s", name, e)
                    continue
    return None, None


class FeeMixin:
    """Relay-fee constant extraction and per-coin fee-behavior detection."""

    @classmethod
    def fee_constants(cls, src_dir: Path) -> tuple[int | None, str | None, int | None, str | None]:
        """Relay rate (max of relay and block-inclusion) plus dust relay fee.

        Miner block-inclusion minimum matters for split-policy chains
        (Dogecoin: DEFAULT_BLOCK_MIN_TX_FEE = RECOMMENDED 1M/kB vs relay
        100k/kB) — inclusion sits above relay, so relay-only fees relay but
        mine last, fatal for HTLC locktimes. rate = max(relay, inclusion);
        equal-rate coins see zero behavior change.
        """
        rate, rate_ev = cls._relay_rate_from_headers(src_dir)
        if rate is None:
            rate, rate_ev = cls._relay_rate_cpp_fallback(src_dir)
        block_rate, block_ev = _block_inclusion_rate(src_dir)
        if block_rate is not None and (rate is None or block_rate > rate):
            prior_ev = rate_ev if rate_ev is not None else "relay not located"
            rate = block_rate
            rate_ev = f"{block_ev} [max(relay {prior_ev}, block-inclusion)]"
        dust, dust_ev = _dust_relay_rate(src_dir)
        return rate, rate_ev, dust, dust_ev

    @classmethod
    # marker cascade: one branch per known source form
    def _relay_rate_from_headers(cls, src_dir: Path) -> tuple[int | None, str | None]:  # noqa: C901, PLR0912
        """DEFAULT_MIN_RELAY_TX_FEE-family constants from headers."""
        patterns = [
            r"DEFAULT_MIN_RELAY_TX_FEE(?:_PER_KB)?\s*[\{=\(]\s*([^;\)\}\n]+)",
            r"DEFAULT_LEGACY_MIN_RELAY_TX_FEE\s*[\{=\(]\s*([^;\)\}\n]+)",
            r"DEFAULT_DIP0001_MIN_RELAY_TX_FEE\s*[\{=\(]\s*([^;\)\}\n]+)",
            r"DEFAULT_TX_RELAY_FEE_PER_KILOBYTE\s*[\{=\(]\s*([^;\)\}\n]+)",
        ]
        files = (
            "src/policy/policy.h",
            "src/validation.h",
            "src/main.h",
            "src/policy/fees.h",
            "src/wallet/wallet.h",
            "src/consensus/validation.h",
            "src/defaultValues.h",
            "divi/src/defaultValues.h",
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
                                rate = (
                                    int(a.strip(), 16) if a.strip().lower().startswith("0x") else int(a.strip())
                                ) // int(b.strip())
                            else:
                                rate = eval_cnum(expr_sub)
                            rate_ev = f"{name}:{txt[: m.start()].count(chr(10)) + 1} (SATOSHI=1)"
                            break
                        except (ValueError, TypeError) as e:
                            # Not a plain SATOSHI=1 literal — fall through to the expression evaluator.
                            logger.debug("fee marker %s not a plain literal: %s", name, e)
                    cand, ev = CppExpressionEvaluator.resolve_cexpr(
                        raw_expr, txt, f"{name}:{txt[: m.start()].count(chr(10)) + 1}", src_dir
                    )
                    if cand is not None:
                        rate, rate_ev = cand, ev
                        break
            if rate is not None:
                break
        return rate, rate_ev

    @classmethod
    # literal parser: one branch per arithmetic shape
    def _relay_rate_cpp_fallback(cls, src_dir: Path) -> tuple[int | None, str | None]:  # noqa: C901, PLR0912
        """Old-stack literal relay: CFeeRate minRelayTxFee = CFeeRate(N) in .cpp."""
        for cpp in ("src/validation.cpp", "src/main.cpp", "src/init.cpp", "divi/src/main.cpp"):
            txt = SourceReader.slurp_src(src_dir, cpp)
            if txt is None:
                continue
            m = re.search(r"CFeeRate\s+minRelayTxFee\s*=\s*CFeeRate\s*\(\s*([^)]+)\)", txt)
            if m:
                expr = m.group(1).strip()
                coin_txt = (
                    SourceReader.slurp_src(src_dir, "src/consensus/amount.h")
                    or SourceReader.slurp_src(src_dir, "src/amount.h")
                    or SourceReader.slurp(src_dir / "src/amount.h")
                    or SourceReader.slurp(src_dir / "src/consensus/amount.h")
                )
                coin_val = 100000000
                if coin_txt is not None:
                    cv, _ = coin_value_from_amount_h(coin_txt, "src/amount.h", src_dir)
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
                                tot *= (
                                    int(a.strip(), 16) if a.strip().lower().startswith("0x") else int(a.strip())
                                ) // int(b.strip())
                            else:
                                tot *= int(p, 16) if p.lower().startswith("0x") else int(p)
                        rate = tot
                    elif "/" in expr_sub:
                        a, b = expr_sub.split("/", 1)
                        rate = (int(a.strip(), 16) if a.strip().lower().startswith("0x") else int(a.strip())) // int(
                            b.strip()
                        )
                    else:
                        rate = eval_cnum(expr_sub)
                    rate_ev = f"{cpp}:{txt[: m.start()].count(chr(10)) + 1} CFeeRate literal {expr}"
                except (ValueError, TypeError) as e:
                    logger.debug("CFeeRate literal %s not parseable: %s", expr, e)
                    continue
                else:
                    return rate, rate_ev
        return None, None

    @classmethod
    def fee_policy(cls, src_dir: Path) -> FeePolicy:
        """Detect the coin's fee behavior from source. No silent defaults:
        anything unparseable stays rounding='unknown' and fails the check."""
        notes: list[str] = []
        ev: list[str] = []

        rounding = cls._detect_rounding(src_dir, ev, notes)
        mempool = _detect_mempool(src_dir, ev)
        dust_model = _detect_dust(src_dir, ev, notes)
        dgp_live = _detect_fee_flags(src_dir, ev, notes)

        return FeePolicy(
            rounding=rounding.rounding,
            mempool=mempool,
            zero_guard=rounding.zero_guard,
            dust_model=dust_model,
            kb_step=rounding.kb_step,
            step_rate=rounding.step_rate,
            fixed_step_bytes=rounding.fixed_step_bytes,
            fixed_step_fee=rounding.fixed_step_fee,
            dgp_live=dgp_live,
            notes=tuple(notes),
            evidence=tuple(ev),
        )

    @classmethod
    # rounding-shape cascade: one branch per known GetFee shape
    def _detect_rounding(cls, src_dir: Path, ev: list[str], notes: list[str]) -> _RoundingFacts:  # noqa: C901, PLR0912
        """Detect the GetFee rounding shape and its step parameters.

        No silent defaults: anything unparseable stays rounding='unknown'
        (the caller turns that into a failed check). The zero-guard is the
        minimum-charge floor a zero-size fee would fall through.
        """
        rounding = "unknown"
        kb_step = 1000
        step_rate: int | None = None
        fixed_step_bytes: int | None = None
        fixed_step_fee: int | None = None
        zero_guard = "one_sat"

        getfee = cls._getfee_source(src_dir)
        if getfee is not None:
            body, getfee_rel = getfee
            if "ONE_KILO_BYTE" in body and "ceil" in body:
                rounding = "ceil_step"
                kb_step, step_rate = cls._ceil_step_params(src_dir, body)
                ev.append(f"{getfee_rel}:ceil_step kb_step={kb_step} step_rate={step_rate}")
            elif "GetMinFee(nBytes_)" in body or ("return GetMinFee" in body and "#if 0" in body):
                rounding = "fixed_steps"
                fixed_step_bytes, fixed_step_fee = cls._fixed_steps_params(src_dir, body)
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
            elif re.search(r"\w+\s*\*\s*nSize\s*/\s*1000", body) or re.search(r"nSize\s*\*\s*\w+\s*/\s*1000", body):
                # Renamed rate units (WAGE nZensPerK, PIVX upiv): same truncating shape.
                rounding = "floor"
                ev.append(f"{getfee_rel}:truncating size*rate/1000, renamed units (floor)")

        if getfee is not None and re.search(r"nFee\s*=\s*(?:nSatoshisPerK|nZensPerK)\s*;", getfee[0]):
            zero_guard = "full_rate"

        # Old-stack literal relay (no GetFee at all, e.g. COLX/UNO/WAGE main.cpp).
        if rounding == "unknown":
            main_txt, main_rel = _slurp_first(src_dir, "src/main.cpp")
            if (
                main_txt is not None
                and re.search(r"GetMinRelayFee|nMinRelayTxFee|minRelayTxFee", main_txt)
                and "CFeeRate::GetFee" not in (getfee[0] if getfee is not None else "")
            ):
                rounding = "literal_flat"
                zero_guard = "full_rate"
                ev.append(f"{main_rel}:flat literal relay, no per-kB GetFee")

        return _RoundingFacts(
            rounding=rounding,
            kb_step=kb_step,
            step_rate=step_rate,
            fixed_step_bytes=fixed_step_bytes,
            fixed_step_fee=fixed_step_fee,
            zero_guard=zero_guard,
        )

    @classmethod
    def _getfee_source(cls, src_dir: Path) -> tuple[str, str] | None:
        """The file that defines GetFee, with its name for evidence.

        Prefers the file that actually defines a GetFee body (e.g. BCH
        keeps GetFee in src/feerate.cpp while src/amount.cpp exists),
        and falls back to the first readable candidate.
        """
        getfee: tuple[str, str] | None = None
        for rel in ("src/policy/feerate.cpp", "src/feerate.cpp", "src/amount.cpp", "divi/src/FeeRate.cpp"):
            txt = SourceReader.slurp_src(src_dir, rel)
            if txt is None:
                continue
            if getfee is None:
                getfee = (txt, rel)
            if "GetFee" in txt and (
                "::GetFee" in txt or "CFeeRate::GetFee" in txt or "GetFeeCeiling" in txt or "GetMinFee" in txt
            ):
                return txt, rel
        return getfee

    @classmethod
    def _ceil_step_params(cls, src_dir: Path, body: str) -> tuple[int, int | None]:
        """ONE_KILO_BYTE step size plus the Verge flat pin.

        Verge's ctor ignores its args and pins nSatoshisPerK = 10 * CENT.
        """
        m_step = re.search(r"ONE_KILO_BYTE\s*=\s*(\d+)", body)
        kb_step = int(m_step.group(1)) if m_step else 1000
        step_rate: int | None = None
        m_flat = re.search(r"nSatoshisPerK\s*=\s*10\s*\*\s*CENT", body)
        if m_flat:
            cent = cls._const_from_amount_h(src_dir, "CENT")
            if cent is not None:
                step_rate = 10 * cent
        return kb_step, step_rate

    @classmethod
    def _fixed_steps_params(cls, src_dir: Path, body: str) -> tuple[int | None, int | None]:
        """Fixed-steps fee: the MIN_TX_FEE base over an nBytes/(N*1024) step."""
        mine_txt, _ = _slurp_first(src_dir, "src/policy/feerate.cpp", "src/amount.h")
        base = 100
        if mine_txt:
            m_min = re.search(r"MIN_TX_FEE\s*=\s*([^;\n]+)", mine_txt)
            if m_min:
                cand, _ = CppExpressionEvaluator.resolve_cexpr(m_min.group(1).strip(), mine_txt, "MIN_TX_FEE", src_dir)
                if cand is not None:
                    base = cand
        fixed_step_fee = base
        m_div = re.search(r"nBytes\s*/\s*\(\s*(\d+)\s*\*\s*1024\s*\)", body)
        fixed_step_bytes = (int(m_div.group(1)) * 1024) if m_div else 10240
        return fixed_step_bytes, fixed_step_fee

    @staticmethod
    def _const_from_amount_h(src_dir: Path, name: str) -> int | None:
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


def coin_value_from_amount_h(txt: str, rel: str, src_dir: Path) -> tuple[int | None, str | None]:
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
    ln = clean[: m.start()].count(chr(10)) + 1
    v, ev = CppExpressionEvaluator.resolve_cexpr(rhs, clean, f"{rel}:{ln}", src_dir)
    if v is None:
        return None, None
    return v, ev


class _TxtimeGuard(NamedTuple):
    """The serialization-guard facts read from transaction.h."""

    cond: bool
    is_dual_chain: bool
    op: str
    chain: str


def _txtime_guard(txt: str, *, serialized: bool, cond: bool) -> _TxtimeGuard:
    """The guard context around the nTime serialization line."""
    if not serialized:
        return _TxtimeGuard(cond=cond, is_dual_chain=False, op="==", chain="")
    slines = txt.splitlines()
    ln0 = next((i for i, line in enumerate(slines) if NTIME_SERIALIZED_OR_RW_RE.search(line)), None)
    if ln0 is None:
        return _TxtimeGuard(cond=cond, is_dual_chain=False, op="==", chain="")
    ctx = "\n".join(slines[max(0, ln0 - 3) : ln0 + 2])
    if re.search(r"\bif\s*\(|SER_[A-Z_]+|CHAIN|Transition|fOptional", ctx):
        cond = True
    if re.search(r"current_chain", ctx, re.I):
        m_guard = re.search(r"CURRENT_CHAIN\W*(==|!=)\s*[\"']([^\"']+)[\"']", ctx, re.I)
        if m_guard:
            return _TxtimeGuard(cond=cond, is_dual_chain=True, op=m_guard.group(1), chain=m_guard.group(2).lower())
    return _TxtimeGuard(cond=cond, is_dual_chain=False, op="==", chain="")


def _txtime_actual(
    txt: str,
    *,
    serialized: bool,
    member: re.Match[str] | None,
    chain_name: str | None,
    guard: _TxtimeGuard,
) -> tuple[bool, str]:
    """(nTime actually serialized, guard evidence text)."""
    actual = bool(member or serialized)
    if guard.is_dual_chain and chain_name:
        # Polarity-aware: serialized exactly when the chain guard holds.
        guard_holds = (chain_name == guard.chain) if guard.op == "==" else (chain_name != guard.chain)
        actual = guard_holds
        if guard_holds:
            return actual, f'CURRENT_CHAIN="{chain_name}" {guard.op} "{guard.chain}" → holds → nTime serialized'
        return actual, f'CURRENT_CHAIN="{chain_name}" {guard.op} "{guard.chain}" → nTime not serialized'
    if not serialized:
        return actual, ""
    g0 = next((i for i, line in enumerate(txt.splitlines()) if NTIME_SERIALIZED_OR_RW_RE.search(line)), None)
    if g0 is None:
        return actual, ""
    for gl in txt.splitlines()[max(0, g0 - 3) : g0 + 1]:
        gs = gl.strip()
        if gs.startswith("if ") or "SER_" in gs:
            return actual, gs[:120]
    return actual, ""


def _txtime_line(txt: str, member: re.Match[str] | None) -> int | None:
    """The 1-based line of the nTime serialization or member declaration."""
    g = next((i for i, line in enumerate(txt.splitlines()) if NTIME_SERIALIZED_OR_RW_RE.search(line)), None)
    if g is not None:
        return g + 1
    if member is not None:
        return txt[: member.start()].count("\n") + 1
    m_struct = re.search(r"(?:struct|class)\s+CTransaction\b", txt)
    if m_struct is not None:
        return txt[: m_struct.start()].count("\n") + 1
    return None


class TxWireMixin:
    """Tx wire-format facts: COIN base unit, TxVersion bounds, nTime serialization."""

    @classmethod
    def check_coin(cls, coin: ManifestCoin, src_dir: Path, xc: dict[str, str]) -> tuple[ParamStatus, str]:
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
            src_n, ev = coin_value_from_amount_h(txt, rel, src_dir)
            if src_n is None:
                return ParamStatus.UNRESOLVED, (f"COIN={conf_n} — source expression unresolvable ({rel})")
            if src_n != conf_n:
                return ParamStatus.WARN, (
                    f"COIN={conf_n} vs source {src_n} ({ev}) — CTxOut(amount*COIN) "
                    f"off by {conf_n / src_n:.1f}x, fund-loss risk"
                )
            return ParamStatus.PASS, f"COIN={conf_n} == source {src_n} ({ev})"
        return ParamStatus.UNRESOLVED, "layout differs — src/amount.h nor src/consensus/amount.h found"

    @classmethod
    def check_txversion(  # noqa: C901, PLR0911, PLR0912, PLR0915  # pattern-matcher: one branch per known source marker
        cls, coin: ManifestCoin, src_dir: Path, xc: dict[str, str]
    ) -> tuple[ParamStatus, str]:
        txt = SourceReader.slurp_src(src_dir, "src/primitives/transaction.h") or SourceReader.slurp(
            src_dir / "src/primitives/transaction.h"
        )
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
                    cur_enum_ev = f"{txh}:{txt[: m_val.start()].count(chr(10)) + 1} TxVersion::{m_enum.group(1)}={cur}"
                else:
                    cur = None
            else:
                cur = None
        else:
            cur = int(m_cur.group(1))
        extra_pre: list[int] = []
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
        extra: list[int] = []
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
        cur_ln = txt[: m_cur.start()].count(chr(10)) + 1 if m_cur else None
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
    def check_txtime(  # verdict table: one return per verdict kind
        cls, coin: ManifestCoin, src_dir: Path, xc: dict[str, str]
    ) -> tuple[ParamStatus, str]:
        raw = SourceReader.slurp_src(src_dir, "src/primitives/transaction.h") or SourceReader.slurp(
            src_dir / "src/primitives/transaction.h"
        )
        if raw is None:
            return ParamStatus.UNRESOLVED, "layout differs — src/primitives/transaction.h not found"

        txt = SourceReader.strip_comments(raw)
        cond = "SER_BTC_TX" in txt
        member = re.search(r"(?:const\s+)?(?:unsigned\s+|u?int\d*_t\s+)nTime\s*;", txt)
        serialized = NTIME_SERIALIZED_RE.search(txt) or re.search(r"READWRITE\([^)]*\bnTime\b", txt)
        conf_v = xc.get("TxWithTimeField", "false").lower() == "true"

        # Generic CURRENT_CHAIN gate detection (smart, no hard-coded tickers)
        chain_name = current_chain(src_dir)
        guard = _txtime_guard(txt, serialized=serialized is not None, cond=cond)
        actual, guard_text = _txtime_actual(
            txt, serialized=serialized is not None, member=member, chain_name=chain_name, guard=guard
        )
        cond = guard.cond

        suffix = f"; serialization guard: {guard_text}" if guard_text else ""
        rel = "src/primitives/transaction.h"
        ln = _txtime_line(txt, member)
        ev = f"{rel}:{ln}" if ln is not None else f"{rel} (no nTime member, CTransaction scope examined)"
        cite = f" ({ev})"
        if conf_v == actual:
            msg = (
                f"TxWithTimeField={str(conf_v).lower()} and nTime is{'' if actual else ' NOT'} serialized{cite}{suffix}"
            )
            return (ParamStatus.WARN if conf_v and cond else ParamStatus.MATCH), msg

        if cond:
            # For dual-chain gated case, already handled; cond remaining is
            # truly conditional but not chain-gated → WARN is correct
            return ParamStatus.WARN, (
                f"TxWithTimeField={str(conf_v).lower()} while nTime is conditionally serialized{cite}{suffix}"
            )
        return ParamStatus.FAIL, (
            f"TxWithTimeField={str(conf_v).lower()} while nTime IS unconditionally serialized - "
            f"tx wire-format mismatch{cite}{suffix}"
        )


def current_chain(src_dir: Path) -> str | None:
    """Chain name for the tree currently at ``src_dir`` (cached per HEAD).

    One folder per coin is switched between tags in place, so the
    cache is keyed by path AND HEAD: a tag switch invalidates the
    name read for the previous tag. Without a usable HEAD (non-git
    fixture, or git unavailable) nothing is cached — a wrong but
    cached chain name would corrupt prefix, port and tx-time rows
    for every later tag. A dirty tree bypasses the cache the same
    way: in-place edits keep HEAD but change the answer. A ``None``
    dirty probe (git error) means never cache, not clean.
    """
    head = _src_head(src_dir)
    if head is None:
        return _compute_current_chain(src_dir)
    if _src_dirty(src_dir) is not False:
        return _compute_current_chain(src_dir)
    cache_key = f"{src_dir}@{head}"
    hit, value = _chain_cached(cache_key)
    if hit:
        return value
    value = _compute_current_chain(src_dir)
    _chain_cache_put(cache_key, value)
    return value


# layout cascade: one branch per source layout
def _compute_current_chain(src_dir: Path) -> str | None:  # noqa: C901, PLR0912
    """Generic CURRENT_CHAIN detection without hard-coding tickers.

    Checks Makefile.am/autogen.sh/configure.ac NAME, fallback to chainparams
    spec keys. Returns lowercased chain name or None if not found.
    """
    # Primary: NAME in autogen.sh is the chain name
    for rel in ("autogen.sh", "src/Makefile.am", "Makefile.am", "configure.ac", "src/Makefile.in", "Makefile.in"):
        t = SourceReader.slurp_src(src_dir, rel) or SourceReader.slurp(src_dir / rel)
        if not t:
            continue
        # Simple NAME search - filter out BITCOIN_DAEMON_NAME etc by ignoring
        # matches where preceding char is '_' (manual check). This correctly
        # captures sed-escaped '\nNAME = lynx' where preceding char is 'n'.
        mn = None
        for m_cand in re.finditer(r"NAME\s*=\s*(\w+)", t):
            if m_cand.start() > 0 and t[m_cand.start() - 1] == "_":
                continue
            mn = m_cand
            break
        # Verify this is chain-related (gate Makefile.in only if CURRENT_CHAIN present)
        if mn and ("CURRENT_CHAIN" in t or rel == "autogen.sh"):
            return mn.group(1).lower()
        m = re.search(r"CURRENT_CHAIN\s*=?\s*\"?\$?\(NAME\)\"?", t)
        if m:
            mn2 = None
            for m_cand in re.finditer(r"NAME\s*=\s*(\w+)", t):
                if m_cand.start() > 0 and t[m_cand.start() - 1] == "_":
                    continue
                mn2 = m_cand
                break
            if mn2:
                return mn2.group(1).lower()
    # Fallback: inspect chainparams spec keys - generic frequency based
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
                        return lk
                return tied[0]
    return None


class ChainTimingMixin:
    """CURRENT_CHAIN detection and effective block-spacing resolution."""

    @classmethod
    def _effective_blocktime(
        cls,
        src_dir: Path,
        main_txt: str,
        start: int,
        end: int,
    ) -> tuple[float | None, int | None, str]:
        """Generic effective spacing: raw nPowTargetSpacing/nTargetSpacing plus
        fork-aware overrides without hard-coding tickers.

        Detected patterns (all generic, tag-scoped):
        - FIRO-like MTP halving: pow.cpp/block.cpp GetTargetBlocksSpacing
          returns nPowTargetSpacingMTP/2 after stage3StartTime
        - QTUM-like RBT: nReduceBlocktimeHeight + nRBTPowTargetSpacing
        - UNO-like KGW: BlocksTargetSpacing = 3*60 in pow.cpp after fork block
        - PoS: nTargetSpacing (nPosTargetSpacing) variant

        The raw scan runs first even when it finds nothing: do not
        early-return on a missing raw value — the PoS/RBT/MTP/KGW
        overrides below may still produce an effective value (e.g.
        chains that only have nPosTargetSpacing). Each override fires
        only when its marker is really present, and the first one wins;
        otherwise the raw value is the effective one.
        """
        raw = cls._raw_spacing(main_txt, start, end)

        found = cls._pos_spacing(main_txt, start, end, raw)
        if found is not None:
            return found
        found = cls._rbt_spacing(main_txt, start, end, raw)
        if found is not None:
            return found
        found = cls._mtp_spacing(src_dir, main_txt, start, end, raw)
        if found is not None:
            return found
        found = cls._kgw_spacing(src_dir, main_txt, start, end, raw)
        if found is not None:
            return found
        found = cls._height_gated_spacing(src_dir, main_txt, start, end, raw)
        if found is not None:
            return found

        # Default: raw is effective
        return raw.val, raw.ln, f"{raw.key}:{raw.ln} raw effective {raw.val}"

    @classmethod
    def _raw_spacing(cls, main_txt: str, start: int, end: int) -> _RawSpacing:
        """Raw candidates in mainnet block (generic, no hard-coding).

        A raw value that is an opaque identifier (multi-algo
        indirection, e.g. consensus.nPowTargetSpacingV2) resolves by
        searching the same slice for the referenced V-suffix definition
        — never by ticker.
        """
        # Raw candidates in mainnet block (generic, no hard-coding)
        for pat, key in (
            (r"nPowTargetSpacing\s*=\s*([^;\n]+)", "nPowTargetSpacing"),
            (r"nTargetSpacing\s*=\s*([^;\n]+)", "nTargetSpacing"),
            (r"nStakeTargetSpacing\s*=\s*([^;\n]+)", "nStakeTargetSpacing"),
            (r"nPosTargetSpacing\s*=\s*([^;\n]+)", "nPosTargetSpacing"),
        ):
            m, ln = regex_in_block(main_txt, start, end, pat)
            if m is None:
                continue
            raw_expr = m.group(1).strip()
            v = _safe_arith_float(raw_expr)
            if v is not None:
                return _RawSpacing(v, ln, key)
            # Generic multi-algo indirection: raw is identifier (e.g. consensus.nPowTargetSpacingV2)
            # Resolve by searching same slice for the referenced V-suffix definition (no ticker hard-code).
            m_ref = re.search(r"nPowTargetSpacingV\w*", raw_expr)
            if m_ref:
                var = m_ref.group(0)
                m_v, ln_v = regex_in_block(main_txt, start, end, rf"{re.escape(var)}\s*=\s*([^;\n]+)")
                if m_v is not None:
                    v2 = _safe_arith_float(m_v.group(1))
                    if v2 is not None:
                        return _RawSpacing(v2, ln_v, f"{key}->{var}")
            # Fallback: opaque identifier - only if nPowTargetSpacing in raw_expr
            elif "nPowTargetSpacing" in raw_expr:
                m_v2, ln_v2 = regex_in_block(main_txt, start, end, r"nPowTargetSpacingV\w*\s*=\s*([^;\n]+)")
                if m_v2 is not None:
                    v2 = _safe_arith_float(m_v2.group(1))
                    if v2 is not None:
                        return _RawSpacing(v2, ln_v2, f"{key}->V*")
        return _RawSpacing(None, None, "")

    @classmethod
    def _pos_spacing(
        cls, main_txt: str, start: int, end: int, raw: _RawSpacing
    ) -> tuple[float, int | None, str] | None:
        """PoS spacing: when nTargetSpacing (PoS) is faster than
        nPowTargetSpacing (PoW), the PoS value is the live cadence.

        Many hybrids define both; the PoS spacing is the live chain spacing.
        Only use when PoS is faster (smaller) than PoW to avoid misclassifying
        pure PoW chains like DGB where nTargetSpacing 60 > nPow 15.
        """
        # 1) PoS spacing: if nTargetSpacing exists and differs from
        #    nPowTargetSpacing, the smaller PoS value is the actual block cadence.
        m_pos, ln_pos = regex_in_block(main_txt, start, end, r"nTargetSpacing\s*=\s*([^;\n]+)")
        m_pow, _ = regex_in_block(main_txt, start, end, r"nPowTargetSpacing\s*=\s*([^;\n]+)")
        if m_pos is not None and m_pow is not None:
            v_pos = _safe_arith_float(m_pos.group(1))
            v_pow = _safe_arith_float(m_pow.group(1))
            if (
                v_pos is not None
                and v_pow is not None
                and v_pos != v_pow
                and v_pos < v_pow
                and re.search(r"nStakeMinConf|nTargetTimespan|nPosTargetSpacing", main_txt[start:end])
            ):
                return v_pos, ln_pos, f"{raw.key}:{raw.ln} PoS effective {v_pos} (raw PoW {v_pow})"
        # Also check nPosTargetSpacing as explicit PoS spacing
        m_ppos, ln_ppos = regex_in_block(main_txt, start, end, r"nPosTargetSpacing\s*=\s*([^;\n]+)")
        if m_ppos is not None:
            v_ppos = _safe_arith_float(m_ppos.group(1))
            # KGW/PoS override: chains with PowTargetSpacingV1/V2/V3 historical;
            # nPosTargetSpacing is live
            if v_ppos is not None and re.search(r"PowTargetSpacingV", main_txt[start:end]):
                return v_ppos, ln_ppos, f"nPosTargetSpacing:{ln_ppos} PoS effective {v_ppos}"
        return None

    @classmethod
    def _rbt_spacing(
        cls, main_txt: str, start: int, end: int, raw: _RawSpacing
    ) -> tuple[float, int | None, str] | None:
        """QTUM-like reduced blocktime: nReduceBlocktimeHeight + nRBTPowTargetSpacing."""
        # 2) QTUM-like reduced blocktime: nReduceBlocktimeHeight + nRBTPowTargetSpacing
        m_rbt, ln_rbt = regex_in_block(main_txt, start, end, r"nRBTPowTargetSpacing\s*=\s*([^;\n]+)")
        if m_rbt is not None:
            v_rbt = _safe_arith_float(m_rbt.group(1))
            # Generic: if Reduce height exists, use RBT value as effective
            # (tip is past reduce height for all our held tags >845k)
            if v_rbt is not None and re.search(r"nReduceBlocktimeHeight", main_txt[start:end]):
                return v_rbt, ln_rbt, f"nRBTPowTargetSpacing:{ln_rbt} effective {v_rbt} (raw {raw.val})"
        return None

    @classmethod
    def _mtp_spacing(
        cls, src_dir: Path, main_txt: str, start: int, end: int, raw: _RawSpacing
    ) -> tuple[float, int | None, str] | None:
        """FIRO-like MTP halving: GetTargetBlocksSpacing returns MTP/2 after stage3."""
        # 3) FIRO-like MTP halving: look for GetTargetBlocksSpacing returning MTP/2
        for rel in ("src/pow.cpp", "src/primitives/block.cpp", "src/consensus/params.cpp"):
            t = SourceReader.slurp_src(src_dir, rel) or SourceReader.slurp(src_dir / rel)
            if t and "GetTargetBlocksSpacing" in t and "nPowTargetSpacingMTP" in t:
                # Find MTP spacing
                for cand in (t, main_txt):
                    m_mtp, ln_mtp = regex_in_block(cand, 0, len(cand), r"nPowTargetSpacingMTP\s*=\s*([^;\n]+)")
                    if m_mtp:
                        v_mtp = _safe_arith_float(m_mtp.group(1))
                        if v_mtp is not None:
                            # Check for /2 halving pattern (stage3)
                            if (
                                "/2" in t[t.find("GetTargetBlocksSpacing") : t.find("GetTargetBlocksSpacing") + 500]
                                or "stage3StartTime" in t
                            ):
                                return (
                                    v_mtp / 2.0,
                                    ln_mtp,
                                    (f"nPowTargetSpacingMTP/2:{ln_mtp} effective {v_mtp / 2.0} (raw {raw.val})"),
                                )
                            return v_mtp, ln_mtp, f"nPowTargetSpacingMTP:{ln_mtp} effective {v_mtp}"
        return None

    @classmethod
    def _kgw_spacing(
        cls, src_dir: Path, main_txt: str, start: int, end: int, raw: _RawSpacing
    ) -> tuple[float, int | None, str] | None:
        """UNO-like KGW: pow.cpp BlocksTargetSpacing after the fork block."""
        # 4) UNO-like KGW: pow.cpp BlocksTargetSpacing = 3*60 after fork
        for rel in ("src/pow.cpp", "src/pow.h", "src/consensus/pow.cpp"):
            t = SourceReader.slurp_src(src_dir, rel) or SourceReader.slurp(src_dir / rel)
            if t and "BlocksTargetSpacing" in t:
                m_bts, ln_bts = regex_in_block(t, 0, len(t), r"BlocksTargetSpacing\s*=\s*([^;\n;]+)")
                if m_bts:
                    # Handle 3 * 60 expression
                    v_bts = _safe_arith_float(m_bts.group(1))
                    # Generic signal: KGW present and fork block passed
                    if (
                        v_bts is not None
                        and v_bts >= _KGW_MIN_SPACING
                        and ("KimotoGravityWell" in t or "PROOF_OF_WORK_FORK_BLOCK" in t)
                    ):
                        return v_bts, ln_bts, f"BlocksTargetSpacing:{ln_bts} KGW effective {v_bts} (raw {raw.val})"
        return None

    @classmethod
    def _height_gated_spacing(
        cls, src_dir: Path, main_txt: str, start: int, end: int, raw: _RawSpacing
    ) -> tuple[float, int | None, str] | None:
        """Generic height-gated TargetSpacing in any .cpp/.h.

        A ``TargetSpacing = <val>`` inside a height gate is a fork
        value: collect every gated assignment across the scanned files
        and pick the max-height one (assumes tip past fork).
        """
        # 5) Generic height-gated TargetSpacing: any .cpp/.h with `TargetSpacing = <val>` inside
        #    a height gate `height > 123456` or ternary `height < nReduce ? a : b`.
        #    Collect candidates (height, value, ref) within 15 lines before assignment,
        #    pick max-height as effective (assumes tip past fork).
        files_to_scan = cls._spacing_scan_files(src_dir, main_txt)
        candidates: list = []
        for file_txt, ref in files_to_scan:
            lines = file_txt.splitlines()
            for idx, line in enumerate(lines):
                for m_tg in re.finditer(r"TargetSpacing\s*=\s*([^;\n]+)", line):
                    val_expr = m_tg.group(1).strip().rstrip(";").strip()
                    ctx_before = "\n".join(lines[max(0, idx - 15) : idx + 1])
                    height_val = cls._spacing_gate_height(ctx_before, files_to_scan)
                    if height_val is None:
                        continue
                    v = cls._spacing_value(val_expr, files_to_scan)
                    if v is None:
                        continue
                    candidates.append((height_val, v, f"{ref}:{idx + 1}"))
        if candidates:
            candidates.sort(key=lambda x: x[0])
            best_h, best_v, best_ref = candidates[-1]
            return (
                best_v,
                None,
                (f"generic height-gated TargetSpacing:{best_ref} h={best_h} effective {best_v} (raw {raw.val})"),
            )
        return None

    @classmethod
    def _spacing_scan_files(cls, src_dir: Path, main_txt: str) -> list[tuple[str, str]]:
        """chainparams plus the fork-bearing sources, in a stable order."""
        # Build file list to scan (main_txt plus slurped sources)
        files_to_scan: list[tuple[str, str]] = [(main_txt, "chainparams.cpp:mainnet")]
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
            txt_cand = SourceReader.slurp_src(src_dir, rel) or SourceReader.slurp(src_dir / rel)
            if txt_cand:
                files_to_scan.append((txt_cand, rel))
        return files_to_scan

    @classmethod
    def _spacing_gate_height(cls, ctx_before: str, files_to_scan: list[tuple[str, str]]) -> int | None:
        """The fork height a spacing assignment is gated on, if any.

        Three shapes: a literal height comparison, a variable height
        resolved across the scanned files, or a ternary ``height < N ?``.
        None means no gate — an ungated assignment is not a fork value.
        """
        # literal height gate
        hm = re.search(
            r"(?:nHeight|height|nReduceBlocktimeHeight|stage3StartTime|PROOF_OF_WORK_FORK_BLOCK)"
            r"\s*(?:>|>=|<|<=|==)\s*(\d+)",
            ctx_before,
            re.I,
        )
        if hm:
            try:
                return int(hm.group(1))
            except ValueError:
                pass
        # variable height e.g. `height < nReduceBlocktimeHeight` -> resolve var
        vm = re.search(r"(?:nHeight|height)\s*(?:>|>=|<|<=|==)\s*([A-Za-z_]\w*)", ctx_before, re.I)
        if vm:
            var_name = vm.group(1)
            for ft2, _ in files_to_scan:
                m_var, _ln = regex_in_block(ft2, 0, len(ft2), rf"{re.escape(var_name)}\s*=\s*(\d+)")
                if m_var:
                    try:
                        return int(m_var.group(1).strip())
                    except ValueError:
                        continue
        # ternary height < 123456 ? ... : ...
        tm = re.search(r"height\s*(?:<|>|<=|>=)\s*(\d+)\s*\?", ctx_before, re.I)
        if tm:
            with contextlib.suppress(ValueError):
                return int(tm.group(1))
        return None

    @classmethod
    def _spacing_value(cls, val_expr: str, files_to_scan: list[tuple[str, str]]) -> float | None:
        """The effective value of a spacing expression, ternaries included.

        A ternary's else-branch resolves as a literal, or as a variable
        across the scanned files.
        """
        v = _safe_arith_float(val_expr)
        if v is not None:
            return v
        if "?" in val_expr and ":" in val_expr:
            else_part = val_expr.rsplit(":", 1)[-1].strip()
            # strip trailing ) etc
            else_part = re.split(r"[;\)\s]+", else_part)[0]
            v_try = _safe_arith_float(else_part)
            if v_try is not None:
                return v_try
            # variable else part
            var_else = re.search(r"[A-Za-z_]\w*", else_part)
            if var_else:
                var_name2 = var_else.group(0)
                for ft2, _ in files_to_scan:
                    m2, _ = regex_in_block(ft2, 0, len(ft2), rf"{re.escape(var_name2)}\s*=\s*([^;\n]+)")
                    if m2:
                        v2 = _safe_arith_float(m2.group(1).strip())
                        if v2 is not None:
                            return v2
        return None

    @classmethod
    def check_blocktime(  # noqa: C901, PLR0911, PLR0912  # pattern-matcher: one branch per known source marker
        cls,
        coin: ManifestCoin,
        src_dir: Path,
        xc: dict[str, str],
        *,
        want_test: bool,
        repo_root: Path,
    ) -> tuple[ParamStatus, str]:
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
                s_tmp, e_tmp = mainnet_slice(cand, want_test=want_test)
                m_tmp, _ = regex_in_block(
                    cand,
                    s_tmp,
                    e_tmp,
                    r"(?:nPowTargetSpacing\w*|nTargetSpacing|nStakeTargetSpacing|nPosTargetSpacing|TargetSpacing)\s*=\s*([^;\n]+)",
                )
                if m_tmp is not None:
                    txt = cand
                    used_rel = rel
                    break

        if txt is None:
            return ParamStatus.UNRESOLVED, "layout differs — src/chainparams.cpp not found"

        start, end = mainnet_slice(txt, want_test=want_test)
        want, ln, ev = cls._effective_blocktime(src_dir, txt, start, end)
        if want is None:
            # Fallback to raw search for better UNRESOLVED message
            m, ln2 = regex_in_block(
                txt,
                start,
                end,
                r"(?:nPowTargetSpacing\w*|nTargetSpacing|nStakeTargetSpacing|nPosTargetSpacing|TargetSpacing)"
                r"\s*=\s*([^;\n]+)",
            )
            if m is not None:
                want2 = _safe_arith_float(m.group(1))
                if want2 is not None:
                    if abs(want2 - bt) < _FLOAT_TOLERANCE:
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
        if abs(want - bt) < _FLOAT_TOLERANCE:
            return ParamStatus.PASS, f"BlockTime={bt} == effective spacing {want:g} ({cite}, {ev})"

        since = SourceReader.lineage_date(repo_root, f"xbridge-confs/{coin.xbridge_conf}", "BlockTime")
        lin = f"; value present since {since}" if since else ""
        return ParamStatus.WARN, f"BlockTime={bt} vs effective spacing {want:g} ({cite}, {ev}){lin}"


# txindex source layouts, newest core first, then the legacy registrations.
_TXINDEX_HEADERS = (
    "src/index/txindex.h",
    "src/validation.h",
    "src/main.h",
    "src/kernel/chainparams.h",
    "src/txdb.h",
    "divi/src/txdb.h",
)
_TXINDEX_FALLBACKS = ("src/main.cpp", "src/txdb.cpp", "divi/src/txdb.cpp", "divi/src/BlockIndexLoading.cpp")
_TXINDEX_REGISTERED = ("src/init.cpp", "src/init/common/args.cpp", "src/main.cpp", "divi/src/BlockIndexLoading.cpp")
_TXINDEX_LEGACY_HELP = ("src/init.cpp", "src/main.cpp")


def _txindex_default(src_dir: Path) -> tuple[bool | None, str | None]:
    """(DEFAULT_TXINDEX default, evidence) from headers, then legacy forks.

    Generic ordered candidates - covers Bitcoin Core evolution:
    0.21+ -> src/index/txindex.h  constexpr {false/true}
    classic -> src/validation.h   = false
    legacy forks -> src/main.h    = false/true
    wrapper (divi) handled via slurp_src
    """
    for rel in _TXINDEX_HEADERS:
        txt = SourceReader.slurp_src(src_dir, rel) or SourceReader.slurp(src_dir / rel)
        if txt is None:
            continue
        m = re.search(r"DEFAULT_TXINDEX\s*(?:=\s*(true|false)|\{\s*(true|false)\s*\})", txt)
        if m:
            val = m.group(1) or m.group(2)
            return val == "true", f"{rel}:{txt[: m.start()].count(chr(10)) + 1}"
    # Fallback: legacy forks without DEFAULT_TXINDEX constant - detect via fTxIndex init or GetBoolArg default
    for rel in _TXINDEX_FALLBACKS:
        txt = SourceReader.slurp_src(src_dir, rel) or SourceReader.slurp(src_dir / rel)
        if txt is None:
            continue
        m = re.search(r"bool\s+fTxIndex\s*=\s*(true|false)", txt)
        if m:
            return m.group(1) == "true", f"{rel}:{txt[: m.start()].count(chr(10)) + 1} fTxIndex"
        m2 = re.search(r'GetBoolArg\s*\(\s*["\']-txindex["\']\s*,\s*(true|false)', txt)
        if m2:
            return m2.group(1) == "true", f"{rel}:{txt[: m2.start()].count(chr(10)) + 1} GetBoolArg-txindex"
    return None, None


def _txindex_registered(src_dir: Path) -> bool:
    """True when -txindex is registered upstream (modern or legacy help style)."""
    for rel in _TXINDEX_REGISTERED:
        t = SourceReader.slurp_src(src_dir, rel) or SourceReader.slurp(src_dir / rel)
        if t and ('"-txindex"' in t or "'-txindex'" in t):
            return True
    for rel in _TXINDEX_LEGACY_HELP:
        t = SourceReader.slurp_src(src_dir, rel) or SourceReader.slurp(src_dir / rel)
        if t and "-txindex" in t:
            return True
    return False


def _txindex_absent_verdict(*, dflt: bool, ev: str | None) -> CheckerTuple:
    """The verdict when the conf carries no txindex line at all."""
    if dflt is False:
        return (
            ParamStatus.WARN,
            (f"txindex missing from conf while DEFAULT_TXINDEX=false ({ev})"),
            "txindex",
        )
    if dflt:
        return ParamStatus.INFO, f"txindex relies on upstream default=true ({ev})"
    return ParamStatus.UNRESOLVED, f"txindex state indeterminate (DEFAULT_TXINDEX={dflt!r} {ev})"


class WalletFlagMixin:
    """Wallet conf flag support: txindex, addresstype/changetype, deprecatedrpc."""

    @classmethod
    def check_txindex(  # verdict table: one return per verdict kind
        cls,
        coin: ManifestCoin,
        src_dir: Path,
        wc: dict[str, str],
    ) -> CheckerTuple:
        dflt, ev = _txindex_default(src_dir)
        if dflt is None:
            return ParamStatus.UNRESOLVED, "DEFAULT_TXINDEX not located"
        if not _txindex_registered(src_dir):
            return ParamStatus.UNRESOLVED, "-txindex option not registered upstream"
        has_line = "txindex" in {k.split(".")[0].lower() for k in wc}
        if not has_line:
            return _txindex_absent_verdict(dflt=dflt, ev=ev)
        try:
            got = int(str(conf_val_ci(wc, "txindex")).strip())
        except ValueError:
            return ParamStatus.FAIL, f"txindex={conf_val_ci(wc, 'txindex')!r} non-numeric ({ev})"
        if got == 1:
            return ParamStatus.PASS, f"txindex=1 explicitly enabled ({ev})"
        return ParamStatus.WARN, f"txindex={got} explicitly disabled while XBridge needs index ({ev})"

    @classmethod
    def check_addrtype(cls, coin: ManifestCoin, src_dir: Path, wc: dict[str, str]) -> tuple[ParamStatus, str]:
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
                    ln = t[: t.find(flag)].count("\n") + 1
                    return ParamStatus.PASS, f"addresstype/changetype supported upstream ({rel}:{ln} {flag})"
        searched = "src/init.cpp, src/wallet/init.cpp, src/wallet/wallet.h"
        return ParamStatus.INFO, (
            f"addresstype/changetype lines are silently absorbed (option not registered) ({searched})"
        )

    @classmethod
    def check_deprecatedrpc(  # noqa: C901, PLR0912  # pattern-matcher: one branch per known source marker
        cls,
        coin: ManifestCoin,
        src_dir: Path,
        wc: dict[str, str],
        repo_root: Path,
    ) -> CheckerTuple:
        raw = conf_val_ci(wc, "deprecatedrpc").strip()
        if raw.lower() == "true":
            raw = "signrawtransaction"
        if not raw:
            return ParamStatus.INFO, "deprecatedrpc not set"

        values = [v.strip() for v in raw.split(",") if v.strip()]
        if not values:
            return ParamStatus.INFO, "deprecatedrpc not set"

        details: list[str] = []
        worst = ParamStatus.INFO
        stale_seen = False
        files_to_check = (
            "src/rpc/server.cpp",
            "src/init.cpp",
            "src/core_write.cpp",
            "src/rpc/blockchain.cpp",
            "src/rpc/rawtransaction.cpp",
            "src/wallet/rpcwallet.cpp",
            "src/rpc/misc.cpp",
        )

        for val in values:
            gate_found = False
            gate_ev = ""
            for rel in files_to_check:
                txt = SourceReader.slurp_src(src_dir, rel) or SourceReader.slurp(src_dir / rel)
                if txt is None:
                    continue
                if f'IsDeprecatedRPCEnabled("{val}")' in txt or f"IsDeprecatedRPCEnabled('{val}')" in txt:
                    ln = txt[: txt.find(val)].count("\n") + 1
                    gate_found = True
                    gate_ev = f'{rel}:{ln} IsDeprecatedRPCEnabled("{val}")'
                    break
                if "IsDeprecatedRPCEnabled" in txt and val in txt:
                    for m in re.finditer(r"IsDeprecatedRPCEnabled\s*\(\s*[\"']" + re.escape(val) + r"[\"']\s*\)", txt):
                        gate_found = True
                        gate_ev = f'{rel}:{txt[: m.start()].count(chr(10)) + 1} IsDeprecatedRPCEnabled("{val}")'
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
                    method_ev = f'{rel}:{txt[:ln].count(chr(10)) + 1} contains "{val}"'

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
                details.append(
                    f'{val} no IsDeprecatedRPCEnabled("{val}") gate and RPC "{val}" not registered at tag '
                    f"{coin.ver_id} — stale, flag does nothing{lin}"
                )
                worst = max_status(worst, ParamStatus.WARN)
                stale_seen = True

        if stale_seen:
            return worst, "; ".join(details), "deprecatedrpc"
        return worst, "; ".join(details)


def _detect_mempool(src_dir: Path, ev: list[str]) -> str:
    """Mempool fee dynamics from txmempool.cpp ('unknown' never returns)."""

    def slurp(*rels: str) -> tuple[str | None, str | None]:
        for rel in rels:
            txt = SourceReader.slurp_src(src_dir, rel)
            if txt is not None:
                return txt, rel
        return None, None

    mempool = "unknown"
    pool_txt, pool_rel = slurp("src/txmempool.cpp")
    if pool_txt is None:
        ev.append("no txmempool.cpp: pre-mempool stack (flat relay)")
        return "none"
    m = re.search(
        r"CFeeRate\s+CTxMemPool::GetMinFee\s*\([^)]*\)\s*const\s*\{(.*?)\n\}",
        pool_txt,
        re.S,
    )
    body = m.group(1) if m else pool_txt
    if "GetMinFee" not in pool_txt:
        mempool = "none"
    elif "rollingMinimumFeeRate" in body:
        mempool = "dynamic"
    elif re.search(r"return\s+CFeeRate\s*\(", body):
        mempool = "flat"
    ev.append(f"{pool_rel}:mempool {mempool}")
    return mempool


def _detect_dust(src_dir: Path, ev: list[str], notes: list[str]) -> str:
    """Dust model from transaction.h + policy.cpp (exemptions and factors)."""

    def slurp(*rels: str) -> tuple[str | None, str | None]:
        for rel in rels:
            txt = SourceReader.slurp_src(src_dir, rel)
            if txt is not None:
                return txt, rel
        return None, None

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
    return dust_model


def _detect_fee_flags(src_dir: Path, ev: list[str], notes: list[str]) -> bool:
    """DGP liveness plus per-marker fee notes (all transparent-swap-safe)."""
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
        for rel in (
            "src/policy/policy.cpp",
            "src/validation.cpp",
            "src/anon.h",
            "src/chainparams.cpp",
            "src/namecoin.cpp",
            "src/spark/state.cpp",
            "src/validation.h",
            "src/consensus/params.h",
        ):
            t = SourceReader.slurp_src(src_dir, rel)
            if t is not None and marker in t:
                found = True
                break
        if found:
            notes.append(note)
    if dgp_live:
        notes.append("dgp-live")
    return dgp_live


@dataclass
class _RawSpacing:
    """The raw spacing scan's result: value, evidence line, conf key."""

    val: float | None
    ln: int | None
    key: str


def _slurp_first(src_dir: Path, *rels: str) -> tuple[str | None, str | None]:
    """The first readable candidate among ``rels``, with its name."""
    for rel in rels:
        txt = SourceReader.slurp_src(src_dir, rel)
        if txt is not None:
            return txt, rel
    return None, None


@dataclass
class _RoundingFacts:
    """GetFee-shape detection results (see FeeMixin.fee_policy)."""

    rounding: str
    kb_step: int
    step_rate: int | None
    fixed_step_bytes: int | None
    fixed_step_fee: int | None
    zero_guard: str


class CppSourceInspector(
    PrefixMixin,
    PortMixin,
    FeeMixin,
    TxWireMixin,
    ChainTimingMixin,
    WalletFlagMixin,
):
    """Fact-checks configuration values against Bitcoin-derivative C++ codebases.

    Composed facade: every method arrives from exactly one mixin above, so the
    historical API (``CppSourceInspector.check_port(...)`` etc.) is unchanged.
    The shared scanners (``mainnet_slice``, ``regex_in_block``,
    ``coin_value_from_amount_h``, ``current_chain``) are module-level
    functions above the mixins.
    """
