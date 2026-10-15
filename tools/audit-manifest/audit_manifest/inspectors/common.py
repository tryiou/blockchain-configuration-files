"""CommonParamCheckers: family-agnostic checks shared by every coin lineage.

Fee/dust gates, cross-file consistency (xbridge Port vs wallet rpcport),
confirmations drift cap, connector dispatch, and conf conventions. These run
for both the C++ and btcd trees — they never parse chain source layout
themselves; they consume what the inspectors extracted.
"""

from __future__ import annotations

import re
from pathlib import Path

from ..checkout import SourceReader
from ..constants import (
    CREATE_TX_METHODS,
    FEE_SWEEP_SIZES,
    XLOCKTIME_DRIFT_SECONDS,
    XMAX_LOCKTIME_DRIFT_BLOCKS,
)
from ..model import CheckerTuple, FeePolicy, ManifestCoin, ParamStatus, chain_floor, max_status, recommended_fees

# Dust-gate inputs: the files that may apply the 3x dust multiplier, the
# markers that prove it, and the rounding models with a flat per-size gate.
_DUST_FACTOR_SOURCES = (
    "src/policy/policy.cpp",
    "src/primitives/transaction.h",
    "divi/src/FeeAndPriorityCalculator.cpp",
    "src/validation.cpp",
)
_DUST_FACTOR_MARKERS = (
    "3 * dustRelayFee",
    "3*dustRelayFee",
    "3 * minimumRelay",
    "3*minimumRelay",
    "3 * minRelayTxFee",
    "3*minRelayTxFee",
)
_FLAT_DUST_ROUNDINGS = ("floor", "ceil", "go_floor", "literal_flat")


class CommonParamCheckers:
    """Verifies XBridge-specific constraints and fee policies across all coin families."""

    @staticmethod
    def _conf_key_line(repo_root: Path, conf_file: str, key: str) -> str:
        txt = SourceReader.slurp(repo_root / conf_file)
        if txt is None:
            return f"{conf_file}:{key}"
        for i, line in enumerate(txt.splitlines(), 1):
            s = line.strip()
            if not s or s.startswith("#") or s.startswith("["):
                continue
            if re.match(rf"^{re.escape(key)}\s*=", s, flags=re.I):
                return f"{conf_file}:{i}"
        return f"{conf_file}:{key}"

    @staticmethod
    def check_rpcport_xbridge(
        coin: ManifestCoin,
        wc: dict[str, str],
        xc: dict[str, str],
        repo_root: Path,
    ) -> tuple[ParamStatus, str]:
        wref = CommonParamCheckers._conf_key_line(repo_root, f"wallet-confs/{coin.wallet_conf}", "rpcport")
        xref = CommonParamCheckers._conf_key_line(repo_root, f"xbridge-confs/{coin.xbridge_conf}", "Port")
        try:
            wrpc = int(wc.get("rpcport", ""))
        except ValueError:
            return ParamStatus.UNRESOLVED, f"wallet conf has no rpcport= line ({wref})"
        try:
            xport = int(xc.get("Port", ""))
        except ValueError:
            return ParamStatus.BROKEN, (
                f"xbridge Port={xc.get('Port')!r} non-numeric vs wallet rpcport={wrpc} ({wref} vs {xref})"
            )
        if wrpc == xport:
            return ParamStatus.MATCH, (
                f"xbridge Port={wrpc} == wallet rpcport ({wref} vs {xref}) (internally consistent)"
            )
        return ParamStatus.BROKEN, (
            f"xbridge Port={xport} != wallet rpcport={wrpc} ({wref} vs {xref}) - our own files disagree"
        )

    # pattern-matcher: one branch per known source marker
    @staticmethod
    def check_fees(  # noqa: C901, PLR0911, PLR0912, PLR0913, PLR0917
        coin: ManifestCoin,
        src_dir: Path,
        xc: dict[str, str],
        rate: int | None,
        rate_ev: str | None,
        dust: int | None,
        dust_ev: str | None,
        policy: FeePolicy | None = None,
    ) -> CheckerTuple:
        try:
            fpb = int(xc.get("FeePerByte", ""))
            mtf = int(xc.get("MinTxFee", ""))
        except ValueError:
            return ParamStatus.FAIL, "FeePerByte/MinTxFee non-numeric"
        if fpb < 0 or mtf < 0:
            return ParamStatus.FAIL, "negative fee values"
        if policy is None:
            return ParamStatus.UNRESOLVED, "fee source unavailable (no checkout resolved)"
        if policy.rounding == "unknown":
            return ParamStatus.FAIL, (
                f"fee extraction failed for {coin.ticker}: GetFee rounding not "
                f"parseable from source ({'; '.join(policy.evidence)})"
            )
        if rate is None or rate == 0:
            return ParamStatus.FAIL, (
                f"fee extraction failed for {coin.ticker}: relay/inclusion rate not resolved ({rate_ev})"
            )
        if policy.rounding == "ceil_step" and policy.step_rate is None:
            return ParamStatus.FAIL, (
                f"fee extraction failed for {coin.ticker}: ceil_step without "
                f"resolved step rate ({'; '.join(policy.evidence)})"
            )
        if policy.rounding == "fixed_steps" and (policy.fixed_step_bytes is None or policy.fixed_step_fee is None):
            return ParamStatus.FAIL, (
                f"fee extraction failed for {coin.ticker}: fixed_steps without "
                f"resolved step params ({'; '.join(policy.evidence)})"
            )

        rec_min, rec_fee = recommended_fees(policy, rate)
        # Sweep ANY n: refund-leg 226 + 260/452 historic + 192n+102 for n=1..520
        # plus ceil-step boundaries so per-kB ceilings cannot hide between points.
        worst: tuple[float, int, int, int] | None = None
        worst_floor = 1
        worst_fee = 0
        for size in FEE_SWEEP_SIZES:
            fee = max(size * fpb, mtf)
            floor = chain_floor(policy, rate, size)
            margin = fee / floor if floor else float("inf")
            if worst is None or margin < worst[0]:
                worst = (margin, size, fee, floor)
                worst_floor = floor
                worst_fee = fee

        if worst is None:
            raise ValueError("fee sweep sizes produced no candidates")
        model = f"{policy.rounding}/{policy.mempool}"
        # integer decisions (no float epsilon)
        if worst_fee < worst_floor:
            return (
                ParamStatus.FAIL,
                (
                    f"FAIL fee below chain gate — got MinTxFee={mtf} FeePerByte={fpb} "
                    f"!= REQUIRED MinTxFee={rec_min} FeePerByte={rec_fee} "
                    f"({worst[0]:.2f}x <1.00x, worst {worst[1]}B, model {model}, "
                    f"rate {rate} sat/kB) ({rate_ev})"
                ),
                "fees",
            )
        if fpb != rec_fee or mtf != rec_min:
            return (
                ParamStatus.WARN,
                (
                    f"WARN overpay — got MinTxFee={mtf} FeePerByte={fpb} "
                    f"!= REQUIRED MinTxFee={rec_min} FeePerByte={rec_fee} "
                    f"({worst[0]:.2f}x, model {model}, rate {rate} sat/kB) ({rate_ev})"
                ),
                "fees",
            )
        detail = (
            f"PASS MinTxFee={mtf} FeePerByte={fpb} == REQUIRED MinTxFee={rec_min} FeePerByte={rec_fee} "
            f"({worst[0]:.2f}x, model {model}, rate {rate} sat/kB) ({rate_ev})"
        )
        if policy.mempool == "dynamic":
            detail += " [note: dynamic mempool floor can exceed this during congestion]"
        if policy.dgp_live:
            detail += " [note: DGP live values override source default]"
        return ParamStatus.PASS, detail

    # pattern-matcher: one branch per known source marker
    @staticmethod
    def _dust_factor(src_dir: Path) -> int:
        """3 when a source file applies the 3x dust multiplier, else 1."""
        for cand in _DUST_FACTOR_SOURCES:
            t = SourceReader.slurp_src(src_dir, cand) or SourceReader.slurp(src_dir / cand)
            if t and any(k in t for k in _DUST_FACTOR_MARKERS):
                return 3
        return 1

    @staticmethod
    def _has_segwit(src_dir: Path) -> bool:
        """True when policy.cpp proves a witness-aware IsDust."""
        cand = "src/policy/policy.cpp"
        t = SourceReader.slurp_src(src_dir, cand) or SourceReader.slurp(src_dir / cand)
        return bool(t and "WITNESS_SCALE_FACTOR" in t and "IsWitnessProgram" in t)

    @staticmethod
    def _dust_at_size(dust: int, size: int, factor: int, policy: FeePolicy | None) -> int:
        """The dust gate at one output size, per the rounding model."""
        if policy is not None and policy.rounding == "ceil_step":
            # ceil_step single-arg rates apply as given (the flat
            # step_rate only comes from the neutralized 2-arg ctor).
            return dust * ((size + policy.kb_step - 1) // policy.kb_step) * factor
        if policy is not None and policy.rounding in _FLAT_DUST_ROUNDINGS:
            # Exact per-model dust gate at typical sizes (P2PKH 182 B).
            return chain_floor(policy, dust, size) * factor
        return dust * size // 1000 * factor

    @staticmethod
    def _dust_disabled_verdict(conf_val: int, policy: FeePolicy) -> CheckerTuple:
        """Verdict for a source that disables dust entirely (IsDust always false)."""
        if conf_val == 0:
            return ParamStatus.INFO, (
                "placeholder DustAmount=0 correct — source disables dust "
                f"(IsDust always false) ({'; '.join(policy.evidence)})"
            )
        return (
            ParamStatus.WARN,
            (f"DustAmount={conf_val} ignored by blocknet loader — source disables dust (IsDust always false)"),
            "dust",
        )

    @staticmethod
    def check_dust(  # noqa: PLR0913, PLR0917  # dispatcher: every hand-off is a named helper
        coin: ManifestCoin,
        src_dir: Path,
        xc: dict[str, str],
        rate: int | None,
        rate_ev: str | None,
        dust: int | None,
        dust_ev: str | None,
        policy: FeePolicy | None = None,
    ) -> CheckerTuple:
        raw = xc.get("DustAmount", "")
        try:
            conf_val = int(raw.strip()) if raw.strip() != "" else None
        except ValueError:
            return ParamStatus.FAIL, f"DustAmount={raw!r} non-numeric"
        if conf_val is None:
            return ParamStatus.UNRESOLVED, "DustAmount missing — expected placeholder 0"

        if policy is not None and policy.dust_model == "disabled":
            return CommonParamCheckers._dust_disabled_verdict(conf_val, policy)

        expected = None
        expected_ev = ""
        is_static_limit = False

        if dust is not None:
            ticker_up = coin.ticker.upper()
            if dust_ev and (
                "DEFAULT_DUST_LIMIT" in dust_ev or ("RECOMMENDED_MIN_TX_FEE" in dust_ev and ticker_up == "DOGE")
            ):
                expected = dust
                expected_ev = f"{dust_ev} -> static dustLimit {dust} sat (IsDust: value < limit)"
                is_static_limit = True
            else:
                factor = CommonParamCheckers._dust_factor(src_dir)
                p2pkh = CommonParamCheckers._dust_at_size(dust, 182, factor, policy)
                if CommonParamCheckers._has_segwit(src_dir):
                    p2wpkh = CommonParamCheckers._dust_at_size(dust, 98, factor, policy)
                    expected = p2pkh
                    expected_ev = f"{dust_ev} (dustRelayFee={dust} sat/kB) -> P2PKH {p2pkh} sat, P2WPKH {p2wpkh} sat"
                else:
                    expected = p2pkh
                    expected_ev = f"{dust_ev} (dustRelayFee={dust} sat/kB) -> P2PKH {p2pkh} sat"
        elif rate is not None:
            p2pkh = 3 * rate * 182 // 1000
            expected = p2pkh
            expected_ev = f"{rate_ev} (relayFee={rate} sat/kB) -> P2PKH {p2pkh} sat (legacy IsDust)"
        else:
            return ParamStatus.UNRESOLVED, "dust constants not located"

        if conf_val == 0:
            desc = f"upstream static dustLimit {expected} sat" if is_static_limit else f"expected P2PKH {expected} sat"
            return ParamStatus.INFO, (
                f"placeholder DustAmount=0 (expected — blocknet computes runtime dust) — {desc} ({expected_ev})"
            )
        return (
            ParamStatus.WARN,
            (f"DustAmount={conf_val} ignored by blocknet loader — expected P2PKH {expected} sat ({expected_ev})"),
            "dust",
        )

    @staticmethod
    def check_confirmations(coin: ManifestCoin, xc: dict[str, str]) -> tuple[ParamStatus, str]:
        xref = f"xbridge-confs/{coin.xbridge_conf}:Confirmations/BlockTime"
        try:
            cf = int(xc.get("Confirmations", ""))
            bt = int(xc.get("BlockTime", "1"))
        except ValueError:
            return ParamStatus.FAIL, f"Confirmations non-numeric ({xref})"
        if bt <= 0:
            return ParamStatus.UNRESOLVED, "BlockTime unusable — Confirmations cap unevaluable"
        cap = max(XLOCKTIME_DRIFT_SECONDS // bt, XMAX_LOCKTIME_DRIFT_BLOCKS)
        ev = (
            f"blocknet/src/xbridge/xbridgewallet.h:96-102 "
            f"XLOCKTIME_DRIFT_SECONDS={XLOCKTIME_DRIFT_SECONDS}/"
            f"XMAX_LOCKTIME_DRIFT_BLOCKS={XMAX_LOCKTIME_DRIFT_BLOCKS}; {xref} BlockTime={bt}"
        )
        if cf > cap:
            return ParamStatus.FAIL, f"Confirmations={cf} exceeds drift cap {cap} ({ev})"
        return ParamStatus.PASS, f"Confirmations={cf} <= cap {cap} ({ev})"

    @staticmethod
    def check_method(coin: ManifestCoin, xc: dict[str, str]) -> tuple[ParamStatus, str]:
        ev = (
            "blocknet/src/xbridge/xbridgeapp.cpp:1043-1090 dispatch (BTC/SYS→Btc, BCD/BCH/DGB/BTG/DEVAULT/STEALTH/PART)"
        )
        method = xc.get("CreateTxMethod", "")
        if method.upper() in ("ETH", "ETHER"):
            return ParamStatus.FAIL, f"CreateTxMethod={method} rejected by blocknet ({ev})"
        if method not in CREATE_TX_METHODS:
            return ParamStatus.FAIL, f"CreateTxMethod={method} unknown connector ({ev})"
        return ParamStatus.PASS, f"CreateTxMethod={method} ({ev})"

    @staticmethod
    def check_structure(coin: ManifestCoin, wc: dict[str, str], xc: dict[str, str]) -> tuple[ParamStatus, str]:
        msgs: list[str] = []
        status = ParamStatus.PASS
        if xc.get("Ip", "") != "127.0.0.1":
            status = max_status(status, ParamStatus.WARN)
            msgs.append(f"Ip={xc.get('Ip')!r}")
        allow = wc.get("rpcallowip") or (wc.get("_has_test_section") and wc.get("rpcallowip")) or ""
        if allow != "127.0.0.1":
            status = max_status(status, ParamStatus.FAIL)
            msgs.append(f"rpcallowip={allow!r} violates repo policy")
        vestigial = [k for k in ("CashAddrPrefix", "ContentType", "JSONVersion") if xc.get(k) == ""]
        if vestigial:
            status = max_status(status, ParamStatus.INFO)
            msgs.append(f"empty vestigial keys: {','.join(vestigial)}")
        if wc.get("rpcuser") or wc.get("rpcpassword"):
            status = max_status(status, ParamStatus.INFO)
            msgs.append("credentials shipped in committed conf")
        compat = "Title/Address/MinimumAmount/GetNewKeySupported/ImportWithNoScanSupported compat-only"
        scope = f"xbridge-confs/{coin.xbridge_conf} + wallet-confs/{coin.wallet_conf}"
        if not msgs:
            return status, f"conventions hold ({scope}; checked Ip/rpcallowip/creds; {compat})"
        return status, "; ".join(msgs) + f"; {compat} ({scope})"
