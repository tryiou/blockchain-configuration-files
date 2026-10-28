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
from ..util import conf_val_ci
from .dust import DustKind, expectation


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

    @staticmethod
    def _parse_dust_conf(xc: dict[str, str]) -> tuple[int | None, CheckerTuple | None]:
        """The conf's DustAmount, or the verdict explaining why it is unusable."""
        raw = conf_val_ci(xc, "DustAmount").strip()
        if raw == "":
            return None, (
                ParamStatus.FAIL,
                "DustAmount missing — every conf must declare the coin's dust threshold",
                "dust",
            )
        try:
            value = int(raw)
        except ValueError:
            return None, (ParamStatus.FAIL, f"DustAmount={raw!r} non-numeric", "dust")
        if value < 0:
            return None, (ParamStatus.FAIL, f"DustAmount={value} negative", "dust")
        return value, None

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
        """Verify the conf's DustAmount against the coin's own dust gate.

        DustAmount is the coin's effective threshold in native base units and
        is the only definition the engines use, so a conf that omits it, or
        carries anything other than the source-derived value, is a defect —
        not a placeholder. The expected value comes from the same
        ``dust.expectation`` the writer uses, so check and fix cannot disagree.
        """
        conf_val, refusal = CommonParamCheckers._parse_dust_conf(xc)
        if refusal is not None:
            return refusal

        expected = expectation(src_dir=src_dir, rate=rate, rate_ev=rate_ev, dust=dust, dust_ev=dust_ev, policy=policy)
        if expected is None:
            return ParamStatus.UNRESOLVED, "dust constants not located — refusing to guess a threshold"

        if conf_val == expected.value:
            return ParamStatus.PASS, (f"DustAmount={conf_val} == source effective threshold ({expected.evidence})")
        if expected.kind is DustKind.DISABLED:
            detail = f"DustAmount={conf_val} != 0 — source disables dust ({expected.evidence})"
        else:
            detail = f"DustAmount={conf_val} != source effective threshold {expected.value} ({expected.evidence})"
        return ParamStatus.WARN, detail, "dust"

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
