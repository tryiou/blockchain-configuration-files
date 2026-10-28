"""The DustAmount contract: one source-derived floor per coin, computed once.

``DustAmount`` is the only definition of a coin's dust threshold. It is
expressed in the coin's own native base units and is the effective P2PKH
threshold: the value at which the daemon's own dust gate starts refusing an
output. P2PKH (34-byte output + 148-byte input = 182 bytes) is the
conservative choice, because every XBridge change output is P2PKH and the
P2PKH gate is never smaller than the P2SH gate on the same coin.

The checker (``CommonParamCheckers.check_dust``) and the writer
(``ConfigAutoFixer.plan_configure_dust``) both call :func:`expectation`, so a
conf can never be validated against one rule and written from another. When
the constants cannot be located the result is ``None`` and the caller refuses
to invent a number.
"""

from __future__ import annotations

import re
from enum import Enum
from pathlib import Path
from typing import NamedTuple

from ..checkout import SourceReader
from ..model import FeePolicy, chain_floor
from .base import CppExpressionEvaluator, line_of

# Spend sizes the dust gate is evaluated at: a P2PKH output plus the input
# that spends it, and its segwit analogue (75% witness discount on the input).
DUST_P2PKH_SIZE = 182
DUST_P2WPKH_SIZE = 98

# The files that may apply the legacy 3x dust multiplier, and the markers
# that prove it. A coin that trips any marker gates at 3x the plain rate.
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

# Rounding models whose dust gate is the chain's exact GetFee() of the size.
_FLAT_ROUNDINGS = ("floor", "ceil", "go_floor", "literal_flat")

# A coin whose IsDust takes a flat amount instead of a fee rate (Dogecoin's
# `bool IsDust(const CAmount dustLimit)` compares `nValue < dustLimit`). The
# gate is then the limit itself, not a per-byte derivation of it.
_STATIC_DUST_RE = re.compile(r"bool\s+IsDust\s*\(\s*(?:const\s+)?CAmount")

# A consensus minimum output amount enforced on every non-empty output
# (Emercoin's `CheckMinTxOut`: `!txout.IsEmpty() && txout.nValue < MIN_TXOUT_AMOUNT`).
_MIN_TXOUT_RE = re.compile(r"\bMIN_TXOUT_AMOUNT\b")


class DustKind(str, Enum):
    """Which gate produced the expected value — reported, never inferred."""

    P2PKH = "p2pkh"
    STATIC = "static"
    MIN_TXOUT = "min_txout"
    DISABLED = "disabled"


class DustExpectation(NamedTuple):
    """The floor a conf must carry, plus the evidence for it."""

    value: int
    evidence: str
    kind: DustKind


def dust_factor(src_dir: Path) -> int:
    """3 when a source file applies the legacy 3x dust multiplier, else 1."""
    for rel in _DUST_FACTOR_SOURCES:
        txt = SourceReader.read_src(src_dir, rel)
        if txt and any(marker in txt for marker in _DUST_FACTOR_MARKERS):
            return 3
    return 1


def has_segwit(src_dir: Path) -> bool:
    """True when policy.cpp proves a witness-aware IsDust."""
    txt = SourceReader.read_src(src_dir, "src/policy/policy.cpp")
    return bool(txt and "WITNESS_SCALE_FACTOR" in txt and "IsWitnessProgram" in txt)


def dust_at_size(rate: int, size: int, factor: int, policy: FeePolicy | None) -> int:
    """The dust gate at one output size, per the coin's own rounding model."""
    if policy is not None and policy.rounding == "ceil_step":
        # ceil_step single-arg rates apply as given (the flat step_rate only
        # comes from the neutralized 2-arg CFeeRate ctor).
        return rate * ((size + policy.kb_step - 1) // policy.kb_step) * factor
    if policy is not None and policy.rounding in _FLAT_ROUNDINGS:
        return chain_floor(policy, rate, size) * factor
    return rate * size // 1000 * factor


def is_static_dust_limit(src_dir: Path) -> bool:
    """True when the coin's IsDust takes a flat amount rather than a fee rate."""
    txt = SourceReader.read_src(src_dir, "src/primitives/transaction.h")
    return bool(txt and _STATIC_DUST_RE.search(txt))


def _p2pkh_expectation(
    src_dir: Path,
    rate: int,
    rate_ev: str | None,
    factor: int,
    policy: FeePolicy | None,
) -> DustExpectation:
    """The per-size dust gate, with the segwit analogue cited as context."""
    value = dust_at_size(rate, DUST_P2PKH_SIZE, factor, policy)
    evidence = f"{rate_ev} (dustRelayFee={rate} sat/kB) -> P2PKH {value} sat"
    if has_segwit(src_dir):
        evidence += f", P2WPKH {dust_at_size(rate, DUST_P2WPKH_SIZE, factor, policy)} sat"
    return DustExpectation(value, evidence, DustKind.P2PKH)


def _min_txout_floor(src_dir: Path) -> DustExpectation | None:
    """The consensus minimum output amount, when the coin enforces one.

    Emercoin rejects any non-empty output below ``MIN_TXOUT_AMOUNT`` in
    mempool admission and block validation, and has no ``IsDust`` at all — so
    the constant *is* the floor. Any coin that enforces it must never be given
    a smaller value: the daemon would reject the output outright.
    """
    enforcement = SourceReader.read_src(src_dir, "src/validation.cpp")
    if enforcement is None or not _MIN_TXOUT_RE.search(enforcement):
        return None
    amount_h = SourceReader.read_src(src_dir, "src/amount.h")
    if amount_h is None:
        return None
    match = re.search(r"\bMIN_TXOUT_AMOUNT\s*=\s*([^;]+);", amount_h)
    if match is None:
        return None
    # The definition is symbolic on this fleet (MIN_TXOUT_AMOUNT = MIN_TX_FEE),
    # so resolve it through the same C++ expression evaluator every other
    # constant uses — including digit separators and one-level hops.
    value, _ev = CppExpressionEvaluator.resolve_cexpr(
        match.group(1),
        amount_h,
        f"src/amount.h:{line_of(amount_h, match)}",
        src_dir,
    )
    if value is None or value <= 0:
        return None
    return DustExpectation(
        value,
        f"src/amount.h MIN_TXOUT_AMOUNT={value}, enforced on every output in src/validation.cpp (no IsDust gate)",
        DustKind.MIN_TXOUT,
    )


def expectation(  # noqa: PLR0913  # the extracted constants ARE the input: one parameter per inspector output
    *,
    src_dir: Path,
    rate: int | None,
    rate_ev: str | None,
    dust: int | None,
    dust_ev: str | None,
    policy: FeePolicy | None,
) -> DustExpectation | None:
    """The floor this coin's conf must carry, or None when unprovable.

    Precedence is the daemon's own: a dedicated dust-relay constant wins over
    the relay rate, a flat-amount gate is its own value, and any consensus
    minimum output amount floors all of it. A source that disables dust has no
    dust *fee* gate, which only means the conf may carry ``0`` when the daemon
    has no consensus floor either — the floor is resolved first, so a coin that
    drops ``IsDust`` but still rejects small outputs keeps a non-zero value.
    """
    disabled = policy if policy is not None and policy.dust_model == "disabled" else None

    base: DustExpectation | None = None
    if disabled is not None:
        base = None
    elif dust is not None:
        if is_static_dust_limit(src_dir):
            # The coin's IsDust takes an amount, so the constant is the gate
            # verbatim. Dogecoin is the fleet's case: DEFAULT_DUST_LIMIT
            # (=RECOMMENDED_MIN_TX_FEE) is the *soft* limit that both charges a
            # dust fee per small output and equals the wallet's change-discard
            # threshold, while the separate hard limit (a tenth of it) is what
            # the mempool rejects outright. The soft limit is the correct value
            # for a change output: below it the transaction owes an extra dust
            # fee the engines do not budget for.
            base = DustExpectation(
                dust,
                f"{dust_ev} -> static dustLimit {dust} sat (IsDust: value < limit)",
                DustKind.STATIC,
            )
        else:
            base = _p2pkh_expectation(src_dir, dust, dust_ev, dust_factor(src_dir), policy)
    elif rate is not None:
        base = _p2pkh_expectation(src_dir, rate, rate_ev, dust_factor(src_dir), policy)

    floor = _min_txout_floor(src_dir)
    if floor is None:
        if disabled is not None:
            return DustExpectation(
                0,
                f"source disables dust (IsDust always false) ({'; '.join(disabled.evidence)})",
                DustKind.DISABLED,
            )
        return base
    if base is None or floor.value >= base.value:
        return floor
    return base
