"""Domain data: status enums, severity maps, and manifest containers.

Every type here is inert — dataclasses and enums only, no I/O, no process
execution. Import order inside this package must never trigger side effects.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, NamedTuple

from .constants import FEE_REF_SIZE, FEE_SWEEP_SIZES


class RepoStatus(str, Enum):
    ALIVE = "ALIVE"
    MOVED = "MOVED"
    DEAD = "DEAD"
    UNKNOWN = "UNKNOWN"
    ERROR = "ERROR"


class ParamStatus(str, Enum):
    FAIL = "FAIL"
    BROKEN = "BROKEN"
    CONFLICT = "CONFLICT"
    DIFFERS = "DIFFERS"
    WARN = "WARN"
    UNRESOLVED = "UNRESOLVED"
    INFO = "INFO"
    SKIP = "SKIP"
    PASS = "PASS"  # noqa: S105  # ParamStatus member name, not a credential
    MATCH = "MATCH"


class ActionType(str, Enum):
    OK = "OK"
    UPGRADE = "UPGRADE"
    REVIEW = "REVIEW"
    UNKNOWN = "UNKNOWN"
    MOVED = "MOVED"
    DEAD = "DEAD"


# Precedence order for status bubbling and summary aggregation
PARAM_STATUS_PRECEDENCE = [
    ParamStatus.FAIL,
    ParamStatus.BROKEN,
    ParamStatus.CONFLICT,
    ParamStatus.DIFFERS,
    ParamStatus.WARN,
    ParamStatus.UNRESOLVED,
    ParamStatus.INFO,
    ParamStatus.SKIP,
    ParamStatus.PASS,
    ParamStatus.MATCH,
]

STATUS_MARKERS: dict[ParamStatus, str] = {
    ParamStatus.FAIL: "!!",
    ParamStatus.BROKEN: "!!",
    ParamStatus.CONFLICT: "!!",
    ParamStatus.DIFFERS: "~-",
    ParamStatus.WARN: "~ ",
    ParamStatus.INFO: "i ",
    ParamStatus.UNRESOLVED: "??",
    ParamStatus.SKIP: "--",
    ParamStatus.MATCH: "ok",
    ParamStatus.PASS: "ok",
}

ACTION_SEVERITY: dict[ActionType, int] = {
    ActionType.OK: 0,
    ActionType.REVIEW: 1,
    ActionType.UPGRADE: 2,
    ActionType.UNKNOWN: 3,
    ActionType.MOVED: 4,
    ActionType.DEAD: 5,
}


@dataclass
class FeePolicy:
    """Per-coin fee behavior extracted from chain source at the supported tag.

    rounding: floor (truncating rate*size/1000) | ceil (rounded up) |
        ceil_step (flat rate per kb_step bytes, e.g. Verge ONE_KILO_BYTE=999) |
        fixed_steps (rate ignored, stepped fixed fee, e.g. Emercoin GetMinFee) |
        literal_flat (old-stack literal relay, e.g. COLX 1*COIN) |
        go_floor (btcd calcMinRequiredTxRelayFee) | unknown (hard error, never PASS)
    mempool: dynamic (rolling minimum) | flat (constant GetMinFee) | none (no estimator)
    zero_guard: one_sat (truncated 0 -> 1) | full_rate (truncated 0 -> full rate) | none
    dust_model: standard | disabled | factor3 | exempt_classes (with exempt note)
    kb_step: bytes per rate step for ceil_step (999 Verge, else 1000)
    step_rate: flat rate per kb_step for ceil_step (10*CENT Verge), else None
    fixed_step_bytes / fixed_step_fee: for fixed_steps (Emercoin 10240 / MIN_TX_FEE)
    dgp_live: True when runtime values override source defaults (MRX) — audit pins
        the source default and says so in the note.
    notes: informational strings (gas layer, name fees, anon mult, SMSG, shields...)
    evidence: file:line citations backing every field above.
    """

    rounding: str = "unknown"
    mempool: str = "unknown"
    zero_guard: str = "one_sat"
    dust_model: str = "standard"
    kb_step: int = 1000
    step_rate: int | None = None
    fixed_step_bytes: int | None = None
    fixed_step_fee: int | None = None
    dgp_live: bool = False
    notes: tuple[str, ...] = ()
    evidence: tuple[str, ...] = ()


def _floor_round(policy: FeePolicy, rate: int, size: int) -> int:
    fl = rate * size // 1000
    if fl == 0 and size != 0 and rate > 0:
        fl = rate if policy.zero_guard == "full_rate" else 1
    return fl


def _floor_full_rate_round(_policy: FeePolicy, rate: int, size: int) -> int:
    """The go_floor and literal_flat shapes: truncating floor whose zero
    guard is always the full rate.

    Both source idioms emit the whole minRelayTxFee when the truncated
    product is zero (btcd calcMinRequiredTxRelayFee; old-stack literal
    relay), and their detectors always set zero_guard="full_rate"
    (inspectors/btcd.py, inspectors/cpp.py). The guard is intrinsic
    here rather than read from the policy: a policy assembled without
    it must not silently drop the floor to one satoshi.
    """
    fl = rate * size // 1000
    if fl == 0 and size != 0 and rate > 0:
        fl = rate
    return fl


def _ceil_round(_policy: FeePolicy, rate: int, size: int) -> int:
    fl = (rate * size + 999) // 1000
    if fl == 0 and size != 0 and rate > 0:
        fl = 1
    return fl


def _ceil_step_round(policy: FeePolicy, _rate: int, size: int) -> int:
    if policy.step_rate is None:
        raise ValueError("ceil_step policy without step_rate")
    n_steps = (size + policy.kb_step - 1) // policy.kb_step if size else 0
    fee = policy.step_rate * n_steps
    if fee == 0 and size != 0 and policy.step_rate > 0:
        fee = 1
    return fee


def _fixed_steps_round(policy: FeePolicy, _rate: int, size: int) -> int:
    if policy.fixed_step_bytes is None or policy.fixed_step_fee is None:
        raise ValueError("fixed_steps policy without step params")
    return (1 + size // policy.fixed_step_bytes) * policy.fixed_step_fee


# One exact handler per rounding model; go_floor and literal_flat share a
# handler because both are the same floor shape with an intrinsic full-rate
# zero guard. An unhandled model raises in chain_floor rather than
# defaulting: a wrong floor is a fund-loss risk.
_ROUNDERS: dict[str, Callable[[FeePolicy, int, int], int]] = {
    "floor": _floor_round,
    "go_floor": _floor_full_rate_round,
    "literal_flat": _floor_full_rate_round,
    "ceil": _ceil_round,
    "ceil_step": _ceil_step_round,
    "fixed_steps": _fixed_steps_round,
}


def chain_floor(policy: FeePolicy, rate: int, size: int) -> int:
    """Exact minimum fee (satoshis) the coin daemon requires for `size` bytes."""
    rounder = _ROUNDERS.get(policy.rounding)
    if rounder is None:
        raise ValueError(f"chain_floor: unhandled rounding {policy.rounding!r} (no silent default)")
    return rounder(policy, rate, size)


def strict_fees(policy: FeePolicy, rate: int) -> tuple[int, int]:
    """Exact (MinTxFee, FeePerByte): smallest values clearing the chain gate.

    MinTxFee = gate at the 452 B reference size. FeePerByte = smallest integer
    with size*fpb >= gate(size) for every sweep size the MinTxFee term does not
    already cover. Zero margin by design."""
    mtf = chain_floor(policy, rate, FEE_REF_SIZE)
    fpb = 1
    for size in FEE_SWEEP_SIZES:
        gate = chain_floor(policy, rate, size)
        if gate > mtf:
            need = (gate + size - 1) // size
            fpb = max(fpb, need)
    return int(mtf), int(fpb)


def recommended_fees(policy: FeePolicy, rate: int) -> tuple[int, int]:
    """Deterministic THE fees — strict-exact per-coin chain gates, safe for ANY
    n (1 to ~520 inputs, 100kB). Single source for check/fix/scaffold."""
    return strict_fees(policy, rate)


@dataclass
class ManifestCoin:
    """Represents a single coin definition from manifest-latest.json."""

    ticker: str
    ver_id: str
    blockchain: str = ""
    ver_name: str = ""
    conf_name: str = ""
    dir_name_linux: str = ""
    dir_name_mac: str = ""
    dir_name_win: str = ""
    repo_url: str = ""
    versions: list[str] = field(default_factory=list)
    wallet_conf: str = ""
    xbridge_conf: str = ""
    daemon_family: str = "btc"
    daemon_stem: str = ""

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ManifestCoin:
        return cls(
            ticker=data.get("ticker", ""),
            ver_id=data.get("ver_id", ""),
            blockchain=data.get("blockchain", ""),
            ver_name=data.get("ver_name", ""),
            conf_name=data.get("conf_name", ""),
            dir_name_linux=data.get("dir_name_linux", ""),
            dir_name_mac=data.get("dir_name_mac", ""),
            dir_name_win=data.get("dir_name_win", ""),
            repo_url=data.get("repo_url", ""),
            versions=list(data.get("versions", [])),
            wallet_conf=data.get("wallet_conf", ""),
            xbridge_conf=data.get("xbridge_conf", ""),
            daemon_family=data.get("daemon_family", "btc"),
            daemon_stem=data.get("daemon_stem", ""),
        )

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "blockchain": self.blockchain,
            "ticker": self.ticker,
            "ver_id": self.ver_id,
            "ver_name": self.ver_name,
            "conf_name": self.conf_name,
            "dir_name_linux": self.dir_name_linux,
            "dir_name_mac": self.dir_name_mac,
            "dir_name_win": self.dir_name_win,
            "repo_url": self.repo_url,
            "versions": self.versions,
            "wallet_conf": self.wallet_conf,
            "xbridge_conf": self.xbridge_conf,
            "daemon_family": self.daemon_family,
        }
        if self.daemon_stem:
            d["daemon_stem"] = self.daemon_stem
        return d

    @property
    def is_btcd(self) -> bool:
        return self.daemon_family.lower() == "btcd"

    def expected_tags(self) -> list[str]:
        """Declared versions are the only held tags (manifest field contract).

        The manifest field table in this repository's root ``README.md``
        defines ``ver_id`` as the unique identifier of this conf version
        group and ``versions`` as the array of wallet versions whose
        strings match the upstream git tags exactly — the sole contract
        for what this entry holds. The ver_id's version-shaped suffix is
        never consulted: it cannot add a held tag or suppress a "newer
        upstream tag" verdict.

        Exact string semantics: FOUND iff byte-equal to a remote tag from
        git ls-remote; no canonical v handling and no parse_version
        normalization — "v4.2.0.1" and "4.2.0.1" are distinct tags.
        """
        return sorted(set(self.versions))


class CheckResult(NamedTuple):
    """A checker's verdict: status, detail, and the optional fixable kind.

    Checkers may return the 2-tuple; the NamedTuple default keeps the
    dispatch boundary the single place the arity is resolved.
    """

    status: ParamStatus
    detail: str
    fixable: str | None = None


# What checker functions declare: (status, detail) or (status, detail,
# fixable kind). ``add_check`` normalizes both into a CheckResult.
CheckerTuple = tuple[ParamStatus, str] | tuple[ParamStatus, str, str | None]


@dataclass
class CheckFinding:
    """Individual rule verification result.

    ``fixable`` names the auto-fix kind this finding authorizes (see
    ``ConfigAutoFixer`` in fixes.py), set by the checker that produced
    the finding. The fix dispatch keys off this field and never off the
    human-readable ``detail``, so reworded messages cannot silently
    disable a fix.
    """

    id: str
    status: ParamStatus
    detail: str
    fixable: str | None = None

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {"id": self.id, "status": self.status.value, "detail": self.detail}
        if self.fixable is not None:
            d["fixable"] = self.fixable
        return d


@dataclass
class ParamAuditResult:
    """Aggregated audit result for a coin entry or specific version."""

    tag: str | None
    source: str | None
    mode: str
    checks: list[CheckFinding] = field(default_factory=list)
    fail: int = 0
    differs: int = 0
    warn: int = 0
    unresolved: int = 0
    conflict: int = 0
    version: str | None = None
    wallet_conf: str | None = None
    xbridge_conf: str | None = None
    per_version: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        res: dict[str, Any] = {
            "tag": self.tag,
            "source": self.source,
            "mode": self.mode,
            "checks": [c.to_dict() for c in self.checks],
            "fail": self.fail,
            "differs": self.differs,
            "warn": self.warn,
            "unresolved": self.unresolved,
        }
        if self.conflict:
            res["conflict"] = self.conflict
        if self.version:
            res["version"] = self.version
        if self.wallet_conf:
            res["wallet_conf"] = self.wallet_conf
        if self.xbridge_conf:
            res["xbridge_conf"] = self.xbridge_conf
        if self.per_version:
            res["per_version"] = self.per_version
        return res


def max_status(a: ParamStatus, b: ParamStatus) -> ParamStatus:
    """Return the higher-severity status according to PARAM_STATUS_PRECEDENCE."""
    idx_a = PARAM_STATUS_PRECEDENCE.index(a)
    idx_b = PARAM_STATUS_PRECEDENCE.index(b)
    return a if idx_a <= idx_b else b
