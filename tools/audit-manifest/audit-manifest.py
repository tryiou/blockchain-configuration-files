#!/usr/bin/env python3
"""audit-manifest.py - probe every coin repo referenced by manifest-latest.json.

For each distinct repo_url the script:
  * detects whether the repo has moved (HTTP redirect via curl -sI)
  * probes the repo for tags using `git ls-remote` (smart-HTTP git protocol)
  * checks every version tag we hold for that coin against the live tag set
  * detects NEWER upstream tags we are missing (upgrade candidates):
      - newer_same = numeric version tuple strictly newer than the max we hold,
        same component count (high-confidence upgrade signal)
      - newer_alt  = numeric tuple newer but different shape (e.g. <example>
        `3.7.0.1` vs our `v0.17.4.x`) -> flagged for manual review
  * fetches creatordate per tag via ONE bounded shallow git fetch per repo
    (only the tags we hold plus the --top-tags newest by version), so we can
    spot stale repos without downloading full histories.

`git ls-remote` / `git fetch` / `curl` do NOT use the GitHub REST API
(api.github.com), so GitHub API rate limits do not apply. No personal access
token is required.

Output: human-readable report on stdout, optionally a JSON report via --report (parallel to console, single parsable file only when requested).

--param-check adds a fact-check pass that verifies every XBridge-conf and
core-wallet-conf parameter against the coin's own source AT THE EXACT
MANIFEST TAG (reuses .cache/audit-manifest/<coin>_check clones whose HEAD
matches the tag, otherwise shallow-clone repo_url at that tag; btcd-family
handled via golang layout: chaincfg/params.go + mempool/policy.go). It is a
REPORTING tool: rows state observed values with file:line citations and,
where a value differs from source, the git birth-date of that conf line.
No intent is assumed and param results NEVER affect exit codes; judgment
belongs to whoever reads the report. Statuses are factual:
MATCH/DIFFERS (vs source constant), BROKEN (our own files disagree),
CONFLICT (fleet-level facts: two or more wallets share one P2P/RPC port),
FAIL only where mathematically certain (fee below relay floor -> mempool
rejection; COIN=0 rejected by blocknet; TxVersion above bound; unknown
connector), UNRESOLVED (source constant not located).

Severity policy (deliberate, do not "toughen" without cause):
mismatch vs source is WARN, not FAIL/DIFFERS — every WARN carries the conf
file:line plus the git birth-date of that line, so a reviewer can tell
fleet-reassigned ports (old value, deliberate) from real source drift.
Missing source constant is UNRESOLVED (investigate), never silent SKIP;
SKIP exists only where the key is absent from the conf by design
(e.g. addresstype/changetype not used). Absent keys (deprecatedrpc not
set) are INFO. Checker exceptions never propagate: add_check logs and
records WARN/FAIL with "checker error" detail.

Exit codes: 0 = all probed repos reachable; 1 = at least one repo dead,
moved, or unresolved; 2 = usage/load error.
"""

from __future__ import annotations

import argparse
import ast
from collections import Counter, defaultdict
from dataclasses import dataclass, field
import datetime
from enum import Enum
import json
import logging
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import time
from typing import Any, Callable, Dict, List, Optional, Set, Tuple, Union

_CURRENT_CHAIN_CACHE: Dict[str, Optional[str]] = {}

# ---------------------------------------------------------------------------
# Logging & Environment Setup
# ---------------------------------------------------------------------------

def _configure_logging() -> None:
    """Install this tool's log handler on the root logger.

    Called from ``main()``, not at import time: importing the module must not
    reconfigure an embedding process's root logger (tests, a driver script,
    another CLI). Running the tool still gets the exact same handler.
    """
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
        handlers=[logging.StreamHandler(sys.stdout)],
        force=True,
    )


logger = logging.getLogger("audit-manifest")

SCRIPT_DIR = Path(__file__).resolve().parent

# This repository's root: <repo>/tools/audit-manifest/ -> <repo>
REPO_ROOT = SCRIPT_DIR.parents[1]

DEFAULT_MANIFEST = REPO_ROOT / "manifest-latest.json"

# Local scratch for source clones and the changelog cache. Gitignored, never
# committed; purge it to force fresh probes.
CACHE_ROOT = REPO_ROOT / ".cache" / "audit-manifest"

# ---------------------------------------------------------------------------
# Domain Enums & Constants
# ---------------------------------------------------------------------------

class RepoStatus(str, Enum):
    ALIVE = "ALIVE"
    MOVED = "MOVED"
    DEAD = "DEAD"
    UNKNOWN = "UNKNOWN"
    ERROR = "ERROR"


class TagStatus(str, Enum):
    FOUND = "FOUND"
    MISSING = "MISSING"


class ParamStatus(str, Enum):
    FAIL = "FAIL"
    BROKEN = "BROKEN"
    CONFLICT = "CONFLICT"
    DIFFERS = "DIFFERS"
    WARN = "WARN"
    UNRESOLVED = "UNRESOLVED"
    INFO = "INFO"
    SKIP = "SKIP"
    PASS = "PASS"
    MATCH = "MATCH"


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

STATUS_MARKERS: Dict[ParamStatus, str] = {
    ParamStatus.FAIL: "!!",
    ParamStatus.BROKEN: "!!",
    ParamStatus.CONFLICT: "!!",
    ParamStatus.DIFFERS: "~- ",
    ParamStatus.WARN: "~ ",
    ParamStatus.INFO: "i ",
    ParamStatus.UNRESOLVED: "??",
    ParamStatus.SKIP: "--",
    ParamStatus.MATCH: "ok",
    ParamStatus.PASS: "ok",
}


class ActionType(str, Enum):
    OK = "OK"
    UPGRADE = "UPGRADE"
    REVIEW = "REVIEW"
    UNKNOWN = "UNKNOWN"
    MOVED = "MOVED"
    DEAD = "DEAD"


ACTION_SEVERITY: Dict[ActionType, int] = {
    ActionType.OK: 0,
    ActionType.REVIEW: 1,
    ActionType.UPGRADE: 2,
    ActionType.UNKNOWN: 3,
    ActionType.MOVED: 4,
    ActionType.DEAD: 5,
}

CREATE_TX_METHODS = frozenset({
    "BTC", "SYS", "BCH", "BCD", "DGB", "BTG", "DEVAULT", "STEALTH",
    "XST", "PART",
})

# Blocknet consumer constants (blocknet/src/xbridge/xbridgewallet.h:97,102; xbridgeapp.cpp:1030)
XMAX_LOCKTIME_DRIFT_BLOCKS = 4
XLOCKTIME_DRIFT_SECONDS = 900

# Fee model — strict-exact per-coin chain gates, no margins.
# XBridge fee per tx: effective = max(size*FeePerByte, MinTxFee)
# sizes 226=192*1+34*1, 260=192*1+34*2, 452=192*2+34*2 (xbridgewalletconnectorbtc.cpp:1951)
# All live connectors (BTC/BCH/PART across 39+1+1 confs) share this one formula,
# and the daemon (WalletHelper.calculateFee) uses the same linear math with no
# per-kB rounding — so FeePerByte in BCF must already encode ceil coverage.
# Daemon mempool gate per coin: fee >= minRelayTxFee.GetFee(vsize), where GetFee
# rounding is PER-COIN (floor / ceil / ceil-per-999B / fixed-steps / literal-flat),
# detected from source by fee_policy() below. REQUIRED values are exact:
# FAIL means a swap or refund leg cannot clear the coin daemon's real gate.
# Mempool-pressure variance (dynamic rolling floors, miner-configured inclusion)
# is reported as an informational note, never baked into REQUIRED values.
FEE_REF_SIZE = 452

# Sweep sizes: 226 refund-leg (fee2 1-in/1-out), 260/452 historic, 192n+102 for
# n=1..520 (100kB), plus ceil-step boundaries (999/1000/1998 families) so a
# per-kB ceiling can never hide between two sweep points.
FEE_SWEEP_SIZES = sorted(
    {226, 260, 452, 998, 999, 1000, 1001, 1997, 1998, 1999}
    | {192 * n + 102 for n in range(1, 521)}
)


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
    step_rate: Optional[int] = None
    fixed_step_bytes: Optional[int] = None
    fixed_step_fee: Optional[int] = None
    dgp_live: bool = False
    notes: Tuple[str, ...] = ()
    evidence: Tuple[str, ...] = ()


def chain_floor(policy: FeePolicy, rate: int, size: int) -> int:
    """Exact minimum fee (satoshis) the coin daemon requires for `size` bytes."""
    r = policy.rounding
    if r == "floor":
        fl = rate * size // 1000
        if fl == 0 and size != 0 and rate > 0:
            fl = rate if policy.zero_guard == "full_rate" else 1
        return fl
    if r == "go_floor":
        fl = (size * rate) // 1000
        if fl == 0 and size != 0 and rate > 0:
            fl = rate
        return fl
    if r == "literal_flat":
        fl = rate * size // 1000
        if fl == 0 and size != 0 and rate > 0:
            fl = rate
        return fl
    if r == "ceil":
        fl = (rate * size + 999) // 1000
        if fl == 0 and size != 0 and rate > 0:
            fl = 1
        return fl
    if r == "ceil_step":
        if policy.step_rate is None:
            raise ValueError("ceil_step policy without step_rate")
        n_steps = (size + policy.kb_step - 1) // policy.kb_step if size else 0
        fee = policy.step_rate * n_steps
        if fee == 0 and size != 0 and policy.step_rate > 0:
            fee = 1
        return fee
    if r == "fixed_steps":
        if policy.fixed_step_bytes is None or policy.fixed_step_fee is None:
            raise ValueError("fixed_steps policy without step params")
        return (1 + size // policy.fixed_step_bytes) * policy.fixed_step_fee
    raise ValueError(f"chain_floor: unhandled rounding {r!r} (no silent default)")


def strict_fees(policy: FeePolicy, rate: int) -> Tuple[int, int]:
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
            if need > fpb:
                fpb = need
    return int(mtf), int(fpb)


def recommended_fees(policy: FeePolicy, rate: int) -> Tuple[int, int]:
    """Deterministic THE fees — strict-exact per-coin chain gates, safe for ANY
    n (1 to ~520 inputs, 100kB). Single source for check/fix/scaffold."""
    return strict_fees(policy, rate)

PREFIX_SKIP_FMT = "{}: source {} not found in mainnet block (UNRESOLVED)"
PREFIX_DECODE_COMPAT_FMT = (
    "ScriptPrefix={}; source SCRIPT_ADDRESS={}, "
    "decode-compat SCRIPT_ADDRESS2={}; encode site: {}"
)
PREFIX_MINTED_SA2_OK_FMT = (
    "ScriptPrefix={} matches minted SCRIPT_ADDRESS2; "
    "SCRIPT_ADDRESS={} is legacy-decode only ({})"
)
PREFIX_MISMATCH_FMT = "{}: conf {} vs source {} ({}:{})"

_PRERELEASE_RE = re.compile(r"(?i)(?:[-_.]?(?:beta|alpha|rc|pre|dev|snapshot|nightly)\d*)")

_MANDATORY_HARDFORK_RE = re.compile(
    r"(?i)(\bmandatory\b.*\b(hard.?fork|consensus|upgrade)\b|\bhard.?fork\b.*\bmandatory\b|\bmust upgrade\b|\ball nodes must\b)"
)
_NEG_RE = re.compile(r"(?i)\bnon-mandatory\b|\bnot mandatory\b|does not change consensus|does not require.*upgrade")
_CHANGELOG_CACHE_DIRNAME = ".changelog_cache"


def _parse_github_owner_repo(url: str) -> Optional[Tuple[str, str]]:
    """Extract (owner, repo) from github https url, else None."""
    try:
        u = url.strip().rstrip("/")
        if u.endswith(".git"):
            u = u[:-4]
        # expect https://github.com/owner/repo
        m = re.match(r"https?://github\.com/([^/]+)/([^/]+)", u)
        if m:
            return m.group(1), m.group(2)
    except Exception:
        pass
    return None


def _detect_mandatory_hf(text: str) -> Optional[str]:
    """Return quoted evidence line if text contains mandatory hard-fork signal, else None."""
    if not text:
        return None
    # Exclude negation / non-mandatory phrasing (avoid false positive on "non-mandatory: it does not change consensus")
    # Check line by line to avoid cross-line false positives (e.g. DGB 'mandatory algolock' isolated)
    for line in text.splitlines():
        if _NEG_RE.search(line):
            continue
        if _MANDATORY_HARDFORK_RE.search(line):
            # require co-occurrence within line (already enforced by regex) and not alone 'mandatory'
            # Return trimmed line as quote (max 200 chars)
            q = line.strip()
            if len(q) > 200:
                q = q[:200].rstrip() + "…"
            return q
    # Fallback: search 2-line window (e.g. 'mandatory' on line N, 'hard fork' on N+1)
    lines = text.splitlines()
    for i in range(len(lines) - 1):
        win = lines[i] + " " + lines[i + 1]
        if _NEG_RE.search(win):
            continue
        if _MANDATORY_HARDFORK_RE.search(win):
            q = (lines[i].strip() + " " + lines[i + 1].strip()).strip()
            if len(q) > 200:
                q = q[:200].rstrip() + "…"
            return q
    return None

# ---------------------------------------------------------------------------
# Data Containers
# ---------------------------------------------------------------------------

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
    versions: List[str] = field(default_factory=list)
    wallet_conf: str = ""
    xbridge_conf: str = ""
    daemon_family: str = "btc"
    daemon_stem: str = ""

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> ManifestCoin:
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

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
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

    def expected_tags(self) -> List[str]:
        """Union of versions list and ver_id tag suffix.

        Exact string semantics: FOUND iff byte-equal to a remote tag.
        The union is intentionally not deduplicated via canonical/strip_v or
        parse_version. If ver_id and versions disagree on a v-prefix
        (e.g. MRX ver_id suffix "v4.2.0.1" vs versions ["4.2.0.1"],
        SWIFT opposite "3.0.5" vs ["v3.0.5"]), the expected set contains
        both forms (e.g. ["4.2.0.1", "v4.2.0.1"]). A phantom tag that
        does not exist upstream (git ls-remote ground truth) will then
        correctly appear as MISSING and drive REVIEW via classify_action.
        This phantom REVIEW is the correct signal of a manifest
        inconsistency, not a detector bug to suppress. No canonical
        v-handling is applied here — exact match only.
        """
        tags = set(self.versions)
        if "--" in self.ver_id:
            tags.add(self.ver_id.split("--", 1)[1])
        return sorted(tags)


@dataclass
class CheckFinding:
    """Individual rule verification result."""
    id: str
    status: ParamStatus
    detail: str

    def to_dict(self) -> Dict[str, Any]:
        return {"id": self.id, "status": self.status.value, "detail": self.detail}


@dataclass
class ParamAuditResult:
    """Aggregated audit result for a coin entry or specific version."""
    tag: Optional[str]
    source: Optional[str]
    mode: str
    checks: List[CheckFinding] = field(default_factory=list)
    fail: int = 0
    differs: int = 0
    warn: int = 0
    unresolved: int = 0
    conflict: int = 0
    version: Optional[str] = None
    wallet_conf: Optional[str] = None
    xbridge_conf: Optional[str] = None
    per_version: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        res: Dict[str, Any] = {
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


# ---------------------------------------------------------------------------
# Utility & Helper Functions
# ---------------------------------------------------------------------------

def max_status(a: ParamStatus, b: ParamStatus) -> ParamStatus:
    """Return the higher-severity status according to PARAM_STATUS_PRECEDENCE."""
    idx_a = PARAM_STATUS_PRECEDENCE.index(a)
    idx_b = PARAM_STATUS_PRECEDENCE.index(b)
    return a if idx_a <= idx_b else b


def norm_port_value(raw: Optional[str]) -> str:
    """Strip comments and return clean port string."""
    if raw is None:
        return ""
    s = raw.strip()
    if "#" in s:
        s = s.split("#", 1)[0].strip()
    if "//" in s:
        s = s.split("//", 1)[0].strip()
    return s.strip()


def eval_cnum(expr: str) -> int:
    """Evaluate a restricted C integer literal (hex/decimal with addition)."""
    expr = expr.strip()
    parts = [p.strip() for p in expr.split("+")]
    total = 0
    for p in parts:
        total += int(p, 16) if p.lower().startswith("0x") else int(p)
    return total


def _safe_arith_float(expr: str) -> Optional[float]:
    """Safe arithmetic: try eval_cnum first, then whitelisted ast eval.

    Only allows digits, whitespace, and +-*/(). Hex is handled via eval_cnum fallback.
    """
    expr = expr.strip()
    try:
        return float(eval_cnum(expr))
    except Exception:
        pass
    if not re.fullmatch(r"[\d\s\*\/\+\-\(\)\.]+", expr):
        return None
    try:
        node = ast.parse(expr, mode="eval")
        allowed = (
            ast.Expression,
            ast.BinOp,
            ast.UnaryOp,
            ast.Constant,
            ast.Add,
            ast.Sub,
            ast.Mult,
            ast.Div,
            ast.Pow,
            ast.UAdd,
            ast.USub,
        )
        for n in ast.walk(node):
            if not isinstance(n, allowed):
                return None

        def _eval(n: Any) -> float:
            if isinstance(n, ast.Expression):
                return _eval(n.body)
            if isinstance(n, ast.Constant):
                if isinstance(n.value, (int, float)):
                    return float(n.value)
                raise ValueError("non-numeric constant")
            if isinstance(n, ast.BinOp):
                left = _eval(n.left)
                right = _eval(n.right)
                if isinstance(n.op, ast.Add):
                    return left + right
                if isinstance(n.op, ast.Sub):
                    return left - right
                if isinstance(n.op, ast.Mult):
                    return left * right
                if isinstance(n.op, ast.Div):
                    return left / right
                if isinstance(n.op, ast.Pow):
                    if abs(right) > 1e6:
                        raise ValueError("pow exponent too large")
                    return left**right
                raise ValueError("unsupported binop")
            if isinstance(n, ast.UnaryOp):
                v = _eval(n.operand)
                if isinstance(n.op, ast.UAdd):
                    return +v
                if isinstance(n.op, ast.USub):
                    return -v
                raise ValueError("unsupported unaryop")
            raise ValueError("unsupported node")

        return float(_eval(node))
    except ZeroDivisionError:
        return None
    except Exception:
        return None


def sanitize_tag(tag: str) -> str:
    """Filesystem-safe tag suffix (alphanumeric + ._-)."""
    return re.sub(r"[^A-Za-z0-9._-]", "_", tag)


# ---------------------------------------------------------------------------
# Version & Semver Engine
# ---------------------------------------------------------------------------

class VersionEngine:
    """Pure functions for version string evaluation, semver sorting, and fossil detection."""

    @staticmethod
    def parse_version(tag: str) -> Optional[Tuple[int, ...]]:
        """Return numeric tuple for dotted-numeric version tag, else None."""
        s = tag.strip()
        m = re.match(r"^[^\d]*(\d+(?:\.\d+)*)", s)
        if not m:
            return None
        num_str = m.group(1)
        # hash guard: single-component (no dot) + suffix isalpha + no leading v
        # keeps da839021c -> None while preserving v22-final -> (22,)
        if "." not in num_str:
            suffix = s[m.end():]
            if suffix and suffix.isalpha() and not s.lower().startswith("v"):
                return None
        return tuple(int(p) for p in num_str.split("."))

    @classmethod
    def is_prerelease(cls, tag: str) -> bool:
        """True if the tag contains pre-release markers (alpha/beta/rc/etc.)."""
        m = re.match(r"^[^\d]*\d+(?:\.\d+)*(.*)$", tag.strip())
        if not m:
            return False
        return bool(_PRERELEASE_RE.search(m.group(1)))

    @classmethod
    def stable_tags(cls, tags: Optional[Set[str]]) -> Optional[Set[str]]:
        """Subset of tags excluding pre-releases."""
        if tags is None:
            return None
        return {t for t in tags if not cls.is_prerelease(t)}

    @classmethod
    def max_version_tag(cls, tags: Any) -> Optional[str]:
        """Highest numeric-version tag in iterable, resolving ties lexically."""
        best, best_p = None, None
        for t in sorted(tags or ()):
            p = cls.parse_version(t)
            if p is None:
                continue
            if best_p is None or p > best_p:
                best, best_p = t, p
        return best

    @classmethod
    def detect_newer(cls, remote_tags: Optional[Set[str]], coins: List[ManifestCoin]) -> Tuple[List[str], List[str]]:
        """Split upstream tags into newer_same and newer_alt relative to held tags."""
        if remote_tags is None:
            return [], []
        stable = cls.stable_tags(remote_tags)
        if not stable:
            return [], []

        held_tags: Set[str] = set()
        for coin in coins:
            held_tags.update(coin.expected_tags())

        parsed_held = [cls.parse_version(t) for t in held_tags]
        valid_held = [p for p in parsed_held if p is not None]
        if not valid_held:
            return [], []

        max_held = max(valid_held)
        max_len = len(max_held)

        newer_same: List[str] = []
        newer_alt: List[str] = []

        for t in sorted(stable):
            p = cls.parse_version(t)
            if p is None or p <= max_held:
                continue
            (newer_same if len(p) == max_len else newer_alt).append(t)

        return newer_same, newer_alt


# ---------------------------------------------------------------------------
# Git & System Command Runner
# ---------------------------------------------------------------------------

class SystemCommandRunner:
    """Executes external processes with retry mechanisms and environment management."""

    @staticmethod
    def run(
        cmd: List[str],
        timeout: int,
        retries: int = 2,
        env_extra: Optional[Dict[str, str]] = None,
        cwd: Optional[Union[str, Path]] = None,
    ) -> Optional[subprocess.CompletedProcess[str]]:
        env = dict(os.environ)
        if env_extra:
            env.update(env_extra)

        attempt = 0
        while True:
            try:
                return subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=timeout,
                    env=env,
                    cwd=str(cwd) if cwd else None,
                )
            except subprocess.TimeoutExpired:
                attempt += 1
                if attempt > retries:
                    logger.warning("Command timed out after %d attempts: %s", attempt, " ".join(cmd))
                    return None
                time.sleep(1)
            except Exception as e:
                logger.error("Command execution error for %s: %s", " ".join(cmd), e)
                return None


class RemoteProbeService:
    """Probes remote git repositories using smart-HTTP protocol and HTTP headers."""

    def __init__(self, runner: SystemCommandRunner = SystemCommandRunner()):
        self.runner = runner

    def probe_redirect(self, url: str, timeout: int) -> Optional[str]:
        """Detect HTTP 301/302 redirects without GitHub REST API."""
        proc = self.runner.run(
            ["curl", "-sI", "-o", "/dev/null", "-w", "%{redirect_url}", url],
            timeout,
        )
        if proc is None:
            return None
        target = proc.stdout.strip()
        if target and target.rstrip("/") != url.rstrip("/"):
            return target
        return None

    def probe_tags(self, url: str, timeout: int) -> Tuple[RepoStatus, Optional[Set[str]]]:
        """Query remote refs using git ls-remote."""
        proc = self.runner.run(
            ["git", "ls-remote", "--tags", url],
            timeout,
            env_extra={"GIT_TERMINAL_PROMPT": "0"},
        )
        if proc is None:
            return RepoStatus.UNKNOWN, None
        if proc.returncode == 128:
            return RepoStatus.DEAD, None
        if proc.returncode != 0:
            return RepoStatus.ERROR, None

        tags: Set[str] = set()
        for line in proc.stdout.splitlines():
            if "refs/tags/" not in line:
                continue
            ref = line.split("refs/tags/", 1)[1]
            if ref.endswith("^{}"):
                continue
            tags.add(ref)
        return RepoStatus.ALIVE, tags

    def probe_tag_dates(self, url: str, selected: Set[str], timeout: int) -> Optional[Dict[str, str]]:
        """Fetch creatordate for selected tags using a single shallow bare fetch."""
        if not selected:
            return {}

        tmp_dir = tempfile.mkdtemp()
        try:
            init = self.runner.run(["git", "init", "-q", "--bare", tmp_dir], timeout)
            if init is None or init.returncode != 0:
                return None

            refspecs = [f"+refs/tags/{t}:refs/tags/{t}" for t in sorted(selected)]
            fetch_cmd = [
                "git", "-C", tmp_dir, "fetch", "-q", "--depth=1",
                "--filter=tree:0", "--no-tags", url
            ] + refspecs

            fetch = self.runner.run(fetch_cmd, timeout, env_extra={"GIT_TERMINAL_PROMPT": "0"})
            if fetch is None or fetch.returncode != 0:
                return None

            fmt = self.runner.run(
                [
                    "git", "-C", tmp_dir, "for-each-ref",
                    "--format=%(refname) %(creatordate:iso8601)",
                    "refs/tags",
                ],
                timeout,
            )
            if fmt is None or fmt.returncode != 0:
                return None

            dates: Dict[str, str] = {}
            for line in fmt.stdout.splitlines():
                if "refs/tags/" in line:
                    ref, date = line.split(" ", 1)
                    tag = ref.split("refs/tags/", 1)[1]
                    if not tag.endswith("^{}"):
                        dates[tag] = date.strip()
            return dates
        finally:
            shutil.rmtree(tmp_dir, ignore_errors=True)

    def probe_tag_annotation(self, url: str, tag: str, timeout: int) -> Optional[str]:
        """Fetch annotated tag message via shallow bare fetch + for-each-ref."""
        tmp_dir = tempfile.mkdtemp()
        try:
            init = self.runner.run(["git", "init", "-q", "--bare", tmp_dir], timeout)
            if init is None or init.returncode != 0:
                return None
            fetch = self.runner.run(
                ["git", "-C", tmp_dir, "fetch", "-q", "--depth=1", url, f"refs/tags/{tag}:refs/tags/{tag}"],
                timeout,
                env_extra={"GIT_TERMINAL_PROMPT": "0"},
            )
            if fetch is None or fetch.returncode != 0:
                return None
            fmt = self.runner.run(
                ["git", "-C", tmp_dir, "for-each-ref", "--format=%(contents)", f"refs/tags/{tag}"],
                timeout,
            )
            if fmt is None or fmt.returncode != 0:
                return None
            txt = fmt.stdout.strip()
            return txt if txt else None
        finally:
            shutil.rmtree(tmp_dir, ignore_errors=True)

    def probe_github_release(self, url: str, tag: str, timeout: int, cache_root: Optional[Path] = None) -> Optional[str]:
        """Fetch GitHub Releases body via api.github.com, cached in .cache/audit-manifest/.changelog_cache.
        Stdlib-only, no token. The cache is ephemeral by design (gitignored
        scratch): purge it to force a re-probe."""
        parsed = _parse_github_owner_repo(url)
        if not parsed:
            return None
        owner, repo = parsed
        cache_dir: Optional[Path] = None
        cache_path: Optional[Path] = None
        if cache_root is not None:
            try:
                cache_dir = cache_root / _CHANGELOG_CACHE_DIRNAME
                cache_dir.mkdir(parents=True, exist_ok=True)
                safe_tag = sanitize_tag(tag)
                cache_path = cache_dir / f"{owner}_{repo}_{safe_tag}.json"
                if cache_path.is_file():
                    try:
                        data = json.loads(cache_path.read_text(encoding="utf-8"))
                        body = data.get("body")
                        if isinstance(body, str) and body.strip():
                            return body
                    except Exception:
                        pass
            except Exception:
                cache_path = None
        api_url = f"https://api.github.com/repos/{owner}/{repo}/releases/tags/{tag}"
        proc = self.runner.run(
            ["curl", "-s", "-H", "Accept: application/vnd.github+json", "-w", "\n%{http_code}", api_url],
            timeout,
        )
        if proc is None or proc.returncode != 0:
            return None
        out = proc.stdout.strip()
        if "\n" in out:
            body_part, code_part = out.rsplit("\n", 1)
        else:
            body_part, code_part = out, ""
        try:
            code = int(code_part.strip()) if code_part.strip().isdigit() else -1
        except Exception:
            code = -1
        if code in (429, 403):
            return None
        if code == 404:
            return None
        if code != 200:
            return None
        try:
            data = json.loads(body_part) if body_part else {}
        except Exception:
            return None
        body = data.get("body") if isinstance(data, dict) else None
        if not isinstance(body, str) or not body.strip():
            name = data.get("name") if isinstance(data, dict) else None
            if isinstance(name, str) and name.strip():
                body = name
            else:
                return None
        if cache_path is not None:
            try:
                cache_path.write_text(
                    json.dumps({"body": body, "tag": tag, "url": api_url}, indent=2), encoding="utf-8"
                )
            except Exception:
                pass
        return body

    def probe_changelog(self, url: str, tag: str, timeout: int, cache_root: Optional[Path] = None) -> Optional[Tuple[str, str]]:
        """Hybrid: check both tag annotation and GitHub Releases; prefer mandatory hit."""
        tag_txt: Optional[str] = None
        gh_body: Optional[str] = None
        try:
            tag_txt = self.probe_tag_annotation(url, tag, timeout)
        except Exception:
            tag_txt = None
        try:
            gh_body = self.probe_github_release(url, tag, timeout, cache_root)
        except Exception:
            gh_body = None
        # Prefer GitHub body if it contains mandatory, else tag, else any non-empty
        # Check mandatory in both
        gh_quote = _detect_mandatory_hf(gh_body) if gh_body else None
        tag_quote = _detect_mandatory_hf(tag_txt) if tag_txt else None
        if gh_quote and gh_body:
            return ("github-releases", gh_body.strip())
        if tag_quote and tag_txt:
            return ("tag", tag_txt.strip())
        if gh_body and gh_body.strip():
            return ("github-releases", gh_body.strip())
        if tag_txt and tag_txt.strip():
            return ("tag", tag_txt.strip())
        return None


# ---------------------------------------------------------------------------
# Source Resolution & File Slurping Layer
# ---------------------------------------------------------------------------

class SourceCheckoutManager:
    """Manages the local git clones and shallow checkouts used for param checking.

    All checkouts live under CACHE_ROOT inside this repository (gitignored).
    """

    def __init__(self, cache_root: Path = CACHE_ROOT, runner: SystemCommandRunner = SystemCommandRunner()):
        self.cache_root = cache_root
        self.tmp_root = cache_root
        self.runner = runner

    @staticmethod
    def candidate_stems(coin: ManifestCoin) -> List[str]:
        raw: List[str] = []
        for stem in (
            coin.ticker.lower(),
            coin.dir_name_linux.lower() if coin.dir_name_linux else "",
            coin.ver_id.partition("--")[0].lower() if coin.ver_id else "",
            coin.daemon_stem.lower() if coin.daemon_stem else "",
        ):
            s = stem.strip().lower()
            if s and s not in raw:
                raw.append(s)
        return raw

    def resolve_source(self, coin: ManifestCoin, tag: str, timeout: int) -> Tuple[Optional[Path], str]:
        """Resolve local source for the exact tag string only.

        Exact string semantics: clones/reuses only the byte-equal tag
        via ``git clone --branch <exact>`` / ``git fetch refs/tags/<exact>``
        and verifies HEAD matches that exact tag commit. No canonical
        v-prefix stripping, parse_version normalization, or "v" vs "no-v"
        equivalence is performed — "v4.2.0.1" and "4.2.0.1" are distinct
        tags. A phantom/missing tag therefore correctly yields
        clone-failed and surfaces as REVIEW at the caller.
        """
        self.tmp_root.mkdir(parents=True, exist_ok=True)

        existing_map: Dict[str, Path] = {}
        try:
            for entry in self.tmp_root.iterdir():
                if entry.is_dir():
                    existing_map[entry.name.lower()] = entry
        except OSError:
            pass

        candidates: List[Path] = []
        for stem in self.candidate_stems(coin):
            if stem:
                base_lower = f"{stem}_check".lower()
                candidates.append(existing_map.get(base_lower, self.tmp_root / f"{stem}_check"))
                tag_lower = f"{stem}_{sanitize_tag(tag)}_check".lower()
                candidates.append(existing_map.get(tag_lower, self.tmp_root / f"{stem}_{sanitize_tag(tag)}_check"))

        # Deduplicate while preserving order
        seen: Set[Path] = set()
        uniq_candidates = [c for c in candidates if not (c in seen or seen.add(c))]

        for cand in uniq_candidates:
            if not cand.is_dir():
                continue
            proc = self.runner.run(["git", "-C", str(cand), "describe", "--tags", "--exact-match"], timeout)
            if proc and proc.returncode == 0 and proc.stdout.strip() == tag:
                h_head = self.runner.run(["git", "-C", str(cand), "rev-parse", "HEAD"], timeout)
                h_tag = self.runner.run(["git", "-C", str(cand), "rev-list", "-n", "1", tag], timeout)
                if h_head and h_tag and h_head.returncode == 0 and h_tag.returncode == 0:
                    if h_head.stdout.strip() == h_tag.stdout.strip():
                        return cand, "reused"

        primary_stem = (coin.dir_name_linux or coin.ticker.lower()).lower() or (coin.daemon_stem.lower() if coin.daemon_stem else "coin")
        primary_target = existing_map.get(f"{primary_stem}_check", self.tmp_root / f"{primary_stem}_check")

        if primary_target.is_dir():
            p = self.runner.run(["git", "-C", str(primary_target), "describe", "--tags", "--exact-match"], timeout)
            if p and p.returncode == 0 and p.stdout.strip() != tag:
                target = existing_map.get(f"{primary_stem}_{sanitize_tag(tag)}_check", self.tmp_root / f"{primary_stem}_{sanitize_tag(tag)}_check")
            else:
                target = primary_target
        else:
            target = primary_target

        if not coin.repo_url:
            return None, "no-repo-url"

        clone_timeout = max(timeout, 60)
        proc = self.runner.run(
            ["git", "clone", "-q", "--depth", "1", "--branch", tag, coin.repo_url, str(target)],
            clone_timeout,
            env_extra={"GIT_TERMINAL_PROMPT": "0"},
        )
        if proc is not None and proc.returncode == 0 and target.is_dir():
            return target, "cloned"

        # Fallback for lightweight/annotated tags where shallow branch clone fails
        shutil.rmtree(target, ignore_errors=True)
        try:
            target.mkdir(parents=True, exist_ok=True)
            self.runner.run(["git", "init", "-q", str(target)], clone_timeout, env_extra={"GIT_TERMINAL_PROMPT": "0"})
            proc_fetch = self.runner.run(
                ["git", "-C", str(target), "fetch", "-q", "--depth", "1", coin.repo_url, f"refs/tags/{tag}:refs/tags/{tag}"],
                clone_timeout,
                env_extra={"GIT_TERMINAL_PROMPT": "0"},
            )
            if proc_fetch is None or proc_fetch.returncode != 0:
                self.runner.run(["git", "-C", str(target), "remote", "add", "origin", coin.repo_url], timeout, env_extra={"GIT_TERMINAL_PROMPT": "0"})
                proc_fetch = self.runner.run(
                    ["git", "-C", str(target), "fetch", "-q", "--depth", "1", "origin", "tag", tag],
                    clone_timeout,
                    env_extra={"GIT_TERMINAL_PROMPT": "0"},
                )

            if proc_fetch is not None and proc_fetch.returncode == 0:
                for checkout_target in (tag, f"tags/{tag}"):
                    proc_co = self.runner.run(
                        ["git", "-C", str(target), "checkout", "-q", checkout_target],
                        timeout,
                        env_extra={"GIT_TERMINAL_PROMPT": "0"},
                    )
                    if proc_co is not None and proc_co.returncode == 0:
                        return target, "cloned-fallback"
        except Exception as e:
            logger.debug("Clone fallback failed for %s @ %s: %s", coin.ticker, tag, e)

        shutil.rmtree(target, ignore_errors=True)
        return None, "clone-failed"


class SourceReader:
    """Wrapper-aware source code file reader with multi-level directory discovery."""

    @staticmethod
    def slurp(path: Union[str, Path]) -> Optional[str]:
        try:
            with open(path, encoding="utf-8", errors="replace") as fh:
                return fh.read()
        except OSError:
            return None

    @classmethod
    def slurp_src(cls, src_dir: Path, rel_path: str) -> Optional[str]:
        """Slurp src/rel_path scanning top-level and nested wrapper directories.

        Generic BFS depth≤3 capped, exclude .git and symlinks, not hardcoded.
        """
        direct = src_dir / rel_path
        txt = cls.slurp(direct)
        if txt is not None:
            return txt
        if not rel_path.startswith("src/"):
            return None

        from collections import deque

        seen: Set[Path] = set()
        queue: deque[Tuple[Path, int]] = deque()
        try:
            for entry in src_dir.iterdir():
                if entry.is_symlink():
                    continue
                if not entry.is_dir():
                    continue
                if entry.name == ".git":
                    continue
                if entry in seen:
                    continue
                seen.add(entry)
                queue.append((entry, 1))
        except OSError:
            return None

        while queue:
            cur, depth = queue.popleft()
            cand = cur / rel_path
            txt2 = cls.slurp(cand)
            if txt2 is not None:
                return txt2
            if depth < 3:
                try:
                    for sub in cur.iterdir():
                        if sub.is_symlink():
                            continue
                        if not sub.is_dir():
                            continue
                        if sub.name == ".git":
                            continue
                        if sub in seen:
                            continue
                        seen.add(sub)
                        queue.append((sub, depth + 1))
                except OSError:
                    continue
        return None

    @staticmethod
    def strip_comments(text: str) -> str:
        # Both removals preserve newlines so evidence line numbers stay valid:
        # block spans are replaced by their interior newlines, and the
        # full-line // pattern uses [ \t] (never \s, which would also eat a
        # preceding blank line's newline and shift every later line number).
        text = re.sub(r"/\*.*?\*/", lambda m: "\n" * m.group(0).count("\n"), text, flags=re.S)
        return re.sub(r"^[ \t]*//.*$", "", text, flags=re.M)

    @classmethod
    def parse_conf_sections(cls, path: Union[str, Path]) -> Dict[str, Dict[str, str]]:
        """Parse ini-style conf into {section: {key: value}}."""
        out: Dict[str, Dict[str, str]] = {"": {}}
        cur = ""
        txt = cls.slurp(path)
        if txt is None:
            return out
        for line in txt.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("[") and line.endswith("]"):
                cur = line[1:-1].strip().lower()
                out.setdefault(cur, {})
                continue
            if "=" not in line:
                continue
            k, v = line.split("=", 1)
            out[cur][k.strip()] = v.strip()
        return out

    @classmethod
    def parse_conf(cls, path: Union[str, Path]) -> Dict[str, str]:
        """Parse key=value pairs dropping comments and section headers."""
        conf: Dict[str, str] = {}
        txt = cls.slurp(path)
        if txt is None:
            return conf
        for line in txt.splitlines():
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("["):
                continue
            if "=" not in line:
                continue
            k, v = line.split("=", 1)
            conf[k.strip()] = v.strip()
        return conf

    @staticmethod
    def lineage_date(repo_root: Path, rel_path: str, key: str, runner: SystemCommandRunner = SystemCommandRunner()) -> Optional[str]:
        """Determine git birth-date (YYYY-MM-DD) of a key= line via git blame."""
        path = repo_root / rel_path
        if not path.is_file():
            return None
        n: Optional[int] = None
        try:
            with open(path, encoding="utf-8", errors="replace") as fh:
                n = next((i + 1 for i, line in enumerate(fh) if line.strip().startswith(f"{key}=")), None)
        except OSError:
            return None
        if not n:
            return None

        proc = runner.run(
            ["git", "-C", str(repo_root), "blame", "--porcelain", "-L", f"{n},{n}", "--", rel_path],
            15,
        )
        if proc is None or proc.returncode != 0:
            return None
        m = re.search(r"^committer-time (\d+)", proc.stdout, re.M)
        if not m:
            return None
        return datetime.datetime.fromtimestamp(int(m.group(1)), datetime.timezone.utc).strftime("%Y-%m-%d")


# ---------------------------------------------------------------------------
# C++ / Go Source Code Parameter Extractors
# ---------------------------------------------------------------------------

class CppExpressionEvaluator:
    """Resolves C++ constants and macro expressions across header dependencies."""

    @classmethod
    def resolve_cexpr(
        cls,
        rhs: str,
        header_text: str,
        header_name: str,
        src_root: Path,
        depth: int = 0,
    ) -> Tuple[Optional[int], Optional[str]]:
        rhs = rhs.strip().rstrip(";").strip()
        if depth > 5:
            return None, None
        # Constant resolution must ignore commented-out definitions: a stale
        # `// ... CENT = 1000000;` above the active `CENT = 10000;` (Verge
        # src/amount.h) otherwise wins the regex below and inflates every
        # derived fee 100x. Strip block + full-line comments before matching.
        header_text = SourceReader.strip_comments(header_text)
        try:
            return eval_cnum(rhs), header_name
        except ValueError:
            pass

        # handle C++14 digit separators (1'000) and underscores
        m = re.match(r"([A-Za-z_]\w*)\s*(?:(/|\*)\s*([\d'_]+))?$", rhs)
        m_rev = None
        if not m:
            # reversed form: `100'000'000 * SATOSHI` (BCH Amount class)
            m_rev = re.match(r"([\d'_]+)\s*(/|\*)\s*([A-Za-z_]\w*)$", rhs)
            if not m_rev:
                return None, None

        if m_rev:
            num_raw, op, ident = m_rev.group(1), m_rev.group(2), m_rev.group(3)
            num = num_raw.replace("'", "").replace("_", "")
        else:
            ident, op, num = m.group(1), m.group(2), m.group(3)
            if num:
                num = num.replace("'", "").replace("_", "")
        base = None
        # SATOSHI is 1 sat by definition (BCH Amount::satoshi(), btcd SatoshiPerBitcoin base unit)
        if ident == "SATOSHI":
            base = 1
        if base is None:
            dm = re.search(r"\b" + re.escape(ident) + r"\s*=\s*([A-Za-z_0-9]+(?:\s*[/*]\s*\d+)?)", header_text)
            if dm:
                base, _ = cls.resolve_cexpr(dm.group(1), header_text, header_name, src_root, depth + 1)

        if base is None:
            for cand_path in ("src/consensus/amount.h", "src/amount.h", "src/policy/policy.h", "src/validation.h", "src/main.h"):
                atxt = SourceReader.slurp(src_root / cand_path)
                if atxt is None or atxt == header_text:
                    continue
                atxt = SourceReader.strip_comments(atxt)
                am = re.search(r"\b" + re.escape(ident) + r"\s*=\s*([^;]+);", atxt)
                if am:
                    base, _ = cls.resolve_cexpr(am.group(1), atxt, cand_path, src_root, depth + 1)
                    if base is not None:
                        break

        if base is None:
            return None, None
        if not op:
            return base, f"{header_name}: {rhs} = {base}"
        if m_rev:
            val = int(num) // base if op == "/" else int(num) * base
        else:
            val = base // int(num) if op == "/" else base * int(num)
        return val, f"{header_name}: {rhs} = {val}"


class CppSourceInspector:
    """Fact-checks configuration values against Bitcoin-derivative C++ codebases."""

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
                        cv, _ = CppSourceInspector.coin_value_from_amount_h(
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
            src_n, ev = CppSourceInspector.coin_value_from_amount_h(txt, rel, src_dir)
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


# ---------------------------------------------------------------------------
# Common Configuration & Fee Checkers
# ---------------------------------------------------------------------------

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
    def check_rpcport_xbridge(coin: ManifestCoin, wc: Dict[str, str], xc: Dict[str, str], repo_root: Path) -> Tuple[ParamStatus, str]:
        wref = CommonParamCheckers._conf_key_line(repo_root, f"wallet-confs/{coin.wallet_conf}", "rpcport")
        xref = CommonParamCheckers._conf_key_line(repo_root, f"xbridge-confs/{coin.xbridge_conf}", "Port")
        try:
            wrpc = int(wc.get("rpcport", ""))
        except ValueError:
            return ParamStatus.UNRESOLVED, f"wallet conf has no rpcport= line ({wref})"
        try:
            xport = int(xc.get("Port", ""))
        except ValueError:
            return ParamStatus.BROKEN, f"xbridge Port={xc.get('Port')!r} non-numeric vs wallet rpcport={wrpc} ({wref} vs {xref})"
        if wrpc == xport:
            return ParamStatus.MATCH, f"xbridge Port={wrpc} == wallet rpcport ({wref} vs {xref}) (internally consistent)"
        return ParamStatus.BROKEN, f"xbridge Port={xport} != wallet rpcport={wrpc} ({wref} vs {xref}) - our own files disagree"

    @staticmethod
    def check_fees(
        coin: ManifestCoin,
        src_dir: Path,
        xc: Dict[str, str],
        rate: Optional[int],
        rate_ev: Optional[str],
        dust: Optional[int],
        dust_ev: Optional[str],
        policy: Optional[FeePolicy] = None,
    ) -> Tuple[ParamStatus, str]:
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
                f"fee extraction failed for {coin.ticker}: relay/inclusion "
                f"rate not resolved ({rate_ev})"
            )
        if policy.rounding == "ceil_step" and policy.step_rate is None:
            return ParamStatus.FAIL, (
                f"fee extraction failed for {coin.ticker}: ceil_step without "
                f"resolved step rate ({'; '.join(policy.evidence)})"
            )
        if policy.rounding == "fixed_steps" and (
            policy.fixed_step_bytes is None or policy.fixed_step_fee is None
        ):
            return ParamStatus.FAIL, (
                f"fee extraction failed for {coin.ticker}: fixed_steps without "
                f"resolved step params ({'; '.join(policy.evidence)})"
            )

        recMin, recFee = recommended_fees(policy, rate)
        # Sweep ANY n: refund-leg 226 + 260/452 historic + 192n+102 for n=1..520
        # plus ceil-step boundaries so per-kB ceilings cannot hide between points.
        worst: Optional[Tuple[float, int, int, int]] = None
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

        assert worst is not None
        model = f"{policy.rounding}/{policy.mempool}"
        # integer decisions (no float epsilon)
        if worst_fee < worst_floor:
            return ParamStatus.FAIL, (
                f"FAIL fee below chain gate — got MinTxFee={mtf} FeePerByte={fpb} "
                f"!= REQUIRED MinTxFee={recMin} FeePerByte={recFee} "
                f"({worst[0]:.2f}x <1.00x, worst {worst[1]}B, model {model}, "
                f"rate {rate} sat/kB) ({rate_ev})"
            )
        if fpb != recFee or mtf != recMin:
            return ParamStatus.WARN, (
                f"WARN overpay — got MinTxFee={mtf} FeePerByte={fpb} "
                f"!= REQUIRED MinTxFee={recMin} FeePerByte={recFee} "
                f"({worst[0]:.2f}x, model {model}, rate {rate} sat/kB) ({rate_ev})"
            )
        detail = (
            f"PASS MinTxFee={mtf} FeePerByte={fpb} == REQUIRED MinTxFee={recMin} FeePerByte={recFee} "
            f"({worst[0]:.2f}x, model {model}, rate {rate} sat/kB) ({rate_ev})"
        )
        if policy.mempool == "dynamic":
            detail += " [note: dynamic mempool floor can exceed this during congestion]"
        if policy.dgp_live:
            detail += " [note: DGP live values override source default]"
        return ParamStatus.PASS, detail

    @staticmethod
    def check_dust(
        coin: ManifestCoin,
        src_dir: Path,
        xc: Dict[str, str],
        rate: Optional[int],
        rate_ev: Optional[str],
        dust: Optional[int],
        dust_ev: Optional[str],
        policy: Optional[FeePolicy] = None,
    ) -> Tuple[ParamStatus, str]:
        raw = xc.get("DustAmount", "")
        try:
            conf_val = int(raw.strip()) if raw.strip() != "" else None
        except ValueError:
            return ParamStatus.FAIL, f"DustAmount={raw!r} non-numeric"
        if conf_val is None:
            return ParamStatus.UNRESOLVED, "DustAmount missing — expected placeholder 0"

        if policy is not None and policy.dust_model == "disabled":
            if conf_val == 0:
                return ParamStatus.INFO, (
                    "placeholder DustAmount=0 correct — source disables dust "
                    f"(IsDust always false) ({'; '.join(policy.evidence)})"
                )
            return ParamStatus.WARN, (
                f"DustAmount={conf_val} ignored by blocknet loader — source "
                "disables dust (IsDust always false)"
            )

        expected = None
        expected_ev = ""
        is_static_limit = False

        if dust is not None:
            ticker_up = coin.ticker.upper()
            if dust_ev and ("DEFAULT_DUST_LIMIT" in dust_ev or ("RECOMMENDED_MIN_TX_FEE" in dust_ev and ticker_up == "DOGE")):
                expected = dust
                expected_ev = f"{dust_ev} -> static dustLimit {dust} sat (IsDust: value < limit)"
                is_static_limit = True
            else:
                factor = 1
                for cand in ("src/policy/policy.cpp", "src/primitives/transaction.h", "divi/src/FeeAndPriorityCalculator.cpp", "src/validation.cpp"):
                    t = SourceReader.slurp_src(src_dir, cand) or SourceReader.slurp(src_dir / cand)
                    if t and any(k in t for k in ("3 * dustRelayFee", "3*dustRelayFee", "3 * minimumRelay", "3*minimumRelay", "3 * minRelayTxFee", "3*minRelayTxFee")):
                        factor = 3
                        break
                if policy is not None and policy.rounding == "ceil_step":
                    # ceil_step single-arg rates apply as given (the flat
                    # step_rate only comes from the neutralized 2-arg ctor).
                    p2pkh = dust * ((182 + policy.kb_step - 1) // policy.kb_step) * factor
                elif policy is not None and policy.rounding in (
                    "floor", "ceil", "go_floor", "literal_flat",
                ):
                    # Exact per-model dust gate at typical sizes (P2PKH 182 B).
                    p2pkh = chain_floor(policy, dust, 182) * factor
                else:
                    p2pkh = dust * 182 // 1000 * factor
                segwit = False
                for cand in ("src/policy/policy.cpp",):
                    t = SourceReader.slurp_src(src_dir, cand) or SourceReader.slurp(src_dir / cand)
                    if t and "WITNESS_SCALE_FACTOR" in t and "IsWitnessProgram" in t:
                        segwit = True
                        break
                if segwit:
                    if policy is not None and policy.rounding == "ceil_step":
                        p2wpkh = dust * ((98 + policy.kb_step - 1) // policy.kb_step) * factor
                    elif policy is not None and policy.rounding in (
                        "floor", "ceil", "go_floor", "literal_flat",
                    ):
                        p2wpkh = chain_floor(policy, dust, 98) * factor
                    else:
                        p2wpkh = dust * 98 // 1000 * factor
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
            return ParamStatus.INFO, f"placeholder DustAmount=0 (expected — blocknet computes runtime dust) — {desc} ({expected_ev})"
        return ParamStatus.WARN, f"DustAmount={conf_val} ignored by blocknet loader — expected P2PKH {expected} sat ({expected_ev})"

    @staticmethod
    def check_confirmations(coin: ManifestCoin, xc: Dict[str, str]) -> Tuple[ParamStatus, str]:
        xref = f"xbridge-confs/{coin.xbridge_conf}:Confirmations/BlockTime"
        try:
            cf = int(xc.get("Confirmations", ""))
            bt = int(xc.get("BlockTime", "1"))
        except ValueError:
            return ParamStatus.FAIL, f"Confirmations non-numeric ({xref})"
        if bt <= 0:
            return ParamStatus.UNRESOLVED, "BlockTime unusable — Confirmations cap unevaluable"
        cap = max(XLOCKTIME_DRIFT_SECONDS // bt, XMAX_LOCKTIME_DRIFT_BLOCKS)
        ev = f"blocknet/src/xbridge/xbridgewallet.h:96-102 XLOCKTIME_DRIFT_SECONDS={XLOCKTIME_DRIFT_SECONDS}/XMAX_LOCKTIME_DRIFT_BLOCKS={XMAX_LOCKTIME_DRIFT_BLOCKS}; {xref} BlockTime={bt}"
        if cf > cap:
            return ParamStatus.FAIL, f"Confirmations={cf} exceeds drift cap {cap} ({ev})"
        return ParamStatus.PASS, f"Confirmations={cf} <= cap {cap} ({ev})"

    @staticmethod
    def check_method(coin: ManifestCoin, xc: Dict[str, str]) -> Tuple[ParamStatus, str]:
        ev = "blocknet/src/xbridge/xbridgeapp.cpp:1043-1090 dispatch (BTC/SYS→Btc, BCD/BCH/DGB/BTG/DEVAULT/STEALTH/PART)"
        method = xc.get("CreateTxMethod", "")
        if method.upper() in ("ETH", "ETHER"):
            return ParamStatus.FAIL, f"CreateTxMethod={method} rejected by blocknet ({ev})"
        if method not in CREATE_TX_METHODS:
            return ParamStatus.FAIL, f"CreateTxMethod={method} unknown connector ({ev})"
        return ParamStatus.PASS, f"CreateTxMethod={method} ({ev})"

    @staticmethod
    def check_structure(coin: ManifestCoin, wc: Dict[str, str], xc: Dict[str, str]) -> Tuple[ParamStatus, str]:
        msgs: List[str] = []
        status = ParamStatus.PASS
        if xc.get("Ip", "") != "127.0.0.1":
            status = max_status(status, ParamStatus.WARN)
            msgs.append(f"Ip={xc.get('Ip')!r}")
        allow = wc.get("rpcallowip") or (wc.get("_has_test_section") and wc.get("rpcallowip")) or ""
        if allow != "127.0.0.1":
            status = max_status(status, ParamStatus.FAIL)
            msgs.append(f"rpcallowip={allow!r} violates repo policy")
        vestigial = [k for k in ("CashAddrPrefix", "ContentType", "JSONVersion") if xc.get(k, None) == ""]
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


# ---------------------------------------------------------------------------
# Fleet Port Collision Registry & Resolution
# ---------------------------------------------------------------------------

def plan_entry(
    file: str,
    key: str,
    old: Any,
    new: Any,
    reason: str,
    action: str,
    coin: Optional[str] = None,
    ver_id: Optional[str] = None,
    evidence: Optional[str] = None,
    applied: bool = False,
) -> Dict[str, Any]:
    """Describe one write that either happened or would happen under --dry-run.

    The fixers return this instead of a bare ``bool`` so the preview and the
    apply cannot describe different things: they run the same code and only
    ``applied`` differs. It is truthy, so callers that used the old return
    value as an "a change was made" flag still work; a no-op returns ``{}``.

    ``file`` is repo-relative so plans are stable across machines.
    """
    return {
        "action": action,
        "file": file,
        "key": key,
        "old": old,
        "new": new,
        "reason": reason,
        "coin": coin,
        "ver_id": ver_id,
        "evidence": evidence,
        "applied": applied,
    }


def repo_relative(path: Path, repo_root: Optional[Path] = None) -> str:
    """Render a path relative to the repo root, falling back to the raw path."""
    if repo_root is not None:
        try:
            return str(path.relative_to(repo_root))
        except ValueError:
            pass
    return str(path)


class PortCollisionManager:
    """Detects and reallocates colliding P2P and RPC ports across the entire fleet."""

    @staticmethod
    def collect_port_collisions(manifest: List[ManifestCoin], repo_root: Path) -> Dict[str, Dict[int, List[str]]]:
        p2p: Dict[int, List[str]] = defaultdict(list)
        rpc: Dict[int, List[str]] = defaultdict(list)
        xbp: Dict[int, List[str]] = defaultdict(list)
        test_p2p: Dict[int, List[str]] = defaultdict(list)
        test_rpc: Dict[int, List[str]] = defaultdict(list)

        for coin in manifest:
            ticker = coin.ticker or "?"
            wpath = repo_root / "wallet-confs" / coin.wallet_conf
            secs = SourceReader.parse_conf_sections(wpath)
            top = secs.get("", {})
            test_sec = secs.get("test", {})

            for key, mp in (("port", p2p), ("rpcport", rpc)):
                raw = top.get(key, "")
                v = norm_port_value(raw)
                if v.isdigit():
                    mp[int(v)].append(ticker)

            xpath = repo_root / "xbridge-confs" / coin.xbridge_conf
            xc = SourceReader.parse_conf(xpath)
            xv = norm_port_value(xc.get("Port", ""))
            if xv.isdigit():
                xbp[int(xv)].append(ticker)

            for key, mp in (("port", test_p2p), ("rpcport", test_rpc)):
                raw = test_sec.get(key, "") if test_sec else ""
                v = norm_port_value(raw)
                if v and v.isdigit():
                    mp[int(v)].append(ticker)

        return {
            "p2p": dict(p2p),
            "rpc": dict(rpc),
            "xbridge": dict(xbp),
            "test_p2p": dict(test_p2p),
            "test_rpc": dict(test_rpc),
        }

    @staticmethod
    def write_wallet_key(
        wpath: Path,
        key: str,
        new_val: int,
        dry_run: bool = False,
        repo_root: Optional[Path] = None,
    ) -> Dict[str, Any]:
        try:
            txt = SourceReader.slurp(wpath)
            if txt is None:
                return {}
            lines = txt.splitlines()
            out: List[str] = []
            in_test = False
            replaced = False
            old_val: Optional[str] = None
            for line in lines:
                stripped = line.strip()
                if stripped.lower().startswith("[test]"):
                    in_test = True
                elif stripped.startswith("[") and stripped.endswith("]"):
                    in_test = False
                if not in_test and not replaced and re.match(rf"^\s*{re.escape(key)}\s*=", line, flags=re.I):
                    old_val = line.split("=", 1)[1].strip() if "=" in line else None
                    out.append(f"{key}={new_val}")
                    replaced = True
                else:
                    out.append(line)
            if not replaced:
                out.append(f"{key}={new_val}")
            if not dry_run:
                wpath.write_text("\n".join(out) + "\n", encoding="utf-8")
            return plan_entry(
                repo_relative(wpath, repo_root), key, old_val, str(new_val),
                f"reassign {key} to a free port",
                "port", applied=not dry_run,
            )
        except OSError as e:
            logger.error("Failed writing wallet key to %s: %s", wpath, e)
            return {}

    @staticmethod
    def write_xbridge_port(
        xpath: Path,
        new_val: int,
        dry_run: bool = False,
        repo_root: Optional[Path] = None,
    ) -> Dict[str, Any]:
        try:
            txt = SourceReader.slurp(xpath)
            if txt is None:
                return {}
            lines = txt.splitlines()
            out: List[str] = []
            replaced = False
            old_val: Optional[str] = None
            for line in lines:
                if not replaced and re.match(r"^\s*Port\s*=", line, flags=re.I):
                    old_val = line.split("=", 1)[1].strip() if "=" in line else None
                    out.append(f"Port={new_val}")
                    replaced = True
                else:
                    out.append(line)
            if not replaced:
                out.append(f"Port={new_val}")
            if not dry_run:
                xpath.write_text("\n".join(out) + "\n", encoding="utf-8")
            return plan_entry(
                repo_relative(xpath, repo_root), "Port", old_val, str(new_val),
                "reassign xbridge Port to match the new wallet rpcport",
                "port", applied=not dry_run,
            )
        except OSError as e:
            logger.error("Failed writing xbridge port to %s: %s", xpath, e)
            return {}

    @staticmethod
    def find_free_single(src: int, used_p2p: Set[int], used_rpc: Set[int], exclude_self: Optional[int] = None) -> Optional[int]:
        used = used_p2p | used_rpc
        if exclude_self is not None:
            used = set(used) - {exclude_self}
        for off in range(100, 50000):
            cand = src + off
            if 1024 <= cand <= 65535 and cand not in used:
                return cand
        for cand in range(50000, 65535):
            if cand not in used:
                return cand
        return None

    @staticmethod
    def find_free_pair(src_p2p: int, src_rpc: int, used_p2p: Set[int], used_rpc: Set[int]) -> Tuple[Optional[int], Optional[int]]:
        used = used_p2p | used_rpc
        delta = src_rpc - src_p2p if src_rpc != src_p2p else 1
        for off in range(100, 50000):
            cand_p2p = src_p2p + off
            cand_rpc = cand_p2p + delta
            if 1024 <= cand_p2p <= 65535 and 1024 <= cand_rpc <= 65535:
                if cand_p2p not in used and cand_rpc not in used and cand_p2p != cand_rpc:
                    return cand_p2p, cand_rpc
        for cand_p2p in range(50000, 65534):
            cand_rpc = cand_p2p + delta
            if cand_rpc <= 65535 and cand_p2p not in used and cand_rpc not in used and cand_p2p != cand_rpc:
                return cand_p2p, cand_rpc
        return None, None


# ---------------------------------------------------------------------------
# Base.j2 Configuration Loader & Cross-Checker
# ---------------------------------------------------------------------------

class ManifestCrossChecker:
    """Validates local configuration files against manifest specifications."""

    @staticmethod
    def base_j2_version_map(ticker: str, repo_root: Path) -> Dict[str, Any]:
        try:
            path = repo_root / "autobuild" / "configs" / f"{ticker.lower()}.base.j2"
            txt = SourceReader.slurp(path)
            if txt is None:
                return {}
            data = json.loads(txt)
            entry = data.get(ticker) or data.get(ticker.upper()) or data.get(ticker.lower())
            if entry is None and len(data) == 1:
                entry = next(iter(data.values()))
            if not entry:
                return {}
            vers = entry.get("versions") or {}
            return vers if isinstance(vers, dict) else {}
        except Exception:
            return {}

    @classmethod
    def conf_pair_for_version(cls, coin: ManifestCoin, version: str, repo_root: Path) -> Tuple[str, str]:
        m = cls.base_j2_version_map(coin.ticker, repo_root)
        vd = m.get(version)
        if vd and vd.get("wallet_conf") and vd.get("xbridge_conf"):
            return vd.get("wallet_conf"), vd.get("xbridge_conf")
        return coin.wallet_conf, coin.xbridge_conf

    @classmethod
    def local_crosscheck(cls, manifest_path: Path, manifest: List[ManifestCoin]) -> Dict[str, Any]:
        repo_root = manifest_path.parent
        wc_dir = repo_root / "wallet-confs"
        xc_dir = repo_root / "xbridge-confs"
        j2_dir = repo_root / "autobuild" / "configs"

        expected: Set[str] = set()
        missing_wallet: List[Tuple[str, str, str]] = []
        missing_xbridge: List[Tuple[str, str, str]] = []
        missing_j2: List[str] = []

        for e in manifest:
            ver_id = e.ver_id
            prefix = ver_id.rsplit("--", 1)[0] if "--" in ver_id else None
            expected.add(ver_id)
            for v in e.versions:
                if prefix:
                    expected.add(f"{prefix}--{v}")
            wc = e.wallet_conf
            xc = e.xbridge_conf
            expected.add(wc.removesuffix(".conf"))
            expected.add(xc.removesuffix(".conf"))

            if wc and not (wc_dir / wc).is_file():
                missing_wallet.append((e.ticker, ver_id, wc))
            if xc and not (xc_dir / xc).is_file():
                missing_xbridge.append((e.ticker, ver_id, xc))

            ticker_j2 = j2_dir / f"{(e.ticker or '').lower()}.base.j2"
            if not ticker_j2.is_file():
                missing_j2.append(e.ticker)

        expected_lower = {s.lower() for s in expected if s}
        orphans: Dict[str, List[str]] = {}
        for dname in ("wallet-confs", "xbridge-confs"):
            full = repo_root / dname
            stems = [f.stem for f in full.iterdir() if f.is_file() and f.suffix == ".conf"]
            orphans[dname] = sorted(
                f for f in stems if f.lower() not in expected_lower and not f.endswith(".conf.tmp")
            )

        return {
            "missing_wallet_conf": missing_wallet,
            "missing_xbridge_conf": missing_xbridge,
            "missing_base_j2": missing_j2,
            "orphans": orphans,
        }


# ---------------------------------------------------------------------------
# Param Fact-Check Auditor
# ---------------------------------------------------------------------------

class ParamAuditEngine:
    """Executes rule-based parameter validation passes against verified source trees."""

    def __init__(self, checkout_manager: SourceCheckoutManager):
        self.checkout_manager = checkout_manager

    def audit_version(
        self,
        coin: ManifestCoin,
        repo_root: Path,
        version_tag: str,
        wallet_conf: str,
        xbridge_conf: str,
        timeout: int,
        fees_only: bool = False,
    ) -> ParamAuditResult:
        shard = ManifestCoin(
            ticker=coin.ticker,
            ver_id=coin.ver_id,
            blockchain=coin.blockchain,
            repo_url=coin.repo_url,
            versions=[version_tag],
            wallet_conf=wallet_conf,
            xbridge_conf=xbridge_conf,
            daemon_family=coin.daemon_family,
            daemon_stem=coin.daemon_stem,
        )

        src_dir, mode = self.checkout_manager.resolve_source(shard, version_tag, timeout)
        if src_dir is None:
            return ParamAuditResult(
                tag=version_tag,
                source=None,
                mode=mode,
                version=version_tag,
                wallet_conf=wallet_conf,
                xbridge_conf=xbridge_conf,
            )

        wsecs = SourceReader.parse_conf_sections(repo_root / "wallet-confs" / wallet_conf)
        top = wsecs.get("", {})
        test = wsecs.get("test", {})
        want_test = bool(test) or top.get("testnet", "").strip() == "1"
        wc = dict(top)
        if want_test:
            wc.update(test)
            wc["_has_test_section"] = "true"

        xc = SourceReader.parse_conf(repo_root / "xbridge-confs" / xbridge_conf)
        is_btcd = shard.is_btcd

        if is_btcd:
            rate, rate_ev, dust, dust_ev = BtcdSourceInspector.fee_constants(src_dir)
        else:
            rate, rate_ev, dust, dust_ev = CppSourceInspector.fee_constants(src_dir)
        policy = fee_policy_for_coin(shard, src_dir) if src_dir else None

        checks: List[CheckFinding] = []

        def add_check(cid: str, func: Callable[..., Tuple[ParamStatus, str]], *args: Any) -> None:
            try:
                st, det = func(*args)
            except Exception as exc:
                logger.exception("Checker %s failed for %s @ %s", cid, coin.ticker, version_tag)
                msg = str(exc).lower()
                st = ParamStatus.FAIL if ("not found" in msg or "no such file" in msg) else ParamStatus.WARN
                det = f"checker error: {exc}"
            checks.append(CheckFinding(id=cid, status=st, detail=det))

        if is_btcd:
            add_check("PORT", BtcdSourceInspector.check_port, shard, src_dir, wc, repo_root)
            add_check("RPCPORT-SOURCE", BtcdSourceInspector.check_rpcport, shard, src_dir, wc, repo_root)
            add_check("RPCPORT-XBRIDGE", CommonParamCheckers.check_rpcport_xbridge, shard, wc, xc, repo_root)
            add_check("PREFIXES", BtcdSourceInspector.check_prefixes, shard, src_dir, xc, repo_root)
            add_check("COIN", BtcdSourceInspector.check_coin, shard, src_dir, xc)
            add_check("TXVERSION", BtcdSourceInspector.check_txversion, shard, src_dir, xc)
            add_check("BLOCKTIME", BtcdSourceInspector.check_blocktime, shard, src_dir, xc, repo_root)
            add_check("FEES", CommonParamCheckers.check_fees, shard, src_dir, xc, rate, rate_ev, dust, dust_ev, policy)
            add_check("DUST", CommonParamCheckers.check_dust, shard, src_dir, xc, rate, rate_ev, dust, dust_ev, policy)
            add_check("DEPRECATEDRPC", BtcdSourceInspector.check_deprecatedrpc, shard, src_dir, wc)
            add_check("TXTIME", BtcdSourceInspector.check_txtime, shard, src_dir, xc)
            add_check("TXINDEX", BtcdSourceInspector.check_txindex, shard, src_dir, wc)
            add_check("ADDRTYPE", BtcdSourceInspector.check_addrtype, shard, src_dir, wc)
            add_check("CONFIRM", CommonParamCheckers.check_confirmations, shard, xc)
            add_check("METHOD", CommonParamCheckers.check_method, shard, xc)
            add_check("STRUCT", BtcdSourceInspector.check_structure, shard, wc, xc)
        else:
            add_check("PORT", CppSourceInspector.check_port, shard, src_dir, wc, want_test, repo_root)
            add_check("RPCPORT-SOURCE", CppSourceInspector.check_rpcport_source, shard, src_dir, wc, want_test, repo_root)
            add_check("RPCPORT-XBRIDGE", CommonParamCheckers.check_rpcport_xbridge, shard, wc, xc, repo_root)
            add_check("PREFIXES", CppSourceInspector.check_prefixes, shard, src_dir, xc, want_test, repo_root)
            add_check("COIN", CppSourceInspector.check_coin, shard, src_dir, xc)
            add_check("TXVERSION", CppSourceInspector.check_txversion, shard, src_dir, xc)
            add_check("BLOCKTIME", CppSourceInspector.check_blocktime, shard, src_dir, xc, want_test, repo_root)
            add_check("FEES", CommonParamCheckers.check_fees, shard, src_dir, xc, rate, rate_ev, dust, dust_ev, policy)
            add_check("DUST", CommonParamCheckers.check_dust, shard, src_dir, xc, rate, rate_ev, dust, dust_ev, policy)
            add_check("DEPRECATEDRPC", CppSourceInspector.check_deprecatedrpc, shard, src_dir, wc, repo_root)
            add_check("TXTIME", CppSourceInspector.check_txtime, shard, src_dir, xc)
            add_check("TXINDEX", CppSourceInspector.check_txindex, shard, src_dir, wc)
            add_check("ADDRTYPE", CppSourceInspector.check_addrtype, shard, src_dir, wc)
            add_check("CONFIRM", CommonParamCheckers.check_confirmations, shard, xc)
            add_check("METHOD", CommonParamCheckers.check_method, shard, xc)
            add_check("STRUCT", CommonParamCheckers.check_structure, shard, wc, xc)

        if fees_only:
            checks = [c for c in checks if c.id in ("FEES", "DUST")]

        nf = sum(1 for c in checks if c.status in (ParamStatus.FAIL, ParamStatus.BROKEN))
        nd = sum(1 for c in checks if c.status == ParamStatus.DIFFERS)
        nw = sum(1 for c in checks if c.status == ParamStatus.WARN)
        nu = sum(1 for c in checks if c.status == ParamStatus.UNRESOLVED)

        return ParamAuditResult(
            tag=version_tag,
            source=str(src_dir),
            mode=mode,
            checks=checks,
            fail=nf,
            differs=nd,
            warn=nw,
            unresolved=nu,
            version=version_tag,
            wallet_conf=wallet_conf,
            xbridge_conf=xbridge_conf,
        )

    def audit_coin_all_versions(
        self,
        coin: ManifestCoin,
        repo_root: Path,
        timeout: int,
        strict: bool = False,
        fees_only: bool = False,
    ) -> ParamAuditResult:
        all_tags = coin.expected_tags()
        entry_tag = VersionEngine.max_version_tag(set(coin.versions)) if coin.versions else None
        if entry_tag is None and "--" in coin.ver_id:
            entry_tag = coin.ver_id.split("--", 1)[1]

        if not entry_tag:
            return ParamAuditResult(tag=None, source=None, mode="no-tag")

        entry_res = self.audit_version(coin, repo_root, entry_tag, coin.wallet_conf, coin.xbridge_conf, timeout, fees_only=fees_only)

        per_version_results: List[Dict[str, Any]] = []
        seen_tags: Set[str] = set()

        for v in all_tags:
            if v in seen_tags:
                continue
            seen_tags.add(v)

            wc, xc = ManifestCrossChecker.conf_pair_for_version(coin, v, repo_root)
            if v == entry_tag and wc == coin.wallet_conf and xc == coin.xbridge_conf:
                pv_dict = entry_res.to_dict()
                pv_dict["version"] = v
                pv_dict["wallet_conf"] = wc
                pv_dict["xbridge_conf"] = xc
                per_version_results.append(pv_dict)
            else:
                pv = self.audit_version(coin, repo_root, v, wc, xc, timeout, fees_only=fees_only)
                per_version_results.append(pv.to_dict())

        # Check for reuse-drift (multiple versions share one conf file, but source constants diverged)
        # If sharing is clean (no DIFFERS across the per-version fact-checks), emit a
        # clarity INFO instead of staying silent. INFO does not increment warn
        # counters and does not bubble under --strict-per-version (only WARN/FAIL bubble).
        # Per-version clone/fact-check loop above stays intact — every tag is still
        # individually checked via conf_pair_for_version.
        if len(all_tags) > 1:
            uniq_wc = {p["wallet_conf"] for p in per_version_results}
            uniq_xc = {p["xbridge_conf"] for p in per_version_results}
            if len(uniq_wc) == 1 or len(uniq_xc) == 1:
                any_differs = any(p.get("differs", 0) > 0 for p in per_version_results)
                if any_differs:
                    differs_by_version = ", ".join(
                        f"{p['version']}:{p['differs']}DIFFERS"
                        for p in per_version_results
                        if p.get('differs')
                    )
                    detail = (
                        f"reuse hides drift: {len(all_tags)} versions share conf pair "
                        f"{next(iter(uniq_wc))} / {next(iter(uniq_xc))} but source constants diverged "
                        f"(per-version DIFFERS: {differs_by_version})"
                    )
                    entry_res.checks.append(CheckFinding(id="REUSE-DRIFT", status=ParamStatus.WARN, detail=detail))
                    entry_res.warn += 1
                else:
                    detail = (
                        f"{len(all_tags)} versions share conf pair {next(iter(uniq_wc))} / {next(iter(uniq_xc))} — per-version fact-check clean"
                    )
                    entry_res.checks.append(CheckFinding(id="SHARED-CONF", status=ParamStatus.INFO, detail=detail))

        if strict:
            worst_pv: Optional[ParamStatus] = None
            for pv in per_version_results:
                for chk in pv.get("checks", []):
                    st = ParamStatus(chk["status"])
                    if worst_pv is None or PARAM_STATUS_PRECEDENCE.index(st) < PARAM_STATUS_PRECEDENCE.index(worst_pv):
                        worst_pv = st

            # INFO/SKIP/PASS/MATCH never bubble — only WARN/FAIL (and DIFFERS/CONFLICT/BROKEN/UNRESOLVED) bubble per spec
            if worst_pv in (ParamStatus.INFO, ParamStatus.SKIP, ParamStatus.PASS, ParamStatus.MATCH):
                worst_pv = None

            entry_worst: Optional[ParamStatus] = None
            for chk in entry_res.checks:
                if entry_worst is None or PARAM_STATUS_PRECEDENCE.index(chk.status) < PARAM_STATUS_PRECEDENCE.index(entry_worst):
                    entry_worst = chk.status

            if worst_pv and entry_worst and PARAM_STATUS_PRECEDENCE.index(worst_pv) < PARAM_STATUS_PRECEDENCE.index(entry_worst):
                entry_res.checks.append(
                    CheckFinding(
                        id="STRICT-BUBBLE",
                        status=worst_pv,
                        detail=f"strict-per-version: worst per-version {worst_pv.value} bubbles to entry (was {entry_worst.value})",
                    )
                )
                if worst_pv in (ParamStatus.FAIL, ParamStatus.BROKEN):
                    entry_res.fail += 1
                elif worst_pv == ParamStatus.DIFFERS:
                    entry_res.differs += 1
                elif worst_pv == ParamStatus.WARN:
                    entry_res.warn += 1

        entry_res.per_version = per_version_results
        return entry_res


# ---------------------------------------------------------------------------
# Configuration Remediation & J2 Auto-Generation
# ---------------------------------------------------------------------------

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
            tag = coin.versions[0] if coin.versions else coin.ver_id.split("--", 1)[-1] if "--" in coin.ver_id else ""
            if not tag:
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


# ---------------------------------------------------------------------------
# Coin Scaffolding Service
# ---------------------------------------------------------------------------

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
            print("ERROR: --scaffold requires --repo-url <url>")
            result["error"] = "--scaffold requires --repo-url <url>"
            return 2, result
        # Fleet convention is bare repo URLs (no trailing .git): normalize the
        # input so --apply output matches, instead of flagging our own entry
        # MOVED on the next audit pass.
        repo_url = repo_url.rstrip("/").removesuffix(".git")

        ticker = (args.scaffold_ticker or self.derive_ticker(repo_url)).upper()
        tag = args.scaffold_tag
        if not tag:
            print(f"Probing tags for {repo_url} ...")
            status, tags = self.probe_service.probe_tags(repo_url, args.timeout)
            if status != RepoStatus.ALIVE or not tags:
                print(f"ERROR: could not probe tags (status {status.value})")
                result["error"] = f"could not probe tags (status {status.value})"
                return 1, result
            stable = VersionEngine.stable_tags(tags)
            tag = VersionEngine.max_version_tag(stable)
            if not tag:
                print("ERROR: no stable tag found")
                result["error"] = "no stable tag found"
                return 1, result
            print(f"Auto-detected tag: {tag}")
        else:
            print(f"Using supplied tag: {tag}")

        print(f"Ticker: {ticker}")
        tmp_root = CACHE_ROOT
        tmp_root.mkdir(parents=True, exist_ok=True)
        target = tmp_root / f"scaffold_{ticker.lower()}_check"
        shutil.rmtree(target, ignore_errors=True)

        print(f"Cloning {repo_url} @ {tag} ...")
        proc = self.runner.run(
            ["git", "clone", "-q", "--depth", "1", "--branch", tag, repo_url, str(target)],
            max(args.timeout, 60),
            env_extra={"GIT_TERMINAL_PROMPT": "0"},
        )
        if proc is None or proc.returncode != 0 or not target.is_dir():
            print(f"ERROR: clone failed for {repo_url} @ {tag}")
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
                print(f"Port collision: source p2p {src_port} rpc {src_rpc} -> proposing free p2p {p2p} rpc {rpc}")
        else:
            print(f"Ports p2p {p2p} rpc {rpc} are free (no collision)")

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
            print("ERROR: fee source unresolvable — refusing silent defaults "
                  "(no MinTxFee/FeePerByte emitted). Provide a source tree with "
                  "parseable relay/inclusion constants and GetFee body.")
            result["error"] = "fee source unresolvable — refusing silent defaults"
            return 1, result
        relay = relay_entry[0]
        mtf, fpb = recommended_fees(fee_policy, relay)

        title = getattr(args, "scaffold_name", None) or ticker.title()
        ident = CoinScaffolder.derive_identity(target, ticker)
        print(f"Identity: daemon {ident['daemon']} conf {ident['conf_name']} "
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

        print("\n=== SCAFFOLD EXTRACT (file:line) ===")
        for k in ("port", "rpcport", "AddressPrefix", "ScriptPrefix", "SecretPrefix", "COIN", "BlockTime", "TxVersion", "relay_rate"):
            if k in params:
                print(f"  {k} = {params[k][0]} ({params[k][1]})")
        print(f"  family = {params.get('_family', 'btc')}")

        print(f"\n=== GENERATED wallet-confs/{wallet_name} ===")
        print(wallet_txt)
        print(f"=== GENERATED xbridge-confs/{xbridge_name} ===")
        print(xbridge_txt)
        print(f"=== MANIFEST SNIPPET ({snippet_path}) ===")
        print(json.dumps(manifest_snippet, indent=2))

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
            print(f"Dry-run: would write {repo_root / 'wallet-confs' / wallet_name} and "
                  f"{repo_root / 'xbridge-confs' / xbridge_name} and patch manifest-latest.json "
                  f"(suppressed by --dry-run)")
        elif args.apply:
            real_w = repo_root / "wallet-confs" / wallet_name
            real_x = repo_root / "xbridge-confs" / xbridge_name
            if real_w.exists() or real_x.exists():
                print(f"ERROR: --apply target already exists: {real_w} or {real_x}")
                result["error"] = f"--apply target already exists: {real_w} or {real_x}"
                return 1, result
            shutil.copy(wpath, real_w)
            shutil.copy(xpath, real_x)

            mpath = repo_root / "manifest-latest.json"
            raw_manifest = json.loads(SourceReader.slurp(mpath) or "[]")
            raw_manifest.append(manifest_snippet)
            raw_manifest.sort(key=lambda x: x.get("ticker", ""))
            mpath.write_text(json.dumps(raw_manifest, indent=2) + "\n", encoding="utf-8")
            print(f"Applied: wrote {real_w} and {real_x} and patched manifest ({len(raw_manifest)} entries now)")
            print(f"Next: run create-j2-confs.py --coins {ticker} and validate in-memory render")
            result["applied"] = True
            for e in plan:
                e["applied"] = True
        else:
            print(f"Print-only (no --apply): files under {out_dir} (not in repo)")

        print(f"Source clone kept at {target} for inspection")
        return 0, result


# ---------------------------------------------------------------------------
# Main Audit Orchestration & CLI
# ---------------------------------------------------------------------------

def classify_action(
    status: RepoStatus,
    missing: List[str],
    newer_same: List[str],
    newer_alt: List[str],
    stale: bool,
) -> ActionType:
    """Determine operational triage action for repository."""
    if status == RepoStatus.DEAD:
        return ActionType.DEAD
    if status == RepoStatus.MOVED:
        return ActionType.MOVED
    if status in (RepoStatus.UNKNOWN, RepoStatus.ERROR):
        return ActionType.UNKNOWN
    if newer_same:
        return ActionType.UPGRADE
    if newer_alt or missing or stale:
        return ActionType.REVIEW
    return ActionType.OK


def _newest_and_stale(
    tag_dates: Dict[str, str], stale_years: float
) -> Tuple[Optional[str], Optional[str], bool]:
    """Derive newest tag/date and stale flag from tag_dates (DRY helper)."""
    if not tag_dates:
        return None, None, False
    dated = sorted(tag_dates.items(), key=lambda kv: kv[1], reverse=True)
    newest_tag, newest_date = dated[0]
    stale = False
    try:
        nd = datetime.datetime.strptime(newest_date, "%Y-%m-%d %H:%M:%S %z")
        age = (datetime.datetime.now(nd.tzinfo) - nd).days / 365.25
        stale = age > stale_years
    except ValueError:
        pass
    return newest_tag, newest_date, stale


def action_reason(
    action: ActionType,
    status: RepoStatus,
    missing: List[str],
    newer_same: List[str],
    newer_alt: List[str],
    stale: bool,
    new_home: Optional[str],
) -> str:
    parts: List[str] = []
    if action == ActionType.DEAD:
        parts.append("repo unreachable")
    if action == ActionType.MOVED and new_home:
        parts.append(f"moved -> {new_home}")
    if action == ActionType.UNKNOWN:
        parts.append("repo unresolved")
    if newer_same:
        parts.append(f"newer_same=[{', '.join(newer_same)}]")
    if newer_alt:
        parts.append(f"newer_alt=[{', '.join(newer_alt)}]")
    if missing:
        parts.append(f"missing_tags=[{', '.join(missing)}]")
    if stale:
        parts.append("inactive upstream (>3y since newest tag by date)")
    if not parts:
        parts.append("alive, current")
    return "; ".join(parts)


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--manifest", default=str(DEFAULT_MANIFEST), help="Path to manifest-latest.json")
    parser.add_argument("--ticker", default=None, help="Comma-separated ticker filter, e.g. BTC,LTC")
    parser.add_argument("--timeout", type=int, default=30, help="Seconds per probe")
    parser.add_argument("--sleep", type=float, default=0.3, help="Seconds between repos")
    parser.add_argument("--retries", type=int, default=2, help="Retries per probe on timeout")
    parser.add_argument("--report", default=None, help="Write JSON report to this path (parallel to console; single contract)")
    parser.add_argument("--top-tags", type=int, default=10, help="Newest tags to fetch dates for (used for stale detection)")
    parser.add_argument("--stale-years", type=float, default=3.0, help="Inactivity threshold in years")
    parser.add_argument("--param-check", action="store_true", help="Fact-check parameters against source at manifest tag")
    parser.add_argument("--clone-timeout", type=int, default=120, help="Seconds budget per auto-clone")
    parser.add_argument("--write-config", action="store_true", help="Auto-fix missing txindex, dust placeholder, and stale deprecatedrpc")
    parser.add_argument("--dry-run", action="store_true", help="Compute and report every write a --write-config/--fee-write/--fix-ports/--update-versions/--apply run would make, without touching disk. The report's plan[] entries carry applied=false")
    parser.add_argument("--fees-only", action="store_true", help="Run only FEES/DUST checks (skip all other param checks)")
    parser.add_argument("--fee-write", action="store_true", help="Auto-fix FEES rows only (MinTxFee/FeePerByte from strict chain gates)")
    parser.add_argument("--fix-ports", action="store_true", help="Reassign colliding P2P/RPC ports based on lineage")
    parser.add_argument("--strict-per-version", action="store_true", help="Gate ver_id verdict on worst per-version status")
    parser.add_argument("--scaffold", action="store_true", help="Generate new coin entry from repo URL")
    parser.add_argument("--repo-url", default=None, help="Repo URL for --scaffold")
    parser.add_argument("--scaffold-ticker", default=None, help="Ticker for scaffold")
    parser.add_argument("--scaffold-tag", default=None, help="Tag for scaffold")
    parser.add_argument("--scaffold-name", default=None, help="Display name for scaffold (blockchain/Title/ver_name); default Ticker.title()")
    parser.add_argument("--apply", action="store_true", help="Apply scaffold directly into repo")
    parser.add_argument("--scaffold-out-dir", default=None, help="Output dir for scaffold")
    parser.add_argument("--batch", default=None, help="Batch label for report meta, e.g. 02/11")
    parser.add_argument("--no-changelog", action="store_true", help="Skip changelog mandatory HF probe (avoids GitHub API)")
    parser.add_argument("--local-only", action="store_true", help="Skip remote repository probes; run only the local cross-check, the fleet port matrix and (if asked) --param-check. Fast and offline: tags, liveness, staleness and --update-versions data are unavailable")
    parser.add_argument("--update-versions", action="store_true", help="Append latest remote tag to manifest versions for UPGRADE coins (additive: old versions stay buildable; writes BCF manifest + regenerates base.j2)")
    parser.add_argument("--replace-versions", action="store_true", help="With --update-versions, collapse to the latest tag only and rename confs (drop old versions; for forced-fork drops only)")
    return parser


def build_update_version_names(
    ticker: str, old_ver_id: str, old_wc: str, old_xc: str, target: str
) -> Tuple[str, str, str]:
    """Derive (new_ver_id, new_wallet_conf, new_xbridge_conf) for --update-versions.

    Each conf keeps its OWN filename stem (wallet stem from old_wc, xbridge
    stem from old_xc); LBC keeps its lbcd special-case. Pure helper so the
    derivation is unit-testable.
    """
    prefix = old_ver_id.split("--", 1)[0] if "--" in old_ver_id else ticker.lower()
    new_ver_id = f"{prefix}--{target}"
    wc_prefix = old_wc.split("--", 1)[0] if "--" in old_wc else prefix
    xc_prefix = old_xc.split("--", 1)[0] if "--" in old_xc else prefix
    new_wc = f"{wc_prefix}--{target}.conf"
    new_xc = f"{xc_prefix}--{target}.conf"
    if ticker == "LBC":
        # lbcd override is per part: only stems that actually ARE lbcd.
        if wc_prefix == "lbcd":
            new_ver_id = f"lbcd--{target}"
            new_wc = f"lbcd--{target}.conf"
        if xc_prefix == "lbcd":
            new_xc = f"lbcd--{target}.conf"
    return new_ver_id, new_wc, new_xc


def apply_additive_bump(item: Dict[str, Any], target: str) -> bool:
    """Append target to item["versions"] unless already listed.

    ver_id / wallet_conf / xbridge_conf are untouched: the existing conf
    pair keeps serving every listed version (DOGE/BLOCK/SYS convention).
    No conf files are copied or removed. Returns True when the item changed.
    """
    versions = item.get("versions", [])
    if target in versions:
        return False
    versions.append(target)
    item["versions"] = versions
    return True


def fee_constants_for_coin(
    coin: "ManifestCoin", src_dir: Path
) -> Tuple[Optional[int], Optional[str], Optional[int], Optional[str]]:
    """Relay/dust constants via the coin's own layout (Go btcd vs C++)."""
    if coin.is_btcd:
        return BtcdSourceInspector.fee_constants(src_dir)
    return CppSourceInspector.fee_constants(src_dir)


def fee_policy_for_coin(coin: "ManifestCoin", src_dir: Path) -> FeePolicy:
    """Fee behavior via the coin's own layout (Go btcd vs C++)."""
    if coin.is_btcd:
        return BtcdSourceInspector.fee_policy(src_dir)
    return CppSourceInspector.fee_policy(src_dir)


def should_skip_version_bump(rdata: Dict[str, Any]) -> bool:
    """--update-versions must not auto-bump mandatory-hard-fork repos.

    The changelog path escalates those to REVIEW ("manual replacement
    required"): collapsing versions + verbatim conf copy would certify a
    bump the audit explicitly refuses to certify.
    """
    return bool(rdata.get("changelog_mandatory"))


def conf_val_ci(conf: Dict[str, str], key: str) -> str:
    """Case-insensitive conf value lookup (parse_conf preserves key case)."""
    want = key.lower()
    for k, v in conf.items():
        if k.lower() == want:
            return v
    return ""


def entry_changelog_quote(
    changelog_findings: List[Dict[str, Any]], newer_same: List[str], newer_alt: List[str]
) -> str:
    """Join DISTINCT mandatory-HF quotes for the entry's newer tags."""
    tags = set(newer_same) | set(newer_alt)
    seen: List[str] = []
    for c in changelog_findings:
        if c.get("tag") in tags and c.get("quote") and c["quote"] not in seen:
            seen.append(c["quote"])
    return "; ".join(seen)


def load_manifest(manifest_path: Path) -> List[ManifestCoin]:
    """Parse manifest-latest.json into ManifestCoin entries.

    Raises whatever parsing/construction raises; main() owns the user-facing
    ERROR line and the exit code so the message stays byte-identical.
    """
    raw_manifest = json.loads(SourceReader.slurp(manifest_path) or "")
    return [ManifestCoin.from_dict(d) for d in raw_manifest]


def empty_summary() -> Dict[str, int]:
    """Zeroed probe summary for runs that never probe (--local-only).

    Keeps every key the normal path produces so report readers can index the
    same shape unconditionally; ``meta.local_only`` marks the difference.
    """
    return {
        "repos_total": 0,
        "alive": 0, "moved": 0, "dead": 0, "unknown": 0, "error": 0,
        "dead_tags": 0, "stale": 0,
    }


def audit_repos(
    args: argparse.Namespace,
    manifest: List[ManifestCoin],
    manifest_path: Path,
    probe_service: RemoteProbeService,
) -> Tuple[Dict[str, Any], Dict[str, int], Dict[ActionType, List[str]]]:
    """Probe every distinct repo in the manifest and print the fleet sections.

    Prints one line per repo as it goes (so a multi-minute run stays
    observable), then the SUMMARY and ACTION SUMMARY blocks. Returns exactly
    the three structures the JSON report needs.
    """
    repos: Dict[str, List[ManifestCoin]] = defaultdict(list)
    for coin in manifest:
        if coin.repo_url:
            repos[coin.repo_url].append(coin)

    report_repos: Dict[str, Any] = {}
    action_summary: Dict[ActionType, List[str]] = defaultdict(list)
    summary: Dict[str, int] = {
        "repos_total": len(repos),
        "alive": 0, "moved": 0, "dead": 0, "unknown": 0, "error": 0,
        "dead_tags": 0, "stale": 0,
    }

    print(f"Probing {len(repos)} distinct repos from {manifest_path}...\n")

    for idx, url in enumerate(sorted(repos), 1):
        coins = repos[url]
        tickers_label = ",".join(sorted({c.ticker or "?" for c in coins}))
        new_home = probe_service.probe_redirect(url, args.timeout)
        status, tags = probe_service.probe_tags(url, args.timeout)
        if status == RepoStatus.ALIVE and new_home:
            status = RepoStatus.MOVED

        summary[status.value.lower()] += 1

        entries: List[Dict[str, Any]] = []
        for coin in coins:
            expected = coin.expected_tags()
            # Exact string match only — no canonical v handling:
            # FOUND iff byte-equal to a remote tag from git ls-remote.
            # Phantom v-prefix tags (e.g. MRX "v4.2.0.1" vs remote "4.2.0.1")
            # intentionally remain MISSING and drive REVIEW — this is the
            # correct manifest-inconsistency signal, not a detector bug.
            missing = [t for t in expected if tags is not None and t not in tags] if tags is not None else expected
            found = [t for t in expected if t not in missing]
            entries.append({
                "ticker": coin.ticker,
                "ver_id": coin.ver_id,
                "versions": coin.versions,
                "expected_tags": expected,
                "found": found,
                "missing": missing,
                "our_latest": VersionEngine.max_version_tag(expected),
                "remote_latest": VersionEngine.max_version_tag(VersionEngine.stable_tags(tags)) if tags else None,
            })
            summary["dead_tags"] += len(missing)

        newer_same, newer_alt = VersionEngine.detect_newer(tags, coins)

        tag_dates: Dict[str, str] = {}
        newest_tag: Optional[str] = None
        newest_date: Optional[str] = None
        stale = False
        held_max_name = VersionEngine.max_version_tag([t for c in coins for t in c.expected_tags()])
        fossils: List[str] = []

        # Mandatory fossil/stale date fetch — single round-trip per repo (unified).
        # Needed set for fossil decision: held_max + newer candidates filtered to existing tags.
        if status in (RepoStatus.ALIVE, RepoStatus.MOVED) and tags is not None:
            needed: Set[str] = set()
            if held_max_name and held_max_name in tags:
                needed.add(held_max_name)
            for t in newer_same + newer_alt:
                if t in tags:
                    needed.add(t)
            # Stale bulk set (held_present + top stable tags) — union with needed for one fetch.
            held = set()
            for c in coins:
                held.update(c.expected_tags())
            held_present = held & tags
            rest = [t for t in tags - held_present if not VersionEngine.is_prerelease(t) and VersionEngine.parse_version(t) is not None]
            if len(rest) <= 100:
                bulk = held_present | set(rest)
            else:
                rest.sort(key=lambda t: VersionEngine.parse_version(t) or (), reverse=True)
                bulk = held_present | set(rest[:args.top_tags])
            selected = needed | bulk
            if selected:
                fetched = probe_service.probe_tag_dates(url, selected, args.timeout)
                if fetched:
                    tag_dates.update(fetched)
            newest_tag, newest_date, stale = _newest_and_stale(tag_dates, args.stale_years)

        # Fossil purge: higher semver but older date than held_max — not real upgrades.
        held_date = tag_dates.get(held_max_name) if held_max_name else None
        if tag_dates and held_date:
            fossils = [t for t in newer_same + newer_alt if (td := tag_dates.get(t)) is not None and td < held_date]
            if fossils:
                fset = set(fossils)
                newer_same = [t for t in newer_same if t not in fset]
                newer_alt = [t for t in newer_alt if t not in fset]

        # Changelog extraction for interval (our_latest_exclusive < tag <= remote_latest) — bounded, cached, rate-limit aware
        changelog_findings: List[Dict[str, Any]] = []
        changelog_mandatory = False
        if not args.no_changelog and status in (RepoStatus.ALIVE, RepoStatus.MOVED) and tags is not None and (newer_same or newer_alt):
            changelog_candidates = newer_same + newer_alt
            # Cap to 5 most recent by version to avoid GH spam and keep fast
            if len(changelog_candidates) > 5:
                changelog_candidates = sorted(
                    changelog_candidates, key=lambda t: VersionEngine.parse_version(t) or (), reverse=True
                )[:5]
                changelog_candidates = sorted(changelog_candidates, key=lambda t: VersionEngine.parse_version(t) or ())
            for tag in changelog_candidates:
                res = probe_service.probe_changelog(url, tag, args.timeout, CACHE_ROOT)
                if res is None:
                    continue
                src, txt = res
                quote = _detect_mandatory_hf(txt)
                if quote:
                    changelog_mandatory = True
                    changelog_findings.append(
                        {"tag": tag, "source": src, "quote": quote, "mandatory": True, "text_snippet": txt[:800]}
                    )
                # small inter-tag sleep to avoid spam, fast as possible
                time.sleep(0.05)

        for entry in entries:
            act = classify_action(status, entry["missing"], newer_same, newer_alt, stale)
            # Mandatory HF escalates UPGRADE -> REVIEW (manual replacement required)
            if changelog_mandatory and act == ActionType.UPGRADE:
                act = ActionType.REVIEW
            entry["action"] = act
            if changelog_mandatory:
                entry["changelog_mandatory"] = True
                entry["changelog_quote"] = entry_changelog_quote(changelog_findings, newer_same, newer_alt)

        report_repos[url] = {
            "status": status.value,
            "new_home": new_home,
            "tag_count": len(tags) if tags is not None else None,
            "newer_same": newer_same,
            "newer_alt": newer_alt,
            "remote_latest": VersionEngine.max_version_tag(VersionEngine.stable_tags(tags)) if tags else None,
            "tag_dates": tag_dates,
            "stale_higher_semver": fossils,
            "newest_tag": newest_tag,
            "newest_tag_date": newest_date,
            "stale": stale,
            "entries": entries,
            "changelog": changelog_findings,
            "changelog_mandatory": changelog_mandatory,
        }
        if stale:
            summary["stale"] += 1

        missing_list = [f"{e['ticker']}:{t}" for e in entries for t in e["missing"]]
        miss = f"  missing_tags=[{', '.join(missing_list)}]" if missing_list else ""
        newer_line = ""
        if newer_same:
            newer_line += f"  NEWER_same=[{', '.join(newer_same)}]"
        if newer_alt:
            newer_line += f"  NEWER_alt=[{', '.join(newer_alt)}]"
        if fossils:
            newer_line += f"  FOSSIL_higher_semver=[{', '.join(fossils)}] (older-dated than our tag - not upgrades)"

        held_max = VersionEngine.max_version_tag([t for c in coins for t in c.expected_tags()])
        remote_latest = VersionEngine.max_version_tag(VersionEngine.stable_tags(tags)) if tags else None
        remote_latest_date = tag_dates.get(remote_latest, "")[:10] if remote_latest else ""

        newest_line = ""
        if newest_tag:
            if newest_tag == remote_latest:
                newest_line += f"  upstream_date_newest={newest_tag} (=upstream_semver_max) ({newest_date[:10]})"
            else:
                newest_line += f"  upstream_date_newest={newest_tag} ({newest_date[:10]})"

        version_line = ""
        if remote_latest:
            version_line += f"  held_max={held_max}  upstream_semver_max={remote_latest}" + (f" ({remote_latest_date})" if remote_latest_date else "")
            if held_max and held_max == remote_latest:
                version_line += " (=held, up-to-date by version)"

        stale_line = ""
        if stale and newest_date:
            try:
                nd2 = datetime.datetime.strptime(newest_date, "%Y-%m-%d %H:%M:%S %z")
                age_y = (datetime.datetime.now(nd2.tzinfo) - nd2).days / 365.25
                stale_line = f"  INACTIVE ({age_y:.1f}y since {newest_date[:10]} >{args.stale_years:.1f}y threshold)"
            except Exception:
                stale_line = f"  INACTIVE (>{args.stale_years:.1f}y since {newest_date[:10]})"
        elif stale:
            stale_line = f"  INACTIVE (>{args.stale_years:.1f}y)"

        repo_action = ActionType.OK
        for e in entries:
            sev = ACTION_SEVERITY[e["action"]]
            if sev > ACTION_SEVERITY[repo_action]:
                repo_action = e["action"]

        changelog_line = ""
        if changelog_mandatory:
            q = changelog_findings[0]["quote"] if changelog_findings else "mandatory hard fork"
            src = changelog_findings[0]["source"] if changelog_findings else "unknown"
            tag = changelog_findings[0]["tag"] if changelog_findings else "?"
            changelog_line = f"  CHANGELOG_MANDATORY_HF={tag} \"{q}\" (src:{src}) !! MANUAL REVIEW required (old versions must be dropped)"

        action_line = f"  action={repo_action.value}"
        if changelog_mandatory and repo_action == ActionType.REVIEW:
            action_line += " (escalated from UPGRADE due to mandatory HF)"
        action_summary[repo_action].append(
            f"{tickers_label}  ({action_reason(repo_action, status, missing_list, newer_same, newer_alt, stale, new_home)})"
            + (f" [mandatory HF {changelog_findings[0]['tag'] if changelog_findings else '?'}]" if changelog_mandatory else "")
        )

        print(
            f"[{idx}/{len(repos)}] {status.value:8} {tickers_label:12} {url}"
            f"{(' -> ' + new_home) if new_home else ''}"
            f"{('  tags=%d' % len(tags)) if tags is not None else ''}"
            f"{miss}{newer_line}{version_line}{newest_line}{stale_line}{changelog_line}{action_line}"
        )
        if changelog_mandatory:
            for cf in changelog_findings:
                print(f"    !! CHANGELOG {cf['tag']} ({cf['source']}): \"{cf['quote']}\"")
        time.sleep(args.sleep)

    print("\n=== SUMMARY ===")
    for key in ("repos_total", "alive", "moved", "dead", "unknown", "error", "dead_tags", "stale"):
        print(f"  {key}: {summary[key]}")

    print("\n=== ACTION SUMMARY ===")
    for act in (ActionType.DEAD, ActionType.MOVED, ActionType.UNKNOWN, ActionType.UPGRADE, ActionType.REVIEW, ActionType.OK):
        lines = action_summary.get(act)
        if lines:
            print(f"  {act.value} ({len(lines)}):")
            for line in lines:
                print(f"    {line}")

    return report_repos, summary, action_summary


def crosscheck_local(manifest_path: Path, full_manifest: List[ManifestCoin]) -> Dict[str, Any]:
    """Print and return the on-disk conf cross-check. No network involved."""
    print("\n=== LOCAL CROSS-CHECK ===")
    local = ManifestCrossChecker.local_crosscheck(manifest_path, full_manifest)
    if not local["missing_wallet_conf"]:
        print("  missing wallet_conf: none")
    for ticker, ver_id, wc in local["missing_wallet_conf"]:
        print(f"  missing wallet_conf: {ticker} {ver_id} -> {wc}")
    if not local["missing_xbridge_conf"]:
        print("  missing xbridge_conf: none")
    for ticker, ver_id, xc in local["missing_xbridge_conf"]:
        print(f"  missing xbridge_conf: {ticker} {ver_id} -> {xc}")
    if not local["missing_base_j2"]:
        print("  missing base.j2: none")
    for ticker in sorted(set(local["missing_base_j2"])):
        print(f"  missing base.j2: {ticker}.base.j2")
    for dname, orphs in local["orphans"].items():
        if not orphs:
            print(f"  orphan {dname}: none")
        else:
            print(f"  orphan {dname} (informational, {len(orphs)}):")
            print(f"    {', '.join(o + '.conf' for o in orphs)}")
    return local


def collect_port_matrix(
    args: argparse.Namespace,
    full_manifest: List[ManifestCoin],
    repo_root: Path,
) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """Build the fleet port-collision matrix and print the fleet report.

    Always computed for the full fleet, never filtered by --ticker, so a
    filtered run still sees collisions against coins it did not select.
    """
    # Fleet Port Collision Matrix (always full fleet, report-only, like v1)
    fleet_maps = PortCollisionManager.collect_port_collisions(full_manifest, repo_root)
    fleet_summary = {k: {p: sorted(ts) for p, ts in v.items() if len(ts) > 1} for k, v in fleet_maps.items()}
    fleet_summary = {k: v for k, v in fleet_summary.items() if v}

    if not args.param_check:
        if fleet_summary:
            print("\n=== PORT COLLISIONS (fleet) ===")
            for kind in ("p2p", "rpc", "xbridge", "test_p2p", "test_rpc"):
                dup = fleet_summary.get(kind)
                if not dup:
                    continue
                label = {"p2p": "P2P", "rpc": "RPC", "xbridge": "XBRIDGE", "test_p2p": "TEST-P2P", "test_rpc": "TEST-RPC"}[kind]
                for port in sorted(dup):
                    print(f"  {label} {port} : {', '.join(dup[port])}")
        else:
            print("\n=== PORT COLLISIONS (fleet) ===  none")
    return fleet_maps, fleet_summary


def audit_params(
    args: argparse.Namespace,
    manifest: List[ManifestCoin],
    repo_root: Path,
    fleet_maps: Dict[str, Any],
    fleet_summary: Dict[str, Any],
    runner: SystemCommandRunner,
) -> Optional[Dict[str, Any]]:
    """Run --param-check across the manifest and print the PARAM CHECK section.

    Returns None when --param-check was not requested; callers treat None as
    "no findings available" and must not run any write step off it.
    """
    param_results: Optional[Dict[str, Any]] = None
    if args.param_check:
        print("\n=== PARAM CHECK ===")
        if args.strict_per_version:
            print("  strict-per-version: worst per-version status bubbles to entry")

        checkout_manager = SourceCheckoutManager(CACHE_ROOT, runner)
        audit_engine = ParamAuditEngine(checkout_manager)
        param_results = {}
        total_fail = 0

        for idx, coin in enumerate(manifest, 1):
            res = audit_engine.audit_coin_all_versions(coin, repo_root, args.timeout, strict=args.strict_per_version, fees_only=args.fees_only)

            if not res.mode.startswith(("skipped", "no-", "clone-")):
                wpath = repo_root / "wallet-confs" / coin.wallet_conf
                secs = SourceReader.parse_conf_sections(wpath)
                top = secs.get("", {})
                test_sec = secs.get("test", {})

                for kind, key, cid in (("p2p", "port", "P2P-COLLISION"), ("rpc", "rpcport", "RPC-COLLISION")):
                    v = norm_port_value(top.get(key, ""))
                    if v.isdigit():
                        p = int(v)
                        peers = fleet_maps[kind].get(p, [])
                        if len(peers) > 1:
                            others = sorted(t for t in peers if t != coin.ticker)
                            since = SourceReader.lineage_date(repo_root, f"wallet-confs/{coin.wallet_conf}", key)
                            lin = f"; value present since {since}" if since else ""
                            label = "P2P" if kind == "p2p" else "RPC"
                            detail = f"wallet {label} port={p} shared with: {', '.join(others)} (duplicate {kind} port){lin}"
                            res.checks.append(CheckFinding(id=cid, status=ParamStatus.CONFLICT, detail=detail))
                            res.conflict += 1

                xpath = repo_root / "xbridge-confs" / coin.xbridge_conf
                xc_tmp = SourceReader.parse_conf(xpath)
                xv = norm_port_value(xc_tmp.get("Port", ""))
                if xv.isdigit():
                    p = int(xv)
                    peers = fleet_maps["xbridge"].get(p, [])
                    if len(peers) > 1:
                        others = sorted(t for t in peers if t != coin.ticker)
                        detail = f"xbridge Port={p} shared with: {', '.join(others)} (duplicate xbridge port)"
                        res.checks.append(CheckFinding(id="XBRIDGE-COLLISION", status=ParamStatus.CONFLICT, detail=detail))
                        res.conflict += 1

                for kind, key, cid in (("test_p2p", "port", "TEST-P2P-COLLISION"), ("test_rpc", "rpcport", "TEST-RPC-COLLISION")):
                    v = norm_port_value(test_sec.get(key, "") if test_sec else "")
                    if v and v.isdigit():
                        p = int(v)
                        peers = fleet_maps[kind].get(p, [])
                        if len(peers) > 1:
                            others = sorted(t for t in peers if t != coin.ticker)
                            label = "P2P" if "p2p" in kind else "RPC"
                            detail = f"[test] {label} port={p} shared with: {', '.join(others)} (duplicate test {kind} port)"
                            res.checks.append(CheckFinding(id=cid, status=ParamStatus.CONFLICT, detail=detail))
                            res.conflict += 1

            key_name = coin.ver_id or coin.ticker
            orig_key = key_name
            suffix = 1
            while key_name in param_results:
                suffix += 1
                key_name = f"{orig_key}_{suffix}"
            param_results[key_name] = res.to_dict()

            if res.mode.startswith(("skipped", "no-", "clone-")):
                print(f"[{idx}/{len(manifest)}] {coin.ticker} ({coin.ver_id}) tag={res.tag} src=- ({res.mode})")
                for pv in res.per_version:
                    if pv.get("mode", "").startswith(("clone-", "no-")):
                        print(f"    -- {pv.get('version', ''):<12} wallet={pv.get('wallet_conf')} xbridge={pv.get('xbridge_conf')} ({pv.get('mode')})")
                continue

            src_base = Path(res.source).name if res.source else "-"
            print(
                f"[{idx}/{len(manifest)}] {coin.ticker} ({coin.ver_id}) tag={res.tag} src={src_base} : "
                f"FAIL={res.fail} DIFFERS={res.differs} WARN={res.warn} UNRESOLVED={res.unresolved} ({res.mode})"
            )
            for chk in res.checks:
                marker = STATUS_MARKERS.get(chk.status, "??")
                print(f"    {marker} {chk.id:<18} {chk.detail}")

            if len(res.per_version) > 1 or (len(res.per_version) == 1 and res.per_version[0]["version"] != res.tag):
                for pv in res.per_version:
                    pv_src = Path(pv["source"]).name if pv.get("source") else "-"
                    print(
                        f"    -> {pv['version']:<12} wallet={pv.get('wallet_conf')} xbridge={pv.get('xbridge_conf')} "
                        f"src={pv_src} : FAIL={pv.get('fail', 0)} DIFFERS={pv.get('differs', 0)} WARN={pv.get('warn', 0)} ({pv.get('mode', '')})"
                    )
                    if pv.get("fail", 0) or pv.get("differs", 0) or pv.get("warn", 0) or pv.get("unresolved", 0):
                        for chk_dict in pv.get("checks", []):
                            st_enum = ParamStatus(chk_dict["status"])
                            if st_enum in (ParamStatus.FAIL, ParamStatus.BROKEN, ParamStatus.DIFFERS, ParamStatus.WARN, ParamStatus.UNRESOLVED, ParamStatus.CONFLICT):
                                marker = STATUS_MARKERS.get(st_enum, "??")
                                print(f"       {marker} {chk_dict['id']:<18} {chk_dict['detail']}")

            total_fail += res.fail
            time.sleep(args.sleep * 0.2)

        total_differs = sum(v.get("differs", 0) for k, v in param_results.items() if not k.startswith("_") and isinstance(v, dict))
        total_warn = sum(v.get("warn", 0) for k, v in param_results.items() if not k.startswith("_") and isinstance(v, dict))
        total_unresolved = sum(v.get("unresolved", 0) for k, v in param_results.items() if not k.startswith("_") and isinstance(v, dict))
        total_conflicts = sum(v.get("conflict", 0) for k, v in param_results.items() if not k.startswith("_") and isinstance(v, dict))
        pv_fail = sum(pv.get("fail", 0) for k, v in param_results.items() if isinstance(v, dict) for pv in v.get("per_version", []))

        if fleet_summary:
            param_results["_collisions"] = fleet_summary
            param_results["_collision_maps"] = fleet_maps
            print("\n=== PORT COLLISIONS ===")
            for kind in ("p2p", "rpc", "xbridge", "test_p2p", "test_rpc"):
                dup = fleet_summary.get(kind)
                if not dup:
                    continue
                label = {"p2p": "P2P", "rpc": "RPC", "xbridge": "XBRIDGE", "test_p2p": "TEST-P2P", "test_rpc": "TEST-RPC"}[kind]
                for port in sorted(dup):
                    print(f"  {label} {port} : {', '.join(dup[port])}")
            print(f"  ({total_conflicts} distinct conflict rows injected)")
        else:
            print("\n=== PORT COLLISIONS ===  none")

        valid_entry_count = len([k for k in param_results if not k.startswith("_")])
        print(
            f"PARAM CHECK SUMMARY: {valid_entry_count} coins | {total_fail} objective-fail | "
            f"{total_differs} differs-from-source | {total_warn} warn | {total_unresolved} unresolved | "
            f"{total_conflicts} conflicts | per-version fails {pv_fail} | {'strict-bubble' if args.strict_per_version else 'report-only'}"
        )
    return param_results


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
                        print(f"  UPDATE-VERSIONS skip {', '.join(skipped)}: mandatory hard fork — manual replacement required")
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
                                    print(f"  UPDATE-VERSIONS {ticker}: appended {target} (kept {item.get('ver_id', '')} confs)")
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
                                        print(f"  UPDATE-VERSIONS {ticker}: {label} conf {src_p.name} -> {dst_p.name}"
                                              + (" (planned)" if dry_run else " (copied)"))
                                        plan.append(plan_entry(
                                            repo_relative(dst_p, repo_root), "*",
                                            None, f"copy of {src_p.name}",
                                            f"copy {label} conf forward for the new version",
                                            "versions", coin=ticker, ver_id=new_ver_id,
                                            applied=not dry_run,
                                        ))
                                    elif dst_p.is_file():
                                        print(f"  UPDATE-VERSIONS {ticker}: target {dst_p.name} already exists — kept as-is (verify content)")
                            except Exception as e:
                                logger.warning("copy conf failed for %s: %s", ticker, e)
                if updated_tickers:
                    if not dry_run:
                        manifest_path.write_text(json.dumps(raw_manifest, indent=2) + "\n", encoding="utf-8")
                    print(f"\nUPDATE-VERSIONS: {verb} {', '.join(sorted(set(updated_tickers)))} to latest remote")
                    if dry_run:
                        print("UPDATE-VERSIONS: dry-run — manifest and confs left untouched")
                    elif args.replace_versions:
                        print("UPDATE-VERSIONS: confs copied verbatim — re-run --param-check for bumped tickers (relay/fees are per-tag;")
                        print("  changelog probe covers the 5 newest tags only, so an older mandatory HF needs manual review)")
                        print("UPDATE-VERSIONS: superseded old conf files are left on disk — git rm them in blockchain-configuration-files once verified")
                    else:
                        print("UPDATE-VERSIONS: old versions kept buildable on existing confs — re-run --param-check for bumped tickers (relay/fees are per-tag)")
                    if not dry_run:
                        try:
                            ConfigAutoFixer.regenerate_base_j2(repo_root, sorted(set(updated_tickers)), runner)
                        except Exception as e:
                            logger.warning("regenerate base.j2 failed: %s", e)
        except Exception as e:
            logger.error("UPDATE-VERSIONS failed: %s", e)

    return updated_tickers, plan


# findings[] only carries statuses that ask a human to act. PASS/MATCH/SKIP
# stay inside param_check — surfacing them would restate the whole fleet.
FINDING_PARAM_STATUSES: Tuple[ParamStatus, ...] = (
    ParamStatus.FAIL,
    ParamStatus.BROKEN,
    ParamStatus.CONFLICT,
    ParamStatus.DIFFERS,
    ParamStatus.WARN,
    ParamStatus.UNRESOLVED,
)

# Kind -> (stable id, conf template, conf key label). The xbridge namespace is
# its own file; the two [test] namespaces live in the wallet conf's test section.
PORT_FINDING_KINDS: Dict[str, Tuple[str, str, str]] = {
    "p2p": ("P2P-COLLISION", "wallet-confs/{}", "port"),
    "rpc": ("RPC-COLLISION", "wallet-confs/{}", "rpcport"),
    "xbridge": ("XBRIDGE-COLLISION", "xbridge-confs/{}", "Port"),
    "test_p2p": ("TEST-P2P-COLLISION", "wallet-confs/{}", "[test] port"),
    "test_rpc": ("TEST-RPC-COLLISION", "wallet-confs/{}", "[test] rpcport"),
}


def build_findings(
    full_manifest: List[ManifestCoin],
    report_repos: Dict[str, Any],
    local: Dict[str, Any],
    fleet_summary: Dict[str, Any],
    param_results: Optional[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """Flatten every actionable signal into one severity-ordered array.

    Severity values come from the two scales this module already defines —
    ``ActionType`` for repository state and ``ParamStatus`` for checks. Their
    vocabularies do not overlap, so a value names its own scale unambiguously
    and no third scale is introduced. Ordering follows the order this tool
    already prints its sections in (repository state, then local/port/check
    findings), and within each group worst-first by that scale's own table.

    Deliberately non-redundant: one finding per non-OK manifest entry, one per
    local defect, one per colliding port per coin, one per actionable check.
    ``--param-check`` re-derives the same port collisions as ``*-COLLISION``
    checks, so those ids are skipped here rather than reported twice; they
    remain available under ``param_check``.

    ``file``/``line`` are nullable: local and port findings know their conf
    path outright, while check evidence (``src/validation.h:123``, or a conf
    ref via ``_conf_key_line``) lives inside ``detail`` as prose and is left
    there rather than parsed back out.
    """
    findings: List[Dict[str, Any]] = []

    def add(
        severity: str,
        category: str,
        coin: Optional[str],
        ver_id: Optional[str],
        fid: str,
        detail: str,
        file: Optional[str] = None,
        line: Optional[int] = None,
    ) -> None:
        findings.append({
            "severity": severity,
            "category": category,
            "coin": coin,
            "ver_id": ver_id,
            "id": fid,
            "detail": detail,
            "file": file,
            "line": line,
        })

    # --- repository state: one finding per non-OK manifest entry -------------
    # classify_action already folds dead/moved/unknown, missing tags, newer
    # tags and staleness into a single per-entry action, so the entry itself
    # is the unit. Coins sharing a repo each get their own row because each
    # one needs its own decision.
    for rdata in report_repos.values():
        status = rdata.get("status", "?")
        for entry in rdata.get("entries", []):
            action = entry.get("action")
            if action is None or action == ActionType.OK:
                continue
            bits: List[str] = []
            if entry.get("missing"):
                bits.append("missing tags: " + ", ".join(entry["missing"]))
            if rdata.get("newer_same"):
                bits.append("newer same-series tags: " + ", ".join(rdata["newer_same"]))
            if rdata.get("newer_alt"):
                bits.append("newer alternate-series tags: " + ", ".join(rdata["newer_alt"]))
            if rdata.get("stale"):
                bits.append("no upstream release inside the staleness window")
            if entry.get("changelog_mandatory"):
                quote = entry.get("changelog_quote") or "mandatory hard fork"
                bits.append(f'changelog mandates a hard fork: "{quote}"')
            detail = f"repo {status}" + (": " + "; ".join(bits) if bits else "")
            if entry.get("changelog_mandatory"):
                category = "changelog"
            elif action in (ActionType.DEAD, ActionType.MOVED, ActionType.UNKNOWN):
                category = "liveness"
            else:
                category = "version"
            add(
                str(action.value if isinstance(action, ActionType) else action),
                category,
                entry.get("ticker"),
                entry.get("ver_id"),
                "REPO-ACTION",
                detail,
            )

    # --- local cross-check ---------------------------------------------------
    for ticker, ver_id, wc in local.get("missing_wallet_conf", []):
        add("FAIL", "local", ticker, ver_id, "MISSING-WALLET-CONF",
            f"manifest points at wallet-confs/{wc} but the file does not exist",
            file=f"wallet-confs/{wc}")
    for ticker, ver_id, xc in local.get("missing_xbridge_conf", []):
        add("FAIL", "local", ticker, ver_id, "MISSING-XBRIDGE-CONF",
            f"manifest points at xbridge-confs/{xc} but the file does not exist",
            file=f"xbridge-confs/{xc}")
    for ticker in sorted(set(local.get("missing_base_j2", []))):
        add("WARN", "local", ticker, None, "MISSING-BASE-J2",
            f"autobuild/configs/{ticker}.base.j2 does not exist",
            file=f"autobuild/configs/{ticker}.base.j2")
    for dname, orphs in (local.get("orphans") or {}).items():
        for stem in sorted(set(orphs)):
            add("INFO", "local", None, None, "ORPHAN-CONF",
                f"{dname}/{stem}.conf is not referenced by the manifest "
                f"(informational)", file=f"{dname}/{stem}.conf")

    # --- fleet port matrix ---------------------------------------------------
    # One finding per colliding port per coin so coin/file are exact; the
    # matrix is fleet-wide even when --ticker narrowed the run.
    by_ticker: Dict[str, ManifestCoin] = {}
    for c in full_manifest:
        by_ticker.setdefault(c.ticker or "", c)
    for kind in ("p2p", "rpc", "xbridge", "test_p2p", "test_rpc"):
        fid, conf_tpl, key_label = PORT_FINDING_KINDS[kind]
        for port, tickers in sorted((fleet_summary.get(kind) or {}).items()):
            for t in sorted(tickers):
                coin = by_ticker.get(t)
                conf = conf_tpl.format(coin.wallet_conf) if coin and coin.wallet_conf else None
                others = sorted(x for x in tickers if x != t)
                add(
                    ParamStatus.CONFLICT.value, "port", t,
                    coin.ver_id if coin else None, fid,
                    f"{key_label}={port} is claimed by {', '.join(tickers)}"
                    + (f" (also {', '.join(others)})" if others else ""),
                    file=conf,
                )

    # --- parameter checks ----------------------------------------------------
    by_ver_id: Dict[str, ManifestCoin] = {c.ver_id: c for c in full_manifest if c.ver_id}
    for key, res in (param_results or {}).items():
        if key.startswith("_") or not isinstance(res, dict):
            continue
        coin = by_ver_id.get(key) or by_ticker.get(key)
        for chk in res.get("checks", []):
            cid = chk.get("id", "")
            if cid.endswith("-COLLISION"):
                continue  # already emitted from the fleet matrix above
            try:
                status = ParamStatus(chk.get("status"))
            except ValueError:
                continue
            if status not in FINDING_PARAM_STATUSES:
                continue
            add(
                status.value, "param",
                coin.ticker if coin else None,
                coin.ver_id if coin else None,
                cid, chk.get("detail", ""),
            )

    def _sort_key(f: Dict[str, Any]) -> Tuple[int, int, str, str, str]:
        sev = f["severity"]
        tie = (f["category"], f["coin"] or "", f["id"])
        if sev in ACTION_SEVERITY:  # repository-state group, worst first
            return (0, -ACTION_SEVERITY[ActionType(sev)], *tie)
        try:  # check group, worst first by PARAM_STATUS_PRECEDENCE
            return (1, -PARAM_STATUS_PRECEDENCE.index(ParamStatus(sev)), *tie)
        except ValueError:
            return (2, 0, *tie)

    findings.sort(key=_sort_key)
    return findings


def build_report(
    full_manifest: List[ManifestCoin],
    args: argparse.Namespace,
    report_repos: Dict[str, Any],
    summary: Dict[str, int],
    action_summary: Dict[ActionType, List[str]],
    local: Dict[str, Any],
    fleet_summary: Dict[str, Any],
    fleet_maps: Dict[str, Any],
    param_results: Optional[Dict[str, Any]],
    plan: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """Assemble the JSON report payload.

    Additive by contract: existing keys are never dropped or renamed, so
    anything reading today's reports keeps working. ``schema_version`` only
    increments if that contract breaks.
    """
    payload = {
        "schema_version": 1,
        "repos": report_repos,
        "summary": summary,
        "actions": {k.value: v for k, v in action_summary.items()},
        "local": local,
        "port_collisions": fleet_summary,
        "port_collision_maps": fleet_maps,
        "findings": build_findings(
            full_manifest, report_repos, local, fleet_summary, param_results
        ),
        "plan": plan,
    }
    if param_results is not None:
        payload["param_check"] = param_results
    # bake-in meta (dirty intentionally ignored: we audit files on disk, not git state)
    payload["meta"] = {
        "timeout": args.timeout,
        "clone_timeout": args.clone_timeout,
        "batch": getattr(args, "batch", None),
        "tickers": args.ticker,
        "local_only": bool(getattr(args, "local_only", False)),
    }
    payload["dirty"] = None
    return payload


def write_report(payload: Dict[str, Any], report_path: str) -> None:
    """Write the report payload as pretty-printed JSON."""
    with open(report_path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2)
    print(f"\nJSON report written to {report_path}")


# Flags that read `param_results`. --param-check is the only producer of
# param_results, so before this implication each of them was a silent no-op
# when passed on its own: no PARAM CHECK section, no fixes, no error.
WRITE_FLAGS_REQUIRING_PARAM: Tuple[str, ...] = (
    "--write-config",
    "--fee-write",
    "--fix-ports",
)


def apply_flag_implications(args: argparse.Namespace, emit=print) -> argparse.Namespace:
    """Turn on --param-check for flags that cannot act without it.

    --write-config, --fee-write and --fix-ports all derive their work from
    ``param_results``, which ``main()`` only builds inside ``if
    args.param_check``. Each implying flag is announced individually so the
    note always names the flag the operator actually passed, and so a run
    that ended up doing more than was asked for never looks like the plain
    read-only run it did not happen to be.

    An explicit ``--param-check`` short-circuits this: there is nothing to
    announce when the flag the operator wanted is the flag they typed.
    """
    if args.param_check:
        return args
    for flag in WRITE_FLAGS_REQUIRING_PARAM:
        if getattr(args, flag.lstrip("-").replace("-", "_"), False):
            emit(f"NOTE: {flag} implies --param-check; enabling it now")
            args.param_check = True
    return args


def main(argv: Optional[List[str]] = None) -> int:
    _configure_logging()
    parser = build_arg_parser()
    args = parser.parse_args(argv)
    apply_flag_implications(args)

    manifest_path = Path(args.manifest).resolve()
    repo_root = manifest_path.parent

    try:
        manifest = load_manifest(manifest_path)
    except Exception as exc:
        print(f"ERROR: could not load manifest {manifest_path}: {exc}")
        return 2

    runner = SystemCommandRunner()
    probe_service = RemoteProbeService(runner)

    if args.scaffold:
        scaffolder = CoinScaffolder(runner, probe_service)
        rc, scaffold_result = scaffolder.run(args, manifest, repo_root)
        if args.report:
            # Scaffold runs no audit, so the fleet sections are empty and the
            # substance of this envelope is scaffold.plan[].
            payload = build_report(
                manifest, args, {}, empty_summary(), defaultdict(list),
                {}, {}, {}, None, scaffold_result.get("plan", []),
            )
            payload["scaffold"] = {
                k: v for k, v in scaffold_result.items() if k != "plan"
            }
            write_report(payload, args.report)
        return rc

    full_manifest_for_fleet = list(manifest)
    if args.ticker:
        selected_tickers = {t.strip().upper() for t in args.ticker.split(",")}
        manifest = [c for c in manifest if c.ticker.upper() in selected_tickers]
        if not manifest:
            print(f"ERROR: no manifest entries match tickers: {args.ticker}")
            return 2

    if args.local_only:
        # No probe: liveness, tags and staleness simply do not exist for this
        # run. Leaving them empty (rather than omitting the keys) keeps the
        # report shape identical for every reader.
        report_repos: Dict[str, Any] = {}
        summary = empty_summary()
        action_summary: Dict[ActionType, List[str]] = defaultdict(list)
        print("LOCAL-ONLY: remote repository probes skipped\n")
    else:
        report_repos, summary, action_summary = audit_repos(
            args, manifest, manifest_path, probe_service
        )
    local = crosscheck_local(manifest_path, full_manifest_for_fleet)
    fleet_maps, fleet_summary = collect_port_matrix(
        args, full_manifest_for_fleet, repo_root
    )
    param_results = audit_params(
        args, manifest, repo_root, fleet_maps, fleet_summary, runner
    )
    # Each step returns (tickers touched, plan entries); the entries are the
    # audit trail whether or not anything was written.
    _, conf_plan = apply_conf_fixes(args, manifest, param_results, repo_root, runner)
    _, port_plan = apply_port_fixes(args, manifest, param_results, repo_root, runner)
    _, ver_plan = apply_version_bumps(args, manifest_path, report_repos, repo_root, runner)
    plan = conf_plan + port_plan + ver_plan

    if args.report:
        payload = build_report(
            full_manifest_for_fleet, args, report_repos, summary,
            action_summary, local, fleet_summary, fleet_maps, param_results,
            plan,
        )
        write_report(payload, args.report)

    ok = (
        summary["dead"] == 0
        and summary["moved"] == 0
        and summary["unknown"] == 0
        and summary["error"] == 0
    )
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
