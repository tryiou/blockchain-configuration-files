"""Static constants: repository paths, compiled patterns, and fixed tables.

Nothing in this module performs I/O at import time and nothing here may ever
be monkeypatched into a different value by tests — paths are resolved from
``__file__`` so the package works from any working directory.
"""

from __future__ import annotations

import logging
from pathlib import Path
import re

logger = logging.getLogger("audit-manifest")

# tools/audit-manifest/audit_manifest/constants.py -> tools/audit-manifest/
SCRIPT_DIR = Path(__file__).resolve().parents[1]

# This repository's root: <repo>/tools/audit-manifest/ -> <repo>
REPO_ROOT = SCRIPT_DIR.parents[1]

DEFAULT_MANIFEST = REPO_ROOT / "manifest-latest.json"

# Local scratch for source clones and the changelog cache. Gitignored, never
# committed; purge it to force fresh probes.
CACHE_ROOT = REPO_ROOT / ".cache" / "audit-manifest"

_CHANGELOG_CACHE_DIRNAME = ".changelog_cache"

# ---------------------------------------------------------------------------
# Compiled patterns
# ---------------------------------------------------------------------------

_PRERELEASE_RE = re.compile(r"(?i)(?:[-_.]?(?:beta|alpha|rc|pre|dev|snapshot|nightly)\d*)")

_MANDATORY_HARDFORK_RE = re.compile(
    r"(?i)(\bmandatory\b.*\b(hard.?fork|consensus|upgrade)\b|\bhard.?fork\b.*\bmandatory\b|\bmust upgrade\b|\ball nodes must\b)"
)
_NEG_RE = re.compile(r"(?i)\bnon-mandatory\b|\bnot mandatory\b|does not change consensus|does not require.*upgrade")

# ---------------------------------------------------------------------------
# Fleet capability tables
# ---------------------------------------------------------------------------

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

# ---------------------------------------------------------------------------
# Report message formats
# ---------------------------------------------------------------------------

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
