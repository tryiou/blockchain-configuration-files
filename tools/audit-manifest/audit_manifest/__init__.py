"""audit-manifest: probe every coin repo referenced by manifest-latest.json.

The executable stays at ``./audit-manifest.py`` (a thin shim that delegates
here). Everything re-exported below is the historical module surface — tests
and driver scripts import these names straight off the package, one home per
symbol.
"""

from __future__ import annotations

import json

from .checkout import SourceCheckoutManager, SourceReader
from .cli import apply_flag_implications, build_arg_parser, main
from .inspectors import (
    BtcdSourceInspector,
    CommonParamCheckers,
    CppSourceInspector,
    _CURRENT_CHAIN_CACHE,
)
from .model import (
    CheckFinding,
    FeePolicy,
    ManifestCoin,
    ParamAuditResult,
    ParamStatus,
    RepoStatus,
    recommended_fees,
)
from .params import ParamAuditEngine, fee_constants_for_coin
from .probe import RemoteProbeService
from .reporting import _configure_logging
from .scaffold import CoinScaffolder
from .util import _safe_arith_float, conf_val_ci, entry_changelog_quote
from .versioning import (
    VersionEngine,
    _newest_and_stale,
    apply_additive_bump,
    build_update_version_names,
    should_skip_version_bump,
)

__all__ = [
    "_CURRENT_CHAIN_CACHE",
    "_configure_logging",
    "_newest_and_stale",
    "_safe_arith_float",
    "apply_additive_bump",
    "apply_flag_implications",
    "BtcdSourceInspector",
    "build_arg_parser",
    "build_update_version_names",
    "CheckFinding",
    "CoinScaffolder",
    "CommonParamCheckers",
    "conf_val_ci",
    "CppSourceInspector",
    "entry_changelog_quote",
    "fee_constants_for_coin",
    "FeePolicy",
    "json",
    "main",
    "ManifestCoin",
    "ParamAuditEngine",
    "ParamAuditResult",
    "ParamStatus",
    "recommended_fees",
    "RemoteProbeService",
    "RepoStatus",
    "should_skip_version_bump",
    "SourceCheckoutManager",
    "SourceReader",
    "VersionEngine",
]
