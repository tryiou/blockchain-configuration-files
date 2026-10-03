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
import json
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .checkout import SourceReader
from .constants import DEFAULT_MANIFEST
from .findings import build_report, empty_summary, write_report
from .fixes import apply_conf_fixes, apply_port_fixes, apply_version_bumps
from .localcheck import crosscheck_local
from .model import ActionType, ManifestCoin
from .pipeline import audit_params, audit_repos
from .ports import collect_port_matrix
from .probe import RemoteProbeService, SystemCommandRunner
from .reporting import _configure_logging, report_line
from .scaffold import CoinScaffolder


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


def load_manifest(manifest_path: Path) -> List[ManifestCoin]:
    """Parse manifest-latest.json into ManifestCoin entries.

    Raises whatever parsing/construction raises; main() owns the user-facing
    ERROR line and the exit code so the message stays byte-identical.
    """
    raw_manifest = json.loads(SourceReader.slurp(manifest_path) or "")
    return [ManifestCoin.from_dict(d) for d in raw_manifest]


# Flags that read `param_results`. --param-check is the only producer of
# param_results, so before this implication each of them was a silent no-op
# when passed on its own: no PARAM CHECK section, no fixes, no error.
WRITE_FLAGS_REQUIRING_PARAM: Tuple[str, ...] = (
    "--write-config",
    "--fee-write",
    "--fix-ports",
)


def apply_flag_implications(args: argparse.Namespace, emit=report_line) -> argparse.Namespace:
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
        report_line(f"ERROR: could not load manifest {manifest_path}: {exc}")
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
            report_line(f"ERROR: no manifest entries match tickers: {args.ticker}")
            return 2

    if args.local_only:
        # No probe: liveness, tags and staleness simply do not exist for this
        # run. Leaving them empty (rather than omitting the keys) keeps the
        # report shape identical for every reader.
        report_repos: Dict[str, Any] = {}
        summary = empty_summary()
        action_summary: Dict[ActionType, List[str]] = defaultdict(list)
        report_line("LOCAL-ONLY: remote repository probes skipped\n")
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
