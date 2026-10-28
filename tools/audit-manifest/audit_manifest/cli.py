"""audit-manifest.py - probe every coin repo referenced by manifest-latest.json.

For each distinct repo_url the script:
  * detects whether the repo has moved (HTTP redirect via curl -sI)
  * probes the repo for tags using `git ls-remote` (smart-HTTP git protocol)
  * checks every version tag we hold for that coin against the live tag set
  * detects NEWER upstream tags we are missing (upgrade candidates):
      - newer_same = numeric version tuple strictly newer than the max we hold,
        same component count (high-confidence upgrade signal)
      - newer_alt  = numeric tuple newer but different shape (e.g.
        `3.7.0.1` vs our `v0.17.4.x`) -> flagged for manual review
  * fetches creatordate per tag via ONE bounded shallow git fetch per repo
    (only the tags we hold plus the --top-tags newest by version), so we can
    spot stale repos without downloading full histories.

`git ls-remote` / `git fetch` never use the GitHub REST API, so bulk
tag/date probing has no API rate limit. The changelog probe alone calls
`api.github.com` (cached, no token): a 429/403 warns and degrades to no
changelog instead of quoting notes never fetched. No personal access
token is required.

Output: human-readable report on stdout, optionally a JSON report via --report (parallel to console, single parsable
file only when requested).

--param-check adds a fact-check pass that verifies every XBridge-conf and
core-wallet-conf parameter against the coin's own source AT THE EXACT
MANIFEST TAG (one checkout per coin at .cache/audit-manifest/repos/<ticker>:
HEAD checked first, reused only when it already is that tag's commit from
this repo URL AND the tree has no edits or leftover files; otherwise the
exact tag is force-fetched into that folder, switched in and verified;
btcd-family handled via golang layout: chaincfg/params.go + mempool/policy.go).
It is a REPORTING tool: rows state observed values with file:line citations
and, where a value differs from source, the git birth-date of that conf line.
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
from typing import Any

from .apply_plan import RegenerationError, apply_entries, apply_plan_file, regenerate_for
from .checkout import SourceReader
from .constants import DEFAULT_MANIFEST
from .findings import ReportInputs, build_report, empty_summary, write_report
from .fixes import apply_conf_fixes, apply_port_fixes, apply_version_bumps, plan_delist_entries, read_probe_repos
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
        epilog=(
            "examples:\n"
            "  audit-manifest.py --ticker BTC,LTC --report fleet.json\n"
            "  audit-manifest.py --local-only --param-check --ticker AAA\n"
            "  audit-manifest.py --update-versions --dry-run\n"
        ),
    )
    scope = parser.add_argument_group("scope")
    scope.add_argument("--manifest", default=str(DEFAULT_MANIFEST), help="Path to the fleet manifest JSON")
    scope.add_argument("--ticker", default=None, help="Comma-separated ticker filter, e.g. BTC,LTC")
    scope.add_argument("--batch", default=None, help="Batch label for report meta, e.g. 02/11")
    scope.add_argument(
        "--local-only",
        action="store_true",
        help="Skip remote repository probes; run only the local "
        "cross-check, the fleet port matrix and (if asked) "
        "--param-check. Fast — no remote probes (a source "
        "checkout still fetches a tag its cache lacks): tags, "
        "liveness, staleness and --update-versions data are "
        "unavailable",
    )
    probes = parser.add_argument_group("probes")
    probes.add_argument("--timeout", type=int, default=30, help="Seconds per probe")
    probes.add_argument("--sleep", type=float, default=0.3, help="Seconds between repos")
    probes.add_argument("--retries", type=int, default=2, help="Retries per probe on timeout")
    probes.add_argument(
        "--top-tags", type=int, default=10, help="Newest tags to fetch dates for (used for stale detection)"
    )
    probes.add_argument("--stale-years", type=float, default=3.0, help="Inactivity threshold in years")
    probes.add_argument("--clone-timeout", type=int, default=120, help="Seconds budget per auto-clone")
    probes.add_argument(
        "--no-changelog", action="store_true", help="Skip changelog mandatory HF probe (avoids GitHub API)"
    )
    probes.add_argument(
        "--param-check", action="store_true", help="Fact-check parameters against source at manifest tag"
    )
    probes.add_argument(
        "--fees-only", action="store_true", help="Run only FEES/DUST checks (skip all other param checks)"
    )
    probes.add_argument(
        "--strict-per-version", action="store_true", help="Gate ver_id verdict on worst per-version status"
    )
    writes = parser.add_argument_group("writes")
    writes.add_argument(
        "--write-config",
        action="store_true",
        help="Auto-fix missing txindex, the source-derived DustAmount, and stale deprecatedrpc",
    )
    writes.add_argument(
        "--dust-write",
        action="store_true",
        help="Auto-fix DustAmount only: write each coin's source-derived dust "
        "threshold into its xbridge conf and regenerate base.j2",
    )
    writes.add_argument(
        "--dry-run",
        action="store_true",
        help="Compute and report every write a "
        "--write-config/--dust-write/--fee-write/--fix-ports/--update-versions/"
        "--apply/--apply-plan/--delist run would make, "
        "without touching disk. The report's plan[] entries carry applied=false",
    )
    writes.add_argument(
        "--fee-write", action="store_true", help="Auto-fix FEES rows only (MinTxFee/FeePerByte from strict chain gates)"
    )
    writes.add_argument("--fix-ports", action="store_true", help="Reassign colliding P2P/RPC ports based on lineage")
    writes.add_argument(
        "--update-versions",
        action="store_true",
        help="Append latest remote tag to manifest versions "
        "for UPGRADE coins (additive: old versions stay "
        "buildable; writes BCF manifest + regenerates "
        "base.j2)",
    )
    writes.add_argument(
        "--replace-versions",
        action="store_true",
        help="With --update-versions, collapse to the "
        "latest tag only and rename confs (drop old "
        "versions; for forced-fork drops only)",
    )
    writes.add_argument(
        "--versions-from",
        default=None,
        metavar="PATH",
        help="Read version data from this probe "
        "report instead of probing (offline; "
        "pairs with --update-versions under "
        "--local-only)",
    )
    writes.add_argument(
        "--apply-plan",
        default=None,
        metavar="PATH",
        help="Apply a reviewed plan file's entries with "
        "per-entry old verification; rewrites the "
        "file with applied flags (0 all applied, 1 "
        "some refused)",
    )
    writes.add_argument(
        "--delist",
        action="store_true",
        help="Remove --ticker coins from the manifest plus every coin file (writes unless --dry-run)",
    )
    scaffold = parser.add_argument_group("scaffold")
    scaffold.add_argument("--scaffold", action="store_true", help="Generate new coin entry from repo URL")
    scaffold.add_argument("--repo-url", default=None, help="Repo URL for --scaffold")
    scaffold.add_argument("--scaffold-ticker", default=None, help="Ticker for scaffold")
    scaffold.add_argument("--scaffold-tag", default=None, help="Tag for scaffold")
    scaffold.add_argument(
        "--scaffold-name",
        default=None,
        help="Display name for scaffold (blockchain/Title/ver_name); default Ticker.title()",
    )
    scaffold.add_argument("--apply", action="store_true", help="Apply scaffold directly into repo")
    scaffold.add_argument("--scaffold-out-dir", default=None, help="Output dir for scaffold")
    output = parser.add_argument_group("output")
    output.add_argument(
        "--report", default=None, help="Write JSON report to this path (parallel to console; single contract)"
    )
    return parser


_MANIFEST_STRING_FIELDS = (
    "ticker",
    "ver_id",
    "blockchain",
    "ver_name",
    "conf_name",
    "dir_name_linux",
    "dir_name_mac",
    "dir_name_win",
    "repo_url",
    "wallet_conf",
    "xbridge_conf",
    "daemon_family",
    "daemon_stem",
)


def load_manifest(manifest_path: Path) -> list[ManifestCoin]:
    """Parse manifest-latest.json into ManifestCoin entries.

    Raises whatever parsing/construction raises; main() owns the user-facing
    ERROR line and the exit code so the message stays byte-identical.
    Wrong-typed fields are refused here — `from_dict` is total by
    construction, so without this a non-string ticker crashes `--ticker`
    filtering, a non-string wallet_conf crashes the local cross-check with
    an AttributeError, a non-string repo_url crashes the probe, and bad
    versions crash tag resolution deep in the run. Validation is total
    over every string-typed field the run consumes, so a corrupt manifest
    always reads as "which entry, which field", exit 2, never a traceback.
    """
    raw_manifest = json.loads(SourceReader.slurp(manifest_path) or "")
    for i, data in enumerate(raw_manifest):
        if not isinstance(data, dict):
            raise TypeError(f"manifest entry #{i} is not an object")
        for field in _MANIFEST_STRING_FIELDS:
            if field in data and not isinstance(data[field], str):
                raise TypeError(f"manifest entry #{i} has a non-string {field}: {data[field]!r}")
        versions = data.get("versions", [])
        if not isinstance(versions, list) or any(not isinstance(v, str) for v in versions):
            label = data.get("ticker") or f"#{i}"
            raise TypeError(f"manifest entry {label} has non-list versions")
    return [ManifestCoin.from_dict(d) for d in raw_manifest]


# Flags that read `param_results`. --param-check is its only producer,
# so without this implication each of them was a silent no-op alone.
WRITE_FLAGS_REQUIRING_PARAM: tuple[str, ...] = (
    "--write-config",
    "--dust-write",
    "--fee-write",
    "--fix-ports",
)


def apply_flag_implications(args: argparse.Namespace, emit=report_line) -> argparse.Namespace:
    """Turn on --param-check and --fix-ports for flows that need them.

    --write-config, --dust-write, --fee-write and --fix-ports all derive their
    work from ``param_results``, which ``main()`` only builds inside ``if
    args.param_check``. Each implying flag is announced individually so the
    note always names the flag the operator actually passed, and so a run
    that ended up doing more than was asked for never looks like the plain
    read-only run it did not happen to be.

    Port checks ride along with every plan/write flow the same way:
    a preview or a write without them could bless or introduce a
    fleet collision, so --write-config and --fee-write imply
    --fix-ports. A dust-only write does not: it never touches a port
    key, so dragging port reassignment into it would be an unasked-for
    fleet change. A bare --dry-run stays cheap: with nothing else to
    plan, collisions stay reported as findings instead of moves.
    An explicit ``--param-check`` or ``--fix-ports``
    short-circuits its own implication: there is nothing to announce
    when the flag the operator wanted is the flag they typed.
    """
    if not args.fix_ports:
        for flag in ("--write-config", "--fee-write"):
            if getattr(args, flag.lstrip("-").replace("-", "_"), False):
                emit(f"NOTE: {flag} implies --fix-ports; enabling it now")
                args.fix_ports = True
                break
    if not args.param_check:
        announced = False
        for flag in WRITE_FLAGS_REQUIRING_PARAM:
            if getattr(args, flag.lstrip("-").replace("-", "_"), False):
                emit(f"NOTE: {flag} implies --param-check; enabling it now")
                args.param_check = True
                announced = True
        if args.fix_ports and not announced:
            emit("NOTE: --fix-ports implies --param-check; enabling it now")
            args.param_check = True
    return args


def _scaffold_verb(  # noqa: PLR0913, PLR0917  # verb wrapper: one parameter per verb input
    args: argparse.Namespace,
    manifest: list[ManifestCoin],
    repo_root: Path,
    runner: SystemCommandRunner,
    probe_service: RemoteProbeService,
    manifest_path: Path,
) -> int:
    """The --scaffold verb: extract, generate, stage; report if asked.

    Scaffold runs no audit, so the report's fleet sections are empty and
    the substance is the plan plus the raw scaffold payload.
    """
    rc, scaffold_result = CoinScaffolder(runner, probe_service).run(args, manifest, repo_root, manifest_path)
    if args.report:
        payload = build_report(
            ReportInputs(
                full_manifest=manifest,
                args=args,
                plan=scaffold_result.get("plan", []),
            )
        )
        payload["scaffold"] = {k: v for k, v in scaffold_result.items() if k != "plan"}
        write_report(payload, args.report)
    return rc


def _apply_plan_verb(
    args: argparse.Namespace,
    manifest: list[ManifestCoin],
    repo_root: Path,
    runner: SystemCommandRunner,
    manifest_path: Path,
) -> int:
    """The --apply-plan verb: apply a reviewed plan file."""
    try:
        rc, out = apply_plan_file(
            Path(args.apply_plan),
            repo_root,
            runner,
            manifest_path=manifest_path,
            dry_run=bool(getattr(args, "dry_run", False)),
        )
    except RegenerationError as exc:
        report_line(f"ERROR: {exc}")
        return 1
    if args.report:
        payload = build_report(
            ReportInputs(
                full_manifest=manifest,
                args=args,
                plan=out,
            )
        )
        write_report(payload, args.report)
    return rc


def _delist_verb(
    args: argparse.Namespace,
    manifest: list[ManifestCoin],
    repo_root: Path,
    runner: SystemCommandRunner,
    manifest_path: Path,
) -> int:
    """The --delist verb: remove the conf pair(s) of every ticked coin."""
    if not args.ticker:
        report_line("ERROR: --delist needs --ticker <coins>")
        return 2
    wanted = {t.strip().upper() for t in args.ticker.split(",") if t.strip()}
    by_ticker = {c.ticker.upper(): c for c in manifest}
    unknown = sorted(wanted - set(by_ticker))
    if unknown:
        report_line(f"ERROR: --delist unknown tickers: {', '.join(unknown)}")
        return 2
    dry_run = bool(getattr(args, "dry_run", False))
    plan: list[dict[str, Any]] = []
    for ticker in sorted(wanted):
        entries, note = plan_delist_entries(by_ticker[ticker], repo_root, manifest_path)
        if note is not None:
            report_line(note)
        plan.extend(entries)
    if not dry_run:
        try:
            apply_entries(plan, repo_root, runner, manifest_path=manifest_path)
        except RegenerationError as exc:
            report_line(f"ERROR: {exc}")
            return 1
        for e in plan:
            if not e.get("applied"):
                report_line(f"  refused {e.get('coin')}: {e.get('file')} — {e.get('error')}")
    if args.report:
        payload = build_report(
            ReportInputs(
                full_manifest=manifest,
                args=args,
                plan=plan,
            )
        )
        write_report(payload, args.report)
    return 0 if all(e.get("applied") or dry_run for e in plan) else 1


def _audit_phases(  # noqa: PLR0913  # the audit pipeline's inputs, keyword-only at the call site
    *,
    args: argparse.Namespace,
    manifest: list[ManifestCoin],
    full_manifest_for_fleet: list[ManifestCoin],
    manifest_path: Path,
    repo_root: Path,
    runner: SystemCommandRunner,
    report_repos: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], dict[str, Any] | None, list[dict[str, Any]]]:
    """Cross-check, fleet matrix, param-check, fix derivation, version bumps.

    Each fix step returns its plan entries; the entries are the audit
    trail whether or not anything was written.
    """
    local = crosscheck_local(manifest_path, full_manifest_for_fleet)
    fleet_maps, fleet_summary = collect_port_matrix(args, full_manifest_for_fleet, repo_root)
    param_results = audit_params(args, manifest, repo_root, fleet_maps, fleet_summary, runner)
    conf_plan = apply_conf_fixes(args, manifest, param_results, repo_root, runner, manifest_path=manifest_path)
    # Port occupancy must see the whole fleet even when the run is scoped
    # by --ticker; writes stay scoped to `manifest` (see the callee's doc).
    port_plan = apply_port_fixes(
        args,
        manifest,
        param_results,
        repo_root,
        runner,
        fleet_manifest=full_manifest_for_fleet,
        manifest_path=manifest_path,
    )
    version_repos = report_repos
    if args.versions_from:
        version_repos, note = read_probe_repos(Path(args.versions_from))
        if note is not None:
            report_line(note)
    ver_plan = apply_version_bumps(args, manifest_path, version_repos, repo_root, runner)
    plan = conf_plan + port_plan + ver_plan
    regenerate_for(plan, repo_root, runner)
    return local, fleet_maps, fleet_summary, param_results, plan


def _emit_audit_report(  # noqa: PLR0913  # report inputs, keyword-only at the call site
    *,
    args: argparse.Namespace,
    full_manifest: list[ManifestCoin],
    report_repos: dict[str, Any],
    summary: dict[str, Any],
    action_summary: dict[ActionType, list[str]],
    local: dict[str, Any],
    fleet_summary: dict[str, Any],
    fleet_maps: dict[str, Any],
    param_results: dict[str, Any] | None,
    plan: list[dict[str, Any]],
) -> None:
    """Write the JSON report when the run asked for one."""
    if not args.report:
        return
    payload = build_report(
        ReportInputs(
            full_manifest=full_manifest,
            args=args,
            report_repos=report_repos,
            summary=summary,
            action_summary=action_summary,
            local=local,
            fleet_summary=fleet_summary,
            fleet_maps=fleet_maps,
            param_results=param_results,
            plan=plan,
        )
    )
    write_report(payload, args.report)


def _audit_phases_guarded(  # noqa: PLR0913  # the audit pipeline's inputs, keyword-only at the call site
    *,
    args: argparse.Namespace,
    manifest: list[ManifestCoin],
    full_manifest_for_fleet: list[ManifestCoin],
    manifest_path: Path,
    repo_root: Path,
    runner: SystemCommandRunner,
    report_repos: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], dict[str, Any] | None, list[dict[str, Any]]] | None:
    """Run every audit phase, reporting a half-applied write as an error line.

    Returns None when the run wrote a conf but could not mirror it into the
    template that regenerates it — the caller then exits non-zero without
    writing a report that would describe the run as applied.
    """
    try:
        return _audit_phases(
            args=args,
            manifest=manifest,
            full_manifest_for_fleet=full_manifest_for_fleet,
            manifest_path=manifest_path,
            repo_root=repo_root,
            runner=runner,
            report_repos=report_repos,
        )
    except RegenerationError as exc:
        report_line(f"ERROR: {exc}")
        return None


def main(argv: list[str] | None = None) -> int:  # noqa: C901, PLR0911  # verb dispatch: one return per verb
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
        return _scaffold_verb(args, manifest, repo_root, runner, probe_service, manifest_path)

    if args.apply_plan:
        return _apply_plan_verb(args, manifest, repo_root, runner, manifest_path)

    if args.delist:
        return _delist_verb(args, manifest, repo_root, runner, manifest_path)

    missing_dirs = [d for d in ("wallet-confs", "xbridge-confs") if not (repo_root / d).is_dir()]
    if missing_dirs:
        report_line(f"ERROR: {repo_root} is not a repo root — missing {', '.join(missing_dirs)}")
        return 2

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
        report_repos: dict[str, Any] = {}
        summary = empty_summary()
        action_summary: dict[ActionType, list[str]] = defaultdict(list)
        report_line("LOCAL-ONLY: remote repository probes skipped\n")
    else:
        report_repos, summary, action_summary = audit_repos(args, manifest, manifest_path, probe_service)

    phases = _audit_phases_guarded(
        args=args,
        manifest=manifest,
        full_manifest_for_fleet=full_manifest_for_fleet,
        manifest_path=manifest_path,
        repo_root=repo_root,
        runner=runner,
        report_repos=report_repos,
    )
    if phases is None:
        return 1
    local, fleet_maps, fleet_summary, param_results, plan = phases
    _emit_audit_report(
        args=args,
        full_manifest=full_manifest_for_fleet,
        report_repos=report_repos,
        summary=summary,
        action_summary=action_summary,
        local=local,
        fleet_summary=fleet_summary,
        fleet_maps=fleet_maps,
        param_results=param_results,
        plan=plan,
    )

    if not getattr(args, "dry_run", False):
        refused = [e for e in plan if isinstance(e, dict) and not e.get("applied")]
        if refused:
            return 1
    ok = summary["dead"] == 0 and summary["moved"] == 0 and summary["unknown"] == 0 and summary["error"] == 0
    return 0 if ok else 1
