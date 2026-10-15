"""The verb layer: the verb table plus each verb's semantics.

``VERBS`` maps a task to its audit invocation, ``build_audit_argv`` performs
the translation, and ``dispatch`` runs it and shapes the JSON envelope —
everything that answers "what does this verb *mean*". The mechanics of
actually launching the audit script live in ``runner``.
"""

from __future__ import annotations

import argparse
import shutil
import time
from collections import Counter
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, NamedTuple
from urllib.parse import urlparse

from . import paths, runner
from .paths import (
    DashboardError,
    read_json,
    read_last_run_meta,
    report_paths,
    write_last_run_meta,
)

# The audit script's usage-error exit code.
_EXIT_USAGE = 2


class Verb(NamedTuple):
    """One agent-facing task and how it maps onto audit-manifest.py.

    ``base`` is appended verbatim to the audit invocation. ``subject`` names
    the payload whose emptiness decides exit code 1: ``"plan"`` for verbs
    that describe writes, ``"findings"`` for everything else. ``write``
    marks verbs that modify the working tree (they report success rather
    than findings, unless they were run as a preview). ``cost`` is the
    class a task row advertises; the default is ``network`` because
    overstating cost is the safe direction.
    """

    name: str
    summary: str
    base: tuple[str, ...]
    subject: str
    write: bool = False
    informational: bool = False
    cost: str = "network"


VERBS: dict[str, Verb] = {
    v.name: v
    for v in (
        Verb(
            "list",
            "Manifest entries in the Log, narrowed by --tickers — instant, no audit",
            (),
            "entries",
            informational=True,
            cost="local",
        ),
        Verb(
            "analyze",
            "Probe the fleet → Findings tab",
            ("--no-changelog",),
            "findings",
            cost="network",
        ),
        Verb(
            "audit",
            "Probe every repo + confs + ports → Findings tab",
            (),
            "findings",
            cost="network",
        ),
        Verb(
            "findings",
            "Worst problems first → Findings tab (skips changelog probes)",
            ("--no-changelog",),
            "findings",
            cost="network",
        ),
        Verb(
            "param-check",
            "Conf values vs coin source → Findings tab",
            ("--local-only", "--param-check"),
            "findings",
            cost="heavy",
        ),
        Verb(
            "ports",
            "Port collisions across the fleet → overview",
            ("--local-only",),
            "findings",
            cost="local",
        ),
        Verb(
            "cross-check",
            "Missing and orphaned conf files → overview",
            ("--local-only",),
            "findings",
            cost="local",
        ),
        Verb(
            "plan-fix",
            "Preview conf/port writes, touches nothing → Plan tab",
            ("--local-only", "--param-check", "--dry-run", "--write-config", "--fee-write", "--fix-ports"),
            "plan",
            cost="heavy",
        ),
        Verb(
            "apply-fix",
            "WRITE: apply the previewed conf/port fixes",
            ("--local-only", "--param-check", "--write-config", "--fee-write", "--fix-ports"),
            "plan",
            write=True,
            cost="heavy",
        ),
        Verb(
            "apply-plan",
            "Apply a reviewed plan file",
            (),
            "plan",
            write=True,
            cost="local",
        ),
        Verb(
            "delist",
            "Preview removal of ticked coins",
            ("--delist", "--dry-run"),
            "plan",
            cost="local",
        ),
        Verb(
            "update-versions",
            "WRITE: manifest versions to the latest tag",
            # No --no-changelog here on purpose: the mandatory-hard-fork gate
            # (should_skip_version_bump) only fires when the changelog path
            # runs, so a fast default could auto-bump repos the audit refuses
            # to certify. The probe is capped at 5 tags per repo.
            ("--update-versions",),
            "plan",
            write=True,
            cost="network",
        ),
        Verb(
            "scaffold",
            "WRITE: new coin from a GitHub URL (asks here)",
            ("--scaffold",),
            "plan",
            write=True,
            cost="network",
        ),
        Verb(
            "report",
            "Last run as a whole in the Log (takes no --tickers) — instant, no audit",
            (),
            "report",
            informational=True,
            cost="local",
        ),
    )
}


# "heavy" is network plus minutes on any connection, so its label says
# slow rather than promising a number no box can keep.
COST_LABELS: dict[str, str] = {
    "local": "local",
    "network": "network",
    "heavy": "network (slow)",
}


# Tasks grouped by intent; every verb appears exactly once, and the
# test suite pins that partition.
GROUPS: dict[str, tuple[str, ...]] = {
    "Observe": ("list", "report", "cross-check", "ports"),
    "Inspect": ("findings", "audit", "analyze"),
    # Preview/plan verbs: they report, never write (delist is hard-pinned to
    # --dry-run in its base).
    "Verify": ("param-check", "plan-fix", "delist"),
    "Write": ("apply-fix", "apply-plan", "update-versions", "scaffold"),
}


def _palette_verb(action_id: str, summary: str, subject: str, cost: str) -> Verb:
    return Verb(action_id, summary, (), subject, cost=cost)


PALETTE_VERBS: dict[str, Verb] = {
    v.name: v
    for v in (
        _palette_verb("analyze-quick", "Local cross-check + ports only — instant, no probe", "findings", "local"),
        _palette_verb("analyze", "Probe the fleet → Findings tab", "findings", "network"),
        _palette_verb("analyze-full", "Probe + changelog → Findings tab", "findings", "network"),
        _palette_verb("analyze-deep", "Conf values vs coin source → Findings tab", "findings", "heavy"),
        _palette_verb("plan", "Preview every write, touches nothing → Plan tab", "plan", "heavy"),
        _palette_verb("apply", "WRITE: apply the previewed fixes", "plan", "heavy"),
        _palette_verb("add-coin", "Preview a new coin from a GitHub URL", "plan", "network"),
        _palette_verb("delist", "Preview removal of ticked coins", "plan", "local"),
    )
}

ACTION_RUN: dict[str, tuple] = {
    "analyze": ("analyze", {}),
    "analyze-quick": ("analyze", {"local_only": True}),
    "analyze-full": ("analyze", {"with_changelog": True}),
    "analyze-deep": ("analyze", {"local_only": True, "param_check": True}),
    "plan": ("plan-fix", {}),
    "apply": ("apply-fix", {}),
    "add-coin": ("scaffold", {}),
}

BUTTON_ACTIONS = ("analyze", "plan", "apply", "add-coin")


def parse_github_repo_url(raw: str) -> str | None:
    """Normalize a GitHub coin-repo URL, or ``None`` when it is not one.

    Strict on purpose: ``https://github.com/<org>/<repo>`` with a
    non-empty org and repo, optional trailing ``/`` or ``.git``. Anything
    else — http, another host, a bare org, empty text — is refused with
    a hint instead of launching a doomed clone. Stdlib-only, so both the
    TUI dialog and the contract suite pin the same function.
    """
    text = (raw or "").strip()
    if not text:
        return None
    try:
        parts = urlparse(text)
    except ValueError:
        return None
    if parts.scheme != "https" or parts.netloc.lower() != "github.com":
        return None
    segments = [s for s in parts.path.split("/") if s and s != "."]
    # owner/repo path needs at least two segments
    if len(segments) < 2 or any(s in (".", "..") for s in segments[:2]):  # noqa: PLR2004
        return None
    org, repo = segments[0], segments[1]
    if repo.endswith(".git"):
        repo = repo[:-4]
    if not org or not repo or any(c.isspace() for c in org + repo):
        return None
    return f"https://github.com/{org}/{repo}"


def default_opts(verb: str) -> argparse.Namespace:
    """Namespace with build_parser()'s defaults, for TUI-initiated runs."""
    return argparse.Namespace(
        verb=verb,
        tickers=None,
        timeout=30,
        batch=None,
        manifest=str(paths.DEFAULT_MANIFEST),
        report=None,
        max_seconds=0,
        local_only=False,
        with_probe=False,
        with_changelog=False,
        param_check=False,
        fees_only=False,
        dry_run=False,
        replace_versions=False,
        apply=False,
        repo_url=None,
        scaffold_ticker=None,
        scaffold_tag=None,
        scaffold_name=None,
        scaffold_out_dir=None,
        with_versions=False,
        versions_from=None,
        apply_plan=None,
    )


# argv builder: one branch per flag implication
def build_audit_argv(opts: argparse.Namespace, raw: Sequence[str]) -> list[str]:  # noqa: C901, PLR0912
    """Translate a verb plus its flags into audit-manifest.py arguments."""
    verb = VERBS[opts.verb]

    argv: list[str] = ["--manifest", opts.manifest, "--timeout", str(opts.timeout)]
    if verb.name == "apply-plan":
        if not opts.apply_plan:
            raise DashboardError("the apply-plan verb requires --apply-plan <path>")
        return [*argv, "--apply-plan", opts.apply_plan]
    if opts.tickers:
        argv += ["--ticker", opts.tickers]
    if opts.batch:
        argv += ["--batch", opts.batch]

    base = list(verb.base)

    # Mode switches. Each verb has one documented default mode; these widen
    # it in the direction the flag name implies and never narrow it silently.
    if opts.with_probe and "--local-only" in base:
        base.remove("--local-only")
    if opts.local_only and "--local-only" not in base:
        base.append("--local-only")
    if opts.with_changelog and "--no-changelog" in base:
        base.remove("--no-changelog")
    if opts.param_check and "--param-check" not in base:
        base.append("--param-check")
    if opts.fees_only:
        base.append("--fees-only")
    if opts.dry_run and "--dry-run" not in base:
        base.append("--dry-run")
    if opts.replace_versions:
        base.append("--replace-versions")
    if opts.with_versions and "--update-versions" not in base:
        base.append("--update-versions")
    if opts.versions_from:
        argv += ["--versions-from", opts.versions_from]

    if verb.name == "scaffold":
        if not opts.repo_url:
            raise DashboardError("the scaffold verb requires --repo-url <url>")
        argv += ["--repo-url", opts.repo_url]
        for flag, value in (
            ("--scaffold-ticker", opts.scaffold_ticker),
            ("--scaffold-tag", opts.scaffold_tag),
            ("--scaffold-name", opts.scaffold_name),
            ("--scaffold-out-dir", opts.scaffold_out_dir),
        ):
            if value:
                argv += [flag, value]
        if opts.apply:
            base.append("--apply")

    argv += base
    argv += list(raw)
    return argv


# ---------------------------------------------------------------------------
# Envelope
# ---------------------------------------------------------------------------


def build_counts(findings: Sequence[dict[str, Any]]) -> dict[str, Any]:
    """Compact rollups an agent can branch on without walking the array."""
    by_coin = Counter(f["coin"] for f in findings if f.get("coin"))
    return {
        "total": len(findings),
        "by_severity": dict(Counter(f.get("severity") for f in findings)),
        "by_category": dict(Counter(f.get("category") for f in findings)),
        # str() the tiebreak: corrupt entries can mix key types, and the
        # rollup must never raise on them. Identical order for clean data.
        "by_coin": dict(sorted(by_coin.items(), key=lambda kv: (-kv[1], str(kv[0])))),
    }


@dataclass
class EnvelopeInputs:
    """Everything :func:`build_envelope` needs, named.

    Ten positional parameters — half of them optional sources metadata —
    made call sites unreadable and silently mis-orderable; construct with
    keywords. ``extra`` merges verb-specific keys over the envelope last.
    """

    verb: Verb
    report: dict[str, Any] | None
    argv: Sequence[str]
    started_at: float | None
    duration: float | None
    audit_exit: int | None
    report_path: Path | None
    log_path: Path | None
    extra: dict[str, Any]
    exit_code: int


def build_envelope(inp: EnvelopeInputs) -> dict[str, Any]:
    findings = (inp.report or {}).get("findings") or []
    plan = (inp.report or {}).get("plan") or []
    age = (time.time() - inp.started_at) if inp.started_at else None

    envelope: dict[str, Any] = {
        "schema_version": paths.SCHEMA_VERSION,
        "verb": inp.verb.name,
        "ok": inp.exit_code != _EXIT_USAGE,
        "exit_code": inp.exit_code,
        "counts": build_counts(findings),
        "plan_count": len(plan),
        "sources": {
            "report": str(inp.report_path) if inp.report_path else None,
            "log": str(inp.log_path) if inp.log_path else None,
            "argv": list(inp.argv),
            "audit_exit_code": inp.audit_exit,
            "duration_seconds": round(inp.duration, 3) if inp.duration is not None else None,
            "age_seconds": round(age, 1) if age is not None else None,
        },
    }
    if inp.report is not None:
        envelope["summary"] = inp.report.get("summary")
        envelope["meta"] = inp.report.get("meta")
        envelope["report_schema_version"] = inp.report.get("schema_version")
    envelope.update(inp.extra)
    return envelope


def decide_exit(verb: Verb, opts: argparse.Namespace, payload: Sequence[Any]) -> int:
    """0 = nothing left to decide, 1 = something is. Errors are handled above.

    A write verb that really wrote returns 0: the work is done, so there is
    no pending decision. A write verb run with ``--dry-run``, and scaffold
    without ``--apply``, are previews and follow the data-verb rule instead.
    """
    if verb.informational:
        return 0
    if verb.write and not opts.dry_run and (verb.name != "scaffold" or opts.apply):
        rows = [p for p in payload if isinstance(p, dict)]
        if any(not p.get("applied") for p in rows):
            return 1
        return 0
    return 1 if payload else 0


# ---------------------------------------------------------------------------
# Verb implementations
# ---------------------------------------------------------------------------


def entries_from_manifest(path: str | Path) -> list[dict[str, Any]]:
    """The manifest rows behind both the ``list`` payload and the coins screen.

    One reader, one shape: the TUI's scope picker and the agent-facing
    ``list`` verb must never disagree about what a coin entry is. A
    missing manifest is an empty fleet (the same contract the ``list``
    verb has always had); a manifest that is not a JSON array is an
    error, because that file is broken, not merely absent.
    """
    manifest_path = Path(path).expanduser()
    raw = read_json(manifest_path) if manifest_path.is_file() else []
    if not isinstance(raw, list):
        raise DashboardError(f"{manifest_path} does not contain a JSON array")
    return [
        {
            "ticker": e.get("ticker"),
            "ver_id": e.get("ver_id"),
            "versions": e.get("versions"),
            "wallet_conf": e.get("wallet_conf"),
            "xbridge_conf": e.get("xbridge_conf"),
            "repo_url": e.get("repo_url"),
        }
        for e in raw
        if isinstance(e, dict)
    ]


def fleet_entries() -> list[dict[str, Any]]:
    """Manifest rows for TUI scope math; ``[]`` on a broken manifest.

    The reader above raises on a non-array file (broken, not absent);
    the TUI must not crash on it — scope math over an empty fleet
    refuses loudly at run time instead.
    """
    try:
        return entries_from_manifest(paths.DEFAULT_MANIFEST)
    except DashboardError:
        return []


def _entries_payload(opts: argparse.Namespace) -> dict[str, Any]:
    manifest_path = Path(opts.manifest).expanduser()
    entries = entries_from_manifest(manifest_path)
    if opts.tickers:
        # A narrowed agent request narrows the rows; the flag is
        # advertised on every verb, so ignoring it would mislead.
        want = {t.strip().upper() for t in opts.tickers.split(",")}
        entries = [e for e in entries if str(e.get("ticker") or "").upper() in want]
    return {"entries": entries, "manifest": str(manifest_path)}


def _param_rollup(report: dict[str, Any]) -> dict[str, Any]:
    """Per-coin status counts for param-check, without the full check blobs.

    The complete checks live in the report file; this rollup is what an
    agent needs to decide which coin to look at next.
    """
    rollup: dict[str, Any] = {}
    for key, res in (report.get("param_check") or {}).items():
        if key.startswith("_") or not isinstance(res, dict):
            continue
        counts = Counter(c.get("status") for c in res.get("checks", []) if isinstance(c, dict))
        rollup[key] = {
            "mode": res.get("mode"),
            "source": res.get("source"),
            "counts": {k: v for k, v in counts.items() if k},
        }
    return rollup


def _raw_tickers(raw: Sequence[str]) -> str | None:
    """A `--ticker` smuggled past `--` still scopes the run: fold it into
    the slot decision. Argv itself passes through verbatim — only the
    cache-slot choice reads it, so the fleet slot never holds scoped
    content however the scope arrived.
    """
    tickers: str | None = None
    args = list(raw)
    i = 0
    while i < len(args):
        arg = args[i]
        if arg == "--ticker" and i + 1 < len(args):
            tickers = args[i + 1]
            i += 2
        elif arg.startswith("--ticker="):
            tickers = arg.split("=", 1)[1]
            i += 1
        else:
            i += 1
    return tickers


def _run_verb(opts: argparse.Namespace, raw: Sequence[str]) -> tuple[dict[str, Any], int]:
    verb = VERBS[opts.verb]
    if verb.name == "scaffold" and getattr(opts, "tickers", None):
        # Scope never applies to a repo-URL verb: refuse loudly instead
        # of ignoring the flag by ordering (the TUI never sends it).
        raise DashboardError("scaffold extracts one coin; it takes no --tickers")
    if verb.name == "apply-plan" and getattr(opts, "tickers", None):
        raise DashboardError("apply-plan applies a file; scope travels in the file, not --tickers")
    argv = build_audit_argv(opts, raw)
    primary, last, log_path = report_paths(
        verb.name,
        opts.report,
        tickers=getattr(opts, "tickers", None) or _raw_tickers(raw),
    )

    cmd = runner.audit_command(argv, primary)
    started_at = time.time()
    result = runner.run_audit(cmd, log_path, opts.max_seconds, verb=verb.name)

    # The audit script uses 2 only for "could not run"; 1 just means the
    # probe found dead/moved/unknown repos, which is a finding, not an error.
    if result["returncode"] == _EXIT_USAGE:
        raise DashboardError(f"audit-manifest.py exited 2 — see {log_path}")

    if verb.name == "apply-plan":
        plan_payload = read_json(Path(opts.apply_plan))
        raw_plan = plan_payload.get("plan") if isinstance(plan_payload, dict) else plan_payload
        report = {
            "findings": [],
            "plan": [e for e in raw_plan if isinstance(e, dict)] if isinstance(raw_plan, list) else [],
        }
        primary = Path(opts.apply_plan)
    else:
        report = read_json(primary)

    paths.CACHE_ROOT.mkdir(parents=True, exist_ok=True)
    if primary != last:
        shutil.copyfile(primary, last)
    write_last_run_meta(verb.name, cmd, primary, log_path, started_at, result["duration"], result["returncode"])

    findings = report.get("findings") or []
    plan = report.get("plan") or []

    extra: dict[str, Any] = {"findings": findings, "plan": plan}
    if verb.name in ("cross-check", "ports"):
        extra["local"] = report.get("local")
        extra["port_collisions"] = report.get("port_collisions")
    if verb.name == "param-check":
        extra["param_check"] = _param_rollup(report)
    if verb.name == "scaffold":
        extra["scaffold"] = report.get("scaffold")

    payload = plan if verb.subject == "plan" else findings
    code = decide_exit(verb, opts, payload)
    envelope = build_envelope(
        EnvelopeInputs(
            verb=verb,
            report=report,
            argv=cmd,
            started_at=started_at,
            duration=result["duration"],
            audit_exit=result["returncode"],
            report_path=primary,
            log_path=log_path,
            extra=extra,
            exit_code=code,
        )
    )
    return envelope, code


def _report_verb(opts: argparse.Namespace) -> tuple[dict[str, Any], int]:
    if opts.tickers:
        # `report` describes the last run as a whole; a coin filter is
        # meaningless on it, so refuse loudly instead of ignoring the flag.
        raise DashboardError("report describes the last run; it takes no --tickers")
    report = read_json(paths.LAST_REPORT)
    findings = report.get("findings") or []
    if not isinstance(findings, list) or any(not isinstance(e, dict) for e in findings):
        # A hand-corrupted last run reads as a clean error, never an
        # AttributeError out of the envelope build below.
        raise DashboardError(f"{paths.LAST_REPORT} holds no readable findings")
    meta = read_last_run_meta()
    verb = VERBS[opts.verb]
    plan = report.get("plan") or []
    extra = {
        "findings": findings,
        "plan": plan,
        "last_run": meta or None,
        "report_path": str(paths.LAST_REPORT),
        "log_path": meta.get("log"),
    }
    envelope = build_envelope(
        EnvelopeInputs(
            verb=verb,
            report=report,
            argv=meta.get("argv", []),
            started_at=meta.get("started_at"),
            duration=meta.get("duration_seconds"),
            audit_exit=meta.get("audit_exit_code"),
            report_path=Path(meta["report"]) if meta.get("report") else paths.LAST_REPORT,
            log_path=Path(meta["log"]) if meta.get("log") else None,
            extra=extra,
            exit_code=0,
        )
    )
    return envelope, 0


def dispatch(opts: argparse.Namespace, raw: Sequence[str]) -> tuple[dict[str, Any], int]:
    verb = VERBS[opts.verb]
    if verb.name == "list":
        payload = _entries_payload(opts)
        envelope = build_envelope(
            EnvelopeInputs(
                verb=verb,
                report=None,
                argv=[],
                started_at=None,
                duration=None,
                audit_exit=None,
                report_path=None,
                log_path=None,
                extra=payload,
                exit_code=0,
            )
        )
        envelope["counts"] = dict(build_counts([]), total=len(payload["entries"]))
        return envelope, 0
    if verb.name == "report":
        return _report_verb(opts)
    return _run_verb(opts, raw)
