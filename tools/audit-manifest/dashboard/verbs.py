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
from pathlib import Path
from typing import Any, Dict, List, NamedTuple, Optional, Sequence, Tuple

from . import paths
from .paths import (
    DashboardError,
    read_json,
    read_last_run_meta,
    report_paths,
    write_last_run_meta,
)
from .runner import audit_command, run_audit


class Verb(NamedTuple):
    """One agent-facing task and how it maps onto audit-manifest.py.

    ``base`` is appended verbatim to the audit invocation. ``subject`` names
    the payload whose emptiness decides exit code 1: ``"plan"`` for verbs
    that describe writes, ``"findings"`` for everything else. ``write``
    marks verbs that modify the working tree (they report success rather
    than findings, unless they were run as a preview).
    """

    name: str
    summary: str
    base: Tuple[str, ...]
    subject: str
    write: bool = False
    informational: bool = False


VERBS: Dict[str, Verb] = {
    v.name: v
    for v in (
        Verb(
            "list",
            "List manifest entries without running an audit",
            (),
            "entries",
            informational=True,
        ),
        Verb(
            "audit",
            "Full fleet audit: probe every repo, cross-check confs, port matrix",
            (),
            "findings",
        ),
        Verb(
            "findings",
            "Aggregated findings, worst-first (probe, changelog probes skipped)",
            ("--no-changelog",),
            "findings",
        ),
        Verb(
            "param-check",
            "Fact-check confs against coin source, skipping the repo probe",
            ("--local-only", "--param-check"),
            "findings",
        ),
        Verb(
            "ports",
            "Fleet port-collision matrix only",
            ("--local-only",),
            "findings",
        ),
        Verb(
            "cross-check",
            "On-disk conf cross-check: missing and orphaned files",
            ("--local-only",),
            "findings",
        ),
        Verb(
            "plan-fix",
            "Preview every write the fix flags would make (dry-run)",
            ("--local-only", "--param-check", "--dry-run",
             "--write-config", "--fee-write", "--fix-ports"),
            "plan",
        ),
        Verb(
            "apply-fix",
            "Apply the conf and port fixes",
            ("--local-only", "--param-check",
             "--write-config", "--fee-write", "--fix-ports"),
            "plan",
            write=True,
        ),
        Verb(
            "update-versions",
            "Bump manifest versions to the latest upstream tag",
            ("--no-changelog", "--update-versions"),
            "plan",
            write=True,
        ),
        Verb(
            "scaffold",
            "Extract a new coin entry from a repo URL (needs --repo-url)",
            ("--scaffold",),
            "plan",
            write=True,
        ),
        Verb(
            "report",
            "Metadata, summary and counts for the most recent run",
            (),
            "report",
            informational=True,
        ),
    )
}


def default_opts(verb: str) -> argparse.Namespace:
    """Namespace with build_parser()'s defaults, for TUI-initiated runs."""
    return argparse.Namespace(
        verb=verb, tickers=None, timeout=30, batch=None,
        manifest=str(paths.DEFAULT_MANIFEST), report=None, max_seconds=0,
        local_only=False, with_probe=False, with_changelog=False,
        param_check=False, fees_only=False, dry_run=False,
        replace_versions=False, apply=False, repo_url=None,
        scaffold_ticker=None, scaffold_tag=None, scaffold_name=None,
        scaffold_out_dir=None,
    )


def build_audit_argv(opts: argparse.Namespace, raw: Sequence[str]) -> List[str]:
    """Translate a verb plus its flags into audit-manifest.py arguments."""
    verb = VERBS[opts.verb]

    argv: List[str] = ["--manifest", opts.manifest, "--timeout", str(opts.timeout)]
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

def build_counts(findings: Sequence[Dict[str, Any]]) -> Dict[str, Any]:
    """Compact rollups an agent can branch on without walking the array."""
    by_coin = Counter(f["coin"] for f in findings if f.get("coin"))
    return {
        "total": len(findings),
        "by_severity": dict(Counter(f.get("severity") for f in findings)),
        "by_category": dict(Counter(f.get("category") for f in findings)),
        "by_coin": dict(sorted(by_coin.items(), key=lambda kv: (-kv[1], kv[0]))),
    }


def build_envelope(
    verb: Verb,
    report: Optional[Dict[str, Any]],
    argv: Sequence[str],
    started_at: Optional[float],
    duration: Optional[float],
    audit_exit: Optional[int],
    report_path: Optional[Path],
    log_path: Optional[Path],
    extra: Dict[str, Any],
    exit_code: int,
) -> Dict[str, Any]:
    findings = (report or {}).get("findings") or []
    plan = (report or {}).get("plan") or []
    age = (time.time() - started_at) if started_at else None

    envelope: Dict[str, Any] = {
        "schema_version": paths.SCHEMA_VERSION,
        "verb": verb.name,
        "ok": exit_code != 2,
        "exit_code": exit_code,
        "counts": build_counts(findings),
        "plan_count": len(plan),
        "sources": {
            "report": str(report_path) if report_path else None,
            "log": str(log_path) if log_path else None,
            "argv": list(argv),
            "audit_exit_code": audit_exit,
            "duration_seconds": round(duration, 3) if duration is not None else None,
            "age_seconds": round(age, 1) if age is not None else None,
        },
    }
    if report is not None:
        envelope["summary"] = report.get("summary")
        envelope["meta"] = report.get("meta")
        envelope["report_schema_version"] = report.get("schema_version")
    envelope.update(extra)
    return envelope


def decide_exit(verb: Verb, opts: argparse.Namespace, payload: Sequence[Any]) -> int:
    """0 = nothing left to decide, 1 = something is. Errors are handled above.

    A write verb that really wrote returns 0: the work is done, so there is
    no pending decision. A write verb run with ``--dry-run``, and scaffold
    without ``--apply``, are previews and follow the data-verb rule instead.
    """
    if verb.informational:
        return 0
    if verb.write and not opts.dry_run:
        if verb.name != "scaffold" or opts.apply:
            return 0
    return 1 if payload else 0


# ---------------------------------------------------------------------------
# Verb implementations
# ---------------------------------------------------------------------------

def _entries_payload(opts: argparse.Namespace) -> Dict[str, Any]:
    manifest_path = Path(opts.manifest).expanduser()
    raw = read_json(manifest_path) if manifest_path.is_file() else []
    if not isinstance(raw, list):
        raise DashboardError(f"{manifest_path} does not contain a JSON array")
    entries = [
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
    return {"entries": entries, "manifest": str(manifest_path)}


def _param_rollup(report: Dict[str, Any]) -> Dict[str, Any]:
    """Per-coin status counts for param-check, without the full check blobs.

    The complete checks live in the report file; this rollup is what an
    agent needs to decide which coin to look at next.
    """
    rollup: Dict[str, Any] = {}
    for key, res in (report.get("param_check") or {}).items():
        if key.startswith("_") or not isinstance(res, dict):
            continue
        counts = Counter(
            c.get("status") for c in res.get("checks", []) if isinstance(c, dict)
        )
        rollup[key] = {
            "mode": res.get("mode"),
            "source": res.get("source"),
            "counts": {k: v for k, v in counts.items() if k},
        }
    return rollup


def _run_verb(opts: argparse.Namespace, raw: Sequence[str]) -> Tuple[Dict[str, Any], int]:
    verb = VERBS[opts.verb]
    argv = build_audit_argv(opts, raw)
    primary, last, log_path = report_paths(verb.name, opts.report)

    cmd = audit_command(argv, primary)
    started_at = time.time()
    result = run_audit(cmd, log_path, opts.max_seconds)

    # The audit script uses 2 only for "could not run"; 1 just means the
    # probe found dead/moved/unknown repos, which is a finding, not an error.
    if result["returncode"] == 2:
        raise DashboardError(f"audit-manifest.py exited 2 — see {log_path}")

    report = read_json(primary)

    paths.CACHE_ROOT.mkdir(parents=True, exist_ok=True)
    if primary != last:
        shutil.copyfile(primary, last)
    write_last_run_meta(
        verb.name, cmd, primary, log_path, started_at, result["duration"], result["returncode"]
    )

    findings = report.get("findings") or []
    plan = report.get("plan") or []

    extra: Dict[str, Any] = {"findings": findings, "plan": plan}
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
        verb, report, cmd, started_at, result["duration"], result["returncode"],
        primary, log_path, extra, code,
    )
    return envelope, code


def _report_verb(opts: argparse.Namespace) -> Tuple[Dict[str, Any], int]:
    report = read_json(paths.LAST_REPORT)
    meta = read_last_run_meta()
    verb = VERBS[opts.verb]
    findings = report.get("findings") or []
    plan = report.get("plan") or []
    extra = {
        "findings": findings,
        "plan": plan,
        "last_run": meta or None,
        "report_path": str(paths.LAST_REPORT),
        "log_path": meta.get("log"),
    }
    envelope = build_envelope(
        verb, report, meta.get("argv", []), meta.get("started_at"),
        meta.get("duration_seconds"), meta.get("audit_exit_code"),
        Path(meta["report"]) if meta.get("report") else paths.LAST_REPORT,
        Path(meta["log"]) if meta.get("log") else None, extra, 0,
    )
    return envelope, 0


def dispatch(opts: argparse.Namespace, raw: Sequence[str]) -> Tuple[Dict[str, Any], int]:
    verb = VERBS[opts.verb]
    if verb.name == "list":
        payload = _entries_payload(opts)
        envelope = build_envelope(
            verb, None, [], None, None, None, None, None, payload, 0
        )
        envelope["counts"] = dict(build_counts([]), total=len(payload["entries"]))
        return envelope, 0
    if verb.name == "report":
        return _report_verb(opts)
    return _run_verb(opts, raw)
