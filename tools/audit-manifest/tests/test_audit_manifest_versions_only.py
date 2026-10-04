#!/usr/bin/env python3
"""``versions`` is the sole source of held tags (manifest field contract).

The manifest field table in this repository's root ``README.md`` defines
``ver_id`` as a unique identifier for a configuration version group and
``versions`` as the array of wallet versions whose strings match the
upstream git tags exactly. The audit must therefore:

* derive expected tags exclusively from ``versions`` — a version-shaped
  ``ver_id`` suffix is never a held tag and cannot suppress a genuine
  "newer upstream tag" verdict;
* report no newer tags when nothing is declared;
* refuse the param-check with mode ``no-tag`` instead of falling back to
  the ``ver_id`` suffix.
"""
from pathlib import Path
from unittest import mock

import audit_manifest as audit
from audit_manifest.cli import load_manifest

ManifestCoin = audit.ManifestCoin
VersionEngine = audit.VersionEngine
ParamAuditEngine = audit.ParamAuditEngine
SourceCheckoutManager = audit.SourceCheckoutManager

# <repo>/tools/audit-manifest/tests/<this file> -> <repo>
REPO_ROOT = Path(__file__).resolve().parents[3]


def test_ver_id_suffix_is_not_a_held_tag():
    """v2.0.0 is newer than the declared v1.0.0, whatever ver_id claims."""
    coin = ManifestCoin(ticker="XXX", ver_id="xxx--v9.9.9", versions=["v1.0.0"])
    newer_same, newer_alt = VersionEngine.detect_newer({"v1.0.0", "v2.0.0"}, [coin])
    assert newer_same == ["v2.0.0"]
    assert newer_alt == []


def test_expected_tags_ignore_the_ver_id_suffix():
    coin = ManifestCoin(ticker="XXX", ver_id="xxx--v9.9.9", versions=["v1.0.0"])
    assert coin.expected_tags() == ["v1.0.0"]


def test_detect_newer_without_declared_versions_reports_nothing():
    coin = ManifestCoin(ticker="XXX", ver_id="xxx--v0.1.0", versions=[])
    newer_same, newer_alt = VersionEngine.detect_newer({"v1.0.0"}, [coin])
    assert newer_same == []
    assert newer_alt == []


def test_param_audit_without_declared_versions_is_no_tag():
    eng = ParamAuditEngine(SourceCheckoutManager())
    coin = ManifestCoin(
        ticker="XXX",
        ver_id="xxx--v9.9.9",
        versions=[],
        wallet_conf="xxx--v9.9.9.conf",
        xbridge_conf="xxx--v9.9.9.conf",
        repo_url="https://example.invalid/x/x",
    )
    # If the ver_id suffix were consulted, the engine would try to audit
    # that phantom tag; the guard below turns that into a hard failure.
    with mock.patch.object(
        eng, "audit_version",
        side_effect=AssertionError("no declared versions → must not audit any tag"),
    ):
        res = eng.audit_coin_all_versions(coin, REPO_ROOT, timeout=10)
    assert res.mode == "no-tag"


def test_every_manifest_entry_holds_only_its_declared_versions():
    """Real-manifest contract: all entries, versions-only, no exceptions."""
    coins = load_manifest(REPO_ROOT / "manifest-latest.json")
    assert coins, "manifest-latest.json must contain entries"
    for coin in coins:
        assert coin.expected_tags() == sorted(set(coin.versions)), (
            f"{coin.ver_id}: expected_tags must equal the declared versions"
        )


# ---------------------------------------------------------------------------
# The versions block on findings (stable key, stable shape, schema v1)
# ---------------------------------------------------------------------------

_EMPTY_LOCAL = {
    "missing_wallet_conf": [],
    "missing_xbridge_conf": [],
    "missing_base_j2": [],
    "orphans": {},
}
_EMPTY_PORTS = {"p2p": {}, "rpc": {}, "xbridge": {}, "test_p2p": {}, "test_rpc": {}}


def _xxx_coin():
    return ManifestCoin(
        ticker="XXX",
        ver_id="xxx--v1.0.0",
        versions=["v1.0.0"],
        wallet_conf="xxx--v1.0.0.conf",
        xbridge_conf="xxx--v1.0.0.conf",
        repo_url="https://example.invalid/x/x",
    )


def test_repo_action_findings_carry_the_versions_block():
    from audit_manifest.findings import build_findings
    from audit_manifest.model import ActionType

    report_repos = {
        "https://example.invalid/x/x": {
            "status": "alive",
            "tag_count": 3,
            "newer_same": ["v2.0.0"],
            "newer_alt": [],
            "remote_latest": "v2.0.0",
            "stale": False,
            "entries": [{
                "ticker": "XXX",
                "ver_id": "xxx--v1.0.0",
                "versions": ["v1.0.0"],
                "expected_tags": ["v1.0.0"],
                "found": ["v1.0.0"],
                "missing": [],
                "our_latest": "v1.0.0",
                "remote_latest": "v2.0.0",
                "action": ActionType.UPGRADE,
            }],
        },
    }
    findings = build_findings(
        [_xxx_coin()], report_repos, dict(_EMPTY_LOCAL), dict(_EMPTY_PORTS), None
    )
    repo_findings = [f for f in findings if f["id"] == "REPO-ACTION"]
    assert len(repo_findings) == 1, [f["id"] for f in findings]
    assert repo_findings[0]["versions"] == {
        "declared": ["v1.0.0"],
        "our_latest": "v1.0.0",
        "remote_latest": "v2.0.0",
        "newer_same": ["v2.0.0"],
        "newer_alt": [],
        "missing": [],
        "found": ["v1.0.0"],
        "tag_count": 3,
        "conf": "xxx--v1.0.0",
    }


def test_versions_block_defaults_sparse_entries_to_empty_lists():
    """README contract: list keys are never null, they are [] when empty."""
    from audit_manifest.findings import build_findings
    from audit_manifest.model import ActionType

    report_repos = {
        "https://example.invalid/x/x": {
            "status": "dead",
            "tag_count": None,
            "newer_same": None,
            "newer_alt": None,
            "remote_latest": None,
            "stale": False,
            "entries": [{
                "ticker": "XXX",
                "ver_id": "xxx--v1.0.0",
                "action": ActionType.DEAD,
            }],
        },
    }
    findings = build_findings(
        [_xxx_coin()], report_repos, dict(_EMPTY_LOCAL), dict(_EMPTY_PORTS), None
    )
    block = next(f for f in findings if f["id"] == "REPO-ACTION")["versions"]
    for key in ("declared", "missing", "found", "newer_same", "newer_alt"):
        assert block[key] == [], key
    assert block["tag_count"] is None
    assert block["conf"] == "xxx--v1.0.0"


def test_non_repo_findings_carry_the_versions_key_as_null():
    from audit_manifest.findings import build_findings

    local = dict(_EMPTY_LOCAL)
    local["missing_wallet_conf"] = [("XXX", "xxx--v1.0.0", "xxx--v1.0.0.conf")]
    findings = build_findings(
        [_xxx_coin()], {}, local, dict(_EMPTY_PORTS), None
    )
    assert findings, "the missing conf must produce a finding"
    for f in findings:
        assert "versions" in f, f["id"]
        assert f["versions"] is None, f["id"]


def test_fee_fixer_never_falls_back_to_ver_id_and_never_skips_silently(caplog):
    """The fixer must not treat ver_id as a tag, and must log any skip.

    A fleet entry with no declared versions is already reported upstream
    as ``no-tag`` (the param-check short-circuits before any fixer runs);
    this guard covers malformed entries handed to the fixer directly — it
    must never substitute the ver_id suffix for a tag, and its skip must
    be logged like every sibling fixer warning instead of returning ``{}``
    silently.
    """
    import logging

    from audit_manifest.fixes import ConfigAutoFixer

    coin = ManifestCoin(ticker="XXX", ver_id="xxx--v9.9.9", versions=[])

    # Any fallback reintroduction must stay offline: resolve_source never
    # runs a real clone attempt (60 s timeout). The fallback itself is
    # detected through the missing "no declared versions" warning below —
    # the AssertionError it raises here is swallowed by fix_fee_margin's
    # broad except and only serves to prevent network I/O.
    with mock.patch.object(
        SourceCheckoutManager, "resolve_source",
        side_effect=AssertionError("a fallback tag reached resolve_source"),
    ):
        with caplog.at_level(logging.WARNING):
            assert ConfigAutoFixer.fix_fee_margin(REPO_ROOT, coin) == {}
    assert any("no declared versions" in r.getMessage() for r in caplog.records), (
        "the skip must be logged like every sibling fixer warning"
    )
