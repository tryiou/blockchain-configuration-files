#!/usr/bin/env python3
"""
Mandatory hard-fork (changelog) findings drive two separate decisions.

should_skip_version_bump() keeps --update-versions away from a repo whose
newest release is a mandatory upgrade, and entry_changelog_quote() must
surface every mandatory finding for a manifest entry rather than only the
first one it happens to walk into.
"""

import audit_manifest as audit


def test_update_versions_skips_mandatory_hardfork():
    assert audit.should_skip_version_bump({"status": "ALIVE", "changelog_mandatory": True}) is True
    assert audit.should_skip_version_bump({"status": "ALIVE", "changelog_mandatory": False}) is False
    assert audit.should_skip_version_bump({"status": "ALIVE"}) is False


def test_entry_quote_joins_all_mandatory_findings():
    findings = [
        {"tag": "v2", "quote": "hard fork at v2", "source": "release"},
        {"tag": "v3", "quote": "mandatory upgrade at v3", "source": "release"},
    ]
    q = audit.entry_changelog_quote(findings, ["v2"], ["v3"])
    assert "hard fork at v2" in q and "mandatory upgrade at v3" in q, f"quotes dropped: {q!r}"
    assert audit.entry_changelog_quote([], ["v2"], []) == ""
