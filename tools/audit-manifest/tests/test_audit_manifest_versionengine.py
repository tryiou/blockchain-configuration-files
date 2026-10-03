#!/usr/bin/env python3
"""
Test for Generic VersionEngine prefix — handle any leading letters (nc, vnc, sc)
Proof-first R9: must FAIL before fix (nc cases None) and PASS after.
"""
import pytest

import audit_manifest as audit

VersionEngine = audit.VersionEngine
ManifestCoin = audit.ManifestCoin


# ---------------------------------------------------------------------------
# parse_version
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("tag,expected", [
    ("nc0.20.0", (0, 20, 0)),
    ("vnc0.20.0", (0, 20, 0)),
    ("nc0.21.0", (0, 21, 0)),
    ("sc0.18", (0, 18)),
    ("v22-final", (22,)),
    ("0.90.9.10", (0, 90, 9, 10)),
    ("v0.8.5emc", (0, 8, 5)),
    ("3.0.5", (3, 0, 5)),
    ("da839021c", None),
    ("abc", None),
    ("", None),
    ("v1.2.3-beta1", (1, 2, 3)),
])
def test_parse_version(tag, expected):
    assert VersionEngine.parse_version(tag) == expected


def test_parse_version_additional_colx():
    assert VersionEngine.parse_version("v1.2.5") == (1, 2, 5)


def test_parse_version_swift_variants():
    # SWIFT 3.0.5 vs v3.0.5 both should parse identically
    assert VersionEngine.parse_version("3.0.5") == (3, 0, 5)
    assert VersionEngine.parse_version("v3.0.5") == (3, 0, 5)


def test_parse_version_mrx():
    assert VersionEngine.parse_version("4.2.0.1") == (4, 2, 0, 1)


def test_parse_version_hash_guard():
    # da839021c must stay None while v22-final must stay (22,)
    assert VersionEngine.parse_version("da839021c") is None
    assert VersionEngine.parse_version("v22-final") == (22,)


# ---------------------------------------------------------------------------
# is_prerelease generic
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("tag,expected", [
    ("nc0.20.0-beta1", True),
    ("vnc0.20.0-rc2", True),
    ("sc0.18", False),
    ("v1.2.3-beta1", True),
    ("da839021c", False),
    ("v22-final", False),
])
def test_is_prerelease(tag, expected):
    assert VersionEngine.is_prerelease(tag) is expected


def test_is_prerelease_additional():
    assert VersionEngine.is_prerelease("nc0.20.0-alpha1") is True
    assert VersionEngine.is_prerelease("v0.8.5emc") is False  # emc not a prerelease marker
    assert VersionEngine.is_prerelease("v1.2.5") is False


# ---------------------------------------------------------------------------
# stable_tags
# ---------------------------------------------------------------------------

def test_stable_tags_exclude_beta():
    tags = {"v1.2.3", "v1.2.3-beta1", "v1.2.4-rc1", "nc0.20.0", "nc0.20.0-beta1"}
    stable = VersionEngine.stable_tags(tags)
    assert "v1.2.3" in stable
    assert "nc0.20.0" in stable
    assert "v1.2.3-beta1" not in stable
    assert "v1.2.4-rc1" not in stable
    assert "nc0.20.0-beta1" not in stable

def test_stable_tags_none():
    assert VersionEngine.stable_tags(None) is None


# ---------------------------------------------------------------------------
# max_version_tag native display
# ---------------------------------------------------------------------------

def test_max_version_tag_native_display():
    tags = {"nc0.20.0", "nc0.21.0", "nc0.20.1"}
    assert VersionEngine.max_version_tag(tags) == "nc0.21.0"

def test_max_version_tag_mixed_prefix():
    # Should keep native tag verbatim, not normalized
    tags = {"v1.2.5", "1.2.6"}
    # numeric ordering: 1.2.6 > 1.2.5, so best is 1.2.6 verbatim
    assert VersionEngine.max_version_tag(tags) == "1.2.6"

def test_max_version_tag_ignores_hash():
    tags = {"nc0.20.0", "da839021c", "nc0.21.0"}
    assert VersionEngine.max_version_tag(tags) == "nc0.21.0"


# ---------------------------------------------------------------------------
# detect_newer — NMC case
# ---------------------------------------------------------------------------

def test_detect_newer_nmc():
    # Simulate NMC held nc0.20.0 vs remote {nc0.20.0, nc0.21.0, nc0.20.1, da839021c}
    coin = ManifestCoin(ticker="NMC", ver_id="namecoin--nc0.20.0", versions=["nc0.20.0"])
    remote = {"nc0.20.0", "nc0.21.0", "nc0.20.1", "da839021c"}
    newer_same, newer_alt = VersionEngine.detect_newer(remote, [coin])
    # Hash must not be counted
    assert "da839021c" not in newer_same and "da839021c" not in newer_alt
    # nc0.21.0 must be detected as newer_same (same len 3)
    assert "nc0.21.0" in newer_same
    # nc0.20.1 may also be newer_same if ordering allows; check at least that newer_same is non-empty
    assert len(newer_same) >= 1
    # All newer tags should be > held
    for t in newer_same + newer_alt:
        assert VersionEngine.parse_version(t) > VersionEngine.parse_version("nc0.20.0")

def test_detect_newer_btc_regression():
    # BTC held v22-final (22,) vs remote v23.0 (23,0) → different len → newer_alt
    coin = ManifestCoin(ticker="BTC", ver_id="bitcoin--v22-final", versions=["v22-final"])
    remote = {"v22-final", "v23.0"}
    newer_same, newer_alt = VersionEngine.detect_newer(remote, [coin])
    # v23.0 is (23,0) len 2 vs held len 1 → should be newer_alt
    assert "v23.0" in newer_alt
    assert "v23.0" not in newer_same
    # Also test same-len case: remote v23 → newer_same
    remote2 = {"v22-final", "v23"}
    ns2, na2 = VersionEngine.detect_newer(remote2, [coin])
    assert "v23" in ns2
    assert "v23" not in na2

def test_detect_newer_none():
    assert VersionEngine.detect_newer(None, []) == ([], [])


def test_detect_newer_stable_filter():
    # prerelease remote tags must be ignored
    coin = ManifestCoin(ticker="NMC", ver_id="namecoin--nc0.20.0", versions=["nc0.20.0"])
    remote = {"nc0.20.0", "nc0.21.0-beta1", "nc0.21.0"}
    ns, na = VersionEngine.detect_newer(remote, [coin])
    assert "nc0.21.0-beta1" not in ns and "nc0.21.0-beta1" not in na
    assert "nc0.21.0" in ns

# ---------------------------------------------------------------------------
# fleet diversity regression checks
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("tag,expected", [
    ("v1.2.5", (1, 2, 5)),      # COLX
    ("v22-final", (22,)),       # BTC
    ("4.2.0.1", (4, 2, 0, 1)),  # MRX
    ("3.0.5", (3, 0, 5)),       # SWIFT
    ("v3.0.5", (3, 0, 5)),      # SWIFT variant
    ("0.90.9.10", (0, 90, 9, 10)),  # BTX
    ("v0.8.5emc", (0, 8, 5)),   # EMC
])
def test_fleet_diversity_parse(tag, expected):
    assert VersionEngine.parse_version(tag) == expected


# ---------------------------------------------------------------------------
# ManifestCoin.expected_tags phantom union — exact string semantics
# ---------------------------------------------------------------------------

def test_expected_tags_mrx_phantom_union():
    # MRX: versions ["4.2.0.1"] vs ver_id suffix "v4.2.0.1" => union both forms
    coin = ManifestCoin(ticker="MRX", ver_id="metrix--v4.2.0.1", versions=["4.2.0.1"])
    assert coin.expected_tags() == ["4.2.0.1", "v4.2.0.1"]


def test_expected_tags_swift_phantom_union():
    # SWIFT: opposite direction — ver_id "3.0.5" vs versions ["v3.0.5"]
    coin = ManifestCoin(ticker="SWIFT", ver_id="swiftcash--3.0.5", versions=["v3.0.5"])
    assert coin.expected_tags() == ["3.0.5", "v3.0.5"]


def test_expected_tags_no_phantom_when_consistent():
    coin = ManifestCoin(ticker="BTC", ver_id="bitcoin--v22-final", versions=["v22-final"])
    assert coin.expected_tags() == ["v22-final"]


def test_expected_tags_exact_match_drives_missing():
    # Exact semantics: FOUND iff byte-equal to remote tag. MRX remote has
    # only "4.2.0.1" — phantom "v4.2.0.1" must remain MISSING and would drive REVIEW.
    coin = ManifestCoin(ticker="MRX", ver_id="metrix--v4.2.0.1", versions=["4.2.0.1"])
    expected = coin.expected_tags()
    remote_tags = {"4.2.0.1", "4.1.0.0"}  # no v-prefix variant upstream
    missing = [t for t in expected if t not in remote_tags]
    found = [t for t in expected if t not in missing]
    assert found == ["4.2.0.1"]
    assert missing == ["v4.2.0.1"]
    # union is intentionally not deduplicated via canonical/strip_v
    assert VersionEngine.parse_version("4.2.0.1") == VersionEngine.parse_version("v4.2.0.1")
    # but strings remain distinct — exact match only
    assert "v4.2.0.1" not in remote_tags
