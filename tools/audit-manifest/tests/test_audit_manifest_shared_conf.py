#!/usr/bin/env python3
"""
Test for plan L — multi-version shared-conf clarity (SHARED-CONF INFO).

Proof-first: LTC 9 tags / BLOCK 7 tags share oldest conf, per-version loop must stay intact,
REUSE-DRIFT WARN only when any_differs>0, clean sharing emits INFO not WARN,
INFO does not increment warn and does not bubble under --strict-per-version.
"""
from pathlib import Path
from unittest import mock

import audit_manifest as audit

ManifestCoin = audit.ManifestCoin
ParamAuditEngine = audit.ParamAuditEngine
ParamStatus = audit.ParamStatus
SourceCheckoutManager = audit.SourceCheckoutManager

# <repo>/tools/audit-manifest/tests/<this file> -> <repo>
REPO_ROOT = Path(__file__).resolve().parents[3]


def _make_engine():
    return ParamAuditEngine(SourceCheckoutManager())


def _mock_audit_version_clean(coin, repo_root, version_tag, wallet_conf, xbridge_conf, timeout, fees_only=False):
    # All clean: no DIFFERS, no FAIL, maybe INFO/MATCH mix — differs=0
    res = audit.ParamAuditResult(tag=version_tag, source="/tmp/fake", mode="reused", version=version_tag, wallet_conf=wallet_conf, xbridge_conf=xbridge_conf)
    res.fail = 0
    res.differs = 0
    res.warn = 0
    res.checks = [audit.CheckFinding(id="FEES", status=ParamStatus.MATCH, detail="ok")]
    return res


def _mock_audit_version_one_drift(coin, repo_root, version_tag, wallet_conf, xbridge_conf, timeout, fees_only=False):
    res = audit.ParamAuditResult(tag=version_tag, source="/tmp/fake", mode="reused", version=version_tag, wallet_conf=wallet_conf, xbridge_conf=xbridge_conf)
    if version_tag == "v0.21.5.6":  # pick last LTC tag as drifted
        res.differs = 1
        res.checks = [audit.CheckFinding(id="PORT", status=ParamStatus.DIFFERS, detail="drift")]
    else:
        res.differs = 0
        res.checks = [audit.CheckFinding(id="PORT", status=ParamStatus.MATCH, detail="ok")]
    res.fail = 0
    res.warn = 0
    return res


def _ltc_coin():
    return ManifestCoin(
        ticker="LTC",
        ver_id="litecoin--v0.21.1",
        versions=["v0.21.1","v0.21.2","v0.21.2.1","v0.21.2.2","v0.21.3","v0.21.4","v0.21.5.4","v0.21.5.5","v0.21.5.6"],
        wallet_conf="litecoin--v0.21.1.conf",
        xbridge_conf="litecoin--v0.21.1.conf",
        repo_url="https://github.com/litecoin-project/litecoin",
    )


def _block_coin():
    return ManifestCoin(
        ticker="BLOCK",
        ver_id="blocknet--v4.2.0",
        versions=["v4.2.0","v4.3.0","v4.3.1","v4.3.2","v4.3.3","v4.4.0","v4.4.1"],
        wallet_conf="blocknet--v4.2.0.conf",
        xbridge_conf="blocknet--v4.2.0.conf",
        repo_url="https://github.com/blocknetdx/blocknet",
    )


def test_ltc_per_version_len_and_shared_conf_info_clean():
    eng = _make_engine()
    coin = _ltc_coin()
    with mock.patch.object(eng, "audit_version", side_effect=_mock_audit_version_clean):
        res = eng.audit_coin_all_versions(coin, REPO_ROOT, timeout=10, strict=False)
    assert len(res.per_version) == 9, f"LTC per_version len expected 9 got {len(res.per_version)}"
    # sharing single pair but clean => SHARED-CONF INFO, no REUSE-DRIFT
    ids = [c.id for c in res.checks]
    assert "SHARED-CONF" in ids, f"clean sharing should emit SHARED-CONF INFO, got {ids}"
    assert "REUSE-DRIFT" not in ids
    # INFO must not increment warn
    assert res.warn == 0, f"INFO should not increment warn, got {res.warn}"
    shared = [c for c in res.checks if c.id == "SHARED-CONF"][0]
    assert shared.status == ParamStatus.INFO
    assert "9 versions share conf pair" in shared.detail
    assert "per-version fact-check clean" in shared.detail
    # conf_pair_for_version invariant for LTC
    assert all(p["wallet_conf"] == "litecoin--v0.21.1.conf" for p in res.per_version)
    assert all(p["xbridge_conf"] == "litecoin--v0.21.1.conf" for p in res.per_version)


def test_block_per_version_len_and_shared_conf_info_clean():
    eng = _make_engine()
    coin = _block_coin()
    with mock.patch.object(eng, "audit_version", side_effect=_mock_audit_version_clean):
        res = eng.audit_coin_all_versions(coin, REPO_ROOT, timeout=10, strict=False)
    assert len(res.per_version) == 7, f"BLOCK per_version len expected 7 got {len(res.per_version)}"
    ids = [c.id for c in res.checks]
    assert "SHARED-CONF" in ids
    assert "REUSE-DRIFT" not in ids
    assert res.warn == 0
    shared = [c for c in res.checks if c.id == "SHARED-CONF"][0]
    assert shared.status == ParamStatus.INFO
    assert "7 versions share conf pair" in shared.detail


def test_reuse_drift_warn_when_any_differs():
    eng = _make_engine()
    coin = _ltc_coin()
    with mock.patch.object(eng, "audit_version", side_effect=_mock_audit_version_one_drift):
        res = eng.audit_coin_all_versions(coin, REPO_ROOT, timeout=10, strict=False)
    ids = [c.id for c in res.checks]
    assert "REUSE-DRIFT" in ids, f"drift should emit REUSE-DRIFT WARN, got {ids}"
    assert "SHARED-CONF" not in ids, "drift must not also emit SHARED-CONF"
    drift = [c for c in res.checks if c.id == "REUSE-DRIFT"][0]
    assert drift.status == ParamStatus.WARN
    assert res.warn == 1, f"REUSE-DRIFT should increment warn to 1, got {res.warn}"


def test_info_does_not_bubble_strict():
    eng = _make_engine()
    coin = _ltc_coin()
    # Clean sharing -> INFO entry, per_version all INFO/MATCH (worst INFO)
    # strict should NOT bubble INFO to entry as STRICT-BUBBLE
    with mock.patch.object(eng, "audit_version", side_effect=_mock_audit_version_clean):
        res = eng.audit_coin_all_versions(coin, REPO_ROOT, timeout=10, strict=True)
    ids = [c.id for c in res.checks]
    # SHARED-CONF INFO present, but no STRICT-BUBBLE with INFO
    assert "SHARED-CONF" in ids
    strict_bubbles = [c for c in res.checks if c.id == "STRICT-BUBBLE"]
    # Should be zero because worst_pv is INFO/MATCH which we suppress
    assert len(strict_bubbles) == 0, f"INFO should not bubble, got {strict_bubbles}"
    assert res.warn == 0


def test_warn_does_bubble_strict_when_drift():
    eng = _make_engine()
    # Make entry clean initially but per_version has WARN worse than entry INFO
    def mock_warn(coin, repo_root, version_tag, wallet_conf, xbridge_conf, timeout, fees_only=False):
        res = audit.ParamAuditResult(tag=version_tag, source="/tmp/fake", mode="reused", version=version_tag, wallet_conf=wallet_conf, xbridge_conf=xbridge_conf)
        # First version WARN, others MATCH
        if version_tag == "v0.21.1":
            res.warn = 1
            res.checks = [audit.CheckFinding(id="FEES", status=ParamStatus.WARN, detail="thin")]
        else:
            res.checks = [audit.CheckFinding(id="FEES", status=ParamStatus.MATCH, detail="ok")]
        res.fail = 0
        res.differs = 0
        return res

    # To make entry not WARN, we need entry_tag to be not the WARN tag.
    # LTC entry_tag is max_version_tag = v0.21.5.6 (lexically max), which in our mock returns MATCH, so entry will be MATCH+INFO
    # per_version worst is WARN (from v0.21.1) -> should bubble.
    coin = _ltc_coin()
    with mock.patch.object(eng, "audit_version", side_effect=mock_warn):
        res = eng.audit_coin_all_versions(coin, REPO_ROOT, timeout=10, strict=True)
    ids = [c.id for c in res.checks]
    assert "SHARED-CONF" in ids  # clean sharing still INFO (no DIFFERS)
    bubbles = [c for c in res.checks if c.id == "STRICT-BUBBLE"]
    assert len(bubbles) == 1, f"WARN should bubble, got {bubbles}"
    assert bubbles[0].status == ParamStatus.WARN
    assert res.warn == 1  # bubbled WARN increments

def test_single_version_no_shared_conf():
    eng = _make_engine()
    coin = ManifestCoin(ticker="BTC", ver_id="bitcoin--v22-final", versions=["v22-final"], wallet_conf="bitcoin--v22-final.conf", xbridge_conf="bitcoin--v22-final.conf", repo_url="https://github.com/bitcoin/bitcoin")
    with mock.patch.object(eng, "audit_version", side_effect=_mock_audit_version_clean):
        res = eng.audit_coin_all_versions(coin, REPO_ROOT, timeout=10, strict=False)
    assert len(res.per_version) == 1
    ids = [c.id for c in res.checks]
    assert "SHARED-CONF" not in ids
    assert "REUSE-DRIFT" not in ids
