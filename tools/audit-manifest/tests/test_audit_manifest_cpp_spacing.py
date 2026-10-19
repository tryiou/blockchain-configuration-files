#!/usr/bin/env python3
"""Blocktime spacing extraction: raw, fork-aware overrides, and refusals.

``check_blocktime`` is the fleet's BlockTime verdict. Its effective
spacing is the raw mainnet value EXCEPT when a fork-aware override is
really present in the source: PoS faster than PoW, QTUM-style reduced
blocktime, FIRO-style MTP halving, UNO-style KGW, or a height-gated
TargetSpacing. Each override below is exercised through the public
checker with one synthetic tree, and the refusal paths are pinned so a
missing marker never becomes a guessed PASS.
"""

import audit_manifest as audit


def _coin():
    return audit.ManifestCoin(ticker="HYPO", ver_id="hypo--v1", daemon_family="cpp")


def _chainparams(tmp_path, main_body):
    """A chainparams.cpp with a mainnet class holding ``main_body``.

    The mainnet slice runs to the next ``class C...``, so the following
    testnet class bounds it exactly like a real file.
    """
    (tmp_path / "src").mkdir(parents=True, exist_ok=True)
    (tmp_path / "src" / "chainparams.cpp").write_text(
        "// chainparams.cpp\n\nclass CMainParams : public CChainParams {\npublic:\n"
        + main_body
        + "\n};\n\nclass CTestNetParams : public CChainParams {\npublic:\n    int64_t nPowTargetSpacing = 60;\n};\n",
        encoding="utf-8",
    )
    return tmp_path


def _check(tmp_path, xc, *, want_test=False):
    return audit.CppSourceInspector.check_blocktime(_coin(), tmp_path, xc, want_test=want_test, repo_root=tmp_path)


def test_raw_pow_spacing_is_effective(tmp_path):
    _chainparams(tmp_path, "    int64_t nPowTargetSpacing = 600;\n")
    st, det = _check(tmp_path, {"BlockTime": "600"})
    assert st == audit.ParamStatus.PASS, det
    assert "raw effective 600" in det, det
    st_w, det_w = _check(tmp_path, {"BlockTime": "300"})
    assert st_w == audit.ParamStatus.WARN and "raw effective 600" in det_w, det_w


def test_pos_spacing_wins_when_faster_than_pow(tmp_path):
    _chainparams(
        tmp_path,
        "    int64_t nPowTargetSpacing = 600;\n    int64_t nTargetSpacing = 60;\n    int nStakeMinConf = 60;\n",
    )
    st, det = _check(tmp_path, {"BlockTime": "60"})
    assert st == audit.ParamStatus.PASS, det
    assert "PoS effective 60.0 (raw PoW 600.0)" in det, det


def test_pos_spacing_via_npos_variant(tmp_path):
    _chainparams(
        tmp_path,
        "    int64_t nPowTargetSpacing = 600;\n"
        "    int64_t nPowTargetSpacingV2 = 300;\n"
        "    int64_t nPosTargetSpacing = 120;\n",
    )
    st, det = _check(tmp_path, {"BlockTime": "120"})
    assert st == audit.ParamStatus.PASS, det
    assert "nPosTargetSpacing" in det and "PoS effective 120" in det, det


def test_rbt_reduced_blocktime_override(tmp_path):
    _chainparams(
        tmp_path,
        "    int64_t nPowTargetSpacing = 600;\n"
        "    int64_t nRBTPowTargetSpacing = 120;\n"
        "    int nReduceBlocktimeHeight = 865000;\n",
    )
    st, det = _check(tmp_path, {"BlockTime": "120"})
    assert st == audit.ParamStatus.PASS, det
    assert "nRBTPowTargetSpacing:6 effective 120.0 (raw 600.0)" in det, det


def test_mtp_halving_override(tmp_path):
    _chainparams(tmp_path, "    int64_t nPowTargetSpacing = 600;\n")
    (tmp_path / "src" / "pow.cpp").write_text(
        "#include <pow.h>\n\n"
        "const int64_t nPowTargetSpacingMTP = 300;\n\n"
        "int64_t GetTargetBlocksSpacing(int nHeight) {\n"
        "    if (nHeight > stage3StartTime) return nPowTargetSpacingMTP / 2;\n"
        "    return nPowTargetSpacing;\n}\n",
        encoding="utf-8",
    )
    st, det = _check(tmp_path, {"BlockTime": "150"})
    assert st == audit.ParamStatus.PASS, det
    assert "nPowTargetSpacingMTP/2:3 effective 150.0 (raw 600.0)" in det, det


def test_mtp_without_halving_uses_full_mtp_value(tmp_path):
    _chainparams(tmp_path, "    int64_t nPowTargetSpacing = 600;\n")
    (tmp_path / "src" / "pow.cpp").write_text(
        "#include <pow.h>\n\n"
        "const int64_t nPowTargetSpacingMTP = 300;\n\n"
        "int64_t GetTargetBlocksSpacing(int nHeight) {\n"
        "    return nPowTargetSpacingMTP;\n}\n",
        encoding="utf-8",
    )
    st, det = _check(tmp_path, {"BlockTime": "300"})
    assert st == audit.ParamStatus.PASS, det
    assert "nPowTargetSpacingMTP:3 effective 300.0" in det, det


def test_kgw_override(tmp_path):
    _chainparams(tmp_path, "    int64_t nPowTargetSpacing = 60;\n")
    (tmp_path / "src" / "pow.cpp").write_text(
        "#include <pow.h>\n\n"
        "unsigned int KimotoGravityWell(const CBlockIndex* pindex) {\n"
        "    return 1;\n}\n\n"
        "static const int64_t BlocksTargetSpacing = 3 * 60;\n",
        encoding="utf-8",
    )
    st, det = _check(tmp_path, {"BlockTime": "180"})
    assert st == audit.ParamStatus.PASS, det
    assert "BlocksTargetSpacing:7 KGW effective 180.0 (raw 60.0)" in det, det


def test_height_gated_target_spacing_override(tmp_path):
    _chainparams(tmp_path, "    int64_t nPowTargetSpacing = 600;\n")
    (tmp_path / "src" / "validation.cpp").write_text(
        "#include <validation.h>\n\n"
        "int64_t EffectiveSpacing(int nHeight) {\n"
        "    if (nHeight > 300000) {\n"
        "        int64_t nTargetSpacing = 30;\n"
        "        return nTargetSpacing;\n"
        "    }\n"
        "    return 600;\n}\n",
        encoding="utf-8",
    )
    st, det = _check(tmp_path, {"BlockTime": "30"})
    assert st == audit.ParamStatus.PASS, det
    assert "generic height-gated TargetSpacing" in det and "h=300000 effective 30" in det, det


def test_raw_identifier_resolves_to_vsuffix_definition(tmp_path):
    _chainparams(
        tmp_path,
        "    int64_t nPowTargetSpacing = consensus.nPowTargetSpacingV2;\n    int64_t nPowTargetSpacingV2 = 300;\n",
    )
    st, det = _check(tmp_path, {"BlockTime": "300"})
    assert st == audit.ParamStatus.PASS, det
    assert "nPowTargetSpacing->nPowTargetSpacingV2" in det, det


def test_opaque_raw_falls_back_to_any_vsuffix(tmp_path):
    _chainparams(
        tmp_path,
        "    int64_t nPowTargetSpacing = nPowTargetSpacingOld;\n"
        "    int64_t nPowTargetSpacingOld = 900;\n"
        "    int64_t nPowTargetSpacingV2 = 300;\n",
    )
    st, det = _check(tmp_path, {"BlockTime": "300"})
    assert st == audit.ParamStatus.PASS, det
    assert "->V*" in det, det


def test_testnet_slice_used_when_want_test(tmp_path):
    _chainparams(tmp_path, "    int64_t nPowTargetSpacing = 600;\n")
    st, det = _check(tmp_path, {"BlockTime": "60"}, want_test=True)
    assert st == audit.ParamStatus.PASS, det
    # The testnet class's own spacing and line, not the mainnet 600.
    assert "src/chainparams.cpp:11" in det and "60" in det, det


def test_no_spacing_marker_is_unresolved(tmp_path):
    _chainparams(tmp_path, "    int nPort = 9333;\n")
    st, det = _check(tmp_path, {"BlockTime": "600"})
    assert st == audit.ParamStatus.UNRESOLVED, det
    assert "no effective target-spacing found" in det, det


def test_missing_chainparams_is_unresolved(tmp_path):
    st, det = _check(tmp_path, {"BlockTime": "600"})
    assert st == audit.ParamStatus.UNRESOLVED and "chainparams.cpp not found" in det, det


def test_blocktime_conf_refusals(tmp_path):
    _chainparams(tmp_path, "    int64_t nPowTargetSpacing = 600;\n")
    st_nan, det_nan = _check(tmp_path, {"BlockTime": "soon"})
    assert st_nan == audit.ParamStatus.FAIL and "non-numeric" in det_nan, det_nan
    st_zero, det_zero = _check(tmp_path, {"BlockTime": "0"})
    assert st_zero == audit.ParamStatus.FAIL and "rejected by blocknet" in det_zero, det_zero
