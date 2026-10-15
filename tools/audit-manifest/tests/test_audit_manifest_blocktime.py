#!/usr/bin/env python3
"""
Test for Generic CURRENT_CHAIN + BlockTime height-gate (plan 07)
Proof-first: generic TargetSpacing height scan must handle
 - simple if (nHeight > 900000) nPowTargetSpacing=45
 - QTUM nPow 128, nRBT 32, nReduce 845000 -> 32
 - UNO 180 via BlocksTargetSpacing
 - FIRO MTP/2 -> 150

These must FAIL before fix (raw fallback) and PASS after generic height-gate fallback.
"""

import shutil
import tempfile
from pathlib import Path
from unittest import mock

import audit_manifest as audit

CppSourceInspector = audit.CppSourceInspector
SourceReader = audit.SourceReader
_safe_arith_float = audit._safe_arith_float


def _run_effective(main_txt: str, slurp_map: dict):
    """Run _effective_blocktime with mocked slurps."""
    # create temp src_dir for _slurp_any (though we mock, need a Path)
    tmp = Path(tempfile.mkdtemp())
    try:
        # start/end is whole main_txt (simulate mainnet slice 0..len)
        start, end = 0, len(main_txt)
        # patch SourceReader.slurp and slurp_src to return from slurp_map
        orig_slurp = SourceReader.slurp
        orig_slurp_src = SourceReader.slurp_src

        def mock_slurp(p):
            # p is Path
            for k, v in slurp_map.items():
                if str(p).endswith(k):
                    return v
            return orig_slurp(p)

        def mock_slurp_src(src_dir, rel):
            if rel in slurp_map:
                return slurp_map[rel]
            return orig_slurp_src(src_dir, rel)

        with (
            mock.patch.object(SourceReader, "slurp", side_effect=mock_slurp),
            mock.patch.object(SourceReader, "slurp_src", side_effect=mock_slurp_src),
        ):
            val, ln, ev = CppSourceInspector._effective_blocktime(tmp, main_txt, start, end)
        return val, ln, ev
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_generic_height_gate_simple():
    main_txt = """
class CMainParams {
    consensus.nPowTargetSpacing = 60;
}
"""
    pow_cpp = """
#include "pow.h"
if (nHeight > 900000) {
    nPowTargetSpacing = 45;
}
"""
    val, _ln, ev = _run_effective(main_txt, {"src/pow.cpp": pow_cpp})
    assert val == 45, f"generic height gate should pick 45 from 900000 gate, got {val} ev={ev}"


def test_generic_height_gate_max_height():
    main_txt = """
class CMainParams {
    consensus.nPowTargetSpacing = 120;
}
"""
    pow_cpp = """
if (nHeight > 500000) nPowTargetSpacing = 60;
if (nHeight > 900000) nPowTargetSpacing = 45;
"""
    val, _ln, ev = _run_effective(main_txt, {"src/pow.cpp": pow_cpp})
    assert val == 45, f"should pick max height 900000 ->45, got {val} ev={ev}"


def test_qtum_rbt_still_32():
    main_txt = """
class CMainParams {
    consensus.nPowTargetSpacing = 128;
    consensus.nRBTPowTargetSpacing = 32;
    consensus.nReduceBlocktimeHeight = 845000;
}
"""
    val, _ln, ev = _run_effective(main_txt, {})
    assert val == 32, f"QTUM RBT should be 32, got {val} ev={ev}"


def test_uno_kgw_180():
    main_txt = """
class CMainParams {
    consensus.nPowTargetSpacing = 60;
}
"""
    pow_cpp = """
// KimotoGravityWell
#include "pow.h"
int64_t BlocksTargetSpacing = 3*60;
 // PROOF_OF_WORK_FORK_BLOCK
"""
    val, _ln, ev = _run_effective(main_txt, {"src/pow.cpp": pow_cpp})
    assert val == 180, f"UNO KGW should be 180, got {val} ev={ev}"


def test_firo_mtp_half_150():
    # MTP spacing 300 -> effective 150 via /2
    main_txt = """
class CMainParams {
    consensus.nPowTargetSpacing = 600;
    consensus.nPowTargetSpacingMTP = 300;
}
"""
    pow_cpp = """
int GetTargetBlocksSpacing(int height) {
    if (height >= stage3StartTime) return nPowTargetSpacingMTP/2;
    return nPowTargetSpacing;
}
int stage3StartTime = 1000000;
"""
    val, _ln, ev = _run_effective(main_txt, {"src/pow.cpp": pow_cpp})
    assert val == 150, f"FIRO MTP/2 should be 150, got {val} ev={ev}"


def test_generic_fallback_when_no_gate_returns_raw():
    main_txt = """
class CMainParams {
    consensus.nPowTargetSpacing = 60;
}
"""
    val, _ln, ev = _run_effective(main_txt, {})
    assert val == 60, f"no gate should return raw 60, got {val} ev={ev}"
