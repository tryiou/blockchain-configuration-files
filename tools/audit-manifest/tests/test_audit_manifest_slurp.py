#!/usr/bin/env python3
"""
Proof-first tests for generic _slurp depth + guards (plan 08)
- src_dir/rel direct depth0
- depth1 divi/src
- depth2 a/b/src
- depth3 a/b/c/src found (generic BFS)
- depth4 a/b/c/d/src None (capped)
- symlink link->a ignored
- .git/src ignored
- non-src rel only direct

These must FAIL before fix (depth3 not found, symlink/.git not guarded)
and PASS after BFS depth≤3 with .git/symlink guard.
"""
import importlib.util
import os
import shutil
import sys
import tempfile
from pathlib import Path

AUDIT_PATH = Path(__file__).resolve().parents[1] / "audit-manifest.py"
spec = importlib.util.spec_from_file_location("audit_manifest_slurp", str(AUDIT_PATH))
audit = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = audit
spec.loader.exec_module(audit)

SourceReader = audit.SourceReader

def _mktree(struct):
    """struct: dict path -> content ; create temp root and return Path"""
    tmp = Path(tempfile.mkdtemp())
    for rel, content in struct.items():
        p = tmp / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content)
    return tmp

def test_depth0_direct():
    tmp = _mktree({"src/chainparams.cpp": "direct"})
    try:
        txt = SourceReader.slurp_src(tmp, "src/chainparams.cpp")
        assert txt == "direct", f"depth0 direct failed got {txt!r}"
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

def test_depth1_divi_src():
    tmp = _mktree({"divi/src/chainparams.cpp": "depth1"})
    try:
        txt = SourceReader.slurp_src(tmp, "src/chainparams.cpp")
        assert txt == "depth1", f"depth1 divi/src failed got {txt!r}"
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

def test_depth2_a_b_src():
    tmp = _mktree({"a/b/src/chainparams.cpp": "depth2"})
    try:
        txt = SourceReader.slurp_src(tmp, "src/chainparams.cpp")
        assert txt == "depth2", f"depth2 a/b/src failed got {txt!r}"
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

def test_depth3_a_b_c_src_found():
    tmp = _mktree({"a/b/c/src/chainparams.cpp": "depth3"})
    try:
        txt = SourceReader.slurp_src(tmp, "src/chainparams.cpp")
        assert txt == "depth3", f"depth3 a/b/c/src should be found (generic BFS), got {txt!r}"
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

def test_depth4_a_b_c_d_src_none_capped():
    tmp = _mktree({"a/b/c/d/src/chainparams.cpp": "depth4"})
    try:
        txt = SourceReader.slurp_src(tmp, "src/chainparams.cpp")
        assert txt is None, f"depth4 a/b/c/d/src must be None (capped depth≤3), got {txt!r}"
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

def test_symlink_ignored():
    tmp = Path(tempfile.mkdtemp())
    try:
        # real dir a/src/chainparams.cpp
        (tmp / "a" / "src").mkdir(parents=True)
        (tmp / "a" / "src" / "chainparams.cpp").write_text("real")
        # symlink link -> a
        os.symlink(tmp / "a", tmp / "link")
        # also create a nested file via symlink path but not via real non-symlink depth?
        # Now slurp should find via a (real) but not via link (ignored).
        # To test symlink ignored specifically: remove real a's file and create only via symlink target?
        # Better: create separate case where only symlink location holds file
        tmp2 = Path(tempfile.mkdtemp())
        (tmp2 / "a" / "src").mkdir(parents=True)
        (tmp2 / "a" / "src" / "chainparams.cpp").write_text("via_a")
        os.symlink(tmp2 / "a", tmp2 / "link")
        # Now remove the real path's file and rely on link? Instead create case where file only under link's target but we ensure link is not traversed:
        # Simpler: tmp3 where src/chainparams.cpp does NOT exist, and only link/src/chainparams.cpp exists via symlink indirection?
        # Actually symlink at top level: link -> a, and a/src exists, then traversing link would find file. We want to ensure link is ignored, so if we delete a/src file and create a differently named target?
        # Let's construct: tmp with only link->a and a holds file, but also ensure no non-symlink path holds file except via link.
        # We'll test: create tmp4 with a/src/chainparams.cpp, plus link->a, then delete a and recreate? Complex.

        # Simpler deterministic: Create tmp_sym where we place file ONLY under link's resolved path but make link the only way to reach it.
        # Isolate: create tmp_sym, then create dir real_target/src/chainparams.cpp outside tmp_sym, symlink tmp_sym/link -> real_target
        # Then SourceReader.slurp_src(tmp_sym, src/chainparams.cpp) should return None if symlink ignored, or "symlinked" if not ignored.
        tmp_sym = Path(tempfile.mkdtemp())
        real_target = Path(tempfile.mkdtemp())
        (real_target / "src").mkdir(parents=True, exist_ok=True)
        (real_target / "src" / "chainparams.cpp").write_text("symlinked")
        os.symlink(real_target, tmp_sym / "link")
        # No other file under tmp_sym direct or depth1 non-symlink
        txt = SourceReader.slurp_src(tmp_sym, "src/chainparams.cpp")
        assert txt is None, f"symlink link->target should be ignored, got {txt!r}"
        shutil.rmtree(real_target, ignore_errors=True)
        shutil.rmtree(tmp_sym, ignore_errors=True)
        shutil.rmtree(tmp2, ignore_errors=True)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

def test_git_ignored():
    tmp = _mktree({".git/src/chainparams.cpp": "git_hidden"})
    try:
        txt = SourceReader.slurp_src(tmp, "src/chainparams.cpp")
        assert txt is None, f".git/src should be ignored, got {txt!r}"
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

def test_nonsrc_rel_only_direct():
    tmp = Path(tempfile.mkdtemp())
    try:
        (tmp / "README.md").write_text("root")
        (tmp / "a" / "README.md").parent.mkdir(parents=True, exist_ok=True)
        (tmp / "a" / "README.md").write_text("nested")
        (tmp / "a" / "b" / "README.md").parent.mkdir(parents=True, exist_ok=True)
        (tmp / "a" / "b" / "README.md").write_text("deep")
        # direct exists -> return direct
        txt = SourceReader.slurp_src(tmp, "README.md")
        assert txt == "root", f"non-src direct should return root, got {txt!r}"
        # now remove direct, nested should NOT be found (non-src only direct)
        (tmp / "README.md").unlink()
        txt2 = SourceReader.slurp_src(tmp, "README.md")
        assert txt2 is None, f"non-src rel with only nested should be None, got {txt2!r}"
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
