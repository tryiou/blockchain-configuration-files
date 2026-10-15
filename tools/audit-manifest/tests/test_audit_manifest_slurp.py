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

import shutil
import tempfile
from pathlib import Path

import audit_manifest as audit

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
        (tmp / "link").symlink_to(tmp / "a")
        # also create a nested file via symlink path but not via real non-symlink depth?
        # Now slurp should find via a (real) but not via link (ignored).
        # To test symlink ignored specifically: remove real a's file and create only via symlink target?
        # Better: create separate case where only symlink location holds file
        tmp2 = Path(tempfile.mkdtemp())
        (tmp2 / "a" / "src").mkdir(parents=True)
        (tmp2 / "a" / "src" / "chainparams.cpp").write_text("via_a")
        (tmp2 / "link").symlink_to(tmp2 / "a")
        # Now remove the real path's file and rely on link? Instead create case where file only under link's target but
        # we ensure link is not traversed:
        # Simpler: tmp3 where src/chainparams.cpp does NOT exist, and only link/src/chainparams.cpp exists via symlink
        # indirection?
        # Actually symlink at top level: link -> a, and a/src exists, then traversing link would find file. We want to
        # ensure link is ignored, so if we delete a/src file and create a differently named target?
        # Let's construct: tmp with only link->a and a holds file, but also ensure no non-symlink path holds file except
        # via link.
        # We'll test: create tmp4 with a/src/chainparams.cpp, plus link->a, then delete a and recreate? Complex.

        # Simpler deterministic: Create tmp_sym where we place file ONLY under link's resolved path but make link the
        # only way to reach it.
        # Isolate: create tmp_sym, then create dir real_target/src/chainparams.cpp outside tmp_sym, symlink tmp_sym/link
        # -> real_target
        # Then SourceReader.slurp_src(tmp_sym, src/chainparams.cpp) should return None if symlink ignored, or
        # "symlinked" if not ignored.
        tmp_sym = Path(tempfile.mkdtemp())
        real_target = Path(tempfile.mkdtemp())
        (real_target / "src").mkdir(parents=True, exist_ok=True)
        (real_target / "src" / "chainparams.cpp").write_text("symlinked")
        (tmp_sym / "link").symlink_to(real_target)
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


def _mksrc(root: Path, rel: str, text: str) -> Path:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text)
    return p


def test_cached_read_never_stales_content():
    """A rewritten source file must be re-read, not answered from a cache.

    The reader memoizes where a file lives per checkout state — never what
    it contains. A first read, a rewrite, and a second read must observe
    the new bytes.
    """
    tmp = Path(tempfile.mkdtemp())
    try:
        f = _mksrc(tmp, "src/chainparams.cpp", "one")
        assert SourceReader.slurp_src(tmp, "src/chainparams.cpp") == "one"
        f.write_text("two")
        assert SourceReader.slurp_src(tmp, "src/chainparams.cpp") == "two"
        f.write_text("three")
        assert SourceReader.slurp_src(tmp, "src/chainparams.cpp") == "three"
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_invalidate_re_resolves_a_replaced_tree():
    """invalidate() is the tree-mutation hook: new files resolve after it.

    resolve_for() calls it before every clone/fetch/switch, so a resolution
    cached for one tag can never answer for the next one.
    """
    tmp = Path(tempfile.mkdtemp())
    try:
        assert SourceReader.slurp_src(tmp, "src/chainparams.cpp") is None
        _mksrc(tmp, "src/chainparams.cpp", "fresh")
        # without invalidation the previous miss is still the memoized answer
        assert SourceReader.slurp_src(tmp, "src/chainparams.cpp") is None
        SourceReader.invalidate()
        assert SourceReader.slurp_src(tmp, "src/chainparams.cpp") == "fresh"
    finally:
        SourceReader.invalidate()
        shutil.rmtree(tmp, ignore_errors=True)


def test_wrapper_order_matches_a_fresh_walk():
    """The memoized wrapper snapshot resolves to the same file a walk would.

    Two wrapper dirs both carrying the rel_path: the first in BFS order
    wins on the first call and on every later one — the snapshot must not
    change which file a repeat lookup sees.
    """
    tmp = Path(tempfile.mkdtemp())
    try:
        _mksrc(tmp, "aaa/src/chainparams.cpp", "from_aaa")
        _mksrc(tmp, "bbb/src/chainparams.cpp", "from_bbb")
        first = SourceReader.slurp_src(tmp, "src/chainparams.cpp")
        assert first in ("from_aaa", "from_bbb"), first
        for _ in range(3):
            assert SourceReader.slurp_src(tmp, "src/chainparams.cpp") == first
        # a fresh, never-cached lookup agrees with the repeated one
        expect = tmp / "aaa" / "src" / "chainparams.cpp"
        assert SourceReader._find_src(tmp, "src/chainparams.cpp") == expect
        assert SourceReader._find_src(tmp, "src/chainparams.cpp") == expect
    finally:
        SourceReader.invalidate()
        shutil.rmtree(tmp, ignore_errors=True)
