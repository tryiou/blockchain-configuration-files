#!/usr/bin/env python3
"""One checkout per coin under ``<cache>/repos/<ticker>`` — never per tag.

Contract under test:

* ``repo_checkout_dir`` is the single source of truth for the checkout
  path; the folder name carries the ticker and no tag;
* a second tag for the same coin is fetched into the SAME folder;
* a matching HEAD is reused without touching the network;
* a failed fetch fails loudly (``fetch-failed`` + ERROR) and leaves the
  existing checkout untouched — never a silent reuse, never a wipe;
* scaffold routes through the same resolver: no ``rmtree`` of an
  existing checkout.

Every fixture is a local ``git init`` repository under ``tmp_path`` —
zero network, zero writes outside the test's own tmp dir.
"""

import argparse
import logging
import os
import shutil
import subprocess
from pathlib import Path

import pytest

import audit_manifest as audit
import audit_manifest.checkout as checkout_mod
import audit_manifest.inspectors.cpp as cpp_mod

ManifestCoin = audit.ManifestCoin
SourceCheckoutManager = audit.SourceCheckoutManager
CoinScaffolder = audit.CoinScaffolder

_GIT_ENV = {
    **os.environ,
    "GIT_AUTHOR_NAME": "fixture",
    "GIT_AUTHOR_EMAIL": "fixture@example.invalid",
    "GIT_COMMITTER_NAME": "fixture",
    "GIT_COMMITTER_EMAIL": "fixture@example.invalid",
    # Neutralize the host's git config so the suite is hermetic even on a
    # machine with commit.gpgsign, status.showUntrackedFiles, templates …
    "GIT_CONFIG_GLOBAL": "/dev/null",
    "GIT_CONFIG_SYSTEM": "/dev/null",
    "GIT_CONFIG_NOSYSTEM": "1",
}


def _git(*args: str, cwd: str = "") -> subprocess.CompletedProcess:
    proc = subprocess.run(
        ["git", *args],
        cwd=cwd or None,
        env=_GIT_ENV,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert proc.returncode == 0, f"git {' '.join(args)} failed: {proc.stderr}"
    return proc


def _make_origin(root: Path, *tags: str) -> Path:
    """Local origin repo: one commit per tag, so tags point at real history."""
    origin = root / "origin"
    if not origin.exists():
        _git("init", "-q", str(origin))
    for tag in tags:
        (origin / "README.md").write_text(f"{tag}\n", encoding="utf-8")
        _git("add", "-A", cwd=str(origin))
        _git("commit", "-q", "-m", tag, cwd=str(origin))
        _git("tag", tag, cwd=str(origin))
    return origin


def _coin(origin: Path) -> ManifestCoin:
    # file:// (not a bare path): git only honours --depth 1 over a real
    # transport, so the fixtures exercise the same shallow code path as
    # a networked origin.
    return ManifestCoin(
        ticker="TST",
        ver_id="tst--v1.0.0",
        versions=["v1.0.0"],
        repo_url=origin.as_uri(),
    )


def _head(repo: Path) -> str:
    return _git("-C", str(repo), "rev-parse", "HEAD").stdout.strip()


def _tag_commit(repo: Path, tag: str) -> str:
    return _git("-C", str(repo), "rev-list", "-n", "1", tag).stdout.strip()


def _folders(cache: Path) -> list:
    repos = cache / "repos"
    return sorted(p.name for p in repos.iterdir()) if repos.is_dir() else []


def test_resolve_creates_one_folder_per_coin(tmp_path):
    origin = _make_origin(tmp_path, "v1.0.0")
    mgr = SourceCheckoutManager(cache_root=tmp_path / "cache")

    src, mode = mgr.resolve_source(_coin(origin), "v1.0.0", timeout=10)

    assert mode == "cloned"
    assert src == checkout_mod.repo_checkout_dir("TST", tmp_path / "cache")
    assert src is not None and src.name == "TST", "folder is the ticker, no tag"
    assert _folders(tmp_path / "cache") == ["TST"]
    # file:// keeps --depth 1 honest: the fixture must really be shallow,
    # otherwise a future drop of --depth would go unnoticed.
    assert _git("-C", str(src), "rev-parse", "--is-shallow-repository").stdout.strip() == "true", (
        "clone must be shallow (--depth 1 over the file:// transport)"
    )


def test_resolve_fetches_second_tag_into_the_same_folder(tmp_path):
    origin = _make_origin(tmp_path, "v1.0.0", "v2.0.0")
    mgr = SourceCheckoutManager(cache_root=tmp_path / "cache")
    coin = _coin(origin)

    src1, mode1 = mgr.resolve_source(coin, "v1.0.0", timeout=10)
    assert mode1 == "cloned"

    src2, mode2 = mgr.resolve_source(coin, "v2.0.0", timeout=10)

    assert mode2 == "fetched"
    assert src2 == src1
    assert _folders(tmp_path / "cache") == ["TST"], "the second tag must not add a folder"
    assert src2 is not None and _head(src2) == _tag_commit(src2, "v2.0.0")


def test_resolve_reuses_and_updates_when_head_matches(tmp_path):
    origin = _make_origin(tmp_path, "v1.0.0")
    mgr = SourceCheckoutManager(cache_root=tmp_path / "cache")
    coin = _coin(origin)

    src1, mode1 = mgr.resolve_source(coin, "v1.0.0", timeout=10)
    assert mode1 == "cloned"

    # Origin gone: any reuse that tried the network would fail here.
    shutil.rmtree(origin)
    src2, mode2 = mgr.resolve_source(coin, "v1.0.0", timeout=10)
    assert mode2 == "reused"
    assert src2 == src1

    # Origin back with a new tag: the SAME folder updates in place.
    origin = _make_origin(tmp_path, "v1.0.0", "v2.0.0")
    src3, mode3 = mgr.resolve_source(coin, "v2.0.0", timeout=10)
    assert mode3 == "fetched"
    assert src3 == src1
    assert _folders(tmp_path / "cache") == ["TST"]


def test_resolve_fetch_failure_is_loud(tmp_path, caplog):
    origin = _make_origin(tmp_path, "v1.0.0")
    mgr = SourceCheckoutManager(cache_root=tmp_path / "cache")
    coin = _coin(origin)

    src1, mode1 = mgr.resolve_source(coin, "v1.0.0", timeout=10)
    assert mode1 == "cloned"
    head_before = _head(src1)

    shutil.rmtree(origin)  # unreachable origin
    with caplog.at_level(logging.ERROR):
        src, mode = mgr.resolve_source(coin, "v2.0.0", timeout=10)

    assert src is None
    assert mode == "fetch-failed"
    assert any("fetch" in r.getMessage().lower() for r in caplog.records), (
        "a failed fetch must log an ERROR, not return silently"
    )
    # The existing checkout survives untouched: no silent reuse, no wipe.
    assert src1 is not None and src1.is_dir()
    assert _head(src1) == head_before


def test_repo_checkout_dir_rejects_path_like_tickers(tmp_path):
    """A ticker must be one path component: separators/.. never escape the cache root."""
    for bad in ("", ".", "..", "../..", "a/b", "TST/..", "a\\b"):
        with pytest.raises(ValueError, match="invalid ticker"):
            checkout_mod.repo_checkout_dir(bad, tmp_path)
    assert checkout_mod.repo_checkout_dir("TST", tmp_path) == tmp_path / "repos" / "TST"


def test_repo_checkout_dir_accepts_fleet_style_tickers(tmp_path):
    """Fleet tickers are path-safe components, not alnum-only: $PAC is real manifest data."""
    for tick in ("$PAC", "MY-COIN", "my_coin", "LTC2"):
        assert checkout_mod.repo_checkout_dir(tick, tmp_path) == tmp_path / "repos" / tick

    origin = _make_origin(tmp_path, "v1.0.0")
    mgr = SourceCheckoutManager(cache_root=tmp_path / "cache")
    coin = ManifestCoin(
        ticker="$PAC",
        ver_id="pac--v1.0.0",
        versions=["v1.0.0"],
        repo_url=origin.as_uri(),
    )
    src, mode = mgr.resolve_source(coin, "v1.0.0", timeout=10)
    assert mode == "cloned"
    assert src == checkout_mod.repo_checkout_dir("$PAC", tmp_path / "cache")
    assert _folders(tmp_path / "cache") == ["$PAC"]


def test_resolve_annotated_tag_clones_and_fetches(tmp_path):
    """Annotated tags motivated the old init+fetch fallback; they must work directly."""
    origin = _make_origin(tmp_path, "v1.0.0")
    (origin / "README.md").write_text("v2.0.0\n", encoding="utf-8")
    _git("add", "-A", cwd=str(origin))
    _git("commit", "-q", "-m", "v2.0.0", cwd=str(origin))
    _git("tag", "-a", "-m", "release", "v2.0.0", cwd=str(origin))
    mgr = SourceCheckoutManager(cache_root=tmp_path / "cache")
    coin = _coin(origin)

    src, mode1 = mgr.resolve_source(coin, "v2.0.0", timeout=10)
    assert mode1 == "cloned"
    assert _folders(tmp_path / "cache") == ["TST"]
    assert src is not None and _head(src) == _tag_commit(src, "v2.0.0")

    src2, mode2 = mgr.resolve_source(coin, "v1.0.0", timeout=10)
    assert mode2 == "fetched" and src2 == src
    assert _head(src2) == _tag_commit(src2, "v1.0.0")

    # fetch path with the annotated tag too (HEAD moves back)
    src3, mode3 = mgr.resolve_source(coin, "v2.0.0", timeout=10)
    assert mode3 == "fetched" and src3 == src
    assert _head(src3) == _tag_commit(src3, "v2.0.0")
    assert _folders(tmp_path / "cache") == ["TST"]


def test_resolve_rejects_a_branch_wearing_a_tag_name(tmp_path, caplog):
    """Exact-tag contract: an upstream BRANCH named like the tag is not the tag."""
    origin = _make_origin(tmp_path, "v1.0.0")
    _git("-C", str(origin), "tag", "-d", "v1.0.0")
    _git("-C", str(origin), "branch", "v1.0.0")  # same name, not refs/tags/

    mgr = SourceCheckoutManager(cache_root=tmp_path / "cache")
    with caplog.at_level(logging.ERROR):
        src, mode = mgr.resolve_source(_coin(origin), "v1.0.0", timeout=10)

    assert src is None, "a branch tip must never be certified as the manifest tag"
    assert mode == "clone-failed"
    assert _folders(tmp_path / "cache") == [], "no checkout may be left behind"
    assert any("refs/tags/v1.0.0" in r.getMessage() for r in caplog.records), (
        "the ERROR must name the shadowed ref so the operator can act"
    )


def test_resolve_ignores_legacy_check_folders(tmp_path):
    """Legacy <coin>_check / <coin>_<tag>_check folders are never read."""
    origin = _make_origin(tmp_path, "v1.0.0")
    cache = tmp_path / "cache"
    legacy = cache / "tst_check"
    legacy.mkdir(parents=True)
    _git("init", "-q", str(legacy))
    (legacy / "old.txt").write_text("legacy\n", encoding="utf-8")
    _git("add", "-A", cwd=str(legacy))
    _git("commit", "-q", "-m", "legacy", cwd=str(legacy))
    _git("tag", "v1.0.0", cwd=str(legacy))  # decoy that even matches the tag

    mgr = SourceCheckoutManager(cache_root=cache)
    src, mode = mgr.resolve_source(_coin(origin), "v1.0.0", timeout=10)

    assert mode == "cloned"
    assert src == checkout_mod.repo_checkout_dir("TST", cache)
    assert src != legacy, "the legacy folder must not be selected"
    assert legacy.is_dir(), "the legacy folder must not be touched"


def test_resolve_symlinked_folder_is_an_obstruction(tmp_path, caplog):
    """A symlink at repos/<ticker> must not be resolved through into another repo."""
    foreign = tmp_path / "foreign-repo"
    _git("init", "-q", str(foreign))
    (foreign / "keep.txt").write_text("foreign work\n", encoding="utf-8")
    _git("add", "-A", cwd=str(foreign))
    _git("commit", "-q", "-m", "base", cwd=str(foreign))
    foreign_head = _head(foreign)

    cache = tmp_path / "cache"
    target = cache / "repos" / "TST"
    target.parent.mkdir(parents=True)
    target.symlink_to(foreign)

    origin = _make_origin(tmp_path, "v1.0.0")
    mgr = SourceCheckoutManager(cache_root=cache)
    with caplog.at_level(logging.ERROR):
        src, mode = mgr.resolve_source(_coin(origin), "v1.0.0", timeout=10)

    assert src is None
    assert mode == "fetch-failed"
    assert any("symlink" in r.getMessage() for r in caplog.records), "a symlinked folder must be named in the ERROR"
    assert _head(foreign) == foreign_head
    assert (foreign / "keep.txt").read_text(encoding="utf-8") == "foreign work\n"
    assert "v1.0.0" not in _git("-C", str(foreign), "tag", "--list").stdout


def test_resolve_reuses_only_a_clean_tree(tmp_path):
    """HEAD matching is not enough: a half-switched tree is repaired, not certified."""
    origin = _make_origin(tmp_path, "v1.0.0")
    mgr = SourceCheckoutManager(cache_root=tmp_path / "cache")
    src, mode = mgr.resolve_source(_coin(origin), "v1.0.0", timeout=10)
    assert mode == "cloned"

    # Simulate a switch killed mid-checkout: tracked content no longer
    # matches HEAD even though the tag commit sits at HEAD.
    (src / "README.md").write_text("half-switched garbage\n", encoding="utf-8")

    src2, mode2 = mgr.resolve_source(_coin(origin), "v1.0.0", timeout=10)
    assert mode2 == "fetched", "a dirty tree must be repaired via the forced fetch, not reused"
    assert src2 == src
    assert (src2 / "README.md").read_text(encoding="utf-8") == "v1.0.0\n"


def test_resolve_rejects_a_tree_with_leftover_files(tmp_path):
    """Untracked leftovers trip the reuse gate — the folder is scratch, not a garden."""
    origin = _make_origin(tmp_path, "v1.0.0")
    mgr = SourceCheckoutManager(cache_root=tmp_path / "cache")
    src, mode = mgr.resolve_source(_coin(origin), "v1.0.0", timeout=10)
    assert mode == "cloned"

    # A file that does not exist at the tag (e.g. left behind by a switch
    # to another tag that was killed before HEAD moved).
    (src / "stray_from_another_tag.py").write_text("leftover\n", encoding="utf-8")

    src2, mode2 = mgr.resolve_source(_coin(origin), "v1.0.0", timeout=10)
    assert mode2 == "fetched", "a tree with leftovers must be repaired, never reused"
    assert src2 == src
    assert not (src2 / "stray_from_another_tag.py").exists(), "the forced switch must leave an exact-tag tree"

    _src3, mode3 = mgr.resolve_source(_coin(origin), "v1.0.0", timeout=10)
    assert mode3 == "reused", "after the repair the folder returns to the offline path"


def test_resolve_dangling_symlink_is_named(tmp_path, caplog):
    """A dangling symlink obstruction reports fetch-failed with a remove-it hint."""
    cache = tmp_path / "cache"
    target = cache / "repos" / "TST"
    target.parent.mkdir(parents=True)
    target.symlink_to(tmp_path / "nowhere")

    origin = _make_origin(tmp_path, "v1.0.0")
    mgr = SourceCheckoutManager(cache_root=cache)
    with caplog.at_level(logging.ERROR):
        src, mode = mgr.resolve_source(_coin(origin), "v1.0.0", timeout=10)

    assert src is None
    assert mode == "fetch-failed"
    assert any("symlink" in r.getMessage() for r in caplog.records)
    assert target.is_symlink() and not target.exists(), "the link must be left standing"


def test_chain_name_is_fresh_when_head_is_unavailable(tmp_path, monkeypatch):
    """No usable HEAD (fixture tree or git failure) must disable caching, not collapse the key to the path."""
    # Pin the condition itself: if TMPDIR ever sits inside a git worktree,
    # rev-parse would walk up and make HEAD "available", which is not what
    # this test is about.
    monkeypatch.setattr(cpp_mod, "_src_head", lambda _src: None)
    src = tmp_path / "tree"
    src.mkdir()
    (src / "autogen.sh").write_text("NAME = alpha\n", encoding="utf-8")
    assert cpp_mod.current_chain(src) == "alpha"

    (src / "autogen.sh").write_text("NAME = beta\n", encoding="utf-8")
    assert cpp_mod.current_chain(src) == "beta", (
        "without a HEAD to key on, the chain name must be recomputed, never cached"
    )


def test_current_chain_follows_the_checked_out_tag(tmp_path):
    """One folder per coin: the chain name must follow the switch, not the first tag read."""
    origin = tmp_path / "origin"
    _git("init", "-q", str(origin))
    (origin / "autogen.sh").write_text("NAME = oldchain\n", encoding="utf-8")
    _git("add", "-A", cwd=str(origin))
    _git("commit", "-q", "-m", "v1", cwd=str(origin))
    _git("tag", "v1.0.0", cwd=str(origin))
    (origin / "autogen.sh").write_text("NAME = newchain\n", encoding="utf-8")
    _git("add", "-A", cwd=str(origin))
    _git("commit", "-q", "-m", "v2", cwd=str(origin))
    _git("tag", "v2.0.0", cwd=str(origin))

    mgr = SourceCheckoutManager(cache_root=tmp_path / "cache")
    coin = ManifestCoin(
        ticker="TST",
        ver_id="tst--v2.0.0",
        versions=["v1.0.0", "v2.0.0"],
        repo_url=origin.as_uri(),
    )
    src1, mode1 = mgr.resolve_source(coin, "v2.0.0", timeout=10)
    assert mode1 == "cloned"
    assert cpp_mod.current_chain(src1) == "newchain"

    src2, mode2 = mgr.resolve_source(coin, "v1.0.0", timeout=10)
    assert mode2 == "fetched"
    assert cpp_mod.current_chain(src2) == "oldchain", (
        "the chain cache must not leak the newer tag's name into the older tag's audit"
    )


def test_fix_fee_margin_names_a_bad_ticker_as_such(tmp_path, caplog):
    """A path-like ticker hitting the fixer is a data error, not a generic failure.

    Mirrors param-check's handling: the checkout layer's ticker-contract
    ValueError must be named by its own handler instead of falling
    through to the broad failure line.
    """
    from audit_manifest.fixes import ConfigAutoFixer

    coin = ManifestCoin(
        ticker="bad/ticker",
        ver_id="bad--v1.0.0",
        versions=["v1.0.0"],
        repo_url="https://example.invalid/x",
    )
    with caplog.at_level(logging.ERROR):
        assert ConfigAutoFixer.plan_fee_margin(tmp_path, coin) == ([], None)
    msgs = [r.getMessage() for r in caplog.records]
    assert any("invalid ticker for a checkout folder" in m for m in msgs)
    assert not any("FIX-FEES" in m and "failed:" in m for m in msgs), (
        "the ticker-contract error must be named by its own handler, not swallowed by the generic failure line"
    )


def test_clone_failure_reports_git_stderr(tmp_path, caplog):
    """A failed clone must name git's own cause on the ERROR line, not just the rc."""
    mgr = SourceCheckoutManager(cache_root=tmp_path / "cache")
    coin = _coin(tmp_path / "never-created-origin")

    src, mode = mgr.resolve_source(coin, "v1.0.0", timeout=10)

    assert src is None and mode == "clone-failed"
    assert any("fatal:" in r.getMessage() for r in caplog.records), (
        "git's stderr must reach the ERROR line so the operator learns why"
    )


def test_fetch_failure_reports_git_stderr(tmp_path, caplog):
    """A failed tag fetch must name git's own cause on the ERROR line."""
    origin = _make_origin(tmp_path, "v1.0.0")
    mgr = SourceCheckoutManager(cache_root=tmp_path / "cache")
    coin = _coin(origin)
    _src, mode = mgr.resolve_source(coin, "v1.0.0", timeout=10)
    assert mode == "cloned"
    caplog.clear()

    src2, mode2 = mgr.resolve_source(coin, "v9.9.9", timeout=10)

    assert src2 is None and mode2 == "fetch-failed"
    assert any("fatal:" in r.getMessage() for r in caplog.records), (
        "git's stderr must reach the ERROR line so the operator learns why"
    )


def test_origin_gate_ignores_url_suffix_form(tmp_path):
    """A cosmetic .git / trailing-slash form of the SAME URL is not a different repo."""
    origin = _make_origin(tmp_path, "v1.0.0")
    mgr = SourceCheckoutManager(cache_root=tmp_path / "cache")
    coin = _coin(origin)
    src, mode = mgr.resolve_source(coin, "v1.0.0", timeout=10)
    assert mode == "cloned"
    # A scaffold run (which normalizes user input) stored the suffix form…
    _git("config", "remote.origin.url", origin.as_uri() + ".git", cwd=str(src))
    # …and the network is gone: only an offline reuse can pass.
    origin.rename(tmp_path / "moved-away")

    src2, mode2 = mgr.resolve_source(coin, "v1.0.0", timeout=10)

    assert src2 == src and mode2 == "reused", "the same URL in another cosmetic form must not force a refetch"


def test_clone_recovers_when_a_branch_shadows_the_tag(tmp_path):
    """branch+tag, same name, different commits: a fresh clone must still land on the tag."""
    origin = _make_origin(tmp_path, "v1.0.0")  # tag at commit A
    (origin / "README.md").write_text("branch tip\n", encoding="utf-8")
    _git("add", "-A", cwd=str(origin))
    _git("commit", "-q", "-m", "branch tip", cwd=str(origin))
    _git("branch", "v1.0.0", cwd=str(origin))  # same name at commit B

    mgr = SourceCheckoutManager(cache_root=tmp_path / "cache")
    src, mode = mgr.resolve_source(_coin(origin), "v1.0.0", timeout=10)

    assert mode == "cloned", "an existing tag must be recoverable from a fresh clone"
    assert (src / "README.md").read_text(encoding="utf-8") == "v1.0.0\n"
    assert _head(src) == _tag_commit(origin, "v1.0.0")


def test_reuse_refetches_when_the_manifest_url_changed(tmp_path):
    """A checkout cloned from another repo_url is never reused for the new URL."""
    origin_a = _make_origin(tmp_path / "a", "v1.0.0")
    origin_b = _make_origin(tmp_path / "b", "v1.0.0")
    cache = tmp_path / "cache"
    coin_a = ManifestCoin(
        ticker="TST",
        ver_id="tst--v1.0.0",
        versions=["v1.0.0"],
        repo_url=origin_a.as_uri(),
    )
    coin_b = ManifestCoin(
        ticker="TST",
        ver_id="tst--v1.0.0",
        versions=["v1.0.0"],
        repo_url=origin_b.as_uri(),
    )
    mgr = SourceCheckoutManager(cache_root=cache)

    src1, mode1 = mgr.resolve_source(coin_a, "v1.0.0", timeout=10)
    assert mode1 == "cloned"

    src2, mode2 = mgr.resolve_source(coin_b, "v1.0.0", timeout=10)
    assert mode2 == "fetched", "a changed repo_url must force a refetch from the new origin"
    assert src2 == src1
    stored = _git("-C", str(src2), "config", "--get", "remote.origin.url").stdout.strip()
    assert stored == origin_b.as_uri(), "the stored origin must follow the manifest URL"

    _src3, mode3 = mgr.resolve_source(coin_b, "v1.0.0", timeout=10)
    assert mode3 == "reused", "once aligned, the offline path returns"


def test_gate_sees_untracked_even_if_status_config_hides_them(tmp_path, monkeypatch):
    """status.showUntrackedFiles=no in user config must not blind the gate."""
    cfg = tmp_path / "gitconfig"
    cfg.write_text("[status]\n\tshowUntrackedFiles = no\n", encoding="utf-8")
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", str(cfg))

    origin = _make_origin(tmp_path, "v1.0.0")
    mgr = SourceCheckoutManager(cache_root=tmp_path / "cache")
    src, mode = mgr.resolve_source(_coin(origin), "v1.0.0", timeout=10)
    assert mode == "cloned"

    (src / "stray.py").write_text("leftover\n", encoding="utf-8")
    _src2, mode2 = mgr.resolve_source(_coin(origin), "v1.0.0", timeout=10)
    assert mode2 == "fetched", "the gate must see untracked files regardless of user config"


def test_repair_removes_a_nested_repo_leftover(tmp_path):
    """The forced repair must clear exactly what the gate reports — nested repos included."""
    origin = _make_origin(tmp_path, "v1.0.0")
    mgr = SourceCheckoutManager(cache_root=tmp_path / "cache")
    src, mode = mgr.resolve_source(_coin(origin), "v1.0.0", timeout=10)
    assert mode == "cloned"

    nested = src / "vendor_leftover"
    _git("init", "-q", str(nested))  # a git repo someone dropped in

    _src2, mode2 = mgr.resolve_source(_coin(origin), "v1.0.0", timeout=10)
    assert mode2 == "fetched"
    assert not nested.exists(), "the repair must clear the nested repo too"

    _src3, mode3 = mgr.resolve_source(_coin(origin), "v1.0.0", timeout=10)
    assert mode3 == "reused", "after the repair the folder returns to the offline path"


def test_param_audit_survives_a_malformed_manifest_ticker(tmp_path):
    """A bad manifest ticker degrades to a structured no-source row, not a traceback."""
    engine = audit.ParamAuditEngine(SourceCheckoutManager(cache_root=tmp_path / "cache"))
    coin = ManifestCoin(
        ticker="a/b",
        ver_id="bad--v1.0.0",
        versions=["v1.0.0"],
        repo_url="file:///nonexistent",
        wallet_conf="w.conf",
        xbridge_conf="x.conf",
    )

    res = engine.audit_version(coin, tmp_path, "v1.0.0", "w.conf", "x.conf", 10)

    assert res.source is None
    assert res.mode == "no-valid-ticker"


def test_param_audit_forwards_kwargs_to_every_checker(tmp_path):
    """The dispatch closure must forward keyword args, not just positional.

    Regression guard: checker signatures are keyword-only for the flags
    (``want_test``, ``repo_root``), so each call site forwards them as
    keywords. A closure that accepts only ``*args`` raises TypeError on
    the first cpp dispatch — which aborts the whole live run at the first
    coin, while every hermetic path that exits before dispatch stays
    green. The second assertion is the silent-degradation detector: a
    mismatch *inside* a checker is swallowed by the closure's except and
    turned into a WARN, so no check may come back as a checker error.
    """
    origin = _make_origin(tmp_path, "v1.0.0")
    (tmp_path / "wallet-confs").mkdir()
    (tmp_path / "xbridge-confs").mkdir()
    (tmp_path / "wallet-confs" / "w.conf").write_text("port=41234\nrpcport=41235\n", encoding="utf-8")
    (tmp_path / "xbridge-confs" / "x.conf").write_text("Port=41235\n", encoding="utf-8")

    engine = audit.ParamAuditEngine(SourceCheckoutManager(cache_root=tmp_path / "cache"))
    coin = _coin(origin)

    res = engine.audit_version(coin, tmp_path, "v1.0.0", "w.conf", "x.conf", 30)

    ids = [c.id for c in res.checks]
    for expected in ("PORT", "RPCPORT-SOURCE", "PREFIXES", "FEES", "STRUCT"):
        assert expected in ids, f"{expected} never dispatched: got {ids}"
    assert len(ids) == 16, f"expected the full cpp checker set, got {ids}"
    for c in res.checks:
        assert "checker error" not in c.detail, f"{c.id} degraded to a checker error: {c.detail}"


def test_resolve_non_git_folder_never_uses_an_enclosing_repo(tmp_path, caplog):
    """A plain dir at repos/<ticker> must not let git walk up into an enclosing repo.

    The tool's cache lives inside its own git repo. Without this guard
    `git -C <dir>` fetches/force-checkouts against THAT repo — silently
    replacing the operator's working tree with the coin's tree.
    """
    parent_repo = tmp_path / "tool-repo"
    _git("init", "-q", str(parent_repo))
    (parent_repo / "keep.txt").write_text("precious uncommitted work\n", encoding="utf-8")
    _git("add", "-A", cwd=str(parent_repo))
    _git("commit", "-q", "-m", "base", cwd=str(parent_repo))
    head_before = _head(parent_repo)

    cache = parent_repo / ".cache"
    target = cache / "repos" / "TST"
    target.mkdir(parents=True)  # plain dir, no git repository of its own

    origin = _make_origin(tmp_path, "v1.0.0")
    mgr = SourceCheckoutManager(cache_root=cache)
    with caplog.at_level(logging.ERROR):
        src, mode = mgr.resolve_source(_coin(origin), "v1.0.0", timeout=10)

    assert src is None
    assert mode == "fetch-failed"
    assert any("not its own git checkout" in r.getMessage() for r in caplog.records), (
        "a non-checkout folder must be named in the ERROR"
    )
    # The enclosing repository is untouched: HEAD, working tree, tags.
    assert _head(parent_repo) == head_before
    assert (parent_repo / "keep.txt").read_text(encoding="utf-8") == "precious uncommitted work\n"
    assert "v1.0.0" not in _git("-C", str(parent_repo), "tag", "--list").stdout


def test_clone_failure_never_deletes_a_folder_it_did_not_create(tmp_path):
    """A concurrent run creating the folder mid-clone keeps its checkout.

    The clone path may only ever remove what this call itself created.
    """
    origin = _make_origin(tmp_path, "v1.0.0")
    cache = tmp_path / "cache"
    target = cache / "repos" / "TST"

    class _RacingRunner:
        def run(self, cmd, timeout, env_extra=None):
            assert "clone" in cmd, f"unexpected command before clone: {cmd}"
            # The winner appears between our existence check and our clone.
            target.mkdir(parents=True, exist_ok=True)
            (target / "their-work.txt").write_text("winner\n", encoding="utf-8")
            return subprocess.CompletedProcess(cmd, 128, stdout="", stderr="fatal: destination path already exists\n")

    mgr = SourceCheckoutManager(cache_root=cache, runner=_RacingRunner())
    src, mode = mgr.resolve_source(_coin(origin), "v1.0.0", timeout=10)

    assert src is None
    assert mode == "clone-failed"
    assert target.is_dir(), "the concurrent run's checkout must survive"
    assert (target / "their-work.txt").read_text(encoding="utf-8") == "winner\n"


def test_resolve_stray_file_at_target_is_loud(tmp_path, caplog):
    """A file squatting on `repos/<ticker>` is named in an ERROR and left alone."""
    origin = _make_origin(tmp_path, "v1.0.0")
    target = tmp_path / "cache" / "repos" / "TST"
    target.parent.mkdir(parents=True)
    target.write_text("obstruction\n", encoding="utf-8")
    mgr = SourceCheckoutManager(cache_root=tmp_path / "cache")

    with caplog.at_level(logging.ERROR):
        src, mode = mgr.resolve_source(_coin(origin), "v1.0.0", timeout=10)

    assert src is None
    assert mode == "clone-failed"
    assert any("not a directory" in r.getMessage() for r in caplog.records), (
        "a stray file blocking the checkout path must be named in an ERROR"
    )
    assert target.is_file(), "the obstruction must not be deleted by the tool"


def test_resolve_repos_root_obstructed_is_loud(tmp_path, caplog):
    """A file squatting on <cache>/repos is a named clone-failed, not a traceback."""
    origin = _make_origin(tmp_path, "v1.0.0")
    (tmp_path / "cache").mkdir()
    (tmp_path / "cache" / "repos").write_text("obstruction\n", encoding="utf-8")
    mgr = SourceCheckoutManager(cache_root=tmp_path / "cache")

    with caplog.at_level(logging.ERROR):
        src, mode = mgr.resolve_source(_coin(origin), "v1.0.0", timeout=10)

    assert src is None
    assert mode == "clone-failed"
    assert any("cannot prepare" in r.getMessage() for r in caplog.records), (
        "an obstructed cache layout must be named in an ERROR, not raise"
    )


def test_resolve_checkout_failure_reports_its_cause(tmp_path, caplog):
    """A failed checkout -f says so; it must not blame HEAD verification."""
    origin = _make_origin(tmp_path, "v1.0.0", "v2.0.0")
    mgr = SourceCheckoutManager(cache_root=tmp_path / "cache")
    coin = _coin(origin)
    src, mode = mgr.resolve_source(coin, "v1.0.0", timeout=10)
    assert mode == "cloned" and src is not None

    # An index lock makes `checkout -f` fail after a successful fetch.
    (src / ".git" / "index.lock").write_text("", encoding="utf-8")
    with caplog.at_level(logging.ERROR):
        src2, mode2 = mgr.resolve_source(coin, "v2.0.0", timeout=10)

    assert src2 is None
    assert mode2 == "fetch-failed"
    assert any("checkout of the tag failed" in r.getMessage() for r in caplog.records), (
        "a failed checkout must say so with its rc, not blame HEAD verification"
    )


def test_scaffold_rejects_path_like_ticker(tmp_path):
    """An invalid --scaffold-ticker is a structured usage error, not a traceback."""
    origin = _make_origin(tmp_path, "v1.0.0")
    args = argparse.Namespace(
        repo_url=origin.as_uri(),
        scaffold_ticker="../..",
        scaffold_tag="v1.0.0",
        scaffold_name=None,
        scaffold_out_dir=str(tmp_path / "out"),
        apply=False,
        dry_run=False,
        timeout=10,
    )
    code, result = CoinScaffolder().run(args, [], tmp_path)

    assert code == 2
    assert "invalid ticker" in str(result["error"])


def test_scaffold_reuses_existing_repo(tmp_path, monkeypatch):
    monkeypatch.setattr(checkout_mod, "CACHE_ROOT", tmp_path / "cache")

    origin = _make_origin(tmp_path, "v1.0.0")
    mgr = SourceCheckoutManager(cache_root=tmp_path / "cache")
    src, mode = mgr.resolve_source(_coin(origin), "v1.0.0", timeout=10)
    assert mode == "cloned"

    # Any rmtree-and-reclone path now fails: the reuse must come from the
    # existing checkout, without the origin.
    shutil.rmtree(origin)
    args = argparse.Namespace(
        repo_url=origin.as_uri(),
        scaffold_ticker="TST",
        scaffold_tag="v1.0.0",
        scaffold_name=None,
        scaffold_out_dir=str(tmp_path / "out"),
        apply=False,
        dry_run=False,
        timeout=10,
    )
    code, result = CoinScaffolder().run(args, [], tmp_path)

    # Reaching the fee-source guard means source resolution succeeded.
    assert result["error"] == "fee source unresolvable — refusing silent defaults"
    assert code == 1
    assert src is not None and src.is_dir(), "scaffold must not rmtree the checkout"
    assert _folders(tmp_path / "cache") == ["TST"]


def test_chain_name_bypasses_cache_on_dirty_tree(tmp_path, monkeypatch):
    """In-place edits keep HEAD but change the answer: never serve stale."""
    monkeypatch.setattr(cpp_mod, "_src_head", lambda _src: "deadbeef")
    monkeypatch.setattr(cpp_mod, "_src_dirty", lambda _src: True)
    audit._CURRENT_CHAIN_CACHE.clear()
    src = tmp_path / "tree"
    src.mkdir()
    (src / "autogen.sh").write_text("NAME = alpha\n", encoding="utf-8")
    assert cpp_mod.current_chain(src) == "alpha"
    (src / "autogen.sh").write_text("NAME = beta\n", encoding="utf-8")
    assert cpp_mod.current_chain(src) == "beta"
