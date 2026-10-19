"""Local source checkouts and conf/source file reading.

``SourceCheckoutManager`` owns clone/fetch/reuse decisions for param checks;
``SourceReader`` reads and parses conf and C/C++ source files. Both are
filesystem-local — network calls go through ``probe.SystemCommandRunner``.
"""

from __future__ import annotations

import datetime
import os
import re
import shutil
import subprocess
from collections import deque
from pathlib import Path
from typing import ClassVar

from .constants import CACHE_ROOT, logger
from .model import ManifestCoin
from .probe import SystemCommandRunner

# Longest git output previewed in a diagnostic line.
_MAX_PREVIEW_CHARS = 200


def repo_checkout_dir(ticker: str, cache_root: Path | None = None) -> Path:
    """``<cache>/repos/<ticker>`` — the one checkout folder for a coin.

    Single source of truth used by the manager, the scaffold, and the
    tests: the folder carries the ticker and never a tag. ``cache_root``
    defaults at call time (never captured in a default argument) so
    tests can redirect the cache root by patching this module's global.

    The ticker must be a safe single path component: non-empty, not
    ``.``/``..``, no path separators or NUL. Ticker characters beyond
    that are fine — ``$PAC``, ``MY-COIN`` and friends are real fleet
    data. Anything else raises ``ValueError`` instead of letting the
    checkout escape the cache root.
    """
    if not ticker or ticker in (".", "..") or "/" in ticker or "\\" in ticker or "\0" in ticker:
        raise ValueError(f"invalid ticker for a checkout folder: {ticker!r}")
    root = cache_root if cache_root is not None else CACHE_ROOT
    return root / "repos" / ticker


def canonical_repo_url(url: str) -> str:
    """Bare fleet-convention form of a repo URL: no trailing ``/``, no ``.git``.

    Cosmetic only — two URLs that canonicalize together are the same
    remote, any real difference survives. Shared by scaffold (which
    normalizes user-supplied ``--repo-url`` input) and the reuse gate,
    so the two flows can never disagree about identity and refetch in
    alternation.
    """
    return url.strip().rstrip("/").removesuffix(".git")


def _stderr_note(proc: subprocess.CompletedProcess | None) -> str:
    """Single-line, truncated git stderr for an ERROR line.

    Failures must be loud about the cause, not only the stage: git's own
    text ("Repository not found", auth prompts, DNS errors) is the only
    place an operator learns WHY a clone or fetch failed.
    """
    if proc is None or not proc.stderr or not proc.stderr.strip():
        return ""
    text = " ".join(proc.stderr.split())
    if len(text) > _MAX_PREVIEW_CHARS:
        text = text[: _MAX_PREVIEW_CHARS - len("...")] + "..."
    return f"; {text}"


class SourceCheckoutManager:
    """Manages the local git clones and shallow checkouts used for param checking.

    One checkout lives under ``<cache>/repos/<ticker>`` per coin (gitignored).
    """

    def __init__(self, cache_root: Path | None = None, runner: SystemCommandRunner | None = None):
        self.cache_root = cache_root
        self.runner = runner or SystemCommandRunner()

    def resolve_source(self, coin: ManifestCoin, tag: str, timeout: int) -> tuple[Path | None, str]:
        """Resolve local source for the exact tag string only (see resolve_for)."""
        return self.resolve_for(coin.ticker, coin.repo_url, tag, timeout)

    def resolve_for(  # noqa: PLR0911  # checkout state machine: one return per resolution outcome
        self,
        ticker: str,
        repo_url: str | None,
        tag: str,
        timeout: int,
    ) -> tuple[Path | None, str]:
        """Fetch ``tag`` for ``ticker`` into the coin's single checkout folder.

        Exact string semantics: only the byte-equal tag counts — "v4.2.0.1"
        and "4.2.0.1" are distinct tags; a tag missing upstream yields
        clone-failed/fetch-failed and surfaces as that failure status in
        the report.

        One folder per coin (``repo_checkout_dir``): a missing folder is
        shallow-cloned at the tag (``cloned``); an existing one is reused
        offline when HEAD already is that tag's commit, the tree has no
        tracked edits and no leftover files, and the stored origin is the
        requested ``repo_url`` (``reused``), otherwise the exact tag ref
        is force-fetched from ``repo_url`` and checked out
        (``fetched``) and HEAD is verified against the tag commit. A
        failed switch is loud — ERROR on the console plus ``fetch-failed``
        in the report — the folder itself is never deleted, it never
        degrades to a silent reuse, and the next pass repairs whatever
        stage the switch died at.
        """
        # This method owns every checkout-tree mutation (clone, staging
        # rename, force-fetch, tag switch). Invalidate memoized source reads
        # first: cached content must never outlive the tree it came from.
        SourceReader.invalidate()
        if not repo_url:
            return None, "no-repo-url"
        target = repo_checkout_dir(ticker, cache_root=self.cache_root)
        try:
            target.parent.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            logger.error(
                "CLONE-FAILED %s @ %s: cannot prepare %s (%s)",
                ticker,
                tag,
                target.parent,
                exc.__class__.__name__,
            )
            return None, "clone-failed"
        op_timeout = max(timeout, 60)

        if target.is_symlink():
            # Never resolve through: the link could point at any other
            # repository, and git -C would operate there. Checked before
            # everything else so dangling links and links to files are
            # covered too — every symlink obstruction fails loud with
            # fetch-failed and a remove-it hint.
            logger.error(
                "FETCH-FAILED %s @ %s: %s is a symlink — remove it to let the tool recreate it",
                ticker,
                tag,
                target,
            )
            return None, "fetch-failed"

        if not target.is_dir():
            if target.exists():
                logger.error(
                    "CLONE-FAILED %s @ %s: %s exists but is not a directory — remove it",
                    ticker,
                    tag,
                    target,
                )
                return None, "clone-failed"
            return self._clone_fresh(ticker, repo_url, tag, target, timeout, op_timeout)

        if not self._is_own_worktree(target, timeout):
            logger.error(
                "FETCH-FAILED %s @ %s: %s is not its own git checkout — remove it to let the tool recreate it",
                ticker,
                tag,
                target,
            )
            return None, "fetch-failed"

        if (
            self._head_is(target, tag, timeout)
            and self._tree_is_clean(target, op_timeout)
            and self._origin_is(target, repo_url, timeout)
        ):
            return target, "reused"

        stage = self._switch_to_tag(target, repo_url, tag, timeout, op_timeout)
        if stage is not None:
            logger.error(
                "FETCH-FAILED %s @ %s: %s — repo at %s",
                ticker,
                tag,
                stage,
                target,
            )
            return None, "fetch-failed"
        return target, "fetched"

    def _clone_fresh(  # noqa: PLR0913, PLR0917  # every ingredient of one clone: identity, source, tag, folder, timeouts
        self, ticker: str, repo_url: str, tag: str, target: Path, timeout: int, op_timeout: int
    ) -> tuple[Path | None, str]:
        """Shallow-clone the tag into a pid-private staging folder, then rename.

        The final folder is only ever created by this call's atomic
        rename and is never rmtree'd, so a folder created by a
        concurrent run between our existence check and our clone can
        never be wiped by us. A clone that lands off the tag (a
        same-named branch shadowing it) recovers through the same tag
        switch the update path uses.
        """
        staging = target.parent / f".{ticker}.{os.getpid()}.staging"
        shutil.rmtree(staging, ignore_errors=True)
        proc = self.runner.run(
            ["git", "clone", "-q", "--depth", "1", "--branch", tag, repo_url, str(staging)],
            op_timeout,
            env_extra={"GIT_TERMINAL_PROMPT": "0"},
        )
        if proc is not None and proc.returncode == 0:
            if self._head_is(staging, tag, timeout):
                stage = None
            else:
                # Landed off the tag (a same-named branch shadowing
                # it): recover exactly like the update path does
                # instead of failing on every future run.
                stage = self._switch_to_tag(staging, repo_url, tag, timeout, op_timeout)
            if stage is None:
                try:
                    staging.rename(target)
                except OSError:
                    # A concurrent run won the folder; keep theirs, drop ours.
                    shutil.rmtree(staging, ignore_errors=True)
                    logger.error(
                        "CLONE-FAILED %s @ %s: another run created %s first, this clone was dropped",
                        ticker,
                        tag,
                        target,
                    )
                    return None, "clone-failed"
                return target, "cloned"
            logger.error(
                "CLONE-FAILED %s @ %s: %s (refs/tags/%s may be shadowed by a branch or absent upstream)",
                ticker,
                tag,
                stage,
                tag,
            )
        else:
            logger.error(
                "CLONE-FAILED %s @ %s: git clone failed (rc=%s)%s",
                ticker,
                tag,
                (proc.returncode if proc else "no-output"),
                _stderr_note(proc),
            )
        # Whatever remains here is staging this call created (pid-private).
        shutil.rmtree(staging, ignore_errors=True)
        return None, "clone-failed"

    def _switch_to_tag(self, target: Path, repo_url: str, tag: str, timeout: int, op_timeout: int) -> str | None:
        """Fetch the exact tag into ``target`` and switch to it.

        Shared by the fresh-clone recovery and the update path, so both
        resolve an existing tag the same way. Returns ``None`` on
        success (HEAD verified at the tag commit, origin aligned, tree
        exact), else a human-readable failure stage for the caller's
        ERROR line.
        """
        proc_fetch = self.runner.run(
            ["git", "-C", str(target), "fetch", "-q", "--depth", "1", repo_url, f"+refs/tags/{tag}:refs/tags/{tag}"],
            op_timeout,
            env_extra={"GIT_TERMINAL_PROMPT": "0"},
        )
        if proc_fetch is None or proc_fetch.returncode != 0:
            return "tag fetch failed" + _stderr_note(proc_fetch)
        proc_co = self.runner.run(
            ["git", "-C", str(target), "checkout", "-q", "-f", f"tags/{tag}"],
            op_timeout,
            env_extra={"GIT_TERMINAL_PROMPT": "0"},
        )
        if proc_co is None or proc_co.returncode != 0:
            return (
                "tag fetched, but checkout of the tag failed "
                f"(rc={proc_co.returncode if proc_co else 'no-output'})"
                f"{_stderr_note(proc_co)}"
            )
        # checkout -f never deletes untracked leftovers; the folder is
        # scratch (README), so the forced switch clears them too and the
        # tree becomes exactly the tag. -ff lets clean remove nested repos
        # as well, so the repair clears exactly what the gate reports
        # (gitignored artifacts are exempt on both sides).
        proc_clean = self.runner.run(
            ["git", "-C", str(target), "clean", "-q", "-ffd"],
            op_timeout,
        )
        if proc_clean is None or proc_clean.returncode != 0:
            return (
                "tag checked out, but clearing untracked leftovers failed "
                f"(rc={proc_clean.returncode if proc_clean else 'no-output'})"
                f"{_stderr_note(proc_clean)}"
            )
        if not self._head_is(target, tag, timeout):
            return "fetched, but HEAD is not the tag commit"
        # The tree now provably comes from repo_url; align the stored
        # origin so the offline reuse gate can trust it next run
        # (best effort — a failure here only costs a refetch later).
        self.runner.run(
            ["git", "-C", str(target), "config", "remote.origin.url", repo_url],
            op_timeout,
        )
        return None

    def _is_own_worktree(self, target: Path, timeout: int) -> bool:
        """True iff ``target`` is the ROOT of its own git worktree.

        Guards against ``git -C`` walking up to an enclosing repository
        (the cache lives inside the tool's own repo) and operating there.
        """
        proc = self.runner.run(["git", "-C", str(target), "rev-parse", "--show-toplevel"], timeout)
        if proc is None or proc.returncode != 0 or not proc.stdout.strip():
            return False
        try:
            return Path(proc.stdout.strip()).resolve() == target.resolve()
        except OSError:
            return False

    def _origin_is(self, target: Path, repo_url: str, timeout: int) -> bool:
        """True iff the checkout's stored origin is the same remote as ``repo_url``.

        Compared in canonical form (see ``canonical_repo_url``): scaffold
        normalizes user-supplied URLs, so a cosmetic .git / trailing-slash
        difference must not make the two flows refetch in alternation. A
        manifest repo_url correction to a DIFFERENT repo still fails here
        — colliding tag names across repos are the norm.
        """
        proc = self.runner.run(["git", "-C", str(target), "config", "--get", "remote.origin.url"], timeout)
        if proc is None or proc.returncode != 0 or not proc.stdout.strip():
            return False
        return canonical_repo_url(proc.stdout.strip()) == canonical_repo_url(repo_url)

    def _tree_is_clean(self, target: Path, timeout: int) -> bool:
        """True iff the tree has no tracked edits AND no untracked leftovers.

        Guards the reuse promise: a switch killed mid-checkout leaves HEAD
        at the tag but the tree half-written, and leftovers from another
        tag are not part of the tag's tree — such a tree must go through
        the forced fetch, never certified as source. The folder is
        declared scratch in the README, so untracked drop-ins count as
        dirt here too; gitignored artifacts are exempt (nothing builds
        inside a checkout), and the repair below clears exactly what this
        check reports.
        """
        proc = self.runner.run(
            ["git", "-C", str(target), "status", "--porcelain", "-uall"],
            timeout,
        )
        return bool(proc and proc.returncode == 0 and not proc.stdout.strip())

    def _head_is(self, target: Path, tag: str, timeout: int) -> bool:
        """True iff HEAD is exactly the commit the byte-equal tag points at.

        The tag is resolved through ``refs/tags/`` explicitly: a bare
        name would let a same-named branch (``git clone --branch``,
        loose-ref rules) stand in for the manifest tag.
        """
        h_head = self.runner.run(["git", "-C", str(target), "rev-parse", "HEAD"], timeout)
        h_tag = self.runner.run(["git", "-C", str(target), "rev-list", "-n", "1", f"refs/tags/{tag}"], timeout)
        return bool(
            h_head
            and h_tag
            and h_head.returncode == 0
            and h_tag.returncode == 0
            and h_head.stdout.strip()
            and h_head.stdout.strip() == h_tag.stdout.strip()
        )


class SourceReader:
    """Wrapper-aware source code file reader with multi-level directory discovery.

    Only path resolution is memoized, and only for the lifetime of one
    stable checkout state: the wrapper-directory walk is the expensive part
    of a lookup, and a probe for a file a coin does not have re-walks the
    whole tree every time. The checkout manager owns every tree mutation
    (clone, staging rename, force-fetch, tag switch) and invalidates the
    cache at the start of ``resolve_for``, so a cached resolution can never
    outlive the tree it was resolved in. File content is always read fresh —
    this cache never decides what a reader sees.
    """

    _RESOLVED: ClassVar[dict[str, Path | None]] = {}
    _WRAPPERS: ClassVar[dict[str, list[Path]]] = {}

    @classmethod
    def invalidate(cls) -> None:
        """Drop every cached resolution; call before mutating a checkout tree."""
        cls._RESOLVED.clear()
        cls._WRAPPERS.clear()

    @staticmethod
    def slurp(path: str | Path) -> str | None:
        try:
            with Path(path).open(encoding="utf-8", errors="replace") as fh:
                return fh.read()
        except OSError:
            return None

    @classmethod
    def slurp_src(cls, src_dir: Path, rel_path: str) -> str | None:
        """Slurp src/rel_path scanning top-level and nested wrapper directories.

        Generic BFS depth<=3 capped, exclude .git and symlinks, not hardcoded.
        The wrapper walk is memoized per stable checkout state, so a probe
        for a file the coin does not have costs one walk per tag, not one
        per conf value. Content is read fresh on every call.
        """
        path = cls._resolve_src(src_dir, rel_path)
        return cls.slurp(path) if path is not None else None

    @classmethod
    def read_src(cls, src_dir: Path, rel_path: str) -> str | None:
        """slurp_src, plus the direct-tree read its None does not imply.

        The path-resolution memo caches misses too, so ``slurp_src`` can
        return None for a file that has appeared since the tree was
        first probed (a scaffold writes sources into a live checkout).
        The direct read is one stat against that, and it is the only
        read that can see such a file without a full re-walk; content
        is read fresh either way.
        """
        return cls.slurp_src(src_dir, rel_path) or cls.slurp(src_dir / rel_path)

    @classmethod
    def _resolve_src(cls, src_dir: Path, rel_path: str) -> Path | None:
        """Locate src/rel_path at top level or inside wrapper directories."""
        key = f"{src_dir}|{rel_path}"
        if key not in cls._RESOLVED:
            cls._RESOLVED[key] = cls._find_src(src_dir, rel_path)
        return cls._RESOLVED[key]

    @classmethod
    def _find_src(cls, src_dir: Path, rel_path: str) -> Path | None:
        """Direct path first, then the wrapper cascade in discovery order."""
        direct = src_dir / rel_path
        if cls.slurp(direct) is not None:
            return direct
        if not rel_path.startswith("src/"):
            return None
        for wrapper in cls._wrapper_dirs(src_dir):
            cand = wrapper / rel_path
            if cls.slurp(cand) is not None:
                return cand
        return None

    @staticmethod
    def _usable_dir(entry: Path) -> bool:
        """A directory the walk may enter: real, readable, not the repo dir."""
        return entry.is_dir() and not entry.is_symlink() and entry.name != ".git"

    @classmethod
    def _wrapper_dirs(cls, src_dir: Path) -> list[Path]:
        """Wrapper-directory snapshot in BFS discovery order, depth<=3.

        Every lookup in one checkout state walks the same tree, so the walk
        itself is memoized per src_dir: the snapshot preserves the exact
        order a per-lookup BFS would have probed, so the resolved file is
        the same file — the only change is that the tree is read once.
        """
        key = f"wrappers:{src_dir}"
        if key in cls._WRAPPERS:
            return cls._WRAPPERS[key]
        seen: set[Path] = set()
        queue: deque[tuple[Path, int]] = deque()
        out: list[Path] = []

        def enqueue(entries, depth: int) -> None:
            for entry in entries:
                if entry in seen or not cls._usable_dir(entry):
                    continue
                seen.add(entry)
                queue.append((entry, depth))

        try:
            enqueue(src_dir.iterdir(), 1)
        except OSError:
            cls._WRAPPERS[key] = out
            return out

        while queue:
            cur, depth = queue.popleft()
            out.append(cur)
            if depth < 3:  # noqa: PLR2004  # source-tree walk depth guard
                try:
                    enqueue(cur.iterdir(), depth + 1)
                except OSError:
                    continue
        cls._WRAPPERS[key] = out
        return out

    @staticmethod
    def strip_comments(text: str) -> str:
        # Both removals preserve newlines so evidence line numbers stay valid:
        # block spans are replaced by their interior newlines, and the
        # full-line // pattern uses [ \t] (never \s, which would also eat a
        # preceding blank line's newline and shift every later line number).
        text = re.sub(r"/\*.*?\*/", lambda m: "\n" * m.group(0).count("\n"), text, flags=re.S)
        return re.sub(r"^[ \t]*//.*$", "", text, flags=re.M)

    @classmethod
    def parse_conf_sections(cls, path: str | Path) -> dict[str, dict[str, str]]:
        """Parse ini-style conf into {section: {key: value}}."""
        out: dict[str, dict[str, str]] = {"": {}}
        cur = ""
        txt = cls.slurp(path)
        if txt is None:
            return out
        for raw_line in txt.splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("[") and line.endswith("]"):
                cur = line[1:-1].strip().lower()
                out.setdefault(cur, {})
                continue
            if "=" not in line:
                continue
            k, v = line.split("=", 1)
            out[cur][k.strip()] = v.strip()
        return out

    @classmethod
    def parse_conf(cls, path: str | Path) -> dict[str, str]:
        """Parse key=value pairs dropping comments and section headers."""
        conf: dict[str, str] = {}
        txt = cls.slurp(path)
        if txt is None:
            return conf
        for raw_line in txt.splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#") or line.startswith("["):
                continue
            if "=" not in line:
                continue
            k, v = line.split("=", 1)
            conf[k.strip()] = v.strip()
        return conf

    @staticmethod
    def lineage_date(repo_root: Path, rel_path: str, key: str, runner: SystemCommandRunner | None = None) -> str | None:
        """Determine git birth-date (YYYY-MM-DD) of a key= line via git blame."""
        runner = runner or SystemCommandRunner()
        path = repo_root / rel_path
        if not path.is_file():
            return None
        n: int | None = None
        try:
            with path.open(encoding="utf-8", errors="replace") as fh:
                n = next((i + 1 for i, line in enumerate(fh) if line.strip().startswith(f"{key}=")), None)
        except OSError:
            return None
        if not n:
            return None

        proc = runner.run(
            ["git", "-C", str(repo_root), "blame", "--porcelain", "-L", f"{n},{n}", "--", rel_path],
            15,
        )
        if proc is None or proc.returncode != 0:
            return None
        m = re.search(r"^committer-time (\d+)", proc.stdout, re.M)
        if not m:
            return None
        return datetime.datetime.fromtimestamp(int(m.group(1)), datetime.timezone.utc).strftime("%Y-%m-%d")
