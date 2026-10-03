"""Local source checkouts and conf/source file reading.

``SourceCheckoutManager`` owns clone/fetch/reuse decisions for param checks;
``SourceReader`` reads and parses conf and C/C++ source files. Both are
filesystem-local — network calls go through ``probe.SystemCommandRunner``.
"""

from __future__ import annotations

import datetime
import re
import shutil
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple, Union

from .constants import CACHE_ROOT, logger
from .model import ManifestCoin
from .probe import SystemCommandRunner
from .util import sanitize_tag


class SourceCheckoutManager:
    """Manages the local git clones and shallow checkouts used for param checking.

    All checkouts live under CACHE_ROOT inside this repository (gitignored).
    """

    def __init__(self, cache_root: Path = CACHE_ROOT, runner: SystemCommandRunner = SystemCommandRunner()):
        self.cache_root = cache_root
        self.tmp_root = cache_root
        self.runner = runner

    @staticmethod
    def candidate_stems(coin: ManifestCoin) -> List[str]:
        raw: List[str] = []
        for stem in (
            coin.ticker.lower(),
            coin.dir_name_linux.lower() if coin.dir_name_linux else "",
            coin.ver_id.partition("--")[0].lower() if coin.ver_id else "",
            coin.daemon_stem.lower() if coin.daemon_stem else "",
        ):
            s = stem.strip().lower()
            if s and s not in raw:
                raw.append(s)
        return raw

    def resolve_source(self, coin: ManifestCoin, tag: str, timeout: int) -> Tuple[Optional[Path], str]:
        """Resolve local source for the exact tag string only.

        Exact string semantics: clones/reuses only the byte-equal tag
        via ``git clone --branch <exact>`` / ``git fetch refs/tags/<exact>``
        and verifies HEAD matches that exact tag commit. No canonical
        v-prefix stripping, parse_version normalization, or "v" vs "no-v"
        equivalence is performed — "v4.2.0.1" and "4.2.0.1" are distinct
        tags. A phantom/missing tag therefore correctly yields
        clone-failed and surfaces as REVIEW at the caller.
        """
        self.tmp_root.mkdir(parents=True, exist_ok=True)

        existing_map: Dict[str, Path] = {}
        try:
            for entry in self.tmp_root.iterdir():
                if entry.is_dir():
                    existing_map[entry.name.lower()] = entry
        except OSError:
            pass

        candidates: List[Path] = []
        for stem in self.candidate_stems(coin):
            if stem:
                base_lower = f"{stem}_check".lower()
                candidates.append(existing_map.get(base_lower, self.tmp_root / f"{stem}_check"))
                tag_lower = f"{stem}_{sanitize_tag(tag)}_check".lower()
                candidates.append(existing_map.get(tag_lower, self.tmp_root / f"{stem}_{sanitize_tag(tag)}_check"))

        # Deduplicate while preserving order
        seen: Set[Path] = set()
        uniq_candidates = [c for c in candidates if not (c in seen or seen.add(c))]

        for cand in uniq_candidates:
            if not cand.is_dir():
                continue
            proc = self.runner.run(["git", "-C", str(cand), "describe", "--tags", "--exact-match"], timeout)
            if proc and proc.returncode == 0 and proc.stdout.strip() == tag:
                h_head = self.runner.run(["git", "-C", str(cand), "rev-parse", "HEAD"], timeout)
                h_tag = self.runner.run(["git", "-C", str(cand), "rev-list", "-n", "1", tag], timeout)
                if h_head and h_tag and h_head.returncode == 0 and h_tag.returncode == 0:
                    if h_head.stdout.strip() == h_tag.stdout.strip():
                        return cand, "reused"

        primary_stem = (coin.dir_name_linux or coin.ticker.lower()).lower() or (coin.daemon_stem.lower() if coin.daemon_stem else "coin")
        primary_target = existing_map.get(f"{primary_stem}_check", self.tmp_root / f"{primary_stem}_check")

        if primary_target.is_dir():
            p = self.runner.run(["git", "-C", str(primary_target), "describe", "--tags", "--exact-match"], timeout)
            if p and p.returncode == 0 and p.stdout.strip() != tag:
                target = existing_map.get(f"{primary_stem}_{sanitize_tag(tag)}_check", self.tmp_root / f"{primary_stem}_{sanitize_tag(tag)}_check")
            else:
                target = primary_target
        else:
            target = primary_target

        if not coin.repo_url:
            return None, "no-repo-url"

        clone_timeout = max(timeout, 60)
        proc = self.runner.run(
            ["git", "clone", "-q", "--depth", "1", "--branch", tag, coin.repo_url, str(target)],
            clone_timeout,
            env_extra={"GIT_TERMINAL_PROMPT": "0"},
        )
        if proc is not None and proc.returncode == 0 and target.is_dir():
            return target, "cloned"

        # Fallback for lightweight/annotated tags where shallow branch clone fails
        shutil.rmtree(target, ignore_errors=True)
        try:
            target.mkdir(parents=True, exist_ok=True)
            self.runner.run(["git", "init", "-q", str(target)], clone_timeout, env_extra={"GIT_TERMINAL_PROMPT": "0"})
            proc_fetch = self.runner.run(
                ["git", "-C", str(target), "fetch", "-q", "--depth", "1", coin.repo_url, f"refs/tags/{tag}:refs/tags/{tag}"],
                clone_timeout,
                env_extra={"GIT_TERMINAL_PROMPT": "0"},
            )
            if proc_fetch is None or proc_fetch.returncode != 0:
                self.runner.run(["git", "-C", str(target), "remote", "add", "origin", coin.repo_url], timeout, env_extra={"GIT_TERMINAL_PROMPT": "0"})
                proc_fetch = self.runner.run(
                    ["git", "-C", str(target), "fetch", "-q", "--depth", "1", "origin", "tag", tag],
                    clone_timeout,
                    env_extra={"GIT_TERMINAL_PROMPT": "0"},
                )

            if proc_fetch is not None and proc_fetch.returncode == 0:
                for checkout_target in (tag, f"tags/{tag}"):
                    proc_co = self.runner.run(
                        ["git", "-C", str(target), "checkout", "-q", checkout_target],
                        timeout,
                        env_extra={"GIT_TERMINAL_PROMPT": "0"},
                    )
                    if proc_co is not None and proc_co.returncode == 0:
                        return target, "cloned-fallback"
        except Exception as e:
            logger.debug("Clone fallback failed for %s @ %s: %s", coin.ticker, tag, e)

        shutil.rmtree(target, ignore_errors=True)
        return None, "clone-failed"


class SourceReader:
    """Wrapper-aware source code file reader with multi-level directory discovery."""

    @staticmethod
    def slurp(path: Union[str, Path]) -> Optional[str]:
        try:
            with open(path, encoding="utf-8", errors="replace") as fh:
                return fh.read()
        except OSError:
            return None

    @classmethod
    def slurp_src(cls, src_dir: Path, rel_path: str) -> Optional[str]:
        """Slurp src/rel_path scanning top-level and nested wrapper directories.

        Generic BFS depth≤3 capped, exclude .git and symlinks, not hardcoded.
        """
        direct = src_dir / rel_path
        txt = cls.slurp(direct)
        if txt is not None:
            return txt
        if not rel_path.startswith("src/"):
            return None

        from collections import deque

        seen: Set[Path] = set()
        queue: deque[Tuple[Path, int]] = deque()
        try:
            for entry in src_dir.iterdir():
                if entry.is_symlink():
                    continue
                if not entry.is_dir():
                    continue
                if entry.name == ".git":
                    continue
                if entry in seen:
                    continue
                seen.add(entry)
                queue.append((entry, 1))
        except OSError:
            return None

        while queue:
            cur, depth = queue.popleft()
            cand = cur / rel_path
            txt2 = cls.slurp(cand)
            if txt2 is not None:
                return txt2
            if depth < 3:
                try:
                    for sub in cur.iterdir():
                        if sub.is_symlink():
                            continue
                        if not sub.is_dir():
                            continue
                        if sub.name == ".git":
                            continue
                        if sub in seen:
                            continue
                        seen.add(sub)
                        queue.append((sub, depth + 1))
                except OSError:
                    continue
        return None

    @staticmethod
    def strip_comments(text: str) -> str:
        # Both removals preserve newlines so evidence line numbers stay valid:
        # block spans are replaced by their interior newlines, and the
        # full-line // pattern uses [ \t] (never \s, which would also eat a
        # preceding blank line's newline and shift every later line number).
        text = re.sub(r"/\*.*?\*/", lambda m: "\n" * m.group(0).count("\n"), text, flags=re.S)
        return re.sub(r"^[ \t]*//.*$", "", text, flags=re.M)

    @classmethod
    def parse_conf_sections(cls, path: Union[str, Path]) -> Dict[str, Dict[str, str]]:
        """Parse ini-style conf into {section: {key: value}}."""
        out: Dict[str, Dict[str, str]] = {"": {}}
        cur = ""
        txt = cls.slurp(path)
        if txt is None:
            return out
        for line in txt.splitlines():
            line = line.strip()
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
    def parse_conf(cls, path: Union[str, Path]) -> Dict[str, str]:
        """Parse key=value pairs dropping comments and section headers."""
        conf: Dict[str, str] = {}
        txt = cls.slurp(path)
        if txt is None:
            return conf
        for line in txt.splitlines():
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("["):
                continue
            if "=" not in line:
                continue
            k, v = line.split("=", 1)
            conf[k.strip()] = v.strip()
        return conf

    @staticmethod
    def lineage_date(repo_root: Path, rel_path: str, key: str, runner: SystemCommandRunner = SystemCommandRunner()) -> Optional[str]:
        """Determine git birth-date (YYYY-MM-DD) of a key= line via git blame."""
        path = repo_root / rel_path
        if not path.is_file():
            return None
        n: Optional[int] = None
        try:
            with open(path, encoding="utf-8", errors="replace") as fh:
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
