"""Remote repository probing: git smart-HTTP, HTTP redirects, GitHub releases.

Every external call goes through :class:`SystemCommandRunner` so timeouts,
retries and environment hardening live in exactly one place. Nothing here
reads the local manifest — callers pass URLs and tags in.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import time
from pathlib import Path

from .constants import (
    _CHANGELOG_CACHE_DIRNAME,
    logger,
)
from .model import RepoStatus
from .util import _detect_mandatory_hf, _parse_github_owner_repo, sanitize_tag

# Git and HTTP outcomes the probe interprets.
_GIT_FATAL_EXIT = 128
_HTTP_OK = 200
_HTTP_NOT_FOUND = 404


class SystemCommandRunner:
    """Executes external processes with retry mechanisms and environment management."""

    @staticmethod
    def run(
        cmd: list[str],
        timeout: int,
        retries: int = 2,
        env_extra: dict[str, str] | None = None,
        cwd: str | Path | None = None,
    ) -> subprocess.CompletedProcess[str] | None:
        env = dict(os.environ)
        if env_extra:
            env.update(env_extra)

        attempt = 0
        while True:
            try:
                return subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=timeout,
                    env=env,
                    cwd=str(cwd) if cwd else None,
                    check=False,  # callers inspect returncode themselves (probe_tags etc.)
                )
            except subprocess.TimeoutExpired:
                attempt += 1
                if attempt > retries:
                    logger.warning("Command timed out after %d attempts: %s", attempt, " ".join(cmd))
                    return None
                time.sleep(1)
            except Exception as e:
                logger.error("Command execution error for %s: %s", " ".join(cmd), e)
                return None


class RemoteProbeService:
    """Probes remote git repositories using smart-HTTP protocol and HTTP headers."""

    def __init__(self, runner: SystemCommandRunner | None = None):
        self.runner = runner or SystemCommandRunner()

    def probe_redirect(self, url: str, timeout: int) -> str | None:
        """Detect HTTP 301/302 redirects without GitHub REST API."""
        proc = self.runner.run(
            ["curl", "-sI", "-o", "/dev/null", "-w", "%{redirect_url}", url],
            timeout,
        )
        if proc is None:
            return None
        target = proc.stdout.strip()
        if target and target.rstrip("/") != url.rstrip("/"):
            return target
        return None

    def probe_tags(self, url: str, timeout: int) -> tuple[RepoStatus, set[str] | None]:
        """Query remote refs using git ls-remote."""
        proc = self.runner.run(
            ["git", "ls-remote", "--tags", url],
            timeout,
            env_extra={"GIT_TERMINAL_PROMPT": "0"},
        )
        if proc is None:
            return RepoStatus.UNKNOWN, None
        if proc.returncode == _GIT_FATAL_EXIT:
            return RepoStatus.DEAD, None
        if proc.returncode != 0:
            return RepoStatus.ERROR, None

        tags: set[str] = set()
        for line in proc.stdout.splitlines():
            if "refs/tags/" not in line:
                continue
            ref = line.split("refs/tags/", 1)[1]
            if ref.endswith("^{}"):
                continue
            tags.add(ref)
        return RepoStatus.ALIVE, tags

    def probe_tag_dates(self, url: str, selected: set[str], timeout: int) -> dict[str, str] | None:
        """Fetch creatordate for selected tags using a single shallow bare fetch."""
        if not selected:
            return {}

        tmp_dir = tempfile.mkdtemp()
        try:
            init = self.runner.run(["git", "init", "-q", "--bare", tmp_dir], timeout)
            if init is None or init.returncode != 0:
                return None

            refspecs = [f"+refs/tags/{t}:refs/tags/{t}" for t in sorted(selected)]
            fetch_cmd = [
                "git",
                "-C",
                tmp_dir,
                "fetch",
                "-q",
                "--depth=1",
                "--filter=tree:0",
                "--no-tags",
                url,
                *refspecs,
            ]

            fetch = self.runner.run(fetch_cmd, timeout, env_extra={"GIT_TERMINAL_PROMPT": "0"})
            if fetch is None or fetch.returncode != 0:
                return None

            fmt = self.runner.run(
                [
                    "git",
                    "-C",
                    tmp_dir,
                    "for-each-ref",
                    "--format=%(refname) %(creatordate:iso8601)",
                    "refs/tags",
                ],
                timeout,
            )
            if fmt is None or fmt.returncode != 0:
                return None

            dates: dict[str, str] = {}
            for line in fmt.stdout.splitlines():
                if "refs/tags/" in line:
                    ref, date = line.split(" ", 1)
                    tag = ref.split("refs/tags/", 1)[1]
                    if not tag.endswith("^{}"):
                        dates[tag] = date.strip()
            return dates
        finally:
            shutil.rmtree(tmp_dir, ignore_errors=True)

    def probe_tag_annotation(self, url: str, tag: str, timeout: int) -> str | None:
        """Fetch annotated tag message via shallow bare fetch + for-each-ref."""
        tmp_dir = tempfile.mkdtemp()
        try:
            init = self.runner.run(["git", "init", "-q", "--bare", tmp_dir], timeout)
            if init is None or init.returncode != 0:
                return None
            fetch = self.runner.run(
                ["git", "-C", tmp_dir, "fetch", "-q", "--depth=1", url, f"refs/tags/{tag}:refs/tags/{tag}"],
                timeout,
                env_extra={"GIT_TERMINAL_PROMPT": "0"},
            )
            if fetch is None or fetch.returncode != 0:
                return None
            fmt = self.runner.run(
                ["git", "-C", tmp_dir, "for-each-ref", "--format=%(contents)", f"refs/tags/{tag}"],
                timeout,
            )
            if fmt is None or fmt.returncode != 0:
                return None
            txt = fmt.stdout.strip()
            return txt if txt else None
        finally:
            shutil.rmtree(tmp_dir, ignore_errors=True)

    def probe_github_release(  # noqa: C901, PLR0911, PLR0912  # release prober: one return per probe outcome
        self,
        url: str,
        tag: str,
        timeout: int,
        cache_root: Path | None = None,
    ) -> str | None:
        """Fetch GitHub Releases body via api.github.com, cached in .cache/audit-manifest/.changelog_cache.
        Stdlib-only, no token. The cache is ephemeral by design (gitignored
        scratch): purge it to force a re-probe."""
        parsed = _parse_github_owner_repo(url)
        if not parsed:
            return None
        owner, repo = parsed
        cache_dir: Path | None = None
        cache_path: Path | None = None
        if cache_root is not None:
            try:
                cache_dir = cache_root / _CHANGELOG_CACHE_DIRNAME
                cache_dir.mkdir(parents=True, exist_ok=True)
                safe_tag = sanitize_tag(tag)
                cache_path = cache_dir / f"{owner}_{repo}_{safe_tag}.json"
                if cache_path.is_file():
                    try:
                        data = json.loads(cache_path.read_text(encoding="utf-8"))
                        body = data.get("body")
                        if isinstance(body, str) and body.strip():
                            return body
                    except Exception as e:
                        # A corrupt/partial cache entry is scratch — re-probe instead of failing.
                        logger.debug("ignoring unreadable release cache %s: %s", cache_path, e)
            except Exception:
                cache_path = None
        api_url = f"https://api.github.com/repos/{owner}/{repo}/releases/tags/{tag}"
        proc = self.runner.run(
            ["curl", "-s", "-H", "Accept: application/vnd.github+json", "-w", "\n%{http_code}", api_url],
            timeout,
        )
        if proc is None or proc.returncode != 0:
            return None
        out = proc.stdout.strip()
        if "\n" in out:
            body_part, code_part = out.rsplit("\n", 1)
        else:
            body_part, code_part = out, ""
        # isdigit() guards int(); the previous try/except was unreachable dead code.
        code = int(code_part.strip()) if code_part.strip().isdigit() else -1
        if code in (429, 403):
            logger.warning("GitHub release probe rate-limited (%s) for %s @ %s — changelog degrades", code, url, tag)
            return None
        if code == _HTTP_NOT_FOUND:
            return None
        if code != _HTTP_OK:
            return None
        try:
            data = json.loads(body_part) if body_part else {}
        except Exception:
            return None
        body = data.get("body") if isinstance(data, dict) else None
        if not isinstance(body, str) or not body.strip():
            name = data.get("name") if isinstance(data, dict) else None
            if isinstance(name, str) and name.strip():
                body = name
            else:
                return None
        if cache_path is not None:
            try:
                cache_path.write_text(
                    json.dumps({"body": body, "tag": tag, "url": api_url}, indent=2), encoding="utf-8"
                )
            except Exception as e:
                # Cache writes are best-effort; a read-only cache dir degrades to re-probing.
                logger.debug("release cache write failed for %s: %s", cache_path, e)
        return body

    def probe_changelog(
        self,
        url: str,
        tag: str,
        timeout: int,
        cache_root: Path | None = None,
    ) -> tuple[str, str] | None:
        """Hybrid: check both tag annotation and GitHub Releases; prefer mandatory hit."""
        tag_txt: str | None = None
        gh_body: str | None = None
        try:
            tag_txt = self.probe_tag_annotation(url, tag, timeout)
        except Exception:
            tag_txt = None
        try:
            gh_body = self.probe_github_release(url, tag, timeout, cache_root)
        except Exception:
            gh_body = None
        # Prefer GitHub body if it contains mandatory, else tag, else any non-empty
        # Check mandatory in both
        gh_quote = _detect_mandatory_hf(gh_body) if gh_body else None
        tag_quote = _detect_mandatory_hf(tag_txt) if tag_txt else None
        if gh_quote and gh_body:
            return ("github-releases", gh_body.strip())
        if tag_quote and tag_txt:
            return ("tag", tag_txt.strip())
        if gh_body and gh_body.strip():
            return ("github-releases", gh_body.strip())
        if tag_txt and tag_txt.strip():
            return ("tag", tag_txt.strip())
        return None
