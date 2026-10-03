"""Version/semver evaluation and repo triage classification.

Pure decision functions: given tags and dates, what is newer, what is
stale, and which operational action (OK/UPGRADE/REVIEW/...) a repo maps to.
"""

from __future__ import annotations

import datetime
import re
from typing import Any, Dict, List, Optional, Set, Tuple

from .constants import _PRERELEASE_RE
from .model import ActionType, ManifestCoin, RepoStatus


class VersionEngine:
    """Pure functions for version string evaluation, semver sorting, and fossil detection."""

    @staticmethod
    def parse_version(tag: str) -> Optional[Tuple[int, ...]]:
        """Return numeric tuple for dotted-numeric version tag, else None."""
        s = tag.strip()
        m = re.match(r"^[^\d]*(\d+(?:\.\d+)*)", s)
        if not m:
            return None
        num_str = m.group(1)
        # hash guard: single-component (no dot) + suffix isalpha + no leading v
        # keeps da839021c -> None while preserving v22-final -> (22,)
        if "." not in num_str:
            suffix = s[m.end():]
            if suffix and suffix.isalpha() and not s.lower().startswith("v"):
                return None
        return tuple(int(p) for p in num_str.split("."))

    @classmethod
    def is_prerelease(cls, tag: str) -> bool:
        """True if the tag contains pre-release markers (alpha/beta/rc/etc.)."""
        m = re.match(r"^[^\d]*\d+(?:\.\d+)*(.*)$", tag.strip())
        if not m:
            return False
        return bool(_PRERELEASE_RE.search(m.group(1)))

    @classmethod
    def stable_tags(cls, tags: Optional[Set[str]]) -> Optional[Set[str]]:
        """Subset of tags excluding pre-releases."""
        if tags is None:
            return None
        return {t for t in tags if not cls.is_prerelease(t)}

    @classmethod
    def max_version_tag(cls, tags: Any) -> Optional[str]:
        """Highest numeric-version tag in iterable, resolving ties lexically."""
        best, best_p = None, None
        for t in sorted(tags or ()):
            p = cls.parse_version(t)
            if p is None:
                continue
            if best_p is None or p > best_p:
                best, best_p = t, p
        return best

    @classmethod
    def detect_newer(cls, remote_tags: Optional[Set[str]], coins: List[ManifestCoin]) -> Tuple[List[str], List[str]]:
        """Split upstream tags into newer_same and newer_alt relative to held tags."""
        if remote_tags is None:
            return [], []
        stable = cls.stable_tags(remote_tags)
        if not stable:
            return [], []

        held_tags: Set[str] = set()
        for coin in coins:
            held_tags.update(coin.expected_tags())

        parsed_held = [cls.parse_version(t) for t in held_tags]
        valid_held = [p for p in parsed_held if p is not None]
        if not valid_held:
            return [], []

        max_held = max(valid_held)
        max_len = len(max_held)

        newer_same: List[str] = []
        newer_alt: List[str] = []

        for t in sorted(stable):
            p = cls.parse_version(t)
            if p is None or p <= max_held:
                continue
            (newer_same if len(p) == max_len else newer_alt).append(t)

        return newer_same, newer_alt


def classify_action(
    status: RepoStatus,
    missing: List[str],
    newer_same: List[str],
    newer_alt: List[str],
    stale: bool,
) -> ActionType:
    """Determine operational triage action for repository."""
    if status == RepoStatus.DEAD:
        return ActionType.DEAD
    if status == RepoStatus.MOVED:
        return ActionType.MOVED
    if status in (RepoStatus.UNKNOWN, RepoStatus.ERROR):
        return ActionType.UNKNOWN
    if newer_same:
        return ActionType.UPGRADE
    if newer_alt or missing or stale:
        return ActionType.REVIEW
    return ActionType.OK


def _newest_and_stale(
    tag_dates: Dict[str, str], stale_years: float
) -> Tuple[Optional[str], Optional[str], bool]:
    """Derive newest tag/date and stale flag from tag_dates (DRY helper)."""
    if not tag_dates:
        return None, None, False
    dated = sorted(tag_dates.items(), key=lambda kv: kv[1], reverse=True)
    newest_tag, newest_date = dated[0]
    stale = False
    try:
        nd = datetime.datetime.strptime(newest_date, "%Y-%m-%d %H:%M:%S %z")
        age = (datetime.datetime.now(nd.tzinfo) - nd).days / 365.25
        stale = age > stale_years
    except ValueError:
        pass
    return newest_tag, newest_date, stale


def action_reason(
    action: ActionType,
    status: RepoStatus,
    missing: List[str],
    newer_same: List[str],
    newer_alt: List[str],
    stale: bool,
    new_home: Optional[str],
) -> str:
    parts: List[str] = []
    if action == ActionType.DEAD:
        parts.append("repo unreachable")
    if action == ActionType.MOVED and new_home:
        parts.append(f"moved -> {new_home}")
    if action == ActionType.UNKNOWN:
        parts.append("repo unresolved")
    if newer_same:
        parts.append(f"newer_same=[{', '.join(newer_same)}]")
    if newer_alt:
        parts.append(f"newer_alt=[{', '.join(newer_alt)}]")
    if missing:
        parts.append(f"missing_tags=[{', '.join(missing)}]")
    if stale:
        parts.append("inactive upstream (>3y since newest tag by date)")
    if not parts:
        parts.append("alive, current")
    return "; ".join(parts)


def build_update_version_names(
    ticker: str, old_ver_id: str, old_wc: str, old_xc: str, target: str
) -> Tuple[str, str, str]:
    """Derive (new_ver_id, new_wallet_conf, new_xbridge_conf) for --update-versions.

    Each conf keeps its OWN filename stem (wallet stem from old_wc, xbridge
    stem from old_xc); LBC keeps its lbcd special-case. Pure helper so the
    derivation is unit-testable.
    """
    prefix = old_ver_id.split("--", 1)[0] if "--" in old_ver_id else ticker.lower()
    new_ver_id = f"{prefix}--{target}"
    wc_prefix = old_wc.split("--", 1)[0] if "--" in old_wc else prefix
    xc_prefix = old_xc.split("--", 1)[0] if "--" in old_xc else prefix
    new_wc = f"{wc_prefix}--{target}.conf"
    new_xc = f"{xc_prefix}--{target}.conf"
    if ticker == "LBC":
        # lbcd override is per part: only stems that actually ARE lbcd.
        if wc_prefix == "lbcd":
            new_ver_id = f"lbcd--{target}"
            new_wc = f"lbcd--{target}.conf"
        if xc_prefix == "lbcd":
            new_xc = f"lbcd--{target}.conf"
    return new_ver_id, new_wc, new_xc


def apply_additive_bump(item: Dict[str, Any], target: str) -> bool:
    """Append target to item["versions"] unless already listed.

    ver_id / wallet_conf / xbridge_conf are untouched: the existing conf
    pair keeps serving every listed version (DOGE/BLOCK/SYS convention).
    No conf files are copied or removed. Returns True when the item changed.
    """
    versions = item.get("versions", [])
    if target in versions:
        return False
    versions.append(target)
    item["versions"] = versions
    return True


def should_skip_version_bump(rdata: Dict[str, Any]) -> bool:
    """--update-versions must not auto-bump mandatory-hard-fork repos.

    The changelog path escalates those to REVIEW ("manual replacement
    required"): collapsing versions + verbatim conf copy would certify a
    bump the audit explicitly refuses to certify.
    """
    return bool(rdata.get("changelog_mandatory"))
