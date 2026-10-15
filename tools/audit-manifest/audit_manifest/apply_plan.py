"""Execute reviewed plans: the single write path for appliable entries.

Derivation never writes (plan halves in ``fixes``/``ports`` return
entries with ``applied=False``); application never derives (every
branch below verifies the entry's ``old`` against the file before
touching it, and refuses on mismatch). Conf key/value edits, manifest
version appends/collapses and conf copies each have one branch; every
other action refuses with a reason instead of guessing. Unknown keys
never reach disk: entries are validated before any write, and a
refusal marks only its own entry.
"""

from __future__ import annotations

import json
import os
import re
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .checkout import SourceReader
from .constants import logger
from .probe import SystemCommandRunner
from .reporting import report_line
from .util import iter_conf_lines, norm_port_value
from .versioning import build_update_version_names


def regenerate_base_j2(repo_root: Path, tickers: list[str], runner: SystemCommandRunner | None = None) -> None:
    runner = runner or SystemCommandRunner()
    utils_dir = repo_root / "autobuild" / "utils"
    script = utils_dir / "create-j2-confs.py"
    if not script.is_file():
        logger.warning("create-j2-confs.py not found at %s", script)
        return

    for t in tickers:
        logger.info("Regenerating base.j2 for %s ...", t)
        res = runner.run(
            ["python3", str(script), "--coins", t],
            timeout=60,
            cwd=utils_dir,
            env_extra={"PYTHONUNBUFFERED": "1"},
        )
        if res and res.returncode == 0:
            logger.info("Regenerated base.j2 successfully for %s", t)
        else:
            logger.error("Failed regenerating base.j2 for %s: %s", t, res.stderr if res else "timeout")


def _key_match(line: str, key: str) -> bool:
    return re.match(rf"^\s*{re.escape(key)}\s*=", line, flags=re.I) is not None


def _current_value(txt: str, key: str, *, section_aware: bool) -> str | None:
    for _lineno, line, in_test in iter_conf_lines(txt, section_aware=section_aware):
        if in_test:
            continue
        if _key_match(line, key):
            return line.split("=", 1)[1].strip() if "=" in line else None
    return None


def key_present(txt: str, key: str, *, section_aware: bool) -> bool:
    for _lineno, line, in_test in iter_conf_lines(txt, section_aware=section_aware):
        if in_test:
            continue
        if _key_match(line, key):
            return True
    return False


def _set_or_append(txt: str, key: str, new_val: str, *, section_aware: bool) -> str:
    out: list[str] = []
    replaced = False
    for _lineno, line, in_test in iter_conf_lines(txt, section_aware=section_aware):
        if not in_test and not replaced and _key_match(line, key):
            out.append(f"{key}={new_val}")
            replaced = True
        else:
            out.append(line)
    if not replaced:
        out.append(f"{key}={new_val}")
    return "\n".join(out) + "\n"


def _remove_key(txt: str, key: str) -> tuple:
    lines = txt.splitlines()
    out_lines: list[str] = []
    removed_lines: list[str] = []
    for line in lines:
        if _key_match(line, key):
            removed_lines.append(line.strip())
            continue
        out_lines.append(line)
    return "\n".join(out_lines) + "\n", removed_lines


# plan-entry derivation: one branch per entry shape
def _clean_port(val: Any) -> str:
    return norm_port_value(val) if isinstance(val, str) else ""


def _wallet_slots(item: dict[str, Any], repo_root: Path) -> list[tuple[str, str]]:
    """The top-level (kind, port) pairs a manifest entry's wallet conf holds."""
    wc = item.get("wallet_conf")
    if not wc:
        return []
    try:
        top = SourceReader.parse_conf_sections(repo_root / "wallet-confs" / wc).get("", {})
    except (OSError, ValueError):
        return []
    if not isinstance(top, dict):
        return []
    slots: list[tuple[str, str]] = []
    for key, kind in (("port", "p2p"), ("rpcport", "rpc")):
        clean = _clean_port(top.get(key))
        if clean:
            slots.append((kind, clean))
    return slots


def _xbridge_slot(item: dict[str, Any], repo_root: Path) -> tuple[str, str] | None:
    """The top-level (xbridge, port) pair a manifest entry's xbridge conf holds."""
    xc = item.get("xbridge_conf")
    if not xc:
        return None
    try:
        conf = SourceReader.parse_conf(repo_root / "xbridge-confs" / xc)
    except (OSError, ValueError):
        return None
    if not isinstance(conf, dict):
        return None
    clean = _clean_port(conf.get("Port"))
    return ("xbridge", clean) if clean else None


def _fleet_port_holders(repo_root: Path) -> dict[tuple, str] | None:
    """Top-level port assignments per coin: (kind, value) → ticker."""
    loaded = ManifestStore.read(repo_root / "manifest-latest.json")
    if isinstance(loaded, str):
        return None
    holders: dict[tuple, str] = {}
    for item in loaded.items:
        if not isinstance(item, dict):
            continue
        ticker = item.get("ticker")
        if not ticker:
            continue
        for slot in _wallet_slots(item, repo_root):
            holders.setdefault(slot, ticker)
        xbridge = _xbridge_slot(item, repo_root)
        if xbridge is not None:
            holders.setdefault(xbridge, ticker)
    return holders


def _top_values(txt: str) -> dict[str, str]:
    """Top-level key=value pairs, skipping [test] sections."""
    found: dict[str, str] = {}
    for _lineno, line, in_test in iter_conf_lines(txt):
        if in_test or "=" not in line:
            continue
        key, val = line.split("=", 1)
        clean = norm_port_value(val) if key.strip().lower() in ("port", "rpcport") else val.strip()
        found.setdefault(key.strip().lower(), clean)
    return found


def _scaffold_conflicts(  # noqa: C901, PLR0912  # conflict derivation: one branch per conflict kind
    entries: list[dict[str, Any]], repo_root: Path
) -> dict[str, str]:
    """Staged coins whose ports are taken, by coin."""
    staged: dict[str, dict[str, str]] = {}
    for e in entries:
        if e.get("action") != "scaffold" or not isinstance(e.get("contents"), str):
            continue
        rel = str(e.get("file") or "")
        coin = e.get("coin")
        if not coin:
            continue
        vals = _top_values(e["contents"])
        if rel.startswith("wallet-confs/"):
            staged.setdefault(str(coin), {}).update({k: vals[k] for k in ("port", "rpcport") if vals.get(k)})
        elif rel.startswith("xbridge-confs/") and vals.get("port"):
            staged.setdefault(str(coin), {})["xbridge"] = vals["port"]
    conflicts: dict[str, str] = {}
    holders = _fleet_port_holders(repo_root)
    kinds = {"port": "p2p", "rpcport": "rpc", "xbridge": "xbridge"}
    seen: dict[tuple, str] = {}
    for coin, claims in staged.items():
        if claims.get("port") and claims.get("port") == claims.get("rpcport"):
            conflicts.setdefault(coin, f"staged port={claims['port']} equals rpcport — degenerate pair")
    for coin, claims in staged.items():
        for key, value in claims.items():
            cell = (kinds[key], value)
            other = seen.get(cell)
            if other is not None and other != coin:
                conflicts.setdefault(coin, f"staged {key}={value} collides with staged {other}")
                conflicts.setdefault(other, f"staged {key}={value} collides with staged {coin}")
            seen.setdefault(cell, coin)
            if holders is None:
                conflicts.setdefault(coin, "manifest unreadable — port safety unverifiable")
            else:
                holder = holders.get(cell)
                if holder is not None and holder != coin:
                    conflicts.setdefault(coin, f"staged {key}={value} collides with {holder}")
    return conflicts


def _atomic_write(path: Path, text: str) -> None:
    """Same-directory temp file + os.replace, so an interrupted run
    leaves the previous bytes intact instead of a truncated conf.

    When replacing an existing file the target's mode is carried over
    (confs may hold rpc credentials an operator tightened).
    """
    tmp = path.with_name(f"{path.name}.tmp")
    tmp.write_text(text, encoding="utf-8")
    if path.exists():
        os.chmod(tmp, path.stat().st_mode & 0o7777)  # noqa: PTH101  # atomic-write contract, see test_writes_reach_disk_through_temp_and_replace
    try:
        os.replace(tmp, path)  # noqa: PTH105  # atomic-write contract, see test_writes_reach_disk_through_temp_and_replace
    except OSError:
        tmp.unlink(missing_ok=True)
        raise


def _refuse(entry: dict[str, Any], reason: str) -> dict[str, Any]:
    entry["applied"] = False
    entry["error"] = reason
    return entry


def _safe_rel(repo_root: Path, rel: str) -> Path | None:
    """A repo-relative path that cannot escape the repo, else None.

    Checks both spellings of escape: ``..``/absolute in the entry, and
    a symlinked directory that resolves outside the repo root.
    """
    if not rel or rel.startswith("/") or ".." in Path(rel).parts:
        return None
    path = repo_root / rel
    try:
        if not path.resolve().is_relative_to(repo_root.resolve()):
            return None
    except OSError:
        return None
    return path


def _apply_conf(  # noqa: C901, PLR0911, PLR0912  # conf-write applier: one return per write kind
    entry: dict[str, Any],
    repo_root: Path,
) -> dict[str, Any]:
    rel = str(entry.get("file") or "")
    key = str(entry.get("key") or "")
    if not key:
        return _refuse(entry, "refused: entry carries no key")
    resolved = _safe_rel(repo_root, rel)
    if resolved is None:
        return _refuse(entry, f"refused: path escapes the repo: {rel!r}")
    parts = Path(rel).parts
    # plan-entry path shape: conf entries are dir/file, templates autobuild/configs/file
    if not (len(parts) == 2 and parts[0] in ("wallet-confs", "xbridge-confs")):  # noqa: PLR2004
        return _refuse(entry, f"refused: conf edits stay in wallet/xbridge-confs: {rel!r}")
    path = resolved
    txt = SourceReader.slurp(path)
    if txt is None:
        return _refuse(entry, f"refused: file gone since planning: {rel}")
    section_aware = path.parent.name == "wallet-confs" and key.lower() in ("port", "rpcport")
    old = entry.get("old")
    new = entry.get("new")
    if key.lower() == "deprecatedrpc":
        if new is not None:
            return _refuse(entry, "refused: removal entry carries a new value")
        want = sorted(s for s in str(old or "").split(", ") if s)
        have = sorted(ln.strip() for ln in txt.splitlines() if _key_match(ln, key))
        if have != want:
            return _refuse(entry, f"refused: {rel} changed since planning")
        new_txt, _ = _remove_key(txt, key)
        _atomic_write(path, new_txt)
        logger.info("FIX %s: removed stale deprecatedrpc from %s", entry.get("coin"), path)
        entry["applied"] = True
        return entry
    if new is None:
        return _refuse(entry, "refused: set entry carries no new value")
    if old is None:
        if key_present(txt, key, section_aware=section_aware):
            return _refuse(entry, f"refused: {rel} already sets {key}")
    elif _current_value(txt, key, section_aware=section_aware) != str(old):
        return _refuse(entry, f"refused: {rel} {key} changed since planning")
    port_kind = None
    if path.parent.name == "wallet-confs" and key.lower() in ("port", "rpcport"):
        port_kind = {"port": "p2p", "rpcport": "rpc"}[key.lower()]
    elif path.parent.name == "xbridge-confs" and key.lower() == "port":
        port_kind = "xbridge"
    if port_kind is not None:
        holders = _fleet_port_holders(repo_root)
        if holders is None:
            return _refuse(entry, "refused: manifest unreadable — port safety unverifiable")
        holder = holders.get((port_kind, norm_port_value(str(new))))
        if holder is not None and holder != entry.get("coin"):
            return _refuse(entry, f"refused: {key}={new} collides with {holder}")
    _atomic_write(path, _set_or_append(txt, key, str(new), section_aware=section_aware))
    logger.info("FIX %s: set %s=%s in %s", entry.get("coin"), key, new, path)
    entry["applied"] = True
    return entry


def _split_versions(text: Any) -> list[str]:
    if not isinstance(text, str) or not text.strip():
        return []
    return [v for v in text.split(", ") if v]


@dataclass(frozen=True)
class ManifestStore:
    """manifest-latest.json as a validated list, with one atomic write path."""

    path: Path
    items: list[Any]

    @staticmethod
    def read(path: Path) -> ManifestStore | str:
        """The store, or the refusal text when the manifest cannot be trusted."""
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return "refused: manifest unreadable"
        if not isinstance(raw, list):
            return "refused: manifest is not an array"
        return ManifestStore(path, raw)

    def item(self, ticker: Any) -> dict[str, Any] | None:
        """The manifest entry for one ticker, None when absent."""
        return next((e for e in self.items if isinstance(e, dict) and e.get("ticker") == ticker), None)

    def tickers(self) -> set[Any]:
        """Every ticker in the manifest."""
        return {e.get("ticker") for e in self.items if isinstance(e, dict)}

    def write(self, items: list[Any]) -> None:
        _atomic_write(self.path, json.dumps(items, indent=2) + "\n")


def _apply_versions_append(  # conf-write applier: one return per write kind
    entry: dict[str, Any],
    repo_root: Path,
) -> dict[str, Any]:
    rel = str(entry.get("file") or "")
    manifest_path = _safe_rel(repo_root, rel)
    if manifest_path is None or manifest_path.name != "manifest-latest.json":
        return _refuse(entry, f"refused: version append outside the manifest: {rel!r}")
    if isinstance(loaded := ManifestStore.read(manifest_path), str):
        return _refuse(entry, loaded)
    ticker = entry.get("coin")
    item = loaded.item(ticker)
    if item is None:
        return _refuse(entry, f"refused: {ticker} left the manifest since planning")
    if list(item.get("versions") or []) != _split_versions(entry.get("old")):
        return _refuse(entry, f"refused: {ticker} versions changed since planning")
    target_versions = _split_versions(entry.get("new"))
    if not target_versions:
        return _refuse(entry, "refused: append entry carries no new versions")
    item["versions"] = target_versions
    loaded.write(loaded.items)
    entry["applied"] = True
    return entry


def _apply_versions_collapse(  # conf-write applier: one return per write kind
    entry: dict[str, Any],
    repo_root: Path,
) -> dict[str, Any]:
    rel = str(entry.get("file") or "")
    manifest_path = _safe_rel(repo_root, rel)
    if manifest_path is None or manifest_path.name != "manifest-latest.json":
        return _refuse(entry, f"refused: version collapse outside the manifest: {rel!r}")
    target = entry.get("target")
    old_ver_id = entry.get("old_ver_id")
    old_wc = entry.get("old_wallet_conf")
    old_xc = entry.get("old_xbridge_conf")
    if not target or not old_ver_id:
        return _refuse(entry, "refused: collapse entry lacks machine fields")
    if isinstance(loaded := ManifestStore.read(manifest_path), str):
        return _refuse(entry, loaded)
    ticker = entry.get("coin")
    item = loaded.item(ticker)
    if item is None:
        return _refuse(entry, f"refused: {ticker} left the manifest since planning")
    if item.get("ver_id") != old_ver_id or item.get("wallet_conf") != old_wc or item.get("xbridge_conf") != old_xc:
        return _refuse(entry, f"refused: {ticker} conf names changed since planning")
    new_ver_id, new_wc, new_xc = build_update_version_names(
        str(ticker), str(old_ver_id), str(old_wc or ""), str(old_xc or ""), str(target)
    )
    item["ver_id"] = new_ver_id
    item["versions"] = [target]
    item["wallet_conf"] = new_wc
    item["xbridge_conf"] = new_xc
    loaded.write(loaded.items)
    entry["applied"] = True
    return entry


def _apply_versions_copy(entry: dict[str, Any], repo_root: Path) -> dict[str, Any]:
    new = str(entry.get("new") or "")
    if not new.startswith("copy of "):
        return _refuse(entry, "refused: copy entry names no source")
    src_name = new[len("copy of ") :]
    rel = str(entry.get("file") or "")
    dst = _safe_rel(repo_root, rel)
    if dst is None:
        return _refuse(entry, f"refused: copy path escapes the repo: {rel!r}")
    if not src_name or "/" in src_name or src_name in (".", ".."):
        return _refuse(entry, "refused: copy source escapes its directory")
    src = dst.parent / src_name
    if not src.is_file():
        return _refuse(entry, f"refused: source gone since planning: {src_name}")
    if dst.is_file():
        return _refuse(entry, f"refused: target already exists: {dst.name}")
    dst.parent.mkdir(parents=True, exist_ok=True)
    tmp = dst.with_name(f"{dst.name}.tmp")
    shutil.copy2(src, tmp)
    os.replace(tmp, dst)  # noqa: PTH105  # atomic-write contract, see test_writes_reach_disk_through_temp_and_replace
    report_line(f"  UPDATE-VERSIONS {entry.get('coin')}: {dst.parent.name} conf {src.name} -> {dst.name} (copied)")
    entry["applied"] = True
    return entry


def _apply_scaffold_file(entry: dict[str, Any], repo_root: Path) -> dict[str, Any]:
    rel = str(entry.get("file") or "")
    dst = _safe_rel(repo_root, rel)
    if dst is None:
        return _refuse(entry, f"refused: path escapes the repo: {rel!r}")
    contents = entry.get("contents")
    if not isinstance(contents, str):
        return _refuse(entry, "refused: staged entry carries no contents")
    if dst.is_file():
        return _refuse(entry, f"refused: target already exists: {dst.name}")
    dst.parent.mkdir(parents=True, exist_ok=True)
    _atomic_write(dst, contents)
    entry["applied"] = True
    return entry


def _apply_scaffold_manifest(entry: dict[str, Any], repo_root: Path) -> dict[str, Any]:
    manifest_path = repo_root / "manifest-latest.json"
    snippet = entry.get("snippet")
    if not isinstance(snippet, dict):
        return _refuse(entry, "refused: staged entry carries no manifest snippet")
    ticker = snippet.get("ticker") or entry.get("coin")
    if isinstance(loaded := ManifestStore.read(manifest_path), str):
        return _refuse(entry, loaded)
    if any(isinstance(e, dict) and e.get("ticker") == ticker for e in loaded.items):
        return _refuse(entry, f"refused: {ticker} already in the manifest")
    loaded.items.append(snippet)
    loaded.items.sort(key=lambda x: x.get("ticker", "") if isinstance(x, dict) else "")
    loaded.write(loaded.items)
    entry["applied"] = True
    return entry


def _apply_delist_manifest(entry: dict[str, Any], repo_root: Path) -> dict[str, Any]:
    manifest_path = repo_root / "manifest-latest.json"
    ticker = entry.get("coin")
    if isinstance(loaded := ManifestStore.read(manifest_path), str):
        return _refuse(entry, loaded)
    kept = [e for e in loaded.items if not (isinstance(e, dict) and e.get("ticker") == ticker)]
    if len(kept) == len(loaded.items):
        return _refuse(entry, f"refused: {ticker} already gone from the manifest")
    gone = next(e for e in loaded.items if isinstance(e, dict) and e.get("ticker") == ticker)
    if entry.get("old") is not None and gone.get("ver_id") != entry.get("old"):
        return _refuse(entry, f"refused: {ticker} changed since planning")
    loaded.write(kept)
    entry["applied"] = True
    return entry


def _apply_delist_file(entry: dict[str, Any], repo_root: Path) -> dict[str, Any]:
    rel = str(entry.get("file") or "")
    path = _safe_rel(repo_root, rel)
    if path is None:
        return _refuse(entry, f"refused: path escapes the repo: {rel!r}")
    parts = Path(rel).parts
    # plan-entry path shape: conf entries are dir/file, templates autobuild/configs/file
    conf_dir = len(parts) == 2 and parts[0] in ("wallet-confs", "xbridge-confs")  # noqa: PLR2004
    # plan-entry path shape: conf entries are dir/file, templates autobuild/configs/file
    base_j2 = (
        len(parts) == 3  # noqa: PLR2004
        and parts[0] == "autobuild"
        and parts[1] == "configs"
        and parts[2].endswith(".base.j2")
    )
    if not (conf_dir or base_j2):
        return _refuse(entry, f"refused: delist stays in conf dirs: {rel!r}")
    if not path.is_file():
        return _refuse(entry, f"refused: already gone: {rel}")
    path.unlink()
    entry["applied"] = True
    return entry


def apply_entry(  # noqa: C901, PLR0911  # plan dispatcher: one return per entry kind
    entry: dict[str, Any],
    repo_root: Path,
) -> dict[str, Any]:
    """Apply one reviewed entry; refusals mark only their own entry."""
    if not isinstance(entry, dict):
        return entry
    try:
        action = entry.get("action")
        key = entry.get("key")
        if action == "delist":
            if entry.get("file") == "manifest-latest.json":
                return _apply_delist_manifest(entry, repo_root)
            return _apply_delist_file(entry, repo_root)
        if action == "scaffold":
            if entry.get("file") == "manifest-latest.json":
                return _apply_scaffold_manifest(entry, repo_root)
            return _apply_scaffold_file(entry, repo_root)
        if action == "versions" and key == "*":
            return _apply_versions_copy(entry, repo_root)
        if action == "versions" and isinstance(key, str) and key.endswith(".versions"):
            return _apply_versions_append(entry, repo_root)
        if action == "versions":
            return _apply_versions_collapse(entry, repo_root)
        if action in ("txindex", "dust", "deprecatedrpc", "fees", "port"):
            return _apply_conf(entry, repo_root)
        return _refuse(entry, f"refused: unknown action {action!r}")
    except Exception as exc:
        return _refuse(entry, f"refused: write failed: {exc}")


def _scaffold_preblocks(  # noqa: C901  # preblock derivation: one branch per entry kind
    entries: list[dict[str, Any]], repo_root: Path
) -> dict[str, str]:
    """Coins whose staged triple cannot land as a unit, by coin.

    Extends the port-conflict pre-pass with existence, duplicate-ticker
    and manifest-readability gates, so a scaffold batch refuses all
    three entries upfront instead of writing two confs and then
    refusing the manifest (or vice versa).
    """
    blocked = dict(_scaffold_conflicts(entries, repo_root))
    staged_coins = {str(e.get("coin")) for e in entries if e.get("action") == "scaffold" and e.get("coin")}
    if not staged_coins:
        return blocked
    if isinstance(loaded := ManifestStore.read(repo_root / "manifest-latest.json"), str):
        for coin in staged_coins:
            blocked.setdefault(
                coin,
                "manifest unreadable — port safety unverifiable"
                if loaded == "refused: manifest unreadable"
                else loaded,
            )
        return blocked
    tickers = loaded.tickers()
    for e in entries:
        if e.get("action") != "scaffold" or not e.get("coin") or e.get("coin") in blocked:
            continue
        coin = str(e.get("coin"))
        rel = str(e.get("file") or "")
        if rel == "manifest-latest.json":
            if coin in tickers:
                blocked.setdefault(coin, f"{coin} already in the manifest")
            if not isinstance(e.get("snippet"), dict):
                blocked.setdefault(coin, "staged entry carries no manifest snippet")
        elif e.get("file", "").startswith(("wallet-confs/", "xbridge-confs/")):
            if not isinstance(e.get("contents"), str):
                blocked.setdefault(coin, "staged entry carries no contents")
            else:
                dst = _safe_rel(repo_root, rel)
                if dst is not None and dst.exists():
                    blocked.setdefault(coin, f"target already exists: {dst.name}")
    return blocked


def _rollback_partial_scaffolds(out: list[dict[str, Any]], repo_root: Path) -> None:
    """Restore the no-partial-coin invariant for scaffold batches.

    Scaffold entries are new files only (the applier refuses existing
    targets), so unlinking an applied conf for a refused coin is safe.
    A manifest row for a refused coin is reverted the same way, by
    removing the staged ticker — never touching other entries.
    """
    by_coin: dict[Any, list[dict[str, Any]]] = {}
    for e in out:
        if e.get("action") == "scaffold" and e.get("coin"):
            by_coin.setdefault(e.get("coin"), []).append(e)
    for coin, rows in by_coin.items():
        if all(r.get("applied") for r in rows) or not any(r.get("applied") for r in rows):
            continue
        for r in rows:
            if not r.get("applied"):
                continue
            if r.get("file") != "manifest-latest.json":
                path = _safe_rel(repo_root, str(r.get("file") or ""))
                try:
                    if path is not None and path.is_file():
                        path.unlink()
                except OSError as exc:
                    logger.warning("rollback %s failed: %s", path, exc)
            else:
                _remove_staged_ticker(repo_root, coin)
            r["applied"] = False
            r["error"] = f"refused: rolled back partial scaffold for {coin}"


def _remove_staged_ticker(repo_root: Path, coin: Any) -> None:
    """Remove one staged ticker from the manifest, if present."""
    loaded = ManifestStore.read(repo_root / "manifest-latest.json")
    if isinstance(loaded, str):
        return
    kept = [e for e in loaded.items if not (isinstance(e, dict) and e.get("ticker") == coin)]
    if len(kept) != len(loaded.items):
        loaded.write(kept)


J2_REGEN_ACTIONS = ("txindex", "dust", "deprecatedrpc", "fees", "port", "versions")


def regenerate_for(
    entries: list[Any],
    repo_root: Path,
    runner: SystemCommandRunner | None,
) -> None:
    """One base.j2 regeneration for a whole batch; no-op without applied work.

    Every applied action that changes a conf a template reads counts, so
    callers that apply several plans in sequence hand the combined list
    here once instead of paying a generator round per plan.
    """
    touched = sorted(
        {
            str(e.get("coin"))
            for e in entries
            if isinstance(e, dict) and e.get("applied") and e.get("action") in J2_REGEN_ACTIONS and e.get("coin")
        }
    )
    if not touched or runner is None:
        return
    try:
        regenerate_base_j2(repo_root, touched, runner)
    except Exception as exc:
        logger.warning("regenerate base.j2 failed: %s", exc)


def apply_entries(
    entries: list[dict[str, Any]],
    repo_root: Path,
    runner: SystemCommandRunner | None = None,
    *,
    regenerate: bool = True,
) -> list[dict[str, Any]]:
    """Apply reviewed entries in order; regenerate base.j2 once after.

    ``regenerate=False`` defers the generator round to a batch caller
    that applies several plans and regenerates once at the end.
    """
    blocked = _scaffold_preblocks(entries, repo_root)
    out = []
    for e in entries:
        coin = e.get("coin")
        if e.get("action") == "scaffold" and coin in blocked:
            out.append(_refuse(e, f"refused: {blocked[str(coin)]}"))
        else:
            out.append(apply_entry(e, repo_root))
    _rollback_partial_scaffolds(out, repo_root)
    if regenerate:
        regenerate_for(out, repo_root, runner)
    return out


def apply_plan_file(  # noqa: C901, PLR0912  # apply orchestrator: one branch per plan-entry action kind
    plan_path: Path,
    repo_root: Path,
    runner: SystemCommandRunner,
    *,
    dry_run: bool = False,
) -> tuple:
    """Apply a plan file's entries and rewrite it with applied flags.

    Under ``dry_run`` the entries are reported as they would apply and
    nothing on disk changes — no conf writes, no plan rewrite.
    """
    try:
        payload = json.loads(plan_path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return 2, []
    if isinstance(payload, dict):
        raw = payload.get("plan")
    elif isinstance(payload, list):
        raw = payload
    else:
        raw = None
    if not isinstance(raw, list):
        return 2, []
    dropped = sum(1 for e in raw if not isinstance(e, dict))
    entries = [e for e in raw if isinstance(e, dict)]
    if dry_run:
        for e in entries:
            e["applied"] = False
        report_line(f"APPLY-PLAN dry-run: {len(entries)} entries, nothing written ({plan_path.name})")
        for e in entries:
            report_line(f"  would apply {e.get('coin')}: {e.get('file')} {e.get('key')}")
        if dropped:
            report_line(f"  dropped {dropped} unreadable row(s)")
        return 0, entries
    out = apply_entries(entries, repo_root, runner)
    if isinstance(payload, dict):
        payload = {**payload, "plan": out}
    else:
        payload = {"schema_version": 1, "plan": out, "findings": []}
    _atomic_write(plan_path, json.dumps(payload, indent=2) + "\n")
    applied = sum(1 for e in out if e.get("applied"))
    refused = len(out) - applied + dropped
    report_line(f"APPLY-PLAN: applied {applied}, refused {refused} ({plan_path.name})")
    if dropped:
        report_line(f"  dropped {dropped} unreadable row(s)")
    for e in out:
        if not e.get("applied"):
            report_line(f"  refused {e.get('coin')}: {e.get('file')} {e.get('key')} — {e.get('error')}")
    return (0 if not refused else 1), out
