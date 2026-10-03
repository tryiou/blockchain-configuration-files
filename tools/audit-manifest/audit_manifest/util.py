"""Pure helpers: conf parsing, path rendering, and safe expression evaluation.

None of these touch the filesystem or the network. ``eval_cnum`` and
``_safe_arith_float`` parse numeric literals out of C/C++ source with an
explicit node whitelist — never ``eval`` on untrusted text.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .constants import _MANDATORY_HARDFORK_RE, _NEG_RE


def _parse_github_owner_repo(url: str) -> Optional[Tuple[str, str]]:
    """Extract (owner, repo) from github https url, else None."""
    try:
        u = url.strip().rstrip("/")
        if u.endswith(".git"):
            u = u[:-4]
        # expect https://github.com/owner/repo
        m = re.match(r"https?://github\.com/([^/]+)/([^/]+)", u)
        if m:
            return m.group(1), m.group(2)
    except Exception:
        pass
    return None


def _detect_mandatory_hf(text: str) -> Optional[str]:
    """Return quoted evidence line if text contains mandatory hard-fork signal, else None."""
    if not text:
        return None
    # Exclude negation / non-mandatory phrasing (avoid false positive on "non-mandatory: it does not change consensus")
    # Check line by line to avoid cross-line false positives (e.g. DGB 'mandatory algolock' isolated)
    for line in text.splitlines():
        if _NEG_RE.search(line):
            continue
        if _MANDATORY_HARDFORK_RE.search(line):
            # require co-occurrence within line (already enforced by regex) and not alone 'mandatory'
            # Return trimmed line as quote (max 200 chars)
            q = line.strip()
            if len(q) > 200:
                q = q[:200].rstrip() + "…"
            return q
    # Fallback: search 2-line window (e.g. 'mandatory' on line N, 'hard fork' on N+1)
    lines = text.splitlines()
    for i in range(len(lines) - 1):
        win = lines[i] + " " + lines[i + 1]
        if _NEG_RE.search(win):
            continue
        if _MANDATORY_HARDFORK_RE.search(win):
            q = (lines[i].strip() + " " + lines[i + 1].strip()).strip()
            if len(q) > 200:
                q = q[:200].rstrip() + "…"
            return q
    return None


def norm_port_value(raw: Optional[str]) -> str:
    """Strip comments and return clean port string."""
    if raw is None:
        return ""
    s = raw.strip()
    if "#" in s:
        s = s.split("#", 1)[0].strip()
    if "//" in s:
        s = s.split("//", 1)[0].strip()
    return s.strip()


def eval_cnum(expr: str) -> int:
    """Evaluate a restricted C integer literal (hex/decimal with addition)."""
    expr = expr.strip()
    parts = [p.strip() for p in expr.split("+")]
    total = 0
    for p in parts:
        total += int(p, 16) if p.lower().startswith("0x") else int(p)
    return total


def _safe_arith_float(expr: str) -> Optional[float]:
    """Safe arithmetic: try eval_cnum first, then whitelisted ast eval.

    Only allows digits, whitespace, and +-*/(). Hex is handled via eval_cnum fallback.
    """
    expr = expr.strip()
    try:
        return float(eval_cnum(expr))
    except Exception:
        pass
    if not re.fullmatch(r"[\d\s\*\/\+\-\(\)\.]+", expr):
        return None
    try:
        node = ast.parse(expr, mode="eval")
        allowed = (
            ast.Expression,
            ast.BinOp,
            ast.UnaryOp,
            ast.Constant,
            ast.Add,
            ast.Sub,
            ast.Mult,
            ast.Div,
            ast.Pow,
            ast.UAdd,
            ast.USub,
        )
        for n in ast.walk(node):
            if not isinstance(n, allowed):
                return None

        def _eval(n: Any) -> float:
            if isinstance(n, ast.Expression):
                return _eval(n.body)
            if isinstance(n, ast.Constant):
                if isinstance(n.value, (int, float)):
                    return float(n.value)
                raise ValueError("non-numeric constant")
            if isinstance(n, ast.BinOp):
                left = _eval(n.left)
                right = _eval(n.right)
                if isinstance(n.op, ast.Add):
                    return left + right
                if isinstance(n.op, ast.Sub):
                    return left - right
                if isinstance(n.op, ast.Mult):
                    return left * right
                if isinstance(n.op, ast.Div):
                    return left / right
                if isinstance(n.op, ast.Pow):
                    if abs(right) > 1e6:
                        raise ValueError("pow exponent too large")
                    return left**right
                raise ValueError("unsupported binop")
            if isinstance(n, ast.UnaryOp):
                v = _eval(n.operand)
                if isinstance(n.op, ast.UAdd):
                    return +v
                if isinstance(n.op, ast.USub):
                    return -v
                raise ValueError("unsupported unaryop")
            raise ValueError("unsupported node")

        return float(_eval(node))
    except ZeroDivisionError:
        return None
    except Exception:
        return None


def sanitize_tag(tag: str) -> str:
    """Filesystem-safe tag suffix (alphanumeric + ._-)."""
    return re.sub(r"[^A-Za-z0-9._-]", "_", tag)


def conf_val_ci(conf: Dict[str, str], key: str) -> str:
    """Case-insensitive conf value lookup (parse_conf preserves key case)."""
    want = key.lower()
    for k, v in conf.items():
        if k.lower() == want:
            return v
    return ""


def repo_relative(path: Path, repo_root: Optional[Path] = None) -> str:
    """Render a path relative to the repo root, falling back to the raw path."""
    if repo_root is not None:
        try:
            return str(path.relative_to(repo_root))
        except ValueError:
            pass
    return str(path)


def plan_entry(
    file: str,
    key: str,
    old: Any,
    new: Any,
    reason: str,
    action: str,
    coin: Optional[str] = None,
    ver_id: Optional[str] = None,
    evidence: Optional[str] = None,
    applied: bool = False,
) -> Dict[str, Any]:
    """Describe one write that either happened or would happen under --dry-run.

    The fixers return this instead of a bare ``bool`` so the preview and the
    apply cannot describe different things: they run the same code and only
    ``applied`` differs. It is truthy, so callers that used the old return
    value as an "a change was made" flag still work; a no-op returns ``{}``.

    ``file`` is repo-relative so plans are stable across machines.
    """
    return {
        "action": action,
        "file": file,
        "key": key,
        "old": old,
        "new": new,
        "reason": reason,
        "coin": coin,
        "ver_id": ver_id,
        "evidence": evidence,
        "applied": applied,
    }


def entry_changelog_quote(
    changelog_findings: List[Dict[str, Any]], newer_same: List[str], newer_alt: List[str]
) -> str:
    """Join DISTINCT mandatory-HF quotes for the entry's newer tags."""
    tags = set(newer_same) | set(newer_alt)
    seen: List[str] = []
    for c in changelog_findings:
        if c.get("tag") in tags and c.get("quote") and c["quote"] not in seen:
            seen.append(c["quote"])
    return "; ".join(seen)
