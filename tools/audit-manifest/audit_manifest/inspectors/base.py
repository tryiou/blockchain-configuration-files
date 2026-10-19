"""C/C++ expression resolution shared by every source inspector."""

from __future__ import annotations

import re
from pathlib import Path

from ..checkout import SourceReader
from ..util import eval_cnum

# One nTime-serialization detector, shared by the engine checkers and the
# scaffolder (F6: this pattern previously lived in five copies, one of which
# had drifted to a non-matching form).
NTIME_SERIALIZED_RE = re.compile(r">>\s*(?:tx\.)?nTime\b")
NTIME_SERIALIZED_OR_RW_RE = re.compile(r">>\s*(?:tx\.)?nTime\b|READWRITE\([^)]*\bnTime\b")


def line_of(text: str, match: re.Match[str]) -> int:
    """1-based line number where ``match`` starts in ``text``.

    Every source-evidence citation cites file:line; this replaces the
    ``text[: match.start()].count("\\n") + 1`` idiom the inspectors each
    spelled out inline.
    """
    return text[: match.start()].count("\n") + 1


# Recursion ceiling for the C++ expression evaluator.
_MAX_CEXPR_DEPTH = 5


class CppExpressionEvaluator:
    """Resolves C++ constants and macro expressions across header dependencies."""

    @classmethod
    def resolve_cexpr(  # noqa: C901, PLR0912  # marker cascade: one branch per known source form
        cls,
        rhs: str,
        header_text: str,
        header_name: str,
        src_root: Path,
        depth: int = 0,
    ) -> tuple[int | None, str | None]:
        rhs = rhs.strip().rstrip(";").strip()
        if depth > _MAX_CEXPR_DEPTH:
            return None, None
        # Constant resolution must ignore commented-out definitions: a stale
        # `// ... CENT = 1000000;` above the active `CENT = 10000;` (Verge
        # src/amount.h) otherwise wins the regex below and inflates every
        # derived fee 100x. Strip block + full-line comments before matching.
        header_text = SourceReader.strip_comments(header_text)
        try:
            return eval_cnum(rhs), header_name
        except ValueError:
            pass

        # handle C++14 digit separators (1'000) and underscores
        m = re.match(r"([A-Za-z_]\w*)\s*(?:(/|\*)\s*([\d'_]+))?$", rhs)
        m_rev = None
        if m is None:
            # reversed form: `100'000'000 * SATOSHI` (BCH Amount class)
            m_rev = re.match(r"([\d'_]+)\s*(/|\*)\s*([A-Za-z_]\w*)$", rhs)
            if m_rev is None:
                return None, None
            num_raw, op, ident = m_rev.group(1), m_rev.group(2), m_rev.group(3)
            num = num_raw.replace("'", "").replace("_", "")
        else:
            ident, op, num = m.group(1), m.group(2), m.group(3)
            if num:
                num = num.replace("'", "").replace("_", "")
        base = None
        # SATOSHI is 1 sat by definition (BCH Amount::satoshi(), btcd SatoshiPerBitcoin base unit)
        if ident == "SATOSHI":
            base = 1
        if base is None:
            dm = re.search(r"\b" + re.escape(ident) + r"\s*=\s*([A-Za-z_0-9]+(?:\s*[/*]\s*\d+)?)", header_text)
            if dm:
                base, _ = cls.resolve_cexpr(dm.group(1), header_text, header_name, src_root, depth + 1)

        if base is None:
            for cand_path in (
                "src/consensus/amount.h",
                "src/amount.h",
                "src/policy/policy.h",
                "src/validation.h",
                "src/main.h",
            ):
                atxt = SourceReader.slurp(src_root / cand_path)
                if atxt is None or atxt == header_text:
                    continue
                atxt = SourceReader.strip_comments(atxt)
                am = re.search(r"\b" + re.escape(ident) + r"\s*=\s*([^;]+);", atxt)
                if am:
                    base, _ = cls.resolve_cexpr(am.group(1), atxt, cand_path, src_root, depth + 1)
                    if base is not None:
                        break

        if base is None:
            return None, None
        if not op:
            return base, f"{header_name}: {rhs} = {base}"
        if m_rev:
            val = int(num) // base if op == "/" else int(num) * base
        else:
            val = base // int(num) if op == "/" else base * int(num)
        return val, f"{header_name}: {rhs} = {val}"
