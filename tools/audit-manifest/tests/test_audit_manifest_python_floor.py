#!/usr/bin/env python3
"""
The tool must actually run on the interpreter floor it documents.

README.md claims "stdlib-only (Python >= 3.9)". Two constructs break that
promise and neither is visible to a 3.12 interpreter's own parser:

* an f-string that reuses its quote delimiter inside a replacement field
  (PEP 701, Python 3.12+) is a SyntaxError on 3.9-3.11;
* a stacked ``@staticmethod`` raises ``TypeError: 'staticmethod' object is
  not callable`` when called on 3.9.

Both are checked in ways that work whichever interpreter runs the suite:
the source is compiled by the current one, and the f-string structure is
read back out of the token stream, which a 3.12+ tokenizer still exposes
even though it accepts the construct.
"""
import importlib.util
import inspect
import io
import sys
import tokenize
from pathlib import Path

import pytest

AUDIT_PATH = Path(__file__).resolve().parents[1] / "audit-manifest.py"
spec = importlib.util.spec_from_file_location("audit_manifest_floor", str(AUDIT_PATH))
audit = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = audit
spec.loader.exec_module(audit)
sys.modules.pop(spec.name, None)


def _quote_of(text: str):
    """The quote delimiter a token opens with, ignoring any prefix letters."""
    for ch in text:
        if ch in "\"'":
            return ch
    return None


def _nested_fstring_delimiters(src: str):
    """``(line, token)`` where an f-string reuses its own delimiter inside.

    A token that opens with the enclosing f-string's quote is only legal once
    PEP 701 landed in 3.12, so on the 3.9-3.11 this file claims to support it
    is a hard SyntaxError.
    """
    offenders = []
    open_delimiters = []
    for tok in tokenize.generate_tokens(io.StringIO(src).readline):
        name = tokenize.tok_name[tok.type]
        if name == "FSTRING_START":
            delim = _quote_of(tok.string)
            if delim and open_delimiters and delim == open_delimiters[-1]:
                offenders.append((tok.start[0], tok.string))
            open_delimiters.append(delim)
        elif name == "FSTRING_END":
            if open_delimiters:
                open_delimiters.pop()
        elif open_delimiters and name == "STRING":
            delim = _quote_of(tok.string)
            if delim and delim == open_delimiters[-1]:
                offenders.append((tok.start[0], tok.string))
    return offenders


def test_source_parses_on_the_declared_floor():
    src = AUDIT_PATH.read_text(encoding="utf-8")

    # 1. Whatever interpreter is running the suite must be able to compile it.
    try:
        compile(src, str(AUDIT_PATH), "exec")
    except SyntaxError as exc:
        pytest.fail(f"{AUDIT_PATH.name} does not parse: {exc}")

    # 2. A 3.12+ parser accepts PEP 701, so go looking for the construct that
    #    the older interpreters this file claims to support would reject.
    offenders = _nested_fstring_delimiters(src)
    assert not offenders, (
        "an f-string reuses its own quote delimiter inside a replacement "
        "field, which is a SyntaxError on Python < 3.12: "
        + "; ".join(f"line {line}: {tok!r}" for line, tok in offenders)
    )


def test_conf_key_line_is_not_wrapped_twice_in_staticmethod():
    # inspect.getattr_static reports what was decorated, without triggering
    # the descriptor protocol that hides the problem on modern Python.
    raw = inspect.getattr_static(audit.CommonParamCheckers, "_conf_key_line")
    depth = 0
    while isinstance(raw, staticmethod):
        raw = raw.__func__
        depth += 1
    assert depth <= 1, (
        f"_conf_key_line carries {depth} stacked @staticmethod decorators; "
        "calling it raises TypeError: 'staticmethod' object is not callable "
        "on Python 3.9"
    )
    assert callable(
        getattr(audit.CommonParamCheckers, "_conf_key_line")
    ), "_conf_key_line must stay callable through the class"
