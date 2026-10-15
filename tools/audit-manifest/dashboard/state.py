"""dashboard.json — the persisted TUI scope (selection, filter, tab).

Loaded at start, written on graceful quit. Resolved through
``paths.state_path()`` at call time so a test redirecting
``CACHE_ROOT`` redirects this file too — never an import-time constant.

Content rules: unreadable, corrupt, wrong-shaped, or unknown
``schema_version`` → the defaults; wrong-typed fields fall back one by
one, so one bad field never discards the rest.
"""

from __future__ import annotations

import json
from typing import Any

from . import paths

STATE_VERSION = 1
TABS = ("findings", "plan", "log")


def defaults() -> dict[str, Any]:
    """A fresh scope: full fleet, no filter, the default results tab."""
    return {"schema_version": STATE_VERSION, "selection": None, "filter": "", "tab": "findings"}


def load() -> dict[str, Any]:
    """Read dashboard.json, sanitized; unusable content yields the defaults."""
    try:
        raw = paths.state_path().read_text(encoding="utf-8")
        data = json.loads(raw)
    except (OSError, ValueError):
        return defaults()
    if not isinstance(data, dict) or data.get("schema_version") != STATE_VERSION:
        return defaults()

    scope = defaults()
    selection = data.get("selection")
    if isinstance(selection, list) and all(isinstance(t, str) for t in selection):
        # A hand-edited file can repeat tickers; duplicates would inflate
        # the scope line and the --ticker flag, so keep first-seen order.
        scope["selection"] = list(dict.fromkeys(selection))
    text = data.get("filter")
    if isinstance(text, str):
        scope["filter"] = text
    tab = data.get("tab")
    if tab in TABS:
        scope["tab"] = tab
    return scope


def save(scope: dict[str, Any]) -> None:
    """Persist the scope to dashboard.json.

    Deliberately unguarded: a write that fails here means the next start
    will not remember the user's choice, and swallowing that would make
    the app lie about having saved.
    """
    path = paths.state_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(scope, indent=2) + "\n", encoding="utf-8")
