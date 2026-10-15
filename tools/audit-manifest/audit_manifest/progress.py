"""``@@PROGRESS@@`` machine events on stderr — the structured channel.

Stdout is the human report (byte-compare contract); stderr is otherwise
never written to, so one prefixed JSON object per line here is a free
machine lane for watchers. The format is a wire contract with
``dashboard.runner.parse_progress``; the two sides stay in step through
tests, never imports across the boundary.

``verb`` comes from ``AUDIT_VERB`` (set by the dashboard on spawn,
``null`` standalone), read per emit so it stays patchable.
"""

from __future__ import annotations

import contextlib
import json
import os
import sys
import time
from typing import Any

PREFIX = "@@PROGRESS@@"


def emit(
    phase: str,
    *,
    index: int | None = None,
    total: int | None = None,
    ticker: str | None = None,
    tag: str | None = None,
) -> None:
    """Write one progress event to stderr as a single line.

    Fixed key set, so consumers never probe for key presence. Best
    effort: progress is advisory telemetry that must never fail the run
    it announces, so a dead stderr is swallowed, not raised.
    """
    event: dict[str, Any] = {
        "phase": phase,
        "index": index,
        "total": total,
        "ticker": ticker,
        "tag": tag,
        "verb": os.environ.get("AUDIT_VERB"),
        "ts": round(time.time(), 3),
    }
    with contextlib.suppress(OSError, ValueError):
        print(f"{PREFIX} {json.dumps(event, separators=(',', ':'))}", file=sys.stderr, flush=True)


def parse(line: str) -> dict[str, Any] | None:
    """Parse one ``@@PROGRESS@@`` line; anything else returns ``None``.

    Total by design: a line from another tool, a truncated stream tail, or
    a non-object payload are all "not a progress event", never an error —
    the consumer's loop must keep running on a mixed stream.
    """
    if not line.startswith(PREFIX):
        return None
    try:
        payload = json.loads(line[len(PREFIX) :].strip())
    except json.JSONDecodeError:
        return None
    return payload if isinstance(payload, dict) else None
