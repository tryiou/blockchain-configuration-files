"""All console output for the audit tool.

Operator-facing console lines go through :func:`report_line` — business
logic must not ``print`` them ad hoc, so stdout stays a contract that can
be captured and compared byte-for-byte. Two seams are deliberately
outside that rule and say so at their call sites: the structured
``@@PROGRESS@@`` event channel (progress.py, machine-parsed by the
dashboard) and the usage/help printer in ``dashboard/cli.py``. Keeping
the output seam and logging setup (:func:`configure_logging`) together
makes the single output path auditable.
"""

from __future__ import annotations

import logging
import sys
from typing import Any


def report_line(*args: Any, **kwargs: Any) -> None:
    """Write one console line. Identical semantics to ``print`` (same args)."""
    print(*args, **kwargs)


def _configure_logging() -> None:
    """Install this tool's log handler on the root logger.

    Called from ``main()``, not at import time: importing the module must not
    reconfigure an embedding process's root logger (tests, a driver script,
    another CLI). Running the tool still gets the exact same handler.
    """
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
        handlers=[logging.StreamHandler(sys.stdout)],
        force=True,
    )
