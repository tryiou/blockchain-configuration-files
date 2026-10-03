"""All console output for the audit tool.

Business logic never calls ``print`` directly — it calls :func:`report_line`,
which writes the exact same bytes to stdout as the tool's historical
``print(...)`` calls did. Keeping one seam here makes stdout a contract that
can be captured and compared byte-for-byte, and keeps logging setup
(:func:`configure_logging`) beside the output path it configures.
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
