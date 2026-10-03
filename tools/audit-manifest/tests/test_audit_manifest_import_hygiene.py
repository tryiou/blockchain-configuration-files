#!/usr/bin/env python3
"""
Importing the tool must stay inert.

``audit-manifest.py`` is both a CLI and an importable module (its own tests
import it, and driver scripts can too). Installing a root logger handler at
import time would silently reconfigure the embedding process: handlers
replaced, level forced to INFO, output redirected to stdout.

The handler belongs to running the tool, so it is installed by ``main()``.
This test pins that split by importing a fresh copy of the module while the
root logger is in a state ``basicConfig(force=True)`` would visibly undo.
"""
import importlib.util
import logging
import sys
from pathlib import Path

AUDIT_PATH = Path(__file__).resolve().parents[1] / "audit-manifest.py"


def _fresh_import():
    """Execute the module body again, bypassing sys.modules caching."""
    spec = importlib.util.spec_from_file_location("audit_manifest_hygiene", str(AUDIT_PATH))
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    try:
        spec.loader.exec_module(module)
    finally:
        sys.modules.pop(spec.name, None)
    return module


def test_import_does_not_configure_the_root_logger():
    root = logging.getLogger()
    saved_handlers = list(root.handlers)
    saved_level = root.level
    # A state only deliberate configuration could change.
    root.setLevel(logging.CRITICAL + 1)
    try:
        module = _fresh_import()

        assert root.level == logging.CRITICAL + 1, (
            "importing audit-manifest.py changed the root logger level; "
            "log configuration must happen in main(), not at import time"
        )
        assert root.handlers == saved_handlers, (
            "importing audit-manifest.py replaced the root logger handlers"
        )
        assert callable(module._configure_logging), (
            "main() is expected to install the tool's handler via "
            "_configure_logging()"
        )
    finally:
        root.handlers[:] = saved_handlers
        root.setLevel(saved_level)
