#!/usr/bin/env python3
"""
Importing the tool must stay inert.

``audit-manifest.py`` (and the ``audit_manifest`` package behind it) is both
a CLI and an importable module (its own tests import it, and driver scripts
can too). Installing a root logger handler at import time would silently
reconfigure the embedding process: handlers replaced, level forced to INFO,
output redirected to stdout.

The handler belongs to running the tool, so it is installed by ``main()``.
This test pins that split by re-executing the whole package — every module
body runs again — while the root logger is in a state
``basicConfig(force=True)`` would visibly undo.
"""

import importlib
import logging
import sys


def _fresh_import():
    """Re-execute the package, bypassing sys.modules caching.

    Purges ``audit_manifest`` and every submodule, imports it fresh so all
    module bodies run again, then restores the session's canonical copy so
    the other tests keep the module object they already hold.
    """

    def _names():
        return [k for k in sys.modules if k == "audit_manifest" or k.startswith("audit_manifest.")]

    saved = {k: sys.modules.pop(k) for k in _names()}
    try:
        return importlib.import_module("audit_manifest")
    finally:
        for k in _names():
            del sys.modules[k]
        sys.modules.update(saved)


def test_import_does_not_configure_the_root_logger():
    root = logging.getLogger()
    saved_handlers = list(root.handlers)
    saved_level = root.level
    # A state only deliberate configuration could change.
    root.setLevel(logging.CRITICAL + 1)
    try:
        module = _fresh_import()

        assert root.level == logging.CRITICAL + 1, (
            "importing the audit tool changed the root logger level; "
            "log configuration must happen in main(), not at import time"
        )
        assert root.handlers == saved_handlers, "importing the audit tool replaced the root logger handlers"
        assert callable(module._configure_logging), (
            "main() is expected to install the tool's handler via _configure_logging()"
        )
    finally:
        root.handlers[:] = saved_handlers
        root.setLevel(saved_level)
