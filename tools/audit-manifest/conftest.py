"""Make the tool directory importable for its own test suite.

Tests import the tool as ``import audit_manifest as audit``; pytest only
prepends the ``tests/`` directory (no ``__init__.py`` anywhere), so the
package's parent directory must be added explicitly. Loading this conftest
is what puts it there — every test below it runs with the tool importable.
"""

import sys
from pathlib import Path

TOOL_DIR = Path(__file__).resolve().parent

if str(TOOL_DIR) not in sys.path:
    sys.path.insert(0, str(TOOL_DIR))
