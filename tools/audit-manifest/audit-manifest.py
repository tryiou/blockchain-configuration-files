#!/usr/bin/env python3
"""Operator entry point: the audit CLI and its domain docstring live in audit_manifest.cli."""

import sys

from audit_manifest.cli import main

if __name__ == "__main__":
    sys.exit(main())
