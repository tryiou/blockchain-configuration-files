#!/usr/bin/env python3
"""Dashboard for audit-manifest: a Textual TUI for humans, and a
verb-per-task JSON interface for agents.

Two modes, chosen by how you invoke it:

    dashboard.py                  TUI when stdout is a TTY, otherwise
                                  usage on stderr and exit 2
    dashboard.py <verb> [...]     exactly one JSON object on stdout

Exit codes in verb mode:

    0   the verb finished and there is nothing left to decide
    1   the verb finished and surfaced something that does
        (findings, collisions, planned-but-not-applied writes)
    2   the verb could not complete (bad usage, the audit script failed,
        or its report could not be read)

stdout carries the JSON envelope and nothing else — every human-readable
line goes to stderr — so ``dashboard.py findings | jq`` always works.

Textual is imported only when the TUI actually starts, so every
agent-facing path stays standard-library-only.

Run ``dashboard.py --help`` for the verb list.
"""

import sys

from dashboard.cli import main

if __name__ == "__main__":
    sys.exit(main())
