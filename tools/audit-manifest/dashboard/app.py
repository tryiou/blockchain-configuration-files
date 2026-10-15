"""Textual application factory.

This module stays importable on a bare interpreter: the widgets module —
which imports Textual at module scope — is loaded only from inside
``_make_app``, i.e. only once the TUI is actually starting.
"""

from __future__ import annotations


def _make_app():
    """Build the Textual application.

    Textual is imported here rather than at module scope so that every
    agent-facing path in this package runs on a bare interpreter.
    """
    from .widgets import DashboardApp  # noqa: PLC0415  # deliberate: keeps Textual out of the agent path

    # An instance, not the class: run_tui() calls app.run() with no
    # arguments, which is only valid once the app has been constructed.
    return DashboardApp()
