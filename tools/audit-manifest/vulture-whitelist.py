# vulture whitelist for the audit-manifest suite.
#
# Vulture cannot see Textual's dispatch: lifecycle methods (compose, on_mount),
# message handlers (on_key, on_resize, tab_activated, *_pressed, *_submitted,
# *_highlighted), @on-decorated handlers and framework-read class attributes
# (BINDINGS, TITLE, SUB_TITLE, ENABLE_COMMAND_PALETTE, cursor_type, max_height)
# are invoked by the framework, never by name from this tree. The attribute
# accesses below mark those names used.
#
# _escalate_task is deliberately write-only: LiveRun.stop() keeps a reference
# so the SIGKILL escalation task cannot be garbage-collected mid-flight.
#
# pytest autouse fixtures in tests/conftest.py are invoked by the framework,
# never by name from this tree, so vulture marks them unused.
#
# Usage: python -m vulture . --exclude vulture-whitelist.py vulture-whitelist.py --min-confidence 60

_ = object()

_._clear_source_reader_cache

_.BINDINGS
_.TITLE
_.SUB_TITLE
_.ENABLE_COMMAND_PALETTE
_.cursor_type
_.max_height
_._escalate_task

_.compose
_.on_mount
_.on_key
_.on_resize
_.tab_activated
_.filter_changed
_.filter_submitted
_.coin_toggled
_.all_pressed
_.none_pressed
_.invert_pressed
_.continue_pressed
_.plan_highlighted
_.finding_highlighted
_.stop_run
_.action_coins
_.any_button
_.btn_preview_plan
_.btn_preview_diff
_.btn_apply
_.get_default_screen
_.no
_.submitted
