"""
Unit tests — Layer 4: LUKS2 plugin import smoke test (P0-4).

The sole Phase 0 requirement is that the module imports successfully.
Before the fix, from ...safety (3 levels) caused ImportError.
"""

from __future__ import annotations


def test_luks2_plugin_imports() -> None:
    """Import must succeed — previously failed with relative-import depth error."""
    import cipherrescue.plugins.luks2_plugin  # noqa: F401


def test_luks2_plugin_class_accessible() -> None:
    from cipherrescue.plugins.luks2_plugin import LUKS2Plugin

    assert LUKS2Plugin.SCHEME == "luks2"


def test_luks2_plugin_available_actions_stub() -> None:
    """available_actions() is implemented (not a stub) and returns 4 actions."""
    from cipherrescue.plugins.luks2_plugin import LUKS2Plugin
    from cipherrescue.safety.write_blocker import WriteBlocker

    plugin = LUKS2Plugin(WriteBlocker(session_key=b"k" * 32))
    actions = plugin.available_actions("/dev/sda", token=None)  # type: ignore[arg-type]
    assert len(actions) == 4
    risk_levels = [a.risk_level for a in actions]
    assert risk_levels == sorted(risk_levels), "Actions should be in risk order"
