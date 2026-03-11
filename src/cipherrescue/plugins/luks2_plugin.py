"""
Layer 4 — LUKS2 Plugin (stub).

Wraps cryptsetup for LUKS2 header diagnosis and recovery.

Planned actions (in risk order):
    1. luks2_header_info      — read-only: dump header JSON (risk 1)
    2. luks2_backup_header    — non-destructive: write backup to file (risk 2)
    3. luks2_restore_header   — destructive: restore from backup (risk 3)
    4. luks2_repair_header    — destructive: cryptsetup repair (risk 3)

LUKS2 magic bytes:  0x4C554B53 0xBABE  (b'LUKS\\xba\\xbe')

Status: STUB — pending implementation after cybersecurity review.
"""

from __future__ import annotations

import logging
from typing import Any

from ...safety.write_blocker import BackupToken
from .._base import Action, AuthToken, PluginError, SchemePlugin

logger = logging.getLogger(__name__)


class LUKS2Plugin(SchemePlugin):
    """Scheme plugin for LUKS2 (Linux Unified Key Setup v2)."""

    SCHEME = "luks2"

    def authenticate(
        self, device_path: str, credential: Any, session_id: str
    ) -> AuthToken:
        # TODO: invoke cryptsetup luksOpen --test-passphrase
        raise PluginError("LUKS2Plugin.authenticate: not yet implemented")

    def available_actions(
        self, device_path: str, token: AuthToken
    ) -> list[Action]:
        return [
                Action(
                    "luks2_header_info",
                    "Dump LUKS2 header metadata",
                    risk_level=1,
                    requires_backup=False,
                ),
                Action(
                    "luks2_backup_header",
                    "Write header backup to recovery media",
                    risk_level=2,
                ),
                Action(
                    "luks2_restore_header",
                    "Restore header from backup",
                    risk_level=3,
                ),
                Action(
                    "luks2_repair_header",
                    "Run cryptsetup repair",
                    risk_level=3,
                ),
            ]

    def execute_action(
        self,
        device_path: str,
        token: AuthToken,
        backup_token: BackupToken,
        action: Action,
    ) -> dict[str, Any]:
        if action.requires_backup:
            self._wb.write_gate(device_path, backup_token)
        raise PluginError(
        f"LUKS2Plugin.execute_action({action.name!r}): not yet implemented"
)
