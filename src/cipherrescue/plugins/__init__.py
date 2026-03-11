"""
Layer 4 — Plugin Layer: Base Contract.

Defines the SchemePlugin abstract base class that all scheme-specific
recovery plugins must implement (Definition 4.1 — Plugin Contract).

Plugin Contract Clauses:
    C1  Plugin declares supported scheme via SCHEME class attribute.
    C2  Plugin exposes authenticate(device, credential) -> AuthToken.
    C3  Plugin exposes available_actions(device, token) -> list[Action].
    C4  Plugin routes ALL writes through safety.write_gate(device, token).
    C5  Plugin raises PluginError (never crashes the orchestrator).

Sandboxing (v1.1):
    Community plugins run under:
        - restricted network namespace  (unshare --net)
        - seccomp profile blocking socket/connect/sendto syscalls
        - GPG signature verification before load

Status: STUB — concrete plugin implementations pending.
"""

from __future__ import annotations

import abc
import logging
from dataclasses import dataclass
from typing import Any

from ..safety.write_blocker import BackupToken, WriteBlocker

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class AuthToken:
    """
    Proof that the operator has successfully authenticated to the scheme.

    Issued by SchemePlugin.authenticate().  Required for any action that
    reads key material or modifies the device.  Zeroed immediately after
    use via ctypes.memset (see spec §7.2).
    """

    scheme: str
    device_path: str
    session_id: str


@dataclass
class Action:
    """A recoverable action offered by a plugin for operator selection."""

    name: str
    description: str
    risk_level: int  # 1=read-only  2=non-destructive  3=destructive  4=irreversible
    requires_backup: bool = True


class PluginError(Exception):
    """Raised by plugins for recoverable errors — never propagates uncaught."""


class SchemePlugin(abc.ABC):
    """
    Abstract base class for all CipherRescue scheme plugins.

    Subclasses implement: LUKS2Plugin, BitLockerPlugin,
    VeraCryptPlugin, OpalPlugin.
    """

    #: Must be set by each concrete plugin, e.g. 'luks2'
    SCHEME: str = ""

    def __init__(self, write_blocker: WriteBlocker) -> None:
        self._wb = write_blocker

    @abc.abstractmethod
    def authenticate(
        self, device_path: str, credential: Any, session_id: str
    ) -> AuthToken:
        """
        Attempt authentication with the provided credential.

        The credential type is scheme-specific:
            LUKS2:      passphrase (str) or key file (bytes)
            BitLocker:  recovery key (str) or TPM-sealed key
            VeraCrypt:  passphrase (str) and optional PIM (int)
            Opal:       MSID or SID credential (str)

        Returns:
            AuthToken if authentication succeeds.

        Raises:
            PluginError: If authentication fails.
        """

    @abc.abstractmethod
    def available_actions(self, device_path: str, token: AuthToken) -> list[Action]:
        """
        Return the list of recovery actions available given the auth token.

        The list should be ordered by risk level (lowest first).
        """

    @abc.abstractmethod
    def execute_action(
        self,
        device_path: str,
        token: AuthToken,
        backup_token: BackupToken,
        action: Action,
    ) -> dict[str, Any]:
        """
        Execute the selected recovery action.

        MUST call self._wb.write_gate(device_path, backup_token) before
        any write operation (Contract clause C4).

        Returns:
            A dict of result metadata logged to the AuditLog.

        Raises:
            PluginError: On failure.
        """

    def plugin_info(self) -> dict[str, str]:
        return {
            "scheme": self.SCHEME,
            "plugin_class": type(self).__name__,
        }
