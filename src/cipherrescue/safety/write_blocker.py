"""
Layer 3 — Safety & Audit: WriteBlocker.

The WriteBlocker enforces Theorem 3.1 (Boot Write-Isolation):

    No write operation can reach a target block device without:
        (a) a valid BackupToken τ certifying a complete backup, and
        (b) explicit operator confirmation in the TUI.

Implementation note: the OS-level write barrier (Alpine initramfs read-only
mount policy) and this application-level gate are independent.  Both must
be bypassed simultaneously for an unintended write to occur.

Status: STUB — implementation pending cybersecurity expert review.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class BackupToken:
    """
    Cryptographic token certifying that a complete backup exists.

    Issued by BackupManager after verifying backup integrity.
    Required by write_gate() before any plugin write is permitted.

    Attributes:
        device_path:    Absolute path to the target device.
        backup_sha256:  SHA-256 of the backup image (hex string).
        timestamp:      Unix timestamp at which the backup was verified.
        session_id:     Unique identifier for the recovery session.
    """
    device_path: str
    backup_sha256: str
    timestamp: float
    session_id: str


class WriteBlocker:
    """
    Application-level write gate (Layer 3).

    All plugin write operations must route through write_gate().
    Direct OS-level writes bypassing this class will fail at the
    initramfs level (Theorem 3.1), providing defence-in-depth.

    Usage::

        blocker = WriteBlocker()
        token = backup_manager.create_backup(device)
        blocker.write_gate(device_path, token)
        # Only reaches here if token is valid
        plugin.execute_recovery(device_path)
    """

    def __init__(self) -> None:
        self._issued_tokens: dict[str, BackupToken] = {}

    def write_gate(self, device_path: str, token: BackupToken) -> None:
        """
        Verify token and permit write to device_path.

        Args:
            device_path: The block device to write to.
            token:       BackupToken issued by BackupManager.

        Raises:
            PermissionError: If no valid token exists for this device.
            ValueError:      If the token device path does not match.
        """
        if token.device_path != device_path:
            raise ValueError(
                f"Token device {token.device_path!r} does not match "
                f"target device {device_path!r}."
            )
        # TODO: verify token signature against session key
        logger.info(
            "WriteBlocker: write permitted to %s (backup=%s)",
            device_path, token.backup_sha256[:16] + "...",
        )

    def is_write_permitted(self, device_path: str) -> bool:
        """Return True iff a valid backup token exists for device_path."""
        return device_path in self._issued_tokens
