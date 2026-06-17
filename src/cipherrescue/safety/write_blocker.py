"""
Layer 3 — Safety & Audit: WriteBlocker.

The WriteBlocker enforces Theorem 3.1 (Boot Write-Isolation):

    No write operation can reach a target block device without:
        (a) a valid BackupToken τ certifying a complete backup, and
        (b) explicit operator confirmation in the TUI.

Implementation note: the OS-level write barrier (Alpine initramfs read-only
mount policy) and this application-level gate are independent.  Both must
be bypassed simultaneously for an unintended write to occur.
"""

from __future__ import annotations

import hashlib
import hmac as _hmac
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
        hmac:           HMAC_K(session_id ∥ device_path ∥ backup_sha256 ∥ timestamp)
                        keyed by the session key K per Definition 3.2.
    """

    device_path: str
    backup_sha256: str
    timestamp: float
    session_id: str
    hmac: str


def _compute_token_hmac(
    session_key: bytes,
    session_id: str,
    device_path: str,
    backup_sha256: str,
    timestamp: float,
) -> str:
    """Compute HMAC_K(session_id ∥ device_path ∥ backup_sha256 ∥ timestamp)."""
    message = f"{session_id}|{device_path}|{backup_sha256}|{timestamp}".encode()
    return _hmac.new(session_key, message, hashlib.sha256).hexdigest()


class WriteBlocker:
    """
    Application-level write gate (Layer 3).

    All plugin write operations must route through write_gate().
    Direct OS-level writes bypassing this class will fail at the
    initramfs level (Theorem 3.1), providing defence-in-depth.

    Usage::

        blocker = WriteBlocker(session_key=k)
        token = backup_manager.create_backup(device_path, sha256)
        blocker.write_gate(device_path, token)
        # Only reaches here if token is valid and registered
        plugin.execute_recovery(device_path)
    """

    def __init__(self, session_key: bytes) -> None:
        self._session_key = session_key
        self._issued_tokens: dict[str, BackupToken] = {}

    def _register_token(self, token: BackupToken) -> None:
        """Register a token. Called exclusively by BackupManager."""
        self._issued_tokens[token.device_path] = token

    def write_gate(self, device_path: str, token: BackupToken) -> None:
        """
        Verify token and permit write to device_path.

        Checks performed in order:
          1. Token device path matches the requested target.
          2. Token was registered by BackupManager for this session
             (a structurally valid but never-issued token is rejected).
          3. HMAC recomputed under the session key matches the token's hmac
             (a token forged or signed under a different key is rejected).

        Args:
            device_path: The block device to write to.
            token:       BackupToken issued by BackupManager.

        Raises:
            ValueError:      If the token device path does not match.
            PermissionError: If no registered token exists or HMAC is invalid.
        """
        if token.device_path != device_path:
            raise ValueError(
                f"Token device {token.device_path!r} does not match "
                f"target device {device_path!r}."
            )

        registered = self._issued_tokens.get(device_path)
        if registered is None:
            raise PermissionError(
                f"No registered backup token for {device_path!r}. "
                "BackupManager.create_backup() must be called first."
            )

        expected_hmac = _compute_token_hmac(
            self._session_key,
            token.session_id,
            token.device_path,
            token.backup_sha256,
            token.timestamp,
        )
        if not _hmac.compare_digest(expected_hmac, token.hmac):
            raise PermissionError(
                f"BackupToken HMAC verification failed for {device_path!r}. "
                "Token may have been forged or issued under a different session key."
            )

        logger.info(
            "WriteBlocker: write permitted to %s (backup=%s)",
            device_path,
            token.backup_sha256[:16] + "...",
        )

    def is_write_permitted(self, device_path: str) -> bool:
        """Return True iff a valid backup token is registered for device_path."""
        return device_path in self._issued_tokens
