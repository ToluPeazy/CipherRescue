"""
Layer 3 — Safety & Audit: BackupManager.

Manages backup creation and HMAC-signed token issuance for WriteBlocker.

Phase 0: token issuance with caller-supplied backup_sha256.  Registered
         tokens bind the WriteBlocker so never-issued tokens are rejected.

Phase 1: create_backup_from_device() performs a real ddrescue-backed backup
         and computes SHA-256 of the completed image before token mint,
         avoiding the TOCTOU gap (hash computed after write completes).
"""

from __future__ import annotations

import hashlib
import logging
import subprocess
import time
from pathlib import Path

from .write_blocker import BackupToken, WriteBlocker, _compute_token_hmac

logger = logging.getLogger(__name__)


class BackupError(Exception):
    """Raised when backup creation or verification fails."""


class BackupManager:
    """
    Issues HMAC-signed BackupTokens after verifying backup integrity.

    The session_key K signs each token per Definition 3.2:
        HMAC_K(session_id ∥ device_path ∥ backup_sha256 ∥ timestamp)

    Issued tokens are registered with the WriteBlocker so that structurally
    valid but never-issued tokens are rejected by write_gate().
    """

    DDRESCUE_TIMEOUT: int = 3600  # seconds; override in tests

    def __init__(
        self,
        write_blocker: WriteBlocker,
        session_key: bytes,
        session_id: str,
    ) -> None:
        self._wb = write_blocker
        self._session_key = session_key
        self._session_id = session_id

    def create_backup(self, device_path: str, backup_sha256: str) -> BackupToken:
        """
        Mint an HMAC-signed BackupToken and register it with the WriteBlocker.

        Phase 0: backup_sha256 must be supplied by the caller.
        Phase 1: use create_backup_from_device() for real backup execution.

        Args:
            device_path:   Block device path (e.g. '/dev/sda').
            backup_sha256: SHA-256 hex digest of the backup image.

        Returns:
            Registered BackupToken.
        """
        timestamp = time.time()
        mac = _compute_token_hmac(
            self._session_key,
            self._session_id,
            device_path,
            backup_sha256,
            timestamp,
        )
        token = BackupToken(
            device_path=device_path,
            backup_sha256=backup_sha256,
            timestamp=timestamp,
            session_id=self._session_id,
            hmac=mac,
        )
        self._wb._register_token(token)
        logger.info(
            "BackupManager: token issued for %s (sha256=%s...)",
            device_path,
            backup_sha256[:16],
        )
        return token

    def create_backup_from_device(
        self, device_path: str, backup_dest: str
    ) -> BackupToken:
        """
        Phase 1: Perform a real backup via ddrescue and mint a registered token.

        Runs ddrescue to copy device_path → backup_dest, then computes SHA-256
        over the completed backup image.  The hash is computed AFTER ddrescue
        exits (not before) to avoid the TOCTOU gap noted in spec §3.2.

        Args:
            device_path: Block device to back up (e.g. '/dev/sda').
            backup_dest: Destination file path for the backup image.

        Returns:
            Registered BackupToken.

        Raises:
            BackupError: If ddrescue fails or is not installed.
        """
        mapfile = backup_dest + ".map"
        logger.info(
            "BackupManager: starting ddrescue %s → %s", device_path, backup_dest
        )
        try:
            result = subprocess.run(  # noqa: S603
                [
                    "ddrescue",
                    "--force",
                    "--no-split",
                    device_path,
                    backup_dest,
                    mapfile,
                ],
                capture_output=True,
                text=True,
                timeout=self.DDRESCUE_TIMEOUT,
            )
        except FileNotFoundError as exc:
            raise BackupError("ddrescue not found — ensure it is installed") from exc
        except subprocess.TimeoutExpired as exc:
            raise BackupError(
                f"ddrescue timed out after {self.DDRESCUE_TIMEOUT}s"
            ) from exc

        if result.returncode != 0:
            raise BackupError(
                f"ddrescue exited {result.returncode}: {result.stderr.strip()}"
            )

        logger.info("BackupManager: ddrescue complete, hashing backup image")
        backup_sha256 = _sha256_file(backup_dest)
        logger.info("BackupManager: backup SHA-256 = %s", backup_sha256)

        return self.create_backup(device_path, backup_sha256)


def _sha256_file(path: str) -> str:
    """Compute SHA-256 hex digest of a file, reading in 4 MiB chunks."""
    h = hashlib.sha256()
    with Path(path).open("rb") as f:
        for chunk in iter(lambda: f.read(4 * 1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()
