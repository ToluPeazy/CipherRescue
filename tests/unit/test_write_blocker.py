"""
Unit tests — Layer 3: WriteBlocker + BackupManager (P0-1).

Verifies that:
  - A token constructed directly (bypassing BackupManager) is rejected.
  - A token issued for device A is rejected when presented for device B.
  - A token whose HMAC is recomputed under a different session key is rejected.
  - A legitimately issued token passes write_gate().
"""

from __future__ import annotations

import pytest

from cipherrescue.safety.backup_manager import BackupManager
from cipherrescue.safety.write_blocker import BackupToken, WriteBlocker

SESSION_KEY = b"test-session-key-32-bytes-padded"
SESSION_ID = "test-session-001"
DEVICE_A = "/dev/sda"
DEVICE_B = "/dev/sdb"
SHA256 = "a" * 64


@pytest.fixture
def blocker() -> WriteBlocker:
    return WriteBlocker(session_key=SESSION_KEY)


@pytest.fixture
def manager(blocker: WriteBlocker) -> BackupManager:
    return BackupManager(blocker, session_key=SESSION_KEY, session_id=SESSION_ID)


class TestWriteBlockerForgedToken:
    """A token constructed directly (bypassing BackupManager) must be rejected."""

    def test_forged_token_rejected_no_registration(self, blocker: WriteBlocker) -> None:
        # Token with a valid HMAC but never registered via BackupManager.
        forged = BackupToken.create_signed(
            session_key=SESSION_KEY,
            session_id=SESSION_ID,
            device_path=DEVICE_A,
            backup_sha256=SHA256,
        )
        # Structurally valid HMAC but never registered — must be rejected.
        with pytest.raises(PermissionError, match="No registered backup token"):
            blocker.write_gate(DEVICE_A, forged)

    def test_forged_token_wrong_hmac_also_rejected(self, blocker: WriteBlocker) -> None:
        # Token with a garbage HMAC — never registered, bad signature.
        forged = BackupToken(
            device_path=DEVICE_A,
            backup_sha256=SHA256,
            timestamp=0.0,
            session_id=SESSION_ID,
            hmac="0" * 64,
        )
        with pytest.raises(PermissionError):
            blocker.write_gate(DEVICE_A, forged)


class TestWriteBlockerDeviceMismatch:
    """A token issued for device A is rejected when presented for device B."""

    def test_token_device_a_rejected_for_device_b(
        self, blocker: WriteBlocker, manager: BackupManager
    ) -> None:
        token_a = manager.create_backup(DEVICE_A, SHA256)
        with pytest.raises(ValueError, match="does not match"):
            blocker.write_gate(DEVICE_B, token_a)

    def test_token_device_a_accepted_for_device_a(
        self, blocker: WriteBlocker, manager: BackupManager
    ) -> None:
        token_a = manager.create_backup(DEVICE_A, SHA256)
        # Should not raise
        blocker.write_gate(DEVICE_A, token_a)


class TestWriteBlockerWrongSessionKey:
    """A token HMAC recomputed under a different key must be rejected."""

    def test_wrong_session_key_rejected(self, manager: BackupManager) -> None:
        token = manager.create_backup(DEVICE_A, SHA256)

        other_blocker = WriteBlocker(session_key=b"different-key-32-bytes-paddingg!")
        # Manually register the token in the other blocker to isolate key check
        other_blocker.register_token(token)

        with pytest.raises(PermissionError, match="HMAC verification failed"):
            other_blocker.write_gate(DEVICE_A, token)


class TestWriteBlockerLegitimateFlow:
    """The legitimate flow (BackupManager → write_gate) passes cleanly."""

    def test_legitimate_token_accepted(
        self, blocker: WriteBlocker, manager: BackupManager
    ) -> None:
        token = manager.create_backup(DEVICE_A, SHA256)
        blocker.write_gate(DEVICE_A, token)  # must not raise

    def test_is_write_permitted_false_before_backup(
        self, blocker: WriteBlocker
    ) -> None:
        assert blocker.is_write_permitted(DEVICE_A) is False

    def test_is_write_permitted_true_after_backup(
        self, blocker: WriteBlocker, manager: BackupManager
    ) -> None:
        manager.create_backup(DEVICE_A, SHA256)
        assert blocker.is_write_permitted(DEVICE_A) is True

    def test_is_write_permitted_per_device(
        self, blocker: WriteBlocker, manager: BackupManager
    ) -> None:
        manager.create_backup(DEVICE_A, SHA256)
        assert blocker.is_write_permitted(DEVICE_A) is True
        assert blocker.is_write_permitted(DEVICE_B) is False
