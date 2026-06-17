"""
Unit tests — Layer 3: AuditLog tamper-evidence (Theorem 3.3).

Covers both hash-chain integrity (pre-existing) and HMAC keying (P0-3).
"""

from __future__ import annotations

import hashlib
import json

import pytest

from cipherrescue.safety.audit_log import AuditLog, Authority

SESSION_KEY = b"test-key-32-bytes-padded-xxxxxxx"


@pytest.fixture
def log() -> AuditLog:
    # session_key defaults to b"" — existing tests pass without modification.
    return AuditLog("test-session-001", Authority.DEVICE_OWNER)


class TestAuditLog:
    def test_chain_valid_after_open(self, log):
        assert log.verify_chain() is True

    def test_chain_valid_after_transitions(self, log):
        log.log_state_transition("INIT", "ENUMERATE")
        log.log_state_transition("ENUMERATE", "DETECT")
        assert log.verify_chain() is True

    def test_chain_valid_after_diagnosis(self, log):
        log.log_diagnosis("SCPRSolution(...)", uncovered_count=0)
        assert log.verify_chain() is True

    def test_chain_valid_after_write(self, log):
        log.log_write("/dev/sda", "abc123", "luks2_backup_header")
        assert log.verify_chain() is True

    def test_tamper_detected(self, log):
        log.log_state_transition("INIT", "ENUMERATE")
        # Retroactively corrupt the first entry's payload
        log._entries[1].payload["from"] = "TAMPERED"
        assert log.verify_chain() is False

    def test_export_json_valid(self, log):
        log.log_state_transition("INIT", "ENUMERATE")
        data = json.loads(log.export_json())
        assert isinstance(data, list)
        assert len(data) >= 2

    def test_session_open_logged(self, log):
        data = json.loads(log.export_json())
        assert data[0]["event_type"] == "SESSION_OPEN"
        assert data[0]["payload"]["authority"] == "device_owner"

    def test_sequence_numbers_monotone(self, log):
        log.log_state_transition("A", "B")
        log.log_state_transition("B", "C")
        data = json.loads(log.export_json())
        seqs = [e["sequence"] for e in data]
        assert seqs == list(range(len(seqs)))


class TestAuditLogHMAC:
    """P0-3: HMAC keying makes the chain non-regeneratable without session key K."""

    def test_hmac_present_in_entries(self):
        log = AuditLog("s1", Authority.DEVICE_OWNER, session_key=SESSION_KEY)
        data = json.loads(log.export_json())
        for entry in data:
            assert "mac" in entry
            assert len(entry["mac"]) == 64  # SHA-256 hex

    def test_chain_valid_with_keyed_log(self):
        log = AuditLog("s1", Authority.DEVICE_OWNER, session_key=SESSION_KEY)
        log.log_state_transition("INIT", "ENUMERATE")
        assert log.verify_chain() is True

    def test_hmac_catches_hash_replay(self):
        """
        Attacker tampers payload AND recomputes entry_hash to match.
        The MAC check must still catch this (hash chain alone cannot).
        """
        log = AuditLog("s1", Authority.DEVICE_OWNER, session_key=SESSION_KEY)
        log.log_state_transition("INIT", "ENUMERATE")

        entry = log._entries[1]
        # Attacker corrupts payload and recomputes entry_hash to match.
        entry.payload["from"] = "TAMPERED"
        raw = json.dumps(
            {
                "seq": entry.sequence,
                "ts": entry.timestamp,
                "type": entry.event_type,
                "payload": entry.payload,
                "prev": entry.prev_hash,
            },
            sort_keys=True,
        )
        entry.entry_hash = hashlib.sha256(raw.encode()).hexdigest()
        # Hash chain now looks consistent — but MAC fails because entry_hash changed.
        assert log.verify_chain() is False

    def test_wrong_session_key_fails_verify(self):
        """A log verified under a different key must fail (chain not regeneratable)."""
        log = AuditLog("s1", Authority.DEVICE_OWNER, session_key=b"key-A" + b"\x00" * 27)
        log.log_state_transition("INIT", "ENUMERATE")

        # Swap to a different key and re-verify
        log._session_key = b"key-B" + b"\x00" * 27
        assert log.verify_chain() is False

    def test_rejected_transition_logged(self):
        log = AuditLog("s1", Authority.DEVICE_OWNER, session_key=SESSION_KEY)
        log.log_rejected_transition("INIT", "EXECUTE")
        data = json.loads(log.export_json())
        rejected = [e for e in data if e["event_type"] == "REJECTED_TRANSITION"]
        assert len(rejected) == 1
        assert rejected[0]["payload"]["to"] == "EXECUTE"
        assert log.verify_chain() is True

    def test_mac_only_tampering_invalidates_chain(self):
        """
        Changing entry.mac on an otherwise valid chain must fail verify_chain().
        This isolates the MAC check from the hash-chain check.
        """
        log = AuditLog("s1", Authority.DEVICE_OWNER, session_key=SESSION_KEY)
        log.log_state_transition("INIT", "ENUMERATE")
        entry = log._entries[1]
        # Flip the last hex character — entry_hash and chain linkage untouched.
        original_last = entry.mac[-1]
        entry.mac = entry.mac[:-1] + ("0" if original_last != "0" else "1")
        assert log.verify_chain() is False

    def test_default_session_key_backward_compat(self):
        """
        AuditLog(session_key=b'') must still produce MACs and verify correctly
        (guards the backward-compatibility contract for callers that omit the key).
        """
        log = AuditLog("s1", Authority.DEVICE_OWNER)  # session_key defaults to b""
        log.log_state_transition("INIT", "ENUMERATE")
        data = json.loads(log.export_json())
        assert all("mac" in e and len(e["mac"]) == 64 for e in data)
        assert log.verify_chain() is True
