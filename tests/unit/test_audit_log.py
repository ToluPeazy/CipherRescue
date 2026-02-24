"""
Unit tests — Layer 3: AuditLog tamper-evidence (Theorem 3.3).
"""

from __future__ import annotations

import json

import pytest

from cipherrescue.safety.audit_log import AuditLog, Authority


@pytest.fixture
def log() -> AuditLog:
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
