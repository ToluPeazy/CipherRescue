"""
Unit tests — Layer 6: Orchestration state machine (P0-2).

Verifies that:
  - INIT → EXECUTE directly raises InvalidTransitionError.
  - CONFIRM → EXECUTE with backup_token=None raises MissingBackupTokenError.
  - The legitimate full path (INIT → … → REPORT) traverses end-to-end.
  - Every rejected transition produces an audit log entry.
"""

from __future__ import annotations

import json

import pytest

from cipherrescue.orchestration import (
    InvalidTransitionError,
    MissingBackupTokenError,
    SessionContext,
    SessionState,
)
from cipherrescue.safety.audit_log import Authority
from cipherrescue.safety.backup_manager import BackupManager
from cipherrescue.safety.write_blocker import WriteBlocker


@pytest.fixture
def ctx() -> SessionContext:
    return SessionContext(Authority.DEVICE_OWNER)


class TestInvalidTransitions:
    def test_init_to_execute_raises(self, ctx: SessionContext) -> None:
        with pytest.raises(InvalidTransitionError):
            ctx.transition(SessionState.EXECUTE)

    def test_init_to_report_raises(self, ctx: SessionContext) -> None:
        with pytest.raises(InvalidTransitionError):
            ctx.transition(SessionState.REPORT)

    def test_aborted_is_terminal(self, ctx: SessionContext) -> None:
        ctx.transition(SessionState.ABORTED)
        with pytest.raises(InvalidTransitionError):
            ctx.transition(SessionState.ENUMERATE)

    def test_state_unchanged_after_invalid(self, ctx: SessionContext) -> None:
        original_state = ctx.state
        with pytest.raises(InvalidTransitionError):
            ctx.transition(SessionState.EXECUTE)
        assert ctx.state == original_state

    def test_skip_several_states_raises(self, ctx: SessionContext) -> None:
        ctx.transition(SessionState.ENUMERATE)
        with pytest.raises(InvalidTransitionError):
            ctx.transition(SessionState.EXECUTE)


class TestMissingBackupToken:
    def test_execute_without_backup_token_raises(self, ctx: SessionContext) -> None:
        # Walk to CONFIRM
        for s in [
            SessionState.ENUMERATE,
            SessionState.DETECT,
            SessionState.DIAGNOSE,
            SessionState.AUTH,
            SessionState.SELECT,
            SessionState.CONFIRM,
        ]:
            ctx.transition(s)

        assert ctx.backup_token is None
        with pytest.raises(MissingBackupTokenError):
            ctx.transition(SessionState.EXECUTE)

    def test_missing_backup_token_is_subclass_of_invalid_transition(
        self, ctx: SessionContext
    ) -> None:
        for s in [
            SessionState.ENUMERATE,
            SessionState.DETECT,
            SessionState.DIAGNOSE,
            SessionState.AUTH,
            SessionState.SELECT,
            SessionState.CONFIRM,
        ]:
            ctx.transition(s)
        with pytest.raises(InvalidTransitionError):
            ctx.transition(SessionState.EXECUTE)


class TestFullPath:
    def test_full_legitimate_path(self) -> None:
        ctx = SessionContext(Authority.DEVICE_OWNER)

        blocker = WriteBlocker(session_key=ctx.session_key)
        manager = BackupManager(blocker, ctx.session_key, ctx.session_id)

        ctx.transition(SessionState.ENUMERATE)
        ctx.transition(SessionState.DETECT)
        ctx.transition(SessionState.DIAGNOSE)
        ctx.transition(SessionState.AUTH)
        ctx.transition(SessionState.SELECT)
        ctx.transition(SessionState.CONFIRM)

        # Wire backup_token (as orchestrator would after BackupManager)
        ctx.backup_token = manager.create_backup("/dev/sda", "a" * 64)

        ctx.transition(SessionState.EXECUTE)
        ctx.transition(SessionState.REPORT)

        assert ctx.state == SessionState.REPORT

    def test_auth_failure_returns_to_detect(self) -> None:
        ctx = SessionContext(Authority.DEVICE_OWNER)
        for s in [
            SessionState.ENUMERATE,
            SessionState.DETECT,
            SessionState.DIAGNOSE,
            SessionState.AUTH,
        ]:
            ctx.transition(s)

        # AUTH failure → DETECT (not ENUMERATE)
        ctx.transition(SessionState.DETECT)
        assert ctx.state == SessionState.DETECT


class TestAuditLogOnRejection:
    def test_rejected_transition_logged(self, ctx: SessionContext) -> None:
        with pytest.raises(InvalidTransitionError):
            ctx.transition(SessionState.EXECUTE)

        entries = json.loads(ctx.audit_log.export_json())
        rejected = [e for e in entries if e["event_type"] == "REJECTED_TRANSITION"]
        assert len(rejected) == 1
        assert rejected[0]["payload"]["to"] == "EXECUTE"

    def test_missing_backup_token_logged(self, ctx: SessionContext) -> None:
        for s in [
            SessionState.ENUMERATE,
            SessionState.DETECT,
            SessionState.DIAGNOSE,
            SessionState.AUTH,
            SessionState.SELECT,
            SessionState.CONFIRM,
        ]:
            ctx.transition(s)

        with pytest.raises(MissingBackupTokenError):
            ctx.transition(SessionState.EXECUTE)

        entries = json.loads(ctx.audit_log.export_json())
        rejected = [e for e in entries if e["event_type"] == "REJECTED_TRANSITION"]
        assert len(rejected) >= 1
