"""
Layer 6 — Orchestration Engine.

Implements the CipherRescue session state machine:

    INIT → ENUMERATE → DETECT → DIAGNOSE → AUTH → SELECT → CONFIRM → EXECUTE → REPORT

State invariants enforced by transition():
    - Adjacency: only permitted edges in VALID_TRANSITIONS may be traversed.
    - AUTH failure returns to DETECT (not ENUMERATE) — device context persists.
    - EXECUTE requires backup_token is not None (Theorem 6.1).
    - Any state may transition to ABORTED.
    - ABORTED is a terminal state — no transitions out.
    - Every permitted and rejected transition is logged to AuditLog.

Reference: spec §6 (Layer 6 — Orchestration Engine), Theorem 6.1
           (Orchestration Safety Property).
"""

from __future__ import annotations

import logging
import os
import uuid
from enum import Enum, auto

from ..safety.audit_log import AuditLog, Authority

logger = logging.getLogger(__name__)


class SessionState(Enum):
    INIT = auto()
    ENUMERATE = auto()
    DETECT = auto()
    DIAGNOSE = auto()
    AUTH = auto()
    SELECT = auto()
    CONFIRM = auto()
    EXECUTE = auto()
    REPORT = auto()
    ABORTED = auto()


# Permitted transition graph per spec §6.
# AUTH → DETECT is the AUTH-failure path (device persists, retry from detection).
VALID_TRANSITIONS: dict[SessionState, set[SessionState]] = {
    SessionState.INIT:      {SessionState.ENUMERATE, SessionState.ABORTED},
    SessionState.ENUMERATE: {SessionState.DETECT, SessionState.ABORTED},
    SessionState.DETECT:    {SessionState.DIAGNOSE, SessionState.ABORTED},
    SessionState.DIAGNOSE:  {SessionState.AUTH, SessionState.ABORTED},
    SessionState.AUTH:      {SessionState.SELECT, SessionState.DETECT, SessionState.ABORTED},
    SessionState.SELECT:    {SessionState.CONFIRM, SessionState.ABORTED},
    SessionState.CONFIRM:   {SessionState.EXECUTE, SessionState.ABORTED},
    SessionState.EXECUTE:   {SessionState.REPORT, SessionState.ABORTED},
    SessionState.REPORT:    {SessionState.ABORTED},
    SessionState.ABORTED:   set(),
}


class CipherRescueError(Exception):
    """Base exception for all CipherRescue errors."""


class InvalidTransitionError(CipherRescueError):
    """Raised when a transition violates the session state machine graph."""


class MissingBackupTokenError(InvalidTransitionError):
    """Raised when EXECUTE is attempted without a registered backup_token."""


class SessionContext:
    """
    Holds all mutable state for a single recovery session.

    Attributes:
        session_id:      Unique session identifier (UUID4).
        session_key:     32-byte random key for HMAC signing (audit log + backup tokens).
        state:           Current state machine state.
        device_path:     Target block device path.
        audit_log:       Append-only tamper-evident log for this session.
        diagnosis:       SCPRSolution from Layer 5 (set after DIAGNOSE).
        auth_token:      AuthToken from the plugin (set after AUTH).
        backup_token:    BackupToken from BackupManager (set after CONFIRM).
        selected_action: Action chosen by operator (set in SELECT).
    """

    def __init__(self, authority: Authority) -> None:
        self.session_id = str(uuid.uuid4())
        self.session_key: bytes = os.urandom(32)
        self.state = SessionState.INIT
        self.device_path: str = ""
        self.audit_log = AuditLog(
            self.session_id, authority, session_key=self.session_key
        )
        self.diagnosis = None
        self.auth_token = None
        self.backup_token = None
        self.selected_action = None

    def transition(self, target: SessionState) -> None:
        """
        Attempt to move the session to target state.

        Raises:
            InvalidTransitionError:   If target is not in the permitted
                                      successor set for the current state.
            MissingBackupTokenError:  If transitioning to EXECUTE without
                                      a registered backup_token (Theorem 6.1).

        Rejected transitions are logged to the audit log before raising.
        """
        permitted = VALID_TRANSITIONS.get(self.state, set())

        if target not in permitted:
            self.audit_log.log_rejected_transition(self.state.name, target.name)
            raise InvalidTransitionError(
                f"Invalid transition {self.state.name} → {target.name}. "
                f"Permitted: {', '.join(s.name for s in permitted) or 'none (terminal state)'}."
            )

        if target == SessionState.EXECUTE and self.backup_token is None:
            self.audit_log.log_rejected_transition(self.state.name, target.name)
            raise MissingBackupTokenError(
                "Cannot transition to EXECUTE: backup_token is None. "
                "BackupManager.create_backup() must complete before execution."
            )

        logger.info(
            "Session %s: %s → %s", self.session_id, self.state.name, target.name
        )
        self.audit_log.log_state_transition(self.state.name, target.name)
        self.state = target


class Orchestrator:
    """
    Layer 6 — Orchestration Engine.

    Drives the session state machine and coordinates all layers.
    Instantiated once per recovery session by the TUI (Layer 7).
    """

    def __init__(self) -> None:
        self.context: SessionContext | None = None

    def start_session(self, authority: Authority) -> SessionContext:
        self.context = SessionContext(authority)
        self.context.transition(SessionState.ENUMERATE)
        return self.context

    def abort(self, reason: str = "") -> None:
        if self.context:
            logger.warning(
                "Session %s aborted: %s", self.context.session_id, reason
            )
            self.context.transition(SessionState.ABORTED)
