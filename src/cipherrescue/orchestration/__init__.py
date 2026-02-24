"""
Layer 6 — Orchestration Engine.

Implements the CipherRescue session state machine:

    INIT → ENUMERATE → DETECT → DIAGNOSE → AUTH → SELECT → CONFIRM → EXECUTE → REPORT

State invariants:
    - No write can occur before CONFIRM state (WriteBlocker enforced).
    - Every transition is logged to AuditLog.
    - AUTH failure returns to DETECT, not ENUMERATE (device persists).
    - CONFIRM requires explicit operator acknowledgement in the TUI.

Reference: spec §6 (Layer 6 — Orchestration Engine), Theorem 6.1
           (Orchestration Safety Property).

Status: STUB — state machine implementation pending.
"""

from __future__ import annotations

import logging
import uuid
from enum import Enum, auto

from ..safety.audit_log import AuditLog, Authority

logger = logging.getLogger(__name__)


class SessionState(Enum):
    INIT      = auto()
    ENUMERATE = auto()
    DETECT    = auto()
    DIAGNOSE  = auto()
    AUTH      = auto()
    SELECT    = auto()
    CONFIRM   = auto()
    EXECUTE   = auto()
    REPORT    = auto()
    ABORTED   = auto()


class SessionContext:
    """
    Holds all mutable state for a single recovery session.

    Attributes:
        session_id:     Unique session identifier (UUID4).
        state:          Current state machine state.
        device_path:    Target block device path.
        audit_log:      Append-only tamper-evident log for this session.
        diagnosis:      SCPRSolution from Layer 5 (set after DIAGNOSE).
        auth_token:     AuthToken from the plugin (set after AUTH).
        backup_token:   BackupToken from BackupManager (set after CONFIRM).
        selected_action: Action chosen by operator (set in SELECT).
    """

    def __init__(self, authority: Authority) -> None:
        self.session_id = str(uuid.uuid4())
        self.state = SessionState.INIT
        self.device_path: str = ""
        self.audit_log = AuditLog(self.session_id, authority)
        self.diagnosis = None
        self.auth_token = None
        self.backup_token = None
        self.selected_action = None

    def transition(self, target: SessionState) -> None:
        logger.info("Session %s: %s → %s",
                    self.session_id, self.state.name, target.name)
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
            logger.warning("Session %s aborted: %s",
                           self.context.session_id, reason)
            self.context.transition(SessionState.ABORTED)
