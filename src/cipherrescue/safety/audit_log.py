"""
Layer 3 — Safety & Audit: AuditLog.

Implements Theorem 3.3 (Log Tamper Evidence):

    The audit log is hash-chained: each entry eₙ includes
    H(eₙ₋₁ ‖ payload), making retrospective alteration detectable.

Each session produces a self-contained, append-only log that records:
    - Authority declaration (device owner / authorised representative /
      law enforcement / corporate IT)
    - Every state machine transition
    - All write operations and their BackupTokens
    - The full SCPRSolution (optimal reasons + dual weights)
    - Any uncovered signals flagged for operator review

Status: STUB — hash chaining and DFXML export pending implementation.
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class Authority(StrEnum):
    DEVICE_OWNER = "device_owner"
    AUTHORISED_REPRESENTATIVE = "authorised_representative"
    LAW_ENFORCEMENT = "law_enforcement"
    CORPORATE_IT = "corporate_it"


@dataclass
class LogEntry:
    sequence: int
    timestamp: float
    event_type: str
    payload: dict[str, Any]
    prev_hash: str
    entry_hash: str = field(init=False)

    def __post_init__(self) -> None:
        raw = json.dumps({
            "seq": self.sequence,
            "ts": self.timestamp,
            "type": self.event_type,
            "payload": self.payload,
            "prev": self.prev_hash,
        }, sort_keys=True)
        self.entry_hash = hashlib.sha256(raw.encode()).hexdigest()


class AuditLog:
    """
    Tamper-evident, append-only audit log for a recovery session.

    The chain can be verified at any time with verify_chain().
    Any modification to a historical entry breaks all subsequent hashes.
    """

    GENESIS_HASH = "0" * 64

    def __init__(self, session_id: str, authority: Authority) -> None:
        self.session_id = session_id
        self.authority = authority
        self._entries: list[LogEntry] = []
        self._append("SESSION_OPEN", {
            "session_id": session_id,
            "authority": authority.value,
        })

    def _append(self, event_type: str, payload: dict[str, Any]) -> LogEntry:
        prev = self._entries[-1].entry_hash if self._entries else self.GENESIS_HASH
        entry = LogEntry(
            sequence=len(self._entries),
            timestamp=time.time(),
            event_type=event_type,
            payload=payload,
            prev_hash=prev,
        )
        self._entries.append(entry)
        return entry

    def log_state_transition(self, from_state: str, to_state: str) -> None:
        self._append("STATE_TRANSITION", {"from": from_state, "to": to_state})

    def log_diagnosis(self, solution_repr: str, uncovered_count: int) -> None:
        self._append("SCPR_DIAGNOSIS", {
            "solution": solution_repr,
            "uncovered_signals": uncovered_count,
        })

    def log_write(self, device: str, backup_sha256: str, action: str) -> None:
        self._append("WRITE_OPERATION", {
            "device": device,
            "backup_sha256": backup_sha256,
            "action": action,
        })

    def verify_chain(self) -> bool:
        """Return True iff the entire chain is unmodified."""
        for i, entry in enumerate(self._entries):
            prev = self._entries[i - 1].entry_hash if i > 0 else self.GENESIS_HASH
            if entry.prev_hash != prev:
                return False
            # Recompute hash and compare
            raw = json.dumps({
                "seq": entry.sequence,
                "ts": entry.timestamp,
                "type": entry.event_type,
                "payload": entry.payload,
                "prev": entry.prev_hash,
            }, sort_keys=True)
            if hashlib.sha256(raw.encode()).hexdigest() != entry.entry_hash:
                return False
        return True

    def export_json(self) -> str:
        return json.dumps(
            [vars(e) for e in self._entries],
            indent=2,
            default=str,
        )
