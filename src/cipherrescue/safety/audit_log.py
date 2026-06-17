"""
Layer 3 — Safety & Audit: AuditLog.

Implements Theorem 3.3 (Log Tamper Evidence):

    The audit log is HMAC-keyed and hash-chained: each entry eₙ includes
    H(eₙ₋₁ ‖ payload) and mac_n = HMAC_K(entry_hash_n), making
    retrospective alteration detectable even by an attacker who knows
    the chain structure but not the session key K.

Each session produces a self-contained, append-only log that records:
    - Authority declaration (device owner / authorised representative /
      law enforcement / corporate IT)
    - Every state machine transition (including rejected transitions)
    - All write operations and their BackupTokens
    - The full SCPRSolution (optimal reasons + dual weights)
    - Any uncovered signals flagged for operator review

Status: hash chaining and HMAC keying implemented. DFXML export pending.
"""

from __future__ import annotations

import hashlib
import hmac as _hmac
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
    mac: str = field(init=False, default="")

    def _raw_json(self) -> str:
        """Canonical JSON serialisation used for both hashing and verification."""
        return json.dumps(
            {
                "seq": self.sequence,
                "ts": self.timestamp,
                "type": self.event_type,
                "payload": self.payload,
                "prev": self.prev_hash,
            },
            sort_keys=True,
        )

    def __post_init__(self) -> None:
        self.entry_hash = self.recompute_hash()

    def recompute_hash(self) -> str:
        """Recompute SHA-256 over the canonical serialisation."""
        return hashlib.sha256(self._raw_json().encode()).hexdigest()

    def set_mac(self, session_key: bytes) -> None:
        """Compute and set HMAC_K(entry_hash). Called by AuditLog._append()."""
        self.mac = _hmac.new(
            session_key, self.entry_hash.encode(), hashlib.sha256
        ).hexdigest()

    def verify_mac(self, session_key: bytes) -> bool:
        """Return True iff HMAC_K(entry_hash) matches the stored mac."""
        expected = _hmac.new(
            session_key, self.entry_hash.encode(), hashlib.sha256
        ).hexdigest()
        return _hmac.compare_digest(expected, self.mac)


class AuditLog:
    """
    Tamper-evident, append-only audit log for a recovery session.

    Each entry is SHA-256 hash-chained and HMAC'd under the session key K
    (Definition 3.1). verify_chain() checks hash linkage, payload integrity,
    and MAC — the chain is not regeneratable without K.
    """

    GENESIS_HASH = "0" * 64

    def __init__(
        self,
        session_id: str,
        authority: Authority,
        session_key: bytes = b"",
    ) -> None:
        self.session_id = session_id
        self.authority = authority
        self._session_key = session_key
        self._entries: list[LogEntry] = []
        self._append(
            "SESSION_OPEN",
            {
                "session_id": session_id,
                "authority": authority.value,
            },
        )

    def _append(self, event_type: str, payload: dict[str, Any]) -> LogEntry:
        prev = self._entries[-1].entry_hash if self._entries else self.GENESIS_HASH
        entry = LogEntry(
            sequence=len(self._entries),
            timestamp=time.time(),
            event_type=event_type,
            payload=payload,
            prev_hash=prev,
        )
        entry.set_mac(self._session_key)
        self._entries.append(entry)
        return entry

    def log_state_transition(self, from_state: str, to_state: str) -> None:
        self._append("STATE_TRANSITION", {"from": from_state, "to": to_state})

    def log_rejected_transition(self, from_state: str, to_state: str) -> None:
        """Log an attempted transition that was rejected by the state machine."""
        self._append("REJECTED_TRANSITION", {"from": from_state, "to": to_state})

    def log_diagnosis(self, solution_repr: str, uncovered_count: int) -> None:
        self._append(
            "SCPR_DIAGNOSIS",
            {
                "solution": solution_repr,
                "uncovered_signals": uncovered_count,
            },
        )

    def log_write(self, device: str, backup_sha256: str, action: str) -> None:
        self._append(
            "WRITE_OPERATION",
            {
                "device": device,
                "backup_sha256": backup_sha256,
                "action": action,
            },
        )

    def verify_chain(self) -> bool:
        """
        Return True iff the entire chain is unmodified.

        Delegates per-entry checks to LogEntry methods:
          1. Hash-chain linkage (prev_hash == previous entry's entry_hash).
          2. Payload integrity (recompute_hash() matches entry_hash).
          3. MAC integrity (verify_mac() under session key K).
        """
        for i, entry in enumerate(self._entries):
            prev = self._entries[i - 1].entry_hash if i > 0 else self.GENESIS_HASH
            if entry.prev_hash != prev:
                return False
            if entry.recompute_hash() != entry.entry_hash:
                return False
            if not entry.verify_mac(self._session_key):
                return False
        return True

    def export_json(self) -> str:
        return json.dumps(
            [vars(e) for e in self._entries],
            indent=2,
            default=str,
        )
