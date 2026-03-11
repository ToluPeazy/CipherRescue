"""
Layer 2 — Detection Engine.

Extracts anomaly signals from a target block device:

    - SMART attribute parsing (via smartctl --json)
    - Entropy measurement over device sectors
    - Header byte signature verification (LUKS, BitLocker, VeraCrypt, Opal)

Output is a set of Signal objects forming the universe U of the SCPR instance
passed to Layer 5.

Status: STUB — signal extractors pending implementation.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

from ..scpr.types import Signal

logger = logging.getLogger(__name__)


# ── Canonical signal names ─────────────────────────────────────────────────
# These must match the covering pair definitions in the SCPR instance builder.

SIGNAL_SMART_REALLOCATED = Signal(
    "smart_reallocated_sectors", "SMART attr 5: reallocated sector count elevated"
)
SIGNAL_SMART_PENDING = Signal(
    "smart_pending_sectors",
    "SMART attr 197: current pending sector count > 0",
)
SIGNAL_SMART_UNCORRECTABLE = Signal(
    "smart_uncorrectable",
    "SMART attr 198: uncorrectable sector count > 0",
)
SIGNAL_SMART_REPORTED_UNCORR = Signal(
    "smart_reported_uncorrectable",
    "SMART attr 187: reported uncorrectable errors > 0",
)
SIGNAL_ENTROPY_LOW = Signal(
    "entropy_low",
    "Sector entropy below encryption floor (~7.9 bits/byte)",
)
SIGNAL_HEADER_CORRUPT = Signal(
    "header_corrupt",
    "Header magic found but structure invalid or truncated",
)
SIGNAL_FS_CHECK_FAIL = Signal(
    "fs_check_fail",
    "Filesystem check reports errors on decrypted volume",
)


@dataclass
class DetectionResult:
    """Signals extracted from a device by the Detection Engine."""

    device_path: str
    signals: frozenset[Signal] = field(default_factory=frozenset)
    raw_smart: dict[str, object] = field(default_factory=dict)
    scheme_hint: str = ""  # 'luks2' | 'bitlocker' | 'veracrypt' | 'opal' | ''
    errors: list[str] = field(default_factory=list)


class DetectionEngine:
    """
    Layer 2 — Detection Engine.

    Runs signal extraction against a block device and returns
    a DetectionResult whose .signals set forms the SCPR universe U.
    """

    def detect(self, device_path: str) -> DetectionResult:
        """
        Run all extractors against device_path.

        Args:
            device_path: e.g. '/dev/sda' or '/dev/nvme0n1'

        Returns:
            DetectionResult with all observed signals.
        """
        logger.info("DetectionEngine: scanning %s", device_path)
        result = DetectionResult(device_path=device_path)

        signals: set[Signal] = set()
        errors: list[str] = []

        # SMART extraction
        try:
            smart_signals, raw = self._extract_smart(device_path)
            signals |= smart_signals
            result.raw_smart = raw
        except Exception as exc:  # noqa: BLE001
            errors.append(f"SMART extraction failed: {exc}")
            logger.warning("SMART extraction failed for %s: %s", device_path, exc)

        # Header signature check
        try:
            header_signals, scheme = self._check_header(device_path)
            signals |= header_signals
            result.scheme_hint = scheme
        except Exception as exc:  # noqa: BLE001
            errors.append(f"Header check failed: {exc}")
            logger.warning("Header check failed for %s: %s", device_path, exc)

        # Entropy check (sampled)
        try:
            entropy_signals = self._check_entropy(device_path)
            signals |= entropy_signals
        except Exception as exc:  # noqa: BLE001
            errors.append(f"Entropy check failed: {exc}")
            logger.warning("Entropy check failed for %s: %s", device_path, exc)

        result.signals = frozenset(signals)
        result.errors = errors
        return result

    # ── Extractors (stubs) ───────────────────────────────────────────────

    def _extract_smart(self, device_path: str) -> tuple[set[Signal], dict[str, object]]:
        """
        Parse SMART attributes via smartctl --json.

        Thresholds validated against Pinheiro et al. (2007) and
        calibrated from the Backblaze 200k-drive dataset (2014-2024).
        """
        # TODO: call smartctl and parse output
        # Placeholder: return empty
        return set(), {}

    def _check_header(self, device_path: str) -> tuple[set[Signal], str]:
        """
        Check the first 4096 bytes for known FDE scheme magic bytes.

        LUKS2:      bytes 0-5  == b'LUKS\\xba\\xbe'
        BitLocker:  bytes 3-10 == b'-FVE-FS-'
        VeraCrypt:  bytes 0-3  == b'\\x00\\x00\\x00\\x00' (hidden header)
        """
        # TODO: open device (read-only), read header bytes, classify
        return set(), ""

    def _check_entropy(self, device_path: str) -> set[Signal]:
        """
        Sample 16 random 512-byte sectors and compute byte entropy.

        Encrypted volumes should show entropy ≥ 7.9 bits/byte.
        Values below this threshold raise SIGNAL_ENTROPY_LOW.
        """
        # TODO: read sectors, compute Shannon entropy
        return set()
