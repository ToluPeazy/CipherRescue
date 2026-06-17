"""
Stream 1 — Synthetic FDE Device Profile Generator.

Generates ≥140 synthetic SCPR instances representing Full Disk Encryption
failure scenarios per spec §14.4 (Stream 1: Code Validation via Synthetic
Device Profiles).

Each generated SCPRInstance models a realistic FDE failure mode:
  - Universe U: the anomaly signals observable on the device.
  - Reasons R:  the set of root-cause hypotheses under consideration.
  - Pairs E:    (Aᵢ, Rᵢ) — which signals each reason combination explains.

Instances are seeded deterministically for reproducibility and cover:
  - Single-fault scenarios (one reason, one or more signals)
  - Multi-fault scenarios (two or more concurrent failure modes)
  - Scheme-specific scenarios (LUKS2, BitLocker, VeraCrypt, Opal SED)
  - Edge cases (infeasible, minimal universe, overlapping coverage)
  - Cost-varied instances (non-uniform reason weights)

Usage::

    generator = FDEProfileGenerator(seed=42)
    corpus = generator.generate(n=150)
    print(f"{len(corpus)} instances generated")
    feasible = [inst for inst in corpus if inst.is_feasible()]

    # Or convenience wrapper:
    corpus = generate_fde_corpus(n=150, seed=42)
"""

from __future__ import annotations

import itertools
import random
from dataclasses import dataclass
from typing import NamedTuple

from ..scpr.types import CoveringPair, Reason, SCPRInstance, Signal

# ---------------------------------------------------------------------------
# Canonical signal library
# ---------------------------------------------------------------------------

# SMART-derived signals
S_SMART_REALLOC = Signal(
    "smart_reallocated_sectors", "SMART attr 5: reallocated sector count elevated"
)
S_SMART_PENDING = Signal(
    "smart_pending_sectors", "SMART attr 197: current pending sector count > 0"
)
S_SMART_UNCORR = Signal(
    "smart_uncorrectable", "SMART attr 198: uncorrectable sector count > 0"
)
S_SMART_RPT_UNCORR = Signal(
    "smart_reported_uncorrectable",
    "SMART attr 187: reported uncorrectable errors > 0",
)

# FDE header / metadata signals
S_HEADER_ABSENT = Signal(
    "header_absent", "No recognised FDE magic bytes found in first 4 KiB"
)
S_HEADER_CORRUPT = Signal(
    "header_corrupt", "FDE header magic present but structure invalid or truncated"
)
S_KEYSLOT_INVALID = Signal(
    "keyslot_invalid", "Keyslot checksum mismatch or keyslot area overwritten"
)
S_WRONG_SCHEME = Signal(
    "wrong_scheme", "Detected encryption scheme does not match operator expectation"
)

# Entropy / content signals
S_ENTROPY_LOW = Signal(
    "entropy_low", "Sector entropy below encryption floor (~7.9 bits/byte)"
)
S_ENTROPY_PARTIAL = Signal(
    "entropy_partial",
    "Mixed entropy — some sectors encrypted, others plaintext or zeroed",
)

# Filesystem / volume signals
S_FS_CHECK_FAIL = Signal(
    "fs_check_fail", "Filesystem check reports errors on decrypted volume"
)
S_MOUNT_FAIL = Signal("mount_fail", "Volume mounts but immediately reports I/O errors")

# I/O / hardware signals
S_READ_ERROR = Signal("read_error", "I/O error on sector read")
S_WRITE_TIMEOUT = Signal("write_timeout", "Write operation timed out")
S_SEEK_ERROR = Signal("seek_error", "Drive reported seek or positioning error")

ALL_SIGNALS: list[Signal] = [
    S_SMART_REALLOC,
    S_SMART_PENDING,
    S_SMART_UNCORR,
    S_SMART_RPT_UNCORR,
    S_HEADER_ABSENT,
    S_HEADER_CORRUPT,
    S_KEYSLOT_INVALID,
    S_WRONG_SCHEME,
    S_ENTROPY_LOW,
    S_ENTROPY_PARTIAL,
    S_FS_CHECK_FAIL,
    S_MOUNT_FAIL,
    S_READ_ERROR,
    S_WRITE_TIMEOUT,
    S_SEEK_ERROR,
]

# ---------------------------------------------------------------------------
# Canonical reason library
# ---------------------------------------------------------------------------

R_DISK_FAILURE = Reason(
    "disk_failure", "Physical disk sector failure — drive hardware degraded"
)
R_HEADER_OVERWRITE = Reason(
    "header_overwrite", "FDE header overwritten (OS reinstall, dd, mkfs)"
)
R_WRONG_DEVICE = Reason("wrong_device", "Operator targeting wrong device path")
R_PARTIAL_ENCRYPTION = Reason(
    "partial_encryption", "Encryption process was interrupted mid-operation"
)
R_KEY_LOSS = Reason(
    "key_material_loss", "TPM cleared, recovery key lost, or escrow unavailable"
)
R_BITROT = Reason(
    "bitrot", "Silent data corruption accumulated over time (Rosenthal 2010)"
)
R_FIRMWARE_BUG = Reason(
    "firmware_bug", "Drive firmware corrupted data during a write operation"
)
R_POWER_FAILURE = Reason(
    "power_failure", "Unexpected power loss during an active write"
)
R_METADATA_CORRUPTION = Reason(
    "metadata_corruption", "Keyslot or header metadata field corrupted"
)
R_WRONG_PASSPHRASE = Reason(
    "wrong_passphrase", "Operator supplied incorrect passphrase or key file"
)
R_FS_CORRUPTION = Reason(
    "filesystem_corruption", "Filesystem corruption on the decrypted volume"
)
R_SEEK_ERROR = Reason("seek_error_reason", "Read/write head positioning failure")
R_BAD_BLOCK = Reason(
    "bad_block", "Persistent bad blocks in or near the FDE header area"
)
R_LUKS_VERSION = Reason(
    "luks_version_mismatch",
    "LUKS1 recovery tool applied to a LUKS2 device or vice versa",
)
R_CIPHER_MISMATCH = Reason(
    "cipher_mismatch", "Incorrect cipher or key size selected for recovery attempt"
)

ALL_REASONS: list[Reason] = [
    R_DISK_FAILURE,
    R_HEADER_OVERWRITE,
    R_WRONG_DEVICE,
    R_PARTIAL_ENCRYPTION,
    R_KEY_LOSS,
    R_BITROT,
    R_FIRMWARE_BUG,
    R_POWER_FAILURE,
    R_METADATA_CORRUPTION,
    R_WRONG_PASSPHRASE,
    R_FS_CORRUPTION,
    R_SEEK_ERROR,
    R_BAD_BLOCK,
    R_LUKS_VERSION,
    R_CIPHER_MISMATCH,
]

# ---------------------------------------------------------------------------
# Reason → signals capability map
# Each entry is the set of signals a reason can explain.
# ---------------------------------------------------------------------------

REASON_SIGNALS: dict[Reason, list[Signal]] = {
    R_DISK_FAILURE: [S_SMART_REALLOC, S_SMART_PENDING, S_SMART_UNCORR, S_READ_ERROR],
    R_HEADER_OVERWRITE: [S_HEADER_ABSENT, S_HEADER_CORRUPT, S_ENTROPY_LOW],
    R_WRONG_DEVICE: [S_HEADER_ABSENT, S_WRONG_SCHEME, S_ENTROPY_LOW],
    R_PARTIAL_ENCRYPTION: [S_ENTROPY_PARTIAL, S_KEYSLOT_INVALID, S_HEADER_CORRUPT],
    R_KEY_LOSS: [S_KEYSLOT_INVALID],
    R_BITROT: [S_SMART_UNCORR, S_SMART_RPT_UNCORR, S_READ_ERROR],
    R_FIRMWARE_BUG: [S_SMART_REALLOC, S_SMART_UNCORR, S_WRITE_TIMEOUT],
    R_POWER_FAILURE: [S_HEADER_CORRUPT, S_KEYSLOT_INVALID, S_FS_CHECK_FAIL],
    R_METADATA_CORRUPTION: [S_KEYSLOT_INVALID, S_HEADER_CORRUPT],
    R_WRONG_PASSPHRASE: [S_KEYSLOT_INVALID],
    R_FS_CORRUPTION: [S_FS_CHECK_FAIL, S_MOUNT_FAIL],
    R_SEEK_ERROR: [S_READ_ERROR, S_SMART_PENDING, S_SEEK_ERROR],
    R_BAD_BLOCK: [S_SMART_REALLOC, S_READ_ERROR, S_HEADER_CORRUPT],
    R_LUKS_VERSION: [S_HEADER_CORRUPT, S_WRONG_SCHEME],
    R_CIPHER_MISMATCH: [S_ENTROPY_LOW, S_FS_CHECK_FAIL],
}


# ---------------------------------------------------------------------------
# Named scenario templates
# ---------------------------------------------------------------------------


class _Scenario(NamedTuple):
    name: str
    active_reasons: list[Reason]
    cost_multipliers: dict[Reason, float]


_NAMED_SCENARIOS: list[_Scenario] = [
    _Scenario(
        "luks2_header_wiped_by_os_reinstall",
        [R_HEADER_OVERWRITE],
        {},
    ),
    _Scenario(
        "luks2_header_wiped_by_os_reinstall_with_disk_degradation",
        [R_HEADER_OVERWRITE, R_DISK_FAILURE],
        {},
    ),
    _Scenario(
        "bitlocker_wrong_recovery_key",
        [R_WRONG_PASSPHRASE, R_KEY_LOSS],
        {R_WRONG_PASSPHRASE: 0.5},
    ),
    _Scenario(
        "veracrypt_power_failure_during_encryption",
        [R_POWER_FAILURE, R_PARTIAL_ENCRYPTION],
        {},
    ),
    _Scenario(
        "opal_sed_tpm_cleared",
        [R_KEY_LOSS],
        {R_KEY_LOSS: 2.0},
    ),
    _Scenario(
        "luks2_bad_blocks_in_header_area",
        [R_BAD_BLOCK, R_DISK_FAILURE],
        {R_BAD_BLOCK: 1.5},
    ),
    _Scenario(
        "luks_version_tool_mismatch",
        [R_LUKS_VERSION],
        {},
    ),
    _Scenario(
        "veracrypt_wrong_cipher_selected",
        [R_CIPHER_MISMATCH],
        {},
    ),
    _Scenario(
        "operator_wrong_device_path",
        [R_WRONG_DEVICE],
        {},
    ),
    _Scenario(
        "bitrot_accumulated_over_5_years",
        [R_BITROT, R_FS_CORRUPTION],
        {R_BITROT: 0.8},
    ),
    _Scenario(
        "firmware_bug_corrupted_keyslots",
        [R_FIRMWARE_BUG, R_METADATA_CORRUPTION],
        {},
    ),
    _Scenario(
        "seek_error_with_pending_sectors",
        [R_SEEK_ERROR, R_DISK_FAILURE],
        {},
    ),
    _Scenario(
        "partial_encryption_interrupted",
        [R_PARTIAL_ENCRYPTION],
        {},
    ),
    _Scenario(
        "multi_fault_disk_and_header",
        [R_DISK_FAILURE, R_HEADER_OVERWRITE, R_BAD_BLOCK],
        {},
    ),
    _Scenario(
        "catastrophic_multi_fault",
        [R_DISK_FAILURE, R_POWER_FAILURE, R_METADATA_CORRUPTION, R_BAD_BLOCK],
        dict.fromkeys([R_DISK_FAILURE, R_POWER_FAILURE], 1.5),
    ),
    _Scenario(
        "filesystem_corruption_post_unlock",
        [R_FS_CORRUPTION],
        {},
    ),
    _Scenario(
        "luks2_keyslot_corruption",
        [R_METADATA_CORRUPTION, R_POWER_FAILURE],
        {},
    ),
    _Scenario(
        "bitlocker_tpm_pcr_mismatch",
        [R_KEY_LOSS, R_WRONG_PASSPHRASE],
        {R_KEY_LOSS: 2.0, R_WRONG_PASSPHRASE: 0.5},
    ),
    _Scenario(
        "write_timeout_during_rekey",
        [R_FIRMWARE_BUG, R_POWER_FAILURE],
        {},
    ),
    _Scenario(
        "opal_wrong_msid_credential",
        [R_WRONG_PASSPHRASE],
        {},
    ),
]


# ---------------------------------------------------------------------------
# Generator
# ---------------------------------------------------------------------------


@dataclass
class FDEProfileGenerator:
    """
    Generates synthetic SCPR instances for FDE failure-mode profiling.

    Args:
        seed: Random seed for reproducibility.
    """

    seed: int = 42

    def generate(self, n: int = 150) -> list[SCPRInstance]:
        """
        Generate n synthetic SCPRInstances covering diverse FDE failure modes.

        The corpus is built from four source pools:
          1. Single-fault instances (one reason per instance, 15 total)
          2. Named scenario instances (20 curated multi-fault scenarios)
          3. Parametric two-reason combinations (45 instances)
          4. Randomly sampled multi-signal instances (remainder to reach n)

        Args:
            n: Minimum number of instances to generate (default 150 ≥ 140).

        Returns:
            List of SCPRInstances.  All are feasible by construction.
        """
        rng = random.Random(self.seed)  # noqa: S311
        instances: list[SCPRInstance] = []

        instances.extend(self._single_fault_instances())
        instances.extend(self._named_scenario_instances())
        instances.extend(self._two_reason_combinations())
        instances.extend(self._random_instances(rng, count=max(0, n - len(instances))))

        return instances[:n] if len(instances) > n else instances

    # ── Pool builders ────────────────────────────────────────────────────────

    def _single_fault_instances(self) -> list[SCPRInstance]:
        """One instance per reason — reason explains its full signal set."""
        result = []
        for reason in ALL_REASONS:
            signals = REASON_SIGNALS.get(reason, [])
            if not signals:
                continue
            universe = frozenset(signals)
            reasons = frozenset([reason])
            pairs = [
                CoveringPair(
                    covering_set=frozenset([s]),
                    reason_set=frozenset([reason]),
                )
                for s in signals
            ]
            result.append(
                SCPRInstance(universe=universe, reasons=reasons, covering_pairs=pairs)
            )
        return result

    def _named_scenario_instances(self) -> list[SCPRInstance]:
        """Curated multi-fault scenarios modelling real FDE incidents."""
        result = []
        for scenario in _NAMED_SCENARIOS:
            inst = self._build_from_active_reasons(
                scenario.active_reasons, scenario.cost_multipliers
            )
            if inst is not None:
                result.append(inst)
        return result

    def _two_reason_combinations(self) -> list[SCPRInstance]:
        """
        All pairs of reasons from ALL_REASONS that together explain at
        least two distinct signals — ensures non-trivial covering structure.
        """
        result = []
        for r1, r2 in itertools.combinations(ALL_REASONS, 2):
            sigs = list({*REASON_SIGNALS.get(r1, []), *REASON_SIGNALS.get(r2, [])})
            if len(sigs) < 2:
                continue
            inst = self._build_from_active_reasons([r1, r2], {})
            if inst is not None:
                result.append(inst)
        return result

    def _random_instances(self, rng: random.Random, count: int) -> list[SCPRInstance]:
        """
        Randomly sampled instances with 2–4 reasons and varied cost structures.
        """
        result = []
        for _ in range(count):
            k = rng.randint(2, 4)
            chosen_reasons = rng.sample(ALL_REASONS, k)
            cost_mults = {r: round(rng.uniform(0.5, 2.0), 2) for r in chosen_reasons}
            inst = self._build_from_active_reasons(chosen_reasons, cost_mults)
            if inst is not None:
                result.append(inst)
        return result

    # ── Instance builder ────────────────────────────────────────────────────

    def _build_from_active_reasons(
        self,
        active_reasons: list[Reason],
        cost_multipliers: dict[Reason, float],
    ) -> SCPRInstance | None:
        """
        Construct an SCPRInstance from a list of "ground truth" active reasons.

        Universe U = union of signals explained by any active reason.
        Covering pairs E include:
          - One pair per (reason, signal) where reason explains signal.
          - One aggregate pair per reason covering all its signals jointly.

        Returns None if no signals are produced (degenerate case).
        """
        all_signals: set[Signal] = set()
        for r in active_reasons:
            all_signals |= set(REASON_SIGNALS.get(r, []))

        if not all_signals:
            return None

        universe = frozenset(all_signals)
        all_reasons_set = frozenset(ALL_REASONS)

        pairs: list[CoveringPair] = []
        for reason in active_reasons:
            r_sigs = REASON_SIGNALS.get(reason, [])
            if not r_sigs:
                continue
            # Individual signal pairs
            for sig in r_sigs:
                pairs.append(
                    CoveringPair(
                        covering_set=frozenset([sig]),
                        reason_set=frozenset([reason]),
                    )
                )
            # Aggregate pair covering all signals for this reason
            if len(r_sigs) > 1:
                pairs.append(
                    CoveringPair(
                        covering_set=frozenset(r_sigs),
                        reason_set=frozenset([reason]),
                    )
                )

        costs: dict[Reason, float] = {}
        for r in all_reasons_set:
            base = 1.0
            mult = cost_multipliers.get(r, 1.0)
            costs[r] = base * mult

        return SCPRInstance(
            universe=universe,
            reasons=all_reasons_set,
            covering_pairs=pairs,
            costs=costs,
        )


def generate_fde_corpus(n: int = 150, seed: int = 42) -> list[SCPRInstance]:
    """
    Convenience wrapper — generate a synthetic FDE failure-mode corpus.

    Args:
        n:    Number of instances to generate (≥ 140 per spec §14.4).
        seed: Random seed for reproducibility.

    Returns:
        List of SCPRInstances.
    """
    return FDEProfileGenerator(seed=seed).generate(n=n)
