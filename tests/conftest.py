"""
Shared pytest fixtures for CipherRescue tests.
"""

from __future__ import annotations

import pytest

from cipherrescue.scpr.types import (
    CoveringPair,
    Reason,
    SCPRInstance,
    Signal,
)

# ── Canonical test signals ─────────────────────────────────────────────────


@pytest.fixture
def sig_smart_realloc() -> Signal:
    return Signal("smart_reallocated_sectors")


@pytest.fixture
def sig_header_absent() -> Signal:
    return Signal("header_absent")


@pytest.fixture
def sig_entropy_low() -> Signal:
    return Signal("entropy_low")


@pytest.fixture
def sig_keyslot_invalid() -> Signal:
    return Signal("keyslot_invalid")


# ── Canonical test reasons ─────────────────────────────────────────────────


@pytest.fixture
def reason_disk_failure() -> Reason:
    return Reason("disk_failure", "Physical disk sector failure")


@pytest.fixture
def reason_header_overwrite() -> Reason:
    return Reason("header_overwrite", "LUKS header overwritten by OS reinstall")


@pytest.fixture
def reason_wrong_device() -> Reason:
    return Reason("wrong_device", "Operator targeting wrong device")


@pytest.fixture
def reason_partial_encryption() -> Reason:
    return Reason("partial_encryption", "Encryption interrupted mid-process")


# ── Minimal feasible SCPR instance ────────────────────────────────────────


@pytest.fixture
def minimal_instance(
    sig_smart_realloc,
    sig_header_absent,
    reason_disk_failure,
    reason_header_overwrite,
) -> SCPRInstance:
    """
    Smallest non-trivial SCPR instance:
        U = {smart_reallocated_sectors, header_absent}
        R = {disk_failure, header_overwrite}
        E = [
            ({smart_reallocated_sectors}, {disk_failure}),
            ({header_absent},             {header_overwrite}),
            ({smart_reallocated_sectors,
              header_absent},             {disk_failure, header_overwrite}),
        ]
    Optimal cover: S* = {disk_failure, header_overwrite}, cost = 2.
    """
    u = frozenset([sig_smart_realloc, sig_header_absent])
    r = frozenset([reason_disk_failure, reason_header_overwrite])
    pairs = [
        CoveringPair(
            covering_set=frozenset([sig_smart_realloc]),
            reason_set=frozenset([reason_disk_failure]),
        ),
        CoveringPair(
            covering_set=frozenset([sig_header_absent]),
            reason_set=frozenset([reason_header_overwrite]),
        ),
        CoveringPair(
            covering_set=frozenset([sig_smart_realloc, sig_header_absent]),
            reason_set=frozenset([reason_disk_failure, reason_header_overwrite]),
        ),
    ]
    return SCPRInstance(universe=u, reasons=r, covering_pairs=pairs)


@pytest.fixture
def single_essential_instance(
    sig_entropy_low,
    reason_partial_encryption,
) -> SCPRInstance:
    """
    Instance with one signal covered by exactly one reason.
    Structural reduction should fix reason_partial_encryption = 1 immediately.
    """
    u = frozenset([sig_entropy_low])
    r = frozenset([reason_partial_encryption])
    pairs = [
        CoveringPair(
            covering_set=frozenset([sig_entropy_low]),
            reason_set=frozenset([reason_partial_encryption]),
        )
    ]
    return SCPRInstance(universe=u, reasons=r, covering_pairs=pairs)


@pytest.fixture
def infeasible_instance(
    sig_keyslot_invalid,
    reason_disk_failure,
) -> SCPRInstance:
    """
    Instance where sig_keyslot_invalid is NOT covered by any pair.
    is_feasible() should return False.
    """
    u = frozenset([sig_keyslot_invalid])
    r = frozenset([reason_disk_failure])
    pairs = [
        CoveringPair(
            covering_set=frozenset([Signal("unrelated_signal")]),
            reason_set=frozenset([reason_disk_failure]),
        )
    ]
    return SCPRInstance(universe=u, reasons=r, covering_pairs=pairs)
