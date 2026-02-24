"""
Layer 5 — SCPR Diagnostic Engine: Beasley Reduction Process.

Adapted from 1771863678660_Python_Beaseley_Reduction_SCPR_1.py:
    Babatunde, A.T. (2025). PhD Thesis, Coventry University.

The thesis implements Beasley's reduction in two passes:

    Pass 1 — Row reduction (essential elements):
        For each u ∈ U covered by exactly one pair e, the reasons in e[1]
        MUST be selected.  Add e[1] to C, remove e from E, remove e[0] from U.

    Pass 2 — Column reduction (dominated pairs):
        For pairs e1, e2 where A₁ ⊆ A₂ and (R₂ minus C) ⊆ R₁, pair e1 is
        dominated: it covers less and requires at least as many reasons.
        Remove e1 from E.

After reduction, C holds the reasons that must be in every optimal solution.
The remaining (U, R, E) is a smaller instance solved by the ILP.

List utility functions (list_remove, list_substract, list_union, is_subset)
are direct ports from the thesis.  They operate on Python lists of any objects
supporting __eq__, which includes the typed Reason and Signal objects used here.

References:
    Beasley (1987). EJOR 31(1):85-93.       [original SCP reduction]
    Beasley (1990). NRL 37(1):151-164.
    Babatunde (2025). PhD Thesis, §3.2.     [generalisation to SCPR]
    Babatunde, England & Sadeghimanesh (2026). arXiv:2601.14424.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

from ._thesis_instance import ThesisSCPR, from_instance
from .types import Reason, SCPRInstance, Signal

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# Result type (unchanged public API)
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class ReductionResult:
    """
    Output of the Beasley reduction applied to a SCPRInstance.

    Attributes:
        reduced_instance:   Smaller SCPR instance (may be empty if fully resolved).
        fixed_in:           Reasons fixed to 1 — must be in every optimal solution.
        fixed_out:          Reasons fixed to 0 — cannot be in any optimal solution.
        reduction_rate:     Fraction of original reasons eliminated.
        is_fully_resolved:  True iff the reduced instance has an empty universe.
    """
    reduced_instance: SCPRInstance
    fixed_in: frozenset[Reason]
    fixed_out: frozenset[Reason]
    reduction_rate: float
    is_fully_resolved: bool


# ─────────────────────────────────────────────────────────────────────────────
# List utilities — direct ports from thesis
# ─────────────────────────────────────────────────────────────────────────────

def _list_remove(L: list, i: object) -> list:
    """Remove element i from list L (copy). Adapted from thesis list_remove."""
    L_copy = L.copy()
    if i in L_copy:
        L_copy.remove(i)
    return L_copy


def _list_subtract(L1: list, L2: list) -> list:
    """Return L1 minus all elements of L2. Adapted from thesis list_substract."""
    for i in L2:
        L1 = _list_remove(L1, i)
    return L1


def _list_union(L1: list, L2: list) -> list:
    """Return union of L1 and L2 (no duplicates). Adapted from thesis list_union."""
    for i in L2:
        if i not in L1:
            L1.append(i)
    return L1


def _is_subset(L1: list, L2: list) -> bool:
    """Return True if every element of L1 is in L2. Adapted from thesis is_subset."""
    for i in L1:
        if i not in L2:
            return False
    return True


# ─────────────────────────────────────────────────────────────────────────────
# Core reduction — direct port from thesis
# ─────────────────────────────────────────────────────────────────────────────

def beasley_reduction(
    U: list, R: list, E: list
) -> tuple[list, list, list, list]:
    """
    Apply Beasley's reduction to the SCPR instance (U, R, E).

    Direct port of beasley_reduction() from the thesis, adapted to work with
    Signal and Reason objects (not integers).  The logic is unchanged.

    Pass 1 — Row reduction:
        Each u ∈ U covered by exactly one pair e must have e[1] ⊆ solution.
        Collect those reasons into C.  Remove covered signals from U.

    Pass 2 — Column reduction:
        Pair e1 dominated by e2 if A₁ ⊆ A₂ and (R₂ minus C) ⊆ R₁.
        Remove e1 (it is never needed in an optimal solution).

    Args:
        U: list of Signal objects.
        R: list of Reason objects.
        E: list of [list[Signal], list[Reason]] pairs.

    Returns:
        (U_reduced, R, E_reduced, C) where C is the list of forced reasons.

    Adapted from Babatunde (2025), PhD Thesis.
    """
    EE = E.copy()
    C: list = []

    # Pass 1: row reduction
    for u in U:
        subsets_containing_u = [e for e in E if u in e[0]]
        if len(subsets_containing_u) == 1:
            e = subsets_containing_u[0]
            EE = _list_remove(EE, e)
            U = _list_subtract(U, e[0])
            C = _list_union(C, e[1])

    # Pass 2: column reduction
    EEE = EE.copy()
    for e1 in EE:
        for e2 in EEE:
            if e2 != e1:
                if _is_subset(e1[0], e2[0]) and _is_subset(
                    _list_subtract(e2[1], C), e1[1]
                ):
                    EEE = _list_remove(EEE, e1)
                    break
        EE = EEE.copy()

    return U, R, EE, C


# ─────────────────────────────────────────────────────────────────────────────
# Public API — wraps beasley_reduction with typed I/O
# ─────────────────────────────────────────────────────────────────────────────

def apply_structural_reduction(instance: SCPRInstance) -> ReductionResult:
    """
    Apply Beasley's reduction to a typed SCPRInstance.

    Wraps beasley_reduction() with conversion from/to SCPRInstance.
    The function name is kept from the original engine.py interface so that
    existing callers and tests do not need to change.

    Args:
        instance: The original SCPR instance.

    Returns:
        ReductionResult with reduced instance, forced/excluded reasons,
        reduction rate, and a flag indicating full resolution.
    """
    A = from_instance(instance)

    U_red, R_red, E_red, C = beasley_reduction(A.U, A.R, A.E)

    fixed_in = frozenset(C)
    # Column reduction removes pairs but does not explicitly fix reasons to 0;
    # we report fixed_out as empty (the engine simply will not select those
    # pairs' reasons unless forced).
    fixed_out: frozenset[Reason] = frozenset()

    is_fully_resolved = len(U_red) == 0

    # Build the reduced SCPRInstance from the remaining (U, E) after reduction
    if is_fully_resolved:
        reduced = SCPRInstance(
            universe=frozenset(),
            reasons=frozenset(),
            covering_pairs=[],
        )
    else:
        from .types import CoveringPair
        reduced_pairs = [
            CoveringPair(
                covering_set=frozenset(e[0]),
                reason_set=frozenset(e[1]),
            )
            for e in E_red
        ]
        reduced_reasons = frozenset(
            r for e in E_red for r in e[1]
        ) - fixed_in

        reduced = SCPRInstance(
            universe=frozenset(U_red),
            reasons=reduced_reasons,
            covering_pairs=reduced_pairs,
            costs={r: instance.costs.get(r, 1.0) for r in reduced_reasons},
        )

    original_count = len(instance.reasons)
    eliminated = len(fixed_in)
    rate = eliminated / original_count if original_count > 0 else 0.0

    logger.info(
        "Beasley reduction: %d reasons fixed in, %d remaining universe elements. "
        "Fully resolved: %s",
        len(fixed_in), len(U_red), is_fully_resolved,
    )

    return ReductionResult(
        reduced_instance=reduced,
        fixed_in=fixed_in,
        fixed_out=fixed_out,
        reduction_rate=rate,
        is_fully_resolved=is_fully_resolved,
    )
