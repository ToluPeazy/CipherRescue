"""
Internal list-based SCPR representation used by the core algorithms.

Adapted from SCPR_Class.py:
    Babatunde, A.T. (2025). PhD Thesis, Coventry University.

The original SCPR_Class stored U, R, E as lists and automatically computed
T = non_single_reason(E) — the set of non-singleton reason prefixes needed
to linearise AND-conjunctions in the ILP formulation.

CipherRescue uses typed objects (Signal, Reason) throughout.  The thesis
algorithms (reduction, LP/ILP) operate on these objects directly, since
Python list operations (index, in, remove) work on any objects that implement
__eq__, which frozen dataclasses do.

The only adaptation from the original:
    - costs dict added to support variable-cost objectives.
    - T is computed from the list of Reason objects in E (not integers).
"""

from __future__ import annotations

from ._extract_reasons import non_single_reason
from .types import Reason, SCPRInstance, Signal


class ThesisSCPR:
    """
    List-based SCPR representation for internal algorithm use.

    Attributes:
        U:     list[Signal]   — universe elements in sorted order.
        R:     list[Reason]   — reasons in sorted order.
        E:     list of [list[Signal], list[Reason]]  — covering pairs.
        T:     list of list[Reason]  — non-singleton reason prefixes,
               one per auxiliary variable in the ILP linearisation.
        costs: dict[Reason, float]  — objective cost per reason.
    """

    def __init__(
        self,
        U: list[Signal],
        R: list[Reason],
        E: list[list],
        costs: dict[Reason, float] | None = None,
    ) -> None:
        self.U = U
        self.R = R
        self.E = E
        self.T: list[list[Reason]] = non_single_reason(E)
        self.costs: dict[Reason, float] = costs if costs is not None else {r: 1.0 for r in R}


def from_instance(instance: SCPRInstance) -> ThesisSCPR:
    """
    Convert a typed SCPRInstance to a ThesisSCPR for algorithm use.

    Sorting is applied so that R.index() lookups are deterministic and
    reproducible across calls.

    Args:
        instance: CipherRescue typed SCPR instance.

    Returns:
        ThesisSCPR with lists of Signal / Reason objects.
    """
    U = sorted(instance.universe, key=lambda s: s.name)
    R = sorted(instance.reasons, key=lambda r: r.name)

    E: list[list] = [
        [
            sorted(pair.covering_set, key=lambda s: s.name),
            sorted(pair.reason_set, key=lambda r: r.name),
        ]
        for pair in instance.covering_pairs
    ]

    return ThesisSCPR(U, R, E, costs=dict(instance.costs))
