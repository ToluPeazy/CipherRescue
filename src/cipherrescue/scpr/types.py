"""
Layer 5 — SCPR Diagnostic Engine: Core Type Definitions.

Implements Definition 1.5.3 from Babatunde (2025):

    SCPR instance: (U, R, E) where
        U = {α₁, ..., αₙ}   — universe (anomaly signals)
        R = {ρ₁, ..., ρᵣ}   — reasons (failure mode hypotheses)
        E = {(Aᵢ, Rᵢ)}      — pairs of covering sets and reason sets

    Goal: find minimal S ⊆ R such that
        ⋃{Aᵢ : Rᵢ ⊆ S} = U

References:
    Babatunde, A.T. (2025). PhD Thesis, Coventry University.  [Definition 1.5.3]
    Babatunde, England & Sadeghimanesh (2026). arXiv:2601.14424.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import FrozenSet


# ---------------------------------------------------------------------------
# Universe elements: anomaly signals observable on a device
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Signal:
    """
    An element αᵢ ∈ U — a single anomaly signal observable on the target device.

    Signals are drawn from SMART attributes, entropy measurements, and
    header anomaly indicators (Layer 2 output).
    """
    name: str
    description: str = ""

    def __repr__(self) -> str:
        return f"Signal({self.name!r})"


# ---------------------------------------------------------------------------
# Reasons: failure mode hypotheses
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Reason:
    """
    An element ρⱼ ∈ R — a failure mode hypothesis.

    Each Reason corresponds to one diagnosable failure mode. The LP dual
    variable y*ⱼ associated with this reason at optimum serves as its
    evidence weight in the FailureReport.
    """
    name: str
    description: str = ""
    # Evidence weight assigned by LP dual variable at optimum (populated
    # by SCPRSolver after solving; None before solve).
    evidence_weight: float | None = None

    def __repr__(self) -> str:
        return f"Reason({self.name!r})"


# ---------------------------------------------------------------------------
# Covering pairs: (Aᵢ, Rᵢ) ∈ E
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class CoveringPair:
    """
    A pair (Aᵢ, Rᵢ) ∈ E ⊆ P(U) × P(R).

    Aᵢ is the set of signals that this pair covers when its reason set Rᵢ
    is included in the solution S.  Rᵢ is the set of reasons required to
    activate this covering pair.

    In the CDCAC application (Sadeghimanesh & England, 2022), Aᵢ represents
    the constraints labelling a CAD cell, and Rᵢ the underlying theory
    constraints that cannot be simultaneously satisfied.

    In the FDE application (CipherRescue), Aᵢ is the subset of anomaly
    signals explained by failure modes Rᵢ.
    """
    covering_set: FrozenSet[Signal]
    reason_set: FrozenSet[Reason]

    def __repr__(self) -> str:
        a = {s.name for s in self.covering_set}
        r = {r.name for r in self.reason_set}
        return f"CoveringPair(A={a}, R={r})"


# ---------------------------------------------------------------------------
# SCPR Instance
# ---------------------------------------------------------------------------

@dataclass
class SCPRInstance:
    """
    A complete SCPR instance (U, R, E) as per Definition 1.5.3.

    Attributes:
        universe:       U — the set of all anomaly signals to be covered.
        reasons:        R — the set of all failure mode hypotheses.
        covering_pairs: E — the list of (Aᵢ, Rᵢ) pairs.
        costs:          Optional cost vector c(ρⱼ) for weighted SCPR.
                        Defaults to uniform unit cost if not provided.
    """
    universe: FrozenSet[Signal]
    reasons: FrozenSet[Reason]
    covering_pairs: list[CoveringPair]
    costs: dict[Reason, float] = field(default_factory=dict)

    def __post_init__(self) -> None:
        # Default to unit cost for all reasons not explicitly costed.
        for r in self.reasons:
            self.costs.setdefault(r, 1.0)

    @property
    def n(self) -> int:
        """Cardinality of the universe |U|."""
        return len(self.universe)

    @property
    def r(self) -> int:
        """Cardinality of the reason set |R|."""
        return len(self.reasons)

    @property
    def m(self) -> int:
        """Number of covering pairs |E|."""
        return len(self.covering_pairs)

    def is_feasible(self) -> bool:
        """
        Return True iff the union of all covering sets equals U.

        An infeasible instance has signals that no covering pair explains,
        regardless of which reasons are selected.  The diagnostic engine
        reports uncovered signals as anomalies requiring operator review.
        """
        covered: set[Signal] = set()
        for pair in self.covering_pairs:
            covered |= pair.covering_set
        return covered >= self.universe


# ---------------------------------------------------------------------------
# SCPR Solution
# ---------------------------------------------------------------------------

@dataclass
class SCPRSolution:
    """
    The output of the SCPR solver for a given instance.

    Attributes:
        instance:           The instance that was solved.
        optimal_reasons:    S* ⊆ R — the minimal reason set.
        objective_value:    Σ c(ρⱼ) for ρⱼ ∈ S*.
        lp_lower_bound:     OPT(LP relaxation) — certifies optimality gap.
        dual_weights:       y*ⱼ — LP dual variables used as evidence weights.
        uncovered_signals:  Signals not explained by any pair with Rᵢ ⊆ S*.
        solver_phase:       Which phase of Algorithm 5.1 produced the solution.
                            'reduction' | 'lp' | 'enumeration'
        reduced_instance:   The instance after Beasley reduction (may differ
                            from the original if reduction was applied).
    """
    instance: SCPRInstance
    optimal_reasons: FrozenSet[Reason]
    objective_value: float
    lp_lower_bound: float
    dual_weights: dict[Reason, float]
    uncovered_signals: FrozenSet[Signal]
    solver_phase: str
    reduced_instance: SCPRInstance | None = None

    @property
    def duality_gap(self) -> float:
        """OPT(ILP) - OPT(LP). Zero certifies LP-optimal solution."""
        return self.objective_value - self.lp_lower_bound

    @property
    def is_optimal(self) -> bool:
        """True iff duality gap is zero (LP relaxation is tight)."""
        return abs(self.duality_gap) < 1e-9

    def __repr__(self) -> str:
        reasons = {r.name for r in self.optimal_reasons}
        return (
            f"SCPRSolution(reasons={reasons}, "
            f"obj={self.objective_value:.4f}, "
            f"gap={self.duality_gap:.4f}, "
            f"phase={self.solver_phase!r})"
        )
