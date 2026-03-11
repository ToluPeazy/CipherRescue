"""
Layer 5 — SCPR Diagnostic Engine: LP and ILP Solvers.

The core algorithm is adapted from SCPR_Linearized.py:
    Babatunde, A.T. (2025). PhD Thesis, Coventry University.

─────────────────────────────────────────────────────────────────────────────
CRITICAL DESIGN NOTE — LP linearisation of AND-conjunctions
─────────────────────────────────────────────────────────────────────────────

For a covering pair (Aᵢ, Rᵢ) with |Rᵢ| > 1, signal coverage requires that
ALL reasons in Rᵢ are selected simultaneously (conjunction).  A naive LP
that sets A[i,j]=1 for each individual reason j ∈ Rᵢ is INCORRECT — it
allows a single reason to cover the signal.

The correct formulation introduces auxiliary variables T (non-singleton reason
prefixes) to linearise the AND:

    For each prefix t = [r₁, ..., rₖ] ∈ T (k ≥ 2), introduce yₜ with:
        yₜ  ≤  y_{t[:k-1]}                      (yₜ ≤ AND of first k-1)
        yₜ  ≤  y_{rₖ}                            (yₜ ≤ last reason)
        yₜ  ≥  y_{t[:k-1]} + y_{rₖ} - 1         (yₜ ≥ AND prev + last - 1)

    These three constraints linearise:  yₜ = y_{t[:k-1]} ∧ y_{rₖ}

The covering constraint for u ∈ U uses yₜ (not individual reasons) whenever
the corresponding pair has |Rᵢ| > 1.

This formulation was developed in the thesis for CDCAC instances and proved
correct on the synthetic benchmark (Zenodo: 10.5281/zenodo.15326494).

Two functions are exposed:
    solve_ilp(A)           — exact ILP (integrality=1), returns selected reasons
    solve_lp(instance)     — LP relaxation (no integrality), returns dual vars

References:
    Beasley (1987). EJOR 31(1):85–93.
    Babatunde (2025). PhD Thesis. §5.
    Babatunde, England & Sadeghimanesh (2026). arXiv:2601.14424.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

import numpy as np
import numpy.typing as npt
import scipy.optimize

from ._thesis_instance import ThesisSCPR, from_instance
from .types import Reason, SCPRInstance, Signal

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# Result types
# ─────────────────────────────────────────────────────────────────────────────


@dataclass
class LPResult:
    """
    Result of the LP relaxation solve.

    Attributes:
        primal:       x* — fractional solution, shape [|R| + |T|].
        dual:         y* — duals for the |U| covering constraints.
        objective:    OPT(P-LP) — lower bound.
        is_optimal:   True iff solver status is 0.
        reason_order: R list (columns of primal[:len(R)]).
        signal_order: U list (rows of dual).
    """

    primal: npt.NDArray[np.float64]
    dual: npt.NDArray[np.float64]
    objective: float
    is_optimal: bool
    reason_order: list[Reason]
    signal_order: list[Signal]

    def dual_weights(self) -> dict[Signal, float]:
        """Map each signal to its LP dual variable (evidence weight)."""
        return {s: float(self.dual[i]) for i, s in enumerate(self.signal_order)}

    def reason_dual_weights(self) -> dict[Reason, float]:
        """Map each reason to its LP dual contribution (for Beasley fixing)."""
        # Build a rough contribution: dual weight of each signal that this
        # reason participates in covering (via the covering constraints).
        dw = self.dual_weights()
        out: dict[Reason, float] = {}
        for r in self.reason_order:
            # We don't store the full A matrix; return the sum of all signal
            # duals as a conservative upper bound.
            out[r] = sum(dw.values())
        return out


@dataclass
class ILPResult:
    """
    Result of the exact ILP solve.

    Attributes:
        selected_reasons: Optimal S* (list of Reason objects).
        objective_value:  Σ c(r) for r ∈ S*.
        is_optimal:       True iff solver status is 0.
    """

    selected_reasons: list[Reason]
    objective_value: float
    is_optimal: bool


# ─────────────────────────────────────────────────────────────────────────────
# Shared matrix builder
# ─────────────────────────────────────────────────────────────────────────────


def _build_system(A: ThesisSCPR) -> tuple[list, list, list]:
    """
    Build (c, Aub, Bub) for the linearised SCPR optimisation.

    Variable layout: [y_R₁ ... y_R_{|R|}  y_T₁ ... y_T_{|T|}]

    Constraint layout (Aub @ x ≤ Bub):
        Rows 0..|U|-1:       covering constraints             (Bub = -1)
        Rows |U|+3k+0:       yₜₖ ≤ y_{prev}                  (Bub =  0)
        Rows |U|+3k+1:       yₜₖ ≤ y_{last_r}                (Bub =  0)
        Rows |U|+3k+2:       -yₜₖ + y_{last_r} + y_{prev} ≤ 1 (Bub = 1)

    Adapted from SCPR_Linearized.py (Babatunde, 2025).
    Change from original: variable costs (c[j] = A.costs[R[j]]) instead of 1.
    """
    nR = len(A.R)
    nT = len(A.T)
    nU = len(A.U)

    # Cost vector
    c = [A.costs.get(r, 1.0) for r in A.R] + [0.0] * nT

    # Constraint matrix
    Aub = [[0.0] * (nR + nT) for _ in range(nU + 3 * nT)]

    # Covering constraints
    for i, u in enumerate(A.U):
        for e in A.E:
            if u in e[0]:
                if len(e[1]) == 1:
                    Aub[i][A.R.index(e[1][0])] = -1.0
                else:
                    Aub[i][nR + A.T.index(e[1])] = -1.0

    # AND-linearisation constraints
    for k, t in enumerate(A.T):
        base = nU + 3 * k
        Aub[base + 0][nR + k] = 1.0
        Aub[base + 1][nR + k] = 1.0
        Aub[base + 2][nR + k] = -1.0

        last_idx = A.R.index(t[-1])
        Aub[base + 1][last_idx] = -1.0
        Aub[base + 2][last_idx] = 1.0

        prev = t[:-1]
        if len(prev) == 1:
            prev_idx = A.R.index(prev[0])
            Aub[base + 0][prev_idx] = -1.0
            Aub[base + 2][prev_idx] = 1.0
        else:
            prev_t_idx = A.T.index(prev)
            Aub[base + 0][nR + prev_t_idx] = -1.0
            Aub[base + 2][nR + prev_t_idx] = 1.0

    # RHS
    Bub = [-1.0] * nU
    for _ in range(nT):
        Bub.extend([0.0, 0.0, 1.0])

    return c, Aub, Bub


# ─────────────────────────────────────────────────────────────────────────────
# Public solvers
# ─────────────────────────────────────────────────────────────────────────────


def solve_ilp(A: ThesisSCPR) -> ILPResult:
    """
    Exact ILP solve via HiGHS branch-and-bound (integrality=1).

    Adapted from SCPR_Linearized.py (Babatunde, 2025).
    Changes from original:
        - Variable costs via A.costs (thesis used uniform cost 1).
        - Returns Reason objects instead of 1-indexed integer positions.

    Args:
        A: ThesisSCPR instance.

    Returns:
        ILPResult with selected Reason objects and objective value.
    """
    if not A.U:
        return ILPResult(selected_reasons=[], objective_value=0.0, is_optimal=True)

    c, Aub, Bub = _build_system(A)
    nR = len(A.R)
    nT = len(A.T)
    bounds = [(0.0, 1.0)] * (nR + nT)
    integrality = [1] * (nR + nT)

    result = scipy.optimize.linprog(
        c,
        A_ub=Aub,
        b_ub=Bub,
        bounds=bounds,
        method="highs",
        integrality=integrality,
        options={"disp": False},
    )

    if result.status not in (0, 1):
        raise ValueError(
            f"ILP failed: status={result.status}, message={result.message}"
        )

    x = [round(v, 0) for v in list(result.x)[:nR]]
    selected = [A.R[i] for i in range(nR) if x[i] == 1.0]
    obj = round(result.fun) if result.fun is not None else 0.0

    logger.info(
        "ILP: OPT=%d, selected=%d/%d reasons",
        obj,
        len(selected),
        nR,
    )
    return ILPResult(
        selected_reasons=selected,
        objective_value=float(obj),
        is_optimal=(result.status == 0),
    )


def solve_lp(instance: SCPRInstance) -> LPResult:
    """
    LP relaxation of the SCPR instance (no integrality).

    Public API used by the engine and tests.  Converts SCPRInstance to
    ThesisSCPR, builds the linearised system, and solves without integrality.
    Dual variables of the |U| covering constraints are returned as evidence
    weights for the FailureReport (Beasley, 1987).

    Args:
        instance: Typed SCPRInstance.

    Returns:
        LPResult with primal, dual, and objective.
    """
    if not instance.universe:
        empty: npt.NDArray[np.float64] = np.array([], dtype=np.float64)
        return LPResult(
            primal=empty,
            dual=empty,
            objective=0.0,
            is_optimal=True,
            reason_order=[],
            signal_order=[],
        )

    A = from_instance(instance)
    return _solve_lp_on_thesis(A)


def _solve_lp_on_thesis(A: ThesisSCPR) -> LPResult:
    """
    LP relaxation on a ThesisSCPR instance.

    Internal variant used by both solve_lp() and the Beasley LP-based reduction.
    """
    if not A.U:
        empty: npt.NDArray[np.float64] = np.array([], dtype=np.float64)
        return LPResult(
            primal=empty,
            dual=empty,
            objective=0.0,
            is_optimal=True,
            reason_order=list(A.R),
            signal_order=list(A.U),
        )

    c, Aub, Bub = _build_system(A)
    nR = len(A.R)
    nT = len(A.T)
    bounds = [(0.0, 1.0)] * (nR + nT)

    result = scipy.optimize.linprog(
        c,
        A_ub=Aub,
        b_ub=Bub,
        bounds=bounds,
        method="highs",
        options={"disp": False},
    )

    if result.status not in (0, 1):
        raise ValueError(
            f"LP relaxation failed: status={result.status}, message={result.message}"
        )

    # Extract duals for covering constraints only (first |U| rows).
    # Negate because linprog convention gives non-positive marginals for ≤.
    if hasattr(result, "ineqlin") and result.ineqlin is not None:
        all_m = np.asarray(result.ineqlin.marginals, dtype=np.float64)
        dual = np.clip(-all_m[: len(A.U)], 0.0, None)
    else:
        logger.warning("LP duals unavailable — evidence weights set to zero")
        dual = np.zeros(len(A.U), dtype=np.float64)

    logger.info(
        "LP relaxation: OPT=%.6f, |R|=%d, |U|=%d, |T|=%d",
        result.fun,
        len(A.R),
        len(A.U),
        len(A.T),
    )

    return LPResult(
        primal=np.asarray(result.x, dtype=np.float64),
        dual=dual,
        objective=float(result.fun),
        is_optimal=(result.status == 0),
        reason_order=list(A.R),
        signal_order=list(A.U),
    )
