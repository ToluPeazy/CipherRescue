"""
Layer 5 — SCPR Diagnostic Engine: Main Solver (Algorithm 5.1).

Orchestrates the full SCPR solve pipeline:

    Phase 1 — Beasley reduction    (reduction.py — adapted from thesis)
    Phase 2 — ILP solve             (lp_solver.solve_ilp — adapted from thesis)
    Phase 3 — LP relaxation         (lp_solver.solve_lp — for dual/evidence weights)

The Beasley + ILP combination matches the architecture of beaseley_scpr() in
the thesis, which reduces first and then dispatches to SCPR_Linearized.

For CipherRescue, the LP relaxation is additionally run to extract dual
variables y* that serve as interpretable evidence weights in the FailureReport.

References:
    Babatunde (2025). PhD Thesis, Coventry University. §3, §5.
    Babatunde, England & Sadeghimanesh (2026). arXiv:2601.14424.
"""

from __future__ import annotations

import logging

from ._thesis_instance import from_instance
from .lp_solver import ILPResult, LPResult, solve_ilp, solve_lp
from .reduction import apply_structural_reduction
from .types import Reason, SCPRInstance, SCPRSolution, Signal

logger = logging.getLogger(__name__)


class SCPRSolver:
    """
    Solver for the Set Covering Problem with Reasons.

    Usage::

        solver = SCPRSolver()
        solution = solver.solve(instance)
        print(solution.optimal_reasons)
        print(solution.dual_weights)  # LP evidence weights
    """

    def solve(self, instance: SCPRInstance) -> SCPRSolution:
        """
        Solve the SCPR instance via Beasley reduction + ILP + LP duals.

        Algorithm:
            1. Beasley reduction — fixes essential reasons, removes dominated pairs.
            2. If fully resolved: LP relaxation on original for dual weights.
            3. Otherwise: exact ILP on reduced instance (thesis formulation).
            4. LP relaxation on reduced instance for dual weights.
            5. Merge forced + ILP reasons into final solution.

        Args:
            instance: Typed SCPRInstance.

        Returns:
            SCPRSolution with optimal reasons and LP dual evidence weights.
        """
        logger.info(
            "SCPRSolver.solve: |U|=%d, |R|=%d, |E|=%d",
            instance.n,
            instance.r,
            instance.m,
        )

        if not instance.is_feasible():
            uncovered = instance.universe - _covered_by_any(instance)
            logger.warning("Instance has %d uncoverable signals", len(uncovered))

        # ── Phase 1: Beasley reduction ───────────────────────────────────────
        reduction = apply_structural_reduction(instance)
        fixed_in = set(reduction.fixed_in)
        reduced = reduction.reduced_instance

        if reduction.is_fully_resolved:
            logger.info("Fully resolved by Beasley reduction.")
            lp = _lp_with_fallback(instance)
            return self._build_solution(
                instance=instance,
                selected=frozenset(fixed_in),
                lp_lower_bound=lp.objective,
                dual_weights=lp.dual_weights(),
                phase="reduction",
                reduced_instance=reduced,
            )

        # ── Phase 2: ILP solve on reduced instance ───────────────────────────
        A_reduced = from_instance(reduced)

        try:
            ilp: ILPResult = solve_ilp(A_reduced)
        except ValueError as exc:
            logger.error("ILP failed: %s — falling back to greedy", exc)
            greedy = _greedy_cover(reduced)
            fixed_in |= greedy
            lp = _lp_with_fallback(instance)
            return self._build_solution(
                instance=instance,
                selected=frozenset(fixed_in),
                lp_lower_bound=lp.objective,
                dual_weights=lp.dual_weights(),
                phase="greedy",
                reduced_instance=reduced,
            )

        fixed_in |= set(ilp.selected_reasons)

        # ── Phase 3: LP relaxation for dual/evidence weights ─────────────────
        lp = _lp_with_fallback(instance)

        return self._build_solution(
            instance=instance,
            selected=frozenset(fixed_in),
            lp_lower_bound=lp.objective,
            dual_weights=lp.dual_weights(),
            phase="ilp" if ilp.is_optimal else "ilp_approx",
            reduced_instance=reduced,
        )

    # ── Internal helpers ─────────────────────────────────────────────────────

    def _build_solution(
        self,
        instance: SCPRInstance,
        selected: frozenset[Reason],
        lp_lower_bound: float,
        dual_weights: dict[Signal, float],
        phase: str,
        reduced_instance: SCPRInstance | None,
    ) -> SCPRSolution:
        """Assemble a typed SCPRSolution from solver state."""
        objective = sum(instance.costs.get(r, 1.0) for r in selected)

        covered: set[Signal] = set()
        for pair in instance.covering_pairs:
            if pair.reason_set <= selected:
                covered |= pair.covering_set
        uncovered = instance.universe - covered

        # Reason-level evidence weights: sum of duals of signals covered by
        # each reason.
        reason_duals: dict[Reason, float] = {}
        for reason in selected:
            w = sum(
                dual_weights.get(sig, 0.0)
                for pair in instance.covering_pairs
                if reason in pair.reason_set
                for sig in pair.covering_set
            )
            reason_duals[reason] = w

        return SCPRSolution(
            instance=instance,
            optimal_reasons=selected,
            objective_value=objective,
            lp_lower_bound=lp_lower_bound,
            dual_weights=reason_duals,
            uncovered_signals=frozenset(uncovered),
            solver_phase=phase,
            reduced_instance=reduced_instance,
        )


# ─────────────────────────────────────────────────────────────────────────────
# Module-level helpers
# ─────────────────────────────────────────────────────────────────────────────


def _lp_with_fallback(instance: SCPRInstance) -> LPResult:
    """Attempt LP relaxation; return zero-dual result on failure."""
    try:
        return solve_lp(instance)
    except (ValueError, Exception) as exc:  # noqa: BLE001
        logger.warning("LP relaxation failed (%s) — using zero duals", exc)
        import numpy as np

        from .lp_solver import LPResult

        return LPResult(
            primal=np.array([]),
            dual=np.array([]),
            objective=0.0,
            is_optimal=False,
            reason_order=[],
            signal_order=[],
        )


def _covered_by_any(instance: SCPRInstance) -> set[Signal]:
    """Signals covered by at least one pair in the instance."""
    covered: set[Signal] = set()
    for pair in instance.covering_pairs:
        covered |= pair.covering_set
    return covered


def _greedy_cover(instance: SCPRInstance) -> frozenset[Reason]:
    """Greedy fallback when ILP fails."""
    covered: set[Signal] = set()
    selected: set[Reason] = set()
    remaining = set(instance.reasons)

    while covered < instance.universe and remaining:
        best: Reason | None = None
        best_ratio = -1.0
        for reason in remaining:
            new: set[Signal] = set()
            for pair in instance.covering_pairs:
                if reason in pair.reason_set:
                    new |= pair.covering_set - covered
            cost = instance.costs.get(reason, 1.0)
            ratio = len(new) / max(cost, 1e-12)
            if ratio > best_ratio:
                best_ratio = ratio
                best = reason
        if best is None:
            break
        remaining.discard(best)
        selected.add(best)
        for pair in instance.covering_pairs:
            if best in pair.reason_set:
                covered |= pair.covering_set

    return frozenset(selected)
