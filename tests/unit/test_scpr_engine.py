"""
Unit tests — Layer 5: SCPR engine (Algorithm 5.1 end-to-end).
"""

from __future__ import annotations

import pytest

from cipherrescue.scpr.engine import SCPRSolver
from cipherrescue.scpr.types import CoveringPair, Reason, SCPRInstance, Signal


@pytest.fixture
def solver() -> SCPRSolver:
    return SCPRSolver()


class TestSCPRSolverCorrectness:
    def test_single_essential_solved(
        self, solver, single_essential_instance, reason_partial_encryption
    ):
        sol = solver.solve(single_essential_instance)
        assert reason_partial_encryption in sol.optimal_reasons

    def test_minimal_instance_covers_universe(self, solver, minimal_instance):
        sol = solver.solve(minimal_instance)
        covered: set[Signal] = set()
        for pair in minimal_instance.covering_pairs:
            if pair.reason_set <= sol.optimal_reasons:
                covered |= pair.covering_set
        assert covered >= minimal_instance.universe

    def test_objective_non_negative(self, solver, minimal_instance):
        sol = solver.solve(minimal_instance)
        assert sol.objective_value >= 0.0

    def test_lp_lower_bound_respected(self, solver, minimal_instance):
        sol = solver.solve(minimal_instance)
        assert sol.objective_value >= sol.lp_lower_bound - 1e-9

    def test_infeasible_reports_uncovered(
        self, solver, infeasible_instance, sig_keyslot_invalid
    ):
        sol = solver.solve(infeasible_instance)
        assert sig_keyslot_invalid in sol.uncovered_signals

    def test_empty_instance(self, solver):
        inst = SCPRInstance(
            universe=frozenset(),
            reasons=frozenset(),
            covering_pairs=[],
        )
        sol = solver.solve(inst)
        assert sol.objective_value == 0.0
        assert not sol.optimal_reasons

    def test_dual_weights_populated(self, solver, minimal_instance):
        sol = solver.solve(minimal_instance)
        assert isinstance(sol.dual_weights, dict)

    def test_solution_repr(self, solver, single_essential_instance):
        sol = solver.solve(single_essential_instance)
        r = repr(sol)
        assert "SCPRSolution" in r
        assert "phase=" in r

    def test_duality_gap_non_negative(self, solver, minimal_instance):
        sol = solver.solve(minimal_instance)
        assert sol.duality_gap >= -1e-9


class TestSCPRSolverMultiReason:
    """Correctness tests for the AND-conjunction linearisation path."""

    def test_multi_reason_pair_both_selected(self, solver):
        """Signal covered only by a 2-reason pair — engine must select both."""
        s1 = Signal("s1")
        r1, r2 = Reason("r1"), Reason("r2")
        inst = SCPRInstance(
            universe=frozenset([s1]),
            reasons=frozenset([r1, r2]),
            covering_pairs=[CoveringPair(frozenset([s1]), frozenset([r1, r2]))],
        )
        sol = solver.solve(inst)
        covered: set[Signal] = set()
        for pair in inst.covering_pairs:
            if pair.reason_set <= sol.optimal_reasons:
                covered |= pair.covering_set
        assert s1 in covered


class TestSCPRSolverScaling:
    def test_ten_signals_ten_reasons(self, solver):
        """Diagonal instance — all 10 reasons are essential."""
        signals = [Signal(f"s{i}") for i in range(10)]
        reasons = [Reason(f"r{i}") for i in range(10)]
        pairs = [
            CoveringPair(frozenset([signals[i]]), frozenset([reasons[i]]))
            for i in range(10)
        ]
        inst = SCPRInstance(
            universe=frozenset(signals),
            reasons=frozenset(reasons),
            covering_pairs=pairs,
        )
        sol = solver.solve(inst)
        assert len(sol.optimal_reasons) == 10
        assert sol.uncovered_signals == frozenset()
