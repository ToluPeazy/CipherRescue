"""
Unit tests — Layer 5: LP solver (relaxation and ILP).

Tests verify correctness of:
    - LP relaxation (dual variables, lower bound)
    - ILP solve via thesis linearisation
    - AND-conjunction handling for multi-reason pairs
"""

from __future__ import annotations

import pytest

from cipherrescue.scpr._thesis_instance import from_instance
from cipherrescue.scpr.lp_solver import solve_ilp, solve_lp
from cipherrescue.scpr.types import CoveringPair, Reason, SCPRInstance, Signal


class TestLPRelaxation:

    def test_minimal_instance_feasible(self, minimal_instance):
        result = solve_lp(minimal_instance)
        assert result.is_optimal
        assert result.objective >= 0.0

    def test_lp_lower_bounds_integer(self, minimal_instance):
        """LP optimal ≤ ILP optimal (relaxation is a lower bound)."""
        lp = solve_lp(minimal_instance)
        ilp = solve_ilp(from_instance(minimal_instance))
        assert lp.objective <= ilp.objective_value + 1e-9

    def test_single_essential_lp(self, single_essential_instance):
        lp = solve_lp(single_essential_instance)
        assert lp.is_optimal
        assert lp.objective >= 0.0

    def test_dual_variables_nonnegative(self, minimal_instance):
        """Dual variables y* ≥ 0 (dual feasibility)."""
        lp = solve_lp(minimal_instance)
        for val in lp.dual_weights().values():
            assert val >= -1e-9, f"Negative dual: {val}"

    def test_dual_weights_dict_keys(self, minimal_instance,
                                    sig_smart_realloc, sig_header_absent):
        lp = solve_lp(minimal_instance)
        weights = lp.dual_weights()
        assert sig_smart_realloc in weights
        assert sig_header_absent in weights

    def test_empty_instance(self):
        inst = SCPRInstance(
            universe=frozenset(), reasons=frozenset(), covering_pairs=[],
        )
        result = solve_lp(inst)
        assert result.objective == 0.0
        assert result.is_optimal

    def test_lp_objective_monotone_cost(self):
        """Doubling all costs doubles the LP objective."""
        sig = Signal("s")
        r = Reason("r")
        pairs = [CoveringPair(frozenset([sig]), frozenset([r]))]
        inst1 = SCPRInstance(frozenset([sig]), frozenset([r]), pairs, costs={r: 1.0})
        inst2 = SCPRInstance(frozenset([sig]), frozenset([r]), pairs, costs={r: 2.0})
        lp1 = solve_lp(inst1)
        lp2 = solve_lp(inst2)
        assert abs(lp2.objective - 2 * lp1.objective) < 1e-9


class TestILP:

    def test_minimal_instance_solved(self, minimal_instance,
                                     reason_disk_failure, reason_header_overwrite):
        A = from_instance(minimal_instance)
        result = solve_ilp(A)
        assert result.is_optimal
        assert reason_disk_failure in result.selected_reasons
        assert reason_header_overwrite in result.selected_reasons

    def test_empty_instance(self):
        inst = SCPRInstance(
            universe=frozenset(), reasons=frozenset(), covering_pairs=[],
        )
        A = from_instance(inst)
        result = solve_ilp(A)
        assert result.objective_value == 0.0
        assert result.selected_reasons == []

    def test_ilp_covers_universe(self, minimal_instance):
        A = from_instance(minimal_instance)
        result = solve_ilp(A)
        covered: set[Signal] = set()
        for pair in minimal_instance.covering_pairs:
            if pair.reason_set <= frozenset(result.selected_reasons):
                covered |= pair.covering_set
        assert covered >= minimal_instance.universe


class TestMultiReasonLinearisation:
    """
    Tests specifically for the AND-conjunction linearisation.
    These would FAIL with the naive incorrect LP formulation where
    A[i,j]=1 for any single reason in a multi-reason pair.
    """

    def test_multi_reason_pair_requires_both(self):
        """
        Signal s1 is covered ONLY by pair ([s1], [r1, r2]) — requires BOTH.
        Selecting only r1 should NOT cover s1.
        The ILP must select both r1 and r2.
        """
        s1 = Signal("s1")
        r1, r2 = Reason("r1"), Reason("r2")

        inst = SCPRInstance(
            universe=frozenset([s1]),
            reasons=frozenset([r1, r2]),
            covering_pairs=[
                CoveringPair(frozenset([s1]), frozenset([r1, r2])),
            ],
        )
        A = from_instance(inst)
        result = solve_ilp(A)
        # Both reasons must be selected to cover s1
        assert r1 in result.selected_reasons
        assert r2 in result.selected_reasons

    def test_three_reason_pair(self):
        """Signal covered by a pair requiring three reasons — all three selected."""
        s1 = Signal("s1")
        r1, r2, r3 = Reason("r1"), Reason("r2"), Reason("r3")

        inst = SCPRInstance(
            universe=frozenset([s1]),
            reasons=frozenset([r1, r2, r3]),
            covering_pairs=[
                CoveringPair(frozenset([s1]), frozenset([r1, r2, r3])),
            ],
        )
        A = from_instance(inst)
        result = solve_ilp(A)
        assert {r1, r2, r3} <= frozenset(result.selected_reasons)

    def test_single_reason_alternative_chosen(self):
        """
        Two paths to cover s1:
            Path A: pair ([s1], [r1, r2])  — costs 2
            Path B: pair ([s1], [r3])      — costs 1
        ILP should prefer Path B.
        """
        s1 = Signal("s1")
        r1, r2, r3 = Reason("r1"), Reason("r2"), Reason("r3")

        inst = SCPRInstance(
            universe=frozenset([s1]),
            reasons=frozenset([r1, r2, r3]),
            covering_pairs=[
                CoveringPair(frozenset([s1]), frozenset([r1, r2])),
                CoveringPair(frozenset([s1]), frozenset([r3])),
            ],
        )
        A = from_instance(inst)
        result = solve_ilp(A)
        # r3 alone is cheaper — it should be selected
        assert r3 in result.selected_reasons
        assert result.objective_value == 1.0
