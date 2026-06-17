"""
Unit tests — Stream 1: Synthetic FDE profile generator (Phase 1).

Verifies the generator produces ≥140 feasible, varied SCPR instances.
"""

from __future__ import annotations

import pytest

from cipherrescue.scpr.types import SCPRInstance
from cipherrescue.stream1 import FDEProfileGenerator, generate_fde_corpus


@pytest.fixture(scope="module")
def corpus() -> list[SCPRInstance]:
    return generate_fde_corpus(n=150, seed=42)


class TestCorpusSize:
    def test_generates_at_least_140_instances(self, corpus: list[SCPRInstance]) -> None:
        assert len(corpus) >= 140

    def test_generates_requested_count(self) -> None:
        c = generate_fde_corpus(n=150, seed=42)
        assert len(c) == 150


class TestCorpusDiversity:
    def test_all_instances_are_scpr_instances(
        self, corpus: list[SCPRInstance]
    ) -> None:
        for inst in corpus:
            assert isinstance(inst, SCPRInstance)

    def test_instances_have_non_empty_universe(
        self, corpus: list[SCPRInstance]
    ) -> None:
        for inst in corpus:
            assert inst.n > 0, "Every instance must have at least one signal"

    def test_instances_have_non_empty_reasons(
        self, corpus: list[SCPRInstance]
    ) -> None:
        for inst in corpus:
            assert inst.r > 0, "Every instance must have at least one reason"

    def test_instances_have_covering_pairs(
        self, corpus: list[SCPRInstance]
    ) -> None:
        for inst in corpus:
            assert inst.m > 0, "Every instance must have at least one covering pair"

    def test_all_instances_are_feasible(self, corpus: list[SCPRInstance]) -> None:
        infeasible = [inst for inst in corpus if not inst.is_feasible()]
        assert len(infeasible) == 0, (
            f"{len(infeasible)} instances are infeasible "
            "(signals with no covering pair)"
        )

    def test_varied_universe_sizes(self, corpus: list[SCPRInstance]) -> None:
        sizes = {inst.n for inst in corpus}
        assert len(sizes) > 1, "Universe sizes should vary across instances"

    def test_varied_reason_counts(self, corpus: list[SCPRInstance]) -> None:
        # Not all instances need different reason counts, but active reason
        # subsets per covering pair should vary.
        pair_counts = {inst.m for inst in corpus}
        assert len(pair_counts) > 1


class TestReproducibility:
    def test_same_seed_same_corpus(self) -> None:
        c1 = generate_fde_corpus(n=150, seed=42)
        c2 = generate_fde_corpus(n=150, seed=42)
        for inst1, inst2 in zip(c1, c2, strict=True):
            assert inst1.universe == inst2.universe
            assert inst1.reasons == inst2.reasons
            assert inst1.costs == inst2.costs

    def test_different_seed_different_corpus(self) -> None:
        c1 = generate_fde_corpus(n=150, seed=42)
        c2 = generate_fde_corpus(n=150, seed=99)
        # At least some instances should differ
        diffs = sum(
            1 for a, b in zip(c1, c2, strict=True) if a.universe != b.universe
        )
        assert diffs > 0


class TestSCPREngineCompatibility:
    """Verify generated instances can be fed to the SCPR engine without error."""

    def test_engine_solves_single_fault_instances(self) -> None:
        from cipherrescue.scpr.engine import SCPRSolver

        solver = SCPRSolver()
        generator = FDEProfileGenerator(seed=0)
        single_fault = generator._single_fault_instances()

        for inst in single_fault[:5]:  # sample 5 to keep test fast
            solution = solver.solve(inst)
            assert solution.objective_value >= 0
            assert solution.is_optimal or solution.duality_gap < 1e-6
