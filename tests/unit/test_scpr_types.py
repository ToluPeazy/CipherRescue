"""
Unit tests — Layer 5: SCPR types and instance properties.
"""

from __future__ import annotations

import pytest

from cipherrescue.scpr.types import (
    CoveringPair,
    SCPRInstance,
    Signal,
)


class TestSignal:
    def test_frozen(self, sig_smart_realloc):
        with pytest.raises((AttributeError, TypeError)):
            sig_smart_realloc.name = "changed"  # type: ignore[misc]

    def test_equality(self):
        s1 = Signal("foo")
        s2 = Signal("foo")
        assert s1 == s2

    def test_repr(self):
        assert "smart_reallocated" in repr(Signal("smart_reallocated_sectors"))


class TestReason:
    def test_default_weight_none(self, reason_disk_failure):
        assert reason_disk_failure.evidence_weight is None

    def test_frozen(self, reason_disk_failure):
        with pytest.raises((AttributeError, TypeError)):
            reason_disk_failure.name = "changed"  # type: ignore[misc]


class TestCoveringPair:
    def test_covering_and_reason_sets(self, sig_smart_realloc, reason_disk_failure):
        pair = CoveringPair(
            covering_set=frozenset([sig_smart_realloc]),
            reason_set=frozenset([reason_disk_failure]),
        )
        assert sig_smart_realloc in pair.covering_set
        assert reason_disk_failure in pair.reason_set

    def test_repr(self, sig_smart_realloc, reason_disk_failure):
        pair = CoveringPair(
            covering_set=frozenset([sig_smart_realloc]),
            reason_set=frozenset([reason_disk_failure]),
        )
        r = repr(pair)
        assert "smart_reallocated" in r
        assert "disk_failure" in r


class TestSCPRInstance:
    def test_dimensions(self, minimal_instance):
        assert minimal_instance.n == 2
        assert minimal_instance.r == 2
        assert minimal_instance.m == 3

    def test_default_unit_costs(
        self, minimal_instance, reason_disk_failure, reason_header_overwrite
    ):
        assert minimal_instance.costs[reason_disk_failure] == 1.0
        assert minimal_instance.costs[reason_header_overwrite] == 1.0

    def test_feasible_instance(self, minimal_instance):
        assert minimal_instance.is_feasible() is True

    def test_infeasible_instance(self, infeasible_instance):
        assert infeasible_instance.is_feasible() is False

    def test_single_essential_feasible(self, single_essential_instance):
        assert single_essential_instance.is_feasible() is True

    def test_custom_costs(self, sig_smart_realloc, reason_disk_failure):
        u = frozenset([sig_smart_realloc])
        r = frozenset([reason_disk_failure])
        pairs = [
            CoveringPair(
                frozenset([sig_smart_realloc]), frozenset([reason_disk_failure])
            )
        ]
        inst = SCPRInstance(u, r, pairs, costs={reason_disk_failure: 5.0})
        assert inst.costs[reason_disk_failure] == 5.0
