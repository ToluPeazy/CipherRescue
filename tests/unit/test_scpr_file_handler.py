"""
Unit tests — Layer 5: file handler (SCPR_File_Handler port).
"""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from cipherrescue.scpr.file_handler import (
    SCPR_reader,
    SCPR_reader_CDCAC,
    to_scpr_instance,
)
from cipherrescue.scpr.types import Signal, Reason


NUMERIC_INSTANCE = """\
3
3
3
1
1
1
1
1
2
1
2
1
3
1
3
"""

CDCAC_INSTANCE = """\
U = {1, 2, 3}
R = {1, 2, 3}
E = [([1], [1]), ([2], [2]), ([3], [3])]
S = [1, 2, 3]
"""


class TestSCPRReader:

    def test_reads_numeric_format(self, tmp_path):
        f = tmp_path / "instance.txt"
        f.write_text(NUMERIC_INSTANCE)
        U, R, E = SCPR_reader(f)
        assert len(E) == 3
        assert isinstance(U, list)
        assert isinstance(R, list)

    def test_u_r_derived_from_e(self, tmp_path):
        f = tmp_path / "instance.txt"
        f.write_text(NUMERIC_INSTANCE)
        U, R, E = SCPR_reader(f)
        # All elements in U should appear in at least one pair's universe subset
        for u in U:
            assert any(u in e[0] for e in E)


class TestSCPRReaderCDCAC:

    def test_reads_cdcac_format(self, tmp_path):
        f = tmp_path / "instance.txt"
        f.write_text(CDCAC_INSTANCE)
        U, R, E, S = SCPR_reader_CDCAC(f)
        assert sorted(U) == [1, 2, 3]
        assert sorted(R) == [1, 2, 3]
        assert len(E) == 3
        assert sorted(S) == [1, 2, 3]


class TestToSCPRInstance:

    def test_converts_to_typed_instance(self):
        U = [1, 2]
        R = [1, 2]
        E = [[[1], [1]], [[2], [2]]]
        inst = to_scpr_instance(U, R, E)
        assert len(inst.universe) == 2
        assert len(inst.reasons) == 2
        assert len(inst.covering_pairs) == 2

    def test_signal_names(self):
        U, R, E = [1], [1], [[[1], [1]]]
        inst = to_scpr_instance(U, R, E)
        names = {s.name for s in inst.universe}
        assert "s1" in names

    def test_reason_names(self):
        U, R, E = [1], [1], [[[1], [1]]]
        inst = to_scpr_instance(U, R, E)
        names = {r.name for r in inst.reasons}
        assert "r1" in names

    def test_default_unit_costs(self):
        U, R, E = [1], [1], [[[1], [1]]]
        inst = to_scpr_instance(U, R, E)
        for cost in inst.costs.values():
            assert cost == 1.0

    def test_custom_costs(self):
        U, R, E = [1], [1], [[[1], [1]]]
        inst = to_scpr_instance(U, R, E, costs={1: 3.5})
        cost_vals = list(inst.costs.values())
        assert 3.5 in cost_vals

    def test_is_feasible(self):
        U, R, E = [1, 2], [1, 2], [[[1], [1]], [[2], [2]]]
        inst = to_scpr_instance(U, R, E)
        assert inst.is_feasible()
