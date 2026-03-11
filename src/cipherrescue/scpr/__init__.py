"""Layer 5 — SCPR Diagnostic Engine."""

from .engine import SCPRSolver
from .file_handler import (
    SCPR_reader,
    SCPR_reader_CDCAC,
    load_benchmark_instance,
    to_scpr_instance,
)
from .lp_solver import ILPResult, LPResult, solve_ilp, solve_lp
from .reduction import ReductionResult, apply_structural_reduction, beasley_reduction
from .types import CoveringPair, Reason, SCPRInstance, SCPRSolution, Signal

__all__ = [
    # Types
    "SCPRSolver",
    "SCPRInstance",
    "SCPRSolution",
    "CoveringPair",
    "Reason",
    "Signal",
    # Solvers
    "solve_lp",
    "solve_ilp",
    "LPResult",
    "ILPResult",
    # Reduction
    "apply_structural_reduction",
    "beasley_reduction",
    "ReductionResult",
    # File I/O
    "SCPR_reader",
    "SCPR_reader_CDCAC",
    "to_scpr_instance",
    "load_benchmark_instance",
]
