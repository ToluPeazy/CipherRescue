"""
Layer 5 — SCPR Diagnostic Engine: File Handler.

Adapted from SCPR_File_Handler.py:
    Babatunde, A.T. (2025). PhD Thesis, Coventry University.

Two benchmark formats are supported:

    1. Numeric SCPR format  (SCPR_reader)
       Used for the Babatunde (2025) synthetic benchmark dataset:
           Zenodo: 10.5281/zenodo.15326494
       Line structure:
           |U|
           |R|
           |E|
           [|A_i| / A_i / |R_i| / R_i]  × |E|

    2. CDCAC key=value format  (SCPR_reader_CDCAC)
       Used for CDCAC instances from the arXiv paper:
           Babatunde, England & Sadeghimanesh (2026). arXiv:2601.14424.
       Line structure:
           U = {frozenset of ints}
           R = {frozenset of ints}
           E = [([int,...], [int,...]), ...]
           S = [int, ...]

Both readers return raw (U, R, E) as integer lists.
Use to_scpr_instance() to wrap them in typed CipherRescue objects.
"""

from __future__ import annotations

import ast
import logging
from pathlib import Path

from .types import CoveringPair, Reason, SCPRInstance, Signal

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# Raw readers — direct ports from SCPR_File_Handler.py (Babatunde, 2025)
# ─────────────────────────────────────────────────────────────────────────────


def SCPR_reader(file_name: str | Path) -> tuple[list, list, list]:
    """
    Read a numeric SCPR instance file.

    Direct port from SCPR_File_Handler.py (Babatunde, 2025).
    """
    with open(file_name) as f:
        lines = f.read().split("\n")

    E_len = int(lines[2])
    E: list[list] = []
    i = 3
    while i < len(lines) and len(E) < E_len:
        if lines[i] == "":
            i += 1
            continue
        uni_part = [int(x) for x in lines[i + 1].split(" ")]
        reas_part = [int(x) for x in lines[i + 3].split(" ")]
        E.append([uni_part, reas_part])
        i += 4

    U = sorted({x for entry in E for x in entry[0]})
    R = sorted({x for entry in E for x in entry[1]})
    return U, R, E


def SCPR_reader_CDCAC(file_name: str | Path) -> tuple[list, list, list, list]:
    """
    Read a CDCAC-format SCPR instance file.

    Direct port from SCPR_File_Handler.py (Babatunde, 2025).
    """
    data: dict = {}
    with open(file_name) as f:
        for line in f:
            line = line.strip()
            if not line or "=" not in line:
                continue
            key, value = line.split("=", 1)
            try:
                data[key.strip()] = ast.literal_eval(value.strip())
            except Exception as exc:
                logger.warning("Could not parse key %r: %s", key.strip(), exc)

    U = sorted(data.get("U", set()))
    R = sorted(data.get("R", set()))
    E = [[sorted(p) for p in pair] for pair in data.get("E", [])]
    S = data.get("S", [])
    return U, R, E, S


# ─────────────────────────────────────────────────────────────────────────────
# Type conversion — wrap integer (U, R, E) in CipherRescue types
# ─────────────────────────────────────────────────────────────────────────────


def to_scpr_instance(
    U: list[int],
    R: list[int],
    E: list[list],
    costs: dict[int, float] | None = None,
) -> SCPRInstance:
    """
    Convert integer-based (U, R, E) to a typed SCPRInstance.

    Signal names are 's{n}', Reason names are 'r{n}' where n is the
    integer from the file.
    """
    signal_map = {u: Signal(f"s{u}") for u in U}
    reason_map = {r: Reason(f"r{r}") for r in R}
    cost_map = {reason_map[r]: (costs or {}).get(r, 1.0) for r in R}

    pairs = [
        CoveringPair(
            covering_set=frozenset(signal_map[u] for u in e[0] if u in signal_map),
            reason_set=frozenset(reason_map[r] for r in e[1] if r in reason_map),
        )
        for e in E
    ]

    return SCPRInstance(
        universe=frozenset(signal_map.values()),
        reasons=frozenset(reason_map.values()),
        covering_pairs=pairs,
        costs=cost_map,
    )


def load_benchmark_instance(
    file_name: str | Path,
    fmt: str = "numeric",
    costs: dict[int, float] | None = None,
) -> SCPRInstance:
    """
    Load a benchmark instance file and return a typed SCPRInstance.

    Args:
        file_name: Path to the instance file.
        fmt:       'numeric' (Zenodo benchmark) or 'cdcac' (arXiv instances).
        costs:     Optional per-reason cost override {reason_int: float}.

    Returns:
        Typed SCPRInstance for the diagnostic engine.
    """
    if fmt == "numeric":
        U, R, E = SCPR_reader(file_name)
    elif fmt == "cdcac":
        U, R, E, _ = SCPR_reader_CDCAC(file_name)
    else:
        raise ValueError(f"Unknown format {fmt!r}. Use 'numeric' or 'cdcac'.")
    return to_scpr_instance(U, R, E, costs=costs)


# ─────────────────────────────────────────────────────────────────────────────
# Pickle reader (thesis benchmark .pkl format)
# ─────────────────────────────────────────────────────────────────────────────


def SCPR_reader_pkl(file_name) -> tuple:
    """
    Read a thesis benchmark .pkl file.

    The pkl format stores a 3-element list [U, R, E] where U, R are integer
    lists and E is a list of [universe_subset, reason_subset] integer pairs.

    This format is used by the Babatunde (2025) PhD thesis benchmark dataset
    (SCPR_Data_N.pkl files).

    Args:
        file_name: Path to the .pkl file.

    Returns:
        (U, R, E) — integer lists.
    """
    import pickle

    with open(file_name, "rb") as f:
        data = pickle.load(f)
    if not (isinstance(data, (list, tuple)) and len(data) >= 3):
        raise ValueError(
            f"Expected pkl to contain [U, R, E], got {type(data).__name__} "
            f"with len={len(data) if hasattr(data, '__len__') else '?'}"
        )
    return list(data[0]), list(data[1]), [list(e) for e in data[2]]


def load_pkl_instance(file_name, costs=None):
    """
    Load a thesis benchmark .pkl instance and return a typed SCPRInstance.

    Args:
        file_name: Path to the .pkl file.
        costs:     Optional per-reason cost override {reason_int: float}.

    Returns:
        Typed SCPRInstance for the diagnostic engine.
    """
    U, R, E = SCPR_reader_pkl(file_name)
    return to_scpr_instance(U, R, E, costs=costs)
