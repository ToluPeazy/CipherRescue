"""
Non-singleton reason prefix extraction.

Direct port of Extract_Reasons.py from:
    Babatunde, A.T. (2025). PhD Thesis, Coventry University.

The function generates all non-singleton prefixes of reason lists in the
combined set E.  These prefixes are the auxiliary variables T introduced
when linearising AND-conjunctions in the ILP formulation (see lp_solver.py).

Example:
    If E contains a pair with reason_set [r1, r2, r3], the function adds
    [r1, r2] and [r1, r2, r3] to T (the prefix [r1] is a singleton and
    is omitted because it needs no auxiliary variable).
"""

from __future__ import annotations


def non_single_reason(combined_set: list[list]) -> list:
    """
    Return all non-singleton reason-list prefixes appearing in combined_set.

    Args:
        combined_set: E — list of [covering_subset, reason_list] pairs.

    Returns:
        List of non-singleton prefixes (each is a list of Reason objects),
        in the order first encountered, without duplicates.

    Adapted from Extract_Reasons.py (Babatunde, 2025).
    """
    non_singleton: list = []

    for i in range(len(combined_set)):
        for j in range(1, len(combined_set[i][1])):
            prefix = combined_set[i][1][: j + 1]
            if prefix not in non_singleton:
                non_singleton.append(prefix)

    return non_singleton
