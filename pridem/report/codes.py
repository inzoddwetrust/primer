"""Exit codes of pridem verdicts and their aggregation.

``0`` -- done, ``1`` -- failed, ``2`` -- done in part (``report.incomplete`` is
not empty). Across several results the worst wins: ``1 > 2 > 0``.
This module imports only the standard library.
"""

from collections.abc import Iterable
from enum import IntEnum


class ExitCode(IntEnum):
    """Exit code of a pridem command."""

    OK = 0
    FAILED = 1
    INCOMPLETE = 2


_SEVERITY = {ExitCode.OK: 0, ExitCode.INCOMPLETE: 1, ExitCode.FAILED: 2}


def worst(codes: Iterable[int]) -> ExitCode:
    """Return the worst of ``codes`` by ``1 > 2 > 0``.

    An empty input is an error, not ``0``: nothing ran, so there is no verdict.
    A code outside ``0, 1, 2`` is an error.
    """
    parsed = [ExitCode(code) for code in codes]
    if not parsed:
        raise ValueError("worst() of no codes: nothing ran, there is no verdict")
    return max(parsed, key=_SEVERITY.__getitem__)
