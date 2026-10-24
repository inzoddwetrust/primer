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


# --- codes of reasons and of incomplete entries (contract 2 v1.6 section 1) ---

REASON_CODES: dict[str, tuple[str, ...]] = {
    "role": ("role",),
    "after-failure": ("phase", "stack", "name"),
    "after-interrupt": (),
    "interrupted": (),
    "no-fact": (),
    "command-failed": ("argv", "exit_code"),
    "command-timed-out": ("argv", "timeout_s"),
    "command-not-started": ("argv", "errno"),
    "exception": ("type",),
}
"""Machine codes of ``steps[].reason`` -> their parameters; the list is closed."""

INCOMPLETE_CODES: dict[str, tuple[str, ...]] = {
    "run/no-verdict": ("ended_at",),
    "run/journal-damaged": ("line",),
    "journal/write-failed": (),
    "journal/quarantined": ("run_id",),
    "state/quarantined": (),
    "restore/needed": (),
}
"""Machine ``what/code`` of ``report.incomplete[]`` -> parameters; closed."""

SKIPPED_AFTER = frozenset({"after-failure", "after-interrupt"})
"""Reason codes of a step skipped because the ladder had stopped."""

STEP_CODE = r"^[a-z][a-z0-9_]*:[a-z][a-z0-9-]*$"
"""A step's code: ``<step>:<code>``; its text comes with the step."""

LOCAL_CODE = r"^[a-z][a-z0-9-]*$"
"""A code as a step declares it, before the machine prefixes the step name."""

RESERVED_PARAMS = frozenset({"code", "what"})


def catalog_key(code: str, what: str | None = None) -> str:
    """The catalog key of a code: a step code itself, ``what/code`` for the
    machine's incomplete entries, the code for the machine's reasons."""
    if what is None or ":" in code:
        return code
    return f"{what}/{code}"
