"""The agent's cursor of ``history/`` (``PRIMER-PANEL-TZ-2`` 9; DM-141, part
B): what of the box's verdicts the Panel holds, so that none is lost while
it is away and none is sent twice after.

``agent/cursor.json`` (0600, written whole by a rename, by the agent alone
under its ``agent.lock``):

- ``through`` -- every run of ``history/`` up to it, by ``run_id``, is held by
  the Panel or given up for good;
- ``held`` -- runs of the window and after ``through`` the Panel holds;
- ``refused`` -- runs of the window and after ``through`` given up, by
  code: ``run-foreign`` and the refusals of the envelope's builder
  (``verdict-reshaped``, ``verdict-damaged``, ``no-verdict``) for good;
  ``unread-<status>`` -- an answer not of contract 4, a Panel behind the
  box (the rule of the release): tried again when the agent starts and once
  a day after (``RETRY_UNREAD_S``).

Pending -- the runs of ``history/`` neither held nor given up (and those
``unread`` when their try is due), after ``through`` or within ``WINDOW_S``
before it. ``through`` moves along ``history/`` in the order of ``run_id``
while the next run is held or given up for good, and never so far that a run
not sent would fall out of the window. A run that died has no verdict until
the next run under the lock -- whose ``recover`` writes it before any newer
verdict (``verbs/run.py``, ``verbs/status.py``): it comes in the order of
``history/`` like any other.

The order of ``run_id`` is the order of runs only to the second: two runs of
one second sort by their random token, and a clock set back gives a later run
an earlier id. So the cursor keeps ``held`` and ``refused`` for the hour
before ``through`` (``WINDOW_S``) and looks there for new runs too; what is
older is dropped -- the file does not grow with ``history/``.

KNOWN CEILING: a run whose id is more than an hour before ``through``.
1. Mechanics: the box's clock set back by more than ``WINDOW_S`` gives a new
   run an id older than the window; the agent takes it as sent.
2. Status: acknowledged by design.
3. Task: none -- the verdict stays in ``history/``; the Panel's view misses it.
4. Trigger: the journal line ``clock-back`` (contract 2, 1.13) of more than
   an hour on a box with an agent.
5. Agreed fix: the cursor keeps the run ids of the clock's step back.
6. Rejected: every held run in the file (it grows with ``history/`` for
   ever); ``mtime`` of the verdicts (a copy or a restore of the box changes
   it).

No file -- no ``through``: the whole history, from the box's birth. A file
that cannot be read is said by the agent and taken as none: the Panel keeps
a verdict once by its ``run_id``.
"""

from datetime import datetime, timedelta
from pathlib import Path

from pydantic import Field, ValidationError

from pridem.contract import Strict
from pridem.files import atomic_write, private_dir
from pridem.identity import agent_dir
from pridem.report.schema import RunId
from pridem.state import HISTORY

CURSOR = "cursor.json"
MODE = 0o600
RETRY_UNREAD_S = 24 * 3600.0
WINDOW_S = 3600.0
"""How far before ``through`` the cursor still looks (see the module)."""
UNREAD = "unread-"
"""The prefix of the codes of answers not of contract 4: not for good."""


def _absent(value: object) -> bool:
    return value is None


class Cursor(Strict):
    """``agent/cursor.json`` (see the module)."""

    through: RunId | None = Field(default=None, exclude_if=_absent)
    held: list[RunId] = []
    refused: dict[RunId, str] = {}


def cursor_path(root: Path) -> Path:
    return agent_dir(root) / CURSOR


class CursorDamaged(Exception):
    """``agent/cursor.json`` cannot be read as a cursor."""


def read_cursor(root: Path) -> Cursor:
    """The cursor; an empty one when there is no file; ``CursorDamaged``."""
    path = cursor_path(root)
    if not path.exists():
        return Cursor()
    try:
        return Cursor.model_validate_json(path.read_bytes())
    except (OSError, ValidationError):
        raise CursorDamaged from None


def write_cursor(root: Path, cursor: Cursor) -> None:
    private_dir(agent_dir(root))
    atomic_write(cursor_path(root), cursor.model_dump_json() + "\n", MODE)


def verdicts(root: Path) -> list[str]:
    """The runs of ``history/``, oldest first."""
    history = root / HISTORY
    return sorted(p.stem for p in history.glob("*.json")) if history.is_dir() else []


def _second(run_id: str) -> datetime:
    """The second a run began: the moment its id starts with."""
    return datetime.strptime(run_id.partition("Z")[0], "%Y-%m-%dT%H:%M:%S")


def _horizon(through: str | None) -> str | None:
    """The oldest id the cursor still looks at: an hour before ``through``."""
    if through is None:
        return None
    return (_second(through) - timedelta(seconds=WINDOW_S)).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )


def pending(root: Path, cursor: Cursor, retry_unread: bool) -> list[str]:
    """The runs to send, oldest first: of the window or after ``through``,
    neither held nor given up -- ``unread`` ones too when their try is due."""
    held = set(cursor.held)
    horizon = _horizon(cursor.through)
    out: list[str] = []
    for run_id in verdicts(root):
        if (horizon is not None and run_id < horizon) or run_id in held:
            continue
        code = cursor.refused.get(run_id)
        if code is None or (retry_unread and code.startswith(UNREAD)):
            out.append(run_id)
    return out


def _settled(cursor: Cursor, run_id: str, held: set[str]) -> bool:
    code = cursor.refused.get(run_id)
    return run_id in held or (code is not None and not code.startswith(UNREAD))


def advanced(root: Path, cursor: Cursor) -> Cursor:
    """``cursor`` with ``through`` moved as far as it goes (see the module)."""
    done = verdicts(root)
    held = set(cursor.held)
    unsettled = [r for r in done if not _settled(cursor, r, held)]
    through = cursor.through
    for run_id in done:
        if through is not None and run_id <= through:
            continue
        if not _settled(cursor, run_id, held):
            break
        horizon = _horizon(run_id)
        if horizon is not None and any(u < horizon for u in unsettled):
            break  # a run not sent would fall out of the window
        through = run_id
    horizon = _horizon(through)

    def kept(run_id: str) -> bool:
        return horizon is None or run_id >= horizon

    data: dict[str, object] = {
        "held": sorted(r for r in held if kept(r)),
        "refused": {r: c for r, c in sorted(cursor.refused.items()) if kept(r)},
    }
    if through is not None:
        data["through"] = through
    return Cursor.model_validate(data)
