"""What every verb is: a name, a strict argument model and a run."""

from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import TextIO

from pridem.contract import Strict

BOX_ROOT = Path("/opt/pridem")


class Refused(Exception):
    """Refused before anything ran: exit 1, a message, no verdict."""


class NoArgs(Strict):
    """The arguments of a verb that takes none."""


@dataclass(frozen=True)
class Context:
    """Where a verb runs: the box's root and the streams it answers on."""

    root: Path
    out: TextIO
    err: TextIO
    json: bool = False


@dataclass(frozen=True)
class Verb:
    """A verb: ``args`` validates the arguments, ``run`` returns the exit code.

    ``positionals`` names the positional arguments in order; ``verdict`` says
    whether the verb ends with a verdict, which ``--json`` prints.
    """

    name: str
    args: type[Strict]
    run: Callable[[Strict, Context], int]
    positionals: tuple[str, ...] = ()
    verdict: bool = True
