"""What every verb is: a name, a strict argument model and a run."""

from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import TextIO

from pridem.contract import Strict
from pridem.runner import Runner, SubprocessRunner

BOX_ROOT = Path("/opt/pridem")


class Refused(Exception):
    """Refused before anything ran: exit 1, a message, no verdict."""


class NoArgs(Strict):
    """The arguments of a verb that takes none."""


@dataclass(frozen=True)
class Context:
    """Where a verb runs: the box's root, the streams it answers on, the runner
    its commands go through, the root of the file system (``/`` on a box) and
    whether a timer of the box started it."""

    root: Path
    out: TextIO
    err: TextIO
    json: bool = False
    runner: Runner = field(default_factory=SubprocessRunner)
    fs_root: Path = Path("/")
    timer: bool = False


@dataclass(frozen=True)
class Verb:
    """A verb: ``args`` validates the arguments, ``run`` returns the exit code.

    ``positionals`` names the positional arguments in order; ``verdict`` says
    whether the verb ends with a verdict, which ``--json`` prints; ``timer`` --
    whether a timer of the box runs it, which ``--timer`` says.
    """

    name: str
    args: type[Strict]
    run: Callable[[Strict, Context], int]
    positionals: tuple[str, ...] = ()
    verdict: bool = True
    timer: bool = False
