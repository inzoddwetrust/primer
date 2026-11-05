"""What every verb is: a name, a strict argument model and a run."""

from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal, TextIO

from pridem.contract import Strict
from pridem.interrupt import Interrupt
from pridem.runner import Runner, SubprocessRunner

BOX_ROOT = Path("/opt/pridem")


class Refused(Exception):
    """Refused before anything ran: exit 1, a message, no verdict."""


class NoArgs(Strict):
    """The arguments of a verb that takes none."""


@dataclass(frozen=True)
class Context:
    """Where a verb runs: the box's root, the streams it answers on, the runner
    its commands go through, the root of the file system (``/`` on a box),
    whether a timer of the box started it, and the command's interrupt (the
    signals ``main`` counted while it runs)."""

    root: Path
    out: TextIO
    err: TextIO
    json: bool = False
    runner: Runner = field(default_factory=SubprocessRunner)
    fs_root: Path = Path("/")
    timer: bool = False
    interrupt: Interrupt = field(default_factory=Interrupt)


OptionKind = Literal["flag", "value", "list"]
"""``--x`` alone (``True``), ``--x <value>`` once, ``--x <value>`` any times."""


@dataclass(frozen=True)
class Verb:
    """A verb: ``args`` validates the arguments, ``run`` returns the exit code.

    ``positionals`` names the positional arguments in order; ``rest`` -- the
    argument that takes the ones after them, as a list (``None``: none may
    follow); ``verdict`` says whether the verb ends with a verdict, which
    ``--json`` prints; ``timer`` -- whether a timer of the box runs it, which
    ``--timer`` says; ``box`` -- whether it works on a box (its lock, its
    journal and ``history/``): ``check`` reads a repository and has none;
    ``options`` -- its options after the verb, ``--name`` -> (the argument,
    its kind); ``prints_json`` -- whether ``--json`` applies, by default when
    the verb writes a verdict (``report`` prints a stored one).
    """

    name: str
    args: type[Strict]
    run: Callable[[Strict, Context], int]
    positionals: tuple[str, ...] = ()
    rest: str | None = None
    verdict: bool = True
    timer: bool = False
    box: bool = True
    options: Mapping[str, tuple[str, OptionKind]] = field(default_factory=dict)
    prints_json: bool | None = None

    @property
    def takes_json(self) -> bool:
        return self.verdict if self.prints_json is None else self.prints_json
