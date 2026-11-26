"""What every verb is: a name, a strict argument model and a run."""

import sys
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


def ask_terminal(question: str) -> str | None:
    """``question`` on stderr, the answer from stdin -- when stdin is a
    terminal; ``None`` otherwise. Ctrl-C and a closed terminal answer
    nothing: ``""``."""
    if not sys.stdin.isatty():
        return None
    sys.stderr.write(question)
    sys.stderr.flush()
    try:
        line = sys.stdin.readline()
    except KeyboardInterrupt:
        sys.stderr.write("\n")
        return ""
    return line.strip()


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
    ask: Callable[[str], str | None] = ask_terminal
    terminal: Callable[[], bool] = lambda: sys.stdin.isatty()  # noqa: E731
    command: str | None = None
    """The Panel's command the verb runs for (``--command``, DM-138): its id
    goes to the journal's header, the lock and the verdict."""
    """Whether a person is at a terminal to be asked (DM-118); a test says."""
    """A question to the person at the terminal; ``None`` -- no terminal (a
    pipe, the Panel). ``destroy`` asks the server's name with it (DM-110)."""


OptionKind = Literal["flag", "value", "list"]
"""``--x`` alone (``True``), ``--x <value>`` once, ``--x <value>`` any times."""

Values = tuple[tuple[str, tuple[str | bool, ...]], ...]
"""Values of a verb's arguments, as data: ``(field, values)`` pairs -- an
argument of the verb's model and the values of it that are meant."""

Group = Literal["server", "deploy", "data", "host", "logs", "project"]
"""The group a verb is shown in -- the machine has no ``--help`` of groups;
the names are those of the TZ's table of verbs (9.1), ``project`` -- the verbs
a product declares."""

GROUPS: tuple[Group, ...] = ("server", "deploy", "data", "host", "logs", "project")
"""Every group, in the order they are shown."""


def _among(values: Values, args: Mapping[str, object]) -> list[str | bool]:
    """The values of ``args`` that ``values`` names, in the order of
    ``values``. A word or a flag alone: a number is neither, ``1`` is no
    ``True``."""
    found: list[str | bool] = []
    for name, meant in values:
        given = args.get(name)
        if isinstance(given, str | bool) and given in meant:
            found.append(given)
    return found


@dataclass(frozen=True)
class Destructive:
    """Whether a verb destroys what cannot be made again -- the server is
    named to it (``--confirm <server.name>``): ``always``; ``when`` an
    argument has one of the values; ``declared`` -- the machine does not know,
    the product says it of each verb it declares (``destructive`` in its
    ``primer.yaml``). All three off -- never."""

    always: bool = False
    when: Values = ()
    declared: bool = False


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

    Four marks say, as data, what the verb is to whoever offers or runs it --
    the console, the box's agent, the Panel -- so none of them keeps a list of
    its own (DM-198): ``group`` -- where it is shown; ``on_box`` -- whether it
    works on a box at all (``check`` reads a repository at a path; ``state``
    reads a box though it takes no lock, so ``box`` is not this);
    ``destructive`` -- whether the server is named to it (``destroys``);
    ``no_verdict`` -- the values of an argument with which a verb that writes
    a verdict writes none (``ssl status``, ``db connect``: ``verdict`` is of
    the whole verb, ``writes_verdict`` -- of a run of it).
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
    group: Group = field(kw_only=True)
    on_box: bool = True
    destructive: Destructive = Destructive()
    no_verdict: Values = ()

    @property
    def takes_json(self) -> bool:
        return self.verdict if self.prints_json is None else self.prints_json

    def without_verdict(self, args: Mapping[str, object]) -> str | None:
        """The words of a run with ``args`` that ends with no verdict --
        ``state``, ``ssl status`` -- and ``None`` for one that ends with it.
        ``args`` -- the arguments by their names, as a command line or a
        command of the queue gives them."""
        if not self.verdict:
            return self.name
        silent = _among(self.no_verdict, args)
        if silent:
            return " ".join([self.name, *(str(value) for value in silent)])
        return None

    def writes_verdict(self, args: Mapping[str, object]) -> bool:
        """Whether a run with ``args`` ends with a verdict: only such a run
        can carry a command of the Panel's queue (``--command``)."""
        return self.without_verdict(args) is None

    def destroys(self, args: Mapping[str, object]) -> bool | None:
        """Whether a run with ``args`` is destructive -- the server is named
        to it; ``None`` -- the product says (``Destructive.declared``)."""
        mark = self.destructive
        if mark.always or _among(mark.when, args):
            return True
        return None if mark.declared else False
