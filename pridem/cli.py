"""Command-line entry point: the command line turned into a verb's arguments.

``pridem [--json] [--timer | --command <id>] <verb> [arguments] [--option
[value] ...]``. Parsing is all this module does; a verb's schema and run live
in ``pridem.verbs``. ``--timer`` says a timer of the box started the verb (its
actor is the machine), and only a verb a timer runs takes it. ``--command``
names the command of the Panel's queue the agent runs the verb for (DM-138):
its id goes to the journal's header, the lock and the verdict, the actor is
the Panel; a run that ends with no verdict is refused it -- which one is the
registry's to say (``Verb.without_verdict``, DM-198: a verb with none, and
``ssl status``, ``db connect``). ``--json`` may also follow the verb.
``pridem agent`` runs the box's agent (DM-141): it takes no argument
and is no verb of ``VERBS``; ``pridem agent install`` makes it the box's
service (DM-143). Anything refused before a run -- an unknown verb,
option or argument, a
busy box -- exits 1 with a message on stderr and no verdict; a busy box with
``--json`` prints the refusal's object on stdout too
(``pridem/report/refusal.py``). 2 is never a parse error here, it means "not
all done".

A contract file a loader rejects (``ContractError``) is a message on stderr --
the file and its problems by path and rule, never a traceback: the loaders
carry no input in the error, and nothing here prints a chain of exceptions.

``main`` holds the command's interrupt for the whole run: SIGINT, SIGTERM,
SIGHUP and SIGQUIT -- a terminal's Ctrl-C, systemd stopping a timer's service,
``kill``, an ssh session dropped -- only set its flag (``pridem/interrupt.py``);
the plan reads it between steps, its ``restore`` and ``finally`` run and the
verb writes its verdict. A signal that stops a command outside a plan
(``check``) is the refusal ``interrupted``, exit 1, never a traceback (DM-92);
``logs -f`` ends by it with 0. A console that is gone mid-run goes silent
(``events.said``); the journal and the verdict are written.
"""

import errno
import sys
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import TextIO

import click
from pydantic import TypeAdapter, ValidationError

from pridem.agent.install import install_service
from pridem.agent.service import run_agent
from pridem.events import ShortSecret, said
from pridem.interrupt import Interrupt, Interrupted
from pridem.report.schema import CommandId
from pridem.runner import Runner, SubprocessRunner
from pridem.stacks.loader import ContractError
from pridem.stacks.stack import CompositionCollision
from pridem.state import (
    HistoryExists,
    JournalDamaged,
    JournalTaken,
    RunIdTaken,
    StateDamaged,
    VerdictDamaged,
)
from pridem.verbs import VERBS, Context, Refused, Verb
from pridem.verbs.base import BOX_ROOT, ask_terminal


@click.command(
    context_settings={
        "help_option_names": [],
        "ignore_unknown_options": True,
        "allow_interspersed_args": False,
    }
)
@click.option("--json", "as_json", is_flag=True)
@click.option("--timer", "by_timer", is_flag=True)
@click.option("--command", "command", default=None)
@click.argument("verb")
@click.argument("rest", nargs=-1, type=click.UNPROCESSED)
def _command(
    as_json: bool,
    by_timer: bool,
    command: str | None,
    verb: str,
    rest: tuple[str, ...],
) -> tuple[str, bool, bool, str | None, tuple[str, ...]]:
    return verb, as_json, by_timer, command, rest


_COMMAND_ID: TypeAdapter[str] = TypeAdapter(CommandId)

AGENT = "agent"
"""``pridem agent`` -- the agent of the box (``pridem/agent/service.py``):
not a verb of ``VERBS``, so never a command of the Panel's queue."""
INSTALL = "install"
"""``pridem agent install`` -- the agent's service (``pridem/agent/install.py``,
DM-143), a plan with its verdict; ``--json`` prints it."""


def _arguments(
    verb: Verb, rest: Sequence[str]
) -> tuple[dict[str, str | bool | list[str]], bool]:
    """The verb's arguments from what follows it, and whether ``--json`` did."""
    given: dict[str, str | bool | list[str]] = {}
    positional: list[str] = []
    as_json = False
    tokens = list(rest)
    while tokens:
        word = tokens.pop(0)
        if word == "--json":
            as_json = True
            continue
        if not word.startswith("--") and word not in verb.options:
            positional.append(word)  # a short option only as the verb declares it
            continue
        known = verb.options.get(word)
        if known is None:
            raise Refused(f"{verb.name}: unknown option {word}")
        name, kind = known
        if kind == "flag":
            given[name] = True
            continue
        if not tokens or tokens[0].startswith("--"):
            raise Refused(f"{verb.name}: {word} needs a value")
        value = tokens.pop(0)
        if kind == "list":
            listed = given.get(name)
            values = listed if isinstance(listed, list) else []
            given[name] = [*values, value]
        elif name in given:
            raise Refused(f"{verb.name}: {word} is given twice")
        else:
            given[name] = value
    given.update(zip(verb.positionals, positional, strict=False))
    tail = positional[len(verb.positionals) :]
    if tail and verb.rest is None:
        raise Refused(f"{verb.name}: unexpected arguments {tail}")
    if verb.rest is not None:
        given[verb.rest] = tail
    return given, as_json


def run(
    argv: Sequence[str],
    *,
    root: Path = BOX_ROOT,
    out: TextIO = sys.stdout,
    err: TextIO = sys.stderr,
    runner: Runner | None = None,
    fs_root: Path = Path("/"),
    interrupt: Interrupt | None = None,
    ask: Callable[[str], str | None] = ask_terminal,
) -> int:
    """Parse ``argv``, run the verb, return the exit code; ``ask`` -- the
    question to the person at the terminal (DM-110)."""
    interrupt = interrupt if interrupt is not None else Interrupt()
    try:
        try:
            name, as_json, by_timer, command, rest = _command.main(
                list(argv), prog_name="pridem", standalone_mode=False
            )
        except click.ClickException as error:
            raise Refused(error.format_message()) from None
        if name == AGENT:  # the agent of the box: no verb of VERBS (DM-141)
            if list(rest) == [INSTALL] and not by_timer and command is None:
                return install_service(  # its service (DM-143)
                    Context(
                        root,
                        out,
                        err,
                        as_json,
                        runner if runner is not None else SubprocessRunner(interrupt),
                        fs_root,
                        False,
                        interrupt,
                        ask,
                    )
                )
            if as_json or by_timer or command is not None or rest:
                raise Refused("agent takes no arguments and no flags")
            return run_agent(
                root,
                out,
                lambda: interrupt.count > 0,
                fs_root=fs_root,
                runner=runner,
            )
        verb = VERBS.get(name)
        if verb is None:
            raise Refused(f"unknown verb {name!r}; verbs: {', '.join(sorted(VERBS))}")
        given, json_after = _arguments(verb, rest)
        as_json = as_json or json_after
        if as_json and not verb.takes_json:
            raise Refused(f"{name} writes no verdict: --json has nothing to print")
        if by_timer and not verb.timer:
            raise Refused(f"{name} is not run by a timer: --timer does not apply")
        if command is not None:  # a command of the Panel's queue (DM-138)
            if by_timer:
                raise Refused("--command and --timer: a run comes from one of them")
            silent = verb.without_verdict(given)  # the registry's mark (DM-198)
            if silent is not None:
                raise Refused(
                    f"{silent} writes no verdict: --command has nothing to carry"
                )
            try:
                _COMMAND_ID.validate_python(command)
            except ValidationError:
                raise Refused(
                    "--command: an id of letters, digits and . _ : -, "
                    "at most 128, a letter or a digit first"
                ) from None
        try:
            args = verb.args.model_validate(given)
        except ValidationError as error:
            raise Refused(f"{name}: {error.error_count()} invalid arguments") from None
        context = Context(
            root,
            out,
            err,
            as_json,
            runner if runner is not None else SubprocessRunner(interrupt),
            fs_root,
            by_timer,
            interrupt,
            ask,
            command=command,
        )
        return verb.run(args, context)
    except Refused as refused:
        said(err, f"pridem: {refused}\n")
        return 1
    except Interrupted:  # a signal outside a plan (check): no traceback (DM-92)
        said(err, "pridem: interrupted\n")
        return 1
    except ContractError as error:  # the loaders quote no input (DM-43)
        err.write(f"pridem: {error}\n")
        return 1
    except MACHINE_ERRORS as error:
        # DM-77: a code and fixed words, never ``str(error)`` -- a pydantic
        # message quotes its input_value; an error not in the list is a defect
        # of the machine and keeps its traceback, to be seen
        err.write(f"pridem: {_said(error)}\n")
        return 1


MACHINE_ERRORS = (
    OSError,
    JournalTaken,
    StateDamaged,
    VerdictDamaged,
    JournalDamaged,
    CompositionCollision,
    ShortSecret,
)
"""What the machine raises that reaches ``run`` and is a state of the box,
not a defect: each is said by a code. ``RunIdTaken`` and ``HistoryExists`` are
``OSError`` (``FileExistsError``) and are told apart first."""


def _said(
    error: OSError
    | JournalTaken
    | StateDamaged
    | VerdictDamaged
    | JournalDamaged
    | CompositionCollision
    | ShortSecret,
) -> str:
    """``<code>: <words>``, with no value the error may carry."""
    if isinstance(error, RunIdTaken | HistoryExists | JournalTaken):
        return "run-id-taken: the run id of this second is taken; run again"
    if isinstance(error, StateDamaged):
        return "state-damaged: state.json cannot be read; see pridem status"
    if isinstance(error, VerdictDamaged):
        return "verdict-damaged: a verdict of history/ cannot be read"
    if isinstance(error, JournalDamaged):
        return "journal-damaged: a journal cannot be read"
    if isinstance(error, CompositionCollision):
        return "composition-collision: two stacks give the same name"
    if isinstance(error, ShortSecret):
        return "short-secret: a secret is shorter than 16 characters"
    name = errno.errorcode.get(error.errno or 0, "unknown")
    where = f" {error.filename}" if error.filename is not None else ""
    return f"os-error: {name}{where}"


def main() -> None:
    """The ``pridem`` console script, under the command's interrupt."""
    interrupt = Interrupt()
    with interrupt.install():
        code = run(sys.argv[1:], interrupt=interrupt)
    raise SystemExit(code)
