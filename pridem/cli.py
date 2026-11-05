"""Command-line entry point: the command line turned into a verb's arguments.

``pridem [--json] [--timer] <verb> [arguments] [--option [value] ...]``.
Parsing is all this module does; a verb's schema and run live in
``pridem.verbs``. ``--timer`` says a timer of the box started the verb (its
actor is the machine), and only a verb a timer runs takes it. ``--json`` may
also follow the verb. Anything refused before a run -- an unknown verb, option
or argument, a busy box -- exits 1 with a message on stderr and no verdict; 2
is never a parse error here, it means "not all done".

A contract file a loader rejects (``ContractError``) is a message on stderr --
the file and its problems by path and rule, never a traceback: the loaders
carry no input in the error, and nothing here prints a chain of exceptions.

``main`` holds the command's interrupt for the whole run: SIGINT and SIGTERM
-- a terminal's Ctrl-C, systemd stopping a timer's service, ``kill`` -- only
set its flag (``pridem/interrupt.py``); the plan reads it between steps, its
``restore`` and ``finally`` run and the verb writes its verdict.
"""

import sys
from collections.abc import Sequence
from pathlib import Path
from typing import TextIO

import click
from pydantic import ValidationError

from pridem.interrupt import Interrupt
from pridem.runner import Runner, SubprocessRunner
from pridem.stacks.loader import ContractError
from pridem.verbs import VERBS, Context, Refused, Verb
from pridem.verbs.base import BOX_ROOT


@click.command(
    context_settings={
        "help_option_names": [],
        "ignore_unknown_options": True,
        "allow_interspersed_args": False,
    }
)
@click.option("--json", "as_json", is_flag=True)
@click.option("--timer", "by_timer", is_flag=True)
@click.argument("verb")
@click.argument("rest", nargs=-1, type=click.UNPROCESSED)
def _command(
    as_json: bool, by_timer: bool, verb: str, rest: tuple[str, ...]
) -> tuple[str, bool, bool, tuple[str, ...]]:
    return verb, as_json, by_timer, rest


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
        if not word.startswith("--"):
            positional.append(word)
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
) -> int:
    """Parse ``argv``, run the verb, return the exit code."""
    interrupt = interrupt if interrupt is not None else Interrupt()
    try:
        try:
            name, as_json, by_timer, rest = _command.main(
                list(argv), prog_name="pridem", standalone_mode=False
            )
        except click.ClickException as error:
            raise Refused(error.format_message()) from None
        verb = VERBS.get(name)
        if verb is None:
            raise Refused(f"unknown verb {name!r}; verbs: {', '.join(sorted(VERBS))}")
        given, json_after = _arguments(verb, rest)
        as_json = as_json or json_after
        if as_json and not verb.takes_json:
            raise Refused(f"{name} writes no verdict: --json has nothing to print")
        if by_timer and not verb.timer:
            raise Refused(f"{name} is not run by a timer: --timer does not apply")
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
        )
        return verb.run(args, context)
    except Refused as refused:
        err.write(f"pridem: {refused}\n")
        return 1
    except ContractError as error:  # the loaders quote no input (DM-43)
        err.write(f"pridem: {error}\n")
        return 1


def main() -> None:
    """The ``pridem`` console script, under the command's interrupt."""
    interrupt = Interrupt()
    with interrupt.install():
        code = run(sys.argv[1:], interrupt=interrupt)
    raise SystemExit(code)
