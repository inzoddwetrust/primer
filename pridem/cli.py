"""Command-line entry point: the command line turned into a verb's arguments.

``pridem [--json] <verb> [arguments]``. Parsing is all this module does; a verb's
schema and run live in ``pridem.verbs``. Anything refused before a run -- an
unknown verb, option or argument, a busy box -- exits 1 with a message on
stderr and no verdict; 2 is never a parse error here, it means "not all done".
"""

import sys
from collections.abc import Sequence
from pathlib import Path
from typing import TextIO

import click
from pydantic import ValidationError

from pridem.verbs import VERBS, Context, Refused
from pridem.verbs.base import BOX_ROOT


@click.command(context_settings={"help_option_names": []})
@click.option("--json", "as_json", is_flag=True)
@click.argument("verb")
@click.argument("rest", nargs=-1)
def _command(
    as_json: bool, verb: str, rest: tuple[str, ...]
) -> tuple[str, bool, tuple[str, ...]]:
    return verb, as_json, rest


def run(
    argv: Sequence[str],
    *,
    root: Path = BOX_ROOT,
    out: TextIO = sys.stdout,
    err: TextIO = sys.stderr,
) -> int:
    """Parse ``argv``, run the verb, return the exit code."""
    try:
        try:
            name, as_json, rest = _command.main(
                list(argv), prog_name="pridem", standalone_mode=False
            )
        except click.ClickException as error:
            raise Refused(error.format_message()) from None
        verb = VERBS.get(name)
        if verb is None:
            raise Refused(f"unknown verb {name!r}; verbs: {', '.join(sorted(VERBS))}")
        if as_json and not verb.verdict:
            raise Refused(f"{name} writes no verdict: --json has nothing to print")
        if len(rest) > len(verb.positionals):
            raise Refused(f"{name}: unexpected arguments {list(rest)}")
        try:
            args = verb.args.model_validate(
                dict(zip(verb.positionals, rest, strict=False))
            )
        except ValidationError as error:
            raise Refused(f"{name}: {error.error_count()} invalid arguments") from None
        return verb.run(args, Context(root, out, err, as_json))
    except Refused as refused:
        err.write(f"pridem: {refused}\n")
        return 1


def main() -> None:
    """The ``pridem`` console script."""
    raise SystemExit(run(sys.argv[1:]))
