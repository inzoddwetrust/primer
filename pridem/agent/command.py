"""A command of the Panel's queue checked by the agent itself, before any run
(``PRIMER-PANEL-TZ-2`` 6; DM-141): defence in depth, the Panel checked it
too.

- ``verb-unknown`` -- no verb of the machine by the name, or a run of one that
  writes no verdict: ``--command`` has nothing to carry there and the machine
  refuses it before a run. Which run writes none is the registry's to say
  (``Verb.writes_verdict``, DM-198) -- ``state``, ``version``, ``report``,
  ``logs``, and ``ssl status`` and ``db connect``, which write none though
  their verbs do; the agent keeps no list of its own. ``agent`` is no verb of
  ``VERBS`` at all.
- ``args-refused`` -- the verb's own argument model refuses the arguments, or
  they do not go on its command line (``argv_of``).
- ``confirmation-missing`` -- ``confirm`` given (the server's name a person
  typed: in the queue only a destructive command carries it) and no
  ``confirmed_at``.
- ``expired`` -- the command is taken after its ``expires_at``.

``argv_of`` turns the arguments back into the verb's command line -- the one
``pridem.cli`` reads into the same arguments: positionals in their order, the
rest after them, then the options; a flag ``True`` is the flag alone, a value
is the option and its value, a list is the option once for each. A value the
command line cannot carry -- a word that begins with ``--`` or is one of the
verb's options (an option to the reader), a type no option takes, a
positional after a gap -- is not turned: ``NotArgv``.
"""

from collections.abc import Mapping
from datetime import datetime

from pydantic import ValidationError

from pridem.events import Json
from pridem.protocol import Command, CommandRefusalCode
from pridem.verbs import VERBS, Verb

CONFIRM = "confirm"


class NotArgv(ValueError):
    """Arguments that do not go on the verb's command line."""


def _word(verb: Verb, value: Json) -> str:
    if not isinstance(value, str) or value.startswith("--") or value in verb.options:
        raise NotArgv("not a word of the command line")
    return value


def argv_of(verb: Verb, args: Mapping[str, Json]) -> list[str]:
    """The command line after ``verb``'s name that gives ``args``."""
    options = {name: (flag, kind) for flag, (name, kind) in verb.options.items()}
    positionals: list[str | None] = [None] * len(verb.positionals)
    rest: list[str] = []
    tail: list[str] = []
    for key, value in args.items():
        if key in verb.positionals:
            positionals[verb.positionals.index(key)] = _word(verb, value)
        elif key == verb.rest:
            if not isinstance(value, list):
                raise NotArgv(key)
            rest = [_word(verb, item) for item in value]
        elif key in options:
            flag, kind = options[key]
            if kind == "flag":
                if not isinstance(value, bool):
                    raise NotArgv(key)
                tail.extend([flag] if value else [])
            elif kind == "value":
                tail.extend([flag, _word(verb, value)])
            else:
                if not isinstance(value, list):
                    raise NotArgv(key)
                for item in value:
                    tail.extend([flag, _word(verb, item)])
        else:
            raise NotArgv(key)
    given = [word for word in positionals if word is not None]
    if positionals[: len(given)] != given or (rest and len(given) < len(positionals)):
        raise NotArgv("a positional after a gap")
    return [*given, *rest, *tail]


def checked(
    command: Command, now: datetime
) -> tuple[Verb, list[str]] | CommandRefusalCode:
    """The verb and its command line, or the code the agent refuses with."""
    verb = VERBS.get(command.verb)
    if verb is None or not verb.writes_verdict(command.args):
        return "verb-unknown"
    try:
        verb.args.model_validate(command.args)
        argv = argv_of(verb, command.args)
    except (ValidationError, NotArgv):
        return "args-refused"
    if CONFIRM in command.args and command.confirmed_at is None:
        return "confirmation-missing"
    if now > datetime.fromisoformat(command.expires_at):
        return "expired"
    return verb, argv
