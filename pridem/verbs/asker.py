"""The person at the terminal asked what the passport lacks (DM-118,
contract 1 rule 3): ``install``, ``reinstall``, ``update``, ``deploy`` and
``rollback`` hand it to the steps that read the passport and render a stack's
env; ``doctor`` never asks -- it writes nothing.

A secret (its schema ``format: password`` / ``writeOnly``) is read with the
echo off, everything else with it. The answer is checked against the field's
schema at once -- its length, form, choices -- and asked again with the
reason, never with the value; an empty answer, a closed terminal or ten
minutes with none is no answer. The read is a loop of ``select``: a signal
(Ctrl-C, a lost terminal) is only counted by the machine's handler (DM-92),
and a blocking read would go on after it -- the loop checks the interrupt
between its waits. Every console's live line stops while the person answers.
"""

import re
import select
import sys
import termios
import time
from collections.abc import Mapping
from typing import TextIO

from pridem.events import Json, paused
from pridem.interrupt import Interrupt
from pridem.steps.passport import Ask

ANSWER_WAIT_S = 600.0
"""Ten minutes a question: the box's lock holds every deploy meanwhile."""
POLL_S = 0.5


def secret(schema: Mapping[str, Json]) -> bool:
    return schema.get("format") == "password" or schema.get("writeOnly") is True


def problem(schema: Mapping[str, Json], answer: str) -> str | None:
    """What the field's schema refuses in ``answer`` -- named, not shown."""
    least, most = schema.get("minLength"), schema.get("maxLength")
    if isinstance(least, int) and len(answer) < least:
        return f"must be at least {least} characters"
    if isinstance(most, int) and len(answer) > most:
        return f"must be at most {most} characters"
    pattern = schema.get("pattern")
    if isinstance(pattern, str) and not re.search(pattern, answer):
        return f"must match {pattern}"
    choices = schema.get("enum")
    if isinstance(choices, list) and answer not in choices:
        return "must be one of " + ", ".join(str(c) for c in choices)
    return None


def read_answer(
    question: str,
    *,
    hidden: bool,
    interrupt: Interrupt,
    wait_s: float,
    stdin: TextIO,
    stderr: TextIO,
) -> str:
    """One answer: ``question`` on ``stderr``, a line from ``stdin`` --
    without the echo when ``hidden``. ``""`` -- none: EOF, or ``wait_s``
    passed. A counted signal raises ``Interrupted`` (``interrupt.check``)."""
    stderr.write(question)
    stderr.flush()
    fd = stdin.fileno()
    saved = termios.tcgetattr(fd) if hidden else None
    if saved is not None:
        quiet = termios.tcgetattr(fd)
        quiet[3] &= ~termios.ECHO
        termios.tcsetattr(fd, termios.TCSADRAIN, quiet)
    try:
        deadline = time.monotonic() + wait_s
        while time.monotonic() < deadline:
            interrupt.check()
            ready, _, _ = select.select([stdin], [], [], POLL_S)
            if ready:
                return stdin.readline().rstrip("\n")
        return ""
    finally:
        if saved is not None:
            termios.tcsetattr(fd, termios.TCSADRAIN, saved)
            stderr.write("\n")
            stderr.flush()


def terminal_asker(
    interrupt: Interrupt,
    *,
    wait_s: float = ANSWER_WAIT_S,
    stdin: TextIO | None = None,
    stderr: TextIO | None = None,
) -> Ask:
    """The steps' ``ask``: each missing field asked until its schema takes
    the answer; ``""`` -- no answer (the step says ``no-answer``)."""

    def ask(field: str, schema: Mapping[str, Json]) -> str | None:
        source, out = stdin or sys.stdin, stderr or sys.stderr
        hidden = secret(schema)
        with paused():
            while True:
                answer = read_answer(
                    f"Value for {field}: ",
                    hidden=hidden,
                    interrupt=interrupt,
                    wait_s=wait_s,
                    stdin=source,
                    stderr=out,
                )
                if not answer:
                    return ""
                why = problem(schema, answer)
                if why is None:
                    return answer
                out.write(f"{field}: {why}\n")
                out.flush()

    return ask
