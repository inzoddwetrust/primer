"""``pridem status``: the box under its lock, answered with a verdict.

Under the lock: runs that ended without a verdict get theirs first
(``recover``), then ``status`` opens its journal and writes its own verdict
with no steps. Both compositions are what ``state.json`` holds, ``{pridem}``
without it; a damaged ``state.json`` and a journal ``recover`` put in
quarantine are named in ``incomplete`` (code 2), as is a journal that did not
close. There is no passport yet, so ``passport_version`` is
absent (contract 2 v1.9). A busy box is refused before anything runs.
"""

import json
import re
from datetime import UTC, datetime
from pathlib import Path

from pridem import __version__
from pridem.contract import Strict
from pridem.events import PlanOutcome, Secrets, said
from pridem.report.catalog import ENGLISH, say
from pridem.report.codes import ExitCode
from pridem.report.render import closing, render_json
from pridem.report.schema import Actor, Verdict, build_verdict
from pridem.runner import RunnerError, Stream
from pridem.state import Box, BoxBusy, JournalHeader
from pridem.verbs.base import Context, NoArgs, Refused, Verb
from pridem.verbs.run import close_journal, finished_at, found_on_box

ACTOR = {"type": "engineer", "via": "local"}
NO_SECRETS = Secrets(())  # no passport, no minted secrets on a fresh box


def _verdict(box: Box) -> Verdict:
    """Everything ``status`` does once it holds the lock: what it finds in
    quarantine and a journal that does not close are its ``incomplete``."""
    recovery = box.recover(NO_SECRETS, __version__, ENGLISH)
    state = box.read_state()
    composition = dict(state.composition) if state else {"pridem": __version__}
    started = datetime.now(UTC).replace(microsecond=0)
    run_id = box.new_run_id(started)
    header = JournalHeader(
        run_id=run_id,
        verb="status",
        mode="status",
        args={},
        actor=Actor(type="engineer", via="local"),
        started=started,
        composition_before=composition,
    )
    journal = box.open_journal(header, NO_SECRETS)
    finished = finished_at(started, journal)
    lost = close_journal(journal)
    incomplete = (*found_on_box(box, recovery), *lost)
    verdict = build_verdict(
        PlanOutcome(
            "status",
            ExitCode.INCOMPLETE if incomplete else ExitCode.OK,
            (),
            incomplete=incomplete,
        ),
        run_id=run_id,
        verb="status",
        args={},
        actor=ACTOR,
        started=started,
        finished=finished,
        passport_version=None,
        composition_before=composition,
        composition_after=composition,
        secrets=NO_SECRETS,
        catalog=ENGLISH,
    )
    box.write_verdict(verdict)
    return verdict


def _run(args: Strict, ctx: Context) -> int:
    box = Box(ctx.root)
    try:
        with box.lock("status"):
            verdict = _verdict(box)
    except BoxBusy as busy:  # raised only by taking the lock
        raise Refused(f"the box is busy: {busy}") from None
    if ctx.json:
        ctx.out.write(render_json(verdict) + "\n")
        return int(verdict.exit_code)
    lines = closing(verdict, ENGLISH)
    lines += _stacks(ctx, box)  # read after the verdict, outside it (DM-107)
    said(ctx.out, "\n".join(lines) + "\n")
    return int(verdict.exit_code)


SHORT = re.compile(r"\b([0-9a-f]{7})[0-9a-f]{33}\b")


def _stacks(ctx: Context, box: Box) -> list[str]:
    """Each stack of ``current``: its release, and whether compose runs it --
    ``docker compose ls --all --format json``, read for the console alone and
    never a step of the verdict: the verdict's JSON stays as it was (DM-107)."""
    state = box.read_state()
    if state is None or not state.current:
        return [say(ENGLISH, "@status.none")]
    lines: list[str] = []
    try:
        found: list[str] = []
        ctx.runner.run(
            ["docker", "compose", "ls", "--all", "--format", "json"],
            timeout=60,
            on_line=lambda s, line, c: (
                found.append(line) if s is Stream.STDOUT else None
            ),
        )
        listed = json.loads("".join(found) or "[]")
        states = {
            str(item.get("Name")): str(item.get("Status"))
            for item in listed
            if isinstance(item, dict)
        }
        why = None
    except (RunnerError, ValueError) as error:
        states, why = {}, type(error).__name__
    for stack, release in sorted(state.current.items()):
        if why is not None:
            shown = say(ENGLISH, "@status.unknown", why=why)
        else:
            shown = states.get(stack) or say(ENGLISH, "@status.down")
        lines.append(
            say(
                ENGLISH,
                "@status.stack",
                stack=stack,
                release=SHORT.sub(r"\1", Path(release).name),
                state=shown,
            )
        )
    return lines


STATUS = Verb("status", NoArgs, _run)
