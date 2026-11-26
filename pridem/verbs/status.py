"""``pridem status``: the box under its lock, answered with a verdict.

Under the lock: runs that ended without a verdict get theirs first
(``recover``), then ``status`` opens its journal and writes its own verdict
with no steps; for the console, the box's state follows it (``pridem state``,
DM-136). Both compositions are what ``state.json`` holds, ``{pridem}``
without it; a journal ``recover`` put in quarantine is named in ``incomplete``
(code 2), as is a journal that did not close. ``status`` writes no
composition, so it never puts ``state.json`` in quarantine: a damaged one, or
one of another schema, refuses it and stays as it is (DM-191). There is no
passport yet, so ``passport_version`` is absent (contract 2 v1.9). A busy box
is refused before anything runs.
"""

from datetime import datetime
from typing import TextIO

from pridem import __version__
from pridem.contract import Strict
from pridem.events import Incomplete, PlanOutcome, Secrets, SecretsUnread, said
from pridem.report.catalog import ENGLISH
from pridem.report.codes import ExitCode
from pridem.report.render import closing, render_json
from pridem.report.schema import Verdict, build_verdict
from pridem.state import Box, BoxBusy, JournalHeader, LockHolder
from pridem.verbs.base import Context, NoArgs, Verb
from pridem.verbs.run import (
    BoxSecrets,
    box_secrets,
    close_journal,
    end_journal,
    finished_at,
    found_on_box,
    lock_holder,
    read_copy,
    refuse_busy,
    sync_journal,
)
from pridem.verbs.state import console_lines, snapshot

NO_SECRETS = Secrets(())  # the verdict of status prints no command's line


def _verdict(
    box: Box, err: TextIO, held: LockHolder, started: datetime, known: BoxSecrets
) -> Verdict:
    """Everything ``status`` does once it holds the lock: what it finds in
    quarantine and a journal that does not reach the disk are its
    ``incomplete``; after its verdict the journal ends with ``run_finished``
    (DM-137) -- a failure to is one line to ``err``."""
    secrets = Secrets(known.values)  # every secret of the box (DM-183)
    recovery = box.recover(secrets, __version__, ENGLISH)
    state = box.read_state()
    composition = dict(state.composition) if state else {"pridem": __version__}
    run_id = held.run_id
    header = JournalHeader.model_validate(
        {
            "run_id": run_id,
            "verb": "status",
            "mode": "status",
            "args": {},
            "actor": held.actor,
            "started": started,
            "composition_before": composition,
            # absent for the console and a timer, never null (DM-138)
            **({} if held.command is None else {"command": held.command}),
        }
    )
    journal = box.open_journal(header, secrets)
    for stack, why in known.unread:  # status goes on: it mends nothing else
        journal.notice(SecretsUnread(stack, why))
    try:
        finished = finished_at(started, journal)
        lost = sync_journal(journal)
        incomplete = (*found_on_box(box, recovery), *lost)
        verdict = _status_verdict(held, started, finished, composition, incomplete)
        box.write_verdict(verdict)
    except BaseException:
        close_journal(journal)  # no verdict: a run that did not end (DM-137)
        raise
    end_journal(journal, verdict, err)
    return verdict


def _status_verdict(
    held: LockHolder,
    started: datetime,
    finished: datetime,
    composition: dict[str, str],
    incomplete: tuple[Incomplete, ...],
) -> Verdict:
    return build_verdict(
        PlanOutcome(
            "status",
            ExitCode.INCOMPLETE if incomplete else ExitCode.OK,
            (),
            incomplete=incomplete,
        ),
        run_id=held.run_id,
        verb="status",
        args={},
        actor=held.actor.model_dump(exclude_none=True),
        started=started,
        finished=finished,
        passport_version=None,
        composition_before=composition,
        composition_after=composition,
        secrets=NO_SECRETS,
        catalog=ENGLISH,
        command=held.command,
    )


def _run(args: Strict, ctx: Context) -> int:
    box = Box(ctx.root, quarantine=False)  # it writes no composition (DM-191)
    held, started = lock_holder(ctx, box, "status")
    try:
        with box.lock(held.model_dump_json()):
            known = box_secrets(ctx, read_copy(ctx).passport)
            verdict = _verdict(box, ctx.err, held, started, known)
    except BoxBusy as busy:  # raised only by taking the lock
        raise refuse_busy(ctx, busy) from None
    if ctx.json:
        ctx.out.write(render_json(verdict) + "\n")
        return int(verdict.exit_code)
    lines = closing(verdict, ENGLISH)
    # the box's state, measured after the lock is given back and outside the
    # verdict: its JSON stays as it was (DM-107, DM-136)
    lines += console_lines(snapshot(ctx))
    said(ctx.out, "\n".join(lines) + "\n")
    return int(verdict.exit_code)


STATUS = Verb("status", NoArgs, _run, group="server")
