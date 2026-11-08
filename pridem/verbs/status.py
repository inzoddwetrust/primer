"""``pridem status``: the box under its lock, answered with a verdict.

Under the lock: runs that ended without a verdict get theirs first
(``recover``), then ``status`` opens its journal and writes its own verdict
with no steps. Both compositions are what ``state.json`` holds, ``{pridem}``
without it; a damaged ``state.json`` and a journal ``recover`` put in
quarantine are named in ``incomplete`` (code 2), as is a journal that did not
close. There is no passport yet, so ``passport_version`` is
absent (contract 2 v1.9). A busy box is refused before anything runs.
"""

from datetime import UTC, datetime

from pridem import __version__
from pridem.contract import Strict
from pridem.events import PlanOutcome, Secrets
from pridem.report.catalog import ENGLISH
from pridem.report.codes import ExitCode
from pridem.report.render import render_json, summary_line
from pridem.report.schema import Actor, Verdict, build_verdict
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
    ctx.out.write((render_json(verdict) if ctx.json else summary_line(verdict)) + "\n")
    return int(verdict.exit_code)


STATUS = Verb("status", NoArgs, _run)
