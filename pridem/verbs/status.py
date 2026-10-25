"""``pridem status``: the box under its lock, answered with a verdict.

Under the lock: runs that ended without a verdict get theirs first
(``recover``), then ``status`` opens its journal and writes its own verdict
with no steps. Both compositions are what ``state.json`` holds, ``{pridem}``
without it; a damaged ``state.json`` is quarantined and named in
``incomplete`` (code 2). There is no passport yet, so ``passport_version`` is
absent (contract 2 v1.9). A busy box is refused before anything runs.
"""

import secrets as token
from datetime import UTC, datetime

from pridem import __version__
from pridem.contract import Strict
from pridem.events import Code, Incomplete, PlanOutcome, Secrets
from pridem.report.catalog import ENGLISH
from pridem.report.codes import ExitCode
from pridem.report.render import render_json, summary_line
from pridem.report.schema import Actor, Verdict, build_verdict
from pridem.state import Box, BoxBusy, JournalHeader
from pridem.verbs.base import Context, NoArgs, Refused, Verb

ACTOR = {"type": "engineer", "via": "local"}
NO_SECRETS = Secrets(())  # no passport, no minted secrets on a fresh box


def _run_id(now: datetime) -> str:
    return f"{now:%Y-%m-%dT%H:%M:%SZ}-{token.token_hex(2)}"


def _verdict(box: Box) -> Verdict:
    """Everything ``status`` does once it holds the lock."""
    box.recover(NO_SECRETS, __version__, ENGLISH)
    state = box.read_state()
    composition = dict(state.composition) if state else {"pridem": __version__}
    started = datetime.now(UTC).replace(microsecond=0)
    run_id = _run_id(started)
    header = JournalHeader(
        run_id=run_id,
        verb="status",
        mode="status",
        args={},
        actor=Actor(type="engineer", via="local"),
        started=started,
        composition_before=composition,
    )
    box.open_journal(header, NO_SECRETS).close()
    incomplete = (
        (Incomplete("state", Code("quarantined")),) if box.state_quarantined else ()
    )
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
        finished=datetime.now(UTC).replace(microsecond=0),
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
