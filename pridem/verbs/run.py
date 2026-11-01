"""A verb whose whole run is one plan of its own steps, under the box lock.

Under the lock: runs that ended without a verdict get theirs first
(``recover``), then the journal opens with its header, the plan runs with the
journal as its sink, and the verdict is written to ``history/``. The passport
is the box's copy (``/opt/pridem/passport.yaml``): its secrets are cleaned from
the journal and the verdict, its version is the verdict's, its role the plan's.
Without a readable copy the steps are given no passport and refuse by their
code ``no-passport``; no step of these verbs depends on the role. Both
compositions are what ``state.json`` holds, ``{pridem}`` without it; a damaged
``state.json`` is quarantined and named in ``incomplete`` (code 2). The actor
is the engineer at the console, or the machine when a timer of the box started
the verb (``--timer``). The console gets the summary line, or the verdict with
``--json``. A busy box is refused before anything runs.
"""

import secrets as token
from collections.abc import Callable, Sequence
from dataclasses import replace
from datetime import UTC, datetime

from pridem import __version__
from pridem.events import Code, Incomplete, Json, PlanMode, PlanOutcome, Secrets
from pridem.plan import Plan, StackSteps
from pridem.report.catalog import ENGLISH
from pridem.report.codes import ExitCode, worst
from pridem.report.render import render_json, summary_line
from pridem.report.schema import Actor, Verdict, build_verdict
from pridem.stacks.loader import ContractError
from pridem.stacks.passport import load_passport
from pridem.state import Box, BoxBusy, JournalHeader
from pridem.steps.base import Role, Step
from pridem.steps.passport import PASSPORT_COPY, Fetched, passport_secrets
from pridem.verbs.base import Context, Refused

Steps = Callable[[Box, str, Fetched, Secrets], Sequence[Step]]
"""The verb's steps for the box, the run id, the passport and the run's secrets."""

ROLE_WITHOUT_PASSPORT: Role = "test"
"""The plan's role when the box has no readable passport: its steps refuse by
``no-passport`` before the role could matter."""


def _run_id(now: datetime) -> str:
    return f"{now:%Y-%m-%dT%H:%M:%SZ}-{token.token_hex(2)}"


def _actor(ctx: Context) -> dict[str, str]:
    if ctx.timer:
        return {"type": "machine", "via": "timer"}
    return {"type": "engineer", "via": "local"}


def _fetched(ctx: Context) -> Fetched:
    copy = ctx.fs_root / PASSPORT_COPY
    if not copy.is_file():
        return Fetched()
    try:
        return Fetched(passport=load_passport(copy))
    except ContractError:
        return Fetched()


def _verdict(
    box: Box,
    ctx: Context,
    *,
    verb: str,
    mode: PlanMode,
    stack: str,
    steps: Steps,
) -> Verdict:
    """Everything the verb does once it holds the lock."""
    fetched = _fetched(ctx)
    passport = fetched.passport
    secrets = Secrets(passport_secrets(passport) if passport is not None else ())
    box.recover(secrets, __version__, ENGLISH)
    state = box.read_state()
    before = dict(state.composition) if state else {"pridem": __version__}
    started = datetime.now(UTC).replace(microsecond=0)
    run_id = _run_id(started)
    actor = _actor(ctx)
    args: dict[str, Json] = {}
    fields: dict[str, object] = {
        "run_id": run_id,
        "verb": verb,
        "mode": mode,
        "args": args,
        "actor": Actor.model_validate(actor),
        "started": started,
        "composition_before": before,
    }
    if passport is not None:  # absent without a passport, never null
        fields["passport_version"] = passport.version
    header = JournalHeader.model_validate(fields)
    journal = box.open_journal(header, secrets)
    interrupt: KeyboardInterrupt | None = None
    try:
        plan = Plan(
            [StackSteps(stack, steps(box, run_id, fetched, secrets), root=True)],
            mode=mode,
            role=passport.server.role
            if passport is not None
            else ROLE_WITHOUT_PASSPORT,
            runner=ctx.runner,
            sink=journal,
        )
        try:
            outcome = plan.run()
        except KeyboardInterrupt as error:  # the plan kept its outcome
            interrupt = error
            if plan.outcome is None:
                raise
            outcome = plan.outcome
    finally:
        journal.close()
    if box.state_quarantined:
        outcome = _with_quarantine(outcome)
    after_state = box.read_state()
    verdict = build_verdict(
        outcome,
        run_id=run_id,
        verb=verb,
        args=args,
        actor=actor,
        started=started,
        finished=datetime.now(UTC).replace(microsecond=0),
        passport_version=passport.version if passport is not None else None,
        composition_before=before,
        composition_after=(
            dict(after_state.composition) if after_state else {"pridem": __version__}
        ),
        secrets=secrets,
        catalog=plan.catalog,
    )
    box.write_verdict(verdict)
    if interrupt is not None:
        raise interrupt
    return verdict


def _with_quarantine(outcome: PlanOutcome) -> PlanOutcome:
    quarantined = Incomplete("state", Code("quarantined"))
    return replace(
        outcome,
        code=worst([outcome.code, ExitCode.INCOMPLETE]),
        incomplete=(*outcome.incomplete, quarantined),
    )


def run_plan_verb(
    ctx: Context,
    *,
    verb: str,
    mode: PlanMode,
    stack: str,
    steps: Steps,
) -> int:
    """Run the verb's plan under the box lock; print; return the exit code."""
    box = Box(ctx.root)
    try:
        with box.lock(verb):
            verdict = _verdict(box, ctx, verb=verb, mode=mode, stack=stack, steps=steps)
    except BoxBusy as busy:  # raised only by taking the lock
        raise Refused(f"the box is busy: {busy}") from None
    ctx.out.write((render_json(verdict) if ctx.json else summary_line(verdict)) + "\n")
    return int(verdict.exit_code)
