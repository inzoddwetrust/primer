"""A verb whose run is one plan, under the box lock.

The box's passport copy (``/opt/pridem/passport.yaml``) is read before the
lock: a copy its loader rejects refuses the command with its problems by path
and rule (``ContractError``, no traceback), never as a quiet "no passport".
Under the lock: runs that ended without a verdict get theirs first
(``recover``), then the journal opens with its header -- one journal per hold
of the lock -- the runner is handed the lock's descriptor, the verb makes its
plan (``Make``) and runs it with the journal as its sink, and the verdict is
written to ``history/``. The copy's secrets are cleaned from the journal and the
verdict from the start; a passport the plan reads adds its own. The verdict's
passport version is the plan's passport, else the copy's. Both compositions
are what ``state.json`` holds, ``{pridem}`` without it.

What the verdict says of the box beside the plan, each once, in the verdict of
the command that found it (code 2): ``state.json`` quarantined, a journal
``recover`` put in quarantine (``{journal, quarantined, run_id}``), and the
journal that did not close (``{journal, write-failed}``) -- the journal closes
before the verdict is built.

The actor is the engineer at the console, or the machine when a timer of the
box started the verb (``--timer``). The console gets the summary line --
``doctor`` puts before it a line for each step that would act, the whole plan
in the ladder's order -- or the verdict with ``--json``. A verb with ``ladder``
also prints its ladder as it runs, to stderr under ``--json``, so stdout is the
object alone. A busy box is refused before anything runs.
"""

import secrets as token
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime

from pridem import __version__
from pridem.events import (
    Code,
    ConsoleSink,
    Event,
    EventSink,
    Incomplete,
    Json,
    PlanMode,
    PlanOutcome,
    Secrets,
)
from pridem.plan import Plan, Stack, StackSteps
from pridem.report.catalog import ENGLISH, Catalog, say
from pridem.report.codes import ExitCode, worst
from pridem.report.render import render_json, summary_line, words
from pridem.report.schema import Actor, Verdict, build_verdict
from pridem.runner import Holding
from pridem.stacks.passport import load_passport
from pridem.state import Box, BoxBusy, JournalHeader, JournalSink, Recovery
from pridem.steps.base import Role, Step
from pridem.steps.passport import PASSPORT_COPY, Fetched, passport_secrets
from pridem.steps.tests import TestReport
from pridem.verbs.base import Context, Refused

ROLE_WITHOUT_PASSPORT: Role = "test"
"""The plan's role while no passport is read: the steps before ``fetch_passport``
carry no role, and a step after it without a passport refuses by
``no-passport`` before the role could matter."""

WRITE_FAILED = Incomplete("journal", Code("write-failed"))


@dataclass(frozen=True)
class Session:
    """What a verb's plan is made from, under the lock."""

    box: Box
    run_id: str
    copy: Fetched
    """The box's passport copy, as it was when the command began."""
    secrets: Secrets


@dataclass(frozen=True)
class Planned:
    """A verb's plan: its stacks, its ``finally``, the passport it reads and
    what its tests report."""

    stacks: Sequence[Stack]
    finally_: Sequence[StackSteps] = ()
    fetched: Fetched | None = None
    report: TestReport = field(default_factory=TestReport)


Make = Callable[[Session], Planned]

Steps = Callable[[Box, str, Fetched, Secrets], Sequence[Step]]
"""The steps of a one-stack verb for the box, the run id, the passport and the
run's secrets."""


def _run_id(now: datetime) -> str:
    return f"{now:%Y-%m-%dT%H:%M:%SZ}-{token.token_hex(2)}"


def _actor(ctx: Context) -> dict[str, str]:
    if ctx.timer:
        return {"type": "machine", "via": "timer"}
    return {"type": "engineer", "via": "local"}


def read_copy(ctx: Context) -> Fetched:
    """The box's passport copy; none on a box without one. A copy its loader
    rejects raises ``ContractError``: the command says so and stops."""
    copy = ctx.fs_root / PASSPORT_COPY
    if not copy.is_file():
        return Fetched()
    return Fetched(passport=load_passport(copy))


def close_journal(journal: JournalSink) -> tuple[Incomplete, ...]:
    """Close the journal; a failure to is ``{journal, write-failed}``."""
    try:
        journal.close()
    except Exception:  # disk full, I/O error: the verdict says so (contract 2)
        return (WRITE_FAILED,)
    return ()


def found_on_box(box: Box, recovery: Recovery) -> tuple[Incomplete, ...]:
    """``state.json`` and the journals this command put in quarantine."""
    found = [
        Incomplete("journal", Code("quarantined", {"run_id": run_id}))
        for run_id in recovery.quarantined
    ]
    if box.state_quarantined:
        found.append(Incomplete("state", Code("quarantined")))
    return tuple(found)


def with_incomplete(outcome: PlanOutcome, extra: Sequence[Incomplete]) -> PlanOutcome:
    """``outcome`` with ``extra`` entries no already there, at code 2 at least."""
    added = tuple(entry for entry in extra if entry not in outcome.incomplete)
    if not added:
        return outcome
    return replace(
        outcome,
        code=worst([outcome.code, ExitCode.INCOMPLETE]),
        incomplete=(*outcome.incomplete, *added),
    )


class _Sinks:
    """The journal, and the console's ladder when the verb prints one."""

    def __init__(self, journal: EventSink, console: EventSink | None) -> None:
        self.journal = journal
        self.console = console

    def emit(self, event: Event) -> None:
        if self.console is not None:
            try:
                self.console.emit(event)
            except Exception:  # a closed terminal never stops the run
                self.console = None
        self.journal.emit(event)


def _verdict(
    box: Box,
    ctx: Context,
    *,
    verb: str,
    mode: PlanMode,
    args: Mapping[str, Json],
    make: Make,
    copy: Fetched,
    ladder: bool,
) -> tuple[Verdict, Catalog]:
    """Everything the verb does once it holds the lock; the verdict and the
    words of its codes."""
    passport = copy.passport
    secrets = Secrets(passport_secrets(passport) if passport is not None else ())
    recovery = box.recover(secrets, __version__, ENGLISH)
    state = box.read_state()
    before = dict(state.composition) if state else {"pridem": __version__}
    started = datetime.now(UTC).replace(microsecond=0)
    run_id = _run_id(started)
    actor = _actor(ctx)
    fields: dict[str, object] = {
        "run_id": run_id,
        "verb": verb,
        "mode": mode,
        "args": dict(args),
        "actor": Actor.model_validate(actor),
        "started": started,
        "composition_before": before,
    }
    if passport is not None:  # absent without a passport, never null
        fields["passport_version"] = passport.version
    header = JournalHeader.model_validate(fields)
    journal = box.open_journal(header, secrets)
    if box.lock_fd is not None and isinstance(ctx.runner, Holding):
        ctx.runner.hold(box.lock_fd)
    lost: tuple[Incomplete, ...] = ()
    try:
        planned = make(Session(box, run_id, copy, secrets))
        read = planned.fetched

        def role() -> Role:
            for found in (read, copy):
                if found is not None and found.passport is not None:
                    return found.passport.server.role
            return ROLE_WITHOUT_PASSPORT

        console: EventSink | None = None
        if ladder:
            stream = ctx.err if ctx.json else ctx.out
            console = ConsoleSink(stream, secrets, lambda: plan.catalog)
        plan = Plan(
            planned.stacks,
            mode=mode,
            role=role,
            runner=ctx.runner,
            sink=_Sinks(journal, console),
            finally_=planned.finally_,
            interrupt=ctx.interrupt,
        )
        outcome = plan.run()
    finally:
        lost = close_journal(journal)
    outcome = with_incomplete(outcome, (*found_on_box(box, recovery), *lost))
    read_passport = planned.fetched.passport if planned.fetched else None
    shown = read_passport if read_passport is not None else passport
    after_state = box.read_state()
    verdict = build_verdict(
        outcome,
        run_id=run_id,
        verb=verb,
        args=dict(args),
        actor=actor,
        started=started,
        finished=datetime.now(UTC).replace(microsecond=0),
        passport_version=shown.version if shown is not None else None,
        composition_before=before,
        composition_after=(
            dict(after_state.composition) if after_state else {"pridem": __version__}
        ),
        secrets=secrets,
        failures=planned.report.failures,
        junit=planned.report.junit,
        catalog=plan.catalog,
    )
    box.write_verdict(verdict)
    return verdict, plan.catalog


def _diff_lines(verdict: Verdict, catalog: Catalog) -> list[str]:
    """What ``doctor`` would do, step by step, in the ladder's order."""
    return [
        say(
            catalog,
            "@doctor.item",
            stack=item.stack,
            name=item.name,
            words=words(catalog, item),
        )
        for item in verdict.report.doctor_diff or []
    ]


def run_plan_verb(
    ctx: Context,
    *,
    verb: str,
    mode: PlanMode,
    make: Make,
    args: Mapping[str, Json] | None = None,
    ladder: bool = False,
    copy: Fetched | None = None,
) -> int:
    """Run the verb's plan under the box lock; print; return the exit code."""
    found = copy if copy is not None else read_copy(ctx)
    box = Box(ctx.root)
    try:
        with box.lock(verb):
            verdict, catalog = _verdict(
                box,
                ctx,
                verb=verb,
                mode=mode,
                args=args or {},
                make=make,
                copy=found,
                ladder=ladder,
            )
    except BoxBusy as busy:  # raised only by taking the lock
        raise Refused(f"the box is busy: {busy}") from None
    if ctx.json:
        ctx.out.write(render_json(verdict) + "\n")
    else:
        lines = [*_diff_lines(verdict, catalog), summary_line(verdict)]
        ctx.out.write("\n".join(lines) + "\n")
    return int(verdict.exit_code)


def one_stack(stack: str, steps: Steps) -> Make:
    """The plan of a verb that is one stack of its own steps (``gc``,
    ``ssl renew``), on the copy's passport."""

    def make(session: Session) -> Planned:
        made = steps(session.box, session.run_id, session.copy, session.secrets)
        return Planned([StackSteps(stack, made, root=True)])

    return make
