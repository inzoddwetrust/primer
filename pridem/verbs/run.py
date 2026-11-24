"""A verb whose run is one plan, under the box lock.

The box's passport copy (``/opt/pridem/passport.yaml``) is read before the
lock: a copy its loader rejects refuses the command with its problems by path
and rule (``ContractError``, no traceback), never as a quiet "no passport".
Under the lock: runs that ended without a verdict get theirs first
(``recover``), then the verb's own check of the box may refuse (``Before``:
no journal, no verdict -- ``rollback``), then the journal opens with its
header -- one journal per hold of the lock -- the runner is handed the lock's
descriptor, the verb makes its plan (``Make``) and runs it with the journal as
its sink, and the verdict is written to ``history/``. The copy's secrets are
cleaned from the journal and the verdict from the start; a passport the plan
reads adds its own. The verdict's passport version is the plan's passport, else
the copy's. Both compositions are what ``state.json`` holds, ``{pridem}``
without it.

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

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from typing import Literal, TextIO

from pydantic import SecretStr

from pridem import __version__
from pridem.contract import SECRET_MIN_LENGTH
from pridem.events import (
    INTERNAL_STACKS,
    Attachable,
    Code,
    ConsoleSink,
    Event,
    EventSink,
    Fact,
    Incomplete,
    Json,
    LogLine,
    Notice,
    PlanMode,
    PlanOutcome,
    Secrets,
    SecretsUnread,
    StepRecord,
    said,
)
from pridem.plan import Plan, Stack, StackSteps
from pridem.report.catalog import ENGLISH, Catalog, say
from pridem.report.codes import ExitCode, worst
from pridem.report.refusal import busy as busy_refusal
from pridem.report.refusal import rendered as rendered_refusal
from pridem.report.render import closing, render_json, words
from pridem.report.schema import Actor, Verdict, build_verdict
from pridem.runner import Holding, Stream
from pridem.stacks import names as machine
from pridem.stacks.env import MINTED_FILE, env_file, parse_env, read_minted
from pridem.stacks.loader import ContractError
from pridem.stacks.passport import Passport, load_passport, size_bytes
from pridem.stacks.schema import load_primer_yaml
from pridem.state import (
    Box,
    BoxBusy,
    JournalHeader,
    JournalSink,
    LockHolder,
    Recovery,
)
from pridem.steps.base import Role, Step, StepFailed
from pridem.steps.destroy import machine_stacks
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
    restore_on: frozenset[str] = frozenset()
    """Codes of a failed step that leave only a restore: the verdict says
    ``{restore, needed}`` (``rollback_check:migrated``, DM-24)."""


Make = Callable[[Session], Planned]

Before = Callable[[Box], None]
"""What a verb checks under the lock before its journal opens -- after
``recover``, so ``history/`` holds every run -- raising ``Refused``: a refusal,
not a command, with no journal and no verdict (``rollback``, DM-24)."""

Notes = Callable[[Verdict, Catalog], Sequence[str]]
"""Lines a verb prints before the summary line, from its verdict."""

Steps = Callable[[Box, str, Fetched, Secrets], Sequence[Step]]
"""The steps of a one-stack verb for the box, the run id, the passport and the
run's secrets."""


def finished_at(started: datetime, journal: JournalSink) -> datetime:
    """Now, or ``started`` when the clock went back during the run (an NTP
    step): the verdict's ``finished`` is never before ``started``, and the
    journal says by how much it went back (DM-77)."""
    now = datetime.now(UTC).replace(microsecond=0)
    if now >= started:
        return now
    back = int((started - now).total_seconds())
    journal.emit(
        LogLine(
            "finally",
            machine.PRIDEM,
            "clock",
            Stream.STDERR,
            f"clock-back {back} s: finished is taken as started",
        )
    )
    return started


def _actor(ctx: Context) -> dict[str, str]:
    if ctx.timer:
        return {"type": "machine", "via": "timer"}
    if ctx.command is not None:  # who pressed is the Panel's record (DM-138)
        return {"type": "engineer", "via": "panel"}
    return {"type": "engineer", "via": "local"}


def lock_holder(ctx: Context, box: Box, verb: str) -> tuple[LockHolder, datetime]:
    """The run's id, taken before the lock -- the lock's file names it -- and
    what the lock says of the run (DM-138). The id is the run's once its
    journal is made, exclusively, under the lock: a second command that took
    the same id is refused by the lock before it."""
    started = datetime.now(UTC).replace(microsecond=0)
    run_id = box.new_run_id(started)
    held: dict[str, object] = {
        "run_id": run_id,
        "verb": verb,
        "actor": Actor.model_validate(_actor(ctx)),
        "since": started,
    }
    if ctx.command is not None:
        held["command"] = ctx.command
    return LockHolder.model_validate(held), started


def refuse_busy(ctx: Context, busy: BoxBusy) -> Refused:
    """The refusal of a busy box: with ``--json`` its object on stdout for the
    agent (DM-138); the line on stderr in every case."""
    if ctx.json:
        said(ctx.out, rendered_refusal(busy_refusal(busy)) + "\n")
    return Refused(f"the box is busy: {busy}")


def read_copy(ctx: Context, *, replaced: bool = False) -> Fetched:
    """The box's passport copy; none on a box without one. A copy its loader
    rejects raises ``ContractError``: the command says so and stops -- but a
    run given a new passport to replace it (``replaced``: ``--passport`` or
    ``--ops``) reads a rejected copy as none, or nothing could ever replace
    it (DM-190, E10)."""
    copy = ctx.fs_root / PASSPORT_COPY
    if not copy.is_file():
        return Fetched()
    try:
        return Fetched(passport=load_passport(copy))
    except ContractError:
        if replaced:
            return Fetched()
        raise


def close_journal(journal: JournalSink) -> tuple[Incomplete, ...]:
    """Close the journal of a run that did not end -- no ``run_finished``
    (DM-137); a failure to is ``{journal, write-failed}``."""
    try:
        journal.close()
    except Exception:  # disk full, I/O error: the verdict says so (contract 2)
        return (WRITE_FAILED,)
    return ()


def sync_journal(journal: JournalSink) -> tuple[Incomplete, ...]:
    """Everything of the run on the disk before its verdict; a failure to is
    ``{journal, write-failed}`` in the verdict (contract 2)."""
    try:
        journal.sync()
    except Exception:  # disk full, I/O error: the verdict says so
        return (WRITE_FAILED,)
    return ()


def end_journal(journal: JournalSink, verdict: Verdict, err: TextIO) -> None:
    """``run_finished`` once the verdict is in ``history/``, and the close
    (DM-137). A failure here cannot reach the verdict, written already: one
    line to stderr, and the exit code stays the verdict's -- the journal then
    reads as a run that did not end, and ``history/`` has its verdict."""
    try:
        journal.finish(verdict.exit_code, verdict.result)
    except Exception as error:  # disk full, I/O error
        err.write(
            f"journal: the end of the run is not written: {type(error).__name__}\n"
        )


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

    def __init__(self, journal: JournalSink, console: EventSink | None) -> None:
        self.journal = journal
        self.console = console

    def emit(self, event: Event) -> None:
        if self.console is not None:
            try:
                self.console.emit(event)
            except Exception:  # a closed terminal never stops the run
                self.console = None
        self.journal.emit(event)

    def attach(self, catalog: Callable[[], Catalog]) -> None:
        """The plan's catalog to the console (DM-107 FIX 2)."""
        if isinstance(self.console, Attachable):
            self.console.attach(catalog)

    def notice(self, notice: Notice) -> None:
        """What a step tells a person -- a key to add -- to the console and
        to the journal, the run's stream (DM-137)."""
        if isinstance(self.console, Attachable):
            self.console.notice(notice)
        self.journal.notice(notice)


GOES_ON_UNREAD = frozenset({"destroy", "reinstall", "status"})
"""The runs that go on when a stack's secrets cannot be read (DM-183): the
ways a box with a broken file is mended or taken off. Every other run is
refused -- it could print a value it does not know to clean."""


@dataclass(frozen=True)
class BoxSecrets:
    """The known secrets of the box, and the stacks whose files said none."""

    values: list[SecretStr]
    unread: list[tuple[str, Literal["minted", "env", "primer-yaml"]]]
    every: frozenset[str] = frozenset()
    """Every value, short ones too: what ``verb`` refuses as an argument."""


def box_secrets(ctx: Context, passport: Passport | None) -> BoxSecrets:
    """Every known secret of the box (contract 2 rule 2, DM-183): ``asked``
    and ``tls`` of the passport, and of each stack with the machine's mark
    and a release ``current`` names -- its ``minted.yaml`` and the values of
    its ``derived`` keys in its env file. A seam is its provider's value,
    there already; an ``address`` is no secret. Read under the lock, before
    the journal: the one place every run goes through. A value shorter than
    ``SECRET_MIN_LENGTH`` is no known secret (contract 2 rule 2): the machine
    mints and derives none such, the passport's rule keeps ``asked`` to it."""
    found: list[str] = []
    if passport is not None:
        found += [secret.get_secret_value() for secret in passport_secrets(passport)]
    unread: list[tuple[str, Literal["minted", "env", "primer-yaml"]]] = []
    for home in machine_stacks(ctx.fs_root):
        current = home / "current"
        if not current.is_symlink():
            continue  # no release: nothing of it runs
        stack = home.name
        try:
            found += list(read_minted(home / "env" / MINTED_FILE).values())
        except (StepFailed, OSError, ValueError):
            unread.append((stack, "minted"))
            continue
        try:
            made = load_primer_yaml(current.resolve() / "primer.yaml")
        except (ContractError, OSError):
            unread.append((stack, "primer-yaml"))
            continue
        derived = {key for key, value in made.env.items() if value.source == "derived"}
        if not derived:
            continue
        try:
            held = parse_env(
                env_file(ctx.fs_root, stack, staged=False).read_text(encoding="utf-8")
            )
        except (OSError, ValueError):
            unread.append((stack, "env"))
            continue
        found += [held[key] for key in sorted(derived) if key in held]
    values = sorted({v for v in found if len(v) >= SECRET_MIN_LENGTH})
    every = frozenset(v for v in found if v.strip())
    return BoxSecrets([SecretStr(v) for v in values], unread, every)


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
    before: Before | None = None,
    held: LockHolder,
    started: datetime,
) -> tuple[Verdict, Catalog]:
    """Everything the verb does once it holds the lock; the verdict and the
    words of its codes. ``held`` -- the run the lock names: its id, actor and
    command go to the journal's header and the verdict."""
    passport = copy.passport
    known = box_secrets(ctx, passport)
    if known.unread and verb not in GOES_ON_UNREAD:
        stack, why = known.unread[0]
        raise Refused(f"{verb}: the secrets of {stack} cannot be read ({why})")
    secrets = Secrets(known.values)  # every secret of the box (DM-183)
    recovery = box.recover(secrets, __version__, ENGLISH)
    if before is not None:
        before(box)
    state = box.read_state()
    composed = dict(state.composition) if state else {"pridem": __version__}
    run_id = held.run_id
    actor = held.actor.model_dump(exclude_none=True)
    fields: dict[str, object] = {
        "run_id": run_id,
        "verb": verb,
        "mode": mode,
        "args": dict(args),
        "actor": held.actor,
        "started": started,
        "composition_before": composed,
    }
    if held.command is not None:  # absent for the console and a timer
        fields["command"] = held.command
    if passport is not None:  # absent without a passport, never null
        fields["passport_version"] = passport.version
    header = JournalHeader.model_validate(fields)
    budget = passport.policies.gc.journal_budget if passport is not None else None
    limit = size_bytes(budget) if budget is not None else None  # DM-24
    journal = box.open_journal(header, secrets, limit)
    unread = [SecretsUnread(stack, why) for stack, why in known.unread]
    for notice in unread:  # a run that goes on says what it could not clean
        journal.notice(notice)
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

        console: ConsoleSink | None = None
        if ladder:
            stream = ctx.err if ctx.json else ctx.out
            console = ConsoleSink(stream, secrets)  # the plan attaches its catalog
            for notice in unread:
                console.notice(notice)
        plan = Plan(
            planned.stacks,
            mode=mode,
            role=role,
            runner=ctx.runner,
            sink=_Sinks(journal, console),
            finally_=planned.finally_,
            interrupt=ctx.interrupt,
        )
        if console is not None:
            server = passport.server.name if passport is not None else None
            console.header(verb, __version__, server)
        try:
            outcome = plan.run()
        finally:
            if console is not None:
                console.close()  # no ticker outlives the plan (DM-107)
        restore = planned.restore_on
        if any(_failed_by(record, restore) for record in outcome.steps):
            outcome = replace(outcome, needs_restore=True, restore_empty=False)
    except BaseException:
        # an error of the machine: the journal ends with no run_finished --
        # a run that did not end, which recover closes (DM-137)
        close_journal(journal)
        raise
    try:
        finished = finished_at(started, journal)
        lost = sync_journal(journal)
        cut = (
            (Incomplete("journal", Code("cut", {"limit": journal.cut})),)
            if journal.cut is not None
            else ()
        )
        outcome = with_incomplete(outcome, (*found_on_box(box, recovery), *lost, *cut))
        read_passport = planned.fetched.passport if planned.fetched else None
        shown = read_passport if read_passport is not None else passport
        after_state = box.read_state()

        def assemble(
            found: PlanOutcome,
            failures: Sequence[Fact],
            junit: Mapping[str, int] | None,
        ) -> Verdict:
            return build_verdict(
                found,
                run_id=run_id,
                verb=verb,
                args=dict(args),
                actor=actor,
                started=started,
                finished=finished,
                passport_version=shown.version if shown is not None else None,
                composition_before=composed,
                composition_after=(
                    dict(after_state.composition)
                    if after_state
                    else {"pridem": __version__}
                ),
                secrets=secrets,
                failures=failures,
                junit=junit,
                catalog=plan.catalog,
                command=held.command,
            )

        try:
            verdict = assemble(outcome, planned.report.failures, planned.report.junit)
        except Exception as error:  # the model refused what the run gave (DM-92)
            # any error of the model's code, not its ValueError alone (DM-190, E7)
            name = type(error).__name__
            note = LogLine(
                "finally", machine.VERDICT, "build", Stream.STDERR, f"{name}: {error}"
            )
            journal.emit(note)  # the stream's own next line (DM-137)
            journal.sync()
            try:
                verdict = assemble(salvaged(outcome, name, assemble), (), None)
            except Exception:  # the last rung: the run, red, and why (E7)
                verdict = assemble(unbuildable(outcome, name), (), None)
        box.write_verdict(verdict)
    except BaseException:
        close_journal(journal)  # no verdict, no end: a run that did not end
        raise
    end_journal(journal, verdict, ctx.err)
    return verdict, plan.catalog


Assemble = Callable[[PlanOutcome, Sequence[Fact], Mapping[str, int] | None], Verdict]


def unbuildable(outcome: PlanOutcome, error: str) -> PlanOutcome:
    """The last rung of a verdict that could not be built (DM-190, E7): red,
    nothing of the run but ``run/unbuildable {type}`` -- a verdict always."""
    return replace(
        outcome,
        code=ExitCode.FAILED,
        steps=(),
        restore=(),
        finally_=(),
        incomplete=(Incomplete("run", Code("unbuildable", {"type": error})),),
        doctor_diff=(),
        needs_restore=False,
    )


def salvaged(outcome: PlanOutcome, error: str, assemble: Assemble) -> PlanOutcome:
    """The outcome of a run whose verdict could not be built: red, every step,
    ``incomplete`` and ``doctor`` entry the verdict takes on its own, no
    failures of tests, and ``run/unbuildable {type}`` -- a verdict always
    (DM-92). An entry is taken when a verdict of it alone is built."""
    base = replace(
        outcome,
        code=ExitCode.FAILED,
        steps=(),
        restore=(),
        finally_=(),
        incomplete=(),
        doctor_diff=(),
        needs_restore=False,
    )

    def fits(part: PlanOutcome) -> bool:
        try:
            assemble(part, (), None)
        except Exception:  # whatever refuses it (DM-190, E7)
            return False
        return True

    return replace(
        base,
        steps=tuple(r for r in outcome.steps if fits(replace(base, steps=(r,)))),
        restore=tuple(r for r in outcome.restore if fits(replace(base, restore=(r,)))),
        finally_=tuple(
            r for r in outcome.finally_ if fits(replace(base, finally_=(r,)))
        ),
        incomplete=(
            *(i for i in outcome.incomplete if fits(replace(base, incomplete=(i,)))),
            Incomplete("run", Code("unbuildable", {"type": error})),
        ),
        doctor_diff=tuple(
            d for d in outcome.doctor_diff if fits(replace(base, doctor_diff=(d,)))
        ),
        needs_restore=outcome.needs_restore,
    )


def _failed_by(record: StepRecord, codes: frozenset[str]) -> bool:
    return (
        record.status == "failed"
        and record.reason is not None
        and (record.reason.code in codes)
    )


def _diff_lines(verdict: Verdict, catalog: Catalog) -> list[str]:
    """What ``doctor`` would do, step by step, in the ladder's order -- each
    step by its title, the stack named only for a product's or a service's
    (DM-107: no internal name in the console)."""
    lines = []
    for item in verdict.report.doctor_diff or []:
        title = catalog.get(f"@title.{item.name}") or item.name
        if item.stack not in INTERNAL_STACKS and not item.stack.startswith("pridem-"):
            title = say(catalog, "@console.of", stack=item.stack, title=title)
        lines.append(
            say(catalog, "@doctor.line", title=title, words=words(catalog, item))
        )
    return lines


def run_plan_verb(
    ctx: Context,
    *,
    verb: str,
    mode: PlanMode,
    make: Make,
    args: Mapping[str, Json] | None = None,
    ladder: bool = False,
    copy: Fetched | None = None,
    before: Before | None = None,
    notes: Notes | None = None,
) -> int:
    """Run the verb's plan under the box lock; print; return the exit code."""
    found = copy if copy is not None else read_copy(ctx)
    box = Box(ctx.root)
    held, started = lock_holder(ctx, box, verb)
    try:
        with box.lock(held.model_dump_json()):
            verdict, catalog = _verdict(
                box,
                ctx,
                verb=verb,
                mode=mode,
                args=args or {},
                make=make,
                copy=found,
                ladder=ladder,
                before=before,
                held=held,
                started=started,
            )
    except BoxBusy as busy:  # raised only by taking the lock
        raise refuse_busy(ctx, busy) from None
    if ctx.json:
        said(ctx.out, render_json(verdict) + "\n")
    else:
        noted = list(notes(verdict, catalog)) if notes is not None else []
        lines = [*_diff_lines(verdict, catalog), *noted, *closing(verdict, catalog)]
        said(ctx.out, "\n".join(lines) + "\n")  # a console gone: the verdict is written
    return int(verdict.exit_code)


def one_stack(stack: str, steps: Steps) -> Make:
    """The plan of a verb that is one stack of its own steps (``gc``,
    ``ssl renew``), on the copy's passport."""

    def make(session: Session) -> Planned:
        made = steps(session.box, session.run_id, session.copy, session.secrets)
        return Planned([StackSteps(stack, made, root=True)])

    return make
