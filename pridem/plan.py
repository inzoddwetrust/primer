"""The plan: a ladder of steps by stacks, modes, point of no return, ``finally``.

The ladder runs the dependencies of the box's root stack in the order given,
then the root stack last; there is exactly one root, of any kind (a box of a
shared remote service has a service as its root). Inside a stack, steps run by
``order``; ``restore`` and ``finally`` steps are chosen the same way, by
``order`` and by ``modes``.

In ``install``, ``deploy`` and ``reinstall`` every step runs ``check``, then
``act`` if needed, then ``verify``. The first failed step stops the ladder: the
rest are ``skipped`` with the reason. If the plan has not yet started the
``act`` of a point-of-no-return step, the caller's ``restore`` steps run; after
that point nothing automatic is done and the outcome says a restore is needed.
``finally`` steps run every time, after everything else; a failed ``finally``
step never stops the others, only an interrupt during a ``finally`` step does
-- one between its steps is kept, and the clean-up goes on to its end.
``doctor`` runs only ``check`` of the ``deploy`` steps and reports what would be
done.

A step never crashes a plan: any exception from a phase is that step's failure.
An interrupt (``KeyboardInterrupt``, and a ``SIGTERM`` turned into one) is an
interrupt of the run wherever it lands -- in a step, between steps, while an
event is written: the rest of the main ladder or ``restore`` is skipped,
``restore`` (before the point of no return) and ``finally`` still run, the
outcome is emitted and kept in ``Plan.outcome``, and the interrupt is raised
again.

A sink never crashes a plan either: its first failure is ``{what: journal,
code: write-failed}`` in the outcome and the sink is not called again; an event
cut by an interrupt is such a failure too (a half-written line ends the
journal).

Every reason is a code with parameters (contract 2 v1.6), never a phrase. A
step a command let down has the code of the runner's error with the command
and its exit code, timeout or ``errno`` -- by name, from the ``OSError`` behind
``CommandNotStarted``, else ``null`` -- never its output. Any other unexpected
exception is ``exception {type}``; its text, and the system's text for a
command that did not start, go to the journal as ``stderr`` lines, where known
secrets are cleaned. A step's own codes (``StepFailed``, ``CheckResult.would``,
``Verified.incomplete``) are prefixed with its name, ``<step>:<code>``;
``catalog`` is the machine's catalog plus the texts the plan's steps declare.
"""

import errno
import time
import traceback
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime

from pridem.events import (
    AFTER_INTERRUPT,
    INTERRUPTED,
    NO_FACT,
    Code,
    DoctorItem,
    Event,
    EventSink,
    Fact,
    Incomplete,
    LogLine,
    Phase,
    PlanFinished,
    PlanMode,
    PlanOutcome,
    Status,
    StepFinished,
    StepRecord,
    StepStarted,
    after_failure,
    role_skip,
)
from pridem.report.catalog import ENGLISH, Catalog, with_steps
from pridem.report.codes import ExitCode, worst
from pridem.runner import (
    CommandFailed,
    CommandNotStarted,
    CommandTimedOut,
    Runner,
    Stream,
)
from pridem.steps.base import (
    MODES,
    CheckResult,
    Mode,
    Role,
    Step,
    StepContext,
    StepFailed,
)


def _errno_name(error: CommandNotStarted) -> str | None:
    """The ``errno`` name of the ``OSError`` behind ``error``, if there is one."""
    cause = error.__cause__
    if isinstance(cause, OSError) and cause.errno is not None:
        return errno.errorcode.get(cause.errno)
    return None


def _failure_code(error: Exception) -> Code:
    """The reason of a step that raised ``error``.

    A runner's command error is the command and what happened to it, never its
    output. Any other error is its type name: its text may quote anything, a
    secret included, and the verdict lives forever; the text goes to the
    journal instead.
    """
    if isinstance(error, CommandFailed):
        return Code(
            "command-failed", {"argv": list(error.argv), "exit_code": error.code}
        )
    if isinstance(error, CommandTimedOut):
        return Code(
            "command-timed-out", {"argv": list(error.argv), "timeout_s": error.timeout}
        )
    if isinstance(error, CommandNotStarted):
        return Code(
            "command-not-started",
            {"argv": list(error.argv), "errno": _errno_name(error)},
        )
    return Code("exception", {"type": type(error).__name__})


def _qualified(step: Step, code: Code) -> Code:
    """A step's own code as the verdict keeps it: ``<step>:<code>``."""
    return Code(f"{step.name}:{code.code}", code.params)


@dataclass(frozen=True)
class StackSteps:
    """The steps of one stack; ``root`` marks the box's root stack."""

    name: str
    steps: Sequence[Step]
    root: bool = False


def _validate_steps(stack: StackSteps) -> None:
    names: set[str] = set()
    orders: set[int] = set()
    for step in stack.steps:
        for attribute in ("name", "order", "modes"):
            if not hasattr(step, attribute):
                raise ValueError(f"{stack.name}: step {step!r} declares no {attribute}")
        if not step.modes or not step.modes <= MODES:
            raise ValueError(
                f"{stack.name}/{step.name}: modes must be a non-empty subset of "
                f"{sorted(MODES)}, got {sorted(step.modes)}"
            )
        if step.name in names:
            raise ValueError(f"{stack.name}: two steps named {step.name!r}")
        if step.order in orders:
            raise ValueError(f"{stack.name}: two steps with order {step.order}")
        names.add(step.name)
        orders.add(step.order)


def ladder(stacks: Sequence[StackSteps]) -> list[StackSteps]:
    """Dependencies in the given order, then the root; exactly one root."""
    roots = [stack for stack in stacks if stack.root]
    if len(roots) != 1:
        raise ValueError(f"a plan needs exactly one root stack, got {len(roots)}")
    seen: set[str] = set()
    for stack in stacks:
        if stack.name in seen:
            raise ValueError(f"two stacks named {stack.name!r}")
        seen.add(stack.name)
        _validate_steps(stack)
    return [stack for stack in stacks if not stack.root] + roots


@dataclass
class _Run:
    """Mutable bookkeeping of one run; never leaves the plan."""

    crossed: bool = False
    interrupt: KeyboardInterrupt | None = None
    incomplete: list[Incomplete] = field(default_factory=list)
    sink_failed: bool = False
    cut: bool = False
    """The step just executed was interrupted while it ran."""


SINK_FAILED = Incomplete("journal", Code("write-failed"))


def _chosen(stacks: Sequence[StackSteps], mode: Mode) -> list[tuple[str, Step]]:
    """The steps of ``stacks`` for ``mode``, by ``order`` inside each stack."""
    return [
        (stack.name, step)
        for stack in stacks
        for step in sorted(stack.steps, key=lambda s: s.order)
        if mode in step.modes
    ]


class Plan:
    """A plan for one mode and role, ready to ``run`` once."""

    def __init__(
        self,
        stacks: Sequence[StackSteps],
        *,
        mode: PlanMode,
        role: Role,
        runner: Runner,
        sink: EventSink,
        restore: Sequence[StackSteps] = (),
        finally_: Sequence[StackSteps] = (),
        clock: Callable[[], float] = time.monotonic,
        now: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        selected: Mode = "deploy" if mode == "doctor" else mode
        self._mode = mode
        self._role = role
        self._runner = runner
        self._sink = sink
        self._clock = clock
        self._now = now
        self._run = _Run()
        self.outcome: PlanOutcome | None = None
        """The outcome of the run, also when ``run`` ends by raising an interrupt."""
        self._steps = _chosen(ladder(stacks), selected)
        if not self._steps:
            raise ValueError(f"no step of the plan runs in mode {mode!r}")
        for extra in (*restore, *finally_):
            _validate_steps(extra)
        self._restore = _chosen(restore, selected)
        self._finally = _chosen(finally_, selected)
        steps = (*self._steps, *self._restore, *self._finally)
        self.catalog: Catalog = with_steps(
            ENGLISH, ((step.name, type(step).codes) for _, step in steps)
        )
        """The machine's texts and those of the plan's steps."""

    # --- events ---------------------------------------------------------------

    def _emit(self, event: Event) -> None:
        """Hand ``event`` to the sink; its failure is recorded, never raised.

        An interrupt while the sink writes is an interrupt of the run, and the
        event is lost like any failed write: the sink is not called again.
        """
        if self._run.sink_failed:
            return
        try:
            self._sink.emit(event)
        except KeyboardInterrupt as interrupt:
            self._run.sink_failed = True
            self._run.interrupt = interrupt
        except Exception:  # disk full, I/O error: the plan goes on (contract 2)
            self._run.sink_failed = True

    def _finish(self, outcome: PlanOutcome) -> PlanOutcome:
        """Emit the outcome; a sink that fails on it still shows in the outcome."""
        failed_before = self._run.sink_failed
        self._emit(PlanFinished(outcome))
        if self._run.sink_failed and not failed_before:
            interrupted = self._run.interrupt is not None
            codes = [outcome.code, ExitCode.INCOMPLETE]
            outcome = replace(
                outcome,
                code=worst([*codes, ExitCode.FAILED] if interrupted else codes),
                incomplete=(*outcome.incomplete, SINK_FAILED),
                interrupted=interrupted,
            )
        self.outcome = outcome
        return outcome

    def _context(self, phase: Phase, stack: str, step: Step) -> StepContext:
        def on_line(stream: Stream, line: str) -> None:
            before = self._run.interrupt
            self._emit(LogLine(phase, stack, step.name, stream, line))
            if self._run.interrupt is not None and self._run.interrupt is not before:
                raise self._run.interrupt  # the runner stops the command's group

        mode: Mode = "deploy" if self._mode == "doctor" else self._mode
        return StepContext(self._runner, mode, self._role, stack, on_line)

    def _record(self, phase: Phase, record: StepRecord) -> StepRecord:
        self._emit(StepFinished(phase, record))
        return record

    def _skipped(
        self, phase: Phase, stack: str, step: Step, reason: Code
    ) -> StepRecord:
        record = StepRecord(stack, step.name, step.order, "skipped", reason)
        return self._record(phase, record)

    def _unexpected(
        self, phase: Phase, stack: str, step: Step, error: Exception
    ) -> Code:
        """The code of ``error``; text a verdict cannot keep goes to the log.

        That is the text of an error from outside the runner, and the system's
        reason a command did not start.
        """
        texts: list[str] = []
        if isinstance(error, CommandNotStarted):
            texts = [error.reason]
        elif not isinstance(error, CommandFailed | CommandTimedOut):
            texts = traceback.format_exception_only(error)
        for text in texts:
            for line in text.rstrip("\n").split("\n"):
                self._emit(LogLine(phase, stack, step.name, Stream.STDERR, line))
        return _failure_code(error)

    # --- the run --------------------------------------------------------------

    def run(self) -> PlanOutcome:
        """Run the plan; emit every event; return the outcome."""
        if self._mode == "doctor":
            return self._doctor()
        state = self._run
        steps = self._ladder("main", self._steps, stop_on_failure=True)
        main_failed = any(record.status == "failed" for record in steps)
        stopped = main_failed or state.interrupt is not None
        restore: list[StepRecord] = []
        if stopped and not state.crossed:
            restore = self._ladder("restore", self._restore, stop_on_failure=True)
        final = self._ladder("finally", self._finally, stop_on_failure=False)
        records = (*steps, *restore, *final)
        if state.sink_failed:
            state.incomplete.append(SINK_FAILED)
        incomplete = tuple(state.incomplete)
        codes = [ExitCode.OK]
        codes += [ExitCode.FAILED for record in records if record.status == "failed"]
        codes += [ExitCode.INCOMPLETE for _ in incomplete]
        if state.interrupt is not None:
            codes.append(ExitCode.FAILED)
        outcome = self._finish(
            PlanOutcome(
                mode=self._mode,
                code=worst(codes),
                steps=tuple(steps),
                restore=tuple(restore),
                finally_=tuple(final),
                incomplete=incomplete,
                needs_restore=stopped and state.crossed,
                interrupted=state.interrupt is not None,
            )
        )
        if state.interrupt is not None:
            raise state.interrupt
        return outcome

    def _ladder(
        self,
        phase: Phase,
        steps: Sequence[tuple[str, Step]],
        *,
        stop_on_failure: bool,
    ) -> list[StepRecord]:
        """Run ``steps``.

        An interrupt during a step (in its phases or while its start is
        written) stops any ladder; the rest is skipped. The main ladder and
        ``restore`` (``stop_on_failure``) also stop on a failed step and on an
        interrupt between steps. ``finally`` stops on nothing else: an interrupt
        between its steps is kept for the final raise and the clean-up goes on
        to its last step.
        """
        state = self._run
        records: list[StepRecord] = []
        stopped: Code | None = None
        for stack, step in steps:
            if stopped is not None:
                records.append(self._skipped(phase, stack, step, stopped))
                continue
            before = state.interrupt
            recorded = False
            while not recorded:
                count = len(records)
                try:
                    if step.roles is not None and self._role not in step.roles:
                        record = self._skipped(
                            phase, stack, step, role_skip(self._role)
                        )
                    else:
                        record = self._execute(phase, stack, step)
                    records.append(record)
                    recorded = True
                except KeyboardInterrupt as interrupt:  # between steps, not in one
                    state.interrupt = interrupt
                    if len(records) > count:
                        recorded = True  # the step ran; only its bookkeeping was cut
                        record = records[-1]
                    elif stop_on_failure:
                        record = self._skipped(phase, stack, step, AFTER_INTERRUPT)
                        records.append(record)
                        recorded = True
                    # finally: the step has not run yet; run it now
            if state.cut:
                stopped = after_failure(phase, stack, step.name)
            elif not stop_on_failure:
                continue
            elif record.status == "failed":
                stopped = after_failure(phase, stack, step.name)
            elif state.interrupt is not before:  # between steps or after its record
                stopped = AFTER_INTERRUPT
        return records

    def _execute(self, phase: Phase, stack: str, step: Step) -> StepRecord:
        state = self._run
        state.cut = False
        before = state.interrupt
        fact: Fact = {}
        reason: Code | None = None
        started = self._now()
        begin = self._clock()
        try:
            self._emit(StepStarted(phase, stack, step.name, step.order, started))
            if state.interrupt is not before:
                raise state.interrupt or KeyboardInterrupt()
            ctx = self._context(phase, stack, step)
            check = step.check(ctx)
            if check.needed:
                if step.point_of_no_return:
                    state.crossed = True
                step.act(ctx, check)
            verified = step.verify(ctx, check)
            fact = dict(verified.fact)
            if not fact:
                reason = NO_FACT
            elif verified.incomplete is not None:
                state.incomplete.append(
                    Incomplete(step.name, _qualified(step, verified.incomplete))
                )
        except StepFailed as error:
            reason, fact = _qualified(step, error.reason), dict(error.fact)
        except KeyboardInterrupt as interrupt:
            state.interrupt = interrupt
            state.cut = True
            reason = INTERRUPTED
        except Exception as error:  # a step never crashes the plan; it fails
            reason = self._unexpected(phase, stack, step, error)
        status: Status = "ok" if reason is None else "failed"
        duration = self._clock() - begin
        return self._record(
            phase,
            StepRecord(
                stack, step.name, step.order, status, reason, started, duration, fact
            ),
        )

    def _doctor(self) -> PlanOutcome:
        state = self._run
        records: list[StepRecord] = []
        diff: list[DoctorItem] = []
        for stack, step in self._steps:
            if state.interrupt is not None:
                records.append(self._skipped("main", stack, step, AFTER_INTERRUPT))
                continue
            count = len(records)
            try:
                if step.roles is not None and self._role not in step.roles:
                    records.append(
                        self._skipped("main", stack, step, role_skip(self._role))
                    )
                    continue
                self._check(stack, step, records, diff)
            except KeyboardInterrupt as interrupt:  # between checks, not in one
                state.interrupt = interrupt
                if len(records) == count:
                    records.append(self._skipped("main", stack, step, AFTER_INTERRUPT))
        if state.sink_failed:
            state.incomplete.append(SINK_FAILED)
        codes = [ExitCode.OK]
        codes += [ExitCode.FAILED for record in records if record.status == "failed"]
        codes += [ExitCode.INCOMPLETE for _ in diff]
        codes += [ExitCode.INCOMPLETE for _ in state.incomplete]
        if state.interrupt is not None:
            codes.append(ExitCode.FAILED)
        outcome = self._finish(
            PlanOutcome(
                mode="doctor",
                code=worst(codes),
                steps=tuple(records),
                incomplete=tuple(state.incomplete),
                doctor_diff=tuple(diff),
                interrupted=state.interrupt is not None,
            )
        )
        if state.interrupt is not None:
            raise state.interrupt
        return outcome

    def _check(
        self,
        stack: str,
        step: Step,
        records: list[StepRecord],
        diff: list[DoctorItem],
    ) -> None:
        """One ``doctor`` check: a failed check is a record, a needed one a diff."""
        state = self._run
        check: CheckResult | None = None
        reason: Code | None = None
        started = self._now()
        begin = self._clock()
        try:
            check = step.check(self._context("main", stack, step))
        except KeyboardInterrupt as interrupt:
            state.interrupt = interrupt
            reason = INTERRUPTED
        except Exception as error:  # a check never crashes doctor; it fails
            reason = self._unexpected("main", stack, step, error)
        if reason is not None:
            record = StepRecord(
                stack,
                step.name,
                step.order,
                "failed",
                reason,
                started,
                self._clock() - begin,
            )
            records.append(self._record("main", record))
        elif check is not None and check.needed and check.would is not None:
            diff.append(DoctorItem(stack, step.name, _qualified(step, check.would)))
