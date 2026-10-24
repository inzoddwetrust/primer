"""The plan: a ladder of steps by stacks, modes, point of no return, ``finally``.

The ladder runs the dependencies of the box's root stack in the order given,
then the root stack last; there is exactly one root, of any kind (a box of a
shared remote service has a service as its root). Inside a stack, steps run by
``order``.

In ``install``, ``deploy`` and ``reinstall`` every step runs ``check``, then
``act`` if needed, then ``verify``. The first failed step stops the ladder: the
rest are ``skipped`` with the reason. If the plan has not yet started the
``act`` of a point-of-no-return step, the caller's ``restore`` steps run; after
that point nothing automatic is done and the outcome says a restore is needed.
``finally`` steps run every time, after everything else. ``doctor`` runs only
``check`` of the ``deploy`` steps and reports what would be done.

A step never crashes a plan: any exception from a phase is that step's failure.
``KeyboardInterrupt`` fails the step as interrupted, still runs ``restore`` and
``finally``, emits the outcome and is then raised again.

The reason of a step a command let down names the command and its exit code
(or its timeout), never its output: the output went to the journal line by
line, and a reason ends up in the verdict, which lives forever (contract 2).
"""

import shlex
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime

from pridem.events import (
    AFTER_INTERRUPT,
    DoctorItem,
    EventSink,
    Fact,
    Incomplete,
    LogLine,
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
from pridem.report.codes import ExitCode, worst
from pridem.runner import CommandFailed, CommandTimedOut, Runner, Stream
from pridem.steps.base import (
    MODES,
    CheckResult,
    Mode,
    Role,
    Step,
    StepContext,
    StepFailed,
)


def _failure_reason(error: Exception) -> str:
    """The reason of a step that raised ``error``; command output stays out."""
    if isinstance(error, CommandFailed):
        return f"command failed: {shlex.join(error.argv)}: exit code {error.code}"
    if isinstance(error, CommandTimedOut):
        return f"command timed out after {error.timeout} s: {shlex.join(error.argv)}"
    return f"{type(error).__name__}: {error}"


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
        self._steps = [
            (stack.name, step)
            for stack in ladder(stacks)
            for step in sorted(stack.steps, key=lambda s: s.order)
            if selected in step.modes
        ]
        if not self._steps:
            raise ValueError(f"no step of the plan runs in mode {mode!r}")
        for extra in (*restore, *finally_):
            _validate_steps(extra)
        self._restore = [(s.name, step) for s in restore for step in s.steps]
        self._finally = [(s.name, step) for s in finally_ for step in s.steps]

    def run(self) -> PlanOutcome:
        """Run the plan; emit every event; return the outcome."""
        if self._mode == "doctor":
            return self._doctor()
        state = _Run()
        steps = self._ladder(self._steps, state, stop_on_failure=True)
        main_failed = any(record.status == "failed" for record in steps)
        restore: list[StepRecord] = []
        if main_failed and not state.crossed:
            restore = self._ladder(self._restore, state, stop_on_failure=True)
        final = self._ladder(self._finally, state, stop_on_failure=False)
        records = (*steps, *restore, *final)
        incomplete = tuple(state.incomplete)
        codes = [ExitCode.OK]
        codes += [ExitCode.FAILED for record in records if record.status == "failed"]
        codes += [ExitCode.INCOMPLETE for _ in incomplete]
        outcome = PlanOutcome(
            mode=self._mode,
            code=worst(codes),
            steps=tuple(steps),
            restore=tuple(restore),
            finally_=tuple(final),
            incomplete=incomplete,
            needs_restore=main_failed and state.crossed,
            interrupted=state.interrupt is not None,
        )
        self._finish(outcome)
        if state.interrupt is not None:
            raise state.interrupt
        return outcome

    def _finish(self, outcome: PlanOutcome) -> PlanOutcome:
        self._sink.emit(PlanFinished(outcome))
        return outcome

    def _context(self, stack: str, step: Step) -> StepContext:
        def on_line(stream: Stream, line: str) -> None:
            self._sink.emit(LogLine(stack, step.name, stream, line))

        mode: Mode = "deploy" if self._mode == "doctor" else self._mode
        return StepContext(self._runner, mode, self._role, stack, on_line)

    def _record(self, record: StepRecord) -> StepRecord:
        self._sink.emit(StepFinished(record))
        return record

    def _skipped(self, stack: str, step: Step, reason: str) -> StepRecord:
        return self._record(StepRecord(stack, step.name, step.order, "skipped", reason))

    def _ladder(
        self, steps: Sequence[tuple[str, Step]], state: _Run, *, stop_on_failure: bool
    ) -> list[StepRecord]:
        records: list[StepRecord] = []
        stopped: StepRecord | None = None
        for stack, step in steps:
            if stopped is not None:
                records.append(
                    self._skipped(
                        stack, step, after_failure(stopped.stack, stopped.name)
                    )
                )
            elif step.roles is not None and self._role not in step.roles:
                records.append(self._skipped(stack, step, role_skip(self._role)))
            else:
                record = self._execute(stack, step, state)
                records.append(record)
                if record.status == "failed" and (
                    stop_on_failure or state.interrupt is not None
                ):
                    stopped = record
        return records

    def _execute(self, stack: str, step: Step, state: _Run) -> StepRecord:
        started = self._now()
        begin = self._clock()
        self._sink.emit(StepStarted(stack, step.name, step.order, started))
        ctx = self._context(stack, step)
        fact: Fact = {}
        reason: str | None = None
        try:
            check = step.check(ctx)
            if check.needed:
                if step.point_of_no_return:
                    state.crossed = True
                step.act(ctx, check)
            verified = step.verify(ctx, check)
            fact = dict(verified.fact)
            if not fact:
                reason = "verify returned no fact"
            elif verified.incomplete is not None:
                state.incomplete.append(verified.incomplete)
        except StepFailed as error:
            reason, fact = error.reason, dict(error.fact)
        except KeyboardInterrupt as interrupt:
            state.interrupt = interrupt
            reason = "interrupted"
        except Exception as error:  # a step never crashes the plan; it fails
            reason = _failure_reason(error)
        status: Status = "ok" if reason is None else "failed"
        duration = self._clock() - begin
        return self._record(
            StepRecord(
                stack, step.name, step.order, status, reason, started, duration, fact
            )
        )

    def _doctor(self) -> PlanOutcome:
        records: list[StepRecord] = []
        diff: list[DoctorItem] = []
        interrupt: KeyboardInterrupt | None = None
        for stack, step in self._steps:
            if interrupt is not None:
                records.append(self._skipped(stack, step, AFTER_INTERRUPT))
                continue
            if step.roles is not None and self._role not in step.roles:
                records.append(self._skipped(stack, step, role_skip(self._role)))
                continue
            check: CheckResult | None = None
            reason: str | None = None
            started = self._now()
            begin = self._clock()
            try:
                check = step.check(self._context(stack, step))
            except KeyboardInterrupt as error:
                interrupt = error
                reason = "interrupted"
            except Exception as error:  # a check never crashes doctor; it fails
                reason = _failure_reason(error)
            if reason is not None:
                records.append(
                    self._record(
                        StepRecord(
                            stack,
                            step.name,
                            step.order,
                            "failed",
                            reason,
                            started,
                            self._clock() - begin,
                        )
                    )
                )
            elif check is not None and check.needed:
                diff.append(DoctorItem(stack, step.name, check.what))
        codes = [ExitCode.OK]
        codes += [ExitCode.FAILED for record in records if record.status == "failed"]
        codes += [ExitCode.INCOMPLETE for _ in diff]
        outcome = PlanOutcome(
            mode="doctor",
            code=worst(codes),
            steps=tuple(records),
            doctor_diff=tuple(diff),
            interrupted=interrupt is not None,
        )
        self._finish(outcome)
        if interrupt is not None:
            raise interrupt
        return outcome
