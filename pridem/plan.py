"""The plan: a ladder of steps by stacks, modes, point of no return, ``finally``.

The ladder runs the dependencies of the box's root stack in the order given,
then the root stack last; there is exactly one root, of any kind (a box of a
shared remote service has a service as its root). Inside a stack, steps run by
``order``; ``restore`` and ``finally`` steps are chosen the same way, by
``order`` and by ``modes``.

A step marked ``final_check`` is the final check of TZ 7.3: in its place the plan
calls ``verify`` of every green step of ``main`` once more, with the check it
was run with; one red fails it by the step's name and code, and the steps after
it (``finalize``) do not run.

In every mode but ``doctor`` -- ``install``, ``deploy``, ``reinstall``,
``destroy`` and the one-step plans ``gc`` and ``renew`` -- every step runs
``check``, then ``act`` if needed, then ``verify``. The first failed step stops
the ladder: the rest are ``skipped`` with the reason. If the plan has not yet
started the ``act`` of a point-of-no-return step, the caller's ``restore``
steps run; after that point nothing automatic is done and the outcome says a
restore is needed.
``finally`` steps run every time, after everything else; nothing stops them --
a failed ``finally`` step never stops the others.
``doctor`` runs only ``check`` of the ``deploy`` steps and reports what would be
done; a step that refuses in ``check`` is recorded by its own code, as in a run.

A step never crashes a plan: any exception from a phase is that step's failure.

An interrupt is a flag, never an exception in the plan's code
(``pridem/interrupt.py``). The plan reads it between steps and between stacks:
an interrupt since the phase began stops ``main`` (and ``doctor``) -- the rest
is ``skipped`` with ``after-interrupt``, ``restore`` (before the point of no
return) and ``finally`` still run, and the outcome says ``interrupted``. An
interrupt while a command or a wait of a step runs stops it there: that step
fails with ``interrupted`` and the rest is skipped after it. ``restore`` stops
on an interrupt during it. ``finally`` is shielded: it runs to its last step,
and an interrupt during one of its steps is a line of that step in the
journal.

A sink never crashes a plan either: its first failure is ``{what: journal,
code: write-failed}`` in the outcome and the sink is not called again.

A plan runs once: a second ``run`` is refused (``RunRefused``) before any event
and any command. The stacks of a plan are given whole (``StackSteps``) or
deferred (``Deferred``): the steps of a deferred stack are made when the
ladder reaches it, from what the steps before it read (the passport, the
product's ``primer.yaml@target``). When they cannot be made yet -- ``doctor``
does not fetch, so a new target is not read -- the stack is the one step
``ladder`` with ``ladder:unresolved``: a difference in ``doctor``, a red step
in a run.

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
import signal
import time
import traceback
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from typing import ClassVar

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
    cut_ctx,
    role_skip,
)
from pridem.interrupt import Interrupt, Interrupted
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
    Verified,
    local_code,
)


class RunRefused(RuntimeError):
    """A plan that already ran was asked to run again: one run, one journal."""


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


@dataclass(frozen=True)
class Deferred:
    """Stacks made when the ladder reaches them.

    ``build`` makes them -- one or several, in ladder order (a product's
    entries) -- from what the steps before read, or returns ``None`` when that
    is not known yet; ``after`` names the step whose fact it waits for, and
    ``name`` is the stack of the step ``ladder`` that says so.
    """

    name: str
    build: Callable[[], Sequence[StackSteps] | None]
    after: str
    root: bool = False


Stack = StackSteps | Deferred


class Unresolved(Step):
    """The one step of a deferred stack whose steps cannot be made yet."""

    name = "ladder"
    order = 0
    modes = MODES
    codes: ClassVar[dict[str, str]] = {
        "unresolved": "the steps of this stack are known after {after}",
    }

    def __init__(self, after: str) -> None:
        self.params: dict[str, str | None] = {"after": after}

    def check(self, ctx: StepContext) -> CheckResult:
        return CheckResult(True, local_code("unresolved", dict(self.params)))

    def act(self, ctx: StepContext, check: CheckResult) -> None:
        raise StepFailed("unresolved", dict(self.params))

    def verify(self, ctx: StepContext, check: CheckResult) -> Verified:
        raise StepFailed("unresolved", dict(self.params))


def _validate_steps(name: str, steps: Sequence[Step]) -> None:
    names: set[str] = set()
    orders: set[int] = set()
    for step in steps:
        for attribute in ("name", "order", "modes"):
            if not hasattr(step, attribute):
                raise ValueError(f"{name}: step {step!r} declares no {attribute}")
        if not step.modes or not step.modes <= MODES:
            raise ValueError(
                f"{name}/{step.name}: modes must be a non-empty subset of "
                f"{sorted(MODES)}, got {sorted(step.modes)}"
            )
        if step.name in names:
            raise ValueError(f"{name}: two steps named {step.name!r}")
        if step.order in orders:
            raise ValueError(f"{name}: two steps with order {step.order}")
        names.add(step.name)
        orders.add(step.order)


def ladder(stacks: Sequence[Stack]) -> list[Stack]:
    """Dependencies in the given order, then the root; exactly one root."""
    roots = [stack for stack in stacks if stack.root]
    if len(roots) != 1:
        raise ValueError(f"a plan needs exactly one root stack, got {len(roots)}")
    seen: set[str] = set()
    for stack in stacks:
        if stack.name in seen:
            raise ValueError(f"two stacks named {stack.name!r}")
        seen.add(stack.name)
        if isinstance(stack, StackSteps):
            _validate_steps(stack.name, stack.steps)
    return [stack for stack in stacks if not stack.root] + roots


@dataclass
class _Run:
    """Mutable bookkeeping of one run; never leaves the plan."""

    crossed: bool = False
    interrupted: bool = False
    incomplete: list[Incomplete] = field(default_factory=list)
    sink_failed: bool = False
    green: list[tuple[str, Step, CheckResult]] = field(default_factory=list)
    """Steps of ``main`` verified green, with their check: the final check."""


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
        stacks: Sequence[Stack],
        *,
        mode: PlanMode,
        role: Role | Callable[[], Role],
        runner: Runner,
        sink: EventSink,
        restore: Sequence[StackSteps] = (),
        finally_: Sequence[StackSteps] = (),
        clock: Callable[[], float] = time.monotonic,
        now: Callable[[], datetime] = lambda: datetime.now(UTC),
        interrupt: Interrupt | None = None,
    ) -> None:
        self._selected: Mode = "deploy" if mode == "doctor" else mode
        self._mode = mode
        self._role_of = role
        self._runner = runner
        self._sink = sink
        self._clock = clock
        self._now = now
        self._interrupt = interrupt if interrupt is not None else Interrupt()
        self._run = _Run()
        self._ran = False
        self.outcome: PlanOutcome | None = None
        """The outcome of the run."""
        self._stacks = ladder(stacks)
        known = [stack for stack in self._stacks if isinstance(stack, StackSteps)]
        deferred = len(known) < len(self._stacks)
        if not deferred and not _chosen(known, self._selected):
            raise ValueError(f"no step of the plan runs in mode {mode!r}")
        for extra in (*restore, *finally_):
            _validate_steps(extra.name, extra.steps)
        self._restore = _chosen(restore, self._selected)
        self._finally = _chosen(finally_, self._selected)
        self._named: list[Step] = [
            *(step for _, step in _chosen(known, self._selected)),
            *(step for _, step in (*self._restore, *self._finally)),
        ]

    @property
    def _role(self) -> Role:
        """The box's role; a function when the plan itself reads the passport."""
        return self._role_of() if callable(self._role_of) else self._role_of

    @property
    def catalog(self) -> Catalog:
        """The machine's texts and those of the plan's steps -- the steps of a
        deferred stack once the ladder made them."""
        return with_steps(
            ENGLISH, ((step.name, type(step).codes) for step in self._named)
        )

    # --- events ---------------------------------------------------------------

    def _emit(self, event: Event) -> None:
        """Hand ``event`` to the sink; its failure is recorded, never raised."""
        if self._run.sink_failed:
            return
        try:
            self._sink.emit(event)
        except Exception:  # disk full, I/O error: the plan goes on (contract 2)
            self._run.sink_failed = True

    def _finish(self, outcome: PlanOutcome) -> PlanOutcome:
        """Emit the outcome; a sink that fails on it still shows in the outcome."""
        failed_before = self._run.sink_failed
        self._emit(PlanFinished(outcome))
        if self._run.sink_failed and not failed_before:
            outcome = replace(
                outcome,
                code=worst([outcome.code, ExitCode.INCOMPLETE]),
                incomplete=(*outcome.incomplete, SINK_FAILED),
            )
        self.outcome = outcome
        return outcome

    def _context(self, phase: Phase, stack: str, step: Step) -> StepContext:
        pieces: set[Stream] = set()  # streams in the middle of a line cut in pieces

        def on_line(stream: Stream, line: str, continued: bool) -> None:
            # KNOWN CEILING: a line longer than the runner's LINE_LIMIT.
            # 1. mechanics: it arrives in pieces, none of them JSON, so its ctx
            #    is not measured and not cut (protocol 9.4: over 8 KB, cut);
            #    its secrets are still cleaned by the sinks, across the pieces.
            # 2. status: acknowledged by design.
            # 3. task: none -- no stack writes such a line yet.
            # 4. trigger: a journal holding a log line of a stack, with ctx,
            #    longer than LINE_LIMIT.
            # 5. agreed fix: join the pieces of a line here up to a bound
            #    before cut_ctx, and pass the rest as pieces.
            # 6. rejected: keeping the head of a cut ctx -- cut before the
            #    sinks clean secrets, it could carry a part of one.
            if continued:
                pieces.add(stream)
            elif stream in pieces:
                pieces.discard(stream)  # the last piece of a long line
            else:
                line = cut_ctx(line)
            self._emit(LogLine(phase, stack, step.name, stream, line, continued))

        return StepContext(
            self._runner, self._selected, self._role, stack, on_line, self._interrupt
        )

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

    # --- the stacks -------------------------------------------------------------

    def _made(self, stack: Stack) -> list[tuple[str, Step]]:
        """The steps of ``stack`` for the plan's mode; deferred stacks are
        made now, or are the one step ``ladder`` when they cannot be."""
        if isinstance(stack, StackSteps):
            return _chosen([stack], self._selected)
        built = stack.build()
        made: Sequence[StackSteps] = (
            [StackSteps(stack.name, [Unresolved(stack.after)])]
            if built is None
            else built
        )
        for part in made:
            _validate_steps(part.name, part.steps)
        chosen = _chosen(made, self._selected)
        self._named.extend(step for _, step in chosen)
        return chosen

    # --- the run --------------------------------------------------------------

    def run(self) -> PlanOutcome:
        """Run the plan; emit every event; return the outcome."""
        if self._ran:
            raise RunRefused("a plan runs once; this one has run")
        self._ran = True
        if self._mode == "doctor":
            return self._doctor()
        state = self._run
        begin = self._interrupt.count
        steps = self._main()
        main_failed = any(record.status == "failed" for record in steps)
        stopped = main_failed or state.interrupted
        restore: list[StepRecord] = []
        if stopped and not state.crossed:
            restore = self._ladder("restore", self._restore)
        final = self._finally_ladder()
        if self._interrupt.count > begin:  # a signal during finally too
            state.interrupted = True
        records = (*steps, *restore, *final)
        if state.sink_failed:
            state.incomplete.append(SINK_FAILED)
        incomplete = tuple(state.incomplete)
        codes = [ExitCode.OK]
        codes += [ExitCode.FAILED for record in records if record.status == "failed"]
        codes += [ExitCode.INCOMPLETE for _ in incomplete]
        if state.interrupted:
            codes.append(ExitCode.FAILED)
        return self._finish(
            PlanOutcome(
                mode=self._mode,
                code=worst(codes),
                steps=tuple(steps),
                restore=tuple(restore),
                finally_=tuple(final),
                incomplete=incomplete,
                needs_restore=stopped and state.crossed,
                interrupted=state.interrupted,
            )
        )

    def _main(self) -> list[StepRecord]:
        """The main ladder, stack by stack; a deferred stack is made when it is
        reached and not made at all once the ladder has stopped."""
        records: list[StepRecord] = []
        stopped: Code | None = None
        begin = self._interrupt.count
        for stack in self._stacks:
            if stopped is None and self._interrupt.count > begin:
                stopped = AFTER_INTERRUPT  # between stacks
            if stopped is not None and isinstance(stack, Deferred):
                continue  # its steps are not known: nothing to skip by name
            part, stopped = self._steps("main", self._made(stack), stopped, begin)
            records.extend(part)
        if self._interrupt.count > begin:
            self._run.interrupted = True
        return records

    def _ladder(
        self, phase: Phase, steps: Sequence[tuple[str, Step]]
    ) -> list[StepRecord]:
        """``restore``: stops on a failed step and on a signal received during it."""
        begin = self._interrupt.count
        records, _ = self._steps(phase, steps, None, begin)
        if self._interrupt.count > begin:
            self._run.interrupted = True
        return records

    def _steps(
        self,
        phase: Phase,
        steps: Sequence[tuple[str, Step]],
        stopped: Code | None,
        begin: int,
    ) -> tuple[list[StepRecord], Code | None]:
        """Run ``steps`` until one fails or a signal received since ``begin``
        stops them; the rest are skipped with the reason."""
        records: list[StepRecord] = []
        for stack, step in steps:
            if stopped is None and self._interrupt.count > begin:
                stopped = AFTER_INTERRUPT  # between steps
            if stopped is not None:
                records.append(self._skipped(phase, stack, step, stopped))
                continue
            if step.roles is not None and self._role not in step.roles:
                records.append(self._skipped(phase, stack, step, role_skip(self._role)))
                continue
            self._interrupt.watch()
            record = self._execute(phase, stack, step)
            records.append(record)
            if record.status == "failed":
                stopped = after_failure(phase, stack, step.name)
        return records, stopped

    def _finally_ladder(self) -> list[StepRecord]:
        """``finally``, shielded: every step runs; a signal received during one
        is a line of that step in the journal."""
        records: list[StepRecord] = []
        with self._interrupt.shield():
            for stack, step in self._finally:
                if step.roles is not None and self._role not in step.roles:
                    records.append(
                        self._skipped("finally", stack, step, role_skip(self._role))
                    )
                    continue
                before = self._interrupt.count
                records.append(self._execute("finally", stack, step))
                for signum in self._interrupt.received[before:]:
                    name = signal.Signals(signum).name
                    line = f"pridem: {name} during finally; the clean-up goes on"
                    self._emit(
                        LogLine("finally", stack, step.name, Stream.STDERR, line)
                    )
        return records

    def _execute(self, phase: Phase, stack: str, step: Step) -> StepRecord:
        state = self._run
        fact: Fact = {}
        reason: Code | None = None
        started = self._now()
        begin = self._clock()
        self._emit(StepStarted(phase, stack, step.name, step.order, started))
        try:
            if step.final_check:
                fact = self._final_check()
            else:
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
                if reason is None and phase == "main":
                    state.green.append((stack, step, check))
        except StepFailed as error:
            reason, fact = _qualified(step, error.reason), dict(error.fact)
        except Interrupted:
            state.interrupted = True
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

    def _final_check(self) -> Fact:
        """``verify`` of every green step of ``main`` once more, with the check
        it was run with; the first red one fails the final check by name."""
        state = self._run
        for stack, step, check in state.green:
            try:
                step.verify(self._context("main", stack, step), check)
            except StepFailed as error:
                code = _qualified(step, error.reason).code
                raise StepFailed(
                    "red", {"stack": stack, "step": step.name, "reason": code}
                ) from None
            except Exception as error:  # a re-verify never crashes the plan
                raise StepFailed(
                    "red",
                    {"stack": stack, "step": step.name, "reason": type(error).__name__},
                ) from None
        return {"verified": len(state.green)}

    def _doctor(self) -> PlanOutcome:
        state = self._run
        records: list[StepRecord] = []
        diff: list[DoctorItem] = []
        begin = self._interrupt.count
        for stack in self._stacks:
            if self._interrupt.count > begin and isinstance(stack, Deferred):
                continue  # its steps are not known: nothing to skip by name
            for name, step in self._made(stack):
                if self._interrupt.count > begin:
                    records.append(self._skipped("main", name, step, AFTER_INTERRUPT))
                    continue
                if step.roles is not None and self._role not in step.roles:
                    records.append(
                        self._skipped("main", name, step, role_skip(self._role))
                    )
                    continue
                self._interrupt.watch()
                self._check(name, step, records, diff)
        if self._interrupt.count > begin:
            state.interrupted = True
        if state.sink_failed:
            state.incomplete.append(SINK_FAILED)
        codes = [ExitCode.OK]
        codes += [ExitCode.FAILED for record in records if record.status == "failed"]
        codes += [ExitCode.INCOMPLETE for _ in diff]
        codes += [ExitCode.INCOMPLETE for _ in state.incomplete]
        if state.interrupted:
            codes.append(ExitCode.FAILED)
        return self._finish(
            PlanOutcome(
                mode="doctor",
                code=worst(codes),
                steps=tuple(records),
                incomplete=tuple(state.incomplete),
                doctor_diff=tuple(diff),
                interrupted=state.interrupted,
            )
        )

    def _check(
        self,
        stack: str,
        step: Step,
        records: list[StepRecord],
        diff: list[DoctorItem],
    ) -> None:
        """One ``doctor`` check: a failed check is a record, a needed one a diff.

        A step that refuses in ``check`` (``StepFailed``) is recorded with its
        own code, parameters and fact, as ``_execute`` records it: one refusal
        reads the same in ``doctor`` and in ``install``; it is no ``exception``
        and leaves no text in the journal.
        """
        state = self._run
        check: CheckResult | None = None
        reason: Code | None = None
        fact: Fact = {}
        started = self._now()
        begin = self._clock()
        try:
            check = step.check(self._context("main", stack, step))
        except StepFailed as error:
            reason, fact = _qualified(step, error.reason), dict(error.fact)
        except Interrupted:
            state.interrupted = True
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
                fact,
            )
            records.append(self._record("main", record))
        elif check is not None and check.needed and check.would is not None:
            diff.append(DoctorItem(stack, step.name, _qualified(step, check.would)))
