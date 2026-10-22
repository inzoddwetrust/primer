"""Scripted steps, a recording sink and fixed clocks for plan tests (DM-6)."""

from collections.abc import Sequence
from datetime import UTC, datetime
from itertools import count

from pridem.events import Event, Fact, Incomplete, LogLine, PlanMode, StepFinished
from pridem.plan import Plan, StackSteps
from pridem.runner import FakeRunner, Runner
from pridem.steps.base import (
    CheckResult,
    Mode,
    Role,
    Step,
    StepContext,
    StepFailed,
    Verified,
)

NOW = datetime(2026, 10, 22, 12, 0, tzinfo=UTC)


class Journal(list[str]):
    """Phases in the order they ran: ``stack/step:phase``."""


class ListSink:
    def __init__(self) -> None:
        self.events: list[Event] = []

    def emit(self, event: Event) -> None:
        self.events.append(event)

    def finished(self) -> list[StepFinished]:
        return [e for e in self.events if isinstance(e, StepFinished)]

    def lines(self) -> list[LogLine]:
        return [e for e in self.events if isinstance(e, LogLine)]


class ScriptedStep(Step):
    """A step whose phases do what the test says and log themselves."""

    def __init__(
        self,
        name: str,
        order: int,
        journal: Journal,
        *,
        modes: frozenset[Mode] = frozenset({"install", "deploy", "reinstall"}),
        point_of_no_return: bool = False,
        roles: frozenset[Role] | None = None,
        needed: bool = True,
        check_raises: BaseException | None = None,
        act_argv: Sequence[str] | None = None,
        act_raises: BaseException | None = None,
        fact: Fact | None = None,
        verify_raises: BaseException | None = None,
        incomplete: Incomplete | None = None,
    ) -> None:
        self.name = name
        self.order = order
        self.modes = modes
        self.point_of_no_return = point_of_no_return
        self.roles = roles
        self._journal = journal
        self._needed = needed
        self._check_raises = check_raises
        self._act_argv = act_argv
        self._act_raises = act_raises
        self._fact: Fact = {"done": name} if fact is None else fact
        self._verify_raises = verify_raises
        self._incomplete = incomplete

    def _log(self, ctx: StepContext, phase: str) -> None:
        self._journal.append(f"{ctx.stack}/{self.name}:{phase}")

    def check(self, ctx: StepContext) -> CheckResult:
        self._log(ctx, "check")
        if self._check_raises is not None:
            raise self._check_raises
        return CheckResult(self._needed, f"do {self.name}" if self._needed else "")

    def act(self, ctx: StepContext, check: CheckResult) -> None:
        self._log(ctx, "act")
        if self._act_argv is not None:
            ctx.runner.run(self._act_argv, timeout=10.0, on_line=ctx.on_line)
        if self._act_raises is not None:
            raise self._act_raises

    def verify(self, ctx: StepContext, check: CheckResult) -> Verified:
        self._log(ctx, "verify")
        if self._verify_raises is not None:
            raise self._verify_raises
        return Verified(self._fact, self._incomplete)


def red(
    name: str, order: int, journal: Journal, *, point_of_no_return: bool = False
) -> ScriptedStep:
    """A step whose verify reads back a contradiction."""
    return ScriptedStep(
        name,
        order,
        journal,
        point_of_no_return=point_of_no_return,
        verify_raises=StepFailed(f"{name} read back the wrong state", {"seen": "x"}),
    )


def plan(
    stacks: Sequence[StackSteps],
    mode: PlanMode = "deploy",
    *,
    role: Role = "test",
    runner: Runner | None = None,
    restore: Sequence[StackSteps] = (),
    finally_: Sequence[StackSteps] = (),
) -> tuple[Plan, ListSink]:
    sink = ListSink()
    ticks = count()
    built = Plan(
        stacks,
        mode=mode,
        role=role,
        runner=runner if runner is not None else FakeRunner(),
        sink=sink,
        restore=restore,
        finally_=finally_,
        clock=lambda: float(next(ticks)),
        now=lambda: NOW,
    )
    return built, sink
