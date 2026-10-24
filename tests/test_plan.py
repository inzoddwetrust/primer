"""State grid of the plan (DM-6): modes, phases, roles, restore, finally, interrupt."""

from pathlib import Path

import pytest
from plan_support import NOW, Journal, ListSink, ScriptedStep, plan, red

from pridem.events import (
    Event,
    Incomplete,
    LogLine,
    PlanFinished,
    Secrets,
    StepStarted,
)
from pridem.plan import Plan, StackSteps
from pridem.report.codes import ExitCode
from pridem.runner import FakeCall, FakeRunner, Stream
from pridem.state import JournalSink
from pridem.steps.base import (
    CheckResult,
    Mode,
    Role,
    StepContext,
    StepFailed,
    Verified,
)


def _root(*steps: ScriptedStep) -> list[StackSteps]:
    return [StackSteps("aivis", list(steps), root=True)]


# --- construction -------------------------------------------------------------


def test_step_without_modes_is_refused() -> None:
    journal = Journal()
    with pytest.raises(ValueError, match="non-empty subset"):
        plan(_root(ScriptedStep("a", 1, journal, modes=frozenset())))


def test_empty_plan_for_the_mode_is_refused() -> None:
    journal = Journal()
    only_install = ScriptedStep("host", 1, journal, modes=frozenset({"install"}))
    with pytest.raises(ValueError, match="no step of the plan runs in mode 'deploy'"):
        plan(_root(only_install), "deploy")


@pytest.mark.parametrize(
    ("second", "message"),
    [(("a", 2), "two steps named 'a'"), (("b", 1), "two steps with order 1")],
)
def test_duplicate_step_name_or_order_in_a_stack(
    second: tuple[str, int], message: str
) -> None:
    journal = Journal()
    steps = _root(ScriptedStep("a", 1, journal), ScriptedStep(*second, journal))
    with pytest.raises(ValueError, match=message):
        plan(steps)


def test_duplicate_stack_name() -> None:
    journal = Journal()
    stacks = [
        StackSteps("comms", [ScriptedStep("a", 1, journal)]),
        StackSteps("comms", [ScriptedStep("a", 1, journal)], root=True),
    ]
    with pytest.raises(ValueError, match="two stacks named 'comms'"):
        plan(stacks)


def test_same_step_name_in_two_stacks_is_distinguished_by_stack() -> None:
    journal = Journal()
    stacks = [
        StackSteps("comms", [ScriptedStep("migrate", 7, journal)]),
        StackSteps("aivis", [ScriptedStep("migrate", 7, journal)], root=True),
    ]
    outcome = plan(stacks)[0].run()
    assert [(r.stack, r.name, r.order) for r in outcome.steps] == [
        ("comms", "migrate", 7),
        ("aivis", "migrate", 7),
    ]


# --- modes -------------------------------------------------------------------------


def test_mode_selects_steps() -> None:
    journal = Journal()
    steps = _root(
        ScriptedStep("host", 1, journal, modes=frozenset({"install"})),
        ScriptedStep("up", 2, journal),
    )
    assert [r.name for r in plan(steps, "install")[0].run().steps] == ["host", "up"]
    assert [r.name for r in plan(steps, "deploy")[0].run().steps] == ["up"]


def test_not_needed_still_verifies() -> None:
    journal = Journal()
    outcome = plan(_root(ScriptedStep("up", 1, journal, needed=False)))[0].run()
    assert journal == ["aivis/up:check", "aivis/up:verify"]
    assert outcome.steps[0].status == "ok"


def test_doctor_without_drift_is_green_and_check_failure_is_red() -> None:
    """A failed check is red; its reason is the exception's type name.

    Until DM-37 the reason carried ``RuntimeError: no docker``; the text of an
    unexpected exception now goes to the journal only (contract 2 v1.4).
    """
    journal = Journal()
    clean = plan(_root(ScriptedStep("up", 1, journal, needed=False)), "doctor")[0]
    result = clean.run()
    assert (result.code, result.doctor_diff, result.steps) == (ExitCode.OK, (), ())
    broken = ScriptedStep("up", 1, journal, check_raises=RuntimeError("no docker"))
    drift = ScriptedStep("env", 2, journal)
    run, sink = plan(_root(broken, drift), "doctor")
    outcome = run.run()
    assert outcome.code is ExitCode.FAILED
    assert [(r.name, r.status, r.reason) for r in outcome.steps] == [
        ("up", "failed", "RuntimeError")
    ]
    assert [line.line for line in sink.lines()] == ["RuntimeError: no docker"]
    assert [d.name for d in outcome.doctor_diff] == ["env"]
    assert not any(entry.endswith((":act", ":verify")) for entry in journal)


def test_doctor_runs_no_restore_and_no_finally() -> None:
    journal = Journal()
    run = plan(
        _root(ScriptedStep("up", 1, journal)),
        "doctor",
        restore=[StackSteps("aivis", [ScriptedStep("old", 1, journal)])],
        finally_=[StackSteps("aivis", [ScriptedStep("gc", 1, journal)])],
    )[0]
    outcome = run.run()
    assert (outcome.restore, outcome.finally_) == ((), ())
    assert journal == ["aivis/up:check"]


# --- phases ------------------------------------------------------------------------


def test_check_raises() -> None:
    """Reason: the type name; the text ``OSError: boom`` is a ``stderr`` log line.

    Until DM-37 the reason was ``OSError: boom`` (contract 2 v1.4 changed it).
    """
    journal = Journal()
    run, sink = plan(
        _root(ScriptedStep("up", 1, journal, check_raises=OSError("boom")))
    )
    outcome = run.run()
    assert (outcome.steps[0].status, outcome.steps[0].reason) == ("failed", "OSError")
    assert [(line.stream, line.line) for line in sink.lines()] == [
        (Stream.STDERR, "OSError: boom")
    ]
    assert journal == ["aivis/up:check"]


def test_runner_failure_in_act_is_the_step_failure() -> None:
    """The reason names the command and its exit code; its output is not in it.

    Before DM-4 the reason carried the runner's message with the command's tail
    output; the output now reaches only the journal (contract 2 v1.2), so the
    test checks the exact reason and finds the output among the log lines.
    """
    journal = Journal()
    runner = FakeRunner(
        FakeCall(
            ("docker", "compose", "up"),
            code=1,
            lines=((Stream.STDERR, "no space left"),),
        )
    )
    with runner:
        step = ScriptedStep("up", 1, journal, act_argv=["docker", "compose", "up"])
        run, sink = plan(_root(step), runner=runner)
        outcome = run.run()
    record = outcome.steps[0]
    assert record.status == "failed"
    assert record.reason == "command failed: docker compose up: exit code 1"
    assert [line.line for line in sink.lines()] == ["no space left"]
    assert journal == ["aivis/up:check", "aivis/up:act"]


def test_command_lines_become_log_lines_of_the_step() -> None:
    journal = Journal()
    runner = FakeRunner(
        FakeCall(
            ("make",),
            lines=((Stream.STDOUT, "x"), (Stream.STDOUT, "x"), (Stream.STDERR, "y")),
        )
    )
    with runner:
        run, sink = plan(
            _root(ScriptedStep("build", 1, journal, act_argv=["make"])), runner=runner
        )
        run.run()
    assert [(e.stack, e.name, e.stream, e.line) for e in sink.lines()] == [
        ("aivis", "build", Stream.STDOUT, "x"),
        ("aivis", "build", Stream.STDOUT, "x"),
        ("aivis", "build", Stream.STDERR, "y"),
    ]


def test_step_without_output_gives_no_log_lines() -> None:
    journal = Journal()
    run, sink = plan(_root(ScriptedStep("up", 1, journal)))
    run.run()
    assert sink.lines() == []
    assert len(sink.finished()) == 1


# --- incomplete --------------------------------------------------------------------


def test_incomplete_gives_code_2_with_the_list() -> None:
    journal = Journal()
    deferred = Incomplete("ssl", "deferred by passport")
    outcome = plan(
        _root(
            ScriptedStep("ssl", 1, journal, incomplete=deferred),
            ScriptedStep("gc", 2, journal, incomplete=Incomplete("gc", "over budget")),
        )
    )[0].run()
    assert outcome.code is ExitCode.INCOMPLETE
    assert outcome.incomplete == (deferred, Incomplete("gc", "over budget"))
    assert [r.status for r in outcome.steps] == ["ok", "ok"]


def test_failed_beats_incomplete() -> None:
    journal = Journal()
    outcome = plan(
        _root(
            ScriptedStep("ssl", 1, journal, incomplete=Incomplete("ssl", "deferred")),
            red("up", 2, journal),
        )
    )[0].run()
    assert outcome.code is ExitCode.FAILED
    assert outcome.incomplete == (Incomplete("ssl", "deferred"),)


def test_incomplete_needs_what_and_why() -> None:
    with pytest.raises(ValueError):
        Incomplete("ssl", "")


# --- roles -------------------------------------------------------------------------


def test_role_skip_is_skipped_with_reason_not_incomplete() -> None:
    journal = Journal()
    steps = _root(
        ScriptedStep("tests", 1, journal, roles=frozenset({"test"})),
        ScriptedStep("up", 2, journal),
    )
    outcome = plan(steps, role="prod")[0].run()
    assert [(r.name, r.status, r.reason) for r in outcome.steps] == [
        ("tests", "skipped", "role prod"),
        ("up", "ok", None),
    ]
    assert outcome.code is ExitCode.OK
    assert outcome.incomplete == ()
    on_test = plan(steps, role="test")[0].run()
    assert [r.status for r in on_test.steps] == ["ok", "ok"]


def test_skipped_and_failed_records_need_a_reason() -> None:
    from pridem.events import StepRecord

    for status in ("skipped", "failed"):
        with pytest.raises(ValueError, match="needs a reason"):
            StepRecord("aivis", "up", 1, status)


# --- point of no return ------------------------------------------------------------


def test_point_whose_check_says_nothing_to_do_is_not_crossed() -> None:
    journal = Journal()
    steps = _root(
        ScriptedStep("migrate", 1, journal, point_of_no_return=True, needed=False),
        red("up", 2, journal),
    )
    restore = [StackSteps("aivis", [ScriptedStep("old", 1, journal)])]
    outcome = plan(steps, restore=restore)[0].run()
    assert (outcome.needs_restore, [r.name for r in outcome.restore]) == (
        False,
        ["old"],
    )


def test_point_whose_check_raises_is_not_crossed() -> None:
    journal = Journal()
    point = ScriptedStep(
        "migrate",
        1,
        journal,
        point_of_no_return=True,
        check_raises=RuntimeError("db down"),
    )
    restore = [StackSteps("aivis", [ScriptedStep("old", 1, journal)])]
    outcome = plan(_root(point), restore=restore)[0].run()
    assert (outcome.needs_restore, [r.name for r in outcome.restore]) == (
        False,
        ["old"],
    )


def test_plan_without_point_restores_on_any_red() -> None:
    journal = Journal()
    restore = [StackSteps("aivis", [ScriptedStep("old", 1, journal)])]
    outcome = plan(
        _root(ScriptedStep("a", 1, journal), red("b", 2, journal)), restore=restore
    )[0].run()
    assert [r.name for r in outcome.restore] == ["old"]


def test_red_restore_is_code_1_with_both_reasons() -> None:
    journal = Journal()
    restore = [
        StackSteps("aivis", [red("old", 1, journal), ScriptedStep("old2", 2, journal)])
    ]
    outcome = plan(_root(red("up", 1, journal)), restore=restore)[0].run()
    assert outcome.code is ExitCode.FAILED
    assert outcome.steps[0].reason == "up read back the wrong state"
    assert [(r.name, r.status) for r in outcome.restore] == [
        ("old", "failed"),
        ("old2", "skipped"),
    ]


def test_finally_failure_after_green_crossed_plan_needs_no_restore() -> None:
    journal = Journal()
    steps = _root(ScriptedStep("migrate", 1, journal, point_of_no_return=True))
    final = [StackSteps("aivis", [red("gc", 1, journal)])]
    outcome = plan(steps, finally_=final)[0].run()
    assert outcome.code is ExitCode.FAILED
    assert outcome.needs_restore is False


# --- finally -----------------------------------------------------------------------


def test_finally_failure_does_not_replace_the_cause_and_runs_every_step() -> None:
    journal = Journal()
    final = [
        StackSteps("aivis", [red("timers", 1, journal), ScriptedStep("gc", 2, journal)])
    ]
    outcome = plan(_root(red("up", 1, journal)), finally_=final)[0].run()
    assert outcome.steps[0].reason == "up read back the wrong state"
    assert [(r.name, r.status) for r in outcome.finally_] == [
        ("timers", "failed"),
        ("gc", "ok"),
    ]
    assert outcome.code is ExitCode.FAILED


def test_finally_failure_on_green_plan_is_red() -> None:
    journal = Journal()
    final = [StackSteps("aivis", [red("gc", 1, journal)])]
    outcome = plan(_root(ScriptedStep("up", 1, journal)), finally_=final)[0].run()
    assert outcome.steps[0].status == "ok"
    assert outcome.code is ExitCode.FAILED


# --- interrupt ---------------------------------------------------------------------


def test_interrupt_in_act_runs_restore_and_finally_then_raises() -> None:
    journal = Journal()
    steps = _root(
        ScriptedStep("build", 1, journal, act_raises=KeyboardInterrupt()),
        ScriptedStep("up", 2, journal),
    )
    restore = [StackSteps("aivis", [ScriptedStep("old", 1, journal)])]
    final = [StackSteps("aivis", [ScriptedStep("gc", 1, journal)])]
    run, sink = plan(steps, restore=restore, finally_=final)
    with pytest.raises(KeyboardInterrupt):
        run.run()
    [finished] = [e for e in sink.events if isinstance(e, PlanFinished)]
    outcome = finished.outcome
    assert outcome.interrupted is True
    assert [(r.name, r.status, r.reason) for r in outcome.steps] == [
        ("build", "failed", "interrupted"),
        ("up", "skipped", "after failed aivis/build"),
    ]
    assert [r.name for r in outcome.restore] == ["old"]
    assert [r.name for r in outcome.finally_] == ["gc"]
    assert outcome.code is ExitCode.FAILED
    assert sink.events[-1] is finished


def test_interrupt_in_doctor_emits_then_raises() -> None:
    journal = Journal()
    steps = _root(
        ScriptedStep("a", 1, journal, check_raises=KeyboardInterrupt()),
        ScriptedStep("b", 2, journal),
    )
    run, sink = plan(steps, "doctor")
    with pytest.raises(KeyboardInterrupt):
        run.run()
    [finished] = [e for e in sink.events if isinstance(e, PlanFinished)]
    assert [(r.name, r.status) for r in finished.outcome.steps] == [
        ("a", "failed"),
        ("b", "skipped"),
    ]


# --- events ------------------------------------------------------------------------


def test_events_carry_start_time_and_order_of_execution() -> None:
    journal = Journal()
    run, sink = plan(
        _root(ScriptedStep("a", 3, journal), ScriptedStep("b", 9, journal))
    )
    outcome = run.run()
    started = [e for e in sink.events if isinstance(e, StepStarted)]
    assert [(e.name, e.order, e.started) for e in started] == [
        ("a", 3, NOW),
        ("b", 9, NOW),
    ]
    assert [r.started for r in outcome.steps] == [NOW, NOW]
    assert all(r.duration_s == 1.0 for r in outcome.steps)
    assert isinstance(sink.events[-1], PlanFinished)


# --- DM-37 ----------------------------------------------------------------------


class _EmptyReason(ScriptedStep):
    def verify(self, ctx: StepContext, check: CheckResult) -> Verified:
        raise StepFailed("")


def test_step_failed_without_a_reason_is_a_failed_step() -> None:
    with pytest.raises(ValueError, match="needs a reason"):
        StepFailed("")
    journal = Journal()
    run, sink = plan(
        _root(_EmptyReason("up", 1, journal)),
        finally_=[StackSteps("aivis", [ScriptedStep("gc", 1, journal)])],
    )
    outcome = run.run()
    assert [(r.name, r.status, r.reason) for r in outcome.steps] == [
        ("up", "failed", "ValueError")
    ]
    assert [r.name for r in outcome.finally_] == ["gc"]
    assert isinstance(sink.events[-1], PlanFinished)


def test_restore_and_finally_run_by_order_and_mode() -> None:
    journal = Journal()

    def stack(*steps: ScriptedStep) -> list[StackSteps]:
        return [StackSteps("aivis", list(steps))]

    install_only: frozenset[Mode] = frozenset({"install"})
    run, _ = plan(
        _root(red("up", 1, journal)),
        restore=stack(
            ScriptedStep("second", 2, journal),
            ScriptedStep("only_install", 3, journal, modes=install_only),
            ScriptedStep("first", 1, journal),
        ),
        finally_=stack(
            ScriptedStep("late", 9, journal),
            ScriptedStep("early", 1, journal),
            ScriptedStep("install_gc", 5, journal, modes=install_only),
        ),
    )
    outcome = run.run()
    assert [r.name for r in outcome.restore] == ["first", "second"]
    assert [r.name for r in outcome.finally_] == ["early", "late"]
    assert not any("install" in entry for entry in journal)


def test_command_not_started_reason_is_the_runner_text() -> None:
    """The whole RunnerError family keeps its text: the command, never output."""
    runner = FakeRunner(FakeCall(("b", "x y"), outcome="not_started"))
    with runner:
        run, sink = plan(
            _root(ScriptedStep("up", 1, Journal(), act_argv=["b", "x y"])),
            runner=runner,
        )
        outcome = run.run()
    assert (
        outcome.steps[0].reason == "command not started: b 'x y': scripted: not started"
    )
    assert sink.lines() == []


def test_interrupt_inside_finally_stops_the_rest_of_finally() -> None:
    journal = Journal()
    run, _ = plan(
        _root(ScriptedStep("up", 1, journal, act_raises=KeyboardInterrupt())),
        finally_=[
            StackSteps(
                "aivis",
                [
                    ScriptedStep("gc", 1, journal, act_raises=KeyboardInterrupt()),
                    ScriptedStep("timers", 2, journal),
                ],
            )
        ],
    )
    with pytest.raises(KeyboardInterrupt):
        run.run()
    assert run.outcome is not None
    assert [(r.name, r.status, r.reason) for r in run.outcome.finally_] == [
        ("gc", "failed", "interrupted"),
        ("timers", "skipped", "after failed aivis/gc"),
    ]


def test_journal_sink_never_creates_its_file(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        JournalSink(tmp_path / "missing.jsonl", Secrets(()))
    assert list(tmp_path.iterdir()) == []


def test_interrupt_while_a_log_line_is_written_stops_the_step() -> None:
    """Ctrl-C during a command's output: the command stops, the step is interrupted."""

    class CutOnLog(ListSink):
        def emit(self, event: Event) -> None:
            if isinstance(event, LogLine):
                raise KeyboardInterrupt
            super().emit(event)

    journal = Journal()
    step = ScriptedStep("up", 1, journal, act_argv=["make", "up"])
    runner = FakeRunner(
        FakeCall(("make", "up"), lines=((Stream.STDOUT, "a"), (Stream.STDOUT, "b")))
    )
    built = Plan(
        _root(step),
        mode="deploy",
        role="test",
        runner=runner,
        sink=CutOnLog(),
        clock=lambda: 0.0,
        now=lambda: NOW,
    )
    with runner, pytest.raises(KeyboardInterrupt):
        built.run()
    assert built.outcome is not None
    assert [(r.status, r.reason) for r in built.outcome.steps] == [
        ("failed", "interrupted")
    ]
    assert "aivis/up:verify" not in journal


class _RolesInterruptOnce(ScriptedStep):
    """Its roles are read by the ladder between steps; the first read is cut."""

    cut = False

    @property
    def roles(self) -> frozenset[Role] | None:
        if not _RolesInterruptOnce.cut:
            _RolesInterruptOnce.cut = True
            raise KeyboardInterrupt
        return None

    @roles.setter
    def roles(self, value: object) -> None:
        pass


def test_interrupt_between_finally_steps_lets_the_clean_up_finish() -> None:
    """FIX DM-37: SIGTERM between two clean-up steps; both still run, then raise."""
    _RolesInterruptOnce.cut = False
    journal = Journal()
    run, _ = plan(
        _root(ScriptedStep("up", 1, journal)),
        finally_=[
            StackSteps(
                "aivis",
                [
                    ScriptedStep("gc", 1, journal),
                    _RolesInterruptOnce("timers", 2, journal),
                    ScriptedStep("logs", 3, journal),
                ],
            )
        ],
    )
    with pytest.raises(KeyboardInterrupt):
        run.run()
    assert run.outcome is not None and run.outcome.interrupted
    assert [(r.name, r.status) for r in run.outcome.finally_] == [
        ("gc", "ok"),
        ("timers", "ok"),
        ("logs", "ok"),
    ]
    assert "aivis/timers:verify" in journal and "aivis/logs:verify" in journal
