"""Console rendering of plan events (DM-6): only what the records carry."""

import io

from plan_support import Journal, ScriptedStep, plan, red

from pridem.events import (
    ConsoleSink,
    DoctorItem,
    Incomplete,
    PlanFinished,
    PlanOutcome,
    StepRecord,
)
from pridem.plan import StackSteps
from pridem.report.codes import ExitCode


def _render(*events: object) -> str:
    out = io.StringIO()
    sink = ConsoleSink(out)
    for event in events:
        assert isinstance(event, PlanFinished)
        sink.emit(event)
    return out.getvalue()


def test_console_prints_the_ladder_and_the_result() -> None:
    journal = Journal()
    out = io.StringIO()
    run, sink = plan(
        [
            StackSteps(
                "aivis",
                [
                    ScriptedStep(
                        "build",
                        1,
                        journal,
                        fact={"image_id": "sha256:ab", "ports": [80]},
                    ),
                    red("up", 2, journal),
                    ScriptedStep("health", 3, journal),
                ],
                root=True,
            )
        ]
    )
    console = ConsoleSink(out)
    run.run()
    for event in sink.events:
        console.emit(event)
    assert out.getvalue().splitlines() == [
        "✓ aivis · build · 1.0 s · image_id=sha256:ab, ports=[80]",
        "✗ aivis · up · 1.0 s · seen=x — up read back the wrong state",
        "– aivis · health — after failed aivis/up",
        "deploy → red",
    ]


def test_console_prints_incomplete_doctor_diff_and_restore_need() -> None:
    outcome = PlanOutcome(
        mode="deploy",
        code=ExitCode.FAILED,
        steps=(StepRecord("aivis", "migrate", 5, "failed", "boom"),),
        incomplete=(Incomplete("ssl", "deferred"),),
        doctor_diff=(DoctorItem("comms", "env", "render env"),),
        needs_restore=True,
        interrupted=True,
    )
    assert _render(PlanFinished(outcome)).splitlines() == [
        "deploy → red · interrupted",
        "  incomplete: ssl — deferred",
        "  would do: comms · env — render env",
        "  past the point of no return: restore from backup is needed",
    ]


def test_console_ignores_command_output_lines() -> None:
    journal = Journal()
    from pridem.runner import FakeCall, FakeRunner, Stream

    runner = FakeRunner(FakeCall(("make",), lines=((Stream.STDOUT, "SECRET=hunter2"),)))
    out = io.StringIO()
    console = ConsoleSink(out)
    with runner:
        run, sink = plan(
            [
                StackSteps(
                    "aivis",
                    [ScriptedStep("build", 1, journal, act_argv=["make"])],
                    root=True,
                )
            ],
            runner=runner,
        )
        run.run()
    for event in sink.events:
        console.emit(event)
    assert "hunter2" not in out.getvalue()
    assert len(sink.lines()) == 1
    assert "build" in out.getvalue()
