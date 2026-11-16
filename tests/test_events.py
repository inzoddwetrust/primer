"""Console rendering of plan events (DM-6): only what the records carry."""

import io
from datetime import datetime

from plan_support import Journal, ScriptedStep, plan, red

from pridem.events import (
    Code,
    ConsoleSink,
    DoctorItem,
    Incomplete,
    PlanFinished,
    PlanOutcome,
    Secrets,
    StepFinished,
    StepRecord,
)
from pridem.plan import StackSteps
from pridem.report.codes import ExitCode

NO_SECRETS = Secrets(())


TEN = datetime(2026, 11, 16, 10, 0, 0)
"""The console's clock in these tests: a line's time is literal (DM-107)."""


def test_console_prints_the_ladder() -> None:
    """One line per finished step and nothing after the last one.

    Until DM-7 the sink also printed ``deploy → red`` at the end; the closing
    line is now the summary line of the verdict (contract 2 section 4). Since
    DM-42 a reason is a code and the console puts it in the plan's catalog's
    words (v1.6). Changed by DM-107 (the console for a person, the gate): a
    line has its time, the beginning of a step is said off a terminal, a fact
    is said only by the step's ``said`` (these steps have none: the journal
    has it), a skipped step is its mark and name -- what the test holds, one
    line per step and nothing after the last, is the same.
    """
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
    console = ConsoleSink(out, NO_SECRETS, run.catalog, now=lambda: TEN)
    run.run()
    for event in sink.events:
        console.emit(event)
    assert out.getvalue().splitlines() == [
        "[10:00:00] → aivis · build…",
        "[10:00:00] ✓ aivis · build · 1 s",
        "[10:00:00] → aivis · up…",
        "[10:00:00] ✗ aivis · up · 1 s — read back x",
        "[10:00:00] – aivis · health",
    ]


def test_console_leaves_the_outcome_to_the_verdict() -> None:
    """The outcome of a plan prints nothing on the console by the way.

    Replaces the DM-6 test of ``ConsoleSink._result`` (removed in DM-7): what it
    printed -- result, incomplete, doctor diff, need of restore -- is the
    summary line and the breakage report of the verdict now. The pair: a
    finished step of the same run does print.
    """
    record = StepRecord("aivis", "migrate", 5, "failed", Code("interrupted"))
    outcome = PlanOutcome(
        mode="deploy",
        code=ExitCode.FAILED,
        steps=(record,),
        incomplete=(Incomplete("ssl", Code("ssl:left")),),
        doctor_diff=(DoctorItem("comms", "env", Code("env:do")),),
        needs_restore=True,
        interrupted=True,
    )
    out = io.StringIO()
    sink = ConsoleSink(out, NO_SECRETS, now=lambda: TEN)  # DM-107: a line's time
    sink.emit(PlanFinished(outcome))
    assert out.getvalue() == ""
    sink.emit(StepFinished("main", record))
    assert out.getvalue() == "[10:00:00] ✗ aivis · migrate — interrupted\n"


def test_console_ignores_command_output_lines() -> None:
    journal = Journal()
    from pridem.runner import FakeCall, FakeRunner, Stream

    runner = FakeRunner(FakeCall(("make",), lines=((Stream.STDOUT, "SECRET=hunter2"),)))
    out = io.StringIO()
    console = ConsoleSink(out, NO_SECRETS)
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
