"""Probes DM-37: a step and a sink never crash the plan, ``finally`` runs every
time, and an unexpected exception leaves only its type name in the verdict.
"""

import io
from collections.abc import Sequence
from itertools import count
from pathlib import Path

import pytest
from plan_support import NOW, Journal, ListSink, ScriptedStep, red
from pydantic import SecretStr
from report_support import build
from state_support import header

from pridem.events import ConsoleSink, Event, EventSink, Secrets, StepFinished
from pridem.plan import Plan, StackSteps
from pridem.report.codes import ExitCode
from pridem.report.render import render_json, render_llm, render_report
from pridem.runner import FakeRunner
from pridem.state import Box


def _plan(
    main: list[ScriptedStep],
    sink: EventSink,
    *,
    restore: Sequence[StackSteps] = (),
    finally_: Sequence[StackSteps] = (),
) -> Plan:
    ticks = count()
    return Plan(
        [StackSteps("aivis", main, root=True)],
        mode="deploy",
        role="test",
        runner=FakeRunner(),
        sink=sink,
        restore=restore,
        finally_=finally_,
        clock=lambda: float(next(ticks)),
        now=lambda: NOW,
    )


class _RolesInterrupt(ScriptedStep):
    """Its roles are read by the ladder between steps; the read is interrupted."""

    @property
    def roles(self) -> None:
        raise KeyboardInterrupt

    @roles.setter
    def roles(self, value: object) -> None:
        pass


class _InterruptOnce(ListSink):
    """A sink whose first ``StepFinished`` is cut by an interrupt."""

    def __init__(self) -> None:
        super().__init__()
        self.cut = False

    def emit(self, event: Event) -> None:
        if isinstance(event, StepFinished) and not self.cut:
            self.cut = True
            raise KeyboardInterrupt
        super().emit(event)


@pytest.mark.parametrize("place", ["in_step", "between_steps", "in_emit"])
def test_probe_DM_37_finally_runs_every_step_after_interrupt(place: str) -> None:
    journal = Journal()
    sink: ListSink = _InterruptOnce() if place == "in_emit" else ListSink()
    build_step = ScriptedStep("build", 1, journal)
    second: ScriptedStep
    if place == "in_step":
        second = ScriptedStep("up", 2, journal, act_raises=KeyboardInterrupt())
    elif place == "between_steps":
        second = _RolesInterrupt("up", 2, journal)
    else:
        second = ScriptedStep("up", 2, journal)
    third = ScriptedStep("health", 3, journal)
    run = _plan(
        [build_step, second, third],
        sink,
        restore=[StackSteps("aivis", [ScriptedStep("old", 1, journal)])],
        finally_=[
            StackSteps(
                "aivis",
                [
                    ScriptedStep("gc", 1, journal, act_raises=OSError("disk")),
                    ScriptedStep("timers", 2, journal),
                ],
            )
        ],
    )
    with pytest.raises(KeyboardInterrupt):
        run.run()
    outcome = run.outcome
    assert outcome is not None and outcome.interrupted
    assert outcome.code is ExitCode.FAILED
    assert [(r.name, r.status) for r in outcome.finally_] == [
        ("gc", "failed"),
        ("timers", "ok"),
    ]
    assert "aivis/timers:verify" in journal and "aivis/old:verify" in journal
    assert "aivis/health:check" not in journal
    assert outcome.steps[-1].status == "skipped"
    lost = [(i.what, i.why) for i in outcome.incomplete]
    if place == "in_emit":
        # the cut event is lost like a failed write; the step's record is kept
        assert lost == [("journal", "journal write failed")]
        assert (outcome.steps[0].name, outcome.steps[0].status) == ("build", "ok")
    else:
        assert lost == []


class _BrokenSink(ListSink):
    """A sink that fails (disk full) on the first event of one kind."""

    def __init__(self, kind: str) -> None:
        super().__init__()
        self.kind = kind
        self.calls_after_failure = 0
        self.failed = False

    def emit(self, event: Event) -> None:
        if self.failed:
            self.calls_after_failure += 1
        if type(event).__name__ == self.kind and not self.failed:
            self.failed = True
            raise OSError(28, "No space left on device")
        super().emit(event)


@pytest.mark.parametrize(
    "kind", ["StepStarted", "StepFinished", "LogLine", "PlanFinished"]
)
def test_probe_DM_37_sink_failure_never_crashes_the_plan(kind: str) -> None:
    journal = Journal()
    sink = _BrokenSink(kind)
    talker = ScriptedStep("up", 2, journal)
    noisy = ScriptedStep("noisy", 1, journal, check_raises=ValueError("x"))
    run = _plan(
        [noisy, talker],
        sink,
        restore=[StackSteps("aivis", [ScriptedStep("old", 1, journal)])],
        finally_=[StackSteps("aivis", [ScriptedStep("gc", 1, journal)])],
    )
    outcome = run.run()
    assert sink.failed and sink.calls_after_failure == 0
    assert [(i.what, i.why) for i in outcome.incomplete] == [
        ("journal", "journal write failed")
    ]
    assert [r.name for r in outcome.steps] == ["noisy", "up"]
    assert [r.name for r in outcome.restore] == ["old"]
    assert [r.name for r in outcome.finally_] == ["gc"]
    assert outcome.code is ExitCode.FAILED and run.outcome == outcome
    assert build(outcome).report.incomplete[0].what == "journal"


def test_probe_DM_37_unexpected_exception_reason_is_type_only(tmp_path: Path) -> None:
    marker = "unexpected-secret-value-41a7"
    secrets = Secrets([SecretStr(marker)])
    journal = Journal()
    box = Box(tmp_path)
    with box.lock("a"):
        sink = box.open_journal(header("2026-10-15T10:42:01Z-a3f9"), secrets)
        console = io.StringIO()
        both = _Tee(sink, ConsoleSink(console, secrets))
        boom = ScriptedStep(
            "up", 1, journal, act_raises=RuntimeError(f"token={marker} rejected")
        )
        own = ScriptedStep("check", 2, journal)
        run = _plan([boom, own], both)
        outcome = run.run()
        sink.close()
    record = outcome.steps[0]
    assert (record.status, record.reason) == ("failed", "RuntimeError")
    verdict = build(outcome, secrets=Secrets(()))  # nothing left to clean
    texts = [
        verdict.model_dump_json(),
        render_json(verdict),
        render_report(verdict, None, secrets),
        render_llm(verdict, None, secrets),
        console.getvalue(),
    ]
    assert all(marker not in text and "rejected" not in text for text in texts)
    written = (tmp_path / "journal" / "2026-10-15T10:42:01Z-a3f9.jsonl").read_text()
    assert "RuntimeError: token=[redacted] rejected" in written
    assert marker not in written
    own_reason = _plan([red("up", 1, Journal())], ListSink()).run()
    assert own_reason.steps[0].reason == "up read back the wrong state"


class _Tee:
    def __init__(self, *sinks: EventSink) -> None:
        self.sinks = sinks

    def emit(self, event: Event) -> None:
        for sink in self.sinks:
            sink.emit(event)
