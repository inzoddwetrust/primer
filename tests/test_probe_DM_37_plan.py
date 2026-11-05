"""Probes DM-37: a step and a sink never crash the plan, ``finally`` runs every
time, and an unexpected exception leaves only its type name in the verdict.
"""

import io
import signal
from collections.abc import Sequence
from itertools import count
from pathlib import Path

import pytest
from plan_support import NOW, Journal, ListSink, ScriptedStep, red
from pydantic import SecretStr
from report_support import build
from state_support import header

from pridem.events import Code, ConsoleSink, Event, EventSink, Secrets, StepFinished
from pridem.interrupt import Interrupt
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
    interrupt: Interrupt | None = None,
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
        interrupt=interrupt,
    )


class _SignalOnce(ListSink):
    """A sink during whose first ``StepFinished`` a signal arrives."""

    def __init__(self, interrupt: Interrupt) -> None:
        super().__init__()
        self.interrupt = interrupt
        self.cut = False

    def emit(self, event: Event) -> None:
        if isinstance(event, StepFinished) and not self.cut:
            self.cut = True
            self.interrupt.receive(signal.SIGINT)
        super().emit(event)


@pytest.mark.parametrize("place", ["in_step", "between_steps", "in_emit"])
def test_probe_DM_37_finally_runs_every_step_after_interrupt(place: str) -> None:
    """DM-42 (contract 2 v1.6): reasons and incomplete entries are codes with
    parameters, not phrases; the data changed form only, each assertion keeps
    its strength.

    DM-45: a signal is a flag (``pridem/interrupt.py``), so the run returns
    its outcome instead of raising; the probe still holds -- after a signal in
    a step, between steps or while an event is written, restore and every step
    of finally run, the rest of main does not. A signal while an event is
    written no longer cuts the write: nothing is lost (it was
    ``write-failed``), the event and the step's record are kept.
    """
    journal = Journal()
    interrupt = Interrupt()
    sink: ListSink = _SignalOnce(interrupt) if place == "in_emit" else ListSink()
    build_step = ScriptedStep(
        "build",
        1,
        journal,
        signal_in="verify" if place == "between_steps" else None,
        signal_stops=False,
    )
    second = ScriptedStep(
        "up", 2, journal, signal_in="act" if place == "in_step" else None
    )
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
        interrupt=interrupt,
    )
    outcome = run.run()
    assert outcome is run.outcome and outcome.interrupted
    assert outcome.code is ExitCode.FAILED
    assert [(r.name, r.status) for r in outcome.finally_] == [
        ("gc", "failed"),
        ("timers", "ok"),
    ]
    assert "aivis/timers:verify" in journal and "aivis/old:verify" in journal
    assert "aivis/health:check" not in journal
    assert outcome.steps[-1].status == "skipped"
    assert (outcome.steps[0].name, outcome.steps[0].status) == ("build", "ok")
    lost = [i.as_json() for i in outcome.incomplete]  # DM-42: codes (v1.6)
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
    """DM-42 (contract 2 v1.6): reasons and incomplete entries are codes with
    parameters, not phrases; the data changed form only, each assertion keeps
    its strength.
    """
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
    assert [i.as_json() for i in outcome.incomplete] == [  # DM-42: codes (v1.6)
        {"what": "journal", "code": "write-failed"}
    ]
    assert [r.name for r in outcome.steps] == ["noisy", "up"]
    assert [r.name for r in outcome.restore] == ["old"]
    assert [r.name for r in outcome.finally_] == ["gc"]
    assert outcome.code is ExitCode.FAILED and run.outcome == outcome
    assert build(outcome).report.incomplete[0].what == "journal"


def test_probe_DM_37_unexpected_exception_reason_is_type_only(tmp_path: Path) -> None:
    """DM-42 (contract 2 v1.6): reasons and incomplete entries are codes with
    parameters, not phrases; the data changed form only, each assertion keeps
    its strength.
    """
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
    # DM-42 (contract 2 v1.6): the type name is the parameter of ``exception``
    assert (record.status, record.reason) == (
        "failed",
        Code("exception", {"type": "RuntimeError"}),
    )
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
    assert own_reason.steps[0].reason == Code("up:wrong-state", {"seen": "x"})


class _Tee:
    def __init__(self, *sinks: EventSink) -> None:
        self.sinks = sinks

    def emit(self, event: Event) -> None:
        for sink in self.sinks:
            sink.emit(event)
