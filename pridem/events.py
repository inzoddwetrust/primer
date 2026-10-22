"""Everything a plan reports leaves through events; the records are their data.

A step record has the fields of a step in contract 2 (verdict) v1.1: ``stack``,
``name``, ``order`` (the phase number of the step, not a running index),
``status``, ``reason`` (required for ``skipped`` and ``failed``), ``started``,
``duration_s``, ``verify`` (the facts the step read back). Events are built
from these records, never from a step object, so a sink sees only what the
step itself put into its fact.
"""

import json
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime
from typing import Literal, Protocol, TextIO

from pridem.report.codes import ExitCode
from pridem.runner import Stream

type Json = None | bool | int | float | str | list[Json] | dict[str, Json]
type Fact = Mapping[str, Json]

Status = Literal["ok", "failed", "skipped"]
PlanMode = Literal["install", "deploy", "doctor", "reinstall"]


@dataclass(frozen=True)
class Incomplete:
    """Something a step should have done and did not, with the reason."""

    what: str
    why: str

    def __post_init__(self) -> None:
        if not self.what or not self.why:
            raise ValueError("incomplete needs both what and why")


@dataclass(frozen=True)
class StepRecord:
    """One step of a plan, in the fields of contract 2."""

    stack: str
    name: str
    order: int
    status: Status
    reason: str | None = None
    started: datetime | None = None
    duration_s: float | None = None
    verify: Fact = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.status in ("skipped", "failed") and not self.reason:
            raise ValueError(f"a {self.status} step needs a reason")
        if self.status == "ok" and not self.verify:
            raise ValueError("an ok step needs a non-empty verify fact")


@dataclass(frozen=True)
class DoctorItem:
    """What ``doctor`` found that a plan would do."""

    stack: str
    name: str
    what: str


@dataclass(frozen=True)
class PlanOutcome:
    """The result of a plan, from which the verdict is built."""

    mode: PlanMode
    code: ExitCode
    steps: tuple[StepRecord, ...]
    restore: tuple[StepRecord, ...] = ()
    finally_: tuple[StepRecord, ...] = ()
    incomplete: tuple[Incomplete, ...] = ()
    doctor_diff: tuple[DoctorItem, ...] = ()
    needs_restore: bool = False
    interrupted: bool = False


@dataclass(frozen=True)
class StepStarted:
    stack: str
    name: str
    order: int
    started: datetime


@dataclass(frozen=True)
class StepFinished:
    record: StepRecord


@dataclass(frozen=True)
class LogLine:
    """One output line of a command a step ran."""

    stack: str
    name: str
    stream: Stream
    line: str


@dataclass(frozen=True)
class PlanFinished:
    outcome: PlanOutcome


type Event = StepStarted | StepFinished | LogLine | PlanFinished


class EventSink(Protocol):
    """Receives every event of a plan, in order."""

    def emit(self, event: Event) -> None:
        """Take one event."""
        ...


_MARK = {"ok": "✓", "failed": "✗", "skipped": "–"}
_RESULT = {
    ExitCode.OK: "green",
    ExitCode.FAILED: "red",
    ExitCode.INCOMPLETE: "incomplete",
}


def _fact_line(fact: Fact) -> str:
    parts = []
    for key, value in fact.items():
        shown = (
            value if isinstance(value, str) else json.dumps(value, ensure_ascii=False)
        )
        parts.append(f"{key}={shown}")
    return ", ".join(parts)


class ConsoleSink:
    """The step ladder as it runs: one line per finished step, then the result.

    Output lines of commands are not printed here; they belong to the journal.
    """

    def __init__(self, stream: TextIO) -> None:
        self._stream = stream

    def emit(self, event: Event) -> None:
        if isinstance(event, StepFinished):
            self._step(event.record)
        elif isinstance(event, PlanFinished):
            self._result(event.outcome)

    def _write(self, line: str) -> None:
        self._stream.write(line + "\n")
        self._stream.flush()

    def _step(self, record: StepRecord) -> None:
        line = f"{_MARK[record.status]} {record.stack} · {record.name}"
        if record.duration_s is not None:
            line += f" · {record.duration_s:.1f} s"
        if record.verify:
            line += f" · {_fact_line(record.verify)}"
        if record.reason:
            line += f" — {record.reason}"
        self._write(line)

    def _result(self, outcome: PlanOutcome) -> None:
        line = f"{outcome.mode} → {_RESULT[outcome.code]}"
        if outcome.interrupted:
            line += " · interrupted"
        self._write(line)
        for item in outcome.incomplete:
            self._write(f"  incomplete: {item.what} — {item.why}")
        for diff in outcome.doctor_diff:
            self._write(f"  would do: {diff.stack} · {diff.name} — {diff.what}")
        if outcome.needs_restore:
            self._write("  past the point of no return: restore from backup is needed")
