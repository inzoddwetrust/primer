"""Everything a plan reports leaves through events; the records are their data.

A step record has the fields of a step in contract 2 (verdict) v1.3 but the
phase: ``stack``, ``name``, ``order`` (the phase number of the step, not a
running index), ``status``, ``reason`` (required for ``skipped`` and
``failed``), ``started``, ``duration_s``, ``verify`` (the facts the step read
back). The plan phase a step ran in (``main``, ``restore``, ``finally``) is a
field of every step event and log line, so a journal tells same-named steps of
different phases apart; the outcome keeps one tuple per phase. Events are
built from these records, never from a step object, so a sink sees only what
the step itself put into its fact.

Known secrets (``asked`` and ``tls`` of the passport, ``minted``) are cleaned by
exact match with ``Secrets`` -- the one function the verdict and the console use
(contract 2 rule 2). The skip reasons a plan writes are built here, so the
renderers that tell a role skip from a skip after a failure read the same text.
"""

import json
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from datetime import datetime
from typing import Literal, Protocol, TextIO

from pydantic import SecretStr

from pridem.contract import SECRET_MIN_LENGTH
from pridem.report.codes import ExitCode
from pridem.runner import Stream

type Json = None | bool | int | float | str | list[Json] | dict[str, Json]
type Fact = Mapping[str, Json]

Status = Literal["ok", "failed", "skipped"]
Phase = Literal["main", "restore", "finally"]
PlanMode = Literal["install", "deploy", "doctor", "reinstall"]

REDACTED = "[redacted]"
ROLE_SKIP = "role "
AFTER_FAILURE = "after failed "
AFTER_INTERRUPT = "after interrupt"


def role_skip(role: str) -> str:
    """The reason of a step skipped because the box's role does not run it."""
    return f"{ROLE_SKIP}{role}"


def after_failure(stack: str, name: str) -> str:
    """The reason of a step skipped because an earlier step failed."""
    return f"{AFTER_FAILURE}{stack}/{name}"


def _forms(secret: str) -> set[str]:
    """The exact forms of ``secret`` that are cleaned (contract 2 rule 2).

    The value whole, at any length; the value without whitespace at its edges
    and each of its lines (a PEM, a YAML block) when at least
    ``SECRET_MIN_LENGTH`` long. A shorter derived form is left alone, as the
    owner accepted (the short tail of a PEM body): it would match ordinary text.
    """
    derived = {secret.strip(), *secret.splitlines()}
    return {secret} | {form for form in derived if len(form) >= SECRET_MIN_LENGTH}


class Secrets:
    """Known secret values and the exact-match cleaning of text and facts.

    Every secret contributes its forms (``_forms``); the forms of all secrets
    are one set, replaced longest first, so a secret that contains another --
    or contains its own lines -- is replaced whole, with no pieces left. An
    empty value is an error: it matches everywhere.
    """

    def __init__(self, values: Iterable[SecretStr]) -> None:
        plain = {value.get_secret_value() for value in values}
        if "" in plain:
            raise ValueError("an empty secret would match every position of a text")
        forms = set().union(*(_forms(secret) for secret in plain))
        self._values = tuple(sorted(forms, key=len, reverse=True))

    def text(self, value: str) -> str:
        """``value`` with every known secret replaced by ``[redacted]``."""
        for secret in self._values:
            value = value.replace(secret, REDACTED)
        return value

    def value(self, value: Json) -> Json:
        """``value`` with every string in it, keys included, cleaned."""
        if isinstance(value, str):
            return self.text(value)
        if isinstance(value, list):
            return [self.value(item) for item in value]
        if isinstance(value, dict):
            return self.fact(value)
        return value

    def fact(self, fact: Fact) -> dict[str, Json]:
        """A cleaned copy of ``fact``; two keys equal after cleaning are an error."""
        out: dict[str, Json] = {}
        for key, item in fact.items():
            clean = self.text(key)
            if clean in out:
                raise ValueError(f"two keys are {clean!r} after cleaning secrets")
            out[clean] = self.value(item)
        return out


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
    phase: Phase
    stack: str
    name: str
    order: int
    started: datetime


@dataclass(frozen=True)
class StepFinished:
    phase: Phase
    record: StepRecord


@dataclass(frozen=True)
class LogLine:
    """One output line of a command a step ran."""

    phase: Phase
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


def _fact_line(fact: Fact) -> str:
    parts = []
    for key, value in fact.items():
        shown = (
            value if isinstance(value, str) else json.dumps(value, ensure_ascii=False)
        )
        parts.append(f"{key}={shown}")
    return ", ".join(parts)


class ConsoleSink:
    """The step ladder as it runs: one line per finished step.

    Output lines of commands are not printed here; they belong to the journal.
    The closing line is the summary line of the verdict (contract 2 section 4),
    printed by whoever holds the verdict, not by this sink. A step's ``reason``
    and ``verify`` are cleaned of known secrets.
    """

    def __init__(self, stream: TextIO, secrets: Secrets) -> None:
        self._stream = stream
        self._secrets = secrets

    def emit(self, event: Event) -> None:
        if isinstance(event, StepFinished):
            self._step(event.record)

    def _write(self, line: str) -> None:
        self._stream.write(line + "\n")
        self._stream.flush()

    def _step(self, record: StepRecord) -> None:
        line = f"{_MARK[record.status]} {record.stack} · {record.name}"
        if record.duration_s is not None:
            line += f" · {record.duration_s:.1f} s"
        if record.verify:
            line += f" · {_fact_line(self._secrets.fact(record.verify))}"
        if record.reason:
            line += f" — {self._secrets.text(record.reason)}"
        self._write(line)
