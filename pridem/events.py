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
(contract 2 rule 2).

A reason, an incomplete entry and a doctor item carry a ``Code``: a code and
its parameters, never a phrase (contract 2 v1.6). The words come from a catalog
(``report/catalog.py``) when something is rendered; the skip codes a plan
writes are built here.
"""

import json
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from datetime import datetime
from typing import Literal, Protocol, TextIO

from pydantic import SecretStr

from pridem.contract import SECRET_MIN_LENGTH
from pridem.report.catalog import ENGLISH, Catalog, say, text
from pridem.report.codes import RESERVED_PARAMS, ExitCode
from pridem.runner import Stream

type Json = None | bool | int | float | str | list[Json] | dict[str, Json]
type Fact = Mapping[str, Json]

Status = Literal["ok", "failed", "skipped"]
Phase = Literal["main", "restore", "finally"]
PlanMode = Literal["install", "deploy", "doctor", "reinstall"]
RunMode = PlanMode | Literal["status"]
"""What a run is: a plan's mode, or a verb that runs no plan (``status``)."""

REDACTED = "[redacted]"


@dataclass(frozen=True)
class Code:
    """A code and its parameters: a fact, not a phrase (contract 2 v1.6).

    ``code`` and ``what`` are taken and are never parameter names.
    """

    code: str
    params: Mapping[str, Json] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.code:
            raise ValueError("a code is not empty")
        taken = sorted(RESERVED_PARAMS & set(self.params))
        if taken:
            raise ValueError(f"parameter names {taken} are taken")

    def as_json(self) -> dict[str, Json]:
        """The flat object of the verdict: ``{"code": ..., **params}``."""
        return {"code": self.code, **self.params}


def role_skip(role: str) -> Code:
    """A step skipped because the box's role does not run it."""
    return Code("role", {"role": role})


def after_failure(phase: Phase, stack: str, name: str) -> Code:
    """A step skipped because the step ``phase stack name`` failed."""
    return Code("after-failure", {"phase": phase, "stack": stack, "name": name})


AFTER_INTERRUPT = Code("after-interrupt")
INTERRUPTED = Code("interrupted")
NO_FACT = Code("no-fact")


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

    The set of a run grows and never shrinks: a secret that appears during the
    run (the passport's after ``fetch_passport``, an answer of ``install``, a
    ``derived`` value) is ``add``-ed to the one object every sink and the
    verdict hold, before the first line that could carry it. The journal's cut
    of a long line is computed from this set on every piece (``safe_cut``), so
    a larger ``longest`` holds from the next piece on; the pieces written
    before could not carry a value the run did not know yet.
    """

    def __init__(self, values: Iterable[SecretStr]) -> None:
        self._values: tuple[str, ...] = ()
        self._pattern: re.Pattern[str] | None = None
        self.add(values)

    def add(self, values: Iterable[SecretStr]) -> None:
        """Know ``values`` too, from now on, wherever this object cleans."""
        plain = {value.get_secret_value() for value in values}
        if "" in plain:
            raise ValueError("an empty secret would match every position of a text")
        forms = set(self._values).union(*(_forms(secret) for secret in plain))
        self._values = tuple(sorted(forms, key=len, reverse=True))
        self._pattern = (
            re.compile("|".join(re.escape(form) for form in self._values))
            if self._values
            else None
        )

    @property
    def longest(self) -> int:
        """Length of the longest form; 0 when no secret is known."""
        return len(self._values[0]) if self._values else 0

    def safe_cut(self, text: str) -> int:
        """Where ``text`` may be cut when more text follows it.

        Everything before the cut can be cleaned now: no form found in ``text``
        crosses the cut, and a form completed by text still to come starts in
        the last ``longest - 1`` characters, which stay after the cut.
        """
        cut = len(text) - max(self.longest - 1, 0)
        if cut <= 0:
            return 0
        if self._pattern is not None:
            for match in self._pattern.finditer(text):
                if match.start() >= cut:
                    break
                if match.end() > cut:
                    return match.start()
        return cut

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
    """Something that should have been done and was not, and its code."""

    what: str
    reason: Code

    def __post_init__(self) -> None:
        if not self.what:
            raise ValueError("incomplete needs what")

    def as_json(self) -> dict[str, Json]:
        """The flat object of the verdict: ``{"what": ..., "code": ..., **params}``."""
        return {"what": self.what, **self.reason.as_json()}


@dataclass(frozen=True)
class StepRecord:
    """One step of a plan, in the fields of contract 2."""

    stack: str
    name: str
    order: int
    status: Status
    reason: Code | None = None
    started: datetime | None = None
    duration_s: float | None = None
    verify: Fact = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.status in ("skipped", "failed") and self.reason is None:
            raise ValueError(f"a {self.status} step needs a reason")
        if self.status == "ok" and not self.verify:
            raise ValueError("an ok step needs a non-empty verify fact")


@dataclass(frozen=True)
class DoctorItem:
    """What ``doctor`` found that a plan would do."""

    stack: str
    name: str
    reason: Code


@dataclass(frozen=True)
class PlanOutcome:
    """The result of a plan, from which the verdict is built."""

    mode: RunMode
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
    """One output line of a command a step ran.

    ``continued``: the line is longer than the runner's limit, this is one of
    its pieces, and more of the same line follows.
    """

    phase: Phase
    stack: str
    name: str
    stream: Stream
    line: str
    continued: bool = False


@dataclass(frozen=True)
class PlanFinished:
    outcome: PlanOutcome


type Event = StepStarted | StepFinished | LogLine | PlanFinished


class EventSink(Protocol):
    """Receives every event of a plan, in order."""

    def emit(self, event: Event) -> None:
        """Take one event."""
        ...


def _fact_line(fact: Fact, catalog: Catalog) -> str:
    parts = []
    for key, value in fact.items():
        shown = (
            value if isinstance(value, str) else json.dumps(value, ensure_ascii=False)
        )
        parts.append(say(catalog, "@fact", key=key, value=shown))
    return say(catalog, "@fact.sep").join(parts)


class ConsoleSink:
    """The step ladder as it runs: one line per finished step.

    Output lines of commands are not printed here; they belong to the journal.
    The closing line is the summary line of the verdict (contract 2 section 4),
    printed by whoever holds the verdict, not by this sink. Every word and mark
    of a line comes from ``catalog``, the step's ``reason`` included; the line's
    ``reason`` and ``verify`` are cleaned of known secrets.
    """

    def __init__(
        self, stream: TextIO, secrets: Secrets, catalog: Catalog = ENGLISH
    ) -> None:
        self._stream = stream
        self._secrets = secrets
        self._catalog = catalog

    def emit(self, event: Event) -> None:
        if isinstance(event, StepFinished):
            self._step(event.record)

    def _write(self, line: str) -> None:
        self._stream.write(line + "\n")
        self._stream.flush()

    def _step(self, record: StepRecord) -> None:
        catalog = self._catalog
        mark = say(catalog, f"@mark.{record.status}")
        line = say(
            catalog, "@console.step", mark=mark, stack=record.stack, name=record.name
        )
        if record.duration_s is not None:
            seconds = say(catalog, "@seconds", s=f"{record.duration_s:.1f}")
            line += say(catalog, "@console.duration", seconds=seconds)
        if record.verify:
            fact = _fact_line(self._secrets.fact(record.verify), catalog)
            line += say(catalog, "@console.fact", fact=fact)
        if record.reason is not None:
            words = text(catalog, record.reason.code, record.reason.params)
            line += say(catalog, "@console.reason", reason=self._secrets.text(words))
        self._write(line)
