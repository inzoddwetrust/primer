"""Contract 2: the verdict -- models, contract rules, builder, JSON Schema.

A verdict ends every command. The models are strict and closed on the one base
``Strict``: a key with nothing to say is absent, never ``null``, and every
optional field is left out of the dump when it is ``None``. Rules checked here:

- rule 1: both compositions are present and each has ``pridem``;
- ``result`` follows from ``exit_code`` (``ExitCode`` of ``report/codes.py``,
  ``True``/``False`` rejected in every mode, JSON included);
- a ``skipped`` or ``failed`` step has a ``reason``; an ``ok`` step has a
  non-empty ``verify`` fact; ``verify``, when present, is not empty;
- ``reason``, an ``incomplete`` entry and a ``doctor_diff`` entry are a code and
  its parameters in one flat object, never a phrase (v1.6): a machine code is
  one of a closed union with exactly its parameters -- ``ended_at`` and
  ``errno`` are the only parameters that may be ``null`` -- and anything else
  must have the form of a step's code, ``<step>:<code>``, with scalar or
  list-of-string parameters, so the verdict of a removed step still loads;
  a step's incomplete entry has ``what`` = its step and a doctor entry
  ``name`` = its step;
- the code agrees with the content: a failed step means 1; 0 means no failed
  step, no ``incomplete`` and no ``doctor_diff`` entry; 2 means no failed step
  and ``incomplete`` or ``doctor_diff`` not empty; 1 without a failed step is
  allowed (rule 4: a run that ended without a verdict is recorded red);
- ``report.doctor_diff`` is present exactly on ``doctor``;
- ``log_ref`` is ``journal/<run_id>.jsonl``; ``started <= finished``;
  ``actor.on_behalf_of`` is present exactly for ``dispatcher`` and ``executor``.

Rule 2 (no secrets) is kept by ``build_verdict``: every string of the raw
verdict, keys included, is cleaned of known secrets before validation, so not
even a validation error can quote one. Rule 6 (every code has a text) is kept by
``build_verdict`` too: a code without a text in the catalog it is given is
refused before the verdict exists. Rule 3 (a role skip is ``skipped``, not
``incomplete``) is how the plan writes records; a model cannot tell it.

``python -m pridem.report.schema --export`` writes the JSON Schema of the
verdict to ``contract/schema/``.
"""

import argparse
import json
import re
import sys
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from typing import Annotated, ClassVar, Literal, Self

from pydantic import (
    AfterValidator,
    AwareDatetime,
    BeforeValidator,
    ConfigDict,
    Discriminator,
    Field,
    Tag,
    TypeAdapter,
    WithJsonSchema,
    model_validator,
)
from pydantic_core import PydanticCustomError

from pridem.contract import (
    SCHEMA_DIR,
    ContractSchema,
    SchemaVersion,
    Strict,
    schema_text,
)
from pridem.events import Fact, Json, Phase, PlanOutcome, Secrets, StepRecord
from pridem.report.catalog import ENGLISH, Catalog, missing
from pridem.report.codes import (
    INCOMPLETE_CODES,
    REASON_CODES,
    RESERVED_PARAMS,
    STEP_CODE,
    ExitCode,
    catalog_key,
)

Result = Literal["green", "red", "incomplete"]
RESULT: Mapping[ExitCode, Result] = {
    ExitCode.OK: "green",
    ExitCode.FAILED: "red",
    ExitCode.INCOMPLETE: "incomplete",
}
RUN_ID = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z-[0-9a-f]{4}")
# pydantic looks for a pattern anywhere in the string: the anchors are what keep
# a run id from naming a path outside its directory (``../<run id>``).
RunId = Annotated[str, Field(pattern=f"^{RUN_ID.pattern}$")]

Text = Annotated[str, Field(min_length=1)]
Count = Annotated[int, Field(ge=0)]


def _is_none(value: object) -> bool:
    return value is None


def _exit_code(value: object) -> object:
    """Only an ``int`` 0, 1 or 2 or an ``ExitCode``.

    Strict mode alone lets an ``IntEnum`` take ``true`` from JSON and ``0.0``
    once ``Strict`` has turned JSON input into Python objects (measured on
    pydantic 2.14.1); both are refused here, by exact type.
    """
    if isinstance(value, ExitCode):
        return value
    if type(value) is not int:
        raise PydanticCustomError(
            "int_type",
            "exit_code must be the integer 0, 1 or 2, not {kind}",
            {"kind": type(value).__name__},
        )
    return ExitCode(value) if value in ExitCode else value


def _moment(value: object) -> object:
    """An ISO 8601 text -> datetime.

    ``Strict`` validates a model before its fields, which turns JSON input into
    Python objects; strict mode then refuses the text of a datetime that JSON
    mode would accept. Only ISO text is parsed -- lax mode would also take a
    Unix timestamp.
    """
    if isinstance(value, str):
        try:
            return datetime.fromisoformat(value)
        except ValueError as error:
            raise PydanticCustomError(
                "datetime_from_iso",
                "not an ISO 8601 datetime: {error}",
                {"error": str(error)},
            ) from error
    return value


Moment = Annotated[AwareDatetime, BeforeValidator(_moment)]


def _composition(value: dict[str, str]) -> dict[str, str]:
    if "pridem" not in value:
        raise ValueError("a composition always names the pridem version (rule 1)")
    for key, version in value.items():
        if not key or not version or any(c.isspace() for c in key + version):
            raise ValueError(f"composition entry {key!r}: {version!r} must be one word")
    return value


# Stack -> commit or release, ``pridem`` -> version, package slot -> ``name@version``.
Composition = Annotated[dict[str, str], AfterValidator(_composition)]


class Actor(Strict):
    type: Literal["owner", "engineer", "dispatcher", "executor", "machine"]
    via: Literal["local", "panel", "timer"]
    on_behalf_of: Text | None = Field(default=None, exclude_if=_is_none)

    @model_validator(mode="after")
    def _llm_acts_for_someone(self) -> Self:
        llm = self.type in ("dispatcher", "executor")
        if llm != (self.on_behalf_of is not None):
            raise ValueError(
                "on_behalf_of is present exactly for dispatcher and executor"
            )
        return self


PhaseName = Literal["main", "restore", "finally"]
Argv = Annotated[list[Text], Field(min_length=1)]
ErrnoName = Annotated[str, Field(pattern=r"^E[A-Z0-9]+$")]
StepParam = int | float | bool | str | list[str]


class _Nullable(Strict):
    """A machine code whose ``NULLABLE`` parameters are written as ``null``."""

    NULLABLE: ClassVar[frozenset[str]] = frozenset()

    @model_validator(mode="before")
    @classmethod
    def _no_explicit_null(cls, data: object) -> object:
        if isinstance(data, dict):
            nulls = sorted(
                str(key)
                for key, value in data.items()
                if value is None and key not in cls.NULLABLE
            )
            if nulls:
                raise PydanticCustomError(
                    "null_forbidden",
                    "explicit null is not allowed (omit the key instead): {keys}",
                    {"keys": ", ".join(nulls)},
                )
        return data


def _or_null(model: type[Strict] | TypeAdapter[str]) -> WithJsonSchema:
    """The JSON Schema of ``model`` or ``null``; the generator drops plain nulls."""
    if isinstance(model, TypeAdapter):
        inner = model.json_schema(schema_generator=ContractSchema)
    else:
        inner = model.model_json_schema(schema_generator=ContractSchema)
    return WithJsonSchema({"anyOf": [inner, {"type": "null"}]})


class At(Strict):
    """A step of a plan: where a journal ends."""

    phase: PhaseName
    stack: Text
    name: Text


class RoleSkip(Strict):
    code: Literal["role"]
    role: Text


class AfterFailure(Strict):
    code: Literal["after-failure"]
    phase: PhaseName
    stack: Text
    name: Text


class AfterInterrupt(Strict):
    code: Literal["after-interrupt"]


class Interrupted(Strict):
    code: Literal["interrupted"]


class NoFact(Strict):
    code: Literal["no-fact"]


class CommandFailedReason(Strict):
    code: Literal["command-failed"]
    argv: Argv
    exit_code: int


class CommandTimedOutReason(Strict):
    code: Literal["command-timed-out"]
    argv: Argv
    timeout_s: Annotated[float, Field(ge=0)]


class CommandNotStartedReason(_Nullable):
    NULLABLE = frozenset({"errno"})
    code: Literal["command-not-started"]
    argv: Argv
    errno: Annotated[ErrnoName | None, _or_null(TypeAdapter(ErrnoName))]


class ExceptionReason(Strict):
    code: Literal["exception"]
    type: Text


class StepCode(Strict):
    """A step's own code, ``<step>:<code>``, with its parameters."""

    model_config = ConfigDict(extra="allow")
    __pydantic_extra__: dict[str, StepParam] = Field(init=False)

    code: Annotated[str, Field(pattern=STEP_CODE)]

    @model_validator(mode="after")
    def _params(self) -> Self:
        taken = sorted(RESERVED_PARAMS & set(self.__pydantic_extra__))
        if taken:
            raise ValueError(f"parameter names {taken} are taken")
        return self

    @property
    def step(self) -> str:
        return self.code.split(":", 1)[0]


def _reason_tag(value: object) -> str:
    code = value.get("code") if isinstance(value, dict) else getattr(value, "code", "")
    return code if code in REASON_CODES else "step"


Reason = Annotated[
    Annotated[RoleSkip, Tag("role")]
    | Annotated[AfterFailure, Tag("after-failure")]
    | Annotated[AfterInterrupt, Tag("after-interrupt")]
    | Annotated[Interrupted, Tag("interrupted")]
    | Annotated[NoFact, Tag("no-fact")]
    | Annotated[CommandFailedReason, Tag("command-failed")]
    | Annotated[CommandTimedOutReason, Tag("command-timed-out")]
    | Annotated[CommandNotStartedReason, Tag("command-not-started")]
    | Annotated[ExceptionReason, Tag("exception")]
    | Annotated[StepCode, Tag("step")],
    Discriminator(_reason_tag),
]
REASON_MODELS: dict[str, type[Strict]] = {
    "role": RoleSkip,
    "after-failure": AfterFailure,
    "after-interrupt": AfterInterrupt,
    "interrupted": Interrupted,
    "no-fact": NoFact,
    "command-failed": CommandFailedReason,
    "command-timed-out": CommandTimedOutReason,
    "command-not-started": CommandNotStartedReason,
    "exception": ExceptionReason,
}


class Step(Strict):
    stack: Text
    name: Text
    phase: PhaseName
    order: int
    status: Literal["ok", "failed", "skipped"]
    reason: Reason | None = Field(default=None, exclude_if=_is_none)
    started: Moment | None = Field(default=None, exclude_if=_is_none)
    duration_s: Annotated[float, Field(ge=0)] | None = Field(
        default=None, exclude_if=_is_none
    )
    verify: dict[str, Json] | None = Field(default=None, exclude_if=_is_none)

    @model_validator(mode="after")
    def _status_needs(self) -> Self:
        if self.status in ("skipped", "failed") and self.reason is None:
            raise ValueError(f"a {self.status} step needs a reason")
        if self.verify == {}:
            raise ValueError("verify, when present, is a non-empty fact (omit the key)")
        if self.status == "ok" and not self.verify:
            raise ValueError("an ok step needs a verify fact read back from the box")
        return self


class Failure(Strict):
    test: Text
    file: Text
    line: Annotated[int, Field(ge=1)]
    message: str
    traceback_project_frames: list[str]
    request_ids: list[str]


class NoVerdict(_Nullable):
    NULLABLE = frozenset({"ended_at"})
    what: Literal["run"]
    code: Literal["no-verdict"]
    ended_at: Annotated[At | None, _or_null(At)]


class JournalDamaged(Strict):
    what: Literal["run"]
    code: Literal["journal-damaged"]
    line: Annotated[int, Field(ge=1)]


class JournalWriteFailed(Strict):
    what: Literal["journal"]
    code: Literal["write-failed"]


class JournalQuarantined(Strict):
    what: Literal["journal"]
    code: Literal["quarantined"]
    run_id: RunId


class StateQuarantined(Strict):
    what: Literal["state"]
    code: Literal["quarantined"]


class RestoreNeeded(Strict):
    what: Literal["restore"]
    code: Literal["needed"]


class StepIncomplete(StepCode):
    """Something a step left undone: ``what`` is the step, ``code`` its own."""

    what: Text

    @model_validator(mode="after")
    def _what_is_the_step(self) -> Self:
        if self.what != self.step:
            raise ValueError(f"a step's incomplete entry names its step: {self.step}")
        return self


def _incomplete_tag(value: object) -> str:
    if isinstance(value, dict):
        what, code = value.get("what"), value.get("code")
    else:
        what, code = getattr(value, "what", ""), getattr(value, "code", "")
    key = f"{what}/{code}"
    return key if key in INCOMPLETE_CODES else "step"


IncompleteEntry = Annotated[
    Annotated[NoVerdict, Tag("run/no-verdict")]
    | Annotated[JournalDamaged, Tag("run/journal-damaged")]
    | Annotated[JournalWriteFailed, Tag("journal/write-failed")]
    | Annotated[JournalQuarantined, Tag("journal/quarantined")]
    | Annotated[StateQuarantined, Tag("state/quarantined")]
    | Annotated[RestoreNeeded, Tag("restore/needed")]
    | Annotated[StepIncomplete, Tag("step")],
    Discriminator(_incomplete_tag),
]
INCOMPLETE_MODELS: dict[str, type[Strict]] = {
    "run/no-verdict": NoVerdict,
    "run/journal-damaged": JournalDamaged,
    "journal/write-failed": JournalWriteFailed,
    "journal/quarantined": JournalQuarantined,
    "state/quarantined": StateQuarantined,
    "restore/needed": RestoreNeeded,
}


class DoctorDiff(StepCode):
    """What ``doctor`` found a step would do: ``name`` is the step of ``code``."""

    stack: Text
    name: Text

    @model_validator(mode="after")
    def _name_is_the_step(self) -> Self:
        if self.name != self.step:
            raise ValueError(f"a doctor entry's code is its step's: {self.name}")
        return self


class DnsCheck(Strict):
    domain: Text
    resolves_to: list[Text]
    expected: Text


class Report(Strict):
    failures: list[Failure]
    incomplete: list[IncompleteEntry]
    doctor_diff: list[DoctorDiff] | None = Field(default=None, exclude_if=_is_none)
    dns: list[DnsCheck] | None = Field(default=None, exclude_if=_is_none)


class Junit(Strict):
    total: Count
    failed: Count
    skipped: Count

    @model_validator(mode="after")
    def _within_total(self) -> Self:
        if self.failed + self.skipped > self.total:
            raise ValueError("failed + skipped exceed total")
        return self


class Verdict(Strict):
    """What a pridem command ends with (contract 2 section 1)."""

    model_config = ConfigDict(serialize_by_alias=True, validate_by_alias=True)

    schema_: SchemaVersion = Field(alias="schema")
    run_id: RunId
    verb: Annotated[str, Field(pattern=r"^[a-z][a-z0-9-]*( [a-z][a-z0-9-]*)*$")]
    args: dict[str, Json]
    actor: Actor
    started: Moment
    finished: Moment
    exit_code: Annotated[ExitCode, BeforeValidator(_exit_code)]
    result: Result
    # absent while the box has no passport (contract 2 v1.9)
    passport_version: Annotated[int, Field(ge=1)] | None = Field(
        default=None, exclude_if=_is_none
    )
    composition_before: Composition
    composition_after: Composition
    steps: list[Step]
    report: Report
    junit: Junit | None = Field(default=None, exclude_if=_is_none)
    log_ref: Text

    @model_validator(mode="after")
    def _rules(self) -> Self:
        if self.result != RESULT[self.exit_code]:
            raise ValueError(
                f"result {self.result!r} does not follow from exit_code "
                f"{int(self.exit_code)} ({RESULT[self.exit_code]!r})"
            )
        doctor = self.verb == "doctor"
        if doctor != (self.report.doctor_diff is not None):
            raise ValueError("report.doctor_diff is present exactly on doctor")
        failed = any(step.status == "failed" for step in self.steps)
        undone = bool(self.report.incomplete) or bool(self.report.doctor_diff)
        if failed and self.exit_code != ExitCode.FAILED:
            raise ValueError("a failed step makes the exit code 1")
        if self.exit_code == ExitCode.OK and undone:
            raise ValueError("exit code 0 with report.incomplete or doctor_diff")
        if self.exit_code == ExitCode.INCOMPLETE and not undone:
            raise ValueError(
                "exit code 2 needs report.incomplete or report.doctor_diff not empty"
            )
        if self.log_ref != f"journal/{self.run_id}.jsonl":
            raise ValueError(f"log_ref must be journal/{self.run_id}.jsonl")
        if self.started > self.finished:
            raise ValueError("started is after finished")
        return self


def _stamp(moment: datetime) -> str:
    return moment.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _step(phase: Phase, record: StepRecord) -> dict[str, Json]:
    raw: dict[str, Json] = {
        "stack": record.stack,
        "name": record.name,
        "phase": phase,
        "order": record.order,
        "status": record.status,
    }
    if record.reason is not None:
        raw["reason"] = record.reason.as_json()
    if record.started is not None:
        raw["started"] = _stamp(record.started)
    if record.duration_s is not None:
        raw["duration_s"] = record.duration_s
    if record.verify:
        raw["verify"] = dict(record.verify)
    return raw


def build_verdict(
    outcome: PlanOutcome,
    *,
    run_id: str,
    verb: str,
    args: Fact,
    actor: Mapping[str, str],
    started: datetime,
    finished: datetime,
    passport_version: int | None,
    composition_before: Mapping[str, str],
    composition_after: Mapping[str, str],
    secrets: Secrets,
    failures: Sequence[Fact] = (),
    dns: Sequence[Fact] | None = None,
    junit: Mapping[str, int] | None = None,
    catalog: Catalog = ENGLISH,
) -> Verdict:
    """The verdict of a plan, cleaned of ``secrets`` before it is validated.

    ``steps`` are the main ladder, then ``restore``, then ``finally``, in the
    order they ran, each with the phase of its tuple. A restore that is needed
    past the point of no return is an ``incomplete`` entry at code 1; an
    interrupted run is the failed step whose reason is ``interrupted``. A code
    without a text in ``catalog`` is refused (contract 2 rule 6).
    """
    keys = [
        catalog_key(record.reason.code)
        for record in (*outcome.steps, *outcome.restore, *outcome.finally_)
        if record.reason is not None
    ]
    keys += [catalog_key(item.reason.code, item.what) for item in outcome.incomplete]
    keys += [item.reason.code for item in outcome.doctor_diff]
    for item in outcome.doctor_diff:
        if {"stack", "name"} & set(item.reason.params):
            raise ValueError(f"{item.reason.code}: stack and name are a doctor entry's")
    absent = missing(catalog, keys)
    if absent:
        raise ValueError(f"no text in the catalog for codes {absent} (rule 6)")
    incomplete: list[Json] = [item.as_json() for item in outcome.incomplete]
    if outcome.needs_restore:
        incomplete.append({"what": "restore", "code": "needed"})
    report: dict[str, Json] = {
        "failures": [dict(item) for item in failures],
        "incomplete": incomplete,
    }
    if outcome.mode == "doctor":
        report["doctor_diff"] = [
            {"stack": item.stack, "name": item.name, **item.reason.as_json()}
            for item in outcome.doctor_diff
        ]
    if dns is None:  # the dns key of any step's fact, whatever the step is called
        found = [
            entry
            for record in (*outcome.steps, *outcome.restore, *outcome.finally_)
            for entry in (record.verify.get("dns") or [])  # type: ignore[union-attr]
            if isinstance(record.verify.get("dns"), list)
        ]
        dns = [entry for entry in found if isinstance(entry, dict)] or None
    if dns is not None:
        report["dns"] = [dict(item) for item in dns]
    raw: dict[str, Json] = {
        "schema": 1,
        "run_id": run_id,
        "verb": verb,
        "args": dict(args),
        "actor": dict(actor),
        "started": _stamp(started),
        "finished": _stamp(finished),
        "exit_code": int(outcome.code),
        "result": RESULT[outcome.code],
        **({} if passport_version is None else {"passport_version": passport_version}),
        "composition_before": dict(composition_before),
        "composition_after": dict(composition_after),
        "steps": [
            *(_step("main", record) for record in outcome.steps),
            *(_step("restore", record) for record in outcome.restore),
            *(_step("finally", record) for record in outcome.finally_),
        ],
        "report": report,
        "log_ref": f"journal/{run_id}.jsonl",
    }
    if junit is not None:
        raw["junit"] = dict(junit)
    return Verdict.model_validate_json(json.dumps(secrets.value(raw)))


VERDICT_SCHEMA = "verdict.v1.json"


def rendered_schema() -> str:
    """The JSON Schema text of the verdict, exported from the model."""
    return schema_text(
        TypeAdapter(Verdict).json_schema(
            mode="validation", schema_generator=ContractSchema
        ),
        "verdict v1",
    )


def main(argv: Sequence[str]) -> int:
    """``--export`` writes the verdict schema to ``contract/schema/``."""
    parser = argparse.ArgumentParser(prog="python -m pridem.report.schema")
    parser.add_argument("--export", action="store_true", required=True)
    parser.parse_args(argv)
    SCHEMA_DIR.mkdir(parents=True, exist_ok=True)
    target = SCHEMA_DIR / VERDICT_SCHEMA
    target.write_text(rendered_schema(), encoding="utf-8")
    print(f"wrote {target}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
