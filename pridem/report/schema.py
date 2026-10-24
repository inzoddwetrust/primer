"""Contract 2: the verdict -- models, contract rules, builder, JSON Schema.

A verdict ends every command. The models are strict and closed on the one base
``Strict``: a key with nothing to say is absent, never ``null``, and every
optional field is left out of the dump when it is ``None``. Rules checked here:

- rule 1: both compositions are present and each has ``pridem``;
- ``result`` follows from ``exit_code`` (``ExitCode`` of ``report/codes.py``,
  ``True``/``False`` rejected in every mode, JSON included);
- a ``skipped`` or ``failed`` step has a ``reason``; an ``ok`` step has a
  non-empty ``verify`` fact; ``verify``, when present, is not empty;
- the code agrees with the content: a failed step means 1; 0 means no failed
  step, no ``incomplete`` and no ``doctor_diff`` entry; 2 means no failed step
  and ``incomplete`` or ``doctor_diff`` not empty; 1 without a failed step is
  allowed (rule 4: a run that ended without a verdict is recorded red);
- ``report.doctor_diff`` is present exactly on ``doctor``;
- ``log_ref`` is ``journal/<run_id>.jsonl``; ``started <= finished``;
  ``actor.on_behalf_of`` is present exactly for ``dispatcher`` and ``executor``.

Rule 2 (no secrets) is kept by ``build_verdict``: every string of the raw
verdict, keys included, is cleaned of known secrets before validation, so not
even a validation error can quote one. Rule 3 (a role skip is ``skipped``, not
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
from typing import Annotated, Literal, Self

from pydantic import (
    AfterValidator,
    AwareDatetime,
    BeforeValidator,
    ConfigDict,
    Field,
    TypeAdapter,
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
from pridem.report.codes import ExitCode

Result = Literal["green", "red", "incomplete"]
RESULT: Mapping[ExitCode, Result] = {
    ExitCode.OK: "green",
    ExitCode.FAILED: "red",
    ExitCode.INCOMPLETE: "incomplete",
}
NEEDS_RESTORE = "past the point of no return: restore from backup is needed"
RUN_ID = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z-[0-9a-f]{4}")

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


class Step(Strict):
    stack: Text
    name: Text
    phase: Literal["main", "restore", "finally"]
    order: int
    status: Literal["ok", "failed", "skipped"]
    reason: Text | None = Field(default=None, exclude_if=_is_none)
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


class Incomplete(Strict):
    what: Text
    why: Text


class DoctorDiff(Strict):
    stack: Text
    name: Text
    what: Text


class DnsCheck(Strict):
    domain: Text
    resolves_to: list[Text]
    expected: Text


class Report(Strict):
    failures: list[Failure]
    incomplete: list[Incomplete]
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
    run_id: Annotated[str, Field(pattern=RUN_ID.pattern)]
    verb: Annotated[str, Field(pattern=r"^[a-z][a-z0-9-]*( [a-z][a-z0-9-]*)*$")]
    args: dict[str, Json]
    actor: Actor
    started: Moment
    finished: Moment
    exit_code: Annotated[ExitCode, BeforeValidator(_exit_code)]
    result: Result
    passport_version: Annotated[int, Field(ge=1)]
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
        raw["reason"] = record.reason
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
    passport_version: int,
    composition_before: Mapping[str, str],
    composition_after: Mapping[str, str],
    secrets: Secrets,
    failures: Sequence[Fact] = (),
    dns: Sequence[Fact] | None = None,
    junit: Mapping[str, int] | None = None,
) -> Verdict:
    """The verdict of a plan, cleaned of ``secrets`` before it is validated.

    ``steps`` are the main ladder, then ``restore``, then ``finally``, in the
    order they ran, each with the phase of its tuple. A restore that is needed
    past the point of no return is an ``incomplete`` entry at code 1; an
    interrupted run is the failed step whose reason says ``interrupted``.
    """
    incomplete: list[Json] = [
        {"what": item.what, "why": item.why} for item in outcome.incomplete
    ]
    if outcome.needs_restore:
        incomplete.append({"what": "restore", "why": NEEDS_RESTORE})
    report: dict[str, Json] = {
        "failures": [dict(item) for item in failures],
        "incomplete": incomplete,
    }
    if outcome.mode == "doctor":
        report["doctor_diff"] = [
            {"stack": item.stack, "name": item.name, "what": item.what}
            for item in outcome.doctor_diff
        ]
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
        "passport_version": passport_version,
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
