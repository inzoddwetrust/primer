"""Probes DM-4: the verdict of contract 2 v1.2 -- model, rules, renders, schema.

Every probe has its pair: the refused form is refused for the rule's own
message, and the accepted form is accepted and not empty, so a probe cannot
pass on a model that refuses everything or on an empty run.
"""

import io
import json

import pytest
from plan_support import Journal, ScriptedStep, plan
from pydantic import SecretStr, ValidationError
from report_support import MARKER, build, example, items, load, section

from pridem.contract import SCHEMA_DIR
from pridem.events import (
    Code,
    ConsoleSink,
    DoctorItem,
    Incomplete,
    Json,
    PlanOutcome,
    Secrets,
    StepRecord,
)
from pridem.plan import StackSteps
from pridem.report.catalog import ENGLISH, with_steps
from pridem.report.codes import ExitCode
from pridem.report.render import render_json, render_llm, render_report, summary_line
from pridem.report.schema import VERDICT_SCHEMA, Verdict, rendered_schema
from pridem.runner import FakeCall, FakeRunner, Stream
from pridem.steps.base import CheckResult, StepContext, local_code

VISIBLE = "visible-0b5d"


def _refused(data: dict[str, Json], message: str) -> None:
    with pytest.raises(ValidationError, match=message):
        load(data)


def _step(data: dict[str, Json], index: int) -> dict[str, Json]:
    step = items(data, "steps")[index]
    assert isinstance(step, dict)
    return step


CATALOG = with_steps(ENGLISH, ((name, ScriptedStep.codes) for name in ("ssl", "env")))
"""DM-42: the words of the scripted steps' codes."""


def _renders(verdict: Verdict, secrets: Secrets) -> dict[str, str]:
    return {
        "dump": verdict.model_dump_json(),
        "summary": summary_line(verdict),
        "json": render_json(verdict),
        "report": render_report(verdict, None, secrets, CATALOG),
        "llm": render_llm(verdict, None, secrets, CATALOG),
    }


def test_probe_DM_4_verdict_requires_composition() -> None:
    for key in ("composition_before", "composition_after"):
        data = example()
        del data[key]
        _refused(data, f"{key}\n  Field required")
        data = example()
        del section(data, key)["pridem"]
        _refused(data, "always names the pridem version")
    verdict = load(example())
    assert verdict.composition_before["pridem"] == "0.3.1"
    assert len(verdict.composition_after) == 4


def test_probe_DM_4_verdict_code2_requires_incomplete() -> None:
    """Code 2 needs ``incomplete`` or ``doctor_diff``; neither -- refused.

    DM-42 (contract 2 v1.6): reasons, incomplete and doctor entries are codes
    with parameters, not phrases; this probe's data changed form only, each
    assertion keeps its strength.
    """
    run, _ = plan(
        [StackSteps("comms", [ScriptedStep("env", 3, Journal())], root=True)],
        "doctor",
    )
    outcome = run.run()
    assert outcome.code is ExitCode.INCOMPLETE and outcome.incomplete == ()
    verdict = build(outcome, verb="doctor", args={})
    assert verdict.exit_code is ExitCode.INCOMPLETE and verdict.report.incomplete == []
    assert [d.model_dump() for d in verdict.report.doctor_diff or []] == [
        {"stack": "comms", "name": "env", "code": "env:do", "step": "env"}
    ]

    neither = example()
    neither["exit_code"], neither["result"] = 2, "incomplete"
    _refused(neither, "exit code 2 needs report.incomplete or report.doctor_diff")
    section(neither, "report")["incomplete"] = [{"what": "ssl", "code": "ssl:left"}]
    assert load(neither).result == "incomplete"


def test_probe_DM_4_verdict_skipped_requires_reason() -> None:
    """A ``skipped`` or ``failed`` step needs a reason.

    DM-42 (contract 2 v1.6): reasons, incomplete and doctor entries are codes
    with parameters, not phrases; this probe's data changed form only, each
    assertion keeps its strength.
    """
    data = example()
    del _step(data, 2)["reason"]
    _refused(data, "a skipped step needs a reason")
    data = example()
    _step(data, 1).update(status="failed")
    del _step(data, 1)["verify"]
    data["exit_code"], data["result"] = 1, "red"
    _refused(data, "a failed step needs a reason")
    _step(data, 1)["reason"] = {"code": "health:status", "status": 502}
    failed = load(data).steps[1].reason
    assert failed is not None
    assert failed.model_dump() == {"code": "health:status", "status": 502}
    skipped = load(example()).steps[2].reason
    assert skipped is not None
    assert skipped.model_dump() == {"code": "role", "role": "prod"}


def test_probe_DM_4_verdict_step_requires_verify_fact() -> None:
    data = example()
    del _step(data, 0)["verify"]
    _refused(data, "an ok step needs a verify fact")
    verdict = load(example())
    assert [s.verify for s in verdict.steps if s.status == "ok"] == [
        {"head": "9a1c4e2", "drift_discarded": []},
        {
            "image_id": "sha256:0f1e",
            "matches_fresh_build": True,
            "health": "ok",
            "ready": 200,
        },
    ]


def test_probe_DM_4_render_llm_excludes_green_and_secrets() -> None:
    """DM-42 (contract 2 v1.6): reasons and incomplete entries are codes with
    parameters, not phrases; the data changed form only, each assertion keeps
    its strength.
    """
    planted = f"tok={MARKER}"
    red = PlanOutcome(
        mode="deploy",
        code=ExitCode.FAILED,
        steps=(
            StepRecord(
                "comms", "up", 10, "ok", None, None, 2.0, {"health": "ok", "v": VISIBLE}
            ),
            StepRecord(
                "aivis",
                "up",
                12,
                "failed",
                Code("command-failed", {"argv": ["make", planted], "exit_code": 2}),
                None,
                None,
                {"seen": {"nested": [planted]}, planted: 1},
            ),
        ),
        incomplete=(Incomplete("ssl", Code("ssl:left", {"thing": planted})),),
    )
    failure: dict[str, Json] = {
        "test": "t",
        "file": "f.py",
        "line": 1,
        "message": planted,
        "traceback_project_frames": [planted],
        "request_ids": [],
    }
    deploy = build(red, args={"ref": "9a1c4e2", "token": planted}, failures=(failure,))
    drift = PlanOutcome(
        "doctor",
        ExitCode.INCOMPLETE,
        (),
        doctor_diff=(DoctorItem("a", "env", Code("env:do", {"step": planted})),),
    )
    doctor = build(drift, verb="doctor", args={})
    secrets = Secrets([SecretStr(MARKER)])
    for verdict in (deploy, doctor):
        for name, text in _renders(verdict, secrets).items():
            assert MARKER not in text, name
            # the doctor summary line carries no planted field to show cleaned
            assert "[redacted]" in text or (verdict, name) == (doctor, "summary"), name

    llm = render_llm(deploy, None, secrets, CATALOG)
    assert "| aivis | up | 12 | failed |" in llm
    assert "| comms | up |" not in llm and VISIBLE not in llm
    assert VISIBLE in render_report(deploy, None, secrets, CATALOG)
    assert VISIBLE in deploy.model_dump_json()


def test_probe_DM_4_schema_export_matches_model() -> None:
    on_disk = (SCHEMA_DIR / VERDICT_SCHEMA).read_text(encoding="utf-8")
    assert rendered_schema() == on_disk, (
        f"{VERDICT_SCHEMA} differs from the model; "
        "regenerate: python -m pridem.report.schema --export"
    )
    schema = json.loads(on_disk)
    assert schema["title"] == "verdict v1"
    assert {"Step", "Report", "Failure", "DnsCheck"} <= set(schema["$defs"])
    assert "schema" in schema["required"] and "composition_before" in schema["required"]


def test_probe_DM_4_console_and_reason_carry_no_secret() -> None:
    """Output of a failed command stays out of the reason; console is cleaned.

    ``OUTPUT`` is not a known secret: only the reason's form keeps it out.
    ``MARKER`` is known: it sits in the command line and in a ``verify`` fact.

    DM-42 (contract 2 v1.6): reasons, incomplete and doctor entries are codes
    with parameters, not phrases; this probe's data changed form only, each
    assertion keeps its strength.
    """
    output = "leaked-output-4f2a"

    class Up(ScriptedStep):
        def check(self, ctx: StepContext) -> CheckResult:
            return CheckResult(True, local_code("do", {"step": "up"}))

    runner = FakeRunner(
        FakeCall(
            ("make", "deploy", f"TOKEN={MARKER}"),
            code=2,
            lines=(
                (Stream.STDERR, f"{output} line 1"),
                (Stream.STDOUT, f"{output} line 2"),
            ),
        )
    )
    seen = ScriptedStep("seen", 1, Journal(), fact={"key": MARKER, "v": VISIBLE})
    up = Up("up", 2, Journal(), act_argv=["make", "deploy", f"TOKEN={MARKER}"])
    with runner:
        run, sink = plan([StackSteps("aivis", [seen, up], root=True)], runner=runner)
        outcome = run.run()
    reason = outcome.steps[1].reason
    assert reason is not None and output not in str(reason.as_json())
    assert reason == Code(
        "command-failed",
        {"argv": ["make", "deploy", f"TOKEN={MARKER}"], "exit_code": 2},
    )
    assert [line.line for line in sink.lines()] == [
        f"{output} line 1",
        f"{output} line 2",
    ]

    secrets = Secrets([SecretStr(MARKER)])
    verdict = build(outcome, secrets=secrets)
    for name, text in _renders(verdict, secrets).items():
        assert output not in text and MARKER not in text, name
    assert '["make","deploy","TOKEN=[redacted]"]' in verdict.model_dump_json()

    out = io.StringIO()
    console = ConsoleSink(out, secrets)
    for event in sink.events:
        console.emit(event)
    printed = out.getvalue()
    assert MARKER not in printed and output not in printed
    assert VISIBLE in printed and "TOKEN=[redacted] — exit code 2" in printed
