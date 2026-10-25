"""The verdict model, its builder and secret cleaning (DM-4, contract 2 v1.2)."""

import ast
import json
from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import Path

import pytest
from plan_support import Journal, ScriptedStep, plan, red
from pydantic import SecretStr, ValidationError
from report_support import (
    MARKER,
    RUN_ID,
    build,
    example,
    items,
    load,
    section,
)

from pridem.contract import SCHEMA_DIR
from pridem.events import Code, Incomplete, Json, PlanOutcome, Secrets, StepRecord
from pridem.plan import StackSteps
from pridem.report.codes import ExitCode
from pridem.runner import FakeCall, FakeRunner, Stream
from pridem.steps.base import CheckResult, StepContext

X = Code("exception", {"type": "OSError"})

REPO = Path(__file__).resolve().parents[1]
AT = datetime(2026, 10, 15, 10, 45, tzinfo=UTC)


def _errors(data: Mapping[str, Json]) -> str:
    with pytest.raises(ValidationError) as error:
        load(data)
    return str(error.value)


def _get(node: Json, key: str | int) -> Json:
    if isinstance(node, list) and isinstance(key, int):
        return node[key]
    assert isinstance(node, dict) and isinstance(key, str)
    return node[key]


def _ok(stack: str, name: str, order: int) -> StepRecord:
    return StepRecord(stack, name, order, "ok", None, AT, 1.0, {"done": name})


# --- the contract's example ---------------------------------------------------


def test_contract_example_loads_and_dumps_back_unchanged() -> None:
    data = example()
    verdict = load(data)
    assert verdict.result == "green" and len(verdict.steps) == 3
    assert json.loads(verdict.model_dump_json()) == data


def test_null_is_refused_in_every_model() -> None:
    """``null`` is never written; a key with nothing to say is absent."""
    paths: list[list[str | int]] = [
        ["junit"],
        ["actor", "on_behalf_of"],
        ["steps", 2, "started"],
        ["report", "doctor_diff"],
        ["report", "dns"],
        ["report", "failures"],
    ]
    for path in paths:
        data = example()
        node: Json = data
        for segment in path[:-1]:
            node = _get(node, segment)
        assert isinstance(node, dict) and isinstance(path[-1], str)
        node[path[-1]] = None
        assert "explicit null is not allowed" in _errors(data), path


def test_null_inside_a_fact_is_a_value_not_a_missing_key() -> None:
    data = example()
    step = items(data, "steps")[0]
    assert isinstance(step, dict)
    section(step, "verify")["drift_discarded"] = None
    assert load(data).steps[0].verify == {"head": "9a1c4e2", "drift_discarded": None}


@pytest.mark.parametrize("value", [True, False, "0", 0.0, 3])
def test_exit_code_takes_only_0_1_2(value: Json) -> None:
    data = example()
    data["exit_code"] = value
    assert "exit_code" in _errors(data)


def test_exit_code_bool_refused_in_python_mode_too() -> None:
    raw = load(example()).model_dump(mode="python", by_alias=True)
    raw["exit_code"] = False
    with pytest.raises(ValidationError, match="not bool"):
        type(load(example())).model_validate(raw)
    raw["exit_code"] = 0
    assert type(load(example())).model_validate(raw).exit_code is ExitCode.OK


def test_result_follows_from_exit_code() -> None:
    data = example()
    data["result"] = "red"
    assert "does not follow from exit_code 0" in _errors(data)


# --- code against content -----------------------------------------------------


def test_failed_step_makes_code_1() -> None:
    data = example()
    items(data, "steps").append(
        {
            "stack": "aivis",
            "name": "gc",
            "phase": "finally",
            "order": 20,
            "status": "failed",
            "reason": {"code": "exception", "type": "OSError"},
        }
    )
    assert "a failed step makes the exit code 1" in _errors(data)
    data["exit_code"], data["result"] = 1, "red"
    assert load(data).exit_code is ExitCode.FAILED


def test_code_0_with_incomplete_is_refused() -> None:
    data = example()
    section(data, "report")["incomplete"] = [{"what": "ssl", "code": "ssl:deferred"}]
    assert "exit code 0 with report.incomplete" in _errors(data)


def test_code_1_without_failed_step_is_rule_4() -> None:
    data = example()
    data["exit_code"], data["result"] = 1, "red"
    section(data, "report")["incomplete"] = [
        {"what": "run", "code": "no-verdict", "ended_at": None}
    ]
    assert load(data).result == "red"


# --- doctor_diff, dns, actor, log_ref, time, junit, steps -----------------------


def test_doctor_diff_exactly_on_doctor() -> None:
    data = example()
    section(data, "report")["doctor_diff"] = []
    assert "present exactly on doctor" in _errors(data)
    data = example()
    data["verb"], data["args"] = "doctor", {}
    assert "present exactly on doctor" in _errors(data)
    section(data, "report")["doctor_diff"] = []
    assert load(data).report.doctor_diff == []


def test_dns_is_a_closed_list() -> None:
    data = example()
    entry: dict[str, Json] = {
        "domain": "api.x.dev",
        "resolves_to": ["203.0.113.7"],
        "expected": "203.0.113.7",
    }
    section(data, "report")["dns"] = [dict(entry)]
    assert load(data).report.dns is not None
    section(data, "report")["dns"] = [{**entry, "ttl": 300}]
    assert "ttl" in _errors(data)


def test_on_behalf_of_exactly_for_llm_actors() -> None:
    data = example()
    data["actor"] = {"type": "executor", "via": "panel"}
    assert "on_behalf_of" in _errors(data)
    data["actor"] = {"type": "executor", "via": "panel", "on_behalf_of": "owner"}
    assert load(data).actor.on_behalf_of == "owner"
    data["actor"] = {"type": "owner", "via": "local", "on_behalf_of": "owner"}
    assert "on_behalf_of" in _errors(data)


def test_log_ref_and_run_id_follow_contract() -> None:
    data = example()
    data["log_ref"] = "journal/other.jsonl"
    assert f"journal/{RUN_ID}.jsonl" in _errors(data)
    data = example()
    data["run_id"] = "run-1"
    assert "run_id" in _errors(data)


def test_started_not_after_finished_and_aware() -> None:
    data = example()
    data["finished"] = "2026-10-15T10:00:00Z"
    assert "started is after finished" in _errors(data)
    data = example()
    data["started"] = "2026-10-15T10:42:07"
    assert "timezone" in _errors(data)


def test_junit_counts_within_total() -> None:
    data = example()
    data["junit"] = {"total": 2, "failed": 2, "skipped": 1}
    assert "exceed total" in _errors(data)


def test_empty_verify_is_absent_not_empty() -> None:
    data = example()
    step = items(data, "steps")[2]
    assert isinstance(step, dict)
    step["verify"] = {}
    assert "omit the key" in _errors(data)


def test_composition_entries_are_one_word() -> None:
    data = example()
    section(data, "composition_after")["aivis"] = "9a1c 4e2"
    assert "must be one word" in _errors(data)


# --- the builder ----------------------------------------------------------------


def test_restore_and_finally_follow_main_steps_in_run_order() -> None:
    outcome = PlanOutcome(
        mode="deploy",
        code=ExitCode.FAILED,
        steps=(_ok("aivis", "build", 1), StepRecord("aivis", "up", 2, "failed", X)),
        restore=(_ok("aivis", "up_old", 2),),
        finally_=(_ok("aivis", "gc", 2),),
    )
    verdict = build(outcome)
    assert [s.name for s in verdict.steps] == ["build", "up", "up_old", "gc"]
    assert [s.order for s in verdict.steps] == [1, 2, 2, 2]


def test_needs_restore_is_incomplete_at_code_1() -> None:
    outcome = PlanOutcome(
        mode="deploy",
        code=ExitCode.FAILED,
        steps=(StepRecord("aivis", "migrate", 5, "failed", X),),
        incomplete=(Incomplete("ssl", Code("ssl:left", {"thing": "x"})),),
        needs_restore=True,
    )
    verdict = build(outcome)
    assert [i.model_dump() for i in verdict.report.incomplete] == [
        {"what": "ssl", "code": "ssl:left", "thing": "x"},
        {"what": "restore", "code": "needed"},
    ]
    assert verdict.exit_code is ExitCode.FAILED


def test_records_map_to_steps_without_loss() -> None:
    record = StepRecord("aivis", "up", 10, "ok", None, AT, 18.5, {"a": [1, None]})
    skipped = StepRecord(
        "aivis", "tests", 11, "skipped", Code("role", {"role": "prod"})
    )
    outcome = PlanOutcome(mode="deploy", code=ExitCode.OK, steps=(record, skipped))
    up, tests = build(outcome).steps
    assert (up.stack, up.name, up.order, up.status) == ("aivis", "up", 10, "ok")
    assert (up.started, up.duration_s, up.verify) == (AT, 18.5, {"a": [1, None]})
    assert tests.reason is not None and tests.verify is None
    assert tests.reason.model_dump() == {"code": "role", "role": "prod"}
    assert tests.started is None and tests.duration_s is None


def test_doctor_without_drift_has_empty_diff_and_code_0() -> None:
    run, _ = plan(
        [StackSteps("aivis", [ScriptedStep("up", 1, Journal(), needed=False)], True)],
        "doctor",
    )
    verdict = build(run.run(), verb="doctor", args={})
    assert verdict.report.doctor_diff == [] and verdict.exit_code is ExitCode.OK
    assert verdict.steps == []


def test_builder_refuses_a_mode_that_disagrees_with_the_verb() -> None:
    run, _ = plan([StackSteps("aivis", [ScriptedStep("up", 1, Journal())], True)])
    with pytest.raises(ValidationError, match="present exactly on doctor"):
        build(run.run(), verb="doctor", args={})


# --- reason of a step a command let down (plan.py) ---------------------------------


def test_timed_out_command_reason_has_no_output() -> None:
    runner = FakeRunner(
        FakeCall(("make", "up"), lines=((Stream.STDERR, "TOKEN=x"),), outcome="timeout")
    )
    with runner:
        step = ScriptedStep("up", 1, Journal(), act_argv=["make", "up"])
        outcome = plan([StackSteps("aivis", [step], True)], runner=runner)[0].run()
    assert outcome.steps[0].reason == Code(
        "command-timed-out", {"argv": ["make", "up"], "timeout_s": 10.0}
    )


def test_doctor_check_command_failure_reason_has_no_output() -> None:
    class Probe(ScriptedStep):
        def check(self, ctx: StepContext) -> CheckResult:
            ctx.runner.run(["dpkg", "-s", "nginx"], timeout=5.0, on_line=ctx.on_line)
            raise AssertionError("the runner raises before this line")

    runner = FakeRunner(
        FakeCall(("dpkg", "-s", "nginx"), code=1, lines=((Stream.STDOUT, "nope"),))
    )
    with runner:
        outcome = plan(
            [StackSteps("host", [Probe("nginx", 1, Journal())], True)],
            "doctor",
            runner=runner,
        )[0].run()
    assert outcome.steps[0].reason == Code(
        "command-failed", {"argv": ["dpkg", "-s", "nginx"], "exit_code": 1}
    )


# --- secrets --------------------------------------------------------------------


def test_secrets_longest_first_keys_included_empty_refused() -> None:
    secrets = Secrets([SecretStr("abc"), SecretStr("abcdef"), SecretStr("abc")])
    assert secrets.text("x abcdef y abc") == "x [redacted] y [redacted]"
    assert secrets.fact({"k-abc": ["abcdef", 1, None]}) == {
        "k-[redacted]": ["[redacted]", 1, None]
    }
    with pytest.raises(ValueError, match="empty secret"):
        Secrets([SecretStr("")])
    with pytest.raises(ValueError, match="after cleaning"):
        secrets.fact({"abc": 1, "abcdef": 2})


def test_validation_error_never_quotes_a_secret() -> None:
    """Cleaning runs before validation: a refused verdict cannot echo a secret."""
    outcome = PlanOutcome(
        mode="deploy",
        code=ExitCode.OK,
        steps=(StepRecord("aivis", "up", 1, "ok", None, AT, 1.0, {"x": MARKER}),),
    )
    with pytest.raises(ValidationError) as error:
        build(outcome, verb=f"Bad {MARKER}")
    assert MARKER not in str(error.value) and "[redacted]" in str(error.value)


# --- one strictness base, schema titles -------------------------------------------


def test_strict_is_defined_once() -> None:
    owners = [
        str(path.relative_to(REPO))
        for path in sorted((REPO / "pridem").rglob("*.py"))
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8")))
        if isinstance(node, ast.ClassDef) and node.name == "Strict"
    ]
    assert owners == ["pridem/contract.py"]


def test_every_schema_file_is_titled_contract_v1() -> None:
    """DM-10 added ``primer-package.yaml``, the file a data package declares."""
    titles = {
        path.name: json.loads(path.read_text(encoding="utf-8"))["title"]
        for path in sorted(SCHEMA_DIR.glob("*.json"))
    }
    assert titles == {
        "passport.v1.json": "passport v1",
        "primer-package.v1.json": "primer-package.yaml v1",
        "primer-lock.v1.json": "primer.lock v1",
        "primer-yaml.v1.json": "primer.yaml v1",
        "verdict.v1.json": "verdict v1",
    }


def test_red_scripted_step_reason_survives_the_builder() -> None:
    run, _ = plan([StackSteps("aivis", [red("up", 1, Journal())], True)])
    verdict = build(run.run())
    assert verdict.steps[0].reason is not None
    assert verdict.steps[0].reason.model_dump() == {
        "code": "up:wrong-state",
        "seen": "x",
    }
    assert verdict.steps[0].verify == {"seen": "x"}
