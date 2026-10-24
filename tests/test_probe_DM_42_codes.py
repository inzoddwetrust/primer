"""Probes DM-42: the verdict keeps codes and parameters, the words come from a
catalog (contract 2 v1.6).

The scenarios below make the machine write every code it can write today --
every reason, every incomplete entry but ``journal/quarantined`` (its writer is
the CLI, DM-16), a step's own codes and a doctor entry -- through the plan, the
builder and the box's recovery, never by hand. Each entry of each verdict must
be exactly a listed code with exactly its parameters, or a step's code; the pair
renders each entry into words. The second probe swaps the catalog and finds the
report, ``--llm`` and the console speak it while the data stays the same.
"""

import ast
import errno
import io
import re
from datetime import UTC, datetime
from itertools import count
from pathlib import Path
from string import Formatter

import pytest
from plan_support import NOW, Journal, ListSink, ScriptedStep, plan
from pydantic import BaseModel, SecretStr, ValidationError
from report_support import build, example, items, load, section
from state_support import header, run_id, state

from pridem.events import (
    Code,
    ConsoleSink,
    DoctorItem,
    Event,
    Incomplete,
    Json,
    PlanOutcome,
    Secrets,
    StepFinished,
    StepRecord,
    StepStarted,
    role_skip,
)
from pridem.plan import Plan, StackSteps
from pridem.report.catalog import ENGLISH, Catalog, Value, text, with_steps
from pridem.report.codes import (
    INCOMPLETE_CODES,
    REASON_CODES,
    STEP_CODE,
    ExitCode,
    catalog_key,
)
from pridem.report.render import render_llm, render_report, words
from pridem.report.schema import INCOMPLETE_MODELS, REASON_MODELS, Verdict
from pridem.runner import CommandNotStarted, FakeCall, FakeRunner
from pridem.stacks import passport, schema
from pridem.state import Box
from pridem.steps.base import StepFailed, local_code

REPO = Path(__file__).resolve().parents[1]
NO_SECRETS = Secrets(())
NAMES = (
    "tests",
    "migrate",
    "build",
    "up",
    "gc",
    "timers",
    "wait",
    "x",
    "probe",
    "ssl",
    "env",
    "a",
    "b",
    "c",
)
CATALOG = with_steps(ENGLISH, ((name, ScriptedStep.codes) for name in NAMES))
NOT_WRITTEN_HERE = {"journal/quarantined"}  # written by the CLI (DM-16)


class _InterruptOnce(ListSink):
    """A sink interrupted while it writes the first finished step."""

    def __init__(self) -> None:
        super().__init__()
        self.fired = False

    def emit(self, event: Event) -> None:
        super().emit(event)
        if isinstance(event, StepFinished) and not self.fired:
            self.fired = True
            raise KeyboardInterrupt


def _root(*steps: ScriptedStep) -> list[StackSteps]:
    return [StackSteps("aivis", list(steps), root=True)]


def _plan_verdicts() -> list[Verdict]:
    out: list[PlanOutcome] = []
    journal = Journal()

    runner = FakeRunner(FakeCall(("make", "build"), code=1))
    with runner:
        run, _ = plan(
            _root(
                ScriptedStep("tests", 1, journal, roles=frozenset({"test"})),
                ScriptedStep("migrate", 2, journal, point_of_no_return=True),
                ScriptedStep("build", 3, journal, act_argv=["make", "build"]),
                ScriptedStep("up", 4, journal),
            ),
            role="prod",
            runner=runner,
            finally_=[
                StackSteps(
                    "aivis",
                    [
                        ScriptedStep("gc", 1, journal, check_raises=RuntimeError("x")),
                        ScriptedStep(
                            "timers",
                            2,
                            journal,
                            verify_raises=StepFailed("wrong-state", {"seen": "y"}),
                        ),
                    ],
                )
            ],
        )
        out.append(run.run())

    runner = FakeRunner(FakeCall(("make", "wait"), outcome="timeout"))
    with runner:
        step = ScriptedStep("wait", 1, journal, act_argv=["make", "wait"])
        out.append(plan(_root(step), runner=runner)[0].run())

    missing = CommandNotStarted(("x",), "No such file or directory")
    missing.__cause__ = FileNotFoundError(errno.ENOENT, "No such file or directory")
    out.append(plan(_root(ScriptedStep("x", 1, journal, act_raises=missing)))[0].run())

    runner = FakeRunner(FakeCall(("b",), outcome="not_started"))
    with runner:
        step = ScriptedStep("b", 1, journal, act_argv=["b"])
        out.append(plan(_root(step), runner=runner)[0].run())

    out.append(plan(_root(ScriptedStep("probe", 1, journal, fact={})))[0].run())
    left = local_code("left", {"thing": "certificate"})
    out.append(plan(_root(ScriptedStep("ssl", 1, journal, incomplete=left)))[0].run())

    cut, _ = plan(
        _root(
            ScriptedStep("a", 1, journal, act_raises=KeyboardInterrupt()),
            ScriptedStep("c", 2, journal),
        )
    )
    with pytest.raises(KeyboardInterrupt):
        cut.run()
    assert cut.outcome is not None
    out.append(cut.outcome)

    ticks = count()
    between = Plan(
        _root(ScriptedStep("a", 1, journal), ScriptedStep("c", 2, journal)),
        mode="deploy",
        role="test",
        runner=FakeRunner(),
        sink=_InterruptOnce(),
        clock=lambda: float(next(ticks)),
        now=lambda: NOW,
    )
    with pytest.raises(KeyboardInterrupt):
        between.run()
    assert between.outcome is not None
    out.append(between.outcome)

    verdicts = [build(outcome, catalog=CATALOG) for outcome in out]
    doctor, _ = plan(_root(ScriptedStep("env", 1, journal)), "doctor")
    verdicts.append(build(doctor.run(), verb="doctor", args={}, catalog=CATALOG))
    return verdicts


def _recovered_verdicts(root: Path) -> list[Verdict]:
    box = Box(root)
    with box.lock("dying"):
        box.write_state(state())
        box.open_journal(header(run_id(1)), NO_SECRETS).close()
        sink = box.open_journal(header(run_id(2)), NO_SECRETS)
        at = datetime(2026, 10, 15, 10, 43, tzinfo=UTC)
        skipped = StepRecord("aivis", "tests", 1, "skipped", role_skip("prod"))
        sink.emit(StepFinished("main", skipped))
        sink.emit(StepStarted("main", "aivis", "up", 2, at))
        sink.close()
        damaged = box.open_journal(header(run_id(3)), NO_SECRETS)
        damaged.emit(StepStarted("main", "aivis", "up", 2, at))
        damaged.close()
    path = root / "journal" / f"{run_id(3)}.jsonl"
    path.write_text(path.read_text() + "{oops\n")
    (root / "state.json").write_bytes(b"{")
    with box.lock("next"):
        return list(box.recover(NO_SECRETS, "0.3.1", CATALOG).verdicts)


def _entries(verdict: Verdict) -> list[tuple[str, BaseModel]]:
    out: list[tuple[str, BaseModel]] = [
        ("reason", step.reason) for step in verdict.steps if step.reason is not None
    ]
    out += [("incomplete", item) for item in verdict.report.incomplete]
    out += [("doctor", item) for item in verdict.report.doctor_diff or []]
    return out


def test_probe_DM_42_verdict_carries_no_prose(tmp_path: Path) -> None:
    verdicts = [*_plan_verdicts(), *_recovered_verdicts(tmp_path)]
    seen: set[str] = set()
    for verdict in verdicts:
        for kind, item in _entries(verdict):
            data = item.model_dump()
            code = str(data["code"])
            if kind == "reason" and code in REASON_CODES:
                assert set(data) == {"code", *REASON_CODES[code]}, data
                seen.add(code)
            elif kind == "incomplete" and f"{data['what']}/{code}" in INCOMPLETE_CODES:
                key = f"{data['what']}/{code}"
                assert set(data) == {"what", "code", *INCOMPLETE_CODES[key]}, data
                seen.add(key)
            else:
                assert re.fullmatch(STEP_CODE, code), data
                seen.add("step:" + kind)
            # the pair: every entry has words, and they are not the code
            said = words(CATALOG, item)
            assert said.strip() and "{" not in said, (code, said)
    # the journal keeps a reason as the same object: the skip read back as written
    (second,) = [v for v in verdicts if v.run_id == run_id(2)]
    assert [s.reason.model_dump() for s in second.steps if s.reason] == [
        {"code": "role", "role": "prod"}
    ]
    assert second.report.incomplete[0].model_dump() == {
        "what": "run",
        "code": "no-verdict",
        "ended_at": {"phase": "main", "stack": "aivis", "name": "up"},
    }
    machine = set(REASON_CODES) | set(INCOMPLETE_CODES)
    assert seen >= machine - NOT_WRITTEN_HERE, sorted(machine - seen)
    assert {"step:reason", "step:incomplete", "step:doctor"} <= seen
    errnos = {
        step.reason.model_dump()["errno"]
        for verdict in verdicts
        for step in verdict.steps
        if step.reason is not None and step.reason.code == "command-not-started"
    }
    assert errnos == {"ENOENT", None}


def test_probe_DM_42_render_text_comes_from_catalog(tmp_path: Path) -> None:
    swapped: Catalog = {key: f"§{key}§ {template}" for key, template in CATALOG.items()}
    verdicts = [*_plan_verdicts(), *_recovered_verdicts(tmp_path)]
    for verdict in verdicts:
        data = verdict.model_dump_json()
        english = render_report(verdict, None, NO_SECRETS, CATALOG)
        other = render_report(verdict, None, NO_SECRETS, swapped)
        llm = render_llm(verdict, None, NO_SECRETS, swapped)
        assert "§" not in english
        for kind, item in _entries(verdict):
            dump = item.model_dump()
            what = dump.get("what") if kind == "incomplete" else None
            mark = f"§{catalog_key(str(dump['code']), what)}§"
            assert mark in other, (kind, mark)
            assert words(swapped, item) in other
            if kind != "reason":
                assert mark in llm
        assert verdict.model_dump_json() == data  # the data does not follow
    out = io.StringIO()
    run, sink = plan(_root(ScriptedStep("probe", 1, Journal(), fact={})))
    run.run()
    console = ConsoleSink(out, NO_SECRETS, swapped)
    for event in sink.events:
        console.emit(event)
    assert "§no-fact§ verify returned no fact" in out.getvalue()


def test_every_machine_code_has_a_text_for_every_parameter() -> None:
    samples: dict[str, Value] = {
        "role": "prod",
        "phase": "main",
        "stack": "aivis",
        "name": "up",
        "argv": ["make", "up"],
        "exit_code": 1,
        "timeout_s": 5.0,
        "errno": None,
        "type": "OSError",
        "ended_at": None,
        "line": 3,
        "run_id": run_id(1),
    }
    for key, params in {**REASON_CODES, **INCOMPLETE_CODES}.items():
        fields = {f for _, f, _, _ in Formatter().parse(ENGLISH[key]) if f}
        assert fields <= set(params), key
        what, _, code = key.rpartition("/")
        said = text(ENGLISH, code, {p: samples[p] for p in params}, what or None)
        assert said and "{" not in said, key
    nowhere = text(ENGLISH, "no-verdict", {"ended_at": None}, "run")
    assert nowhere.endswith("the start")
    at: dict[str, Value] = {"phase": "main", "stack": "aivis", "name": "up"}
    assert "main aivis · up" in text(ENGLISH, "no-verdict", {"ended_at": at}, "run")
    assert "make up" in text(
        ENGLISH, "command-failed", {"argv": ["make", "up"], "exit_code": 1}
    )


def test_models_and_lists_name_the_same_parameters() -> None:
    for code, params in REASON_CODES.items():
        assert set(REASON_MODELS[code].model_fields) == {"code", *params}, code
    for key, params in INCOMPLETE_CODES.items():
        fields = set(INCOMPLETE_MODELS[key].model_fields)
        assert fields == {"what", "code", *params}, key


def _step(data: dict[str, Json], index: int) -> dict[str, Json]:
    step = items(data, "steps")[index]
    assert isinstance(step, dict)
    return step


@pytest.mark.parametrize(
    "reason",
    [
        {"code": "bogus"},
        {"code": "role"},
        {"code": "role", "role": "prod", "extra": 1},
        {"code": "interrupted", "role": "prod"},
        {"code": "command-not-started", "argv": ["x"], "errno": "no such file"},
        {"code": "after-failure", "stack": "aivis", "name": "up"},
        {"code": "ssl:deferred", "what": "x"},
        {"code": "ssl:deferred", "seen": {"nested": 1}},
        {"code": "role", "role": None},
        "role prod",
    ],
)
def test_model_refuses_a_reason_outside_the_contract(reason: Json) -> None:
    data = example()
    _step(data, 2)["reason"] = reason
    with pytest.raises(ValidationError):
        load(data)


def test_model_keeps_a_removed_step_code_and_the_nulls() -> None:
    data = example()
    _step(data, 2)["reason"] = {"code": "gone:old", "n": 1, "l": ["a"]}
    data["exit_code"], data["result"] = 1, "red"
    section(data, "report")["incomplete"] = [
        {"what": "run", "code": "no-verdict", "ended_at": None}
    ]
    verdict = load(data)
    assert verdict.steps[2].reason is not None
    assert verdict.steps[2].reason.model_dump() == {
        "code": "gone:old",
        "n": 1,
        "l": ["a"],
    }
    assert '"ended_at":null' in verdict.model_dump_json()


def test_build_refuses_a_code_without_text() -> None:
    outcome = PlanOutcome(
        "deploy",
        ExitCode.FAILED,
        (StepRecord("aivis", "up", 1, "failed", Code("up:unknown")),),
    )
    with pytest.raises(ValueError, match="no text in the catalog"):
        build(outcome, catalog=ENGLISH)
    drift = PlanOutcome(
        "doctor",
        ExitCode.INCOMPLETE,
        (),
        doctor_diff=(DoctorItem("a", "env", Code("env:do", {"stack": "x"})),),
    )
    with pytest.raises(ValueError, match="doctor entry"):
        build(drift, verb="doctor", args={}, catalog=CATALOG)
    with pytest.raises(ValueError, match="taken"):
        Incomplete("ssl", Code("ssl:left", {"what": "x"}))


def test_llm_counts_skips_by_code(tmp_path: Path) -> None:
    verdicts = _plan_verdicts()
    for verdict in verdicts:
        skipped = [
            s
            for s in verdict.steps
            if s.reason is not None
            and s.reason.code in ("after-failure", "after-interrupt")
        ]
        if skipped:
            llm = render_llm(verdict, None, NO_SECRETS, CATALOG)
            assert f"{len(skipped)} steps skipped after the failure." in llm
    codes = {s.reason.code for v in verdicts for s in v.steps if s.reason is not None}
    assert {"after-failure", "after-interrupt"} <= codes


def test_secret_in_argv_is_cleaned_everywhere() -> None:
    marker = "argv-secret-value-6f3a"
    secrets = Secrets([SecretStr(marker)])
    runner = FakeRunner(FakeCall(("make", f"T={marker}"), code=1))
    with runner:
        step = ScriptedStep("up", 1, Journal(), act_argv=["make", f"T={marker}"])
        run, sink = plan(_root(step), runner=runner)
        outcome = run.run()
    verdict = build(outcome, secrets=secrets, catalog=CATALOG)
    out = io.StringIO()
    console = ConsoleSink(out, secrets, run.catalog)
    for event in sink.events:
        console.emit(event)
    for said in (
        verdict.model_dump_json(),
        render_report(verdict, None, secrets, CATALOG),
        out.getvalue(),
    ):
        assert marker not in said and "[redacted]" in said


def test_rules_tables_are_the_one_source_of_rule_texts() -> None:
    """Every ``R<n>.<name>``/``S.<name>`` used in a loader is in its table, and
    every entry of a table is used (DM-42, work 4)."""

    def used(files: list[str]) -> set[str]:
        found: set[str] = set()
        for file in files:
            tree = ast.parse((REPO / file).read_text())
            table: set[int] = set()
            for node in ast.walk(tree):
                if isinstance(node, ast.Assign) and any(
                    isinstance(t, ast.Name) and t.id == "RULES" for t in node.targets
                ):
                    table |= {id(n) for n in ast.walk(node)}
            for node in ast.walk(tree):
                if (
                    id(node) not in table
                    and isinstance(node, ast.Constant)
                    and isinstance(node.value, str)
                    and re.fullmatch(r"(R\d+|S)\.[a-z0-9-]+", node.value)
                ):
                    found.add(node.value)
        return found

    stacks = [
        "pridem/stacks/schema.py",
        "pridem/stacks/lock.py",
        "pridem/stacks/stack.py",
    ]
    for table, files in (
        (schema.RULES, stacks),
        (passport.RULES, ["pridem/stacks/passport.py"]),
    ):
        codes = used(files)
        assert codes and codes == set(table)
