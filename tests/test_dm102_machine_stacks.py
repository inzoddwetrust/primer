"""DM-102 (R3-N1 of review 0003): every stack of the machine is
``pridem-<name>`` -- of every plan of every verb, of the journal, of the
docker objects it labels -- named in one module; a product may take any other
name; a fact's key ``(stack, step)`` is one, even of stacks built late."""

import ast
import io
from collections.abc import Sequence
from datetime import UTC, datetime
from itertools import count
from pathlib import Path

import pytest
from plan_support import ListSink

from pridem.events import Json, Secrets
from pridem.plan import Deferred, Plan, StackSteps
from pridem.report.codes import ExitCode
from pridem.runner import FakeRunner
from pridem.stacks import names as machine
from pridem.stacks.schema import PRIMER_YAML, RESERVED_NAMES, rule_problems
from pridem.steps.base import CheckResult, Step, StepContext, Verified

PRIDEM = Path(__file__).resolve().parent.parent / "pridem"


# --- one source of the names --------------------------------------------------------


def _positions(tree: ast.AST) -> list[ast.expr]:
    """The expressions that name a stack: the first argument of
    ``StackSteps``, ``Deferred``, ``StepRecord``, ``StepStarted``,
    ``one_stack``, the second of ``LogLine``, a keyword ``stack``."""
    found: list[ast.expr] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        name = func.id if isinstance(func, ast.Name) else getattr(func, "attr", "")
        if name in ("StackSteps", "Deferred", "StepRecord", "StepStarted", "one_stack"):
            found += node.args[:1]
        if name == "LogLine":
            found += node.args[1:2]
        found += [kw.value for kw in node.keywords if kw.arg == "stack"]
    return found


def test_no_stack_of_the_machine_is_named_outside_its_module() -> None:
    """In ``pridem/``, outside ``stacks/names.py``, no string literal stands
    where a stack is named: a stack of the machine comes from the module, a
    product's from its ``primer.yaml`` (a variable). The pair: the module
    itself names every one, each with the prefix."""
    literal: list[str] = []
    for path in sorted(PRIDEM.rglob("*.py")):
        if path.name == "names.py" and path.parent.name == "stacks":
            continue
        for node in _positions(ast.parse(path.read_text(encoding="utf-8"))):
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                literal.append(
                    f"{path.relative_to(PRIDEM)}:{node.lineno} {node.value!r}"
                )
    assert literal == []
    assert machine.MACHINE_STACKS and all(
        name.startswith(machine.MACHINE_PREFIX) for name in machine.MACHINE_STACKS
    )


# --- every plan of every verb -------------------------------------------------------


def test_every_stack_of_a_deploy_plan_is_the_machine_s(tmp_path: Path) -> None:
    """``install``, ``reinstall``, ``deploy`` with a rollback, ``doctor``:
    every stack and every stack of ``finally`` -- declared or deferred -- is
    ``pridem-<name>`` (the product's entries come once the deferred ones are
    built, under the product's names)."""
    from pridem.state import Box
    from pridem.steps.passport import Fetched
    from pridem.verbs.plans import Source, Wanted, deploy_plan
    from pridem.verbs.run import Session

    box = Box(tmp_path / "opt" / "pridem")
    for mode, back in (
        ("install", False), ("reinstall", False), ("deploy", True), ("doctor", False),
    ):  # fmt: skip
        wanted = Wanted(mode=mode, source=Source(file=tmp_path / "x"), rollback=back)
        planned = deploy_plan(
            Session(box, "r1", Fetched(), Secrets(())), tmp_path, wanted, None
        )
        names = [stack.name for stack in [*planned.stacks, *planned.finally_]]
        assert names and all(n.startswith(machine.MACHINE_PREFIX) for n in names), (
            mode,
            names,
        )


VERDICT_VERBS = [  # status reports with no step: no stack to name
    "gc", "ssl", "install", "update", "deploy", "reinstall", "doctor",
    "destroy", "rollback", "db", "backup", "seed", "verb", "start", "stop", "restart",
]  # fmt: skip


@pytest.mark.parametrize("name", VERDICT_VERBS)
def test_every_stack_of_a_verdict_is_an_entry_or_the_machine_s(
    tmp_path: Path, name: str
) -> None:
    """Every verb with a verdict, on a box that runs the blank, its commands
    refused (the probe of DM-54's way): every stack of its verdict is the
    blank's entry or ``pridem-<name>``; the pair -- the blank's entry has no
    prefix and is there whenever an entry's step is."""
    from data_support import blank_box
    from history_support import NEW, OLD, release_box, released, run_of
    from passport_support import passport_example, section, write_passport
    from test_probe_DM_54_recover import ARGV, PASSPORT, ROLLBACK, Refusing

    from pridem.cli import run
    from pridem.report.schema import Verdict

    root = tmp_path / "opt" / "pridem"
    data = passport_example()
    section(data, "server")["role"] = "test"
    file = write_passport(tmp_path, data)
    argv = [str(file) if word == PASSPORT else word for word in ARGV[name]]
    seeded: set[str] = set()
    if name == "verb":
        from test_verbs_project import _box

        _box(tmp_path)
    elif name in ROLLBACK:
        release_box(tmp_path, "prod", NEW, released(1, OLD), released(2, NEW))
        seeded = {run_of(1), run_of(2)}
    else:
        blank_box(tmp_path)
    out, err = io.StringIO(), io.StringIO()
    run(argv, root=root, out=out, err=err, runner=Refusing(), fs_root=tmp_path)
    [verdict] = [
        Verdict.model_validate_json(path.read_text())
        for path in (root / "history").iterdir()
        if path.stem not in seeded
    ]
    entries = {"blank", "aivis"}
    stacks = {step.stack for step in verdict.steps}
    assert stacks
    strangers = {s for s in stacks if s not in entries and not s.startswith("pridem-")}
    assert strangers == set(), sorted(stacks)
    assert not any(e.startswith("pridem-") for e in entries)


# --- what a product may name --------------------------------------------------------


def _product(**entries: Json) -> dict[str, Json]:
    return {
        "schema": 1,
        "name": "aivis",
        "kind": "product",
        "stacks": {
            "aivis": {
                "compose": "docker-compose.yml",
                "app": {"service": "app", "port": 8000, "health": "/h", "ready": "/r"},
            },
            **entries,
        },
        "env": {},
        "report": {"health": "/h", "ready": "/r", "logs": "json", "junit": True},
    }


def _codes(raw: dict[str, Json]) -> list[str]:
    return [p.code for p in rule_problems(PRIMER_YAML.validate_python(raw))]


@pytest.mark.parametrize("entry", ["frontend", "backup", "edge", "services", "host"])
def test_a_product_takes_the_plain_words_again(entry: str) -> None:
    """``RESERVED_NAMES`` holds the machine's own names and ``product``; an
    entry ``frontend`` or ``edge`` is the product's (the pair: ``pridem-x``
    is refused)."""
    assert RESERVED_NAMES == frozenset({"pridem", "product"})
    other: Json = {"compose": "o.yml"}
    assert "S.name-reserved" not in _codes(_product(**{entry: other}))
    assert "S.name-reserved" in _codes(_product(**{"pridem-x": other}))


# --- the labels of the machine's objects -------------------------------------------


def test_the_machine_s_objects_carry_its_prefix_and_destroy_reads_them() -> None:
    from pridem.steps import edge, egress, host
    from pridem.steps.destroy import MACHINE_ENTRIES

    assert host.STACK_LABEL == {"pridem.stack": "pridem-host"}
    assert edge.STACK_LABEL == {"pridem.stack": "pridem-edge"}
    assert egress.STACK_LABEL == {"pridem.stack": "pridem-egress"}
    assert egress.LABEL_FILTER == "label=pridem.stack=pridem-egress"
    assert MACHINE_ENTRIES == {"pridem-host", "pridem-edge", "pridem-egress"}


# --- a fact's key, of stacks built late --------------------------------------------


class _Fact(Step):
    order = 1
    modes = frozenset({"install"})

    def __init__(self, name: str) -> None:
        self.name = name

    def check(self, ctx: StepContext) -> CheckResult:
        return CheckResult(False, None, {})

    def act(self, ctx: StepContext, check: CheckResult) -> None:
        raise AssertionError

    def verify(self, ctx: StepContext, check: CheckResult) -> Verified:
        return Verified({"step": self.name})


def _plan(*deferred: tuple[str, str, Sequence[str]]) -> Plan:
    """A real ``Plan`` with a root step and deferred stacks, each building
    ``stack`` with the steps named."""
    ticks = count()
    root = StackSteps(machine.FINALIZE, [_Fact("root")], root=True)

    def builder(stack: str, steps: Sequence[str]):  # type: ignore[no-untyped-def]
        return lambda: [StackSteps(stack, [_Fact(s) for s in steps])]

    stacks = [
        Deferred(name, builder(stack, steps), after="root")
        for name, stack, steps in deferred
    ]
    return Plan(
        [*stacks, root],
        mode="install",
        role="test",
        runner=FakeRunner(),
        sink=ListSink(),
        clock=lambda: float(next(ticks)),
        now=lambda: datetime(2026, 11, 14, tzinfo=UTC),
    )


def test_two_stacks_built_late_share_a_stack_but_not_a_fact_s_key() -> None:
    """The pair (the services and the product both build ``pridem-seams``):
    ``seams_check`` and ``seams_verify`` in one stack -- green, both facts.
    Red: two deferred stacks build one step in one stack -- the second is a
    red ``ladder``, ``two steps named …`` (DM-102: the key is ``(stack,
    step)``, not the stack's name)."""
    seams = machine.SEAMS
    green = _plan(
        (machine.SERVICES, seams, ["seams_check"]),
        (machine.PRODUCT, seams, ["seams_verify"]),
    ).run()
    assert green.code is ExitCode.OK, green.steps
    keys = {(s.stack, s.name) for s in green.steps}
    assert {(seams, "seams_check"), (seams, "seams_verify")} <= keys
    red = _plan(
        (machine.SERVICES, seams, ["seams_check"]),
        (machine.PRODUCT, seams, ["seams_check"]),
    ).run()
    failed = [s for s in red.steps if s.reason is not None]
    assert red.code is not ExitCode.OK and failed
    assert failed[0].stack == machine.PRODUCT and failed[0].name == "ladder"
