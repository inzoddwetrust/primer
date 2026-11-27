"""Probe of DM-209: ``pridem check`` refuses a ``test.services`` that names
no service of the stack's compose -- by the rule, the code and the text the
step ``tests`` refuses by on a box.

The repository is the blank's of ``test_probe_DM_57_check.py`` and its strict
``FakeRunner``: ``check`` makes no command it did not make before (the
services are those of the ``config`` it already read). The step of a box is
given the same compose and must say the same.
"""

import json
from pathlib import Path

import pytest
import yaml
from compose_support import in_release, stdout
from env_support import context
from test_probe_DM_57_check import (
    BLANK,
    RAW,
    _reason,
    _steps,
    check,
    config_call,
    green_calls,
    repo,
    version_call,
)

from pridem.events import Json, Secrets
from pridem.report.catalog import ENGLISH, with_steps
from pridem.runner import FakeCall, FakeRunner
from pridem.stacks.schema import load_primer_yaml
from pridem.steps import tests as tests_step
from pridem.steps.base import StepFailed
from pridem.steps.compose import ComposeStack, refusal
from pridem.steps.tests import (
    TEST_SERVICE_UNKNOWN,
    TestReport,
    Tests,
    unknown_services,
)
from pridem.verbs.check import CODES

SHA = "a" * 40
TEXT = "test.services of {stack} names {services}, not services of its compose"


def _named(root: Path, services: list[str] | None) -> None:
    """``stacks.blank.test.services`` of the repository: ``services``, or no
    key."""
    path = root / "primer.yaml"
    data = yaml.safe_load(path.read_text())
    test = data["stacks"]["blank"]["test"]
    test.pop("services", None)
    if services is not None:
        test["services"] = services
    path.write_text(yaml.safe_dump(data, sort_keys=False))


HEALTH: dict[str, Json] = {"test": ["CMD", "redis-cli", "ping"]}


def _with_service(
    document: dict[str, Json], name: str, profiles: list[str] | None = None
) -> dict[str, Json]:
    """``document`` with a service ``name`` that the machine's lists take --
    an image and a healthcheck -- and, given, its ``profiles``."""
    changed = json.loads(json.dumps(document))
    body: dict[str, Json] = {"image": "redis:7", "healthcheck": HEALTH}
    if profiles is not None:
        body["profiles"] = list[Json](profiles)
    changed["services"][name] = body
    assert isinstance(changed, dict)
    return changed


def _params(reason: dict[str, Json]) -> dict[str, Json]:
    """The parameters of a reason of the verdict: beside its code."""
    return {key: value for key, value in reason.items() if key != "code"}


def _on_a_box(root: Path, document: dict[str, Json]) -> StepFailed | None:
    """The step ``tests`` of a box on the repository's ``primer.yaml`` and
    the compose ``document``, up to its refusals before any command of the
    database: what it refuses by, or ``None``."""
    stack = load_primer_yaml(root / "primer.yaml")
    box = root.parent / "box"
    step = Tests(
        stack,
        "blank",
        release=box / "r",
        ref="main",
        commit=SHA,
        report=TestReport(),
        secrets=Secrets(()),
        root=box,
    )
    compose = ComposeStack(stack, "blank", box / "r", "main", SHA, box, staged=True)
    config = FakeCall(
        tuple(compose.product_argv("config", "--format", "json")),
        lines=stdout(json.dumps(document)),
    )
    with FakeRunner(config) as runner:
        try:
            step._database(context(runner))
        except StepFailed as refused:
            return refused
    return None


def test_probe_DM_209_check_refuses_a_test_service_the_compose_does_not_have(
    tmp_path: Path,
) -> None:
    """``test.services: [nope]`` -- the measure of the line meet on v0.1.10,
    where ``check`` was green: exit 1, the step ``tests`` of the stack red by
    ``tests:test-service-unknown`` with the stack and the name, the steps
    before it green. The step of a box, given the same file and the same
    compose, refuses by the same code with the same parameters, and the text
    of the catalog is one. The pair: ``[postgres]``, a service of that
    compose -- exit 0, the step green and naming it; the box refuses
    nothing."""
    root = repo(tmp_path)
    _named(root, ["nope"])
    code, verdict, _ = check(root, green_calls(root))
    assert code == 1 and verdict["result"] == "red"
    steps = _steps(verdict)
    assert list(steps) == [
        "blank/primer_yaml",
        "blank/primer_lock",
        "blank/compose",
        "blank/packages",
        "blank/tests",
    ]
    assert [step["status"] for step in steps.values()] == ["ok"] * 4 + ["failed"]
    assert steps["blank/tests"]["order"] == 5
    reason = _reason(verdict, "blank/tests")
    assert reason["code"] == "tests:test-service-unknown"
    assert _params(reason) == {"stack": "blank", "services": ["nope"]}
    # the same on a box: one rule
    on_box = _on_a_box(root, BLANK)
    assert on_box is not None
    assert on_box.reason.code == "test-service-unknown"
    assert dict(on_box.reason.params) == _params(reason)
    # one text of the catalog, written out here
    assert TEST_SERVICE_UNKNOWN == TEXT == Tests.codes["test-service-unknown"]
    assert CODES["tests"] == {"test-service-unknown": TEXT}
    catalog = with_steps(ENGLISH, CODES.items())
    assert catalog["tests:test-service-unknown"] == TEXT
    # the pair
    _named(root, ["postgres"])
    code, verdict, _ = check(root, green_calls(root))
    assert code == 0 and verdict["result"] == "green"
    assert _steps(verdict)["blank/tests"]["status"] == "ok"
    assert _steps(verdict)["blank/tests"]["verify"] == {"services": ["postgres"]}
    assert _on_a_box(root, BLANK) is None


def test_a_service_behind_a_profile_is_refused_before_the_rule_alike(
    tmp_path: Path,
) -> None:
    """``cache`` behind ``profiles: [cache]``, named in ``test.services``.
    ``profiles`` is no key the machine's lists allow: ``check`` is red at
    ``compose`` by ``compose-forbidden`` with the finding ``cache:
    profiles``, and its step ``tests`` is skipped -- the rule never sees such
    a service. On a box ``build`` refuses it first, by the same function
    (``refusal``) and the same finding. The pair: the same service with no
    profile -- ``compose`` green, the rule takes it, ``tests`` green."""
    root = repo(tmp_path)
    _named(root, ["cache"])
    raw, document = (_with_service(d, "cache", ["cache"]) for d in (RAW, BLANK))
    code, verdict, _ = check(root, green_calls(root, raw, document))
    assert code == 1
    found = _reason(verdict, "blank/compose")
    assert found["code"] == "compose:compose-forbidden"
    assert found["found"] == ["cache: profiles"]
    assert _steps(verdict)["blank/tests"]["status"] == "skipped"
    # build on a box: the same function, the same finding -- given the
    # documents as config gives them in that release
    stack = load_primer_yaml(root / "primer.yaml")
    compose = ComposeStack(stack, "blank", root, "check", "", root)
    raw, document = in_release(raw, root), in_release(document, root)
    refused = refusal(compose, document, raw, [])
    assert refused == (
        "compose-forbidden",
        {"stack": "blank", "found": ["cache: profiles"]},
    )
    # the pair
    raw, document = (_with_service(d, "cache") for d in (RAW, BLANK))
    code, verdict, _ = check(root, green_calls(root, raw, document))
    assert code == 0, _steps(verdict)
    assert _steps(verdict)["blank/tests"]["verify"] == {"services": ["cache"]}
    assert _on_a_box(root, document) is None
    raw, document = in_release(raw, root), in_release(document, root)
    assert refusal(compose, document, raw, []) is None


def test_check_and_the_box_ask_one_function(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """One truth: with the rule's function answering "none unknown", neither
    ``check`` nor the step of a box refuses ``[nope]`` -- neither keeps a
    comparison of its own beside it."""
    root = repo(tmp_path)
    _named(root, ["nope"])
    assert check(root, green_calls(root))[0] == 1
    assert _on_a_box(root, BLANK) is not None
    monkeypatch.setattr(tests_step, "unknown_services", lambda names, document: [])
    code, verdict, _ = check(root, green_calls(root))
    assert code == 0 and _steps(verdict)["blank/tests"]["status"] == "ok"
    assert _on_a_box(root, BLANK) is None


def test_a_stack_that_names_no_service_has_no_step_of_tests(tmp_path: Path) -> None:
    """Twin EMPTINESS: ``test`` without ``services`` -- the verdict of
    ``check`` is the four steps it was. ``services: []`` is the loader's: red
    at ``primer_yaml`` (the list's own form, ``too_short``), the step
    ``tests`` never there."""
    root = repo(tmp_path)
    code, verdict, _ = check(root, green_calls(root))
    assert code == 0
    assert list(_steps(verdict)) == [
        "blank/primer_yaml",
        "blank/primer_lock",
        "blank/compose",
        "blank/packages",
    ]
    _named(root, [])
    code, verdict, _ = check(root, [])
    assert code == 1
    reason = _reason(verdict, "blank/primer_yaml")
    assert reason["code"] == "primer_yaml:invalid"
    assert reason["problems"] == [
        "stacks.blank.test.services: [too_short] "
        "List should have at least 1 item after validation, not 0"
    ]
    assert "blank/tests" not in _steps(verdict)


def test_every_unknown_name_is_said_in_the_order_written(tmp_path: Path) -> None:
    root = repo(tmp_path)
    _named(root, ["zeta", "postgres", "alpha", "queue"])
    code, verdict, _ = check(root, green_calls(root))
    assert code == 1
    assert _params(_reason(verdict, "blank/tests")) == {
        "stack": "blank",
        "services": ["zeta", "alpha", "queue"],
    }


def test_a_compose_that_did_not_pass_leaves_the_tests_unchecked(tmp_path: Path) -> None:
    """The services of a compose ``check`` refused, or could not read, are
    not known: the step is skipped, not green and not red by a name. No
    compose here at all -- skipped by that reason, exit 2 as it was."""
    root = repo(tmp_path)
    _named(root, ["nope"])
    # refused: a key the machine's lists do not have
    forbidden = json.loads(json.dumps(BLANK))
    forbidden["services"]["app"]["privileged"] = True
    code, verdict, _ = check(root, green_calls(root, RAW, forbidden))
    assert code == 1
    assert _steps(verdict)["blank/compose"]["status"] == "failed"
    skipped = _steps(verdict)["blank/tests"]
    assert skipped["status"] == "skipped"
    # unread: config fails
    failing = [version_call(), config_call(root, RAW, raw=True, code=1)]
    code, verdict, _ = check(root, failing)
    assert code == 1
    assert _steps(verdict)["blank/compose"]["status"] == "failed"
    assert _steps(verdict)["blank/tests"]["status"] == "skipped"
    # no compose binary
    missing = FakeCall(("docker", "compose", "version"), outcome="not_started")
    code, verdict, _ = check(root, [missing])
    assert code == 2
    skipped = _steps(verdict)["blank/tests"]
    assert skipped["status"] == "skipped"
    reason = skipped["reason"]
    assert isinstance(reason, dict) and reason["code"] == "compose:not-found"


def test_a_name_is_a_service_of_its_own_stack_s_compose(tmp_path: Path) -> None:
    """A product of two entries, each with its compose: ``cache`` is a
    service of the second entry's file. Named in ``test.services`` of the
    first, it is unknown there -- a test container sees the network of its
    own stack. The second entry names no service and has no step."""
    root = repo(tmp_path)
    path = root / "primer.yaml"
    data = yaml.safe_load(path.read_text())
    data["stacks"]["blank"]["test"]["services"] = ["cache"]
    data["stacks"]["blank-cache"] = {"compose": "cache-compose.yml"}
    path.write_text(yaml.safe_dump(data, sort_keys=False))
    second: dict[str, Json] = {
        "name": "blank-cache",
        "services": {
            "cache": {
                "image": "redis:7",
                "healthcheck": {"test": ["CMD", "redis-cli", "ping"]},
            }
        },
    }
    (root / "cache-compose.yml").write_text(yaml.safe_dump(second))

    def second_call(raw: bool) -> FakeCall:
        argv = ["docker", "compose", "-p", "blank-cache"]
        argv += ["-f", str(root / "cache-compose.yml"), "--profile", "*"]
        argv += ["config", "--format", "json", *(["--no-interpolate"] if raw else [])]
        made = config_call(root, second, raw=raw)
        return FakeCall(tuple(argv), lines=made.lines, env=made.env)

    calls = [*green_calls(root), second_call(True), second_call(False)]
    code, verdict, _ = check(root, calls)
    steps = _steps(verdict)
    assert steps["blank-cache/compose"]["status"] == "ok", steps["blank-cache/compose"]
    assert code == 1
    assert _params(_reason(verdict, "blank/tests")) == {
        "stack": "blank",
        "services": ["cache"],
    }
    assert "blank-cache/tests" not in steps


@pytest.mark.parametrize(
    ("document", "unknown"),
    [
        ({"services": {"a": {}, "b": {}}}, []),
        ({"services": {"a": {}}}, ["b"]),
        ({"services": {"a": None, "b": "text"}}, []),
        ({"services": {}}, ["a", "b"]),
        ({"services": ["a", "b"]}, ["a", "b"]),
        ({"services": None}, ["a", "b"]),
        ({}, ["a", "b"]),
    ],
)
def test_a_name_is_known_when_the_document_has_the_service(
    document: dict[str, Json], unknown: list[str]
) -> None:
    """Twins EMPTINESS and SHORTAGE of the document: no services, services
    that are not an object -- every name unknown, none taken."""
    assert unknown_services(["a", "b"], document) == unknown
