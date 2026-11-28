"""Probes of DM-220: every name and port of ``primer.yaml`` that points at the
compose of its own entry is checked by one function in ``pridem check`` and
on a box -- ``app``, ``frontend``, the points, the secret files, ``host.ports``
both ways -- and ``check`` says what the box says of the junit and of the
routes. One probe per field closed, each with its pair.

The repository is the blank's of ``test_probe_DM_57_check.py`` and its strict
``FakeRunner``; the box's ``build`` is the blank's of ``compose_support``.
"""

import json
from pathlib import Path

import pytest
import yaml
from compose_support import (
    SHA,
    config_call,
    executable_calls,
    in_release,
    raw_config_call,
    stdout,
)
from env_support import run
from test_probe_DM_55_compose import BLANK as BOX_BLANK
from test_probe_DM_55_compose import build, comms, released
from test_probe_DM_57_check import (
    BLANK,
    ENV_KEYS,
    RAW,
    _reason,
    _steps,
    check,
    green_calls,
    repo,
    version_call,
)
from test_probe_DM_57_check import config_call as check_config
from test_probe_DM_209_check import _on_a_box

from pridem.events import Code, Json
from pridem.runner import FakeCall, FakeRunner
from pridem.stacks.routes import targets
from pridem.stacks.schema import PRIMER_YAML, Product, load_primer_yaml
from pridem.steps import tests as tests_step
from pridem.steps.base import StepFailed
from pridem.steps.build import Build
from pridem.steps.compose import ComposeStack, forbidden, host_ports, refusal
from pridem.steps.tests import refuse_junit

HEALTH: dict[str, Json] = {"test": ["CMD", "true"]}


def _without(document: dict[str, Json], name: str) -> dict[str, Json]:
    changed = json.loads(json.dumps(document))
    del changed["services"][name]
    assert isinstance(changed, dict)
    return changed


def _edit(root: Path, change: dict[str, object]) -> None:
    """Merge ``change`` into ``stacks.blank`` of the repository's primer.yaml
    (key ``env`` -- into the top-level ``env``; ``host`` -- the top-level)."""
    path = root / "primer.yaml"
    data = yaml.safe_load(path.read_text())
    for key, value in change.items():
        if key == "env":
            data["env"].update(value)
        elif key == "routes":
            data["host"]["routes"] = value
        else:
            data["stacks"]["blank"][key] = value
    path.write_text(yaml.safe_dump(data, sort_keys=False))


def _compose_of(root: Path) -> ComposeStack:
    stack = load_primer_yaml(root / "primer.yaml")
    return ComposeStack(stack, "blank", root, "check", "", root)


def _box_refuses(box_root: Path, document: dict[str, Json]) -> Code | None:
    """``build`` of the blank on a box, ``document`` as ``config`` prints it:
    what it refuses by, with nothing built."""
    cs = released(box_root)
    with FakeRunner(
        raw_config_call(cs, document),
        config_call(cs, document),
        *executable_calls(cs, document, document),
    ) as runner:
        outcome, _ = run([build(box_root)], runner)
    assert not cs.override.exists()
    return outcome.steps[0].reason


def test_probe_DM_220_app_service_unknown_is_refused_alike(tmp_path: Path) -> None:
    """The measure of meet on v0.1.12: ``app.service`` names no service of the
    compose -- ``check`` exit 1, ``compose`` red by ``compose-forbidden`` with
    ``app: no service app``; ``build`` on a box refuses by the same finding,
    nothing built (it was a ``command-failed`` of ``compose build``, the
    override naming a service with no image). The pair: the compose with it
    -- green in both."""
    root = repo(tmp_path / "repo")
    raw, document = (_without(d, "app") for d in (RAW, BLANK))
    code, verdict, _ = check(root, green_calls(root, raw, document))
    assert code == 1
    reason = _reason(verdict, "blank/compose")
    assert reason["code"] == "compose:compose-forbidden"
    assert "app: no service app" in reason["found"]  # type: ignore[operator]
    on_box = _box_refuses(tmp_path / "box", _without(BOX_BLANK, "app"))
    assert on_box is not None and on_box.code == "build:compose-forbidden"
    assert "app: no service app" in on_box.params["found"]  # type: ignore[operator]
    # the pair
    code, verdict, _ = check(root, green_calls(root))
    assert code == 0 and _steps(verdict)["blank/compose"]["status"] == "ok"
    cs = released(tmp_path / "box-pair")
    assert forbidden(cs, in_release(BOX_BLANK, cs.release)) == []


def test_probe_DM_220_frontend_service_unknown_is_refused_alike(
    tmp_path: Path,
) -> None:
    """``frontend.service`` names no service: ``check`` and ``build`` refuse by
    ``frontend: no service frontend``, the only finding. The pair: with it,
    no finding."""
    root = repo(tmp_path / "repo")
    raw, document = (_without(d, "frontend") for d in (RAW, BLANK))
    code, verdict, _ = check(root, green_calls(root, raw, document))
    assert code == 1
    assert _reason(verdict, "blank/compose")["found"] == [
        "frontend: no service frontend"
    ]
    on_box = _box_refuses(tmp_path / "box", _without(BOX_BLANK, "frontend"))
    assert on_box == Code(
        "build:compose-forbidden",
        {"stack": "blank", "found": ["frontend: no service frontend"]},
    )
    cs = released(tmp_path / "pair")
    assert forbidden(cs, in_release(BOX_BLANK, cs.release)) == []


def test_probe_DM_220_point_service_unknown_is_refused_alike(tmp_path: Path) -> None:
    """A point of the entry whose service the compose has not -- read
    nowhere before while the point had no consumer: ``check`` refuses by
    ``expose.events: no service cache``, and the function ``build`` refuses
    by (``refusal``) says the same. The pair: the compose with ``cache``."""
    root = repo(tmp_path)
    _edit(
        root,
        {"expose": {"events": {"service": "cache", "port": 6379, "scheme": "redis"}}},
    )
    code, verdict, _ = check(root, green_calls(root))
    assert code == 1
    assert _reason(verdict, "blank/compose")["found"] == [
        "expose.events: no service cache"
    ]
    cs = _compose_of(root)
    document = in_release(BLANK, root)
    assert refusal(cs, document, in_release(RAW, root)) == (
        "compose-forbidden",
        {"stack": "blank", "found": ["expose.events: no service cache"]},
    )
    # the pair
    raw, document = (json.loads(json.dumps(d)) for d in (RAW, BLANK))
    for one in (raw, document):
        one["services"]["cache"] = {"image": "redis:7", "healthcheck": HEALTH}
    code, verdict, _ = check(root, green_calls(root, raw, document))
    assert code == 0, _steps(verdict)


def test_probe_DM_220_secret_file_service_unknown_is_refused_alike(
    tmp_path: Path,
) -> None:
    """A secret file for a service the compose has not -- ``check`` did not
    look at all, a box only for a file of an option on that the passport
    gives: now every file the stack declares, with no passport, in ``check``
    and in ``build`` by one function -- ``secret_file: no service ghost``.
    The pair: the file for ``app`` -- no finding."""
    root = repo(tmp_path)
    file = {"source": "asked", "file": {"path": "/run/key", "services": ["ghost"]}}
    _edit(root, {"env": {"AGE_KEY": file}})
    keys = (*ENV_KEYS, "AGE_KEY")  # the stand-ins of check: every key of env
    calls = [
        version_call(),
        check_config(root, RAW, raw=True, keys=keys),
        check_config(root, BLANK, raw=False, keys=keys),
    ]
    code, verdict, _ = check(root, calls)
    assert code == 1
    assert _reason(verdict, "blank/compose")["found"] == [
        "secret_file: no service ghost"
    ]
    cs = _compose_of(root)
    assert forbidden(cs, in_release(BLANK, root)) == ["secret_file: no service ghost"]
    # the pair
    _edit(
        root,
        {
            "env": {
                "AGE_KEY": {**file, "file": {"path": "/run/key", "services": ["app"]}}
            }
        },
    )
    calls = [
        version_call(),
        check_config(root, RAW, raw=True, keys=keys),
        check_config(root, BLANK, raw=False, keys=keys),
    ]
    code, verdict, _ = check(root, calls)
    assert code == 0, _steps(verdict)


def test_probe_DM_220_host_ports_equal_both_ways(tmp_path: Path) -> None:
    """``host.ports`` and the published ports are equal sets (contract 3,
    additions 1.42): a port published and not declared -- ``ports=…`` of its
    service (as before); a port declared and published by no compose of the
    service's entries -- ``host.ports: <port>/<proto> not published``, one
    finding however many times it is written. ``check`` and ``build`` take
    the second side from one function (``host_ports``). The pair: equal --
    nothing."""
    udp = {"proto": "udp", "port": 10000}
    tcp = {"proto": "tcp", "port": 3478}
    cs = comms(tmp_path, [udp, tcp, tcp])
    published: dict[str, Json] = {
        "target": 10000,
        "published": "10000",
        "protocol": "udp",
    }
    body: dict[str, Json] = {"image": "comms:1", "healthcheck": HEALTH}
    document: dict[str, Json] = {
        "services": {"comms-app": {**body, "ports": [published]}}
    }
    assert host_ports(cs.stack, {"comms": document}) == [
        "host.ports: 3478/tcp not published"
    ]
    both: dict[str, Json] = {"target": 3478, "published": "3478", "protocol": "tcp"}
    equal: dict[str, Json] = {
        "services": {"comms-app": {**body, "ports": [published, both]}}
    }
    assert host_ports(cs.stack, {"comms": equal}) == []
    # a port in another entry's compose counts: the stack's, not one file's
    split: dict[str, Json] = {"services": {"turn": {**body, "ports": [both]}}}
    assert host_ports(cs.stack, {"comms": document, "turn": split}) == []
    # udp is not tcp
    wrong: dict[str, Json] = {"target": 3478, "published": "3478", "protocol": "udp"}
    other: dict[str, Json] = {
        "services": {"comms-app": {**body, "ports": [published, wrong]}}
    }
    assert host_ports(cs.stack, {"comms": other}) == [
        "host.ports: 3478/tcp not published"
    ]
    assert forbidden(cs, other) == ["comms-app: ports=3478/udp"]  # the other side


def test_probe_DM_220_junit_path_in_check(tmp_path: Path) -> None:
    """``report.junit`` on and ``test.run`` with no ``--junitxml=`` -- ``check``
    exit 1, ``tests:junit-path-unknown``, the step a box refuses by
    (``tests``, ``refuse_junit``) says the same code. The pair: the blank's
    run with ``--junitxml=`` -- green, its directory in the fact."""
    root = repo(tmp_path)
    _edit(root, {"test": {"run": "python -m pytest tests/", "target": "test"}})
    code, verdict, _ = check(root, green_calls(root))
    assert code == 1
    tests = _steps(verdict)["blank/tests"]
    assert (tests["status"], tests["order"]) == ("failed", 5)
    assert _reason(verdict, "blank/tests") == {"code": "tests:junit-path-unknown"}
    on_box = _on_a_box(root, BLANK)
    assert on_box is not None and on_box.reason == Code("junit-path-unknown")
    try:
        refuse_junit(True, "python -m pytest tests/")
    except StepFailed as refused:
        assert refused.reason == Code("junit-path-unknown")
    else:
        raise AssertionError("refuse_junit passed a run with no --junitxml=")
    # the pair
    root = repo(tmp_path / "pair")
    code, verdict, _ = check(root, green_calls(root))
    assert code == 0
    assert _steps(verdict)["blank/tests"]["verify"] == {"junit": "/tmp"}  # noqa: S108
    assert _on_a_box(root, BLANK) is None


def test_probe_DM_220_route_target_in_check(tmp_path: Path) -> None:
    """A route to a ``service:port`` that is no ``app`` or ``frontend`` of
    the product -- ``check`` exit 1, the step ``nginx`` (order 6) red by
    ``nginx:route-target-unknown {route, to}``: the function ``nginx`` refuses
    by on a box (``routes.targets``), the same code. Two entries with the same
    target -- ``nginx:route-ambiguous``. The pair: the blank's routes --
    green, each route and its target in the fact."""
    root = repo(tmp_path)
    _edit(
        root, {"routes": {"frontend": {"to": "frontend:80"}, "api": {"to": "app:9000"}}}
    )
    code, verdict, _ = check(root, green_calls(root))
    assert code == 1
    step = _steps(verdict)["blank/nginx"]
    assert (step["status"], step["order"]) == ("failed", 6)
    assert _reason(verdict, "blank/nginx") == {
        "code": "nginx:route-target-unknown",
        "route": "api",
        "to": "app:9000",
    }
    stack = load_primer_yaml(root / "primer.yaml")
    assert isinstance(stack, Product)
    try:
        targets(stack)
    except StepFailed as refused:
        assert refused.reason == Code(
            "route-target-unknown", {"route": "api", "to": "app:9000"}
        )
    else:
        raise AssertionError("targets passed a route to nothing")
    # two entries' app on the same service:port: no one target
    data = yaml.safe_load((root / "primer.yaml").read_text())
    data["host"]["routes"]["api"] = {"to": "app:8000"}
    data["stacks"]["blank-two"] = {
        "compose": "docker-compose.yml",
        "app": {"service": "app", "port": 8000, "health": "/health", "ready": "/ready"},
    }
    twice = PRIMER_YAML.validate_python(data)
    assert isinstance(twice, Product)
    try:
        targets(twice)
    except StepFailed as refused:
        assert refused.reason == Code(
            "route-ambiguous",
            {"route": "api", "to": "app:8000", "stacks": ["blank", "blank-two"]},
        )
    else:
        raise AssertionError("targets passed a route two entries declare")
    # the pair
    root = repo(tmp_path / "pair")
    code, verdict, _ = check(root, green_calls(root))
    assert code == 0
    assert _steps(verdict)["blank/nginx"]["verify"] == {
        "routes": {"api": "blank/app:8000", "frontend": "blank/frontend:80"}
    }


def test_a_secret_file_with_no_services_is_for_the_app(tmp_path: Path) -> None:
    """A secret file without ``services`` is the ``app``'s (contract 3,
    additions 1.39): a compose with no ``app`` names it twice -- the app's
    own finding and the file's."""
    root = repo(tmp_path)
    _edit(root, {"env": {"AGE_KEY": {"source": "asked", "file": {"path": "/run/k"}}}})
    cs = _compose_of(root)
    assert forbidden(cs, in_release(_without(BLANK, "app"), root)) == [
        "app: no service app",
        "secret_file: no service app",
    ]
    assert forbidden(cs, in_release(BLANK, root)) == []


def test_check_and_the_box_ask_one_rule_of_the_junit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """One truth: with the rule's own reading of ``--junitxml=`` answering
    "there is one", neither ``check`` nor the step of a box refuses a run
    without it -- neither keeps a rule of its own beside ``refuse_junit``."""
    root = repo(tmp_path)
    _edit(root, {"test": {"run": "python -m pytest tests/", "target": "test"}})
    assert check(root, green_calls(root))[0] == 1
    assert _on_a_box(root, BLANK) is not None
    monkeypatch.setattr(tests_step, "junit_dir", lambda run: "/x")
    code, verdict, _ = check(root, green_calls(root))
    assert code == 0, _steps(verdict)
    assert _on_a_box(root, BLANK) is None


TURN = """schema: 1
name: turn
kind: service
stacks:
  turn:
    compose: docker-compose.yml
    app: { service: turn-app, port: 8000, health: /health, ready: /ready }
host:
  ports:
    - { proto: udp, port: 3478 }
    - { proto: tcp, port: 5349 }
report: { health: /health, ready: /ready, logs: json, junit: false }
"""


def _turn(published: list[dict[str, Json]]) -> dict[str, Json]:
    body: dict[str, Json] = {"image": "turn:1", "healthcheck": HEALTH}
    if published:
        body["ports"] = list[Json](published)
    return {"name": "turn", "services": {"turn-app": body}}


def test_check_of_a_service_says_a_port_declared_and_not_published(
    tmp_path: Path,
) -> None:
    """``check`` of a service's repository: ``compose`` red by
    ``host.ports: 5349/tcp not published`` -- the function ``build`` takes
    too (``host_ports``). The pair: both ports published -- green."""
    root = tmp_path / "turn"
    root.mkdir()
    (root / "primer.yaml").write_text(TURN)
    (root / "docker-compose.yml").write_text("services: {}\n")
    udp: dict[str, Json] = {"target": 3478, "published": "3478", "protocol": "udp"}
    tcp: dict[str, Json] = {"target": 5349, "published": "5349", "protocol": "tcp"}

    def calls(document: dict[str, Json]) -> list[FakeCall]:
        argv = [
            "docker",
            "compose",
            "-p",
            "turn",
            "-f",
            str(root / "docker-compose.yml"),
        ]
        argv += ["--profile", "*", "config", "--format", "json"]
        made = check_config(root, document, raw=False, keys=())
        lines = stdout(json.dumps(in_release(document, root)))
        return [
            version_call(),
            FakeCall((*argv, "--no-interpolate"), lines=lines, env=made.env),
            FakeCall(tuple(argv), lines=lines, env=made.env),
        ]

    code, verdict, _ = check(root, calls(_turn([udp])))
    assert code == 1, _steps(verdict)
    assert _reason(verdict, "turn/compose") == {
        "code": "compose:compose-forbidden",
        "stack": "turn",
        "found": ["host.ports: 5349/tcp not published"],
    }
    code, verdict, _ = check(root, calls(_turn([udp, tcp])))
    assert code == 0, _steps(verdict)


def test_build_of_a_service_says_a_port_declared_and_not_published(
    tmp_path: Path,
) -> None:
    """``build`` of a service on a box: refused by the same finding, nothing
    built. The pair: published -- no such finding."""
    cs = comms(tmp_path, [{"proto": "udp", "port": 10000}])
    step = Build(
        cs.stack, cs.entry, release=cs.release, ref="v1.0.0", commit=SHA, root=tmp_path
    )
    document: dict[str, Json] = {
        "services": {"comms-app": {"image": "comms:1", "healthcheck": HEALTH}}
    }
    with FakeRunner(
        raw_config_call(cs, document),
        config_call(cs, document),
        *executable_calls(cs, document, document),
    ) as runner:
        outcome, _ = run([step], runner)
    assert outcome.steps[0].reason == Code(
        "build:compose-forbidden",
        {"stack": "comms", "found": ["host.ports: 10000/udp not published"]},
    )
