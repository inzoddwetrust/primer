"""Conformance of a live stack (DM-15): the checks as pure functions, ``observe``
on a strict ``FakeRunner`` and a real local HTTP server, ``--selftest`` and
its step in CI."""

import json
import sys
import threading
from collections.abc import Iterator, Mapping
from dataclasses import replace
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest
import yaml

import pridem.conformance.stack as conformance
from pridem.conformance.stack import (
    LOG_TAIL,
    Observed,
    Problem,
    check_health,
    check_logs,
    check_stack,
    conforming,
    main,
    observe,
    problems_param,
    size_bytes,
)
from pridem.events import FREE_LIMIT, Json, free_size
from pridem.runner import FakeCall, FakeRunner, Stream, SubprocessRunner
from pridem.stacks.schema import PRIMER_YAML, Product
from pridem.steps.base import StepContext

REPO = Path(__file__).resolve().parents[1]
GOOD_STACK, GOOD = conforming()


def health(**change: object) -> bytes:
    document = json.loads(GOOD.health or b"{}")
    for key, value in change.items():
        if value == "<absent>":
            document.pop(key)
        else:
            document[key] = value
    return json.dumps(document).encode()


def stack(
    *, migrate: bool = True, max_body: str | None = "1M", port: int = 8000
) -> Product:
    entry: dict[str, object] = {
        "compose": "docker-compose.yml",
        "app": {"service": "app", "port": port, "health": "/health", "ready": "/ready"},
    }
    if migrate:
        entry["migrate"] = "python -m alembic upgrade head"
    route: dict[str, object] = {"to": f"app:{port}"}
    if max_body is not None:
        route["max_body"] = max_body
    made = PRIMER_YAML.validate_python(
        {
            "schema": 1,
            "name": "blank",
            "kind": "product",
            "stacks": {"blank": entry},
            "env": {},
            "host": {"domains": ["api"], "routes": {"api": route}},
            "report": {
                "health": "/health",
                "ready": "/ready",
                "logs": "json",
                "junit": True,
            },
        }
    )
    assert isinstance(made, Product)
    return made


def codes(problems: list[Problem]) -> list[str]:
    return [problem.line() for problem in problems]


# --- probes ---------------------------------------------------------------------


def test_probe_DM_15_health_without_alembic_head_is_red() -> None:
    seen = replace(GOOD, health=health(alembic_head="<absent>"))
    assert codes(check_stack(stack(), "blank", seen)) == [
        "health-field field=alembic_head problem=missing"
    ]
    # without migrate the field is still owed
    assert codes(check_stack(stack(migrate=False), "blank", seen)) == [
        "health-field field=alembic_head problem=missing"
    ]
    # the pairs: null is red with migrate, normal without; a head is green
    empty = replace(GOOD, health=health(alembic_head=None))
    assert codes(check_stack(stack(), "blank", empty)) == ["alembic-head-null"]
    assert check_stack(stack(migrate=False), "blank", empty) == []
    assert check_stack(stack(), "blank", GOOD) == []


def test_probe_DM_15_max_body_mismatch_with_health_limits_is_red() -> None:
    assert codes(check_stack(stack(max_body="2M"), "blank", GOOD)) == [
        "max-body route=api max_body=2M max_upload_mb=1"
    ]
    assert codes(check_stack(stack(max_body="1000k"), "blank", GOOD)) == [
        "max-body route=api max_body=1000k max_upload_mb=1"
    ]
    # the pair: the same size in any unit is green; no max_body -- no comparison
    for same in ("1M", "1m", "1024k", "1048576"):
        assert check_stack(stack(max_body=same), "blank", GOOD) == [], same
    assert check_stack(stack(max_body=None), "blank", GOOD) == []
    big = replace(GOOD, health=health(limits={"max_upload_mb": 100}))
    assert check_stack(stack(max_body="100M"), "blank", big) == []


def test_probe_DM_15_logging_in_compose_is_red() -> None:
    config: dict[str, Json] = {
        "services": {"app": {"image": "a"}, "worker": {"logging": {"driver": "x"}}}
    }
    seen = replace(GOOD, configs={"docker-compose.yml": config})
    assert codes(check_stack(stack(), "blank", seen)) == [
        "compose-logging file=docker-compose.yml services=worker"
    ]
    # the pair: without logging -- clean
    assert check_stack(stack(), "blank", GOOD) == []


def test_probe_DM_15_conformance_selftest_catches_planted_defects(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    out: list[str] = []
    result = SubprocessRunner().run(
        [sys.executable, "-m", "pridem.conformance.stack", "--selftest"],
        timeout=60,
        on_line=lambda stream, line, cut: out.append(line),
    )
    assert result.code == 0, out
    assert out[-1].endswith(" 0 missed")
    # the pair: a check that stops catching makes the selftest red
    monkeypatch.setattr(conformance, "check_max_body", lambda *args: [])
    assert main(["--selftest"]) == 1
    assert any("max-body" in line for line in conformance.selftest())


# --- the grid -------------------------------------------------------------------


@pytest.mark.parametrize(
    ("seen", "expected"),
    [
        (replace(GOOD, health=None), ["health-unreachable"]),
        (replace(GOOD, health=b"<html>"), ["health-not-json"]),
        (replace(GOOD, health=b"[1]"), ["health-not-json"]),
        (
            replace(GOOD, health=health(extra=1)),
            ["health-field field=extra problem=extra"],
        ),
        (
            replace(GOOD, health=health(uptime_s=True)),
            ["health-field field=uptime_s problem=type"],
        ),
        (
            replace(GOOD, health=health(uptime_s=-1)),
            ["health-field field=uptime_s problem=type"],
        ),
        (
            replace(GOOD, health=health(service="")),
            ["health-field field=service problem=type"],
        ),
        (
            replace(GOOD, health=health(modules="core")),
            ["health-field field=modules problem=type"],
        ),
        (
            replace(GOOD, health=health(seams={"provides": []})),
            ["health-field field=seams problem=type"],
        ),
        (
            replace(GOOD, health=health(checks={"db": "fine"})),
            ["health-field field=checks problem=type"],
        ),
        (
            replace(GOOD, health=health(limits={})),
            ["health-field field=limits.max_upload_mb problem=missing"],
        ),
        (
            replace(
                GOOD,
                health=health(status="degraded", checks={"db": "error", "s3": "ok"}),
            ),
            ["health-degraded checks=db"],
        ),
        (replace(GOOD, ready=503), ["ready status=503"]),
        (replace(GOOD, ready=None), ["ready-unreachable"]),
        (replace(GOOD, logs=[]), ["logs-empty"]),
        (replace(GOOD, logs=[*GOOD.logs, "INFO: Started"]), ["log-not-json line=3"]),
        (
            replace(GOOD, logs=[GOOD.logs[0].replace('"event"', '"evt"')]),
            ["log-fields line=1 missing=event extra=evt"],
        ),
        (replace(GOOD, running=False), ["app-not-running service=app"]),
        (replace(GOOD, address=None), ["app-not-on-network network=pridem"]),
    ],
)
def test_each_problem_by_its_name(seen: Observed, expected: list[str]) -> None:
    assert codes(check_stack(stack(), "blank", seen)) == expected


def test_empty_checks_and_open_limits_conform() -> None:
    """A stack with no dependency has nothing to check (gate 15, fix 1)."""
    seen = replace(GOOD, health=health(checks={}, limits={"max_upload_mb": 1, "x": 2}))
    assert check_stack(stack(), "blank", seen) == []


def test_sizes_are_nginx_sizes() -> None:
    assert [size_bytes(s) for s in ("0", "10", "1k", "1K", "2m", "1g")] == [
        0,
        10,
        1024,
        1024,
        2 * 1024**2,
        1024**3,
    ]
    with pytest.raises(ValueError):
        size_bytes("1T")


def test_problems_param_is_a_list_of_strings() -> None:
    problems = check_stack(stack(max_body="2M"), "blank", replace(GOOD, ready=500))
    assert problems_param(problems) == [
        "ready status=500",
        "max-body route=api max_body=2M max_upload_mb=1",
    ]


# --- observe --------------------------------------------------------------------


@pytest.fixture
def app() -> Iterator[tuple[int, list[str]]]:
    """A real HTTP app on localhost: ``/health`` of the selftest, ``/ready`` 200."""
    asked: list[str] = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802 -- the stdlib's name
            asked.append(self.path)
            body = (GOOD.health or b"") if self.path == "/health" else b"{}"
            self.send_response(200 if self.path in ("/health", "/ready") else 404)
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, format: str, *args: object) -> None:
            return

    server = HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.server_address[1], asked
    finally:
        server.shutdown()
        server.server_close()


def compose_calls(
    release: Path, port_networks: Mapping[str, object], logs: list[str]
) -> list[FakeCall]:
    base = ("docker", "compose", "-p", "blank", "--env-file", "/opt/blank/env/.env")
    own = (*base, "-f", str(release / "docker-compose.yml"))
    config = json.dumps(GOOD.configs["docker-compose.yml"])
    return [
        FakeCall(
            (*own, "config", "--format", "json"), lines=((Stream.STDOUT, config),)
        ),
        FakeCall((*own, "ps", "-q", "app"), lines=((Stream.STDOUT, "c0ffee"),)),
        FakeCall(
            ("docker", "inspect", "-f", "{{json .NetworkSettings.Networks}}", "c0ffee"),
            lines=((Stream.STDOUT, json.dumps(port_networks)),),
        ),
        FakeCall(
            (
                *own,
                "logs",
                "--no-color",
                "--no-log-prefix",
                "--tail",
                str(LOG_TAIL),
                "app",
            ),
            lines=tuple((Stream.STDOUT, line) for line in logs),
        ),
    ]


def test_observe_reads_the_live_app_and_keeps_command_output(
    tmp_path: Path, app: tuple[int, list[str]]
) -> None:
    port, asked = app
    made = stack(port=port)
    printed: list[str] = []
    networks = {
        "pridem": {"IPAddress": "127.0.0.1"},
        "blank_default": {"IPAddress": "x"},
    }
    with FakeRunner(*compose_calls(tmp_path, networks, list(GOOD.logs))) as runner:
        ctx = StepContext(
            runner=runner,
            mode="install",
            role="test",
            stack="blank",
            on_line=lambda stream, line, cut: printed.append(line),
        )
        seen = observe(
            ctx,
            made,
            "blank",
            release=tmp_path,
            project="blank",
            env_file=Path("/opt/blank/env/.env"),
        )
    assert (seen.address, seen.ready, seen.health) == ("127.0.0.1", 200, GOOD.health)
    assert asked == ["/health", "/ready"]
    assert check_stack(made, "blank", seen) == []
    assert printed == []  # the app's log and docker's output stay with the check


def test_observe_without_the_network_pridem_asks_nothing(tmp_path: Path) -> None:
    networks = {"blank_default": {"IPAddress": "172.18.0.2"}}
    with FakeRunner(*compose_calls(tmp_path, networks, list(GOOD.logs))) as runner:
        ctx = StepContext(
            runner=runner,
            mode="install",
            role="test",
            stack="blank",
            on_line=lambda stream, line, cut: None,
        )
        seen = observe(
            ctx,
            stack(),
            "blank",
            release=tmp_path,
            project="blank",
            env_file=Path("/opt/blank/env/.env"),
        )
    assert codes(check_stack(stack(), "blank", seen)) == [
        "app-not-on-network network=pridem"
    ]


# --- CI -------------------------------------------------------------------------


def selftest_problems(workflow: str) -> list[str]:
    """Conformance modules with ``--selftest`` that the CI does not run."""
    document = yaml.safe_load(workflow)
    runs = [
        str(step.get("run", ""))
        for job in document["jobs"].values()
        for step in job["steps"]
    ]
    out: list[str] = []
    for module in sorted((REPO / "pridem" / "conformance").glob("*.py")):
        if "--selftest" not in module.read_text(encoding="utf-8"):
            continue
        call = f"python -m pridem.conformance.{module.stem} --selftest"
        if not any(call in run for run in runs):
            out.append(call)
    return out


def test_ci_runs_every_conformance_selftest() -> None:
    workflow = (REPO / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    assert selftest_problems(workflow) == []
    # the pair: there is such a module, and a CI without its step is caught
    assert (REPO / "pridem" / "conformance" / "stack.py").exists()
    planted = workflow.replace("python -m pridem.conformance.stack --selftest", "true")
    assert selftest_problems(planted) == [
        "python -m pridem.conformance.stack --selftest"
    ]


def test_an_eighth_log_field_is_red_by_its_name() -> None:
    """The seven fields of protocol 9.4 and the optional ``ctx`` are all a line
    may have: an extra one alone is red (until FIX 3 of DM-55 the seven were
    exact; ``ctx`` is allowed since)."""
    line = GOOD.logs[0][:-1] + ', "trace": "t"}'
    assert json.loads(line)["trace"] == "t"
    [problem] = check_stack(stack(), "blank", replace(GOOD, logs=[GOOD.logs[0], line]))
    assert (problem.code, dict(problem.params)) == (
        "log-fields",
        {"line": 2, "missing": [], "extra": ["trace"]},
    )


def _found(
    seen: Observed, *, migrate: bool = True
) -> list[tuple[str, dict[str, Json]]]:
    return [
        (problem.code, dict(problem.params))
        for problem in check_stack(stack(migrate=migrate), "blank", seen)
    ]


@pytest.mark.parametrize(
    ("details", "problem"),
    [
        ("<absent>", None),
        ({}, None),
        ({"queue": {"depth": 3}, "mail": "error"}, None),
        ("x" * 10, "type"),
        ([1, 2], "type"),
        (None, "type"),
    ],
)
def test_health_details_is_an_optional_object(
    details: object, problem: str | None
) -> None:
    """Protocol 9.1 (FIX 3): ``details`` may be there, as an object; the eleven
    fields stay what they were."""
    body = health() if details == "<absent>" else health(details=details)
    found = _found(replace(GOOD, health=body))
    expected: list[tuple[str, dict[str, Json]]] = (
        []
        if problem is None
        else [("health-field", {"field": "details", "problem": problem})]
    )
    assert found == expected


def test_health_details_is_at_most_8_kb_of_compact_json() -> None:
    """``FREE_LIMIT`` bytes of the compact UTF-8 JSON: 8192 is green, one
    more is ``size``; a non-ASCII character counts its UTF-8 bytes."""
    frame = len(json.dumps({"x": ""}, separators=(",", ":")))
    at: dict[str, Json] = {"x": "y" * (FREE_LIMIT - frame)}
    assert free_size(at) == FREE_LIMIT
    assert _found(replace(GOOD, health=health(details=at))) == []
    over: dict[str, Json] = {
        "x": "y" * (FREE_LIMIT - frame - 1) + "ж"
    }  # one character, two bytes
    assert free_size(over) == FREE_LIMIT + 1
    assert _found(replace(GOOD, health=health(details=over))) == [
        ("health-field", {"field": "details", "problem": "size"})
    ]


def test_a_twelfth_health_field_but_details_is_extra() -> None:
    assert _found(replace(GOOD, health=health(trace="t"))) == [
        ("health-field", {"field": "trace", "problem": "extra"})
    ]


def test_a_degraded_stack_is_not_red_for_a_null_head() -> None:
    """Protocol 9.5 (FIX 3): a degraded stack's head is not read -- degraded
    and ``alembic_head: null`` is ``health-degraded`` alone; ``ok`` and null
    of a stack with migrations is ``alembic-head-null`` as before."""
    degraded = health(status="degraded", checks={"db": "error"}, alembic_head=None)
    assert _found(replace(GOOD, health=degraded)) == [
        ("health-degraded", {"checks": ["db"]})
    ]
    assert _found(replace(GOOD, health=health(alembic_head=None))) == [
        ("alembic-head-null", {})
    ]


@pytest.mark.parametrize(
    ("ctx", "red"),
    [
        ({}, False),
        ({"job": "7", "sqlstate": "23505"}, False),
        ("job 7", True),
        ([1], True),
        (None, True),
    ],
)
def test_a_log_line_may_carry_ctx_as_an_object(ctx: object, red: bool) -> None:
    """Protocol 9.4 (FIX 3): ``ctx`` beside the seven fields, an object of any
    size (over ``FREE_LIMIT`` the machine cuts it itself); any other eighth
    field is red as before."""
    line = json.dumps({**json.loads(GOOD.logs[0]), "ctx": ctx})
    found = _found(replace(GOOD, logs=[GOOD.logs[0], line]))
    assert found == ([("log-ctx", {"line": 2})] if red else [])
    big = json.dumps({**json.loads(GOOD.logs[0]), "ctx": {"x": "y" * FREE_LIMIT}})
    assert _found(replace(GOOD, logs=[big])) == []


# --- the name of the stack (DM-72; protocol 9.1, 9.4) ------------------------------


REPORT = {"health": "/health", "ready": "/ready", "logs": "json", "junit": True}


def _two_entries() -> Product:
    """``primer-blank`` with a second entry ``worker``: the name of an entry
    is not the name of the stack."""
    app = {"service": "app", "port": 8000, "health": "/health", "ready": "/ready"}
    made = PRIMER_YAML.validate_python(
        {
            "schema": 1,
            "name": "primer-blank",
            "kind": "product",
            "stacks": {
                "primer-blank": {"compose": "docker-compose.yml", "app": app},
                "worker": {"compose": "worker-compose.yml", "app": app},
            },
            "env": {},
            "report": {
                "health": "/health",
                "ready": "/ready",
                "logs": "json",
                "junit": True,
            },
        }
    )
    assert isinstance(made, Product)
    return made


def _named(service: str) -> conformance.Observed:
    line = json.loads(GOOD.logs[0])
    line["service"] = service
    return replace(GOOD, health=health(service=service), logs=[json.dumps(line)])


def test_probe_DM_72_health_service_is_the_stack_name() -> None:
    """The entry ``worker`` of ``primer-blank`` answering ``/health`` with its
    entry's name -- ``health-service`` (and ``log-service`` for its lines): the
    name is the stack's, not the entry's. The pair: the stack's name -- clean."""
    made = _two_entries()
    found = check_stack(made, "worker", _named("worker"))
    assert [p.code for p in found] == ["health-service", "log-service"]
    assert found[0].params == {"service": "worker", "stack": "primer-blank"}
    assert check_stack(made, "worker", _named("primer-blank")) == []  # the pair


def test_another_name_in_health_is_health_service() -> None:
    found = check_health(health(service="blank-old"), migrate=True, stack_name="blank")
    assert [(p.code, p.params) for p in found] == [
        ("health-service", {"service": "blank-old", "stack": "blank"})
    ]


@pytest.mark.parametrize(
    ("given", "problem"),
    [("<absent>", "missing"), ("", "type"), (5, "type")],
    ids=["absent", "empty", "not-a-string"],
)
def test_a_service_field_missing_or_not_a_string_is_health_field_alone(
    given: object, problem: str
) -> None:
    """Twin EMPTY and LACK: one cause, one code -- no ``health-service``."""
    found = check_health(health(service=given), migrate=True, stack_name="blank")
    assert [(p.code, p.params) for p in found] == [
        ("health-field", {"field": "service", "problem": problem})
    ]


def test_every_line_of_another_name_is_log_service() -> None:
    """Twin REPEAT: each line named by its number; a line without ``service``
    stays ``log-fields`` alone."""
    good = json.loads(GOOD.logs[0])
    other = json.dumps({**good, "service": "other"})
    bare = json.dumps({k: v for k, v in good.items() if k != "service"})
    found = check_logs([GOOD.logs[0], other, other, bare], stack_name="blank")
    assert [(p.code, p.params) for p in found] == [
        ("log-service", {"line": 2, "service": "other", "stack": "blank"}),
        ("log-service", {"line": 3, "service": "other", "stack": "blank"}),
        ("log-fields", {"line": 4, "missing": ["service"], "extra": []}),
    ]


def test_selftest_catches_the_planted_names() -> None:
    """Changed by DM-81: two defects more are planted -- a ``/health`` over
    its bound and a log line over its bound."""
    planted = [code for code, _ in conformance._planted()]
    assert planted.count("health-service") == planted.count("log-service") == 1
    assert planted.count("health-too-big") == planted.count("log-too-long") == 1
    assert len(planted) == 27 and conformance.selftest() == []


NEAR = ["primer", "blank", "primer-blank-x"]
"""Names that are not ``primer-blank`` and yet a prefix of it, a part of it,
or contain it -- the prefix is no border (par0 14.4; the case of DM-70:
``service: blank`` at the stack ``primer-blank``)."""


@pytest.mark.parametrize("given", NEAR)
def test_a_name_near_the_stacks_is_still_health_service(given: str) -> None:
    """DM-72 FIX: equality, not containment and not a prefix."""
    found = check_health(health(service=given), migrate=True, stack_name="primer-blank")
    assert [(p.code, p.params) for p in found] == [
        ("health-service", {"service": given, "stack": "primer-blank"})
    ]


@pytest.mark.parametrize("given", NEAR)
def test_a_name_near_the_stacks_is_still_log_service(given: str) -> None:
    """DM-72 FIX: the same for a log line."""
    line = json.dumps({**json.loads(GOOD.logs[0]), "service": given})
    found = check_logs([line], stack_name="primer-blank")
    assert [(p.code, p.params) for p in found] == [
        ("log-service", {"line": 1, "service": given, "stack": "primer-blank"})
    ]
