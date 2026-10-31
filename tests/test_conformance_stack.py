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
    check_stack,
    conforming,
    main,
    observe,
    problems_param,
    size_bytes,
)
from pridem.events import Json
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
    """The seven fields of TZ 11 item 5 are exact: an extra one alone is red."""
    line = GOOD.logs[0][:-1] + ', "trace": "t"}'
    assert json.loads(line)["trace"] == "t"
    [problem] = check_stack(stack(), "blank", replace(GOOD, logs=[GOOD.logs[0], line]))
    assert (problem.code, dict(problem.params)) == (
        "log-fields",
        {"line": 2, "missing": [], "extra": ["trace"]},
    )
