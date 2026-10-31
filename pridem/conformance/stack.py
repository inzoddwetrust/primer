"""Conformance of a live stack (TZ 11 items 4-5, 8; contract 3 rules 4, 9).

After ``up`` the machine reads what the stack's application says of itself
and checks it, for every entry of ``stacks`` with an ``app``:

- ``GET <app.health>``: exactly the eleven fields of TZ 11 item 4, each of its
  type; ``status: degraded`` is red, and so is ``alembic_head: null`` of a
  stack that declares ``migrate`` (a stack without a database has no head);
- ``GET <app.ready>``: 200;
- the last ``LOG_TAIL`` lines of the ``app`` container, read after the
  ``/health`` request: every one a JSON object with exactly the seven fields
  of TZ 11 item 5 (owner's decision of 25.10: only ``app``; images of others --
  nginx, postgres -- write no JSON by construction);
- every route to ``<app.service>:<app.port>`` with ``max_body``: equal, in
  bytes, to ``limits.max_upload_mb`` MiB (nginx sizes: ``k``, ``m``, ``g`` are
  binary multiples, no suffix is bytes);
- every compose file of the stack: no service with ``logging`` (log limits
  are the host's ``daemon.json``), read from ``docker compose config``, which
  has expanded anchors, ``x-`` and ``extends``.

The application is reached from the host at its address on the network
``pridem`` (the machine attaches it there, TZ 7.3; no port is published).
``observe`` gathers what is seen with ``docker`` through the runner and
stdlib HTTP; the output of those commands is kept by the check and never
passed on -- the application's log is not the run's journal. ``check_stack``
is a pure function of what was observed; a problem names what is wrong --
a field, a line number, a route -- never a value the application printed.

The step that calls it (``up``, DM-18) turns a non-empty list into its own
code, ``up:conformance``, with ``problems_param`` as its parameter.

``python -m pridem.conformance.stack --selftest`` plants every defect the
checks must catch into a conforming observation and exits 1 if one is missed.
"""

import http.client
import json
import re
import sys
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field, replace
from pathlib import Path

from pridem.events import Json
from pridem.runner import Stream
from pridem.stacks.schema import PRIMER_YAML, Product, Service
from pridem.steps.base import StepContext

HEALTH_FIELDS = (
    "service",
    "release",
    "commit",
    "alembic_head",
    "uptime_s",
    "status",
    "checks",
    "seams",
    "limits",
    "edition",
    "modules",
)
LOG_FIELDS = ("ts", "level", "service", "release", "request_id", "event", "msg")
LOG_TAIL = 50
HTTP_TIMEOUT_S = 5.0
COMMAND_TIMEOUT_S = 120
NETWORK = "pridem"
_SIZE = re.compile(r"(\d+)([kKmMgG]?)")
_MULTIPLE = {"": 1, "k": 1024, "m": 1024**2, "g": 1024**3}
MIB = 1024**2

Stack = Product | Service


@dataclass(frozen=True)
class Problem:
    """What is wrong, by name; never a value the application printed."""

    code: str
    params: Mapping[str, Json] = field(default_factory=dict)

    def line(self) -> str:
        parts = [self.code]
        for key, value in self.params.items():
            shown = ",".join(map(str, value)) if isinstance(value, list) else value
            parts.append(f"{key}={shown}")
        return " ".join(parts)


@dataclass(frozen=True)
class Observed:
    """One look at a live stack entry; ``None`` -- nothing answered."""

    running: bool
    address: str | None
    health: bytes | None
    ready: int | None
    logs: Sequence[str]
    configs: Mapping[str, Json]


def problems_param(problems: Sequence[Problem]) -> list[Json]:
    """The list ``up:conformance`` carries as its parameter."""
    return [problem.line() for problem in problems]


def size_bytes(text: str) -> int:
    """An nginx size (``max_body``) in bytes."""
    found = _SIZE.fullmatch(text)
    if found is None:
        raise ValueError(f"not an nginx size: {text!r}")
    return int(found.group(1)) * _MULTIPLE[found.group(2).lower()]


# --- the checks -------------------------------------------------------------------


def _text(value: Json) -> bool:
    return isinstance(value, str) and bool(value)


def _strings(value: Json) -> bool:
    return isinstance(value, list) and all(isinstance(item, str) for item in value)


def _type_ok(name: str, value: Json) -> bool:
    match name:
        case "service" | "release" | "commit" | "edition":
            return _text(value)
        case "alembic_head":
            return value is None or _text(value)
        case "uptime_s":
            return isinstance(value, int) and not isinstance(value, bool) and value >= 0
        case "status":
            return value in ("ok", "degraded")
        case "checks":
            return isinstance(value, dict) and all(
                isinstance(key, str) and state in ("ok", "error")
                for key, state in value.items()
            )
        case "seams":
            return (
                isinstance(value, dict)
                and set(value) == {"provides", "requires_satisfied"}
                and _strings(value["provides"])
                and isinstance(value["requires_satisfied"], bool)
            )
        case "limits":
            return isinstance(value, dict)
        case "modules":
            return _strings(value)
    return False


def check_health(body: bytes | None, *, migrate: bool) -> list[Problem]:
    """``/health`` against the form of TZ 11 item 4."""
    if body is None:
        return [Problem("health-unreachable")]
    try:
        document = json.loads(body)
    except (UnicodeDecodeError, json.JSONDecodeError):
        return [Problem("health-not-json")]
    if not isinstance(document, dict):
        return [Problem("health-not-json")]
    out: list[Problem] = []
    for name in HEALTH_FIELDS:
        if name not in document:
            out.append(Problem("health-field", {"field": name, "problem": "missing"}))
        elif not _type_ok(name, document[name]):
            out.append(Problem("health-field", {"field": name, "problem": "type"}))
    for name in document:
        if name not in HEALTH_FIELDS:
            out.append(Problem("health-field", {"field": name, "problem": "extra"}))
    limits = document.get("limits")
    if isinstance(limits, dict):
        upload = limits.get("max_upload_mb")
        if upload is None:
            out.append(
                Problem(
                    "health-field",
                    {"field": "limits.max_upload_mb", "problem": "missing"},
                )
            )
        elif not isinstance(upload, int) or isinstance(upload, bool) or upload < 0:
            out.append(
                Problem(
                    "health-field", {"field": "limits.max_upload_mb", "problem": "type"}
                )
            )
    checks = document.get("checks")
    if document.get("status") == "degraded" and isinstance(checks, dict):
        failing = sorted(str(name) for name, state in checks.items() if state != "ok")
        out.append(Problem("health-degraded", {"checks": list[Json](failing)}))
    if migrate and "alembic_head" in document and document["alembic_head"] is None:
        out.append(Problem("alembic-head-null"))
    return out


def check_ready(status: int | None) -> list[Problem]:
    if status is None:
        return [Problem("ready-unreachable")]
    if status != 200:
        return [Problem("ready", {"status": status})]
    return []


def check_logs(lines: Sequence[str]) -> list[Problem]:
    """Every line a JSON object with exactly the fields of TZ 11 item 5."""
    if not lines:
        return [Problem("logs-empty")]
    out: list[Problem] = []
    for number, line in enumerate(lines, start=1):
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            out.append(Problem("log-not-json", {"line": number}))
            continue
        if not isinstance(record, dict):
            out.append(Problem("log-not-json", {"line": number}))
            continue
        missing = [name for name in LOG_FIELDS if name not in record]
        extra = sorted(str(name) for name in record if name not in LOG_FIELDS)
        if missing or extra:
            out.append(
                Problem(
                    "log-fields",
                    {
                        "line": number,
                        "missing": list[Json](missing),
                        "extra": list[Json](extra),
                    },
                )
            )
    return out


def check_max_body(stack: Stack, entry: str, body: bytes | None) -> list[Problem]:
    """Routes to this entry's app with ``max_body`` against ``limits``."""
    app = stack.stacks[entry].app
    routes = stack.host.routes if isinstance(stack, Product) and stack.host else {}
    if app is None or not routes:
        return []
    try:
        document = json.loads(body) if body is not None else None
    except (UnicodeDecodeError, json.JSONDecodeError):
        return []  # check_health names it
    limits = document.get("limits") if isinstance(document, dict) else None
    upload = limits.get("max_upload_mb") if isinstance(limits, dict) else None
    if not isinstance(upload, int) or isinstance(upload, bool):
        return []  # check_health names it
    out: list[Problem] = []
    for name, route in routes.items():
        if route.to != f"{app.service}:{app.port}" or route.max_body is None:
            continue
        if size_bytes(route.max_body) != upload * MIB:
            out.append(
                Problem(
                    "max-body",
                    {
                        "route": name,
                        "max_body": route.max_body,
                        "max_upload_mb": upload,
                    },
                )
            )
    return out


def check_compose(configs: Mapping[str, Json]) -> list[Problem]:
    """No service of a stack's compose sets ``logging`` (contract 3 rule 9)."""
    out: list[Problem] = []
    for file, config in configs.items():
        services = config.get("services") if isinstance(config, dict) else None
        if not isinstance(services, dict):
            out.append(Problem("compose-unreadable", {"file": file}))
            continue
        logging = sorted(
            str(name)
            for name, service in services.items()
            if isinstance(service, dict) and "logging" in service
        )
        if logging:
            out.append(
                Problem(
                    "compose-logging", {"file": file, "services": list[Json](logging)}
                )
            )
    return out


def check_stack(stack: Stack, entry: str, observed: Observed) -> list[Problem]:
    """Every problem of one live stack entry; empty -- it conforms."""
    stage = stack.stacks[entry]
    out: list[Problem] = []
    if stage.app is not None:
        if not observed.running:
            out.append(Problem("app-not-running", {"service": stage.app.service}))
        elif observed.address is None:
            out.append(Problem("app-not-on-network", {"network": NETWORK}))
        else:
            out += check_health(observed.health, migrate=stage.migrate is not None)
            out += check_ready(observed.ready)
            out += check_max_body(stack, entry, observed.health)
        if observed.running:
            out += check_logs(observed.logs)
    out += check_compose(observed.configs)
    return out


# --- what is seen -----------------------------------------------------------------


def _out(ctx: StepContext, argv: list[str]) -> list[str]:
    """stdout of ``argv``, kept by the check: none of it reaches the sinks."""
    lines: list[str] = []

    def keep(stream: Stream, line: str, cut: bool) -> None:
        if stream is Stream.STDOUT:
            lines.append(line)

    ctx.runner.run(argv, timeout=COMMAND_TIMEOUT_S, on_line=keep)
    return lines


def _get(address: str, port: int, path: str) -> tuple[int, bytes] | None:
    connection = http.client.HTTPConnection(address, port, timeout=HTTP_TIMEOUT_S)
    try:
        connection.request("GET", path)
        response = connection.getresponse()
        return response.status, response.read()
    except (OSError, http.client.HTTPException):
        return None
    finally:
        connection.close()


def observe(
    ctx: StepContext,
    stack: Stack,
    entry: str,
    *,
    release: Path,
    project: str,
    env_file: Path,
) -> Observed:
    """Look at a live stack entry: its app over HTTP, its log, its compose."""
    compose = ["docker", "compose", "-p", project, "--env-file", str(env_file)]
    stage = stack.stacks[entry]
    files = sorted({entry_.compose for entry_ in stack.stacks.values()})
    configs: dict[str, Json] = {
        file: json.loads(
            "\n".join(
                _out(
                    ctx,
                    [*compose, "-f", str(release / file), "config", "--format", "json"],
                )
            )
        )
        for file in files
    }
    app = stage.app
    if app is None:
        return Observed(False, None, None, None, [], configs)
    own = [*compose, "-f", str(release / stage.compose)]
    ids = [line for line in _out(ctx, [*own, "ps", "-q", app.service]) if line.strip()]
    if not ids:
        return Observed(False, None, None, None, [], configs)
    networks = json.loads(
        "\n".join(
            _out(
                ctx,
                [
                    "docker",
                    "inspect",
                    "-f",
                    "{{json .NetworkSettings.Networks}}",
                    ids[0],
                ],
            )
        )
    )
    attached = networks.get(NETWORK) if isinstance(networks, dict) else None
    address = attached.get("IPAddress") if isinstance(attached, dict) else None
    health = ready = None
    if isinstance(address, str) and address:
        got = _get(address, app.port, app.health)
        health = None if got is None else got[1]
        answered = _get(address, app.port, app.ready)
        ready = None if answered is None else answered[0]
    else:
        address = None
    logs = _out(
        ctx,
        [
            *own,
            "logs",
            "--no-color",
            "--no-log-prefix",
            "--tail",
            str(LOG_TAIL),
            app.service,
        ],
    )
    return Observed(True, address, health, ready, logs, configs)


# --- selftest ---------------------------------------------------------------------

_GOOD_HEALTH: dict[str, Json] = {
    "service": "blank",
    "release": "v1.0.0",
    "commit": "0e82be5",
    "alembic_head": "0001",
    "uptime_s": 12,
    "status": "ok",
    "checks": {"db": "ok"},
    "seams": {"provides": [], "requires_satisfied": True},
    "limits": {"max_upload_mb": 1},
    "edition": "core",
    "modules": ["core"],
}
_GOOD_LOG = json.dumps(
    {
        "ts": "2026-10-31T00:00:00.000Z",
        "level": "info",
        "service": "blank",
        "release": "v1.0.0",
        "request_id": "0123abcd",
        "event": "uvicorn.access",
        "msg": "GET /health 200",
    }
)
_GOOD_STACK: dict[str, object] = {
    "schema": 1,
    "name": "blank",
    "kind": "product",
    "editions": {"core": {"services": []}},
    "stacks": {
        "blank": {
            "compose": "docker-compose.yml",
            "app": {
                "service": "app",
                "port": 8000,
                "health": "/health",
                "ready": "/ready",
            },
            "migrate": "python -m alembic upgrade head",
        }
    },
    "env": {},
    "host": {
        "domains": ["api"],
        "routes": {"api": {"to": "app:8000", "max_body": "1M"}},
    },
    "report": {"health": "/health", "ready": "/ready", "logs": "json", "junit": True},
}
_GOOD_CONFIG: dict[str, Json] = {
    "services": {"app": {"image": "x"}, "postgres": {"image": "y"}}
}


def _health(**change: Json) -> bytes:
    document = dict(_GOOD_HEALTH)
    for key, value in change.items():
        if value == "<absent>":
            document.pop(key, None)
        else:
            document[key] = value
    return json.dumps(document).encode()


def _stack(max_body: str = "1M") -> Stack:
    data = json.loads(json.dumps(_GOOD_STACK))
    data["host"]["routes"]["api"]["max_body"] = max_body
    return PRIMER_YAML.validate_python(data)


def conforming() -> tuple[Stack, Observed]:
    """An observation of a stack that conforms: the selftest's ground."""
    return _stack(), Observed(
        True,
        "10.0.0.2",
        _health(),
        200,
        [_GOOD_LOG, _GOOD_LOG],
        {"docker-compose.yml": _GOOD_CONFIG},
    )


def _planted() -> list[tuple[str, Callable[[], list[Problem]]]]:
    stack, good = conforming()
    logging_config: dict[str, Json] = {
        "services": {"app": {}, "worker": {"logging": {"driver": "json-file"}}}
    }

    def with_(observed: Observed, size: str = "1M") -> Callable[[], list[Problem]]:
        return lambda: check_stack(_stack(size), "blank", observed)

    return [
        ("health-unreachable", with_(replace(good, health=None))),
        ("health-not-json", with_(replace(good, health=b"<html>"))),
        ("health-field", with_(replace(good, health=_health(alembic_head="<absent>")))),
        ("health-field", with_(replace(good, health=_health(extra="x")))),
        ("health-field", with_(replace(good, health=_health(uptime_s=True)))),
        ("health-field", with_(replace(good, health=_health(checks={"db": "fine"})))),
        ("health-field", with_(replace(good, health=_health(limits={})))),
        (
            "health-degraded",
            with_(
                replace(good, health=_health(status="degraded", checks={"db": "error"}))
            ),
        ),
        ("alembic-head-null", with_(replace(good, health=_health(alembic_head=None)))),
        ("ready", with_(replace(good, ready=503))),
        ("ready-unreachable", with_(replace(good, ready=None))),
        ("logs-empty", with_(replace(good, logs=[]))),
        ("log-not-json", with_(replace(good, logs=[_GOOD_LOG, "Started server"]))),
        (
            "log-fields",
            with_(replace(good, logs=[_GOOD_LOG.replace('"request_id"', '"rid"')])),
        ),
        ("max-body", with_(good, "2M")),
        ("max-body", with_(good, "1000k")),
        (
            "compose-logging",
            with_(replace(good, configs={"docker-compose.yml": logging_config})),
        ),
        ("app-not-running", with_(replace(good, running=False))),
        ("app-not-on-network", with_(replace(good, address=None))),
    ]


def selftest() -> list[str]:
    """Each planted defect caught by its code, the ground clean: what is missed."""
    missed: list[str] = []
    stack, good = conforming()
    if check_stack(stack, "blank", good):
        missed.append("the conforming observation is not clean")
    for number, (code, run) in enumerate(_planted(), start=1):
        if code not in {problem.code for problem in run()}:
            missed.append(f"planted defect {number} is not caught as {code}")
    return missed


def main(argv: Sequence[str]) -> int:
    if list(argv) != ["--selftest"]:
        print("usage: python -m pridem.conformance.stack --selftest", file=sys.stderr)
        return 2
    missed = selftest()
    for line in missed:
        print(f"MISSED {line}")
    caught = len(_planted()) - len(missed)
    print(f"conformance.stack selftest: {caught} caught, {len(missed)} missed")
    return 1 if missed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
