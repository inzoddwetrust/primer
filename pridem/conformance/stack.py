"""Conformance of a live stack (TZ 11 items 4-5, 8; contract 3 rules 4, 9).

After ``up`` the machine reads what the stack's application says of itself
and checks it, for every entry of ``stacks`` with an ``app``:

- ``GET <app.health>``: the eleven fields of protocol 9.1, each of its type,
  and no other but the optional ``details`` -- an object of at most
  ``FREE_LIMIT`` bytes; ``status: degraded`` is red, and so is ``alembic_head:
  null`` of a stack that declares ``migrate`` and is not ``degraded`` (a stack
  without a database has no head; a degraded one's head is not read, protocol
  9.5);
- ``GET <app.ready>``: 200;
- the last ``LOG_TAIL`` lines of the ``app`` container, read after the
  ``/health`` request: every one a JSON object with the seven fields of
  protocol 9.4 and no other but the optional ``ctx`` -- an object of any size:
  over ``FREE_LIMIT`` the machine cuts it where it writes the line
  (``events.cut_ctx``), so its size is no conformance (owner's decision of
  25.10: only ``app``; images of others -- nginx, postgres -- write no JSON by
  construction);
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
a field, a line number, a route. A name the application gave (its
``service``, a check, a field it should not have) is shown cut: a string to
``VALUE_LIMIT`` characters, a list to ``LIST_LIMIT`` names, anything but a
string by its JSON type (``shown``) -- the verdict carries no more of the
application than that (DM-81).

What is read has a bound (DM-81): a line of a command's output longer than
the runner's ``LINE_LIMIT`` comes in pieces and is joined back (``continued``),
up to ``LINE_LIMIT_JOINED`` -- a log line over it is ``log-too-long``, never
parsed; ``GET`` reads at most ``BODY_LIMIT`` bytes within ``HTTP_DEADLINE_S``
-- a ``/health`` over it is ``health-too-big``, a body still coming at the
deadline is nothing answered.

The step that calls it (``up``, DM-18) turns a non-empty list into its own
code, ``up:conformance``, with ``problems_param`` as its parameter.

``python -m pridem.conformance.stack --selftest`` plants every defect the
checks must catch into a conforming observation and exits 1 if one is missed.
"""

import http.client
import json
import re
import sys
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field, replace
from pathlib import Path

from pridem.events import FREE_LIMIT, Json, free_size
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
HEALTH_OPTIONAL = "details"
LOG_FIELDS = ("ts", "level", "service", "release", "request_id", "event", "msg")
LOG_OPTIONAL = "ctx"
LOG_TAIL = 50
HTTP_TIMEOUT_S = 5.0
HTTP_DEADLINE_S = 15.0
"""The whole of one ``GET``, its body included: a body sent byte by byte
inside each socket timeout ends here."""
BODY_LIMIT = 65536
"""The most of ``/health`` and ``/ready`` read: eleven fields and ``details``
of at most ``FREE_LIMIT`` fit many times over."""
LINE_LIMIT_JOINED = 1024 * 1024
"""The longest line of a command's output joined back from its pieces."""
VALUE_LIMIT = 64
LIST_LIMIT = 8
COMMAND_TIMEOUT_S = 120
NETWORK = "pridem"
_SIZE = re.compile(r"(\d+)([kKmMgG]?)")
_MULTIPLE = {"": 1, "k": 1024, "m": 1024**2, "g": 1024**3}
MIB = 1024**2

Stack = Product | Service


def shown(value: Json) -> Json:
    """What a problem carries of a value the application gave: a string cut
    to ``VALUE_LIMIT`` characters (``...+<n>`` says how many more), a list
    cut to ``LIST_LIMIT`` of them (each shown), anything else by its JSON
    type, ``<object>`` and the like -- never more of it."""
    if isinstance(value, str):
        if len(value) <= VALUE_LIMIT:
            return value
        return f"{value[:VALUE_LIMIT]}...+{len(value) - VALUE_LIMIT}"
    if isinstance(value, list):
        head: list[Json] = [shown(item) for item in value[:LIST_LIMIT]]
        if len(value) > LIST_LIMIT:
            head.append(f"...+{len(value) - LIST_LIMIT}")
        return head
    return f"<{_json_type(value)}>"


def _json_type(value: Json) -> str:
    match value:
        case bool():
            return "boolean"
        case int() | float():
            return "number"
        case dict():
            return "object"
        case None:
            return "null"
        case _:
            return "value"


class BodyTooBig(Exception):
    """``GET`` answered ``status`` with a body over its limit."""

    def __init__(self, status: int, limit: int) -> None:
        super().__init__(status, limit)
        self.status = status
        self.limit = limit


@dataclass(frozen=True)
class Problem:
    """What is wrong, by name; of a value the application gave, only what
    ``shown`` leaves of it."""

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
    long_lines: frozenset[int] = frozenset()
    """Numbers (from 1) of the lines of ``logs`` over ``LINE_LIMIT_JOINED``:
    the line holds only its first piece."""
    health_too_big: bool = False
    """``/health`` answered over ``BODY_LIMIT``: ``health`` is ``None``."""


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


def check_health(
    body: bytes | None, *, migrate: bool, stack_name: str, too_big: bool = False
) -> list[Problem]:
    """``/health`` against the form of protocol 9.1. ``service`` is the name of
    the stack (``stack_name``, not of its entry): another name is
    ``health-service``; a field missing or not a string stays ``health-field``
    -- one cause, one code."""
    if too_big:
        return [Problem("health-too-big", {"limit": BODY_LIMIT})]
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
        elif name == "service" and document[name] != stack_name:
            out.append(
                Problem(
                    "health-service",
                    {"service": shown(document[name]), "stack": stack_name},
                )
            )
    for name in document:
        if name not in (*HEALTH_FIELDS, HEALTH_OPTIONAL):
            out.append(
                Problem("health-field", {"field": shown(name), "problem": "extra"})
            )
    if HEALTH_OPTIONAL in document:
        details = document[HEALTH_OPTIONAL]
        if not isinstance(details, dict):
            out.append(
                Problem("health-field", {"field": HEALTH_OPTIONAL, "problem": "type"})
            )
        elif free_size(details) > FREE_LIMIT:
            out.append(
                Problem("health-field", {"field": HEALTH_OPTIONAL, "problem": "size"})
            )
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
        out.append(Problem("health-degraded", {"checks": shown(list[Json](failing))}))
    degraded = document.get("status") == "degraded"
    head = document.get("alembic_head", "<absent>")
    if migrate and head is None and not degraded:  # degraded: its head is not read
        out.append(Problem("alembic-head-null"))
    return out


def check_ready(status: int | None) -> list[Problem]:
    if status is None:
        return [Problem("ready-unreachable")]
    if status != 200:
        return [Problem("ready", {"status": status})]
    return []


def check_logs(
    lines: Sequence[str], *, stack_name: str, long_lines: frozenset[int] = frozenset()
) -> list[Problem]:
    """Every line a JSON object with the fields of protocol 9.4, ``ctx`` an
    object if it is there, ``service`` the name of the stack (``log-service``;
    a line without ``service`` stays ``log-fields``)."""
    if not lines:
        return [Problem("logs-empty")]
    out: list[Problem] = []
    for number, line in enumerate(lines, start=1):
        if number in long_lines:
            out.append(
                Problem("log-too-long", {"line": number, "limit": LINE_LIMIT_JOINED})
            )
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            out.append(Problem("log-not-json", {"line": number}))
            continue
        if not isinstance(record, dict):
            out.append(Problem("log-not-json", {"line": number}))
            continue
        missing = [name for name in LOG_FIELDS if name not in record]
        extra = sorted(
            str(name) for name in record if name not in (*LOG_FIELDS, LOG_OPTIONAL)
        )
        if LOG_OPTIONAL in record and not isinstance(record[LOG_OPTIONAL], dict):
            out.append(Problem("log-ctx", {"line": number}))
        if "service" in record and record["service"] != stack_name:
            given: Json = shown(record["service"])
            out.append(
                Problem(
                    "log-service",
                    {"line": number, "service": given, "stack": stack_name},
                )
            )
        if missing or extra:
            out.append(
                Problem(
                    "log-fields",
                    {
                        "line": number,
                        "missing": list[Json](missing),
                        "extra": shown(list[Json](extra)),
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
            out += check_health(
                observed.health,
                migrate=stage.migrate is not None,
                stack_name=stack.name,
                too_big=observed.health_too_big,
            )
            out += check_ready(observed.ready)
            out += check_max_body(stack, entry, observed.health)
        if observed.running:
            out += check_logs(
                observed.logs, stack_name=stack.name, long_lines=observed.long_lines
            )
    out += check_compose(observed.configs)
    return out


# --- what is seen -----------------------------------------------------------------


def _out(ctx: StepContext, argv: list[str]) -> list[str]:
    """stdout of ``argv``, kept by the check: none of it reaches the sinks."""
    return _read(ctx, argv)[0]


def _read(ctx: StepContext, argv: list[str]) -> tuple[list[str], frozenset[int]]:
    """stdout of ``argv`` by line, a line in pieces (``continued``) joined
    back up to ``LINE_LIMIT_JOINED``; and the numbers (from 1) of the lines
    over it, which keep only what fits."""
    lines: list[str] = []
    long: set[int] = set()
    joining = False

    def keep(stream: Stream, line: str, cut: bool) -> None:
        nonlocal joining
        if stream is not Stream.STDOUT:
            return
        if joining and lines:
            if len(lines) not in long:
                if len(lines[-1]) + len(line) > LINE_LIMIT_JOINED:
                    long.add(len(lines))
                else:
                    lines[-1] += line
        else:
            lines.append(line)
        joining = cut

    ctx.runner.run(argv, timeout=COMMAND_TIMEOUT_S, on_line=keep)
    return lines, frozenset(long)


def http_get(
    address: str,
    port: int,
    path: str,
    *,
    limit: int,
    deadline_s: float = HTTP_DEADLINE_S,
    clock: Callable[[], float] = time.monotonic,
) -> tuple[int, bytes] | None:
    """``GET`` of the app at ``address``; ``None`` -- nothing answered, or the
    body still coming at ``deadline_s``. A body over ``limit`` bytes is
    ``BodyTooBig``: at most ``limit + 1`` bytes are read."""
    connection = http.client.HTTPConnection(address, port, timeout=HTTP_TIMEOUT_S)
    end = clock() + deadline_s
    try:
        connection.request("GET", path)
        response = connection.getresponse()
        body = b""
        while len(body) <= limit:
            if clock() >= end:
                return None
            chunk = response.read1(min(65536, limit + 1 - len(body)))
            if not chunk:
                return response.status, body
            body += chunk
        raise BodyTooBig(response.status, limit)
    except (OSError, http.client.HTTPException):
        return None
    finally:
        connection.close()


def app_address(
    ctx: StepContext, own: Sequence[str], service: str
) -> tuple[bool, str | None]:
    """Whether ``service`` runs, and its address on the network ``pridem``."""
    ids = [line for line in _out(ctx, [*own, "ps", "-q", service]) if line.strip()]
    if not ids:
        return False, None
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
    return True, address if isinstance(address, str) and address else None


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
    running, address = app_address(ctx, own, app.service)
    if not running:
        return Observed(False, None, None, None, [], configs)
    health = ready = None
    too_big = False
    if address is not None:
        try:
            got = http_get(address, app.port, app.health, limit=BODY_LIMIT)
            health = None if got is None else got[1]
        except BodyTooBig:
            too_big = True
        try:
            answered = http_get(address, app.port, app.ready, limit=BODY_LIMIT)
            ready = None if answered is None else answered[0]
        except BodyTooBig as error:
            ready = error.status  # /ready is its status; the body is not read
    logs, long_lines = _read(
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
    return Observed(
        True,
        address,
        health,
        ready,
        logs,
        configs,
        long_lines=long_lines,
        health_too_big=too_big,
    )


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
        # an eighth field alone that is not ctx: an extra one is red too
        ("log-fields", with_(replace(good, logs=[_GOOD_LOG[:-1] + ', "trace": "t"}']))),
        ("log-ctx", with_(replace(good, logs=[_GOOD_LOG[:-1] + ', "ctx": "job 7"}']))),
        # DM-72: a name that is not the stack's, in /health and in a line
        ("health-service", with_(replace(good, health=_health(service="other")))),
        (
            "log-service",
            with_(
                replace(
                    good,
                    logs=[
                        _GOOD_LOG.replace('"service": "blank"', '"service": "other"')
                    ],
                )
            ),
        ),
        ("health-field", with_(replace(good, health=_health(details=[1])))),
        (
            "health-field",
            with_(replace(good, health=_health(details={"x": "y" * FREE_LIMIT}))),
        ),
        ("max-body", with_(good, "2M")),
        ("max-body", with_(good, "1000k")),
        (
            "compose-logging",
            with_(replace(good, configs={"docker-compose.yml": logging_config})),
        ),
        # DM-81: what is over its bound is named, never read
        ("health-too-big", with_(replace(good, health=None, health_too_big=True))),
        ("log-too-long", with_(replace(good, long_lines=frozenset({1})))),
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
