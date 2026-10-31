"""A blank-like stack, its compose config, and the commands of build, migrate
and up as a strict ``FakeRunner`` script (DM-18).

``app`` answers over real HTTP on localhost (``LiveApp``): ``observe`` of
DM-15 reaches it at the address ``docker inspect`` reports.
"""

import json
import threading
from collections.abc import Iterator, Mapping, Sequence
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, HTTPServer
from itertools import count
from pathlib import Path

from plan_support import ListSink

from pridem.events import Json, PlanOutcome
from pridem.plan import Plan, StackSteps
from pridem.runner import FakeCall, Runner, Stream
from pridem.stacks.schema import PRIMER_YAML, Product
from pridem.steps.base import Step
from pridem.steps.compose import ComposeStack

ENTRY = "blank"
REF = "main"
SHA = "0e82be562d186afc933b8779d91dddcae4278cea"
OLD_SHA = "1" * 40
APP_IMAGE = "sha256:" + "a" * 64
FRONT_IMAGE = "sha256:" + "f" * 64
OLD_IMAGE = "sha256:" + "0" * 64
CONTAINER = "c0ffee"
HEAD = "0001"
CONFIG: dict[str, Json] = {
    "name": "blank",
    "services": {
        "app": {
            "build": {"context": "/r/backend", "dockerfile": "Dockerfile"},
            "networks": {"default": None},
        },
        "frontend": {
            "build": {"context": "/r/frontend", "dockerfile": "Dockerfile"},
            "networks": {"default": None},
        },
        "postgres": {"image": "postgres@sha256:x", "networks": {"default": None}},
    },
    "networks": {"default": {"name": "blank_default"}},
    "volumes": {"pgdata": {"name": "blank_pgdata"}},
}
LOG = json.dumps(
    {
        "ts": "2026-10-31T00:00:00.000Z",
        "level": "info",
        "service": "blank",
        "release": REF,
        "request_id": "0123abcd",
        "event": "uvicorn.access",
        "msg": "GET /health 200",
    }
)


def health(**change: Json) -> dict[str, Json]:
    document: dict[str, Json] = {
        "service": "blank",
        "release": REF,
        "commit": SHA,
        "alembic_head": HEAD,
        "uptime_s": 3,
        "status": "ok",
        "checks": {"db": "ok"},
        "seams": {"provides": [], "requires_satisfied": True},
        "limits": {"max_upload_mb": 1},
        "edition": "core",
        "modules": ["core"],
    }
    document.update(change)
    return document


def blank(port: int = 8000) -> Product:
    made = PRIMER_YAML.validate_python(
        {
            "schema": 1,
            "name": "blank",
            "kind": "product",
            "editions": {"core": {"services": []}},
            "stacks": {
                "blank": {
                    "compose": "docker-compose.yml",
                    "app": {
                        "service": "app",
                        "port": port,
                        "health": "/health",
                        "ready": "/ready",
                    },
                    "frontend": {"service": "frontend", "port": 80},
                    "migrate": "python -m alembic upgrade head",
                }
            },
            "env": {},
            "host": {
                "domains": ["api"],
                "routes": {"api": {"to": f"app:{port}", "max_body": "1M"}},
            },
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


def compose(root: Path, port: int = 8000, commit: str = SHA) -> ComposeStack:
    return ComposeStack(blank(port), ENTRY, root / "release", REF, commit, root)


def stdout(*lines: str) -> tuple[tuple[Stream, str], ...]:
    return tuple((Stream.STDOUT, line) for line in lines)


# --- the script of commands -----------------------------------------------------


def config_call(cs: ComposeStack, document: Mapping[str, Json] = CONFIG) -> FakeCall:
    return FakeCall(
        tuple(cs.product_argv("config", "--format", "json")),
        lines=stdout(json.dumps(document)),
    )


def image_call(cs: ComposeStack, service: str, *ids: str) -> FakeCall:
    return FakeCall(
        (
            "docker",
            "image",
            "ls",
            "--quiet",
            "--no-trunc",
            "--filter",
            f"label=pridem.stack={cs.entry}",
            "--filter",
            f"label=pridem.commit={cs.commit}",
            "--filter",
            f"label=pridem.service={service}",
        ),
        lines=stdout(*ids),
    )


def build_call(cs: ComposeStack, code: int = 0) -> FakeCall:
    return FakeCall(
        tuple(
            cs.argv(
                "build",
                "--build-arg",
                f"PRIMER_RELEASE={cs.ref}",
                "--build-arg",
                f"PRIMER_COMMIT={cs.commit}",
            )
        ),
        code=code,
        lines=stdout("built"),
    )


def ps_call(cs: ComposeStack, *ids: str) -> FakeCall:
    return FakeCall(tuple(cs.argv("ps", "-q", "app")), lines=stdout(*ids))


def inspect_image_call(container: str, image: str) -> FakeCall:
    return FakeCall(
        ("docker", "inspect", "-f", "{{.Image}}", container), lines=stdout(image)
    )


def alembic_call(cs: ComposeStack, what: str, *lines: str, deps: bool) -> FakeCall:
    throwaway = ("run", "--rm") if deps else ("run", "--rm", "--no-deps")
    return FakeCall(
        tuple(cs.argv(*throwaway, "app", "python", "-m", "alembic", what)),
        lines=stdout(*lines),
    )


def migrate_call(cs: ComposeStack, code: int = 0) -> FakeCall:
    return FakeCall(
        tuple(
            cs.argv("run", "--rm", "app", "python", "-m", "alembic", "upgrade", "head")
        ),
        code=code,
    )


def up_call(cs: ComposeStack, code: int = 0) -> FakeCall:
    return FakeCall(
        tuple(cs.argv("up", "-d", "--no-build", "--wait", "--wait-timeout", "300")),
        code=code,
    )


def observe_calls(
    cs: ComposeStack, *, running: bool = True, logs: Sequence[str] = (LOG,)
) -> list[FakeCall]:
    """What ``observe`` of DM-15 runs: config, ps, inspect, logs."""
    own = cs.product_argv()
    calls = [
        config_call(cs),
        FakeCall(
            (*own, "ps", "-q", "app"), lines=stdout(*([CONTAINER] if running else []))
        ),
    ]
    if not running:
        return calls
    networks = {"pridem": {"IPAddress": "127.0.0.1"}}
    return [
        *calls,
        FakeCall(
            (
                "docker",
                "inspect",
                "-f",
                "{{json .NetworkSettings.Networks}}",
                CONTAINER,
            ),
            lines=stdout(json.dumps(networks)),
        ),
        FakeCall(
            (*own, "logs", "--no-color", "--no-log-prefix", "--tail", "50", "app"),
            lines=stdout(*logs),
        ),
    ]


# --- the live app ---------------------------------------------------------------


class LiveApp:
    """A real HTTP app on localhost whose ``/health`` the test sets."""

    def __init__(self) -> None:
        self.health: dict[str, Json] = health()
        owner = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:  # noqa: N802 -- the stdlib's name
                if self.path == "/health":
                    body = json.dumps(owner.health).encode()
                elif self.path == "/ready":
                    body = b"{}"
                else:
                    self.send_response(404)
                    self.end_headers()
                    return
                self.send_response(200)
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, format: str, *args: object) -> None:
                return

        self.server = HTTPServer(("127.0.0.1", 0), Handler)
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()


def live() -> Iterator[LiveApp]:
    app = LiveApp()
    try:
        yield app
    finally:
        app.close()


def run(
    steps: Sequence[Step],
    runner: Runner,
    *,
    mode: str = "install",
    restore: Sequence[Step] = (),
) -> tuple[PlanOutcome, ListSink]:
    ticks = count()
    sink = ListSink()
    outcome = Plan(
        [StackSteps(ENTRY, steps, root=True)],
        mode=mode,  # type: ignore[arg-type]
        role="test",
        runner=runner,
        sink=sink,
        clock=lambda: float(next(ticks)),
        now=lambda: datetime(2026, 10, 31, tzinfo=UTC),
        restore=[StackSteps(ENTRY, restore, root=True)] if restore else (),
    ).run()
    return outcome, sink
