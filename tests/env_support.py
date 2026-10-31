"""Stacks, passports and plans for the env and seams tests (DM-14).

A stack is written as a ``primer.yaml`` and loaded by the machine's loader, so
the model's rules hold for every fixture; a passport is written as the box's
local copy and loaded from it, as ``fetch_passport`` leaves it.
"""

from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from itertools import count
from pathlib import Path
from typing import Protocol

import yaml
from passport_support import passport_example
from plan_support import ListSink

from pridem.events import Event, PlanOutcome, Secrets
from pridem.plan import Plan, StackSteps
from pridem.runner import Runner, Stream
from pridem.stacks.passport import load_passport
from pridem.stacks.schema import Product, Service, load_primer_yaml
from pridem.stacks.seams import SeamMemory
from pridem.steps.base import Step, StepContext
from pridem.steps.env import RenderEnv
from pridem.steps.passport import PASSPORT_COPY, Ask, Fetched

Data = dict[str, object]
IMAGE = "sha256:" + "0" * 64
REPORT = {"health": "/health", "ready": "/ready", "logs": "json", "junit": True}
COMMS_REPO = {"repo": "git@github.com:acme/comms.git", "version": ">=3.0,<4"}


class Sink(Protocol):
    """Any sink: what a test passes to a plan to watch its events."""

    def emit(self, event: Event) -> None: ...


def product_data(
    env: Mapping[str, object],
    *,
    dependencies: Mapping[str, object] | None = None,
    provides: Mapping[str, object] | None = None,
    editions: Mapping[str, object] | None = None,
    domains: Sequence[str] = (),
) -> Data:
    data: Data = {
        "schema": 1,
        "name": "aivis",
        "kind": "product",
        "dependencies": dict(dependencies or {}),
        "editions": dict(editions or {}),
        "stacks": {
            "aivis": {
                "compose": "docker-compose.yml",
                "app": {"service": "app", "port": 8000, "health": "/h", "ready": "/r"},
            }
        },
        "env": dict(env),
        "provides": dict(provides or {}),
        "report": REPORT,
    }
    if domains:
        data["host"] = {"domains": list(domains)}
    return data


def service_data(
    env: Mapping[str, object],
    *,
    provides: Sequence[str] = (),
    requires: Sequence[str] = (),
) -> Data:
    return {
        "schema": 1,
        "name": "comms",
        "kind": "service",
        "stacks": {
            "comms": {
                "compose": "deploy/docker-compose.yml",
                "app": {
                    "service": "comms-app",
                    "port": 8000,
                    "health": "/health",
                    "ready": "/ready",
                },
            }
        },
        "env": dict(env),
        "provides": list(provides),
        "requires": list(requires),
        "report": REPORT,
    }


def load(tmp: Path, data: Data) -> Product | Service:
    """``data`` through the machine's ``primer.yaml`` loader, rules included."""
    file = tmp / f"{data['name']}-primer.yaml"
    file.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
    return load_primer_yaml(file)


def product(tmp: Path, env: Mapping[str, object], **parts: object) -> Product:
    stack = load(tmp, product_data(env, **parts))  # type: ignore[arg-type]
    assert isinstance(stack, Product)
    return stack


def service(tmp: Path, env: Mapping[str, object], **parts: object) -> Service:
    stack = load(tmp, service_data(env, **parts))  # type: ignore[arg-type]
    assert isinstance(stack, Service)
    return stack


def passport_data(
    *,
    asked: Mapping[str, Mapping[str, str]] | None = None,
    params: Mapping[str, Mapping[str, str]] | None = None,
    domains: Mapping[str, str] | None = None,
    edition: str | None = "full",
) -> Data:
    data = passport_example()
    data["asked"] = {k: dict(v) for k, v in (asked or {}).items()}
    data["params"] = {k: dict(v) for k, v in (params or {}).items()}
    data["domains"] = dict(
        domains if domains is not None else {"frontend": "a.example.org"}
    )
    data["packages"] = {}
    if edition is None:
        data.pop("edition", None)
    else:
        data["edition"] = edition
    return data


def box(tmp: Path, data: Data) -> tuple[Path, Fetched]:
    """A box whose local copy of the passport is ``data``, as fetched."""
    root = tmp / "box"
    copy = root / PASSPORT_COPY
    copy.parent.mkdir(parents=True, exist_ok=True)
    copy.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
    copy.chmod(0o600)
    return root, Fetched(passport=load_passport(copy))


def render(
    stack: Product | Service,
    root: Path,
    fetched: Fetched,
    *,
    product: Product | None = None,
    secrets: Secrets | None = None,
    memory: SeamMemory | None = None,
    ask: Ask | None = None,
    image: str | None = None,
) -> RenderEnv:
    owner = product if product is not None else stack
    assert isinstance(owner, Product)
    return RenderEnv(
        stack,
        product=owner,
        fetched=fetched,
        secrets=Secrets(()) if secrets is None else secrets,
        memory=SeamMemory() if memory is None else memory,
        root=root,
        ask=ask,
        image=image,
    )


def run(
    steps: Sequence[Step],
    runner: Runner,
    *,
    mode: str = "install",
    sink: Sink | None = None,
) -> tuple[PlanOutcome, ListSink]:
    ticks = count()
    seen = ListSink()

    class Both:
        def emit(self, event: Event) -> None:
            seen.emit(event)
            if sink is not None:
                sink.emit(event)

    outcome = Plan(
        [StackSteps("stack", steps, root=True)],
        mode=mode,  # type: ignore[arg-type]
        role="test",
        runner=runner,
        sink=Both(),
        clock=lambda: float(next(ticks)),
        now=lambda: datetime(2026, 10, 31, tzinfo=UTC),
    ).run()
    return outcome, seen


def context(runner: Runner) -> StepContext:
    return StepContext(
        runner=runner,
        mode="install",
        role="test",
        stack="stack",
        on_line=lambda stream, line, cut: None,
    )


def printed(sink: ListSink) -> str:
    return "\n".join(event.line for event in sink.lines())


def env_of(root: Path, name: str) -> Path:
    return root / "opt" / name / "env" / ".env"


def minted_of(root: Path, name: str) -> Path:
    return root / "opt" / name / "env" / "minted.yaml"


def read_env(root: Path, name: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for line in env_of(root, name).read_text(encoding="utf-8").splitlines():
        key, _, quoted = line.partition("=")
        out[key] = quoted[1:-1]
    return out


STDOUT = Stream.STDOUT
STDERR = Stream.STDERR
