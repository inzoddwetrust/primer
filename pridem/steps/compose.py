"""Compose of one entry of ``stacks`` as the machine runs it (TZ 7.3).

Every command is ``docker compose -p <entry> --env-file /opt/<name>/env/.env
-f <release>/<compose> -f /opt/<name>/compose/<entry>.yml``: the project name
is the machine's, the env is the rendered one (DM-14), the product's compose
is read from the immutable release, and the second file is the machine's own
override. The product's compose is never changed (contract 3 rule 9).

The override is rendered from ``docker compose config --format json`` of the
product's file and carries what the machine adds:

- labels ``pridem.stack``, ``pridem.release``, ``pridem.commit`` on every
  service (its containers) and on every ``build`` (its image, plus
  ``pridem.service``): ``gc`` cleans by them;
- the label ``pridem.stack`` alone on the project's volumes and on its
  network ``default``: they outlive releases, and a release label would put a
  database volume under the clean-up of old releases;
- the external network ``pridem`` and, on the ``app`` service, the alias
  ``<name>-<app.service>`` (the ``address`` source, contract 3) next to the
  networks the service already had -- a service's ``networks`` in an override
  replaces the implicit ``default``, so the override names it.

``down``, ``rm`` and ``--remove-orphans`` are never part of a command.
"""

import json
import os
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

from pridem.events import Json
from pridem.runner import Stream
from pridem.stacks.schema import Product, Service
from pridem.steps.base import StepContext

NETWORK = "pridem"
COMMAND_TIMEOUT_S = 120
BUILD_TIMEOUT_S = 3600
UP_WAIT_S = 300
_HEAD = re.compile(r"^(\S+) \(head\)")
_CURRENT = re.compile(r"^([0-9A-Za-z_]+)(?: \(head\))?$")

Stack = Product | Service


@dataclass(frozen=True)
class ComposeStack:
    """One entry of ``stacks`` at one release of its repository."""

    stack: Stack
    entry: str
    release: Path
    ref: str
    commit: str
    root: Path = Path("/")

    @property
    def name(self) -> str:
        return self.stack.name

    @property
    def project(self) -> str:
        return self.entry

    @property
    def env_file(self) -> Path:
        return self.root / "opt" / self.name / "env" / ".env"

    @property
    def compose_file(self) -> Path:
        return self.release / self.stack.stacks[self.entry].compose

    @property
    def override(self) -> Path:
        return self.root / "opt" / self.name / "compose" / f"{self.entry}.yml"

    @property
    def app_service(self) -> str | None:
        app = self.stack.stacks[self.entry].app
        return None if app is None else app.service

    def product_argv(self, *args: str) -> list[str]:
        """Compose of the product's file alone (what ``config`` reads)."""
        return [
            "docker",
            "compose",
            "-p",
            self.project,
            "--env-file",
            str(self.env_file),
            "-f",
            str(self.compose_file),
            *args,
        ]

    def argv(self, *args: str) -> list[str]:
        """Compose of the product's file with the machine's override."""
        return [
            "docker",
            "compose",
            "-p",
            self.project,
            "--env-file",
            str(self.env_file),
            "-f",
            str(self.compose_file),
            "-f",
            str(self.override),
            *args,
        ]

    def stack_labels(self) -> dict[str, str]:
        return {"pridem.stack": self.entry}

    def release_labels(self) -> dict[str, str]:
        return {
            "pridem.stack": self.entry,
            "pridem.release": self.ref,
            "pridem.commit": self.commit,
        }


def out(
    ctx: StepContext,
    argv: Sequence[str],
    *,
    expect: tuple[int, ...] = (0,),
    timeout: float = COMMAND_TIMEOUT_S,
    passed_on: bool = True,
) -> tuple[int, list[str]]:
    """Run ``argv``; its exit code and stdout lines. ``passed_on`` -- every line
    also goes to the run's sinks (a build's output); off -- kept by the step
    (JSON a step parses)."""
    lines: list[str] = []

    def keep(stream: Stream, line: str, cut: bool) -> None:
        if passed_on:
            ctx.on_line(stream, line, cut)
        if stream is Stream.STDOUT:
            lines.append(line)

    result = ctx.runner.run(argv, expect=expect, timeout=timeout, on_line=keep)
    return result.code, lines


def config(ctx: StepContext, compose: ComposeStack) -> dict[str, Json]:
    """``docker compose config --format json`` of the product's file."""
    _, lines = out(
        ctx, compose.product_argv("config", "--format", "json"), passed_on=False
    )
    document = json.loads("\n".join(lines))
    if not isinstance(document, dict):
        raise ValueError("docker compose config did not print an object")
    return document


def _mapping(value: Json | None) -> dict[str, Json]:
    return value if isinstance(value, dict) else {}


def built_services(document: Mapping[str, Json]) -> list[str]:
    services = _mapping(document.get("services"))
    return sorted(name for name, body in services.items() if "build" in _mapping(body))


def override_text(compose: ComposeStack, document: Mapping[str, Json]) -> str:
    """The machine's override for the product's compose ``document``."""
    services: dict[str, Json] = {}
    app = compose.app_service
    for name, body in sorted(_mapping(document.get("services")).items()):
        part: dict[str, Json] = {"labels": dict[str, Json](compose.release_labels())}
        if "build" in _mapping(body):
            labels: dict[str, Json] = {
                **compose.release_labels(),
                "pridem.service": name,
            }
            part["build"] = {"labels": labels}
        if name == app:
            networks: dict[str, Json] = dict(_mapping(_mapping(body).get("networks")))
            if not networks:
                networks["default"] = None
            networks[NETWORK] = {"aliases": [f"{compose.name}-{name}"]}
            part["networks"] = networks
        services[name] = part
    volumes: dict[str, Json] = {
        name: {"labels": dict[str, Json](compose.stack_labels())}
        for name, body in sorted(_mapping(document.get("volumes")).items())
        if not _mapping(body).get("external")
    }
    networks_top: dict[str, Json] = {NETWORK: {"external": True}}
    if "default" in _mapping(document.get("networks")):
        networks_top["default"] = {"labels": dict[str, Json](compose.stack_labels())}
    rendered: dict[str, Json] = {"services": services, "networks": networks_top}
    if volumes:
        rendered["volumes"] = volumes
    return json.dumps(rendered, indent=2, sort_keys=True) + "\n"


def write_override(compose: ComposeStack, text: str) -> None:
    """The override file, replaced whole: temp, fsync, rename."""
    path = compose.override
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_name(path.name + ".tmp")
    try:
        with temp.open("w", encoding="utf-8") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp, path)
    finally:
        temp.unlink(missing_ok=True)


def image_of(ctx: StepContext, compose: ComposeStack, service: str) -> list[str]:
    """IDs of the images built for ``service`` at this commit, by labels."""
    _, lines = out(
        ctx,
        [
            "docker",
            "image",
            "ls",
            "--quiet",
            "--no-trunc",
            "--filter",
            f"label=pridem.stack={compose.entry}",
            "--filter",
            f"label=pridem.commit={compose.commit}",
            "--filter",
            f"label=pridem.service={service}",
        ],
        passed_on=False,
    )
    return sorted({line.strip() for line in lines if line.strip()})


def running_image(ctx: StepContext, compose: ComposeStack, service: str) -> str | None:
    """The image ID the running container of ``service`` was made from."""
    _, ids = out(ctx, compose.argv("ps", "-q", service), passed_on=False)
    found = [line.strip() for line in ids if line.strip()]
    if not found:
        return None
    _, lines = out(
        ctx, ["docker", "inspect", "-f", "{{.Image}}", found[0]], passed_on=False
    )
    return lines[0].strip() if lines else None


def heads(lines: Sequence[str]) -> list[str]:
    return [found.group(1) for line in lines if (found := _HEAD.match(line.strip()))]


def current(lines: Sequence[str]) -> list[str]:
    return [found.group(1) for line in lines if (found := _CURRENT.match(line.strip()))]
