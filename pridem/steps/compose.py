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
- the external network ``pridem`` and, on the ``app`` service and on every
  service a route of ``host.routes`` goes to, the alias ``<entry>-<service>``
  (TZ 7.3; nginx and the ``address`` source reach it there) next to the
  networks the service already had -- a service's ``networks`` in an override
  replaces the implicit ``default``, so the override names it.

``down``, ``rm`` and ``--remove-orphans`` are never part of a command.

``forbidden`` is the trust boundary of a stack's compose, read from the same
``config`` output (anchors, ``extends`` and relative paths already resolved;
top-level ``x-`` keys are not services and are not read): what would give a
container the host is refused before anything is built (contract 3 rules 9,
12; TZ 7.3). A service may not be ``privileged``, add capabilities, take
devices, share a namespace of the host (``pid``, ``ipc``, ``network_mode``,
``userns_mode``, ``cgroup``) or another container's (``network_mode`` or
``volumes_from`` ``container:``), drop its confinement (``security_opt``
``unconfined``, ``label:disable``), mount ``docker.sock``, bind or build from
a path that resolves out of the release (a symlink of the release counts
where it leads), or publish a port of the host its stack does not declare in
``host.ports`` (a product declares none). A named volume that binds a path out
of the release, a ``configs`` or ``secrets`` file out of it, and a package
mounted into a service the compose does not have are refused the same way.
"""

import json
import os
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

from pridem.events import Json, as_list
from pridem.files import atomic_write
from pridem.runner import Stream
from pridem.stacks.routes import alias, routed_services
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


_HOST_NAMESPACES = ("pid", "ipc", "network_mode", "userns_mode", "cgroup")
_UNCONFINED = re.compile(r"^(?:[a-z_]+[:=]unconfined|label[:=]disable)$")


def _within(path: str, release: Path) -> bool:
    """``path`` resolves into ``release`` (a symlink counts where it leads)."""
    real = Path(os.path.realpath(path))
    return real.is_relative_to(Path(os.path.realpath(release)))


def _socket(path: str) -> bool:
    return "docker.sock" in (Path(path).name, Path(os.path.realpath(path)).name)


def _item(value: Json) -> str:
    """One element of a compose list as it reads: a string, or its source."""
    if isinstance(value, dict):
        return str(value.get("source", json.dumps(value, sort_keys=True)))
    return str(value)


def _service_problems(
    body: Mapping[str, Json], release: Path, declared: set[tuple[str, int]]
) -> list[str]:
    found: list[str] = []
    if body.get("privileged") is True:
        found.append("privileged")
    found += [f"cap_add={_item(cap)}" for cap in as_list(body.get("cap_add"))]
    found += [f"devices={_item(dev)}" for dev in as_list(body.get("devices"))]
    for key in _HOST_NAMESPACES:
        if body.get(key) == "host":
            found.append(f"{key}=host")
    mode = body.get("network_mode")
    if isinstance(mode, str) and mode.startswith("container:"):
        found.append(f"network_mode={mode}")
    for option in as_list(body.get("security_opt")):
        if _UNCONFINED.match(_item(option)):
            found.append(f"security_opt={_item(option)}")
    for source in as_list(body.get("volumes_from")):
        if _item(source).startswith("container:"):
            found.append(f"volumes_from={_item(source)}")
    for volume in as_list(body.get("volumes")):
        mount = _mapping(volume)
        if mount.get("type") != "bind":
            continue
        source = str(mount.get("source", ""))
        if _socket(source):
            found.append("volumes=docker.sock")
        elif not _within(source, release):
            found.append(f"volumes={source}")
    build = _mapping(body.get("build"))
    context = build.get("context")
    if isinstance(context, str):
        dockerfile = build.get("dockerfile")
        if not _within(context, release):
            found.append(f"build.context={context}")
        elif isinstance(dockerfile, str):
            path = os.path.join(context, dockerfile)  # an absolute one stays
            if not _within(path, release):
                found.append(f"build.dockerfile={dockerfile}")
    for port in as_list(body.get("ports")):
        entry = _mapping(port)
        proto = str(entry.get("protocol", "tcp"))
        published = entry.get("published")
        if published is None:  # a port of the host all the same: a random one
            found.append(f"ports={entry.get('target')}/{proto} on a random port")
        elif (
            not str(published).isdigit() or (proto, int(str(published))) not in declared
        ):
            found.append(f"ports={published}/{proto}")
    return found


def forbidden(
    compose: ComposeStack,
    document: Mapping[str, Json],
    mounts: Sequence[tuple[str, str]] = (),
) -> list[str]:
    """What the compose ``document`` asks of the host beyond the stack's trust,
    one ``<where>: <key>`` per finding, sorted; ``mounts`` -- the packages'
    ``(slot, service)`` the machine would bind."""
    release = compose.release
    stack = compose.stack
    declared: set[tuple[str, int]] = set()
    if isinstance(stack, Service) and stack.host is not None:
        declared = {(port.proto, int(port.port)) for port in stack.host.ports}
    services = _mapping(document.get("services"))
    found: list[str] = []
    for name, body in services.items():
        problems = _service_problems(_mapping(body), release, declared)
        found += [f"{name}: {problem}" for problem in problems]
    for name, body in _mapping(document.get("volumes")).items():
        device = _mapping(_mapping(body).get("driver_opts")).get("device")
        if device is not None and not _within(str(device), release):
            found.append(f"volumes.{name}: driver_opts.device={device}")
    for kind in ("configs", "secrets"):
        for name, body in _mapping(document.get(kind)).items():
            file = _mapping(body).get("file")
            if isinstance(file, str) and not _within(file, release):
                found.append(f"{kind}.{name}: file={file}")
    for slot, service in mounts:
        if service not in services:
            found.append(f"{service}: packages.{slot}.mount (no such service)")
    return sorted(found)


def built_services(document: Mapping[str, Json]) -> list[str]:
    services = _mapping(document.get("services"))
    return sorted(name for name, body in services.items() if "build" in _mapping(body))


def override_text(
    compose: ComposeStack,
    document: Mapping[str, Json],
    mounts: Mapping[str, Sequence[str]] | None = None,
) -> str:
    """The machine's override for the product's compose ``document``;
    ``mounts`` -- read-only binds of the instance's packages by service."""
    services: dict[str, Json] = {}
    app = compose.app_service
    aliased = {app} if app is not None else set()
    if isinstance(compose.stack, Product):
        aliased |= set(routed_services(compose.stack, compose.entry))
    for name, body in sorted(_mapping(document.get("services")).items()):
        part: dict[str, Json] = {"labels": dict[str, Json](compose.release_labels())}
        if "build" in _mapping(body):
            labels: dict[str, Json] = {
                **compose.release_labels(),
                "pridem.service": name,
            }
            part["build"] = {"labels": labels}
        if name in aliased:
            networks: dict[str, Json] = dict(_mapping(_mapping(body).get("networks")))
            if not networks:
                networks["default"] = None
            networks[NETWORK] = {"aliases": [alias(compose.entry, name)]}
            part["networks"] = networks
        binds = (mounts or {}).get(name)
        if binds:
            part["volumes"] = list[Json](binds)
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
    """The override file, replaced whole by ``atomic_write`` (0644)."""
    path = compose.override
    path.parent.mkdir(parents=True, exist_ok=True)
    atomic_write(path, text, 0o644)


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
