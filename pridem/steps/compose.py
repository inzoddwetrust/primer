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
top-level ``x-`` keys are not services and are not read). It is a list of what
a stack may use, not of what it may not (the owner's decision: anything else
and the instance does not start; contract 3 rules 9, 12; TZ 7.3): a service
has only the keys of ``SERVICE_KEYS``, its ``build`` only those of
``BUILD_KEYS`` and its ``volumes`` are named volumes or binds of the release
(``realpath``: a symlink of the release counts where it leads; ``docker.sock``
is named as such). A port of the host is one its stack declares in
``host.ports`` (a product declares none). A top-level volume or network may
not be ``external``, and a named volume may not bind a path out of the
release. A package mounted into a service the compose does not have is refused
the same way. ``config`` inlines ``env_file`` into ``environment``; its paths
are read from ``config --no-interpolate`` (``env_files_out_of_release``) and
must be in the release too.
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


def config(
    ctx: StepContext, compose: ComposeStack, *, interpolate: bool = True
) -> dict[str, Json]:
    """``docker compose config --format json`` of the product's file; without
    ``interpolate`` -- ``--no-interpolate``, where ``env_file`` is still named."""
    argv = ["config", "--format", "json"] + (
        [] if interpolate else ["--no-interpolate"]
    )
    _, lines = out(ctx, compose.product_argv(*argv), passed_on=False)
    document = json.loads("\n".join(lines))
    if not isinstance(document, dict):
        raise ValueError("docker compose config did not print an object")
    return document


def _mapping(value: Json | None) -> dict[str, Json]:
    return value if isinstance(value, dict) else {}


SERVICE_KEYS = frozenset(
    {
        "image",
        "build",
        "environment",
        "volumes",
        "networks",
        "depends_on",
        "healthcheck",
        "command",
        "entrypoint",
        "restart",
        "ports",
        "labels",
        "user",
        "working_dir",
    }
)
"""What a service may have. ``config`` adds ``command``, ``entrypoint`` (null)
and ``networks`` (``default``) to every service itself -- all on this list."""
BUILD_KEYS = frozenset({"context", "dockerfile", "target", "args"})
"""What a ``build`` may have; ``config`` adds ``dockerfile`` itself."""
VOLUME_KEYS = frozenset({"type", "source", "target", "read_only", "volume", "bind"})
"""What an entry of ``volumes`` may have; ``config`` adds ``volume: {}`` to a
named volume and ``bind: {create_host_path: true}`` to a short bind itself."""
VOLUME_TYPES = frozenset({"volume", "bind"})
BIND_KEYS = frozenset({"create_host_path"})


def _within(path: str, release: Path) -> bool:
    """``path`` resolves into ``release`` (a symlink counts where it leads)."""
    real = Path(os.path.realpath(path))
    return real.is_relative_to(Path(os.path.realpath(release)))


def _socket(path: str) -> bool:
    return "docker.sock" in (Path(path).name, Path(os.path.realpath(path)).name)


def _extra(found: Mapping[str, Json], allowed: frozenset[str]) -> list[str]:
    return sorted(key for key in found if key not in allowed)


def _volume_problems(volume: Mapping[str, Json], release: Path) -> list[str]:
    kind = volume.get("type")
    found = [f"volumes.{key}" for key in _extra(volume, VOLUME_KEYS)]
    found += [
        f"volumes.bind.{key}" for key in _extra(_mapping(volume.get("bind")), BIND_KEYS)
    ]
    if kind not in VOLUME_TYPES:
        found.append(f"volumes type={kind}")
    elif kind == "bind":
        source = str(volume.get("source", ""))
        if _socket(source):
            found.append("volumes=docker.sock")
        elif not _within(source, release):
            found.append(f"volumes={source}")
    return found


def _service_problems(
    body: Mapping[str, Json], release: Path, declared: set[tuple[str, int]]
) -> list[str]:
    found = _extra(body, SERVICE_KEYS)
    for volume in as_list(body.get("volumes")):
        found += _volume_problems(_mapping(volume), release)
    build = _mapping(body.get("build"))
    found += [f"build.{key}" for key in _extra(build, BUILD_KEYS)]
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
        volume = _mapping(body)
        if volume.get("external"):
            found.append(f"volumes.{name}: external")
        device = _mapping(volume.get("driver_opts")).get("device")
        if device is not None and not _within(str(device), release):
            found.append(f"volumes.{name}: driver_opts.device={device}")
    for name, body in _mapping(document.get("networks")).items():
        if _mapping(body).get("external"):
            found.append(f"networks.{name}: external")
    for slot, service in mounts:
        if service not in services:
            found.append(f"{service}: packages.{slot}.mount (no such service)")
    return sorted(found)


def env_files_out_of_release(
    compose: ComposeStack, uninterpolated: Mapping[str, Json]
) -> list[str]:
    """The ``env_file`` paths of ``config --no-interpolate`` (where they are
    still named, absolute, ``extends`` resolved) that are not in the release; a
    path that still holds a variable cannot be checked and is one of them."""
    found: list[str] = []
    for name, body in _mapping(uninterpolated.get("services")).items():
        for entry in as_list(_mapping(body).get("env_file")):
            path = _mapping(entry).get("path") if isinstance(entry, dict) else entry
            text = str(path)
            if "$" in text or not _within(text, compose.release):
                found.append(f"{name}: env_file={text}")
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
