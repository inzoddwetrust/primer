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
has only the keys of ``SERVICE_KEYS`` (protocol 3.3), its ``build`` only those
of ``BUILD_KEYS`` and its ``volumes`` are named volumes or binds of the
release (``realpath``: a symlink of the release counts where it leads;
``docker.sock`` is named as such). A port of the host is one its stack
declares in ``host.ports`` (a product declares none). The top level is a list
too: only the keys of ``TOP_KEYS`` (``x-`` ones are not read); a volume has
only those of ``TOP_VOLUME_KEYS`` -- its ``driver`` is ``local`` or none and
its ``driver_opts`` are exactly a bind of the release -- and a network only
those of ``TOP_NETWORK_KEYS`` -- its ``driver`` is ``bridge`` or none, its
``ipam`` the empty one ``config`` prints itself, and it may be ``internal``.
The ``name`` of either is the one ``config`` gives it under the machine's
project (``<project>_<key>``): another name takes another stack's object past
``-p`` and the labels gc goes by. So ``external`` is refused by the list, and
so are ``labels``, driver options of a network and every driver but these two.
A package mounted into a service the compose does not have is refused the same
way. A service has no ``env_file`` (protocol 3.4: values come from the machine
alone); ``config`` inlines it into ``environment``, so it is read from
``config --no-interpolate`` (``env_files``), where it is still named.
"""

import json
import os
import re
from collections.abc import Iterable, Mapping, Sequence
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

    def checked_argv(self, *args: str) -> list[str]:
        """Compose of the product's file with no env file: what ``pridem
        check`` reads in a repository, its values in the environment."""
        return [
            "docker",
            "compose",
            "-p",
            self.project,
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
    env: Mapping[str, str] | None = None,
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

    result = ctx.runner.run(argv, expect=expect, timeout=timeout, env=env, on_line=keep)
    return result.code, lines


def config(
    ctx: StepContext,
    compose: ComposeStack,
    *,
    interpolate: bool = True,
    values: Mapping[str, str] | None = None,
) -> dict[str, Json]:
    """``docker compose config --format json`` of the product's file; without
    ``interpolate`` -- ``--no-interpolate``, where ``env_file`` and the
    variables are still as written. ``values`` -- the check of a repository
    (``pridem check``): no env file is read or written, the values are the
    environment of compose alone (``PATH``, ``HOME`` and them), and compose's
    own ``.env`` of the directory is off (``COMPOSE_DISABLE_ENV_FILE``)."""
    args = ["config", "--format", "json"] + (
        [] if interpolate else ["--no-interpolate"]
    )
    if values is None:
        _, lines = out(ctx, compose.product_argv(*args), passed_on=False)
    else:
        env = {
            "PATH": os.environ.get("PATH", ""),
            "HOME": os.environ.get("HOME", ""),
            "COMPOSE_DISABLE_ENV_FILE": "true",
            **values,
        }
        _, lines = out(ctx, compose.checked_argv(*args), passed_on=False, env=env)
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
        "stop_grace_period",
        "shm_size",
    }
)
"""What a service may have. ``config`` adds ``command``, ``entrypoint`` (null)
and ``networks`` (``default``) to every service itself -- all on this list."""
BUILD_KEYS = frozenset({"context", "dockerfile", "target"})
"""What a ``build`` may have; ``config`` adds ``dockerfile`` itself. Build
arguments are the machine's (``PRIMER_RELEASE``, ``PRIMER_COMMIT``,
``PRIMER_EDITION``; protocol 3.4): ``args`` is off the list."""
VOLUME_KEYS = frozenset({"type", "source", "target", "read_only", "volume", "bind"})
"""What an entry of ``volumes`` may have; ``config`` adds ``volume: {}`` to a
named volume and ``bind: {create_host_path: true}`` to a short bind itself."""
VOLUME_TYPES = frozenset({"volume", "bind"})
BIND_KEYS = frozenset({"create_host_path"})
TOP_KEYS = frozenset({"name", "services", "volumes", "networks"})
"""What the top level may have (``x-`` keys aside); ``config`` prints ``name``
itself, from ``-p``, and ``configs``/``secrets`` only for a service that uses
them."""
TOP_VOLUME_KEYS = frozenset({"name", "driver", "driver_opts"})
"""What a top-level volume may have; ``config`` gives one ``{}`` its
``name``."""
TOP_NETWORK_KEYS = frozenset({"name", "driver", "ipam", "internal"})
"""What a top-level network may have; ``config`` gives every one its ``name``
and ``ipam: {}``, and prints ``internal`` only when it is ``true``."""
BIND_OPTIONS = frozenset({"type", "o", "device"})


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


def _top_name(kind: str, key: str, body: Mapping[str, Json], project: str) -> list[str]:
    name = body.get("name")
    if name is None or name == f"{project}_{key}":
        return []
    return [f"{kind}.{key}: name={name}"]


def _top_volume_problems(
    key: str, body: Mapping[str, Json], project: str, release: Path
) -> list[str]:
    found = [f"volumes.{key}: {extra}" for extra in _extra(body, TOP_VOLUME_KEYS)]
    found += _top_name("volumes", key, body, project)
    driver = body.get("driver")
    if driver not in (None, "local"):
        found.append(f"volumes.{key}: driver={driver}")
    if "driver_opts" in body:
        options = _mapping(body.get("driver_opts"))
        device = options.get("device")
        bind = set(options) == BIND_OPTIONS and options.get("type") == "none"
        if not bind or options.get("o") != "bind":
            found.append(f"volumes.{key}: driver_opts (not the options of a bind)")
        elif not _within(str(device), release):
            found.append(
                f"volumes.{key}: driver_opts (device={device} not in the release)"
            )
    return found


def _top_network_problems(
    key: str, body: Mapping[str, Json], project: str
) -> list[str]:
    found = [f"networks.{key}: {extra}" for extra in _extra(body, TOP_NETWORK_KEYS)]
    found += _top_name("networks", key, body, project)
    driver = body.get("driver")
    if driver not in (None, "bridge"):
        found.append(f"networks.{key}: driver={driver}")
    if "ipam" in body and body.get("ipam") != {}:
        found.append(f"networks.{key}: ipam")
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
    """What the compose ``document`` uses beyond the lists of what a stack may
    use -- of its services, of its top level and of the volumes and networks
    there -- one ``<where>: <key>`` per finding, sorted (``compose: <key>`` for
    the top level); ``mounts`` -- the packages' ``(slot, service)`` the machine
    would bind."""
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
    top = [key for key in document if not key.startswith("x-")]
    found += [f"compose: {key}" for key in sorted(top) if key not in TOP_KEYS]
    project = compose.project
    for name, body in _mapping(document.get("volumes")).items():
        found += _top_volume_problems(name, _mapping(body), project, release)
    for name, body in _mapping(document.get("networks")).items():
        found += _top_network_problems(name, _mapping(body), project)
    for slot, service in mounts:
        if service not in services:
            found.append(f"{service}: packages.{slot}.mount (no such service)")
    return sorted(found)


def env_files(uninterpolated: Mapping[str, Json]) -> list[str]:
    """Every service of ``config --no-interpolate`` (the only output that still
    names ``env_file``; ``config`` inlines it into ``environment``) with an
    ``env_file``: values come from the machine alone (protocol 3.4)."""
    services = _mapping(uninterpolated.get("services"))
    return sorted(
        f"{name}: env_file"
        for name, body in services.items()
        if "env_file" in _mapping(body)
    )


_VARIABLE = re.compile(r"\$(?:\$|\{([^}]*)\}|([A-Za-z_][A-Za-z0-9_]*))")
_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_REQUIRED = re.compile(r"[A-Za-z_][A-Za-z0-9_]*:\?.*", re.DOTALL)
"""``${NAME:?}`` and ``${NAME:?message}``: a variable that must have a value
(protocol 3.4); every other form may leave it empty or give it a default."""


def _strings(value: Json, where: str) -> list[tuple[str, str]]:
    if isinstance(value, str):
        return [(where, value)]
    if isinstance(value, list):
        return [found for item in value for found in _strings(item, where)]
    if isinstance(value, dict):
        return [found for item in value.values() for found in _strings(item, where)]
    return []


def variables(uninterpolated: Mapping[str, Json], env: Iterable[str]) -> list[str]:
    """The variables of ``config --no-interpolate`` (written as in the file)
    that are not ``${NAME:?}`` or ``${NAME:?message}`` and those whose name is
    not a key of the stack's ``env`` (protocol 3.4, contract 3 rule 18), one
    ``<where>: ...`` each, sorted; ``$$`` is a dollar, not a variable.
    ``<where>`` is the service, or the top-level section and its entry."""
    keys = set(env)
    places: list[tuple[str, str]] = []
    for section, body in uninterpolated.items():
        if section.startswith("x-") or section == "name":
            continue
        for name, entry in _mapping(body).items():
            where = name if section == "services" else f"{section}.{name}"
            places += _strings(entry, where)
    found: set[str] = set()
    for where, text in places:
        for match in _VARIABLE.finditer(text):
            braced, bare = match.group(1), match.group(2)
            if braced is None and bare is None:
                continue  # $$
            inner = braced if braced is not None else bare
            head = _NAME.match(inner)
            name = head.group(0) if head else inner
            if braced is None or not _REQUIRED.fullmatch(braced):
                found.add(f"{where}: {match.group(0)} is not ${{{name}:?}}")
            if name not in keys:
                found.add(f"{where}: {name} is not a key of env")
    return sorted(found)


def refusal(
    compose: ComposeStack,
    document: Mapping[str, Json],
    mounts: Sequence[tuple[str, str]] = (),
    also: Sequence[str] = (),
) -> tuple[str, dict[str, Json]] | None:
    """What ``build`` refuses ``document`` with, as its code and parameters,
    or ``None``: build arguments first (``instance-args``), then every finding
    of ``forbidden`` with ``also`` (``compose-forbidden``). One function for
    the step and for ``pridem check`` (protocol 10.1)."""
    services = document.get("services")
    if isinstance(services, dict):
        given = sorted(
            name
            for name, body in services.items()
            if isinstance(body, dict)
            and isinstance(build := body.get("build"), dict)
            and build.get("args")
        )
        if given:
            return "instance-args", {
                "stack": compose.entry,
                "services": list[Json](given),
            }
    found = sorted([*forbidden(compose, document, mounts), *also])
    if found:
        return "compose-forbidden", {"stack": compose.entry, "found": list[Json](found)}
    return None


REFUSAL_CODES = {
    "instance-args": "the compose of {stack} gives build arguments to {services}",
    "compose-forbidden": "the compose of {stack} asks the host for {found}",
}
"""The texts of ``refusal``'s codes, for every step that gives them."""


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
