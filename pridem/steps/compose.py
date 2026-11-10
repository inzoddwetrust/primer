"""Compose of one entry of ``stacks`` as the machine runs it (TZ 7.3).

Every command is ``docker compose -p <entry> --env-file /opt/<name>/env/<file>
-f <release>/<compose> -f /opt/<name>/compose/<entry>.yml``: the project name
is the machine's, the env is the rendered one (DM-14) -- ``next.env``, the
deploy's, for the steps of a deploy (``staged_env``), ``.env``, the release's
``current`` names, for any other command (DM-68; ``stacks.env.env_file``) --
the product's compose
is read from the immutable release, and the second file is the machine's own
override. The product's compose is never changed (contract 3 rule 9).

The override is rendered from ``docker compose config --format json`` of the
product's file and carries what the machine adds:

- every entry of a service's ``volumes`` that reaches into the release (a
  bind of it, a named volume bound to it), again with ``read_only: true``:
  no container writes the release it runs from (DM-81);
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
  replaces the implicit ``default``, so the override names it;
- for a product (protocol 4.1, 4.2): ``internal: true`` on every network of its
  compose -- with ``pridem`` and ``pridem-egress`` internal too (the host steps)
  no container of a product has a route out of the box. When the product
  declares ``egress``, every service of the entry joins the external network
  ``pridem-egress``, where the machine's proxy answers at ``PROXY_URL``, and
  gets that address as ``HTTPS_PROXY`` and ``https_proxy``; with ``egress``
  empty neither the network nor the variables are there. A service's stack
  keeps its networks as they are: a service reaches the internet itself.

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
A product's service is not named as the machine names things on the shared
networks (``reserved``): ``pridem-*`` (the proxy's alias), the alias
``<entry>-<service>`` of another entry of the product on ``pridem``, and
``<dependency>-*`` -- another project's -- are ``<service>: name reserved``.
Where a package goes is the product's, not one compose's (``package_places``):
a ``mount`` or a ``build`` place whose service is in no compose of the
product's stacks, or a ``build`` place on a service with no ``build``, is a
finding for every stack; a service of another stack is none. A service has no
``env_file`` (protocol 3.4: values come from the machine
alone); ``config`` inlines it into ``environment``, so it is read from
``config --no-interpolate`` (``env_files``), where it is still named.
"""

import json
import os
import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field, replace
from pathlib import Path

import yaml

from pridem.events import Json, as_list
from pridem.files import PathOutside, atomic_write, resolve_inside
from pridem.runner import Stream
from pridem.stacks.env import env_file
from pridem.stacks.routes import alias, routed_services
from pridem.stacks.schema import PROXY_VARIABLES, Product, Service
from pridem.stacks.seams import Pair
from pridem.steps.base import StepContext, StepFailed

NETWORK = "pridem"
EGRESS_NETWORK = "pridem-egress"
"""The internal network of a product's services and the machine's proxy."""
PROXY_ALIAS = "pridem-egress-proxy"
PROXY_PORT = 3128
PROXY_URL = f"http://{PROXY_ALIAS}:{PROXY_PORT}"
COMMAND_TIMEOUT_S = 120
BUILD_TIMEOUT_S = 3600
UP_WAIT_S = 300
# what compose stamps on a container it makes: the hash of its service's
# configuration (``config --hash``) and the service's name
CONFIG_HASH_LABEL = "com.docker.compose.config-hash"
SERVICE_LABEL = "com.docker.compose.service"
RUNNING_HASH_FORMAT = (
    f'{{{{index .Config.Labels "{SERVICE_LABEL}"}}}} '
    f'{{{{index .Config.Labels "{CONFIG_HASH_LABEL}"}}}}'
)
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
    next: bool = False
    """The candidate override (``build``'s of this run) in place of the one on
    disk: ``override`` names ``<entry>.next.yml``."""
    staged_env: bool = False
    """The deploy's environment (``env/next.env``) in place of the one of the
    release ``current`` names (``env/.env``): what a step of a deploy runs on.
    The default is the running release's -- a command that does not ask for
    the deploy's never reads a value no gate passed yet (DM-68)."""

    @property
    def name(self) -> str:
        return self.stack.name

    def candidate(self) -> "ComposeStack":
        """The same entry with the candidate override."""
        return replace(self, next=True)

    @property
    def project(self) -> str:
        return self.entry

    @property
    def env_file(self) -> Path:
        return env_file(self.root, self.name, staged=self.staged_env)

    @property
    def compose_file(self) -> Path:
        return self.release / self.stack.stacks[self.entry].compose

    @property
    def override(self) -> Path:
        suffix = ".next.yml" if self.next else ".yml"
        return self.root / "opt" / self.name / "compose" / f"{self.entry}{suffix}"

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


def _csv_field(field: str) -> str:
    """One field of ``--mount``: docker reads the value as CSV, so a field with
    a comma or a quote is quoted, its quotes doubled."""
    if "," in field or '"' in field:
        return '"' + field.replace('"', '""') + '"'
    return field


def mount_flag(source: Path | str, target: str, *, read_only: bool = True) -> list[str]:
    """A bind of ``docker run`` as ``--mount``, never ``-v``: ``-v`` splits its
    spec at every colon, and a path of the box can hold one -- a ``run_id``
    always does (DM-86 FIX)."""
    fields = ["type=bind", f"source={source}", f"target={target}"]
    if read_only:
        fields.append("readonly")
    return ["--mount", ",".join(_csv_field(field) for field in fields)]


def bind(source: Path | str, target: str) -> dict[str, Json]:
    """A read-only bind of the override in compose's long form: no part of it
    is split at a colon (DM-86 FIX)."""
    return {"type": "bind", "source": str(source), "target": target, "read_only": True}


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


def unfolded(compose: ComposeStack) -> list[str]:
    """What ``config`` would unfold before the machine sees it (DM-78): a
    top-level ``include``, a service's ``extends`` -- both gone from its
    document, read with or without interpolation -- and ``env_file``, which
    compose reads off the host on ``config``. Read from the file itself, with
    no symlink on its way out of the release."""
    try:
        path = resolve_inside(
            compose.release, compose.stack.stacks[compose.entry].compose
        )
    except PathOutside:
        return ["compose: symlink"]
    if not path.is_file():
        return []  # no compose: the callers' own refusal (no-compose)
    try:
        document = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (yaml.YAMLError, UnicodeDecodeError):
        return []  # config says what is wrong with it, as before
    if not isinstance(document, dict):
        return []
    found = ["compose: include"] if "include" in document else []
    for name, body in _mapping(document.get("services")).items():
        found += [
            f"{name}: {key}" for key in ("extends", "env_file") if key in _mapping(body)
        ]
    return sorted(found)


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
    found = unfolded(compose)
    if found:  # before compose reads a file of the host for them (DM-78)
        raise StepFailed(
            "compose-forbidden", {"stack": compose.entry, "found": list[Json](found)}
        )
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


def reserved(
    stack: Product | Service, entry: str
) -> tuple[frozenset[str], tuple[str, ...]]:
    """The names a product's service of ``entry`` may not have, exactly, and
    the prefixes of names it may not have: the aliases of the product's other
    entries on ``pridem`` (``<entry>-<app>`` and the services routes go to:
    computed from ``primer.yaml`` alike in ``pridem check`` and on a box), and
    ``pridem-`` and ``<dependency>-`` (another project's names). A service's
    stack reserves nothing."""
    if not isinstance(stack, Product):
        return frozenset(), ()
    names: set[str] = set()
    for other, stage in stack.stacks.items():
        if other == entry:
            continue
        if stage.app is not None:
            names.add(alias(other, stage.app.service))
        names |= {alias(other, name) for name in routed_services(stack, other)}
    prefixes = ("pridem-", *(f"{name}-" for name in sorted(stack.dependencies)))
    return frozenset(names), prefixes


def package_places(
    stack: Product | Service, documents: Mapping[str, Mapping[str, Json]]
) -> list[str]:
    """Where the product's packages go, against the compose ``documents`` of
    all its stack entries: a ``mount`` or ``build`` place whose service is in
    none of them, or a ``build`` place on a service with no ``build``, one
    ``<service>: packages.<slot>.<form> (...)`` each, sorted. A service of
    another entry is no finding: a package belongs to the stack its service is
    in. One function for ``build`` and ``pridem check``."""
    if not isinstance(stack, Product):
        return []
    bodies: dict[str, dict[str, Json]] = {}
    for document in documents.values():
        for name, body in _mapping(document.get("services")).items():
            bodies.setdefault(name, _mapping(body))
    found: list[str] = []
    for slot, package in sorted(stack.packages.items()):
        for mount in package.mount:
            if mount.service is not None and mount.service not in bodies:
                found.append(
                    f"{mount.service}: packages.{slot}.mount (no such service)"
                )
        for place in package.build:
            body = bodies.get(place.service)
            if body is None:
                found.append(
                    f"{place.service}: packages.{slot}.build (no such service)"
                )
            elif "build" not in body:
                found.append(f"{place.service}: packages.{slot}.build (no build)")
    return sorted(set(found))


def job_services(compose: ComposeStack) -> frozenset[str]:
    """The services of the entry's ``jobs`` (contract 3 rule 24, DM-22): run
    once by ``up`` and gone, no healthcheck asked of them, no container left
    for ``stale`` to compare."""
    jobs = compose.stack.stacks[compose.entry].jobs
    return frozenset(job.service for job in jobs.values())


def _health_checked(body: Mapping[str, Json]) -> bool:
    """The service declares a healthcheck compose runs: the key, not
    ``disable: true``, not ``test: [NONE]`` (DM-22). One of the image alone
    is not read: protocol 3.4 asks it of the compose file."""
    check = body.get("healthcheck")
    if not isinstance(check, dict) or check.get("disable") is True:
        return False
    test = check.get("test")
    return not (test == ["NONE"] or test == "NONE")


def _job_problems(compose: ComposeStack, services: Mapping[str, Json]) -> list[str]:
    """A job is in compose; no service but a job depends on it -- the machine
    runs it before the rest (contract 3 rule 24), and compose would run it
    again as a dependency, under ``--no-deps`` and in ``run --rm <app>`` of
    ``migrate`` alike (DM-22 FIX, measured on tier 3); and it has no
    ``restart`` but ``no``."""
    jobs = compose.stack.stacks[compose.entry].jobs
    by_service = {part.service: name for name, part in jobs.items()}
    found: list[str] = []
    for job, part in jobs.items():
        body = services.get(part.service)
        if body is None:
            found.append(f"jobs.{job}: no service {part.service}")
            continue
        policy = _mapping(body).get("restart")
        if policy is not None and policy != "no":
            found.append(f"jobs.{job}: restart {policy}")
    for name, body in services.items():
        if name in by_service:
            continue
        for needed in _mapping(_mapping(body).get("depends_on")):
            if needed in by_service:
                found.append(f"{name}: depends on job {by_service[needed]}")
    return found


def depended(services: Mapping[str, Json], start: str) -> set[str]:
    """Every service ``start`` depends on in ``config``, through any of them."""
    seen: set[str] = set()
    todo = list(_mapping(_mapping(services.get(start)).get("depends_on")))
    while todo:
        name = todo.pop()
        if name not in seen:
            seen.add(name)
            todo += list(_mapping(_mapping(services.get(name)).get("depends_on")))
    return seen


def _stop_problems(compose: ComposeStack, services: Mapping[str, Json]) -> list[str]:
    """``stop_for_migrate`` (DM-22): a service compose has, and none that
    ``run --rm <app>`` of ``migrate`` would bring up again by ``depends_on``."""
    stage = compose.stack.stacks[compose.entry]
    needed = depended(services, stage.app.service) if stage.app is not None else set()
    found: list[str] = []
    for name in stage.stop_for_migrate:
        if name not in services:
            found.append(f"stop_for_migrate: no service {name}")
        elif name in needed:
            found.append(f"{name}: stopped for migrate, migrate needs it")
    return found


def forbidden(compose: ComposeStack, document: Mapping[str, Json]) -> list[str]:
    """What the compose ``document`` uses beyond the lists of what a stack may
    use -- of its services, of its top level and of the volumes and networks
    there -- and the names it may not give its services, one ``<where>: <key>``
    per finding, sorted (``compose: <key>`` for the top level)."""
    release = compose.release
    stack = compose.stack
    declared: set[tuple[str, int]] = set()
    if isinstance(stack, Service) and stack.host is not None:
        declared = {(port.proto, int(port.port)) for port in stack.host.ports}
    services = _mapping(document.get("services"))
    found: list[str] = []
    jobs = job_services(compose)
    for name, body in services.items():
        problems = _service_problems(_mapping(body), release, declared)
        if name not in jobs and not _health_checked(_mapping(body)):
            problems.append("no healthcheck")  # protocol 3.4 (DM-22)
        found += [f"{name}: {problem}" for problem in problems]
    found += _job_problems(compose, services)
    found += _stop_problems(compose, services)
    top = [key for key in document if not key.startswith("x-")]
    found += [f"compose: {key}" for key in sorted(top) if key not in TOP_KEYS]
    project = compose.project
    for name, body in _mapping(document.get("volumes")).items():
        found += _top_volume_problems(name, _mapping(body), project, release)
    for name, body in _mapping(document.get("networks")).items():
        found += _top_network_problems(name, _mapping(body), project)
    exact, prefixes = reserved(stack, compose.entry)
    found += [
        f"{name}: name reserved"
        for name in services
        # the name itself is a DNS name on pridem too (compose gives every
        # service its name on each network); its alias against the other
        # entries' aliases, whole -- velo + storage-init is velo-storage + init
        # (DM-78); a prefix -- others' names only
        if name in exact
        or alias(compose.entry, name) in exact
        or name.startswith(prefixes)
    ]
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


def product_build_args(uninterpolated: Mapping[str, Json]) -> list[str]:
    """The services whose ``build`` has ``args`` in any form, sorted: read in
    ``config --no-interpolate`` by the key alone. Its value there is ``{}``,
    ``null``, a mapping or a list (measured, compose 2.27 and 2.40);
    ``config`` itself drops ``{}``, ``[]``, ``{A: null}`` and an entry of a
    list whose variable has no value, so it would show none of them."""
    return sorted(
        name
        for name, body in _mapping(uninterpolated.get("services")).items()
        if "args" in _mapping(_mapping(body).get("build"))
    )


def refusal(
    compose: ComposeStack,
    document: Mapping[str, Json],
    raw: Mapping[str, Json],
    also: Sequence[str] = (),
) -> tuple[str, dict[str, Json]] | None:
    """What ``build`` refuses ``document`` with, as its code and parameters,
    or ``None``: build arguments first (``instance-args``), then every finding
    of ``forbidden`` with ``also`` (``compose-forbidden``; ``package_places``
    is one of the callers' ``also``). One function for the step and for
    ``pridem check`` (protocol 10.1). ``document`` is the product's ``config``
    without the machine's override: ``PRIMER_EDITION`` is the machine's own
    build argument, given only by the override, and never read here. The
    build arguments of the product are read from ``raw`` -- the same file's
    ``config --no-interpolate`` -- by ``product_build_args`` (protocol 3.4:
    ``build.args`` in no form), never from ``document``, which loses some
    forms; every caller reads it."""
    given = product_build_args(raw)
    if given:
        return "instance-args", {"stack": compose.entry, "services": list[Json](given)}
    found = sorted([*forbidden(compose, document), *also])
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


_REFERENCE = "${{{}"


def _pair_networks(
    compose: ComposeStack, references: Mapping[str, Json], points: Sequence[Pair]
) -> tuple[dict[str, dict[str, Json]], dict[str, Json]]:
    """This entry's side of the pairs of the box (DM-62), by service and the
    networks to declare. As the provider: the point's service joins each of
    its pairs' networks under the one alias, and the entry declares them --
    internal, labelled. As the consumer: each service whose ``environment``
    names the pair's variable joins it; the network is the provider's
    (``external``) unless this very entry provides it.

    ``references`` is the product's ``config --no-interpolate``: there a
    variable is ``${VAR:?}``; in the interpolated document its value already
    stands in its place, and no consumer would be found (DM-62 FIX 2, par0
    14.4: DM-57)."""
    joins: dict[str, dict[str, Json]] = {}
    declared: dict[str, Json] = {}
    own = compose.stack.name
    for pair in points:
        key = pair.network.removeprefix("pridem-")
        if pair.provider == compose.entry:
            joins.setdefault(pair.service, {})[key] = {"aliases": [pair.alias]}
            declared[key] = {
                "name": pair.network,
                "internal": True,
                "labels": {
                    **compose.stack_labels(),
                    "pridem.point": f"{pair.provider}/{pair.endpoint}",
                    "pridem.consumer": pair.consumer,
                },
            }
        if pair.consumer == own:
            reference = _REFERENCE.format(pair.variable)
            for name, body in _mapping(references.get("services")).items():
                environment = _mapping(_mapping(body).get("environment"))
                if any(
                    isinstance(v, str) and _names(v, reference, pair.variable)
                    for v in environment.values()
                ):
                    joins.setdefault(name, {}).setdefault(key, None)
                    declared.setdefault(key, {"name": pair.network, "external": True})
    return joins, declared


def _names(value: str, reference: str, variable: str) -> bool:
    """``value`` refers to ``${variable}`` exactly -- ``${VAR:?}`` or
    ``${VAR}``, not ``${VAR_LONGER}``."""
    at = value.find(reference)
    while at >= 0:
        after = value[at + len(reference) : at + len(reference) + 1]
        if after in (":", "}"):
            return True
        at = value.find(reference, at + 1)
    return False


def _release_binds(
    body: Mapping[str, Json], document: Mapping[str, Json], release: Path
) -> list[Json]:
    """The entries of ``volumes`` of a service that reach into the release --
    a bind of it, or a named volume whose ``driver_opts`` bind it -- and are
    not read-only yet, each again with ``read_only: true``. compose merges
    an override's entry with the file's by ``target``: the release is never
    written from a container (TZ 7.3, immutable checkouts), so its files --
    the compose, the ``Dockerfile``, the context, the data a service takes --
    are the ones ``forbidden`` and ``drift`` read, not a container's (DM-81)."""
    tops = _mapping(document.get("volumes"))
    found: list[Json] = []
    for entry in as_list(body.get("volumes")):
        volume = _mapping(entry)
        if volume.get("read_only") is True:
            continue
        kind = volume.get("type")
        if kind == "bind":
            inside = _within(str(volume.get("source", "")), release)
        elif kind == "volume":
            options = _mapping(
                _mapping(tops.get(str(volume.get("source")))).get("driver_opts")
            )
            device = options.get("device")
            inside = options.get("o") == "bind" and _within(str(device), release)
        else:
            inside = False
        if inside:
            found.append({**volume, "read_only": True})
    return found


def override_text(
    compose: ComposeStack,
    document: Mapping[str, Json],
    mounts: Mapping[str, Sequence[Json]] | None = None,
    builds: Mapping[str, Mapping[str, Json]] | None = None,
    environment: Mapping[str, Mapping[str, str]] | None = None,
    *,
    proxy: bool,
    points: Sequence[Pair] = (),
    references: Mapping[str, Json],
) -> str:
    """The machine's override for the product's compose ``document``;
    ``mounts`` -- read-only binds of the instance's packages, and of the data a
    service takes (form D), by service; ``environment`` -- the machine's
    variables by service beside the proxy's: the paths of that data;
    ``builds`` -- by service a package is built into (``apply: build``), what
    its ``build`` gets beside the labels: the context with the package, the
    ``Dockerfile`` in it, ``PRIMER_EDITION`` and the labels of the image's key
    (``steps/packages.py``); ``proxy`` -- the product has a host of ``egress``
    open (``open_hosts``): every service gets the proxy's variables."""
    services: dict[str, Json] = {}
    joins, networks_of_pairs = _pair_networks(compose, references, points)
    app = compose.app_service
    aliased = {app} if app is not None else set()
    product = isinstance(compose.stack, Product)
    egress = proxy
    if isinstance(compose.stack, Product):
        aliased |= set(routed_services(compose.stack, compose.entry))
    for name, body in sorted(_mapping(document.get("services")).items()):
        part: dict[str, Json] = {"labels": dict[str, Json](compose.release_labels())}
        if "build" in _mapping(body):
            labels: dict[str, Json] = {
                **compose.release_labels(),
                "pridem.service": name,
            }
            extra = dict((builds or {}).get(name, {}))
            labels.update(_mapping(extra.pop("labels", None)))
            part["build"] = {**extra, "labels": labels}
        if name in aliased or egress or name in joins:
            networks: dict[str, Json] = dict(_mapping(_mapping(body).get("networks")))
            if not networks:
                networks["default"] = None
            if name in aliased:
                networks[NETWORK] = {"aliases": [alias(compose.entry, name)]}
            if egress:
                networks[EGRESS_NETWORK] = None
            networks.update(joins.get(name, {}))  # the networks of its pairs
            part["networks"] = networks
        variables: dict[str, Json] = (
            {key: PROXY_URL for key in PROXY_VARIABLES} if egress else {}
        )
        variables.update((environment or {}).get(name, {}))
        if variables:
            part["environment"] = variables
        own = _release_binds(_mapping(body), document, compose.release)
        binds = (mounts or {}).get(name)
        if own or binds:
            part["volumes"] = [*own, *list[Json](binds or [])]
        services[name] = part
    volumes: dict[str, Json] = {
        name: {"labels": dict[str, Json](compose.stack_labels())}
        for name, body in sorted(_mapping(document.get("volumes")).items())
        if not _mapping(body).get("external")
    }
    networks_top: dict[str, Json] = {NETWORK: {"external": True}}
    for name in sorted(_mapping(document.get("networks"))):
        network: dict[str, Json] = {}
        if name == "default":
            network["labels"] = dict[str, Json](compose.stack_labels())
        if product:
            network["internal"] = True
        if network:
            networks_top[name] = network
    if egress:
        networks_top[EGRESS_NETWORK] = {"external": True}
    networks_top.update(networks_of_pairs)  # the points' own (DM-62)
    rendered: dict[str, Json] = {"services": services, "networks": networks_top}
    if volumes:
        rendered["volumes"] = volumes
    return json.dumps(rendered, indent=2, sort_keys=True) + "\n"


@dataclass
class OverrideHandoff:
    """The override ``build`` rendered in this run, by entry: it waits as the
    candidate (``ComposeStack.candidate``) until ``packages`` puts it in place
    after a green ``validate``. Kept in memory only: a candidate a red run
    left on disk is never put in place by a later run."""

    texts: dict[str, str] = field(default_factory=dict)


def write_override(compose: ComposeStack, text: str) -> None:
    """The override file, replaced whole by ``atomic_write`` (0644)."""
    path = compose.override
    path.parent.mkdir(parents=True, exist_ok=True)
    atomic_write(path, text, 0o644)


def image_of(
    ctx: StepContext,
    compose: ComposeStack,
    service: str,
    key: Mapping[str, str] | None = None,
) -> list[str]:
    """IDs of the images of ``service`` by labels: the stack, the commit, the
    service, and ``key`` -- for a service a package is built into
    (``apply: build``), the edition and the packages' releases
    (``steps.packages.image_key``); empty for every other service, whose
    image is the commit's."""
    filters = [
        f"label=pridem.stack={compose.entry}",
        f"label=pridem.commit={compose.commit}",
        f"label=pridem.service={service}",
        *(f"label={name}={value}" for name, value in sorted((key or {}).items())),
    ]
    _, lines = out(
        ctx,
        [
            "docker",
            "image",
            "ls",
            "--quiet",
            "--no-trunc",
            *(word for found in filters for word in ("--filter", found)),
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


def config_hashes(ctx: StepContext, compose: ComposeStack) -> dict[str, str]:
    """The hash of each service's configuration -- the product's file with
    the machine's override, as ``up`` reads them: ``config --hash "*"``, one
    ``<service> <hash>`` a line."""
    _, lines = out(ctx, compose.argv("config", "--hash", "*"), passed_on=False)
    found: dict[str, str] = {}
    for line in lines:
        words = line.split()
        if len(words) == 2:
            found[words[0]] = words[1]
    return found


def running_hashes(ctx: StepContext, compose: ComposeStack) -> dict[str, str]:
    """The configuration hash on the running container of each service
    (``CONFIG_HASH_LABEL``); a service with no running container is absent."""
    _, ids = out(ctx, compose.argv("ps", "-q"), passed_on=False)
    found = sorted({line.strip() for line in ids if line.strip()})
    if not found:
        return {}
    _, lines = out(
        ctx, ["docker", "inspect", "-f", RUNNING_HASH_FORMAT, *found], passed_on=False
    )
    running: dict[str, str] = {}
    for line in lines:
        service, _, value = line.strip().partition(" ")
        if service and value:
            running[service] = value
    return running


def stale(ctx: StepContext, compose: ComposeStack) -> dict[str, tuple[str, str]]:
    """Every service whose running container is not on its configuration --
    another mount, environment, image name -- or that has none: ``{service:
    (expected, running)}``, ``running`` ``"none"`` without a container. On one
    commit only this tells that ``up`` has something to do for a service whose
    image did not change (a package of another version, apply: runtime). A
    job's service is none of them: it ran and is gone (DM-22)."""
    jobs = job_services(compose)  # no container after their run (DM-22)
    expected = {
        service: value
        for service, value in config_hashes(ctx, compose).items()
        if service not in jobs
    }
    if not expected:
        return {}
    running = running_hashes(ctx, compose)
    return {
        service: (value, running.get(service, "none"))
        for service, value in sorted(expected.items())
        if running.get(service) != value
    }


def heads(lines: Sequence[str]) -> list[str]:
    return [found.group(1) for line in lines if (found := _HEAD.match(line.strip()))]


def current(lines: Sequence[str]) -> list[str]:
    return [found.group(1) for line in lines if (found := _CURRENT.match(line.strip()))]
