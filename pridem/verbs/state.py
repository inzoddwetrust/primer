"""``pridem state [--json]``: the state of the box, read and never written
(DM-136).

No lock (taking it is a write: its file, its directories, the temp files it
clears), no journal, no verdict, nothing in ``history/`` -- so a heartbeat
may ask it as often as it likes and a run under the lock is never in its way.
``status`` prints the same form after its verdict; ``ssl status`` prints its
part ``ssl``.

Every part is measured on the box, never taken from ``state.json``
(TZ 7.3): the stacks by their mark ``/opt/<stack>/.pridem`` and the
``primer.yaml`` of ``current``; the services of an entry by ``compose config
--services`` of its current release -- ``--services`` alone: the whole output
carries the values of the environment -- and their containers by docker's
labels; the disks by ``statvfs``; memory and swap by ``/proc/meminfo``; the
images by ``docker system df``; the certificate by ``openssl``. Of the
passport copy only ``version``, ``policies.ssl`` and ``domains`` are read. A
part docker or a file does not give is ``{"unmeasured": <code>}``.
"""

import json
import os
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path

from pridem import __version__
from pridem.contract import Strict
from pridem.events import said
from pridem.report.box_snapshot import (
    BoxSnapshot,
    ContainerState,
    Disk,
    DomainPart,
    EntryPart,
    Health,
    Images,
    MachineStackPart,
    Memory,
    PassportPart,
    Resources,
    ServiceState,
    Space,
    SslPart,
    StackPart,
    Swap,
    Unmeasured,
)
from pridem.report.catalog import ENGLISH, say
from pridem.runner import RunnerError, Stream
from pridem.stacks import names as machine
from pridem.stacks.loader import ContractError
from pridem.stacks.passport import Passport
from pridem.stacks.schema import load_primer_yaml
from pridem.state import HISTORY, JOURNAL, LOCK, holders
from pridem.steps.compose import ComposeStack
from pridem.steps.destroy import machine_stacks
from pridem.steps.edge import certs_dir
from pridem.steps.gc import UnreadableOutput, docker_size, reclaimable_size
from pridem.steps.ssl import CERT_ARGS, RENEW_BEFORE, read_cert
from pridem.verbs.base import Context, NoArgs, Verb
from pridem.verbs.run import read_copy

DOCKER_TIMEOUT_S = 60
"""One command of docker of the state: a minute at most."""

DISK_PATHS = ("", "var/lib/docker")
"""The disks of the state, under the root of the file system: ``/`` and
docker's own directory."""

MACHINE_LABELS = (machine.EDGE_LABEL, machine.EGRESS_LABEL)
"""The stacks of the machine's own whose containers the state names."""

STAMP = "%Y-%m-%dT%H:%M:%SZ"

_STATES: dict[str, ContainerState] = {
    "running": "running",
    "exited": "exited",
    "restarting": "restarting",
    "paused": "paused",
    "created": "created",
    "dead": "dead",
    "removing": "removing",
}
"""Every ``State.Status`` docker has; another word is not docker's answer."""
_HEALTHS: dict[str, Health] = {
    "healthy": "healthy",
    "unhealthy": "unhealthy",
    "starting": "starting",
}


class DockerGone(Exception):
    """docker did not answer a command of the state."""


def _lines(ctx: Context, argv: list[str]) -> list[str]:
    """What ``argv`` prints on stdout; ``DockerGone`` on any failure."""
    found: list[str] = []
    try:
        ctx.runner.run(
            argv,
            timeout=DOCKER_TIMEOUT_S,
            on_line=lambda s, line, c: (
                found.append(line) if s is Stream.STDOUT else None
            ),
        )
    except RunnerError:
        raise DockerGone(argv[0]) from None
    return found


# --- containers -------------------------------------------------------------------


Container = tuple[str, str, ContainerState, Health]
"""``(pridem.stack, service, state, health)`` of one container."""


def _containers(ctx: Context) -> list[Container]:
    """Every container with the label ``pridem.stack``, one-off containers of
    ``compose run`` left out (a seed, a test, a verb running now)."""
    ids = _lines(
        ctx,
        ["docker", "ps", "-a", "-q", "--no-trunc", "--filter", "label=pridem.stack"],
    )
    ids = [line.strip() for line in ids if line.strip()]
    if not ids:
        return []
    try:
        found = json.loads("".join(_lines(ctx, ["docker", "inspect", "--", *ids])))
    except ValueError:
        raise DockerGone("inspect") from None
    out: list[Container] = []
    for item in found if isinstance(found, list) else []:
        config = item.get("Config") if isinstance(item, dict) else None
        state = item.get("State") if isinstance(item, dict) else None
        labels = config.get("Labels") if isinstance(config, dict) else None
        if not isinstance(labels, dict) or not isinstance(state, dict):
            raise DockerGone("inspect")
        if str(labels.get("com.docker.compose.oneoff", "")).lower() == "true":
            continue
        status = _STATES.get(str(state.get("Status")))
        health = state.get("Health")
        if status is None or not (health is None or isinstance(health, dict)):
            raise DockerGone("inspect")  # not docker's answer: never a guess
        # no Health at all: the container has no healthcheck (measured, DM-136)
        known: Health = "none"
        if isinstance(health, dict):
            said_health = _HEALTHS.get(str(health.get("Status")))
            if said_health is None:
                raise DockerGone("inspect")
            known = said_health
        out.append(
            (
                str(labels.get("pridem.stack")),
                str(labels.get("com.docker.compose.service", "")),
                status,
                known,
            )
        )
    return sorted(out)


def _services(
    expected: list[str], containers: list[Container], stack: str
) -> list[ServiceState]:
    """Every service of ``expected`` by its containers, ``absent`` without
    one; a container of a service the compose no longer names is shown too."""
    mine = [c for c in containers if c[0] == stack]
    found = [
        ServiceState(service=service, state=state, health=health)
        for _, service, state, health in mine
    ]
    seen = {c[1] for c in mine}
    found += [
        ServiceState(service=name, state="absent", health="none")
        for name in expected
        if name not in seen
    ]
    return sorted(found, key=lambda s: (s.service, s.state))


# --- stacks -----------------------------------------------------------------------


def _stacks(
    ctx: Context, containers: list[Container] | None
) -> list[StackPart] | Unmeasured:
    parts: list[StackPart] = []
    for home in machine_stacks(ctx.fs_root):
        current = home / "current"
        if not current.is_symlink():
            parts.append(
                StackPart(
                    stack=home.name,
                    release=Unmeasured(unmeasured="no-current"),
                    entries=Unmeasured(unmeasured="no-current"),
                )
            )
            continue
        release = current.resolve()
        parts.append(
            StackPart(
                stack=home.name,
                release=release.name,
                entries=_entries(ctx, home.name, release, containers),
            )
        )
    return parts


def _entries(
    ctx: Context, stack: str, release: Path, containers: list[Container] | None
) -> list[EntryPart] | Unmeasured:
    try:
        made = load_primer_yaml(release / "primer.yaml")
    except (ContractError, OSError):
        return Unmeasured(unmeasured="primer-yaml-unreadable")
    entries: list[EntryPart] = []
    for entry, stage in sorted(made.stacks.items()):
        services: list[ServiceState] | Unmeasured
        if containers is None:
            services = Unmeasured(unmeasured="docker-unreachable")
        else:
            compose = ComposeStack(
                made, entry, release, release.name, release.name, ctx.fs_root
            )
            try:
                # --services alone: the whole config carries the env's values
                expected = _lines(ctx, compose.argv("config", "--services"))
                services = _services(
                    [line.strip() for line in expected if line.strip()],
                    containers,
                    entry,
                )
            except DockerGone:
                services = Unmeasured(unmeasured="compose-unread")
        entries.append(
            EntryPart(entry=entry, persistent=stage.persistent, services=services)
        )
    return entries


# --- resources --------------------------------------------------------------------


def _disk(root: Path, path: str) -> Disk:
    where = "/" + path
    try:
        found = os.statvfs(root / path)
    except OSError:
        return Disk(path=where, space=Unmeasured(unmeasured="path-missing"))
    return Disk(
        path=where,
        space=Space(
            total_bytes=found.f_blocks * found.f_frsize,
            free_bytes=found.f_bavail * found.f_frsize,
        ),
    )


def _meminfo(root: Path) -> dict[str, int] | None:
    """``/proc/meminfo`` in bytes by its keys; ``None`` -- not readable."""
    try:
        text = (root / "proc" / "meminfo").read_text(encoding="utf-8")
    except OSError:
        return None
    found: dict[str, int] = {}
    for line in text.splitlines():
        key, _, rest = line.partition(":")
        words = rest.split()
        if words and words[0].isdigit():
            unit = 1024 if words[1:2] == ["kB"] else 1
            found[key.strip()] = int(words[0]) * unit
    return found


def _memory(info: dict[str, int] | None) -> Memory | Unmeasured:
    if info is None or "MemTotal" not in info or "MemAvailable" not in info:
        return Unmeasured(unmeasured="meminfo-unreadable")
    return Memory(total_bytes=info["MemTotal"], available_bytes=info["MemAvailable"])


def _swap(info: dict[str, int] | None) -> Swap | Unmeasured:
    if info is None or "SwapTotal" not in info or "SwapFree" not in info:
        return Unmeasured(unmeasured="meminfo-unreadable")
    return Swap(total_bytes=info["SwapTotal"], free_bytes=info["SwapFree"])


def _images(ctx: Context) -> Images | Unmeasured:
    try:
        lines = _lines(ctx, ["docker", "system", "df", "--format", "json"])
        for line in lines:
            row = json.loads(line) if line.strip() else {}
            if isinstance(row, dict) and row.get("Type") == "Images":
                return Images(
                    count=int(str(row["TotalCount"])),
                    bytes=docker_size(str(row["Size"])),
                    reclaimable_bytes=reclaimable_size(str(row["Reclaimable"])),
                )
    except (DockerGone, ValueError, KeyError, UnreadableOutput):
        pass
    return Unmeasured(unmeasured="docker-unreachable")


# --- ssl --------------------------------------------------------------------------


def _covered(domain: str, names: list[str]) -> bool:
    """``domain`` is a name of the certificate, or under one of its wildcards
    by one label (``*.preview.x`` covers ``a.preview.x``, not ``preview.x``)."""
    for name in names:
        if name == domain:
            return True
        if name.startswith("*.") and "." in domain:
            head, _, rest = domain.partition(".")
            if head and rest == name[2:]:
                return True
    return False


def _ssl(ctx: Context, passport: Passport | None) -> SslPart | Unmeasured:
    if passport is None:
        return Unmeasured(unmeasured="no-passport")
    cert = certs_dir(ctx.fs_root) / "fullchain.pem"
    if not cert.is_file():
        return Unmeasured(unmeasured="no-certificate")
    try:
        facts = read_cert(
            _lines(ctx, ["openssl", "x509", "-in", str(cert), *CERT_ARGS])
        )
    except (DockerGone, KeyError, ValueError):
        return Unmeasured(unmeasured="certificate-unreadable")
    expires = datetime.strptime(str(facts["cert_expires"]), STAMP).replace(tzinfo=UTC)
    mode = passport.policies.ssl
    names = [str(name) for name in facts["domains"]]  # type: ignore[union-attr]
    return SslPart(
        mode=mode,
        expires=expires.strftime(STAMP),
        self_signed=bool(facts["self_signed"]),
        renews_from=(
            Unmeasured(unmeasured="renewed-by-passport")
            if mode == "provided"
            else (expires - RENEW_BEFORE).strftime(STAMP)
        ),
        domains=[
            DomainPart(domain=domain, covered=_covered(domain, names))
            for domain in sorted(set(passport.domains.values()))
        ],
    )


# --- the form ---------------------------------------------------------------------


def _passport(ctx: Context) -> tuple[Passport | None, PassportPart | Unmeasured]:
    """The passport copy, and its part of the form: its version alone."""
    try:
        passport = read_copy(ctx).passport
    except (ContractError, OSError):
        return None, Unmeasured(unmeasured="passport-unreadable")
    if passport is None:
        return None, Unmeasured(unmeasured="no-passport")
    return passport, PassportPart(version=passport.version)


def ssl_part(ctx: Context) -> SslPart | Unmeasured:
    """The part ``ssl`` alone, for ``ssl status``: the passport copy and the
    certificate, nothing of docker."""
    passport, part = _passport(ctx)
    if isinstance(part, Unmeasured) and part.unmeasured == "passport-unreadable":
        return part
    return _ssl(ctx, passport)


def snapshot(ctx: Context, now: Callable[[], datetime] | None = None) -> BoxSnapshot:
    """The state of the box, measured now; nothing on the box is written."""
    moment = (now or (lambda: datetime.now(UTC)))().replace(microsecond=0)
    passport, passport_part = _passport(ctx)
    try:
        containers: list[Container] | None = _containers(ctx)
    except DockerGone:
        containers = None
    info = _meminfo(ctx.fs_root)
    history, journal = ctx.root / HISTORY, ctx.root / JOURNAL
    verdicts = {p.stem for p in history.glob("*.json")} if history.is_dir() else set()
    journals = (
        sorted(p.stem for p in journal.glob("*.jsonl")) if journal.is_dir() else []
    )
    return BoxSnapshot.model_validate(
        {
            "schema": 1,
            "measured_at": moment.strftime(STAMP),
            "machine": {"version": __version__},
            "passport": passport_part,
            "lock_open_by": list(holders(ctx.root / LOCK)),
            "journals_without_verdict": [j for j in journals if j not in verdicts],
            "stacks": _stacks(ctx, containers),
            "machine_stacks": (
                Unmeasured(unmeasured="docker-unreachable")
                if containers is None
                else [
                    MachineStackPart(
                        stack=label, services=_services([], containers, label)
                    )
                    for label in MACHINE_LABELS
                ]
            ),
            "resources": Resources(
                disk=[_disk(ctx.fs_root, path) for path in DISK_PATHS],
                memory=_memory(info),
                swap=_swap(info),
                images=_images(ctx),
            ),
            "ssl": (
                passport_part
                if isinstance(passport_part, Unmeasured)
                and passport_part.unmeasured == "passport-unreadable"
                else _ssl(ctx, passport)
            ),
        },
        strict=False,
    )


def rendered(state: BoxSnapshot) -> str:
    """The form as ``--json`` prints it: the JSON of the model."""
    return state.model_dump_json(by_alias=True, indent=2)


# --- the console ------------------------------------------------------------------


def _size(count: int) -> str:
    for unit, step in (("GB", 10**9), ("MB", 10**6), ("kB", 10**3)):
        if count >= step:
            return f"{count / step:.1f} {unit}"
    return f"{count} B"


def _why(part: Unmeasured) -> str:
    return say(ENGLISH, "@state.unmeasured", why=part.unmeasured)


def ssl_lines(ssl: SslPart | Unmeasured) -> list[str]:
    """``ssl status``: the mode, the end, from when it renews, each domain."""
    if isinstance(ssl, Unmeasured):
        return [say(ENGLISH, "@state.ssl.none", why=_why(ssl))]
    renews = (
        ssl.renews_from if isinstance(ssl.renews_from, str) else _why(ssl.renews_from)
    )
    lines = [
        say(
            ENGLISH,
            "@state.ssl",
            mode=ssl.mode,
            expires=ssl.expires,
            renews=renews,
        )
    ]
    for domain in ssl.domains:
        key = "@state.ssl.covered" if domain.covered else "@state.ssl.uncovered"
        lines.append(say(ENGLISH, key, domain=domain.domain, expires=ssl.expires))
    return lines


def console_lines(state: BoxSnapshot) -> list[str]:
    """The form for a person: stacks, entries, services, resources, SSL."""
    lines: list[str] = []
    if isinstance(state.stacks, Unmeasured):
        lines.append(say(ENGLISH, "@state.stacks.none", why=_why(state.stacks)))
    elif not state.stacks:
        lines.append(say(ENGLISH, "@state.stacks.empty"))
    for stack in state.stacks if isinstance(state.stacks, list) else []:
        release = (
            stack.release if isinstance(stack.release, str) else _why(stack.release)
        )
        lines.append(say(ENGLISH, "@state.stack", stack=stack.stack, release=release))
        if isinstance(stack.entries, Unmeasured):
            lines.append(say(ENGLISH, "@state.entry.none", why=_why(stack.entries)))
            continue
        for entry in stack.entries:
            if isinstance(entry.services, Unmeasured):
                shown = _why(entry.services)
            else:
                shown = ", ".join(
                    say(ENGLISH, "@state.service", service=s.service, state=s.state)
                    + (f" ({s.health})" if s.health != "none" else "")
                    for s in entry.services
                ) or say(ENGLISH, "@state.entry.empty")
            lines.append(
                say(ENGLISH, "@state.entry", entry=entry.entry, services=shown)
            )
    res = state.resources
    for disk in res.disk:
        shown = (
            _why(disk.space)
            if isinstance(disk.space, Unmeasured)
            else say(
                ENGLISH,
                "@state.free",
                free=_size(disk.space.free_bytes),
                total=_size(disk.space.total_bytes),
            )
        )
        lines.append(say(ENGLISH, "@state.disk", path=disk.path, shown=shown))
    for key, part in (("@state.memory", res.memory), ("@state.swap", res.swap)):
        if isinstance(part, Unmeasured):
            shown = _why(part)
        elif isinstance(part, Memory):
            shown = say(
                ENGLISH,
                "@state.free",
                free=_size(part.available_bytes),
                total=_size(part.total_bytes),
            )
        elif part.total_bytes == 0:
            shown = say(ENGLISH, "@state.swap.none")
        else:
            shown = say(
                ENGLISH,
                "@state.free",
                free=_size(part.free_bytes),
                total=_size(part.total_bytes),
            )
        lines.append(say(ENGLISH, key, shown=shown))
    images = res.images
    lines.append(
        say(ENGLISH, "@state.images", shown=_why(images))
        if isinstance(images, Unmeasured)
        else say(
            ENGLISH,
            "@state.images",
            shown=say(
                ENGLISH,
                "@state.images.size",
                count=images.count,
                size=_size(images.bytes),
                reclaimable=_size(images.reclaimable_bytes),
            ),
        )
    )
    lines += ssl_lines(state.ssl)
    if state.lock_open_by:
        lines.append(say(ENGLISH, "@state.lock", by=", ".join(state.lock_open_by)))
    if state.journals_without_verdict:
        lines.append(
            say(
                ENGLISH,
                "@state.journals",
                runs=", ".join(state.journals_without_verdict),
            )
        )
    return lines


def _run(args: Strict, ctx: Context) -> int:
    state = snapshot(ctx)
    if ctx.json:
        ctx.out.write(rendered(state) + "\n")
    else:
        said(ctx.out, "\n".join(console_lines(state)) + "\n")
    return 0


STATE = Verb("state", NoArgs, _run, verdict=False, box=False, prints_json=True)
"""``pridem state``: read, as ``logs`` and ``report`` -- no lock, no verdict."""
