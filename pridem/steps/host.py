"""Steps of the host (TZ sections 6.2 item 5, 7.3; incident III): a clean
Ubuntu 24.04 becomes a box ready for stacks.

The host is shared with other actors -- ``cloud-init``, the ``apt-daily*``
timers, an administrator -- so every step waits instead of breaking: ``apt``
always runs with ``DPkg::Lock::Timeout``, no lock is removed and no process
killed. Every step reads its fact back: a package is installed when
``dpkg-query`` says so, not when ``apt`` exited 0.

- ``preflight`` -- Ubuntu 24.04, root, free disk, a living docker if docker is
  installed, and DNS: each domain resolves to the box's public IP (two echo
  services must agree) and nowhere else -- an extra A record, say an old box's,
  is a mismatch. It has no ``act``; it fails before any step acts.
  The table ``{domain, resolves_to, expected}`` is the ``dns`` key of its
  fact, which the verdict builder copies to ``report.dns``.
- ``wait_host_quiet`` -- ``cloud-init status --wait`` when cloud-init is
  installed, the ``apt-daily*`` timers stopped for the run, the ``apt-daily*``
  services waited out. The stopped timers are recorded in
  ``host/paused-timers.json`` before they stop, so a run that dies still
  leaves the record; ``restore_timers`` in ``finally`` starts exactly them and
  deletes the record (contract 2 section 3). A record that is not a JSON list
  of timer names is ``paused-broken`` in both steps and stays as it is.
- ``provision_host`` -- the host packages, docker among them, from noble;
  ``apt-get`` runs with ``APT_ENV`` and asks nothing.
- ``daemon_json`` -- docker's log driver ``local`` (TZ section 7.3); docker is
  restarted only by ``install``, see ``DaemonJson``.
- ``ensure_network`` -- the machine's networks ``pridem`` (nginx and the
  applications of the stacks) and ``pridem-egress`` (a product's services and
  the proxy), both internal: no route out of the box goes through either
  (protocol 4.1). ``verify`` reads ``Internal`` back; a network of that name
  that is not internal is red, never recreated -- it is not this machine's.
- ``locale`` -- a UTF-8 locale: the console writes ``→ — ✓ ✗``.

Steps get their inputs from whoever builds the plan (domains, limits) and read
host files under ``root``; the machine's limits are constants.
"""

import ipaddress
import json
import os
import time
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import ClassVar

from pridem.events import Json, strings
from pridem.files import atomic_write
from pridem.runner import Stream
from pridem.steps.base import (
    CheckResult,
    Mode,
    StepContext,
    StepFailed,
    Verified,
    local_code,
)
from pridem.steps.base import Step as _Step
from pridem.steps.compose import EGRESS_NETWORK, NETWORK

APT_LOCK_TIMEOUT_S = 600
"""How long ``apt`` waits for a dpkg lock another actor holds: a constant of
the machine, not a passport field; longer means the host is not quiet."""

MIN_FREE_DISK_GIB = 10
"""Free space the root file system needs before anything is built."""

QUIET_TIMEOUT_S = 1800
"""How long ``wait_host_quiet`` waits for ``apt-daily*`` services and cloud-init."""

HOST_PACKAGES = ("docker.io", "docker-compose-v2", "ca-certificates", "locales")
APT_TIMERS = ("apt-daily.timer", "apt-daily-upgrade.timer")
APT_SERVICES = ("apt-daily.service", "apt-daily-upgrade.service")
ECHO_SERVICES = ("https://api.ipify.org", "https://checkip.amazonaws.com")
NETWORKS = (NETWORK, EGRESS_NETWORK)
UTF8_LOCALES = ("C.UTF-8", "en_US.UTF-8")
PAUSED = Path("opt/pridem/host/paused-timers.json")
PAUSED_CODES = {"paused-broken": "{path} is not a JSON list of timer names: {problem}"}
"""The code of a record of paused timers that cannot be read; both steps that
read it say it."""
ALL_MODES: frozenset[Mode] = frozenset({"install", "deploy", "reinstall"})


APT_ENV = {"DEBIAN_FRONTEND": "noninteractive", "NEEDRESTART_MODE": "a"}
"""What ``apt-get`` needs to ask nobody: no debconf dialog, and needrestart
restarts services by itself instead of asking (Ubuntu 24.04 asks)."""


def apt_get(*args: str, timeout_s: int) -> list[str]:
    """``apt-get`` that waits for a held dpkg lock instead of failing on it."""
    return ["apt-get", "-o", f"DPkg::Lock::Timeout={timeout_s}", *args]


def apt_env() -> dict[str, str]:
    """The environment of ``apt-get``: the machine's whole one and ``APT_ENV``."""
    return {**os.environ, **APT_ENV}


def _out(
    ctx: StepContext,
    argv: Sequence[str],
    *,
    expect: tuple[int, ...] = (0,),
    timeout: float = 120,
    env: Mapping[str, str] | None = None,
) -> tuple[int, list[str]]:
    """Run ``argv``; its stdout lines, and every line to the step's log."""
    lines: list[str] = []

    def keep(stream: Stream, line: str, cut: bool) -> None:
        ctx.on_line(stream, line, cut)
        if stream is Stream.STDOUT:
            lines.append(line)

    result = ctx.runner.run(
        list(argv), expect=expect, timeout=timeout, env=env, on_line=keep
    )
    return result.code, lines


def _j(items: Sequence[str]) -> list[Json]:
    """Strings as a JSON list (a fact or a code's parameter)."""
    return list(items)


def _installed(ctx: StepContext, package: str) -> bool:
    code, lines = _out(
        ctx, ["dpkg-query", "-W", "-f=${Status}", package], expect=(0, 1)
    )
    return code == 0 and lines == ["install ok installed"]


def _active(ctx: StepContext, unit: str) -> bool:
    code, _ = _out(ctx, ["systemctl", "is-active", unit], expect=(0, 3))
    return code == 0


class _HostStep(_Step):
    """A host step: runs in every mode, on every role, reads files under ``root``."""

    modes = ALL_MODES

    def __init__(self, root: Path = Path("/")) -> None:
        self.root = root

    def _read(self, relative: str | Path) -> str | None:
        path = self.root / relative
        return path.read_text(encoding="utf-8") if path.exists() else None


def public_ip(ctx: StepContext) -> str:
    """The box's public IPv4, agreed by every echo service, or red."""
    answers: list[str] = []
    for url in ECHO_SERVICES:
        _, lines = _out(ctx, ["curl", "-fsS", "--max-time", "10", url])
        answers.append(lines[0].strip() if lines else "")
    try:
        addresses = {str(ipaddress.IPv4Address(answer)) for answer in answers}
    except ValueError:
        addresses = set()
    if len(addresses) != 1:
        raise StepFailed("public-ip-unknown", {"answers": _j(answers)})
    return addresses.pop()


def dns_table(
    ctx: StepContext, domains: Sequence[str]
) -> tuple[str, list[Json], list[str]]:
    """The box's public IP, ``domain -> resolves_to -> expected`` for each
    domain, and the domains that do not resolve to the box (contract 1 rule
    6). ``preflight`` and ``ssl`` (DM-17) read DNS by this one function."""
    ip = public_ip(ctx)
    table: list[Json] = []
    wrong: list[str] = []
    for domain in domains:
        _, lines = _out(ctx, ["getent", "ahostsv4", domain], expect=(0, 2))
        resolved = sorted({line.split()[0] for line in lines if line.strip()})
        table.append({"domain": domain, "resolves_to": _j(resolved), "expected": ip})
        if resolved != [ip]:  # every address is the box's
            wrong.append(domain)
    return ip, table, wrong


class Preflight(_HostStep):
    name = "preflight"
    order = 1
    codes: ClassVar[dict[str, str]] = {
        "not-ubuntu-24.04": "needs Ubuntu 24.04, found {found}",
        "not-root": "needs root, runs as uid {uid}",
        "disk-low": "{free_gib} GiB free on {path}, needs {min_gib}",
        "docker-dead": "docker is installed and does not answer",
        "public-ip-unknown": "the echo services disagree on the public IP: {answers}",
        "dns-mismatch": "domains do not resolve to this box: {domains}",
    }

    def __init__(
        self,
        root: Path = Path("/"),
        *,
        domains: Sequence[str] = (),
        min_free_gib: float = MIN_FREE_DISK_GIB,
    ) -> None:
        super().__init__(root)
        self.domains = tuple(domains)
        self.min_free_gib = min_free_gib

    def check(self, ctx: StepContext) -> CheckResult:
        return CheckResult(False)  # preflight only reads; it never acts

    def act(self, ctx: StepContext, check: CheckResult) -> None:
        raise AssertionError("preflight has no act")

    def _os(self) -> str:
        pairs = {}
        for line in (self._read("etc/os-release") or "").splitlines():
            key, _, value = line.partition("=")
            pairs[key] = value.strip('"')
        return f"{pairs.get('ID', '')} {pairs.get('VERSION_ID', '')}".strip()

    def verify(self, ctx: StepContext, check: CheckResult) -> Verified:
        found = self._os()
        if found != "ubuntu 24.04":
            raise StepFailed("not-ubuntu-24.04", {"found": found or "none"})
        _, uid = _out(ctx, ["id", "-u"])
        if uid != ["0"]:
            raise StepFailed("not-root", {"uid": uid[0] if uid else "?"})
        disk = os.statvfs(self.root)
        free_gib = round(disk.f_bavail * disk.f_frsize / 2**30, 1)
        if free_gib < self.min_free_gib:
            raise StepFailed(
                "disk-low",
                {
                    "free_gib": free_gib,
                    "path": str(self.root),
                    "min_gib": self.min_free_gib,
                },
            )
        fact: dict[str, Json] = {"os": found, "root": True, "free_gib": free_gib}
        if _installed(ctx, "docker.io"):
            code, version = _out(
                ctx,
                ["docker", "version", "--format", "{{.Server.Version}}"],
                expect=(0, 1),
            )
            if code != 0:
                raise StepFailed("docker-dead")
            fact["docker"] = version[0] if version else ""
        if self.domains:
            ip, table, wrong = dns_table(ctx, self.domains)
            fact["public_ip"] = ip
            fact["dns"] = table
            if wrong:
                raise StepFailed("dns-mismatch", {"domains": _j(wrong)}, fact)
        return Verified(fact)


class WaitHostQuiet(_HostStep):
    name = "wait_host_quiet"
    order = 2
    codes: ClassVar[dict[str, str]] = {
        "pause": "stop {timers} and wait for {services}",
        "host-busy": "{services} still running after {timeout_s} s",
        "timers-running": "{timers} still active after the pause",
        **PAUSED_CODES,
    }

    def __init__(
        self,
        root: Path = Path("/"),
        *,
        timeout_s: float = QUIET_TIMEOUT_S,
        poll_s: float = 5.0,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        super().__init__(root)
        self.timeout_s = timeout_s
        self.poll_s = poll_s
        self.clock = clock
        self.sleep = sleep

    def check(self, ctx: StepContext) -> CheckResult:
        timers = [timer for timer in APT_TIMERS if _active(ctx, timer)]
        services = [service for service in APT_SERVICES if _active(ctx, service)]
        if not timers and not services:
            return CheckResult(False)
        return CheckResult(
            True,
            local_code("pause", {"timers": _j(timers), "services": _j(services)}),
            {"timers": _j(timers)},
        )

    def act(self, ctx: StepContext, check: CheckResult) -> None:
        if _installed(ctx, "cloud-init"):
            _out(ctx, ["cloud-init", "status", "--wait"], timeout=self.timeout_s)
        timers = strings(check.data.get("timers"))
        if timers:
            _record_paused(
                self.root, timers
            )  # before stopping: a dying run leaves the record
            _out(ctx, ["systemctl", "stop", *timers])
        deadline = self.clock() + self.timeout_s
        while busy := [service for service in APT_SERVICES if _active(ctx, service)]:
            if self.clock() >= deadline:
                raise StepFailed(
                    "host-busy", {"services": _j(busy), "timeout_s": self.timeout_s}
                )
            ctx.interrupt.check()  # a signal ends the wait (DM-45)
            self.sleep(self.poll_s)
            ctx.interrupt.check()

    def verify(self, ctx: StepContext, check: CheckResult) -> Verified:
        paused = _paused(self.root)
        running = [timer for timer in paused if _active(ctx, timer)]
        if running:
            raise StepFailed("timers-running", {"timers": _j(running)})
        busy = [service for service in APT_SERVICES if _active(ctx, service)]
        if busy:
            raise StepFailed(
                "host-busy", {"services": _j(busy), "timeout_s": self.timeout_s}
            )
        return Verified({"paused": _j(paused), "busy": []})


def _paused(root: Path) -> list[str]:
    """The timers in the record; a record that is not a JSON list of names is
    ``paused-broken`` and stays as it is: which timers it held is not known."""
    path = root / PAUSED
    if not path.exists():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except UnicodeDecodeError:
        raise StepFailed(
            "paused-broken", {"path": str(path), "problem": "not UTF-8"}
        ) from None
    except json.JSONDecodeError as error:
        raise StepFailed(
            "paused-broken", {"path": str(path), "problem": f"line {error.lineno}"}
        ) from None
    if not isinstance(data, list):
        raise StepFailed("paused-broken", {"path": str(path), "problem": "not a list"})
    timers = [timer for timer in data if isinstance(timer, str)]
    if len(timers) != len(data):
        raise StepFailed(
            "paused-broken", {"path": str(path), "problem": "not a list of strings"}
        )
    return timers


def _record_paused(root: Path, timers: Sequence[str]) -> None:
    """Add ``timers`` to the record (0600, ``atomic_write``); a crash keeps the
    old one."""
    path = root / PAUSED
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    merged = sorted({*_paused(root), *timers})
    atomic_write(path, json.dumps(merged), 0o600)


class RestoreTimers(_HostStep):
    """``finally``: start exactly the timers ``wait_host_quiet`` recorded."""

    name = "restore_timers"
    order = 1
    codes: ClassVar[dict[str, str]] = {
        "restore": "start {timers}",
        "timers-stopped": "{timers} did not start again",
        **PAUSED_CODES,
    }

    def check(self, ctx: StepContext) -> CheckResult:
        paused = _paused(self.root)
        if not paused:
            return CheckResult(False)
        return CheckResult(
            True, local_code("restore", {"timers": _j(paused)}), {"timers": _j(paused)}
        )

    def act(self, ctx: StepContext, check: CheckResult) -> None:
        timers = _paused(self.root)
        _out(ctx, ["systemctl", "start", *timers])
        (self.root / PAUSED).unlink()

    def verify(self, ctx: StepContext, check: CheckResult) -> Verified:
        timers = strings(check.data.get("timers"))
        stopped = [timer for timer in timers if not _active(ctx, timer)]
        if stopped:
            raise StepFailed("timers-stopped", {"timers": _j(stopped)})
        return Verified(
            {"restored": _j(timers), "record": (self.root / PAUSED).exists()}
        )


class ProvisionHost(_HostStep):
    name = "provision_host"
    order = 3
    codes: ClassVar[dict[str, str]] = {
        "install": "install {packages}",
        "package-missing": "{packages} not installed after apt-get",
        "docker-dead": "docker is installed and does not run",
    }

    def __init__(
        self,
        root: Path = Path("/"),
        *,
        packages: Sequence[str] = HOST_PACKAGES,
        lock_timeout_s: int = APT_LOCK_TIMEOUT_S,
    ) -> None:
        super().__init__(root)
        self.packages = tuple(packages)
        self.lock_timeout_s = lock_timeout_s

    def check(self, ctx: StepContext) -> CheckResult:
        missing = [package for package in self.packages if not _installed(ctx, package)]
        if not missing:
            return CheckResult(False)
        return CheckResult(
            True,
            local_code("install", {"packages": _j(missing)}),
            {"missing": _j(missing)},
        )

    def act(self, ctx: StepContext, check: CheckResult) -> None:
        missing = strings(check.data.get("missing"))
        timeout = self.lock_timeout_s + 1800
        update = apt_get("update", timeout_s=self.lock_timeout_s)
        _out(ctx, update, timeout=timeout, env=apt_env())
        install = apt_get(
            "install",
            "-y",
            "--no-install-recommends",
            *missing,
            timeout_s=self.lock_timeout_s,
        )
        _out(ctx, install, timeout=timeout, env=apt_env())

    def verify(self, ctx: StepContext, check: CheckResult) -> Verified:
        missing = [package for package in self.packages if not _installed(ctx, package)]
        if missing:
            raise StepFailed("package-missing", {"packages": _j(missing)})
        if not _active(ctx, "docker"):
            raise StepFailed("docker-dead")
        _, version = _out(ctx, ["docker", "version", "--format", "{{.Server.Version}}"])
        return Verified(
            {"packages": _j(self.packages), "docker": version[0] if version else ""}
        )


class DaemonJson(_HostStep):
    """docker logs with ``local``: in ``daemon.json`` and in the running daemon.

    The file is written when it says otherwise (``atomic_write``, 0644; its
    other keys kept). Whether docker must restart is the running daemon's driver
    (``docker info``), not the file: a daemon already on ``local`` needs none.
    ``install`` restarts docker (``systemctl restart docker``) when the running
    daemon is on another driver, and its ``verify`` reads the driver again: a
    daemon still not on ``local`` after the restart is red ``log-driver-wrong``.
    Only ``install`` restarts docker -- on a box that runs its stacks
    (``deploy``, ``reinstall``) a restart would stop every container, so a
    daemon still on another driver is ``incomplete restart-needed`` (exit 2),
    the file waiting for docker's next restart. A ``daemon.json`` that is not
    JSON is refused by its code and never overwritten: its other keys are not
    known.
    """

    name = "daemon_json"
    order = 4
    codes: ClassVar[dict[str, str]] = {
        "log-driver": "set docker's log driver to local",
        "restart": "set docker's log driver to local and restart docker",
        "log-driver-wrong": "docker logs with {found}, not local",
        "restart-needed": (
            "docker logs with {found} until its next restart; daemon.json says local"
        ),
        "daemon-json-broken": "{path} is not a JSON object: {problem}",
    }
    PATH = Path("etc/docker/daemon.json")

    def _config(self) -> dict[str, Json]:
        text = self._read(self.PATH)
        if text is None or not text.strip():
            return {}
        try:
            loaded = json.loads(text)
        except json.JSONDecodeError as error:
            raise StepFailed(
                "daemon-json-broken",
                {"path": str(self.root / self.PATH), "problem": f"line {error.lineno}"},
            ) from None
        if not isinstance(loaded, dict):
            raise StepFailed(
                "daemon-json-broken",
                {"path": str(self.root / self.PATH), "problem": "not an object"},
            )
        return loaded

    def _running(self, ctx: StepContext) -> str:
        _, lines = _out(ctx, ["docker", "info", "--format", "{{.LoggingDriver}}"])
        return lines[0].strip() if lines else ""

    def check(self, ctx: StepContext) -> CheckResult:
        written = self._config().get("log-driver") == "local"
        running = self._running(ctx)
        if written and running == "local":
            return CheckResult(False)
        restart = running != "local" and ctx.mode == "install"
        code = local_code("restart" if restart else "log-driver")
        return CheckResult(True, code, {"restart": restart})

    def act(self, ctx: StepContext, check: CheckResult) -> None:
        config = self._config()
        if config.get("log-driver") != "local":
            config = {**config, "log-driver": "local"}  # other keys are kept
            path = self.root / self.PATH
            path.parent.mkdir(parents=True, exist_ok=True)
            atomic_write(path, json.dumps(config, indent=2) + "\n", 0o644)
        if check.data.get("restart") is True:  # only install decides so
            _out(ctx, ["systemctl", "restart", "docker"])

    def verify(self, ctx: StepContext, check: CheckResult) -> Verified:
        written = self._config().get("log-driver")
        if written != "local":
            raise StepFailed("log-driver-wrong", {"found": str(written or "none")})
        found = self._running(ctx)
        fact: dict[str, Json] = {"log_driver": found or "none", "daemon_json": "local"}
        if found == "local":
            return Verified(fact)
        if ctx.mode == "install":
            raise StepFailed("log-driver-wrong", {"found": found or "none"})
        return Verified(
            fact, incomplete=local_code("restart-needed", {"found": found or "none"})
        )


class EnsureNetwork(_HostStep):
    name = "ensure_network"
    order = 5
    codes: ClassVar[dict[str, str]] = {
        "create": "create the internal docker networks {networks}",
        "missing": "the docker network {network} is missing",
        "not-internal": "the docker network {network} is not internal",
    }

    def _internal(self, ctx: StepContext, network: str) -> bool | None:
        """Whether ``network`` is internal; ``None`` -- there is none."""
        code, lines = _out(
            ctx,
            ["docker", "network", "inspect", "--format", "{{.Internal}}", network],
            expect=(0, 1),
        )
        if code != 0:
            return None
        return lines == ["true"]

    def check(self, ctx: StepContext) -> CheckResult:
        missing: list[str] = []
        for network in NETWORKS:
            internal = self._internal(ctx, network)
            if internal is None:
                missing.append(network)
            elif not internal:
                raise StepFailed("not-internal", {"network": network})
        if not missing:
            return CheckResult(False)
        return CheckResult(
            True,
            local_code("create", {"networks": _j(missing)}),
            {"missing": _j(missing)},
        )

    def act(self, ctx: StepContext, check: CheckResult) -> None:
        for network in strings(check.data.get("missing")):
            _out(
                ctx,
                [
                    "docker",
                    "network",
                    "create",
                    "--internal",
                    "--label",
                    "pridem.stack=host",
                    network,
                ],
            )

    def verify(self, ctx: StepContext, check: CheckResult) -> Verified:
        for network in NETWORKS:
            internal = self._internal(ctx, network)
            if internal is None:
                raise StepFailed("missing", {"network": network})
            if not internal:
                raise StepFailed("not-internal", {"network": network})
        return Verified({"networks": _j(NETWORKS), "internal": True})


class Locale(_HostStep):
    name = "locale"
    order = 6
    codes: ClassVar[dict[str, str]] = {
        "set": "set LANG={lang}",
        "not-utf8": "LANG is {found}, not UTF-8",
    }
    PATH = Path("etc/default/locale")

    def _lang(self) -> str:
        for line in (self._read(self.PATH) or "").splitlines():
            key, _, value = line.partition("=")
            if key.strip() == "LANG":
                return value.strip().strip('"')
        return ""

    def check(self, ctx: StepContext) -> CheckResult:
        if self._lang() in UTF8_LOCALES:
            return CheckResult(False)
        return CheckResult(True, local_code("set", {"lang": UTF8_LOCALES[0]}))

    def act(self, ctx: StepContext, check: CheckResult) -> None:
        _out(ctx, ["update-locale", f"LANG={UTF8_LOCALES[0]}"])

    def verify(self, ctx: StepContext, check: CheckResult) -> Verified:
        lang = self._lang()
        if lang not in UTF8_LOCALES:
            raise StepFailed("not-utf8", {"found": lang or "none"})
        return Verified({"lang": lang})


def host_steps(
    root: Path = Path("/"),
    *,
    domains: Sequence[str] = (),
    min_free_gib: float = MIN_FREE_DISK_GIB,
    lock_timeout_s: int = APT_LOCK_TIMEOUT_S,
    quiet_timeout_s: float = QUIET_TIMEOUT_S,
) -> tuple[list[_Step], list[_Step]]:
    """The host ladder and its ``finally``: what a plan builder puts first."""
    main: list[_Step] = [
        Preflight(root, domains=domains, min_free_gib=min_free_gib),
        WaitHostQuiet(root, timeout_s=quiet_timeout_s),
        ProvisionHost(root, lock_timeout_s=lock_timeout_s),
        DaemonJson(root),
        EnsureNetwork(root),
        Locale(root),
    ]
    return main, [RestoreTimers(root)]
