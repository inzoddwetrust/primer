"""``egress``: the machine's proxy for a product's ``egress`` (protocol 4.1,
4.2; DM-64).

No container of a product has a route out of the box: the networks of its
stacks are internal (the override, ``steps/compose.py``), and so are
``pridem`` and ``pridem-egress`` (``ensure_network``). A product that declares
``egress`` reaches exactly those hosts through this proxy: squid, from the
image ``SQUID_IMAGE`` pinned by digest, in the compose project
``pridem-egress`` of the machine's file ``/opt/pridem/egress/compose.yml``. The
proxy sits on ``pridem-egress`` under ``PROXY_ALIAS`` -- every service of the
product's stacks joins it and has the address as ``HTTPS_PROXY`` and
``https_proxy`` -- and on its project's own ordinary network ``default``, its
way out. Every object carries ``pridem.stack=egress``.

The proxy runs as the image's user ``proxy`` from its first instruction, by
``/usr/sbin/squid`` itself in the foreground (``entrypoint``, ``command``), its
own messages on stderr (``-d 1``). squid opens its access log after it drops to
``proxy``, and ``/dev/stdout`` of a container is the pipe runc gives the
container's user: started as root, squid cannot open it and stops (``FATAL:
Cannot open '/dev/stdout' for writing``; measured with squid 6.6 of Ubuntu
24.04, the image's version, DM-45 FIX); started as ``proxy``, the pipe is its
own.

The config (``/opt/pridem/egress/squid.conf``, rendered by ``config_text``) lets
through ``CONNECT`` to port 443 of a host of ``egress``, by its name exactly
(``dstdomain -n``, no leading dot: ``zoom.us`` is not ``api.zoom.us``), and
nothing else: any other method, any other port, any address of a private range
(a name that resolves into the box is refused) and any other host get 403. It
keeps no cache. Its access log goes to the container's stdout (the host's
docker keeps it, driver ``local``): one line per request, ``LOG_TAG``, the
host, the port, the status sent and squid's result -- ``TCP_TUNNEL`` let
through, ``TCP_DENIED`` 403 -- and never a path, a query or a body.

The step runs once per product, in its ladder after ``migrate`` -- the point of
no return: a failed migration leaves the old code on the old list -- and before
``up``: the new application starts with its proxy ready. ``check`` compares the
rendered files with those on disk, the running container with the pinned image;
``act`` writes the files (``atomic_write``, 0644: squid reads its config as its
own user) and recreates the container (``up -d --force-recreate``). With
``egress`` empty there is no proxy: ``act`` removes the one a previous release
left (``down`` of its project, or ``rm -f`` by label when its file is gone) and
the files. ``verify`` reads the fact back:

- empty ``egress`` -- no container labelled ``pridem.stack=egress``, running or
  not, and no file;
- otherwise -- the files are the rendered ones; one container runs, on the
  image of ``SQUID_IMAGE``; the config it reads is the rendered one; and the
  behaviour: from the host, at the proxy's address on its own network,
  ``CONNECT`` to ``SENTINEL`` -- a host on no list -- is 403, and to every host
  of ``egress`` is anything but 403 (200, or a 5xx when the host itself does not
  answer: the list is what is read, not the host's health); and the access
  log, read from ``docker logs`` up to ``ready_s``: a line of ``SENTINEL``, port
  443, 403.

A proxy that does not answer, that writes no line of ``SENTINEL``, that the
config cannot be read from (``docker exec``) or that is not running is red with
what docker says of it in the fact (``diagnosis``): the container's ``Status``,
``ExitCode``, ``RestartCount`` and ``Error``, and the last ``LOG_TAIL`` lines of
``docker logs`` -- squid's own messages among them. Those lines go to the run's
journal too. A command of the diagnosis that fails is named in the fact by its
exit code; it never hides the refusal it explains.
"""

import json
import socket
import time
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import ClassVar

from pridem.events import Fact, Json
from pridem.runner import CommandFailed, Stream
from pridem.stacks.options import open_hosts, switched_on
from pridem.stacks.schema import Product
from pridem.steps.base import (
    CheckResult,
    Mode,
    Step,
    StepContext,
    StepFailed,
    Verified,
    local_code,
)
from pridem.steps.compose import EGRESS_NETWORK, PROXY_ALIAS, PROXY_PORT, out
from pridem.steps.edge import write_file
from pridem.steps.passport import NO_PASSPORT, Fetched

ALL_MODES: frozenset[Mode] = frozenset({"install", "deploy", "reinstall"})
PROJECT = "pridem-egress"
STACK_LABEL = {"pridem.stack": "egress"}
LABEL_FILTER = "label=pridem.stack=egress"
OUTSIDE = f"{PROJECT}_default"
"""The proxy's own ordinary network: its way out, and where the host reads it."""

SQUID_IMAGE = (
    "ubuntu/squid:6.6-24.04_beta@sha256:"
    "6a097f68bae708cedbabd6188d68c7e2e7a38cedd05a176e1cc0ba29e3bbe029"
)
"""squid of Canonical on Ubuntu 24.04, pinned by digest: the index digest
Docker Hub shows for the tag ``6.6-24.04_beta`` (DM-64). docker pulls by the
digest; the tag is for people. Tier 3 checks on every run that this tag names
this digest (``tier3/test_tier3_whole_install.py``)."""

CONTAINER_CONFIG = "/etc/squid/squid.conf"
SQUID_USER = "proxy"
"""The user of squid in the image: the container runs as it (above)."""
SQUID_COMMAND = ["-N", "-d", "1", "-f", CONTAINER_CONFIG]
"""``/usr/sbin/squid`` in the foreground, its messages on stderr."""
LOG_TAIL = 40
"""Lines of ``docker logs`` a refusal of the proxy carries in its fact."""
LINE_MAX = 400
STATE_FORMAT = (
    '{"status":{{json .State.Status}},"exit_code":{{.State.ExitCode}},'
    '"restarts":{{.RestartCount}},"error":{{json .State.Error}}}'
)
LOG_TAG = "pridem-egress"
LOG_FORMAT = f"{LOG_TAG} host=%>rd port=%>rP status=%>Hs result=%Ss"
"""squid 6 ``logformat`` codes: the request's domain and port, the status sent
to the client, squid's own result. No ``%ru``: a request that is not
``CONNECT`` carries its path there."""
SENTINEL = "refused.pridem.invalid"
"""A host on no list (``.invalid`` never resolves): the proxy must refuse it."""
PRIVATE = (
    "0.0.0.0/8",
    "10.0.0.0/8",
    "100.64.0.0/10",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "::1",
    "fc00::/7",
    "fe80::/10",
)
"""Addresses the proxy never connects to: the box and its networks."""
CONNECT_TIMEOUT_S = 10
"""How long squid waits for a host of ``egress`` to accept."""
ANSWER_TIMEOUT_S = 20
"""How long ``verify`` waits for the proxy's answer to one ``CONNECT``."""
READY_S = 30
"""How long ``verify`` waits for a recreated proxy to answer at all."""
REFUSED = 403

Answer = Callable[[str, int, str], int | None]
"""The status of ``CONNECT <host>:443`` sent to the proxy at ``(address, port)``;
``None`` -- no answer."""


def home(root: Path) -> Path:
    return root / "opt" / "pridem" / "egress"


def config_file(root: Path) -> Path:
    return home(root) / "squid.conf"


def compose_file(root: Path) -> Path:
    return home(root) / "compose.yml"


def argv(root: Path, *args: str) -> list[str]:
    return ["docker", "compose", "-p", PROJECT, "-f", str(compose_file(root)), *args]


def config_text(hosts: Sequence[str]) -> str:
    """squid's config: ``CONNECT`` to port 443 of ``hosts`` by name, nothing else."""
    lines = [
        "# rendered by pridem (protocol 4.2): CONNECT to the product's egress only",
        f"http_port {PROXY_PORT}",
        "acl SSL_ports port 443",
        "acl CONNECT method CONNECT",
        f"acl private dst {' '.join(PRIVATE)}",
        f"acl egress dstdomain -n {' '.join(hosts)}",
        "http_access deny !CONNECT",
        "http_access deny !SSL_ports",
        "http_access deny private",
        "http_access allow egress",
        "http_access deny all",
        "cache deny all",
        f"logformat pridem {LOG_FORMAT}",
        "access_log stdio:/dev/stdout pridem",
        f"connect_timeout {CONNECT_TIMEOUT_S} seconds",
        "shutdown_lifetime 1 seconds",
        "pid_filename none",
    ]
    return "\n".join(lines) + "\n"


def compose_text(root: Path) -> str:
    """The proxy's compose file: one service, on ``pridem-egress`` and its own
    ``default``."""
    labels: dict[str, Json] = dict[str, Json](STACK_LABEL)
    document: dict[str, Json] = {
        "services": {
            "proxy": {
                "image": SQUID_IMAGE,
                "user": SQUID_USER,
                "entrypoint": ["/usr/sbin/squid"],
                "command": list[Json](SQUID_COMMAND),
                "restart": "unless-stopped",
                "labels": labels,
                "networks": {
                    EGRESS_NETWORK: {"aliases": [PROXY_ALIAS]},
                    "default": None,
                },
                "volumes": [f"{config_file(root)}:{CONTAINER_CONFIG}:ro"],
            },
        },
        "networks": {EGRESS_NETWORK: {"external": True}, "default": {"labels": labels}},
    }
    return json.dumps(document, indent=2, sort_keys=True) + "\n"


def connect_status(address: str, port: int, host: str) -> int | None:
    """``CONNECT <host>:443`` to the proxy at ``(address, port)``: the status of
    its answer, ``None`` when it gives none."""
    request = f"CONNECT {host}:443 HTTP/1.1\r\nHost: {host}:443\r\n\r\n"
    try:
        with socket.create_connection((address, port), ANSWER_TIMEOUT_S) as conn:
            conn.sendall(request.encode("ascii"))
            line = conn.makefile("rb").readline(256)
    except OSError:
        return None
    parts = line.split()
    if len(parts) < 2 or not parts[0].startswith(b"HTTP/") or not parts[1].isdigit():
        return None
    return int(parts[1])


class Egress(Step):
    """The proxy of one product: there exactly when its ``egress`` is not empty."""

    name = "egress"
    order = 12
    modes = ALL_MODES
    codes: ClassVar[dict[str, str]] = {
        **NO_PASSPORT,
        "render": "run the proxy for {hosts}",
        "remove": "remove the proxy: no host of egress is open ({found})",
        "drift": "{files} are not the rendered ones",
        "not-running": "{count} proxy containers run, not one",
        "image-wrong": "the proxy runs on {running}, not on {expected}",
        "config-not-seen": "the proxy reads another config than the rendered one",
        "no-address": "the proxy has no address on {network}",
        "log-missing": "the proxy's log in its stdout has no line of {host}",
        "proxy-silent": "the proxy at {address} does not answer for {host}",
        "proxy-open": "the proxy lets {host} through: {status}, not 403",
        "host-refused": "the proxy refuses {hosts} of egress",
        "proxy-left": "egress is empty and the proxy is left: {found}",
    }

    def __init__(
        self,
        product: Product,
        *,
        fetched: Fetched,
        root: Path = Path("/"),
        answer: Answer = connect_status,
        port: int = PROXY_PORT,
        ready_s: float = READY_S,
        poll_s: float = 1.0,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self.product = product
        self.fetched = fetched
        self.root = root
        self.answer = answer
        self.port = port
        self.ready_s = ready_s
        self.poll_s = poll_s
        self.clock = clock
        self.sleep = sleep

    @property
    def hosts(self) -> list[str]:
        """The hosts the proxy lets through: the options on decide (rule 40)."""
        passport = self.fetched.passport
        if passport is None:
            raise StepFailed("no-passport")
        return open_hosts(self.product, switched_on(passport))

    def _files(self) -> list[Path]:
        return [
            path
            for path in (config_file(self.root), compose_file(self.root))
            if path.exists()
        ]

    def _drift(self) -> list[str]:
        """The machine's files that differ from the rendered ones."""
        wanted = {
            config_file(self.root): config_text(self.hosts),
            compose_file(self.root): compose_text(self.root),
        }
        return [
            str(path)
            for path, text in wanted.items()
            if not path.exists() or path.read_text(encoding="utf-8") != text
        ]

    def _containers(self, ctx: StepContext, *, running: bool) -> list[str]:
        args = ["docker", "ps", "-q", "--no-trunc", "--filter", LABEL_FILTER]
        if not running:
            args.insert(2, "-a")
        _, lines = out(ctx, args, passed_on=False)
        return [line.strip() for line in lines if line.strip()]

    def _one(self, ctx: StepContext, argv_: list[str]) -> str:
        _, lines = out(ctx, argv_, passed_on=False)
        return lines[0].strip() if lines else ""

    def _image(self, ctx: StepContext, container: str) -> tuple[str, str]:
        """The image the container was made from, and the one of ``SQUID_IMAGE``."""
        running = self._one(ctx, ["docker", "inspect", "-f", "{{.Image}}", container])
        expected = self._one(
            ctx, ["docker", "image", "inspect", "-f", "{{.Id}}", SQUID_IMAGE]
        )
        return running, expected

    # --- the step ------------------------------------------------------------------

    def check(self, ctx: StepContext) -> CheckResult:
        if not self.hosts:
            found = self._containers(ctx, running=False)
            files = self._files()
            if not found and not files:
                return CheckResult(False)
            params: dict[str, Json] = {
                "found": list[Json]([*found, *(str(path) for path in files)])
            }
            return CheckResult(True, local_code("remove", params), {"remove": True})
        needed = CheckResult(
            True, local_code("render", {"hosts": list[Json](self.hosts)})
        )
        if self._drift():
            return needed
        running = self._containers(ctx, running=True)
        if len(running) != 1:
            return needed
        image, expected = self._image(ctx, running[0])
        if not image or image != expected:
            return needed
        return CheckResult(False)

    def act(self, ctx: StepContext, check: CheckResult) -> None:
        if check.data.get("remove") is True:
            if compose_file(self.root).exists():
                out(ctx, argv(self.root, "down"))
            else:
                found = self._containers(ctx, running=False)
                if found:
                    out(ctx, ["docker", "rm", "-f", *found])
            for path in self._files():
                path.unlink()
            return
        write_file(config_file(self.root), config_text(self.hosts).encode(), 0o644)
        write_file(compose_file(self.root), compose_text(self.root).encode(), 0o644)
        out(ctx, argv(self.root, "up", "-d", "--force-recreate", "proxy"))

    def verify(self, ctx: StepContext, check: CheckResult) -> Verified:
        if not self.hosts:
            found = self._containers(ctx, running=False)
            files = [str(path) for path in self._files()]
            if found or files:
                raise StepFailed("proxy-left", {"found": list[Json]([*found, *files])})
            return Verified({"hosts": [], "proxy": "absent"})
        drift = self._drift()
        if drift:
            raise StepFailed("drift", {"files": list[Json](drift)})
        running = self._containers(ctx, running=True)
        if len(running) != 1:
            every = self._containers(ctx, running=False)
            fact = self.diagnosis(ctx, every[0]) if every else {"proxy": "none"}
            raise StepFailed("not-running", {"count": len(running)}, fact)
        container = running[0]
        image, expected = self._image(ctx, container)
        if not image or image != expected:
            raise StepFailed(
                "image-wrong", {"running": image or "none", "expected": SQUID_IMAGE}
            )
        try:
            _, seen = out(
                ctx,
                ["docker", "exec", container, "cat", CONTAINER_CONFIG],
                passed_on=False,
            )
        except CommandFailed as error:  # a container that restarts runs nothing
            fact = {**self.diagnosis(ctx, container), "exec_exit_code": error.code}
            raise StepFailed("not-running", {"count": 0}, fact) from None
        if "\n".join(seen) + "\n" != config_text(self.hosts):
            raise StepFailed("config-not-seen")
        address = self._address(ctx, container)
        refused = self._first_answer(ctx, address, container)
        if refused != REFUSED:
            raise StepFailed("proxy-open", {"host": SENTINEL, "status": refused})
        allowed: dict[str, Json] = {}
        denied: list[str] = []
        for host in self.hosts:
            status = self.answer(address, self.port, host)
            if status is None:
                raise StepFailed(
                    "proxy-silent",
                    {"address": address, "host": host},
                    self.diagnosis(ctx, container),
                )
            if status == REFUSED:
                denied.append(host)
            allowed[host] = status
        if denied:
            # DM-76 FIX: the refusal carries docker's word on the proxy (par0
            # 14.3) -- the reason of a 403 is in squid's log, not in the step
            raise StepFailed(
                "host-refused",
                {"hosts": list[Json](denied)},
                self.diagnosis(ctx, container),
            )
        return Verified(
            {
                "hosts": list[Json](self.hosts),
                "image": SQUID_IMAGE,
                "refused": {SENTINEL: REFUSED},
                "allowed": allowed,
                "log": self._logged(ctx, container),
            }
        )

    def _logged(self, ctx: StepContext, container: str) -> str:
        """The access log's line of the refused ``SENTINEL``, from the
        container's stdout, waiting up to ``ready_s`` for squid to write it."""
        wanted = f"{LOG_TAG} host={SENTINEL} port=443 status={REFUSED} "
        deadline = self.clock() + self.ready_s
        while True:
            _, lines = out(ctx, ["docker", "logs", container], passed_on=False)
            found = [line.strip() for line in lines if line.startswith(wanted)]
            if found:
                return found[-1]
            if self.clock() >= deadline:
                raise StepFailed(
                    "log-missing", {"host": SENTINEL}, self.diagnosis(ctx, container)
                )
            ctx.interrupt.check()
            self.sleep(self.poll_s)
            ctx.interrupt.check()

    def _address(self, ctx: StepContext, container: str) -> str:
        """The proxy's address on its own network, where the host reaches it."""
        text = self._one(
            ctx,
            [
                "docker",
                "inspect",
                "-f",
                "{{json .NetworkSettings.Networks}}",
                container,
            ],
        )
        try:
            networks = json.loads(text) if text else {}
        except json.JSONDecodeError:
            networks = {}
        attached = networks.get(OUTSIDE) if isinstance(networks, dict) else None
        address = attached.get("IPAddress") if isinstance(attached, dict) else None
        if not isinstance(address, str) or not address:
            raise StepFailed("no-address", {"network": OUTSIDE})
        return address

    def diagnosis(self, ctx: StepContext, container: str) -> Fact:
        """What docker says of the proxy: its state and the end of its log,
        both streams; each line also goes to the journal. A command here that
        fails is named by its exit code in the fact."""
        fact: dict[str, Json] = {"container": container}
        lines: list[tuple[Stream, str]] = []

        def keep(stream: Stream, line: str, cut: bool) -> None:
            lines.append((stream, line))
            ctx.on_line(stream, line, cut)

        state = ["docker", "inspect", "-f", STATE_FORMAT, container]
        result = ctx.runner.run(state, expect=(0, 1), timeout=60, on_line=keep)
        text = "\n".join(line for stream, line in lines if stream is Stream.STDOUT)
        try:
            found = json.loads(text) if result.code == 0 else None
        except json.JSONDecodeError:
            found = None
        fact["state"] = found if isinstance(found, dict) else {"inspect": result.code}
        lines.clear()
        tail = ["docker", "logs", "--tail", str(LOG_TAIL), container]
        result = ctx.runner.run(tail, expect=(0, 1), timeout=60, on_line=keep)
        fact["logs"] = [
            f"{'err' if stream is Stream.STDERR else 'out'}: {line[:LINE_MAX]}"
            for stream, line in lines
        ]
        if result.code != 0:
            fact["logs_exit_code"] = result.code
        return fact

    def _first_answer(self, ctx: StepContext, address: str, container: str) -> int:
        """The answer for ``SENTINEL``, waiting up to ``ready_s`` for a
        recreated proxy to answer at all."""
        deadline = self.clock() + self.ready_s
        while (status := self.answer(address, self.port, SENTINEL)) is None:
            if self.clock() >= deadline:
                raise StepFailed(
                    "proxy-silent",
                    {"address": address, "host": SENTINEL},
                    self.diagnosis(ctx, container),
                )
            ctx.interrupt.check()  # a signal ends the wait (DM-45)
            self.sleep(self.poll_s)
            ctx.interrupt.check()
        return status
