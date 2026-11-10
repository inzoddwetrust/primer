"""git for the machine: one environment, one identity per repository.

git runs through the runner with an explicit environment, never a copy of the
caller's (``env`` replaces it): an inherited ``GIT_DIR`` or ``GIT_WORK_TREE``
would aim git at another repository, a root ``url.*.insteadOf`` would change an
address, and a prompt for ``https`` credentials would wait. The box and a test
see the same git.

A repository's identity is its full path -- host, port, account, name -- so
``partner-x/velo-look`` and ``partner-y/velo-look`` get two keys and two ssh
aliases, and so do one path on two ports. ``file://`` repositories need no key.

An address is read without losses: the scp form ``[user@]host:path`` and
``ssh://[user@]host[:port]/path`` keep their user (``git`` when the address
names none), port and path as given; git is pointed at the ssh alias in the
same form, and the alias's ``Host`` block carries the user and the port.
``https://`` and ``http://`` are refused: the machine reaches repositories by
deploy keys over ssh only (passport ``access.mode: deploy-keys``).
"""

import os
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from pridem.runner import Stream
from pridem.steps.base import StepContext

KEYS = Path("opt/pridem/keys")
"""The machine's keys, ``ssh_config`` and ``known_hosts`` (contract 2 section 3)."""

_SCP = re.compile(r"^(?:(?P<user>[\w.-]+)@)?(?P<host>[\w.-]+):(?P<path>[^/].*)$")
_SSH = re.compile(
    r"^ssh://(?:(?P<user>[\w.-]+)@)?(?P<host>[\w.-]+)(?::(?P<port>[0-9]+))?/(?P<path>.+)$"
)
_WEB = re.compile(r"^(?P<scheme>https?)://", re.IGNORECASE)
DEFAULT_USER = "git"
"""The ssh user when an address names none: the user of git hostings."""
GITHUB = "github.com"

Form = Literal["scp", "ssh", "file"]


@dataclass(frozen=True)
class Repo:
    """A repository as the machine reaches it."""

    address: str
    host: str  # "" for file://
    path: str  # account/name, without .git and slashes at the ends
    user: str = DEFAULT_USER  # "" for file://
    port: int | None = None
    form: Form = "scp"
    remote: str = ""  # the path as the address gives it

    @property
    def local(self) -> bool:
        return not self.host

    @property
    def pinned(self) -> bool:
        """GitHub on its ssh port: its host keys are the machine's own copy."""
        return self.host.lower() == GITHUB and self.port in (None, 22)

    @property
    def alias(self) -> str:
        """The ssh alias and key name: from host, port and full path, lower case."""
        port = "" if self.port is None else f"-{self.port}"
        raw = f"{self.host}{port}-{self.path}"
        return "pridem-" + re.sub(r"[^a-z0-9.-]+", "-", raw.lower()).strip("-")

    @property
    def name(self) -> str:
        return self.path.rsplit("/", 1)[-1]

    def url(self) -> str:
        """What git fetches from: the alias in the address's own form for ssh, the
        address itself for file://."""
        if self.form == "file":
            return self.address
        if self.form == "ssh":
            return f"ssh://{self.alias}/{self.remote}"
        return f"{self.alias}:{self.remote}"


def repo(address: str) -> Repo:
    """Parse ``[user@]host:path``, ``ssh://[user@]host[:port]/path`` or
    ``file://``; ``https://`` and ``http://`` are refused."""
    if address.startswith("file://"):
        path = address.removeprefix("file://").removesuffix(".git")
        return Repo(address, "", path, user="", form="file", remote=path)
    web = _WEB.match(address)
    if web is not None:
        raise ValueError(
            f"{web['scheme'].lower()} is not supported: add an ssh address"
        )
    ssh = _SSH.match(address)
    match = ssh or _SCP.match(address)
    if match is None:
        raise ValueError(f"not a repository address: {address!r}")
    port = int(ssh["port"]) if ssh is not None and ssh["port"] is not None else None
    if port is not None and not 1 <= port <= 65535:
        raise ValueError(f"not a repository address: {address!r} (port {port})")
    path = match["path"].strip("/").removesuffix(".git")
    if not path:
        raise ValueError(f"not a repository address: {address!r} (no path)")
    return Repo(
        address,
        match["host"],
        path,
        user=match["user"] or DEFAULT_USER,
        port=port,
        form="ssh" if ssh is not None else "scp",
        remote=match["path"],
    )


def collisions(addresses: Sequence[str]) -> list[str]:
    """Different repositories, or one repository by two users, that would share
    one alias (one key, one ``Host`` block with one user): sorted."""
    seen: dict[str, tuple[str, str]] = {}
    clashes: set[str] = set()
    for address in addresses:
        found = repo(address)
        if found.local:
            continue
        other = seen.setdefault(found.alias, (found.path, found.user))
        if other != (found.path, found.user):
            clashes.add(found.alias)
    return sorted(clashes)


def git_env(root: Path) -> dict[str, str]:
    """The whole environment of every git the machine runs."""
    keys = root / KEYS
    return {
        "PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "HOME": str(keys),
        "GIT_SSH_COMMAND": f"ssh -F {keys / 'ssh_config'}",
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
    }


def run_git(
    ctx: StepContext,
    root: Path,
    args: Sequence[str],
    *,
    expect: tuple[int, ...] = (0,),
    timeout: float = 600,
    env: Mapping[str, str] | None = None,
    stderr: list[str] | None = None,
) -> tuple[int, list[str]]:
    """``git <args>`` with the machine's environment; its stdout lines.

    Pieces of a long line (``continued``) are joined back, so a file read with
    ``git show`` comes back whole. ``stderr``, when given, gets the lines of
    stderr too, as they come (pieces not joined).
    """
    lines: list[str] = []
    joining = False

    def keep(stream: Stream, line: str, cut: bool) -> None:
        nonlocal joining
        ctx.on_line(stream, line, cut)
        if stream is not Stream.STDOUT:
            if stderr is not None:
                stderr.append(line)
            return
        if joining and lines:
            lines[-1] += line
        else:
            lines.append(line)
        joining = cut

    result = ctx.runner.run(
        ["git", *args],
        expect=expect,
        timeout=timeout,
        env=dict(env) if env is not None else git_env(root),
        on_line=keep,
    )
    return result.code, lines
