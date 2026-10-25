"""git for the machine: one environment, one identity per repository.

git runs through the runner with an explicit environment, never a copy of the
caller's (``env`` replaces it): an inherited ``GIT_DIR`` or ``GIT_WORK_TREE``
would aim git at another repository, a root ``url.*.insteadOf`` would change an
address, and a prompt for ``https`` credentials would wait. The box and a test
see the same git.

A repository's identity is its full path -- host, account, name -- so
``partner-x/velo-look`` and ``partner-y/velo-look`` get two keys and two ssh
aliases. ``file://`` repositories need no key.
"""

import os
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

from pridem.runner import Stream
from pridem.steps.base import StepContext

KEYS = Path("opt/pridem/keys")
"""The machine's keys, ``ssh_config`` and ``known_hosts`` (contract 2 section 3)."""

_SCP = re.compile(r"^(?:[\w.-]+@)?(?P<host>[\w.-]+):(?P<path>[^/].*)$")
_URL = re.compile(
    r"^(?:ssh|https?)://(?:[\w.-]+@)?(?P<host>[\w.-]+)(?::\d+)?/(?P<path>.+)$"
)


@dataclass(frozen=True)
class Repo:
    """A repository as the machine reaches it."""

    address: str
    host: str  # "" for file://
    path: str  # account/name, without .git

    @property
    def local(self) -> bool:
        return not self.host

    @property
    def alias(self) -> str:
        """The ssh alias and key name: from host and full path, lower case."""
        raw = f"{self.host}-{self.path}"
        return "pridem-" + re.sub(r"[^a-z0-9.-]+", "-", raw.lower()).strip("-")

    @property
    def name(self) -> str:
        return self.path.rsplit("/", 1)[-1]

    def url(self) -> str:
        """What git fetches from: the alias for ssh, the address itself for file://."""
        return self.address if self.local else f"{self.alias}:{self.path}.git"


def repo(address: str) -> Repo:
    """Parse ``git@host:acct/name.git``, ``ssh://``, ``https://`` or ``file://``."""
    if address.startswith("file://"):
        return Repo(address, "", address.removeprefix("file://").removesuffix(".git"))
    match = _URL.match(address) or _SCP.match(address)
    if match is None:
        raise ValueError(f"not a repository address: {address!r}")
    return Repo(address, match["host"], match["path"].strip("/").removesuffix(".git"))


def collisions(addresses: Sequence[str]) -> list[str]:
    """Different repositories that would share one alias (one key): sorted."""
    seen: dict[str, str] = {}
    clashes: set[str] = set()
    for address in addresses:
        found = repo(address)
        if found.local:
            continue
        other = seen.setdefault(found.alias, found.path)
        if other != found.path:
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
) -> tuple[int, list[str]]:
    """``git <args>`` with the machine's environment; its stdout lines.

    Pieces of a long line (``continued``) are joined back, so a file read with
    ``git show`` comes back whole.
    """
    lines: list[str] = []
    joining = False

    def keep(stream: Stream, line: str, cut: bool) -> None:
        nonlocal joining
        ctx.on_line(stream, line, cut)
        if stream is not Stream.STDOUT:
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
