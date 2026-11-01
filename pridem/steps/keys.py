"""The deploy-key ceremony (TZ section 6.2 item 3): a key per repository.

For a repository reached over ssh the machine mints an ed25519 pair under
``/opt/pridem/keys/`` (the private part 0600), prints the public part, and
waits until the repository answers ``git ls-remote`` with it -- the owner adds
the public part as a read-only deploy key meanwhile. ssh goes through the
machine's ``ssh_config``: ``Host <alias>`` per repository with its user, its
port when the address names one, its key only (``IdentitiesOnly yes``) and no
prompt ever (``BatchMode yes``). GitHub on its ssh port is checked against the
machine's own copy of GitHub's host keys, ``known_hosts.github``, and nothing
else (``StrictHostKeyChecking yes``, ``GlobalKnownHostsFile none``): no trust on
first use. Every other host goes to the machine's ``known_hosts``
(``StrictHostKeyChecking accept-new``). A repository's block is drawn again from
its address each time, the blocks of other repositories are kept; root's
``~/.ssh`` is never touched.
A key already in place with access and files already as drawn need no
``act`` -- tier 3 puts the key there from the CI secrets. ``check`` only
compares: the files are written by ``act`` and read back by ``verify``, so
``doctor`` changes nothing on disk. The private part is never in a fact, a log
or a reason.
"""

import time
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import ClassVar

from pridem.events import Json
from pridem.files import atomic_write
from pridem.runner import Stream
from pridem.steps.base import (
    CheckResult,
    Mode,
    Step,
    StepContext,
    StepFailed,
    Verified,
    local_code,
)
from pridem.steps.git import KEYS, Repo, collisions, repo, run_git

KEY_WAIT_S = 1800
"""How long the ceremony waits for the owner to add the public part."""

ALL_MODES: frozenset[Mode] = frozenset({"install", "deploy", "reinstall"})


GITHUB_HOST_KEYS: tuple[str, ...] = (
    (
        "ssh-ed25519 "
        "AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9"
        "GKJl"
    ),
    (
        "ecdsa-sha2-nistp256 "
        "AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBEmKSENjQEez"
        "OmxkZMy7opKgwFB9nkt5YRrYMjNuG5N87uRgg6CLrbo5wAdT/y6v0mKV0U2w0WZ2"
        "YB/++Tpockg="
    ),
    (
        "ssh-rsa "
        "AAAAB3NzaC1yc2EAAAADAQABAAABgQCj7ndNxQowgcQnjshcLrqPEiiphnt+VTTv"
        "DP6mHBL9j1aNUkY4Ue1gvwnGLVlOhGeYrnZaMgRK6+PKCUXaDbC7qtbW8gIkhL7a"
        "GCsOr/C56SJMy/BCZfxd1nWzAOxSDPgVsmerOBYfNqltV9/hWCqBywINIR+5dIg6"
        "JTJ72pcEpEjcYgXkE2YEFXV1JHnsKgbLWNlhScqb2UmyRkQyytRLtL+38TGxkxCf"
        "lmO+5Z8CSSNY7GidjMIZ7Q4zMjA2n1nGrlTDkzwDCsw+wqFPGQA179cnfGWOWRVr"
        "uj16z6XyvxvjJwbz0wQZ75XK5tKSb7FNyeIEs4TT4jk+S4dhPeAUC5y+bDYirYgM"
        "4GC7uEnztnZyaVWQ7B381AK4Qdrwt51ZqExKbQpTUNn+EjqoTwvqNj4kqx5QUCI0"
        "ThS/YkOxJCXmPUWZbhjpCg56i+2aB6CmK2JGhn57K5mj0MNdBXA4/WnwH6XoPWJz"
        "K5Nyu2zB3nAZp+S5hpQs+p1vN1/wsjk="
    ),
)
"""GitHub's ssh host keys, ``<type> <base64>``: the ``known_hosts`` lines of
GitHub's publication "GitHub's SSH key fingerprints",
https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/githubs-ssh-key-fingerprints,
read on 2026-11-01. Their SHA256 fingerprints are the ones the same page lists
(tier 1 checks it); tier 3 checks them against ``ssh-keyscan github.com`` and
``api.github.com/meta`` on every run, so a rotation turns tier 3 red."""

PINNED = "known_hosts.github"
"""The machine's copy of GitHub's host keys, beside its ``known_hosts``."""


def pinned_known_hosts() -> str:
    """``known_hosts.github``: one line per GitHub host key."""
    return "".join(f"github.com {key}\n" for key in GITHUB_HOST_KEYS)


def _block(keys: Path, found: Repo) -> str:
    lines = [
        f"Host {found.alias}",
        f"  HostName {found.host}",
        f"  User {found.user}",
    ]
    if found.port is not None:
        lines.append(f"  Port {found.port}")
    lines += [
        f"  IdentityFile {keys / found.alias}",
        "  IdentitiesOnly yes",
        "  BatchMode yes",
    ]
    if found.pinned:
        lines += [
            "  StrictHostKeyChecking yes",
            f"  UserKnownHostsFile {keys / PINNED}",
            "  GlobalKnownHostsFile none",
        ]
    else:
        lines += [
            "  StrictHostKeyChecking accept-new",
            f"  UserKnownHostsFile {keys / 'known_hosts'}",
        ]
    return "\n".join(lines) + "\n"


def ssh_config(root: Path, repos: Sequence[Repo]) -> str:
    """``ssh_config`` of the machine for ``repos`` (ssh ones)."""
    keys = root / KEYS
    return "\n".join(_block(keys, found) for found in repos if not found.local)


def _blocks(text: str) -> dict[str, str]:
    """``Host`` alias -> its block, in the order of the file."""
    found: dict[str, str] = {}
    current: str | None = None
    for line in text.splitlines(keepends=True):
        if line.startswith("Host "):
            current = line.split()[1]
            found[current] = ""
        if current is not None and line.strip():
            found[current] += line
    return found


def _present(path: Path) -> str:
    return path.read_text(encoding="utf-8") if path.exists() else ""


def drawn_ssh_config(root: Path, repos: Sequence[Repo]) -> dict[Path, str]:
    """The machine's ``ssh_config`` with the blocks of ``repos`` drawn and the
    other blocks kept, and ``known_hosts.github`` when one of them is GitHub;
    nothing is written."""
    keys = root / KEYS
    config = keys / "ssh_config"
    blocks = _blocks(_present(config))
    for found in repos:
        if not found.local:
            blocks[found.alias] = _block(keys, found)
    files = {config: "\n".join(blocks.values())}
    if any(found.pinned for found in repos if not found.local):
        files[keys / PINNED] = pinned_known_hosts()
    return files


def ssh_config_differs(root: Path, repos: Sequence[Repo]) -> list[Path]:
    """The files of ``drawn_ssh_config`` that are not as drawn."""
    drawn = drawn_ssh_config(root, repos)
    return [path for path, text in drawn.items() if _present(path) != text]


def write_ssh_config(root: Path, repos: Sequence[Repo]) -> None:
    """Write the files of ``drawn_ssh_config`` (0600) that are not as drawn."""
    (root / KEYS).mkdir(mode=0o700, parents=True, exist_ok=True)
    drawn = drawn_ssh_config(root, repos)
    for path in ssh_config_differs(root, repos):
        atomic_write(path, drawn[path], 0o600)


def has_access(ctx: StepContext, root: Path, found: Repo) -> bool:
    """``git ls-remote`` answers: the key works (read access is enough)."""
    code, _ = run_git(ctx, root, ["ls-remote", "--heads", found.url()], expect=(0, 128))
    return code == 0


class DeployKey(Step):
    """The key of one repository; ``name`` is the step, ``repo`` its address."""

    order = 1
    modes = ALL_MODES
    codes: ClassVar[dict[str, str]] = {
        "mint": "mint a deploy key for {repo} and wait for access",
        "alias-clash": "repositories share one key: {aliases}",
        "ssh-config": "draw {repo} into {files}",
        "ssh-config-differs": "{path} is not as drawn after the write",
        "no-access": "no read access to {repo} with key {public_key} after {wait_s} s",
    }

    def __init__(
        self,
        address: str,
        root: Path = Path("/"),
        *,
        name: str = "deploy_key",
        others: Sequence[str] = (),
        wait_s: float = KEY_WAIT_S,
        poll_s: float = 10.0,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self.repo = repo(address)
        self.root = root
        self.name = name
        self.others = tuple(others)
        self.wait_s = wait_s
        self.poll_s = poll_s
        self.clock = clock
        self.sleep = sleep

    @property
    def _key(self) -> Path:
        return self.root / KEYS / self.repo.alias

    def check(self, ctx: StepContext) -> CheckResult:
        clash = collisions([self.repo.address, *self.others])
        if clash:
            raise StepFailed("alias-clash", {"aliases": list[Json](clash)})
        if self.repo.local:
            return CheckResult(False)
        mint = CheckResult(True, local_code("mint", {"repo": self.repo.address}))
        if not self._key.exists():
            return mint
        differs = ssh_config_differs(self.root, [self.repo])
        if differs:  # ls-remote would read the old files: act draws them first
            files = list[Json](str(path) for path in differs)
            params: dict[str, Json] = {"repo": self.repo.address, "files": files}
            return CheckResult(True, local_code("ssh-config", params))
        if has_access(ctx, self.root, self.repo):
            return CheckResult(False)
        return mint

    def act(self, ctx: StepContext, check: CheckResult) -> None:
        write_ssh_config(self.root, [self.repo])
        if self._key.exists() and has_access(ctx, self.root, self.repo):
            return  # only the files were not as drawn
        if not self._key.exists():
            self._key.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            comment = f"pridem {self.repo.alias}"
            argv = ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", comment]
            ctx.runner.run(
                [*argv, "-f", str(self._key)], timeout=60, on_line=ctx.on_line
            )
            self._key.chmod(0o600)
        ctx.on_line(Stream.STDOUT, f"deploy key for {self.repo.address}:", False)
        ctx.on_line(Stream.STDOUT, self._public(), False)
        deadline = self.clock() + self.wait_s
        while not has_access(ctx, self.root, self.repo):
            if self.clock() >= deadline:
                raise StepFailed(
                    "no-access",
                    {
                        "repo": self.repo.address,
                        "public_key": self._public(),
                        "wait_s": self.wait_s,
                    },
                )
            self.sleep(self.poll_s)

    def _public(self) -> str:
        path = self._key.with_name(self._key.name + ".pub")
        return path.read_text(encoding="utf-8").strip() if path.exists() else ""

    def verify(self, ctx: StepContext, check: CheckResult) -> Verified:
        if self.repo.local:
            return Verified({"repo": self.repo.address, "key": "none: file://"})
        for path in ssh_config_differs(self.root, [self.repo]):
            raise StepFailed("ssh-config-differs", {"path": str(path)})
        if not has_access(ctx, self.root, self.repo):
            raise StepFailed(
                "no-access",
                {"repo": self.repo.address, "public_key": self._public(), "wait_s": 0},
            )
        mode = oct(self._key.stat().st_mode & 0o777)
        return Verified(
            {
                "repo": self.repo.address,
                "alias": self.repo.alias,
                "key_mode": mode,
                "host_keys": PINNED if self.repo.pinned else "accept-new",
            }
        )
