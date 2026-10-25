"""The deploy-key ceremony (TZ section 6.2 item 3): a key per repository.

For a repository reached over ssh the machine mints an ed25519 pair under
``/opt/pridem/keys/`` (the private part 0600), prints the public part, and
waits until the repository answers ``git ls-remote`` with it -- the owner adds
the public part as a read-only deploy key meanwhile. ssh goes through the
machine's ``ssh_config``: ``Host <alias>`` per repository with its key only
(``IdentitiesOnly yes``) and the machine's ``known_hosts``
(``StrictHostKeyChecking accept-new``); root's ``~/.ssh`` is never touched.
A key already in place with access needs no ``act`` -- tier 3 puts it there
from the CI secrets. The private part is never in a fact, a log or a reason.
"""

import time
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import ClassVar

from pridem.events import Json
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


def ssh_config(root: Path, repos: Sequence[Repo]) -> str:
    """``ssh_config`` of the machine for ``repos`` (ssh ones)."""
    keys = root / KEYS
    blocks = [
        f"Host {found.alias}\n"
        f"  HostName {found.host}\n"
        "  User git\n"
        f"  IdentityFile {keys / found.alias}\n"
        "  IdentitiesOnly yes\n"
        "  StrictHostKeyChecking accept-new\n"
        f"  UserKnownHostsFile {keys / 'known_hosts'}\n"
        for found in repos
        if not found.local
    ]
    return "\n".join(blocks)


def write_ssh_config(root: Path, repos: Sequence[Repo]) -> None:
    """Add ``repos`` to the machine's ``ssh_config`` (0600), keeping the others."""
    keys = root / KEYS
    keys.mkdir(mode=0o700, parents=True, exist_ok=True)
    known = sorted(
        {p.name for p in keys.glob("pridem-*") if not p.name.endswith(".pub")}
    )
    wanted = {found.alias: found for found in repos if not found.local}
    config = keys / "ssh_config"
    present = config.read_text(encoding="utf-8") if config.exists() else ""
    hosts = {
        line.split()[1] for line in present.splitlines() if line.startswith("Host ")
    }
    extra = [found for alias, found in wanted.items() if alias not in hosts]
    if not extra and set(known) >= set(wanted):
        return
    text = present + ("\n" if present else "") + ssh_config(root, extra)
    temp = config.with_name("ssh_config.tmp")
    temp.write_text(text, encoding="utf-8")
    temp.chmod(0o600)
    temp.replace(config)


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
        write_ssh_config(self.root, [self.repo])
        if self._key.exists() and has_access(ctx, self.root, self.repo):
            return CheckResult(False)
        return CheckResult(True, local_code("mint", {"repo": self.repo.address}))

    def act(self, ctx: StepContext, check: CheckResult) -> None:
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
        if not has_access(ctx, self.root, self.repo):
            raise StepFailed(
                "no-access",
                {"repo": self.repo.address, "public_key": self._public(), "wait_s": 0},
            )
        mode = oct(self._key.stat().st_mode & 0o777)
        return Verified(
            {"repo": self.repo.address, "alias": self.repo.alias, "key_mode": mode}
        )
