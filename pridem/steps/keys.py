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

``ls-remote`` is 128 both when the server refuses the key and when ssh never
reached it; git's own line is the same (``Could not read from remote
repository``). Only ssh's line tells: ssh prefixes its own failures --
the name not resolved, the connection refused or timed out -- with ``ssh:``.
Such a 128, in ``check``, ``act`` or any poll of the wait, is
``unreachable`` at once: no key the owner adds can answer it, and waiting
``KEY_WAIT_S`` under the box's lock for it would end in a false ``no-access``
(DM-81). Any other 128 is the server's refusal: the ceremony waits.
"""

import time
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import ClassVar

from pridem.events import Code, Json
from pridem.files import atomic_write, commit_set, private_dir, temp_of
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
    private_dir(root / KEYS)
    drawn = drawn_ssh_config(root, repos)
    for path in ssh_config_differs(root, repos):
        atomic_write(path, drawn[path], 0o600)


SSH_OWN = "ssh: "
"""How ssh starts a line of its own failure (not the server's refusal)."""


def has_access(ctx: StepContext, root: Path, found: Repo) -> bool:
    """``git ls-remote`` answers: the key works (read access is enough);
    ``False`` -- the server refused it. ssh's own failure (``SSH_OWN``) is
    ``unreachable``: the server never saw the key."""
    errors: list[str] = []
    code, _ = run_git(
        ctx,
        root,
        ["ls-remote", "--heads", found.url()],
        expect=(0, 128),
        stderr=errors,
    )
    if code != 0 and any(line.startswith(SSH_OWN) for line in errors):
        raise StepFailed("unreachable", {"repo": found.address})
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
        "unreachable": "ssh does not reach {repo}: no key can answer before it does",
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
        if self._access(ctx):
            return CheckResult(False)
        return mint

    def _access(self, ctx: StepContext) -> bool:
        """The key works for what it is for: read, ``git ls-remote``."""
        return has_access(ctx, self.root, self.repo)

    @property
    def _title(self) -> str:
        return "deploy key"

    def act(self, ctx: StepContext, check: CheckResult) -> None:
        write_ssh_config(self.root, [self.repo])
        if self._key.exists() and self._access(ctx):
            return  # only the files were not as drawn
        if not self._key.exists():
            self._mint(ctx)
        ctx.on_line(Stream.STDOUT, f"{self._title} for {self.repo.address}:", False)
        ctx.on_line(Stream.STDOUT, self._public(), False)
        deadline = self.clock() + self.wait_s
        while not self._access(ctx):
            if self.clock() >= deadline:
                raise StepFailed(
                    "no-access",
                    {
                        "repo": self.repo.address,
                        "public_key": self._public(),
                        "wait_s": self.wait_s,
                    },
                )
            ctx.interrupt.check()  # a signal ends the wait (DM-45)
            self.sleep(self.poll_s)
            ctx.interrupt.check()

    def _mint(self, ctx: StepContext) -> None:
        """A new pair as one change (DM-80): ``ssh-keygen`` writes both parts
        into temporary files, the public part is renamed first and the private
        part last -- a key in place always has its ``.pub``, and a crash leaves
        no key, so the next run mints again."""
        private_dir(self._key.parent)
        temp = temp_of(self._key)
        public = self._key.with_name(self._key.name + ".pub")
        temp_public = temp.with_name(temp.name + ".pub")
        temp.unlink(missing_ok=True)  # left by a run that died
        temp_public.unlink(missing_ok=True)
        comment = f"pridem {self.repo.alias}"
        argv = ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", comment]
        try:
            ctx.runner.run([*argv, "-f", str(temp)], timeout=60, on_line=ctx.on_line)
            temp.chmod(0o600)
        except BaseException:
            temp.unlink(missing_ok=True)
            temp_public.unlink(missing_ok=True)
            raise
        commit_set([(temp_public, public), (temp, self._key)])

    def _public(self) -> str:
        path = self._key.with_name(self._key.name + ".pub")
        return path.read_text(encoding="utf-8").strip() if path.exists() else ""

    def verify(self, ctx: StepContext, check: CheckResult) -> Verified:
        if self.repo.local:
            return Verified({"repo": self.repo.address, "key": "none: file://"})
        for path in ssh_config_differs(self.root, [self.repo]):
            raise StepFailed("ssh-config-differs", {"path": str(path)})
        if not self._access(ctx):
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


WRITE_CHECK = "refs/pridem/write-check"
"""The ref a dry push names to ask for write access: a ref of the machine's
own, so the answer never depends on the branch or the commit."""


def has_write_access(
    ctx: StepContext, root: Path, found: Repo, git_dir: Path, commit: str
) -> bool:
    """``git push --dry-run`` of ``commit`` to ``WRITE_CHECK`` through the
    write key's alias answers 0: the key may write; anything else -- refused.
    Nothing is written: a dry run sends no object and moves no ref. ssh's own
    failure (``SSH_OWN``) is ``unreachable``, as for ``has_access``.

    KNOWN CEILING (DM-63).

    1. Mechanics: that a dry push through a read-only deploy key is refused by
       GitHub before anything is sent, and one through a key with write
       access answers 0, is not measured: port 22 is closed from the sandbox
       and tier 3 reaches its repositories by ``file://``, where no key is
       asked. A server that accepts the dry run of a key it would refuse on
       the real push leaves ``types`` to find it: ``write-refused``.
    2. Status: acknowledged by design.
    3. Task: none -- the first box of the role test with ``types`` on GitHub
       measures it.
    4. Trigger: ``write_key`` green and ``types:write-refused`` on the same
       run, or ``write_key:no-access`` with the key added with write access.
    5. Agreed fix: the answer of GitHub to a dry push measured on a live box,
       and the check made by what it says.
    6. Rejected: checking by a real push of a ref -- it writes the product's
       repository for a question.
    """
    errors: list[str] = []
    code, _ = run_git(
        ctx,
        root,
        [
            "--git-dir",
            str(git_dir),
            "push",
            "--dry-run",
            "--porcelain",
            found.url(),
            f"{commit}:{WRITE_CHECK}",
        ],
        expect=(0, 1, 128),
        stderr=errors,
    )
    if code != 0 and any(line.startswith(SSH_OWN) for line in errors):
        raise StepFailed("unreachable", {"repo": found.address})
    return code == 0


class WriteKey(DeployKey):
    """The key that writes the types of a ``test`` box (DM-63): a deploy key
    with write access, its own pair and alias (``<alias>-write``), the ceremony
    of ``DeployKey``. It runs after ``finalize``, with ``types``: whatever it
    is refused is left undone -- ``incomplete``, never a red verdict."""

    name = "write_key"
    order = 3  # in the root stack: after final_check and finalize
    codes: ClassVar[dict[str, str]] = {
        **DeployKey.codes,
        "mint": "mint a write key for {repo} and wait for write access",
        "no-access": "no write access to {repo} with key {public_key} after "
        "{wait_s} s: add it as a deploy key with write access",
    }

    def __init__(
        self,
        address: str,
        root: Path = Path("/"),
        *,
        git_dir: Path,
        commit: str,
        wait_s: float = KEY_WAIT_S,
        poll_s: float = 10.0,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        super().__init__(
            address,
            root,
            name="write_key",
            wait_s=wait_s,
            poll_s=poll_s,
            clock=clock,
            sleep=sleep,
        )
        self.repo = repo(address, write=True)
        self.git_dir = git_dir
        self.commit = commit
        self.left: Code | None = None

    def _access(self, ctx: StepContext) -> bool:
        return has_write_access(ctx, self.root, self.repo, self.git_dir, self.commit)

    @property
    def _title(self) -> str:
        return "write key (a deploy key with write access)"

    def check(self, ctx: StepContext) -> CheckResult:
        self.left = None
        try:
            return super().check(ctx)
        except StepFailed as error:
            self.left = error.reason
            return CheckResult(True, error.reason, {"left": True})

    def act(self, ctx: StepContext, check: CheckResult) -> None:
        if check.data.get("left") is True:
            return
        try:
            super().act(ctx, check)
        except StepFailed as error:
            self.left = error.reason

    def verify(self, ctx: StepContext, check: CheckResult) -> Verified:
        if self.left is None:
            try:
                return super().verify(ctx, check)
            except StepFailed as error:
                self.left = error.reason
        return Verified(
            {"repo": self.repo.address, "left": self.left.code}, incomplete=self.left
        )
