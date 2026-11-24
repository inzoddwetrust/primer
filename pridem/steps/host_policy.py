"""``policies.host`` of the passport: what the machine makes of the host itself
(DM-132, the owner's decisions of 22.11 and 24.11).

The stack ``pridem-host-policy`` stands right after the passport is read --
before ``destroy`` of ``reinstall`` and before the first build: the host
ladder runs before the passport, and with ``--ops`` on a first install it has
none. Its steps, in order:

- ``swap`` -- a swap of ``policies.host.swap`` when the box has none switched
  on at all. Any swap switched on -- a file or a partition, made by hand or by
  the machine -- counts and is never touched: no ``swapoff`` on any branch, a
  live swap is not resized. One smaller than the passport's is named in the
  fact (``short_by_gib``). One that is not in ``/etc/fstab`` is gone after a
  reboot: the step is incomplete (exit 2) and names it -- except the
  machine's own file, whose line the step writes. The machine's own swap is
  the file ``/opt/pridem/host/swapfile``; a file of it not switched on (an
  ``act`` cut short) is made again whole. Room: the disk keeps
  ``MIN_FREE_DISK_GIB`` beside the swap, checked before the file is made
  (``disk-low``). No field -- no swap is made.
- ``memory`` -- RAM and the swap switched on, from ``/proc/meminfo`` after
  ``swap``: below ``MIN_RAM_GIB`` of RAM or ``MIN_MEMORY_GIB`` of both,
  refused before anything is built (``memory-low``). Judged with or without
  the field. It only reads; ``doctor`` names nothing of it.
- ``password_login`` -- with ``policies.host.password_login: closed``, the
  login by password is closed, only when root has a key: see
  ``PasswordLogin``. Without the field nothing is touched.
"""

import os
from pathlib import Path
from typing import ClassVar

from pridem.events import Json
from pridem.files import atomic_write
from pridem.hostinfo import GIB, meminfo
from pridem.stacks.passport import HostPolicy, Passport, size_bytes
from pridem.steps.base import (
    CheckResult,
    Mode,
    Step,
    StepContext,
    StepFailed,
    Verified,
    local_code,
)
from pridem.steps.compose import out
from pridem.steps.host import MIN_FREE_DISK_GIB
from pridem.steps.passport import NO_PASSPORT, Fetched

POLICY_MODES: frozenset[Mode] = frozenset({"install", "deploy", "reinstall"})

SWAPFILE = Path("opt/pridem/host/swapfile")
"""The machine's own swap, under the root: the path tells it from one made by
hand (``/swapfile`` on goodo-test and velo-dev is kept as it is)."""
FSTAB = Path("etc/fstab")
SWAPON = ("swapon", "--show=NAME,TYPE,SIZE", "--bytes", "--noheadings", "--raw")
"""What is switched on, one line each, the size in bytes; ``--raw`` writes a
space of a path as ``\\x20``."""
SIZE_SLACK = 2**20
"""``swapon`` shows a file's size less its header page: a swap within a MiB of
the passport's is that size."""

MIN_RAM_GIB = 3.5
"""The RAM a box needs, swap or no swap. A VPS sold as 4 GB reports about
3.8 GiB of ``MemTotal`` (goodo-test, velo-dev): it passes; a 2 GB one does
not, whatever its swap -- a build that lives in swap is the build of goodo-test
without one, 26 min at a load of 49 (22.11)."""
MIN_MEMORY_GIB = 7.5
"""RAM and swap together. velo-dev -- 3.8 GiB of RAM and a swap of 4 GB --
has installed velo green since 23.11; goodo-test with the same RAM and no swap
built velo in 26 min at a load of 49 beside its running instance (22.11). The
floor is that working pair, 3.8 + 4 = 7.8, less what a kernel keeps."""


def _passport(fetched: Fetched) -> Passport:
    if fetched.passport is None:
        raise StepFailed("no-passport")
    return fetched.passport


def _policy(fetched: Fetched) -> HostPolicy:
    host = _passport(fetched).policies.host
    return host if host is not None else HostPolicy()


def _close_asked(fetched: Fetched) -> bool:
    """``policies.host.password_login`` asks the login by password closed."""
    return _policy(fetched).password_login is not None  # its one value: closed


def _gib(size: int) -> float:
    return round(size / GIB, 1)


def active_swaps(ctx: StepContext) -> list[tuple[str, str, int]]:
    """``(path, type, bytes)`` of every swap switched on, by ``swapon``."""
    _, lines = out(ctx, list(SWAPON), passed_on=False)
    found: list[tuple[str, str, int]] = []
    for line in lines:
        words = line.split()
        if len(words) == 3 and words[2].isdigit():
            path = words[0].replace("\\x20", " ")
            found.append((path, words[1], int(words[2])))
    return found


def _fstab_swaps(text: str) -> set[str]:
    """The devices ``/etc/fstab`` switches on as swap."""
    found: set[str] = set()
    for line in text.splitlines():
        fields = line.split()
        if len(fields) >= 3 and not fields[0].startswith("#") and fields[2] == "swap":
            found.add(fields[0])
    return found


class Swap(Step):
    """A swap of ``policies.host.swap`` on a box with none switched on."""

    name = "swap"
    title = "Make the swap"
    said = "{swap_gib} GiB of swap"
    order = 1
    modes = POLICY_MODES
    codes: ClassVar[dict[str, str]] = {
        **NO_PASSPORT,
        "make": "make a swap of {size} at {path}",
        "fstab": "write the line of {path} into /etc/fstab",
        "disk-low": "{free_gib} GiB free on {path}, needs {need_gib} "
        "({min_gib} beside a swap of {size})",
        "not-on": "{path} is not switched on after swapon",
        "not-in-fstab": "{path} is switched on and not in /etc/fstab",
        "foreign-not-in-fstab": "swap not in /etc/fstab, gone after a reboot: {paths}",
    }

    def __init__(
        self,
        *,
        fetched: Fetched,
        root: Path = Path("/"),
        min_free_gib: float = MIN_FREE_DISK_GIB,
    ) -> None:
        self.fetched = fetched
        self.root = root
        self.min_free_gib = min_free_gib
        """What the disk keeps beside the swap: ``preflight``'s floor."""

    @property
    def path(self) -> Path:
        return self.root / SWAPFILE

    def _fstab(self) -> str:
        file = self.root / FSTAB
        return file.read_text(encoding="utf-8") if file.exists() else ""

    def check(self, ctx: StepContext) -> CheckResult:
        wanted = _policy(self.fetched).swap
        on = active_swaps(ctx)
        mine = str(self.path)
        if any(path == mine for path, _, _ in on):
            if mine in _fstab_swaps(self._fstab()):
                return CheckResult(False)
            return CheckResult(True, local_code("fstab", {"path": mine}))
        if wanted is None or on:
            return CheckResult(False)
        return CheckResult(True, local_code("make", {"size": wanted, "path": mine}))

    def act(self, ctx: StepContext, check: CheckResult) -> None:
        if check.would is not None and check.would.code == "make":
            self._make(ctx, _policy(self.fetched).swap or "")
        fstab = self._fstab()
        if str(self.path) not in _fstab_swaps(fstab):
            head = fstab if not fstab or fstab.endswith("\n") else fstab + "\n"
            atomic_write(
                self.root / FSTAB, f"{head}{self.path} none swap sw 0 0\n", 0o644
            )

    def _make(self, ctx: StepContext, size: str) -> None:
        """The machine's own file, made whole: one cut short is made again."""
        wanted = size_bytes(size)
        self.path.unlink(missing_ok=True)  # ours and off: its room is free again
        self.path.parent.mkdir(parents=True, exist_ok=True)
        disk = os.statvfs(self.path.parent)
        free = disk.f_bavail * disk.f_frsize
        need = int(self.min_free_gib * GIB) + wanted
        if free < need:
            raise StepFailed(
                "disk-low",
                {
                    "free_gib": _gib(free),
                    "path": str(self.path.parent),
                    "need_gib": _gib(need),
                    "min_gib": self.min_free_gib,
                    "size": size,
                },
            )
        fd = os.open(self.path, os.O_CREAT | os.O_WRONLY | os.O_TRUNC, 0o600)
        try:
            os.posix_fallocate(fd, 0, wanted)  # no holes: swapon refuses them
            os.fsync(fd)
        finally:
            os.close(fd)
        os.chmod(self.path, 0o600)
        out(ctx, ["mkswap", str(self.path)])
        out(ctx, ["swapon", str(self.path)])

    def verify(self, ctx: StepContext, check: CheckResult) -> Verified:
        wanted = _policy(self.fetched).swap
        on = active_swaps(ctx)
        in_fstab = _fstab_swaps(self._fstab())
        mine = str(self.path)
        if check.needed and not any(path == mine for path, _, _ in on):
            raise StepFailed("not-on", {"path": mine})
        if any(path == mine for path, _, _ in on) and mine not in in_fstab:
            raise StepFailed("not-in-fstab", {"path": mine})
        total = sum(size for _, _, size in on)
        fact: dict[str, Json] = {
            "swaps": [
                {"path": path, "type": kind, "size_gib": _gib(size)}
                for path, kind, size in on
            ],
            "swap_gib": _gib(total),
            "wanted": wanted if wanted is not None else "none",
        }
        if wanted is not None and total + SIZE_SLACK < size_bytes(wanted):
            fact["short_by_gib"] = _gib(size_bytes(wanted) - total)
        lost = sorted(path for path, _, _ in on if path not in in_fstab)
        if lost:
            params: dict[str, Json] = {"paths": list[Json](lost)}
            return Verified(fact, local_code("foreign-not-in-fstab", params))
        return Verified(fact)


class Memory(Step):
    """RAM and swap enough for a build beside a running instance."""

    name = "memory"
    title = "Check the memory"
    said = "{ram_gib} GiB of RAM, {swap_gib} GiB of swap"
    order = 2
    modes = POLICY_MODES
    codes: ClassVar[dict[str, str]] = {
        "meminfo-unreadable": "/proc/meminfo has no MemTotal or SwapTotal",
        "memory-low": "RAM {ram_gib} GiB + swap {swap_gib} GiB = {total_gib} GiB, "
        "needs {min_gib} GiB, and {min_ram_gib} GiB of RAM: add RAM, or a swap "
        "by policies.host.swap",
    }

    def __init__(
        self,
        root: Path = Path("/"),
        *,
        min_ram_gib: float = MIN_RAM_GIB,
        min_memory_gib: float = MIN_MEMORY_GIB,
    ) -> None:
        self.root = root
        self.min_ram_gib = min_ram_gib
        self.min_memory_gib = min_memory_gib

    def check(self, ctx: StepContext) -> CheckResult:
        return CheckResult(False)  # it only reads

    def act(self, ctx: StepContext, check: CheckResult) -> None:
        raise AssertionError("memory has no act")

    def verify(self, ctx: StepContext, check: CheckResult) -> Verified:
        info = meminfo(self.root)
        if info is None or "MemTotal" not in info or "SwapTotal" not in info:
            raise StepFailed("meminfo-unreadable")
        ram, swap = info["MemTotal"], info["SwapTotal"]
        fact: dict[str, Json] = {
            "ram_gib": _gib(ram),
            "swap_gib": _gib(swap),
            "total_gib": _gib(ram + swap),
        }
        if ram < self.min_ram_gib * GIB or ram + swap < self.min_memory_gib * GIB:
            low = {
                **fact,
                "min_gib": self.min_memory_gib,
                "min_ram_gib": self.min_ram_gib,
            }
            raise StepFailed("memory-low", low, fact)
        return Verified(fact)


SSHD = Path("usr/sbin/sshd")
DROP_IN = Path("etc/ssh/sshd_config.d/00-pridem.conf")
"""The machine's own file: sshd takes the first value it reads, the files of
``sshd_config.d`` in their order, and Ubuntu's cloud images ship
``50-cloud-init.conf`` with ``PasswordAuthentication yes`` -- ``00-`` comes
first. A value set in ``sshd_config`` above its ``Include`` wins still:
``verify`` reads what sshd will do, not this file."""
DROP_IN_TEXT = (
    "# written by pridem: policies.host.password_login of the passport\n"
    "PasswordAuthentication no\n"
    "KbdInteractiveAuthentication no\n"
)
AS_ROOT = ("-C", "user=root,host=localhost,addr=127.0.0.1")
"""The connection ``sshd -T`` answers for: root's, so ``Match`` blocks count."""
PRIVSEP = Path("run/sshd")
"""sshd's privilege separation directory; ``sshd -t`` refuses without it, and
with socket activation (Ubuntu 24.04) it exists only while the service runs."""


class PasswordLogin(Step):
    """``policies.host.password_login: closed`` -- the login by password
    closed, only when root has a key.

    Closed means what sshd will do for root: ``passwordauthentication no`` and
    ``kbdinteractiveauthentication no`` (the second is a password by PAM) in
    ``sshd -T -C user=root,…``, which reads ``sshd_config``, its ``Include``
    and the ``Match`` blocks. Without the field the step touches nothing and
    its fact says ``open`` or ``closed``; there is no value that opens.

    A key of root, before anything is written: ``permitrootlogin`` is not
    ``no``, ``pubkeyauthentication`` is ``yes``, a file of
    ``authorizedkeysfile`` exists and ``ssh-keygen -l`` reads a key in it, and
    with ``strictmodes`` root's home, its ``.ssh`` and the file are root's and
    writable by no group and no other. Asked to close and no such key -- the
    login stays as it is and the step is incomplete (exit 2) with why.

    What the machine cannot see from inside: that someone holds the private
    half of the key, that a login over the network reaches the box (a
    firewall, an address, ``AllowUsers`` of another ``Match``), that the key
    has not been revoked elsewhere. It closes the password on a key it can
    read, not on a login it has seen.

    ``act`` writes ``DROP_IN``, checks the whole config with ``sshd -t`` --
    red, the file goes and the step is red -- and reloads ``ssh`` when it
    runs; ``verify`` reads ``sshd -T`` again.
    """

    name = "password_login"
    title = "Close the login by password"
    said = "password login {password}"
    order = 3
    modes = POLICY_MODES
    codes: ClassVar[dict[str, str]] = {
        **NO_PASSPORT,
        "close": "close the login by password: root has a key in {keys}",
        "not-closed": "policies.host.password_login is closed and the login by "
        "password stays open: {why}",
        "config-invalid": "sshd -t refuses the config with {path}; it is removed",
        "sshd-unread": "sshd -T refuses to say what it would do for root",
        "still-open": "{key} is {value} for root after {path}: a value read "
        "before sshd_config.d wins",
    }
    WHY: ClassVar[dict[str, str]] = {
        "root-login-off": "PermitRootLogin is no",
        "pubkey-off": "PubkeyAuthentication is not yes",
        "no-key": "root has no authorized key file",
        "key-unreadable": "ssh-keygen reads no key in root's authorized keys",
        "strict-modes": "root's keys are writable by others: StrictModes refuses them",
    }

    def __init__(
        self, *, fetched: Fetched, root: Path = Path("/"), root_uid: int = 0
    ) -> None:
        self.fetched = fetched
        self.root = root
        self.root_uid = root_uid
        """Who owns root's keys for StrictModes: root (tests pass their own)."""
        self._keys: list[str] = []

    def _effective(self, ctx: StepContext) -> dict[str, str] | None:
        """What sshd will do for root; ``None`` -- ``sshd -T`` refused (its
        lines are in the step's log)."""
        code, lines = out(
            ctx, ["sshd", "-T", *AS_ROOT], expect=(0, 255), passed_on=False
        )
        if code != 0:
            return None
        found: dict[str, str] = {}
        for line in lines:
            key, _, value = line.strip().partition(" ")
            found.setdefault(key.lower(), value.strip())
        return found

    @staticmethod
    def _state(effective: dict[str, str]) -> str:
        keys = ("passwordauthentication", "kbdinteractiveauthentication")
        return "closed" if all(effective.get(k) == "no" for k in keys) else "open"

    def _files(self, effective: dict[str, str]) -> list[Path]:
        """Root's authorized key files as sshd names them: ``%h``, ``%u``,
        ``%%``; a relative one is under root's home."""
        found: list[Path] = []
        for word in effective.get("authorizedkeysfile", "").split():
            name = word.replace("%h", "/root").replace("%u", "root")
            name = name.replace("%%", "%")
            path = Path(name) if name.startswith("/") else Path("/root") / name
            found.append(self.root / path.relative_to("/"))
        return found

    def _strict(self, file: Path) -> bool:
        """``file``, its directory and root's home: root's, no one else writes."""
        for part in (file, file.parent, self.root / "root"):
            info = part.stat()
            if info.st_uid != self.root_uid or info.st_mode & 0o022:
                return False
        return True

    def _why_not(self, ctx: StepContext, effective: dict[str, str]) -> str | None:
        """Why root has no key to close the password on; ``None`` -- it has."""
        if effective.get("permitrootlogin", "") == "no":
            return "root-login-off"
        if effective.get("pubkeyauthentication", "") != "yes":
            return "pubkey-off"
        present = [file for file in self._files(effective) if file.is_file()]
        if not present:
            return "no-key"
        readable: list[Path] = []
        for file in present:
            code, lines = out(
                ctx, ["ssh-keygen", "-l", "-f", str(file)], expect=(0, 1, 255)
            )
            if code == 0 and any(line.strip() for line in lines):
                readable.append(file)
        if not readable:
            return "key-unreadable"
        strict = effective.get("strictmodes", "yes") == "yes"
        if strict and not any(self._strict(file) for file in readable):
            return "strict-modes"
        self._keys = [str(file) for file in readable]
        return None

    def check(self, ctx: StepContext) -> CheckResult:
        asked = _close_asked(self.fetched)
        if not asked or not (self.root / SSHD).exists():
            return CheckResult(False)
        effective = self._effective(ctx)
        if effective is None:
            raise StepFailed("sshd-unread")
        if self._state(effective) == "closed":
            return CheckResult(False)
        why = self._why_not(ctx, effective)
        if why is not None:
            return CheckResult(False, None, {"why": why})
        keys: list[Json] = list(self._keys)
        return CheckResult(True, local_code("close", {"keys": keys}))

    def act(self, ctx: StepContext, check: CheckResult) -> None:
        file = self.root / DROP_IN
        file.parent.mkdir(parents=True, exist_ok=True)
        atomic_write(file, DROP_IN_TEXT, 0o644)
        (self.root / PRIVSEP).mkdir(mode=0o755, parents=True, exist_ok=True)
        code, _ = out(ctx, ["sshd", "-t"], expect=(0, 255))
        if code != 0:
            file.unlink()
            raise StepFailed("config-invalid", {"path": str(file)})
        active, _ = out(
            ctx, ["systemctl", "is-active", "--quiet", "ssh"], expect=(0, 3, 4)
        )
        if active == 0:
            out(ctx, ["systemctl", "reload", "ssh"])

    def verify(self, ctx: StepContext, check: CheckResult) -> Verified:
        if not (self.root / SSHD).exists():
            return Verified({"password": "no sshd"})
        effective = self._effective(ctx)
        if effective is None:  # asked, check read it: only without the field
            if _close_asked(self.fetched):
                raise StepFailed("sshd-unread")
            return Verified({"password": "unread"})
        state = self._state(effective)
        if check.needed and state != "closed":
            key = next(
                k
                for k in ("passwordauthentication", "kbdinteractiveauthentication")
                if effective.get(k) != "no"
            )
            params: dict[str, Json] = {
                "key": key,
                "value": effective.get(key, "unset"),
                "path": str(self.root / DROP_IN),
            }
            raise StepFailed("still-open", params, {"password": state})
        fact: dict[str, Json] = {"password": state}
        why = check.data.get("why")
        if isinstance(why, str) and state != "closed":
            fact["why"] = why
            return Verified(fact, local_code("not-closed", {"why": self.WHY[why]}))
        return Verified(fact)


def host_policy_steps(root: Path, *, fetched: Fetched) -> list[Step]:
    """The ``pridem-host-policy`` ladder, right after the passport's."""
    return [
        Swap(fetched=fetched, root=root),
        Memory(root),
        PasswordLogin(fetched=fetched, root=root),
    ]
