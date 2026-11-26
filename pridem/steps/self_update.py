"""``pridem self-update <tag>`` (DM-163): the machine installs a release of
itself the way ``install.sh`` does, its pins checked, and turns ``current`` to
it in one ``rename``.

The release is its ``install.sh``, read as text and never run: by default
from the machine's home (``RELEASES``, ``.../releases/download/<tag>/
install.sh``), with ``--from`` from a ``file://`` or loopback ``http://``
address (tier 3, tests). Its pins are checked in six layers before anything
is switched:

1. ``TAG`` in the file is the tag asked;
2. ``REPO`` is ``RELEASES`` -- unless ``--from`` named the file: else a file
   with a repository of its own would vouch for its own commit;
3. the tag's commit in ``REPO`` (``git ls-remote``, the peeled commit of an
   annotated tag) is ``COMMIT``;
4. the clone at the tag is ``COMMIT``;
5. the wheel's sha256 is ``WHEEL_SHA256``;
6. the machine built says ``pridem <version of the tag>``.

There is no signature of a release: the trust is the first contact's -- TLS
to GitHub -- and these cross-checks.

The build goes where ``install.sh`` builds, ``versions/<tag>``: a venv cannot
be moved (``install.sh``), so it is built in place. That directory is no
one's while ``current`` points elsewhere; one that is there and is not
``current`` is the rest of an earlier try or an older install -- removed and
built again. The directory ``current`` points to is never removed: ``release``
refuses at once, before anything is fetched, a tag whose directory is the
machine in use and does not say its version (``current-differs``) -- under the
lock nothing else turns ``current`` between that check and the build.

The point of no return is ``switch``: a symlink ``current.next`` turned into
``current`` by ``os.replace`` -- one ``rename(2)``: before it the machine is
the old one whole, after it the new one whole (``install.sh``'s ``ln -sfn``
is an ``unlink`` and a ``symlink``). ``/usr/local/bin/pridem`` points to
``current/venv/bin/pridem`` and is not touched. The ``finally`` of the plan
removes ``versions/<tag>`` this run built when the switch did not happen; a
hard break leaves an incomplete one no one points to, which the next try
knows by its ``pridem version`` and builds again.

Before the switch the schema of ``state.json`` the release writes is read
from the machine built (``STATE_SCHEMA``; a release before DM-191 has none --
1) and held to the box's: different either way -- ``schema-differs``.

The same version, ``current`` already ``versions/<tag>`` saying it: nothing to
do, no network. A lower one is allowed -- a rollback by the same button -- as
long as the schema holds.

After the switch: run from the console with the agent's service active, the
service is restarted (``agent_restart``) -- the new machine runs it. Run by
the agent as a command of the Panel, it is not: the agent's service would take
this very run down with it (one cgroup); the agent sends the verdict and
exits, and systemd starts the new machine (``pridem/agent/service.py``).
"""

import hashlib
import json
import os
import re
import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import ClassVar
from urllib.parse import urlsplit

from pridem.events import Json
from pridem.state import STATE
from pridem.steps.agent_service import UNIT
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
from pridem.steps.timers import UNIT_DIR

RELEASES = "https://github.com/inzoddwetrust/primer"
"""The machine's home: its releases and its repository."""
TAG = re.compile(r"^v([0-9]+\.[0-9]+\.[0-9]+)$")
PINS = ("TAG", "COMMIT", "WHEEL_SHA256", "REPO", "WHEEL_URL")
PIN = re.compile(r'^(TAG|COMMIT|WHEEL_SHA256|REPO|WHEEL_URL)="([^"]*)"$', re.M)
FORMS = {
    "TAG": TAG,
    "COMMIT": re.compile(r"^[0-9a-f]{40}$"),
    "WHEEL_SHA256": re.compile(r"^[0-9a-f]{64}$"),
    "REPO": re.compile(
        r"^(https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+|file:///\S+)$"
    ),
    "WHEEL_URL": re.compile(r"^(https://github\.com/|file:///)\S+\.whl$"),
}
"""The forms ``install.sh`` holds its pins to (its step 1)."""
BUILD_TIMEOUT_S = 900.0
MODES: frozenset[Mode] = frozenset({"command"})
LOOPBACK = frozenset({"127.0.0.1", "::1", "localhost"})
SCHEMA = "import pridem.state as s; print(getattr(s, 'STATE_SCHEMA', 1))"
"""What the machine built says its ``state.json`` schema is (DM-191)."""


def from_address(value: str) -> str:
    """``--from``: a ``file://`` address or an ``http://`` one on the loopback;
    ``ValueError`` otherwise."""
    parts = urlsplit(value)
    if parts.scheme == "file" and parts.path.startswith("/") and not parts.netloc:
        return value
    if parts.scheme == "http" and parts.hostname in LOOPBACK:
        return value
    raise ValueError("--from is file:// or http:// on the loopback")


@dataclass
class Release:
    """What the steps of one ``self-update`` share."""

    tag: str
    source: str
    named: bool
    """``--from`` named the file: ``REPO`` is taken from it as it is."""
    work: Path
    pins: dict[str, str] = field(default_factory=dict)
    nothing: bool = False
    built: bool = False
    switched: bool = False

    @property
    def version(self) -> str:
        found = TAG.match(self.tag)
        return found[1] if found else ""


def _says(ctx: StepContext, pridem: Path) -> str:
    """What ``pridem version`` of a machine says; empty when it cannot."""
    if not pridem.exists():
        return ""
    code, lines = out(ctx, [str(pridem), "version"], expect=(0, 1, 2), passed_on=False)
    return lines[0].strip() if code == 0 and lines else ""


def _current(root: Path) -> Path | None:
    link = root / "current"
    return link.resolve() if link.is_symlink() else None


class ReleaseOf(Step):
    """The release asked: its ``install.sh``, its pins checked."""

    name = "release"
    title = "The release asked"
    said = "{tag} at {commit}"
    order = 1
    modes = MODES
    codes: ClassVar[dict[str, str]] = {
        "fetch": "read the pins of {tag} from {source}",
        "not-a-release": "{tag} is not a release of the machine: {why}",
        "pin-differs": "the pin {pin} of {tag} is {pinned}, found {found}",
        "current-differs": (
            "{path} is the machine in use and does not say {tag}: install.sh "
            "of {tag} builds it again"
        ),
    }

    def __init__(self, root: Path, release: Release) -> None:
        self.root = root
        self.release = release

    def check(self, ctx: StepContext) -> CheckResult:
        tag = self.release.tag
        if not TAG.match(tag):
            raise StepFailed("not-a-release", {"tag": tag, "why": "not vX.Y.Z"})
        target = self.root / "versions" / tag
        if _current(self.root) == target.resolve():
            said = _says(ctx, target / "venv" / "bin" / "pridem")
            if said != f"pridem {self.release.version}":  # never the machine in use
                raise StepFailed("current-differs", {"path": str(target), "tag": tag})
            self.release.nothing = True
            return CheckResult(False)
        return CheckResult(
            True, local_code("fetch", {"tag": tag, "source": self.release.source})
        )

    def _pin_differs(self, what: str, pinned: str, found: str) -> StepFailed:
        params: dict[str, Json] = {
            "tag": self.release.tag, "pin": what, "pinned": pinned, "found": found,
        }  # fmt: skip
        return StepFailed("pin-differs", params)

    def act(self, ctx: StepContext, check: CheckResult) -> None:
        release, tag = self.release, self.release.tag
        release.work.mkdir(parents=True, exist_ok=True)
        script = release.work / "install.sh"
        code, _ = out(
            ctx,
            ["curl", "-fsSL", "--proto", "=https,file,http", "-o", str(script),
             release.source],
            expect=(0, 22),
        )  # fmt: skip
        if code == 22:
            raise StepFailed("not-a-release", {"tag": tag, "why": "no install.sh"})
        pins = dict(PIN.findall(script.read_text(encoding="utf-8")))
        for name in PINS:
            if not FORMS[name].match(pins.get(name, "")):
                why = f"its install.sh has no pin {name}"
                raise StepFailed("not-a-release", {"tag": tag, "why": why})
        if pins["TAG"] != tag:
            raise self._pin_differs("tag", pins["TAG"], tag)
        if not release.named and pins["REPO"] != RELEASES:
            raise self._pin_differs("repo", RELEASES, pins["REPO"])
        _, lines = out(
            ctx,
            ["git", "ls-remote", pins["REPO"] + ".git", f"refs/tags/{tag}",
             f"refs/tags/{tag}^{{}}"],
            passed_on=False,
        )  # fmt: skip
        refs: dict[str, str] = {}
        for line in lines:
            sha, _, ref = line.partition("\t")
            if ref:
                refs[ref.strip()] = sha.strip()
        commit = refs.get(f"refs/tags/{tag}^{{}}") or refs.get(f"refs/tags/{tag}")
        if commit is None:
            raise StepFailed(
                "not-a-release", {"tag": tag, "why": f"no tag in {pins['REPO']}"}
            )
        if commit != pins["COMMIT"]:
            raise self._pin_differs("commit", pins["COMMIT"], commit)
        release.pins = pins

    def verify(self, ctx: StepContext, check: CheckResult) -> Verified:
        if self.release.nothing:
            return Verified({"tag": self.release.tag, "commit": "", "current": True})
        pins = self.release.pins
        return Verified(
            {
                "tag": pins["TAG"],
                "commit": pins["COMMIT"],
                "sha256": pins["WHEEL_SHA256"],
                "repo": pins["REPO"],
                "current": False,
            }
        )


class Build(Step):
    """The machine of the release in ``versions/<tag>``, as ``install.sh``
    builds it."""

    name = "build"
    title = "Build the machine of the release"
    said = "{path}: {version}"
    order = 2
    modes = MODES
    codes: ClassVar[dict[str, str]] = {
        "build": "build {path}",
        "pin-differs": ReleaseOf.codes["pin-differs"],
    }

    def __init__(self, root: Path, release: Release) -> None:
        self.root = root
        self.release = release
        self.target = root / "versions" / release.tag

    def check(self, ctx: StepContext) -> CheckResult:
        if self.release.nothing:
            return CheckResult(False)
        return CheckResult(True, local_code("build", {"path": str(self.target)}))

    def _differs(self, what: str, pinned: str, found: str) -> StepFailed:
        params: dict[str, Json] = {
            "tag": self.release.tag, "pin": what, "pinned": pinned, "found": found,
        }  # fmt: skip
        return StepFailed("pin-differs", params)

    def act(self, ctx: StepContext, check: CheckResult) -> None:
        release, pins = self.release, self.release.pins
        clone = release.work / "pridem"
        shutil.rmtree(clone, ignore_errors=True)
        out(
            ctx,
            ["git", "clone", "--quiet", "--depth", "1", "--branch", release.tag,
             pins["REPO"] + ".git", str(clone)],
            timeout=BUILD_TIMEOUT_S,
        )  # fmt: skip
        _, head = out(
            ctx, ["git", "-C", str(clone), "rev-parse", "HEAD"], passed_on=False
        )
        found = head[0].strip() if head else ""
        if found != pins["COMMIT"]:
            raise self._differs("head", pins["COMMIT"], found)
        wheel = release.work / f"pridem-{release.version}-py3-none-any.whl"
        out(
            ctx,
            ["curl", "-fsSL", "--proto", "=https,file,http", "-o", str(wheel),
             pins["WHEEL_URL"]],
            timeout=BUILD_TIMEOUT_S,
        )  # fmt: skip
        digest = hashlib.sha256(wheel.read_bytes()).hexdigest()
        if digest != pins["WHEEL_SHA256"]:
            raise self._differs("sha256", pins["WHEEL_SHA256"], digest)
        release.built = True  # not current: release's check refused that
        shutil.rmtree(self.target, ignore_errors=True)
        venv = self.target / "venv"
        out(ctx, ["python3", "-m", "venv", str(venv)], timeout=BUILD_TIMEOUT_S)
        pip = str(venv / "bin" / "pip")
        out(
            ctx,
            [pip, "install", "--no-index", "--find-links", str(clone / "wheels"),
             "--require-hashes", "-r", str(clone / "requirements.lock")],
            timeout=BUILD_TIMEOUT_S,
        )  # fmt: skip
        out(
            ctx,
            [pip, "install", "--no-index", "--no-deps", str(wheel)],
            timeout=BUILD_TIMEOUT_S,
        )

    def verify(self, ctx: StepContext, check: CheckResult) -> Verified:
        said = _says(ctx, self.target / "venv" / "bin" / "pridem")
        wanted = f"pridem {self.release.version}"
        if said != wanted:
            raise self._differs("version", wanted, said or "nothing")
        return Verified({"path": str(self.target), "version": said})


class Schema(Step):
    """The schema of ``state.json`` the release writes is the box's."""

    name = "schema"
    title = "The schema of state.json"
    said = "{release}"
    order = 3
    modes = MODES
    codes: ClassVar[dict[str, str]] = {
        "schema-differs": (
            "state.json of the box is of schema {box}, the release writes "
            "{release}: no migration between them"
        ),
    }

    def __init__(self, root: Path, release: Release) -> None:
        self.root = root
        self.release = release

    def _box(self) -> int | None:
        path = self.root / STATE
        if not path.exists():
            return None
        found = json.loads(path.read_text(encoding="utf-8")).get("schema", 1)
        return found if isinstance(found, int) else 1

    def _release(self, ctx: StepContext) -> int:
        python = self.root / "versions" / self.release.tag / "venv" / "bin" / "python"
        _, lines = out(ctx, [str(python), "-c", SCHEMA], passed_on=False)
        return int(lines[0].strip())

    def check(self, ctx: StepContext) -> CheckResult:
        if self.release.nothing:
            return CheckResult(False)
        box, release = self._box(), self._release(ctx)
        if box is not None and box != release:
            raise StepFailed("schema-differs", {"box": box, "release": release})
        return CheckResult(False)

    def act(self, ctx: StepContext, check: CheckResult) -> None:
        raise RuntimeError("schema never acts")

    def verify(self, ctx: StepContext, check: CheckResult) -> Verified:
        if self.release.nothing:
            return Verified({"release": "the machine in use"})
        return Verified({"release": self._release(ctx)})


class Switch(Step):
    """``current`` turned to the release: the point of no return."""

    name = "switch"
    title = "Turn current to the release"
    said = "current -> {path}"
    order = 4
    modes = MODES
    codes: ClassVar[dict[str, str]] = {
        "switch": "turn current to {path}",
        "not-switched": "current is {found}, not {path}",
    }

    def __init__(self, root: Path, release: Release) -> None:
        self.root = root
        self.release = release
        self.target = root / "versions" / release.tag

    def check(self, ctx: StepContext) -> CheckResult:
        if _current(self.root) == self.target.resolve():
            return CheckResult(False)
        return CheckResult(True, local_code("switch", {"path": str(self.target)}))

    def act(self, ctx: StepContext, check: CheckResult) -> None:
        link = self.root / "current"
        following = self.root / "current.next"
        following.unlink(missing_ok=True)
        os.symlink(self.target, following)
        os.replace(following, link)
        self.release.switched = True

    def verify(self, ctx: StepContext, check: CheckResult) -> Verified:
        found = _current(self.root)
        if found != self.target.resolve():
            raise StepFailed(
                "not-switched", {"path": str(self.target), "found": str(found)}
            )
        said = _says(ctx, self.root / "current" / "venv" / "bin" / "pridem")
        return Verified({"path": str(self.target), "version": said})


class AgentRestart(Step):
    """The agent's service runs the new machine: restarted when the console
    ran the update; the agent restarts itself when it did."""

    name = "agent_restart"
    title = "The agent runs the new machine"
    said = "{agent}"
    order = 5
    modes = MODES
    codes: ClassVar[dict[str, str]] = {
        "restart": "restart {unit}",
        "not-active": "{unit} is {state} after its restart",
    }

    def __init__(self, fs_root: Path, release: Release, by_command: bool) -> None:
        self.unit = fs_root / UNIT_DIR / UNIT
        self.release = release
        self.by_command = by_command

    def _active(self, ctx: StepContext) -> str:
        _, lines = out(
            ctx, ["systemctl", "is-active", UNIT], expect=(0, 1, 3, 4), passed_on=False
        )
        return lines[0].strip() if lines else ""

    def check(self, ctx: StepContext) -> CheckResult:
        if self.release.nothing or self.by_command or not self.unit.exists():
            return CheckResult(False)
        if self._active(ctx) != "active":
            return CheckResult(False)
        return CheckResult(True, local_code("restart", {"unit": UNIT}))

    def act(self, ctx: StepContext, check: CheckResult) -> None:
        out(ctx, ["systemctl", "restart", UNIT])

    def verify(self, ctx: StepContext, check: CheckResult) -> Verified:
        if not check.needed:
            why = (
                "nothing to do" if self.release.nothing
                else "the agent restarts itself" if self.by_command
                else "no service running"
            )  # fmt: skip
            return Verified({"agent": why})
        state = self._active(ctx)
        if state != "active":
            raise StepFailed("not-active", {"unit": UNIT, "state": state})
        return Verified({"agent": f"{UNIT} restarted"})


class Leftover(Step):
    """``finally``: the ``versions/<tag>`` this run built and did not switch
    to is removed; never the machine in use."""

    name = "leftover"
    title = "Remove what was not switched to"
    said = "{removed}"
    order = 1
    modes = MODES
    codes: ClassVar[dict[str, str]] = {
        "remove": "remove {path}",
        "not-removed": "{path} is still there after its removal",
    }

    def __init__(self, root: Path, release: Release) -> None:
        self.root = root
        self.release = release
        self.target = root / "versions" / release.tag

    def check(self, ctx: StepContext) -> CheckResult:
        shutil.rmtree(self.release.work, ignore_errors=True)
        if (
            not self.release.built
            or self.release.switched
            or _current(self.root) == self.target.resolve()
        ):
            return CheckResult(False)
        return CheckResult(True, local_code("remove", {"path": str(self.target)}))

    def act(self, ctx: StepContext, check: CheckResult) -> None:
        shutil.rmtree(self.target, ignore_errors=True)

    def verify(self, ctx: StepContext, check: CheckResult) -> Verified:
        removed = str(self.target) if check.needed else "nothing"
        if check.needed and self.target.exists():
            raise StepFailed("not-removed", {"path": str(self.target)})
        return Verified({"removed": removed})
