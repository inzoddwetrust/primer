"""A box for the tests of ``pridem self-update`` (DM-163).

``Releases`` answers the commands ``self-update`` gives -- ``curl`` of an
``install.sh`` or a wheel, ``git ls-remote``, ``git clone``, ``git rev-parse``,
``python3 -m venv``, ``pip install``, ``<venv>/bin/pridem version``,
``<venv>/bin/python -c`` of the schema, ``systemctl`` -- with what a release
holds, and does what they do on the file system: the file written, the clone
made, the venv laid out (``bin/pridem`` and ``bin/python`` as text naming the
version and the schema). A command it does not know is a failure of the test
(``unplanned``). A release's parts can be spoiled one by one (``Spoil``) --
the planted defects of the checks.

The machine in use is laid out the same way under ``versions/<tag>`` with
``current`` pointing to it -- ``install_machine``.
"""

import hashlib
import shutil
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path

from pridem.runner import CommandFailed, OnLine, Result, Stream

REPO = "file:///srv/primer"
RELEASES = "https://github.com/inzoddwetrust/primer"


@dataclass
class Spoil:
    """One defect of a release, or none."""

    install_sh: str | None = None
    """``missing`` -- no asset (404); ``no-pin`` -- a pin left out."""
    tag: str | None = None
    """The tag the file names instead of its own."""
    repo: str | None = None
    commit: str | None = None
    """The commit the tag is in the repository, instead of the pin."""
    head: str | None = None
    """The commit the clone is at, instead of the pin."""
    wheel: bytes | None = None
    """The wheel's bytes instead of the pinned ones."""
    version: str | None = None
    """What the machine built says instead of its version."""
    schema: int = 1
    pip_fails: bool = False
    sha256_tail: bool = False
    """The pin ``WHEEL_SHA256`` is the wheel's first 8 signs and another tail
    (DM-217): the wheel itself is the right one."""


@dataclass
class Release:
    tag: str
    commit: str
    wheel: bytes
    spoil: Spoil = field(default_factory=Spoil)

    @property
    def version(self) -> str:
        return self.tag[1:]

    def _pinned_sha256(self) -> str:
        digest = hashlib.sha256(self.wheel).hexdigest()
        if not self.spoil.sha256_tail:
            return digest
        tail = "".join("0" if sign != "0" else "1" for sign in digest[8:])
        return digest[:8] + tail

    def install_sh(self, repo: str) -> str:
        pins = {
            "TAG": self.spoil.tag or self.tag,
            "COMMIT": self.commit,
            "WHEEL_SHA256": self._pinned_sha256(),
            "REPO": self.spoil.repo or repo,
            "WHEEL_URL": f"file:///srv/releases/{self.tag}/pridem-{self.version}"
            "-py3-none-any.whl",
        }
        if self.spoil.install_sh == "no-pin":
            pins.pop("COMMIT")
        lines = [f'{name}="{value}"' for name, value in pins.items()]
        return "#!/usr/bin/env bash\nset -euo pipefail\n" + "\n".join(lines) + "\n"


def install_machine(root: Path, tag: str, schema: int = 1) -> None:
    """The machine in use: ``versions/<tag>`` and ``current`` to it."""
    _lay_venv(root / "versions" / tag / "venv", tag[1:], schema)
    (root / "current").symlink_to(root / "versions" / tag)


def _lay_venv(venv: Path, version: str, schema: int) -> None:
    (venv / "bin").mkdir(parents=True, exist_ok=True)
    (venv / "bin" / "pridem").write_text(f"version={version}\n")
    (venv / "bin" / "python").write_text(f"schema={schema}\n")


def _field(path: Path, name: str) -> str:
    for line in path.read_text().splitlines():
        key, _, value = line.partition("=")
        if key == name:
            return value
    raise AssertionError(f"{path} has no {name}")


@dataclass
class Releases:
    """The runner of a box whose releases are ``releases``."""

    releases: Mapping[str, Release]
    repo: str = REPO
    calls: list[tuple[str, ...]] = field(default_factory=list)
    unplanned: list[tuple[str, ...]] = field(default_factory=list)
    agent_active: bool = False
    restarted: bool = False

    def _release_of_url(self, url: str) -> tuple[Release, str]:
        for release in self.releases.values():
            if f"/{release.tag}/" in url:
                return release, url.rsplit("/", 1)[1]
        raise KeyError(url)

    def run(
        self,
        argv: Sequence[str],
        *,
        expect: tuple[int, ...] = (0,),
        timeout: float,
        cwd: Path | None = None,
        env: Mapping[str, str] | None = None,
        on_line: OnLine,
    ) -> Result:
        command = tuple(argv)
        self.calls.append(command)
        code, lines = self._answer(command)
        for line in lines:
            on_line(Stream.STDOUT, line, False)
        if code not in expect:
            raise CommandFailed(command, code, expect, ())
        return Result(command, code)

    def _answer(self, command: tuple[str, ...]) -> tuple[int, list[str]]:
        head = command[0]
        if head == "curl":
            target, url = Path(command[command.index("-o") + 1]), command[-1]
            try:
                release, name = self._release_of_url(url)
            except KeyError:
                return 22, []
            if name == "install.sh":
                if release.spoil.install_sh == "missing":
                    return 22, []
                target.write_text(release.install_sh(self.repo))
            else:
                target.write_bytes(release.spoil.wheel or release.wheel)
            return 0, []
        if command[:2] == ("git", "ls-remote"):
            tag = command[3].removeprefix("refs/tags/")
            found = self.releases.get(tag)
            if found is None:
                return 0, []
            release = found
            commit = release.spoil.commit or release.commit
            return 0, [
                f"{commit}\trefs/tags/{tag}^{{}}",
                f"{'0' * 40}\trefs/tags/{tag}",
            ]
        if command[:2] == ("git", "clone"):
            tag, clone = command[command.index("--branch") + 1], Path(command[-1])
            (clone / "wheels").mkdir(parents=True)
            (clone / "requirements.lock").write_text("")
            (clone / ".head").write_text(
                self.releases[tag].spoil.head or self.releases[tag].commit
            )
            return 0, []
        if command[:2] == ("git", "-C") and command[3:] == ("rev-parse", "HEAD"):
            return 0, [(Path(command[2]) / ".head").read_text()]
        if command[:3] == ("python3", "-m", "venv"):
            (Path(command[3]) / "bin").mkdir(parents=True)
            return 0, []
        if head.endswith("/bin/pip"):
            venv = Path(head).parent.parent
            if "--no-deps" not in command:
                return 0, []
            release = self._release_of_wheel(command[-1])
            if release.spoil.pip_fails:
                return 1, []
            _lay_venv(
                venv, release.spoil.version or release.version, release.spoil.schema
            )
            return 0, []
        if head.endswith("/bin/pridem") and command[1:] == ("version",):
            return 0, [f"pridem {_field(Path(head), 'version')}"]
        if head.endswith("/bin/python") and command[1] == "-c":
            return 0, [_field(Path(head), "schema")]
        if command[:2] == ("systemctl", "is-active"):
            return (0, ["active"]) if self.agent_active else (3, ["inactive"])
        if command[:2] == ("systemctl", "restart"):
            self.restarted = True
            return 0, []
        self.unplanned.append(command)
        return 127, []

    def _release_of_wheel(self, path: str) -> Release:
        for release in self.releases.values():
            if f"pridem-{release.version}-" in path:
                return release
        raise AssertionError(path)

    def assert_clean(self) -> None:
        assert self.unplanned == [], self.unplanned


def releases(*tags: str, **spoils: Spoil) -> dict[str, Release]:
    """Releases of ``tags``, each its own commit and wheel; ``spoils`` by tag
    with ``.`` as ``_`` (``v0_1_12``)."""
    found: dict[str, Release] = {}
    for number, tag in enumerate(tags, start=1):
        spoil = spoils.get(tag.replace(".", "_"), Spoil())
        found[tag] = Release(tag, f"{number:040x}", f"wheel of {tag}".encode(), spoil)
    return found


def tree(root: Path) -> list[str]:
    """What is under ``versions/`` and where ``current`` points."""
    versions = root / "versions"
    names = sorted(p.name for p in versions.iterdir()) if versions.is_dir() else []
    current = (
        (root / "current").resolve().name if (root / "current").is_symlink() else ""
    )
    return [*names, f"current={current}"]


def gone(path: Path) -> None:
    shutil.rmtree(path, ignore_errors=True)
