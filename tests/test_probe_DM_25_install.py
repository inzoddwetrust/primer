"""Probes DM-25: ``install.sh`` -- five actions, pins, no index, no questions.

Tier 1: the script runs under ``bash`` through ``SubprocessRunner`` (the only
place a process starts) with ``apt-get``, ``git``, ``curl``, ``uname``, ``id``,
``python3`` and the venv's ``pip`` and ``pridem`` replaced on ``PATH`` by one
Python stub written to a temporary directory; the stub records every call. No
shell file is tracked for it. ``PRIDEM_ROOT`` points the script's paths into the
test's directory. The real run on a clean Ubuntu 24.04 is tier 3 (DM-16), the
same file.

The template is rendered as ``release.yml`` renders it -- tag, commit and the
wheel's sha256 -- and the pinned sha256 of ``sops`` is swapped for the stub's
bytes, so a wrong download is a wrong hash and nothing else.
"""

import hashlib
import json
import re
import stat
import sys
from dataclasses import dataclass, field
from pathlib import Path

import pytest
import yaml
from test_probe_DM_41_ci import ci_problems, unpinned

from pridem.runner import Stream, SubprocessRunner

REPO = Path(__file__).resolve().parents[1]
INSTALL = REPO / "install.sh"
RELEASE = REPO / ".github" / "workflows" / "release.yml"
TAG, VERSION = "v0.1.0", "0.1.0"
GITHUB = "https://github.com/inzoddwetrust/primer"
WHEEL_URL = f"{GITHUB}/releases/download/{TAG}/pridem-{VERSION}-py3-none-any.whl"
COMMIT = "a" * 40
SOPS_BYTES, WHEEL_BYTES = b"sops-binary", b"pridem-wheel"
INSTALLS = ("python3", "pip")

STUB = """#!{python}
import json, os, pathlib, sys
name = pathlib.Path(sys.argv[0]).name
args = sys.argv[1:]
with open(os.environ["STUB_LOG"], "a") as log:
    log.write(json.dumps([name, *args]) + "\\n")
if name == "uname":
    print(os.environ["STUB_ARCH"])
elif name == "id":
    print(os.environ["STUB_UID"])
elif name == "git" and args[0] == "clone":
    dest = pathlib.Path(args[-1])
    (dest / "wheels").mkdir(parents=True)
    (dest / "requirements.lock").write_text("")
elif name == "git":
    print(os.environ["STUB_HEAD"])
elif name == "curl":
    url = args[-1]
    data = os.environ["STUB_SOPS"] if "getsops" in url else os.environ["STUB_WHEEL"]
    pathlib.Path(args[args.index("-o") + 1]).write_bytes(data.encode())
elif name in ("python3", "pip"):
    me = pathlib.Path(sys.argv[0]).read_text()
    made = []
    if name == "python3":
        made = [pathlib.Path(args[2]) / "bin" / "pip"]
    elif any(arg.endswith(".whl") for arg in args):
        made = [pathlib.Path(sys.argv[0]).parent / "pridem"]
    for path in made:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(me)
        path.chmod(0o755)
elif name == "pridem":
    print("pridem " + os.environ["STUB_VERSION"])
"""


def render(
    *,
    tag: str = TAG,
    commit: str = COMMIT,
    wheel: bytes = WHEEL_BYTES,
    sops: bytes = SOPS_BYTES,
    repo: str = GITHUB,
    wheel_url: str | None = None,
) -> str:
    """``install.sh`` with its pins, as the release workflow writes it.

    DM-16 added the two source pins (repository, wheel address).
    """
    url = (
        wheel_url or f"{repo}/releases/download/{tag}/pridem-{tag[1:]}-py3-none-any.whl"
    )
    text = INSTALL.read_text()
    text = text.replace("@PRIDEM_TAG@", tag).replace("@PRIDEM_COMMIT@", commit)
    text = text.replace("@PRIDEM_REPO@", repo).replace("@PRIDEM_WHEEL_URL@", url)
    text = text.replace("@PRIDEM_WHEEL_SHA256@", hashlib.sha256(wheel).hexdigest())
    pinned = re.search(r'SOPS_SHA256="([0-9a-f]{64})"', text)
    assert pinned is not None
    return text.replace(pinned.group(1), hashlib.sha256(sops).hexdigest())


@dataclass
class Box:
    root: Path
    os_release: str | None = 'NAME="Ubuntu"\nID=ubuntu\nVERSION_ID="24.04"\n'
    arch: str = "x86_64"
    uid: str = "0"
    head: str = COMMIT
    wheel: bytes = WHEEL_BYTES
    sops: bytes = SOPS_BYTES
    version: str = VERSION
    lines: list[str] = field(default_factory=list)

    def run(self, script: str) -> int:
        stubs = self.root / "stubs"
        stubs.mkdir(exist_ok=True)
        for name in ("uname", "id", "apt-get", "git", "curl", "python3"):
            path = stubs / name
            path.write_text(STUB.format(python=sys.executable))
            path.chmod(0o755)
        (self.root / "etc").mkdir(exist_ok=True)
        if self.os_release is not None:
            (self.root / "etc" / "os-release").write_text(self.os_release)
        (self.root / "usr" / "local" / "bin").mkdir(parents=True, exist_ok=True)
        file = self.root / "install.sh"
        file.write_text(script)
        env = {
            "PATH": f"{stubs}:/usr/bin:/bin",
            "PRIDEM_ROOT": str(self.root),
            "STUB_LOG": str(self.root / "calls.jsonl"),
            "STUB_ARCH": self.arch,
            "STUB_UID": self.uid,
            "STUB_HEAD": self.head,
            "STUB_SOPS": self.sops.decode(),
            "STUB_WHEEL": self.wheel.decode(),
            "STUB_VERSION": self.version,
        }

        def keep(stream: Stream, line: str, cut: bool) -> None:
            self.lines.append(line)

        result = SubprocessRunner().run(
            ["bash", str(file)], expect=(0, 1), timeout=60, env=env, on_line=keep
        )
        return result.code

    def calls(self) -> list[list[str]]:
        log = self.root / "calls.jsonl"
        if not log.exists():
            return []
        return [json.loads(line) for line in log.read_text().splitlines()]

    def names(self) -> list[str]:
        return [call[0] for call in self.calls()]


def _installed(box: Box) -> bool:
    home = box.root / "opt" / "pridem"
    current = home / "current"
    # FIX DM-16: the machine's home is 0700, root's alone
    private = stat.S_IMODE(home.stat().st_mode) == 0o700 if home.exists() else False
    return (
        private
        and current.is_symlink()
        and (box.root / "usr/local/bin/pridem").is_symlink()
    )


def _clean(tmp_path: Path) -> Box:
    """The pair of every refusal: the same box with nothing wrong installs."""
    box = Box(tmp_path / "clean")
    box.root.mkdir()
    assert box.run(render()) == 0, box.lines
    assert _installed(box)
    return box


def test_probe_DM_25_wrong_hash_aborts_before_any_install(tmp_path: Path) -> None:
    box = Box(tmp_path, head="b" * 40)
    assert box.run(render()) == 1
    assert "git" in box.names()
    assert not any(name in INSTALLS for name in box.names()), box.names()
    assert not (tmp_path / "opt" / "pridem").exists()
    assert any(f"the pin is {COMMIT}" in line for line in box.lines)
    clean = _clean(tmp_path)
    assert {"python3", "pip"} <= set(clean.names())


def test_probe_DM_25_installs_with_pypi_blocked(tmp_path: Path) -> None:
    """No pip call may reach an index; downloads only from GitHub releases."""
    box = _clean(tmp_path)
    pips = [call for call in box.calls() if call[0] == "pip"]
    assert len(pips) == 2 and all("--no-index" in call for call in pips)
    runtime, own = pips
    assert "--require-hashes" in runtime
    assert runtime[runtime.index("-r") + 1].endswith("/requirements.lock")
    assert runtime[runtime.index("--find-links") + 1].endswith("/wheels")
    assert "--no-deps" in own and own[-1].endswith(f"pridem-{VERSION}-py3-none-any.whl")
    urls = [call[-1] for call in box.calls() if call[0] == "curl"]
    assert len(urls) == 2
    assert all(
        re.fullmatch(r"https://github\.com/[^/]+/[^/]+/releases/download/.+", u)
        for u in urls
    )


def test_probe_DM_25_apt_called_with_lock_timeout(tmp_path: Path) -> None:
    box = _clean(tmp_path)
    apts = [call for call in box.calls() if call[0] == "apt-get"]
    assert len(apts) == 2
    for call in apts:
        assert call[1:3] == ["-o", "DPkg::Lock::Timeout=600"], call
    install = apts[1]
    assert install[3:5] == ["install", "-y"]
    assert set(install[5:]) == {"python3", "python3-venv", "git", "curl", "age"}


@pytest.mark.parametrize(
    "os_release",
    [
        'ID=ubuntu\nVERSION_ID="22.04"\n',
        'ID=ubuntu\nVERSION_ID="24.10"\n',
        'ID=debian\nVERSION_ID="12"\n',
        'ID=ubuntu\nVERSION_ID="24.04.1"\n',
        "",
    ],
)
def test_probe_DM_25_wrong_os_aborts(tmp_path: Path, os_release: str) -> None:
    box = Box(tmp_path, os_release=os_release)
    assert box.run(render()) == 1
    assert box.names() == []
    assert any("needs Ubuntu 24.04" in line for line in box.lines)
    _clean(tmp_path)


def test_os_release_missing_aborts(tmp_path: Path) -> None:
    box = Box(tmp_path, os_release=None)
    assert box.run(render()) == 1
    assert box.names() == []
    assert any("no /etc/os-release" in line for line in box.lines)


@pytest.mark.parametrize("arch", ["aarch64", "i686", ""])
def test_probe_DM_25_wrong_arch_aborts(tmp_path: Path, arch: str) -> None:
    box = Box(tmp_path, arch=arch)
    assert box.run(render()) == 1
    assert box.names() == ["uname"]
    assert any("needs x86_64" in line for line in box.lines)
    _clean(tmp_path)


def test_not_root_aborts(tmp_path: Path) -> None:
    box = Box(tmp_path, uid="1000")
    assert box.run(render()) == 1
    assert box.names() == ["uname", "id"]
    assert any("needs root" in line for line in box.lines)


@pytest.mark.parametrize(
    ("tag", "commit", "repo", "wheel_url"),
    [
        ("@PRIDEM_TAG@", COMMIT, GITHUB, None),
        (TAG, "@PRIDEM_COMMIT@", GITHUB, None),
        ("main", COMMIT, GITHUB, None),
        (TAG, "a" * 39, GITHUB, None),
        (TAG, COMMIT, "@PRIDEM_REPO@", WHEEL_URL),
        (TAG, COMMIT, "https://example.com/a/b", WHEEL_URL),
        (TAG, COMMIT, GITHUB, "@PRIDEM_WHEEL_URL@"),
        (TAG, COMMIT, GITHUB, "https://example.com/pridem.whl"),
        (TAG, COMMIT, GITHUB, "file:///tmp/pridem.tar.gz"),
    ],
)
def test_template_without_pins_refuses(
    tmp_path: Path, tag: str, commit: str, repo: str, wheel_url: str | None
) -> None:
    """DM-16 added the source pins: a repository and a wheel address of the
    accepted forms (``https://github.com/...`` or ``file:///...``)."""
    box = Box(tmp_path)
    assert box.run(render(tag=tag, commit=commit, repo=repo, wheel_url=wheel_url)) == 1
    assert box.names() == []
    assert any("pins are not set" in line for line in box.lines)
    unrendered = Box(tmp_path / "raw")
    unrendered.root.mkdir()
    assert unrendered.run(INSTALL.read_text()) == 1 and unrendered.names() == []


def test_wrong_wheel_or_sops_aborts_before_pip(tmp_path: Path) -> None:
    wheel = Box(tmp_path / "wheel", wheel=b"other-wheel")
    wheel.root.mkdir()
    assert wheel.run(render()) == 1
    assert "pip" not in wheel.names() and "python3" not in wheel.names()
    sops = Box(tmp_path / "sops", sops=b"other-sops")
    sops.root.mkdir()
    assert sops.run(render()) == 1
    assert "git" not in sops.names()
    assert not (sops.root / "usr/local/bin/sops").exists()


def test_rerun_same_version_changes_nothing_and_new_one_goes_beside(
    tmp_path: Path,
) -> None:
    box = _clean(tmp_path)
    before = len(box.calls())
    assert box.run(render()) == 0
    again = box.names()[before:]
    assert again == ["uname", "id", "pridem"], again
    assert box.run(render(tag="v0.2.0")) == 1  # the stub's pridem says 0.1.0
    box.version = "0.2.0"
    assert box.run(render(tag="v0.2.0")) == 0
    current = (box.root / "opt/pridem/current").resolve()
    assert (
        current.name == "v0.2.0" and (box.root / "opt/pridem/versions/v0.1.0").is_dir()
    )


def test_broken_attempt_is_removed_and_installed_again(tmp_path: Path) -> None:
    box = Box(tmp_path)
    left = tmp_path / "opt/pridem/versions" / TAG / "venv"
    left.mkdir(parents=True)
    (left / "junk").write_text("x")
    assert box.run(render()) == 0
    assert not (left / "junk").exists() and _installed(box)


def test_install_sh_is_the_only_shell_file_and_never_silent() -> None:
    shells = [p for p in REPO.rglob("*.sh") if ".venv" not in p.parts]
    assert shells == [INSTALL]
    text = INSTALL.read_text()
    assert "set -euo pipefail" in text
    assert "/dev/null" not in text and "|| true" not in text and "read -p" not in text
    assert text.count("DPkg::Lock::Timeout") == text.count("apt-get ") > 0


def _release() -> dict[object, object]:
    document = yaml.safe_load(RELEASE.read_text())
    assert isinstance(document, dict)
    return document


def _runs(job: object) -> list[str]:
    assert isinstance(job, dict)
    steps = job["steps"]
    assert isinstance(steps, list)
    return [str(step.get("run", "")) for step in steps if isinstance(step, dict)]


def test_release_builds_only_after_tier1_of_the_same_commit() -> None:
    document = _release()
    triggers = document.get(True, document.get("on"))  # YAML reads `on` as true
    assert triggers == {"push": {"tags": ["v*"]}}
    jobs = document["jobs"]
    assert isinstance(jobs, dict)
    release = jobs["release"]
    assert isinstance(release, dict) and release["needs"] == "tier1"
    tier1 = " ".join(_runs(jobs["tier1"]))
    for check in (
        "ruff check .",
        "ruff format --check .",
        "mypy .",
        "pytest",
        "shellcheck install.sh",
    ):
        assert check in tier1, check
    # tier 1 installs by the same locked-runtime recipe as ci.yml
    assert ci_problems(yaml.safe_dump({"jobs": {"tier1": jobs["tier1"]}})) == []
    count, bad = unpinned(RELEASE.read_text())
    assert count > 0 and bad == []


def test_release_checks_the_tag_builds_pinned_and_publishes_two_assets() -> None:
    jobs = _release()["jobs"]
    assert isinstance(jobs, dict)
    runs = "\n".join(_runs(jobs["release"]))
    assert 'if [ "$GITHUB_REF_NAME" != "v$version" ]' in runs
    assert "git rev-list --first-parent origin/main" in runs
    assert "pip install --require-hashes -r requirements-build.lock" in runs
    assert "pip wheel --no-deps --no-build-isolation --no-index" in runs
    pins = ["@PRIDEM_TAG@", "@PRIDEM_COMMIT@", "@PRIDEM_WHEEL_SHA256@"]
    pins += ["@PRIDEM_REPO@", "@PRIDEM_WHEEL_URL@"]  # DM-16: the sources
    for pin in pins:
        assert f"s/{pin}/" in runs or f"s|{pin}|" in runs, pin
        assert pin in INSTALL.read_text()
    assert "shellcheck dist/install.sh" in runs
    create = [line for line in runs.splitlines() if "gh release create" in line]
    assert create and "py3-none-any.whl" in runs and "dist/install.sh" in runs
    lock = (REPO / "requirements-build.lock").read_text()
    assert re.search(
        r"^flit-core==4\.1\.0 \\\n    --hash=sha256:[0-9a-f]{64}$", lock, re.M
    )
