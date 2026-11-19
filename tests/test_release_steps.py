"""DM-82: the steps of the release and of the deploy key, run as the workflow
runs them -- their ``run`` text under ``bash -eo pipefail`` -- against the
inputs that broke them.

- The tag and the commit (DM-119): the first step names them -- ``TAG`` and
  ``SHA`` for every later step -- a pushed tag and its commit, or the
  button's ``v{__version__}`` and the head of ``main``; only it reads
  ``GITHUB_REF_NAME`` and ``GITHUB_SHA``. Only ``vX.Y.Z`` passes, before any
  step uses it; a tag of another form (``v1/e``, ``v1.2``, ``1.2.3``, with a
  space, with a suffix) stops the release there. The button refuses a run
  off ``main``, a tag that exists, a version not after the last tag.
- The first parent: ``git rev-list`` goes into a file, not into ``grep -q``
  through a pipe -- on a history longer than a pipe holds, ``grep`` leaving at
  the first match killed ``rev-list`` with SIGPIPE and ``pipefail`` refused a
  commit that is on the first parent. A commit that is only a second parent of
  ``main``, or not in ``main``, is refused.
- The deploy key: an empty secret (GitHub gives a secret that is not set as an
  empty string) is a refusal that names the secret and holds no value; a set
  one is written as before.
"""

import os
import stat
from pathlib import Path

import pytest
import yaml

from pridem.runner import Stream, SubprocessRunner

REPO = Path(__file__).resolve().parents[1]
WORKFLOWS = REPO / ".github" / "workflows"
TAG_STEP = "the tag and the commit of this release"
FIRST_PARENT_STEP = "tag is v{__version__} on the first parent of main"
KEY_STEP = "the deploy key of primer-blank, from the CI secrets (DM-10)"
# Longer than a pipe holds: 41 bytes a commit, 64 KiB a pipe.
HISTORY = 3000
VERSION = "1.2.3"


def _step(workflow: str, job: str, name: str) -> str:
    document = yaml.safe_load((WORKFLOWS / workflow).read_text(encoding="utf-8"))
    [step] = [s for s in document["jobs"][job]["steps"] if s.get("name") == name]
    assert "if" not in step or name == KEY_STEP
    return str(step["run"])


def _bash(script: str, env: dict[str, str], cwd: Path | None = None) -> tuple[int, str]:
    said: list[str] = []

    def keep(stream: Stream, line: str, cut: bool) -> None:
        said.append(line)

    done = SubprocessRunner().run(
        ["bash", "-eo", "pipefail", "-c", script],
        expect=(0, 1),
        timeout=120,
        cwd=cwd,
        env={"PATH": os.environ["PATH"], "HOME": os.environ.get("HOME", "/"), **env},
        on_line=keep,
    )
    return done.code, "\n".join(said)


def _pushed(tmp: Path, tag: str) -> dict[str, str]:
    return {
        "GITHUB_EVENT_NAME": "push",
        "GITHUB_REF_NAME": tag,
        "GITHUB_SHA": "a" * 40,
        "GITHUB_ENV": str(tmp / "env"),
        "RUNNER_TEMP": str(tmp),
    }


def test_only_a_tag_of_the_form_vxyz_is_released(tmp_path: Path) -> None:
    """Changed by DM-119: the form is checked in the step that names the tag
    and the commit; a pushed tag that passes becomes ``TAG``, its commit
    ``SHA``."""
    step = _step("release.yml", "release", TAG_STEP)
    for tag in ("v1.2.3", "v0.0.0", "v10.20.30"):
        (tmp_path / "env").write_text("")
        assert _bash(step, _pushed(tmp_path, tag))[0] == 0, tag
        named = (tmp_path / "env").read_text().splitlines()
        assert named == [f"TAG={tag}", f"SHA={'a' * 40}"]
    for tag in ("v1/e", "v1.2", "1.2.3", "v1.2.3 x", "v1.2.3-rc1", "v1.2.3\nv", ""):
        (tmp_path / "env").write_text("")
        code, said = _bash(step, _pushed(tmp_path, tag))
        assert code == 1 and "is not vX.Y.Z" in said, (tag, said)
        assert (tmp_path / "env").read_text() == ""


def test_only_the_first_step_reads_the_event_s_tag_and_commit() -> None:
    """Changed by DM-119 (was: the tag's form is checked before any step
    uses it): one logic for both ways -- the first step reads
    ``GITHUB_REF_NAME`` and ``GITHUB_SHA`` and checks the form; every later
    step reads ``TAG`` and ``SHA`` (the pair: at least three do)."""
    document = yaml.safe_load((WORKFLOWS / "release.yml").read_text(encoding="utf-8"))
    steps = document["jobs"]["release"]["steps"]
    runs = [str(s.get("run", "")) for s in steps]
    raw = [
        i
        for i, run in enumerate(runs)
        if "GITHUB_REF_NAME" in run or "GITHUB_SHA" in run
    ]
    names = [s.get("name") for s in steps]
    assert raw == [names.index(TAG_STEP)]
    named = [i for i, run in enumerate(runs) if "$TAG" in run or "$SHA" in run]
    assert len(named) >= 4 and min(named) > raw[0]


def _history(root: Path, *, merged: bool) -> dict[str, str]:
    """A repository at ``root`` whose ``origin/main`` is ``HISTORY`` commits on
    its first parent, the first with ``pridem/__init__.py``; with ``merged``,
    a side commit merged as a second parent at the tip. Returns the marks."""
    lines: list[str] = []
    init = f'__version__ = "{VERSION}"\n'
    for number in range(1, HISTORY + 1):
        message = f"c{number}"
        lines += [
            "commit refs/heads/main",
            f"mark :{number}",
            f"committer t <t@t> {1_700_000_000 + number} +0000",
            f"data {len(message)}",
            message,
        ]
        if number > 1:
            lines.append(f"from :{number - 1}")
        else:
            lines += ["M 100644 inline pridem/__init__.py", f"data {len(init)}", init]
        lines.append("")
    if merged:
        side, merge = HISTORY + 1, HISTORY + 2
        lines += [
            "commit refs/heads/side",
            f"mark :{side}",
            "committer t <t@t> 1800000000 +0000",
            "data 4",
            "side",
            f"from :{HISTORY - 1}",
            "",
            "commit refs/heads/main",
            f"mark :{merge}",
            "committer t <t@t> 1800000001 +0000",
            "data 5",
            "merge",
            f"from :{HISTORY}",
            f"merge :{side}",
            "",
        ]
    stream = root.parent / f"{root.name}.stream"
    stream.write_text("\n".join(lines) + "\n", encoding="utf-8")
    script = (
        f"git init -q {root} && cd {root} && git fast-import --quiet < {stream}"
        " && git update-ref refs/remotes/origin/main refs/heads/main"
        " && git checkout -q main"
        " && git rev-parse refs/heads/main && git rev-parse refs/heads/main~1"
    )
    if merged:
        script += " && git rev-parse refs/heads/side"
    code, said = _bash(script, {})
    assert code == 0, said
    shas = said.split()
    marks = {"tip": shas[0], "below": shas[1]}
    if merged:
        marks["side"] = shas[2]
    return marks


def test_a_commit_on_the_first_parent_of_a_long_main_is_released(
    tmp_path: Path,
) -> None:
    step = _step("release.yml", "release", FIRST_PARENT_STEP)
    repo = tmp_path / "long"
    marks = _history(repo, merged=False)
    env = {"TAG": f"v{VERSION}", "RUNNER_TEMP": str(tmp_path)}
    # the tip: the first line rev-list writes, so grep stops at once
    for sha in (marks["tip"], marks["below"]):
        code, said = _bash(step, {**env, "SHA": sha}, cwd=repo)
        assert code == 0, said
    code, said = _bash(step, {**env, "SHA": "0" * 40}, cwd=repo)
    assert code == 1 and "is not on the first parent of main" in said, said
    code, said = _bash(step, {**env, "TAG": "v9.9.9", "SHA": marks["tip"]}, cwd=repo)
    assert code == 1 and "is not v1.2.3" in said, said


def test_a_second_parent_of_main_is_not_released(tmp_path: Path) -> None:
    step = _step("release.yml", "release", FIRST_PARENT_STEP)
    repo = tmp_path / "merged"
    marks = _history(repo, merged=True)
    env = {"TAG": f"v{VERSION}", "RUNNER_TEMP": str(tmp_path)}
    code, said = _bash(step, {**env, "SHA": marks["side"]}, cwd=repo)
    assert code == 1 and "is not on the first parent of main" in said, said
    code, said = _bash(step, {**env, "SHA": marks["tip"]}, cwd=repo)
    assert code == 0, said  # the pair: the merge itself is


def _released(root: Path, version: str, *tags: str) -> str:
    """A repository at ``root``: ``pridem/__init__.py`` at ``version`` on
    ``main``, with ``tags`` on it; the head back."""
    init = root / "pridem" / "__init__.py"
    init.parent.mkdir(parents=True)
    init.write_text(f'"""pridem."""\n\n__version__ = "{version}"\n')
    script = (
        f"git init -q -b main {root} && cd {root} && git add -A"
        " && git -c user.name=t -c user.email=t@t commit -q -m c"
        + "".join(f" && git tag {tag}" for tag in tags)
        + " && git rev-parse HEAD"
    )
    code, said = _bash(script, {})
    assert code == 0, said
    return said.split()[-1]


def _button(tmp: Path, head: str, ref: str = "refs/heads/main") -> dict[str, str]:
    return {
        "GITHUB_EVENT_NAME": "workflow_dispatch",
        "GITHUB_REF": ref,
        "GITHUB_SHA": head,
        "GITHUB_ENV": str(tmp / "env"),
        "RUNNER_TEMP": str(tmp),
    }


def test_the_button_releases_the_head_of_main_as_its_version(tmp_path: Path) -> None:
    """DM-119: on ``main``, a version after every tag -- ``TAG`` is
    ``v{__version__}``, ``SHA`` the head."""
    repo = tmp_path / "repo"
    head = _released(repo, "0.1.3", "v0.1.0", "v0.1.2")
    (tmp_path / "env").write_text("")
    code, said = _bash(
        _step("release.yml", "release", TAG_STEP), _button(tmp_path, head), cwd=repo
    )
    assert code == 0, said
    assert (tmp_path / "env").read_text().splitlines() == ["TAG=v0.1.3", f"SHA={head}"]


@pytest.mark.parametrize(
    ("version", "ref", "said"),
    [
        ("0.1.2", "refs/heads/main", "v0.1.2 exists: this version is released"),
        ("0.1.1", "refs/heads/main", "v0.1.1 is not after v0.1.2"),
        ("0.1.3", "refs/heads/side", "the release is run on main, not refs/heads/side"),
    ],
    ids=["exists", "not-after", "off-main"],
)
def test_the_button_refuses_before_anything_is_made(
    tmp_path: Path, version: str, ref: str, said: str
) -> None:
    """A tag that exists, a version not after the last tag, a run off
    ``main``: refused in the first step -- nothing named, nothing built."""
    repo = tmp_path / "repo"
    head = _released(repo, version, "v0.1.0", "v0.1.2")
    (tmp_path / "env").write_text("")
    step = _step("release.yml", "release", TAG_STEP)
    code, out = _bash(step, _button(tmp_path, head, ref), cwd=repo)
    assert code == 1 and said in out, out
    assert (tmp_path / "env").read_text() == ""


def test_an_empty_deploy_key_is_a_refusal_with_no_value(tmp_path: Path) -> None:
    step = _step("tier3.yml", "box", KEY_STEP)
    key = "-----BEGIN PLANTED KEY-----\nplanted\n-----END PLANTED KEY-----"
    written = tmp_path / "set"
    written.mkdir()
    code, said = _bash(
        step, {"RUNNER_TEMP": str(written), "PRIMER_BLANK_DEPLOY_KEY": key}
    )
    assert code == 0 and "planted" not in said, said  # the key is not printed
    file = written / "deploy_key"
    assert file.read_text() == key + "\n"
    assert stat.S_IMODE(file.stat().st_mode) == 0o600
    for label, env in (("empty", {"PRIMER_BLANK_DEPLOY_KEY": ""}), ("not set", {})):
        place = tmp_path / label.replace(" ", "-")
        place.mkdir()
        code, said = _bash(step, {"RUNNER_TEMP": str(place), **env})
        assert code == 1, (label, said)
        assert "secret PRIMER_BLANK_DEPLOY_KEY is empty or not set" in said, said
        assert not (place / "deploy_key").exists(), label
