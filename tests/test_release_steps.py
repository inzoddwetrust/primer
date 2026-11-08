"""DM-82: the steps of the release and of the deploy key, run as the workflow
runs them -- their ``run`` text under ``bash -eo pipefail`` -- against the
inputs that broke them.

- The tag: only ``vX.Y.Z`` passes, before any step uses it; a tag of another
  form (``v1/e``, ``v1.2``, ``1.2.3``, with a space, with a suffix) stops the
  release there.
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

import yaml

from pridem.runner import Stream, SubprocessRunner

REPO = Path(__file__).resolve().parents[1]
WORKFLOWS = REPO / ".github" / "workflows"
TAG_STEP = "the tag is vX.Y.Z"
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


def test_only_a_tag_of_the_form_vxyz_is_released() -> None:
    step = _step("release.yml", "release", TAG_STEP)
    for tag in ("v1.2.3", "v0.0.0", "v10.20.30"):
        assert _bash(step, {"GITHUB_REF_NAME": tag})[0] == 0, tag
    for tag in ("v1/e", "v1.2", "1.2.3", "v1.2.3 x", "v1.2.3-rc1", "v1.2.3\nv", ""):
        code, said = _bash(step, {"GITHUB_REF_NAME": tag})
        assert code == 1 and "is not vX.Y.Z" in said, (tag, said)


def test_the_tag_is_checked_before_any_step_uses_it() -> None:
    document = yaml.safe_load((WORKFLOWS / "release.yml").read_text(encoding="utf-8"))
    steps = document["jobs"]["release"]["steps"]
    users = [
        i for i, s in enumerate(steps) if "GITHUB_REF_NAME" in str(s.get("run", ""))
    ]
    names = [s.get("name") for s in steps]
    assert users and names.index(TAG_STEP) == min(users)  # the pair: it is used
    assert len(users) >= 3


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
    env = {"GITHUB_REF_NAME": f"v{VERSION}", "RUNNER_TEMP": str(tmp_path)}
    # the tip: the first line rev-list writes, so grep stops at once
    for sha in (marks["tip"], marks["below"]):
        code, said = _bash(step, {**env, "GITHUB_SHA": sha}, cwd=repo)
        assert code == 0, said
    code, said = _bash(step, {**env, "GITHUB_SHA": "0" * 40}, cwd=repo)
    assert code == 1 and "is not on the first parent of main" in said, said
    code, said = _bash(
        step, {**env, "GITHUB_REF_NAME": "v9.9.9", "GITHUB_SHA": marks["tip"]}, cwd=repo
    )
    assert code == 1 and "is not v1.2.3" in said, said


def test_a_second_parent_of_main_is_not_released(tmp_path: Path) -> None:
    step = _step("release.yml", "release", FIRST_PARENT_STEP)
    repo = tmp_path / "merged"
    marks = _history(repo, merged=True)
    env = {"GITHUB_REF_NAME": f"v{VERSION}", "RUNNER_TEMP": str(tmp_path)}
    code, said = _bash(step, {**env, "GITHUB_SHA": marks["side"]}, cwd=repo)
    assert code == 1 and "is not on the first parent of main" in said, said
    code, said = _bash(step, {**env, "GITHUB_SHA": marks["tip"]}, cwd=repo)
    assert code == 0, said  # the pair: the merge itself is


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
