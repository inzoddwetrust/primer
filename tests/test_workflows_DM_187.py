"""DM-187 (REVIEW-0006 K6: S8, D1, D2, D3, D7): the release and the secrets of
the stand.

- The probe, on real git: a tag moved onto another commit is ``moved``
  (``tools/release_tag.py``) -- ``tag-moved``.
- The release makes its tag by ``POST git/refs`` -- refused when the ref is
  there -- and publishes on it (``--verify-tag``, no ``--target``), with
  ``SHA256SUMS``; its job is in the environment ``release``.
- A pushed tag releases nothing: ``tag.yml`` reads it.
- The secrets of the stand leave the runner in ``always()``, read back.

Each check is a function of the text it reads; each test plants the defects
it must catch next to the tree it must pass (par0 9).
"""

import os
import sys
from pathlib import Path

import yaml

from pridem.runner import Stream, SubprocessRunner

REPO = Path(__file__).resolve().parents[1]
WORKFLOWS = REPO / ".github" / "workflows"
CLEANUP = "the secrets of the stand leave the runner"
GONE = (
    '"$RUNNER_TEMP/deploy_key"',
    '"$RUNNER_TEMP/github_api_header"',
    "/root/.docker",
)


def _tool(remote: str, tag: str, commit: str) -> tuple[int, list[str], list[str]]:
    """``tools/release_tag.py`` as ``release.yml`` and ``tag.yml`` run it: its
    exit, its stdout and its stderr."""
    out: list[str] = []
    err: list[str] = []

    def keep(stream: Stream, line: str, cut: bool) -> None:
        (out if stream is Stream.STDOUT else err).append(line)

    found = SubprocessRunner().run(
        [sys.executable, str(REPO / "tools" / "release_tag.py"), remote, tag, commit],
        expect=(0, 1),
        timeout=60,
        on_line=keep,
    )
    return found.code, out, err


def _git(*args: str, cwd: Path) -> str:
    env = {
        **os.environ,
        "GIT_AUTHOR_NAME": "t",
        "GIT_AUTHOR_EMAIL": "t@t",
        "GIT_COMMITTER_NAME": "t",
        "GIT_COMMITTER_EMAIL": "t@t",
    }
    lines: list[str] = []

    def keep(stream: Stream, line: str, cut: bool) -> None:
        if stream is Stream.STDOUT:
            lines.append(line)

    SubprocessRunner().run(["git", *args], timeout=60, cwd=cwd, env=env, on_line=keep)
    return "\n".join(lines).strip()


def _steps(text: str, job: str) -> list[dict[str, object]]:
    steps = yaml.safe_load(text)["jobs"][job]["steps"]
    assert isinstance(steps, list)
    return steps


def _runs(steps: list[dict[str, object]]) -> str:
    return "\n".join(str(step.get("run", "")) for step in steps)


# --- the probe ----------------------------------------------------------------


def test_probe_DM_187_a_moved_tag_is_tag_moved(tmp_path: Path) -> None:
    """A bare repository, a tag v1 at A (annotated): v1 against A -- ``same``,
    exit 0; a tag not there -- ``new``, exit 0; v1 pushed again by force onto
    B -- against A, ``moved``, exit 1 and ``tag-moved`` with both commits."""
    origin = tmp_path / "origin.git"
    work = tmp_path / "work"
    _git("init", "-q", "--bare", str(origin), cwd=tmp_path)
    _git("init", "-q", str(work), cwd=tmp_path)
    _git("commit", "-q", "--allow-empty", "-m", "a", cwd=work)
    a = _git("rev-parse", "HEAD", cwd=work)
    _git("commit", "-q", "--allow-empty", "-m", "b", cwd=work)
    b = _git("rev-parse", "HEAD", cwd=work)
    _git("tag", "-a", "v1", "-m", "v1", a, cwd=work)
    _git("push", "-q", str(origin), "HEAD:main", "v1", cwd=work)
    remote = str(origin)
    assert _tool(remote, "v1", a) == (0, ["same"], [])
    assert _tool(remote, "v2", a) == (0, ["new"], [])
    _git("tag", "-f", "-a", "v1", "-m", "moved", b, cwd=work)
    _git("push", "-q", "-f", str(origin), "v1", cwd=work)
    assert _tool(remote, "v1", a) == (
        1,
        ["moved"],
        [f"tag-moved: v1 is {b}, the release is {a}"],
    )
    assert _tool(remote, "v1", b) == (0, ["same"], [])  # the pair: its own commit


# --- the release --------------------------------------------------------------


def release_problems(text: str) -> list[str]:
    """What keeps the release from making its tag where it is not and from
    publishing on that tag alone, with ``SHA256SUMS``, in its environment."""
    document = yaml.safe_load(text)
    triggers = document.get(True, document.get("on"))
    problems: list[str] = []
    if triggers != {"workflow_dispatch": None}:
        problems.append("a release by something else than the button")
    job = document["jobs"]["release"]
    if job.get("environment") != "release":
        problems.append("the release job is not in the environment release")
    steps = _steps(text, "release")
    lines = [
        (i, line.strip())
        for i, step in enumerate(steps)
        for line in str(step.get("run", "")).splitlines()
    ]
    made = [i for i, line in lines if line.startswith('gh api -X POST "repos/')]
    made_refs = [line for _, line in lines if "/git/refs" in line and "POST" in line]
    create = [(i, line) for i, line in lines if line.startswith("gh release create")]
    if not made or not made_refs:
        problems.append("no tag made by POST git/refs")
    if not create:
        problems.append("no release")
    elif made and not made[0] < create[0][0]:
        problems.append("the tag is made after the release")
    runs = _runs(steps)
    if "--target" in runs:
        problems.append("--target: a tag made by someone else would be taken")
    if not any("--verify-tag" in line for _, line in create):
        problems.append("the release does not stand on its own tag (--verify-tag)")
    published = [
        str(step.get("run", "")).split("gh release create", 1)[-1]
        for step in steps
        if "gh release create" in str(step.get("run", ""))
    ]
    if not any("dist/SHA256SUMS" in run for run in published):
        problems.append("no SHA256SUMS in the release")
    if "sha256sum" not in runs or "> SHA256SUMS" not in runs:
        problems.append("SHA256SUMS is not made")
    return problems


def test_the_release_makes_its_tag_where_it_is_not() -> None:
    """D2, D7: the tag by ``POST git/refs`` before the release, the release on
    it with ``--verify-tag`` and no ``--target``, ``SHA256SUMS`` made and
    published, the job in the environment ``release``, the button alone."""
    text = (WORKFLOWS / "release.yml").read_text()
    assert release_problems(text) == []
    steps = _steps(text, "release")
    [made] = [s for s in steps if s.get("name") == "the tag, made where it is not"]
    moved = yaml.safe_load(text)
    order = [s for s in steps if s is not made] + [made]
    moved["jobs"]["release"]["steps"] = order
    planted = {
        "--target back": text.replace(
            'gh release create "$TAG" --verify-tag',
            'gh release create "$TAG" --target "$SHA"',
        ),
        "no POST git/refs": text.replace("-X POST", "-X GET", 1),
        "the tag after the release": yaml.safe_dump(moved),
        "no SHA256SUMS published": text.replace(" dist/SHA256SUMS \\", " \\", 1),
        "no SHA256SUMS made": text.replace("> SHA256SUMS", "> /dev/null", 1),
        "no environment": text.replace("    environment: release", "", 1),
        "a pushed tag releases": text.replace(
            "on:\n  workflow_dispatch:\n",
            'on:\n  push:\n    tags: ["v*"]\n  workflow_dispatch:\n',
        ),
    }
    for label, defect in planted.items():
        assert defect != text, label
        assert release_problems(defect) != [], label


def tag_guard_problems(text: str) -> list[str]:
    """``tag.yml``: on a pushed tag alone, it reads the release of the tag and
    the tag by ``tools/release_tag.py``."""
    document = yaml.safe_load(text)
    triggers = document.get(True, document.get("on"))
    problems: list[str] = []
    if triggers != {"push": {"tags": ["v*"]}}:
        problems.append("the guard runs on something else than a pushed tag")
    runs = _runs(_steps(text, "tag"))
    if "tag-not-released" not in runs:
        problems.append("a tag with no release passes")
    if "python tools/release_tag.py" not in runs:
        problems.append("the tag is not read against the release")
    if "^COMMIT=" not in runs:
        problems.append("the release's commit is not read from its install.sh")
    return problems


def test_a_pushed_tag_is_read_against_its_release() -> None:
    """S8: ``tag.yml`` -- a tag with no release is red, a tag at another commit
    than its release's is ``tag-moved``; it releases nothing."""
    text = (WORKFLOWS / "tag.yml").read_text()
    assert tag_guard_problems(text) == []
    assert "gh release create" not in text
    planted = {
        "no release_tag": text.replace("python tools/release_tag.py", "true", 1),
        "no release, no red": text.replace('echo "tag-not-released:', 'echo "fine:'),
        "on main too": text.replace(
            'on:\n  push:\n    tags: ["v*"]\n',
            'on:\n  push:\n    tags: ["v*"]\n    branches: [main]\n',
        ),
    }
    for label, defect in planted.items():
        assert defect != text, label
        assert tag_guard_problems(defect) != [], label


# --- the secrets of the stand -------------------------------------------------


def cleanup_problems(text: str) -> list[str]:
    """The secrets of the stand leave the runner in ``always()``, after the
    last step that reads them, and their leaving is read back."""
    steps = _steps(text, "box")
    names = [str(step.get("name", "")) for step in steps]
    if CLEANUP not in names:
        return ["the secrets stay on the runner"]
    at = names.index(CLEANUP)
    step = steps[at]
    problems: list[str] = []
    if step.get("if") != "always()":
        problems.append("the secrets leave only when the run is green")
    run = str(step.get("run", ""))
    for path in GONE:
        if path not in run.split("for path in", 1)[0]:
            problems.append(f"{path} is not removed")
        if path not in run.split("for path in", 1)[-1]:
            problems.append(f"{path} is not read back")
    readers = [i for i, s in enumerate(steps) if "/root/.docker/config.json" in str(s)]
    if readers and max(readers) > at:
        problems.append("a step reads the login after it left")
    return problems


def test_the_secrets_of_the_stand_leave_the_runner() -> None:
    """D3: the deploy key, the API header of the job token and root's docker
    login are removed in ``always()`` and read back as gone -- after the
    measure of the pull limit, which reads the login."""
    text = (WORKFLOWS / "tier3.yml").read_text()
    assert cleanup_problems(text) == []
    steps = _steps(text, "box")
    [cleanup] = [s for s in steps if s.get("name") == CLEANUP]
    early = yaml.safe_load(text)
    early["jobs"]["box"]["steps"] = [cleanup] + [s for s in steps if s is not cleanup]
    planted = {
        "only when green": text.replace(
            f"      - name: {CLEANUP}\n        if: always()\n",
            f"      - name: {CLEANUP}\n        if: success()\n",
        ),
        "the key stays": text.replace('rm -f "$RUNNER_TEMP/deploy_key" ', "rm -f ", 1),
        "the login stays": text.replace("sudo rm -rf /root/.docker\n", "", 1),
        "not read back": text.replace(
            '"$RUNNER_TEMP/github_api_header" /root/.docker; do',
            '"$RUNNER_TEMP/github_api_header"; do',
        ),
        "before the last reader": yaml.safe_dump(early),
        "no cleanup": text.replace(f"      - name: {CLEANUP}\n", "      - name: x\n"),
    }
    for label, defect in planted.items():
        assert defect != text, label
        assert cleanup_problems(defect) != [], label
