"""DM-55: a release of the machine needs a green tier 3 on its commit; CI and
tier 3 run on pull requests, without secrets.

The release gate is the first step of the ``release`` job: it runs here as
the workflow runs it -- its ``run`` text under ``bash`` -- with a stub ``gh``
on ``PATH`` that answers the runs of ``tier3.yml`` from a file and records its
arguments. The rest is read from the workflow text; each check is a function
of the text, so each planted defect sits next to the tree it must pass.
"""

import json
import os
import re
import sys
from pathlib import Path

import yaml

from pridem.runner import Stream, SubprocessRunner

REPO = Path(__file__).resolve().parents[1]
WORKFLOWS = REPO / ".github" / "workflows"
GATE = "tier 3 is green on this commit"
SHA = "0123456789abcdef0123456789abcdef01234567"
DM_10 = "test_probe_DM_10_blank_is_fetched_by_ref_over_ssh"
STUB = f"""#!{sys.executable}
import json, os, sys
with open(os.environ["STUB_LOG"], "a") as log:
    log.write(json.dumps(sys.argv[1:]) + "\\n")
sys.stdout.write(open(os.environ["STUB_RUNS"]).read())
"""


def _text(name: str) -> str:
    return (WORKFLOWS / name).read_text(encoding="utf-8")


def _document(text: str) -> dict[str, object]:
    loaded = yaml.safe_load(text)
    assert isinstance(loaded, dict)
    return loaded


def _triggers(text: str) -> dict[str, object]:
    loaded = yaml.safe_load(text)
    found = loaded.get("on", loaded.get(True))  # YAML 1.1 reads `on` as true
    assert isinstance(found, dict)
    return found


def _steps(text: str, job: str) -> list[dict[str, object]]:
    jobs = _document(text)["jobs"]
    assert isinstance(jobs, dict)
    steps = jobs[job]["steps"]
    assert isinstance(steps, list)
    return steps


def gate_problems(text: str) -> list[str]:
    """What the release workflow ``text`` lacks to release only a commit with a
    green tier 3."""
    jobs = _document(text)["jobs"]
    assert isinstance(jobs, dict)
    release = jobs["release"]
    problems: list[str] = []
    if release.get("permissions", {}).get("actions") != "read":
        problems.append("release: no actions: read")
    names = [
        str(step.get("name", step.get("run", step.get("uses"))))
        for step in release["steps"]
    ]
    if GATE not in names:
        return [*problems, "release: no tier 3 gate"]
    gate = names.index(GATE)
    later = [
        i
        for i, step in enumerate(release["steps"])
        if "gh release create" in str(step.get("run", ""))
        or "pip wheel" in str(step.get("run", ""))
    ]
    if not later or gate > min(later):
        problems.append(
            "release: the tier 3 gate is not before the wheel and the release"
        )
    return problems


def _gate(
    tmp_path: Path, runs: list[dict[str, object]]
) -> tuple[int, str, list[list[str]]]:
    [step] = [
        s for s in _steps(_text("release.yml"), "release") if s.get("name") == GATE
    ]
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(exist_ok=True)
    gh = bin_dir / "gh"
    gh.write_text(STUB)
    gh.chmod(0o755)
    (tmp_path / "runs.json").write_text(
        json.dumps({"total_count": len(runs), "workflow_runs": runs})
    )
    log = tmp_path / "gh.log"
    log.write_text("")
    env = {
        "PATH": f"{bin_dir}:{os.environ['PATH']}",
        "GITHUB_REPOSITORY": "inzoddwetrust/primer",
        "GITHUB_SHA": SHA,
        "RUNNER_TEMP": str(tmp_path),
        "STUB_RUNS": str(tmp_path / "runs.json"),
        "STUB_LOG": str(log),
    }
    said: list[str] = []

    def keep(stream: Stream, line: str, cut: bool) -> None:
        said.append(line)

    done = SubprocessRunner().run(
        ["bash", "-eo", "pipefail", "-c", str(step["run"])],
        expect=(0, 1),
        timeout=60,
        env=env,
        on_line=keep,
    )
    calls = [json.loads(line) for line in log.read_text().splitlines()]
    return done.code, "\n".join(said), calls


def _run(number: int, status: str, conclusion: str | None) -> dict[str, object]:
    return {
        "run_number": number,
        "status": status,
        "conclusion": conclusion,
        "html_url": f"https://github.com/inzoddwetrust/primer/actions/runs/{number}",
    }


def test_a_release_needs_the_latest_tier_3_of_its_commit_green(tmp_path: Path) -> None:
    code, said, calls = _gate(tmp_path, [_run(7, "completed", "success")])
    assert (code, calls) == (
        0,
        [
            [
                "api",
                f"repos/inzoddwetrust/primer/actions/workflows/tier3.yml/runs?head_sha={SHA}&event=push&per_page=100",
            ]
        ],
    )
    assert "tier 3 on this commit is green" in said
    refused = {
        "red": ([_run(7, "completed", "failure")], "is failure"),
        "running": ([_run(7, "in_progress", None)], "is in_progress"),
        "queued": ([_run(7, "queued", None)], "is queued"),
        "not run": ([], "has not run on this commit"),
        "red after green": (
            [_run(7, "completed", "success"), _run(8, "completed", "failure")],
            "is failure",
        ),
    }
    for label, (runs, words) in refused.items():
        code, said, _ = _gate(tmp_path, runs)
        assert code == 1 and words in said, (label, said)
    # the pair of "red after green": green after red is a release
    code, _, _ = _gate(
        tmp_path, [_run(8, "completed", "success"), _run(7, "completed", "failure")]
    )
    assert code == 0


def test_the_gate_comes_first_with_its_permission() -> None:
    text = _text("release.yml")
    assert gate_problems(text) == []
    planted = {
        "no permission": text.replace("      actions: read\n", ""),
        "no gate": text.replace(
            f"      - name: {GATE}\n", "      - name: something else\n"
        ),
    }
    steps = _steps(text, "release")
    [gate] = [s for s in steps if s.get("name") == GATE]
    moved = yaml.safe_load(text)
    moved["jobs"]["release"]["steps"] = [s for s in steps if s is not gate] + [gate]
    planted["after the release"] = yaml.safe_dump(moved)
    for label, defect in planted.items():
        assert defect != text, label
        assert gate_problems(defect) != [], label


def trigger_problems(text: str) -> list[str]:
    """A workflow that does not run on pull requests to main, or gives a secret
    to one."""
    problems: list[str] = []
    triggers = _triggers(text)
    pull = triggers.get("pull_request")
    if not isinstance(pull, dict) or pull.get("branches") != ["main"]:
        problems.append("no pull_request to main")
    if "push" not in triggers:
        problems.append("no push")
    for job, body in yaml.safe_load(text)["jobs"].items():
        for step in body["steps"]:
            if (
                "secrets." in json.dumps(step)
                and step.get("if") != "github.event_name != 'pull_request'"
            ):
                problems.append(f"{job}: a secret reaches a pull request")
    return problems


def test_ci_and_tier3_run_on_pull_requests_without_secrets() -> None:
    for name in ("ci.yml", "tier3.yml"):
        assert trigger_problems(_text(name)) == [], name
    tier3 = _text("tier3.yml")
    assert tier3.count("secrets.") == 1  # the pair: the check has a secret to see
    planted = {
        "ci without pull_request": _text("ci.yml").replace(
            "  pull_request:\n    branches: [main]\n", ""
        ),
        "tier3 without pull_request": tier3.replace(
            "  pull_request:\n    branches: [main]\n", ""
        ),
        "a secret on a pull request": tier3.replace(
            "        if: github.event_name != 'pull_request'\n", ""
        ),
    }
    for label, defect in planted.items():
        assert trigger_problems(defect) != [], label


def deselect_problems(text: str) -> list[str]:
    """The tier 3 probes on a pull request must leave out the probe that needs
    the deploy key, by its name, and say so."""
    [probes] = [s for s in _steps(text, "box") if s.get("name") == "tier 3 probes"]
    run = str(probes["run"])
    guarded = re.search(
        r'if \[ "\$GITHUB_EVENT_NAME" = pull_request \]; then\n(.*?)\n\s*fi\n',
        run,
        re.S,
    )
    if guarded is None:
        return ["no pull_request branch in the probes"]
    problems: list[str] = []
    if f'deselect=(-k "not {DM_10}")' not in guarded.group(1):
        problems.append("DM-10 is not left out on a pull request")
    if "echo" not in guarded.group(1):
        problems.append("leaving DM-10 out is not said")
    if '"${deselect[@]}"' not in run.split("pytest", 1)[-1]:
        problems.append("pytest does not get the deselection")
    return problems


def test_a_pull_request_leaves_out_only_the_probe_with_the_key() -> None:
    text = _text("tier3.yml")
    assert deselect_problems(text) == []
    sources = (REPO / "tier3" / "test_tier3_sources.py").read_text(encoding="utf-8")
    assert f"def {DM_10}(" in sources  # the name left out is the probe's
    planted = {
        "no -k": text.replace(f'deselect=(-k "not {DM_10}")', "deselect=()"),
        "silent": re.sub(r'\n\s*echo "pull_request: no secrets.*', "", text),
        "not passed": text.replace(' "${deselect[@]}"', ""),
    }
    for label, defect in planted.items():
        assert defect != text, label
        assert deselect_problems(defect) != [], label
