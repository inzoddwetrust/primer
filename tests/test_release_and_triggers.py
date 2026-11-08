"""DM-55: a release of the machine needs a green tier 3 on its commit; CI and
tier 3 run on pull requests, without secrets.

DM-82: the release needs ``ci.yml`` green on its commit too, and its tier 1
runs every check of ``ci.yml``; neither the gate nor the release job can be
made conditional or allowed to fail. The secret check reads the parsed
workflow, not a string: a secret is any ``${{ }}`` expression that names
``secrets`` -- ``secrets.X``, ``secrets['X']``, ``toJSON(secrets)`` -- anywhere
in the document, and only the ``env`` of a step that does not run on a pull
request may hold one; ``secrets: inherit``, ``pull_request_target`` and
``workflow_run`` (which run with secrets on code a pull request sent) are
refused in every workflow.

The release gate runs here as the workflow runs it -- its ``run`` text under
``bash`` -- with a stub ``gh`` on ``PATH`` that answers the runs of each
workflow from its own file and records its arguments. The rest is read from
the workflow text; each check is a function of the text, so each planted
defect sits next to the tree it must pass.
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
GATE = "ci and tier 3 are green on this commit"
GATED = ("ci.yml", "tier3.yml")
SECRET = re.compile(r"\$\{\{[^}]*\bsecrets\b")
NOT_ON_PULL_REQUESTS = "github.event_name != 'pull_request'"
UNSAFE_TRIGGERS = ("pull_request_target", "workflow_run")
SHA = "0123456789abcdef0123456789abcdef01234567"
DM_10 = "test_probe_DM_10_blank_is_fetched_by_ref_over_ssh"
STUB = f"""#!{sys.executable}
import json, os, sys
with open(os.environ["STUB_LOG"], "a") as log:
    log.write(json.dumps(sys.argv[1:]) + "\\n")
workflow = sys.argv[2].split("/actions/workflows/")[1].split("/")[0]
sys.stdout.write(open(os.path.join(os.environ["STUB_RUNS"], workflow)).read())
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
    for job_name, job in jobs.items():
        for key in ("if", "continue-on-error"):
            if key in job:
                problems.append(f"{job_name}: the job has {key}:")
            for step in job["steps"]:
                if key in step:
                    problems.append(f"{job_name}: a step has {key}:")
    names = [
        str(step.get("name", step.get("run", step.get("uses"))))
        for step in release["steps"]
    ]
    if GATE not in names:
        return [*problems, "release: no gate"]
    gate = names.index(GATE)
    run = str(release["steps"][gate].get("run", ""))
    for workflow in GATED:
        if workflow not in run:
            problems.append(f"release: the gate does not ask {workflow}")
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
    tmp_path: Path,
    runs: list[dict[str, object]],
    ci: list[dict[str, object]] | None = None,
) -> tuple[int, str, list[list[str]]]:
    """The gate with ``runs`` for tier 3 and ``ci`` for ci.yml (the same runs
    when not given)."""
    [step] = [
        s for s in _steps(_text("release.yml"), "release") if s.get("name") == GATE
    ]
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(exist_ok=True)
    gh = bin_dir / "gh"
    gh.write_text(STUB)
    gh.chmod(0o755)
    answers = tmp_path / "runs"
    answers.mkdir(exist_ok=True)
    for workflow, given in (
        ("tier3.yml", runs),
        ("ci.yml", runs if ci is None else ci),
    ):
        (answers / workflow).write_text(
            json.dumps({"total_count": len(given), "workflow_runs": given})
        )
    log = tmp_path / "gh.log"
    log.write_text("")
    env = {
        "PATH": f"{bin_dir}:{os.environ['PATH']}",
        "GITHUB_REPOSITORY": "inzoddwetrust/primer",
        "GITHUB_SHA": SHA,
        "RUNNER_TEMP": str(tmp_path),
        "STUB_RUNS": str(answers),
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
                f"repos/inzoddwetrust/primer/actions/workflows/{workflow}/runs?head_sha={SHA}&event=push&per_page=100",
            ]
            for workflow in GATED
        ],
    )
    for workflow in GATED:
        assert f"{workflow} on this commit is green" in said
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
    green = [_run(9, "completed", "success")]
    for label, (runs, words) in refused.items():
        # each refusal by each workflow, the other one green
        for workflow, tier3, ci in (
            ("ci.yml", green, runs),
            ("tier3.yml", runs, green),
        ):
            code, said, _ = _gate(tmp_path, tier3, ci=ci)
            [line] = [x for x in said.splitlines() if words in x]
            assert code == 1 and line.startswith(workflow), (label, workflow, said)
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
    gate_line = f"      - name: {GATE}\n"
    planted["the gate conditional"] = text.replace(
        gate_line, gate_line + "        if: github.ref == 'refs/heads/x'\n"
    )
    planted["the gate may fail"] = text.replace(
        gate_line, gate_line + "        continue-on-error: true\n"
    )
    planted["the release job may fail"] = text.replace(
        "    needs: tier1\n", "    needs: tier1\n    continue-on-error: true\n"
    )
    planted["tier 1 conditional"] = text.replace(
        "  tier1:\n", "  tier1:\n    if: github.ref == 'refs/heads/x'\n"
    )
    planted["the gate without ci"] = text.replace(
        "for workflow in ci.yml tier3.yml; do", "for workflow in tier3.yml; do"
    )
    for label, defect in planted.items():
        assert defect != text, label
        assert gate_problems(defect) != [], label


def _check_lines(job: dict[str, object]) -> list[str]:
    steps = job["steps"]
    assert isinstance(steps, list)
    return [
        line.strip()
        for step in steps
        if isinstance(step, dict) and isinstance(step.get("run"), str)
        for line in str(step["run"]).splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]


def tier1_problems(ci: str, release: str) -> list[str]:
    """Lines of the Python jobs of ``ci.yml`` that tier 1 of the release does
    not run: every check of CI runs on the commit of a release."""
    ci_jobs = _document(ci)["jobs"]
    release_jobs = _document(release)["jobs"]
    assert isinstance(ci_jobs, dict) and isinstance(release_jobs, dict)
    tier1 = set(_check_lines(release_jobs["tier1"]))
    problems: list[str] = []
    python_jobs = [
        job
        for job in ci_jobs.values()
        if "actions/setup-python@" in json.dumps(job["steps"])
    ]
    if not python_jobs:
        return ["ci.yml: no Python job"]
    for job in python_jobs:
        for line in _check_lines(job):
            if line not in tier1:
                problems.append(f"tier1 of the release does not run: {line}")
    return problems


def test_tier1_of_a_release_runs_every_check_of_ci() -> None:
    ci, release = _text("ci.yml"), _text("release.yml")
    assert tier1_problems(ci, release) == []
    assert "python -m pridem.conformance.stack --selftest" in ci  # the pair
    planted = {
        "no conformance": release.replace(
            "        run: python -m pridem.conformance.stack --selftest\n", ""
        ),
        "no groups": release.replace(
            "          python tier3/groups.py --selftest\n", ""
        ),
        "no mypy": release.replace("      - run: mypy .\n", ""),
    }
    for label, defect in planted.items():
        assert defect != release, label
        assert tier1_problems(ci, defect) != [], label


def secret_problems(text: str) -> list[str]:
    """Secrets the workflow ``text`` could give to code a pull request sent:
    an unsafe trigger, ``secrets: inherit``, or a secret anywhere but the
    ``env`` of a step that does not run on a pull request."""
    document = _document(text)
    problems = [
        f"on: {trigger} runs with secrets on a pull request's code"
        for trigger in UNSAFE_TRIGGERS
        if trigger in _triggers(text)
    ]
    jobs = document["jobs"]
    assert isinstance(jobs, dict)
    allowed: list[object] = []
    for job_name, job in jobs.items():
        if job.get("secrets") == "inherit":
            problems.append(f"{job_name}: secrets: inherit")
        for step in job.get("steps", []):
            env = step.get("env")
            if step.get("if") == NOT_ON_PULL_REQUESTS and isinstance(env, dict):
                allowed.extend(env.values())

    def walk(node: object, where: str) -> None:
        if any(node is value for value in allowed):
            return
        if isinstance(node, dict):
            for key, value in node.items():
                walk(value, f"{where}.{key}")
        elif isinstance(node, list):
            for index, value in enumerate(node):
                walk(value, f"{where}[{index}]")
        elif isinstance(node, str) and SECRET.search(node):
            problems.append(f"{where}: a secret reaches a pull request")

    walk(document, "")
    return problems


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
    return problems + secret_problems(text)


def test_ci_and_tier3_run_on_pull_requests_without_secrets() -> None:
    for name in ("ci.yml", "tier3.yml"):
        assert trigger_problems(_text(name)) == [], name
    assert secret_problems(_text("release.yml")) == []
    tier3 = _text("tier3.yml")
    assert len(SECRET.findall(tier3)) == 1  # the pair: the check has a secret to see
    key = "PRIMER_BLANK_DEPLOY_KEY: ${{ secrets.PRIMER_BLANK_DEPLOY_KEY }}"
    on_push = "on:\n  push:\n"
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
        "secrets by index": tier3.replace(
            "          TIER3_GROUP: ${{ matrix.group }}\n",
            "          TIER3_GROUP: ${{ secrets['PRIMER_BLANK_DEPLOY_KEY'] }}\n",
        ),
        "every secret at once": tier3.replace(
            "          TIER3_GROUP: ${{ matrix.group }}\n",
            "          TIER3_GROUP: ${{ toJSON(secrets) }}\n",
        ),
        "a secret in the env of a job": tier3.replace(
            "    runs-on: ubuntu-24.04\n",
            f"    runs-on: ubuntu-24.04\n    env:\n      {key}\n",
        ),
        "a secret in the env of the workflow": tier3.replace(
            "permissions:\n", f"env:\n  {key}\npermissions:\n"
        ),
        "secrets: inherit": tier3.replace(
            "    runs-on: ubuntu-24.04\n",
            "    runs-on: ubuntu-24.04\n    secrets: inherit\n",
        ),
        "pull_request_target": tier3.replace(
            on_push, "on:\n  pull_request_target:\n    branches: [main]\n  push:\n"
        ),
        "workflow_run": tier3.replace(
            on_push, "on:\n  workflow_run:\n    workflows: [ci]\n  push:\n"
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
