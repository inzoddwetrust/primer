"""Every job that runs ``pytest`` has ``age`` and ``sops`` first (DM-13).

The passport tests decrypt with the real tools, so a job without them is red
for the wrong reason, or -- worse -- a later edit makes the tests skip. A job
has the tools when, before its ``pytest`` line, it either runs ``install.sh``
(tier 3: the box's own bootstrap) or installs ``age`` with apt and ``sops`` by
the version and sha256 it reads from ``install.sh`` -- one copy of the pin --
checked by ``sha256sum -c``. Each check is a function of the workflow text, so
each planted defect sits next to the tree it must pass.
"""

import re
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parents[1]
WORKFLOWS = REPO / ".github" / "workflows"

_PYTEST = re.compile(r"(^|\s|/)(-m\s+)?pytest(\s|$)")
_BOOTSTRAP = re.compile(r"\bbash\s+\S*install\.sh\b")
_NEEDED = (
    re.compile(r"\^SOPS_VERSION=.*\binstall\.sh\b"),
    re.compile(r"\^SOPS_SHA256=.*\binstall\.sh\b"),
    re.compile(r"\bsha256sum -c --strict\b"),
    re.compile(r"\bapt-get\b.*\binstall -y age\b"),
    re.compile(r"getsops/sops/releases/download/\$sops_version/"),
)


def _lines(step: object) -> list[str]:
    run = step.get("run") if isinstance(step, dict) else None
    if not isinstance(run, str):
        return []
    return [line for line in run.splitlines() if not line.lstrip().startswith("#")]


def tool_problems(text: str) -> list[str]:
    """Jobs of the workflow ``text`` that run ``pytest`` without the tools."""
    problems: list[str] = []
    document = yaml.safe_load(text)
    for name, job in document["jobs"].items():
        seen: list[str] = []
        for step in job["steps"]:
            lines = _lines(step)
            if any(_PYTEST.search(line) for line in lines):
                bootstrap = any(_BOOTSTRAP.search(line) for line in seen)
                pinned = all(
                    any(need.search(line) for line in seen) for need in _NEEDED
                )
                if not (bootstrap or pinned):
                    problems.append(f"{name}: pytest without age and sops by the pin")
            seen += lines
    return problems


def _pytest_jobs(text: str) -> int:
    document = yaml.safe_load(text)
    return sum(
        any(_PYTEST.search(line) for step in job["steps"] for line in _lines(step))
        for job in document["jobs"].values()
    )


def test_every_pytest_job_has_age_and_sops_by_the_pin() -> None:
    files = sorted(WORKFLOWS.glob("*.yml"))
    texts = {file.name: file.read_text(encoding="utf-8") for file in files}
    # the pair: there are such jobs, in ci, release and tier3
    assert {name for name, text in texts.items() if _pytest_jobs(text)} == {
        "ci.yml",
        "release.yml",
        "tier3.yml",
    }
    for name, text in texts.items():
        assert tool_problems(text) == [], name


def _tools_last(text: str) -> str:
    """``text`` with the tools step of job ``pytest`` moved after ``pytest``."""
    document = yaml.safe_load(text)
    steps = document["jobs"]["pytest"]["steps"]
    [tools] = [s for s in steps if str(s.get("name", "")).startswith("age and sops")]
    steps.remove(tools)
    steps.append(tools)
    return yaml.safe_dump(document, sort_keys=False)


def test_planted_defects_are_caught() -> None:
    ci = (WORKFLOWS / "ci.yml").read_text(encoding="utf-8")
    planted = {
        "no checksum": ci.replace("sha256sum -c --strict", "true"),
        "pin typed in": ci.replace(
            """$(sed -n 's/^SOPS_VERSION="\\(.*\\)"$/\\1/p' install.sh)""", "v3.13.3"
        ),
        "no age": ci.replace("install -y age", "install -y git"),
        "after pytest": _tools_last(ci),
    }
    for label, text in planted.items():
        assert text != ci, label
        assert tool_problems(text) != [], label
