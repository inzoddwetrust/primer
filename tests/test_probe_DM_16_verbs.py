"""Probes DM-16: the verbs ``version`` and ``status`` behind the CLI.

``status`` takes the box's lock, recovers runs that ended without a verdict,
opens its journal and writes one verdict with no steps; the box root is the
test's directory through ``run(..., root=...)``. Anything refused before a run
exits 1 with stderr and leaves the box untouched (contract 2 v1.9).
"""

import io
import json
import re
from pathlib import Path

import pytest
import yaml
from state_support import header, run_id, state

from pridem import __version__
from pridem.cli import run
from pridem.events import Secrets
from pridem.report.schema import Verdict
from pridem.state import Box

NO_SECRETS = Secrets(())


def _run(argv: list[str], root: Path) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    code = run(argv, root=root, out=out, err=err)
    return code, out.getvalue(), err.getvalue()


def _verdicts(root: Path) -> list[Verdict]:
    return [
        Verdict.model_validate_json(path.read_text())
        for path in sorted((root / "history").iterdir())
    ]


def test_probe_DM_16_status_writes_one_verdict(tmp_path: Path) -> None:
    root = tmp_path / "opt" / "pridem"
    code, out, err = _run(["status"], root)
    assert (code, err) == (0, "")
    [verdict] = _verdicts(root)
    assert (verdict.verb, verdict.exit_code, verdict.result) == ("status", 0, "green")
    assert verdict.steps == [] and verdict.passport_version is None
    assert (
        verdict.composition_before
        == verdict.composition_after
        == {"pridem": __version__}
    )
    assert "passport_version" not in verdict.model_dump_json()
    assert [p.name for p in (root / "journal").iterdir()] == [f"{verdict.run_id}.jsonl"]
    assert out.startswith("status → green · ") and "passport" not in out

    # the pair: a run that ended without a verdict gets its own red one first
    other = tmp_path / "other"
    box = Box(other)
    with box.lock("dying"):
        box.open_journal(header(run_id(1)), NO_SECRETS).close()
    assert _run(["status"], other)[0] == 0
    first, second = _verdicts(other)
    assert (first.run_id, first.result) == (run_id(1), "red")
    assert (second.verb, second.result) == ("status", "green")


@pytest.mark.parametrize(
    "argv",
    [
        ["nope"],
        ["status", "extra"],
        ["status", "--force"],
        ["--force", "status"],
        ["version", "--json"],
        ["version", "extra"],
        [],
    ],
)
def test_probe_DM_16_unknown_verb_or_arg_refused_before_run(
    tmp_path: Path, argv: list[str]
) -> None:
    root = tmp_path / "opt" / "pridem"
    code, out, err = _run(argv, root)
    assert (code, out) == (1, "")
    assert err.startswith("pridem: ") and err.endswith("\n")
    assert not root.exists(), "refused before anything ran"
    # the pair: the same root is created by a run that is not refused
    assert _run(["status"], root)[0] == 0 and root.is_dir()


def test_status_json_prints_the_verdict(tmp_path: Path) -> None:
    root = tmp_path / "box"
    code, out, _ = _run(["--json", "status"], root)
    assert code == 0
    printed = Verdict.model_validate_json(out)
    [written] = _verdicts(root)
    assert printed == written
    assert json.loads(out)["steps"] == []


def test_status_composition_comes_from_state_json(tmp_path: Path) -> None:
    root = tmp_path / "box"
    box = Box(root)
    with box.lock("install"):
        box.write_state(state())
    assert _run(["status"], root)[0] == 0
    [verdict] = _verdicts(root)
    assert verdict.composition_before == state().composition
    assert verdict.composition_after == state().composition


def test_status_quarantines_a_damaged_state_json(tmp_path: Path) -> None:
    root = tmp_path / "box"
    root.mkdir(mode=0o700)
    (root / "state.json").write_bytes(b"{")
    code, _, _ = _run(["status"], root)
    assert code == 2
    [verdict] = _verdicts(root)
    assert verdict.result == "incomplete"
    assert [i.model_dump() for i in verdict.report.incomplete] == [
        {"what": "state", "code": "quarantined"}
    ]
    assert verdict.composition_before == {"pridem": __version__}
    assert (root / "state.json.damaged").exists()


def test_status_on_a_busy_box_is_refused_without_a_verdict(tmp_path: Path) -> None:
    root = tmp_path / "box"
    assert _run(["status"], root)[0] == 0
    box = Box(root)
    with box.lock("deploy"):
        code, out, err = _run(["status"], root)
    assert (code, out) == (1, "")
    assert "busy" in err
    assert len(_verdicts(root)) == 1
    assert len(list((root / "journal").iterdir())) == 1


def test_version_prints_the_version_and_touches_no_box(tmp_path: Path) -> None:
    root = tmp_path / "box"
    assert _run(["version"], root) == (0, f"pridem {__version__}\n", "")
    assert not root.exists()


def test_two_status_runs_write_two_verdicts(tmp_path: Path) -> None:
    root = tmp_path / "box"
    assert _run(["status"], root)[0] == 0
    assert _run(["status"], root)[0] == 0
    first, second = _verdicts(root)
    assert first.run_id != second.run_id


# --- FIX DM-16: tier 3 steps do not depend on the directory they start in ---

REPO = Path(__file__).resolve().parents[1]
TIER3 = REPO / ".github" / "workflows" / "tier3.yml"
REPO_NAMES = (
    "install.sh",
    "requirements-build.lock",
    "requirements.lock",
    "wheels",
    "pyproject.toml",
    "pridem/",
    "tier3",
)
RELATIVE = re.compile(
    r"(?<![\w/$.-])(?:" + "|".join(re.escape(name) for name in REPO_NAMES) + r")"
)


def workflow_problems(text: str) -> list[str]:
    """Steps of ``text`` that read the repository before the clone exists, or
    name a file of it relative to the directory they start in."""
    document = yaml.safe_load(text)
    problems: list[str] = []
    for name, job in document["jobs"].items():
        defaults = (job.get("defaults") or {}).get("run") or {}
        if defaults.get("working-directory") != "${{ github.workspace }}":
            problems.append(f"{name}: no working-directory ${{{{ github.workspace }}}}")
        cloned = False
        for index, step in enumerate(job["steps"]):
            if str(step.get("uses", "")).startswith("actions/checkout@"):
                cloned = True
                continue
            run = "\n".join(  # a comment reads nothing
                line
                for line in str(step.get("run", "")).splitlines()
                if not line.lstrip().startswith("#")
            )
            reads = "$GITHUB_WORKSPACE" in run or RELATIVE.search(run) is not None
            if reads and not cloned:
                problems.append(
                    f"{name}: step {index} reads the repository before checkout"
                )
            if RELATIVE.search(run):
                problems.append(
                    f"{name}: step {index} names a repository file relatively"
                )
    return problems


def test_tier3_steps_read_the_repository_only_after_checkout() -> None:
    text = TIER3.read_text()
    assert workflow_problems(text) == []
    assert "$GITHUB_WORKSPACE/requirements-build.lock" in text  # the check sees reads
    found = re.search(r"      - uses: actions/checkout@.*\n        with:\n.*\n", text)
    assert found is not None
    checkout = found.group(0)
    late = text.replace(checkout, "").replace(
        "      - name: tier 3 probes\n", checkout + "      - name: tier 3 probes\n"
    )
    assert late != text and any("before checkout" in p for p in workflow_problems(late))
    relative = text.replace(
        '-r "$GITHUB_WORKSPACE/requirements-build.lock"', "-r requirements-build.lock"
    )
    assert relative != text
    assert workflow_problems(relative) == [
        "box: step 2 names a repository file relatively"
    ]
    anywhere = text.replace("        working-directory: ${{ github.workspace }}\n", "")
    assert anywhere != text and len(workflow_problems(anywhere)) == 1
