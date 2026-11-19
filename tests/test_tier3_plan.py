"""Which groups of tier 3 a push runs, and the gate of a release (DM-125).

``tier3/groups.py``: ``affected`` maps the files a push changed to groups --
every unknown path to all of them, never fewer checks; ``full_run`` takes only
a run of tier 3 where every group's job ran green, by a push or by hand.
"""

import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "tier3"))

import groups  # noqa: E402 -- tier 3's module, by its directory

FILES = groups.groups_of_files()
ALL = list(groups.ALL)


def test_a_file_of_tier_3_runs_the_groups_of_its_tests() -> None:
    """G3: a file of tier 3 -- exactly the groups of its tests, as ``GROUPS``
    has them; the pair: another file -- its own groups."""
    box = {
        group for test, group in groups.GROUPS if test.startswith("test_probe_DM_16")
    }
    assert (
        set(groups.affected(["tier3/test_tier3_box.py"], FILES))
        == box | FILES["tier3/test_tier3_box.py"]
    )
    assert groups.affected(["tier3/test_tier3_box.py"], FILES) == ["a"]
    assert set(groups.affected(["tier3/test_tier3_whole_install.py"], FILES)) == set(
        FILES["tier3/test_tier3_whole_install.py"]
    )


def test_tier_1_documents_and_schemas_run_no_group() -> None:
    """G5: tier 1, the README, the contract's schemas, ci.yml -- no group; the
    pair: with one file of the machine among them -- every group."""
    quiet = ["tests/test_console.py", "README.md", "contract/schema/verdict.v1.json"]
    assert groups.affected([*quiet, ".github/workflows/ci.yml"], FILES) == []
    assert groups.affected([*quiet, "pridem/events.py"], FILES) == ALL


def test_an_unknown_path_and_an_unknown_change_run_every_group() -> None:
    """G2, G4: a path the map does not know, the support of tier 3, the box's
    preparation, and no list of files at all -- every group."""
    for path in (
        "something/new.txt",
        "tier3/conftest.py",
        "tier3/groups.py",
        "install.sh",
        ".github/workflows/tier3.yml",
        "requirements.lock",
        "wheels/x.whl",
    ):
        assert groups.affected([path], FILES) == ALL, path
    assert groups.affected(None, FILES) == ALL
    assert groups.affected([], FILES) == []


def _run(
    run_id: int, number: int, event: str = "push", ok: bool = True
) -> dict[str, object]:
    return {
        "id": run_id,
        "run_number": number,
        "event": event,
        "status": "completed",
        "conclusion": "success" if ok else "failure",
        "html_url": f"https://x/runs/{run_id}",
    }


def _jobs(*group_names: str, red: str = "") -> list[dict[str, object]]:
    out: list[dict[str, object]] = [{"name": "plan", "conclusion": "success"}]
    for group in group_names:
        out.append(
            {
                "name": f"box ({group})",
                "conclusion": "failure" if group == red else "success",
            }
        )
    return out


def test_the_release_takes_only_a_run_of_every_group_green() -> None:
    """G1: of the runs on the commit, those of every group; the newest must be
    green -- a green run of some groups is not a release's, a red full run
    after a green one refuses, a green full run after a red one is a release;
    by a push or by hand, never by a pull request."""
    some = _run(1, 10)
    full = _run(2, 11, event="workflow_dispatch")
    red = _run(3, 12, ok=False)
    jobs = {1: _jobs("a", "c"), 2: _jobs(*ALL), 3: _jobs(*ALL, red="d")}
    assert groups.full_run([some], jobs)[0] is False
    assert groups.full_run([some, full], jobs) == (
        True,
        "in full on this commit is green: https://x/runs/2",
    )
    assert groups.full_run([some, full, red], jobs)[0] is False
    later = _run(4, 13)
    assert groups.full_run([red, later], {**jobs, 4: _jobs(*ALL)})[0] is True
    assert (
        groups.full_run([_run(5, 14, event="pull_request")], {5: _jobs(*ALL)})[0]
        is False
    )


def test_the_matrix_of_box_is_the_plan_s(tmp_path: Path) -> None:
    """The job ``box`` runs the groups of ``plan`` -- a fixed list in the
    workflow is no group (the check of ``groups.py`` refuses it)."""
    assert groups.matrix() == ALL
    fixed = tmp_path / "tier3.yml"
    fixed.write_text(
        "jobs:\n  box:\n    strategy:\n      matrix:\n        group: [a, b]\n"
    )
    assert groups.matrix(fixed) == []
