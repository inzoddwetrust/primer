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


def test_a_full_run_of_the_new_groups_is_a_release() -> None:
    """DM-162: tier 3 in ten groups, cut so that none takes more than 10 minutes
    -- a run where every one of them ran green is a release; a run without one
    of the new groups (g, h, i, j) is not.

    Changed by DM-208: fifteen groups -- a run without one of k, l, m, n, o is
    not a release either; a full run of the ten groups of before is none."""
    assert ALL == list("abcdefghijklmno")
    full = _run(1, 10)
    assert groups.full_run([full], {1: _jobs(*ALL)})[0] is True
    assert groups.full_run([full], {1: _jobs(*"abcdefghij")})[0] is False
    for missing in ("g", "h", "i", "j", "k", "l", "m", "n", "o"):
        some = [group for group in ALL if group != missing]
        assert groups.full_run([full], {1: _jobs(*some)})[0] is False, missing


def _order() -> list[str]:
    """Every test of tier 3 in the order of the files: the order a group runs
    its own in (``keep_group``), whatever the order of the rows of ``GROUPS``."""
    return groups.test_functions()


def _found(case: groups.Case) -> list[str]:
    return groups.problems(*case)


def _real() -> tuple[list[str], groups.Rows, list[str]]:
    return _order(), list(groups.GROUPS), groups.matrix()


def test_the_pairs_that_stand_on_each_other_stay_in_one_group_in_order() -> None:
    """N4: what a test of tier 3 stands on stays in its group, before it -- the
    restore half-way after the dump; the verb on a job, then destroy, then
    destroy --all, last of their group; the last of a, b and d last.

    Changed by DM-208: the chains and the last tests are the tables of
    ``tier3/groups.py`` (``CHAINS``, ``LAST``, ``FIRST``), which its check
    reads -- not a list of this test's own. What N4 named is in them, held
    here by name; the order is the files', which a group runs in -- not the
    order of the rows of ``GROUPS``."""
    order = _order()
    group = dict(groups.GROUPS)
    chained = {(one, two) for chain in groups.CHAINS for one, two in pairs(chain)}
    assert (
        "test_tier3_a_dump_of_the_blank_restores_what_was_in_it",
        "test_tier3_a_restore_that_fails_half_way_leaves_the_database_as_it_was",
    ) in chained
    assert (
        "test_tier3_destroy_takes_the_blank_off_the_box",
        "test_tier3_destroy_all_wipes_the_persistent_volume",
    ) in chained
    assert any(
        chain[0] == "test_tier3_a_verb_on_a_job_of_another_entry_and_a_seam_from_asked"
        and chain[-1] == "test_tier3_destroy_all_wipes_the_persistent_volume"
        for chain in groups.CHAINS
    )
    for last in (
        "test_tier3_destroy_all_wipes_the_persistent_volume",
        "test_probe_DM_24_sigkill_leaves_the_lock_to_the_grandchild",
        "test_tier3_gc_trims_the_build_cache_to_the_budget",
        "test_tier3_doctor_is_empty_with_the_apt_timers_on",
    ):
        assert last in groups.LAST
    # the tables hold on the real cut, read here apart from the check itself
    for chain in groups.CHAINS:
        assert len({group[test] for test in chain}) == 1, chain
        mine = [test for test in order if group[test] == group[chain[0]]]
        at = mine.index(chain[0])
        assert tuple(mine[at : at + len(chain)]) == tuple(chain), chain
    for last in groups.LAST:
        assert [test for test in order if group[test] == group[last]][-1] == last
    for first in groups.FIRST:
        assert [test for test in order if group[test] == group[first]][0] == first
    assert _found(_real()) == []


def pairs(chain: tuple[str, ...]) -> list[tuple[str, str]]:
    return list(zip(chain, chain[1:], strict=False))


DUMP = "test_tier3_a_dump_of_the_blank_restores_what_was_in_it"
RESTORE = "test_tier3_a_restore_that_fails_half_way_leaves_the_database_as_it_was"
STOPPED = "test_tier3_services_stopped_for_migrate_come_back"
PLANTED = groups.PLANTED


def test_each_planted_defect_of_a_cut_is_refused_by_its_own_check() -> None:
    """DM-208: the selftest of ``groups.py`` asks only that a planted defect
    is refused. Here -- by what: each of the seven defects of ``FIRST``,
    ``LAST`` and ``CHAINS`` gives exactly the finding of its own check, so a
    check that stopped looking is red here even while another one still
    refuses the same plant."""
    t, g, j = _real()
    plant = groups.DEFECTS
    assert _found(plant["a chain in two groups"](t, g, j)) == [
        f"{RESTORE}: in group a, its chain in group c"
    ]
    assert _found(plant["a chain out of its order"](t, g, j)) == [
        f"{DUMP}: runs before {STOPPED} of its chain",
        f"{STOPPED}: between {DUMP} and {RESTORE} of a chain",
    ]
    assert _found(plant["a test between two of a chain"](t, g, j)) == [
        f"{PLANTED}: between {DUMP} and {RESTORE} of a chain"
    ]
    last = "test_probe_DM_24_sigkill_leaves_the_lock_to_the_grandchild"
    assert _found(plant["a test after the last of its group"](t, g, j)) == [
        f"{last}: not the last of group a -- {PLANTED} is"
    ]
    first = "test_tier3_the_whole_install_of_the_blank"
    assert _found(plant["a test before the first of its group"](t, g, j)) == [
        f"{first}: not the first of group b -- {PLANTED} is"
    ]
    assert _found(plant["a chain of one test"](t, g, j)) == [f"a chain of 1: {t[0]}"]
    assert _found(plant["a table that names no test"](t, g, j)) == [
        "test_planted_renamed_away: in LAST, and no such test"
    ]


def test_a_table_of_a_cut_names_each_test_once_and_only_tests() -> None:
    """Twins of the tables themselves: a name twice in ``LAST`` or ``FIRST``,
    a name of ``FIRST`` or of a chain that is no test, a chain with no test at
    all -- each said; the pair is the real tables, with nothing to say."""
    t, g, j = _real()
    twice = (groups.FIRST, [*groups.LAST, groups.LAST[0]], groups.CHAINS)
    assert groups.stands(t, g, twice) == [f"{groups.LAST[0]}: twice in LAST"]
    ghost = ([*groups.FIRST, "test_ghost"], groups.LAST, groups.CHAINS)
    assert groups.stands(t, g, ghost) == ["test_ghost: in FIRST, and no such test"]
    chain = (groups.FIRST, groups.LAST, [(DUMP, "test_ghost")])
    assert groups.stands(t, g, chain) == ["test_ghost: in a chain, and no such test"]
    empty = (groups.FIRST, groups.LAST, [()])
    assert groups.stands(t, g, empty) == ["a chain of 0: no test"]
    assert groups.stands(t, g, (groups.FIRST, groups.LAST, groups.CHAINS)) == []


def test_every_part_of_an_installed_group_installs_its_box() -> None:
    """N1: c, e and f were installed by a fixture; every part cut out of them
    (g, h out of c; i out of e; j out of f) is too -- else its first test finds
    no blank on the box.

    Changed by DM-208: the five groups cut out of them and of b and d (k, l,
    m, n, o) are too; b and d, and only they, start with the install of their
    first test (``FIRST``), and a has none."""
    assert set("cefghijklmno") == groups.NEEDS_BOX
    assert {"a", "b", "d"}.isdisjoint(groups.NEEDS_BOX)
    group = dict(groups.GROUPS)
    assert {group[first] for first in groups.FIRST} == {"b", "d"}
    # every group is one of the three kinds: a, its own install, a fixture's
    assert set(groups.ALL) == {"a"} | {"b", "d"} | groups.NEEDS_BOX
