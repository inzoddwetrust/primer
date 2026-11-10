"""The groups of tier 3 (DM-73): each test in exactly one, each group a job.

Tier 3 runs as a matrix of ``tier3.yml``: one job per group, each on its own
clean runner with its own preparation of the box. A group that needs the
blank installed gets it from a fixture (``NEEDS_BOX``) -- except ``b``, whose
first test is the whole install itself. Inside a group the tests run in the
order of their files.

``GROUPS`` is the one table: a test function of ``tier3/test_*.py`` and its
group. ``python tier3/groups.py`` checks, without running a test, that every
test function is in exactly one group, every row names a test that exists,
and the groups of the table are exactly the ``matrix.group`` of the job in
``tier3.yml``; ``--selftest`` plants each defect it must catch. A test without
a group is not skipped quietly: tier 3 refuses to collect it (``select``).

    python tier3/groups.py
    python tier3/groups.py --selftest
"""

import argparse
import ast
import sys
from collections.abc import Callable, Sequence
from pathlib import Path

import pytest
import yaml

HERE = Path(__file__).resolve().parent
WORKFLOW = HERE.parent / ".github" / "workflows" / "tier3.yml"

GROUPS: tuple[tuple[str, str], ...] = (
    # a -- no install: the box, the host, the passport, the sources, checks
    ("test_probe_DM_16_status_on_a_fresh_box_is_green", "a"),
    ("test_probe_DM_16_box_files_are_private_on_the_runner", "a"),
    ("test_probe_DM_12_host_steps_on_a_clean_runner", "a"),
    ("test_probe_DM_12_planted_dpkg_lock_waits_then_passes", "a"),
    ("test_probe_DM_12_planted_dpkg_lock_over_timeout_is_red_without_checkmark", "a"),
    ("test_tier3_box_decrypts_its_passport_from_the_ops_repository", "a"),
    ("test_tier3_passport_not_for_this_box_is_red_with_its_key", "a"),
    ("test_probe_DM_10_blank_is_fetched_by_ref_over_ssh", "a"),
    ("test_tier3_check_of_the_blank_and_of_a_planted_copy", "a"),
    ("test_tier3_compose_takes_a_single_quoted_value_as_it_is", "a"),
    ("test_tier3_certbot_tag_has_the_pinned_digest", "a"),
    # b -- the whole install and the tests on the box it leaves
    ("test_tier3_the_whole_install_of_the_blank", "b"),
    ("test_tier3_the_new_health_of_the_blank_and_its_service", "b"),
    ("test_probe_DM_64_product_reaches_only_its_egress_hosts", "b"),
    ("test_probe_DM_58_skin_version_switch_needs_no_rebuild", "b"),
    ("test_tier3_both_slots_from_one_brand_package_by_subpath", "b"),
    # c -- an install of its own: services, languages, options, then destroy
    ("test_tier3_a_service_of_the_edition_goes_up_before_the_product", "c"),
    ("test_tier3_two_instances_with_their_own_languages", "c"),
    ("test_tier3_an_option_off_is_the_literal_and_on_the_value", "c"),
    ("test_tier3_only_the_declared_consumer_reaches_a_point", "c"),
    ("test_tier3_destroy_takes_the_blank_off_the_box", "c"),
    # d -- a clean box: the blank without its service, then with it
    ("test_probe_DM_59_product_gets_the_seams_of_its_service_after_health", "d"),
    # e -- an install of its own: the build mode of packages
    ("test_tier3_build_mode_of_the_blank", "e"),
)

NEEDS_BOX = frozenset({"c", "e"})
"""Groups whose tests need the blank installed by a fixture first."""


def group_of(name: str) -> str:
    """The group of the test function ``name`` in ``GROUPS`` as it is when
    called; in no group or in two -- an error."""
    found = [group for test, group in GROUPS if test == name]
    if len(found) != 1:
        raise LookupError(f"{name}: in {len(found)} groups of tier3/groups.py")
    return found[0]


def select(names: Sequence[str], group: str) -> tuple[list[str], list[str]]:
    """``names`` of the collected tests (the function's, before any ``[``):
    those of ``group`` and the others. A test in no group or in two is an
    error, never a skip."""
    mine: list[str] = []
    others: list[str] = []
    for name in names:
        (mine if group_of(name.partition("[")[0]) == group else others).append(name)
    return mine, others


def keep_group(config: pytest.Config, items: list[pytest.Item]) -> None:
    """``pytest_collection_modifyitems`` of tier 3 (``tier3/conftest.py``):
    only the tests of this job's group, in the order of their files; a test
    in no group or in two is a usage error, not a skip (no quiet mode)."""
    group = str(config.getoption("--tier3-group"))
    try:
        mine, _ = select([item.name for item in items], group)
    except LookupError as error:
        raise pytest.UsageError(str(error)) from None
    if not mine:
        raise pytest.UsageError(f"tier 3 group {group!r} has no test")
    keep = [item for item in items if item.name in mine]
    config.hook.pytest_deselected(items=[i for i in items if i.name not in mine])
    items[:] = keep


def test_functions(directory: Path = HERE) -> list[str]:
    """Every top-level ``test*`` function of ``test_*.py``, by reading the
    files (no import, no collection)."""
    out: list[str] = []
    for path in sorted(directory.glob("test_*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        out += [
            node.name
            for node in tree.body
            if isinstance(node, ast.FunctionDef) and node.name.startswith("test")
        ]
    return out


def matrix(workflow: Path = WORKFLOW) -> list[str]:
    """``jobs.box.strategy.matrix.group`` of ``tier3.yml``."""
    document = yaml.safe_load(workflow.read_text(encoding="utf-8"))
    groups = document["jobs"]["box"]["strategy"]["matrix"]["group"]
    return [str(group) for group in groups]


def problems(
    tests: Sequence[str], groups: Sequence[tuple[str, str]], jobs: Sequence[str]
) -> list[str]:
    """What breaks "each test in exactly one group, each group a job"."""
    out: list[str] = []
    for test in tests:
        count = sum(1 for name, _ in groups if name == test)
        if count == 0:
            out.append(f"{test}: in no group")
        elif count > 1:
            out.append(f"{test}: in {count} groups")
    out += [f"{name}: no such test" for name, _ in groups if name not in tests]
    named = {group for _, group in groups}
    out += [f"group {g}: no job in tier3.yml" for g in sorted(named - set(jobs))]
    out += [f"job {g}: no test in tier3/groups.py" for g in jobs if g not in named]
    return out


def check() -> int:
    tests, jobs = test_functions(), matrix()
    found = problems(tests, GROUPS, jobs)
    for line in found:
        print(line, file=sys.stderr)
    if not found:
        print(f"tier 3: {len(tests)} test functions, each in one of {len(jobs)} groups")
    return 1 if found else 0


Rows = list[tuple[str, str]]
Case = tuple[list[str], Rows, list[str]]
Plant = Callable[[list[str], Rows, list[str]], Case]


def _no_group(t: list[str], g: Rows, j: list[str]) -> Case:
    return [*t, "test_planted_without_a_group"], g, j


def _two_groups(t: list[str], g: Rows, j: list[str]) -> Case:
    return t, [*g, (t[0], "b" if g[0][1] != "b" else "a")], j


def _row_without_test(t: list[str], g: Rows, j: list[str]) -> Case:
    return t, [*g, ("test_planted_renamed_away", g[0][1])], j


def _group_without_job(t: list[str], g: Rows, j: list[str]) -> Case:
    return t, g, [x for x in j if x != g[0][1]]


def _job_without_tests(t: list[str], g: Rows, j: list[str]) -> Case:
    return t, g, [*j, "z"]


DEFECTS: dict[str, Plant] = {
    "a test in no group": _no_group,
    "a test in two groups": _two_groups,
    "a row with no test": _row_without_test,
    "a group with no job": _group_without_job,
    "a job with no tests": _job_without_tests,
}


def selftest() -> int:
    """The real table must pass; each planted defect must not."""
    tests, jobs = test_functions(), matrix()
    if problems(tests, GROUPS, jobs):
        print("selftest: the real table does not pass", file=sys.stderr)
        return 1
    passed = []
    for name, plant in DEFECTS.items():
        found = problems(*plant(list(tests), list(GROUPS), list(jobs)))
        if found:
            print(f"selftest: {name!r} refused: {found[0]}")
        else:
            passed.append(name)
    for name in passed:
        print(f"selftest: planted defect {name!r} passed", file=sys.stderr)
    return 1 if passed else 0


def main(argv: Sequence[str]) -> int:
    parser = argparse.ArgumentParser(prog="python tier3/groups.py")
    parser.add_argument("--selftest", action="store_true")
    args = parser.parse_args(argv)
    return selftest() if args.selftest else check()


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
