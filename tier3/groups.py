"""The groups of tier 3 (DM-73): each test in exactly one, each group a job.

Tier 3 runs as a matrix of ``tier3.yml``: one job per group, each on its own
clean runner with its own preparation of the box. A group that needs the
blank installed gets it from a fixture (``NEEDS_BOX``) -- except ``b`` and
``d``, whose first test is an install on a clean box itself (``FIRST``).
Inside a group the tests run in the order of their files.

``GROUPS`` is the one table: a test function of ``tier3/test_*.py`` and its
group. ``python tier3/groups.py`` checks, without running a test, that every
test function is in exactly one group, every row names a test that exists,
and the groups of the table are exactly the ``matrix.group`` of the job in
``tier3.yml``; ``--selftest`` plants each defect it must catch. A test without
a group is not skipped quietly: tier 3 refuses to collect it (``select``).

The groups are cut by what a group costs (DM-208): the preparation of its job
and the install of its box -- about three and a half minutes before its first
test -- and the durations of its tests, the worst of three full runs each; the
sum of the worst of every group is under ten minutes. What a cut must keep is
in three tables the same check reads (``stands``): ``FIRST`` and ``LAST`` --
the tests that open and close their group -- and ``CHAINS`` -- the tests that
stand on each other, together and one after another. A test moved to another
group, or a new one put between two of a chain, is refused here, in tier 1,
not found red on the stand.

    python tier3/groups.py
    python tier3/groups.py --selftest

The groups a push runs (DM-125): ``affected`` maps the files a push changed to
the groups that read them -- a file of tier 3 to the groups of its tests, the
machine, the box's preparation and any path the map does not know to every
group, tier 1, the documents and the contract's schemas to none. A pull
request and a run by hand run every group. ``full_run`` is the gate of a
release: a run of tier 3 on the commit where every group ran green -- a run of
some groups is never a release's.

    python tier3/groups.py --affected PATHS_FILE   (no file: every group)
    python tier3/groups.py --full-run RUNS_JSON JOBS_DIR

Only the standard library at the top: the job that plans the groups and the
gate of a release run it with the runner's own Python.
"""

from __future__ import annotations

import argparse
import ast
import json
import sys
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import pytest

HERE = Path(__file__).resolve().parent
WORKFLOW = HERE.parent / ".github" / "workflows" / "tier3.yml"

GROUPS: tuple[tuple[str, str], ...] = (
    # a -- no install: the box, the host, the passport, the sources, checks
    ("test_probe_DM_16_status_on_a_fresh_box_is_green", "a"),
    ("test_probe_DM_16_box_files_are_private_on_the_runner", "a"),
    ("test_tier3_install_sh_shows_its_own_lines_alone", "a"),
    ("test_tier3_install_sh_refused_shows_why_the_tail_and_the_log", "a"),
    # a measure before the host's probes: docker-ce and provision_host (DM-190)
    ("test_tier3_provision_host_on_a_host_with_docker_ce", "a"),
    ("test_probe_DM_12_host_steps_on_a_clean_runner", "a"),
    ("test_probe_DM_12_planted_dpkg_lock_waits_then_passes", "a"),
    ("test_probe_DM_12_planted_dpkg_lock_over_timeout_is_red_without_checkmark", "a"),
    ("test_probe_DM_132_swap_on_the_box_and_memory_refused", "a"),  # DM-132
    ("test_tier3_box_decrypts_its_passport_from_the_ops_repository", "a"),
    ("test_tier3_passport_not_for_this_box_is_red_with_its_key", "a"),
    ("test_probe_DM_10_blank_is_fetched_by_ref_over_ssh", "a"),
    ("test_tier3_ssh_github_on_443_serves_the_pinned_keys", "a"),  # DM-188
    ("test_tier3_check_of_the_blank_and_of_a_planted_copy", "a"),
    # test.services against the compose of its stack (DM-209)
    ("test_tier3_check_refuses_a_test_service_its_compose_has_not", "a"),
    ("test_tier3_compose_takes_a_single_quoted_value_as_it_is", "a"),
    ("test_tier3_certbot_tag_has_the_pinned_digest", "a"),
    ("test_tier3_the_panel_s_host_through_the_machine_s_proxy", "a"),  # DM-146
    # the proxy refuses a name off its list before any lookup of it (DM-188)
    ("test_probe_DM_188_an_unlisted_name_is_never_resolved_by_the_proxy", "a"),
    # the last of a: SIGKILL with a process left holding the lock (DM-24);
    # it leaves the box half installed
    ("test_probe_DM_24_sigkill_leaves_the_lock_to_the_grandchild", "a"),
    # b -- the whole install and tests on the box it leaves: the proxy of DM-64,
    # reinstall, and last a budget of the build cache the box is over (FIX DM-126)
    ("test_tier3_the_whole_install_of_the_blank", "b"),
    ("test_tier3_the_new_health_of_the_blank_and_its_service", "b"),
    ("test_probe_DM_64_product_reaches_only_its_egress_hosts", "b"),
    ("test_tier3_reinstall_keeps_the_persistent_volume", "b"),
    ("test_tier3_gc_trims_the_build_cache_to_the_budget", "b"),
    # c, and every group after d -- an install of their own each, by a fixture
    # (NEEDS_BOX). c: languages, a stop for migrate and what stands on the head it
    # leaves the database at -- a dump, its restore half-way, a reset -- then the
    # box registers in a Panel on the loopback, its agent, the Panel away and back
    # (DM-139, DM-141)
    ("test_tier3_two_instances_with_their_own_languages", "c"),
    ("test_tier3_services_stopped_for_migrate_come_back", "c"),
    ("test_tier3_a_dump_of_the_blank_restores_what_was_in_it", "c"),
    ("test_tier3_a_restore_that_fails_half_way_leaves_the_database_as_it_was", "c"),
    ("test_tier3_a_reset_of_the_blank_makes_its_database_new", "c"),
    # restore into a new database and the swap; reset by the code's head (DM-186)
    ("test_probe_DM_186_S9_an_older_dump_restores_the_database_it_was", "c"),
    ("test_probe_DM_186_B12_a_reset_is_green_ahead_of_and_behind_the_code", "c"),
    ("test_probe_DM_139_register_on_the_runner", "c"),
    ("test_probe_DM_141_agent_on_the_runner", "c"),
    ("test_probe_DM_141_no_verdict_lost_on_the_runner", "c"),
    # d -- a clean box: a first install red at the product's tests and its
    # destroy (DM-126), the blank with its service (DM-59), every journal of the
    # group (DM-137), and last the apt timers on (DM-105)
    ("test_tier3_red_tests_stop_before_any_migrate", "d"),
    ("test_tier3_destroy_after_an_interrupted_install", "d"),
    ("test_probe_DM_59_product_gets_the_seams_of_its_service_after_health", "d"),
    ("test_tier3_every_journal_has_its_seq_and_its_end", "d"),
    ("test_tier3_doctor_is_empty_with_the_apt_timers_on", "d"),
    # e -- the build mode of packages without its longest test (m); last a stream
    # through a path of a route (DM-147)
    (
        "test_tier3_optional_build_slot_without_a_package_serves_the_repository_s_front",
        "e",
    ),
    ("test_tier3_a_skin_built_into_a_frontend_built_from_the_root", "e"),
    ("test_probe_DM_147_sse_arrives_in_parts_through_the_path", "e"),
    # f -- options, a point; last the state of the box with its lock held (DM-136)
    ("test_tier3_an_option_off_is_the_literal_and_on_the_value", "f"),
    ("test_tier3_only_the_declared_consumer_reaches_a_point", "f"),
    ("test_tier3_state_of_the_box_with_its_lock_held", "f"),
    # g -- runtime packages, the project's verbs, logs and a session; last a
    # command plan that prints no secret of the box (DM-183)
    ("test_probe_DM_58_skin_version_switch_needs_no_rebuild", "g"),
    ("test_tier3_a_project_verb_runs_in_its_service", "g"),
    ("test_tier3_logs_restart_stop_start_and_a_read_only_session", "g"),
    ("test_tier3_a_command_plan_prints_no_secret_of_the_box", "g"),
    # h -- seeds, a verb on a job and a seam, gc of dangling images (DM-207), a
    # privileged service behind a profile (DM-182), then destroy and destroy --all
    ("test_tier3_seed_resets_run_the_products_commands", "h"),  # DM-133
    ("test_tier3_a_verb_on_a_job_of_another_entry_and_a_seam_from_asked", "h"),
    ("test_tier3_gc_removes_a_dangling_image_and_measures_the_cache_in_bytes", "h"),
    ("test_tier3_a_privileged_service_behind_a_profile_never_comes_up", "h"),
    ("test_tier3_destroy_takes_the_blank_off_the_box", "h"),
    ("test_tier3_destroy_all_wipes_the_persistent_volume", "h"),
    # i -- alembic, a point of the product, then what nginx serves (DM-185)
    ("test_tier3_alembic_runs_with_the_apps_environment", "i"),  # DM-124
    ("test_tier3_a_service_takes_a_point_of_the_product", "i"),  # DM-23
    ("test_probe_DM_185_served_is_the_file_after_renew", "i"),
    ("test_probe_DM_185_served_is_the_file_after_provided_changes", "i"),
    ("test_probe_DM_185_a_bad_provided_pair_leaves_the_working_one", "i"),
    ("test_probe_DM_185_renew_leaves_a_ca_certificate", "i"),
    # j -- a secret file, the data of a service, an entry named frontend, and
    # after it -- no deploy follows that entry -- first contact (DM-143)
    ("test_tier3_a_secret_file_in_the_live_container", "j"),  # DM-145
    ("test_tier3_every_listed_service_reads_the_data", "j"),  # DM-100
    ("test_tier3_an_entry_named_frontend_is_the_product_s_own", "j"),  # DM-102
    ("test_probe_DM_143_no_token_installs_the_machine_and_says_why", "j"),
    ("test_probe_DM_143_one_command_installs_registers_and_runs_the_agent", "j"),
    ("test_probe_DM_143_the_agent_service_survives_a_restart", "j"),
    ("test_probe_DM_143_a_used_token_is_refused", "j"),
    # k -- a job on every deploy: the longest test of tier 3, alone (DM-208)
    ("test_tier3_a_job_runs_before_its_dependent_on_every_deploy", "k"),
    # l -- both slots from one package, then the types (DM-63), the second longest
    ("test_tier3_both_slots_from_one_brand_package_by_subpath", "l"),
    ("test_tier3_types_are_made_by_the_products_commands", "l"),  # DM-63
    # m -- the build mode of the blank (DM-61), the third longest, alone
    ("test_tier3_build_mode_of_the_blank", "m"),
    # n -- a service of the edition, then a failed job on the repeat (DM-126)
    ("test_tier3_a_service_of_the_edition_goes_up_before_the_product", "n"),
    ("test_tier3_a_failed_job_runs_on_the_repeat", "n"),  # DM-126
    # the last of n: the agent's checks with their planted defects, the Panel
    # away in the middle of a run (DM-144)
    ("test_probe_DM_144_a_planted_defect_reddens_the_agent_s_checks", "n"),
    ("test_probe_DM_144_the_panel_away_in_the_middle_of_a_run", "n"),
    # o -- derive with no network, then a command of the Panel's queue and a busy
    # box that names it (DM-138)
    ("test_tier3_product_derive_reaches_nothing", "o"),
    ("test_tier3_a_command_runs_and_a_busy_box_names_it", "o"),
    # the machine updates itself from the Panel (DM-163): a release made in the
    # run, the agent a service -- a group of its own
    ("test_probe_DM_163_self_update_from_the_panel", "p"),
)

NEEDS_BOX = frozenset({"c", "e", "f", "g", "h", "i", "j", "k", "l", "m", "n", "o", "p"})
"""Groups whose tests need the blank installed by a fixture first."""

FIRST: tuple[str, ...] = (
    "test_tier3_the_whole_install_of_the_blank",
    "test_tier3_red_tests_stop_before_any_migrate",
)
"""The tests that are the first of their group: each installs on a clean box,
and its group has no install of a fixture."""

LAST: tuple[str, ...] = (
    # it leaves the box half installed
    "test_probe_DM_24_sigkill_leaves_the_lock_to_the_grandchild",
    "test_tier3_gc_trims_the_build_cache_to_the_budget",
    "test_probe_DM_141_no_verdict_lost_on_the_runner",
    # apt may hold dpkg after it
    "test_tier3_doctor_is_empty_with_the_apt_timers_on",
    "test_probe_DM_147_sse_arrives_in_parts_through_the_path",
    "test_tier3_state_of_the_box_with_its_lock_held",
    "test_tier3_a_command_plan_prints_no_secret_of_the_box",
    "test_tier3_destroy_all_wipes_the_persistent_volume",
    "test_probe_DM_185_renew_leaves_a_ca_certificate",
    # it leaves the machine installed anew
    "test_probe_DM_143_a_used_token_is_refused",
)
"""The tests that are the last of their group: no test of the group runs on
the box they leave."""

CHAINS: tuple[tuple[str, ...], ...] = (
    ("test_tier3_the_whole_install_of_the_blank",
     "test_tier3_the_new_health_of_the_blank_and_its_service"),
    # the cache's budget runs on the box reinstall left
    ("test_tier3_reinstall_keeps_the_persistent_volume",
     "test_tier3_gc_trims_the_build_cache_to_the_budget"),
    # the stop for migrate takes the database to a head the blank at its pin
    # does not know: nothing deploys that pin after it; the restore half-way
    # stands on the dump; the agent on the registration, part B on part A
    ("test_tier3_services_stopped_for_migrate_come_back",
     "test_tier3_a_dump_of_the_blank_restores_what_was_in_it",
     "test_tier3_a_restore_that_fails_half_way_leaves_the_database_as_it_was",
     "test_tier3_a_reset_of_the_blank_makes_its_database_new",
     # DM-186: the restore into a new database, the reset by the code's head
     "test_probe_DM_186_S9_an_older_dump_restores_the_database_it_was",
     "test_probe_DM_186_B12_a_reset_is_green_ahead_of_and_behind_the_code",
     "test_probe_DM_139_register_on_the_runner",
     "test_probe_DM_141_agent_on_the_runner",
     "test_probe_DM_141_no_verdict_lost_on_the_runner"),
    # each on the box the one before it left
    ("test_tier3_red_tests_stop_before_any_migrate",
     "test_tier3_destroy_after_an_interrupted_install",
     "test_probe_DM_59_product_gets_the_seams_of_its_service_after_health",
     "test_tier3_every_journal_has_its_seq_and_its_end",
     "test_tier3_doctor_is_empty_with_the_apt_timers_on"),
    # after the verb on a job no passport is deployed over its lock
    ("test_tier3_a_verb_on_a_job_of_another_entry_and_a_seam_from_asked",
     "test_tier3_gc_removes_a_dangling_image_and_measures_the_cache_in_bytes",
     "test_tier3_a_privileged_service_behind_a_profile_never_comes_up",
     "test_tier3_destroy_takes_the_blank_off_the_box",
     "test_tier3_destroy_all_wipes_the_persistent_volume"),
    # each after the one before: self-signed, provided, a bad pair, a CA's
    ("test_probe_DM_185_served_is_the_file_after_renew",
     "test_probe_DM_185_served_is_the_file_after_provided_changes",
     "test_probe_DM_185_a_bad_provided_pair_leaves_the_working_one",
     "test_probe_DM_185_renew_leaves_a_ca_certificate"),
    # the entry named frontend stays on the box: no deploy follows it
    ("test_tier3_an_entry_named_frontend_is_the_product_s_own",
     "test_probe_DM_143_no_token_installs_the_machine_and_says_why",
     "test_probe_DM_143_one_command_installs_registers_and_runs_the_agent",
     "test_probe_DM_143_the_agent_service_survives_a_restart",
     "test_probe_DM_143_a_used_token_is_refused"),
)  # fmt: skip
"""The tests that stand on each other (DM-208): the tests of a chain are in
one group and run there one after another, in the order written -- no other
test of the group between two of them."""


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
    import pytest

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


ALL = ("a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m", "n", "o", "p")
"""Every group: the jobs of a full run of tier 3."""

PLANNED = "${{ fromJSON(needs.plan.outputs.groups) }}"
"""``jobs.box.strategy.matrix.group`` of ``tier3.yml``: the groups ``plan``
gives (DM-125)."""


def matrix(workflow: Path = WORKFLOW) -> list[str]:
    """The groups the job ``box`` of ``tier3.yml`` can run: ``ALL``, when its
    matrix is the plan's; anything else in the workflow is no group at all."""
    import yaml

    document = yaml.safe_load(workflow.read_text(encoding="utf-8"))
    groups = document["jobs"]["box"]["strategy"]["matrix"]["group"]
    return list(ALL) if groups == PLANNED else []


NONE_PREFIXES = ("tests/", "contract/", "docs/")
"""Paths tier 3 does not run: tier 1, the contract's schemas (exports of the
models, checked by tier 1; the wheel holds the package alone), documents."""

NONE_FILES = frozenset({".github/workflows/ci.yml", ".github/workflows/release.yml"})


def groups_of_files(directory: Path = HERE) -> dict[str, set[str]]:
    """``tier3/test_*.py`` -> the groups of its tests (by ``GROUPS``)."""
    out: dict[str, set[str]] = {}
    for path in sorted(directory.glob("test_*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        names = [
            node.name
            for node in tree.body
            if isinstance(node, ast.FunctionDef) and node.name.startswith("test")
        ]
        rel = f"tier3/{path.name}"
        out[rel] = {group for test, group in GROUPS if test in names}
    return out


def affected(paths: Sequence[str] | None, files: Mapping[str, set[str]]) -> list[str]:
    """The groups a push runs for the files it changed (DM-125); ``None`` --
    the change is not known (a first push, a lost ``before``): every group. A
    file of tier 3 -- its groups; tier 1, documents, schemas -- none; anything
    else -- every group: an unknown path is never fewer checks."""
    if paths is None:
        return list(ALL)
    found: set[str] = set()
    for path in paths:
        if path.endswith(".md") or path.startswith(NONE_PREFIXES) or path in NONE_FILES:
            continue
        if path in files:
            found |= files[path] or set(ALL)
            continue
        found |= set(ALL)
    return [group for group in ALL if group in found]


def full_run(
    runs: Sequence[Mapping[str, object]],
    jobs: Mapping[int, Sequence[Mapping[str, object]]],
) -> tuple[bool, str]:
    """The gate of a release (DM-125): of the runs of tier 3 on the commit --
    by a push or by hand -- those that ran every group; the newest of them
    must have ended green. A run of some groups is never a release's; a red
    full run after a green one refuses, as the newest run did before."""

    def number(run: Mapping[str, object]) -> int:
        value = run.get("run_number")
        return value if isinstance(value, int) else -1

    def full(run: Mapping[str, object]) -> bool:
        run_id = run.get("id")
        names = {
            str(job.get("name"))
            for job in (jobs.get(run_id, ()) if isinstance(run_id, int) else ())
        }
        return all(f"box ({group})" in names for group in ALL)

    found = [
        run
        for run in runs
        if run.get("event") in ("push", "workflow_dispatch") and full(run)
    ]
    if not found:
        return False, "has no run of every group on this commit"
    last = max(found, key=number)
    state = (
        last.get("conclusion")
        if last.get("status") == "completed"
        else last.get("status")
    )
    if state != "success":
        return False, f"in full on this commit is {state}: {last.get('html_url')}"
    return True, f"in full on this commit is green: {last.get('html_url')}"


Stands = tuple[Sequence[str], Sequence[str], Sequence[Sequence[str]]]
"""``FIRST``, ``LAST`` and ``CHAINS``, as ``stands`` reads them."""


def stands(
    tests: Sequence[str],
    groups: Sequence[tuple[str, str]],
    tables: Stands,
) -> list[str]:
    """What breaks ``FIRST``, ``LAST`` and ``CHAINS`` of ``tables``. ``tests``
    -- every test in the order of the files, which is the order a group runs
    its own in. A test of a table that is in no group, or in two, is said by
    ``problems`` already and is passed over here."""
    first, last, chains = tables
    out: list[str] = []
    group = {name: g for name, g in groups}
    once = {name for name in tests if sum(1 for n, _ in groups if n == name) == 1}
    ran: dict[str, list[str]] = {}
    for name in tests:
        if name in once:
            ran.setdefault(group[name], []).append(name)
    for table, names in (("FIRST", first), ("LAST", last)):
        for name in dict.fromkeys(names):
            if list(names).count(name) > 1:
                out.append(f"{name}: twice in {table}")
            if name not in tests:
                out.append(f"{name}: in {table}, and no such test")
    for name in first:
        if name in once and ran[group[name]][0] != name:
            before = ran[group[name]][0]
            out.append(f"{name}: not the first of group {group[name]} -- {before} is")
    for name in last:
        if name in once and ran[group[name]][-1] != name:
            after = ran[group[name]][-1]
            out.append(f"{name}: not the last of group {group[name]} -- {after} is")
    for chain in chains:
        if len(chain) < 2:
            out.append(f"a chain of {len(chain)}: {', '.join(chain) or 'no test'}")
            continue
        missing = [name for name in chain if name not in tests]
        out += [f"{name}: in a chain, and no such test" for name in missing]
        if missing or any(name not in once for name in chain):
            continue
        home = group[chain[0]]
        apart = [name for name in chain if group[name] != home]
        if apart:
            out += [
                f"{name}: in group {group[name]}, its chain in group {home}"
                for name in apart
            ]
            continue
        mine = ran[home]
        for one, two in zip(chain, chain[1:], strict=False):
            gap = mine.index(two) - mine.index(one)
            if gap < 1:
                out.append(f"{two}: runs before {one} of its chain")
            elif gap > 1:
                between = mine[mine.index(one) + 1]
                out.append(f"{between}: between {one} and {two} of a chain")
    return out


def problems(
    tests: Sequence[str],
    groups: Sequence[tuple[str, str]],
    jobs: Sequence[str],
    tables: Stands | None = None,
) -> list[str]:
    """What breaks "each test in exactly one group, each group a job", and
    what breaks ``tables`` -- by default ``FIRST``, ``LAST`` and ``CHAINS``."""
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
    return out + stands(tests, groups, tables or (FIRST, LAST, CHAINS))


def check() -> int:
    tests, jobs = test_functions(), matrix()
    found = problems(tests, GROUPS, jobs)
    for line in found:
        print(line, file=sys.stderr)
    if not found:
        print(f"tier 3: {len(tests)} test functions, each in one of {len(jobs)} groups")
    return 1 if found else 0


Rows = list[tuple[str, str]]
Case = tuple[list[str], Rows, list[str]] | tuple[list[str], Rows, list[str], Stands]
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


PLANTED = "test_planted_by_the_selftest"


def _moved(g: Rows, name: str, to: str) -> Rows:
    return [(test, to if test == name else group) for test, group in g]


def _chain_apart(t: list[str], g: Rows, j: list[str]) -> Case:
    """The middle of a chain in another group: neither first nor last of any."""
    return t, _moved(g, CHAINS[2][2], "a"), j


def _chain_out_of_order(t: list[str], g: Rows, j: list[str]) -> Case:
    """Two tests of a chain change places in the files."""
    one, two = t.index(CHAINS[2][0]), t.index(CHAINS[2][1])
    swapped = list(t)
    swapped[one], swapped[two] = swapped[two], swapped[one]
    return swapped, g, j


def _test_inside_a_chain(t: list[str], g: Rows, j: list[str]) -> Case:
    """A new test of the group, in the files between two of its chain."""
    at = t.index(CHAINS[2][2])
    home = dict(g)[CHAINS[2][2]]
    return [*t[:at], PLANTED, *t[at:]], [*g, (PLANTED, home)], j


def _after_the_last(t: list[str], g: Rows, j: list[str]) -> Case:
    """A new test at the end of the files, in the group of ``LAST[0]``."""
    return [*t, PLANTED], [*g, (PLANTED, dict(g)[LAST[0]])], j


def _before_the_first(t: list[str], g: Rows, j: list[str]) -> Case:
    """A new test at the start of the files, in the group of ``FIRST[0]``."""
    return [PLANTED, *t], [*g, (PLANTED, dict(g)[FIRST[0]])], j


def _chain_of_one(t: list[str], g: Rows, j: list[str]) -> Case:
    return t, g, j, (FIRST, LAST, [*CHAINS, (t[0],)])


def _table_names_no_test(t: list[str], g: Rows, j: list[str]) -> Case:
    return t, g, j, (FIRST, [*LAST, "test_planted_renamed_away"], CHAINS)


DEFECTS: dict[str, Plant] = {
    "a test in no group": _no_group,
    "a test in two groups": _two_groups,
    "a row with no test": _row_without_test,
    "a group with no job": _group_without_job,
    "a job with no tests": _job_without_tests,
    "a chain in two groups": _chain_apart,
    "a chain out of its order": _chain_out_of_order,
    "a test between two of a chain": _test_inside_a_chain,
    "a test after the last of its group": _after_the_last,
    "a test before the first of its group": _before_the_first,
    "a chain of one test": _chain_of_one,
    "a table that names no test": _table_names_no_test,
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


def _affected(paths_file: str | None) -> int:
    """``plan`` of ``tier3.yml``: the groups as JSON on stdout, the reason of
    each on stderr (the run's log)."""
    files = groups_of_files()
    if paths_file is None:
        paths = None
        print("plan: the change is not known -- every group", file=sys.stderr)
    else:
        paths = [line for line in Path(paths_file).read_text().splitlines() if line]
        for path in paths:
            print(
                f"plan: {path} -> {affected([path], files) or 'none'}", file=sys.stderr
            )
    print(json.dumps(affected(paths, files)))
    return 0


def _full_run(runs_json: str, jobs_dir: str) -> int:
    """The gate of a release (``release.yml``)."""
    runs = json.loads(Path(runs_json).read_text())["workflow_runs"]
    jobs = {
        int(path.stem): json.loads(path.read_text())["jobs"]
        for path in Path(jobs_dir).glob("*.json")
    }
    green, said = full_run(runs, jobs)
    if not green:
        print(f"tier3.yml {said} -- run it in full (Run workflow): no release")
        return 1
    print(f"tier3.yml {said}")
    return 0


def main(argv: Sequence[str]) -> int:
    parser = argparse.ArgumentParser(prog="python tier3/groups.py")
    parser.add_argument("--selftest", action="store_true")
    parser.add_argument(
        "--affected", nargs="?", const="", default=None, metavar="PATHS"
    )
    parser.add_argument("--full-run", nargs=2, metavar=("RUNS_JSON", "JOBS_DIR"))
    args = parser.parse_args(argv)
    if args.full_run:
        return _full_run(*args.full_run)
    if args.affected is not None:
        return _affected(args.affected or None)
    return selftest() if args.selftest else check()


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
