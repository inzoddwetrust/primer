"""DM-86, pass 2: ``db reset``, ``db migrate``, the seeds of ``install`` and
the verb ``seed``; the image a one-off container of a verb starts from."""

from collections.abc import Sequence
from datetime import UTC, datetime
from itertools import count
from pathlib import Path

import pytest
import yaml
from data_support import APP_IMAGE, SHA, STACK, blank_box
from plan_support import ListSink
from test_verbs_data import (
    _cli,
    _service,
    _verdict,
    compose,
    config_call,
    git_call,
    head_call,
    lines,
    running_call,
)

from pridem.events import Json, PlanOutcome
from pridem.plan import Plan, StackSteps
from pridem.report.codes import ExitCode
from pridem.runner import FakeCall, FakeRunner
from pridem.stacks.schema import PRIMER_YAML, Product
from pridem.steps.base import CheckResult, Role, Step, StepContext, Verified
from pridem.steps.compose import ComposeStack
from pridem.steps.data import DbMigrate, SeedRun, Seeds, StartRestored, StopForRestore
from pridem.steps.migrate import Migrate, StopForMigrate, Stopped
from pridem.steps.up import Up

IMAGE_LABEL = '{{index .Config.Labels "pridem.commit"}}'
OID, NEW_OID = "16384", "16999"


def image_calls(cs: ComposeStack, commit: str = SHA) -> list[FakeCall]:
    """The image ``compose run app`` starts -- the name the release's override
    gives it (DM-90; it was compose's own, ``<project>-app``) -- and the
    commit of the current release."""
    inspect = ("docker", "image", "inspect", "-f", IMAGE_LABEL, APP_IMAGE)
    return [FakeCall(inspect, lines=lines(commit)), git_call(cs)]


def psql_call(cs: ComposeStack, sql: str, *out: str) -> FakeCall:
    argv = cs.argv(
        "exec", "-T", "postgres", "psql", "-U", "blank", "-d", "postgres", "-tAc", sql
    )
    return FakeCall(tuple(argv), lines=lines(*out))


OID_SQL = "SELECT oid FROM pg_database WHERE datname = 'blank'"
MIGRATE = ("python", "-m", "alembic", "upgrade", "head")


def reset_calls(
    cs: ComposeStack, *, oid_after: str = NEW_OID, head_after: str = "0001"
) -> list[FakeCall]:
    """``db reset`` of the blank: its check (before anything is stopped), the
    stop of all but the database, the reset and its migration, the start."""
    check = [
        config_call(cs),
        *image_calls(cs),
        psql_call(cs, OID_SQL, OID),
        head_call(cs),
    ]
    calls = [
        *check,  # db_reset's check, run by stop_for_restore first
        config_call(cs),
        running_call(cs, "app", "c-app"),
        running_call(cs, "frontend", "c-front"),
        FakeCall(tuple(cs.argv("stop", "app", "frontend"))),
        running_call(cs, "app"),
        running_call(cs, "frontend"),
        *check,  # db_reset's own
        psql_call(cs, 'DROP DATABASE "blank" WITH (FORCE)'),
        psql_call(cs, 'CREATE DATABASE "blank" OWNER "blank"'),
        FakeCall(tuple(cs.argv("run", "--rm", "app", *MIGRATE))),
        psql_call(cs, OID_SQL, oid_after),
    ]
    if oid_after in (OID, ""):  # red on the OID: the head is not read
        return calls
    calls.append(head_call(cs, head_after))
    if head_after != "0001":
        return calls
    return [
        *calls,
        FakeCall(tuple(cs.argv("start", "app", "frontend"))),
        running_call(cs, "app", "c-app"),
        running_call(cs, "frontend", "c-front"),
    ]


RESET = ["db", "reset", STACK, "--confirm", "box-1"]


# --- db reset -----------------------------------------------------------------------


def test_db_reset_on_test_with_the_name_makes_the_database_new(tmp_path: Path) -> None:
    """The pair of the card: on ``test`` with ``--confirm <server.name>`` -- a
    new database (another OID), migrated to the release's head, the app back;
    on ``prod`` -- refused before the run (an empty script)."""
    blank_box(tmp_path, name="box-1")
    cs = compose(tmp_path)
    with FakeRunner(*reset_calls(cs)) as runner:
        code, out, err = _cli(tmp_path, RESET, runner)
    verdict = _verdict(out)
    assert code == 0, (err, verdict.steps)
    assert [s.name for s in verdict.steps] == [
        "stop_for_restore",
        "db_reset",
        "start_restored",
        "start_stopped",
    ]
    assert verdict.steps[1].verify == {
        "stack": STACK,
        "oid_before": OID,
        "oid_after": NEW_OID,
        "alembic_head": "0001",
    }
    prod = tmp_path / "prod"
    prod.mkdir()
    blank_box(prod, role="prod", name="box-1")
    with FakeRunner() as runner:
        code, out, err = _cli(prod, RESET, runner)
    assert (code, out) == (1, "") and "role test only" in err


@pytest.mark.parametrize(
    ("role", "confirm", "said"),
    [
        ("preview", ["--confirm", "box-1"], "role test only"),
        ("test", [], "--confirm box-1"),
        ("test", ["--confirm", "box-2"], "--confirm box-1"),
    ],
)
def test_db_reset_is_refused_before_the_run(
    tmp_path: Path, role: str, confirm: list[str], said: str
) -> None:
    blank_box(tmp_path, role=role, name="box-1")
    with FakeRunner() as runner:
        code, out, err = _cli(tmp_path, ["db", "reset", STACK, *confirm], runner)
    assert (code, out) == (1, "")
    assert said in err


def test_db_reset_of_an_entry_without_migrate_is_refused(tmp_path: Path) -> None:
    """A reset without ``migrate`` would leave a database with no schema --
    no "database as new"."""
    blank_box(tmp_path, name="box-1")
    _service(tmp_path, "comms", with_database=True)
    with FakeRunner() as runner:
        code, out, err = _cli(
            tmp_path, ["db", "reset", "comms", "--confirm", "box-1"], runner
        )
    assert (code, out) == (1, "") and "no migrate" in err


@pytest.mark.parametrize(
    ("oid_after", "head_after", "code"),
    [
        (OID, "0001", "db_reset:not-reset"),
        ("", "0001", "db_reset:not-reset"),  # no database at all after it
        (NEW_OID, "0002", "db_reset:head-mismatch"),
    ],
)
def test_a_reset_that_did_not_take_is_red_past_the_point(
    tmp_path: Path, oid_after: str, head_after: str, code: str
) -> None:
    """The same database after the reset, or another head -- red, restore
    needed, nothing started again (the KNOWN CEILING of ``StartStopped``)."""
    blank_box(tmp_path, name="box-1")
    calls = reset_calls(compose(tmp_path), oid_after=oid_after, head_after=head_after)
    with FakeRunner(*calls) as runner:
        exit_code, out, _ = _cli(tmp_path, RESET, runner)
    verdict = _verdict(out)
    assert exit_code == 1
    assert verdict.steps[1].reason is not None
    assert verdict.steps[1].reason.code == code
    assert [i.code for i in verdict.report.incomplete] == ["needed"]
    assert verdict.steps[3].verify == {"started": {}}


@pytest.mark.parametrize(
    ("image_commit", "release_commit"),
    [("1" * 40, SHA), (SHA, "2" * 40)],
    ids=["image-of-another-commit", "release-of-another-commit"],
)
def test_an_image_not_of_the_current_release_is_refused_before_anything_stops(
    tmp_path: Path, image_commit: str, release_commit: str
) -> None:
    """After a red deploy of a new commit, ``compose run`` would start the new
    build: red before ``stop_for_restore`` stops anything, the text naming the
    way out. Each side of the comparison has its case."""
    blank_box(tmp_path, name="box-1")
    cs = compose(tmp_path)
    inspect = ("docker", "image", "inspect", "-f", IMAGE_LABEL, APP_IMAGE)
    calls = [
        config_call(cs),
        FakeCall(inspect, lines=lines(image_commit)),
        git_call(cs, release_commit),
    ]
    with FakeRunner(*calls) as runner:
        exit_code, out, _ = _cli(tmp_path, RESET, runner)
    verdict = _verdict(out)
    assert exit_code == 1
    reason = verdict.steps[0].reason
    assert reason is not None
    assert reason.model_dump() == {
        "code": "stop_for_restore:image-not-current",
        "stack": STACK,
        "image_commit": image_commit,
        "release_commit": release_commit,
    }
    assert verdict.steps[3].verify == {"started": {}}
    from pridem.report.catalog import ENGLISH, with_steps

    text = with_steps(ENGLISH, [("db_reset", StopForRestore.codes)])
    assert "a green deploy first" in text["db_reset:image-not-current"]


# --- db migrate ---------------------------------------------------------------------


def migrate_check(cs: ComposeStack, current: str) -> list[FakeCall]:
    heads = cs.argv(
        "run", "--rm", "--no-deps", "app", "python", "-m", "alembic", "heads"
    )
    return [
        config_call(cs),
        *image_calls(cs),
        FakeCall(tuple(heads), lines=lines("0002 (head)")),
        head_call(cs, current),
    ]


def test_db_migrate_brings_the_database_to_the_head_of_its_code(tmp_path: Path) -> None:
    """After a restore of an older dump: ``current`` 0001, the code's head
    0002 -- ``migrate`` on the release's image, read back. The pair: at the
    head -- nothing to do, nothing migrated (no ``upgrade`` in the script)."""
    blank_box(tmp_path)
    cs = compose(tmp_path)
    calls = [
        *migrate_check(cs, "0001"),  # stop_for_migrate: empty list, no check
        FakeCall(tuple(cs.argv("run", "--rm", "app", *MIGRATE))),
        head_call(cs, "0002"),
    ]
    with FakeRunner(*calls) as runner:
        code, out, _ = _cli(tmp_path, ["db", "migrate", STACK], runner)
    verdict = _verdict(out)
    assert code == 0, verdict.steps
    names = [s.name for s in verdict.steps]
    assert names == [
        "stop_for_migrate",
        "db_migrate",
        "start_restored",
        "start_stopped",
    ]
    assert verdict.steps[1].verify == {"stack": STACK, "alembic_head": "0002"}
    same = [*migrate_check(cs, "0002"), head_call(cs, "0002")]
    with FakeRunner(*same) as runner:
        code, out, _ = _cli(tmp_path, ["db", "migrate", STACK], runner)
    assert code == 0, _verdict(out).steps


def test_db_migrate_with_two_heads_is_red_before_it_acts(tmp_path: Path) -> None:
    blank_box(tmp_path)
    cs = compose(tmp_path)
    heads = cs.argv(
        "run", "--rm", "--no-deps", "app", "python", "-m", "alembic", "heads"
    )
    calls = [
        config_call(cs),
        *image_calls(cs),
        FakeCall(tuple(heads), lines=lines("0002a (head)", "0002b (head)")),
    ]
    with FakeRunner(*calls) as runner:
        code, out, _ = _cli(tmp_path, ["db", "migrate", STACK], runner)
    reason = _verdict(out).steps[1].reason
    assert reason is not None and reason.code == "db_migrate:alembic-heads"


def test_the_ladders_of_the_verbs_go_in_order() -> None:
    """``start_restored`` after ``db_migrate`` (12) in ``db migrate``; the
    seeds of ``install`` after ``up``."""
    assert StopForMigrate.order < DbMigrate.order < 13
    assert StartRestored(compose_stub(), stopped_stub(), order=13).order == 13
    assert StopForRestore.order < 2 < StartRestored.order < SeedRun.order
    assert Up.order < Seeds.order and Migrate.order < Up.order


def compose_stub() -> ComposeStack:
    return ComposeStack(_product({}), STACK, Path("/r"), "main", SHA, Path("/"))


def stopped_stub() -> Stopped:
    return Stopped()


# --- seeds of install ---------------------------------------------------------------


def _product(seeds: dict[str, Json]) -> Product:
    raw: dict[str, Json] = {
        "schema": 1,
        "name": STACK,
        "kind": "product",
        "stacks": {
            STACK: {
                "compose": "docker-compose.yml",
                "app": {"service": "app", "port": 8000, "health": "/h", "ready": "/r"},
                "migrate": "python -m alembic upgrade head",
                "seeds": seeds,
            }
        },
        "env": {},
        "report": {"health": "/h", "ready": "/r", "logs": "json", "junit": True},
    }
    made = PRIMER_YAML.validate_python(raw)
    assert isinstance(made, Product)
    return made


SEEDS: dict[str, Json] = {
    "bootstrap": {"run": "python -m app.seed bootstrap", "when": "install"},
    "demo": {"run": "python -m app.seed demo", "when": "command"},
    "staff": {
        "run": "python -m app.seed staff",
        "when": "install",
        "roles": ["test", "preview"],
    },
}


def _plan(
    steps: Sequence[Step], runner: FakeRunner, mode: str, role: Role
) -> PlanOutcome:
    ticks = count()
    return Plan(
        [StackSteps(STACK, list(steps), root=True)],
        mode=mode,  # type: ignore[arg-type]
        role=role,
        runner=runner,
        sink=ListSink(),
        clock=lambda: float(next(ticks)),
        now=lambda: datetime(2026, 11, 11, tzinfo=UTC),
    ).run()


def _seed_call(cs: ComposeStack, name: str) -> FakeCall:
    return FakeCall(
        tuple(cs.argv("run", "--rm", "app", "python", "-m", "app.seed", name))
    )


def test_probe_DM_22_install_seeds_run_only_on_install(tmp_path: Path) -> None:
    """Contract 3 rule 17, by ``when`` and not by name: on ``install`` the
    profiles of ``when: install`` run in their order, ``when: command`` does
    not; on ``deploy`` -- no seed at all (the step is not in the plan). The
    pair of ``reinstall``: the same as ``install`` -- a new database."""
    cs = ComposeStack(
        _product(SEEDS), STACK, tmp_path, "main", SHA, tmp_path, staged=True
    )
    for mode in ("install", "reinstall"):
        calls = [_seed_call(cs, "bootstrap"), _seed_call(cs, "staff")]
        with FakeRunner(*calls) as runner:
            outcome = _plan([Seeds(cs)], runner, mode, "test")
        assert outcome.code is ExitCode.OK, outcome.steps
        assert outcome.steps[0].verify == {
            "stack": STACK,
            "ran": ["bootstrap", "staff"],
            "outside_role": [],
        }
    with FakeRunner() as runner:  # deploy: nothing runs
        outcome = _plan([Seeds(cs), _Marker()], runner, "deploy", "test")
    assert [s.name for s in outcome.steps] == ["marker"]


class _Marker(Step):
    """A step of ``deploy`` that shows the plan ran."""

    name = "marker"
    order = 99
    modes = frozenset({"deploy"})

    def check(self, ctx: StepContext) -> CheckResult:
        return CheckResult(False, None, {})

    def act(self, ctx: StepContext, check: CheckResult) -> None:
        raise AssertionError

    def verify(self, ctx: StepContext, check: CheckResult) -> Verified:
        return Verified({"marker": True})


def test_a_seed_outside_its_roles_is_not_run_on_install(tmp_path: Path) -> None:
    """``staff`` is for ``test`` and ``preview``: on ``prod`` it is not run
    (the script has no call for it) and the fact names it."""
    cs = ComposeStack(
        _product(SEEDS), STACK, tmp_path, "main", SHA, tmp_path, staged=True
    )
    with FakeRunner(_seed_call(cs, "bootstrap")) as runner:
        outcome = _plan([Seeds(cs)], runner, "install", "prod")
    assert outcome.steps[0].verify == {
        "stack": STACK,
        "ran": ["bootstrap"],
        "outside_role": ["staff"],
    }


def test_seeds_in_their_order_of_primer_yaml(tmp_path: Path) -> None:
    ordered: dict[str, Json] = {
        "zeta": {"run": "python -m app.seed zeta", "when": "install"},
        "alpha": {"run": "python -m app.seed alpha", "when": "install"},
    }
    cs = ComposeStack(
        _product(ordered), STACK, tmp_path, "main", SHA, tmp_path, staged=True
    )
    with FakeRunner(_seed_call(cs, "zeta"), _seed_call(cs, "alpha")) as runner:
        outcome = _plan([Seeds(cs)], runner, "install", "test")
    assert outcome.steps[0].verify == {
        "stack": STACK,
        "ran": ["zeta", "alpha"],
        "outside_role": [],
    }


# --- the verb seed ------------------------------------------------------------------


def _with_seeds(fs_root: Path, role: str, seeds: dict[str, Json]) -> ComposeStack:
    blank_box(fs_root, role=role, name="box-1")
    release = (fs_root / "opt" / STACK / "current").resolve()
    primer = yaml.safe_load((release / "primer.yaml").read_text())
    primer["stacks"][STACK]["seeds"] = seeds
    (release / "primer.yaml").write_text(yaml.safe_dump(primer, sort_keys=False))
    return compose(fs_root)


def _run_seed_calls(cs: ComposeStack, name: str) -> list[FakeCall]:
    return [config_call(cs), *image_calls(cs), _seed_call(cs, name)]


ROLED: dict[str, Json] = {
    "demo": {
        "run": "python -m app.seed demo",
        "when": "command",
        "roles": ["test", "preview"],
    },
    "bootstrap": {"run": "python -m app.seed bootstrap", "when": "install"},
}


def test_probe_DM_22_seed_outside_its_role_is_refused(tmp_path: Path) -> None:
    """The pair of the card: ``roles: [test, preview]`` on ``prod`` -- refused,
    nothing ran (an empty script); on ``test`` -- it runs."""
    _with_seeds(tmp_path, "prod", ROLED)
    with FakeRunner() as runner:
        code, out, err = _cli(tmp_path, ["seed", STACK, "--profile", "demo"], runner)
    assert (code, out) == (1, "") and "not for the role prod" in err
    other = tmp_path / "test"
    other.mkdir()
    cs = _with_seeds(other, "test", ROLED)
    with FakeRunner(*_run_seed_calls(cs, "demo")) as runner:
        code, out, _ = _cli(other, ["seed", STACK, "--profile", "demo"], runner)
    verdict = _verdict(out)
    assert code == 0 and verdict.steps[0].verify == {"stack": STACK, "profile": "demo"}


def test_probe_DM_22_seed_dry_run_writes_nothing(tmp_path: Path) -> None:
    """``--dry-run``: the command it would run in the fact, no command at all
    (an empty strict script), nothing new on the box but the verdict."""
    cs = _with_seeds(tmp_path, "test", ROLED)
    box_files = sorted(p for p in tmp_path.rglob("*") if "history" not in p.parts)
    with FakeRunner() as runner:
        code, out, _ = _cli(
            tmp_path, ["seed", STACK, "--profile", "demo", "--dry-run"], runner
        )
    verdict = _verdict(out)
    assert code == 0
    assert verdict.steps[0].verify == {
        "stack": STACK,
        "profile": "demo",
        "service": "app",
        "argv": list(cs.argv("run", "--rm", "app", "python", "-m", "app.seed", "demo")),
    }
    after = sorted(
        p
        for p in tmp_path.rglob("*")
        if "history" not in p.parts and "journal" not in p.parts
    )
    assert [p for p in after if p not in box_files and p.name != "state.json"] == []


@pytest.mark.parametrize(
    ("argv", "said"),
    [
        (["seed", STACK, "--profile", "bootstrap"], "install only"),
        (["seed", STACK, "--profile", "ghost"], "no profile ghost"),
        (
            ["seed", STACK, "--profile", "demo", "--dry-run", "--reset"],
            "resets nothing",
        ),
        (
            ["seed", STACK, "--profile", "demo", "--confirm", "box-1"],
            "goes with --reset",
        ),
        (["seed", STACK], "--profile"),
        (["seed", "--list", STACK], "nothing else"),
    ],
)
def test_the_verb_seed_refuses_before_the_run(
    tmp_path: Path, argv: list[str], said: str
) -> None:
    _with_seeds(tmp_path, "test", ROLED)
    with FakeRunner() as runner:
        code, out, err = _cli(tmp_path, argv, runner)
    assert (code, out) == (1, ""), err
    assert said in err


def test_seed_reset_resets_then_seeds_on_test_with_the_name(tmp_path: Path) -> None:
    """``--reset``: ``db reset`` of the entry, then the seed -- two forms in a
    row; on ``preview`` -- refused (``db reset`` is for ``test``)."""
    cs = _with_seeds(tmp_path, "test", ROLED)
    calls = [*reset_calls(cs), *_run_seed_calls(cs, "demo")]
    argv = ["seed", STACK, "--profile", "demo", "--reset", "--confirm", "box-1"]
    with FakeRunner(*calls) as runner:
        code, out, _ = _cli(tmp_path, argv, runner)
    verdict = _verdict(out)
    assert code == 0, verdict.steps
    assert [s.name for s in verdict.steps] == [
        "stop_for_restore",
        "db_reset",
        "start_restored",
        "seed",
        "start_stopped",
    ]
    other = tmp_path / "preview"
    other.mkdir()
    _with_seeds(other, "preview", ROLED)
    with FakeRunner() as runner:
        code, out, err = _cli(other, argv, runner)
    assert (code, out) == (1, "") and "role test only" in err


def test_seed_list_names_every_entry_s_profiles(tmp_path: Path) -> None:
    _with_seeds(tmp_path, "test", ROLED)
    _service(tmp_path, "comms", with_database=True)
    with FakeRunner() as runner:
        code, out, _ = _cli(tmp_path, ["seed", "--list"], runner)
    verdict = _verdict(out)
    assert code == 0
    assert verdict.steps[0].verify == {
        "entries": {
            "comms": [],
            STACK: [
                {"profile": "demo", "when": "command", "roles": ["test", "preview"]},
                {"profile": "bootstrap", "when": "install"},
            ],
        }
    }


def test_a_stop_step_has_the_codes_of_the_check_it_runs_first() -> None:
    """``stop_for_migrate`` and ``stop_for_restore`` run the check of the step
    they stop for and are red by its refusal: they carry its codes, or the
    verdict has no text for them (contract 2 rule 6). Found by pass 2:
    ``stop_for_migrate`` had none of ``migrate``'s."""
    from pridem.steps.data import DbReset, DbRestore

    assert set(Migrate.codes) <= set(StopForMigrate.codes)
    assert set(DbMigrate.codes) <= set(StopForMigrate.codes)
    for wiping in (DbRestore, DbReset):
        own = {"restore", "reset", "head-mismatch"}
        assert set(wiping.codes) - own <= set(StopForRestore.codes), wiping


def test_a_migration_that_leaves_the_database_behind_is_red(tmp_path: Path) -> None:
    """``migrate`` exits 0 and the database is still at 0001 --
    ``db_migrate:not-at-head``: the fact is read back, not taken from the
    code."""
    blank_box(tmp_path)
    cs = compose(tmp_path)
    calls = [
        *migrate_check(cs, "0001"),
        FakeCall(tuple(cs.argv("run", "--rm", "app", *MIGRATE))),
        head_call(cs, "0001"),
    ]
    with FakeRunner(*calls) as runner:
        code, out, _ = _cli(tmp_path, ["db", "migrate", STACK], runner)
    reason = _verdict(out).steps[1].reason
    assert code == 1 and reason is not None
    assert reason.code == "db_migrate:not-at-head"


def test_an_image_with_no_commit_label_is_refused(tmp_path: Path) -> None:
    """``<no value>`` from ``image inspect`` -- an image the machine did not
    build: ``image-unread``, nothing stopped."""
    blank_box(tmp_path, name="box-1")
    cs = compose(tmp_path)
    inspect = ("docker", "image", "inspect", "-f", IMAGE_LABEL, APP_IMAGE)
    calls = [config_call(cs), FakeCall(inspect, lines=lines("<no value>"))]
    with FakeRunner(*calls) as runner:
        code, out, _ = _cli(tmp_path, RESET, runner)
    reason = _verdict(out).steps[0].reason
    assert reason is not None
    assert reason.code == "stop_for_restore:image-unread"
