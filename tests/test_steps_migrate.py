"""``migrate`` (DM-18): one alembic head, compared with the running app's
``/health.alembic_head``; the point of no return."""

from collections.abc import Iterator
from pathlib import Path

import pytest
from compose_support import (
    ENTRY,
    HEAD,
    LiveApp,
    alembic_call,
    compose,
    health,
    live,
    migrate_call,
    observe_calls,
    run,
)
from plan_support import Journal, ScriptedStep

from pridem.events import Code
from pridem.report.codes import ExitCode
from pridem.runner import FakeRunner
from pridem.steps.base import StepFailed
from pridem.steps.migrate import Migrate


@pytest.fixture
def app() -> Iterator[LiveApp]:
    yield from live()


def migrate(root: Path, port: int) -> Migrate:
    cs = compose(root, port)
    return Migrate(
        cs.stack, cs.entry, release=cs.release, ref=cs.ref, commit=cs.commit, root=root
    )


# --- probes ---------------------------------------------------------------------


def test_probe_DM_18_two_alembic_heads_red_before_up(tmp_path: Path) -> None:
    cs = compose(tmp_path)
    heads = alembic_call(cs, "heads", "0002a (head)", "0002b (head)", deps=False)
    later = ScriptedStep("up", 10, Journal())
    with FakeRunner(heads) as runner:  # no migrate, no current, no up
        outcome, _ = run([migrate(tmp_path, 8000), later], runner)
    assert outcome.steps[0].reason == Code(
        "migrate:alembic-heads",
        {"stack": ENTRY, "count": 2, "heads": ["0002a", "0002b"]},
    )
    assert [r.status for r in outcome.steps] == ["failed", "skipped"]
    assert not outcome.needs_restore  # never crossed


def test_probe_DM_18_migrate_is_point_of_no_return(
    tmp_path: Path, app: LiveApp
) -> None:
    cs = compose(tmp_path, app.port)
    assert Migrate.point_of_no_return is True
    first_install = [
        alembic_call(cs, "heads", f"{HEAD} (head)", deps=False),
        *observe_calls(cs, running=False),
        migrate_call(cs),
        alembic_call(cs, "current", f"{HEAD} (head)", deps=True),
    ]
    red_after = ScriptedStep("up", 10, Journal(), fact={})  # verify reads nothing
    with FakeRunner(*first_install) as runner:
        outcome, _ = run([migrate(tmp_path, app.port), red_after], runner)
    assert [r.status for r in outcome.steps] == ["ok", "failed"]
    assert outcome.steps[0].verify == {"alembic_head": HEAD}
    assert outcome.needs_restore  # after the point: nothing automatic
    # the pair: red before the point -- restore runs, no restore needed
    journal = Journal()
    early = ScriptedStep("build", 8, journal, check_raises=StepFailed("x"))
    back = ScriptedStep("bring_back", 1, journal)
    with FakeRunner() as runner:
        outcome, _ = run([early, migrate(tmp_path, app.port)], runner, restore=[back])
    assert not outcome.needs_restore
    assert any(entry.endswith("bring_back:verify") for entry in journal)


# --- the rest -------------------------------------------------------------------


def test_the_running_head_is_the_new_head_no_act(tmp_path: Path, app: LiveApp) -> None:
    """Gate fix 1: the same head as ``/health.alembic_head`` -- no ``act``, the
    point of no return is not crossed."""
    cs = compose(tmp_path, app.port)
    same = [
        alembic_call(cs, "heads", f"{HEAD} (head)", deps=False),
        *observe_calls(cs),
        alembic_call(cs, "current", f"{HEAD} (head)", deps=True),
    ]
    red_after = ScriptedStep("up", 10, Journal(), fact={})
    with FakeRunner(*same) as runner:  # no migrate in the script
        outcome, _ = run([migrate(tmp_path, app.port), red_after], runner)
    assert [r.status for r in outcome.steps] == ["ok", "failed"]
    assert not outcome.needs_restore
    # the pair: the running app is behind -- act, crossed
    app.health = health(alembic_head="0000")
    behind = [
        alembic_call(cs, "heads", f"{HEAD} (head)", deps=False),
        *observe_calls(cs),
        migrate_call(cs),
        alembic_call(cs, "current", f"{HEAD} (head)", deps=True),
    ]
    with FakeRunner(*behind) as runner:
        outcome, _ = run([migrate(tmp_path, app.port), red_after], runner)
    assert outcome.needs_restore


def test_no_head_is_no_migration(tmp_path: Path) -> None:
    cs = compose(tmp_path)
    with FakeRunner(alembic_call(cs, "heads", deps=False)) as runner:
        outcome, _ = run([migrate(tmp_path, 8000)], runner)
    assert outcome.code is ExitCode.OK
    assert outcome.steps[0].verify == {"alembic_heads": 0}


def test_database_not_at_head_after_migrate_is_red(
    tmp_path: Path, app: LiveApp
) -> None:
    cs = compose(tmp_path, app.port)
    script = [
        alembic_call(cs, "heads", f"{HEAD} (head)", deps=False),
        *observe_calls(cs, running=False),
        migrate_call(cs),
        alembic_call(cs, "current", "0000", deps=True),
    ]
    with FakeRunner(*script) as runner:
        outcome, _ = run([migrate(tmp_path, app.port)], runner)
    assert outcome.steps[0].reason == Code(
        "migrate:not-at-head", {"stack": ENTRY, "head": HEAD, "current": "0000"}
    )
