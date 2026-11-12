"""``migrate`` (DM-18): one alembic head, compared with the running app's
``/health.alembic_head``; the point of no return."""

from collections.abc import Iterator
from pathlib import Path

import pytest
from compose_support import (
    APP_IMAGE,
    ENTRY,
    HEAD,
    LiveApp,
    alembic_call,
    compose,
    heads_call,
    health,
    image_call,
    live,
    migrate_call,
    observe_calls,
    run,
    show_call,
    stdout,
)
from plan_support import Journal, ScriptedStep

from pridem.events import Code
from pridem.runner import FakeCall, FakeRunner
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
    heads = [
        image_call(cs, "app", APP_IMAGE),
        heads_call(cs, APP_IMAGE, "0002a (head)", "0002b (head)"),
    ]
    later = ScriptedStep("up", 13, Journal())
    with FakeRunner(*heads) as runner:  # no migrate, no current, no up
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
        image_call(cs, "app", APP_IMAGE),
        heads_call(cs, APP_IMAGE, f"{HEAD} (head)"),
        *observe_calls(cs, running=False),
        migrate_call(cs),
        alembic_call(cs, "current", f"{HEAD} (head)", deps=True),
    ]
    red_after = ScriptedStep("up", 13, Journal(), fact={})  # verify reads nothing
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
        image_call(cs, "app", APP_IMAGE),
        heads_call(cs, APP_IMAGE, f"{HEAD} (head)"),
        *observe_calls(cs),
        alembic_call(cs, "current", f"{HEAD} (head)", deps=True),
    ]
    red_after = ScriptedStep("up", 13, Journal(), fact={})
    with FakeRunner(*same) as runner:  # no migrate in the script
        outcome, _ = run([migrate(tmp_path, app.port), red_after], runner)
    assert [r.status for r in outcome.steps] == ["ok", "failed"]
    assert not outcome.needs_restore
    # the pair: the running app is behind -- act, crossed
    app.health = health(alembic_head="0000")
    behind = [
        image_call(cs, "app", APP_IMAGE),
        heads_call(cs, APP_IMAGE, f"{HEAD} (head)"),
        *observe_calls(cs),
        image_call(cs, "app", APP_IMAGE),
        show_call(cs, APP_IMAGE, "0000"),  # a head the code knows (DM-24)
        migrate_call(cs),
        alembic_call(cs, "current", f"{HEAD} (head)", deps=True),
    ]
    with FakeRunner(*behind) as runner:
        outcome, _ = run([migrate(tmp_path, app.port), red_after], runner)
    assert outcome.needs_restore


def test_a_database_ahead_of_the_code_is_red_before_act(
    tmp_path: Path, app: LiveApp
) -> None:
    """DM-24 (tier 3 of DM-86: ``upgrade head`` on a database at 0002 with code
    at 0001 failed past the point of no return): the running app says a head
    the image's ``alembic show`` does not know -- ``migrate:db-ahead`` before
    any ``act``, no restore needed. The pair: a head it knows acts (the test
    above)."""
    cs = compose(tmp_path, app.port)
    app.health = health(alembic_head="0002")
    ahead = [
        image_call(cs, "app", APP_IMAGE),
        heads_call(cs, APP_IMAGE, f"{HEAD} (head)"),
        *observe_calls(cs),
        image_call(cs, "app", APP_IMAGE),
        show_call(cs, APP_IMAGE, "0002", known=False),
    ]
    with FakeRunner(*ahead) as runner:  # no migrate in the script
        outcome, _ = run([migrate(tmp_path, app.port)], runner)
    [record] = outcome.steps
    assert record.reason == Code("migrate:db-ahead", {"entry": "blank", "head": "0002"})
    assert not outcome.needs_restore


def test_another_refusal_of_alembic_show_is_a_failed_command(
    tmp_path: Path, app: LiveApp
) -> None:
    """Exit 255 without alembic's line: a form the machine cannot read is a
    failed command before any ``act`` -- never a migration, never
    ``db-ahead``."""
    cs = compose(tmp_path, app.port)
    app.health = health(alembic_head="0002")
    show = show_call(cs, APP_IMAGE, "0002", known=False)
    other = FakeCall(show.argv, code=255, lines=stdout("FAILED: No config file"))
    script = [
        image_call(cs, "app", APP_IMAGE),
        heads_call(cs, APP_IMAGE, f"{HEAD} (head)"),
        *observe_calls(cs),
        image_call(cs, "app", APP_IMAGE),
        other,
    ]
    with FakeRunner(*script) as runner:
        outcome, _ = run([migrate(tmp_path, app.port)], runner)
    [record] = outcome.steps
    assert record.reason is not None
    assert record.reason.code == "command-failed"
    assert not outcome.needs_restore


def test_no_head_read_is_red_before_act(tmp_path: Path) -> None:
    """A stack that declares ``migrate`` has a head: none read is red in
    ``check`` -- never "no migration", never a skipped ``act``."""
    cs = compose(tmp_path)
    script = [
        image_call(cs, "app", APP_IMAGE),
        heads_call(cs, APP_IMAGE, "INFO  [x] y"),
    ]
    later = ScriptedStep("up", 13, Journal())
    with FakeRunner(*script) as runner:  # no migrate, no current
        outcome, _ = run([migrate(tmp_path, 8000), later], runner)
    assert outcome.steps[0].reason == Code(
        "migrate:no-heads", {"stack": ENTRY, "lines": 1}
    )
    assert [r.status for r in outcome.steps] == ["failed", "skipped"]
    assert not outcome.needs_restore
    # the pair: one head read from the same image -- the check goes on
    with FakeRunner(
        image_call(cs, "app", APP_IMAGE),
        heads_call(cs, APP_IMAGE, f"{HEAD} (head)"),
        *observe_calls(cs, running=False),
        migrate_call(cs),
        alembic_call(cs, "current", f"{HEAD} (head)", deps=True),
    ) as runner:
        outcome, _ = run([migrate(tmp_path, 8000)], runner)
    assert outcome.steps[0].verify == {"alembic_head": HEAD}


def test_heads_without_the_built_image_is_red(tmp_path: Path) -> None:
    cs = compose(tmp_path)
    with FakeRunner(image_call(cs, "app")) as runner:
        outcome, _ = run([migrate(tmp_path, 8000)], runner)
    assert outcome.steps[0].reason == Code(
        "migrate:no-image", {"service": "app", "commit": cs.commit}
    )


def test_database_not_at_head_after_migrate_is_red(
    tmp_path: Path, app: LiveApp
) -> None:
    cs = compose(tmp_path, app.port)
    script = [
        image_call(cs, "app", APP_IMAGE),
        heads_call(cs, APP_IMAGE, f"{HEAD} (head)"),
        *observe_calls(cs, running=False),
        migrate_call(cs),
        alembic_call(cs, "current", "0000", deps=True),
    ]
    with FakeRunner(*script) as runner:
        outcome, _ = run([migrate(tmp_path, app.port)], runner)
    assert outcome.steps[0].reason == Code(
        "migrate:not-at-head", {"stack": ENTRY, "head": HEAD, "current": "0000"}
    )
