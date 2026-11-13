"""``rollback`` (TZ 10.6, 19; DM-24): on test the stand moves only by its
branch; on prod the previous release, unless migrations ran between them.

The previous release is the one ``gc`` keeps (``steps/history.py``): the
newest green verdict whose ``finalize`` put another release in ``current``.
The verb's plan is the deploy plan of that release with ``rollback_check``
before any act; here the plan is the real ``deploy_plan``'s ``Wanted`` and
``restore_on`` with the real ``rollback_check`` as its only stack -- the rest
of the ladder is ``deploy <ref>``, tested where it lives (``finalize`` puts
``current``, ``.env`` and the override in place). Commands are literal: the
image's heads and what ``observe`` runs, from ``compose_support``.
"""

import io
from collections.abc import Callable, Iterator
from pathlib import Path

import pytest
from compose_support import (
    APP_IMAGE,
    HEAD,
    LiveApp,
    compose,
    heads_call,
    health,
    image_call,
    live,
    observe_calls,
)
from history_support import (
    NEW,
    OLD,
    STACK,
    deploy_verdict,
    history,
    release_box,
    released,
    run_of,
    sha,
)
from passport_support import passport_example, section, write_passport
from plan_support import plan

from pridem.cli import run
from pridem.events import Code, Secrets, StepRecord
from pridem.plan import Deferred, StackSteps
from pridem.report.schema import Verdict
from pridem.runner import FakeCall, FakeRunner
from pridem.state import Box
from pridem.steps.history import previous_releases
from pridem.steps.migrate import Migrate
from pridem.steps.passport import Fetched
from pridem.steps.stand import RollbackCheck
from pridem.verbs import deploy as deploy_verbs
from pridem.verbs.plans import Source, Wanted, deploy_plan
from pridem.verbs.run import Planned, Session


@pytest.fixture
def app() -> Iterator[LiveApp]:
    yield from live()


def _cli(
    fs_root: Path, file: Path, runner: FakeRunner
) -> tuple[int, str, str, list[Verdict]]:
    out, err = io.StringIO(), io.StringIO()
    box = Box(fs_root / "opt" / "pridem")
    before = set(box.history_ids())
    with runner:
        code = run(
            ["rollback", "--passport", str(file)],
            root=box.root,
            out=out,
            err=err,
            runner=runner,
            fs_root=fs_root,
        )
    added = [box.read_verdict(r) for r in box.history_ids() if r not in before]
    return code, out.getvalue(), err.getvalue(), added


Captured = dict[str, Wanted]


def _plan_of(
    fs_root: Path, port: int, captured: Captured
) -> Callable[[Session, Path, Wanted, object], Planned]:
    """The real ``deploy_plan``'s ``Wanted`` and ``restore_on``; its stack --
    the real ``rollback_check`` of the blank's entry on a live app."""

    def make(session: Session, root: Path, wanted: Wanted, preread: object) -> Planned:
        captured["wanted"] = wanted
        real = deploy_plan(session, root, wanted, None)
        cs = compose(fs_root, port)
        migrate = Migrate(
            cs.stack,
            cs.entry,
            release=cs.release,
            ref=cs.ref,
            commit=cs.commit,
            root=fs_root,
        )
        check = RollbackCheck([migrate], NEW)
        return Planned(
            [StackSteps("rollback", [check], root=True)],
            restore_on=real.restore_on,
        )

    return make


def _measured(fs_root: Path, port: int) -> list[FakeCall]:
    cs = compose(fs_root, port)
    return [
        image_call(cs, "app", APP_IMAGE),
        heads_call(cs, APP_IMAGE, f"{HEAD} (head)"),
        *observe_calls(cs),
    ]


# --- probes ---------------------------------------------------------------------


def test_probe_DM_24_test_rollback_never_moves_current_past_branch(
    tmp_path: Path,
) -> None:
    """On test ``rollback`` is a refusal that says how to roll back by the
    branch -- the red commit to revert and the branch -- with no journal, no
    verdict and ``current`` where it was. The pair: on prod with a previous
    release the verb runs a plan of that release."""
    red = sha("b")
    file = release_box(
        tmp_path,
        "test",
        sha("1"),
        released(1, sha("1")),
        deploy_verdict(2, head=red),
    )
    link = tmp_path / "opt" / STACK / "current"
    code, out, err, added = _cli(tmp_path, file, FakeRunner())
    assert code == 1 and out == ""
    assert f"git revert {red} on main" in err, err
    assert added == []
    assert list((tmp_path / "opt" / "pridem" / "journal").iterdir()) == []
    assert link.resolve() == tmp_path / "opt" / STACK / "releases" / sha("1")


def test_probe_DM_24_prod_rollback_to_previous_release_without_migrations(
    tmp_path: Path, app: LiveApp, monkeypatch: pytest.MonkeyPatch
) -> None:
    """On prod at ``NEW`` with ``OLD`` before it: the plan goes to ``OLD`` as
    a roll-back; the same head live and in ``OLD``'s image -- green, its fact
    names the passport's ref, and the console says the next update brings it
    back."""
    file = release_box(tmp_path, "prod", NEW, released(1, OLD), released(2, NEW))
    captured: Captured = {}
    monkeypatch.setattr(
        deploy_verbs, "deploy_plan", _plan_of(tmp_path, app.port, captured)
    )
    runner = FakeRunner(*_measured(tmp_path, app.port))
    code, out, err, [verdict] = _cli(tmp_path, file, runner)
    wanted = captured["wanted"]
    assert (wanted.mode, wanted.ref, wanted.rollback) == ("deploy", OLD, True)
    assert code == 0, err
    assert (verdict.verb, verdict.result) == ("rollback", "green")
    [step] = verdict.steps
    assert step.verify == {"heads": {"blank": HEAD}, "passport_ref": NEW}
    assert f"the passport still names {NEW}" in out


def test_probe_DM_24_prod_rollback_with_migrations_refuses_needs_restore(
    tmp_path: Path, app: LiveApp, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The database is at another head than ``OLD``'s image: red before any
    act -- the strict runner holds no command of an act -- and the verdict says
    a restore is needed."""
    file = release_box(tmp_path, "prod", NEW, released(1, OLD), released(2, NEW))
    app.health = health(alembic_head="0002")
    captured: Captured = {}
    monkeypatch.setattr(
        deploy_verbs, "deploy_plan", _plan_of(tmp_path, app.port, captured)
    )
    runner = FakeRunner(*_measured(tmp_path, app.port))
    code, out, _, [verdict] = _cli(tmp_path, file, runner)
    assert code == 1
    [step] = verdict.steps
    assert step.reason is not None
    assert step.reason.code == "rollback_check:migrated"
    assert step.reason.model_dump()["entries"] == ["blank"]
    assert [(i.what, i.code) for i in verdict.report.incomplete] == [
        ("restore", "needed")
    ]
    assert "the passport still names" not in out


# --- the rest -------------------------------------------------------------------


def test_no_previous_release_is_a_refusal(tmp_path: Path) -> None:
    file = release_box(tmp_path, "prod", NEW, released(1, NEW))
    code, _, err, added = _cli(tmp_path, file, FakeRunner())
    assert code == 1 and added == []
    assert f"no previous green release of {STACK}" in err


def test_no_current_release_is_a_refusal(tmp_path: Path) -> None:
    file = release_box(tmp_path, "prod", NEW, released(1, OLD), released(2, NEW))
    (tmp_path / "opt" / STACK / "current").unlink()
    code, _, err, added = _cli(tmp_path, file, FakeRunner())
    assert code == 1 and added == []
    assert f"{STACK} has no current release" in err


def test_a_second_rollback_goes_back_again(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``NEW``, rolled back to ``OLD``: the previous is ``NEW`` again -- the
    roll-back is \"the previous release\", and ``gc`` keeps exactly it."""
    rolled = deploy_verdict(
        3, verb="rollback", result="green", head=sha("3"), release=OLD
    )
    file = release_box(
        tmp_path, "prod", OLD, released(1, OLD), released(2, NEW), rolled
    )
    captured: Captured = {}

    def make(session: Session, root: Path, wanted: Wanted, preread: object) -> Planned:
        captured["wanted"] = wanted  # the target is all this test reads
        check = RollbackCheck([], NEW)
        return Planned([StackSteps("rollback", [check], root=True)])

    monkeypatch.setattr(deploy_verbs, "deploy_plan", make)
    _cli(tmp_path, file, FakeRunner())
    assert captured["wanted"].ref == NEW


def test_a_head_the_app_does_not_say_is_refused(tmp_path: Path) -> None:
    cs = compose(tmp_path)
    migrate = Migrate(
        cs.stack,
        cs.entry,
        release=cs.release,
        ref=cs.ref,
        commit=cs.commit,
        root=tmp_path,
    )
    calls = [
        image_call(cs, "app", APP_IMAGE),
        heads_call(cs, APP_IMAGE, f"{HEAD} (head)"),
        *observe_calls(cs, running=False),
    ]
    with FakeRunner(*calls) as runner:
        record = _check(RollbackCheck([migrate], NEW), runner)
    assert record == Code("rollback_check:head-unread", {"entry": "blank"})


def test_an_image_the_box_lost_is_refused(tmp_path: Path) -> None:
    cs = compose(tmp_path)
    migrate = Migrate(
        cs.stack,
        cs.entry,
        release=cs.release,
        ref=cs.ref,
        commit=cs.commit,
        root=tmp_path,
    )
    with FakeRunner(image_call(cs, "app")) as runner:
        record = _check(RollbackCheck([migrate], NEW), runner)
    assert record is not None and record.code == "rollback_check:no-image"


def test_no_entry_that_migrates_is_green_with_the_ref(tmp_path: Path) -> None:
    with FakeRunner() as runner:
        built = _plan([StackSteps("rollback", [RollbackCheck([], NEW)], root=True)])
        outcome = built(runner)
    [record] = outcome
    assert record.verify == {"heads": {}, "passport_ref": NEW}


@pytest.mark.parametrize("rollback", [True, False])
def test_the_plan_of_a_rollback(tmp_path: Path, rollback: bool) -> None:
    """``rollback_check`` stands after the dependencies and before the services
    -- before any stack acts -- and leaves a restore after ``migrated``; a
    deploy has neither."""
    data = passport_example()
    section(data, "server")["role"] = "prod"
    section(data, "product")["ref"] = NEW
    file = write_passport(tmp_path, data)
    box = Box(tmp_path / "opt" / "pridem")
    wanted = Wanted(mode="deploy", source=Source(file=file), ref=OLD, rollback=rollback)
    session = Session(box, "2026-11-11T10:00:00Z-a3f9", Fetched(), _no_secrets())
    planned = deploy_plan(session, tmp_path, wanted, None)
    names = [stack.name for stack in planned.stacks]
    if rollback:
        at = names.index("rollback")
        assert names[at - 1 : at + 2] == ["dependencies", "rollback", "services"]
        assert isinstance(planned.stacks[at], Deferred)
        assert planned.restore_on == frozenset({"rollback_check:migrated"})
    else:
        assert "rollback" not in names
        assert planned.restore_on == frozenset()


# --- helpers --------------------------------------------------------------------


def _no_secrets() -> Secrets:
    return Secrets(())


def _plan(stacks: list[StackSteps]) -> Callable[[FakeRunner], tuple[StepRecord, ...]]:
    def go(runner: FakeRunner) -> tuple[StepRecord, ...]:
        built, _ = plan(stacks, runner=runner)
        return built.run().steps

    return go


def _check(step: RollbackCheck, runner: FakeRunner) -> Code | None:
    [record] = _plan([StackSteps("rollback", [step], root=True)])(runner)
    return record.reason


def test_an_incomplete_deploy_that_went_live_is_the_previous_release(
    tmp_path: Path,
) -> None:
    """R2-B16 (DM-92): since DM-63 ``incomplete`` is a frequent end of a deploy
    -- the release it put in ``current`` is live, and it is the previous one
    for ``rollback`` and ``gc`` alike (one function). The pair: an incomplete
    run whose ``finalize`` never ran is no release."""
    mid = "v1.5.0"
    unswitched = deploy_verdict(4, result="incomplete", head=sha("4"), release="v1.9.0")
    unswitched = unswitched.model_copy(
        update={"steps": [s for s in unswitched.steps if s.name != "finalize"]}
    )
    box = history(
        tmp_path,
        released(1, OLD),
        deploy_verdict(2, result="incomplete", head=sha("2"), release=mid),
        deploy_verdict(3, result="incomplete", head=sha("3"), release=NEW),
        unswitched,
    )
    found = previous_releases(box, {STACK: NEW})
    assert found.previous == {STACK: mid}
    assert [v.run_id for v in found.current_verdicts] == [run_of(3)]
