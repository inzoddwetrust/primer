"""A red stand blocks the stand (TZ 9.3; DM-24): ``stand`` after ``fetch_root``.

The block is read from ``history/`` (``steps/history.py``): the newest verdict
of a deploy that names the commit it fetched decides; red blocks by that
commit. ``stand`` refuses a commit of another task -- the task is the set of the
commit's ``Task`` git trailers -- by a red verdict of its own, which never
decides the block. Commands are literal (``par0`` 14.2): ``git log`` of the
trailers, in the bare repository of the root stack.
"""

from pathlib import Path

import pytest
from history_support import (
    ADDRESS,
    STACK,
    deploy_verbs_box,
    deploy_verdict,
    history,
    log_call,
    sha,
)
from plan_support import plan

from pridem.events import Code, StepRecord
from pridem.plan import Deferred, StackSteps
from pridem.runner import FakeCall, FakeRunner
from pridem.state import Box
from pridem.steps.sources import FetchRoot, Resolved, Target
from pridem.steps.stand import Stand

RED = sha("b")
"""The red commit of task DM-1."""
NEW = sha("c")
"""The commit the deploy goes to."""


def _stand(fs_root: Path, box: Box, commit: str = NEW) -> Stand:
    fetch = FetchRoot(
        Resolved(), fs_root, stack=STACK, address=ADDRESS, ref="main", tag=False
    )
    fetch.target = Target("main", False, commit)
    return Stand(fetch, box, fs_root)


def _record(fs_root: Path, box: Box, *calls: FakeCall) -> StepRecord:
    with FakeRunner(*calls) as runner:
        stack = StackSteps("sources", [_stand(fs_root, box)], root=True)
        built, _ = plan([stack], runner=runner)
        outcome = built.run()
    [record] = outcome.steps
    return record


def _box(tmp: Path, *verdicts: object) -> Box:
    return history(tmp / "opt" / "pridem", *verdicts)  # type: ignore[arg-type]


# --- probes ---------------------------------------------------------------------


def test_probe_DM_24_foreign_task_deploy_refused_on_red_stand(tmp_path: Path) -> None:
    """Red by DM-1 at ``RED``: a commit of DM-2 is refused by the code of
    ``stand`` with the blocking task and commit, before anything acts."""
    box = _box(
        tmp_path,
        deploy_verdict(1, result="green", head=sha("a")),
        deploy_verdict(2, head=RED),
    )
    record = _record(
        tmp_path,
        box,
        log_call(tmp_path, RED, "DM-1"),
        log_call(tmp_path, NEW, "DM-2"),
    )
    assert record.status == "failed"
    assert record.reason == Code("stand:blocked", {"task": "DM-1", "sha": RED})


def test_probe_DM_24_same_task_deploy_allowed_on_red_stand(tmp_path: Path) -> None:
    """The pair: a commit of DM-1 goes on the stand red by DM-1, and the fact
    says what blocked it."""
    box = _box(tmp_path, deploy_verdict(2, head=RED))
    record = _record(
        tmp_path,
        box,
        log_call(tmp_path, RED, "DM-1"),
        log_call(tmp_path, NEW, "DM-1"),
    )
    assert record.status == "ok"
    assert record.verify == {"blocked": True, "sha": RED, "task": "DM-1"}


def test_probe_DM_24_green_deploy_unblocks(tmp_path: Path) -> None:
    """Red, then green: the stand is free -- no task is even read. Before the
    green the same commit is refused."""
    red = deploy_verdict(2, head=RED)
    blocked = _record(
        tmp_path,
        _box(tmp_path, red),
        log_call(tmp_path, RED, "DM-1"),
        log_call(tmp_path, NEW, "DM-2"),
    )
    assert blocked.status == "failed"
    box = _box(tmp_path, deploy_verdict(3, result="green", head=sha("d")))
    free = _record(tmp_path, box)  # no git at all
    assert (free.status, free.verify) == ("ok", {"blocked": False})


def test_probe_DM_24_block_is_read_from_history_not_state(tmp_path: Path) -> None:
    """``state.json`` gone, then damaged (quarantined under the lock): the
    block is the same, read from ``history/``."""
    box = _box(tmp_path, deploy_verdict(2, head=RED))
    calls = (log_call(tmp_path, RED, "DM-1"), log_call(tmp_path, NEW, "DM-2"))
    state = box.root / "state.json"
    assert not state.exists()
    gone = _record(tmp_path, box, *calls)
    state.write_text("{not json", encoding="utf-8")
    with box.lock("quarantine"):
        assert box.read_state() is None and box.state_quarantined
    quarantined = _record(tmp_path, box, *calls)
    expected = Code("stand:blocked", {"task": "DM-1", "sha": RED})
    assert gone.reason == quarantined.reason == expected


# --- the rest -------------------------------------------------------------------


def test_a_refusal_never_decides_the_block(tmp_path: Path) -> None:
    """Red by DM-1, then a deploy of DM-2 refused by ``stand``: the stand is
    still red by DM-1 -- DM-1 goes on, DM-3 is refused naming DM-1."""
    refusal = Code("stand:blocked", {"task": "DM-1", "sha": RED}).as_json()
    box = _box(
        tmp_path,
        deploy_verdict(2, head=RED),
        deploy_verdict(3, head=sha("e"), refused=dict(refusal)),
    )
    same = _record(
        tmp_path, box, log_call(tmp_path, RED, "DM-1"), log_call(tmp_path, NEW, "DM-1")
    )
    assert same.status == "ok"
    other = _record(
        tmp_path, box, log_call(tmp_path, RED, "DM-1"), log_call(tmp_path, NEW, "DM-3")
    )
    assert other.reason == Code("stand:blocked", {"task": "DM-1", "sha": RED})


def test_a_red_without_a_trailer_takes_a_commit_without_one(tmp_path: Path) -> None:
    """The empty set is a task: a revert without a trailer goes on; a commit
    with one is refused, untasked."""
    box = _box(tmp_path, deploy_verdict(2, head=RED))
    bare = _record(tmp_path, box, log_call(tmp_path, RED), log_call(tmp_path, NEW))
    assert (bare.status, bare.verify) == ("ok", {"blocked": True, "sha": RED})
    tasked = _record(
        tmp_path, box, log_call(tmp_path, RED), log_call(tmp_path, NEW, "DM-2")
    )
    assert tasked.reason == Code("stand:blocked-untasked", {"sha": RED})


def test_a_task_of_two_trailers_is_both(tmp_path: Path) -> None:
    """Two ``Task`` trailers: the same pair goes on, one of them is another task."""
    box = _box(tmp_path, deploy_verdict(2, head=RED))
    pair = _record(
        tmp_path,
        box,
        log_call(tmp_path, RED, "DM-1", "DM-2"),
        log_call(tmp_path, NEW, "DM-2", "DM-1"),
    )
    assert pair.status == "ok"
    one = _record(
        tmp_path,
        box,
        log_call(tmp_path, RED, "DM-1", "DM-2"),
        log_call(tmp_path, NEW, "DM-1"),
    )
    assert one.reason == Code("stand:blocked", {"task": "DM-1,DM-2", "sha": RED})


def test_a_blocking_commit_the_repository_lost_is_unknown(tmp_path: Path) -> None:
    box = _box(tmp_path, deploy_verdict(2, head=RED))
    record = _record(tmp_path, box, log_call(tmp_path, RED, code=128))
    assert record.reason == Code("stand:blocked-unknown", {"sha": RED})


def test_a_run_without_a_fetched_commit_is_passed_over(tmp_path: Path) -> None:
    """Red by ``RED``, then a red with no ``fetch_root`` (a ref the remote has
    not): still blocked by ``RED``. A red ``recover`` wrote after ``fetch_root``
    blocks by its own commit."""
    box = _box(
        tmp_path,
        deploy_verdict(2, head=RED),
        deploy_verdict(3, head=None),
    )
    record = _record(
        tmp_path, box, log_call(tmp_path, RED, "DM-1"), log_call(tmp_path, NEW, "DM-2")
    )
    assert record.reason == Code("stand:blocked", {"task": "DM-1", "sha": RED})
    box = _box(tmp_path, deploy_verdict(4, verb="update", head=sha("f")))
    later = _record(
        tmp_path,
        box,
        log_call(tmp_path, sha("f"), "DM-5"),
        log_call(tmp_path, NEW, "DM-2"),
    )
    assert later.reason == Code("stand:blocked", {"task": "DM-5", "sha": sha("f")})


def test_an_incomplete_deploy_is_no_block(tmp_path: Path) -> None:
    """Code 2 (a certificate deferred): the stand is not red."""
    box = _box(
        tmp_path,
        deploy_verdict(2, head=RED),
        deploy_verdict(3, result="incomplete", head=sha("d")),
    )
    assert _record(tmp_path, box).verify == {"blocked": False}


@pytest.mark.parametrize("verb", ["install", "reinstall", "update"])
def test_every_deploy_verb_decides(tmp_path: Path, verb: str) -> None:
    """``install`` and ``reinstall`` clear the block by their green and set it
    by their red, as ``update`` does; ``doctor`` and others decide nothing."""
    box = _box(
        tmp_path,
        deploy_verdict(2, head=RED),
        deploy_verdict(3, verb=verb, result="green", head=sha("d")),
    )
    assert _record(tmp_path, box).verify == {"blocked": False}
    box = _box(tmp_path, deploy_verdict(4, verb=verb, head=sha("e")))
    red = _record(
        tmp_path, box, log_call(tmp_path, sha("e"), "DM-7"), log_call(tmp_path, NEW)
    )
    assert red.reason == Code("stand:blocked", {"task": "DM-7", "sha": sha("e")})


def test_another_verb_decides_nothing(tmp_path: Path) -> None:
    box = _box(
        tmp_path,
        deploy_verdict(2, head=RED),
        deploy_verdict(3, verb="rollback", result="green", head=sha("d")),
    )
    record = _record(
        tmp_path, box, log_call(tmp_path, RED, "DM-1"), log_call(tmp_path, NEW, "DM-2")
    )
    assert record.status == "failed"


def test_a_damaged_verdict_is_passed_over(tmp_path: Path) -> None:
    box = _box(tmp_path, deploy_verdict(2, head=RED))
    (box.history / "2026-11-11T11:00:00Z-a3f9.json").write_text("{", encoding="utf-8")
    record = _record(
        tmp_path, box, log_call(tmp_path, RED, "DM-1"), log_call(tmp_path, NEW, "DM-2")
    )
    assert record.reason == Code("stand:blocked", {"task": "DM-1", "sha": RED})


@pytest.mark.parametrize(
    ("verb", "role", "guarded"),
    [
        ("update", "test", True),
        ("deploy", "test", True),
        ("update", "prod", False),
        ("deploy", "prod", False),
        ("install", "test", False),
        ("reinstall", "test", False),
        ("doctor", "test", False),
    ],
)
def test_stand_is_in_update_and_deploy_on_test(
    tmp_path: Path, verb: str, role: str, guarded: bool
) -> None:
    """``stand`` stands right after ``fetch_root`` in the plan of ``update``
    and ``deploy`` on a test box, and nowhere else."""
    sources = deploy_verbs_box(tmp_path, verb, role)
    assert isinstance(sources, Deferred)
    built = sources.build()
    assert built is not None
    [stack] = built
    ladder = sorted(stack.steps, key=lambda step: step.order)  # as the plan runs
    names = [step.name for step in ladder]
    expected = ["deploy_key", "fetch_root", *(["stand"] if guarded else [])]
    assert names[: len(expected) + 1] == [*expected, "fetch_packages"]
    assert ("stand" in names) is guarded
