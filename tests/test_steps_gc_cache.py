"""``gc`` and the build cache (FIX of DM-126, owner's decision of 22.11).

The budget of the passport is of the cache no image holds -- the records
neither in use nor shared -- not of the whole cache, which counts the layers
the images hold as well. A prune with a limit stops early, so it is repeated
while the cache is over the budget and the last call made it smaller.
Measured on docker 29.1.3 with buildx 0.30.1; the box of velo-dev was red by a
cache whose whole size was over the budget and whose own records were not:
the prune rightly removed nothing, and ``verify`` read the whole size back.

Changed by DM-207 (REVIEW-0006 B18; the gate of 26.11): the cache is read in
bytes from the Engine API, not from the rounded line of ``docker system df``
-- every scenario here gives its measurements to ``run_gc`` (``cache=``, a
strict script) where it had lines of ``df``; what each test holds is as it
was.
"""

from pathlib import Path

import pytest
from engine_support import GB, cache, engine_says
from env_support import context
from test_steps_gc import (
    GIB,
    IMAGES,
    GitReal,
    df,
    fact,
    image,
    kept_world,
    listed,
    prune_argv,
    run_gc,
)

from pridem.events import Code
from pridem.report.codes import ExitCode
from pridem.runner import FakeCall
from pridem.steps import engine
from pridem.steps.gc import UnreadableOutput, gc_steps, reclaimable_size

BUDGET = 3 * GIB
"""``builder_cache_budget: 3G`` of the tests' passport."""


def _quiet() -> list[FakeCall]:
    """``check`` finds no container and no image, dangling or the machine's."""
    return [*listed([], kind="container"), *listed([], kind="image")]


def test_a_cache_the_images_hold_is_not_over_the_budget(tmp_path: Path) -> None:
    """The box of velo-dev: 5GB of cache as a whole, 1GB of it no image's --
    under the budget. Nothing to prune: no command (the strict script has
    none), a green step, the fact holds both numbers. The pair: the same
    whole with 5GB of its own is pruned."""
    world, _, _ = kept_world(tmp_path)
    shared = cache(5 * GB, 1 * GB, count=9)
    with GitReal(df(), *_quiet(), df()) as runner:
        outcome, _ = run_gc(world, runner, cache=[shared, shared])
    assert outcome.code is ExitCode.OK, outcome.steps
    after = fact(outcome)["after"]
    assert isinstance(after, dict)
    assert after["build_cache"] == {
        "count": 9,
        "bytes": 5_000_000_000,
        "reclaimable": 1_000_000_000,
    }
    # check alone, as doctor runs it: nothing gc would do
    [step] = gc_steps(world.root, box=world.box, run_id="r2", fetched=world.fetched)
    with (
        engine_says(shared),
        world.box.lock("doctor"),
        GitReal(df(), *_quiet()) as runner,
    ):
        assert step.check(context(runner)).needed is False
    # the pair: its own records are over the budget -- pruned, down to it
    world, _, _ = kept_world(tmp_path / "pair")
    left = cache(2 * GB, count=3)
    with GitReal(df(), *_quiet(), FakeCall(prune_argv(BUDGET)), df()) as runner:
        outcome, _ = run_gc(world, runner, cache=[cache(5 * GB, count=9), left, left])
    assert outcome.code is ExitCode.OK, outcome.steps


def test_the_prune_is_repeated_down_to_the_budget(tmp_path: Path) -> None:
    """One prune with a limit stops early (measured): the cache of its own is
    5GB, then 4GB -- smaller and still over -- then 2GB. Two prunes, a read
    of the cache after each, and a green step."""
    world, _, _ = kept_world(tmp_path)
    done = cache(2_500_000_000, 2 * GB, count=3)
    with GitReal(
        df(),
        *_quiet(),
        FakeCall(prune_argv(BUDGET)),
        FakeCall(prune_argv(BUDGET)),
        df(),
    ) as runner:
        outcome, _ = run_gc(
            world,
            runner,
            cache=[
                cache(6 * GB, 5 * GB, count=9),
                cache(5 * GB, 4 * GB, count=7),
                done,
                done,
            ],
        )
    assert outcome.code is ExitCode.OK, outcome.steps
    assert outcome.incomplete == ()


def test_a_call_that_took_shared_records_alone_is_followed_by_another(
    tmp_path: Path,
) -> None:
    """Measured: a call may remove records the images share and none of the
    cache's own -- the whole is smaller, the cache no image holds is the
    same. That is not the end: the next call goes on, and takes it to the
    budget."""
    world, _, _ = kept_world(tmp_path)
    done = cache(3_500_000_000, 2 * GB, count=2)
    with GitReal(
        df(),
        *_quiet(),
        FakeCall(prune_argv(BUDGET)),
        FakeCall(prune_argv(BUDGET)),
        df(),
    ) as runner:
        outcome, _ = run_gc(
            world,
            runner,
            cache=[
                cache(6 * GB, 4 * GB, count=9),
                cache(5 * GB, 4 * GB, count=6),  # 1GB of shared records went
                done,
                done,
            ],
        )
    assert outcome.code is ExitCode.OK, outcome.steps


@pytest.mark.parametrize(
    "then",
    [
        pytest.param((9, 6 * GB), id="grew"),
        pytest.param((12, 5 * GB), id="more-records-same-size"),
        pytest.param((8, 5 * GB), id="fewer-records-same-size"),
    ],
)
def test_a_cache_that_did_not_shrink_ends_the_calls(
    tmp_path: Path, then: tuple[int, int]
) -> None:
    """The calls are as many as the cache can shrink: a cache that after a
    prune is not smaller -- it grew, or only its count of records changed --
    gets no second prune (the strict script has one), whatever changed in
    it. Its own records are no fewer than before the first prune:
    ``not-removed``."""
    world, _, _ = kept_world(tmp_path)
    count, size = then
    after = cache(size, count=count)
    with GitReal(df(), *_quiet(), FakeCall(prune_argv(BUDGET)), df()) as runner:
        outcome, _ = run_gc(world, runner, cache=[cache(5 * GB, count=9), after, after])
    assert outcome.steps[0].reason == Code(
        "gc:not-removed", {"objects": ["build-cache"]}
    )


def test_the_layers_of_an_image_that_went_are_measured_before_the_prune(
    tmp_path: Path,
) -> None:
    """``check`` finds 1GB of the cache's own under 5GB as a whole -- nothing
    to prune -- and an image to remove. With the image gone its layers are the
    cache's alone: measured again, 4GB, over the budget -- pruned in this
    run, not reported as ``over-budget`` by a ``gc`` that never tried. The
    pair -- a whole under the budget needs no second measure, whatever
    went -- is every test of ``test_steps_gc.py`` that removes an image."""
    world, _, _ = kept_world(tmp_path)
    old = image(3, world.commits[0])
    done = cache(3 * GB, 2 * GB, count=4)
    with GitReal(
        df(),
        *listed([], kind="container"),
        *listed([old], kind="image"),
        FakeCall(("docker", "image", "rm", str(old["Id"]))),
        FakeCall(prune_argv(BUDGET)),
        df(),
        FakeCall(IMAGES),
    ) as runner:
        outcome, _ = run_gc(
            world,
            runner,
            cache=[
                cache(5 * GB, 1 * GB, count=9),
                cache(5 * GB, 4 * GB, count=9),  # the image's layers, the cache's now
                done,
                done,
            ],
        )
    assert outcome.code is ExitCode.OK, outcome.steps
    assert outcome.incomplete == ()


def test_over_budget_names_the_cache_no_image_holds(tmp_path: Path) -> None:
    """After every call the cache of its own is still over: ``over-budget``
    with that number -- 3.5GB -- not the 6GB of the whole."""
    world, _, _ = kept_world(tmp_path)
    stuck = cache(6 * GB, 3_500_000_000, count=7)
    with GitReal(
        df(),
        *_quiet(),
        FakeCall(prune_argv(BUDGET)),
        FakeCall(prune_argv(BUDGET)),
        df(),
    ) as runner:
        outcome, _ = run_gc(
            world,
            runner,
            cache=[cache(7 * GB, 4 * GB, count=9), stuck, stuck, stuck],
        )
    assert outcome.code is ExitCode.INCOMPLETE
    [entry] = outcome.incomplete
    assert entry.reason.code == "gc:over-budget"
    assert entry.reason.params["builder_cache_bytes"] == 3_500_000_000
    assert entry.reason.params["over"] == ["build-cache"]


def test_a_record_in_use_or_shared_is_not_the_cache_s_own(tmp_path: Path) -> None:
    """The budget is of the records neither in use nor shared -- each flag
    alone takes a record out of it. 9GB of cache: 4GB in use, 4GB shared,
    1GB neither -- under the budget of 3G, no prune (the strict script has
    none), and the fact says 1GB. The pair: the same 9GB with neither flag
    anywhere is pruned (``test_a_cache_the_images_hold...``, its pair)."""
    world, _, _ = kept_world(tmp_path)
    records = [
        engine.CacheRecord(4 * GB, in_use=True, shared=False),
        engine.CacheRecord(4 * GB, in_use=False, shared=True),
        engine.CacheRecord(1 * GB, in_use=False, shared=False),
    ]
    with GitReal(df(), *_quiet(), df()) as runner:
        outcome, _ = run_gc(world, runner, cache=[records, records])
    assert outcome.code is ExitCode.OK, outcome.steps
    after = fact(outcome)["after"]
    assert isinstance(after, dict)
    assert after["build_cache"] == {
        "count": 3,
        "bytes": 9_000_000_000,
        "reclaimable": 1_000_000_000,
    }
    assert fact(outcome)["prune_calls"] == 0


@pytest.mark.parametrize(
    ("text", "size"),
    [
        ("120.1MB", 120_100_000),
        ("20.01MB (7%)", 20_010_000),
        ("0B (0%)", 0),
        ("0B", 0),
        ("26B", 26),
    ],
)
def test_reclaimable_is_a_size_with_or_without_its_share(text: str, size: int) -> None:
    """Docker prints the share in brackets for some lines (measured: the
    images' has it, the build cache's does not): both are read."""
    assert reclaimable_size(text) == size


@pytest.mark.parametrize("text", ["None", "(7%)", "a lot", ""])
def test_a_reclaimable_docker_never_prints_is_an_error(text: str) -> None:
    with pytest.raises(UnreadableOutput):
        reclaimable_size(text)


@pytest.mark.parametrize(
    ("error", "kind"),
    [
        pytest.param(
            engine.EngineUnread("/system/df: no BuildCache"),
            "EngineUnread",
            id="answer-unread",
        ),
        pytest.param(
            FileNotFoundError(2, "No such file or directory"),
            "FileNotFoundError",
            id="daemon-unreachable",
        ),
    ],
)
def test_a_cache_the_engine_does_not_give_is_not_started(
    tmp_path: Path, error: Exception, kind: str
) -> None:
    """Twin SHORTAGE. Replaces ``test_a_cache_line_without_reclaimable_is_
    not_started`` (DM-207): the line of ``docker system df`` is not what the
    budget is read from any more, so a line without ``Reclaimable`` is no
    state of ``gc``. What it held is held by the source that is read: an
    answer of the Engine API the records cannot be read from, or a daemon
    nobody reaches -- the machine cannot tell what the budget is of, and
    removes nothing. The pair -- the same box with an answer -- is every
    test above."""
    world, previous, current = kept_world(tmp_path)
    with GitReal(df()) as runner:
        outcome, _ = run_gc(world, runner, cache=error)
    assert outcome.code is ExitCode.INCOMPLETE
    [entry] = outcome.incomplete
    assert entry.reason == Code(
        "gc:not-started", {"cause": "unreadable", "command": kind}
    )
    assert previous.is_dir() and current.is_dir()
