"""``gc`` and the build cache (FIX of DM-126, owner's decision of 22.11).

The budget of the passport is of the cache no image holds -- ``Reclaimable``
of docker's ``Build Cache`` line, not ``Size``, which counts the layers the
images hold as well. A prune with a limit stops early, so it is repeated while
the cache is over the budget and the last call made it smaller. Measured on
docker 29.1.3 with buildx 0.30.1; the box of velo-dev was red by a cache whose
``Size`` was over the budget and whose own records were not: the prune rightly
removed nothing, and ``verify`` read ``Size`` back.
"""

from pathlib import Path

import pytest
from env_support import context
from test_steps_gc import (
    DF,
    GIB,
    IMAGES,
    GitReal,
    df,
    fact,
    image,
    kept_world,
    listed,
    out,
    prune_argv,
    run_gc,
)

from pridem.events import Code
from pridem.report.codes import ExitCode
from pridem.runner import FakeCall
from pridem.steps.gc import UnreadableOutput, gc_steps, reclaimable_size

BUDGET = 3 * GIB
"""``builder_cache_budget: 3G`` of the tests' passport."""


def _quiet() -> list[FakeCall]:
    """``check`` finds no container and no image of the machine's."""
    return [*listed([], kind="container"), *listed([], kind="image")]


def test_a_cache_the_images_hold_is_not_over_the_budget(tmp_path: Path) -> None:
    """The box of velo-dev: 5GB of cache by ``Size``, 1GB of it no image's --
    under the budget. Nothing to prune: no command (the strict script has
    none), a green step, the fact holds both numbers. The pair: the same
    ``Size`` with 5GB of its own is pruned."""
    world, _, _ = kept_world(tmp_path)
    shared = df(cache=(9, "5GB"), own="1GB")
    with GitReal(shared, *_quiet(), shared) as runner:
        outcome, _ = run_gc(world, runner)
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
    with world.box.lock("doctor"), GitReal(shared, *_quiet()) as runner:
        assert step.check(context(runner)).needed is False
    # the pair: its own records are over the budget -- pruned, down to it
    world, _, _ = kept_world(tmp_path / "pair")
    left = df(cache=(3, "2GB"), own="2GB")
    with GitReal(
        df(cache=(9, "5GB"), own="5GB"),
        *_quiet(),
        FakeCall(prune_argv(BUDGET)),
        left,
        left,
    ) as runner:
        outcome, _ = run_gc(world, runner)
    assert outcome.code is ExitCode.OK, outcome.steps


def test_the_prune_is_repeated_down_to_the_budget(tmp_path: Path) -> None:
    """One prune with a limit stops early (measured): the cache of its own is
    5GB, then 4GB -- smaller and still over -- then 2GB. Two prunes, a read
    of the cache after each, and a green step."""
    world, _, _ = kept_world(tmp_path)
    done = df(cache=(3, "2.5GB"), own="2GB")
    with GitReal(
        df(cache=(9, "6GB"), own="5GB"),
        *_quiet(),
        FakeCall(prune_argv(BUDGET)),
        df(cache=(7, "5GB"), own="4GB"),
        FakeCall(prune_argv(BUDGET)),
        done,
        done,
    ) as runner:
        outcome, _ = run_gc(world, runner)
    assert outcome.code is ExitCode.OK, outcome.steps
    assert outcome.incomplete == ()


def test_a_call_that_took_shared_records_alone_is_followed_by_another(
    tmp_path: Path,
) -> None:
    """Measured: a call may remove records the images share and none of the
    cache's own -- ``Size`` is smaller, the cache no image holds is the same.
    That is not the end: the next call goes on, and takes it to the budget."""
    world, _, _ = kept_world(tmp_path)
    done = df(cache=(2, "3.5GB"), own="2GB")
    with GitReal(
        df(cache=(9, "6GB"), own="4GB"),
        *_quiet(),
        FakeCall(prune_argv(BUDGET)),
        df(cache=(6, "5GB"), own="4GB"),  # 1GB of shared records went
        FakeCall(prune_argv(BUDGET)),
        done,
        done,
    ) as runner:
        outcome, _ = run_gc(world, runner)
    assert outcome.code is ExitCode.OK, outcome.steps


@pytest.mark.parametrize(
    "then",
    [
        pytest.param((9, "6GB", "6GB"), id="grew"),
        pytest.param((12, "5GB", "5GB"), id="more-records-same-size"),
        pytest.param((8, "5GB", "5GB"), id="fewer-records-same-size"),
    ],
)
def test_a_cache_that_did_not_shrink_ends_the_calls(
    tmp_path: Path, then: tuple[int, str, str]
) -> None:
    """The calls are as many as the cache can shrink: a cache whose ``Size``
    after a prune is not smaller -- it grew, or only its count of records
    changed -- gets no second prune (the strict script has one), whatever
    changed in its line. Its own records are no fewer than before the first
    prune: ``not-removed``."""
    world, _, _ = kept_world(tmp_path)
    count, size, own = then
    with GitReal(
        df(cache=(9, "5GB"), own="5GB"),
        *_quiet(),
        FakeCall(prune_argv(BUDGET)),
        df(cache=(count, size), own=own),
        df(cache=(count, size), own=own),
    ) as runner:
        outcome, _ = run_gc(world, runner)
    assert outcome.steps[0].reason == Code(
        "gc:not-removed", {"objects": ["build-cache"]}
    )


def test_the_layers_of_an_image_that_went_are_measured_before_the_prune(
    tmp_path: Path,
) -> None:
    """``check`` finds 1GB of the cache's own under 5GB of ``Size`` -- nothing
    to prune -- and an image to remove. With the image gone its layers are the
    cache's alone: measured again, 4GB, over the budget -- pruned in this
    run, not reported as ``over-budget`` by a ``gc`` that never tried. The
    pair -- a ``Size`` under the budget needs no second measure, whatever
    went -- is every test of ``test_steps_gc.py`` that removes an image."""
    world, _, _ = kept_world(tmp_path)
    old = image(3, world.commits[0])
    done = df(cache=(4, "3GB"), own="2GB")
    with GitReal(
        df(cache=(9, "5GB"), own="1GB"),
        *listed([], kind="container"),
        *listed([old], kind="image"),
        FakeCall(("docker", "image", "rm", str(old["Id"]))),
        df(cache=(9, "5GB"), own="4GB"),  # the image's layers, the cache's now
        FakeCall(prune_argv(BUDGET)),
        done,
        done,
        FakeCall(IMAGES),
    ) as runner:
        outcome, _ = run_gc(world, runner)
    assert outcome.code is ExitCode.OK, outcome.steps
    assert outcome.incomplete == ()


def test_over_budget_names_the_cache_no_image_holds(tmp_path: Path) -> None:
    """After every call the cache of its own is still over: ``over-budget``
    with that number -- 3.5GB -- not the 6GB of ``Size``."""
    world, _, _ = kept_world(tmp_path)
    stuck = df(cache=(7, "6GB"), own="3.5GB")
    with GitReal(
        df(cache=(9, "7GB"), own="4GB"),
        *_quiet(),
        FakeCall(prune_argv(BUDGET)),
        stuck,
        FakeCall(prune_argv(BUDGET)),
        stuck,
        stuck,
    ) as runner:
        outcome, _ = run_gc(world, runner)
    assert outcome.code is ExitCode.INCOMPLETE
    [entry] = outcome.incomplete
    assert entry.reason.code == "gc:over-budget"
    assert entry.reason.params["builder_cache_bytes"] == 3_500_000_000
    assert entry.reason.params["over"] == ["build-cache"]


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


def test_a_cache_line_without_reclaimable_is_not_started(tmp_path: Path) -> None:
    """Twin SHORTAGE: the line of the build cache with no ``Reclaimable`` --
    the machine cannot tell what the budget is of, and removes nothing."""
    world, _, _ = kept_world(tmp_path)
    line = '{"Type": "Build Cache", "TotalCount": "3", "Size": "1GB"}'
    with GitReal(FakeCall(DF, lines=out(line))) as runner:
        outcome, _ = run_gc(world, runner)
    assert outcome.code is ExitCode.INCOMPLETE
    [entry] = outcome.incomplete
    assert entry.reason == Code(
        "gc:not-started", {"cause": "unreadable", "command": "UnreadableOutput"}
    )
