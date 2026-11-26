"""Probes of DM-207: ``gc`` removes dangling images and holds the build cache
to its budget in bytes (REVIEW-0006 B18).

git runs for real; docker follows a strict script, and so does the Engine
API: a command or a read of the cache ``gc`` must not make fails where it is
made, one it must make and does not fails at the end.
"""

from pathlib import Path

from engine_support import cache
from test_steps_gc import (
    GIB,
    IMAGES,
    GitReal,
    alive,
    container,
    df,
    fact,
    image,
    kept_world,
    listed,
    loose,
    prune_argv,
    run_gc,
    short,
)

from pridem.events import Code
from pridem.report.codes import ExitCode
from pridem.runner import FakeCall
from pridem.steps.gc import PRUNE_CALLS

BUDGET = 3 * GIB
"""``builder_cache_budget: 3G`` of the tests' passport: 3 221 225 472."""


def test_probe_DM_207_dangling_image_is_removed_and_needed_ones_stay(
    tmp_path: Path,
) -> None:
    """Three dangling images on a box with a current and a previous release:
    one no container holds, one a running container was made from, one a
    stopped one (``container ls --all`` lists both). The first goes, by its
    ID and without ``--force``; ``verify`` asks for it by that ID. Nothing
    else is named by an ``image rm``: not the two dangling images with a
    container, not the images of the current and the previous release with
    their names, not an image of somebody else -- with a name and no label
    it is in no list ``gc`` makes. The fact names what went and the free
    bytes of the disk before and after."""
    world, _, _ = kept_world(tmp_path)
    previous = image(1, world.commits[1], ["blank-app:111111111111"])
    current = image(2, world.commits[2], ["blank-app:222222222222"])
    gone, running, stopped = loose(5), loose(6), loose(7)
    containers = [
        container(1, str(current["Id"])),
        container(2, str(running["Id"])),
        container(3, str(stopped["Id"])),
    ]
    with GitReal(
        df(),
        *listed(containers, kind="container"),
        *listed([previous, current], kind="image", dangling=[gone, running, stopped]),
        FakeCall(("docker", "image", "rm", str(gone["Id"]))),
        df(),
        alive(gone, there=False),
    ) as runner:
        outcome, _ = run_gc(world, runner)
    assert outcome.code is ExitCode.OK, outcome.steps
    assert outcome.incomplete == ()
    # nothing but the one dangling image is removed, and it is not forced
    assert [a for a in runner.argvs if a[:3] == ("docker", "image", "rm")] == [
        ("docker", "image", "rm", str(gone["Id"]))
    ]
    # the pair: the needed ones were there and were read -- each list was
    # asked once in check, and the label's list is not asked again in verify
    assert runner.argvs.count(IMAGES) == 1
    found = fact(outcome)
    removed, kept = found["removed"], found["kept"]
    assert isinstance(removed, dict) and isinstance(kept, dict)
    assert removed["dangling"] == [short(5)]
    assert removed["images"] == [short(5)]
    assert kept["in_use"] == [short(2), short(6), short(7)]
    assert kept["commits"] == sorted(world.commits[1:3])
    for when in ("before", "after"):
        measured = found[when]
        assert isinstance(measured, dict)
        disk = measured["disk"]
        assert isinstance(disk, dict)
        free = disk["free_bytes"]
        assert isinstance(free, int) and not isinstance(free, bool) and free > 0


def test_probe_DM_207_cache_to_the_budget_by_exact_size_and_the_loop_ends(
    tmp_path: Path,
) -> None:
    """The budget is compared in bytes. One byte over it -- which docker's
    line prints as ``3.221GB``, under the budget -- is over: pruned; exactly
    the budget afterwards is not over: one call, a green step, the bytes in
    the fact. The pair: a cache of exactly the budget is not pruned at all.

    The loop ends. A cache that after a call is not one byte smaller gets no
    second call (``not-removed``: its own records are no fewer than before).
    A cache that every call makes one byte smaller -- progress docker's
    rounded line cannot show -- gets ``PRUNE_CALLS`` calls and not one more,
    then ``over-budget`` with its bytes."""
    over = cache(BUDGET + 1, count=9)
    at = cache(BUDGET, count=8)
    world, _, _ = kept_world(tmp_path)
    with GitReal(
        df(),
        *listed([], kind="container"),
        *listed([], kind="image"),
        FakeCall(prune_argv(BUDGET)),
        df(),
    ) as runner:
        outcome, _ = run_gc(world, runner, cache=[over, at, at])
    assert outcome.code is ExitCode.OK, outcome.steps
    assert outcome.incomplete == ()
    found = fact(outcome)
    before, after = found["before"], found["after"]
    assert isinstance(before, dict) and isinstance(after, dict)
    assert before["build_cache"] == {
        "count": 9,
        "bytes": 3_221_225_473,
        "reclaimable": 3_221_225_473,
    }
    assert after["build_cache"] == {
        "count": 8,
        "bytes": 3_221_225_472,
        "reclaimable": 3_221_225_472,
    }
    assert found["prune_calls"] == 1

    # the pair: exactly the budget -- no prune (the strict script has none)
    world, _, _ = kept_world(tmp_path / "at")
    with GitReal(
        df(), *listed([], kind="container"), *listed([], kind="image"), df()
    ) as runner:
        outcome, _ = run_gc(world, runner, cache=[at, at])
    assert outcome.code is ExitCode.OK, outcome.steps
    assert fact(outcome)["prune_calls"] == 0

    # no progress: the same bytes after the call, in fewer records -- no
    # second call
    world, _, _ = kept_world(tmp_path / "stuck")
    same = cache(BUDGET + 1, count=4)
    with GitReal(
        df(),
        *listed([], kind="container"),
        *listed([], kind="image"),
        FakeCall(prune_argv(BUDGET)),
        df(),
    ) as runner:
        outcome, _ = run_gc(world, runner, cache=[over, same, same])
    assert outcome.code is ExitCode.FAILED
    assert outcome.steps[0].reason == Code(
        "gc:not-removed", {"objects": ["build-cache"]}
    )

    # the limit: a byte less after every call, still over -- PRUNE_CALLS
    # calls, the read after each, and no call more
    assert PRUNE_CALLS == 20
    world, _, _ = kept_world(tmp_path / "limit")
    start = BUDGET + 1000
    shrinking = [cache(start - n, count=9) for n in range(PRUNE_CALLS + 1)]
    with GitReal(
        df(),
        *listed([], kind="container"),
        *listed([], kind="image"),
        *(FakeCall(prune_argv(BUDGET)) for _ in range(PRUNE_CALLS)),
        df(),
    ) as runner:
        outcome, _ = run_gc(world, runner, cache=[*shrinking, shrinking[-1]])
    assert outcome.code is ExitCode.INCOMPLETE, outcome.steps
    assert outcome.steps[0].status == "ok"
    [entry] = outcome.incomplete
    assert entry.reason.code == "gc:over-budget"
    assert entry.reason.params["over"] == ["build-cache"]
    assert entry.reason.params["builder_cache_bytes"] == start - PRUNE_CALLS
    assert entry.reason.params["builder_cache_budget"] == BUDGET
    assert fact(outcome)["prune_calls"] == PRUNE_CALLS
    prunes = [a for a in runner.argvs if a[:3] == ("docker", "builder", "prune")]
    assert len(prunes) == PRUNE_CALLS
