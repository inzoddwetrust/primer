"""``gc`` and dangling images (DM-207): the grid around the probe.

A dangling image is what ``docker image ls --filter dangling=true`` lists: no
name points at it. ``gc`` removes it by its ID unless a container was made
from it, and asks for it by its ID afterwards. docker follows a strict
script, so an image ``gc`` must not remove is one no ``image rm`` names.
"""

import json
from pathlib import Path

import pytest
from engine_support import GB, cache, engine_steady
from env_support import context
from test_steps_gc import (
    DANGLING,
    DF,
    GIB,
    IMAGES,
    GitReal,
    alive,
    df,
    fact,
    image,
    kept_world,
    listed,
    loose,
    out,
    prune_argv,
    run_gc,
    short,
)

from pridem.events import Code, Json
from pridem.report.codes import ExitCode
from pridem.runner import FakeCall
from pridem.steps.gc import gc_steps


def rm(found: dict[str, Json]) -> FakeCall:
    return FakeCall(("docker", "image", "rm", str(found["Id"])))


def test_a_dangling_image_still_there_after_its_removal_is_red(tmp_path: Path) -> None:
    """``image rm`` exits 0 and the image answers ``inspect`` by its ID: the
    step is red, ``not-removed`` names it. The pair -- the same script with
    the image gone, green -- is the probe."""
    world, _, _ = kept_world(tmp_path)
    left = loose(5)
    with GitReal(
        df(),
        *listed([], kind="container"),
        *listed([], kind="image", dangling=[left]),
        rm(left),
        df(),
        alive(left, there=True),
    ) as runner:
        outcome, _ = run_gc(world, runner)
    assert outcome.code is ExitCode.FAILED
    assert outcome.steps[0].reason == Code("gc:not-removed", {"objects": [short(5)]})


def test_an_image_with_a_name_is_not_taken_as_dangling(tmp_path: Path) -> None:
    """The list of the dangling ones names an image whose own ``RepoTags`` is
    not empty: it stays -- no ``image rm`` in the script -- and ``gc`` has
    nothing to do. The pair: the same image with no name goes."""
    world, _, _ = kept_world(tmp_path)
    named = loose(5)
    named["RepoTags"] = ["theirs:1"]
    with GitReal(
        df(),
        *listed([], kind="container"),
        *listed([], kind="image", dangling=[named]),
        df(),
    ) as runner:
        outcome, _ = run_gc(world, runner)
    assert outcome.code is ExitCode.OK, outcome.steps
    removed = fact(outcome)["removed"]
    assert isinstance(removed, dict)
    assert removed["images"] == [] and "dangling" not in removed
    world, _, _ = kept_world(tmp_path / "pair")
    bare = loose(5)
    with GitReal(
        df(),
        *listed([], kind="container"),
        *listed([], kind="image", dangling=[bare]),
        rm(bare),
        df(),
        alive(bare, there=False),
    ) as runner:
        outcome, _ = run_gc(world, runner)
    assert outcome.code is ExitCode.OK, outcome.steps


@pytest.mark.parametrize("tags", [None, "absent"], ids=["null", "no-key"])
def test_a_dangling_image_whose_names_docker_does_not_print_goes(
    tmp_path: Path, tags: str | None
) -> None:
    """Twin EMPTINESS: ``RepoTags`` null, or not there at all, is no name --
    docker listed the image as dangling, and nothing says otherwise."""
    world, _, _ = kept_world(tmp_path)
    bare = loose(5)
    if tags is None:
        bare["RepoTags"] = None
    else:
        del bare["RepoTags"]
    with GitReal(
        df(),
        *listed([], kind="container"),
        *listed([], kind="image", dangling=[bare]),
        rm(bare),
        df(),
        alive(bare, there=False),
    ) as runner:
        outcome, _ = run_gc(world, runner)
    assert outcome.code is ExitCode.OK, outcome.steps


def test_a_dangling_image_without_its_id_is_not_started(tmp_path: Path) -> None:
    """Twin SHORTAGE: ``inspect`` of a dangling image with no ``Id`` -- there
    is nothing to remove it by, and no name is made up for ``image rm``:
    ``not-started``, nothing removed."""
    world, previous, current = kept_world(tmp_path)
    ident = str(loose(5)["Id"])
    nameless = {"RepoTags": [], "Config": {"Labels": None}}
    with GitReal(
        df(),
        *listed([], kind="container"),
        FakeCall(DANGLING, lines=out(ident)),
        FakeCall(
            ("docker", "image", "inspect", ident), lines=out(json.dumps([nameless]))
        ),
    ) as runner:
        outcome, _ = run_gc(world, runner)
    assert outcome.code is ExitCode.INCOMPLETE
    [entry] = outcome.incomplete
    assert entry.reason == Code(
        "gc:not-started", {"cause": "unreadable", "command": "UnreadableOutput"}
    )
    assert previous.is_dir() and current.is_dir()


def test_a_dangling_image_of_the_current_commit_goes_once(tmp_path: Path) -> None:
    """An image with the machine's labels and the commit of the current
    release, and no name: both lists name it (the label's and the dangling
    ones'). No release can take it -- a release takes its image by a name --
    so the commit does not keep it; it is removed by one command, and the
    fact names it once. The pair in the same script: the image of that commit
    with its name stays."""
    world, _, _ = kept_world(tmp_path)
    current = world.commits[2]
    named = image(2, current, ["blank-app:222222222222"])
    bare = loose(5, {"pridem.stack": "blank", "pridem.commit": current})
    with GitReal(
        df(),
        *listed([], kind="container"),
        *listed([named, bare], kind="image", dangling=[bare]),
        rm(bare),
        df(),
        alive(bare, there=False),
    ) as runner:
        outcome, _ = run_gc(world, runner)
    assert outcome.code is ExitCode.OK, outcome.steps
    removed = fact(outcome)["removed"]
    assert isinstance(removed, dict)
    assert removed["images"] == [short(5)] and removed["dangling"] == [short(5)]
    assert [a for a in runner.argvs if a[:3] == ("docker", "image", "rm")] == [
        ("docker", "image", "rm", str(bare["Id"]))
    ]


def test_a_dangling_image_of_an_old_commit_goes_once(tmp_path: Path) -> None:
    """An image with the machine's labels, a commit neither current nor
    previous, and no name: the label's list would remove it and the dangling
    ones' would too. One ``image rm``, not two -- the strict script has one
    -- and the fact names it once, asked for by its ID in ``verify``, not by
    the label's list."""
    world, _, _ = kept_world(tmp_path)
    bare = loose(5, {"pridem.stack": "blank", "pridem.commit": world.commits[0]})
    with GitReal(
        df(),
        *listed([], kind="container"),
        *listed([bare], kind="image", dangling=[bare]),
        rm(bare),
        df(),
        alive(bare, there=False),
    ) as runner:
        outcome, _ = run_gc(world, runner)
    assert outcome.code is ExitCode.OK, outcome.steps
    removed = fact(outcome)["removed"]
    assert isinstance(removed, dict)
    assert removed["images"] == [short(5)] and removed["dangling"] == [short(5)]
    assert [a for a in runner.argvs if a[:3] == ("docker", "image", "rm")] == [
        ("docker", "image", "rm", str(bare["Id"]))
    ]


@pytest.mark.parametrize(
    ("extra", "prunes"), [(0, 0), (1, 1)], ids=["at-the-budget", "a-byte-over"]
)
def test_act_prunes_a_cache_over_the_budget_and_not_one_at_it(
    tmp_path: Path, extra: int, prunes: int
) -> None:
    """``act`` runs for a dangling image, and the cache -- 4GiB as a whole,
    so measured again once the image went -- is of its own exactly the
    budget: not over, no prune. The pair: one byte more is pruned, once."""
    world, _, _ = kept_world(tmp_path)
    bare = loose(5)
    budget = 3 * GIB
    seen = cache(4 * GIB, budget + extra, count=9)
    done = cache(4 * GIB - extra, budget, count=9)
    with GitReal(
        df(),
        *listed([], kind="container"),
        *listed([], kind="image", dangling=[bare]),
        rm(bare),
        *(FakeCall(prune_argv(budget)) for _ in range(prunes)),
        df(),
        alive(bare, there=False),
    ) as runner:
        measures = [cache(4 * GIB, 1 * GB, count=9), seen, *[done] * prunes, done]
        outcome, _ = run_gc(world, runner, cache=measures)
    assert outcome.code is ExitCode.OK, outcome.steps
    assert outcome.incomplete == ()
    assert fact(outcome)["prune_calls"] == prunes


def test_a_labelled_image_and_a_dangling_one_both_go_and_are_told_apart(
    tmp_path: Path,
) -> None:
    """An image of an old commit (by its label) and a dangling one: each by
    its own command, ``removed.images`` names both, ``removed.dangling`` the
    dangling one alone; ``verify`` asks the list for the first and the ID for
    the second."""
    world, _, _ = kept_world(tmp_path)
    old = image(3, world.commits[0])
    bare = loose(5)
    with GitReal(
        df(),
        *listed([], kind="container"),
        *listed([old], kind="image", dangling=[bare]),
        rm(old),
        rm(bare),
        df(),
        FakeCall(IMAGES),
        alive(bare, there=False),
    ) as runner:
        outcome, _ = run_gc(world, runner)
    assert outcome.code is ExitCode.OK, outcome.steps
    removed = fact(outcome)["removed"]
    assert isinstance(removed, dict)
    assert removed["images"] == [short(3), short(5)]
    assert removed["dangling"] == [short(5)]


def test_a_second_gc_finds_no_dangling_image_and_runs_no_removal(
    tmp_path: Path,
) -> None:
    """Twin REPEAT: after the dangling image went, the next ``gc`` lists
    none: ``check`` needs no ``act``, no ``image rm``, no ``inspect`` by an
    ID, the fact has no ``dangling``."""
    world, _, _ = kept_world(tmp_path)
    bare = loose(5)
    with GitReal(
        df(),
        *listed([], kind="container"),
        *listed([], kind="image", dangling=[bare]),
        rm(bare),
        df(),
        alive(bare, there=False),
    ) as runner:
        first, _ = run_gc(world, runner)
    assert first.code is ExitCode.OK, first.steps
    with GitReal(
        df(), *listed([], kind="container"), *listed([], kind="image"), df()
    ) as runner:
        second, _ = run_gc(world, runner, run_id="2026-11-01T00:00:01Z-0001")
    assert second.code is ExitCode.OK, second.steps
    removed = fact(second)["removed"]
    assert isinstance(removed, dict) and "dangling" not in removed
    [step] = gc_steps(world.root, box=world.box, run_id="r3", fetched=world.fetched)
    with (
        engine_steady(),
        world.box.lock("doctor"),
        GitReal(
            df(), *listed([], kind="container"), *listed([], kind="image")
        ) as runner,
    ):
        assert step.check(context(runner)).needed is False


def test_doctor_says_a_dangling_image_would_go(tmp_path: Path) -> None:
    """``check`` alone: one dangling image is one image of ``gc:clean``."""
    world, _, _ = kept_world(tmp_path)
    [step] = gc_steps(world.root, box=world.box, run_id="r2", fetched=world.fetched)
    with (
        engine_steady(),
        world.box.lock("doctor"),
        GitReal(
            df(),
            *listed([], kind="container"),
            *listed([], kind="image", dangling=[loose(5)]),
        ) as runner,
    ):
        found = step.check(context(runner))
    assert found.needed is True
    assert found.would == Code(
        "clean",  # the step's own code: the plan names its step
        {"images": 1, "releases": [], "build_cache": False, "journals": False},
    )


def test_a_dangling_image_docker_refuses_to_remove_is_red_not_forced(
    tmp_path: Path,
) -> None:
    """docker refuses the removal (a container made from the image since the
    list): the command's failure is the step's, and no second command with
    ``--force`` follows -- the strict script has none."""
    world, _, _ = kept_world(tmp_path)
    bare = loose(5)
    refused = FakeCall(("docker", "image", "rm", str(bare["Id"])), code=1)
    with GitReal(
        df(),
        *listed([], kind="container"),
        *listed([], kind="image", dangling=[bare]),
        refused,
    ) as runner:
        outcome, _ = run_gc(world, runner)
    assert outcome.code is ExitCode.FAILED
    reason = outcome.steps[0].reason
    assert reason is not None and reason.code == "command-failed"
    assert not [a for a in runner.argvs if "--force" in a and "rm" in a]


def test_the_layers_of_a_dangling_image_that_went_are_measured_before_the_prune(
    tmp_path: Path,
) -> None:
    """As with an image of an old commit (``test_steps_gc_cache.py``): the
    layers of the dangling image that went are the cache's alone now. 1GB of
    its own under 5GB as a whole at ``check``; measured again after the
    removal -- 4GB, over the budget -- and pruned in this run."""
    world, _, _ = kept_world(tmp_path)
    bare = loose(5)
    done = cache(3 * GB, 2 * GB, count=4)
    with GitReal(
        df(),
        *listed([], kind="container"),
        *listed([], kind="image", dangling=[bare]),
        rm(bare),
        FakeCall(prune_argv(3 * GIB)),
        df(),
        alive(bare, there=False),
    ) as runner:
        outcome, _ = run_gc(
            world,
            runner,
            cache=[
                cache(5 * GB, 1 * GB, count=9),
                cache(5 * GB, 4 * GB, count=9),
                done,
                done,
            ],
        )
    assert outcome.code is ExitCode.OK, outcome.steps
    assert fact(outcome)["prune_calls"] == 1


def test_gc_does_not_read_the_build_cache_from_dockers_line(tmp_path: Path) -> None:
    """``docker system df`` says ``9GB`` of build cache here (``df``), three
    times the budget; the Engine API says 1GB. No prune: the line is not
    read. The pair -- the Engine API over the budget, pruned -- is the
    probe of the cache."""
    world, _, _ = kept_world(tmp_path)
    with GitReal(
        df(), *listed([], kind="container"), *listed([], kind="image"), df()
    ) as runner:
        outcome, _ = run_gc(world, runner, cache=[cache(1 * GB), cache(1 * GB)])
    assert outcome.code is ExitCode.OK, outcome.steps
    assert DF in runner.argvs  # the line was printed to gc, and not believed
    found = fact(outcome)
    assert found["prune_calls"] == 0
    after = found["after"]
    assert isinstance(after, dict)
    assert after["build_cache"] == {"count": 5, "bytes": GB, "reclaimable": GB}
