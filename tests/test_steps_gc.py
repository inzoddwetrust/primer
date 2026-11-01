"""``gc`` (DM-20): the clean-up by labels, measured before and after.

git runs for real on a bare repository and its release worktrees in ``tmp``;
docker follows a strict script, so a command ``gc`` must never run -- a volume
command, an unfiltered image list -- fails the test where it is made.
"""

import json
import os
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from itertools import count
from pathlib import Path

import pytest
from env_support import box as passport_box
from env_support import passport_data
from plan_support import Journal, ListSink, ScriptedStep, red

from pridem.events import Code, Json, PlanOutcome, Secrets, StepRecord
from pridem.plan import Plan, StackSteps
from pridem.report.catalog import ENGLISH
from pridem.report.codes import ExitCode
from pridem.report.schema import build_verdict
from pridem.runner import (
    FakeCall,
    FakeRunner,
    OnLine,
    Result,
    Stream,
    SubprocessRunner,
)
from pridem.state import Box, JournalHeader
from pridem.steps.gc import GC_STACK, Gc, docker_size, gc_steps
from pridem.steps.passport import PASSPORT_COPY, Fetched

STACK = "blank"
NOW = datetime(2026, 11, 1, tzinfo=UTC)
SETUP_ENV = {
    "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
    "HOME": "/nonexistent",
    "GIT_CONFIG_GLOBAL": os.devnull,
    "GIT_CONFIG_NOSYSTEM": "1",
    "GIT_AUTHOR_NAME": "t",
    "GIT_AUTHOR_EMAIL": "t@example.org",
    "GIT_COMMITTER_NAME": "t",
    "GIT_COMMITTER_EMAIL": "t@example.org",
}
DF = ("docker", "system", "df", "--format", "{{json .}}")
CONTAINERS = ("docker", "container", "ls", "--all", "--quiet", "--no-trunc")
IMAGES = (
    "docker",
    "image",
    "ls",
    "--quiet",
    "--no-trunc",
    "--filter",
    "label=pridem.commit",
)
GIB = 1024**3


def _git(*args: str) -> list[str]:
    lines: list[str] = []

    def keep(stream: Stream, line: str, cut: bool) -> None:
        if stream is Stream.STDOUT:
            lines.append(line)

    SubprocessRunner().run(["git", *args], timeout=60, env=SETUP_ENV, on_line=keep)
    return lines


class GitReal(FakeRunner):
    """git runs for real; every other command follows the script."""

    def __init__(self, *calls: FakeCall) -> None:
        super().__init__(*calls)
        self.argvs: list[tuple[str, ...]] = []
        self._real = SubprocessRunner()

    def run(
        self,
        argv: Sequence[str],
        *,
        expect: tuple[int, ...] = (0,),
        timeout: float,
        cwd: Path | None = None,
        env: Mapping[str, str] | None = None,
        on_line: OnLine,
    ) -> Result:
        self.argvs.append(tuple(argv))
        if argv[0] == "git":
            return self._real.run(
                argv, expect=expect, timeout=timeout, cwd=cwd, env=env, on_line=on_line
            )
        return super().run(
            argv, expect=expect, timeout=timeout, cwd=cwd, env=env, on_line=on_line
        )


def out(*lines: str) -> tuple[tuple[Stream, str], ...]:
    return tuple((Stream.STDOUT, line) for line in lines)


def df(
    *,
    images: tuple[int, str] = (4, "2GB"),
    containers: tuple[int, str] = (3, "10MB"),
    volumes: tuple[int, str] = (2, "100MB"),
    cache: tuple[int, str] | None = (5, "1GB"),
) -> FakeCall:
    rows = [
        ("Images", images),
        ("Containers", containers),
        ("Local Volumes", volumes),
    ]
    if cache is not None:
        rows.append(("Build Cache", cache))
    lines = [
        json.dumps(
            {
                "Active": "1",
                "Reclaimable": "0B (0%)",
                "Size": size,
                "TotalCount": str(number),
                "Type": kind,
            }
        )
        for kind, (number, size) in rows
    ]
    return FakeCall(DF, lines=out(*lines))


def image_id(n: int) -> str:
    return "sha256:" + f"{n:x}" * 64


def image(n: int, commit: str, tags: Sequence[str] = ()) -> dict[str, Json]:
    return {
        "Id": image_id(n)[:71],
        "RepoTags": list[Json](tags),
        "Config": {
            "Labels": {
                "pridem.stack": STACK,
                "pridem.release": "main",
                "pridem.commit": commit,
            }
        },
    }


def listed(found: Sequence[dict[str, Json]], *, kind: str) -> list[FakeCall]:
    """``ls`` of ``kind`` and, when it lists anything, ``inspect`` of them."""
    ids = sorted(str(item["Id"]) for item in found)
    ls = CONTAINERS if kind == "container" else IMAGES
    calls = [FakeCall(ls, lines=out(*ids))]
    if ids:
        calls.append(
            FakeCall(("docker", kind, "inspect", *ids), lines=out(json.dumps(found)))
        )
    return calls


def container(n: int, image_ref: str, mounts: Sequence[str] = ()) -> dict[str, Json]:
    return {
        "Id": f"{n:x}" * 64,
        "Image": image_ref,
        "Mounts": [{"Source": source} for source in mounts],
    }


def short(n: int) -> str:
    return image_id(n)[:71].removeprefix("sha256:")[:12]


class World:
    """A box with the stack ``blank``: a bare repository, releases, history."""

    def __init__(
        self,
        tmp: Path,
        *,
        keep: int = 2,
        cache_budget: str = "3G",
        journal_budget: str = "200M",
        packages: Mapping[str, object] | None = None,
    ) -> None:
        data = passport_data()
        if packages is not None:
            data["packages"] = dict(packages)
        policies = data["policies"]
        assert isinstance(policies, dict)
        policies["gc"] = {
            "keep_releases": keep,
            "builder_cache_budget": cache_budget,
            "journal_budget": journal_budget,
        }
        self.root, self.fetched = passport_box(tmp, data)
        self.box = Box(self.root / "opt" / "pridem")
        source = tmp / "source"
        _git("init", "-q", "-b", "main", str(source))
        self.commits: list[str] = []
        for n in range(5):
            _git("-C", str(source), "commit", "-q", "--allow-empty", "-m", f"c{n}")
            self.commits.append(_git("-C", str(source), "rev-parse", "HEAD")[0])
        self.home = self.root / "opt" / STACK
        self.bare = self.home / "git"
        self.home.mkdir(parents=True)
        _git("clone", "-q", "--bare", str(source), str(self.bare))
        self.releases = self.home / "releases"
        self.releases.mkdir()
        self._runs = count(1)

    def release(self, n: int, *, age: int = 0) -> Path:
        """The worktree of commit ``n``; ``age`` seconds older than the others."""
        path = self.releases / self.commits[n]
        _git("-C", str(self.bare), "worktree", "add", "-q", "--detach", str(path),
             self.commits[n])  # fmt: skip
        stamp = 1_800_000_000 - age
        os.utime(path, (stamp, stamp))
        return path

    def current(self, path: Path) -> None:
        link = self.home / "current"
        link.unlink(missing_ok=True)
        link.symlink_to(path)

    def green(self, n: int, *, composition: Mapping[str, str] | None = None) -> str:
        """A green deploy in history whose ``finalize`` made release ``n`` current."""
        run = f"2026-10-15T10:42:{next(self._runs):02d}Z-a3f9"
        commit = self.commits[n]
        steps = (
            StepRecord(
                STACK,
                "fetch_root",
                2,
                "ok",
                verify={"stack": STACK, "head": commit, "release": commit},
            ),
            StepRecord(
                "finalize",
                "finalize",
                2,
                "ok",
                verify={"current": {STACK: commit}, "state": "written"},
            ),
        )
        after = dict(composition or {STACK: commit, "pridem": "0.1.0"})
        verdict = build_verdict(
            PlanOutcome("deploy", ExitCode.OK, steps),
            run_id=run,
            verb="deploy",
            args={},
            actor={"type": "engineer", "via": "local"},
            started=NOW,
            finished=NOW,
            passport_version=1,
            composition_before={"pridem": "0.1.0"},
            composition_after=after,
            secrets=Secrets(()),
            catalog=ENGLISH,
        )
        with self.box.lock("test"):
            self.box.write_verdict(verdict)
        return run


def run_gc(
    world: World, runner: FakeRunner, *, run_id: str = "2026-11-01T00:00:00Z-0000"
) -> tuple[PlanOutcome, ListSink]:
    ticks = count()
    sink = ListSink()
    with world.box.lock("gc"):
        outcome = Plan(
            [StackSteps(GC_STACK, gc_steps(world.root, box=world.box, run_id=run_id,
                                           fetched=world.fetched), root=True)],
            mode="gc",
            role="test",
            runner=runner,
            sink=sink,
            clock=lambda: float(next(ticks)),
            now=lambda: NOW,
        ).run()  # fmt: skip
    return outcome, sink


def fact(outcome: PlanOutcome) -> dict[str, Json]:
    [record] = [*outcome.steps, *outcome.finally_]
    return dict(record.verify)


def kept_world(tmp: Path) -> tuple[World, Path, Path]:
    """Release 1 previous (history), release 2 current."""
    world = World(tmp)
    previous, current = world.release(1, age=100), world.release(2)
    world.green(1)
    world.green(2)
    world.current(current)
    return world, previous, current


# --- probes ---------------------------------------------------------------------


def test_probe_DM_20_planted_noop_prune_makes_verify_red(tmp_path: Path) -> None:
    world, _, _ = kept_world(tmp_path)
    old = image(3, world.commits[0])
    script = [
        df(),
        *listed([], kind="container"),
        *listed([old], kind="image"),
        FakeCall(("docker", "image", "rm", str(old["Id"]))),  # exit 0, removes nothing
        df(),
        FakeCall(IMAGES, lines=out(str(old["Id"]))),  # still there
    ]
    with GitReal(*script) as runner:
        outcome, _ = run_gc(world, runner)
    assert outcome.code is ExitCode.FAILED
    [record] = outcome.steps
    assert record.reason == Code("gc:not-removed", {"objects": [short(3)]})
    # the pair: the same image really removed -- green, and the fact names it
    world, _, _ = kept_world(tmp_path / "pair")
    old = image(3, world.commits[0])
    with GitReal(
        df(),
        *listed([], kind="container"),
        *listed([old], kind="image"),
        FakeCall(("docker", "image", "rm", str(old["Id"]))),
        df(),
        FakeCall(IMAGES),
    ) as runner:
        outcome, _ = run_gc(world, runner)
    assert outcome.code is ExitCode.OK, outcome.steps
    removed = fact(outcome)["removed"]
    assert isinstance(removed, dict) and removed["images"] == [short(3)]
    # a build cache over budget that a prune left as it was is red the same way
    world, _, _ = kept_world(tmp_path / "cache")
    with GitReal(
        df(cache=(9, "5GB")),
        *listed([], kind="container"),
        *listed([], kind="image"),
        FakeCall(prune_argv(3 * GIB)),
        df(cache=(9, "5GB")),
    ) as runner:
        outcome, _ = run_gc(world, runner)
    assert outcome.steps[0].reason == Code(
        "gc:not-removed", {"objects": ["build-cache"]}
    )


def test_probe_DM_20_previous_release_image_is_kept(tmp_path: Path) -> None:
    world, previous, current = kept_world(tmp_path)
    old = world.release(0, age=500)
    images = [
        image(1, world.commits[1]),  # previous
        image(2, world.commits[2], ["blank-app:latest"]),  # current
        image(3, world.commits[0]),  # older: goes
    ]
    with GitReal(
        df(),
        *listed([], kind="container"),
        *listed(images, kind="image"),
        FakeCall(("docker", "image", "rm", str(images[2]["Id"]))),
        df(),
        FakeCall(IMAGES, lines=out(str(images[0]["Id"]), str(images[1]["Id"]))),
    ) as runner:
        outcome, _ = run_gc(world, runner)
    assert outcome.code is ExitCode.OK, outcome.steps
    found = fact(outcome)
    kept = found["kept"]
    assert isinstance(kept, dict)
    assert kept["commits"] == sorted(world.commits[1:3])
    removed = found["removed"]
    assert isinstance(removed, dict) and removed["images"] == [short(3)]
    # keep_releases 2: the current and the previous stay, the older goes
    assert previous.is_dir() and current.is_dir() and not old.exists()


def test_probe_DM_20_unlabelled_and_base_images_are_kept(tmp_path: Path) -> None:
    world, _, _ = kept_world(tmp_path)
    old = image(3, world.commits[0])
    runner = GitReal(
        # five images on the box -- postgres, nginx, a FROM base among them --
        # and the one labelled with a foreign commit is the only one removed
        df(images=(5, "3GB")),
        *listed([], kind="container"),
        *listed([old], kind="image"),
        FakeCall(("docker", "image", "rm", str(old["Id"]))),
        df(images=(4, "2.5GB")),
        FakeCall(IMAGES),
    )
    with runner:
        outcome, _ = run_gc(world, runner)
    assert outcome.code is ExitCode.OK, outcome.steps
    docker = [argv for argv in runner.argvs if argv[0] == "docker"]
    # every image command names the label or one labelled ID: nothing else is
    # ever listed, so nothing else can be removed
    assert [a for a in docker if a[:3] == ("docker", "image", "ls")] == [IMAGES] * 2
    assert [a for a in docker if a[:3] == ("docker", "image", "rm")] == [
        ("docker", "image", "rm", str(old["Id"]))
    ]
    found = fact(outcome)
    before, after = found["before"], found["after"]
    assert isinstance(before, dict) and isinstance(after, dict)
    assert (before["images"], after["images"]) == (
        {"count": 5, "bytes": 3_000_000_000},
        {"count": 4, "bytes": 2_500_000_000},
    )


def test_probe_DM_20_volumes_never_touched(tmp_path: Path) -> None:
    world, _, _ = kept_world(tmp_path)
    old = image(3, world.commits[0])
    runner = GitReal(
        df(volumes=(3, "800MB"), cache=(9, "4GB")),
        *listed([], kind="container"),
        *listed([old], kind="image"),
        FakeCall(("docker", "image", "rm", str(old["Id"]))),
        FakeCall(prune_argv(3 * GIB)),
        df(volumes=(3, "800MB"), cache=(2, "1GB")),
        FakeCall(IMAGES),
    )
    with runner:  # strict: any volume command would be unplanned
        outcome, _ = run_gc(world, runner)
    assert outcome.code is ExitCode.OK, outcome.steps
    assert not [a for a in runner.argvs if "volume" in a]
    found = fact(outcome)
    before, after = found["before"], found["after"]
    assert isinstance(before, dict) and isinstance(after, dict)
    # the pair: there are volumes, and they are all still there
    assert before["volumes"] == after["volumes"] == {"count": 3, "bytes": 800_000_000}
    # fewer volumes after than before is red, whoever took them
    world, _, _ = kept_world(tmp_path / "taken")
    with GitReal(
        df(volumes=(3, "800MB")),
        *listed([], kind="container"),
        *listed([], kind="image"),
        df(volumes=(2, "500MB")),
    ) as runner:
        outcome, _ = run_gc(world, runner)
    assert outcome.steps[0].reason == Code(
        "gc:volumes-changed", {"before": 3, "after": 2}
    )


def test_probe_DM_20_runs_in_finally_after_red_plan(tmp_path: Path) -> None:
    world, _, _ = kept_world(tmp_path)
    old = image(3, world.commits[0])
    journal = Journal()
    run_id = "2026-11-01T00:00:00Z-0000"
    ticks = count()
    with (
        world.box.lock("deploy"),
        GitReal(
            df(),
            *listed([], kind="container"),
            *listed([old], kind="image"),
            FakeCall(("docker", "image", "rm", str(old["Id"]))),
            df(),
            FakeCall(IMAGES),
        ) as runner,
    ):
        outcome = Plan(
            [StackSteps(STACK, [red("build", 1, journal)], root=True)],
            mode="deploy",
            role="test",
            runner=runner,
            sink=ListSink(),
            finally_=[
                StackSteps(
                    GC_STACK,
                    gc_steps(world.root, box=world.box, run_id=run_id,
                             fetched=world.fetched),
                )
            ],
            clock=lambda: float(next(ticks)),
            now=lambda: NOW,
        ).run()  # fmt: skip
    assert outcome.code is ExitCode.FAILED
    assert [(r.name, r.status) for r in outcome.steps] == [("build", "failed")]
    [record] = outcome.finally_
    assert (record.stack, record.name, record.status) == (GC_STACK, "gc", "ok")
    removed = record.verify["removed"]
    assert isinstance(removed, dict) and removed["images"] == [short(3)]


def test_probe_DM_20_over_budget_gives_exit_2_with_numbers(tmp_path: Path) -> None:
    world, _, _ = kept_world(tmp_path)
    with GitReal(
        df(cache=(9, "5GB")),
        *listed([], kind="container"),
        *listed([], kind="image"),
        FakeCall(prune_argv(3 * GIB)),
        df(cache=(7, "4GB")),  # shrank, yet over: the rest is in use
    ) as runner:
        outcome, _ = run_gc(world, runner)
    assert outcome.code is ExitCode.INCOMPLETE
    [entry] = outcome.incomplete
    assert entry.what == "gc"
    assert entry.reason == Code(
        "gc:over-budget",
        {
            "over": ["build-cache"],
            "builder_cache_bytes": 4_000_000_000,
            "builder_cache_budget": 3 * GIB,
            "journal_bytes": 0,
            "journal_budget": 200 * 1024**2,
            "releases": [],
            "keep_releases": 2,
        },
    )
    assert outcome.steps[0].status == "ok"  # what it could do, it did


# --- the rest of the grid -------------------------------------------------------


def prune_argv(budget: int) -> tuple[str, ...]:
    return (
        "docker",
        "builder",
        "prune",
        "--force",
        "--all",
        "--keep-storage",
        str(budget),
    )


def test_image_of_a_container_stays_running_or_stopped(tmp_path: Path) -> None:
    world, _, _ = kept_world(tmp_path)
    running, stopped, loose = (image(n, world.commits[0]) for n in (3, 4, 5))
    containers = [
        container(1, str(running["Id"])),
        container(2, str(stopped["Id"])),
    ]
    with GitReal(
        df(),
        *listed(containers, kind="container"),
        *listed([running, stopped, loose], kind="image"),
        FakeCall(("docker", "image", "rm", str(loose["Id"]))),
        df(),
        FakeCall(IMAGES, lines=out(str(running["Id"]), str(stopped["Id"]))),
    ) as runner:
        outcome, _ = run_gc(world, runner)
    assert outcome.code is ExitCode.OK, outcome.steps
    kept = fact(outcome)["kept"]
    assert isinstance(kept, dict)
    assert kept["in_use"] == sorted([short(3), short(4)])


def test_an_image_with_tags_loses_them_all(tmp_path: Path) -> None:
    world, _, _ = kept_world(tmp_path)
    old = image(3, world.commits[0], ["blank-app:latest", "blank-app:old"])
    with GitReal(
        df(),
        *listed([], kind="container"),
        *listed([old], kind="image"),
        FakeCall(("docker", "image", "rm", "blank-app:latest", "blank-app:old")),
        df(),
        FakeCall(IMAGES),
    ) as runner:
        outcome, _ = run_gc(world, runner)
    assert outcome.code is ExitCode.OK, outcome.steps


def nothing(images: Sequence[dict[str, Json]] = ()) -> list[FakeCall]:
    """A ``gc`` that finds nothing to remove: check, then verify."""
    return [df(), *listed([], kind="container"), *listed(images, kind="image"), df()]


def worktrees(world: World) -> list[str]:
    return [
        line.removeprefix("worktree ")
        for line in _git("-C", str(world.bare), "worktree", "list", "--porcelain")
        if line.startswith("worktree ")
    ]


def test_releases_keep_the_current_the_previous_then_the_newest(tmp_path: Path) -> None:
    world = World(tmp_path, keep=3)
    oldest, older = world.release(0, age=400), world.release(1, age=300)
    previous, newest = world.release(2, age=200), world.release(3, age=100)
    current = world.release(4, age=500)  # its mtime does not matter
    tmp = world.releases / "deadbeef.tmp"
    tmp.mkdir()  # sources owns it
    world.green(2)
    world.green(4)
    world.current(current)
    with GitReal(*nothing()) as runner:
        outcome, _ = run_gc(world, runner)
    assert outcome.code is ExitCode.OK, outcome.steps
    # 3 kept: the current, the previous (older than the newest), then the newest
    assert {p for p in world.releases.iterdir()} == {current, previous, newest, tmp}
    assert not oldest.exists() and not older.exists()
    assert str(oldest) not in worktrees(world) and str(older) not in worktrees(world)
    found = fact(outcome)
    removed = found["removed"]
    assert isinstance(removed, dict)
    assert removed["releases"] == [str(older), str(oldest)]
    # the second run finds nothing to do and says so by its fact
    with GitReal(*nothing()) as runner:
        outcome, _ = run_gc(world, runner)
    assert outcome.code is ExitCode.OK
    again = fact(outcome)["removed"]
    assert again == {"images": [], "releases": []}


def test_keep_one_removes_the_previous_release_but_keeps_its_image(
    tmp_path: Path,
) -> None:
    world = World(tmp_path, keep=1)
    previous, current = world.release(1, age=100), world.release(2)
    world.green(1)
    world.green(2)
    world.current(current)
    images = [image(1, world.commits[1])]
    with GitReal(*nothing(images)) as runner:
        outcome, _ = run_gc(world, runner)
    assert outcome.code is ExitCode.OK, outcome.steps
    assert not previous.exists() and current.is_dir()
    kept = fact(outcome)["kept"]
    assert isinstance(kept, dict) and world.commits[1] in str(kept["commits"])


def test_a_mounted_release_stays_and_is_over_budget(tmp_path: Path) -> None:
    world = World(tmp_path, keep=1)
    mounted, current = world.release(1, age=100), world.release(2)
    world.green(2)
    world.current(current)
    containers = [container(1, image_id(9), [str(mounted / "config")])]
    with GitReal(
        df(),
        *listed(containers, kind="container"),
        *listed([], kind="image"),
        df(),
    ) as runner:
        outcome, _ = run_gc(world, runner)
    assert mounted.is_dir() and current.is_dir()
    assert outcome.code is ExitCode.INCOMPLETE
    [entry] = outcome.incomplete
    assert entry.reason.params["over"] == ["releases"]
    assert entry.reason.params["releases"] == [f"{STACK}:2"]


def package(world: World, name: str) -> Path:
    """A package worktree of the stack, from its own bare repository."""
    bare = world.home / "packages" / "pridem-look.git"
    if not bare.exists():
        _git("clone", "-q", "--bare", str(world.bare), str(bare))
    path = world.releases / name
    _git("-C", str(bare), "worktree", "add", "-q", "--detach", str(path),
         world.commits[0])  # fmt: skip
    return path


def test_packages_stay_mounted_or_named_by_the_previous_release(tmp_path: Path) -> None:
    world = World(tmp_path, keep=2)
    previous, current = world.release(1, age=100), world.release(2)
    named, mounted, loose = (
        package(world, "look@1.0.0"),
        package(world, "look@1.1.0"),
        package(world, "look@0.9.0"),
    )
    world.green(
        1,
        composition={STACK: world.commits[1], "skin": "look@1.0.0", "pridem": "0.1.0"},
    )
    world.green(
        2,
        composition={STACK: world.commits[2], "skin": "look@1.1.0", "pridem": "0.1.0"},
    )
    world.current(current)
    containers = [container(1, image_id(9), [str(mounted)])]
    with GitReal(
        df(),
        *listed(containers, kind="container"),
        *listed([], kind="image"),
        df(),
    ) as runner:
        outcome, _ = run_gc(world, runner)
    assert outcome.code is ExitCode.OK, outcome.steps
    assert named.is_dir() and mounted.is_dir() and not loose.exists()
    assert previous.is_dir() and current.is_dir()
    kept = fact(outcome)["kept"]
    assert isinstance(kept, dict)
    # packages are not releases of the stack: they hold no slot of keep_releases
    assert kept["releases"] == {STACK: sorted([current.name, previous.name])}


def test_journals_go_to_the_budget_and_the_current_one_stays(tmp_path: Path) -> None:
    world = World(tmp_path, journal_budget="1K")
    runs = [f"2026-11-01T00:00:0{n}Z-0000" for n in range(3)]
    world.box.journals.mkdir(parents=True)
    for run in runs:
        (world.box.journals / f"{run}.jsonl").write_bytes(b"x" * 600)
    with GitReal(*nothing()) as runner:
        outcome, _ = run_gc(world, runner, run_id=runs[0])  # the oldest is current
    assert outcome.code is ExitCode.OK, outcome.steps
    left = sorted(p.name for p in world.box.journals.iterdir())
    assert left == [f"{runs[0]}.jsonl"]  # the others went oldest first, it stayed
    before, after = fact(outcome)["before"], fact(outcome)["after"]
    assert isinstance(before, dict) and isinstance(after, dict)
    assert (before["journal"], after["journal"]) == ({"bytes": 1800}, {"bytes": 600})
    # the current journal alone over budget: 2, with the numbers
    (world.box.journals / f"{runs[0]}.jsonl").write_bytes(b"x" * 2000)
    with GitReal(*nothing()) as runner:
        outcome, _ = run_gc(world, runner, run_id=runs[0])
    assert outcome.code is ExitCode.INCOMPLETE
    [entry] = outcome.incomplete
    assert entry.reason.params["over"] == ["journal"]
    assert entry.reason.params["journal_bytes"] == 2000


def test_an_empty_box_measures_and_is_green(tmp_path: Path) -> None:
    data = passport_data()
    root, fetched = passport_box(tmp_path, data)
    box = Box(root / "opt" / "pridem")
    step = Gc(box=box, run_id="2026-11-01T00:00:00Z-0000", fetched=fetched, root=root)
    ticks = count()
    with (
        box.lock("gc"),
        GitReal(
            df(cache=None),  # no build cache line at all
            *listed([], kind="container"),
            *listed([], kind="image"),
            df(cache=None),
        ) as runner,
    ):
        outcome = Plan(
            [StackSteps(GC_STACK, [step], root=True)],
            mode="gc",
            role="test",
            runner=runner,
            sink=ListSink(),
            clock=lambda: float(next(ticks)),
            now=lambda: NOW,
        ).run()
    assert outcome.code is ExitCode.OK, outcome.steps
    after = fact(outcome)["after"]
    assert isinstance(after, dict)
    assert after["build_cache"] == {"count": 0, "bytes": 0}


def test_without_any_passport_gc_removes_nothing_and_says_so(tmp_path: Path) -> None:
    """Without a passport ``gc`` cannot know its budgets: nothing is removed,
    ``incomplete gc:not-started`` (exit 2). Until DM-53 this was red."""
    world, _, _ = kept_world(tmp_path)
    (world.root / PASSPORT_COPY).unlink()
    step = Gc(box=world.box, run_id="r", fetched=Fetched(), root=world.root)
    ticks = count()
    with world.box.lock("gc"), GitReal() as runner:
        outcome = Plan(
            [StackSteps(GC_STACK, [step], root=True)],
            mode="gc",
            role="test",
            runner=runner,
            sink=ListSink(),
            clock=lambda: float(next(ticks)),
            now=lambda: NOW,
        ).run()
    assert outcome.code is ExitCode.INCOMPLETE
    [entry] = outcome.incomplete
    assert (entry.what, entry.reason) == (
        "gc",
        Code("gc:not-started", {"cause": "no-passport", "command": ""}),
    )
    assert outcome.steps[0].status == "ok"


def test_without_a_fetched_passport_gc_reads_the_box_copy(tmp_path: Path) -> None:
    world, _, _ = kept_world(tmp_path)
    world.fetched = Fetched()
    with GitReal(*nothing()) as runner:
        outcome, _ = run_gc(world, runner)
    assert outcome.code is ExitCode.OK, outcome.steps


def test_a_damaged_verdict_is_skipped_and_counted(tmp_path: Path) -> None:
    world, previous, _ = kept_world(tmp_path)
    with world.box.lock("test"):
        damaged = world.box.history / "2026-10-16T00:00:00Z-dead.json"
        damaged.write_text("{", encoding="utf-8")
    images = [image(1, world.commits[1])]
    with GitReal(*nothing(images)) as runner:
        outcome, _ = run_gc(world, runner)
    assert outcome.code is ExitCode.OK, outcome.steps
    assert previous.is_dir()  # the previous is still found past the damage


def test_a_red_verdict_names_no_previous_release(tmp_path: Path) -> None:
    world, previous, current = kept_world(tmp_path)
    red_release = world.release(3, age=50)
    run = world.green(3)
    path = world.box.history / f"{run}.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    path.unlink()
    data.update(exit_code=1, result="red")
    data["steps"][0].update(status="failed", reason={"code": "fetch_root:fetch"})
    data["steps"][0].pop("verify")
    with world.box.lock("test"):
        path.write_text(json.dumps(data), encoding="utf-8")
    images = [image(3, world.commits[3])]
    with GitReal(
        df(),
        *listed([], kind="container"),
        *listed(images, kind="image"),
        FakeCall(("docker", "image", "rm", str(images[0]["Id"]))),
        df(),
        FakeCall(IMAGES),
    ) as runner:
        outcome, _ = run_gc(world, runner)
    assert outcome.code is ExitCode.OK, outcome.steps
    # the previous is release 1, past the red run: keep 2 holds it and the current
    assert previous.is_dir() and current.is_dir() and not red_release.exists()


@pytest.mark.parametrize(
    ("text", "size"),
    [
        ("0B", 0),
        ("4.096kB", 4096),
        ("1.234GB", 1_234_000_000),
        ("10.39GB", 10_390_000_000),
        ("12MB", 12_000_000),
    ],
)
def test_docker_size_is_decimal(text: str, size: int) -> None:
    assert docker_size(text) == size


def test_a_size_docker_never_prints_is_an_error() -> None:
    with pytest.raises(ValueError, match="not a docker size"):
        docker_size("3GiB")


def test_the_journal_header_takes_the_gc_mode(tmp_path: Path) -> None:
    box = Box(tmp_path)
    header = JournalHeader.model_validate(
        {
            "run_id": "2026-11-01T00:00:00Z-0000",
            "verb": "gc",
            "mode": "gc",
            "args": {},
            "actor": {"type": "machine", "via": "timer"},
            "started": NOW,
            "composition_before": {"pridem": "0.1.0"},
        }
    )
    with box.lock("gc"):
        box.open_journal(header, Secrets(())).close()
        assert box.read_journal(header.run_id) is not None


# --- DM-53: nothing started is incomplete; packages of the current release ------


def test_a_gc_that_cannot_measure_removes_nothing_and_is_incomplete(
    tmp_path: Path,
) -> None:
    world, previous, current = kept_world(tmp_path)
    with GitReal(FakeCall(DF, code=1)) as runner:  # docker does not answer
        outcome, _ = run_gc(world, runner)
    assert outcome.code is ExitCode.INCOMPLETE
    [entry] = outcome.incomplete
    assert (entry.what, entry.reason) == (
        "gc",
        Code(
            "gc:not-started", {"cause": "command-failed", "command": "docker system df"}
        ),
    )
    assert outcome.steps[0].status == "ok"
    assert not [a for a in runner.argvs if a[0] == "docker"][1:]  # df only
    assert previous.is_dir() and current.is_dir()


def test_a_gc_in_finally_that_removed_nothing_leaves_a_green_plan_at_2(
    tmp_path: Path,
) -> None:
    world, _, _ = kept_world(tmp_path)
    journal = Journal()
    ticks = count()
    clean = gc_steps(world.root, box=world.box, run_id="r", fetched=world.fetched)
    with world.box.lock("deploy"), GitReal(FakeCall(DF, code=1)) as runner:
        outcome = Plan(
            [StackSteps(STACK, [ScriptedStep("build", 1, journal)], root=True)],
            mode="deploy",
            role="test",
            runner=runner,
            sink=ListSink(),
            finally_=[StackSteps(GC_STACK, clean)],
            clock=lambda: float(next(ticks)),
            now=lambda: NOW,
        ).run()  # fmt: skip
    assert outcome.code is ExitCode.INCOMPLETE  # 2, not 1
    assert [r.status for r in (*outcome.steps, *outcome.finally_)] == ["ok", "ok"]


def test_a_gc_that_began_removing_and_failed_is_red(tmp_path: Path) -> None:
    world, _, _ = kept_world(tmp_path)
    old = image(3, world.commits[0])
    with GitReal(
        df(),
        *listed([], kind="container"),
        *listed([old], kind="image"),
        FakeCall(("docker", "image", "rm", str(old["Id"])), code=1),
    ) as runner:
        outcome, _ = run_gc(world, runner)
    assert outcome.code is ExitCode.FAILED
    reason = outcome.steps[0].reason
    assert reason is not None and reason.code == "command-failed"


def test_packages_of_the_current_release_stay_without_containers(
    tmp_path: Path,
) -> None:
    skin = {"repo": "git@github.com:partner/look.git", "version": "1.2.0"}
    world = World(tmp_path, keep=2, packages={"skin": skin})
    previous, current = world.release(1, age=100), world.release(2)
    by_passport = package(world, "look@1.2.0")  # the passport's: named nowhere else
    by_current = package(world, "look@1.1.0")  # the current release's composition
    loose = package(world, "look@0.9.0")
    world.green(1, composition={STACK: world.commits[1], "pridem": "0.1.0"})
    world.green(
        2,
        composition={STACK: world.commits[2], "skin": "look@1.1.0", "pridem": "0.1.0"},
    )
    world.current(current)
    with GitReal(*nothing()) as runner:  # no container at all
        outcome, _ = run_gc(world, runner)
    assert outcome.code is ExitCode.OK, outcome.steps
    assert by_passport.is_dir() and by_current.is_dir() and not loose.exists()
    assert previous.is_dir() and current.is_dir()
