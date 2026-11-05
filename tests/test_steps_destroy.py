"""``destroy`` (DM-45): what the machine put on the box goes, but the volumes of
``persistent`` entries, ``minted.yaml``, the journal, the history and the keys;
a volume that cannot be told persistent or not is never removed by guess."""

from itertools import count
from pathlib import Path

import pytest
import yaml
from contract_support import example
from plan_support import ListSink
from state_support import state

from pridem.events import PlanOutcome
from pridem.plan import Plan, StackSteps
from pridem.report.codes import ExitCode
from pridem.runner import FakeCall, FakeRunner, Stream
from pridem.state import Box
from pridem.steps.destroy import LABEL, destroy_steps
from pridem.steps.timers import UNIT_DIR

DPKG = ("dpkg-query", "-W", "-f=${Status}", "docker.io")


def _out(*lines: str) -> tuple[tuple[Stream, str], ...]:
    return tuple((Stream.STDOUT, line) for line in lines)


def listed(
    containers: tuple[str, ...] = (),
    networks: tuple[str, ...] = (),
    volumes: tuple[str, ...] = (),
    images: tuple[str, ...] = (),
) -> list[FakeCall]:
    return [
        FakeCall(("docker", "ps", "-aq", "--filter", LABEL), lines=_out(*containers)),
        FakeCall(
            ("docker", "network", "ls", "--filter", LABEL, "--format", "{{.Name}}"),
            lines=_out(*networks),
        ),
        FakeCall(
            (
                "docker",
                "volume",
                "ls",
                "--filter",
                LABEL,
                "--format",
                '{{.Name}}\t{{.Label "pridem.stack"}}',
            ),
            lines=_out(*volumes),
        ),
        FakeCall(
            ("docker", "image", "ls", "-q", "--no-trunc", "--filter", LABEL),
            lines=_out(*images),
        ),
    ]


def docker(installed: bool = True) -> FakeCall:
    return FakeCall(DPKG, lines=_out("install ok installed") if installed else ())


def box_with_release(tmp: Path, persistent: set[str]) -> tuple[Path, Box]:
    """``state.json`` naming stack ``aivis`` and its ``current`` release, whose
    ``primer.yaml`` has two entries; ``persistent`` ones are marked."""
    root = tmp / "fs"
    box = Box(root / "opt" / "pridem")
    data = example("product.yaml")
    stacks = data["stacks"]
    assert isinstance(stacks, dict)
    stacks["storage"] = {"compose": "storage.yml"}
    for name in persistent:
        entry = stacks[name]
        assert isinstance(entry, dict)
        entry["persistent"] = True
    release = root / "opt" / "aivis" / "releases" / "9a1c4e2"
    release.mkdir(parents=True)
    (release / "primer.yaml").write_text(yaml.safe_dump(data))
    (root / "opt" / "aivis" / "current").symlink_to(release)
    with box.lock("setup"):
        box.write_state(state())
    return root, box


def run(root: Path, box: Box, runner: FakeRunner, **kw: bool) -> PlanOutcome:
    ticks = count()
    return Plan(
        [StackSteps("destroy", destroy_steps(root, box=box, **kw), root=True)],
        mode="destroy",
        role="test",
        runner=runner,
        sink=ListSink(),
        clock=lambda: float(next(ticks)),
    ).run()


def test_persistent_volumes_stay_and_are_named(tmp_path: Path) -> None:
    """Every labelled container, network, image and volume goes, but the volume
    of the persistent entry ``storage``: the fact names it. The pair: the
    other entry's volume is removed."""
    root, box = box_with_release(tmp_path, {"storage"})
    seen = listed(("c1",), ("pridem",), ("files\tstorage", "db\taivis"), ("sha256:1",))
    script = [
        docker(),
        *seen,
        docker(),
        *seen,
        FakeCall(("docker", "rm", "-f", "c1")),
        FakeCall(("docker", "volume", "rm", "db")),
        FakeCall(("docker", "network", "rm", "pridem")),
        FakeCall(("docker", "image", "rm", "-f", "sha256:1")),
        *listed(volumes=("files\tstorage",)),
    ]
    with box.lock("destroy"), FakeRunner(*script) as runner:
        outcome = run(root, box, runner)
    assert outcome.code is ExitCode.OK, outcome.steps
    first = outcome.steps[0]
    assert first.verify["kept_volumes"] == ["files"]
    assert not (box.root / "state.json").exists()


@pytest.mark.parametrize("why", ["no-state", "release-unreadable"])
def test_a_volume_the_box_cannot_place_is_never_removed(
    tmp_path: Path, why: str
) -> None:
    """No ``state.json``, or a ``current`` whose ``primer.yaml`` is gone: the
    volumes cannot be told persistent or not -- red before any removal (no
    ``rm`` in the script); the pair: the same box with no labelled volume
    removes its containers."""
    root, box = box_with_release(tmp_path, set())
    if why == "no-state":
        (box.root / "state.json").unlink()
    else:
        (root / "opt" / "aivis" / "current" / "primer.yaml").unlink()
    with (
        box.lock("destroy"),
        FakeRunner(docker(), *listed(volumes=("db\taivis",))) as r,
    ):
        outcome = run(root, box, r)
    reason = outcome.steps[0].reason
    assert reason is not None and reason.code == "remove_objects:persistent-unknown"
    assert reason.params == {"volumes": ["db"]}
    # the pair: nothing to place, the container goes
    seen = listed(("c1",))
    script = [docker(), *seen, docker(), *seen, FakeCall(("docker", "rm", "-f", "c1"))]
    script += listed()
    with box.lock("destroy"), FakeRunner(*script) as runner:
        outcome = run(root, box, runner)
    assert outcome.steps[0].status == "ok", outcome.steps


@pytest.mark.parametrize("new_secrets", [False, True])
def test_files_go_but_minted_and_what_is_not_the_machines(
    tmp_path: Path, new_secrets: bool
) -> None:
    """``/opt/<stack>`` goes but ``env/minted.yaml`` (``--new-secrets``: it
    too); the edge's and the proxy's directories go; history, journal, keys,
    the passport copy and a directory of ``/opt`` the machine did not make
    stay."""
    root, box = box_with_release(tmp_path, set())
    home = root / "opt" / "aivis"
    (home / "env").mkdir()
    (home / "env" / ".env").write_text("A=1\n")
    (home / "env" / "minted.yaml").write_text("S: x\n")
    (home / "git").mkdir()
    (home / "git" / "HEAD").write_text("ref\n")
    pridem = root / "opt" / "pridem"
    for kept in ("history", "journal", "keys"):
        (pridem / kept).mkdir(exist_ok=True)
    (pridem / "passport.yaml").write_text("x\n")
    for gone in ("edge", "egress"):
        (pridem / gone).mkdir()
        (pridem / gone / "compose.yml").write_text("{}\n")
    foreign = root / "opt" / "containerd"
    foreign.mkdir()
    units = root / UNIT_DIR
    units.mkdir(parents=True)
    (units / "pridem-gc.timer").write_text("[Timer]\n")
    script = [
        docker(False),
        docker(False),
        FakeCall(("systemctl", "disable", "--now", "pridem-gc.timer")),
        FakeCall(("systemctl", "daemon-reload")),
    ]
    with box.lock("destroy"), FakeRunner(*script) as runner:
        outcome = run(root, box, runner, new_secrets=new_secrets)
    assert outcome.code is ExitCode.OK, outcome.steps
    left = (
        sorted(str(p.relative_to(root)) for p in home.rglob("*"))
        if home.exists()
        else []
    )
    assert left == (
        [] if new_secrets else ["opt/aivis/env", "opt/aivis/env/minted.yaml"]
    )
    assert not (pridem / "edge").exists() and not (pridem / "egress").exists()
    assert all((pridem / kept).is_dir() for kept in ("history", "journal", "keys"))
    assert (pridem / "passport.yaml").exists() and foreign.is_dir()
    assert not (units / "pridem-gc.timer").exists()
    assert outcome.steps[1].verify["new_secrets"] is new_secrets


def test_a_clean_box_has_nothing_to_destroy(tmp_path: Path) -> None:
    """``destroy`` again: every check says so, nothing acts, green."""
    root = tmp_path / "fs"
    box = Box(root / "opt" / "pridem")
    script = [docker(), *listed(), *listed()]
    with box.lock("destroy"), FakeRunner(*script) as runner:
        outcome = run(root, box, runner)
    assert outcome.code is ExitCode.OK, outcome.steps
    assert [s.verify for s in outcome.steps] == [
        {"containers": 0, "networks": 0, "images": 0, "kept_volumes": []},
        {"kept_minted": [], "new_secrets": False},
        {"units": []},
        {"state": "absent"},
    ]
