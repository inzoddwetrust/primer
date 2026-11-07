"""``destroy`` (DM-45): what the machine put on the box goes, but the volumes of
``persistent`` entries, ``minted.yaml``, the journal, the history and the keys;
a volume that cannot be told persistent or not is never removed by guess."""

import json
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
from pridem.steps.sources import mark
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
    mark(root / "opt" / "aivis", "aivis")  # as fetch_root leaves it (DM-76)
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
    stay.

    Changed by DM-76: the machine's mark stays while the minted secret does;
    with ``--new-secrets`` the directory goes whole."""
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
        []
        if new_secrets
        else ["opt/aivis/.pridem", "opt/aivis/env", "opt/aivis/env/minted.yaml"]
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


# --- DM-76: the machine's own directories and the volumes it keeps -----------------


def _with_minted(root: Path) -> Path:
    home = root / "opt" / "aivis"
    (home / "env").mkdir()
    (home / "env" / "minted.yaml").write_text("S: x\n")
    return home


def _tree(path: Path) -> dict[str, bytes]:
    return {
        str(p.relative_to(path)): p.read_bytes() for p in path.rglob("*") if p.is_file()
    }


def test_probe_DM_76_a_foreign_opt_dir_is_left_alone(tmp_path: Path) -> None:
    """``/opt/myapp`` with a virtualenv ``env/`` and its data beside the
    machine's stack (the review's case): ``destroy`` is green and leaves it
    byte for byte. The pair: the machine's ``/opt/aivis`` is down to its mark
    and ``minted.yaml``."""
    root, box = box_with_release(tmp_path, set())
    home = _with_minted(root)
    myapp = root / "opt" / "myapp"
    (myapp / "env" / "bin").mkdir(parents=True)
    (myapp / "env" / "bin" / "python").write_text("#!/bin/sh\n")
    (myapp / "data").mkdir()
    (myapp / "data" / "db.sqlite").write_bytes(b"SQLite format 3\x00rows")
    (myapp / "releases").mkdir()
    before = _tree(myapp)
    with box.lock("destroy"), FakeRunner(docker(False), docker(False)) as runner:
        outcome = run(root, box, runner)
    assert outcome.code is ExitCode.OK, outcome.steps
    assert _tree(myapp) == before
    assert sorted(str(p.relative_to(home)) for p in home.rglob("*")) == [
        ".pridem",
        "env",
        "env/minted.yaml",
    ]


def test_opt_pridem_keeps_all_but_the_edge_and_the_proxy(tmp_path: Path) -> None:
    """Item 5 of the card: ``/opt/pridem`` holds what an old guess took for a
    stack (``releases/``, ``env/``, ``git/HEAD``) -- it is not one: only
    ``edge/`` and ``egress/`` go, ``state.json`` by ``forget_state``."""
    root, box = box_with_release(tmp_path, set())
    pridem = root / "opt" / "pridem"
    for part in ("releases/r1", "env", "git", "history", "keys"):
        (pridem / part).mkdir(parents=True, exist_ok=True)
    (pridem / "git" / "HEAD").write_text("ref\n")
    (pridem / "env" / "x").write_text("x\n")
    (pridem / "passport.yaml").write_text("x\n")
    for gone in ("edge", "egress"):
        (pridem / gone).mkdir()
    with box.lock("destroy"), FakeRunner(docker(False), docker(False)) as runner:
        outcome = run(root, box, runner)
    assert outcome.code is ExitCode.OK, outcome.steps
    for kept in (
        "releases/r1",
        "env/x",
        "git/HEAD",
        "history",
        "keys",
        "passport.yaml",
    ):
        assert (pridem / kept).exists(), kept
    for gone in ("edge", "egress", "state.json"):
        assert not (pridem / gone).exists(), gone


def test_a_mark_naming_another_stack_refuses_before_any_removal(tmp_path: Path) -> None:
    """``foreign-marker``: a directory the machine cannot place -- refused in
    ``remove_objects``, before the point of no return, nothing called."""
    root, box = box_with_release(tmp_path, set())
    stray = root / "opt" / "copied"
    stray.mkdir()
    (stray / ".pridem").write_text("aivis\n")
    with box.lock("destroy"), FakeRunner() as runner:
        outcome = run(root, box, runner)
    reason = outcome.steps[0].reason
    assert reason is not None and reason.code == "remove_objects:foreign-marker"
    assert reason.params == {"paths": [str(stray)]}
    assert (root / "opt" / "aivis" / "current").exists()


def test_the_kept_volumes_outlive_destroy(tmp_path: Path) -> None:
    """The volume of a persistent entry is written to ``kept-volumes.json``
    before the first removal; the next ``destroy`` -- no ``state.json``, no
    ``current`` -- keeps it by the file and is green."""
    root, box = box_with_release(tmp_path, {"storage"})
    seen = listed(("c1",), (), ("files\tstorage",))
    script = [
        docker(),
        *seen,
        docker(),
        *seen,
        FakeCall(("docker", "rm", "-f", "c1")),
        *listed(volumes=("files\tstorage",)),
    ]
    with box.lock("destroy"), FakeRunner(*script) as runner:
        assert run(root, box, runner).code is ExitCode.OK
    kept = json.loads((box.root / "kept-volumes.json").read_text())
    assert kept == {"schema": 1, "volumes": {"files": "storage"}}
    assert not (box.root / "state.json").exists()
    script = [docker(), *listed(volumes=("files\tstorage",))] * 1
    script += listed(volumes=("files\tstorage",))
    with box.lock("destroy"), FakeRunner(*script) as runner:
        again = run(root, box, runner)
    assert again.code is ExitCode.OK, again.steps
    assert again.steps[0].verify["kept_volumes"] == ["files"]


def test_the_file_is_written_before_the_first_removal(tmp_path: Path) -> None:
    """D5: the first ``docker rm`` fails -- the file is already on disk."""
    root, box = box_with_release(tmp_path, {"storage"})
    seen = listed(("c1",), (), ("files\tstorage", "db\taivis"))
    script = [
        docker(),
        *seen,
        docker(),
        *seen,
        FakeCall(("docker", "rm", "-f", "c1"), code=1),
    ]
    with box.lock("destroy"), FakeRunner(*script) as runner:
        outcome = run(root, box, runner)
    assert outcome.steps[0].status == "failed"
    kept = json.loads((box.root / "kept-volumes.json").read_text())
    assert kept["volumes"] == {"files": "storage"}


def test_a_repeat_after_the_release_is_gone_keeps_the_volume(tmp_path: Path) -> None:
    """Twin REPEAT: the first ``destroy`` stops after ``remove_files`` took
    ``current`` (its timers fail); ``state.json`` stays but names a release
    nobody can read -- the repeat keeps the volume by the file."""
    root, box = box_with_release(tmp_path, {"storage"})
    units = root / UNIT_DIR
    units.mkdir(parents=True)
    (units / "pridem-gc.timer").write_text("[Timer]\n")
    seen = listed(("c1",), (), ("files\tstorage",))
    failing = FakeCall(("systemctl", "disable", "--now", "pridem-gc.timer"), code=1)
    script = [
        docker(),
        *seen,
        docker(),
        *seen,
        FakeCall(("docker", "rm", "-f", "c1")),
        *listed(volumes=("files\tstorage",)),
        failing,
    ]
    with box.lock("destroy"), FakeRunner(*script) as runner:
        first = run(root, box, runner)
    assert first.code is not ExitCode.OK
    assert (box.root / "state.json").exists()
    assert not (root / "opt" / "aivis" / "current").exists()
    script = [
        docker(),
        *listed(volumes=("files\tstorage",)),
        *listed(volumes=("files\tstorage",)),
        FakeCall(("systemctl", "disable", "--now", "pridem-gc.timer")),
        FakeCall(("systemctl", "daemon-reload")),
    ]
    with box.lock("destroy"), FakeRunner(*script) as runner:
        again = run(root, box, runner)
    assert again.code is ExitCode.OK, again.steps
    assert again.steps[0].verify["kept_volumes"] == ["files"]


def test_a_volume_of_an_entry_no_longer_named_is_never_removed(tmp_path: Path) -> None:
    """A volume whose entry the current ``primer.yaml`` no longer has (renamed
    or removed): ``persistent-unknown``, by name, nothing removed. The pair:
    an entry it names without ``persistent`` -- the volume goes."""
    root, box = box_with_release(tmp_path, set())
    with (
        box.lock("destroy"),
        FakeRunner(docker(), *listed(volumes=("old\tgone", "db\taivis"))) as r,
    ):
        outcome = run(root, box, r)
    reason = outcome.steps[0].reason
    assert reason is not None and reason.code == "remove_objects:persistent-unknown"
    assert reason.params == {"volumes": ["old"]}
    seen = listed(volumes=("db\taivis",))
    script = [
        docker(),
        *seen,
        docker(),
        *seen,
        FakeCall(("docker", "volume", "rm", "db")),
    ]
    script += listed()
    with box.lock("destroy"), FakeRunner(*script) as runner:
        assert run(root, box, runner).steps[0].status == "ok"


def test_persistent_wins_where_the_sources_differ(tmp_path: Path) -> None:
    """The file keeps ``db``; the current ``primer.yaml`` says its entry is
    not persistent -- the volume stays (people's data is never removed by
    guess)."""
    root, box = box_with_release(tmp_path, set())
    (box.root / "kept-volumes.json").write_text(
        json.dumps({"schema": 1, "volumes": {"db": "aivis"}})
    )
    seen = listed(("c1",), (), ("db\taivis",))
    script = [docker(), *seen, docker(), *seen, FakeCall(("docker", "rm", "-f", "c1"))]
    script += listed(volumes=("db\taivis",))
    with box.lock("destroy"), FakeRunner(*script) as runner:
        outcome = run(root, box, runner)
    assert outcome.code is ExitCode.OK, outcome.steps
    assert outcome.steps[0].verify["kept_volumes"] == ["db"]


def test_new_secrets_with_volumes_kept_is_refused(tmp_path: Path) -> None:
    """``reinstall --new-secrets`` against a kept volume: refused before the
    point of no return, the volume named. The pair: no volume kept -- the
    minted secrets go as before."""
    root, box = box_with_release(tmp_path, {"storage"})
    with (
        box.lock("destroy"),
        FakeRunner(docker(), *listed(volumes=("files\tstorage",))) as runner,
    ):
        outcome = run(root, box, runner, new_secrets=True)
    reason = outcome.steps[0].reason
    assert reason is not None and reason.code == "remove_objects:new-secrets-kept"
    assert reason.params == {"volumes": ["files"]}
    assert (root / "opt" / "aivis" / "current").exists()
    _with_minted(root)
    script = [docker(), *listed(), *listed()]
    with box.lock("destroy"), FakeRunner(*script) as runner:
        assert run(root, box, runner, new_secrets=True).code is ExitCode.OK
    assert not (root / "opt" / "aivis").exists()


def test_the_volumes_of_the_machines_own_stacks_go(tmp_path: Path) -> None:
    """DM-76 FIX: the edge's ACME webroot (``pridem.stack=edge``), and any
    volume of the proxy or the host's networks, is the machine's -- no record
    of a product names it, and it goes, as before DM-76. The pair: a volume
    whose label nobody names is ``persistent-unknown``
    (``test_a_volume_of_an_entry_no_longer_named_is_never_removed``)."""
    root, box = box_with_release(tmp_path, set())
    seen = listed(volumes=("pridem-edge_acme\tedge", "x\tegress", "y\thost"))
    removal = FakeCall(("docker", "volume", "rm", "pridem-edge_acme", "x", "y"))
    script = [docker(), *seen, docker(), *seen, removal, *listed()]
    with box.lock("destroy"), FakeRunner(*script) as runner:
        outcome = run(root, box, runner)
    assert outcome.steps[0].status == "ok", outcome.steps
    assert outcome.steps[0].verify["kept_volumes"] == []
