"""DM-106 FIX: an anonymous volume compose handed over to the container it
recreated is not that container's own -- ``rm -v`` leaves it (measured on a
live daemon). ``remove_objects`` and the proxy's removal read the anonymous
volumes their containers mount before they go, and remove those no container
mounts any more; a named volume -- ``persistent`` among them -- is never in
the list."""

from pathlib import Path

from test_steps_destroy import box_with_release, docker, listed, mounts, run

from pridem.report.codes import ExitCode
from pridem.runner import FakeCall, FakeRunner

ANONYMOUS = (
    "docker",
    "volume",
    "ls",
    "-q",
    "--filter",
    "label=com.docker.volume.anonymous",
)
DANGLING = ("docker", "volume", "ls", "-q", "--filter", "dangling=true")


def _lines(*items: str) -> tuple[tuple[object, str], ...]:
    from pridem.runner import Stream

    return tuple((Stream.STDOUT, item) for item in items)


def _script(dangling: tuple[str, ...], after: tuple[str, ...]) -> list[FakeCall]:
    """``c1`` mounts the anonymous ``anon1``, the persistent ``files`` and the
    entry's named ``db``: only ``anon1`` is anonymous."""
    seen = listed(("c1",), ("pridem",), ("files\tstorage", "db\taivis"), ("sha256:1",))
    calls = [
        docker(),
        *seen,
        docker(),
        *seen,
        mounts("c1", names=("anon1", "files", "db")),
        FakeCall(ANONYMOUS, lines=_lines("anon1", "stranger")),  # type: ignore[arg-type]
        FakeCall(("docker", "rm", "-f", "-v", "c1")),
        FakeCall(DANGLING, lines=_lines(*dangling)),  # type: ignore[arg-type]
    ]
    if "anon1" in dangling:
        calls.append(FakeCall(("docker", "volume", "rm", "--", "anon1")))
    calls += [
        FakeCall(("docker", "volume", "rm", "db")),
        FakeCall(("docker", "network", "rm", "pridem")),
        FakeCall(("docker", "image", "rm", "-f", "sha256:1")),
        *listed(volumes=("files\tstorage",)),
    ]
    if "anon1" in dangling:
        calls.append(FakeCall(("docker", "volume", "ls", "-q"), lines=_lines(*after)))  # type: ignore[arg-type]
    return calls


def test_a_handed_over_anonymous_volume_goes_and_persistent_stays(
    tmp_path: Path,
) -> None:
    """``c1`` was recreated: ``anon1`` is not its own. Read before ``rm``,
    removed after it once no container mounts it; ``files`` (persistent) and
    ``db`` are named -- not in the list; ``files`` stays, ``db`` goes by the
    entry's volumes as before. The fact names what went."""
    root, box = box_with_release(tmp_path, {"storage"})
    # after rm all three are dangling -- the persistent files among them: the
    # list is the anonymous mounts only, so files is never asked to go
    script = _script(("anon1", "files", "db"), ("files",))
    with box.lock("destroy"), FakeRunner(*script) as runner:
        outcome = run(root, box, runner)
    assert outcome.code is ExitCode.OK, outcome.steps
    fact = outcome.steps[0].verify
    assert fact is not None
    assert fact["kept_volumes"] == ["files"]
    assert fact["anonymous_volumes"] == ["anon1"]
    assert "anonymous_held" not in fact


def test_an_anonymous_volume_another_container_mounts_is_left_and_named(
    tmp_path: Path,
) -> None:
    """``anon1`` still mounted (``volumes_from``, someone else's container):
    not dangling -- left, ``volume rm`` not asked, named in the fact."""
    root, box = box_with_release(tmp_path, {"storage"})
    with box.lock("destroy"), FakeRunner(*_script((), ())) as runner:
        outcome = run(root, box, runner)
    assert outcome.code is ExitCode.OK, outcome.steps
    fact = outcome.steps[0].verify
    assert fact is not None
    assert fact["anonymous_held"] == ["anon1"]
    assert "anonymous_volumes" not in fact


def test_an_anonymous_volume_still_there_after_its_removal_is_red(
    tmp_path: Path,
) -> None:
    """Read back: ``anon1`` removed and still listed -- ``remove_objects:left``."""
    root, box = box_with_release(tmp_path, {"storage"})
    script = _script(("anon1",), ("files", "anon1"))
    with box.lock("destroy"), FakeRunner(*script) as runner:
        outcome = run(root, box, runner)
    reason = outcome.steps[0].reason
    assert reason is not None and reason.code == "remove_objects:left"


def test_the_proxy_takes_the_anonymous_volume_it_was_handed(tmp_path: Path) -> None:
    """The proxy is recreated by every ``up``: its anonymous volume (if squid's
    image declares one) is read before it goes and removed after."""
    from compose_support import run as egress_run
    from test_steps_egress import (
        PROXY,
        ZOOM,
        Proxy,
        _mounts,
        _project,
        call,
        ps,
        step,
        write,
    )

    write(tmp_path, ZOOM)
    script = [
        ps(PROXY, every=True),
        ps(PROXY, every=True),
        _mounts("spool"),
        call(*ANONYMOUS, lines=("spool",)),
        _project(tmp_path, "rm", "-s", "-f", "-v"),
        _project(tmp_path, "down"),
        call(*DANGLING, lines=("spool",)),
        call("docker", "volume", "rm", "--", "spool"),
        ps(every=True),
    ]
    with FakeRunner(*script) as runner:
        outcome, _ = egress_run([step(tmp_path, [], Proxy([]))], runner)
    assert outcome.code is ExitCode.OK, outcome.steps
