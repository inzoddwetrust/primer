"""The probes of DM-126: a first install that can be repeated and taken off.

1. The tests of every entry of the product run before the first ``migrate``
   of any stack (owner's decision of 19.11); a seam is ready with the
   provider's environment, not its health.
2. ``destroy`` takes a first install that never reached ``finalize``: with no
   ``state.json`` the entries are those of the releases on the disk.
3. A job with no record of a good run is run again, alone, though every
   service of its entry is up.
4. A key no run saw work steadily is fresh in the next run.
5. ``docker-buildx`` comes with docker; the plugin's answer is in the fact.
"""

import copy
import json
from datetime import UTC, datetime
from itertools import count
from pathlib import Path

import pytest
import yaml
from compose_support import (
    APP_IMAGE,
    CONFIG,
    CONTAINER,
    HASHES,
    LiveApp,
    config_call,
    hash_calls,
    image_call,
    inspect_image_call,
    observe_calls,
    ps_call,
    stdout,
)
from compose_support import run as run_up
from env_support import box as env_box
from env_support import context, passport_data, read_env, render
from env_support import product as product_stack
from env_support import run as run_env
from env_support import service as service_stack
from plan_support import Journal, ListSink, ScriptedStep
from services_support import deferred, planned
from test_probe_DM_22_forms import (
    JOB_HASHES,
    JOBBED,
    cs_of,
    data,
    hashed,
    jobbed,
    run_argv,
    up_argv,
    up_of,
    verifying,
)
from test_probe_DM_22_forms import made as made_of
from test_steps_destroy import box_with_release, docker, listed, mounts
from test_steps_destroy import run as run_destroy
from test_steps_host import BUILDX, BUILDX_SAYS, active, box, call, dpkg
from test_steps_host import run as run_host
from test_steps_keys import ADDRESS, PUBLIC, _key_in_place, keygen, lsremote
from test_steps_keys import run as run_key
from test_steps_up import app as app  # noqa: F401 -- the fixture

from pridem.events import Code, PlanOutcome
from pridem.plan import Deferred, Plan, StackSteps
from pridem.report.codes import ExitCode
from pridem.runner import FakeCall, FakeRunner
from pridem.stacks.seams import SeamMemory, SeamNotReady
from pridem.state import Box
from pridem.steps.base import StepFailed
from pridem.steps.compose import ComposeStack
from pridem.steps.destroy import KEPT
from pridem.steps.git import KEYS, repo
from pridem.steps.host import HOST_PACKAGES, ProvisionHost
from pridem.steps.keys import FRESH_SUFFIX, STEADY, DeployKey, FreshKeys, WriteKey
from pridem.steps.sources import MARKER
from pridem.steps.up import job_record
from pridem.verbs.run import Planned

# --- 1. tests before the first migrate -------------------------------------------


def _second_entry(data: dict[str, object]) -> None:
    """The product gets a second entry with its own app, tests and migrate."""
    stacks = data["stacks"]
    assert isinstance(stacks, dict)
    stacks["files"] = {
        "compose": "files-compose.yml",
        "app": {"service": "api", "port": 8100, "health": "/health", "ready": "/ready"},
        "migrate": "python -m alembic upgrade head",
        "test": {
            "run": "python -m pytest tests/ --junitxml=/tmp/junit.xml",
            "target": "test",
        },
    }


def _order(made: Planned) -> list[tuple[str, str]]:
    """The ladder as it runs: what ``pridem-services`` makes, then what
    ``pridem-product`` makes."""
    return [
        (stack.name, step.name)
        for name in ("pridem-services", "pridem-product")
        for stack in deferred(made, name)
        for step in sorted(stack.steps, key=lambda s: s.order)
    ]


def _as_scripted(
    made: Planned, journal: Journal, red: tuple[str, str] | None
) -> list[Deferred]:
    """The ladder of the plan builder with every step a scripted one of the
    same stack, name and order -- ``migrate`` the point of no return, as the
    real one; ``red`` fails in ``verify``."""

    def build(name: str) -> list[StackSteps]:
        return [
            StackSteps(
                stack.name,
                [
                    ScriptedStep(
                        step.name,
                        step.order,
                        journal,
                        point_of_no_return=step.point_of_no_return,
                        verify_raises=(
                            StepFailed("wrong-state", {"seen": "x"}, {"seen": "x"})
                            if (stack.name, step.name) == red
                            else None
                        ),
                    )
                    for step in stack.steps
                ],
            )
            for stack in deferred(made, name)
        ]

    return [
        Deferred(name, lambda name=name: build(name), after="fetch_root")  # type: ignore[misc]
        for name in ("pridem-services", "pridem-product")
    ]


def _run_scripted(stacks: list[Deferred]) -> PlanOutcome:
    ticks = count()
    return Plan(
        [*stacks, StackSteps("root", [], root=True)],
        mode="install",
        role="test",
        runner=FakeRunner(),
        sink=ListSink(),
        clock=lambda: float(next(ticks)),
        now=lambda: datetime(2026, 11, 19, tzinfo=UTC),
    ).run()


def test_probe_DM_126_tests_of_every_entry_before_the_first_migrate(
    tmp_path: Path,
) -> None:
    """Two services that migrate, a product of two entries that each test and
    migrate: every ``tests`` stands before every ``migrate`` -- of a service
    and of the product's other entry -- and before every ``up`` of an
    application; ``up`` of the product after ``up`` of each service. Red
    tests of the second entry: no ``migrate``, no ``stop_for_migrate``, no
    ``up`` begins, and no restore is needed. The pair: green tests -- every
    ``migrate`` and ``up`` of the ladder runs, the tests before them."""
    made, _ = planned(tmp_path, "full", product_patch=_second_entry)
    order = _order(made)
    tests = [at for at, (_, name) in enumerate(order) if name == "tests"]
    migrates = [at for at, (_, name) in enumerate(order) if name == "migrate"]
    ups = [at for at, (_, name) in enumerate(order) if name == "up"]
    assert [order[at][0] for at in tests] == ["aivis", "files"], order
    assert [order[at][0] for at in migrates] == [
        "comms",
        "payments",
        "aivis",
        "files",
    ], order
    assert max(tests) < min(migrates) and max(tests) < min(ups), order
    assert max(tests) < order.index(("comms", "stop_for_migrate")), order
    for service in ("comms", "payments"):
        assert order.index((service, "up")) < order.index(("aivis", "up")), order
    assert len(order) == len(set(order)), order  # one step per (stack, name)

    journal = Journal()
    red = _run_scripted(_as_scripted(made, journal, ("files", "tests")))
    assert red.code is ExitCode.FAILED
    assert not red.needs_restore
    acted = [line for line in journal if line.endswith(":act")]
    assert "files/tests:act" in acted and "aivis/tests:act" in acted
    assert not [
        line
        for line in journal
        if line.split("/")[1].split(":")[0] in ("migrate", "stop_for_migrate", "up")
    ], journal
    # the pair: green -- the same ladder goes through every migrate and up
    journal = Journal()
    green = _run_scripted(_as_scripted(made, journal, None))
    assert green.code is ExitCode.OK, green.steps
    acted = [line for line in journal if line.endswith(":act")]
    assert [line for line in acted if "/migrate:" in line] == [
        "comms/migrate:act",
        "payments/migrate:act",
        "aivis/migrate:act",
        "files/migrate:act",
    ]
    assert acted.index("files/tests:act") < acted.index("comms/migrate:act")


def test_red_after_the_first_migrate_still_needs_a_restore(tmp_path: Path) -> None:
    """The pair of the probe on the other side of the point: a step red after
    a ``migrate`` that acted is past it."""
    made, _ = planned(tmp_path, "full", product_patch=_second_entry)
    red = _run_scripted(_as_scripted(made, Journal(), ("comms", "up")))
    assert red.code is ExitCode.FAILED and red.needs_restore


COMMS = {"comms": {"repo": "git@github.com:a/comms.git", "version": ">=1,<2"}}
SEAM_ENV = {
    "COMMS_API_URL": {"source": "address"},
    "COMMS_SERVICE_TOKEN": {"source": "minted"},
}


def test_a_seam_is_ready_with_the_providers_environment(tmp_path: Path) -> None:
    """A service with nothing to derive: its ``render_env`` read its
    ``next.env`` back -- its ``provides`` are in the plan's memory, no ``up``
    and no health asked, and the product renders with them. Before it: not
    ready. (It replaces ``test_seams_reach_the_memory_after_health`` of
    ``test_steps_up.py``: ``up`` no longer gives the seams, owner's decision
    of 19.11.)"""
    comms = service_stack(
        tmp_path, SEAM_ENV, provides=["COMMS_API_URL", "COMMS_SERVICE_TOKEN"]
    )
    made = product_stack(
        tmp_path,
        {"COMMS_API_URL": {"source": "seam", "from": "comms"}},
        dependencies={
            "comms": {"repo": "git@github.com:a/comms.git", "version": ">=1,<2"}
        },
    )
    root, fetched = env_box(tmp_path, passport_data())
    memory = SeamMemory()
    with pytest.raises(SeamNotReady):
        memory.values("comms", ["COMMS_API_URL"])
    provider = render(comms, root, fetched, product=made, memory=memory)
    assert run_env([provider], FakeRunner())[0].code is ExitCode.OK
    token = read_env(root, "comms")["COMMS_SERVICE_TOKEN"]
    assert memory.values("comms", ["COMMS_API_URL", "COMMS_SERVICE_TOKEN"]) == {
        "COMMS_API_URL": "http://comms-comms-app:8000",
        "COMMS_SERVICE_TOKEN": token,
    }
    late, _ = run_env([render(made, root, fetched, memory=memory)], FakeRunner())
    assert late.code is ExitCode.OK, late.steps
    assert read_env(root, "aivis")["COMMS_API_URL"] == "http://comms-comms-app:8000"
    # check alone, as doctor runs it, on the env already there: ready again
    again = SeamMemory()
    step = render(comms, root, fetched, product=made, memory=again)
    assert step.check(context(FakeRunner())).needed is False
    assert again.values("comms", ["COMMS_SERVICE_TOKEN"]) == {
        "COMMS_SERVICE_TOKEN": token
    }


def test_a_placeholder_never_reaches_the_consumer(tmp_path: Path) -> None:
    """A service with a value still to derive: ``render_env`` read the file
    back with ``<derived>`` in it -- nothing goes to the memory, and the
    product's ``render_env`` is refused by name. (The value after
    ``derive_env`` reaching the product is the probe of DM-67.)"""
    env = {
        **SEAM_ENV,
        "TELEGRAM_BOT_URL": {"source": "derived", "run": "comms derive bot-url"},
    }
    comms = service_stack(tmp_path, env, provides=["COMMS_API_URL", "TELEGRAM_BOT_URL"])
    made = product_stack(
        tmp_path,
        {"COMMS_API_URL": {"source": "seam", "from": "comms"}},
        dependencies={
            "comms": {"repo": "git@github.com:a/comms.git", "version": ">=1,<2"}
        },
    )
    root, fetched = env_box(tmp_path, passport_data())
    memory = SeamMemory()
    provider = render(comms, root, fetched, product=made, memory=memory)
    assert run_env([provider], FakeRunner())[0].code is ExitCode.OK
    assert read_env(root, "comms")["TELEGRAM_BOT_URL"] == "<derived>"
    with pytest.raises(SeamNotReady):
        memory.values("comms", ["COMMS_API_URL"])
    early, _ = run_env([render(made, root, fetched, memory=memory)], FakeRunner())
    assert early.steps[0].reason is not None
    assert early.steps[0].reason.code == "render_env:seam-before-health"


# --- 2. destroy of an install that never reached finalize ------------------------


def _interrupted(tmp: Path, persistent: set[str]) -> tuple[Path, Box]:
    """A first install cut before ``finalize``: the release on the disk under
    the stack's mark, no ``current``, no ``state.json``."""
    root, made = box_with_release(tmp, persistent)
    (made.root / "state.json").unlink()
    (root / "opt" / "aivis" / "current").unlink()
    return root, made


def test_probe_DM_126_destroy_takes_an_interrupted_first_install(
    tmp_path: Path,
) -> None:
    """No ``state.json`` and no ``current``: the entries are those of the
    release on the disk -- the volume of ``aivis`` goes, the volume of the
    persistent ``storage`` stays and is written to ``kept-volumes.json``
    before the first removal. The pair: the same box whose release has no
    ``primer.yaml`` -- ``persistent-unknown``, nothing removed."""
    root, made = _interrupted(tmp_path, {"storage"})
    seen = listed(("c1",), ("pridem",), ("files\tstorage", "db\taivis"), ("sha256:1",))
    script = [
        docker(),
        *seen,
        docker(),
        *seen,
        mounts("c1"),
        FakeCall(("docker", "rm", "-f", "-v", "c1")),
        FakeCall(("docker", "volume", "rm", "db")),
        FakeCall(("docker", "network", "rm", "pridem")),
        FakeCall(("docker", "image", "rm", "-f", "sha256:1")),
        *listed(volumes=("files\tstorage",)),
    ]
    with made.lock("destroy"), FakeRunner(*script) as runner:
        outcome = run_destroy(root, made, runner)
    assert outcome.code is ExitCode.OK, outcome.steps
    assert outcome.steps[0].verify is not None
    assert outcome.steps[0].verify["kept_volumes"] == ["files"]
    kept = json.loads((made.root / KEPT).read_text())
    assert kept["volumes"] == {"files": "storage"}
    assert not (root / "opt" / "aivis" / "releases").exists()
    # the pair: no primer.yaml to read -- never by guess
    root, made = _interrupted(tmp_path / "pair", set())
    (root / "opt" / "aivis" / "releases" / "9a1c4e2" / "primer.yaml").unlink()
    with (
        made.lock("destroy"),
        FakeRunner(docker(), *listed(volumes=("db\taivis",))) as runner,
    ):
        outcome = run_destroy(root, made, runner)
    reason = outcome.steps[0].reason
    assert reason == Code("remove_objects:persistent-unknown", {"volumes": ["db"]})


def _release(root: Path, name: str, persistent: bool, stack: str = "aivis") -> Path:
    """One more release of ``aivis`` on the disk, its entry ``storage``
    persistent or not; ``stack`` -- the ``name`` its ``primer.yaml`` says."""
    first = root / "opt" / "aivis" / "releases" / "9a1c4e2" / "primer.yaml"
    data = yaml.safe_load(first.read_text())
    data["name"] = stack
    data["stacks"]["storage"] = {"compose": "storage.yml", "persistent": persistent}
    release = root / "opt" / "aivis" / "releases" / name
    release.mkdir()
    (release / "primer.yaml").write_text(yaml.safe_dump(data))
    return release


def _refused(root: Path, made: Box) -> Code | None:
    seen = listed(volumes=("files\tstorage",))
    with made.lock("destroy"), FakeRunner(docker(), *seen) as runner:
        return run_destroy(root, made, runner).steps[0].reason


@pytest.mark.parametrize("later", ["0000000", "fffffff"])
def test_persistent_in_any_release_on_the_disk_wins(tmp_path: Path, later: str) -> None:
    """Two releases of an install that never finished: the entry is
    persistent in one and not in the other -- its volume stays, whichever the
    disk lists first (``--new-secrets`` is refused by it: the volume is
    kept)."""
    root, made = _interrupted(tmp_path, set())
    _release(root, later, persistent=True)
    seen = listed(volumes=("files\tstorage",))
    with made.lock("destroy"), FakeRunner(docker(), *seen) as runner:
        outcome = run_destroy(root, made, runner, new_secrets=True)
    assert outcome.steps[0].reason == Code(
        "remove_objects:new-secrets-kept", {"volumes": ["files"]}
    )


def test_a_package_among_the_releases_and_another_stacks_file_say_nothing(
    tmp_path: Path,
) -> None:
    """Twin SHORTAGE: the only ``primer.yaml`` naming the entry lies in a
    package of the instance (``<name>@<version>``), or says another stack's
    name than its directory -- neither places the volume:
    ``persistent-unknown``. The pair: the same file in a release of the
    stack, under the stack's name, places it (the volume is kept)."""
    root, made = _interrupted(tmp_path / "package", set())
    first = root / "opt" / "aivis" / "releases" / "9a1c4e2"
    data = yaml.safe_load((first / "primer.yaml").read_text())
    del data["stacks"]["storage"]
    (first / "primer.yaml").write_text(yaml.safe_dump(data))
    _release(root, "velo-look@1.4.2", persistent=False)
    unknown = Code("remove_objects:persistent-unknown", {"volumes": ["files"]})
    assert _refused(root, made) == unknown

    root, made = _interrupted(tmp_path / "other", set())
    first = root / "opt" / "aivis" / "releases" / "9a1c4e2"
    (first / "primer.yaml").write_text(yaml.safe_dump(data))
    _release(root, "abcdef0", persistent=False, stack="velo")
    assert _refused(root, made) == unknown

    # the pair: a release of the stack itself names the entry
    root, made = _interrupted(tmp_path / "own", set())
    first = root / "opt" / "aivis" / "releases" / "9a1c4e2"
    (first / "primer.yaml").write_text(yaml.safe_dump(data))
    _release(root, "abcdef0", persistent=True)
    seen = listed(volumes=("files\tstorage",))
    with made.lock("destroy"), FakeRunner(docker(), *seen, *seen) as runner:
        outcome = run_destroy(root, made, runner)
    assert outcome.steps[0].status == "ok", outcome.steps
    assert outcome.steps[0].verify is not None
    assert outcome.steps[0].verify["kept_volumes"] == ["files"]


def test_a_directory_without_the_mark_names_no_entry(tmp_path: Path) -> None:
    """Twin EMPTINESS: the release lies under ``/opt/<n>`` with no mark of the
    machine -- not the machine's stack, its ``primer.yaml`` is not read."""
    root, made = _interrupted(tmp_path, set())
    (root / "opt" / "aivis" / MARKER).unlink()
    with (
        made.lock("destroy"),
        FakeRunner(docker(), *listed(volumes=("db\taivis",))) as runner,
    ):
        outcome = run_destroy(root, made, runner)
    assert outcome.steps[0].reason == Code(
        "remove_objects:persistent-unknown", {"volumes": ["db"]}
    )
    (root / "opt" / "aivis" / MARKER).write_text("aivis\n")  # the pair: read
    seen = listed(volumes=("db\taivis",))
    script = [
        docker(),
        *seen,
        docker(),
        *seen,
        FakeCall(("docker", "volume", "rm", "db")),
        *listed(),
    ]
    with made.lock("destroy"), FakeRunner(*script) as runner:
        assert run_destroy(root, made, runner).steps[0].status == "ok"


# --- 3. a job with no record of a good run -----------------------------------------


def _all_up(cs: ComposeStack) -> list[FakeCall]:
    """``check`` of ``up`` on an entry whose every service runs as it should:
    the image, the configuration, the live checks -- then the jobs' hashes."""
    return [
        image_call(cs, "app", APP_IMAGE),
        ps_call(cs, CONTAINER),
        inspect_image_call(CONTAINER, APP_IMAGE),
        *hash_calls(cs, running=HASHES, expected=JOB_HASHES),
        *observe_calls(cs),
        hashed(cs),
    ]


def test_probe_DM_126_a_failed_job_runs_again(
    tmp_path: Path,
    app: LiveApp,  # noqa: F811
) -> None:
    """The job failed on the first run -- red, no record. Then every service
    of the entry is up as it should be (the one the job needs came up before
    it failed; here all of them): the repeat still acts -- the job alone,
    after what it needs, no other ``up`` -- its fact names it and its record
    is written; ``doctor`` before the repeat says ``up`` has something to do.
    The pair: after the good run the same box needs no ``act`` and runs no
    job."""
    stack = jobbed(app.port)
    cs = cs_of(stack, tmp_path)
    record = job_record(cs, "init")
    first = [
        image_call(cs, "app", APP_IMAGE),
        ps_call(cs),
        *_acting_until_the_job(cs),
        FakeCall(run_argv(cs, "init"), code=1, lines=stdout("init: no bucket")),
    ]
    with FakeRunner(*first) as runner:
        red, _ = run_up([up_of(stack, tmp_path)], runner)
    assert red.code is ExitCode.FAILED and not record.exists()

    with FakeRunner(*_all_up(cs)) as runner:  # doctor: check alone
        found = up_of(stack, tmp_path).check(context(runner))
    assert found.needed and found.would is not None and found.would.code == "up"
    assert found.data["jobs"] == ["init"]

    again = [
        *_all_up(cs),
        *_acting_until_the_job(cs),
        FakeCall(run_argv(cs, "init"), lines=stdout("init: done")),
        *verifying(cs),  # no up of the rest: the script has none
    ]
    with FakeRunner(*again) as runner:
        outcome, _ = run_up([up_of(stack, tmp_path)], runner)
    assert outcome.code is ExitCode.OK, outcome.steps
    assert outcome.steps[0].verify is not None
    assert outcome.steps[0].verify["jobs"] == ["init"]
    assert record.read_text() == JOB_HASHES["init"] + "\n"
    # the pair: the job ended well -- nothing to do, no job in the fact
    with FakeRunner(*_all_up(cs), *verifying(cs)) as runner:
        outcome, _ = run_up([up_of(stack, tmp_path)], runner)
    assert outcome.code is ExitCode.OK, outcome.steps
    assert outcome.steps[0].verify is not None
    assert "jobs" not in outcome.steps[0].verify


def _acting_until_the_job(cs: ComposeStack) -> list[FakeCall]:
    return [
        config_call(cs, JOBBED),
        hashed(cs),
        FakeCall(up_argv(cs, "postgres")),
    ]


def test_a_record_of_another_configuration_is_no_record(
    tmp_path: Path,
    app: LiveApp,  # noqa: F811
) -> None:
    """Twin SHORTAGE: the record holds the hash of the job's configuration of
    an earlier deploy -- the job ran well on something else: it runs again.
    The pair is the probe's: the record of this configuration -- no run."""
    stack = jobbed(app.port)
    cs = cs_of(stack, tmp_path)
    record = job_record(cs, "init")
    record.parent.mkdir(parents=True)
    record.write_text("0" * 64 + "\n")
    script = [
        *_all_up(cs),
        *_acting_until_the_job(cs),
        FakeCall(run_argv(cs, "init")),
        *verifying(cs),
    ]
    with FakeRunner(*script) as runner:
        outcome, _ = run_up([up_of(stack, tmp_path)], runner)
    assert outcome.code is ExitCode.OK, outcome.steps
    assert record.read_text() == JOB_HASHES["init"] + "\n"


def test_of_two_jobs_the_one_without_a_record_runs_alone(
    tmp_path: Path,
    app: LiveApp,  # noqa: F811
) -> None:
    """``first`` ended well on this configuration, ``second`` has no record:
    ``second`` alone runs, after the service it needs -- no run of ``first``
    in the strict script. The fact names ``second``."""
    stack = made_of(
        data(
            app.port,
            jobs={"first": {"service": "first"}, "second": {"service": "second"}},
        )
    )
    document = copy.deepcopy(CONFIG)
    services = document["services"]
    assert isinstance(services, dict)
    services["first"] = {"image": "j@sha256:x"}
    services["second"] = {
        "image": "j@sha256:x",
        "depends_on": {"first": {}, "postgres": {}},
    }
    cs = cs_of(stack, tmp_path)
    hashes = {**HASHES, "first": "2" * 64, "second": "3" * 64}
    record = job_record(cs, "first")
    record.parent.mkdir(parents=True)
    record.write_text(hashes["first"] + "\n")
    script = [
        image_call(cs, "app", APP_IMAGE),
        ps_call(cs, CONTAINER),
        inspect_image_call(CONTAINER, APP_IMAGE),
        *hash_calls(cs, running=HASHES, expected=hashes),
        *observe_calls(cs),
        hashed(cs, hashes),
        config_call(cs, document),
        hashed(cs, hashes),
        FakeCall(up_argv(cs, "postgres")),
        FakeCall(run_argv(cs, "second")),
        hashed(cs, hashes),
        image_call(cs, "app", APP_IMAGE),
        ps_call(cs, CONTAINER),
        inspect_image_call(CONTAINER, APP_IMAGE),
        *hash_calls(cs, running=HASHES, expected=hashes),
        *observe_calls(cs),
    ]
    with FakeRunner(*script) as runner:
        outcome, _ = run_up([up_of(stack, tmp_path)], runner)
    assert outcome.code is ExitCode.OK, outcome.steps
    assert outcome.steps[0].verify is not None
    assert outcome.steps[0].verify["jobs"] == ["second"]
    assert job_record(cs, "second").read_text() == hashes["second"] + "\n"


def test_a_job_whose_record_is_not_written_is_red(
    tmp_path: Path,
    app: LiveApp,  # noqa: F811
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``verify`` reads the records back: a job that ran with no record after
    it is ``jobs-undone``, by name -- never a green step whose next run would
    run the job again without a word."""
    import pridem.steps.up as up_module

    monkeypatch.setattr(up_module, "atomic_write", lambda *args, **kw: None)
    stack = jobbed(app.port)
    cs = cs_of(stack, tmp_path)
    script = [
        *_all_up(cs),
        *_acting_until_the_job(cs),
        FakeCall(run_argv(cs, "init")),
        hashed(cs),
    ]
    with FakeRunner(*script) as runner:
        outcome, _ = run_up([up_of(stack, tmp_path)], runner)
    assert outcome.steps[0].reason == Code(
        "up:jobs-undone", {"entry": cs.entry, "jobs": ["init"]}
    )


# --- 4. a key no run saw steady ---------------------------------------------------


def _mark(root: Path) -> Path:
    key = root / KEYS / repo(ADDRESS).alias
    return key.with_name(key.name + FRESH_SUFFIX)


def test_probe_DM_126_a_key_not_steady_is_fresh_in_the_next_run(
    tmp_path: Path,
) -> None:
    """The run that minted the key ended before the key worked (its wait was
    cut): the mark stays. The next run: one look answers, and it is no
    answer -- the step waits ``STEADY`` looks, the key is in the run's
    ``FreshKeys`` with the end of a whole new wait, and the mark goes. The
    pair: the run after that takes one look and has no fresh key."""
    clock = iter([0.0, 5.0, 11.0])
    first = DeployKey(
        ADDRESS, tmp_path, wait_s=10, clock=lambda: next(clock), sleep=lambda s: None
    )
    cut, _ = run_key(
        tmp_path,
        first,
        [keygen(tmp_path), lsremote(tmp_path, 128), lsremote(tmp_path, 128)],
    )
    assert cut.code is ExitCode.FAILED
    assert (
        _mark(tmp_path).is_file() and (tmp_path / KEYS / repo(ADDRESS).alias).is_file()
    )

    fresh = FreshKeys(tmp_path, clock=lambda: 100.0, sleep=lambda s: None)
    step = DeployKey(
        ADDRESS,
        tmp_path,
        wait_s=1800,
        clock=lambda: 100.0,
        sleep=lambda s: None,
        fresh=fresh,
    )
    looks = [lsremote(tmp_path, 0)] * (1 + STEADY + 1)  # check, the row, verify
    outcome, sink = run_key(tmp_path, step, looks)
    assert outcome.code is ExitCode.OK, outcome.steps
    assert fresh.deadline(repo(ADDRESS)) == 1900.0
    assert not _mark(tmp_path).exists()
    assert PUBLIC in "\n".join(str(event) for event in sink.events)  # shown again
    # the pair: a key a run saw steady -- one look, and it is not fresh
    late = FreshKeys(tmp_path, clock=lambda: 200.0, sleep=lambda s: None)
    step = DeployKey(ADDRESS, tmp_path, fresh=late)
    outcome, _ = run_key(tmp_path, step, [lsremote(tmp_path, 0), lsremote(tmp_path, 0)])
    assert outcome.code is ExitCode.OK, outcome.steps
    assert late.deadline(repo(ADDRESS)) is None


def test_doctor_names_a_key_no_run_saw_steady(tmp_path: Path) -> None:
    """``check`` alone on a key with the mark that answers: ``steady``, and
    nothing on the disk changes. The pair: without the mark -- nothing."""
    from test_steps_keys import _doctor

    from pridem.steps.keys import write_ssh_config

    _key_in_place(tmp_path)
    write_ssh_config(tmp_path, [repo(ADDRESS)])
    _mark(tmp_path).write_text("pridem\n")
    found = _doctor(tmp_path, [lsremote(tmp_path, 0)])
    assert [(d.name, d.reason.code) for d in found.doctor_diff] == [
        ("deploy_key", "deploy_key:steady")
    ]
    assert _mark(tmp_path).is_file()
    _mark(tmp_path).unlink()
    assert _doctor(tmp_path, [lsremote(tmp_path, 0)]).doctor_diff == ()


def test_a_mark_without_a_key_says_nothing(tmp_path: Path) -> None:
    """Twin SHORTAGE: a run died between the mark and the pair -- the mark
    alone. The next run mints, as on a box with nothing, and the key it
    minted has the mark until it is steady."""
    _mark(tmp_path).parent.mkdir(parents=True)
    _mark(tmp_path).write_text("pridem\n")
    step = DeployKey(
        ADDRESS, tmp_path, wait_s=100, clock=lambda: 0.0, sleep=lambda s: None
    )
    calls = [keygen(tmp_path), *[lsremote(tmp_path, 0)] * (STEADY + 1)]
    outcome, _ = run_key(tmp_path, step, calls)
    assert outcome.code is ExitCode.OK, outcome.steps
    assert not _mark(tmp_path).exists()


def test_the_write_key_keeps_no_mark(tmp_path: Path) -> None:
    """The write key waits only in the run that minted it (DM-63 FIX): it is
    minted without the mark, and a mark by its name changes nothing."""
    assert DeployKey.marks_fresh and not WriteKey.marks_fresh
    step = WriteKey(ADDRESS, tmp_path, git_dir=tmp_path / "git", commit="c" * 40)
    assert not step._marked()
    key = step._key
    key.parent.mkdir(parents=True)
    key.write_text("k")
    step._mark.write_text("pridem\n")
    assert not step._marked()


# --- 5. buildx ----------------------------------------------------------------------


def test_probe_DM_126_buildx_comes_with_docker(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A box with docker and no ``docker-buildx``: the step installs exactly
    it, and its fact holds what the plugin says of itself. The pair: the
    package is there and the plugin does not answer -- red by the command,
    not a green host whose ``docker build`` is the classic builder.

    Changed by DM-190, on the dispatcher's word 25.11: provision_host reads
    ``dpkg --audit`` (E12) -- its call is in the scenario, with an empty
    answer, in check and in verify; what the probe asserts is as it was."""
    from test_steps_host import apt_get_env

    from pridem.steps.host import APT_LOCK_TIMEOUT_S

    assert "docker-buildx" in HOST_PACKAGES and "docker.io" in HOST_PACKAGES
    root = box(tmp_path)
    env = apt_get_env(monkeypatch)
    timeout = f"DPkg::Lock::Timeout={APT_LOCK_TIMEOUT_S}"
    before = [dpkg(p, p != "docker-buildx") for p in HOST_PACKAGES]
    apt = [
        call("apt-get", "-o", timeout, "update", env=env),
        call(
            "apt-get",
            "-o",
            timeout,
            "install",
            "-y",
            "--no-install-recommends",
            "docker-buildx",
            env=env,
        ),
    ]
    after = [dpkg(p) for p in HOST_PACKAGES]
    version = call(
        "docker", "version", "--format", "{{.Server.Version}}", lines=("29.1.3",)
    )
    tail = [active("docker", True), version]
    audit = FakeCall(("dpkg", "--audit"))
    script = [*before, audit, *apt, *after, audit, *tail, BUILDX]
    outcome = run_host([ProvisionHost(root)], script)
    assert outcome.code is ExitCode.OK, outcome.steps
    assert outcome.steps[0].verify is not None
    assert outcome.steps[0].verify["buildx"] == BUILDX_SAYS
    assert "docker-buildx" in outcome.steps[0].verify["packages"]  # type: ignore[operator]
    # the pair: installed, and no plugin answers
    dead = call("docker", "buildx", "version", code=1)
    red = run_host([ProvisionHost(root)], [*after, audit, *after, audit, *tail, dead])
    assert red.steps[0].reason == Code(
        "command-failed", {"argv": ["docker", "buildx", "version"], "exit_code": 1}
    )
