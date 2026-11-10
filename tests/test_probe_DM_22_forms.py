"""The forms of ``primer.yaml`` velo waits for (DM-22, part A): jobs of an
entry (contract 3 rule 24), the length of a ``minted`` value, ``roles`` of a
seed, a healthcheck on every service but a job (protocol 3.4)."""

import copy
import re
from collections.abc import Iterator
from datetime import UTC, datetime
from itertools import count
from pathlib import Path

import pydantic
import pytest
import yaml
from compose_support import (
    APP_IMAGE,
    CONFIG,
    CONTAINER,
    ENTRY,
    HASHES,
    HEAD,
    HEALTHCHECK,
    REF,
    SHA,
    LiveApp,
    alembic_call,
    config_call,
    hash_calls,
    heads_call,
    health,
    image_call,
    inspect_image_call,
    live,
    migrate_call,
    observe_calls,
    ps_call,
    run,
    stdout,
)
from env_support import (
    box,
    context,
    minted_of,
    passport_data,
    product,
    read_env,
    render,
)
from env_support import run as run_env
from plan_support import ListSink

from pridem.events import Code, Json, PlanOutcome
from pridem.plan import Plan, StackSteps
from pridem.report.codes import ExitCode
from pridem.runner import FakeCall, FakeRunner
from pridem.stacks.env import MINT_ALPHABET, env_file, mint
from pridem.stacks.schema import PRIMER_YAML, Product, rule_problems
from pridem.steps.base import (
    CheckResult,
    Step,
    StepContext,
    StepFailed,
    Verified,
    Waiting,
)
from pridem.steps.compose import ComposeStack, forbidden, stale
from pridem.steps.migrate import Migrate, StartStopped, StopForMigrate, Stopped
from pridem.steps.up import Up, job_order, needed_by

ONCE = Waiting(deadline_s=0, poll_s=0)
REPORT: dict[str, Json] = {
    "health": "/health",
    "ready": "/ready",
    "logs": "json",
    "junit": True,
}
ALPHABET = re.compile(r"[A-Za-z0-9_-]+")


@pytest.fixture
def app() -> Iterator[LiveApp]:
    yield from live()


# --- the stack ---------------------------------------------------------------------


def data(port: int = 8000, **entry: Json) -> dict[str, Json]:
    """The blank of ``compose_support`` with ``entry``'s fields added."""
    stage: dict[str, Json] = {
        "compose": "docker-compose.yml",
        "app": {"service": "app", "port": port, "health": "/health", "ready": "/ready"},
        "frontend": {"service": "frontend", "port": 80},
        "migrate": "python -m alembic upgrade head",
    }
    stage.update(entry)
    return {
        "schema": 1,
        "name": "blank",
        "kind": "product",
        "editions": {"core": {"services": []}},
        "stacks": {"blank": stage},
        "env": {},
        "host": {
            "domains": ["api"],
            "routes": {"api": {"to": f"app:{port}", "max_body": "1M"}},
        },
        "report": REPORT,
    }


def made(raw: dict[str, Json]) -> Product:
    stack = PRIMER_YAML.validate_python(raw)
    assert isinstance(stack, Product)
    return stack


def jobbed(port: int = 8000) -> Product:
    return made(data(port, jobs={"init": {"service": "init"}}))


JOBBED: dict[str, Json] = copy.deepcopy(CONFIG)
"""``CONFIG`` with the job ``init``: it needs ``postgres``; no service depends
on it in compose (DM-22 FIX: ``forbidden`` refuses that)."""
_services = JOBBED["services"]
assert isinstance(_services, dict)
_services["init"] = {
    "image": "init@sha256:x",
    "depends_on": {"postgres": {"condition": "service_healthy"}},
    "networks": {"default": None},
}
JOB_HASHES = {**HASHES, "init": "1" * 64}


def cs_of(stack: Product, root: Path, commit: str = SHA) -> ComposeStack:
    return ComposeStack(stack, ENTRY, root / "release", REF, commit, root, staged=True)


def up_of(stack: Product, root: Path, commit: str = SHA) -> Up:
    cs = cs_of(stack, root, commit)
    return Up(
        stack,
        ENTRY,
        release=cs.release,
        ref=REF,
        commit=commit,
        root=root,
        waiting=ONCE,
    )


def up_argv(cs: ComposeStack, *services: str) -> tuple[str, ...]:
    head = ("up", "-d", "--no-build", "--wait", "--wait-timeout", "300")
    return tuple(cs.argv(*head, "--no-deps", *services))


def run_argv(cs: ComposeStack, job: str) -> tuple[str, ...]:
    return tuple(cs.argv("run", "--rm", "--no-deps", job))


def acting(cs: ComposeStack, job_code: int = 0) -> list[FakeCall]:
    """``check`` finds nothing running, ``act`` with the job: what it needs
    up, the job, then every other service."""
    calls = [
        image_call(cs, "app", APP_IMAGE),
        ps_call(cs),
        config_call(cs, JOBBED),
        FakeCall(up_argv(cs, "postgres")),
        FakeCall(run_argv(cs, "init"), code=job_code, lines=stdout("init: done")),
    ]
    if job_code == 0:
        calls.append(FakeCall(up_argv(cs, "app", "frontend", "postgres")))
    return calls


def verifying(cs: ComposeStack) -> list[FakeCall]:
    """``verify``: the app on its image, every service but the job on its
    configuration -- the job's hash is printed, it has no container."""
    return [
        image_call(cs, "app", APP_IMAGE),
        ps_call(cs, CONTAINER),
        inspect_image_call(CONTAINER, APP_IMAGE),
        *hash_calls(cs, running=HASHES, expected=JOB_HASHES),
        *observe_calls(cs),
    ]


# --- probes ------------------------------------------------------------------------


def test_probe_DM_22_job_runs_on_every_deploy_and_red_on_nonzero(
    tmp_path: Path, app: LiveApp
) -> None:
    """Contract 3 rule 24: the job after the service it depends on is up and
    before the app that depends on it -- on every deploy that acts: twice,
    twice; its code 1 is red with its command and nothing after it comes up.
    The pair: code 0 -- the dependent is brought up."""
    stack = jobbed(app.port)
    cs = cs_of(stack, tmp_path)
    for _ in range(2):
        with FakeRunner(*acting(cs), *verifying(cs)) as runner:
            outcome, _ = run([up_of(stack, tmp_path)], runner)
        assert outcome.code is ExitCode.OK, outcome.steps
        assert outcome.steps[0].verify is not None
        assert outcome.steps[0].verify["jobs"] == ["init"]

    # code 1: red with the job's command; the final up is not in the script
    with FakeRunner(*acting(cs, job_code=1)) as runner:
        red, _ = run([up_of(stack, tmp_path)], runner)
    assert red.code is not ExitCode.OK
    assert red.steps[0].reason == Code(
        "command-failed", {"argv": list(run_argv(cs, "init")), "exit_code": 1}
    )


def test_probe_DM_22_minted_length_40_is_exactly_40(tmp_path: Path) -> None:
    """``length: 40`` -- exactly 40 characters of the machine's alphabet in
    ``minted.yaml`` and ``.env``. The pair: no ``length`` -- 43."""
    env = {
        "STORAGE_SECRET_KEY": {"source": "minted", "length": 40},
        "SECRET_KEY": {"source": "minted"},
    }
    stack = product(tmp_path, env)
    root, fetched = box(tmp_path, passport_data())
    outcome, _ = run_env([render(stack, root, fetched)], FakeRunner())
    assert outcome.code is ExitCode.OK, outcome.steps
    minted = yaml.safe_load(minted_of(root, stack.name).read_text())
    values = read_env(root, stack.name)
    for key, length in (("STORAGE_SECRET_KEY", 40), ("SECRET_KEY", 43)):
        assert len(minted[key]) == length and ALPHABET.fullmatch(minted[key]), key
        assert values[key] == minted[key]


# --- jobs --------------------------------------------------------------------------


def test_an_update_with_nothing_changed_runs_no_job_and_doctor_is_empty(
    tmp_path: Path, app: LiveApp
) -> None:
    """The reading of "every deploy" (DM-22 gate): a job runs when ``up`` of
    its entry acts. Nothing changed -- the job's hash has no container to
    compare, ``stale`` leaves it out, ``check`` needs no ``act``: no ``run``
    (the strict script has none), and ``check`` alone -- ``doctor`` -- says
    nothing. The pair is the probe: a new commit acts."""
    stack = jobbed(app.port)
    cs = cs_of(stack, tmp_path)
    checked = [
        image_call(cs, "app", APP_IMAGE),
        ps_call(cs, CONTAINER),
        inspect_image_call(CONTAINER, APP_IMAGE),
        *hash_calls(cs, running=HASHES, expected=JOB_HASHES),
        *observe_calls(cs),
    ]
    with FakeRunner(*checked, *verifying(cs)) as runner:
        outcome, _ = run([up_of(stack, tmp_path)], runner)
    assert outcome.code is ExitCode.OK, outcome.steps
    assert outcome.steps[0].verify is not None
    assert "jobs" not in outcome.steps[0].verify
    with FakeRunner(*checked) as runner:
        found = up_of(stack, tmp_path).check(context(runner))
    assert found.needed is False


def test_stale_leaves_the_jobs_out_and_keeps_every_other_service(
    tmp_path: Path,
) -> None:
    """A job ran and is gone: no container, not stale. The pair: a service
    that is no job and runs no container is."""
    cs = cs_of(jobbed(), tmp_path)
    with FakeRunner(*hash_calls(cs, running=HASHES, expected=JOB_HASHES)) as r:
        assert stale(context(r), cs) == {}
    running = {k: v for k, v in HASHES.items() if k != "frontend"}
    with FakeRunner(*hash_calls(cs, running=running, expected=JOB_HASHES)) as r:
        assert stale(context(r), cs) == {"frontend": (HASHES["frontend"], "none")}


def _graph(**edges: list[str]) -> dict[str, Json]:
    return {
        "services": {
            name: {"depends_on": {d: {"condition": "x"} for d in deps}}
            for name, deps in edges.items()
        }
    }


def test_jobs_run_in_the_order_of_depends_on_and_by_name_otherwise() -> None:
    """The job ``y`` needs ``b``, which needs the job ``z``: ``z`` before
    ``y``, though after it by name; ``c`` waits for nothing and goes first by
    name -- each tie is broken by name."""
    graph = _graph(z=[], b=["z"], y=["b"], app=["y"], c=[], postgres=[])
    jobs = frozenset({"z", "y", "c"})
    assert job_order(graph, jobs) == ["c", "z", "y"]
    assert job_order(_graph(m=[], k=[]), frozenset({"m", "k"})) == ["k", "m"]


def test_a_job_needs_what_it_depends_on_through_any_service_but_a_job() -> None:
    """``init -> pgbouncer -> postgres``: both, the farther one too; through
    the job ``seed`` -- not: it ran before."""
    graph = _graph(
        init=["pgbouncer", "seed"],
        pgbouncer=["postgres"],
        postgres=[],
        seed=["cache"],
        cache=[],
    )
    jobs = frozenset({"init", "seed"})
    assert needed_by(graph, "init", jobs) == ["pgbouncer", "postgres"]
    assert needed_by(graph, "seed", jobs) == ["cache"]
    assert needed_by(_graph(init=[]), "init", frozenset({"init"})) == []


def test_two_jobs_each_after_what_it_needs_then_the_rest(
    tmp_path: Path, app: LiveApp
) -> None:
    """``first`` needs nothing -- no up before it; ``second`` needs ``first``
    (a job: ran) and ``postgres``; then every service but the jobs."""
    stack = made(
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
    jobs = {"first": "2" * 64, "second": "3" * 64}
    script = [
        image_call(cs, "app", APP_IMAGE),
        ps_call(cs),
        config_call(cs, document),
        FakeCall(run_argv(cs, "first")),
        FakeCall(up_argv(cs, "postgres")),
        FakeCall(run_argv(cs, "second")),
        FakeCall(up_argv(cs, "app", "frontend", "postgres")),
        image_call(cs, "app", APP_IMAGE),
        ps_call(cs, CONTAINER),
        inspect_image_call(CONTAINER, APP_IMAGE),
        *hash_calls(cs, running=HASHES, expected={**HASHES, **jobs}),
        *observe_calls(cs),
    ]
    with FakeRunner(*script) as runner:
        outcome, _ = run([up_of(stack, tmp_path)], runner)
    assert outcome.code is ExitCode.OK, outcome.steps
    assert outcome.steps[0].verify is not None
    assert outcome.steps[0].verify["jobs"] == ["first", "second"]


def test_an_entry_of_jobs_alone_brings_nothing_else_up(tmp_path: Path) -> None:
    """Twin EMPTINESS: no service but the job -- the job runs, no ``up`` of an
    empty list (a bare ``up`` would start the job as a service)."""
    stack = made(data(jobs={"init": {"service": "init"}}))
    cs = cs_of(stack, tmp_path)
    document: dict[str, Json] = {"services": {"init": {"image": "j@sha256:x"}}}
    step = up_of(stack, tmp_path)
    with FakeRunner(config_call(cs, document), FakeCall(run_argv(cs, "init"))) as r:
        assert step._with_jobs(context(r), frozenset({"init"})) == ["init"]


# --- healthcheck and the job's service in compose -------------------------------------


def _released(tmp_path: Path, stack: Product) -> ComposeStack:
    cs = cs_of(stack, tmp_path)
    cs.release.mkdir(parents=True, exist_ok=True)
    return cs


@pytest.mark.parametrize(
    "check",
    [None, {"disable": True}, {"test": ["NONE"]}, {"test": "NONE"}],
    ids=["absent", "disable", "test-none", "test-none-string"],
)
def test_a_service_without_a_healthcheck_is_named(tmp_path: Path, check: Json) -> None:
    """Protocol 3.4: every service declares a healthcheck compose runs; a job
    needs none. The pair: the same document with one -- no finding."""
    cs = _released(tmp_path, jobbed())
    body: dict[str, Json] = {"image": "w@sha256:x"}
    if check is not None:
        body["healthcheck"] = check
    healthy: dict[str, Json] = {"image": "a@sha256:x", "healthcheck": HEALTHCHECK}
    job: dict[str, Json] = {"image": "j@sha256:x"}
    document: dict[str, Json] = {
        "services": {"app": healthy, "worker": body, "init": job}
    }
    assert forbidden(cs, document) == ["worker: no healthcheck"]
    fixed: dict[str, Json] = {
        "services": {"app": healthy, "worker": healthy, "init": job}
    }
    assert forbidden(cs, fixed) == []


def test_a_job_with_a_healthcheck_is_green_and_a_service_named_by_no_job_is_not(
    tmp_path: Path,
) -> None:
    """The exemption is for the job's service only: ``init`` with a
    healthcheck passes; the same document without ``jobs`` names ``init``."""
    healthy: dict[str, Json] = {"image": "a@sha256:x", "healthcheck": HEALTHCHECK}
    bare: dict[str, Json] = {"image": "j@sha256:x"}
    document: dict[str, Json] = {"services": {"app": healthy, "init": healthy}}
    assert forbidden(_released(tmp_path, jobbed()), document) == []
    plain = made(data())
    plain_doc: dict[str, Json] = {"services": {"app": healthy, "init": bare}}
    assert forbidden(_released(tmp_path, plain), plain_doc) == ["init: no healthcheck"]


def test_a_job_whose_service_is_not_in_compose_is_named(tmp_path: Path) -> None:
    healthy: dict[str, Json] = {"image": "a@sha256:x", "healthcheck": HEALTHCHECK}
    cs = _released(tmp_path, jobbed())
    assert forbidden(cs, {"services": {"app": healthy}}) == [
        "jobs.init: no service init"
    ]


# --- the loader --------------------------------------------------------------------


def _codes(raw: dict[str, Json]) -> list[str]:
    try:
        stack = PRIMER_YAML.validate_python(raw)
    except pydantic.ValidationError as error:
        return sorted(str(e["type"]) for e in error.errors())
    return sorted(p.code for p in rule_problems(stack))


def _with_env(**env: Json) -> dict[str, Json]:
    raw = data()
    raw["env"] = env
    return raw


@pytest.mark.parametrize(
    ("length", "codes"),
    [
        (32, []),
        (40, []),
        (31, ["S.minted-length"]),
        (0, ["S.minted-length"]),
        ("40", ["int_type"]),
        (True, ["int_type"]),
    ],
)
def test_the_length_of_minted_is_32_or_more(length: Json, codes: list[str]) -> None:
    assert _codes(_with_env(K={"source": "minted", "length": length})) == codes


def test_length_belongs_to_minted_alone() -> None:
    assert _codes(_with_env(K={"source": "asked", "length": 40})) == ["extra_forbidden"]


def test_mint_of_a_length_draws_that_many_of_the_alphabet() -> None:
    assert set(MINT_ALPHABET) == set(
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-"
    )
    values = [mint(40) for _ in range(64)]
    assert all(len(v) == 40 and ALPHABET.fullmatch(v) for v in values)
    assert len(set(values)) == 64
    # every one of the 64 characters is drawn: 2560 draws miss one with
    # probability under 64 * (63/64) ** 2560, about 1e-16
    assert set("".join(values)) == set(MINT_ALPHABET)
    assert len(mint()) == 43


def test_a_value_minted_with_another_length_is_red_not_minted_again(
    tmp_path: Path,
) -> None:
    """Twin REPEAT: the key minted before ``length: 40`` was declared (43
    characters) -- ``render_env:minted-length``, the file as it was: a secret
    is minted once (TZ 7.3). The pair: the value of 40 -- green."""
    plain = product(tmp_path, {"STORE_KEY": {"source": "minted"}})
    root, fetched = box(tmp_path, passport_data())
    assert run_env([render(plain, root, fetched)], FakeRunner())[0].code is (
        ExitCode.OK
    )
    before = minted_of(root, plain.name).read_bytes()
    longer = product(tmp_path, {"STORE_KEY": {"source": "minted", "length": 40}})
    outcome, _ = run_env([render(longer, root, fetched)], FakeRunner())
    assert outcome.steps[0].reason == Code(
        "render_env:minted-length", {"key": "STORE_KEY", "length": 40, "found": 43}
    )
    assert minted_of(root, plain.name).read_bytes() == before
    fresh = tmp_path / "fresh"
    fresh.mkdir()
    root2, fetched2 = box(fresh, passport_data())
    assert run_env([render(longer, root2, fetched2)], FakeRunner())[0].code is (
        ExitCode.OK
    )


@pytest.mark.parametrize(
    ("entry", "detail"),
    [
        ({"jobs": {"init": {"service": "app"}}}, "app"),
        ({"jobs": {"init": {"service": "frontend"}}}, "frontend"),
        (
            {
                "jobs": {"init": {"service": "redis"}},
                "expose": {
                    "bus": {"service": "redis", "port": 6379, "scheme": "redis"}
                },
            },
            "redis",
        ),
        (
            {
                "jobs": {"init": {"service": "postgres"}},
                "test": {"run": "pytest", "target": "test", "services": ["postgres"]},
            },
            "postgres",
        ),
        (
            {"jobs": {"a": {"service": "init"}, "b": {"service": "init"}}},
            "job 'a'",
        ),
    ],
    ids=["app", "frontend", "point", "test-service", "two-jobs"],
)
def test_a_job_is_no_service_the_machine_keeps_or_reads(
    entry: dict[str, Json], detail: str
) -> None:
    """``S.job-service``; the pair: a job of its own service passes. The
    route goes to ``frontend`` here, so the app is caught as the app, not as
    a route's service; the frontend case keeps the route to the app."""
    raw = data(8000, **entry)
    if detail == "app":
        host = raw["host"]
        assert isinstance(host, dict)
        host["routes"] = {"api": {"to": "frontend:80", "max_body": "1M"}}
    stack = PRIMER_YAML.validate_python(raw)
    found = rule_problems(stack)
    assert [p.code for p in found] == ["S.job-service"]
    assert detail in found[0].message
    assert _codes(data(jobs={"init": {"service": "init"}})) == []


def test_a_route_s_service_is_no_job() -> None:
    raw = data(jobs={"init": {"service": "web"}})
    host = raw["host"]
    assert isinstance(host, dict)
    host["domains"] = ["api", "web"]
    host["routes"] = {
        "api": {"to": "app:8000", "max_body": "1M"},
        "web": {"to": "web:80"},
    }
    assert _codes(raw) == ["S.job-service"]


def test_a_job_has_no_option() -> None:
    """Twin: ``when`` is no field of a job (contract 3 rule 24) -- refused by
    the model, no branch for it."""
    assert _codes(data(jobs={"init": {"service": "init", "when": "x"}})) == [
        "extra_forbidden"
    ]


@pytest.mark.parametrize(
    ("roles", "codes"),
    [
        (["test", "preview"], []),
        (["prod"], []),
        ([], ["too_short"]),
        (["staging"], ["literal_error"]),
    ],
)
def test_a_seed_has_roles_of_the_form_of_a_verb(
    roles: list[str], codes: list[str]
) -> None:
    """DM-22: ``roles`` as ``verbs`` has them; the refusal of a seed outside
    its roles comes with the running of seeds (DM-86). Absent -- ``None``."""
    seed: dict[str, Json] = {
        "run": "python -m app.seed demo",
        "when": "command",
        "roles": list[Json](roles),
    }
    raw = data(seeds={"demo": seed})
    assert _codes(raw) == codes
    if not codes:
        stack = made(raw)
        assert stack.stacks["blank"].seeds["demo"].roles == roles
    none = made(data(seeds={"demo": {"run": "x", "when": "install"}}))
    assert none.stacks["blank"].seeds["demo"].roles is None


# --- stop_for_migrate ----------------------------------------------------------------


def stopping(port: int, *services: str) -> Product:
    return made(data(port, stop_for_migrate=list[Json](services)))


def ladder(
    stack: Product, root: Path
) -> tuple[StopForMigrate, Migrate, StartStopped, Stopped]:
    cs = cs_of(stack, root)
    migrate = Migrate(stack, ENTRY, release=cs.release, ref=REF, commit=SHA, root=root)
    stopped = Stopped()
    return StopForMigrate(migrate, stopped), migrate, StartStopped(stopped), stopped


def run_with_finally(
    main: list[Step], final: list[Step], runner: FakeRunner
) -> PlanOutcome:
    ticks = count()
    return Plan(
        [StackSteps(ENTRY, main, root=True)],
        mode="install",
        role="test",
        runner=runner,
        sink=ListSink(),
        clock=lambda: float(next(ticks)),
        now=lambda: datetime(2026, 11, 10, tzinfo=UTC),
        finally_=[StackSteps("stopped", final)],
    ).run()


def migrate_check(cs: ComposeStack) -> list[FakeCall]:
    """``check`` of ``migrate``: the image's head, the running app's."""
    return [
        image_call(cs, "app", APP_IMAGE),
        heads_call(cs, APP_IMAGE, f"{HEAD} (head)"),
        *observe_calls(cs),
    ]


def stop_call(cs: ComposeStack, *services: str, code: int = 0) -> FakeCall:
    return FakeCall(tuple(cs.argv("stop", *services)), code=code)


def running_call(cs: ComposeStack, service: str, *ids: str) -> FakeCall:
    argv = cs.argv("ps", "--status", "running", "-q", service)
    return FakeCall(tuple(argv), lines=stdout(*ids))


def test_stop_for_migrate_stops_before_the_migration_and_up_is_left_the_rest(
    tmp_path: Path, app: LiveApp
) -> None:
    """Protocol 6.3: the app is behind -- ``migrate`` will act, so its
    ``check`` read by ``stop_for_migrate`` says stop: ``worker`` and the app
    itself (protocol 6.3 allows any service) stopped before ``migrate``,
    read back as not running; ``migrate`` green, past the point of no return:
    ``start_stopped`` starts nothing -- ``up`` brings them up."""
    app.health = health(alembic_head="0000")
    stack = stopping(app.port, "worker", "app")
    stop, migrate, start, _ = ladder(stack, tmp_path)
    cs = cs_of(stack, tmp_path)
    script = [
        *migrate_check(cs),
        stop_call(cs, "worker", "app"),
        running_call(cs, "worker"),
        running_call(cs, "app"),
        *migrate_check(cs),
        migrate_call(cs),
        alembic_call(cs, "current", f"{HEAD} (head)", deps=True),
    ]
    with FakeRunner(*script) as runner:  # no start: migrate acted
        outcome = run_with_finally([stop, migrate], [start], runner)
    assert outcome.code is ExitCode.OK, outcome.steps
    assert [r.name for r in outcome.steps] == ["stop_for_migrate", "migrate"]
    assert outcome.steps[0].verify == {"stack": "blank", "stopped": ["worker", "app"]}
    assert outcome.finally_[0].status == "ok"


def test_nothing_is_stopped_when_migrate_has_nothing_to_do(
    tmp_path: Path, app: LiveApp
) -> None:
    """The running app is at the head: ``migrate`` needs no ``act``, so the
    step stops nothing (the strict script has no ``stop``). The pair is the
    test above. An entry without the field asks docker nothing at all."""
    stack = stopping(app.port, "worker")
    stop, migrate, start, _ = ladder(stack, tmp_path)
    cs = cs_of(stack, tmp_path)
    script = [
        *migrate_check(cs),
        *migrate_check(cs),
        alembic_call(cs, "current", f"{HEAD} (head)", deps=True),
    ]
    with FakeRunner(*script) as runner:
        outcome = run_with_finally([stop, migrate], [start], runner)
    assert outcome.code is ExitCode.OK, outcome.steps
    assert outcome.steps[0].verify == {"stack": "blank", "stopped": []}
    plain, _, _, _ = ladder(made(data(app.port)), tmp_path)
    with FakeRunner() as runner:
        assert plain.check(context(runner)).needed is False


def test_a_red_stop_crosses_no_point_and_finally_starts_what_it_stopped(
    tmp_path: Path, app: LiveApp
) -> None:
    """``stop`` exits 1: ``command-failed``, ``migrate`` never runs, the point
    of no return is not crossed, and ``start_stopped`` starts the list again
    and reads it running."""
    app.health = health(alembic_head="0000")
    stack = stopping(app.port, "worker")
    stop, migrate, start, _ = ladder(stack, tmp_path)
    cs = cs_of(stack, tmp_path)
    script = [
        *migrate_check(cs),
        stop_call(cs, "worker", code=1),
        FakeCall(tuple(cs.argv("start", "worker"))),
        running_call(cs, "worker", "c-worker"),
    ]
    with FakeRunner(*script) as runner:
        outcome = run_with_finally([stop, migrate], [start], runner)
    assert outcome.steps[0].reason == Code(
        "command-failed", {"argv": list(cs.argv("stop", "worker")), "exit_code": 1}
    )
    assert outcome.steps[1].status == "skipped"
    assert outcome.needs_restore is False
    assert outcome.finally_[0].verify == {"started": {"blank": ["worker"]}}


def test_a_service_that_still_runs_after_stop_is_red_before_the_point(
    tmp_path: Path, app: LiveApp
) -> None:
    """Twin LACK: ``stop`` exits 0 but ``worker`` runs -- the step reads it
    back: ``stop_for_migrate:stop-failed``, no ``migrate``; ``finally``
    starts the list."""
    app.health = health(alembic_head="0000")
    stack = stopping(app.port, "worker")
    stop, migrate, start, _ = ladder(stack, tmp_path)
    cs = cs_of(stack, tmp_path)
    script = [
        *migrate_check(cs),
        stop_call(cs, "worker"),
        running_call(cs, "worker", "c-worker"),
        FakeCall(tuple(cs.argv("start", "worker"))),
        running_call(cs, "worker", "c-worker"),
    ]
    with FakeRunner(*script) as runner:
        outcome = run_with_finally([stop, migrate], [start], runner)
    assert outcome.steps[0].reason == Code(
        "stop_for_migrate:stop-failed", {"stack": "blank", "services": ["worker"]}
    )
    assert outcome.needs_restore is False


def test_a_red_migrate_leaves_the_stopped_stopped(tmp_path: Path, app: LiveApp) -> None:
    """The KNOWN CEILING of ``StartStopped``: ``stop`` green, ``migrate`` red
    -- restore needed, and nothing is started (no ``start`` in the strict
    script): the old code on a schema that may be half migrated."""
    app.health = health(alembic_head="0000")
    stack = stopping(app.port, "worker")
    stop, migrate, start, _ = ladder(stack, tmp_path)
    cs = cs_of(stack, tmp_path)
    script = [
        *migrate_check(cs),
        stop_call(cs, "worker"),
        running_call(cs, "worker"),
        *migrate_check(cs),
        migrate_call(cs, code=1),
    ]
    with FakeRunner(*script) as runner:
        outcome = run_with_finally([stop, migrate], [start], runner)
    assert outcome.steps[1].status == "failed"
    assert outcome.needs_restore is True
    assert outcome.steps[0].verify == {"stack": "blank", "stopped": ["worker"]}
    assert outcome.finally_[0].verify == {"started": {}}


def test_stop_for_migrate_runs_right_before_migrate() -> None:
    """The order of the ladder (DM-22 gate): ``stop_for_migrate`` after
    ``tests``, right before ``migrate``, ``migrate`` before ``egress`` and
    ``up``."""
    from pridem.steps.egress import Egress
    from pridem.steps.tests import Tests

    orders = [Tests.order, StopForMigrate.order, Migrate.order, Egress.order, Up.order]
    assert orders == sorted(orders) and len(set(orders)) == len(orders)
    assert Migrate.order - StopForMigrate.order == 1


@pytest.mark.parametrize(
    ("entry", "codes"),
    [
        ({"stop_for_migrate": ["worker", "app"]}, []),
        ({"stop_for_migrate": ["worker", "worker"]}, ["S.stop-service"]),
        ({"stop_for_migrate": ["worker"], "migrate": None}, ["S.stop-service"]),
        ({"stop_for_migrate": ["worker"], "app": None}, ["S.stop-service"]),
        (
            {"stop_for_migrate": ["init"], "jobs": {"init": {"service": "init"}}},
            ["S.job-service"],
        ),
    ],
    ids=["app-allowed", "twice", "no-migrate", "no-app", "a-job"],
)
def test_stop_for_migrate_in_the_loader(
    entry: dict[str, Json], codes: list[str]
) -> None:
    """``app`` may be stopped (protocol 6.3); twice, with no ``migrate`` or no
    app to run it in (no ``migrate`` step then) -- ``S.stop-service``; a job
    -- ``S.job-service``. A field set to ``None`` here is taken out."""
    raw = data(8000, **{k: v for k, v in entry.items() if v is not None})
    stacks = raw["stacks"]
    assert isinstance(stacks, dict)
    stage = stacks["blank"]
    assert isinstance(stage, dict)
    for key in [k for k, v in entry.items() if v is None]:
        del stage[key]
    if "app" not in stage:  # the route goes to the frontend then
        raw["host"] = {
            "domains": ["api"],
            "routes": {"api": {"to": "frontend:80", "max_body": "1M"}},
        }
    assert _codes(raw) == codes


def test_stop_for_migrate_names_a_service_compose_has_and_migrate_does_not_need(
    tmp_path: Path,
) -> None:
    """``run --rm app`` of ``migrate`` brings up what ``app`` depends on, here
    through ``pgbouncer``: ``postgres`` and ``pgbouncer`` are refused; a
    service compose lacks -- named; ``worker`` -- green."""
    healthy: dict[str, Json] = {"image": "a@sha256:x", "healthcheck": HEALTHCHECK}
    document: dict[str, Json] = {
        "services": {
            "app": {**healthy, "depends_on": {"pgbouncer": {}}},
            "pgbouncer": {**healthy, "depends_on": {"postgres": {}}},
            "postgres": healthy,
            "worker": {**healthy, "depends_on": {"postgres": {}}},
        }
    }
    stack = made(data(stop_for_migrate=["postgres", "pgbouncer", "ghost", "worker"]))
    assert forbidden(_released(tmp_path, stack), document) == [
        "pgbouncer: stopped for migrate, migrate needs it",
        "postgres: stopped for migrate, migrate needs it",
        "stop_for_migrate: no service ghost",
    ]
    green = made(data(stop_for_migrate=["worker"]))
    assert forbidden(_released(tmp_path, green), document) == []


# --- FIX: no service depends on a job, a job does not restart; the final check ----


def test_a_service_that_depends_on_a_job_is_named(tmp_path: Path) -> None:
    """DM-22 FIX (tier 3: the job ran three times): compose runs a job again
    as a dependency -- under ``--no-deps`` and in ``run --rm <app>`` of
    ``migrate`` -- so no service but a job depends on one; the machine keeps
    the order. The pair: the same document without it; a job on a job is
    the machine's order too, and passes."""
    healthy: dict[str, Json] = {"image": "a@sha256:x", "healthcheck": HEALTHCHECK}
    job: dict[str, Json] = {"image": "j@sha256:x"}
    on_job: dict[str, Json] = {**healthy, "depends_on": {"init": {}}}
    cs = _released(tmp_path, jobbed())
    assert forbidden(cs, {"services": {"app": on_job, "init": job}}) == [
        "app: depends on job init"
    ]
    assert forbidden(cs, {"services": {"app": healthy, "init": job}}) == []
    two = made(data(jobs={"init": {"service": "init"}, "seed": {"service": "seed"}}))
    seed: dict[str, Json] = {**job, "depends_on": {"init": {}}}
    document: dict[str, Json] = {
        "services": {"app": healthy, "init": job, "seed": seed}
    }
    assert forbidden(_released(tmp_path, two), document) == []


@pytest.mark.parametrize(
    ("policy", "found"),
    [
        (None, []),
        ("no", []),
        ("always", ["jobs.init: restart always"]),
        ("unless-stopped", ["jobs.init: restart unless-stopped"]),
        ("on-failure", ["jobs.init: restart on-failure"]),
    ],
)
def test_a_job_has_no_restart_but_no(
    tmp_path: Path, policy: str | None, found: list[str]
) -> None:
    healthy: dict[str, Json] = {"image": "a@sha256:x", "healthcheck": HEALTHCHECK}
    job: dict[str, Json] = {"image": "j@sha256:x"}
    if policy is not None:
        job["restart"] = policy
    document: dict[str, Json] = {"services": {"app": healthy, "init": job}}
    assert forbidden(_released(tmp_path, jobbed()), document) == found


class _Undone(Step):
    """Green the first time ``verify`` is called, red the second: what
    ``stop_for_migrate`` looks like to the final check once ``up`` brought
    its services back."""

    name = "stop_for_migrate"
    order = 11
    modes = frozenset({"install"})

    def __init__(self, rechecked: bool) -> None:
        self.rechecked = rechecked
        self.calls = 0

    def check(self, ctx: StepContext) -> CheckResult:
        return CheckResult(False, None, {})

    def act(self, ctx: StepContext, check: CheckResult) -> None:
        raise AssertionError("no act")

    def verify(self, ctx: StepContext, check: CheckResult) -> Verified:
        self.calls += 1
        if self.calls > 1:
            raise StepFailed("stop-failed", {"stack": "blank", "services": ["w"]})
        return Verified({"stack": "blank", "stopped": ["w"]})


def test_the_final_check_leaves_a_step_a_later_step_undoes() -> None:
    """DM-22 FIX: ``stop_for_migrate`` is not ``rechecked`` -- the final check
    does not read it again, its fact stays. The pair: the same step
    ``rechecked`` -- the final check is red by it."""
    from pridem.steps.finalize import FinalCheck

    assert StopForMigrate.rechecked is False and Migrate.rechecked is True
    for rechecked in (False, True):
        step = _Undone(rechecked)
        built = Plan(
            [
                StackSteps("blank", [step], root=False),
                StackSteps("finalize", [FinalCheck()], root=True),
            ],
            mode="install",
            role="test",
            runner=FakeRunner(),
            sink=ListSink(),
        )
        outcome = built.run()
        if not rechecked:
            assert outcome.code is ExitCode.OK, outcome.steps
            assert outcome.steps[0].verify == {"stack": "blank", "stopped": ["w"]}
            assert outcome.steps[1].verify == {"verified": 0}
            assert step.calls == 1
        else:
            assert outcome.steps[1].reason == Code(
                "final_check:red",
                {
                    "stack": "blank",
                    "step": "stop_for_migrate",
                    "reason": "stop_for_migrate:stop-failed",
                },
            )


# --- FIX 2: what "every deploy" is -------------------------------------------------


def test_a_value_the_passport_puts_in_env_changes_it_its_number_alone_does_not(
    tmp_path: Path,
) -> None:
    """FIX 2: a job runs when ``up`` of its entry acts -- on a deploy that
    changes the entry: commit, environment, data, package. The passport's
    number alone writes nothing new into the stack's ``.env`` (so its
    configuration hash stays and the job does not run); a value of the
    passport in the stack's env changes the file."""
    stack = product(tmp_path, {"SUPPORT_LANGUAGE": {"source": "param"}})
    texts: list[bytes] = []
    for number, value in ((1, "en"), (2, "en"), (3, "ru")):
        passport = passport_data(params={stack.name: {"SUPPORT_LANGUAGE": value}})
        passport["version"] = number
        place = tmp_path / f"v{number}"
        place.mkdir()
        root, fetched = box(place, passport)
        outcome, _ = run_env([render(stack, root, fetched)], FakeRunner())
        assert outcome.code is ExitCode.OK, outcome.steps
        # DM-68: render_env writes the deploy's file
        texts.append(env_file(root, stack.name, staged=True).read_bytes())
    assert texts[0] == texts[1]  # the number alone
    assert texts[1] != texts[2]  # a value the passport puts in env


def test_a_service_on_another_configuration_acts_and_the_job_runs(
    tmp_path: Path, app: LiveApp
) -> None:
    """The pair of ``..._nothing_changed_runs_no_job...``: the app runs on a
    configuration hash the entry no longer has (another env, a new commit) --
    ``up`` acts and the job runs; the same hash -- no act, no job."""
    stack = jobbed(app.port)
    cs = cs_of(stack, tmp_path)
    behind = {**HASHES, "app": "9" * 64}
    script = [
        image_call(cs, "app", APP_IMAGE),
        ps_call(cs, CONTAINER),
        inspect_image_call(CONTAINER, APP_IMAGE),
        *hash_calls(cs, running=behind, expected=JOB_HASHES),  # stale: act
        config_call(cs, JOBBED),
        FakeCall(up_argv(cs, "postgres")),
        FakeCall(run_argv(cs, "init")),
        FakeCall(up_argv(cs, "app", "frontend", "postgres")),
        *verifying(cs),
    ]
    with FakeRunner(*script) as runner:
        outcome, _ = run([up_of(stack, tmp_path)], runner)
    assert outcome.code is ExitCode.OK, outcome.steps
    assert outcome.steps[0].verify is not None
    assert outcome.steps[0].verify["jobs"] == ["init"]
