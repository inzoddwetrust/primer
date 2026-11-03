"""``up`` (DM-18): up without down, labels from the override, ``verify`` on
the built image, conformance and the release ``/health`` reports."""

import json
from collections.abc import Iterator, Mapping, Sequence
from pathlib import Path

import pytest
from compose_support import (
    APP_IMAGE,
    CONFIG,
    CONTAINER,
    FRONT_IMAGE,
    HASHES,
    HEAD,
    OLD_IMAGE,
    SHA,
    LiveApp,
    alembic_call,
    build_call,
    compose,
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
    raw_config_call,
    run,
    up_call,
)

from pridem.events import Code
from pridem.report.codes import ExitCode
from pridem.runner import FakeCall, FakeRunner, OnLine, Result
from pridem.stacks.seams import SeamMemory
from pridem.steps.build import Build
from pridem.steps.compose import NETWORK, ComposeStack, override_text
from pridem.steps.migrate import Migrate
from pridem.steps.up import Up


@pytest.fixture
def app() -> Iterator[LiveApp]:
    yield from live()


def up(root: Path, port: int, **extra: object) -> Up:
    cs = compose(root, port)
    return Up(
        cs.stack,
        cs.entry,
        release=cs.release,
        ref=cs.ref,
        commit=cs.commit,
        root=root,
        **extra,  # type: ignore[arg-type]
    )


def first_up(root: Path, port: int, running: str = APP_IMAGE) -> list[FakeCall]:
    """check (nothing runs), act, verify on ``running``."""
    cs = compose(root, port)
    return [
        image_call(cs, "app", APP_IMAGE),
        ps_call(cs),
        up_call(cs),
        image_call(cs, "app", APP_IMAGE),
        ps_call(cs, CONTAINER),
        inspect_image_call(CONTAINER, running),
        *hash_calls(cs),
        *observe_calls(cs),
    ]


class Recording(FakeRunner):
    def __init__(self, *calls: FakeCall) -> None:
        super().__init__(*calls)
        self.argvs: list[tuple[str, ...]] = []

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
        return super().run(
            argv, expect=expect, timeout=timeout, cwd=cwd, env=env, on_line=on_line
        )


# --- probes ---------------------------------------------------------------------


def test_probe_DM_18_container_on_old_image_id_is_red_verify(
    tmp_path: Path, app: LiveApp
) -> None:
    # verify stops on the image, before the configuration and conformance
    script = first_up(tmp_path, app.port, running=OLD_IMAGE)[:6]
    with FakeRunner(*script) as runner:
        outcome, _ = run([up(tmp_path, app.port)], runner)
    assert outcome.steps[0].reason == Code(
        "up:old-image", {"service": "app", "expected": APP_IMAGE, "running": OLD_IMAGE}
    )
    # the pair: on the built image -- green, and /health says the build's release
    with FakeRunner(*first_up(tmp_path, app.port)) as runner:
        outcome, _ = run([up(tmp_path, app.port)], runner)
    assert outcome.code is ExitCode.OK, outcome.steps
    assert outcome.steps[0].verify == {
        "stack": "blank",
        "image": APP_IMAGE,
        "release": "main",
        "commit": SHA,
        "health": "ok",
        "ready": 200,
    }


def test_build_release_and_commit_come_back_from_health(
    tmp_path: Path, app: LiveApp
) -> None:
    """The pair of ``build_gets_release_and_commit_only``: an app that reports
    another release or commit is red."""
    app.health = health(commit="2" * 40)
    with FakeRunner(*first_up(tmp_path, app.port)) as runner:
        outcome, _ = run([up(tmp_path, app.port)], runner)
    assert outcome.steps[0].reason == Code(
        "up:release-mismatch",
        {
            "release": "main",
            "commit": "2" * 40,
            "expected_release": "main",
            "expected_commit": SHA,
        },
    )


def test_probe_DM_18_no_down_in_step(tmp_path: Path, app: LiveApp) -> None:
    cs = compose(tmp_path, app.port)
    parts = {
        "release": cs.release,
        "ref": cs.ref,
        "commit": cs.commit,
        "root": tmp_path,
    }
    ladder = [
        Build(cs.stack, cs.entry, **parts),  # type: ignore[arg-type]
        Migrate(cs.stack, cs.entry, **parts),  # type: ignore[arg-type]
        Up(cs.stack, cs.entry, **parts),  # type: ignore[arg-type]
    ]
    script = [
        raw_config_call(cs),
        config_call(cs),
        config_call(cs),
        build_call(cs),
        config_call(cs),
        image_call(cs, "app", APP_IMAGE),
        image_call(cs, "frontend", FRONT_IMAGE),
        image_call(cs, "app", APP_IMAGE),
        heads_call(cs, APP_IMAGE, f"{HEAD} (head)"),
        *observe_calls(cs, running=False),
        migrate_call(cs),
        alembic_call(cs, "current", f"{HEAD} (head)", deps=True),
        *first_up(tmp_path, app.port),
    ]
    runner = Recording(*script)
    with runner:
        outcome, _ = run(ladder, runner)
    assert outcome.code is ExitCode.OK, outcome.steps
    forbidden = {"down", "rm", "--remove-orphans", "kill", "stop"}
    assert not [argv for argv in runner.argvs if forbidden & set(argv)]
    # the pair: the stack was brought up, by up -d
    assert any(argv[-6:-4] == ("up", "-d") for argv in runner.argvs)


def test_probe_DM_18_every_created_object_has_labels(tmp_path: Path) -> None:
    """Every object the stack's compose creates carries ``pridem.*`` labels.

    DM-64: the project's network of a product is also internal (protocol 4.1),
    so its rendered entry holds ``internal: true`` next to the label; the label
    stays the stack's alone."""
    cs = compose(tmp_path)
    rendered = json.loads(override_text(cs, CONFIG))
    release = {"pridem.stack": "blank", "pridem.release": "main", "pridem.commit": SHA}
    for name in ("app", "frontend", "postgres"):  # every container
        assert rendered["services"][name]["labels"] == release, name
    for name in ("app", "frontend"):  # every built image
        assert rendered["services"][name]["build"]["labels"] == {
            **release,
            "pridem.service": name,
        }
    assert "build" not in rendered["services"]["postgres"]  # pulled: not ours
    # volumes and the project's network outlive a release: the stack alone
    assert rendered["volumes"] == {"pgdata": {"labels": {"pridem.stack": "blank"}}}
    assert rendered["networks"] == {
        "default": {"labels": {"pridem.stack": "blank"}, "internal": True},
        NETWORK: {"external": True},
    }
    # app keeps its default network and joins pridem under <name>-<service>
    assert rendered["services"]["app"]["networks"] == {
        "default": None,
        NETWORK: {"aliases": ["blank-app"]},
    }
    assert "networks" not in rendered["services"]["frontend"]


# --- the rest -------------------------------------------------------------------


def test_up_with_the_same_image_and_a_clean_app_needs_no_act(
    tmp_path: Path, app: LiveApp
) -> None:
    cs = compose(tmp_path, app.port)
    script = [
        image_call(cs, "app", APP_IMAGE),
        ps_call(cs, CONTAINER),
        inspect_image_call(CONTAINER, APP_IMAGE),
        *hash_calls(cs),
        *observe_calls(cs),
        *first_up(tmp_path, app.port)[3:],  # verify only
    ]
    with FakeRunner(*script) as runner:  # no up call
        outcome, _ = run([up(tmp_path, app.port)], runner)
    assert outcome.code is ExitCode.OK, outcome.steps


def test_conformance_red_is_up_conformance(tmp_path: Path, app: LiveApp) -> None:
    app.health = health(alembic_head=None)
    with FakeRunner(*first_up(tmp_path, app.port)) as runner:
        outcome, _ = run([up(tmp_path, app.port)], runner)
    assert outcome.steps[0].reason == Code(
        "up:conformance", {"stack": "blank", "problems": ["alembic-head-null"]}
    )


def test_seams_reach_the_memory_after_health(tmp_path: Path, app: LiveApp) -> None:
    class Provider:
        def provided(self) -> dict[str, str]:
            return {"BLANK_API_URL": "http://blank-app:8000"}

    memory = SeamMemory()
    step = up(tmp_path, app.port, memory=memory, render=Provider())
    with FakeRunner(*first_up(tmp_path, app.port)) as runner:
        assert run([step], runner)[0].code is ExitCode.OK
    assert memory.values("blank", ["BLANK_API_URL"]) == {
        "BLANK_API_URL": "http://blank-app:8000"
    }


def test_override_names_default_when_config_lists_no_network_of_app(
    tmp_path: Path,
) -> None:
    """A service's ``networks`` in an override replaces the implicit
    ``default``: the override names it even when ``config`` lists none."""
    cs = compose(tmp_path)
    document = json.loads(json.dumps(CONFIG))
    del document["services"]["app"]["networks"]
    rendered = json.loads(override_text(cs, document))
    assert rendered["services"]["app"]["networks"] == {
        "default": None,
        NETWORK: {"aliases": ["blank-app"]},
    }


# --- the configuration of every service (DM-58) ---------------------------------


def _same_image_check(cs: ComposeStack, running: dict[str, str]) -> list[FakeCall]:
    """check: app on its image, the services on ``running`` hashes."""
    return [
        image_call(cs, "app", APP_IMAGE),
        ps_call(cs, CONTAINER),
        inspect_image_call(CONTAINER, APP_IMAGE),
        *hash_calls(cs, running=running),
    ]


@pytest.mark.parametrize(
    "running",
    [
        {**HASHES, "app": "1" * 64},  # another environment of app, same image
        {**HASHES, "postgres": "1" * 64},  # the last service, not the first
        {k: v for k, v in HASHES.items() if k != "frontend"},  # no container
    ],
    ids=["environment", "last-service", "no-container"],
)
def test_up_acts_when_a_service_is_not_on_its_configuration(
    tmp_path: Path, app: LiveApp, running: dict[str, str]
) -> None:
    """The same image of app and a service whose container is not on the
    configuration ``config --hash`` gives now -- another mount of a package
    (apply: runtime), another environment, or none running: ``up`` acts. The
    pair -- every service on its hash -- is
    ``test_up_with_the_same_image_and_a_clean_app_needs_no_act``."""
    cs = compose(tmp_path, app.port)
    script = [*_same_image_check(cs, running), *first_up(tmp_path, app.port)[2:]]
    runner = Recording(*script)
    with runner:
        outcome, _ = run([up(tmp_path, app.port)], runner)
    assert outcome.code is ExitCode.OK, outcome.steps
    assert tuple(
        cs.argv("up", "-d", "--no-build", "--wait", "--wait-timeout", "300")
    ) in (runner.argvs)


def test_up_verify_is_red_when_a_service_stays_on_an_old_configuration(
    tmp_path: Path, app: LiveApp
) -> None:
    """verify reads the hash on the container back: frontend still on the
    configuration of the old package after ``up`` -- red, by its name."""
    cs = compose(tmp_path, app.port)
    old = {**HASHES, "frontend": "1" * 64}
    script = [
        *_same_image_check(cs, old),
        up_call(cs),
        image_call(cs, "app", APP_IMAGE),
        ps_call(cs, CONTAINER),
        inspect_image_call(CONTAINER, APP_IMAGE),
        *hash_calls(cs, running=old),
    ]
    with FakeRunner(*script) as runner:
        outcome, _ = run([up(tmp_path, app.port)], runner)
    assert outcome.steps[0].reason == Code(
        "up:old-config",
        {"service": "frontend", "expected": HASHES["frontend"], "running": "1" * 64},
    )
    # no container at all: "none" names it
    gone = {k: v for k, v in HASHES.items() if k != "postgres"}
    script = [
        *_same_image_check(cs, gone),
        up_call(cs),
        image_call(cs, "app", APP_IMAGE),
        ps_call(cs, CONTAINER),
        inspect_image_call(CONTAINER, APP_IMAGE),
        *hash_calls(cs, running=gone),
    ]
    with FakeRunner(*script) as runner:
        outcome, _ = run([up(tmp_path, app.port)], runner)
    assert outcome.steps[0].reason == Code(
        "up:old-config",
        {"service": "postgres", "expected": HASHES["postgres"], "running": "none"},
    )
