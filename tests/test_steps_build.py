"""``build`` (DM-18): two build arguments, images with labels, a red build
touches no container, the machine's override."""

import copy
import json
import os
import stat
from dataclasses import replace
from pathlib import Path

import pytest
from compose_support import (
    APP_IMAGE,
    CONFIG,
    FRONT_IMAGE,
    SHA,
    build_call,
    compose,
    config_call,
    executable_calls,
    image_call,
    placed,
    raw_config_call,
    run,
)
from env_support import context

from pridem.events import Code, Json
from pridem.report.codes import ExitCode
from pridem.runner import FakeCall, FakeRunner
from pridem.steps.base import CheckResult, StepContext, StepFailed
from pridem.steps.build import Build
from pridem.steps.compose import override_text
from pridem.steps.env import DeriveEnv, RenderEnv
from pridem.steps.migrate import Migrate
from pridem.steps.packages import Packages
from pridem.steps.services import DataCopy
from pridem.steps.up import Up


def steps(root: Path) -> tuple[Build, Migrate, Up]:
    cs = compose(root)
    parts = {"release": cs.release, "ref": cs.ref, "commit": cs.commit, "root": root}
    return (
        Build(cs.stack, cs.entry, **parts),  # type: ignore[arg-type]
        Migrate(cs.stack, cs.entry, **parts),  # type: ignore[arg-type]
        Up(cs.stack, cs.entry, **parts),  # type: ignore[arg-type]
    )


def green_build(root: Path) -> list[FakeCall]:
    """Changed by DM-182: the compose check reads the executable form -- its
    calls are in the scenario."""
    cs = compose(root)
    return [
        raw_config_call(cs),  # check: env_file (DM-55 FIX)
        config_call(cs),  # check: no override yet
        *executable_calls(cs, CONFIG, CONFIG),  # DM-182
        raw_config_call(cs),  # act -- DM-57 FIX: act and verify read build.args
        config_call(cs),  # act
        *executable_calls(cs, CONFIG, CONFIG),  # DM-182
        build_call(cs),
        raw_config_call(cs),  # verify
        config_call(cs),  # verify
        *executable_calls(cs, CONFIG, CONFIG),  # DM-182
        image_call(cs, "app", APP_IMAGE),
        image_call(cs, "frontend", FRONT_IMAGE),
    ]


# --- probes ---------------------------------------------------------------------


def test_probe_DM_18_red_build_leaves_site_untouched(tmp_path: Path) -> None:
    """Changed by DM-182, on the dispatcher's word 24.11: the compose check reads
    the executable form -- its calls are in the scenario."""
    cs = compose(tmp_path)
    script = [
        raw_config_call(cs),
        config_call(cs),
        *executable_calls(cs),  # DM-182
        raw_config_call(cs),  # act reads the build arguments too (DM-57 FIX)
        config_call(cs),
        *executable_calls(cs),  # DM-182
        build_call(cs, code=1),
    ]
    with FakeRunner(*script) as runner:  # nothing else may run: no ps, no up
        outcome, _ = run(list(steps(tmp_path)), runner)
    assert outcome.code is ExitCode.FAILED
    assert [(r.name, r.status) for r in outcome.steps] == [
        ("build", "failed"),
        ("migrate", "skipped"),
        ("up", "skipped"),
    ]
    assert outcome.steps[0].reason is not None
    assert outcome.steps[0].reason.code == "command-failed"
    assert not outcome.needs_restore


def test_probe_DM_18_build_gets_release_and_commit_only(tmp_path: Path) -> None:
    """Changed by DM-182, on the dispatcher's word 24.11: the compose check reads the
    executable form -- its calls are in the scenario, through ``green_build``."""
    cs = compose(tmp_path)
    with FakeRunner(*green_build(tmp_path)) as runner:
        outcome, _ = run([steps(tmp_path)[0]], runner)
    assert outcome.code is ExitCode.OK, outcome.steps
    [argv] = [call.argv for call in green_build(tmp_path) if "build" in call.argv]
    given = [argv[i + 1] for i, word in enumerate(argv) if word == "--build-arg"]
    assert given == [f"PRIMER_RELEASE={cs.ref}", f"PRIMER_COMMIT={SHA}"]
    # the pair -- /health says the same release and commit -- is in test_steps_up


# --- the rest -------------------------------------------------------------------


def test_build_fact_names_the_app_image_for_derive(tmp_path: Path) -> None:
    with FakeRunner(*green_build(tmp_path)) as runner:
        outcome, _ = run([steps(tmp_path)[0]], runner)
    assert outcome.steps[0].verify == {
        "release": "main",
        "commit": SHA,
        "images": {"app": APP_IMAGE, "frontend": FRONT_IMAGE},
        "app_image": APP_IMAGE,
    }


def test_the_same_commit_again_needs_no_build(tmp_path: Path) -> None:
    """Changed by DM-182: the compose check reads the executable form -- its
    calls are in the scenario."""
    cs = compose(tmp_path)
    with FakeRunner(*green_build(tmp_path)) as runner:
        run([steps(tmp_path)[0]], runner)
    placed(cs)  # DM-45: the green run's packages put the override in place
    again = [
        raw_config_call(cs),
        config_call(cs),
        *executable_calls(cs, CONFIG, CONFIG),  # DM-182
        image_call(cs, "app", APP_IMAGE),
        image_call(cs, "frontend", FRONT_IMAGE),
        raw_config_call(cs),  # verify reads the build arguments too (DM-57 FIX)
        config_call(cs),
        *executable_calls(cs, CONFIG, CONFIG),  # DM-182
        image_call(cs, "app", APP_IMAGE),
        image_call(cs, "frontend", FRONT_IMAGE),
    ]
    with FakeRunner(*again) as runner:  # no build in the script
        outcome, _ = run([steps(tmp_path)[0]], runner)
    assert outcome.code is ExitCode.OK, outcome.steps
    # a changed override is a rebuild, whatever the images say
    cs.override.write_text("{}\n")
    with FakeRunner(*green_build(tmp_path)) as runner:
        outcome, _ = run([steps(tmp_path)[0]], runner)
    assert outcome.code is ExitCode.OK, outcome.steps
    # DM-89: build writes the deploy's; the running release's waits for
    # finalize (was: for packages, DM-45)
    rendered = override_text(cs, CONFIG, proxy=False, references=CONFIG)
    assert cs.override.read_text() == rendered
    assert replace(cs, staged=False).override.read_text() == rendered  # placed


def test_the_override_is_written_0644_whatever_the_umask(tmp_path: Path) -> None:
    """DM-54: the machine's override is read by compose, not a secret: 0644,
    written whole by ``atomic_write`` with no file left beside it. DM-89:
    build writes the deploy's, the file ``finalize`` puts in place."""
    cs = compose(tmp_path)
    old = os.umask(0o077)
    try:
        with FakeRunner(*green_build(tmp_path)) as runner:
            outcome, _ = run([steps(tmp_path)[0]], runner)
    finally:
        os.umask(old)
    assert outcome.code is ExitCode.OK, outcome.steps
    candidate = cs.override
    assert stat.S_IMODE(candidate.stat().st_mode) == 0o644
    assert [p.name for p in candidate.parent.iterdir()] == [candidate.name]


def test_build_args_in_the_products_compose_are_refused(tmp_path: Path) -> None:
    """Changed by DM-182: the compose check reads the executable form -- its
    calls are in the scenario."""
    cs = compose(tmp_path)
    document = json.loads(json.dumps(CONFIG))
    document["services"]["frontend"]["build"]["args"] = {"VITE_API_URL": "x"}
    with FakeRunner(
        raw_config_call(cs, document),
        config_call(cs, document),
        *executable_calls(cs, document, document),  # DM-182
    ) as runner:
        outcome, _ = run([steps(tmp_path)[0]], runner)
    assert outcome.steps[0].reason == Code(
        "build:instance-args", {"stack": "blank", "services": ["frontend"]}
    )
    assert not cs.override.exists()


def test_build_names_a_variable_that_is_loose_or_not_of_env(tmp_path: Path) -> None:
    """DM-57: the same ``variables`` as ``pridem check`` -- one that may be
    empty and one that is not a key of ``env`` are findings of
    ``compose-forbidden``, before anything is built; the pair: the harness's
    compose has no variable and its ``env`` none (the other tests of this
    file stay green).

    Changed by DM-182: the compose check reads the executable form -- its calls are
    in the scenario."""
    cs = compose(tmp_path)
    raw = json.loads(json.dumps(CONFIG))
    raw["services"]["app"]["environment"] = {"A": "$LOOSE"}
    with FakeRunner(
        raw_config_call(cs, raw),
        config_call(cs),
        *executable_calls(cs, CONFIG, raw),  # DM-182
    ) as runner:
        outcome, _ = run([steps(tmp_path)[0]], runner)
    reason = outcome.steps[0].reason
    assert reason is not None and reason.code == "build:compose-forbidden"
    assert reason.params["found"] == [
        "app: $LOOSE is not ${LOOSE:?}",
        "app: LOOSE is not a key of env",
    ]


def test_build_refuses_the_velo_form_of_build_args(tmp_path: Path) -> None:
    """DM-57 FIX: ``args: [VITE_API_BASE_URL]`` with no such value -- ``config``
    drops the key, ``--no-interpolate`` keeps it as ``null`` (measured) --
    is ``instance-args`` before anything is built.

    Changed by DM-182: the compose check reads the executable form -- its calls are
    in the scenario."""
    cs = compose(tmp_path)
    raw = json.loads(json.dumps(CONFIG))
    raw["services"]["frontend"]["build"]["args"] = None
    with FakeRunner(
        raw_config_call(cs, raw),
        config_call(cs),
        *executable_calls(cs, CONFIG, raw),  # DM-182
    ) as runner:
        outcome, _ = run([steps(tmp_path)[0]], runner)
    assert outcome.steps[0].reason == Code(
        "build:instance-args", {"stack": "blank", "services": ["frontend"]}
    )
    assert not cs.override.exists()


def test_verify_reads_the_build_arguments_as_check_does(tmp_path: Path) -> None:
    """DM-57 FIX: ``verify`` reads ``config --no-interpolate`` too and states
    the same fact as ``check`` -- the velo form of ``build.args``, which the
    interpolated ``config`` drops, is ``instance-args`` there as well.

    Changed by DM-182: the compose check reads the executable form -- its calls are
    in the scenario."""
    cs = compose(tmp_path)
    raw = json.loads(json.dumps(CONFIG))
    raw["services"]["frontend"]["build"]["args"] = None
    step = steps(tmp_path)[0]
    with FakeRunner(
        raw_config_call(cs, raw),
        config_call(cs),
        *executable_calls(cs, CONFIG, raw),  # DM-182
    ) as runner:
        ctx = StepContext(runner, "install", "test", "blank", lambda *_: None)
        with pytest.raises(StepFailed) as raised:
            step.verify(ctx, CheckResult(False))
    assert raised.value.reason == Code(
        "instance-args", {"stack": "blank", "services": ["frontend"]}
    )


# --- DM-67: the app image for derive_env ------------------------------------------


def _with_env(value: str) -> dict[str, Json]:
    """``CONFIG`` with a ``derived`` variable of ``app`` interpolated to
    ``value``: what ``config`` prints with the ``.env`` of that run."""
    document = copy.deepcopy(CONFIG)
    services = document["services"]
    assert isinstance(services, dict)
    app = services["app"]
    assert isinstance(app, dict)
    app["environment"] = {"TELEGRAM_BOT_URL": value}
    return document


def test_build_does_not_depend_on_the_values_of_env(tmp_path: Path) -> None:
    """Condition 1 of the gate: ``install`` builds with ``<derived>`` in the
    env, the next ``update`` reads the real value -- ``check`` needs no
    build, and finds the app image there for ``derive_env``.

    Changed by DM-182: the compose check reads the executable form -- its calls are
    in the scenario."""
    cs = compose(tmp_path)
    placeholder, real = _with_env("<derived>"), _with_env("https://t.me/b" * 3)
    first = [
        raw_config_call(cs, placeholder),
        config_call(cs, placeholder),
        *executable_calls(cs, placeholder),  # DM-182
        raw_config_call(cs, placeholder),
        config_call(cs, placeholder),
        *executable_calls(cs, placeholder),  # DM-182
        build_call(cs),
        raw_config_call(cs, placeholder),
        config_call(cs, placeholder),
        *executable_calls(cs, placeholder),  # DM-182
        image_call(cs, "app", APP_IMAGE),
        image_call(cs, "frontend", FRONT_IMAGE),
    ]
    with FakeRunner(*first) as runner:
        outcome, _ = run([steps(tmp_path)[0]], runner)
    assert outcome.code is ExitCode.OK, outcome.steps
    placed(cs)
    build = steps(tmp_path)[0]
    again = [
        raw_config_call(cs, real),
        config_call(cs, real),
        *executable_calls(cs, real),  # DM-182
        image_call(cs, "app", APP_IMAGE),
        image_call(cs, "frontend", FRONT_IMAGE),
    ]
    with FakeRunner(*again) as runner:  # no build in the script
        found = build.check(context(runner))
    assert not found.needed
    assert (build.app_image, build.app_built) == (APP_IMAGE, True)


def test_check_with_something_to_build_knows_no_app_image(tmp_path: Path) -> None:
    """The pair: ``check`` that needs a build has no image of this commit to
    give -- ``app_image`` stays ``None`` until ``verify``.

    Changed by DM-182: the compose check reads the executable form -- its calls are
    in the scenario."""
    cs = compose(tmp_path)
    build = steps(tmp_path)[0]
    with FakeRunner(
        raw_config_call(cs),
        config_call(cs),
        *executable_calls(cs, CONFIG, CONFIG),  # DM-182
    ) as runner:
        found = build.check(context(runner))  # no override on disk: a build
    assert found.needed and build.app_image is None and build.app_built is True
    with FakeRunner(*green_build(tmp_path)) as runner:
        outcome, _ = run([build], runner)
    assert outcome.code is ExitCode.OK, outcome.steps
    assert build.app_image == APP_IMAGE


def test_an_app_without_build_has_no_image_for_derive(tmp_path: Path) -> None:
    """Twin LACK: ``app`` runs a ready image (``image:``), nothing builds it.

    Changed by DM-182: the compose check reads the executable form -- its calls are
    in the scenario."""
    cs = compose(tmp_path)
    document = copy.deepcopy(CONFIG)
    services = document["services"]
    assert isinstance(services, dict)
    services["app"] = {
        "image": "app@sha256:x",
        "healthcheck": {"test": ["CMD", "true"]},
        "networks": {"default": None},
    }
    build = steps(tmp_path)[0]
    with FakeRunner(
        raw_config_call(cs, document),
        config_call(cs, document),
        *executable_calls(cs, document, document),  # DM-182
    ) as r:
        build.check(context(r))
    assert build.app_built is False and build.app_image is None


def test_build_comes_before_derive_env_in_a_stack() -> None:
    assert Build.order < DeriveEnv.order < min(Packages.order, DataCopy.order)
    assert RenderEnv.order < Build.order


def test_build_finds_a_consumer_of_a_point_by_the_uninterpolated_document(
    tmp_path: Path,
) -> None:
    """DM-62 FIX 2: on the box ``config`` gives the value of ``${POINT_ADDRESS}``
    in its interpolated document; only ``--no-interpolate`` still names the
    variable. ``build`` gives the override that one to find the consumers of
    a pair by: ``app``, whose environment names the point's variable, joins
    the pair's network.

    Changed by DM-182: the compose check reads the executable form -- its calls are
    in the scenario."""
    from compose_support import blank

    from pridem.stacks.schema import Param
    from pridem.stacks.seams import Pair

    made = blank()
    made = made.model_copy(
        update={"env": {**made.env, "POINT_ADDRESS": Param(source="param")}}
    )
    base = compose(tmp_path)
    cs = replace(base, stack=made)
    pair = Pair("svc", "probe", "point", "blank", "POINT_ADDRESS")

    def with_app_env(value: str) -> dict[str, Json]:
        document = copy.deepcopy(CONFIG)
        services = document["services"]
        assert isinstance(services, dict)
        app = services["app"]
        assert isinstance(app, dict)
        app["environment"] = {"POINT_ADDRESS": value}
        return document

    raw = with_app_env("${POINT_ADDRESS:?}")  # config --no-interpolate
    interpolated = with_app_env("svc-point:7000")  # config, on the box
    calls = [
        raw_config_call(cs, raw),
        config_call(cs, interpolated),
        *executable_calls(cs, interpolated),  # DM-182
        raw_config_call(cs, raw),
        config_call(cs, interpolated),
        *executable_calls(cs, interpolated),  # DM-182
        build_call(cs),
        raw_config_call(cs, raw),
        config_call(cs, interpolated),
        *executable_calls(cs, interpolated),  # DM-182
        image_call(cs, "app", APP_IMAGE),
        image_call(cs, "frontend", FRONT_IMAGE),
    ]
    parts = {
        "release": cs.release,
        "ref": cs.ref,
        "commit": cs.commit,
        "root": tmp_path,
    }
    step = Build(made, cs.entry, **parts, points=[pair])  # type: ignore[arg-type]
    with FakeRunner(*calls) as runner:
        outcome, _ = run([step], runner)
    assert outcome.code is ExitCode.OK, outcome.steps
    rendered = json.loads(cs.override.read_text())
    key = pair.network.removeprefix("pridem-")
    assert key in rendered["services"]["app"]["networks"]
    assert rendered["networks"][key] == {"name": pair.network, "external": True}
