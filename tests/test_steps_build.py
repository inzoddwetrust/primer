"""``build`` (DM-18): two build arguments, images with labels, a red build
touches no container, the machine's override."""

import json
import os
import stat
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
    image_call,
    placed,
    raw_config_call,
    run,
)

from pridem.events import Code
from pridem.report.codes import ExitCode
from pridem.runner import FakeCall, FakeRunner
from pridem.steps.base import CheckResult, StepContext, StepFailed
from pridem.steps.build import Build
from pridem.steps.compose import OverrideHandoff, override_text
from pridem.steps.migrate import Migrate
from pridem.steps.up import Up


def steps(root: Path) -> tuple[Build, Migrate, Up]:
    cs = compose(root)
    parts = {"release": cs.release, "ref": cs.ref, "commit": cs.commit, "root": root}
    return (
        Build(cs.stack, cs.entry, **parts, handoff=OverrideHandoff()),  # type: ignore[arg-type]
        Migrate(cs.stack, cs.entry, **parts),  # type: ignore[arg-type]
        Up(cs.stack, cs.entry, **parts),  # type: ignore[arg-type]
    )


def green_build(root: Path) -> list[FakeCall]:
    cs = compose(root)
    return [
        raw_config_call(cs),  # check: env_file (DM-55 FIX)
        config_call(cs),  # check: no override yet
        raw_config_call(cs),  # act -- DM-57 FIX: act and verify read build.args
        config_call(cs),  # act
        build_call(cs),
        raw_config_call(cs),  # verify
        config_call(cs),  # verify
        image_call(cs, "app", APP_IMAGE),
        image_call(cs, "frontend", FRONT_IMAGE),
    ]


# --- probes ---------------------------------------------------------------------


def test_probe_DM_18_red_build_leaves_site_untouched(tmp_path: Path) -> None:
    cs = compose(tmp_path)
    script = [
        raw_config_call(cs),
        config_call(cs),
        raw_config_call(cs),  # act reads the build arguments too (DM-57 FIX)
        config_call(cs),
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
    cs = compose(tmp_path)
    with FakeRunner(*green_build(tmp_path)) as runner:
        run([steps(tmp_path)[0]], runner)
    placed(cs)  # DM-45: the green run's packages put the override in place
    again = [
        raw_config_call(cs),
        config_call(cs),
        image_call(cs, "app", APP_IMAGE),
        image_call(cs, "frontend", FRONT_IMAGE),
        raw_config_call(cs),  # verify reads the build arguments too (DM-57 FIX)
        config_call(cs),
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
    # DM-45: build writes the candidate; the override on disk waits for packages
    assert cs.candidate().override.read_text() == override_text(cs, CONFIG)
    assert cs.override.read_text() == "{}\n"


def test_the_override_is_written_0644_whatever_the_umask(tmp_path: Path) -> None:
    """DM-54: the machine's override is read by compose, not a secret: 0644,
    written whole by ``atomic_write`` with no file left beside it. DM-45:
    build writes it as the candidate, the file ``packages`` puts in place."""
    cs = compose(tmp_path)
    old = os.umask(0o077)
    try:
        with FakeRunner(*green_build(tmp_path)) as runner:
            outcome, _ = run([steps(tmp_path)[0]], runner)
    finally:
        os.umask(old)
    assert outcome.code is ExitCode.OK, outcome.steps
    candidate = cs.candidate().override
    assert stat.S_IMODE(candidate.stat().st_mode) == 0o644
    assert [p.name for p in candidate.parent.iterdir()] == [candidate.name]


def test_build_args_in_the_products_compose_are_refused(tmp_path: Path) -> None:
    cs = compose(tmp_path)
    document = json.loads(json.dumps(CONFIG))
    document["services"]["frontend"]["build"]["args"] = {"VITE_API_URL": "x"}
    with FakeRunner(raw_config_call(cs, document), config_call(cs, document)) as runner:
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
    file stay green)."""
    cs = compose(tmp_path)
    raw = json.loads(json.dumps(CONFIG))
    raw["services"]["app"]["environment"] = {"A": "$LOOSE"}
    with FakeRunner(raw_config_call(cs, raw), config_call(cs)) as runner:
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
    is ``instance-args`` before anything is built."""
    cs = compose(tmp_path)
    raw = json.loads(json.dumps(CONFIG))
    raw["services"]["frontend"]["build"]["args"] = None
    with FakeRunner(raw_config_call(cs, raw), config_call(cs)) as runner:
        outcome, _ = run([steps(tmp_path)[0]], runner)
    assert outcome.steps[0].reason == Code(
        "build:instance-args", {"stack": "blank", "services": ["frontend"]}
    )
    assert not cs.override.exists()


def test_verify_reads_the_build_arguments_as_check_does(tmp_path: Path) -> None:
    """DM-57 FIX: ``verify`` reads ``config --no-interpolate`` too and states
    the same fact as ``check`` -- the velo form of ``build.args``, which the
    interpolated ``config`` drops, is ``instance-args`` there as well."""
    cs = compose(tmp_path)
    raw = json.loads(json.dumps(CONFIG))
    raw["services"]["frontend"]["build"]["args"] = None
    step = steps(tmp_path)[0]
    with FakeRunner(raw_config_call(cs, raw), config_call(cs)) as runner:
        ctx = StepContext(runner, "install", "test", "blank", lambda *_: None)
        with pytest.raises(StepFailed) as raised:
            step.verify(ctx, CheckResult(False))
    assert raised.value.reason == Code(
        "instance-args", {"stack": "blank", "services": ["frontend"]}
    )
