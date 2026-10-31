"""``build`` (DM-18): two build arguments, images with labels, a red build
touches no container, the machine's override."""

import json
from pathlib import Path

from compose_support import (
    APP_IMAGE,
    CONFIG,
    FRONT_IMAGE,
    SHA,
    build_call,
    compose,
    config_call,
    image_call,
    run,
)

from pridem.events import Code
from pridem.report.codes import ExitCode
from pridem.runner import FakeCall, FakeRunner
from pridem.steps.build import Build
from pridem.steps.compose import override_text
from pridem.steps.migrate import Migrate
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
    cs = compose(root)
    return [
        config_call(cs),  # check: no override yet
        config_call(cs),  # act
        build_call(cs),
        config_call(cs),  # verify
        image_call(cs, "app", APP_IMAGE),
        image_call(cs, "frontend", FRONT_IMAGE),
    ]


# --- probes ---------------------------------------------------------------------


def test_probe_DM_18_red_build_leaves_site_untouched(tmp_path: Path) -> None:
    cs = compose(tmp_path)
    script = [config_call(cs), config_call(cs), build_call(cs, code=1)]
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
    again = [
        config_call(cs),
        image_call(cs, "app", APP_IMAGE),
        image_call(cs, "frontend", FRONT_IMAGE),
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
    assert cs.override.read_text() == override_text(cs, CONFIG)


def test_build_args_in_the_products_compose_are_refused(tmp_path: Path) -> None:
    cs = compose(tmp_path)
    document = json.loads(json.dumps(CONFIG))
    document["services"]["frontend"]["build"]["args"] = {"VITE_API_URL": "x"}
    with FakeRunner(config_call(cs, document)) as runner:
        outcome, _ = run([steps(tmp_path)[0]], runner)
    assert outcome.steps[0].reason == Code(
        "build:instance-args", {"stack": "blank", "services": ["frontend"]}
    )
    assert not cs.override.exists()
