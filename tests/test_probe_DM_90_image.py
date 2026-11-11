"""Probe of DM-90: a compose command of the running release takes the image of
its own commit.

The override of every service with a ``build`` names the release's image,
``<entry>-<service>:<commit12>``, never pulled: ``build`` of a new commit
writes the deploy's override with the new name and builds under it; the
running release's override, which only ``finalize`` replaces, keeps its own
name -- so after a red step past ``build`` a compose command of the release
``current`` names makes its container of the old commit's image. The pair: a
green deploy -- the new commit's image. Names are literal (``par0`` 14.2).
"""

import json
from dataclasses import replace
from pathlib import Path

from compose_support import (
    APP_IMAGE,
    CONFIG,
    FRONT_IMAGE,
    OLD_SHA,
    compose,
    config_call,
    image_call,
    raw_config_call,
)
from env_support import box, passport_data
from plan_support import Journal, ScriptedStep, plan
from test_steps_build import green_build

from pridem.plan import StackSteps
from pridem.report.codes import ExitCode
from pridem.runner import FakeRunner
from pridem.stacks.env import env_file, write_private
from pridem.state import Box
from pridem.steps.base import StepFailed
from pridem.steps.build import Build
from pridem.steps.compose import ComposeStack, override_text, write_override
from pridem.steps.finalize import FinalCheck, Finalize

OLD_APP = "blank-app:111111111111"
NEW_APP = "blank-app:0e82be562d18"


def _images(path: Path) -> dict[str, object]:
    services = json.loads(path.read_text(encoding="utf-8"))["services"]
    return {name: body.get("image") for name, body in services.items()}


def _deploy(root: Path, *, red: bool) -> tuple[ExitCode, ComposeStack]:
    """The release at ``OLD_SHA`` runs, its override in place; a deploy of
    ``SHA`` builds, then ``red``: the step after (``tests``, before the point
    of no return) is red. The running release's compose comes back."""
    deploy = compose(root)
    running = replace(compose(root, commit=OLD_SHA), staged=False)
    write_override(
        running, override_text(running, CONFIG, proxy=False, references=CONFIG)
    )
    write_private(env_file(root, "blank", staged=True), "")  # render_env's
    deploy.release.mkdir(parents=True, exist_ok=True)
    journal = Journal()
    gate = (
        ScriptedStep(
            "tests", 10, journal, check_raises=StepFailed("wrong-state", {"seen": "x"})
        )
        if red
        else ScriptedStep("tests", 10, journal, fact={"tests": "ok"})
    )
    build = Build(
        deploy.stack,
        deploy.entry,
        release=deploy.release,
        ref=deploy.ref,
        commit=deploy.commit,
        root=root,
    )
    pridem = Box(root / "opt" / "pridem")
    finalize = Finalize(
        releases={"blank": deploy.release},
        entries={"blank": ["blank"]},
        composition={"blank": deploy.commit, "pridem": "0.0.0"},
        box=pridem,
        fetched=box(root / "p", passport_data())[1],
        root=root,
    )
    script = green_build(root)
    if not red:  # the final check reads build back once more
        script += [
            raw_config_call(deploy),
            config_call(deploy),
            image_call(deploy, "app", APP_IMAGE),
            image_call(deploy, "frontend", FRONT_IMAGE),
        ]
    stacks = [
        StackSteps("blank", [build, gate]),
        StackSteps("finalize", [FinalCheck(), finalize], root=True),
    ]
    with FakeRunner(*script) as runner, pridem.lock("probe"):
        outcome = plan(stacks, "install", runner=runner)[0].run()
    return outcome.code, running


def test_probe_DM_90_red_after_build_leaves_the_running_release_its_image(
    tmp_path: Path,
) -> None:
    code, running = _deploy(tmp_path / "red", red=True)
    assert code is ExitCode.FAILED
    argv = running.argv("up", "-d")
    override = Path(argv[[i for i, w in enumerate(argv) if w == "-f"][-1] + 1])
    assert _images(override)["app"] == OLD_APP  # the old commit's, by its name
    assert _images(replace(running, staged=True).override)["app"] == NEW_APP

    # the pair: green -- the new release on the new commit's image
    code, running = _deploy(tmp_path / "green", red=False)
    assert code is ExitCode.OK
    assert _images(running.override)["app"] == NEW_APP
