"""Probe of DM-89: the running release keeps its override until ``finalize``.

``build`` writes the deploy's override (``<entry>.next.yml``); ``packages``
validates the package it binds and puts nothing in place; the override of
the release ``current`` names (``<entry>.yml``) changes only in ``finalize``,
with ``current`` and ``.env``. A new package, a green ``validate``, a red step
before the point of no return: a compose command of the running release gets
its own override, the old bind of the package. The pair: a green deploy --
the new override, the new bind.
"""

from dataclasses import replace
from pathlib import Path

from compose_support import ENTRY, REF, SHA, hash_calls
from plan_support import Journal, ScriptedStep, plan
from test_steps_frontend import (
    _image,
    _validate,
    config_call,
    made,
    packages,
    skin_box,
    skin_product,
)

from pridem.plan import StackSteps
from pridem.report.codes import ExitCode
from pridem.runner import FakeRunner
from pridem.stacks.env import env_file, write_private
from pridem.state import Box
from pridem.steps.base import StepFailed
from pridem.steps.compose import ComposeStack, write_override
from pridem.steps.finalize import FinalCheck, Finalize

OLD = "services: {frontend: {volumes: [velo-look@1.4.1]}}\n"
NEW = "services: {frontend: {volumes: [velo-look@1.4.2]}}\n"


def _deploy(tmp: Path, *, red: bool) -> tuple[ExitCode, ComposeStack]:
    """A deploy of the blank with the new package ``velo-look@1.4.2``: the
    running release's override binds 1.4.1, ``build`` of this run rendered the
    one that binds 1.4.2; ``packages`` validates it green; ``red``: the step
    after (``tests``, before the point of no return) is red. The running
    release's compose comes back."""
    tmp.mkdir(parents=True, exist_ok=True)
    stack = made(tmp, skin_product("css"))
    root, fetched, package = skin_box(tmp)
    release = root / "release"
    release.mkdir(parents=True, exist_ok=True)
    deploy = ComposeStack(stack, ENTRY, release, REF, SHA, root, staged=True)
    running = replace(deploy, staged=False)
    write_override(running, OLD)
    write_override(deploy, NEW)  # build's of this run
    write_private(env_file(root, stack.name, staged=True), "")  # render_env's
    later = config_call(root, stack)
    script = [
        later,
        *hash_calls(deploy, running={}),  # the frontend is not on the new one
        later,
        _image(),
        _validate(package, 0),
        later,  # verify reads the mounts back
    ]
    if not red:
        script.append(later)  # the final check reads them back once more
    journal = Journal()
    gate = (
        ScriptedStep(
            "tests", 10, journal, check_raises=StepFailed("wrong-state", {"seen": "x"})
        )
        if red
        else ScriptedStep("tests", 10, journal, fact={"tests": "ok"})
    )
    pridem = Box(root / "opt" / "pridem")
    finalize = Finalize(
        releases={stack.name: release},
        entries={stack.name: list(stack.stacks)},
        composition={stack.name: SHA, "pridem": "0.0.0"},
        box=pridem,
        fetched=fetched,
        root=root,
    )
    stacks = [
        StackSteps(ENTRY, [packages(root, fetched, stack), gate]),
        StackSteps("finalize", [FinalCheck(), finalize], root=True),
    ]
    with FakeRunner(*script) as runner, pridem.lock("probe"):
        outcome = plan(stacks, "install", runner=runner)[0].run()
    return outcome.code, running


def _override_of(compose: ComposeStack) -> str:
    argv = compose.argv("up", "-d")
    files = [argv[i + 1] for i, word in enumerate(argv) if word == "-f"]
    return Path(files[-1]).read_text(encoding="utf-8")


def test_probe_DM_89_red_before_the_point_of_no_return_leaves_the_running_release_its_override(  # noqa: E501 -- the probe's name is the gate's
    tmp_path: Path,
) -> None:
    code, running = _deploy(tmp_path / "red", red=True)
    assert code is ExitCode.FAILED
    assert _override_of(running) == OLD  # the running release, the old bind
    assert running.override.name == f"{ENTRY}.yml"
    assert replace(running, staged=True).override.read_text() == NEW

    # the pair: green -- the new release on the new override
    code, running = _deploy(tmp_path / "green", red=False)
    assert code is ExitCode.OK
    assert _override_of(running) == NEW
