"""Probe of DM-68: the running release keeps its environment until ``finalize``.

A deploy's ``render_env`` writes the deploy's ``env/next.env``; ``env/.env``,
which every compose command of the release ``current`` names reads, changes
only in ``finalize``, with ``current``. A new value of the passport on the same
commit -- the same release, the same name -- and a red step before the point
of no return: a compose command of the running release gets its old
environment. The pair: a green deploy -- the new release has the new one.
"""

from pathlib import Path

from env_support import box, passport_data, product, render
from plan_support import Journal, ScriptedStep, plan

from pridem.plan import StackSteps
from pridem.report.codes import ExitCode
from pridem.stacks.env import parse_env
from pridem.state import Box
from pridem.steps.base import StepFailed
from pridem.steps.compose import ComposeStack
from pridem.steps.finalize import FinalCheck, Finalize, current_link

COMMIT = "c" * 40


def _deploy(tmp: Path, value: str, *, red: bool) -> tuple[ExitCode, ComposeStack]:
    """A deploy of ``aivis`` at ``COMMIT`` with ``PLAIN`` of the passport at
    ``value``; ``red``: the step after ``render_env`` (``tests``, before the
    point of no return) is red. The running release's compose comes back."""
    root, fetched = box(tmp, passport_data(params={"aivis": {"PLAIN": value}}))
    made = product(tmp, {"PLAIN": {"source": "param"}})
    release = root / "opt" / "aivis" / "releases" / COMMIT
    release.mkdir(parents=True, exist_ok=True)
    pridem = Box(root / "opt" / "pridem")
    journal = Journal()
    gate = (
        ScriptedStep(
            "tests", 10, journal, check_raises=StepFailed("wrong-state", {"seen": "x"})
        )
        if red
        else ScriptedStep("tests", 10, journal, fact={"tests": "ok"})
    )
    finalize = Finalize(
        releases={"aivis": release},
        composition={"aivis": COMMIT, "pridem": "0.0.0"},
        box=pridem,
        fetched=fetched,
        root=root,
    )
    stacks = [
        StackSteps("aivis", [render(made, root, fetched), gate]),
        StackSteps("finalize", [FinalCheck(), finalize], root=True),
    ]
    with pridem.lock("probe"):
        outcome = plan(stacks, "install")[0].run()
    # a compose command of the release current names: no deploy asks for it
    return outcome.code, ComposeStack(made, "aivis", release, "main", COMMIT, root)


def _plain(compose: ComposeStack) -> str:
    argv = compose.argv("up", "-d")
    env_file = Path(argv[argv.index("--env-file") + 1])
    return parse_env(env_file.read_text(encoding="utf-8"))["PLAIN"]


def test_probe_DM_68_red_before_the_point_of_no_return_leaves_the_running_release_its_env(  # noqa: E501 -- the probe's name is the card's
    tmp_path: Path,
) -> None:
    code, running = _deploy(tmp_path / "red", "old", red=False)
    assert code is ExitCode.OK and _plain(running) == "old"
    code, running = _deploy(tmp_path / "red", "new", red=True)
    assert code is ExitCode.FAILED
    assert _plain(running) == "old"  # the running release, its own values
    assert running.env_file.name == ".env"
    staged = running.env_file.with_name("next.env")
    assert parse_env(staged.read_text(encoding="utf-8"))["PLAIN"] == "new"

    # the pair: green -- the new release runs on the new environment
    code, running = _deploy(tmp_path / "green", "old", red=False)
    code, running = _deploy(tmp_path / "green", "new", red=False)
    assert code is ExitCode.OK
    assert _plain(running) == "new"
    assert current_link(running.root, "aivis").resolve() == running.release
