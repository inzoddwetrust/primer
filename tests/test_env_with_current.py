"""DM-68: the deploy's environment and the running release's, switched with
``current``.

Each test is a row of the grid of the card's gate: the one function of the
path, ``finalize`` putting the deploy's ``next.env`` in place as ``.env`` and
reading it back, a second run with nothing to do, an empty environment, and a
run cut between ``current`` and ``.env``.
"""

import os
from pathlib import Path

import pytest
from env_support import box, context, passport_data, product, render
from plan_support import Journal, ScriptedStep, plan
from services_support import deferred, planned
from test_steps_finalize import finalize, tail

from pridem.report.codes import ExitCode
from pridem.runner import FakeRunner
from pridem.stacks.env import env_file, write_private
from pridem.stacks.seams import PRODUCT
from pridem.state import Box
from pridem.steps import finalize as finalize_module
from pridem.steps.base import StepFailed
from pridem.steps.compose import ComposeStack
from pridem.steps.finalize import FinalCheck, Finalize, current_link
from pridem.steps.services import SeamsVerify


def _green(box_: Box, step: Finalize) -> ExitCode:
    green = ScriptedStep("up", 12, Journal(), fact={"up": "ok"})
    with box_.lock("t"):
        return plan(tail(green, FinalCheck(), step), "install")[0].run().code


def test_the_env_path_is_one_function(tmp_path: Path) -> None:
    """``ComposeStack`` names the running release's ``.env`` unless it asks
    for the deploy's; ``render_env`` writes the deploy's -- each by
    ``env_file``."""
    root, fetched = box(tmp_path, passport_data(params={"aivis": {"PLAIN": "p"}}))
    made = product(tmp_path, {"PLAIN": {"source": "param"}})
    running = ComposeStack(made, "aivis", root / "r", "main", "c" * 40, root)
    deploy = ComposeStack(
        made, "aivis", root / "r", "main", "c" * 40, root, staged_env=True
    )
    assert running.env_file == env_file(root, "aivis", staged=False)
    assert running.env_file.name == ".env"
    assert deploy.env_file == env_file(root, "aivis", staged=True)
    assert deploy.env_file.name == "next.env"
    step = render(made, root, fetched)
    step.act(context(FakeRunner()), step.check(context(FakeRunner())))
    assert deploy.env_file.is_file() and not running.env_file.exists()


def test_finalize_puts_the_deploys_env_in_place_and_reads_it_back(
    tmp_path: Path,
) -> None:
    """Green: ``.env`` is ``next.env``, 0600, named in the fact; a second
    look has nothing to do. ``.env`` changed behind the machine: ``check``
    switches again, ``verify`` before that is red ``env``."""
    pridem = Box(tmp_path / "pridem")
    step, _ = finalize(tmp_path, pridem)
    staged = env_file(tmp_path, "blank", staged=True)
    running = env_file(tmp_path, "blank", staged=False)
    assert not running.exists()
    assert _green(pridem, step) is ExitCode.OK
    assert running.read_bytes() == staged.read_bytes()
    assert oct(running.stat().st_mode & 0o777) == oct(0o600)
    ctx = context(FakeRunner())
    with pridem.lock("t"):
        assert not step.check(ctx).needed
        fact = step.verify(ctx, step.check(ctx)).fact
        assert fact["env"] == ["blank"]
        running.write_text("A='other'\n")
        check = step.check(ctx)
        assert check.needed and check.would is not None
        assert check.would.params == {"stacks": ["blank"]}
        with pytest.raises(StepFailed) as behind:
            step.verify(ctx, check)
        assert behind.value.reason.code == "env"
        assert behind.value.reason.params == {"stack": "blank"}
        step.act(ctx, check)
        assert running.read_text() == "A='new'\n"


def test_an_empty_env_is_put_in_place_empty(tmp_path: Path) -> None:
    pridem = Box(tmp_path / "pridem")
    step, _ = finalize(tmp_path, pridem)
    write_private(env_file(tmp_path, "blank", staged=True), "")
    assert _green(pridem, step) is ExitCode.OK
    assert env_file(tmp_path, "blank", staged=False).read_text() == ""


def test_a_run_cut_between_current_and_env_is_closed_by_the_next(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``current`` first, then ``.env``: a run cut between them leaves the new
    release under ``current`` with the old ``.env`` (KNOWN CEILING in
    ``finalize``), never the old release on the new values. The next run
    finds ``.env`` behind and puts it in place."""
    pridem = Box(tmp_path / "pridem")
    step, release = finalize(tmp_path, pridem)
    running = env_file(tmp_path, "blank", staged=False)
    write_private(running, "A='old'\n")

    def cut(path: Path, text: str) -> None:
        raise OSError("the run is cut here")

    monkeypatch.setattr(finalize_module, "write_private", cut)
    ctx = context(FakeRunner())
    with pridem.lock("t"), pytest.raises(OSError):
        step.act(ctx, step.check(ctx))
    assert Path(os.readlink(current_link(tmp_path, "blank"))) == release
    assert running.read_text() == "A='old'\n"
    monkeypatch.undo()
    with pridem.lock("t"):
        check = step.check(ctx)
        assert check.needed
        step.act(ctx, check)
        step.verify(ctx, step.check(ctx))
    assert running.read_text() == "A='new'\n"


def test_every_compose_of_a_deploys_steps_is_on_the_deploys_env(
    tmp_path: Path,
) -> None:
    """Each step of the services' ladders and of the product's that runs
    compose runs it on ``next.env``; ``seams_verify`` too, for every stack it
    reads. Something of each is there: the list is not empty."""
    made, _ = planned(tmp_path, "full")
    found: list[tuple[str, ComposeStack]] = []
    for stack in (*deferred(made, "services"), *deferred(made, PRODUCT)):
        for step in stack.steps:
            compose = getattr(step, "compose", None)
            if isinstance(compose, ComposeStack):
                found.append((f"{stack.name}.{step.name}", compose))
            if isinstance(step, SeamsVerify):
                found += [(f"seams.{n}", c) for n, c in step.stacks.items()]
    names = {name for name, _ in found}
    for wanted in ("comms.build", "comms.data_copy", "comms.migrate", "comms.up"):
        assert wanted in names, sorted(names)
    assert {"seams.comms", "seams.aivis"} <= names, sorted(names)
    assert [name for name, c in found if not c.staged_env] == []
