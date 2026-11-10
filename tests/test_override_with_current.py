"""DM-89: the deploy's override and the running release's, switched with
``current`` and ``.env``.

Each test is a row of the grid of the card's gate: the one function of the
path and the one flag of a deploy, ``finalize`` over every entry of a stack,
an entry the stack no longer has, and a run cut between ``.env`` and the
overrides.
"""

import os
from pathlib import Path

import pytest
from env_support import box, context, passport_data, product
from plan_support import Journal, ScriptedStep, plan
from test_steps_finalize import finalize, tail

from pridem.report.codes import ExitCode
from pridem.runner import FakeRunner
from pridem.stacks.env import env_file
from pridem.state import Box
from pridem.steps import finalize as finalize_module
from pridem.steps.base import StepFailed
from pridem.steps.compose import ComposeStack, override_file
from pridem.steps.finalize import FinalCheck, Finalize, current_link


def _two_entries(tmp: Path) -> tuple[Box, Finalize]:
    """``finalize`` of ``blank`` with two entries, ``blank`` and ``web``, each
    with the deploy's override as ``build`` writes it."""
    pridem = Box(tmp / "pridem")
    step, _ = finalize(tmp, pridem)
    web = override_file(tmp, "blank", "web", staged=True)
    web.write_text("services: {web: {}}\n")
    step.entries["blank"] = ["blank", "web"]
    return pridem, step


def _green(box_: Box, step: Finalize) -> ExitCode:
    green = ScriptedStep("up", 12, Journal(), fact={"up": "ok"})
    with box_.lock("t"):
        return plan(tail(green, FinalCheck(), step), "install")[0].run().code


def test_one_flag_gives_a_deploy_its_two_files(tmp_path: Path) -> None:
    """``staged`` is the deploy's environment and override together; the
    default is the running release's two -- each path by its one function."""
    root, _ = box(tmp_path, passport_data(params={"aivis": {"PLAIN": "p"}}))
    made = product(tmp_path, {"PLAIN": {"source": "param"}})
    running = ComposeStack(made, "aivis", root / "r", "main", "c" * 40, root)
    deploy = ComposeStack(
        made, "aivis", root / "r", "main", "c" * 40, root, staged=True
    )
    assert running.override == override_file(root, "aivis", "aivis", staged=False)
    assert running.override.name == "aivis.yml"
    assert running.env_file == env_file(root, "aivis", staged=False)
    assert deploy.override == override_file(root, "aivis", "aivis", staged=True)
    assert deploy.override.name == "aivis.next.yml"
    assert deploy.env_file == env_file(root, "aivis", staged=True)
    argv = deploy.argv("up")
    assert argv[argv.index("--env-file") + 1] == str(deploy.env_file)
    assert argv[argv.index("-f", argv.index("-f") + 1) + 1] == str(deploy.override)


def test_finalize_puts_every_entrys_override_in_place_and_reads_them_back(
    tmp_path: Path,
) -> None:
    """Green: the override of each entry is the deploy's, named in the fact; a
    second look has nothing to do. The second entry's changed behind the
    machine: ``check`` switches again, ``verify`` before that is red
    ``override`` naming it."""
    pridem, step = _two_entries(tmp_path)
    assert _green(pridem, step) is ExitCode.OK
    for entry in ("blank", "web"):
        staged = override_file(tmp_path, "blank", entry, staged=True)
        running = override_file(tmp_path, "blank", entry, staged=False)
        assert running.read_bytes() == staged.read_bytes(), entry
        assert oct(running.stat().st_mode & 0o777) == oct(0o644)
    ctx = context(FakeRunner())
    with pridem.lock("t"):
        assert not step.check(ctx).needed
        fact = step.verify(ctx, step.check(ctx)).fact
        assert fact["override"] == ["blank/blank", "blank/web"]
        web = override_file(tmp_path, "blank", "web", staged=False)
        web.write_text("services: {other: {}}\n")
        check = step.check(ctx)
        assert check.needed and check.would is not None
        assert check.would.params == {"stacks": ["blank"]}
        with pytest.raises(StepFailed) as behind:
            step.verify(ctx, check)
        assert behind.value.reason.code == "override"
        assert behind.value.reason.params == {"stack": "blank", "entry": "web"}
        step.act(ctx, check)
    assert web.read_text() == "services: {web: {}}\n"


def test_an_entry_the_stack_no_longer_has_is_never_put_in_place(
    tmp_path: Path,
) -> None:
    """A deploy's override of an entry ``primer.yaml`` no longer names (a run
    of another release left it) is not switched: the entries come from the
    stack, not from the files in the directory."""
    gone = override_file(tmp_path, "blank", "gone", staged=True)
    gone.parent.mkdir(parents=True)
    gone.write_text("services: {gone: {}}\n")  # there before this run
    pridem = Box(tmp_path / "pridem")
    step, _ = finalize(tmp_path, pridem)
    assert _green(pridem, step) is ExitCode.OK
    assert override_file(tmp_path, "blank", "blank", staged=False).is_file()
    assert not override_file(tmp_path, "blank", "gone", staged=False).exists()


def test_a_run_cut_between_env_and_the_overrides_is_closed_by_the_next(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``current``, then ``.env``, then the overrides: a run cut at the
    overrides leaves the new release under ``current`` with its ``.env`` and
    the old overrides (KNOWN CEILING in ``finalize``), never the old release
    on the new ones. The next run finds them behind and puts them in place."""
    pridem, step = _two_entries(tmp_path)
    old = override_file(tmp_path, "blank", "blank", staged=False)
    old.write_text("services: {old: {}}\n")

    def cut(path: Path, data: bytes | str, mode: int) -> None:
        raise OSError("the run is cut here")

    monkeypatch.setattr(finalize_module, "atomic_write", cut)
    ctx = context(FakeRunner())
    with pridem.lock("t"), pytest.raises(OSError):
        step.act(ctx, step.check(ctx))
    release = tmp_path / "opt" / "blank" / "releases" / ("c" * 40)
    assert Path(os.readlink(current_link(tmp_path, "blank"))) == release
    assert env_file(tmp_path, "blank", staged=False).read_text() == "A='new'\n"
    assert old.read_text() == "services: {old: {}}\n"
    monkeypatch.undo()
    with pridem.lock("t"):
        check = step.check(ctx)
        assert check.needed
        step.act(ctx, check)
        step.verify(ctx, step.check(ctx))
    assert old.read_text() == "services: {new: {}}\n"
