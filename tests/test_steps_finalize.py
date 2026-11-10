"""The final check and ``finalize`` (DM-19): ``current`` and ``state.json``
only after a green final check; the final check re-verifies every green step."""

import os
from pathlib import Path

import pytest
from env_support import box as passport_box
from env_support import passport_data
from plan_support import Journal, ScriptedStep, plan
from state_support import state

from pridem.events import Code
from pridem.plan import StackSteps
from pridem.report.codes import ExitCode
from pridem.stacks.env import env_file, write_private
from pridem.state import Box
from pridem.steps.base import CheckResult, Step, StepContext, StepFailed, Verified
from pridem.steps.compose import override_file
from pridem.steps.finalize import FinalCheck, Finalize, current_link
from pridem.steps.passport import Fetched


class Flips(ScriptedStep):
    """Green the first time ``verify`` is called, red the second."""

    def __init__(self, name: str, order: int, journal: Journal) -> None:
        super().__init__(name, order, journal, fact={"seen": "ok"})
        self.calls = 0

    def verify(self, ctx: StepContext, check: CheckResult) -> Verified:
        self.calls += 1
        if self.calls > 1:
            raise StepFailed("wrong-state", {"seen": "gone"})
        return super().verify(ctx, check)


def fetched_passport(tmp: Path) -> Fetched:
    _, fetched = passport_box(tmp / "p", passport_data())
    return fetched


def finalize(tmp: Path, box: Box) -> tuple[Finalize, Path]:
    """``finalize`` of the stack ``blank``, its release made and the deploy's
    environment and override written, as ``render_env`` and ``build`` of the
    plan write them (DM-68, DM-89)."""
    release = tmp / "opt" / "blank" / "releases" / ("c" * 40)
    release.mkdir(parents=True)
    write_private(env_file(tmp, "blank", staged=True), "A='new'\n")
    staged = override_file(tmp, "blank", "blank", staged=True)
    staged.parent.mkdir(parents=True, exist_ok=True)
    staged.write_text("services: {new: {}}\n")
    step = Finalize(
        releases={"blank": release},
        entries={"blank": ["blank"]},
        composition={"blank": "c" * 40, "pridem": "0.0.0"},
        box=box,
        fetched=fetched_passport(tmp),
        root=tmp,
    )
    return step, release


def tail(*steps: Step) -> list[StackSteps]:
    return [
        StackSteps("blank", steps[:-2], root=False),
        StackSteps("finalize", steps[-2:], root=True),
    ]


# --- probes ---------------------------------------------------------------------


def test_probe_DM_19_current_not_switched_on_red(tmp_path: Path) -> None:
    box = Box(tmp_path / "pridem")
    step, release = finalize(tmp_path, box)
    journal = Journal()
    red = ScriptedStep(
        "up", 12, journal, check_raises=StepFailed("wrong-state", {"seen": "x"})
    )
    with box.lock("probe"):
        outcome = plan(tail(red, FinalCheck(), step), "install")[0].run()
    assert outcome.code is ExitCode.FAILED
    assert [(r.name, r.status) for r in outcome.steps] == [
        ("up", "failed"),
        ("final_check", "skipped"),
        ("finalize", "skipped"),
    ]
    assert not current_link(tmp_path, "blank").exists()
    with box.lock("probe"):
        assert box.read_state() is None
    # the pair: green -- current names the release, state.json is written
    green = ScriptedStep("up", 12, journal, fact={"up": "ok"})
    with box.lock("probe"):
        outcome = plan(tail(green, FinalCheck(), step), "install")[0].run()
        written = box.read_state()
    assert outcome.code is ExitCode.OK, outcome.steps
    assert Path(os.readlink(current_link(tmp_path, "blank"))) == release
    assert written is not None and written.current == {"blank": "c" * 40}
    assert outcome.steps[1].verify == {"verified": 1}


def test_probe_DM_19_final_check_red_prevents_completed(tmp_path: Path) -> None:
    box = Box(tmp_path / "pridem")
    step, _ = finalize(tmp_path, box)
    journal = Journal()
    flips = Flips("up", 12, journal)
    with box.lock("probe"):
        outcome = plan(tail(flips, FinalCheck(), step), "install")[0].run()
        written = box.read_state()
    assert outcome.code is ExitCode.FAILED  # not green: not completed
    up, final, last = outcome.steps
    assert up.status == "ok"
    assert final.reason == Code(
        "final_check:red", {"stack": "blank", "step": "up", "reason": "up:wrong-state"}
    )
    assert last.status == "skipped"
    assert not current_link(tmp_path, "blank").exists() and written is None
    assert flips.calls == 2  # the plan itself re-verified it


# --- the rest -------------------------------------------------------------------


def test_doctor_shows_current_behind_after_a_red_final_check(tmp_path: Path) -> None:
    """Gate fix 3: the containers run the new release, ``current`` the old --
    a fact ``doctor`` reports, not something it repairs."""
    box = Box(tmp_path / "pridem")
    step, release = finalize(tmp_path, box)
    old = release.parent / ("b" * 40)
    old.mkdir()
    os.symlink(old, current_link(tmp_path, "blank"))
    journal = Journal()
    with box.lock("probe"):
        box.write_state(state())
        plan(tail(Flips("up", 12, journal), FinalCheck(), step), "install")[0].run()
        outcome = plan(
            tail(ScriptedStep("up", 12, journal, needed=False), FinalCheck(), step),
            "doctor",
        )[0].run()
    assert Path(os.readlink(current_link(tmp_path, "blank"))) == old
    assert [d.reason.code for d in outcome.doctor_diff] == ["finalize:switch"]
    assert outcome.code is ExitCode.INCOMPLETE


def test_current_is_replaced_atomically(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``current`` is never absent: a temporary symlink replaces it. DM-54:
    ``unlink`` and ``symlink`` are watched too -- neither ever touches
    ``current`` itself, and ``current`` is there at every call."""
    box = Box(tmp_path / "pridem")
    step, release = finalize(tmp_path, box)
    old = release.parent / ("b" * 40)
    old.mkdir()
    link = current_link(tmp_path, "blank")
    os.symlink(old, link)
    calls: list[tuple[str, str]] = []
    real_replace, real_unlink, real_symlink = os.replace, os.unlink, os.symlink

    def watch_replace(src: str, dst: str) -> None:
        calls.append(("replace", f"{src} -> {dst}"))
        assert link.is_symlink()  # never absent
        real_replace(src, dst)

    def watch_unlink(path: str, *, dir_fd: int | None = None) -> None:
        calls.append(("unlink", str(path)))
        assert link.is_symlink()
        real_unlink(path, dir_fd=dir_fd)

    def watch_symlink(src: str, dst: str) -> None:
        calls.append(("symlink", str(dst)))
        assert link.is_symlink()
        real_symlink(src, dst)

    monkeypatch.setattr(os, "replace", watch_replace)
    monkeypatch.setattr(os, "unlink", watch_unlink)
    monkeypatch.setattr(os, "symlink", watch_symlink)
    with box.lock("probe"):
        plan(
            tail(ScriptedStep("up", 12, Journal(), fact={"a": 1}), FinalCheck(), step),
            "install",
        )[0].run()
    temp = link.with_name(".current.tmp")
    assert ("symlink", str(temp)) in calls
    assert ("replace", f"{temp} -> {link}") in calls
    assert not [c for c in calls if c[0] in ("unlink", "symlink") and c[1] == str(link)]
    assert Path(os.readlink(link)) == release


@pytest.mark.parametrize("red", ["last", "middle"])
def test_final_check_reverifies_every_green_step_and_names_the_red_one(
    tmp_path: Path, red: str
) -> None:
    """DM-19 fix: a red re-verify anywhere among several green steps fails the
    final check by that step's name; every green step is verified again."""
    box = Box(tmp_path / "pridem")
    step, _ = finalize(tmp_path, box)
    journal = Journal()
    names = ["build", "migrate", "up"]
    flipping = names[-1] if red == "last" else names[1]
    steps: list[Step] = [
        Flips(name, order, journal)
        if name == flipping
        else ScriptedStep(name, order, journal, fact={"seen": "ok"})
        for name, order in zip(names, (10, 11, 12), strict=True)
    ]
    with box.lock("probe"):
        outcome = plan(tail(*steps, FinalCheck(), step), "install")[0].run()
        written = box.read_state()
    final = outcome.steps[3]
    assert final.reason == Code(
        "final_check:red",
        {"stack": "blank", "step": flipping, "reason": f"{flipping}:wrong-state"},
    )
    assert outcome.code is ExitCode.FAILED and written is None
    # the pair: every green step up to the red one was verified a second time
    # (Flips logs only its green call; its own count says the second came)
    for name in names[: names.index(flipping)]:
        assert journal.count(f"blank/{name}:verify") == 2, (name, journal)
    [flips] = [s for s in steps if isinstance(s, Flips)]
    assert flips.calls == 2


def test_a_green_final_check_verified_every_green_step(tmp_path: Path) -> None:
    box = Box(tmp_path / "pridem")
    step, _ = finalize(tmp_path, box)
    journal = Journal()
    names = ["build", "migrate", "up"]
    steps: list[Step] = [
        ScriptedStep(name, order, journal, fact={"seen": "ok"})
        for name, order in zip(names, (10, 11, 12), strict=True)
    ]
    with box.lock("probe"):
        outcome = plan(tail(*steps, FinalCheck(), step), "install")[0].run()
    assert outcome.code is ExitCode.OK, outcome.steps
    assert outcome.steps[3].verify == {"verified": 3}
    assert [journal.count(f"blank/{name}:verify") for name in names] == [2, 2, 2]


def test_the_switch_of_current_is_made_durable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """DM-55: after ``current`` is replaced, its directory is fsynced, so the
    switch survives a power loss -- the rename alone may not."""
    box = Box(tmp_path / "pridem")
    step, release = finalize(tmp_path, box)
    link = current_link(tmp_path, "blank")
    order: list[str] = []
    real_replace, real_fsync = os.replace, os.fsync

    def watch_replace(src: str, dst: str) -> None:
        order.append(f"replace {Path(dst).name}")
        real_replace(src, dst)

    def watch_fsync(fd: int) -> None:
        if os.fstat(fd).st_ino == link.parent.stat().st_ino:
            order.append("fsync the directory of current")
        real_fsync(fd)

    monkeypatch.setattr(os, "replace", watch_replace)
    monkeypatch.setattr(os, "fsync", watch_fsync)
    with box.lock("probe"):
        outcome = plan(
            tail(ScriptedStep("up", 12, Journal(), fact={"a": 1}), FinalCheck(), step),
            "install",
        )[0].run()
    assert outcome.code is ExitCode.OK, outcome.steps
    switch = order.index("replace current")
    assert order[switch + 1] == "fsync the directory of current"
    assert Path(os.readlink(link)) == release
