"""The probes of DM-190, delivery A: the runner and the edges of a run.

B2 with real processes: a child the command left in its group that holds its
pipe does not hold the step; a child that left the group (``setsid``) keeps
the box's lock (DM-24). B3 with a real SIGTERM before the plan; B10 a ladder
of no form; B11 a signal in ``finally``. E6 -- a wait of a step ends at a
signal; E7 -- the fallback verdict is built whatever refuses the first.
"""

import os
import signal
import threading
import time
from pathlib import Path

import pytest
from plan_support import Journal, ScriptedStep, plan
from test_box_held import _gone
from test_probe_DM_45_cli import _cli, _fake_plan, _passport

from pridem.events import Code
from pridem.interrupt import Interrupt, Interrupted
from pridem.plan import Deferred, StackSteps
from pridem.report import schema
from pridem.report.codes import ExitCode
from pridem.report.schema import Verdict
from pridem.runner import SubprocessRunner
from pridem.state import Box, BoxBusy
from pridem.steps.base import StepContext, Waiting, wait_until
from pridem.verbs import deploy as deploy_verbs
from pridem.verbs import run as run_module

SH = "/bin/sh"


def _alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    return True


# --- probes -----------------------------------------------------------------------


def test_probe_DM_190_B2_a_child_left_in_the_group_does_not_hold_the_step() -> None:
    """A real command whose own process ends at once and leaves a child in
    its group holding the pipe: the command is done in seconds, not at its
    timeout, and the child is stopped with the group. Run with and without
    ``PYTHONUNBUFFERED`` (par0 6.3): the child's buffering decides nothing."""
    lines: list[str] = []
    started = time.monotonic()
    result = SubprocessRunner().run(
        [SH, "-c", "sleep 300 & echo $!"],
        timeout=60,
        on_line=lambda stream, line, cut: lines.append(line),
    )
    spent = time.monotonic() - started
    assert result.code == 0 and spent < 15, spent
    child = int(lines[0])
    for _ in range(50):
        if not _alive(child):
            break
        time.sleep(0.1)
    assert not _alive(child), "the child left in the group still runs"


def test_probe_DM_190_B2_a_child_out_of_the_group_keeps_the_lock(
    tmp_path: Path,
) -> None:
    """The pair, DM-24 as it was: a child that left the group (``setsid``)
    is no child of the machine's -- the command ends, the child lives on and
    holds the box's lock; the box names it."""
    box = Box(tmp_path)
    seen: list[str] = []
    with box.lock("update 2026-11-24T10:00:00Z-a3f9 pid 7"):
        runner = SubprocessRunner()
        assert box.lock_fd is not None
        runner.hold(box.lock_fd)
        runner.run(
            [SH, "-c", "setsid sleep 30 </dev/null >/dev/null 2>&1 & echo $!"],
            timeout=60,
            on_line=lambda stream, line, cut: seen.append(line),
        )
    pid = int(seen[0])
    try:
        time.sleep(0.5)  # setsid has detached by now
        with pytest.raises(BoxBusy) as busy, box.lock("status"):
            pass
        assert [p for p in busy.value.processes if p.startswith(f"pid {pid} ")]
    finally:
        _gone(pid)


def test_probe_DM_190_B3_a_signal_before_the_plan_stops_it_with_a_reason(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A real SIGTERM to the process while the plan is made -- before its
    first step: the first step of ``main`` is ``failed`` with
    ``interrupted`` and never asked; the rest are skipped
    ``after-interrupt``; ``finally`` runs; the verdict is red with its
    reason. The pair: no signal -- every step runs."""
    journal = Journal()
    make = _fake_plan(journal)

    def signalling(*args: object, **kwargs: object) -> object:
        os.kill(os.getpid(), signal.SIGTERM)  # a real signal, under the handler
        return make(*args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(deploy_verbs, "deploy_plan", signalling)
    interrupt = Interrupt()
    with interrupt.install():
        code, out, _ = _cli(
            tmp_path,
            ["--json", "update", "--passport", str(_passport(tmp_path))],
            interrupt=interrupt,
        )
    assert interrupt.received == [signal.SIGTERM]
    assert code == ExitCode.FAILED
    verdict = Verdict.model_validate_json(out)
    main = [s for s in verdict.steps if s.phase == "main"]
    first = main[0]
    assert first.status == "failed" and first.reason is not None, first
    assert first.reason.code == "interrupted", first
    assert all(
        s.reason is not None and s.reason.code == "after-interrupt" for s in main[1:]
    )
    assert any(s.phase == "finally" and s.status == "ok" for s in verdict.steps)
    assert f"{first.stack}/{first.name}:check" not in journal  # never asked


def test_probe_DM_190_B10_a_ladder_of_no_form_is_a_red_step() -> None:
    """A stack made when the ladder reaches it whose steps are of no form
    (two of one order): a red step ``ladder``, ``finally`` and a verdict --
    never an exception out of the plan."""
    journal = Journal()
    bad = Deferred(
        "blank",
        lambda: [
            StackSteps(
                "blank", [ScriptedStep("a", 1, journal), ScriptedStep("b", 1, journal)]
            )
        ],
        "a",
        root=True,
    )
    gc = StackSteps("pridem-box", [ScriptedStep("gc", 1, journal)])
    built, _ = plan([bad], finally_=[gc])
    outcome = built.run()
    assert outcome.code is ExitCode.FAILED
    [red] = [r for r in outcome.steps if r.status == "failed"]
    assert red.reason is not None and red.reason.code == "exception", red
    assert [r.status for r in outcome.finally_] == ["ok"]


def test_probe_DM_190_B11_a_signal_in_finally_leaves_no_red_without_a_reason() -> None:
    """The first signal during ``finally`` is shielded: the clean-up runs to
    its end and the run is what ``main`` made of it -- green here, never red
    with no step to say why. The pair: a second signal stops the step of
    ``finally`` it lands in, which says ``interrupted``."""
    journal = Journal()
    clean = StackSteps(
        "pridem-box",
        [ScriptedStep("gc", 1, journal, signal_in="act", signal_stops=False)],
    )
    built, _ = plan([StackSteps("blank", [ScriptedStep("a", 1, journal)], root=True)],
                    finally_=[clean])  # fmt: skip
    outcome = built.run()
    assert outcome.code is ExitCode.OK and not outcome.interrupted, outcome
    # the pair: two signals -- the second stops the step it lands in
    twice = Interrupt()
    twice.receive(signal.SIGTERM)
    stopped = StackSteps(
        "pridem-box", [ScriptedStep("gc", 1, journal, signal_in="act")]
    )
    built, _ = plan(
        [StackSteps("blank", [ScriptedStep("a", 1, journal)], root=True)],
        finally_=[stopped],
        interrupt=twice,
    )
    outcome = built.run()
    reasons = [r.reason for r in (*outcome.steps, *outcome.finally_) if r.reason]
    assert Code("interrupted") in reasons, outcome


# --- around the probes ------------------------------------------------------------


def test_a_wait_of_a_step_ends_at_a_signal() -> None:
    """E6: a step's wait with no sleep of its own sleeps by the interrupt --
    a signal ends a wait of a minute in a slice."""
    interrupt = Interrupt()
    ctx = StepContext(
        SubprocessRunner(),
        "deploy",
        "test",
        "blank",
        lambda *_: None,
        interrupt=interrupt,
    )
    timer = threading.Timer(0.3, interrupt.receive, args=(signal.SIGTERM,))
    timer.start()
    started = time.monotonic()
    try:
        with pytest.raises(Interrupted):
            wait_until(ctx, lambda: False, Waiting(deadline_s=600, poll_s=60))
    finally:
        timer.cancel()
    assert time.monotonic() - started < 5


def test_the_fallback_verdict_is_built_whatever_refuses_the_first(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """E7: the verdict's model refuses with a ``TypeError``, not its
    ``ValueError``: the fallback still writes a red verdict with
    ``run/unbuildable``; and when the fallback itself cannot be built, its
    last rung does."""
    journal = Journal()
    monkeypatch.setattr(deploy_verbs, "deploy_plan", _fake_plan(journal))
    real = schema.build_verdict

    def refusing(outcome: object, **kwargs: object) -> Verdict:
        if getattr(outcome, "steps", ()):
            raise TypeError("planted")
        return real(outcome, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(run_module, "build_verdict", refusing)
    code, out, _ = _cli(
        tmp_path, ["--json", "update", "--passport", str(_passport(tmp_path))]
    )
    verdict = Verdict.model_validate_json(out)
    assert code == ExitCode.FAILED
    codes = [entry.model_dump()["code"] for entry in verdict.report.incomplete]
    assert "unbuildable" in codes
    # the last rung: the fallback refused too
    monkeypatch.setattr(
        run_module, "salvaged", lambda *a: (_ for _ in ()).throw(TypeError("x"))
    )
    code, out, _ = _cli(
        tmp_path, ["--json", "update", "--passport", str(_passport(tmp_path))]
    )
    last = Verdict.model_validate_json(out)
    assert code == ExitCode.FAILED and last.steps == []
    assert [e.model_dump()["code"] for e in last.report.incomplete] == ["unbuildable"]
