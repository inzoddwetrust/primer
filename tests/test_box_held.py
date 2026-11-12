"""DM-24, pass 2: what keeps the box held and what never locks it for good.

- the lock: ``pridem`` closes its descriptor and never ``LOCK_UN`` -- a process
  a command left with the descriptor keeps the box held after a normal end too
  (measured: ``LOCK_UN`` dropped it for every holder), and ``BoxBusy`` names it;
- ``recover``: a journal no verdict can be built from (a code this machine's
  catalog no longer has) is quarantined, never a box every command fails on;
- the journal of a run: output past its limit is one line, the events stay;
- ``watch``: a signal that stopped ``main`` does not stop ``restore`` after it;
- ``pdeathsig``: the leader of a command dies with ``pridem``.

Real processes where the property is the kernel's (the lock, ``pdeathsig``);
the box on ``tmp_path``.
"""

import io
import json
import os
import signal
import sys
import time
from pathlib import Path

import pytest
import yaml
from data_support import blank_box
from deadline_support import deadline
from plan_support import Journal, ScriptedStep, plan
from report_support import SECRETS
from state_support import header, run_id

from pridem.cli import run as cli
from pridem.events import Code, LogLine, StepFinished, StepRecord, StepStarted
from pridem.interrupt import Interrupt
from pridem.plan import StackSteps
from pridem.report.schema import Verdict
from pridem.runner import FakeCall, FakeRunner, Stream, SubprocessRunner
from pridem.state import Box, BoxBusy
from pridem.steps.base import CheckResult, StepContext
from pridem.steps.passport import PASSPORT_COPY
from pridem.verbs import deploy as deploy_verbs
from pridem.verbs.run import Planned, Session

LEFT = ["sh", "-c", "setsid sleep 30 </dev/null >/dev/null 2>&1 & echo $!"]
"""A command that leaves a process with the lock's descriptor; prints its pid."""


def _leave(box: Box) -> int:
    """A command under the lock leaves a process behind; ``pridem`` ends
    normally. The pid of the process left."""
    seen: list[str] = []
    with box.lock("update 2026-11-12T10:00:00Z-a3f9 pid 7"):
        runner = SubprocessRunner()
        assert box.lock_fd is not None
        runner.hold(box.lock_fd)
        runner.run(LEFT, timeout=30, on_line=lambda s, line, c: seen.append(line))
    return int(seen[0])


def _gone(pid: int) -> None:
    os.kill(pid, signal.SIGKILL)
    with deadline(10.0):
        while Path(f"/proc/{pid}").exists() and _state(pid) != "Z":
            time.sleep(0.05)


def _state(pid: int) -> str:
    try:
        return Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()[0]
    except OSError:
        return "gone"


def test_a_process_a_command_left_holds_the_box_after_a_normal_end(
    tmp_path: Path,
) -> None:
    """``pridem`` ended normally, the process its command left lives: the next
    command is ``BoxBusy`` -- the holder written by the first and the process
    by its pid and name. The pair: once that process is gone, the box is free."""
    box = Box(tmp_path)
    left = _leave(box)
    try:
        with deadline(5.0), pytest.raises(BoxBusy) as busy, box.lock("status"):
            pass
        assert busy.value.holder == "update 2026-11-12T10:00:00Z-a3f9 pid 7"
        comm = Path(f"/proc/{left}/comm").read_text().strip()  # setsid, then sleep
        assert busy.value.processes == (f"pid {left} ({comm})",)
        assert f"held by pid {left} ({comm})" in str(busy.value)
    finally:
        _gone(left)
    with box.lock("status"):
        pass


def test_a_box_held_in_this_process_names_no_process(tmp_path: Path) -> None:
    """The holder is this very process (a second ``Box`` of one command): the
    refusal names the holder and no process -- its own pid is never a holder."""
    first, second = Box(tmp_path), Box(tmp_path)
    with first.lock("deploy"):
        with pytest.raises(BoxBusy) as busy, second.lock("doctor"):
            pass
    assert busy.value.processes == ()
    assert str(busy.value) == "the box is busy: deploy"


def _orphan_with(box: Box, run: str, code: str) -> Path:
    """A run that died after a step that failed with ``code``."""
    with box.lock(f"dying {run}"):
        sink = box.open_journal(header(run), SECRETS)
        failed = Code(code)
        record = StepRecord("aivis", "packages", 9, "failed", failed, None, 0.1, {})
        sink.emit(StepFinished("main", record))
        sink.close()
    return box.journals / f"{run}.jsonl"


def test_a_journal_no_verdict_can_be_built_from_is_quarantined(
    tmp_path: Path,
) -> None:
    """A dead run whose step failed with ``packages:override`` -- a code
    contract 2 removed (1.20), measured to make ``recover`` raise on every
    command: quarantined and named, the next journal recovered, the next
    command not blocked. The pair: a code the catalog has is a red verdict."""
    box = Box(tmp_path)
    removed = _orphan_with(box, run_id(1), "packages:override")
    _orphan_with(box, run_id(2), "command-failed")
    with box.lock("next"):
        done = box.recover(SECRETS, "0.3.1")
    assert done.quarantined == (run_id(1),)
    assert [v.run_id for v in done.verdicts] == [run_id(2)]
    assert not removed.exists()
    assert (box.journals / f"{run_id(1)}.jsonl.damaged").exists()
    with box.lock("after"):
        assert box.recover(SECRETS, "0.3.1").verdicts == ()


def _journal(box: Box, limit: int | None, lines: int) -> list[dict[str, object]]:
    run = run_id(1)
    with box.lock("a"):
        sink = box.open_journal(header(run), SECRETS, limit)
        sink.emit(StepStarted("main", "aivis", "tests", 10, header(run).started))
        for n in range(lines):
            sink.emit(LogLine("main", "aivis", "tests", Stream.STDOUT, f"line {n:04d}"))
        record = StepRecord("aivis", "tests", 10, "ok", None, None, 1.0, {"ran": 1})
        sink.emit(StepFinished("main", record))
        sink.close()
        cut = sink.cut
    text = (box.journals / f"{run}.jsonl").read_text(encoding="utf-8")
    found = [json.loads(line) for line in text.splitlines()]
    found.append({"cut": cut})
    return found


def test_output_past_the_limit_is_one_line_and_the_events_stay(
    tmp_path: Path,
) -> None:
    """2 000 lines of output, a limit of 4 KiB: the lines up to it, then one
    line ``output-cut 4096 bytes``, then no output -- ``step_finished`` is still
    written and the sink says the limit was reached. The pair: no limit -- all
    2 000 lines."""
    *events, said = _journal(Box(tmp_path / "a"), 4096, 2000)
    logs = [e["line"] for e in events if e["event"] == "log"]
    assert 0 < len(logs) < 2000
    assert logs[-1] == "output-cut 4096 bytes: the journal is at its limit"
    assert logs[:-1] == [f"line {n:04d}" for n in range(len(logs) - 1)]
    assert [e["event"] for e in events][-1] == "step_finished"
    assert said == {"cut": 4096}
    *whole, said = _journal(Box(tmp_path / "b"), None, 2000)
    assert len([e for e in whole if e["event"] == "log"]) == 2000
    assert said == {"cut": None}


class Asking(ScriptedStep):
    """A step whose ``check`` asks the interrupt, as a wait of a real step
    does (``Interrupt.check``), with no signal of its own."""

    def check(self, ctx: StepContext) -> CheckResult:
        ctx.interrupt.check()
        return super().check(ctx)


def test_a_signal_that_stopped_main_does_not_stop_restore() -> None:
    """``main`` is stopped by a signal before the point of no return;
    ``restore`` runs after it and asks the interrupt: that old signal does not
    stop it -- each step watches from its own start (``watch``). The pair: a
    signal during ``restore`` stops it."""
    journal = Journal()
    up = ScriptedStep("up", 1, journal, signal_in="act")
    run, _ = plan(
        [StackSteps("aivis", [up], root=True)],
        restore=[StackSteps("aivis", [Asking("rollback", 1, journal)])],
    )
    outcome = run.run()
    assert outcome.interrupted
    assert [(r.name, r.status) for r in outcome.restore] == [("rollback", "ok")]
    up = ScriptedStep("up", 1, journal, signal_in="act")
    stopped = Asking("rollback", 1, journal, signal_in="act")
    run, _ = plan(
        [StackSteps("aivis", [up], root=True)],
        restore=[StackSteps("aivis", [stopped])],
    )
    assert [(r.name, r.status) for r in run.run().restore] == [("rollback", "failed")]


CHILD = """
import sys
from pridem.runner import SubprocessRunner
SubprocessRunner().run(
    ["sh", "-c", "echo $$ > " + sys.argv[1] + "; exec sleep 60"],
    timeout=120,
    on_line=lambda s, line, c: None,
)
"""

SCENE = """
"$1" -c "$2" "$3" &
pridem=$!
while [ ! -s "$3" ]; do sleep 0.05; done
leader=$(cat "$3")
[ -d /proc/$leader ] && echo "before: running"
kill -9 $pridem
wait $pridem 2>/dev/null
for _ in $(seq 100); do
  [ -d /proc/$leader ] || { echo "after: gone"; exit 0; }
  sleep 0.05
done
echo "after: alive"
kill -9 $leader
"""


def test_the_leader_of_a_command_dies_with_pridem(tmp_path: Path) -> None:
    """``pridem`` (a Python running the real runner) is killed outright while
    its command runs: the command's leader dies with it (``setpriv
    --pdeathsig KILL``), not left running. The pair: before the kill it runs."""
    seen: list[str] = []
    pid_file = tmp_path / "leader"
    SubprocessRunner().run(
        ["sh", "-c", SCENE, "scene", sys.executable, CHILD, str(pid_file)],
        timeout=60,
        on_line=lambda s, line, c: seen.append(line),
    )
    assert seen == ["before: running", "after: gone"]


def test_the_first_signal_of_a_command_does_not_stop_a_shielded_wait() -> None:
    """``Interrupt``: under the shield the command's first signal leaves a wait
    alone, the second stops it -- every one after the first (DM-24, Р1)."""
    interrupt = Interrupt()
    with interrupt.shield():
        interrupt.watch()
        interrupt.receive(signal.SIGINT)
        assert not interrupt.stops()
        interrupt.receive(signal.SIGINT)
        assert interrupt.stops()


def test_a_verdict_says_its_journal_was_cut(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The box's passport gives the journal 1 KiB; a step's command writes
    more: the verdict says ``{journal, cut, limit: 1024}`` and the code is 2,
    the plan green. The pair: within the limit -- green, nothing incomplete."""
    for lines, code, incomplete in (
        (200, 2, [{"what": "journal", "code": "cut", "limit": 1024}]),
        (3, 0, []),
    ):
        root = tmp_path / str(lines)
        blank_box(root, name="tier1-box")
        copy = root / PASSPORT_COPY
        data = yaml.safe_load(copy.read_text(encoding="utf-8"))
        data["policies"]["gc"]["journal_budget"] = "1K"
        copy.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
        said = tuple((Stream.STDOUT, f"output line {n:04d}") for n in range(lines))

        def make(session: Session, *_: object) -> Planned:
            step = ScriptedStep("tests", 1, Journal(), act_argv=["run", "tests"])
            return Planned([StackSteps("blank", [step], root=True)])

        monkeypatch.setattr(deploy_verbs, "deploy_plan", make)
        out, err = io.StringIO(), io.StringIO()
        with FakeRunner(FakeCall(("run", "tests"), lines=said)) as runner:
            got = cli(
                ["--json", "update"],
                root=root / "opt" / "pridem",
                out=out,
                err=err,
                runner=runner,
                fs_root=root,
            )
        verdict = Verdict.model_validate_json(out.getvalue())
        assert got == code, err.getvalue()
        assert [i.model_dump() for i in verdict.report.incomplete] == incomplete
