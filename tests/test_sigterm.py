"""SIGTERM (DM-53): systemd stopping a timer's service, or ``kill``, goes the way
of an interrupt -- the command's group stopped, ``finally`` run, the outcome
kept. A real child process runs a plan whose step sleeps in a command; the test
sends SIGTERM to it and reads what it printed.
"""

import json
import os
import signal
import sys
import threading
import time
from pathlib import Path

from pridem.runner import Stream, SubprocessRunner

CHILD = """
import json
import os
import sys
from pathlib import Path

from pridem.cli import stop_on_sigterm
from pridem.plan import Plan, StackSteps
from pridem.runner import SubprocessRunner
from pridem.steps.base import CheckResult, Step, Verified, local_code

stop_on_sigterm()
here = Path(sys.argv[1])


class Sleep(Step):
    name, order, modes = "sleep", 1, frozenset({"install"})
    codes = {"do": "sleep"}

    def check(self, ctx):
        return CheckResult(True, local_code("do"))

    def act(self, ctx, check):
        (here / "pid").write_text(str(os.getpid()))
        ctx.runner.run(["sleep", "60"], timeout=120, on_line=ctx.on_line)

    def verify(self, ctx, check):
        return Verified({"slept": True})


class Mark(Sleep):
    name = "mark"

    def act(self, ctx, check):
        (here / "finally").write_text("ran")

    def verify(self, ctx, check):
        return Verified({"marked": True})


class Sink:
    def emit(self, event):
        pass


plan = Plan(
    [StackSteps("box", [Sleep()], root=True)],
    mode="install", role="test", runner=SubprocessRunner(), sink=Sink(),
    finally_=[StackSteps("box", [Mark()])],
)
try:
    plan.run()
    print("OUTCOME " + json.dumps({"interrupted": False}))
except KeyboardInterrupt:
    outcome = plan.outcome
    print("OUTCOME " + json.dumps({
        "interrupted": outcome.interrupted,
        "code": int(outcome.code),
        "main": [r.status for r in outcome.steps],
        "finally": [r.status for r in outcome.finally_],
    }))
"""


def test_sigterm_runs_finally_and_keeps_the_outcome(tmp_path: Path) -> None:
    lines: list[str] = []

    def keep(stream: Stream, line: str, cut: bool) -> None:
        lines.append(line)

    child = threading.Thread(
        target=lambda: SubprocessRunner().run(
            [sys.executable, "-c", CHILD, str(tmp_path)],
            expect=(0, 1, -15, 143),
            timeout=120,
            on_line=keep,
        )
    )
    child.start()
    pid_file = tmp_path / "pid"
    deadline = time.monotonic() + 60
    while not pid_file.exists() and time.monotonic() < deadline:
        time.sleep(0.05)
    assert pid_file.exists(), lines
    time.sleep(0.3)  # the sleep command has started
    os.kill(int(pid_file.read_text()), signal.SIGTERM)
    child.join(timeout=60)
    assert not child.is_alive()
    [outcome] = [x for x in lines if x.startswith("OUTCOME ")]
    assert json.loads(outcome.removeprefix("OUTCOME ")) == {
        "interrupted": True,
        "code": 1,
        "main": ["failed"],
        "finally": ["ok"],
    }
    assert (tmp_path / "finally").read_text() == "ran"
