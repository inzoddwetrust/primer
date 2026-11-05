"""SIGTERM (DM-53): systemd stopping a timer's service, or ``kill``, goes the way
of an interrupt -- the command's group stopped, ``finally`` run, the outcome
kept. A real child process runs a plan whose step sleeps in a command; the test
sends SIGTERM to it and reads what it printed.

DM-45: the signal sets the flag of the command's ``Interrupt`` (installed as
``pridem``'s ``main`` installs it); the runner stops the command's group in the
middle of the command and the plan returns its outcome instead of raising. The
statement of DM-53 holds as before, and is now measured: the sleeping command
is gone, long before its 60 seconds.
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

from pridem.interrupt import Interrupt
from pridem.plan import Plan, StackSteps
from pridem.runner import SubprocessRunner
from pridem.steps.base import CheckResult, Step, Verified, local_code

interrupt = Interrupt()
here = Path(sys.argv[1])


class Sleep(Step):
    name, order, modes = "sleep", 1, frozenset({"install"})
    codes = {"do": "sleep"}

    def check(self, ctx):
        return CheckResult(True, local_code("do"))

    def act(self, ctx, check):
        (here / "pid").write_text(str(os.getpid()))
        ctx.runner.run(
            ["sh", "-c", f"echo $$ > {here / 'sleeper'}; exec sleep 60"],
            timeout=120,
            on_line=ctx.on_line,
        )

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
    mode="install", role="test", runner=SubprocessRunner(interrupt), sink=Sink(),
    finally_=[StackSteps("box", [Mark()])], interrupt=interrupt,
)
with interrupt.install():
    outcome = plan.run()
print("OUTCOME " + json.dumps({
    "interrupted": outcome.interrupted,
    "code": int(outcome.code),
    "main": [(r.status, r.reason.code if r.reason else None) for r in outcome.steps],
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
    sleeper_file = tmp_path / "sleeper"
    while not sleeper_file.exists() and time.monotonic() < deadline:
        time.sleep(0.05)
    time.sleep(0.3)  # the sleep command has started
    sleeper = int(sleeper_file.read_text())
    os.kill(sleeper, 0)  # the pair: it runs before the signal
    sent = time.monotonic()
    os.kill(int(pid_file.read_text()), signal.SIGTERM)
    child.join(timeout=60)
    assert not child.is_alive()
    assert time.monotonic() - sent < 30  # stopped mid-command, not after 60 s
    [outcome] = [x for x in lines if x.startswith("OUTCOME ")]
    assert json.loads(outcome.removeprefix("OUTCOME ")) == {
        "interrupted": True,
        "code": 1,
        "main": [["failed", "interrupted"]],
        "finally": ["ok"],
    }
    assert (tmp_path / "finally").read_text() == "ran"
    try:
        os.kill(sleeper, 0)
    except ProcessLookupError:
        pass  # the command's group is gone
    else:
        raise AssertionError(f"the command {sleeper} outlived its interrupt")
