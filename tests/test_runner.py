"""State grid of the runner (DM-5): inputs, exit codes, output, time, FakeRunner."""

import sys
import threading
import time
from pathlib import Path

import pytest

from pridem import runner
from pridem.runner import (
    TAIL_LINES,
    CommandFailed,
    CommandNotStarted,
    CommandTimedOut,
    FakeCall,
    FakeRunner,
    Runner,
    Stream,
    SubprocessRunner,
    UnplannedCommand,
)

TIMEOUT = 30.0
PY = sys.executable
SH = "/bin/sh"
DEADLOCK_JOIN_SECONDS = 30.0


class Lines:
    """An ``on_line`` sink that keeps every line with its stream."""

    def __init__(self) -> None:
        self.seen: list[tuple[Stream, str]] = []

    def __call__(self, stream: Stream, line: str) -> None:
        self.seen.append((stream, line))

    def of(self, stream: Stream) -> list[str]:
        return [line for s, line in self.seen if s is stream]


def _dead_or_zombie(pid: int) -> bool:
    """A process is gone, or a zombie nobody reaped (PID 1 of a sandbox may not)."""
    stat = Path(f"/proc/{pid}/stat")
    if not stat.exists():
        return True
    return stat.read_text().rsplit(")", 1)[1].split()[0] == "Z"


# --- argv, expect, timeout: refused before anything starts -------------------


@pytest.mark.parametrize("make", [SubprocessRunner, FakeRunner])
def test_empty_argv_is_refused(make: type[SubprocessRunner] | type[FakeRunner]) -> None:
    with pytest.raises(ValueError, match="argv"):
        make().run([], timeout=TIMEOUT, on_line=Lines())


@pytest.mark.parametrize("make", [SubprocessRunner, FakeRunner])
def test_string_argv_is_refused(
    make: type[SubprocessRunner] | type[FakeRunner],
) -> None:
    with pytest.raises(TypeError, match="not a string"):
        make().run("ls -l", timeout=TIMEOUT, on_line=Lines())


@pytest.mark.parametrize("make", [SubprocessRunner, FakeRunner])
def test_empty_expect_is_refused(
    make: type[SubprocessRunner] | type[FakeRunner],
) -> None:
    with pytest.raises(ValueError, match="expect"):
        make().run([PY, "-c", "pass"], expect=(), timeout=TIMEOUT, on_line=Lines())


@pytest.mark.parametrize("timeout", [0.0, -1.0])
def test_non_positive_timeout_is_refused(timeout: float) -> None:
    with pytest.raises(ValueError, match="timeout"):
        SubprocessRunner().run([PY, "-c", "pass"], timeout=timeout, on_line=Lines())


def test_command_not_in_path_is_not_started() -> None:
    with pytest.raises(CommandNotStarted) as error:
        SubprocessRunner().run(
            ["pridem-no-such-command"], timeout=TIMEOUT, on_line=Lines()
        )
    assert error.value.argv == ("pridem-no-such-command",)


def test_not_executable_file_is_not_started(tmp_path: Path) -> None:
    script = tmp_path / "script"
    script.write_text("#!/bin/sh\n")
    with pytest.raises(CommandNotStarted):
        SubprocessRunner().run([str(script)], timeout=TIMEOUT, on_line=Lines())


# --- exit codes --------------------------------------------------------------


def test_duplicate_codes_in_expect_are_accepted() -> None:
    result = SubprocessRunner().run(
        [PY, "-c", "pass"], expect=(0, 0), timeout=TIMEOUT, on_line=Lines()
    )
    assert result.code == 0


def test_killed_by_signal_is_negative_code() -> None:
    argv = [PY, "-c", "import os, signal; os.kill(os.getpid(), signal.SIGTERM)"]
    with pytest.raises(CommandFailed) as failed:
        SubprocessRunner().run(argv, timeout=TIMEOUT, on_line=Lines())
    assert failed.value.code == -15
    result = SubprocessRunner().run(
        argv, expect=(-15,), timeout=TIMEOUT, on_line=Lines()
    )
    assert result.code == -15


def test_failure_carries_last_lines_with_streams() -> None:
    script = (
        "import sys\n"
        "for i in range(30): print(i)\n"
        "sys.stderr.write('last\\n')\n"
        "sys.exit(1)\n"
    )
    with pytest.raises(CommandFailed) as failed:
        SubprocessRunner().run([PY, "-c", script], timeout=TIMEOUT, on_line=Lines())
    tail = failed.value.tail
    assert len(tail) == TAIL_LINES
    assert (Stream.STDOUT, "29") in tail
    assert (Stream.STDOUT, "9") not in tail
    assert (Stream.STDERR, "last") in tail
    assert "[stderr] last" in str(failed.value)


# --- output ------------------------------------------------------------------


def test_one_line() -> None:
    lines = Lines()
    SubprocessRunner().run([PY, "-c", "print('only')"], timeout=TIMEOUT, on_line=lines)
    assert lines.seen == [(Stream.STDOUT, "only")]


def test_repeated_and_empty_lines_are_each_delivered() -> None:
    lines = Lines()
    SubprocessRunner().run(
        [PY, "-c", "print('x'); print('x'); print(); print('y')"],
        timeout=TIMEOUT,
        on_line=lines,
    )
    assert lines.of(Stream.STDOUT) == ["x", "x", "", "y"]


def test_non_utf8_bytes_are_replaced_not_fatal() -> None:
    lines = Lines()
    script = "import sys; sys.stdout.buffer.write(b'\\xff\\xfeok\\n')"
    SubprocessRunner().run([PY, "-c", script], timeout=TIMEOUT, on_line=lines)
    assert lines.of(Stream.STDOUT) == ["\ufffd\ufffdok"]


def test_multibyte_character_split_between_reads_is_kept() -> None:
    script = (
        "import sys, time\n"
        "sys.stdout.buffer.write(b'\\xd0'); sys.stdout.flush(); time.sleep(0.3)\n"
        "sys.stdout.buffer.write(b'\\x96\\n'); sys.stdout.flush()\n"
    )
    lines = Lines()
    SubprocessRunner().run([PY, "-c", script], timeout=TIMEOUT, on_line=lines)
    assert lines.of(Stream.STDOUT) == ["\u0416"]


def test_lines_arrive_while_the_command_runs() -> None:
    arrived: list[float] = []

    def stamp(stream: Stream, line: str) -> None:
        arrived.append(time.monotonic())

    script = (
        "import time\nprint('a', flush=True)\ntime.sleep(1.0)\nprint('b', flush=True)"
    )
    SubprocessRunner().run([PY, "-c", script], timeout=TIMEOUT, on_line=stamp)
    assert len(arrived) == 2
    assert arrived[1] - arrived[0] >= 0.8


def test_output_larger_than_pipe_buffer_on_both_streams_does_not_deadlock() -> None:
    """1 MB on stderr and on stdout: reading one pipe to EOF first would block."""
    script = (
        "import sys\n"
        "for _ in range(1024): sys.stderr.write('e' * 1023 + '\\n')\n"
        "for _ in range(1024): sys.stdout.write('o' * 1023 + '\\n')\n"
    )
    lines = Lines()
    errors: list[BaseException] = []

    def target() -> None:
        try:
            SubprocessRunner().run(
                [PY, "-c", script], timeout=TIMEOUT * 4, on_line=lines
            )
        except BaseException as error:  # handed over to the test thread below
            errors.append(error)

    worker = threading.Thread(target=target, daemon=True)
    worker.start()
    worker.join(DEADLOCK_JOIN_SECONDS)
    if worker.is_alive():
        pytest.fail(
            f"runner did not finish in {DEADLOCK_JOIN_SECONDS} s "
            "on 2 MB of output: pipe deadlock"
        )
    assert errors == []
    assert len(lines.of(Stream.STDERR)) == 1024
    assert len(lines.of(Stream.STDOUT)) == 1024


def test_on_line_error_stops_the_command_and_propagates() -> None:
    def explode(stream: Stream, line: str) -> None:
        raise RuntimeError("sink failed")

    started = time.monotonic()
    script = "import time\nprint('x', flush=True)\ntime.sleep(300)"
    with pytest.raises(RuntimeError, match="sink failed"):
        SubprocessRunner().run([PY, "-c", script], timeout=TIMEOUT, on_line=explode)
    assert time.monotonic() - started < TIMEOUT


# --- cwd, env, stdin -----------------------------------------------------------


def test_cwd_and_env_are_passed(tmp_path: Path) -> None:
    lines = Lines()
    script = (
        "import os\n"
        "print(os.getcwd())\n"
        "print(os.environ.get('PRIDEM_X'))\n"
        "print('HOME' in os.environ)\n"
    )
    SubprocessRunner().run(
        [PY, "-c", script],
        timeout=TIMEOUT,
        cwd=tmp_path,
        env={"PRIDEM_X": "y"},
        on_line=lines,
    )
    assert lines.of(Stream.STDOUT) == [str(tmp_path), "y", "False"]


def test_stdin_is_closed() -> None:
    lines = Lines()
    SubprocessRunner().run(
        [PY, "-c", "import sys; print(repr(sys.stdin.read()))"],
        timeout=TIMEOUT,
        on_line=lines,
    )
    assert lines.of(Stream.STDOUT) == ["''"]


# --- time --------------------------------------------------------------------


def test_timeout_kills_the_whole_group(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(runner, "KILL_GRACE_SECONDS", 1.0)
    lines = Lines()
    with pytest.raises(CommandTimedOut) as timed_out:
        SubprocessRunner().run(
            [SH, "-c", "sleep 300 & echo $!; wait"], timeout=1.0, on_line=lines
        )
    grandchild = int(lines.of(Stream.STDOUT)[0])
    assert _dead_or_zombie(grandchild)
    assert timed_out.value.tail == ((Stream.STDOUT, str(grandchild)),)


def test_timeout_escalates_to_sigkill_after_grace(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(runner, "KILL_GRACE_SECONDS", 1.0)
    script = (
        "import signal, time\n"
        "signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
        "print('ignoring TERM', flush=True)\n"
        "time.sleep(300)\n"
    )
    started = time.monotonic()
    with pytest.raises(CommandTimedOut):
        SubprocessRunner().run([PY, "-c", script], timeout=1.0, on_line=Lines())
    elapsed = time.monotonic() - started
    assert 1.9 <= elapsed < 10.0


def test_descendant_holding_the_pipe_is_a_timeout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(runner, "KILL_GRACE_SECONDS", 1.0)
    lines = Lines()
    with pytest.raises(CommandTimedOut):
        SubprocessRunner().run(
            [SH, "-c", "sleep 300 & echo hi"], timeout=1.0, on_line=lines
        )
    assert lines.of(Stream.STDOUT) == ["hi"]


def test_finishing_in_time_is_not_a_timeout() -> None:
    result = SubprocessRunner().run(
        [PY, "-c", "import time; time.sleep(0.2)"], timeout=TIMEOUT, on_line=Lines()
    )
    assert result.code == 0


# --- FakeRunner ----------------------------------------------------------------


def test_fake_matching_argv_out_of_order_fails() -> None:
    fake = FakeRunner(FakeCall(("a",)), FakeCall(("b",)))
    with pytest.raises(UnplannedCommand, match="expected argv=\\['a'\\]"):
        fake.run(["b"], timeout=TIMEOUT, on_line=Lines())


def test_fake_same_argv_twice_consumes_in_order() -> None:
    with FakeRunner(FakeCall(("a",), code=0), FakeCall(("a",), code=2)) as fake:
        first = fake.run(["a"], timeout=TIMEOUT, on_line=Lines())
        second = fake.run(["a"], expect=(2,), timeout=TIMEOUT, on_line=Lines())
    assert (first.code, second.code) == (0, 2)


@pytest.mark.parametrize(
    ("cwd", "env"),
    [(Path("/elsewhere"), None), (None, {"X": "1"})],
)
def test_fake_cwd_and_env_are_part_of_the_match(
    cwd: Path | None, env: dict[str, str] | None
) -> None:
    fake = FakeRunner(FakeCall(("a",)))
    with pytest.raises(UnplannedCommand):
        fake.run(["a"], timeout=TIMEOUT, cwd=cwd, env=env, on_line=Lines())


def test_fake_scripted_timeout_and_not_started() -> None:
    with FakeRunner(
        FakeCall(("a",), lines=((Stream.STDOUT, "half"),), outcome="timeout"),
        FakeCall(("b",), outcome="not_started"),
    ) as fake:
        with pytest.raises(CommandTimedOut) as timed_out:
            fake.run(["a"], timeout=TIMEOUT, on_line=Lines())
        with pytest.raises(CommandNotStarted):
            fake.run(["b"], timeout=TIMEOUT, on_line=Lines())
    assert timed_out.value.tail == ((Stream.STDOUT, "half"),)


def test_fake_empty_script_without_calls_closes_cleanly() -> None:
    with FakeRunner() as fake:
        pass
    assert fake.calls == []


def test_both_runners_satisfy_the_protocol() -> None:
    """mypy checks this assignment; the runtime part only shows it is not empty."""
    runners: list[Runner] = [SubprocessRunner(), FakeRunner()]
    assert len(runners) == 2
