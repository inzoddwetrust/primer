"""State grid of the runner (DM-5): inputs, exit codes, output, time, FakeRunner."""

import contextlib
import json
import os
import pwd
import shlex
import signal
import sys
import threading
import time
from pathlib import Path

import pytest
from deadline_support import deadline

from pridem import runner
from pridem.interrupt import Interrupt, Interrupted
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

    def __call__(self, stream: Stream, line: str, continued: bool) -> None:
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
    """The text names the command as every runner error does: ``shlex.join``."""
    argv = ["pridem-no-such-command", "an arg"]
    with pytest.raises(CommandNotStarted) as error:
        SubprocessRunner().run(argv, timeout=TIMEOUT, on_line=Lines())
    assert error.value.argv == ("pridem-no-such-command", "an arg")
    assert error.value.reason
    assert str(error.value) == (
        f"command not started: pridem-no-such-command 'an arg': {error.value.reason}"
    )


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


def test_failure_carries_the_last_lines_of_one_stream() -> None:
    script = "import sys\nfor i in range(30): print(i)\nsys.exit(1)\n"
    with pytest.raises(CommandFailed) as failed:
        SubprocessRunner().run([PY, "-c", script], timeout=TIMEOUT, on_line=Lines())
    assert failed.value.tail == tuple((Stream.STDOUT, str(i)) for i in range(10, 30))
    assert len(failed.value.tail) == TAIL_LINES


def test_failure_tail_labels_both_streams() -> None:
    """The tail keeps both streams with labels; their mutual order is not asserted.

    The earlier form wrote 30 stdout lines and then one stderr line and expected
    the stderr line among the last 20. That held only where the child's stdout
    was unbuffered (PYTHONUNBUFFERED=1 in the sandbox): on the CI runner stdout
    is block-buffered in a pipe, flushed at exit after stderr, and the stderr line
    left the tail. The order between streams is arrival order, not write order,
    so the test now fits both streams into the tail and checks only labels.

    The text of the error used to carry the tail too; since DM-35 it names the
    command and its exit code only (the output is for the journal), so the
    labels are checked on ``tail`` and the text is checked exactly.
    """
    script = (
        "import sys\n"
        "for i in range(TAIL_LINES - 1): print(i)\n"
        "sys.stderr.write('last\\n')\n"
        "sys.exit(1)\n"
    ).replace("TAIL_LINES", str(TAIL_LINES))
    argv = [PY, "-c", script]
    with pytest.raises(CommandFailed) as failed:
        SubprocessRunner().run(argv, timeout=TIMEOUT, on_line=Lines())
    tail = failed.value.tail
    assert len(tail) == TAIL_LINES
    assert (Stream.STDERR, "last") in tail
    assert (Stream.STDOUT, "0") in tail
    assert str(failed.value) == f"command failed: {shlex.join(argv)}: exit code 1"


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

    def stamp(stream: Stream, line: str, continued: bool) -> None:
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


def _kill(*pids: int) -> None:
    """Clean-up by pid, never by group: a broken runner may share pytest's group."""
    for pid in pids:
        with contextlib.suppress(ProcessLookupError):
            os.kill(pid, signal.SIGKILL)


def test_on_line_error_stops_the_command_and_propagates() -> None:
    """The deadline turns a runner that cannot stop the command red by assertion
    (DM-39: it hung for 300 s); the command prints its pid for the clean-up."""
    seen: list[int] = []

    def explode(stream: Stream, line: str, continued: bool) -> None:
        seen.append(int(line))
        raise RuntimeError("sink failed")

    started = time.monotonic()
    script = "import os, time\nprint(os.getpid(), flush=True)\ntime.sleep(300)"
    try:
        with deadline(15.0), pytest.raises(RuntimeError, match="sink failed"):
            SubprocessRunner().run([PY, "-c", script], timeout=TIMEOUT, on_line=explode)
        assert time.monotonic() - started < TIMEOUT
    finally:
        _kill(*seen)


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


CONSTANT = {
    "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    "LANG": "C.UTF-8",
    "LC_ALL": "C.UTF-8",
}
"""The constants a command run with no ``env`` sees, written out here: a key
missing from ``CONSTANT_ENV`` or another value in it is red (DM-79)."""


def clean(home: str) -> dict[str, str]:
    """What a command run with no ``env`` sees for a user whose home is
    ``home`` in ``passwd`` (DM-88)."""
    return {**CONSTANT, "HOME": home, "DOCKER_CONFIG": f"{home}/.docker"}


def environment_seen() -> dict[str, str]:
    """The whole environment of a command run with no ``env``."""
    lines = Lines()
    SubprocessRunner().run(
        [PY, "-c", "import json, os; print(json.dumps(dict(os.environ)))"],
        timeout=TIMEOUT,
        on_line=lines,
    )
    seen: dict[str, str] = json.loads(lines.of(Stream.STDOUT)[0])
    return seen


def test_no_env_is_the_clean_minimum_not_the_process_one(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """DM-79: an ssh session's ``DOCKER_HOST``, ``COMPOSE_*`` or a product's
    variable never reaches a command run with no ``env``, and a process with
    no ``HOME`` (the timer's) gives the same environment: exactly the clean
    minimum. The pair -- an explicit ``env`` is passed as it is -- is
    ``test_cwd_and_env_are_passed``.

    The home expected is the running user's in ``passwd``, not ``/root``
    (DM-88): tier 1 runs as the runner's user, the sandbox as root, and the
    test is the same in both."""
    monkeypatch.setenv("DOCKER_HOST", "tcp://elsewhere:2375")
    monkeypatch.setenv("COMPOSE_PROJECT_NAME", "other")
    monkeypatch.setenv("POSTGRES_PASSWORD", "from-the-session")
    seen = []
    for home in ("/home/somebody", None):
        if home is None:
            monkeypatch.delenv("HOME", raising=False)
        else:
            monkeypatch.setenv("HOME", home)
        seen.append(environment_seen())
    expected = clean(pwd.getpwuid(os.getuid()).pw_dir)
    assert seen == [expected, expected]


def test_no_env_is_one_for_two_sessions_of_one_user(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """DM-88, repeat: two sessions of one user -- the timer's, with no
    ``HOME`` and an empty ``DOCKER_CONFIG``, and an ssh one with another
    ``HOME`` and ``DOCKER_CONFIG`` -- give one environment, the clean one of
    the user in ``passwd``; neither ``DOCKER_CONFIG`` of the process is in it."""
    monkeypatch.delenv("HOME", raising=False)
    monkeypatch.setenv("DOCKER_CONFIG", "")
    timer = environment_seen()
    monkeypatch.setenv("HOME", "/home/somebody")
    monkeypatch.setenv("DOCKER_CONFIG", "/home/somebody/.docker-elsewhere")
    session = environment_seen()
    home = pwd.getpwuid(os.getuid()).pw_dir
    assert timer == session == clean(home)
    assert timer["DOCKER_CONFIG"] == f"{home}/.docker"


def test_no_env_with_no_passwd_entry_is_not_started(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """DM-88, a uid with no entry in ``passwd`` (a CI job's ``--user N``):
    there is no home to give, so a command with no ``env`` is not started
    and says why; the pair -- the same uid with an explicit ``env`` runs."""
    uid = 4242
    real = pwd.getpwuid

    def entry(asked: int) -> pwd.struct_passwd:
        if asked == uid:
            raise KeyError(f"getpwuid(): uid not found: {asked}")
        return real(asked)

    monkeypatch.setattr(os, "getuid", lambda: uid)
    monkeypatch.setattr(pwd, "getpwuid", entry)
    with pytest.raises(CommandNotStarted) as raised:
        SubprocessRunner().run([PY, "-c", "pass"], timeout=TIMEOUT, on_line=Lines())
    assert raised.value.reason == f"no passwd entry for uid {uid}"
    lines = Lines()
    SubprocessRunner().run(
        [PY, "-c", "print('ran')"],
        timeout=TIMEOUT,
        env={"PATH": "/usr/bin:/bin"},
        on_line=lines,
    )
    assert lines.of(Stream.STDOUT) == ["ran"]


def test_no_env_finds_a_program_on_the_clean_path_alone(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """DM-79: a program on the process's ``PATH`` alone is not started: the
    clean ``PATH`` is the only one; the pair -- the same name with that
    directory in an explicit ``env`` runs."""
    program = tmp_path / "pridem-dm79-only-here"
    program.write_text("#!/bin/sh\necho here\n")
    program.chmod(0o755)
    monkeypatch.setenv("PATH", f"{tmp_path}:{os.environ['PATH']}")
    with pytest.raises(CommandNotStarted):
        SubprocessRunner().run([program.name], timeout=TIMEOUT, on_line=Lines())
    lines = Lines()
    SubprocessRunner().run(
        [program.name],
        timeout=TIMEOUT,
        env={"PATH": f"{tmp_path}:/usr/bin:/bin"},
        on_line=lines,
    )
    assert lines.of(Stream.STDOUT) == ["here"]


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
    """The deadline makes a runner that cannot reach the group red by assertion.

    The shell prints its own pid and the sleeper's, so a test that hit its
    deadline still kills both (DM-39: it used to hang for 300 s).
    """
    monkeypatch.setattr(runner, "KILL_GRACE_SECONDS", 1.0)
    lines = Lines()
    try:
        with deadline(10.0), pytest.raises(CommandTimedOut) as timed_out:
            SubprocessRunner().run(
                [SH, "-c", "sleep 300 & echo $$ $!; wait"], timeout=1.0, on_line=lines
            )
        shell, grandchild = map(int, lines.of(Stream.STDOUT)[0].split())
        assert _dead_or_zombie(grandchild)
        assert timed_out.value.tail == ((Stream.STDOUT, f"{shell} {grandchild}"),)
    finally:
        _kill(*map(int, " ".join(lines.of(Stream.STDOUT)[:1]).split()))


def test_timeout_escalates_to_sigkill_after_grace(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A command ignoring SIGTERM dies by SIGKILL after the grace; red by assertion
    within the deadline if it does not (DM-39: it used to hang for 300 s)."""
    monkeypatch.setattr(runner, "KILL_GRACE_SECONDS", 1.0)
    script = (
        "import os, signal, time\n"
        "signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
        "print(os.getpid(), flush=True)\n"
        "time.sleep(300)\n"
    )
    lines = Lines()
    started = time.monotonic()
    try:
        with deadline(10.0), pytest.raises(CommandTimedOut):
            SubprocessRunner().run([PY, "-c", script], timeout=1.0, on_line=lines)
        elapsed = time.monotonic() - started
        assert 1.9 <= elapsed < 10.0
    finally:
        _kill(*map(int, lines.of(Stream.STDOUT)[:1]))


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
        FakeCall(("b", "x y"), outcome="not_started"),
    ) as fake:
        with pytest.raises(CommandTimedOut) as timed_out:
            fake.run(["a"], timeout=TIMEOUT, on_line=Lines())
        with pytest.raises(CommandNotStarted) as not_started:
            fake.run(["b", "x y"], timeout=TIMEOUT, on_line=Lines())
    assert timed_out.value.tail == ((Stream.STDOUT, "half"),)
    assert str(not_started.value) == (
        "command not started: b 'x y': scripted: not started"
    )


def test_fake_empty_script_without_calls_closes_cleanly() -> None:
    with FakeRunner() as fake:
        pass
    assert fake.calls == []


def test_both_runners_satisfy_the_protocol() -> None:
    """mypy checks this assignment; the runtime part only shows it is not empty."""
    runners: list[Runner] = [SubprocessRunner(), FakeRunner()]
    assert len(runners) == 2


def test_an_emptied_group_gets_no_sigkill(monkeypatch: pytest.MonkeyPatch) -> None:
    """DM-39: once the group is gone its id may be someone else's; no SIGKILL.

    The pair: a group still alive when the grace ends does get SIGKILL.
    """
    monkeypatch.setattr(runner, "KILL_GRACE_SECONDS", 1.0)
    sent: list[int] = []
    real = os.killpg

    def recording(pgid: int, sig: int) -> None:
        sent.append(sig)
        real(pgid, sig)

    monkeypatch.setattr(os, "killpg", recording)
    with deadline(10.0), pytest.raises(CommandTimedOut):
        SubprocessRunner().run(
            [PY, "-c", "import time; time.sleep(300)"], timeout=0.5, on_line=Lines()
        )
    assert sent[0] == signal.SIGTERM and signal.SIGKILL not in sent
    sent.clear()
    stubborn = (
        "import signal, time\n"
        "signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
        "time.sleep(300)\n"
    )
    with deadline(10.0), pytest.raises(CommandTimedOut):
        SubprocessRunner().run([PY, "-c", stubborn], timeout=1.5, on_line=Lines())
    assert sent[0] == signal.SIGTERM and sent[-1] == signal.SIGKILL


# --- DM-45: the interrupt and the box lock -----------------------------------------


def _signal_after(interrupt: Interrupt, seconds: float) -> threading.Thread:
    def fire() -> None:
        time.sleep(seconds)
        interrupt.receive(signal.SIGTERM)

    thread = threading.Thread(target=fire)
    thread.start()
    return thread


def test_a_signal_stops_the_command_mid_way_unless_shielded() -> None:
    """A signal while a command runs stops its group there: ``Interrupted``
    long before the command would end; the pair: under the shield of
    ``finally`` the command runs to its end."""
    interrupt = Interrupt()
    runner = SubprocessRunner(interrupt)
    interrupt.watch()
    thread = _signal_after(interrupt, 0.3)
    began = time.monotonic()
    with pytest.raises(Interrupted):
        runner.run(["sleep", "20"], timeout=60, on_line=lambda *_: None)
    assert time.monotonic() - began < 10
    thread.join()
    with interrupt.shield():
        thread = _signal_after(interrupt, 0.1)
        result = runner.run(["sleep", "0.6"], timeout=60, on_line=lambda *_: None)
        thread.join()
    assert result.code == 0


def test_the_box_lock_is_handed_to_the_command(tmp_path: Path) -> None:
    """``hold``: the lock's descriptor is open in the command, so the box stays
    held while any process of it lives; the pair: without ``hold`` it is not."""
    lock = os.open(tmp_path / "lock", os.O_RDWR | os.O_CREAT, 0o600)
    seen: list[str] = []
    probe = ["sh", "-c", f"test -e /proc/self/fd/{lock} && echo held || echo free"]
    try:
        SubprocessRunner().run(
            probe, timeout=30, on_line=lambda s, line, c: seen.append(line)
        )
        held = SubprocessRunner()
        held.hold(lock)
        held.run(probe, timeout=30, on_line=lambda s, line, c: seen.append(line))
    finally:
        os.close(lock)
    assert seen == ["free", "held"]
