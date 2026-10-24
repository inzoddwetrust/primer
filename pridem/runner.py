"""The only place in pridem that starts external commands.

Every command goes through a ``Runner``. There is no quiet mode: the caller
names the exit codes it expects, and any other code raises ``CommandFailed``;
the caller must pass ``on_line``, which receives every output line as it
arrives; the caller must pass ``timeout``, after which the whole process group
is stopped and ``CommandTimedOut`` is raised.

``SubprocessRunner`` runs real processes. ``FakeRunner`` is a strict script for
tests: calls must arrive in the scripted order, an unplanned call fails at the
moment it is made, and an expectation left unconsumed fails when the script is
closed.

Every command error names the command one way, ``shlex.join(argv)``. The text
of ``CommandFailed`` and ``CommandTimedOut`` names the command and its exit
code or timeout, never its output: the last lines are the ``tail``
attribute, for the journal. A step that wraps the text of the error in its own
cannot carry the output into a reason, and a reason lives in the verdict.
"""

import codecs
import os
import re
import selectors
import shlex
import signal
import subprocess
import time
from collections import deque
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from types import TracebackType
from typing import IO, Literal, Protocol, Self, cast

KILL_GRACE_SECONDS = 5.0
"""Seconds between SIGTERM and SIGKILL to the process group on timeout.

SIGTERM first lets a command such as dpkg release shared host locks; SIGKILL
follows for whatever is still alive when the grace ends.
"""

TAIL_LINES = 20
"""Number of last output lines carried by ``CommandFailed`` and ``CommandTimedOut``."""

LINE_LIMIT = 65536
"""Longest output line handed to ``on_line``, in characters of decoded text.

A longer line arrives as consecutive pieces of this length and a remainder,
each its own call, every piece but the last with ``continued``: nothing is
dropped, and joined they are the line. Pending
text never exceeds this, so a command printing without newlines costs neither
unbounded memory nor quadratic copying. Characters, not bytes: a piece never
cuts a UTF-8 character.
"""

_READ_SIZE = 65536
_BREAK = re.compile(r"\r\n|\r|\n")
_POLL_SECONDS = 0.05


class Stream(StrEnum):
    """Output stream of a command."""

    STDOUT = "stdout"
    STDERR = "stderr"


# ``on_line(stream, line, continued)``: ``continued`` -- this is a piece of a line
# longer than ``LINE_LIMIT`` and more of the same line follows.
OnLine = Callable[[Stream, str, bool], None]
Tail = tuple[tuple[Stream, str], ...]


@dataclass(frozen=True)
class Result:
    """A finished command whose exit code was expected."""

    argv: tuple[str, ...]
    code: int


class RunnerError(Exception):
    """Base of the errors a runner raises for a command."""


class CommandNotStarted(RunnerError):
    """The command could not be started (not found, not executable)."""

    def __init__(self, argv: tuple[str, ...], reason: str) -> None:
        self.argv = argv
        self.reason = reason
        super().__init__(f"command not started: {shlex.join(argv)}: {reason}")


class CommandFailed(RunnerError):
    """The command exited with a code outside ``expect``."""

    def __init__(
        self, argv: tuple[str, ...], code: int, expect: tuple[int, ...], tail: Tail
    ) -> None:
        self.argv = argv
        self.code = code
        self.expect = expect
        self.tail = tail
        super().__init__(f"command failed: {shlex.join(argv)}: exit code {code}")


class CommandTimedOut(RunnerError):
    """The command did not finish in time; its process group was stopped."""

    def __init__(self, argv: tuple[str, ...], timeout: float, tail: Tail) -> None:
        self.argv = argv
        self.timeout = timeout
        self.tail = tail
        super().__init__(f"command timed out after {timeout} s: {shlex.join(argv)}")


class UnplannedCommand(AssertionError):
    """A ``FakeRunner`` received a call its script does not have at this point."""


class UnconsumedExpectation(AssertionError):
    """A ``FakeRunner`` was closed with scripted calls that never arrived."""


class Runner(Protocol):
    """Runs one external command and reports its output line by line."""

    def run(
        self,
        argv: Sequence[str],
        *,
        expect: tuple[int, ...] = (0,),
        timeout: float,
        cwd: Path | None = None,
        env: Mapping[str, str] | None = None,
        on_line: OnLine,
    ) -> Result:
        """Run ``argv``; return its result or raise a ``RunnerError``."""
        ...


def _validate(
    argv: Sequence[str], expect: tuple[int, ...], timeout: float
) -> tuple[str, ...]:
    if isinstance(argv, str):
        raise TypeError("argv must be a sequence of strings, not a string")
    if not argv:
        raise ValueError("argv must not be empty")
    if not expect:
        raise ValueError("expect must name at least one exit code")
    if timeout <= 0:
        raise ValueError(f"timeout must be positive, got {timeout}")
    return tuple(argv)


def _check(
    argv: tuple[str, ...], code: int, expect: tuple[int, ...], tail: Tail
) -> Result:
    if code not in expect:
        raise CommandFailed(argv, code, expect, tail)
    return Result(argv, code)


class SubprocessRunner:
    """Runs real processes, each in its own session and process group."""

    def run(
        self,
        argv: Sequence[str],
        *,
        expect: tuple[int, ...] = (0,),
        timeout: float,
        cwd: Path | None = None,
        env: Mapping[str, str] | None = None,
        on_line: OnLine,
    ) -> Result:
        """Run ``argv``; return its result or raise a ``RunnerError``."""
        command = _validate(argv, expect, timeout)
        deadline = time.monotonic() + timeout
        tail: deque[tuple[Stream, str]] = deque(maxlen=TAIL_LINES)

        def emit(stream: Stream, line: str, continued: bool) -> None:
            tail.append((stream, line))
            on_line(stream, line, continued)

        try:
            process = subprocess.Popen(
                command,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=cwd,
                env=None if env is None else dict(env),
                start_new_session=True,
            )
        except OSError as error:
            raise CommandNotStarted(command, error.strerror or str(error)) from error

        finished = False
        try:
            if not _pump(process, deadline, emit):
                raise CommandTimedOut(command, timeout, tuple(tail))
            try:
                code = process.wait(timeout=max(deadline - time.monotonic(), 0.0))
            except subprocess.TimeoutExpired as error:
                raise CommandTimedOut(command, timeout, tuple(tail)) from error
            finished = True
        finally:
            if not finished:
                _stop_group(process)
            for pipe in (process.stdout, process.stderr):
                if pipe is not None:
                    pipe.close()
        return _check(command, code, expect, tuple(tail))


class _Splitter:
    """Decoded output of one stream -> lines.

    ``\n``, ``\r`` and ``\r\n`` each end a line (progress bars of pip, apt and
    docker rewrite a line with a bare ``\r``); a ``\r`` at the very end of a
    piece is held until the next piece tells whether ``\n`` follows. A line
    longer than ``LINE_LIMIT`` is emitted in pieces of that length.
    """

    def __init__(self) -> None:
        self.pending = ""
        self._held_cr = False

    def feed(self, text: str) -> list[tuple[str, bool]]:
        """``(line, continued)`` completed by ``text``; the rest stays pending."""
        if self._held_cr:
            self._held_cr = False
            if text.startswith("\n"):
                text = text[1:]
        if text.endswith("\r"):
            self._held_cr = True
            text = text[:-1] + "\n"
        *lines, rest = _BREAK.split(text)
        out: list[tuple[str, bool]] = []
        for line in lines:
            out.extend(self._take(line, complete=True))
        out.extend(self._take(rest, complete=False))
        return out

    def finish(self) -> list[tuple[str, bool]]:
        """The unterminated last line, if there is one."""
        rest, self.pending = self.pending, ""
        return [(rest, False)] if rest else []

    def _take(self, part: str, *, complete: bool) -> list[tuple[str, bool]]:
        """Join ``part`` to the pending text; emit what is complete or full."""
        out: list[tuple[str, bool]] = []
        room = LINE_LIMIT - len(self.pending)
        while len(part) > room:
            out.append((self.pending + part[:room], True))
            self.pending, part, room = "", part[room:], LINE_LIMIT
        if complete:
            out.append((self.pending + part, False))
            self.pending = ""
        else:
            self.pending += part
        return out


def _pump(process: "subprocess.Popen[bytes]", deadline: float, emit: OnLine) -> bool:
    """Read both pipes to EOF, emitting lines; False if the deadline passed.

    At the deadline the unterminated line of each stream is emitted before the
    return: output is cut, never lost.
    """
    # Popen was called with stdout=PIPE and stderr=PIPE, so both are set.
    pipes = {
        cast("IO[bytes]", process.stdout).fileno(): Stream.STDOUT,
        cast("IO[bytes]", process.stderr).fileno(): Stream.STDERR,
    }
    decoders = {
        stream: codecs.getincrementaldecoder("utf-8")(errors="replace")
        for stream in Stream
    }
    splitters = {stream: _Splitter() for stream in Stream}
    with selectors.DefaultSelector() as selector:
        for fd in pipes:
            selector.register(fd, selectors.EVENT_READ)
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                # the cut output of a hung command is not lost: hand over what
                # each stream holds, its last undecoded bytes included
                for stream, splitter in splitters.items():
                    text = decoders[stream].decode(b"", final=True)
                    for line, continued in [*splitter.feed(text), *splitter.finish()]:
                        emit(stream, line, continued)
                return False
            for key, _ in selector.select(timeout=remaining):
                stream = pipes[key.fd]
                chunk = os.read(key.fd, _READ_SIZE)
                text = decoders[stream].decode(chunk, final=not chunk)
                splitter = splitters[stream]
                for line, continued in splitter.feed(text):
                    emit(stream, line, continued)
                if not chunk:
                    selector.unregister(key.fd)
                    for line, continued in splitter.finish():
                        emit(stream, line, continued)
    return True


def _signal_group(pgid: int, sig: int) -> bool:
    """Send ``sig`` to the process group; False when the group has no members."""
    try:
        os.killpg(pgid, sig)
    except ProcessLookupError:
        return False
    return True


def _stop_group(process: "subprocess.Popen[bytes]") -> None:
    """SIGTERM the process group, wait out the grace, SIGKILL it if still alive."""
    pgid = process.pid
    if _signal_group(pgid, signal.SIGTERM):
        grace_ends = time.monotonic() + KILL_GRACE_SECONDS
        alive = True
        while alive and time.monotonic() < grace_ends:
            process.poll()
            alive = _signal_group(pgid, 0)
            if alive:
                time.sleep(_POLL_SECONDS)
        # an emptied group's id may already belong to someone else: no SIGKILL
        if alive:
            _signal_group(pgid, signal.SIGKILL)
    process.wait()


@dataclass(frozen=True)
class FakeCall:
    """One scripted call of a ``FakeRunner`` and its recorded outcome."""

    argv: tuple[str, ...]
    code: int = 0
    lines: Tail = ()
    cwd: Path | None = None
    env: Mapping[str, str] | None = None
    outcome: Literal["exit", "timeout", "not_started"] = "exit"


class FakeRunner:
    """A strict scripted runner for tests.

    Calls are matched against the script in order by ``argv``, ``cwd`` and
    ``env``. A call that does not match the head of the script raises
    ``UnplannedCommand`` at once and is also remembered, so code under test
    that swallows the error still fails ``assert_consumed``. Recorded lines
    are replayed through ``on_line``; the recorded exit code goes through the
    same ``expect`` check as a real command. An empty script is allowed; a
    test that relies on "no command ran" must also show that something else
    did happen.
    """

    def __init__(self, *calls: FakeCall) -> None:
        self._script: deque[FakeCall] = deque(calls)
        self._violations: list[str] = []
        self.calls: list[tuple[str, ...]] = []

    def run(
        self,
        argv: Sequence[str],
        *,
        expect: tuple[int, ...] = (0,),
        timeout: float,
        cwd: Path | None = None,
        env: Mapping[str, str] | None = None,
        on_line: OnLine,
    ) -> Result:
        """Consume the next scripted call or fail on the spot."""
        command = _validate(argv, expect, timeout)
        actual = f"argv={list(command)} cwd={cwd} env={env}"
        if not self._script:
            self._violations.append(f"unplanned call, script is empty: {actual}")
            raise UnplannedCommand(self._violations[-1])
        head = self._script[0]
        if (head.argv, head.cwd, head.env) != (command, cwd, env):
            expected = f"argv={list(head.argv)} cwd={head.cwd} env={head.env}"
            self._violations.append(
                f"unplanned call: expected {expected}, got {actual}"
            )
            raise UnplannedCommand(self._violations[-1])
        self._script.popleft()
        self.calls.append(command)
        tail: deque[tuple[Stream, str]] = deque(maxlen=TAIL_LINES)
        for stream, line in head.lines:
            tail.append((stream, line))
            on_line(stream, line, False)
        if head.outcome == "timeout":
            raise CommandTimedOut(command, timeout, tuple(tail))
        if head.outcome == "not_started":
            raise CommandNotStarted(command, "scripted: not started")
        return _check(command, head.code, expect, tuple(tail))

    def assert_consumed(self) -> None:
        """Fail if any call was unplanned or any scripted call never arrived."""
        if self._violations:
            raise UnplannedCommand("\n".join(self._violations))
        if self._script:
            left = "\n".join(f"argv={list(call.argv)}" for call in self._script)
            raise UnconsumedExpectation(f"scripted calls never arrived:\n{left}")

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.assert_consumed()
