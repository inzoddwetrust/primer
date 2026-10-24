"""Probes DM-5: the runner boundary, the strict FakeRunner, exit-code aggregation."""

import sys

import pytest

from pridem.report.codes import ExitCode, worst
from pridem.runner import (
    CommandFailed,
    FakeCall,
    FakeRunner,
    Stream,
    SubprocessRunner,
    UnconsumedExpectation,
    UnplannedCommand,
)

TIMEOUT = 30.0
PY = sys.executable


class Lines:
    """An ``on_line`` sink that keeps every line with its stream."""

    def __init__(self) -> None:
        self.seen: list[tuple[Stream, str]] = []

    def __call__(self, stream: Stream, line: str, continued: bool) -> None:
        self.seen.append((stream, line))

    def of(self, stream: Stream) -> list[str]:
        return [line for s, line in self.seen if s is stream]


def test_probe_DM_5_unplanned_command_fails_test() -> None:
    fake = FakeRunner(FakeCall(("git", "fetch")))
    with pytest.raises(UnplannedCommand):
        fake.run(["git", "pull"], timeout=TIMEOUT, on_line=Lines())
    assert issubclass(UnplannedCommand, AssertionError)

    # Code under test that swallows the error does not hide it.
    swallowing = FakeRunner()
    caught = False
    try:
        swallowing.run(["rm", "-rf", "/opt/x"], timeout=TIMEOUT, on_line=Lines())
    except Exception:  # stands for code under test that swallows errors
        caught = True
    assert caught
    with pytest.raises(UnplannedCommand, match="rm"):
        swallowing.assert_consumed()

    # Pair: the planned call passes and is recorded.
    with FakeRunner(FakeCall(("git", "fetch"))) as planned:
        result = planned.run(["git", "fetch"], timeout=TIMEOUT, on_line=Lines())
    assert result.code == 0
    assert planned.calls == [("git", "fetch")]


def test_probe_DM_5_unconsumed_expectation_fails_test() -> None:
    fake = FakeRunner(FakeCall(("a",)), FakeCall(("b",)))
    fake.run(["a"], timeout=TIMEOUT, on_line=Lines())
    with pytest.raises(UnconsumedExpectation, match="'b'"):
        fake.assert_consumed()

    with pytest.raises(UnconsumedExpectation):
        with FakeRunner(FakeCall(("a",))):
            pass

    # Pair: a fully consumed script closes cleanly, and both calls happened.
    with FakeRunner(FakeCall(("a",)), FakeCall(("b",))) as full:
        full.run(["a"], timeout=TIMEOUT, on_line=Lines())
        full.run(["b"], timeout=TIMEOUT, on_line=Lines())
    assert full.calls == [("a",), ("b",)]


def test_probe_DM_5_expect_mismatch_raises_command_failed() -> None:
    argv = [PY, "-c", "print('before exit'); raise SystemExit(3)"]
    with pytest.raises(CommandFailed) as failed:
        SubprocessRunner().run(argv, timeout=TIMEOUT, on_line=Lines())
    assert failed.value.code == 3
    assert failed.value.argv == tuple(argv)
    assert failed.value.tail == ((Stream.STDOUT, "before exit"),)

    fake = FakeRunner(FakeCall(("x",), code=3, lines=((Stream.STDERR, "boom"),)))
    with pytest.raises(CommandFailed) as fake_failed:
        fake.run(["x"], timeout=TIMEOUT, on_line=Lines())
    assert fake_failed.value.code == 3
    assert fake_failed.value.tail == ((Stream.STDERR, "boom"),)

    # Pair: the same code is a result when it is expected.
    result = SubprocessRunner().run(argv, expect=(3,), timeout=TIMEOUT, on_line=Lines())
    assert result.code == 3


def test_probe_DM_5_output_lines_become_events() -> None:
    script = (
        "import sys\n"
        "print('one'); print('two')\n"
        "sys.stderr.write('err-1\\nerr-2\\n')\n"
        "sys.stdout.write('no newline')\n"
    )
    lines = Lines()
    SubprocessRunner().run([PY, "-c", script], timeout=TIMEOUT, on_line=lines)
    assert lines.of(Stream.STDOUT) == ["one", "two", "no newline"]
    assert lines.of(Stream.STDERR) == ["err-1", "err-2"]

    replayed = Lines()
    recorded = ((Stream.STDOUT, "one"), (Stream.STDERR, "err-1"))
    with FakeRunner(FakeCall(("x",), lines=recorded)) as fake:
        fake.run(["x"], timeout=TIMEOUT, on_line=replayed)
    assert replayed.seen == list(recorded)

    # Pair: empty output gives zero lines and is not a failure.
    silent = Lines()
    result = SubprocessRunner().run([PY, "-c", "pass"], timeout=TIMEOUT, on_line=silent)
    assert result.code == 0
    assert silent.seen == []


def test_probe_DM_5_aggregate_worst_code() -> None:
    assert worst([0, 2, 1]) is ExitCode.FAILED
    assert worst([0, 2]) is ExitCode.INCOMPLETE
    assert worst([0]) is ExitCode.OK
    with pytest.raises(ValueError, match="no codes"):
        worst([])
