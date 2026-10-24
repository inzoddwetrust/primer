"""Probes DM-39: an output line is bounded and ``\\r`` ends a line.

Linearity is measured by what is pending between reads, not by time: pending
text never exceeds ``LINE_LIMIT``, so each read copies at most the limit plus
the piece, whatever the length of the line.
"""

import sys

import pytest
from deadline_support import deadline

from pridem.runner import LINE_LIMIT, Stream, SubprocessRunner, _Splitter

PY = sys.executable


def _split(pieces: list[str]) -> list[str]:
    splitter = _Splitter()
    out: list[str] = []
    for piece in pieces:
        out += [line for line, _ in splitter.feed(piece)]
    return out + [line for line, _ in splitter.finish()]


class _Lines:
    def __init__(self) -> None:
        self.got: list[tuple[Stream, str]] = []

    def __call__(self, stream: Stream, line: str, continued: bool) -> None:
        self.got.append((stream, line))


def test_probe_DM_39_endless_line_is_bounded() -> None:
    piece = "é" * 65536  # two bytes each: a cut never splits a character
    splitter = _Splitter()
    emitted: list[str] = []
    for _ in range(160):  # 10 Mi characters, no newline
        emitted += [line for line, _ in splitter.feed(piece)]
        assert len(splitter.pending) <= LINE_LIMIT
    emitted += [line for line, _ in splitter.finish()]
    assert all(len(line) <= LINE_LIMIT for line in emitted)
    assert "".join(emitted) == piece * 160  # nothing dropped
    assert [len(x) for x in _split(["y" * LINE_LIMIT + "\n"])] == [LINE_LIMIT]
    assert [len(x) for x in _split(["y" * (LINE_LIMIT + 1)])] == [LINE_LIMIT, 1]

    lines = _Lines()
    script = "import sys; sys.stdout.write('x' * (1 << 20)); sys.stdout.flush()"
    with deadline(30.0):
        SubprocessRunner().run([PY, "-c", script], timeout=20.0, on_line=lines)
    out = [line for stream, line in lines.got if stream is Stream.STDOUT]
    assert all(len(line) <= LINE_LIMIT for line in out)
    assert "".join(out) == "x" * (1 << 20) and len(out) == 16


@pytest.mark.parametrize(
    ("pieces", "lines"),
    [
        (["a\rb\r\nc\n"], ["a", "b", "c"]),
        (["a\r", "\nb"], ["a", "b"]),  # \r ends a read, \n begins the next
        (["a\r", "b"], ["a", "b"]),
        (["50%\r100%\rdone\n"], ["50%", "100%", "done"]),
        (["x\r"], ["x"]),
        (["a\n\nb"], ["a", "", "b"]),
    ],
    ids=[
        "mixed",
        "crlf-across-reads",
        "cr-across-reads",
        "progress",
        "cr-at-eof",
        "empty",
    ],
)
def test_probe_DM_39_carriage_return_splits_lines(
    pieces: list[str], lines: list[str]
) -> None:
    assert _split(pieces) == lines


def test_progress_of_a_live_command_arrives_line_by_line() -> None:
    script = (
        "import sys, time\n"
        "for n in (10, 50, 100):\n"
        "    sys.stdout.write(f'{n}%\\r'); sys.stdout.flush(); time.sleep(0.05)\n"
        "sys.stdout.write('done\\r\\n')\n"
    )
    lines = _Lines()
    with deadline(30.0):
        SubprocessRunner().run([PY, "-c", script], timeout=20.0, on_line=lines)
    assert [line for _, line in lines.got] == ["10%", "50%", "100%", "done"]
