"""Probe DM-44: a known secret cut by a piece boundary of a long line never
reaches the journal, whole or in parts; the plan's docstring says what the plan
does, not how signals reach it.

The marker is made of characters the surrounding text of the probe never uses
(the filler is dots), so any shared stretch of five characters is a leak, not
a coincidence.
"""

import json
import sys
from pathlib import Path

import pytest
from deadline_support import deadline
from plan_support import NOW, Journal, ListSink, ScriptedStep
from pydantic import SecretStr
from state_support import header, run_id

import pridem.plan
from pridem.events import REDACTED, LogLine, Secrets, StepFinished, StepRecord
from pridem.plan import Plan, StackSteps
from pridem.runner import LINE_LIMIT, Stream, SubprocessRunner, _Splitter
from pridem.state import Box, JournalSink

MARKER = "Q7Z3X9W1V5K8J2H6"
LONG = (MARKER * (LINE_LIMIT // len(MARKER) + 2))[: LINE_LIMIT + 10]


def _journal_lines(path: Path) -> list[dict[str, object]]:
    rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
    return [row for row in rows if row.get("event") == "log"]


def _leaks(text: str, secret: str) -> list[str]:
    return sorted({secret[i : i + 5] for i in range(len(secret) - 4)} & _fives(text))


def _fives(text: str) -> set[str]:
    return {text[i : i + 5] for i in range(len(text) - 4)}


def _write(tmp_path: Path, secret: str, line: str) -> list[dict[str, object]]:
    """``line`` through the splitter and the journal sink; the written log rows."""
    box = Box(tmp_path)
    run = run_id(1)
    with box.lock("a"):
        box.open_journal(header(run), Secrets(())).close()
    sink = JournalSink(box.journals / f"{run}.jsonl", Secrets([SecretStr(secret)]))
    splitter = _Splitter()
    for piece, continued in [*splitter.feed(line + "\n"), *splitter.finish()]:
        sink.emit(LogLine("main", "aivis", "up", Stream.STDOUT, piece, continued))
    sink.close()
    return _journal_lines(box.journals / f"{run}.jsonl")


@pytest.mark.parametrize("offset", range(len(MARKER) + 1))
def test_probe_DM_44_secret_across_a_chunk_boundary_is_redacted(
    tmp_path: Path, offset: int
) -> None:
    """The piece boundary falls before each character of the secret and after it."""
    line = "." * (LINE_LIMIT - offset) + MARKER + "." * 100
    rows = _write(tmp_path, MARKER, line)
    written = "".join(str(row["line"]) for row in rows)
    assert _leaks(json.dumps(rows), MARKER) == []
    assert written == line.replace(MARKER, REDACTED)  # nothing else lost
    assert [row.get("continued", False) for row in rows][-1] is False


def test_secret_longer_than_a_piece_is_redacted(tmp_path: Path) -> None:
    line = "." * 100 + LONG + "." * 100
    rows = _write(tmp_path, LONG, line)
    assert _leaks(json.dumps(rows), LONG) == []
    assert "".join(str(row["line"]) for row in rows) == line.replace(LONG, REDACTED)


def test_two_secrets_at_one_boundary(tmp_path: Path) -> None:
    other = "M4N8P2R6T0V3W7Y1"
    secrets = Secrets([SecretStr(MARKER), SecretStr(other)])
    text = "." * 20 + MARKER + other
    # MARKER ends before the hold, ``other`` crosses it: the cut moves to its start
    assert secrets.safe_cut(text) == 20 + len(MARKER)
    line = "." * (LINE_LIMIT - 8) + MARKER + other + "." * 50
    box = Box(tmp_path)
    with box.lock("a"):
        box.open_journal(header(run_id(1)), Secrets(())).close()
    path = box.journals / f"{run_id(1)}.jsonl"
    sink = JournalSink(path, secrets)
    splitter = _Splitter()
    for piece, continued in [*splitter.feed(line + "\n"), *splitter.finish()]:
        sink.emit(LogLine("main", "aivis", "up", Stream.STDOUT, piece, continued))
    sink.close()
    rows = _journal_lines(path)
    assert (
        _leaks(json.dumps(rows), MARKER) == [] and _leaks(json.dumps(rows), other) == []
    )


def test_held_end_is_written_when_the_line_never_ends(tmp_path: Path) -> None:
    """A line cut by a timeout: what is held goes out at StepFinished and close."""
    box = Box(tmp_path)
    with box.lock("a"):
        box.open_journal(header(run_id(1)), Secrets(())).close()
    path = box.journals / f"{run_id(1)}.jsonl"
    sink = JournalSink(path, Secrets([SecretStr(MARKER)]))
    head = "." * (LINE_LIMIT - 5) + MARKER[:5]
    sink.emit(LogLine("main", "aivis", "up", Stream.STDOUT, head, True))
    sink.emit(LogLine("main", "aivis", "logs", Stream.STDERR, "x" * LINE_LIMIT, True))
    record = StepRecord("aivis", "up", 1, "ok", None, NOW, 1.0, {"cut": True})
    sink.emit(StepFinished("main", record))
    lines = _journal_lines(path)
    assert "".join(str(row["line"]) for row in lines if row["name"] == "up") == head
    sink.close()
    lines = _journal_lines(path)
    assert "".join(str(row["line"]) for row in lines if row["name"] == "logs") == (
        "x" * LINE_LIMIT
    )


def test_live_command_through_the_plan(tmp_path: Path) -> None:
    """Runner -> plan -> journal: the runner says ``continued``, the sink cleans."""
    script = (
        "import sys\n"
        f"sys.stdout.write('.' * {LINE_LIMIT - 7} + '{MARKER}' + '...' + '\\n')\n"
    )
    box = Box(tmp_path)
    run = run_id(1)
    with box.lock("a"):
        sink = box.open_journal(header(run), Secrets([SecretStr(MARKER)]))
        step = ScriptedStep("up", 1, Journal(), act_argv=[sys.executable, "-c", script])
        plan = Plan(
            [StackSteps("aivis", [step], root=True)],
            mode="deploy",
            role="test",
            runner=SubprocessRunner(),
            sink=sink,
            clock=lambda: 0.0,
            now=lambda: NOW,
        )
        with deadline(30.0):
            plan.run()
        sink.close()
    rows = _journal_lines(box.journals / f"{run}.jsonl")
    assert _leaks(json.dumps(rows), MARKER) == []
    assert any(row.get("continued") for row in rows)
    assert REDACTED in "".join(str(row["line"]) for row in rows)


def test_hung_command_keeps_its_unterminated_line() -> None:
    """DM-44 work 3: at the deadline the cut line of each stream is handed over."""
    script = (
        "import sys, time\n"
        "sys.stdout.write('half a line'); sys.stdout.flush()\n"
        "sys.stderr.write('и полстроки'); sys.stderr.flush()\n"
        "time.sleep(300)\n"
    )
    got: list[tuple[Stream, str]] = []

    def collect(stream: Stream, line: str, continued: bool) -> None:
        got.append((stream, line))

    from pridem import runner

    with deadline(15.0), pytest.raises(runner.CommandTimedOut) as timed_out:
        SubprocessRunner().run(
            [sys.executable, "-c", script], timeout=1.0, on_line=collect
        )
    assert set(got) == {
        (Stream.STDOUT, "half a line"),
        (Stream.STDERR, "и полстроки"),
    }
    assert len(timed_out.value.tail) == 2


def test_plan_docstring_says_nothing_of_signal_mechanics() -> None:
    doc = pridem.plan.__doc__ or ""
    assert "KeyboardInterrupt" in doc
    assert "SIGTERM" not in doc and "signal" not in doc.lower()


def test_list_sink_still_takes_pieces() -> None:
    """A sink that is not the journal gets the pieces as they come."""
    sink = ListSink()
    sink.emit(LogLine("main", "aivis", "up", Stream.STDOUT, "a", True))
    assert sink.lines()[0].continued is True
