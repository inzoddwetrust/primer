"""Probes DM-36: no damaged file blocks the box, its files are private, a run id
cannot leave its directory (contract 2 v1.4, TZ 0.7.8 section 7.3).
"""

import os
import stat
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

import pytest
from pydantic import ValidationError
from report_support import MARKER, SECRETS, example, load
from state_support import AFTER, header, run_id, state, verdict

from pridem.events import LogLine, StepFinished, StepRecord, StepStarted
from pridem.runner import Stream
from pridem.state import Box, JournalHeader, Recovery

BUILD_STEP = {"phase": "main", "stack": "aivis", "name": "build"}

STARTED = header(run_id(1)).started
DAMAGED_STATE = [
    b"not json at all " + MARKER.encode(),
    b'{"composition": "' + MARKER.encode() + b'"}',
    b'{"composition": {"pridem": "\xff\xfe' + MARKER.encode() + b'"}}',
    b"",
]


def _journal(box: Box, run: str) -> Path:
    """A run that finished a step, logged a line and died."""
    sink = box.open_journal(header(run), SECRETS)
    sink.emit(StepStarted("main", "aivis", "build", 6, STARTED))
    record = StepRecord("aivis", "build", 6, "ok", None, STARTED, 1.0, {"id": "x"})
    sink.emit(StepFinished("main", record))
    sink.emit(LogLine("main", "aivis", "up", Stream.STDOUT, "working"))
    sink.close()
    return box.journals / f"{run}.jsonl"


def test_probe_DM_36_torn_utf8_never_blocks_the_box(tmp_path: Path) -> None:
    """DM-42 (contract 2 v1.6): reasons and incomplete entries are codes with
    parameters, not phrases; the data changed form only, each assertion keeps
    its strength.
    """
    box = Box(tmp_path)
    with box.lock("dying"):
        torn, middle, head = (_journal(box, run_id(n)) for n in (1, 2, 3))
    # the writer died inside a two-byte character of its last line
    torn.write_bytes(torn.read_bytes() + b'{"event": "log", "line": "\xd0')
    lines = middle.read_bytes().split(b"\n")
    lines[2] = b'{"event": "log", "line": "\xff\xfe"}'
    middle.write_bytes(b"\n".join(lines))
    head.write_bytes(b"\xff" + head.read_bytes())
    with box.lock("next"):
        done = box.recover(SECRETS, "0.3.1")
    assert done.quarantined == (run_id(3),)
    assert [v.run_id for v in done.verdicts] == [run_id(1), run_id(2)]
    # DM-42 (contract 2 v1.6): codes with parameters instead of phrases
    entries = [v.report.incomplete[0].model_dump() for v in done.verdicts]
    assert entries == [
        {"what": "run", "code": "no-verdict", "ended_at": BUILD_STEP},
        {"what": "run", "code": "journal-damaged", "line": 3},
    ]
    with box.lock("after"):  # the box is not blocked
        assert box.recover(SECRETS, "0.3.1") == Recovery((), ())


@pytest.mark.parametrize(
    "content", DAMAGED_STATE, ids=["text", "schema", "utf8", "empty"]
)
def test_probe_DM_36_damaged_state_is_quarantined(
    tmp_path: Path, content: bytes
) -> None:
    """DM-42 (contract 2 v1.6): reasons and incomplete entries are codes with
    parameters, not phrases; the data changed form only, each assertion keeps
    its strength.
    """
    box = Box(tmp_path)
    with box.lock("dying"):
        _journal(box, run_id(1))
    (tmp_path / "state.json").write_bytes(content)
    with box.lock("next"):
        done = box.recover(SECRETS, "0.3.1")
        assert box.state_quarantined and done.state_quarantined
    assert not (tmp_path / "state.json").exists()
    assert (tmp_path / "state.json.damaged").read_bytes() == content
    (red,) = done.verdicts
    # DM-42 (contract 2 v1.6): codes with parameters instead of phrases
    assert [i.model_dump() for i in red.report.incomplete] == [
        {"what": "run", "code": "no-verdict", "ended_at": BUILD_STEP},
        {"what": "state", "code": "quarantined"},
    ]
    assert red.composition_after == {"pridem": "0.3.1"}
    assert MARKER not in red.model_dump_json()

    healthy = Box(tmp_path / "healthy")
    with healthy.lock("a"):
        healthy.write_state(state())
        healthy.write_verdict(verdict(run_id(2)))
        assert not healthy.state_quarantined
    kept = healthy.read_state()
    assert kept is not None and kept.composition == AFTER
    assert kept.last_run == {"deploy": run_id(2)}


@contextmanager
def _umask(mask: int) -> Iterator[None]:
    old = os.umask(mask)
    try:
        yield
    finally:
        os.umask(old)


@pytest.mark.parametrize("mask", [0o000, 0o077], ids=["open", "tight"])
def test_probe_DM_36_box_files_are_private(tmp_path: Path, mask: int) -> None:
    root = tmp_path / "pridem"
    box = Box(root)
    with _umask(mask):
        with box.lock("a"):
            box.write_state(state())
            box.open_journal(header(run_id(1)), SECRETS).close()
            box.write_verdict(verdict(run_id(1)))
        (root / "state.json").write_bytes(b"{")
        with box.lock("b"):
            assert box.read_state() is None  # quarantined
    modes = {
        str(path.relative_to(root)): stat.S_IMODE(path.stat().st_mode)
        for path in [root, *root.rglob("*")]
    }
    assert modes == {
        ".": 0o700,
        "history": 0o700,
        "journal": 0o700,
        "lock": 0o600,
        "state.json.damaged": 0o600,
        f"history/{run_id(1)}.json": 0o600,
        f"journal/{run_id(1)}.jsonl": 0o600,
    }


ESCAPES = [
    f"../{run_id(1)}",
    f"history/../../{run_id(1)}",
    f"x{run_id(1)}",
    f"{run_id(1)}x",
    f"{run_id(1)}/..",
]


@pytest.mark.parametrize("bad", ESCAPES)
def test_probe_DM_36_run_id_cannot_leave_its_directory(
    tmp_path: Path, bad: str
) -> None:
    root = tmp_path / "pridem"
    box = Box(root)
    data = example()
    data["run_id"], data["log_ref"] = bad, f"journal/{bad}.jsonl"
    with pytest.raises(ValidationError, match="run_id"):
        load(data)
    raw = header(run_id(1)).model_dump()
    raw["run_id"] = bad
    with pytest.raises(ValidationError, match="run_id"):
        JournalHeader.model_validate(raw)
    (tmp_path / f"{run_id(1)}.json").write_text("outside", encoding="utf-8")
    for read in (box.read_verdict, box.read_journal):
        with pytest.raises(ValidationError):
            read(bad)
    with box.lock("a"):
        box.write_verdict(verdict(run_id(1)))
    assert box.read_verdict(run_id(1)).run_id == run_id(1)
    assert sorted(p.name for p in tmp_path.iterdir()) == [f"{run_id(1)}.json", "pridem"]
