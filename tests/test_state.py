"""state.json, history/, journal/, the box lock and recovery (DM-7)."""

import json
import os
import stat
import threading
import traceback
from collections.abc import Callable
from pathlib import Path

import pytest
from plan_support import Journal as Phases
from plan_support import ScriptedStep, plan
from pydantic import SecretStr, ValidationError
from report_support import MARKER, SECRETS, build
from state_support import AFTER, BEFORE, STARTED, header, run_id, state, verdict

from pridem.events import LogLine, Secrets, StepFinished, StepRecord, StepStarted
from pridem.plan import StackSteps
from pridem.report.render import render_report
from pridem.runner import FakeCall, FakeRunner, Stream
from pridem.stacks.passport import size_bytes
from pridem.state import (
    Box,
    BoxBusy,
    BoxState,
    JournalDamaged,
    NotLocked,
    Recovery,
    StateDamaged,
    VerdictDamaged,
    read_journal,
)

# --- lock ---------------------------------------------------------------------


def test_second_command_is_refused_with_the_holder(tmp_path: Path) -> None:
    first, second = Box(tmp_path), Box(tmp_path)
    with first.lock("deploy 2026-10-15T10:42:01Z-a3f9 pid 41"):
        with pytest.raises(BoxBusy) as busy, second.lock("doctor"):
            pass
        assert busy.value.holder == "deploy 2026-10-15T10:42:01Z-a3f9 pid 41"
    with second.lock("doctor"):
        second.write_state(state())
    assert second.read_state() == state()


def test_two_commands_racing_for_the_box_one_wins(tmp_path: Path) -> None:
    """Both try at the same moment; exactly one holds the box, the other is refused."""
    start = threading.Barrier(2)
    held = threading.Event()
    done = threading.Event()
    results: dict[str, str] = {}

    def command(name: str) -> None:
        start.wait()
        try:
            with Box(tmp_path).lock(name):
                results[name] = "held"
                held.set()
                done.wait(5)
        except BoxBusy as busy:
            held.wait(5)
            results[name] = f"busy:{busy.holder}"

    threads = [threading.Thread(target=command, args=(n,)) for n in ("a", "b")]
    for thread in threads:
        thread.start()
    held.wait(5)
    while len(results) < 2 and any(t.is_alive() for t in threads):
        threading.Event().wait(0.01)
    done.set()
    for thread in threads:
        thread.join(5)
    winner = [n for n, r in results.items() if r == "held"]
    assert len(winner) == 1
    (loser,) = set(results) - set(winner)
    # the holder is written right after the lock is taken; a loser that reads in
    # between sees an empty holder (reported as "a command is starting")
    assert results[loser] in (f"busy:{winner[0]}", "busy:")


def test_writes_outside_the_lock_are_refused(tmp_path: Path) -> None:
    box = Box(tmp_path)
    with pytest.raises(NotLocked):
        box.write_state(state())
    with pytest.raises(NotLocked):
        box.write_verdict(verdict(run_id(1)))
    with pytest.raises(NotLocked):
        box.open_journal(header(run_id(1)), SECRETS)
    with pytest.raises(NotLocked):
        box.evict_journals(1, keep=run_id(1))
    with pytest.raises(NotLocked):
        box.recover(SECRETS, "0.3.1")
    assert box.read_state() is None


def test_temp_files_of_a_dead_writer_go_under_the_lock(tmp_path: Path) -> None:
    box = Box(tmp_path)
    with box.lock("a"):
        pass
    leftovers = [
        tmp_path / ".state.json.tmp",
        tmp_path / "history" / f".{run_id(1)}.json.tmp",
        tmp_path / "journal" / f".{run_id(1)}.jsonl.tmp",
    ]
    for path in leftovers:
        path.write_text("half", encoding="utf-8")
    keep = tmp_path / "history" / f"{run_id(2)}.json"
    keep.write_text("{}", encoding="utf-8")
    with box.lock("b"):
        pass
    assert not any(path.exists() for path in leftovers)
    assert keep.exists()


# --- state.json ---------------------------------------------------------------


def test_state_is_read_strictly_from_json(tmp_path: Path) -> None:
    """A ``state.json`` off the schema is damaged.

    Until DM-36 ``read_state`` raised pydantic's ``ValidationError``, which
    quotes the file; outside the lock it is now ``StateDamaged``, naming only
    the kind of damage (under the lock: quarantine).
    """
    box = Box(tmp_path)
    with box.lock("a"):
        box.write_state(state())
    raw = json.loads((tmp_path / "state.json").read_text(encoding="utf-8"))
    assert raw["composition"] == AFTER
    raw["passport_version"] = 7.0
    (tmp_path / "state.json").write_text(json.dumps(raw), encoding="utf-8")
    with pytest.raises(StateDamaged, match=r"\(ValidationError\)$"):
        box.read_state()
    raw["passport_version"], raw["composition"] = 7, {"aivis": "9a1c4e2"}
    (tmp_path / "state.json").write_text(json.dumps(raw), encoding="utf-8")
    with pytest.raises(StateDamaged):
        box.read_state()


def test_verdict_without_state_json_writes_history_only(tmp_path: Path) -> None:
    """Only ``Box.write_state`` writes ``state.json``; a verdict never creates it.

    Replaces the DM-7 test that had ``write_verdict`` create ``state.json`` from
    the verdict: after a red first ``install`` that file named a composition
    the box did not have (FIX DM-7).
    """
    box = Box(tmp_path)
    with box.lock("a"):
        box.write_verdict(verdict(run_id(2)))
    assert box.read_state() is None
    assert not (tmp_path / "state.json").exists()
    assert box.history_ids() == [run_id(2)]


def test_verdict_records_the_last_run_of_its_verb(tmp_path: Path) -> None:
    box = Box(tmp_path)
    with box.lock("a"):
        box.write_state(state())
        box.write_verdict(verdict(run_id(2)))
        box.write_verdict(verdict(run_id(3), verb="doctor"))
        box.write_verdict(verdict(run_id(1)))  # older than the recorded deploy
    final = box.read_state()
    assert final is not None
    assert final.model_copy(update={"last_run": {}}) == state()
    assert final.last_run == {"deploy": run_id(2), "doctor": run_id(3)}
    assert box.history_ids() == [run_id(1), run_id(2), run_id(3)]


# --- journal ------------------------------------------------------------------


def test_journal_is_header_then_events_with_phase_and_no_secret(
    tmp_path: Path,
) -> None:
    box = Box(tmp_path)
    run = run_id(1)
    with box.lock("a"):
        sink = box.open_journal(header(run, args={"token": MARKER}), SECRETS)
        sink.emit(StepStarted("main", "aivis", "up", 10, header(run).started))
        sink.emit(LogLine("main", "aivis", "up", Stream.STDERR, f"tok {MARKER}"))
        record = StepRecord(
            "aivis", "up", 10, "failed", f"command failed: x {MARKER}", None, None, {}
        )
        sink.emit(StepFinished("restore", record))
        sink.close()
    text = (tmp_path / "journal" / f"{run}.jsonl").read_text(encoding="utf-8")
    assert MARKER not in text and "[redacted]" in text
    lines = [json.loads(line) for line in text.splitlines()]
    assert [line["event"] for line in lines] == [
        "header",
        "step_started",
        "log",
        "step_finished",
    ]
    assert [line.get("phase") for line in lines[1:]] == ["main", "main", "restore"]
    journal = read_journal(tmp_path / "journal" / f"{run}.jsonl")
    assert journal.header.args == {"token": "[redacted]"} and not journal.torn
    assert [type(e).__name__ for e in journal.events] == [
        "StepStarted",
        "LogLine",
        "StepFinished",
    ]


def test_torn_last_line_is_dropped_damage_elsewhere_is_named(
    tmp_path: Path,
) -> None:
    """A torn last line is dropped; a damaged line in the middle ends the events
    and is named; a damaged header raises (FIX DM-7: damage no longer raises
    past the header, so a damaged journal still gets its verdict)."""
    box = Box(tmp_path)
    run = run_id(1)
    with box.lock("a"):
        sink = box.open_journal(header(run), SECRETS)
        sink.emit(LogLine("main", "aivis", "up", Stream.STDOUT, "one"))
        sink.emit(LogLine("main", "aivis", "up", Stream.STDOUT, "two"))
        sink.close()
    path = tmp_path / "journal" / f"{run}.jsonl"
    whole = path.read_text(encoding="utf-8")
    path.write_text(whole + '{"event": "log", "phase": "ma', encoding="utf-8")
    journal = read_journal(path)
    assert journal.torn and len(journal.events) == 2 and journal.damaged_at is None
    lines = whole.splitlines()
    path.write_text("\n".join([lines[0], lines[1], "{oops", lines[2]]) + "\n")
    journal = read_journal(path)
    assert journal.damaged_at == 3 and len(journal.events) == 1
    path.write_text(lines[1] + "\n", encoding="utf-8")
    with pytest.raises(JournalDamaged, match=":1:"):
        read_journal(path)


def test_same_named_steps_of_two_phases_keep_their_own_lines(tmp_path: Path) -> None:
    """A restore step named as the main one shows only its own output."""
    phases = Phases()
    main = ScriptedStep("up", 10, phases, act_argv=["make", "up"])
    back = ScriptedStep("up", 10, phases, act_argv=["make", "back"])
    runner = FakeRunner(
        FakeCall(("make", "up"), code=1, lines=((Stream.STDERR, "main output"),)),
        FakeCall(("make", "back"), code=1, lines=((Stream.STDERR, "restore output"),)),
    )
    with runner:
        run, events = plan(
            [StackSteps("aivis", [main], root=True)],
            runner=runner,
            restore=[StackSteps("aivis", [back], root=True)],
        )
        outcome = run.run()
    built = build(outcome)
    assert [(s.phase, s.name, s.status) for s in built.steps] == [
        ("main", "up", "failed"),
        ("restore", "up", "failed"),
    ]
    box = Box(tmp_path)
    with box.lock("a"):
        sink = box.open_journal(header(built.run_id), SECRETS)
        for event in events.events:
            sink.emit(event)
        sink.close()
    journal = box.read_journal(built.run_id)
    assert journal is not None
    lines = [e for e in journal.events if isinstance(e, LogLine)]
    report = render_report(built, lines, SECRETS)
    first, second = report.split("### aivis · up · order 10")[1:3]
    assert "main output" in first and "restore output" not in first
    assert "restore output" in second and "main output" not in second


# --- recovery -----------------------------------------------------------------


def test_run_dead_before_its_first_step_is_red_from_the_header(
    tmp_path: Path,
) -> None:
    box = Box(tmp_path)
    run = run_id(1)
    with box.lock("dead"):
        box.open_journal(header(run, args={"token": MARKER}), SECRETS).close()
    with box.lock("next"):
        (recovered,) = box.recover(SECRETS, "0.3.1").verdicts
    assert recovered.result == "red" and recovered.steps == []
    assert [(i.what, i.why) for i in recovered.report.incomplete] == [
        ("run", "no verdict found; journal ends at step the start")
    ]
    assert recovered.composition_before == BEFORE
    assert recovered.composition_after == {"pridem": "0.3.1"}
    assert recovered.args == {"token": "[redacted]"}
    on_disk = (tmp_path / "history" / f"{run}.json").read_text(encoding="utf-8")
    journal = (tmp_path / "journal" / f"{run}.jsonl").read_text(encoding="utf-8")
    assert MARKER not in on_disk and MARKER not in journal


def test_recovery_runs_once_and_skips_runs_with_a_verdict(tmp_path: Path) -> None:
    box = Box(tmp_path)
    with box.lock("a"):
        box.open_journal(header(run_id(1)), SECRETS).close()
        box.open_journal(header(run_id(2)), SECRETS).close()
        box.write_verdict(verdict(run_id(2)))
        done = box.recover(SECRETS, "0.3.1")
        assert [v.run_id for v in done.verdicts] == [run_id(1)]
        assert box.recover(SECRETS, "0.3.1") == Recovery((), ())
    assert box.history_ids() == [run_id(1), run_id(2)]


def test_journal_budget_keeps_a_current_journal_over_budget(tmp_path: Path) -> None:
    box = Box(tmp_path)
    with box.lock("a"):
        box.open_journal(header(run_id(1)), SECRETS).close()
        current = box.open_journal(header(run_id(2)), SECRETS)
        for n in range(50):
            current.emit(LogLine("main", "aivis", "up", Stream.STDOUT, f"line {n}"))
        current.close()
        fact = box.evict_journals(10, keep=run_id(2))
    assert fact["evicted"] == [run_id(1)] and fact["over_budget"] is True
    assert sorted(p.stem for p in (tmp_path / "journal").glob("*.jsonl")) == [run_id(2)]


@pytest.mark.parametrize(
    ("size", "count"), [("1K", 1024), ("200M", 200 * 1024**2), ("3G", 3 * 1024**3)]
)
def test_passport_sizes_are_binary(size: str, count: int) -> None:
    assert size_bytes(size) == count


def test_secret_cleaning_covers_minted_values_too(tmp_path: Path) -> None:
    """The journal cleans whatever ``Secrets`` it is given, not only the passport's."""
    minted = "minted-secret-value-0001"
    box = Box(tmp_path)
    with box.lock("a"):
        sink = box.open_journal(header(run_id(1)), Secrets([SecretStr(minted)]))
        sink.emit(LogLine("main", "aivis", "up", Stream.STDOUT, f"KEY={minted}"))
        sink.close()
    text = (tmp_path / "journal" / f"{run_id(1)}.jsonl").read_text(encoding="utf-8")
    assert minted not in text and "KEY=[redacted]" in text


def test_state_model_has_no_null(tmp_path: Path) -> None:
    with pytest.raises(ValidationError, match="explicit null"):
        BoxState.model_validate_json(
            json.dumps(
                {
                    "composition": None,
                    "passport_version": 7,
                    "current": {},
                    "last_run": {},
                }
            )
        )


# --- FIX DM-7: a damaged journal never blocks the box ---------------------------


def _orphan(box: Box, run: str) -> Path:
    """A run that finished one step, logged a line and died."""
    sink = box.open_journal(header(run), SECRETS)
    record = StepRecord("aivis", "build", 6, "ok", None, None, 1.0, {"id": "x"})
    sink.emit(StepFinished("main", record))
    sink.emit(LogLine("main", "aivis", "up", Stream.STDOUT, "working"))
    sink.close()
    return box.journals / f"{run}.jsonl"


def test_damage_after_the_header_is_its_own_red_verdict(tmp_path: Path) -> None:
    box = Box(tmp_path)
    with box.lock("dying"):
        damaged = _orphan(box, run_id(1))
        _orphan(box, run_id(2))
    lines = damaged.read_text(encoding="utf-8").splitlines()
    damaged.write_text("\n".join([lines[0], lines[1], "{oops", lines[2]]) + "\n")
    with box.lock("next"):
        done = box.recover(SECRETS, "0.3.1")
    assert done.quarantined == ()
    first, second = done.verdicts
    assert [(i.what, i.why) for i in first.report.incomplete] == [
        ("run", "no verdict found; journal damaged at line 3")
    ]
    assert [(s.phase, s.name) for s in first.steps] == [("main", "build")]
    assert second.report.incomplete[0].why == (
        "no verdict found; journal ends at step main aivis/build"
    )
    with box.lock("after"):  # the box is not blocked
        assert box.recover(SECRETS, "0.3.1") == Recovery((), ())
    assert box.history_ids() == [run_id(1), run_id(2)]


def test_damaged_header_is_quarantined_and_recovery_goes_on(tmp_path: Path) -> None:
    box = Box(tmp_path)
    with box.lock("dying"):
        bad = _orphan(box, run_id(1))
        _orphan(box, run_id(2))
    bad.write_text("{not a header\n" + "\n".join(bad.read_text().splitlines()[1:]))
    with box.lock("next"):
        done = box.recover(SECRETS, "0.3.1")
    assert done.quarantined == (run_id(1),)
    assert [v.run_id for v in done.verdicts] == [run_id(2)]
    quarantine = box.journals / f"{run_id(1)}.jsonl.damaged"
    assert quarantine.exists() and not bad.exists()
    with box.lock("again"):
        assert box.recover(SECRETS, "0.3.1") == Recovery((), ())
    assert quarantine.exists()
    assert box.history_ids() == [run_id(2)]


def test_eviction_counts_quarantine_oldest_first(tmp_path: Path) -> None:
    box = Box(tmp_path)
    with box.lock("a"):
        _orphan(box, run_id(1)).rename(box.journals / f"{run_id(1)}.jsonl.damaged")
        _orphan(box, run_id(2))
        _orphan(box, run_id(3))
        sizes = sorted(p.stat().st_size for p in box.journals.iterdir())
        fact = box.evict_journals(sizes[0] + sizes[1], keep=run_id(3))
    assert fact["evicted"] == [run_id(1)]
    assert sorted(p.name for p in box.journals.iterdir()) == [
        f"{run_id(2)}.jsonl",
        f"{run_id(3)}.jsonl",
    ]


# --- DM-36: what the box claims about writes, and damaged files -----------------


def _fsyncs(monkeypatch: pytest.MonkeyPatch) -> list[bool]:
    """Every ``os.fsync`` from now on, as ``True`` for a directory."""
    seen: list[bool] = []
    real = os.fsync

    def spy(fd: int) -> None:
        seen.append(stat.S_ISDIR(os.fstat(fd).st_mode))
        real(fd)

    monkeypatch.setattr(os, "fsync", spy)
    return seen


def test_every_rename_and_link_is_followed_by_a_directory_fsync(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    box = Box(tmp_path)
    with box.lock("a"):
        seen = _fsyncs(monkeypatch)
        writes: list[Callable[[], None]] = [
            lambda: box.write_state(state()),
            lambda: box.write_verdict(verdict(run_id(1))),
            lambda: box.open_journal(header(run_id(2)), SECRETS).close(),
        ]
        for write in writes:
            seen.clear()
            write()
            assert True in seen, write


def test_journal_is_fsynced_on_finished_steps_only(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    box = Box(tmp_path)
    with box.lock("a"):
        sink = box.open_journal(header(run_id(1)), SECRETS)
        seen = _fsyncs(monkeypatch)
        sink.emit(LogLine("main", "aivis", "up", Stream.STDOUT, "x"))
        sink.emit(StepStarted("main", "aivis", "up", 10, STARTED))
        assert seen == []
        record = StepRecord("aivis", "up", 10, "ok", None, None, 1.0, {"x": 1})
        sink.emit(StepFinished("main", record))
        assert seen == [False]
        sink.close()


def test_orphan_never_finishes_before_it_started(tmp_path: Path) -> None:
    box = Box(tmp_path)
    with box.lock("dying"):
        box.open_journal(header(run_id(1)), SECRETS).close()
    path = box.journals / f"{run_id(1)}.jsonl"
    earlier = STARTED.timestamp() - 3600  # the clock was stepped back
    os.utime(path, (earlier, earlier))
    with box.lock("next"):
        (red,) = box.recover(SECRETS, "0.3.1").verdicts
    assert red.finished == red.started == STARTED


def test_damaged_journal_header_is_not_quoted(tmp_path: Path) -> None:
    box = Box(tmp_path)
    with box.lock("a"):
        box.open_journal(header(run_id(1)), SECRETS).close()
    path = box.journals / f"{run_id(1)}.jsonl"
    path.write_text('{"event": "header", "verb": "' + MARKER + '"}\n')
    with pytest.raises(JournalDamaged) as damaged:
        read_journal(path)
    shown = "".join(traceback.format_exception(damaged.value))
    assert MARKER not in shown and str(damaged.value).endswith(":1: ValidationError")


def test_damaged_state_outside_the_lock_is_an_error_and_stays(tmp_path: Path) -> None:
    """``None`` means only «no state.json»; damage read without the lock raises."""
    box = Box(tmp_path)
    assert box.read_state() is None
    path = tmp_path / "state.json"
    content = '{"composition": "' + MARKER + '"'
    path.write_text(content, encoding="utf-8")
    with pytest.raises(StateDamaged) as damaged:
        box.read_state()
    shown = "".join(traceback.format_exception(damaged.value))
    assert MARKER not in shown and "state.json is damaged" in shown
    assert path.read_text(encoding="utf-8") == content
    assert not (tmp_path / "state.json.damaged").exists()
    with box.lock("a"):
        assert box.read_state() is None and box.state_quarantined
    assert (tmp_path / "state.json.damaged").read_text(encoding="utf-8") == content
    assert box.read_state() is None


DAMAGED_VERDICTS = [
    b"\xff\xfe" + MARKER.encode(),
    b"not json " + MARKER.encode(),
    b'{"schema": 1, "run_id": "' + MARKER.encode() + b'"}',
]


@pytest.mark.parametrize("content", DAMAGED_VERDICTS, ids=["utf8", "json", "schema"])
def test_damaged_verdict_is_named_not_quoted(tmp_path: Path, content: bytes) -> None:
    """FIX DM-36: reading history/ quotes no file, as journal and state.json."""
    box = Box(tmp_path)
    with box.lock("a"):
        box.write_verdict(verdict(run_id(1)))
    (box.history / f"{run_id(2)}.json").write_bytes(content)
    with pytest.raises(VerdictDamaged) as damaged:
        box.read_verdict(run_id(2))
    shown = "".join(traceback.format_exception(damaged.value))
    assert MARKER not in shown
    assert str(damaged.value).startswith(str(box.history / f"{run_id(2)}.json") + ": ")
    assert box.read_verdict(run_id(1)) == verdict(run_id(1))
