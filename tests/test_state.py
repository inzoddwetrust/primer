"""state.json, history/, journal/, the box lock and recovery (DM-7)."""

import json
import threading
from pathlib import Path

import pytest
from plan_support import Journal as Phases
from plan_support import ScriptedStep, plan
from pydantic import SecretStr, ValidationError
from report_support import MARKER, SECRETS, build
from state_support import AFTER, BEFORE, header, run_id, state, verdict

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
    box = Box(tmp_path)
    with box.lock("a"):
        box.write_state(state())
    raw = json.loads((tmp_path / "state.json").read_text(encoding="utf-8"))
    assert raw["composition"] == AFTER
    raw["passport_version"] = 7.0
    (tmp_path / "state.json").write_text(json.dumps(raw), encoding="utf-8")
    with pytest.raises(ValidationError):
        box.read_state()
    raw["passport_version"], raw["composition"] = 7, {"aivis": "9a1c4e2"}
    (tmp_path / "state.json").write_text(json.dumps(raw), encoding="utf-8")
    with pytest.raises(ValidationError, match="pridem"):
        box.read_state()


def test_verdict_records_the_last_run_of_its_verb(tmp_path: Path) -> None:
    box = Box(tmp_path)
    with box.lock("a"):
        box.write_verdict(verdict(run_id(2)))
        created = box.read_state()
        assert created is not None
        assert created.composition == verdict(run_id(2)).composition_after
        assert created.last_run == {"deploy": run_id(2)}
        box.write_state(created.model_copy(update={"current": {"aivis": "r/1"}}))
        box.write_verdict(verdict(run_id(3), verb="doctor"))
        box.write_verdict(verdict(run_id(1)))  # older than the recorded deploy
    final = box.read_state()
    assert final is not None and final.current == {"aivis": "r/1"}
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


def test_torn_last_line_is_dropped_damage_elsewhere_is_refused(
    tmp_path: Path,
) -> None:
    box = Box(tmp_path)
    run = run_id(1)
    with box.lock("a"):
        sink = box.open_journal(header(run), SECRETS)
        sink.emit(LogLine("main", "aivis", "up", Stream.STDOUT, "one"))
        sink.close()
    path = tmp_path / "journal" / f"{run}.jsonl"
    whole = path.read_text(encoding="utf-8")
    path.write_text(whole + '{"event": "log", "phase": "ma', encoding="utf-8")
    journal = read_journal(path)
    assert journal.torn and len(journal.events) == 1
    lines = whole.splitlines()
    path.write_text("\n".join([lines[0], "{oops", lines[1]]) + "\n", encoding="utf-8")
    with pytest.raises(JournalDamaged, match=":2:"):
        read_journal(path)
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
        (recovered,) = box.recover(SECRETS, "0.3.1")
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
        assert [v.run_id for v in box.recover(SECRETS, "0.3.1")] == [run_id(1)]
        assert box.recover(SECRETS, "0.3.1") == []
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
