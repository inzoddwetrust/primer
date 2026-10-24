"""Probes DM-7: state.json, history/, journal/, composition (contract 2 v1.3 section 3).

Each probe has its pair: the refused or broken case leaves the box as it was,
and the ordinary case does what it says, so no probe passes on a box that
writes nothing.
"""

import os
from pathlib import Path

import pytest
from report_support import MARKER, SECRETS
from state_support import AFTER, BEFORE, STARTED, header, run_id, state, verdict

from pridem.events import LogLine, StepFinished, StepRecord, StepStarted
from pridem.report.render import render_report
from pridem.runner import Stream
from pridem.stacks.passport import Package
from pridem.stacks.stack import CompositionCollision, Stack, composition
from pridem.state import Box, HistoryExists


def test_probe_DM_7_state_write_is_atomic(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    box = Box(tmp_path)
    first, second = state(), state({"aivis": "0000000", "pridem": "0.4.0"})
    with box.lock("a"):
        box.write_state(first)

        def dies(*_: object) -> None:
            raise OSError("power lost")

        for name in ("replace", "fsync"):
            with monkeypatch.context() as patch:
                patch.setattr(os, name, dies)
                with pytest.raises(OSError, match="power lost"):
                    box.write_state(second)
            assert box.read_state() == first, name
    with box.lock("b"):  # the next command clears what the dead write left
        assert sorted(p.name for p in tmp_path.iterdir() if p.is_file()) == [
            "lock",
            "state.json",
        ]
        box.write_state(second)
    assert box.read_state() == second


def test_probe_DM_7_history_is_append_only(tmp_path: Path) -> None:
    box = Box(tmp_path)
    run = run_id(1)
    with box.lock("a"):
        box.write_verdict(verdict(run))
        written = (tmp_path / "history" / f"{run}.json").read_bytes()
        other = verdict(run, verb="doctor")
        with pytest.raises(HistoryExists):
            box.write_verdict(other)
        assert (tmp_path / "history" / f"{run}.json").read_bytes() == written
        box.write_verdict(verdict(run_id(2)))
    assert box.read_verdict(run).verb == "deploy"
    assert box.history_ids() == [run, run_id(2)]


def test_probe_DM_7_orphan_journal_becomes_red_verdict(tmp_path: Path) -> None:
    """The run died inside ``up`` after ``finalize`` had already written state.json."""
    box = Box(tmp_path)
    run = run_id(1)
    with box.lock("dying"):
        box.write_state(state(BEFORE))
        sink = box.open_journal(
            header(run, args={"ref": "9a1c4e2", "t": MARKER}), SECRETS
        )
        built = StepRecord("aivis", "build", 6, "ok", None, STARTED, 1.0, {"id": "x"})
        sink.emit(StepStarted("main", "aivis", "build", 6, STARTED))
        sink.emit(StepFinished("main", built))
        sink.emit(StepStarted("main", "aivis", "up", 10, STARTED))
        sink.emit(LogLine("main", "aivis", "up", Stream.STDERR, "dying here"))
        box.write_state(state(AFTER))
        # no close, no verdict: the process is gone
    with box.lock("next"):
        box.open_journal(header(run_id(2)), SECRETS).close()
        box.write_verdict(verdict(run_id(2)))
        recovered = box.recover(SECRETS, "0.3.1")
    assert [v.run_id for v in recovered] == [run]
    (red,) = recovered
    assert (red.exit_code, red.result) == (1, "red")
    assert [(i.what, i.why) for i in red.report.incomplete] == [
        ("run", "no verdict found; journal ends at step main aivis/up")
    ]
    assert [(s.phase, s.name, s.status) for s in red.steps] == [("main", "build", "ok")]
    assert red.composition_before == BEFORE and red.composition_after == AFTER
    assert red.args == {"ref": "9a1c4e2", "t": "[redacted]"}
    assert box.read_verdict(run) == red
    assert box.read_verdict(run_id(2)) == verdict(run_id(2))


def test_probe_DM_7_journal_budget_evicts_oldest_first(tmp_path: Path) -> None:
    box = Box(tmp_path)
    runs = [run_id(n) for n in (1, 2, 3, 4)]
    with box.lock("a"):
        for run in runs:
            box.open_journal(header(run), SECRETS).close()
            box.write_verdict(verdict(run))
        # mtimes in reverse: the order is the run id, not the file time
        for age, run in enumerate(runs):
            path = tmp_path / "journal" / f"{run}.jsonl"
            os.utime(path, (10_000 - age, 10_000 - age))
        one = (tmp_path / "journal" / f"{runs[0]}.jsonl").stat().st_size
        fact = box.evict_journals(2 * one, keep=runs[3])
    assert fact == {"evicted": runs[:2], "kept_bytes": 2 * one, "over_budget": False}
    left = sorted(p.stem for p in (tmp_path / "journal").glob("*.jsonl"))
    assert left == runs[2:]
    assert box.history_ids() == runs
    first = box.read_verdict(runs[0])
    assert box.read_journal(runs[0]) is None
    assert "## Composition" in render_report(first, None, SECRETS)


def test_probe_DM_7_composition_name_collision_is_refused() -> None:
    skin = Package.model_validate(
        {"repo": "git@github.com:partner-x/velo-look.git", "version": "1.4.2"}
    )
    clashing = [
        Stack("aivis", "product", "9a1c4e2"),
        Stack("aivis", "service", "1.0.0"),
        Stack("pridem", "service", "2.0.0"),
        Stack("skin", "service", "1.0.0"),
    ]
    with pytest.raises(CompositionCollision) as refused:
        composition(
            clashing, machine_version="0.3.1", packages={"skin": skin, "pridem": skin}
        )
    assert refused.value.problems == (
        "two stacks are named 'aivis'",
        "a stack is named 'pridem', the machine's key",
        "stack 'pridem' has the name of a package slot",
        "stack 'skin' has the name of a package slot",
        "a package slot is named 'pridem', the machine's key",
    )
    built = composition(
        [Stack("aivis", "product", "9a1c4e2"), Stack("comms", "service", "3.0.0")],
        machine_version="0.3.1",
        packages={"skin": skin},
    )
    assert built == {
        "aivis": "9a1c4e2",
        "comms": "3.0.0",
        "pridem": "0.3.1",
        "skin": "velo-look@1.4.2",
    }
