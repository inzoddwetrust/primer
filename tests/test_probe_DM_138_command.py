"""The probes of DM-138: the command of the Panel in the run, the busy box by
its holder.

``pridem --json --command <id> <verb>`` -- the call the agent makes for a
command of the queue: its id is in the journal's header, the lock's file and
the verdict, ``recover`` carries it to the verdict of a run that did not end.
A busy box refuses with ``--json`` by an object on stdout that names the run
holding the lock.
"""

import io
import json
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path

import pytest
from data_support import blank_box
from plan_support import Journal, ScriptedStep
from test_box_held import LEFT, _gone

from pridem.cli import run
from pridem.events import Json, LogLine, PlanOutcome
from pridem.plan import Plan, StackSteps
from pridem.report.refusal import Refusal
from pridem.report.schema import Verdict
from pridem.runner import FakeRunner, Runner, Stream, SubprocessRunner
from pridem.state import Box, LockHolder, read_journal
from pridem.steps.base import Step
from pridem.verbs import deploy as deploy_verbs
from pridem.verbs.run import Planned, Session

COMMAND = "6f1c2d8e-4b7a-4e0f-9a3d-2c5b8e1f7a90"
"""An id as the Panel mints it (DM-153: uuid4)."""


def _cli(
    root: Path, argv: list[str], runner: Runner | None = None
) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    code = run(
        argv,
        root=root / "opt" / "pridem",
        out=out,
        err=err,
        runner=runner or FakeRunner(),
        fs_root=root,
    )
    return code, out.getvalue(), err.getvalue()


@pytest.fixture
def planned(monkeypatch: pytest.MonkeyPatch) -> list[Step]:
    """The plan of ``update``: the steps the test puts in this list."""
    steps: list[Step] = [ScriptedStep("first", 1, Journal())]

    def make(session: Session, *_: object) -> Planned:
        return Planned([StackSteps("blank", list(steps), root=True)])

    monkeypatch.setattr(deploy_verbs, "deploy_plan", make)
    return steps


def _header(root: Path, run_id: str) -> dict[str, Json]:
    path = root / "opt" / "pridem" / "journal" / f"{run_id}.jsonl"
    first: dict[str, Json] = json.loads(path.read_text().splitlines()[0])
    return first


def _verdict(root: Path, run_id: str) -> Verdict:
    path = root / "opt" / "pridem" / "history" / f"{run_id}.json"
    return Verdict.model_validate_json(path.read_text())


# --- probes -----------------------------------------------------------------------


def test_probe_DM_138_the_command_is_in_the_journal_and_the_verdict(
    tmp_path: Path, planned: list[Step]
) -> None:
    """``--json --command <id> update``: the journal's header and the verdict
    carry the id, the actor is the Panel. A run of the Panel that did not end
    (an error of the machine) -- ``recover`` gives its red verdict the same
    id. The pair: without ``--command`` there is no key, the actor is the
    console."""
    blank_box(tmp_path)
    code, out, _ = _cli(tmp_path, ["--json", "--command", COMMAND, "update"])
    verdict = Verdict.model_validate_json(out)
    assert code == 0 and verdict.command == COMMAND
    assert verdict.actor.model_dump(exclude_none=True) == {
        "type": "engineer",
        "via": "panel",
    }
    assert json.loads(out)["command"] == COMMAND
    header = _header(tmp_path, verdict.run_id)
    assert header["command"] == COMMAND
    assert header["actor"] == {"type": "engineer", "via": "panel"}
    # a run of the Panel that did not end: recover carries its command
    cut = "a1b2c3d4-0000-4000-8000-000000000001"

    def broken(self: Plan) -> PlanOutcome:
        self._sink.emit(LogLine("main", "blank", "first", Stream.STDOUT, "working"))
        raise RuntimeError("an error of the machine")

    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(Plan, "run", broken)
        with pytest.raises(RuntimeError):
            _cli(tmp_path, ["--json", "--command", cut, "update"])
    home = tmp_path / "opt" / "pridem"
    [orphan] = [
        p.stem
        for p in (home / "journal").glob("*.jsonl")
        if not (home / "history" / f"{p.stem}.json").exists()
    ]
    assert read_journal(home / "journal" / f"{orphan}.jsonl").header.command == cut
    # the pair: the console -- no command anywhere; its run recovers the cut one
    code, out, _ = _cli(tmp_path, ["--json", "update"])
    plain = json.loads(out)
    assert code == 0 and "command" not in plain
    assert plain["actor"] == {"type": "engineer", "via": "local"}
    assert "command" not in _header(tmp_path, plain["run_id"])
    recovered = _verdict(tmp_path, orphan)
    assert recovered.result == "red" and recovered.command == cut


@pytest.fixture
def held(tmp_path: Path) -> Iterator[tuple[LockHolder, int]]:
    """Another process holds the box as a run of the Panel does: the lock's
    file names the run, its verb and its command; a process left with the
    lock's descriptor keeps it held. The holder and the process's pid."""
    blank_box(tmp_path)
    holder = LockHolder.model_validate(
        {
            "run_id": "2026-11-24T10:00:00Z-a3f9",
            "verb": "update",
            "actor": {"type": "engineer", "via": "panel"},
            "since": datetime(2026, 11, 24, 10, 0, tzinfo=UTC),
            "command": COMMAND,
        }
    )
    box = Box(tmp_path / "opt" / "pridem")
    seen: list[str] = []
    with box.lock(holder.model_dump_json()):
        runner = SubprocessRunner()
        assert box.lock_fd is not None
        runner.hold(box.lock_fd)
        runner.run(LEFT, timeout=30, on_line=lambda s, line, c: seen.append(line))
    pid = int(seen[0])
    yield holder, pid
    _gone(pid)


def test_probe_DM_138_a_busy_box_refuses_with_its_holder(
    tmp_path: Path, held: tuple[LockHolder, int], planned: list[Step]
) -> None:
    """The box is held by a run of the Panel: ``--json`` -- exit 1, on stdout
    one object ``box-busy`` with the holder's run, verb, actor, command and
    the process holding the lock; stderr says it as ever; no verdict is
    written. The pair: without ``--json`` -- the line on stderr, stdout
    empty."""
    holder, pid = held
    history = tmp_path / "opt" / "pridem" / "history"
    before = sorted(history.iterdir()) if history.exists() else []
    for argv in (["--json", "--command", "c-2", "update"], ["--json", "status"]):
        code, out, err = _cli(tmp_path, argv)
        assert code == 1, err
        refusal = Refusal.model_validate_json(out)
        assert refusal.refused == "box-busy"
        assert refusal.holder == holder
        assert refusal.holder_unread is None
        assert [p for p in refusal.processes if p.startswith(f"pid {pid} ")]
        assert "the box is busy" in err and holder.run_id in err
    assert (sorted(history.iterdir()) if history.exists() else []) == before
    code, out, err = _cli(tmp_path, ["update"])
    assert (code, out) == (1, "") and "the box is busy" in err


# --- around the probes ------------------------------------------------------------


def test_the_lock_names_the_run_that_holds_it(
    tmp_path: Path, planned: list[Step]
) -> None:
    """While a run of the Panel holds the box, the lock's file is its
    ``LockHolder``: the run's id is the one of its journal and verdict."""
    blank_box(tmp_path)
    seen: list[str] = []

    class Looking(ScriptedStep):
        def act(self, ctx: object, check: object) -> None:
            seen.append((tmp_path / "opt" / "pridem" / "lock").read_text())

    planned[:] = [Looking("look", 1, Journal())]
    code, out, _ = _cli(tmp_path, ["--json", "--command", COMMAND, "update"])
    verdict = json.loads(out)
    holder = LockHolder.model_validate_json(seen[0])
    assert (holder.run_id, holder.verb, holder.command) == (
        verdict["run_id"],
        "update",
        COMMAND,
    )
    assert holder.actor.via == "panel"


def test_status_names_its_run_in_the_lock(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``status`` takes the lock as every command with a verdict: the lock's
    file is its ``LockHolder`` -- verb ``status``, the run of its verdict."""
    import pridem.verbs.status as status

    blank_box(tmp_path)
    seen: list[str] = []
    real = status._verdict

    def looking(box: Box, err: object, held: LockHolder, started: datetime) -> Verdict:
        seen.append((tmp_path / "opt" / "pridem" / "lock").read_text())
        return real(box, err, held, started)  # type: ignore[arg-type]

    monkeypatch.setattr(status, "_verdict", looking)
    code, out, _ = _cli(tmp_path, ["--json", "--command", COMMAND, "status"])
    holder = LockHolder.model_validate_json(seen[0])
    assert (holder.verb, holder.run_id, holder.command) == (
        "status",
        json.loads(out)["run_id"],
        COMMAND,
    )


@pytest.mark.parametrize(
    ("written", "unread"),
    [("", "starting"), ("update", "unreadable"), ('{"run_id": "x"}', "unreadable")],
)
def test_a_holder_that_cannot_be_named_is_said_so(
    tmp_path: Path, written: str, unread: str
) -> None:
    """Twin SHORTAGE: the lock's file empty (a command just took it) or of
    another form (a machine of an earlier version) -- the refusal says why
    there is no holder; it never makes one up."""
    blank_box(tmp_path)
    box = Box(tmp_path / "opt" / "pridem")
    with box.lock(written):
        code, out, _ = _cli(tmp_path, ["--json", "status"])
    refusal = json.loads(out)
    assert code == 1
    assert refusal == {
        "refused": "box-busy",
        "holder_unread": unread,
        "processes": [],
    }


@pytest.mark.parametrize(
    ("argv", "said"),
    [
        (["--command", "", "update"], "--command: an id"),
        (["--command", "has space", "update"], "--command: an id"),
        (["--command", "-x", "update"], "--command: an id"),
        (["--command", "a" * 129, "update"], "--command: an id"),
        (["--command", "c1", "--timer", "gc"], "--command and --timer"),
        (["--command", "c1", "state"], "writes no verdict"),
        (["--command", "c1", "version"], "writes no verdict"),
        (["--command", "c1", "ssl", "status"], "writes no verdict"),
    ],
)
def test_a_command_is_refused_before_the_lock(
    tmp_path: Path, argv: list[str], said: str
) -> None:
    """An id of another form, a command with ``--timer``, a verb that writes
    no verdict: refused before the lock, nothing written."""
    blank_box(tmp_path)
    home = tmp_path / "opt" / "pridem"
    before = sorted(home.rglob("*"))
    code, out, err = _cli(tmp_path, argv)
    assert (code, out) == (1, "") and said in err, err
    assert sorted(home.rglob("*")) == before


def test_the_id_of_the_panel_has_the_form(tmp_path: Path) -> None:
    """The longest id taken, and a uuid4 as the Panel mints it."""
    blank_box(tmp_path)
    for command in ("a" * 128, COMMAND, "cmd.1:2_3-4"):
        code, out, _ = _cli(tmp_path, ["--json", "--command", command, "status"])
        assert code == 0 and json.loads(out)["command"] == command


def test_the_schema_on_disk_is_the_export_of_the_refusal() -> None:
    from pridem.contract import SCHEMA_DIR
    from pridem.report.refusal import CLI_REFUSAL_SCHEMA, rendered_schema

    on_disk = (SCHEMA_DIR / CLI_REFUSAL_SCHEMA).read_text(encoding="utf-8")
    assert on_disk == rendered_schema(), "python -m pridem.report.refusal --export"


def test_a_refusal_names_its_holder_or_why_not() -> None:
    """Both, or neither, is not a refusal of this form."""
    with pytest.raises(ValueError):
        Refusal.model_validate({"refused": "box-busy", "processes": []})
    holder = {
        "run_id": "2026-11-24T10:00:00Z-a3f9",
        "verb": "update",
        "actor": {"type": "engineer", "via": "panel"},
        "since": "2026-11-24T10:00:00Z",
    }
    with pytest.raises(ValueError):
        Refusal.model_validate_json(
            json.dumps(
                {
                    "refused": "box-busy",
                    "holder": holder,
                    "holder_unread": "starting",
                    "processes": [],
                }
            )
        )
