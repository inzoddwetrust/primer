"""The probes of DM-137: the journal of a run is its stream of events.

Every line has ``seq`` -- its number in the file, the header 1, no gap -- and
``at``; the last line of a run that ended is ``run_finished``, written after
the verdict is in ``history/``; a run that did not end has none.
"""

import io
import json
import sys
from collections.abc import Callable, Iterator, Sequence
from pathlib import Path

import pytest
import yaml
from data_support import blank_box
from plan_support import Journal, ScriptedStep

from pridem.cli import run
from pridem.events import Json, KeyNeeded, LogLine, PlanOutcome, RecipientNeeded
from pridem.plan import Plan, StackSteps
from pridem.report.codes import ExitCode
from pridem.report.schema import Verdict
from pridem.runner import FakeRunner, Runner, Stream, SubprocessRunner
from pridem.state import Box, JournalDamaged, JournalSink, read_journal
from pridem.steps.base import CheckResult, Step, StepContext
from pridem.steps.passport import PASSPORT_COPY
from pridem.verbs import deploy as deploy_verbs
from pridem.verbs.run import Planned, Session

KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPridemTestKeyOnly pridem"

Line = dict[str, Json]


def _secret(root: Path) -> str:
    """A value of ``asked`` of the box's passport: a known secret of a run."""
    copy = yaml.safe_load((root / PASSPORT_COPY).read_text())
    return str(next(iter(next(iter(copy["asked"].values())).values())))


class Talking(ScriptedStep):
    """A step that says what a run says: a line in two pieces with a known
    secret across their seam and a notice between them, a second notice,
    then ``lines`` more lines -- enough to pass a small journal limit."""

    def __init__(self, name: str, order: int, secret: str, lines: int) -> None:
        super().__init__(name, order, Journal())
        self.secret = secret
        self.lines = lines

    def act(self, ctx: StepContext, check: CheckResult) -> None:
        half = len(self.secret) // 2
        # the first piece's tail is held to clean the secret across the seam;
        # the notice is written meanwhile -- the held tail takes the next seq
        head = "head " * 20 + "token=" + self.secret[:half]
        ctx.on_line(Stream.STDOUT, head, True)
        ctx.notice(
            KeyNeeded(
                repo="git@github.com:a/blank.git",
                key=KEY,
                page="https://github.com/a/blank/settings/keys",
                write=False,
                why=None,
                wait_s=1800,
            )
        )
        ctx.on_line(Stream.STDOUT, self.secret[half:] + " end", False)
        ctx.notice(RecipientNeeded(key="age1pridemtestrecipient", path=None, wait_s=0))
        for number in range(self.lines):
            ctx.on_line(Stream.STDERR, f"line {number} " + "x" * 80, False)


def _update(
    root: Path, steps: Sequence[Step], runner: Runner | None = None
) -> tuple[int, str]:
    """``update`` of the blank's box whose plan is ``steps``: its exit code
    and the path of its journal under the machine's home."""
    out, err = io.StringIO(), io.StringIO()

    def make(session: Session, *_: object) -> Planned:
        return Planned([StackSteps("blank", list(steps), root=True)])

    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(deploy_verbs, "deploy_plan", make)
        code = run(
            ["--json", "update"],
            root=root / "opt" / "pridem",
            out=out,
            err=err,
            runner=runner or FakeRunner(),
            fs_root=root,
        )
    verdict = json.loads(out.getvalue()) if out.getvalue() else {}
    return code, str(verdict.get("log_ref", ""))


def _lines(root: Path, ref: str) -> list[Line]:
    path = root / "opt" / "pridem" / ref
    return [json.loads(line) for line in path.read_text().splitlines()]


def _small_budget(root: Path, budget: str) -> None:
    copy = root / PASSPORT_COPY
    data = yaml.safe_load(copy.read_text())
    data["policies"]["gc"]["journal_budget"] = budget
    copy.write_text(yaml.safe_dump(data, sort_keys=False))


@pytest.fixture
def ended() -> Iterator[list[bool]]:
    """Whether the journal already had its end when the verdict was written:
    one entry per verdict of the test."""
    seen: list[bool] = []
    real = Box.write_verdict

    def write(self: Box, verdict: Verdict) -> None:
        path = self.journals / f"{verdict.run_id}.jsonl"
        seen.append('"run_finished"' in path.read_text())
        real(self, verdict)

    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(Box, "write_verdict", write)
        yield seen


# --- probes -----------------------------------------------------------------------


def test_probe_DM_137_seq_without_gaps_and_the_end_last(
    tmp_path: Path, ended: list[bool]
) -> None:
    """A run that says a line in two pieces with a secret across the seam and
    a notice between them, a second notice, and more than its journal may
    hold: every line has ``seq`` -- 1 to N, its number, no gap -- and ``at``;
    the held tail of the first piece is written after the notice, with the
    next number; the secret is nowhere; past ``output-cut`` the steps and the
    end are still written. The last line is ``run_finished`` with the
    verdict's code and result, and it was not there when the verdict was
    written."""
    blank_box(tmp_path)
    secret = _secret(tmp_path)
    _small_budget(tmp_path, "1K")
    steps = [Talking("talk", 1, secret, 40), ScriptedStep("after", 2, Journal())]
    code, ref = _update(tmp_path, steps)
    lines = _lines(tmp_path, ref)
    assert [line["seq"] for line in lines] == list(range(1, len(lines) + 1))
    assert all(str(line["at"]).endswith("Z") for line in lines)
    assert lines[0]["event"] == "header"
    assert secret not in "\n".join(json.dumps(line) for line in lines)
    events = [str(line["event"]) for line in lines]
    seam = events.index("log")
    assert events[seam : seam + 3] == ["log", "notice", "log"]
    assert str(lines[seam]["line"]).startswith("head ")
    assert lines[seam]["continued"] is True
    assert str(lines[seam + 2]["line"]).endswith(" end")
    assert "[redacted]" in str(lines[seam + 2]["line"])
    kinds = [
        line["notice"]["kind"]
        for line in lines
        if line["event"] == "notice" and isinstance(line["notice"], dict)
    ]
    assert kinds == ["key_needed", "recipient_needed"]
    logs = [str(line["line"]) for line in lines if line["event"] == "log"]
    assert any("output-cut" in line for line in logs)
    finished = [line["name"] for line in lines if line["event"] == "step_finished"]
    assert finished[-1] == "after"
    history = tmp_path / "opt" / "pridem" / "history"
    verdict = json.loads((history / f"{lines[0]['run_id']}.json").read_text())
    end = lines[-1]
    assert (end["event"], end["exit_code"], end["result"]) == (
        "run_finished",
        verdict["exit_code"],
        verdict["result"],
    )
    assert code == verdict["exit_code"] == ExitCode.INCOMPLETE  # the journal is cut
    assert ended == [False]
    journal = read_journal(tmp_path / "opt" / "pridem" / ref)
    assert journal.damaged_at is None and journal.finished is not None
    assert [type(e).__name__ for e in journal.events].count("KeyNeeded") == 1


def test_probe_DM_137_a_cut_run_is_told_from_a_finished_one(tmp_path: Path) -> None:
    """An error of the machine in the middle of a run: the journal has what
    the run wrote and no ``run_finished`` -- ``read_journal`` says
    ``finished`` is ``None``, no verdict. The pair: the same plan without the
    error ends with ``run_finished``; its ``recover`` gave the cut run a red
    verdict and wrote nothing into its journal."""
    blank_box(tmp_path)

    def broken(self: Plan) -> PlanOutcome:
        self._sink.emit(LogLine("main", "blank", "first", Stream.STDOUT, "working"))
        raise RuntimeError("an error of the machine")

    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(Plan, "run", broken)
        with pytest.raises(RuntimeError):
            _update(tmp_path, [ScriptedStep("first", 1, Journal())])
    home = tmp_path / "opt" / "pridem"
    [path] = sorted((home / "journal").glob("*.jsonl"))
    cut = read_journal(path)
    assert cut.finished is None and cut.damaged_at is None
    assert [type(e).__name__ for e in cut.events] == ["LogLine"]
    assert not (home / "history" / f"{path.stem}.json").exists()
    # the pair: it ends -- run_finished; recover closed the cut run
    code, ref = _update(tmp_path, [ScriptedStep("first", 1, Journal())])
    assert code == 0
    done = read_journal(home / ref)
    assert done.finished is not None and done.finished.exit_code == ExitCode.OK
    recovered = json.loads((home / "history" / f"{path.stem}.json").read_text())
    assert recovered["result"] == "red"
    assert read_journal(path).finished is None  # recover writes no journal


# --- around the probes ------------------------------------------------------------


def _status(root: Path) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    with FakeRunner() as runner:
        code = run(
            ["--json", "status"],
            root=root / "opt" / "pridem",
            out=out,
            err=err,
            runner=runner,
            fs_root=root,
        )
    return code, out.getvalue(), err.getvalue()


def test_status_ends_its_journal(tmp_path: Path) -> None:
    """``status`` writes its own journal: the header and ``run_finished``."""
    blank_box(tmp_path)
    code, out, _ = _status(tmp_path)
    verdict = json.loads(out)
    lines = _lines(tmp_path, verdict["log_ref"])
    assert [(line["event"], line["seq"]) for line in lines] == [
        ("header", 1),
        ("run_finished", 2),
    ]
    assert lines[-1]["exit_code"] == code == verdict["exit_code"]


def test_a_failure_to_write_the_end_is_said_and_keeps_the_code(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The end cannot be written (disk full after the verdict): one line to
    stderr, the exit code is the verdict's -- never silent."""
    blank_box(tmp_path)

    def full(self: JournalSink, *_: object) -> None:
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(JournalSink, "finish", full)
    code, out, err = _status(tmp_path)
    assert code == json.loads(out)["exit_code"] == 0
    assert err == "journal: the end of the run is not written: OSError\n"


def test_a_notice_is_cleaned_of_known_secrets(tmp_path: Path) -> None:
    """A notice carries what a step put in it: a known secret in it is
    cleaned in the journal, as every line is (contract 2 rule 2). The pair:
    the rest of the notice is there."""
    blank_box(tmp_path)
    secret = _secret(tmp_path)

    class Telling(ScriptedStep):
        def act(self, ctx: StepContext, check: CheckResult) -> None:
            ctx.notice(
                KeyNeeded(
                    repo="git@github.com:a/blank.git",
                    key=KEY,
                    page=None,
                    write=True,
                    why=f"it pushes with {secret}",
                    wait_s=0,
                )
            )

    _, ref = _update(tmp_path, [Telling("tell", 1, Journal())])
    [notice] = [line for line in _lines(tmp_path, ref) if line["event"] == "notice"]
    assert secret not in json.dumps(notice)
    assert notice["notice"] == {
        "kind": "key_needed",
        "repo": "git@github.com:a/blank.git",
        "key": KEY,
        "write": True,
        "why": "it pushes with [redacted]",
        "wait_s": 0,
        "again": False,
    }


def _no_seq(line: Line) -> object:
    return line.pop("seq")


def _no_at(line: Line) -> object:
    return line.pop("at")


def _a_gap(line: Line) -> object:
    line["seq"] = 3
    return None


def _seconds(line: Line) -> object:
    line["at"] = "2026-11-24T10:00:00Z"
    return None


@pytest.mark.parametrize("change", [_no_seq, _no_at, _a_gap, _seconds])
def test_a_line_out_of_the_stream_is_damaged(
    tmp_path: Path, change: Callable[[Line], object]
) -> None:
    """Twin SHORTAGE: a line without ``seq`` or ``at`` -- a journal of an
    earlier machine -- a ``seq`` that is not its number, an ``at`` not to the
    millisecond: the reader stops at that line and names it."""
    blank_box(tmp_path)
    _, ref = _update(tmp_path, [ScriptedStep("first", 1, Journal())])
    path = tmp_path / "opt" / "pridem" / ref
    lines = path.read_text().splitlines()
    first = json.loads(lines[1])
    change(first)
    lines[1] = json.dumps(first)
    path.write_text("\n".join(lines) + "\n")
    found = read_journal(path)
    assert found.damaged_at == 2 and found.finished is None


def test_a_line_after_the_end_is_damaged(tmp_path: Path) -> None:
    """Twin REPEAT: a line after ``run_finished`` -- the stream ended there."""
    blank_box(tmp_path)
    _, ref = _update(tmp_path, [ScriptedStep("first", 1, Journal())])
    path = tmp_path / "opt" / "pridem" / ref
    lines = path.read_text().splitlines()
    extra = json.loads(lines[-1])
    extra["seq"] = len(lines) + 1
    path.write_text("\n".join([*lines, json.dumps(extra)]) + "\n")
    found = read_journal(path)
    assert found.damaged_at == len(lines) + 1 and found.finished is not None


def test_a_header_without_its_seq_is_damaged(tmp_path: Path) -> None:
    """The header is line 1 of the stream: another ``seq`` is
    ``JournalDamaged``."""
    blank_box(tmp_path)
    _, ref = _update(tmp_path, [ScriptedStep("first", 1, Journal())])
    path = tmp_path / "opt" / "pridem" / ref
    lines = path.read_text().splitlines()
    header = json.loads(lines[0])
    header["seq"] = 2
    path.write_text("\n".join([json.dumps(header), *lines[1:]]) + "\n")
    with pytest.raises(JournalDamaged):
        read_journal(path)


class Printing(ScriptedStep):
    """A step whose command is a real child Python printing five lines."""

    def act(self, ctx: StepContext, check: CheckResult) -> None:
        ctx.runner.run(
            [sys.executable, "-c", "for n in range(5): print(f'child {n}')"],
            timeout=60,
            on_line=ctx.on_line,
        )


def test_the_lines_of_a_child_keep_their_order_in_the_stream(tmp_path: Path) -> None:
    """A real child process prints five lines: they are lines of the stream in
    their order, ``seq`` rising one by one. Run with and without
    ``PYTHONUNBUFFERED`` (par0 6.3): the child's buffering never reorders."""
    blank_box(tmp_path)
    _, ref = _update(tmp_path, [Printing("print", 1, Journal())], SubprocessRunner())
    lines = _lines(tmp_path, ref)
    printed = [line for line in lines if line["event"] == "log"]
    assert [line["line"] for line in printed] == [f"child {n}" for n in range(5)]
    seqs = [int(str(line["seq"])) for line in printed]
    assert seqs == list(range(seqs[0], seqs[0] + 5))
    assert lines[-1]["event"] == "run_finished"
