"""Where the truth about runs lives on a box (contract 2 section 3).

``<root>/`` (``/opt/pridem`` on a box) holds:

- ``lock`` -- one active command per box: ``flock(LOCK_EX | LOCK_NB)``; a second
  command is refused with ``BoxBusy`` naming the holder, it never waits. The
  kernel drops the lock with its process, so a dead run never holds the box.
  Every write below requires the lock; it is checked, not hoped for.
- ``state.json`` -- composition, passport version, ``current`` of each stack,
  last ``run_id`` per verb; replaced atomically (temp + fsync + rename + fsync
  of the directory).
- ``history/<run_id>.json`` -- every verdict, append-only: written as temp +
  fsync + ``link`` to the final name, so a name already taken is
  ``HistoryExists`` and the first verdict stays as it was. Nothing here edits
  or removes a verdict.
- ``journal/<run_id>.jsonl`` -- the header first (``run_id, verb, mode, args,
  actor, started, passport_version, composition_before``), created with it by
  temp + link before the first step, so no journal exists without one; then
  one JSON line per step event and log line, each with its plan phase. Known
  secrets are cleaned on write. A line is flushed when written; the file is
  fsynced on every finished step and when closed. A reader drops a torn last
  line (the writer died in it) and stops at the first damaged line after the
  header, naming it; a damaged header is ``JournalDamaged``. Journals are
  evicted oldest ``run_id`` first down to the passport's budget, quarantined
  ones (``<run_id>.jsonl.damaged``) with them; the journal of the current run is
  never evicted, and a verdict outlives its journal.

A run that ended without a verdict (journal, no verdict) is recovered under
the lock before a new journal opens: a red verdict whose steps are the
finished steps of the journal and whose ``incomplete`` names the last step the
journal reached, or the line where it is damaged (contract 2 rule 4). Its
``composition_before`` is the header's; its ``composition_after`` is what
``state.json`` holds at recovery -- a run may die between ``finalize`` writing
``state.json`` and its verdict, so only the header knows the composition
before. A journal whose header is damaged cannot give a verdict (no verb, no
actor): it is quarantined and recovery goes on, so one bad file never blocks
the box.

``state.json`` is created by ``finalize`` only. ``write_verdict`` records the
last run of a verb in an existing ``state.json`` and writes nothing else: a
red first ``install`` must not leave a composition the box does not have.
"""

import fcntl
import json
import os
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated, Literal, TextIO

from pydantic import Field, TypeAdapter, ValidationError

from pridem.contract import Strict
from pridem.events import (
    Event,
    Incomplete,
    Json,
    LogLine,
    Phase,
    PlanMode,
    PlanOutcome,
    Secrets,
    StepFinished,
    StepRecord,
    StepStarted,
)
from pridem.report.codes import ExitCode
from pridem.report.schema import (
    RUN_ID,
    Actor,
    Composition,
    Moment,
    Text,
    Verdict,
    build_verdict,
)
from pridem.runner import Stream

STATE = "state.json"
LOCK = "lock"
HISTORY = "history"
JOURNAL = "journal"
_TEMP_SUFFIX = ".tmp"
_QUARANTINE_SUFFIX = ".damaged"

RunId = Annotated[str, Field(pattern=f"^{RUN_ID.pattern}$")]
JournalEvent = StepStarted | StepFinished | LogLine


class BoxBusy(Exception):
    """Another command holds the box."""

    def __init__(self, holder: str) -> None:
        self.holder = holder
        super().__init__(f"the box is busy: {holder or 'a command is starting'}")


class NotLocked(RuntimeError):
    """A write to the box outside the lock."""


class HistoryExists(FileExistsError):
    """A verdict with this run_id is already in history/; history is append-only."""


class JournalDamaged(ValueError):
    """The header line of a journal is not a valid journal header."""


class BoxState(Strict):
    composition: Composition
    passport_version: Annotated[int, Field(ge=1)]
    current: dict[str, Text]
    last_run: dict[str, RunId]


class JournalHeader(Strict):
    run_id: RunId
    verb: Text
    mode: PlanMode
    args: dict[str, Json]
    actor: Actor
    started: Moment
    passport_version: Annotated[int, Field(ge=1)]
    composition_before: Composition


class _Started(Strict):
    event: Literal["step_started"]
    phase: Phase
    stack: Text
    name: Text
    order: int
    started: Moment


class _Finished(Strict):
    event: Literal["step_finished"]
    phase: Phase
    stack: Text
    name: Text
    order: int
    status: Literal["ok", "failed", "skipped"]
    reason: str | None = None
    started: Moment | None = None
    duration_s: float | None = None
    verify: dict[str, Json] = {}


class _Log(Strict):
    event: Literal["log"]
    phase: Phase
    stack: Text
    name: Text
    stream: Literal["stdout", "stderr"]
    line: str


_LINE: TypeAdapter[_Started | _Finished | _Log] = TypeAdapter(
    Annotated[_Started | _Finished | _Log, Field(discriminator="event")]
)


@dataclass(frozen=True)
class Journal:
    """A journal as read back: header, events, whether the last line was torn."""

    header: JournalHeader
    events: tuple[JournalEvent, ...]
    torn: bool
    written: datetime
    """When the journal was last written (its mtime)."""
    damaged_at: int | None = None
    """The first damaged line after the header; ``events`` end before it."""


@dataclass(frozen=True)
class Recovery:
    """What ``recover`` did: verdicts written, journals put in quarantine."""

    verdicts: tuple[Verdict, ...]
    quarantined: tuple[str, ...]


def _stamp(moment: datetime) -> str:
    return moment.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _fsync_dir(directory: Path) -> None:
    fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _temp(final: Path) -> Path:
    return final.with_name(f".{final.name}{_TEMP_SUFFIX}")


def _write_new(final: Path, text: str, *, replace: bool) -> None:
    """Write ``text`` to ``final`` atomically.

    ``replace`` renames over an existing file; otherwise the temp file is linked
    to ``final`` and an existing ``final`` is ``FileExistsError``, untouched.
    """
    temp = _temp(final)
    with temp.open("w", encoding="utf-8") as handle:
        handle.write(text)
        handle.flush()
        os.fsync(handle.fileno())
    if replace:
        os.replace(temp, final)
    else:
        try:
            os.link(temp, final)
        finally:
            temp.unlink()
    _fsync_dir(final.parent)


def _event_line(event: JournalEvent, secrets: Secrets) -> str:
    raw: dict[str, Json]
    if isinstance(event, StepStarted):
        raw = {
            "event": "step_started",
            "phase": event.phase,
            "stack": event.stack,
            "name": event.name,
            "order": event.order,
            "started": _stamp(event.started),
        }
    elif isinstance(event, StepFinished):
        record = event.record
        raw = {
            "event": "step_finished",
            "phase": event.phase,
            "stack": record.stack,
            "name": record.name,
            "order": record.order,
            "status": record.status,
        }
        if record.reason is not None:
            raw["reason"] = secrets.text(record.reason)
        if record.started is not None:
            raw["started"] = _stamp(record.started)
        if record.duration_s is not None:
            raw["duration_s"] = record.duration_s
        raw["verify"] = secrets.fact(record.verify)
    else:
        raw = {
            "event": "log",
            "phase": event.phase,
            "stack": event.stack,
            "name": event.name,
            "stream": event.stream.value,
            "line": secrets.text(event.line),
        }
    return json.dumps(raw, ensure_ascii=False) + "\n"


def _event(line: _Started | _Finished | _Log) -> JournalEvent:
    if isinstance(line, _Started):
        return StepStarted(line.phase, line.stack, line.name, line.order, line.started)
    if isinstance(line, _Finished):
        record = StepRecord(
            line.stack,
            line.name,
            line.order,
            line.status,
            line.reason,
            line.started,
            line.duration_s,
            line.verify,
        )
        return StepFinished(line.phase, record)
    return LogLine(line.phase, line.stack, line.name, Stream(line.stream), line.line)


class JournalSink:
    """The journal of the current run as an event sink; cleans secrets on write."""

    def __init__(self, path: Path, secrets: Secrets) -> None:
        self._secrets = secrets
        self._handle: TextIO = path.open("a", encoding="utf-8")

    def emit(self, event: Event) -> None:
        if not isinstance(event, StepStarted | StepFinished | LogLine):
            return  # the outcome belongs to the verdict, not to the journal
        self._handle.write(_event_line(event, self._secrets))
        self._handle.flush()
        if isinstance(event, StepFinished):
            os.fsync(self._handle.fileno())

    def close(self) -> None:
        self._handle.flush()
        os.fsync(self._handle.fileno())
        self._handle.close()


def read_journal(path: Path) -> Journal:
    """The journal at ``path``.

    A torn last line is dropped; the first damaged line after the header ends
    the events and is named in ``damaged_at``; a damaged header raises.
    """
    lines = path.read_text(encoding="utf-8").split("\n")
    torn = lines[-1] != ""
    body = lines if torn else lines[:-1]
    try:
        first = json.loads(body[0])
        if not isinstance(first, dict) or first.pop("event", None) != "header":
            raise ValueError("the first line is not a journal header")
        header = JournalHeader.model_validate(first)
    except (IndexError, ValueError) as error:
        raise JournalDamaged(f"{path}:1: {error}") from error
    events: list[JournalEvent] = []
    damaged_at: int | None = None
    for number, text in enumerate(body[1:], start=2):
        try:
            events.append(_event(_LINE.validate_json(text)))
        except ValidationError:
            if not (torn and number == len(body)):
                damaged_at = number
            break
    written = datetime.fromtimestamp(path.stat().st_mtime, UTC)
    return Journal(header, tuple(events), torn, written, damaged_at)


def _run_of(path: Path) -> str:
    """The run id of a journal file, quarantined or not."""
    return path.name.partition(".")[0]


def _actor(actor: Actor) -> Mapping[str, str]:
    return {k: v for k, v in actor.model_dump().items() if isinstance(v, str)}


class Box:
    """The machine's directory on a box; writes only under the box lock."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self.history = root / HISTORY
        self.journals = root / JOURNAL
        self._locked = False

    def _require_lock(self) -> None:
        if not self._locked:
            raise NotLocked("the box is written only under its lock")

    @contextmanager
    def lock(self, holder: str) -> Iterator[None]:
        """Hold the box for one command; ``BoxBusy`` if another holds it."""
        for directory in (self.root, self.history, self.journals):
            directory.mkdir(parents=True, exist_ok=True)
        fd = os.open(self.root / LOCK, os.O_RDWR | os.O_CREAT, 0o600)
        try:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                held = os.pread(fd, 4096, 0).decode("utf-8", "replace")
                raise BoxBusy(held) from None
            os.ftruncate(fd, 0)
            os.pwrite(fd, holder.encode("utf-8"), 0)
            os.fsync(fd)
            self._locked = True
            try:
                self._remove_temps()
                yield
            finally:
                self._locked = False
                fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)

    def _remove_temps(self) -> None:
        """Temp files a dead writer left; none is a verdict, a state or a journal."""
        for directory in (self.root, self.history, self.journals):
            for temp in directory.glob(f".*{_TEMP_SUFFIX}"):
                temp.unlink()

    # --- state.json -------------------------------------------------------------

    def read_state(self) -> BoxState | None:
        """The box state, or ``None`` on a box no command has written one yet."""
        path = self.root / STATE
        if not path.exists():
            return None
        return BoxState.model_validate_json(path.read_text(encoding="utf-8"))

    def write_state(self, state: BoxState) -> None:
        """Replace ``state.json`` atomically."""
        self._require_lock()
        _write_new(self.root / STATE, state.model_dump_json(indent=2), replace=True)

    # --- history/ ---------------------------------------------------------------

    def read_verdict(self, run_id: str) -> Verdict:
        path = self.history / f"{run_id}.json"
        return Verdict.model_validate_json(path.read_text(encoding="utf-8"))

    def history_ids(self) -> list[str]:
        """Run ids in history, oldest first."""
        return sorted(path.stem for path in self.history.glob("*.json"))

    def write_verdict(self, verdict: Verdict) -> None:
        """Add ``verdict`` to history, then record it as the last run of its verb."""
        self._require_lock()
        final = self.history / f"{verdict.run_id}.json"
        try:
            _write_new(final, verdict.model_dump_json(indent=2), replace=False)
        except FileExistsError as error:
            raise HistoryExists(f"history already holds {verdict.run_id}") from error
        state = self.read_state()
        if state is None:
            return  # state.json is finalize's to create
        last = state.last_run.get(verdict.verb)
        if last is None or last < verdict.run_id:
            runs = {**state.last_run, verdict.verb: verdict.run_id}
            self.write_state(state.model_copy(update={"last_run": runs}))

    # --- journal/ ---------------------------------------------------------------

    def open_journal(self, header: JournalHeader, secrets: Secrets) -> JournalSink:
        """Create the journal of a run with its header line; return its sink."""
        self._require_lock()
        final = self.journals / f"{header.run_id}.jsonl"
        raw = header.model_dump(mode="json", exclude_none=True)
        raw["args"] = secrets.value(raw["args"])
        line = json.dumps({"event": "header", **raw}, ensure_ascii=False) + "\n"
        _write_new(final, line, replace=False)
        return JournalSink(final, secrets)

    def read_journal(self, run_id: str) -> Journal | None:
        """The journal of ``run_id``, or ``None`` when it was evicted."""
        path = self.journals / f"{run_id}.jsonl"
        return read_journal(path) if path.exists() else None

    def evict_journals(self, budget: int, keep: str) -> dict[str, Json]:
        """Evict journals oldest ``run_id`` first until ``journal/`` fits ``budget``.

        The journal of ``keep`` (the current run) is never evicted; when it alone
        exceeds the budget every other journal goes and the fact says so.
        """
        self._require_lock()
        files = sorted(self._journal_files(), key=_run_of)
        sizes = {path: path.stat().st_size for path in files}
        total = sum(sizes.values())
        evicted: list[Json] = []
        for path in files:
            if total <= budget:
                break
            if path.name == f"{keep}.jsonl":
                continue
            path.unlink()
            total -= sizes[path]
            evicted.append(_run_of(path))
        if evicted:
            _fsync_dir(self.journals)
        return {"evicted": evicted, "kept_bytes": total, "over_budget": total > budget}

    # --- a run that ended without a verdict ---------------------------------------

    def _journal_files(self) -> list[Path]:
        return [
            *self.journals.glob("*.jsonl"),
            *self.journals.glob(f"*.jsonl{_QUARANTINE_SUFFIX}"),
        ]

    def recover(self, secrets: Secrets, machine_version: str) -> Recovery:
        """Write a red verdict for every journal that has none (contract 2 rule 4).

        A journal whose header is damaged is renamed ``<run_id>.jsonl.damaged``
        and listed in the result; recovery goes on with the next journal.
        """
        self._require_lock()
        verdicts: list[Verdict] = []
        quarantined: list[str] = []
        for path in sorted(self.journals.glob("*.jsonl"), key=_run_of):
            if (self.history / f"{path.stem}.json").exists():
                continue
            try:
                journal = read_journal(path)
            except JournalDamaged:
                path.rename(path.with_name(path.name + _QUARANTINE_SUFFIX))
                _fsync_dir(self.journals)
                quarantined.append(path.stem)
                continue
            verdict = self._orphan_verdict(journal, secrets, machine_version)
            self.write_verdict(verdict)
            verdicts.append(verdict)
        return Recovery(tuple(verdicts), tuple(quarantined))

    def _orphan_verdict(
        self, journal: Journal, secrets: Secrets, machine_version: str
    ) -> Verdict:
        header = journal.header
        phases: dict[Phase, list[StepRecord]] = {
            "main": [],
            "restore": [],
            "finally": [],
        }
        last = "the start"
        for event in journal.events:
            if isinstance(event, StepStarted):
                last = f"{event.phase} {event.stack}/{event.name}"
            elif isinstance(event, StepFinished):
                phases[event.phase].append(event.record)
                last = f"{event.phase} {event.record.stack}/{event.record.name}"
        if journal.damaged_at is not None:
            ended = f"journal damaged at line {journal.damaged_at}"
        else:
            ended = f"journal ends at step {last}"
        outcome = PlanOutcome(
            mode=header.mode,
            code=ExitCode.FAILED,
            steps=tuple(phases["main"]),
            restore=tuple(phases["restore"]),
            finally_=tuple(phases["finally"]),
            incomplete=(Incomplete("run", f"no verdict found; {ended}"),),
        )
        state = self.read_state()
        after = state.composition if state else {"pridem": machine_version}
        return build_verdict(
            outcome,
            run_id=header.run_id,
            verb=header.verb,
            args=header.args,
            actor=_actor(header.actor),
            started=header.started,
            # a clock stepped back must not make a run end before it began
            finished=max(journal.written, header.started),
            passport_version=header.passport_version,
            composition_before=header.composition_before,
            composition_after=after,
            secrets=secrets,
        )
