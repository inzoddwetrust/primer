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

from pydantic import Field, TypeAdapter

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
    Actor,
    Composition,
    Moment,
    RunId,
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
_DIR_MODE = 0o700
_FILE_MODE = 0o600
STATE_DAMAGED = "state damaged; quarantined"

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


class VerdictDamaged(ValueError):
    """A file in ``history/`` cannot be read as a verdict; the text never quotes it."""


class StateDamaged(ValueError):
    """``state.json`` is there but cannot be read; read outside the lock.

    Under the lock a damaged ``state.json`` is quarantined instead. The message
    never quotes the file: it names the kind of damage only.
    """


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


_RUN_ID: TypeAdapter[str] = TypeAdapter(RunId)
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
    state_quarantined: bool = False


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
    # private from creation: a umask can only narrow 0600, never widen it
    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, _FILE_MODE)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        if replace:
            os.replace(temp, final)
        else:
            os.link(temp, final)
    finally:
        # a failed write leaves no temp behind (O_EXCL would refuse the next one);
        # after replace there is none, after link the final name holds the data
        temp.unlink(missing_ok=True)
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
        # the journal exists (open_journal created it, 0600); never create one here
        fd = os.open(path, os.O_WRONLY | os.O_APPEND)
        self._handle: TextIO = os.fdopen(fd, "a", encoding="utf-8")

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
    """The journal at ``path``, read as bytes and decoded line by line.

    A torn last line is dropped (a writer can die inside a UTF-8 character);
    the first damaged line after the header -- invalid UTF-8 included -- ends
    the events and is named in ``damaged_at``; a damaged header raises.
    """
    lines = path.read_bytes().split(b"\n")
    torn = lines[-1] != b""
    body = lines if torn else lines[:-1]
    try:
        first = json.loads(body[0].decode("utf-8"))
        if not isinstance(first, dict) or first.pop("event", None) != "header":
            raise ValueError("the first line is not a journal header")
        header = JournalHeader.model_validate(first)
    except (IndexError, ValueError) as error:  # UnicodeDecodeError is a ValueError
        # the line is not quoted: a header carries the run's args
        raise JournalDamaged(f"{path}:1: {type(error).__name__}") from None
    events: list[JournalEvent] = []
    damaged_at: int | None = None
    for number, raw in enumerate(body[1:], start=2):
        try:
            events.append(_event(_LINE.validate_json(raw.decode("utf-8"))))
        except ValueError:  # ValidationError and UnicodeDecodeError alike
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
        self.state_quarantined = False
        """``state.json`` was quarantined while this ``Box`` held the lock."""

    def _require_lock(self) -> None:
        if not self._locked:
            raise NotLocked("the box is written only under its lock")

    @contextmanager
    def lock(self, holder: str) -> Iterator[None]:
        """Hold the box for one command; ``BoxBusy`` if another holds it."""
        for directory in (self.root, self.history, self.journals):
            directory.mkdir(mode=_DIR_MODE, parents=True, exist_ok=True)
        fd = os.open(self.root / LOCK, os.O_RDWR | os.O_CREAT, _FILE_MODE)
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
            self.state_quarantined = False
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
        """The box state, or ``None`` when there is no ``state.json``.

        A damaged ``state.json`` (not UTF-8, not JSON, not the schema, empty) is
        quarantined under the lock -- renamed ``state.json.damaged`` over an
        earlier one, ``state_quarantined`` set -- and the box lives as without
        it (TZ section 7.3). Outside the lock it is ``StateDamaged`` and stays
        where it is: ``None`` means only that there is no file.
        """
        path = self.root / STATE
        if not path.exists():
            return None
        try:
            return BoxState.model_validate_json(path.read_bytes().decode("utf-8"))
        except ValueError as error:  # ValidationError and UnicodeDecodeError alike
            kind = type(error).__name__
        if not self._locked:
            raise StateDamaged(f"{path} is damaged ({kind})") from None
        os.replace(path, path.with_name(STATE + _QUARANTINE_SUFFIX))
        _fsync_dir(self.root)
        self.state_quarantined = True
        return None

    def write_state(self, state: BoxState) -> None:
        """Replace ``state.json`` atomically."""
        self._require_lock()
        _write_new(self.root / STATE, state.model_dump_json(indent=2), replace=True)

    # --- history/ ---------------------------------------------------------------

    def read_verdict(self, run_id: str) -> Verdict:
        """The verdict of ``run_id``; a damaged file is ``VerdictDamaged``.

        History is append-only, so a damaged verdict stays where it is; the
        error names the kind of damage only, never the file's content.
        """
        path = self.history / f"{_RUN_ID.validate_python(run_id)}.json"
        try:
            return Verdict.model_validate_json(path.read_bytes().decode("utf-8"))
        except ValueError as error:  # ValidationError and UnicodeDecodeError alike
            kind = type(error).__name__
        raise VerdictDamaged(f"{path}: {kind}") from None

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
        path = self.journals / f"{_RUN_ID.validate_python(run_id)}.jsonl"
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
        ``state.json`` is read once, before the journals: a damaged one is
        quarantined then, and every verdict written here carries
        ``{state, state damaged; quarantined}`` beside ``{run, ...}`` -- its
        ``composition_after`` is the bare ``{pridem}`` for that reason.
        """
        self._require_lock()
        state = self.read_state()
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
            verdict = self._orphan_verdict(journal, state, secrets, machine_version)
            self.write_verdict(verdict)
            verdicts.append(verdict)
        return Recovery(tuple(verdicts), tuple(quarantined), self.state_quarantined)

    def _orphan_verdict(
        self,
        journal: Journal,
        state: BoxState | None,
        secrets: Secrets,
        machine_version: str,
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
            incomplete=(
                Incomplete("run", f"no verdict found; {ended}"),
                *(
                    (Incomplete("state", STATE_DAMAGED),)
                    if self.state_quarantined
                    else ()
                ),
            ),
        )
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
