"""``pridem agent``: the agent of the box (``PRIMER-PANEL-TZ-2`` 5-10;
DM-141).

One process per box: it holds ``agent/agent.lock`` of the box's agent
directory by ``flock`` for its whole life; a second agent is refused, the
holder named. It never takes the box's lock: the verbs it runs take it.

Two loops, two threads:

- **The heartbeat** -- every ``heartbeat_s`` of the registration a light one
  (``light_beat``: the moment, the machine's version, the processes that hold
  the box's lock, the journals with no verdict, the last run of
  ``history/``), every ``full_state_s`` and after every run a full one, with
  the state of ``pridem state --json`` (DM-136) measured in the process.
- **The queue** -- while the box's lock is held (a run of the console or a
  timer) the agent does not ask for a command: it looks again in
  ``BUSY_PAUSE_S``. Free: first what of ``history/`` the Panel does not hold
  (``sync``, below), then the long-poll ``commands/next``; a 204 faster than
  ``QUIET_POLL_S`` is followed by a pause to it. A command is
  checked (``pridem.agent.command``) and refused by its code before any run,
  or run as the console would run it: ``pridem --json --command <id> <verb>
  ...``, a process of the runner. A run refused by a busy box (a race with
  the console) is run again every ``BUSY_PAUSE_S`` until ``expires_at``,
  then refused ``expired``; another refusal of the command line before a run
  is a line of the agent's log -- the Panel expires the command. One run at a
  time: no command is asked for while one runs.

The run's journal is the one whose header names the command, written since
the run began. Every ``STREAM_TICK_S`` the agent reads it whole and sends the
lines after the last ``seq`` the Panel holds with no gap, in batches of
``BATCH``; the Panel's answer is where it goes on. When the run is over the
rest of the lines go, then the verdict in its signed envelope (DM-140) --
one try; the next heartbeat is a full one.

**No verdict lost** (part B): the cursor of ``history/``
(``pridem.agent.history``) says which runs the Panel holds. Before every
long-poll -- so when the agent starts and when the Panel is back -- every
pending run goes, oldest first: its lines while its journal lives, then its
envelope; envelopes in batches of ``HISTORY_BATCH`` by ``history``, a
batch the Panel cannot read (422) one by one. A run of the console, of a
timer, of a command whose verdict did not go, of a command whose run died
with the agent (its verdict written by ``recover`` of the next run under the
lock) -- all go the same way. The cursor's hour before ``through`` and its
KNOWN CEILING (a clock set back by more than it): ``pridem.agent.history``.

The Panel away: the queue's turn and the heartbeat are repeated after a
pause of 1, 2, 4 ... up to 300 s, with no end (``Backoff``); so are the codes
of the transport (``signature-bad``, ``box-unknown``, ``protocol-too-old``,
``protocol-too-new``, ``clock-skew``) -- the Panel mends them on its side. A
run goes on while the Panel is away; its lines and its verdict wait in
``history/`` and ``journal/``. A refusal of one run (``run-foreign``, an
answer not of contract 4) is kept in the cursor by its code.

The log of the agent says codes, verbs, command ids and run ids -- never a
body, never a value.
"""

import fcntl
import io
import json
import os
import threading
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime
from functools import partial
from pathlib import Path
from typing import TextIO

from pydantic import TypeAdapter

from pridem import __version__
from pridem.agent.client import (
    BaseMismatch,
    PanelClient,
    PanelDown,
    Refused,
    Unread,
)
from pridem.agent.command import checked
from pridem.agent.envelope import EnvelopeRefused, envelope
from pridem.agent.history import (
    RETRY_UNREAD_S,
    UNREAD,
    Cursor,
    CursorDamaged,
    advanced,
    pending,
    read_cursor,
    write_cursor,
)
from pridem.files import private_dir
from pridem.identity import (
    KeyDamaged,
    RegistrationDamaged,
    agent_dir,
    load_seed,
    read_registration,
)
from pridem.protocol import (
    Command,
    EventBatch,
    Heartbeat,
    HistoryBatch,
    RefusalCode,
    VerdictEnvelope,
)
from pridem.report.box_snapshot import BoxSnapshot
from pridem.runner import Runner, RunnerError, Stream, SubprocessRunner
from pridem.state import (
    HISTORY,
    JOURNAL,
    LOCK,
    HeaderLine,
    JournalLine,
    holders,
)
from pridem.steps.identity import HttpTransport, PanelUnreachable, Requests
from pridem.verbs.base import Context
from pridem.verbs.base import Refused as Refusal
from pridem.verbs.state import snapshot

AGENT_LOCK = "agent.lock"
BUSY_PAUSE_S = 5.0
STREAM_TICK_S = 1.0
BATCH = 200
QUIET_POLL_S = 1.0
"""A long-poll the Panel answers 204 faster than this is followed by a pause
to it: a Panel that holds no long-poll is not asked in a loop."""
HISTORY_BATCH = 20
RUN_TIMEOUT_S = 24 * 3600.0
"""A run the agent started longer than a day is stopped: no rollout lasts so
long; ``recover`` of the next run gives it its verdict."""
BACKOFF_S = (1.0, 300.0)
"""The first pause after a failed request and the longest (TZ-2 10)."""
TRANSPORT: frozenset[RefusalCode] = frozenset(
    {
        "signature-bad",
        "box-unknown",
        "protocol-too-old",
        "protocol-too-new",
        "clock-skew",
    }
)
"""Refusals of any request by who sends it: repeated, never given up."""
STAMP = "%Y-%m-%dT%H:%M:%SZ"

_LINE: TypeAdapter[JournalLine] = TypeAdapter(JournalLine)


class Backoff:
    """Pauses of 1, 2, 4 ... up to 300 s after failed requests."""

    def __init__(self) -> None:
        self.next = BACKOFF_S[0]

    def reset(self) -> None:
        self.next = BACKOFF_S[0]

    def wait(self, pause: Callable[[float], bool]) -> bool:
        """Pause; ``False`` -- the agent stops."""
        seconds = self.next
        self.next = min(self.next * 2, BACKOFF_S[1])
        return pause(seconds)


def light_beat(
    root: Path, now: datetime, state: BoxSnapshot | None = None
) -> Heartbeat:
    """The heartbeat: what the box says of itself, measured as ``pridem
    state`` measures it; with ``state`` -- the full one."""
    history, journal = root / HISTORY, root / JOURNAL
    verdicts = {p.stem for p in history.glob("*.json")} if history.is_dir() else set()
    journals = (
        sorted(p.stem for p in journal.glob("*.jsonl")) if journal.is_dir() else []
    )
    found: dict[str, object] = {
        "measured_at": now.astimezone(UTC).strftime(STAMP),
        "machine_version": __version__,
        "lock_open_by": list(holders(root / LOCK)),
        "journals_without_verdict": [j for j in journals if j not in verdicts],
    }
    if verdicts:
        found["last_run_id"] = max(verdicts)
    if state is not None:
        found["state"] = state
    return Heartbeat.model_validate(found)


def journal_lines(path: Path) -> list[JournalLine]:
    """The whole lines of a journal in their order, up to the first that is
    not (a torn last line of a run going on, a damaged one)."""
    lines: list[JournalLine] = []
    for number, raw in enumerate(path.read_bytes().split(b"\n"), start=1):
        try:
            line = _LINE.validate_json(raw)
        except ValueError:
            break
        if line.seq != number:
            break
        lines.append(line)
    return lines


def journal_of(root: Path, command_id: str, since: float) -> Path | None:
    """The journal of the run of ``command_id``: its header names the
    command, it was written since ``since`` (a time of ``time.time``)."""
    directory = root / JOURNAL
    if not directory.is_dir():
        return None
    for path in sorted(directory.glob("*.jsonl")):
        try:
            if path.stat().st_mtime < since - 1:
                continue
            with path.open("rb") as file:
                header = _LINE.validate_json(file.readline())
        except (OSError, ValueError):
            continue
        if isinstance(header, HeaderLine) and header.command == command_id:
            return path
    return None


@dataclass
class Agent:
    """The agent of the box at ``root``; ``pause`` sleeps and says whether
    the agent goes on; ``say`` -- a line of its log."""

    root: Path
    client: PanelClient
    runner: Runner
    now: Callable[[], datetime]
    pause: Callable[[float], bool]
    say: Callable[[str], None]
    state: Callable[[], BoxSnapshot]
    owner: int
    heartbeat_s: int
    full_state_s: int
    executable: str = "pridem"
    monotonic: Callable[[], float] = time.monotonic
    full_due: threading.Event = field(default_factory=threading.Event)
    _cursor: Cursor | None = None
    _retried: float | None = None

    # --- the heartbeat ----------------------------------------------------------

    def beat(self, full: bool) -> None:
        """One heartbeat to the Panel."""
        state = self.state() if full else None
        self.client.heartbeat(light_beat(self.root, self.now(), state))

    def beats(self, stopping: Callable[[], bool]) -> None:
        """The heartbeat's loop."""
        backoff = Backoff()
        last_full: datetime | None = None
        while not stopping():
            now = self.now()
            full = (
                last_full is None
                or (now - last_full).total_seconds() >= self.full_state_s
                or self.full_due.is_set()
            )
            if self._tried(partial(self.beat, full), "heartbeat"):
                backoff.reset()
                if full:
                    last_full = now
                    self.full_due.clear()
                if not self.pause(self.heartbeat_s):
                    return
            elif not backoff.wait(self.pause):
                return

    # --- the queue ----------------------------------------------------------------

    def turn(self) -> None:
        """One turn of the queue: nothing while the box's lock is held,
        else one long-poll and the command it gives. A failed request
        raises to ``serve``."""
        if holders(self.root / LOCK):
            self.pause(BUSY_PAUSE_S)
            return
        self.sync()
        asked = self.monotonic()
        command = self.client.next_command()
        if command is not None:
            self.handle(command)
            return
        quick = self.monotonic() - asked
        if quick < QUIET_POLL_S:  # a Panel that holds no long-poll
            self.pause(QUIET_POLL_S - quick)

    def handle(self, command: Command) -> None:
        """A command taken: refused by its code, or run."""
        found = checked(command, self.now())
        if isinstance(found, str):
            code = found
            self.say(f"command {command.id} refused: {code}")
            self._deliver(lambda: self.client.refuse(command.id, code), "refusal")
            return
        verb, argv = found
        line = [self.executable, "--json", "--command", command.id, verb.name, *argv]
        while True:
            ran = self._run(command, line)
            if ran != "busy":
                return
            if self.now() > datetime.fromisoformat(command.expires_at):
                self.say(f"command {command.id}: the box stayed busy: expired")
                self._deliver(
                    partial(self.client.refuse, command.id, "expired"), "refusal"
                )
                return
            if not self.pause(BUSY_PAUSE_S):
                return

    def _run(self, command: Command, argv: list[str]) -> str:
        """Run ``argv`` and stream its journal; ``busy`` -- the box's lock
        refused it before a run."""
        printed: list[str] = []
        failed: list[RunnerError] = []
        since = time.time()

        def work() -> None:
            try:
                self.runner.run(
                    argv,
                    expect=(0, 1, 2),
                    timeout=RUN_TIMEOUT_S,
                    on_line=lambda stream, text, cut: (
                        printed.append(text) if stream is Stream.STDOUT else None
                    ),
                )
            except RunnerError as error:
                failed.append(error)

        worker = threading.Thread(target=work, name="pridem-run", daemon=True)
        worker.start()
        path: Path | None = None
        last = 0
        while True:
            alive = worker.is_alive()
            path = path or journal_of(self.root, command.id, since)
            if path is not None:
                last = self._stream_once(path, last)
            if not alive:
                break
            worker.join(STREAM_TICK_S)
        if failed:
            self.say(f"command {command.id}: {type(failed[0]).__name__}")
        if path is None:
            if any(_busy(text) for text in printed):
                return "busy"
            self.say(f"command {command.id}: refused by the machine before a run")
            return "refused"
        self.finish(path, last)
        return "ran"

    def finish(self, path: Path, last: int) -> None:
        """A run that is over: its lines after ``last``, then its verdict --
        one try; what does not go stays pending for ``sync``. The next
        heartbeat a full one."""
        run_id = path.name.partition(".")[0]
        self.full_due.set()
        try:
            held = self._send_lines(path, last)
            lines = journal_lines(path)
            if lines and held < lines[-1].seq:
                raise NotHeld(held)
            self._send_verdicts([run_id])
        except (PanelUnreachable, PanelDown, Refused, Unread, NotHeld) as failed:
            self.say(f"run {run_id}: waits for the Panel ({_said(failed)})")

    # --- history/ ------------------------------------------------------------------

    def sync(self) -> None:
        """Every pending run of ``history/`` to the Panel, oldest first: its
        lines while its journal lives, then its envelope, in batches. A
        failed request raises to the queue's loop: what did not go stays
        pending."""
        cursor = self.cursor()
        now = self.monotonic()
        retry = self._retried is None or now - self._retried >= RETRY_UNREAD_S
        runs = pending(self.root, cursor, retry)
        if retry:
            self._retried = now
        for start in range(0, len(runs), HISTORY_BATCH):
            self._send_verdicts(runs[start : start + HISTORY_BATCH], lines=True)

    def cursor(self) -> Cursor:
        """The cursor, read once; a damaged file said and taken as none."""
        if self._cursor is None:
            try:
                self._cursor = read_cursor(self.root)
            except CursorDamaged:
                self.say("history: agent/cursor.json cannot be read: all of it again")
                self._cursor = Cursor()
        return self._cursor

    def _keep(self, held: list[str], refused: dict[str, str]) -> None:
        old = self.cursor()
        merged = Cursor.model_validate(
            {
                **({"through": old.through} if old.through is not None else {}),
                "held": sorted({*old.held, *held}),
                "refused": {
                    **{r: c for r, c in old.refused.items() if r not in held},
                    **refused,
                },
            }
        )
        self._cursor = advanced(self.root, merged)
        write_cursor(self.root, self._cursor)

    def _send_verdicts(self, runs: list[str], lines: bool = False) -> None:
        """The envelopes of ``runs`` -- one by ``runs/<id>/verdict``, more by
        ``history``; a batch refused whole -- 422, ``run-foreign`` -- sends its
        envelopes one by one, to find whose."""
        sealed: list[VerdictEnvelope] = []
        refused: dict[str, str] = {}
        for run_id in runs:
            try:
                sealed.append(envelope(self.root, run_id, owner=self.owner))
            except EnvelopeRefused as no:
                self.say(f"run {run_id}: no envelope: {no.code}")
                refused[run_id] = no.code
                continue
            path = self.root / JOURNAL / f"{run_id}.jsonl"
            if lines and path.is_file():
                try:
                    self._send_lines(path, 0)
                except Refused as no:
                    if no.code in TRANSPORT:
                        raise
                    self.say(f"run {run_id}: refused: {no.code}")
                    refused[run_id] = no.code
                    sealed.pop()
                except Unread as unread:  # the lines are the Panel's to lose
                    self.say(f"run {run_id}: lines unread ({unread.status})")
        if refused:
            self._keep([], refused)
        if not sealed:
            return
        if len(sealed) > 1:
            try:
                held = self.client.history(HistoryBatch(envelopes=sealed))
            except Unread as unread:
                if unread.status != 422:
                    raise
            except Refused as no:  # one run of the batch refused: whose?
                if no.code in TRANSPORT:
                    raise
            else:
                self._keep(held, {})
                return
        for one in sealed:
            run_id = one.verdict.run_id
            try:
                self.client.verdict(run_id, one)
            except Refused as no:
                if no.code in TRANSPORT:
                    raise
                self.say(f"run {run_id}: refused: {no.code}")
                self._keep([], {run_id: no.code})
            except Unread as unread:
                self.say(f"run {run_id}: an answer not of contract 4 ({unread.status})")
                self._keep([], {run_id: f"{UNREAD}{unread.status}"})
            else:
                self._keep([run_id], {})

    # --- a run's lines and its verdict -------------------------------------------

    def _send_lines(self, path: Path, last: int) -> int:
        """The lines after ``last`` to the Panel; the last ``seq`` it holds."""
        run_id = path.name.partition(".")[0]
        lines = [line for line in journal_lines(path) if line.seq > last]
        while lines:
            batch = EventBatch(from_seq=lines[0].seq, events=lines[:BATCH])
            held = self.client.events(run_id, batch)
            if held <= last:  # the Panel holds no more: it is its to say why
                return held
            last = held
            lines = [line for line in lines if line.seq > held]
        return last

    def _stream_once(self, path: Path, last: int) -> int:
        """A tick of a run going on: what the Panel did not get, if it is
        there to get it."""
        try:
            return self._send_lines(path, last)
        except (PanelUnreachable, PanelDown, Refused, Unread):
            return last  # the rest goes when the run is over

    # --- delivery ---------------------------------------------------------------

    def _tried(self, action: Callable[[], None], what: str) -> bool:
        """``action`` once; whether it went, its failure said."""
        try:
            action()
        except PanelUnreachable as away:
            self.say(f"{what}: the Panel did not answer ({away.cause})")
            return False
        except PanelDown as down:
            self.say(f"{what}: the Panel answered {down.status}")
            return False
        except Refused as refused:
            self.say(f"{what}: refused: {refused.code}")
            return False
        except Unread as unread:
            self.say(f"{what}: an answer not of contract 4 ({unread.status})")
            return False
        return True

    def _deliver(self, action: Callable[[], None], what: str) -> bool:
        """``action`` until it goes, a pause after each failure; a refusal of
        the message itself gives it up. ``False`` -- not delivered."""
        backoff = Backoff()
        while True:
            try:
                action()
                return True
            except Refused as refused:
                self.say(f"{what}: refused: {refused.code}")
                if refused.code not in TRANSPORT:
                    return False
            except Unread as unread:
                self.say(f"{what}: an answer not of contract 4 ({unread.status})")
                return False
            except PanelUnreachable as away:
                self.say(f"{what}: the Panel did not answer ({away.cause})")
            except PanelDown as down:
                self.say(f"{what}: the Panel answered {down.status}")
            except NotHeld as behind:
                self.say(f"{what}: the Panel holds up to seq {behind.seq}")
            if not backoff.wait(self.pause):
                return False

    # --- the whole ----------------------------------------------------------------

    def serve(self, stopping: Callable[[], bool]) -> None:
        """Both loops until ``stopping``."""
        heart = threading.Thread(
            target=self.beats, args=(stopping,), name="pridem-heartbeat", daemon=True
        )
        heart.start()
        self.queue(stopping)
        heart.join(self.heartbeat_s + 1)

    def queue(self, stopping: Callable[[], bool]) -> None:
        """The queue's loop: turns, a pause after each failed request."""
        backoff = Backoff()
        while not stopping():
            if self._tried(self.turn, "commands"):
                backoff.reset()
            elif not backoff.wait(self.pause):
                return


def _said(failed: Exception) -> str:
    """A failure of a request in the agent's words: its code, no body."""
    if isinstance(failed, PanelUnreachable):
        return f"no answer, {failed.cause}"
    if isinstance(failed, PanelDown | Unread):
        return f"answer {failed.status}"
    if isinstance(failed, Refused):
        return f"refused: {failed.code}"
    return f"lines held to seq {failed}"


class NotHeld(Exception):
    """The Panel holds the lines of a run that is over up to ``seq`` only."""

    def __init__(self, seq: int) -> None:
        super().__init__(seq)
        self.seq = seq


def _busy(text: str) -> bool:
    """A line of ``--json`` that is the refusal of a busy box (contract 2,
    ``cli-refusal.v1.json``)."""
    try:
        found = json.loads(text)
    except ValueError:
        return False
    return isinstance(found, dict) and found.get("refused") == "box-busy"


class AgentRunning(Exception):
    """Another agent holds the box's agent lock."""


@contextmanager
def agent_lock(root: Path) -> Iterator[None]:
    """The agent's lock of the box for the life of the process."""
    directory = agent_dir(root)
    private_dir(directory)
    path = directory / AGENT_LOCK
    fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise AgentRunning(", ".join(holders(path))) from None
        yield
    finally:
        os.close(fd)


def pauser(stopping: Callable[[], bool]) -> Callable[[float], bool]:
    """A pause cut short when the agent stops; ``False`` then."""

    def pause(seconds: float) -> bool:
        end = time.monotonic() + seconds
        while not stopping():
            left = end - time.monotonic()
            if left <= 0:
                return True
            time.sleep(min(left, 0.5))
        return False

    return pause


def run_agent(
    root: Path,
    out: TextIO,
    stopping: Callable[[], bool],
    *,
    fs_root: Path = Path("/"),
    runner: Runner | None = None,
    requests: Requests | None = None,
    now: Callable[[], datetime] = lambda: datetime.now(UTC),
    owner: int | None = None,
) -> int:
    """``pridem agent``: the agent of the box until ``stopping``."""
    uid = os.geteuid() if owner is None else owner
    try:
        registration = read_registration(root)
    except RegistrationDamaged:
        raise Refusal("agent: the box's registration cannot be read") from None
    if registration is None:
        raise Refusal("agent: the box is not registered -- pridem register first")
    try:
        seed = load_seed(root, uid)
    except (FileNotFoundError, KeyDamaged):
        raise Refusal("agent: the box's key cannot be read") from None
    try:
        client = PanelClient(registration, seed, requests or HttpTransport(), now)
    except BaseMismatch as mismatch:
        raise Refusal(f"agent: {mismatch}") from None
    machine = runner if runner is not None else SubprocessRunner()

    def say(text: str) -> None:
        out.write(f"agent: {text}\n")
        out.flush()

    def measured() -> BoxSnapshot:
        quiet = io.StringIO()
        return snapshot(Context(root, quiet, quiet, runner=machine, fs_root=fs_root))

    try:
        with agent_lock(root):
            say(f"box {registration.box_id}: the Panel {client.base}")
            Agent(
                root=root,
                client=client,
                runner=machine,
                now=now,
                pause=pauser(stopping),
                say=say,
                state=measured,
                owner=uid,
                heartbeat_s=registration.heartbeat_s,
                full_state_s=registration.full_state_s,
            ).serve(stopping)
    except AgentRunning as running:
        held = f" ({running})" if str(running) else ""
        raise Refusal(f"agent: another agent runs{held}") from None
    return 0
