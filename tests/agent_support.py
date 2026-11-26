"""The Panel's side of the agent and the machine in process, for the tests of
``pridem agent`` (DM-141).

``AgentPanel`` answers the agent's requests as ``primer-panel`` holds them
(``app/agent/router.py``, ``runs.py``, ``queue.py``, ``signature.py``), read
and kept by sense, and as the gate of DM-196 settles where the Panel at
``e08697c`` differs: every command is given with ``expires_at`` -- taken plus
ten minutes; a command or a run of another box is ``run-foreign`` (403).
Every request is checked as the Panel checks it: the headers of contract 4,
the box known, the time in ±300 s, the signature by the box's public half
over ``signing_string`` (``cryptography``). Giving a command is taking it.
Lines are kept by ``(run_id, seq)``, a repeat changes nothing, the answer is
the last ``seq`` held with no gap. A verdict is kept once by its ``run_id``,
``verified`` over its JSON object as the envelope carries it -- the Panel at
``29b3e35`` (DM-196); ``history`` keeps each envelope of a batch the same way
and answers the runs it holds (``drop`` -- runs it leaves out of the answer);
a batch with a run of ``unreadable`` is 422 whole, as a body the Panel cannot
read.

The Panel is strict: a request to a path it has not is a failure of the
test (``unplanned``), and what a test scripts -- answers it gives instead of
its own (``outages``), commands it queues -- must be used by the end
(``assert_consumed``).

``PridemInProcess`` is the runner of the agent in tier 1: the command line
``pridem ...`` the agent runs is run by ``pridem.cli.run`` in this process on
the test's box -- its journal and its verdict real, its own commands (docker)
a strict ``FakeRunner``. A real process of ``pridem`` is tier 3's: the
machine has no root but ``/opt/pridem`` for a process.
"""

import base64
import io
import json
import threading
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from urllib.parse import urlsplit

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from pydantic import ValidationError

from pridem import identity
from pridem.agent.history import Cursor, write_cursor
from pridem.cli import run
from pridem.events import Json
from pridem.protocol import (
    Command as CommandMessage,
)
from pridem.protocol import (
    CommandRefusal,
    EventBatch,
    EventsAccepted,
    HeaderMissing,
    Heartbeat,
    HistoryAccepted,
    HistoryBatch,
    Refusal,
    RefusalCode,
    VerdictEnvelope,
    accepts,
    signed_headers,
    signing_string,
    verdict_bytes,
)
from pridem.runner import (
    CommandFailed,
    FakeCall,
    FakeRunner,
    OnLine,
    Result,
    Runner,
    Stream,
)
from pridem.state import Box, HeaderLine
from pridem.steps.identity import Answer, PanelUnreachable

STATUS: dict[RefusalCode, int] = {
    "signature-bad": 401,
    "clock-skew": 401,
    "box-unknown": 403,
    "run-foreign": 403,
    "protocol-too-old": 400,
    "protocol-too-new": 400,
    "token-unknown": 404,
    "token-used": 410,
    "token-expired": 410,
    "name-taken": 409,
    "product-mismatch": 409,
}
WINDOW_S = 300
EXPIRE_AFTER = timedelta(minutes=10)
AGENT = "/agent/v1/"
STAMP = "%Y-%m-%dT%H:%M:%SZ"


def refused(code: RefusalCode) -> Answer:
    return Answer(STATUS[code], Refusal(code=code).model_dump_json().encode())


def _invalid() -> Answer:
    return Answer(422, b'{"error":"invalid","message":"The request does not match"}')


@dataclass
class Kept:
    """A verdict the Panel keeps."""

    envelope: VerdictEnvelope
    verified: bool


@dataclass
class Clock:
    """The time of the box and the Panel in a test."""

    at: datetime = datetime(2026, 11, 25, 12, 0, 0, tzinfo=UTC)

    def __call__(self) -> datetime:
        return self.at

    def move(self, seconds: float) -> None:
        self.at += timedelta(seconds=seconds)


@dataclass
class AgentPanel:
    """The Panel's side of the agent (module docstring)."""

    clock: Clock
    keys: dict[str, bytes] = field(default_factory=dict)
    """``box_id -> public half`` of the registrations."""
    queue: list[dict[str, Json]] = field(default_factory=list)
    """``{verb, args, confirmed?}`` of commands to give, oldest first."""
    outages: list[Answer | str] = field(default_factory=list)
    """Answers given instead of the Panel's own, in order: an ``Answer``, or
    the cause of ``PanelUnreachable``."""
    given: dict[str, dict[str, Json]] = field(default_factory=dict)
    """``command id -> what was given`` (taken)."""
    refusals: dict[str, str] = field(default_factory=dict)
    beats: list[Heartbeat] = field(default_factory=list)
    lines: dict[str, dict[int, Json]] = field(default_factory=dict)
    verdicts: dict[str, Kept] = field(default_factory=dict)
    owners: dict[str, str] = field(default_factory=dict)
    """``run_id or command id -> box_id``."""
    batches: list[tuple[str, int, int]] = field(default_factory=list)
    histories: list[list[str]] = field(default_factory=list)
    """The runs of every ``history`` batch, in order."""
    drop: set[str] = field(default_factory=set)
    unreadable: set[str] = field(default_factory=set)
    """``(run_id, from_seq, lines)`` of every batch of lines, in order."""
    requests: list[tuple[str, str]] = field(default_factory=list)
    unplanned: list[tuple[str, str]] = field(default_factory=list)
    _lock: threading.Lock = field(default_factory=threading.Lock)

    def enrol(self, root: Path) -> str:
        """Know the box at ``root`` by its registration: its public half."""
        registration = identity.read_registration(root)
        assert registration is not None
        seed = identity.key_path(root).read_bytes()
        raw = base64.b64decode(identity.public_key(seed))
        self.keys[registration.box_id] = raw
        return registration.box_id

    def assert_consumed(self) -> None:
        assert self.unplanned == [], self.unplanned
        assert self.outages == [], self.outages
        assert self.queue == [], self.queue

    # --- the transport ---------------------------------------------------------

    def request(
        self,
        method: str,
        url: str,
        body: bytes,
        headers: Mapping[str, str],
        timeout: float,
    ) -> Answer:
        path = urlsplit(url).path
        with self._lock:
            self.requests.append((method, path))
            if self.outages:
                outage = self.outages.pop(0)
                if isinstance(outage, str):
                    raise PanelUnreachable(outage)  # type: ignore[arg-type]
                return outage
            return self._answer(method, path, body, headers)

    def _answer(
        self, method: str, path: str, body: bytes, headers: Mapping[str, str]
    ) -> Answer:
        try:
            signed = signed_headers(headers)
        except HeaderMissing:
            return refused("signature-bad")
        too = accepts(signed.protocol)
        if too is not None:
            return refused(too)
        public = self.keys.get(signed.box)
        if public is None:
            return refused("box-unknown")
        if abs(signed.time - int(self.clock().timestamp())) > WINDOW_S:
            return refused("clock-skew")
        message = signing_string(method, path, signed.time, body).encode()
        try:
            Ed25519PublicKey.from_public_bytes(public).verify(
                base64.b64decode(signed.signature), message
            )
        except InvalidSignature:
            return refused("signature-bad")
        where = path.removeprefix(AGENT)
        parts = where.split("/")
        try:
            if (method, where) == ("POST", "heartbeat"):
                self.beats.append(Heartbeat.model_validate_json(body))
                return Answer(204, b"")
            if (method, where) == ("GET", "commands/next"):
                return self._next(signed.box)
            if (
                method == "POST"
                and len(parts) == 3
                and parts[::2]
                == [
                    "commands",
                    "refusal",
                ]
            ):
                return self._refusal(signed.box, parts[1], body)
            if method == "POST" and len(parts) == 3 and parts[0] == "runs":
                if parts[2] == "events":
                    return self._events(signed.box, parts[1], body)
                if parts[2] == "verdict":
                    return self._verdict(signed.box, parts[1], body)
            if (method, where) == ("POST", "history"):
                return self._history(signed.box, body)
        except ValidationError:
            return _invalid()
        self.unplanned.append((method, path))
        return Answer(404, b"")

    def _next(self, box: str) -> Answer:
        if not self.queue:
            return Answer(204, b"")
        queued = self.queue.pop(0)
        number = f"cmd-{len(self.given) + 1}"
        given: dict[str, Json] = {
            "id": number,
            "verb": queued["verb"],
            "args": queued.get("args", {}),
            "expires_at": (self.clock() + EXPIRE_AFTER).strftime(STAMP),
        }
        if queued.get("confirmed"):
            given["confirmed_at"] = self.clock().strftime(STAMP)
        message = CommandMessage.model_validate(given)
        self.given[number] = given
        self.owners[number] = box
        return Answer(200, message.model_dump_json().encode())

    def _refusal(self, box: str, number: str, body: bytes) -> Answer:
        refusal = CommandRefusal.model_validate_json(body)
        if self.owners.get(number) != box:
            return refused("run-foreign")
        self.refusals[number] = refusal.code
        return Answer(204, b"")

    def _owned(self, box: str, run_id: str) -> bool:
        owner = self.owners.setdefault(run_id, box)
        return owner == box

    def _events(self, box: str, run_id: str, body: bytes) -> Answer:
        batch = EventBatch.model_validate_json(body)
        self.batches.append((run_id, batch.from_seq, len(batch.events)))
        if not self._owned(box, run_id):
            return refused("run-foreign")
        held = self.lines.setdefault(run_id, {})
        for line in batch.events:
            if isinstance(line, HeaderLine) and line.run_id != run_id:
                return _invalid()
            held.setdefault(line.seq, line.model_dump(mode="json"))
        last = 0
        while last + 1 in held:
            last += 1
        return Answer(200, EventsAccepted(last_seq=last).model_dump_json().encode())

    def _verdict(self, box: str, run_id: str, body: bytes) -> Answer:
        envelope = VerdictEnvelope.model_validate_json(body)
        raw: dict[str, Json] = json.loads(body)["verdict"]
        if run_id in self.unreadable:
            return _invalid()
        return self._keep(box, run_id, envelope, raw)

    def _keep(
        self, box: str, run_id: str, envelope: VerdictEnvelope, raw: dict[str, Json]
    ) -> Answer:
        if envelope.verdict.run_id != run_id:
            return _invalid()
        if not self._owned(box, run_id):
            return refused("run-foreign")
        try:
            Ed25519PublicKey.from_public_bytes(self.keys[box]).verify(
                base64.b64decode(envelope.signature), verdict_bytes(raw)
            )
            verified = True
        except InvalidSignature:
            verified = False
        self.verdicts.setdefault(run_id, Kept(envelope, verified))
        return Answer(204, b"")

    def _history(self, box: str, body: bytes) -> Answer:
        batch = HistoryBatch.model_validate_json(body)
        raws: list[dict[str, Json]] = [
            e["verdict"] for e in json.loads(body)["envelopes"]
        ]
        runs = [envelope.verdict.run_id for envelope in batch.envelopes]
        self.histories.append(runs)
        if self.unreadable & set(runs):
            return _invalid()
        held: list[str] = []
        for envelope, raw in zip(batch.envelopes, raws, strict=True):
            run_id = envelope.verdict.run_id
            answer = self._keep(box, run_id, envelope, raw)
            if answer.status != 204:
                return answer
            if run_id not in self.drop:
                held.append(run_id)
        return Answer(200, HistoryAccepted(run_ids=held).model_dump_json().encode())


@dataclass
class PridemInProcess:
    """The command line ``pridem ...`` run by ``pridem.cli.run`` in this
    process on the box at ``fs_root`` (module docstring)."""

    fs_root: Path
    inner: Sequence[Sequence[FakeCall]] = ()
    """The commands each run gives docker, one script per run in order."""
    calls: list[tuple[str, ...]] = field(default_factory=list)
    errors: list[BaseException] = field(default_factory=list)
    """What a run raised that is no answer of a runner: a failure of the
    test, kept -- the agent runs the machine in a thread of its own."""
    before: Callable[[], None] | None = None
    machine: Runner | None = None
    """The runner of the machine's own commands instead of a script
    (``self_update_support.Releases``, DM-163)."""
    """Done before each run (a test that frees a busy box)."""

    def run(
        self,
        argv: Sequence[str],
        *,
        expect: tuple[int, ...] = (0,),
        timeout: float,
        cwd: Path | None = None,
        env: Mapping[str, str] | None = None,
        on_line: OnLine,
    ) -> Result:
        command = tuple(argv)
        assert command[0] == "pridem", command
        script = (
            self.inner[len(self.calls)] if len(self.calls) < len(self.inner) else ()
        )
        self.calls.append(command)
        if self.before is not None:
            self.before()
        out, err = io.StringIO(), io.StringIO()
        try:
            if self.machine is not None:
                code = run(
                    list(command[1:]),
                    root=self.fs_root / "opt" / "pridem",
                    out=out,
                    err=err,
                    runner=self.machine,
                    fs_root=self.fs_root,
                )
            else:
                with FakeRunner(*script) as runner:
                    code = run(
                        list(command[1:]),
                        root=self.fs_root / "opt" / "pridem",
                        out=out,
                        err=err,
                        runner=runner,
                        fs_root=self.fs_root,
                    )
        except BaseException as error:
            self.errors.append(error)
            raise
        for line in out.getvalue().splitlines():
            on_line(Stream.STDOUT, line, False)
        if code not in expect:
            raise CommandFailed(command, code, expect, ())
        return Result(command, code)

    def assert_clean(self) -> None:
        assert self.errors == [], self.errors
        assert len(self.calls) >= len(self.inner), "a script of docker never ran"


def held_so_far(root: Path) -> None:
    """The box's past is with the Panel: the cursor through its last run --
    a test of the queue alone sends none of it."""
    ids = Box(root).history_ids()
    if ids:
        write_cursor(root, Cursor.model_validate({"through": ids[-1], "held": ids}))
