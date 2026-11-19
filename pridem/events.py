"""Everything a plan reports leaves through events; the records are their data.

A step record has the fields of a step in contract 2 (verdict) v1.3 but the
phase: ``stack``, ``name``, ``order`` (the phase number of the step, not a
running index), ``status``, ``reason`` (required for ``skipped`` and
``failed``), ``started``, ``duration_s``, ``verify`` (the facts the step read
back). The plan phase a step ran in (``main``, ``restore``, ``finally``) is a
field of every step event and log line, so a journal tells same-named steps of
different phases apart; the outcome keeps one tuple per phase. Events are
built from these records, never from a step object, so a sink sees only what
the step itself put into its fact.

Known secrets (``asked`` and ``tls`` of the passport, ``minted``) are cleaned by
exact match with ``Secrets`` -- the one function the verdict and the console use
(contract 2 rule 2).

A reason, an incomplete entry and a doctor item carry a ``Code``: a code and
its parameters, never a phrase (contract 2 v1.6). The words come from a catalog
(``report/catalog.py``) when something is rendered; the skip codes a plan
writes are built here.
"""

import contextlib
import json
import os
import re
import threading
import time
import weakref
from collections.abc import Callable, Iterable, Iterator, Mapping
from dataclasses import dataclass, field
from datetime import datetime
from typing import Literal, Protocol, TextIO, runtime_checkable

from pydantic import SecretStr

from pridem.contract import SECRET_MIN_LENGTH
from pridem.report.catalog import (
    CAUSE_LINES,
    ENGLISH,
    Catalog,
    is_a_cause,
    say,
    text,
)
from pridem.report.codes import RESERVED_PARAMS, ExitCode
from pridem.runner import Stream

type Json = None | bool | int | float | str | list[Json] | dict[str, Json]
type Fact = Mapping[str, Json]


def as_list(value: Json) -> list[Json]:
    """``value`` when it is a JSON list, else empty: a fact or a check's data
    read back by key."""
    return value if isinstance(value, list) else []


def strings(value: Json) -> list[str]:
    """Each item of ``as_list(value)`` as a string."""
    return [str(item) for item in as_list(value)]


Status = Literal["ok", "failed", "skipped"]
Phase = Literal["main", "restore", "finally"]
PlanMode = Literal[
    "install", "deploy", "doctor", "reinstall", "destroy", "gc", "renew", "command"
]
"""``command`` -- the one-step plans of the data verbs (``db``, ``backup``,
DM-86); ``gc`` and ``renew`` are those of ``gc`` and ``ssl renew``."""
RunMode = PlanMode | Literal["status", "check"]
"""What a run is: a plan's mode, or a verb that runs no plan (``status``,
``check``)."""

REDACTED = "[redacted]"


@dataclass(frozen=True)
class Code:
    """A code and its parameters: a fact, not a phrase (contract 2 v1.6).

    ``code`` and ``what`` are taken and are never parameter names.
    """

    code: str
    params: Mapping[str, Json] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.code:
            raise ValueError("a code is not empty")
        taken = sorted(RESERVED_PARAMS & set(self.params))
        if taken:
            raise ValueError(f"parameter names {taken} are taken")

    def as_json(self) -> dict[str, Json]:
        """The flat object of the verdict: ``{"code": ..., **params}``."""
        return {"code": self.code, **self.params}


def role_skip(role: str) -> Code:
    """A step skipped because the box's role does not run it."""
    return Code("role", {"role": role})


def after_failure(phase: Phase, stack: str, name: str) -> Code:
    """A step skipped because the step ``phase stack name`` failed."""
    return Code("after-failure", {"phase": phase, "stack": stack, "name": name})


AFTER_INTERRUPT = Code("after-interrupt")
INTERRUPTED = Code("interrupted")
NO_FACT = Code("no-fact")


def _forms(secret: str) -> set[str]:
    """The exact forms of ``secret`` that are cleaned (contract 2 rule 2).

    The value whole, at any length; the value as a JSON string writes it,
    without its quotes, both with ``\\uXXXX`` for every non-ASCII character
    and without (a stack's JSON log line -- its ``ctx`` too -- escapes a
    quote, a backslash or a control character, protocol 9.4); the value
    without whitespace at its edges and each of its lines (a PEM, a YAML
    block) when at least ``SECRET_MIN_LENGTH`` long. A shorter derived form is
    left alone, as the owner accepted (the short tail of a PEM body): it would
    match ordinary text.
    """
    derived = {secret.strip(), *secret.splitlines()}
    escaped = {json.dumps(secret, ensure_ascii=ascii)[1:-1] for ascii in (True, False)}
    long = {form for form in derived if len(form) >= SECRET_MIN_LENGTH}
    return {secret} | escaped | long


FREE_LIMIT = 8192
"""The most a stack's free object may take -- ``details`` of ``/health``,
``ctx`` of a log line (protocol 9.1, 9.4): bytes of its compact JSON in UTF-8
(``free_size``)."""
CUT_MARK = "pridem_cut_bytes"
"""What a cut ``ctx`` becomes: ``{CUT_MARK: <its size>}``."""


def free_size(value: Json) -> int:
    """The bytes of ``value`` as compact JSON in UTF-8."""
    text = json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    return len(text.encode("utf-8"))


def cut_ctx(line: str) -> str:
    """``line`` with its ``ctx`` cut when it is over ``FREE_LIMIT`` (protocol
    9.4): a JSON object of a stack's log keeps its other fields, and its
    ``ctx`` -- whatever it is -- becomes ``{CUT_MARK: <size>}``. Nothing of the
    cut ``ctx`` is kept: a kept head would be cut before the secrets of the
    line are cleaned (the sinks clean the whole line, ``ctx`` with it) and could
    carry a part of one. Any other line is returned as it came."""
    if not line.lstrip().startswith("{"):
        return line
    try:
        record = json.loads(line)
    except (json.JSONDecodeError, RecursionError, ValueError):
        # not a log line of a stack (an integer over 4300 digits is a
        # ValueError of the parser, DM-77): it passes as it is
        return line
    if not isinstance(record, dict) or "ctx" not in record:
        return line
    size = free_size(record["ctx"])
    if size <= FREE_LIMIT:
        return line
    record["ctx"] = {CUT_MARK: size}
    return json.dumps(record, ensure_ascii=False, separators=(",", ":"))


class ShortSecret(ValueError):
    """A value too short to be a secret was given to ``Secrets``."""


class Secrets:
    """Known secret values and the exact-match cleaning of text and facts.

    Every secret contributes its forms (``_forms``); the forms of all secrets
    are one set, replaced longest first, so a secret that contains another --
    or contains its own lines -- is replaced whole, with no pieces left.

    The set of a run grows and never shrinks: a secret that appears during the
    run (the passport's after ``fetch_passport``, an answer of ``install``, a
    ``derived`` value) is ``add``-ed to the one object every sink and the
    verdict hold, before the first line that could carry it. A value shorter
    than ``SECRET_MIN_LENGTH`` is refused here, for every path that adds one
    (``ShortSecret``): cleaned out of every text it would cut ordinary words,
    and it is too short to be a secret. The journal's cut
    of a long line is computed from this set on every piece (``safe_cut``), so
    a larger ``longest`` holds from the next piece on; the pieces written
    before could not carry a value the run did not know yet.
    """

    def __init__(self, values: Iterable[SecretStr]) -> None:
        self._values: tuple[str, ...] = ()
        self._pattern: re.Pattern[str] | None = None
        self.add(values)

    def add(self, values: Iterable[SecretStr]) -> None:
        """Know ``values`` too, from now on, wherever this object cleans."""
        plain = {value.get_secret_value() for value in values}
        if any(len(secret) < SECRET_MIN_LENGTH for secret in plain):
            raise ShortSecret(  # the value itself is never in the message
                f"a secret is shorter than {SECRET_MIN_LENGTH} characters"
            )
        forms = set(self._values).union(*(_forms(secret) for secret in plain))
        self._values = tuple(sorted(forms, key=len, reverse=True))
        self._pattern = (
            re.compile("|".join(re.escape(form) for form in self._values))
            if self._values
            else None
        )

    @property
    def longest(self) -> int:
        """Length of the longest form; 0 when no secret is known."""
        return len(self._values[0]) if self._values else 0

    def safe_cut(self, text: str) -> int:
        """Where ``text`` may be cut when more text follows it.

        Everything before the cut can be cleaned now: no form found in ``text``
        crosses the cut, and a form completed by text still to come starts in
        the last ``longest - 1`` characters, which stay after the cut.
        """
        cut = len(text) - max(self.longest - 1, 0)
        if cut <= 0:
            return 0
        if self._pattern is not None:
            for match in self._pattern.finditer(text):
                if match.start() >= cut:
                    break
                if match.end() > cut:
                    return match.start()
        return cut

    def text(self, value: str) -> str:
        """``value`` with every known secret replaced by ``[redacted]``."""
        for secret in self._values:
            value = value.replace(secret, REDACTED)
        return value

    def value(self, value: Json) -> Json:
        """``value`` with every string in it, keys included, cleaned."""
        if isinstance(value, str):
            return self.text(value)
        if isinstance(value, list):
            return [self.value(item) for item in value]
        if isinstance(value, dict):
            return self.fact(value)
        return value

    def fact(self, fact: Fact) -> dict[str, Json]:
        """A cleaned copy of ``fact``; two keys equal after cleaning are an error."""
        out: dict[str, Json] = {}
        for key, item in fact.items():
            clean = self.text(key)
            if clean in out:
                raise ValueError(f"two keys are {clean!r} after cleaning secrets")
            out[clean] = self.value(item)
        return out


@dataclass(frozen=True)
class Incomplete:
    """Something that should have been done and was not, and its code."""

    what: str
    reason: Code

    def __post_init__(self) -> None:
        if not self.what:
            raise ValueError("incomplete needs what")

    def as_json(self) -> dict[str, Json]:
        """The flat object of the verdict: ``{"what": ..., "code": ..., **params}``."""
        return {"what": self.what, **self.reason.as_json()}


@dataclass(frozen=True)
class StepRecord:
    """One step of a plan, in the fields of contract 2."""

    stack: str
    name: str
    order: int
    status: Status
    reason: Code | None = None
    started: datetime | None = None
    duration_s: float | None = None
    verify: Fact = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.status in ("skipped", "failed") and self.reason is None:
            raise ValueError(f"a {self.status} step needs a reason")
        if self.status == "ok" and not self.verify:
            raise ValueError("an ok step needs a non-empty verify fact")


@dataclass(frozen=True)
class DoctorItem:
    """What ``doctor`` found that a plan would do."""

    stack: str
    name: str
    reason: Code


@dataclass(frozen=True)
class PlanOutcome:
    """The result of a plan, from which the verdict is built."""

    mode: RunMode
    code: ExitCode
    steps: tuple[StepRecord, ...]
    restore: tuple[StepRecord, ...] = ()
    finally_: tuple[StepRecord, ...] = ()
    incomplete: tuple[Incomplete, ...] = ()
    doctor_diff: tuple[DoctorItem, ...] = ()
    needs_restore: bool = False
    interrupted: bool = False


@dataclass(frozen=True)
class StepStarted:
    phase: Phase
    stack: str
    name: str
    order: int
    started: datetime


@dataclass(frozen=True)
class StepFinished:
    phase: Phase
    record: StepRecord


@dataclass(frozen=True)
class LogLine:
    """One output line of a command a step ran.

    ``continued``: the line is longer than the runner's limit, this is one of
    its pieces, and more of the same line follows.
    """

    phase: Phase
    stack: str
    name: str
    stream: Stream
    line: str
    continued: bool = False


@dataclass(frozen=True)
class PlanFinished:
    outcome: PlanOutcome


type Event = StepStarted | StepFinished | LogLine | PlanFinished


class EventSink(Protocol):
    """Receives every event of a plan, in order."""

    def emit(self, event: Event) -> None:
        """Take one event."""
        ...


@runtime_checkable
class Attachable(Protocol):
    """A sink the plan itself connects (DM-107 FIX 2): it takes the plan's
    catalog -- the steps' titles and ``said`` -- and what the steps tell the
    console alone (``notice``). Any builder of a plan -- the CLI, a script of
    tier 3 -- gets the same console by the same path."""

    def attach(self, catalog: Callable[[], Catalog]) -> None:
        """The plan's catalog, unless the sink was given its own."""
        ...

    def notice(self, notice: "Notice") -> None:
        """What a step tells the console alone."""
        ...


def _fact_line(fact: Fact, catalog: Catalog) -> str:
    parts = []
    for key, value in fact.items():
        shown = (
            value if isinstance(value, str) else json.dumps(value, ensure_ascii=False)
        )
        parts.append(say(catalog, "@fact", key=key, value=shown))
    return say(catalog, "@fact.sep").join(parts)


COLORS = {
    "red": "\x1b[31m",
    "green": "\x1b[32m",
    "yellow": "\x1b[33m",
    "blue": "\x1b[34m",
    "dim": "\x1b[2m",
}


EMPTY = frozenset({"none", "absent", "not needed"})
"""A fact's word for nothing."""


def _empty(value: object) -> bool:
    """A fact's value that says nothing was there to do (DM-112)."""
    if isinstance(value, str):
        return value in EMPTY
    return value == [] or value == {}


def _short(found: re.Match[str]) -> str:
    return found.group(0)[:7]


def muted(stream: TextIO) -> None:
    """The terminal of ``stream`` is gone -- an ssh session dropped, a write
    is ``EIO`` or ``EPIPE`` (measured on a live pty, DM-92): its descriptor
    goes to ``/dev/null``, so no later write and no flush at the interpreter's
    exit raises; the journal and the verdict are written as ever."""
    try:
        fd = stream.fileno()
    except (OSError, ValueError):  # a stream with no descriptor of its own
        return
    null = os.open(os.devnull, os.O_WRONLY)
    try:
        os.dup2(null, fd)
    finally:
        os.close(null)


def said(stream: TextIO, text: str) -> None:
    """``text`` to the console; a console that is gone is muted, never an
    error of the run."""
    try:
        stream.write(text)
        stream.flush()
    except OSError:
        muted(stream)


HASH = re.compile(r"\b[0-9a-f]{40}\b")
"""A full commit in a fact: the console says its first seven characters."""

INTERNAL_STACKS = frozenset(
    {
        "sources",
        "dependencies",
        "seams",
        "edge",
        "frontend",
        "finalize",
        "types",
        "box",
        "stopped",
        "host",
        "passport",
        "network",
        "timers",
        "destroy",
        "rollback",
        "verdict",
    }
)
"""Stacks of the machine itself: their steps are said by their title alone."""

SPINNER = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"


@dataclass(frozen=True)
class KeyNeeded:
    """A step needs a person to add a key (DM-107): the console shows the key,
    the repository it goes to and its page, with which rights, and that it
    waits."""

    repo: str
    """The repository's address."""
    key: str
    """The public key, whole."""
    page: str | None
    """The repository's page of deploy keys; ``None`` -- not a GitHub address."""
    write: bool
    """The key must be allowed to write."""
    why: str | None
    """Why it must write."""
    wait_s: float
    """How long the step waits for the key to work."""
    again: bool = False
    """The key was taken and the next request refused it: GitHub has not
    spread it yet -- the block again, the box waits again (DM-111)."""


@dataclass(frozen=True)
class RecipientNeeded:
    """The box's age key must become a recipient of its passport in the ops
    repository (contract 1 section 3: the passport is encrypted by sops with
    age for the owner's key and each box's; the box prints its public part --
    the same ceremony as a deploy key). DM-107 FIX."""

    key: str
    """The box's public age key, whole."""
    path: str | None
    """The passport's file in the ops repository; ``None`` -- not known yet."""
    wait_s: float
    """How long the step waits for it; 0 -- it does not wait."""


Notice = KeyNeeded | RecipientNeeded
"""What a step tells the console alone -- never the journal (DM-107)."""


def _spent(catalog: Catalog, seconds: float) -> str:
    """How long, in the catalog's words: ``@seconds`` under a minute, then
    ``@duration.m`` / ``@duration.h`` -- every unit is the catalog's (DM-42)."""
    whole = int(seconds)
    if whole < 60:
        return say(catalog, "@seconds", s=whole)
    hours, rest = divmod(whole, 3600)
    minutes, secs = divmod(rest, 60)
    if hours:
        return say(catalog, "@duration.h", h=hours, m=f"{minutes:02d}", s=f"{secs:02d}")
    return say(catalog, "@duration.m", m=minutes, s=f"{secs:02d}")


CONSOLES: "weakref.WeakSet[ConsoleSink]" = weakref.WeakSet()
"""The consoles of this process: a question pauses their live lines."""


@contextlib.contextmanager
def paused() -> Iterator[None]:
    """Every console's live line stopped while the person answers (DM-118)."""
    live = list(CONSOLES)
    for console in live:
        console.pause()
    try:
        yield
    finally:
        for console in live:
            console.resume()


class ConsoleSink:
    """The run as a person reads it (DM-107; the form of velo's old install).

    One line per finished step -- the time, a mark, the step's title (the
    stack's name only for a product's or a service's stack), how long, its
    fact in one sentence when the step has one (``said``), the reason of a
    failure in the catalog's words; never the step's internal name, a fact
    in JSON or a whole commit -- those are the journal's. While a step runs,
    a terminal shows it live (a spinner and its time), redrawn by a ticker
    that ends with the step, on ``close`` and when the terminal is gone;
    elsewhere one line says it began. ``notice`` shows what a person must do
    (a key to add) and that the run waits. Colors only on a terminal, never
    under ``NO_COLOR`` or ``TERM=dumb``. Every word comes from ``catalog``;
    lines are cleaned of known secrets.
    """

    def __init__(
        self,
        stream: TextIO,
        secrets: Secrets,
        catalog: Catalog | Callable[[], Catalog] | None = None,
        *,
        tty: bool | None = None,
        environ: Mapping[str, str] | None = None,
        clock: Callable[[], float] = time.monotonic,
        now: Callable[[], datetime] = datetime.now,
        tick_s: float = 1.0,
    ) -> None:
        """``catalog`` may be given as a function: the texts of a plan whose
        deferred stacks add their steps' codes while it runs; not given, the
        plan attaches its own (``attach``), and before that the words are
        ``ENGLISH``."""
        self._stream = stream
        self._secrets = secrets
        self._catalog = catalog
        env = os.environ if environ is None else environ
        if tty is None:
            isatty = getattr(stream, "isatty", None)
            tty = bool(isatty()) if callable(isatty) else False
        self.tty = tty
        self.color = tty and "NO_COLOR" not in env and env.get("TERM") != "dumb"
        self._clock = clock
        self._now = now
        self._tick_s = tick_s
        self._lock = threading.Lock()
        self._live: tuple[str, float] | None = None
        self._waiting: tuple[str, str, float] | None = None
        self._stop = threading.Event()
        self._ticker: threading.Thread | None = None
        self.dead = False
        self._causes: dict[Stream, list[str]] = {}
        CONSOLES.add(self)

    # --- what the plan hands it --------------------------------------------

    def emit(self, event: Event) -> None:
        if isinstance(event, StepStarted):
            self._causes.clear()
            self._started(event)
        elif isinstance(event, LogLine):
            self._heard(event)
        elif isinstance(event, StepFinished):
            self._finished(event.record)

    def _heard(self, line: LogLine) -> None:
        """The last lines of the running step's commands that can say why one
        failed -- ``CAUSE_LINES`` of them (DM-111, DM-124: comms says why a line
        above its last): stderr's, else stdout's; never git's set phrases
        (``catalog.NOT_A_CAUSE``)."""
        said = line.line.strip()
        if not said or not is_a_cause(said):
            return
        kept = self._causes.setdefault(line.stream, [])
        kept.append(said)
        del kept[:-CAUSE_LINES]  # the last few, never the whole output

    def notice(self, notice: Notice) -> None:
        """A key to add: the block, then the live line waits for it."""
        if isinstance(notice, RecipientNeeded):
            self._recipient(notice)
            return
        catalog = self._words()
        self._clear()
        rule = "═" * 60
        lines = [
            "",
            rule,
            say(catalog, "@key.title", repo=notice.repo),
            rule,
            notice.key,
            "",
        ]
        if notice.again:  # taken, then refused: GitHub spreads it (DM-111)
            lines.insert(4, say(catalog, "@key.again", repo=notice.repo))
        if notice.page is not None:
            lines.append(say(catalog, "@key.go", page=notice.page))
        lines.append(say(catalog, "@key.add"))
        if notice.write:
            lines.append(
                self._paint("red", say(catalog, "@key.write", why=notice.why or ""))
            )
        else:
            lines.append(self._paint("green", say(catalog, "@key.read")))
        lines += [say(catalog, "@key.already"), ""]
        self._write("\n".join(lines) + "\n")
        with self._lock:
            self._waiting = ("@key.waiting", notice.repo, notice.wait_s)
        if not self.tty:
            wait = _spent(catalog, notice.wait_s)
            self._line(say(catalog, "@key.waits", repo=notice.repo, wait=wait))

    def _recipient(self, notice: RecipientNeeded) -> None:
        """The box's age key to add to its passport's recipients: the block,
        then -- when the step waits for it -- the live line."""
        catalog = self._words()
        self._clear()
        rule = "═" * 60
        where = notice.path or say(catalog, "@recipient.any")
        lines = ["", rule, say(catalog, "@recipient.title"), rule, notice.key, ""]
        lines.append(say(catalog, "@recipient.add", path=where))
        lines += [say(catalog, "@recipient.then"), ""]
        self._write("\n".join(lines) + "\n")
        if notice.wait_s <= 0:
            return
        with self._lock:
            self._waiting = ("@recipient.waiting", where, notice.wait_s)
        if not self.tty:
            wait = _spent(catalog, notice.wait_s)
            self._line(say(catalog, "@recipient.waits", path=where, wait=wait))

    def close(self) -> None:
        """No ticker outlives the plan."""
        self._halt()

    def header(self, verb: str, version: str, server: str | None) -> None:
        """The run's head between rules, as velo's old install had it."""
        catalog = self._words()
        rule = "═" * 60
        where = say(catalog, "@header.on", server=server) if server else ""
        head = say(catalog, "@header", version=version, verb=verb, where=where)
        self._write(f"{rule}\n{self._paint('blue', head)}\n{rule}\n")

    # --- the step's lines ----------------------------------------------------

    def attach(self, catalog: Callable[[], Catalog]) -> None:
        """The plan's catalog -- only when none was given (DM-107 FIX 2)."""
        if self._catalog is None:
            self._catalog = catalog

    def _words(self) -> Catalog:
        if self._catalog is None:
            return ENGLISH
        return self._catalog() if callable(self._catalog) else self._catalog

    def _label(self, stack: str, name: str) -> str:
        catalog = self._words()
        title = catalog.get(f"@title.{name}") or name
        if stack in INTERNAL_STACKS or stack.startswith("pridem-"):
            return title
        return say(catalog, "@console.of", stack=stack, title=title)

    def _started(self, event: StepStarted) -> None:
        self._halt()
        label = self._label(event.stack, event.name)
        with self._lock:
            self._live = (label, self._clock())
            self._waiting = None
        if not self.tty:
            self._line(say(self._words(), "@console.begins", label=label))
            return
        self._stop = threading.Event()
        self._ticker = threading.Thread(target=self._tick, daemon=True)
        self._ticker.start()

    def _tick(self) -> None:
        turn = 0
        while not self._stop.is_set() and not self.dead:
            with self._lock:
                live, waiting = self._live, self._waiting
            if live is None:
                return
            label, began = live
            spent = _spent(self._words(), self._clock() - began)
            if waiting is not None:
                key, subject, wait_s = waiting
                text_ = say(
                    self._words(),
                    key,
                    subject=subject,
                    spent=spent,
                    wait=_spent(self._words(), wait_s),
                )
            else:
                text_ = say(self._words(), "@console.live", label=label, spent=spent)
            self._write(f"\r\x1b[2K{SPINNER[turn % len(SPINNER)]} {text_}")
            turn += 1
            self._stop.wait(self._tick_s)

    def pause(self) -> None:
        """The live line stopped and wiped -- a question takes the terminal
        (DM-118); ``resume`` brings it back."""
        if not self.tty or self._ticker is None:
            return
        self._halt()
        with self._lock:
            self._write("\r\x1b[2K")

    def resume(self) -> None:
        if not self.tty or self._ticker is not None or self._live is None:
            return
        self._stop = threading.Event()
        self._ticker = threading.Thread(target=self._tick, daemon=True)
        self._ticker.start()

    def _halt(self) -> None:
        self._stop.set()
        ticker = self._ticker
        if ticker is not None and ticker is not threading.current_thread():
            ticker.join(timeout=5)
        self._ticker = None

    def _clear(self) -> None:
        self._halt()
        if self.tty:
            self._write("\r\x1b[2K")

    def _finished(self, record: StepRecord) -> None:
        self._clear()
        with self._lock:
            self._live = None
            self._waiting = None
        catalog = self._words()
        label = self._label(record.stack, record.name)
        idle = catalog.get(f"@idle.{record.name}")
        if (
            record.status == "ok"
            and idle
            and record.verify
            and _empty(record.verify.get(idle))
        ):
            # nothing to do, by the step's fact -- never by its check (DM-112)
            mark = self._paint("dim", say(catalog, "@mark.skipped"))
            self._line(
                say(catalog, "@console.step", mark=mark, label=label)
                + say(catalog, "@console.idle")
            )
            return
        mark = say(catalog, f"@mark.{record.status}")
        color = {"ok": "green", "failed": "red", "skipped": "dim"}.get(record.status)
        line = say(catalog, "@console.step", mark=self._paint(color, mark), label=label)
        if record.duration_s is not None and record.status != "skipped":
            seconds = _spent(catalog, record.duration_s)
            line += say(catalog, "@console.duration", seconds=seconds)
        said_ = catalog.get(f"@said.{record.name}")
        if said_ and record.verify and record.status == "ok":
            try:
                fact = said_.format_map(self._secrets.fact(record.verify))
            except (KeyError, IndexError, TypeError, ValueError):
                fact = ""
            if fact:
                line += say(catalog, "@console.fact", fact=HASH.sub(_short, fact))
        if record.reason is not None and record.status == "failed":
            words = text(catalog, record.reason.code, record.reason.params)
            reason = self._secrets.text(HASH.sub(_short, words))
            line += say(catalog, "@console.reason", reason=reason)
        causes: list[str] = []
        failed = record.reason is not None and record.status == "failed"
        if (
            failed
            and record.reason is not None
            and (record.reason.code == "command-failed")
        ):
            causes = self._causes.get(Stream.STDERR) or self._causes.get(
                Stream.STDOUT, []
            )
        self._causes.clear()
        self._line(line)
        for cause in causes:  # what the command said, cleaned (DM-111, DM-124)
            words = say(catalog, "@console.cause", cause=self._secrets.text(cause))
            self._write(words + "\n")

    def _line(self, line: str) -> None:
        stamp = self._paint("dim", f"[{self._now():%H:%M:%S}]")
        self._write(f"{stamp} {line}\n")

    def _paint(self, color: str | None, words: str) -> str:
        if not self.color or color is None:
            return words
        return f"{COLORS[color]}{words}\x1b[0m"

    def _write(self, text_: str) -> None:
        if self.dead:
            return
        try:
            self._stream.write(text_)
            self._stream.flush()
        except OSError:  # the terminal is gone (DM-92): silent from now on
            self.dead = True
            muted(self._stream)
