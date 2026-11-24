"""The envelope of a verdict (``PRIMER-PANEL-TZ-2`` 8, 9; DM-140): what the
agent sends the Panel for a run of ``history/``.

``envelope`` reads ``history/<run_id>.json`` as it is, signs it with the box's
key over ``verdict_bytes`` of contract 4 (``pridem.identity.sign_verdict``),
puts in the report for a model -- what ``pridem report <run_id> --llm``
prints -- and says whether the verdict was written before the box was
registered (``signed_on_send``). It writes nothing and takes no lock: the
verdict and ``history/`` stay as they are (the verdict's schema is closed, the
signature is outside it -- R-12), the journal is read as ``report`` reads it.
Sending is the agent's (DM-141).

The verdict inside the envelope is the file's: the file is read by
``json.loads`` for the signature and by contract 2's model for the envelope,
and the two must dump to the same bytes. A verdict this machine's model does
not give back as the file holds it -- written by another version of the
machine in a form the model reads but writes otherwise -- gets no envelope
(``verdict-reshaped``): the Panel never gets a verdict that differs from
``history/``.

A refusal is ``EnvelopeRefused`` with its code, checked in this order: the
registration (``not-registered``, ``registration-damaged``), the key
(``no-key``, ``key-damaged {cause}``), the verdict (``no-verdict``,
``verdict-damaged``, ``verdict-reshaped``). The agent decides what a refusal
means; nothing here retries.

``signed_on_send`` is ``finished < registered_at``: every envelope is signed
when it is built, so the flag says what ``PRIMER-PANEL-TZ-2`` 9 asks -- the
verdict was written before the box had its key and its registration.

KNOWN CEILING: a verdict of the second the box registered in.
1. Mechanics: ``finished`` and ``registered_at`` are moments to the second.
   A run that ended in the second of the registration, before ``register``
   took the lock, has ``finished == registered_at`` and gets
   ``signed_on_send: false`` though it was written before the key.
2. Status: acknowledged by design.
3. Task: none -- the flag is a mark for the Panel's screen; the signature
   holds either way.
4. Trigger: ``registered_at`` written with fractions of a second.
5. Agreed fix: compare the run's end with ``registered_at`` in the finer
   unit.
6. Rejected: ``<=`` (marks the verdict of ``register`` itself, written after
   the key, as signed on send); the files' ``mtime`` (a copy or a restore of
   the box changes it).
"""

import json
from collections.abc import Mapping
from datetime import datetime
from pathlib import Path

from pydantic import ValidationError

from pridem.events import Json, LogLine, Secrets
from pridem.identity import (
    KeyDamaged,
    RegistrationDamaged,
    load_seed,
    read_registration,
    sign_verdict,
)
from pridem.protocol import VerdictEnvelope, verdict_bytes
from pridem.report.render import render_llm
from pridem.report.schema import RUN_ID, Verdict
from pridem.state import Box, JournalDamaged
from pridem.verbs.report import machine_catalog

CODES = frozenset(
    {
        "not-registered",
        "registration-damaged",
        "no-key",
        "key-damaged",
        "no-verdict",
        "verdict-damaged",
        "verdict-reshaped",
    }
)
"""The refusals of ``envelope``, by the order they are checked in."""


class EnvelopeRefused(Exception):
    """No envelope for the run: ``code`` of ``CODES``, ``params`` its facts."""

    def __init__(self, code: str, params: Mapping[str, Json] | None = None) -> None:
        super().__init__(code)
        self.code = code
        self.params: dict[str, Json] = dict(params or {})


def _verdict_text(root: Path, run_id: str) -> str:
    """The text of ``history/<run_id>.json``; a run id not of its form names
    no verdict."""
    if RUN_ID.fullmatch(run_id) is None:
        raise EnvelopeRefused("no-verdict")
    path = Box(root).history / f"{run_id}.json"
    if path.is_symlink() or not path.is_file():
        raise EnvelopeRefused("no-verdict")
    try:
        return path.read_bytes().decode("utf-8")
    except UnicodeDecodeError:
        raise EnvelopeRefused("verdict-damaged") from None


def _report_llm(root: Path, verdict: Verdict) -> str:
    """What ``pridem report <run_id> --llm`` prints, without its last newline;
    a journal evicted, or with a damaged header, is a report with none."""
    try:
        journal = Box(root).read_journal(verdict.run_id)
    except JournalDamaged:
        journal = None
    lines = (
        None
        if journal is None
        else [event for event in journal.events if isinstance(event, LogLine)]
    )
    return render_llm(verdict, lines, Secrets(()), machine_catalog())


def envelope(root: Path, run_id: str, *, owner: int) -> VerdictEnvelope:
    """The signed envelope of the verdict ``run_id`` of the box at ``root``
    (``/opt/pridem``); ``owner`` -- the uid the key must have."""
    try:
        registration = read_registration(root)
    except RegistrationDamaged:
        raise EnvelopeRefused("registration-damaged") from None
    if registration is None:
        raise EnvelopeRefused("not-registered")
    try:
        seed = load_seed(root, owner)
    except FileNotFoundError:
        raise EnvelopeRefused("no-key") from None
    except KeyDamaged as damaged:
        raise EnvelopeRefused("key-damaged", {"cause": damaged.cause}) from None
    text = _verdict_text(root, run_id)
    try:
        verdict = Verdict.model_validate_json(text)
    except ValidationError:
        raise EnvelopeRefused("verdict-damaged") from None
    found: dict[str, Json] = json.loads(text)  # the model read it: an object
    if verdict_bytes(verdict.model_dump(mode="json")) != verdict_bytes(found):
        raise EnvelopeRefused("verdict-reshaped")
    registered_at = datetime.fromisoformat(registration.registered_at)
    return VerdictEnvelope(
        verdict=verdict,
        signature=sign_verdict(seed, found),
        report_llm=_report_llm(root, verdict),
        signed_on_send=verdict.finished < registered_at,
    )
