"""Contract 4: the protocol of the agent -- every message between a box and
the Panel (``PRIMER-PANEL-TZ-2``), one schema for both sides (DM-135).

The box holds outgoing connections alone: the agent asks, the Panel answers.
Every path is under ``/agent/v1/`` on the Panel's API:

=====================================  ====================  ==================
request                                body                  answer
=====================================  ====================  ==================
``POST register``                      ``RegisterRequest``   ``RegisterResponse``
``POST heartbeat``                     ``Heartbeat``         empty
``GET commands/next`` (long-poll)      --                    ``Command`` / 204
``POST commands/<id>/refusal``         ``CommandRefusal``    empty
``POST runs/<run_id>/events``          ``EventBatch``        ``EventsAccepted``
``POST runs/<run_id>/verdict``         ``VerdictEnvelope``   empty
``POST history``                       ``HistoryBatch``      ``HistoryAccepted``
=====================================  ====================  ==================

Any request the Panel refuses is answered ``Refusal {code}`` -- a closed list,
no text; the words are the Panel's. Every message is idempotent: a repeat after
a broken connection changes nothing.

**Versions.** Every request carries the protocol's version in one place, the
header ``X-Primer-Protocol`` -- never in a body. The Panel takes the version
``PROTOCOL_VERSION`` and the one before it (``accepts``), and answers in the
version of the request: a field new in an answer comes with a new version of
the protocol, never into an old one. So both sides read strictly -- a field
the reader does not know is a refusal -- and a box one version behind lives
with a newer Panel. Version 1 is the first: there is no version 0 to read.
Version 1 takes its final form before the first box runs the agent (DM-141):
until then its messages grow and tighten inside it (DM-189), and the Panel
follows by the rule of the machine's release -- it is pinned to a release of
the machine and moves up after it. From the first box with an agent on, a new
field in an answer of the Panel comes with a new version, never into version 1.

**Strictness.** A message never carries an explicit ``null``: a field with
nothing to say is absent -- contract 4's own optional fields are left out of
every dump (``exclude_if``), so no side dumps with ``exclude_none``, which
would also take away the ``null`` contract 2 keeps on purpose (``errno``,
``ended_at``) and part the verdict from its signature. The registration's
token is a ``SecretStr``: no ``repr`` and no text of an error shows it, and
only its JSON form -- the wire -- carries its value. A model that reads an
alias writes it too (``serialize_by_alias``).

**Signature.** Every request is signed with the box's key (ed25519, DM-139):
the headers ``X-Primer-Box`` (``box_id``), ``X-Primer-Time`` (UTC, seconds)
and ``X-Primer-Signature`` sign ``signing_string`` -- method, path, time and
the SHA-256 of the body. The header of the version is not signed: changing it
gets a refusal (``protocol-too-old``, ``protocol-too-new``) or a body read in
another version and refused by its form, never another box's action. The
window of time (±300 s, ``clock-skew``) is the Panel's to check, not the
form's.

**A verdict's signature.** ``VerdictEnvelope.signature`` signs
``verdict_bytes`` (DM-140): the verdict as a JSON object -- the box reads
``history/<run_id>.json`` by ``json.loads``, the Panel dumps the envelope's
verdict by ``model_dump(mode="json")`` -- keys sorted, no spaces, UTF-8. No
model stands between the file and the bytes: they do not depend on the
reader's version of contract 2, and for a verdict the box sends the two forms
are the same bytes (the box builds no envelope where they differ).

The models are the contract: ``python -m pridem.protocol --export`` writes
``contract/schema/agent-protocol.v1.json``, every message in its ``$defs``.
The verdict of a run is contract 2's model, the full state of a box is
``box-state.v1``, an event of a run is a line of its journal (DM-137): this
contract names them, never copies them.
"""

import argparse
import hashlib
import json
import sys
from collections.abc import Mapping, Sequence
from typing import Annotated, Literal

from pydantic import (
    ConfigDict,
    Field,
    SecretStr,
    ValidationError,
    field_serializer,
    model_validator,
)
from pydantic.json_schema import models_json_schema

from pridem.contract import SCHEMA_DIR, ContractSchema, Strict, schema_text
from pridem.events import Json
from pridem.report.box_snapshot import BoxSnapshot, Moment
from pridem.report.schema import CommandId, RunId, Text, Verdict
from pridem.state import JournalLine

PROTOCOL_VERSION = 1
"""The version of the protocol this machine speaks."""

AGENT_PROTOCOL_SCHEMA = "agent-protocol.v1.json"

PROTOCOL_HEADER = "X-Primer-Protocol"
BOX_HEADER = "X-Primer-Box"
TIME_HEADER = "X-Primer-Time"
SIGNATURE_HEADER = "X-Primer-Signature"

Seq = Annotated[int, Field(ge=1)]


def _absent(value: object) -> bool:
    """A field with nothing to say is left out of the dump (see the module)."""
    return value is None


HEARTBEAT_S = (5, 60)
"""The light heartbeat, in seconds: 30 by ``PRIMER-PANEL-TZ-2`` 5; "not
answering" is three of them."""
POLL_S = (5, 85)
"""The long-poll, in seconds: 60 by ``PRIMER-PANEL-TZ-2`` 6, under the 90 s
the route of ``commands/next`` waits (2, DM-147) -- a longer one is cut."""
FULL_STATE_S = (60, 3600)
"""The full state, in seconds: 5 minutes by ``PRIMER-PANEL-TZ-2`` 5. Its
least is the light heartbeat's most: the full state is never more often."""
AGENT_URL = r"^https://(?:[a-z0-9-]+\.)*[a-z0-9-]+/agent/v1/$"
"""Where the agent goes: ``https`` to a host -- a DNS name or IPv4, lower case
-- with no user, no port, no query, at ``/agent/v1/``. The host is the one
the box registered with: ``register`` holds the two the same."""
AgentUrl = Annotated[str, Field(pattern=AGENT_URL)]
Base64 = Annotated[str, Field(min_length=1, pattern=r"^[A-Za-z0-9+/]+={0,2}$")]

RefusalCode = Literal[
    "token-unknown",
    "token-used",
    "token-expired",
    "name-taken",
    "product-mismatch",
    "protocol-too-old",
    "protocol-too-new",
    "clock-skew",
    "signature-bad",
    "box-unknown",
    "run-foreign",
]
"""Why the Panel refuses a request: registration (``PRIMER-PANEL-TZ-2`` 4),
the time of the signature (3), the version (11), a signature that does not
hold, a box the Panel does not know, a run of another box (7, 8)."""

CommandRefusalCode = Literal[
    "verb-unknown", "args-refused", "confirmation-missing", "expired"
]
"""Why the agent refuses a command before any run (``PRIMER-PANEL-TZ-2`` 6):
a verb the machine does not have, arguments the verb's schema refuses, a
destructive command without ``confirmed_at``, a command past its
``expires_at``."""


class Refusal(Strict):
    """The Panel's answer to a request it refuses."""

    code: RefusalCode


# --- registration ----------------------------------------------------------------


class RegisterRequest(Strict):
    """``POST register``: the one-time token and what the Panel checks it with
    -- the server's name, free in the whole Panel; the product's repository,
    the project's; the public half of the box's key. The token is a secret:
    hidden in ``repr`` and in the text of any error, given by its JSON form
    alone."""

    model_config = ConfigDict(hide_input_in_errors=True)

    token: Annotated[SecretStr, Field(min_length=16)]
    server_name: Text
    role: Literal["test", "prod", "preview"]
    product_repo: Text
    machine_version: Text
    box_key_public: Text

    @field_serializer("token", when_used="json")
    def _token_on_the_wire(self, token: SecretStr) -> str:
        return token.get_secret_value()


class RegisterResponse(Strict):
    """The box's ``box_id``, where the agent goes from now on, and its
    intervals: a light heartbeat, the full state, the long-poll."""

    box_id: Text
    agent_url: AgentUrl
    heartbeat_s: Annotated[int, Field(ge=HEARTBEAT_S[0], le=HEARTBEAT_S[1])]
    full_state_s: Annotated[int, Field(ge=FULL_STATE_S[0], le=FULL_STATE_S[1])]
    poll_s: Annotated[int, Field(ge=POLL_S[0], le=POLL_S[1])]


# --- heartbeat --------------------------------------------------------------------


class Heartbeat(Strict):
    """``POST heartbeat``: light -- what the box says of itself every few
    seconds; full -- with ``state``, the whole form ``box-state.v1`` (DM-136).
    The answer is empty: what the Panel wants of the box is in its queue."""

    measured_at: Moment
    machine_version: Text
    lock_open_by: list[str]
    journals_without_verdict: list[str]
    last_run_id: RunId | None = Field(default=None, exclude_if=_absent)
    state: BoxSnapshot | None = Field(default=None, exclude_if=_absent)


# --- the queue --------------------------------------------------------------------


class Command(Strict):
    """``GET commands/next``: a verb of the machine and its arguments, as the
    console would run it; ``expires_at`` -- after it the command is not taken
    (``PRIMER-PANEL-TZ-2`` 6: the Panel expires it); ``confirmed_at`` -- when a
    person confirmed a destructive one, before ``expires_at``. The agent checks
    it against the verb's own schema. The confirmation is bound to the server
    by the verb itself: a destructive verb of the machine names the server in
    its ``--confirm``."""

    id: CommandId
    verb: Text
    args: dict[str, Json]
    expires_at: Moment
    confirmed_at: Moment | None = Field(default=None, exclude_if=_absent)

    @model_validator(mode="after")
    def _confirmed_in_time(self) -> "Command":
        if self.confirmed_at is not None and self.confirmed_at > self.expires_at:
            raise ValueError("confirmed_at is after expires_at")
        return self


class CommandRefusal(Strict):
    """``POST commands/<id>/refusal``: the agent refused the command before
    any run -- so there is no journal and no verdict to say it."""

    code: CommandRefusalCode


# --- a run ------------------------------------------------------------------------


class EventBatch(Strict):
    """``POST runs/<run_id>/events``: lines of the run's journal, from
    ``from_seq`` on, in their order. The Panel keeps them by ``(run_id,
    seq)``: a repeated line changes nothing."""

    from_seq: Seq
    events: list[JournalLine]

    @model_validator(mode="after")
    def _from_the_first(self) -> "EventBatch":
        if self.events and self.events[0].seq != self.from_seq:
            raise ValueError("from_seq is not the seq of the first event")
        for before, after in zip(self.events, self.events[1:], strict=False):
            if after.seq <= before.seq:
                raise ValueError("seq does not rise in the batch")
        return self


class EventsAccepted(Strict):
    """The last ``seq`` of the run the Panel holds with no gap before it: the
    agent goes on from the next."""

    last_seq: Annotated[int, Field(ge=0)]


class VerdictEnvelope(Strict):
    """``POST runs/<run_id>/verdict``: the verdict of ``history/`` as it is
    (contract 2), its signature with the box's key (DM-140) and the report for
    a model (``report --llm``). ``signed_on_send`` -- the verdict was written
    before the box had its key and was signed when sent."""

    verdict: Verdict
    signature: Base64
    report_llm: str
    signed_on_send: bool


class HistoryBatch(Strict):
    """``POST history``: verdicts of ``history/`` the Panel has not
    confirmed, after registration and after every return of the
    connection."""

    envelopes: list[VerdictEnvelope]


class HistoryAccepted(Strict):
    """The runs the Panel holds now: the agent's cursor moves past them."""

    run_ids: list[RunId]


# --- the signature ----------------------------------------------------------------


class SignedHeaders(Strict):
    """The headers of a signed request."""

    box: Text
    time: Annotated[int, Field(ge=0)]
    signature: Base64
    protocol: Annotated[int, Field(ge=1)]


class HeaderMissing(ValueError):
    """A header of a signed request is absent or not of its form."""


def signed_headers(headers: Mapping[str, str]) -> SignedHeaders:
    """The headers of a request read: every one there, the time and the
    version whole numbers. ``HeaderMissing`` otherwise."""
    found = {key.lower(): value for key, value in headers.items()}
    names = (BOX_HEADER, TIME_HEADER, SIGNATURE_HEADER, PROTOCOL_HEADER)
    absent = [name for name in names if name.lower() not in found]
    if absent:
        raise HeaderMissing(f"no {', '.join(absent)}")
    numbers: dict[str, int] = {}
    for name in (TIME_HEADER, PROTOCOL_HEADER):
        value = found[name.lower()]
        if not value.isascii() or not value.isdigit():
            raise HeaderMissing(f"{name} is not a whole number")
        numbers[name] = int(value)
    try:
        return SignedHeaders(
            box=found[BOX_HEADER.lower()],
            time=numbers[TIME_HEADER],
            signature=found[SIGNATURE_HEADER.lower()],
            protocol=numbers[PROTOCOL_HEADER],
        )
    except ValidationError as error:
        fields = sorted({str(item["loc"][0]) for item in error.errors() if item["loc"]})
        raise HeaderMissing(f"not of its form: {', '.join(fields)}") from None


def signing_string(method: str, path: str, time: int, body: bytes) -> str:
    """What the box signs: ``method \\n path \\n time \\n sha256(body)``,
    the method upper case, the digest in hex. The version's header is not in
    it (see the module)."""
    digest = hashlib.sha256(body).hexdigest()
    return f"{method.upper()}\n{path}\n{time}\n{digest}"


def verdict_bytes(verdict: Mapping[str, Json]) -> bytes:
    """What the signature of a verdict's envelope signs: the verdict as a JSON
    object, keys sorted at every level, ``,`` and ``:`` with no spaces,
    non-ASCII as it is, in UTF-8 (see the module)."""
    text = json.dumps(
        verdict, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    )
    return text.encode("utf-8")


# --- versions ---------------------------------------------------------------------


def accepts(version: int) -> RefusalCode | None:
    """``None`` -- the version is read: ``PROTOCOL_VERSION`` or the one before
    it; otherwise the refusal."""
    if version > PROTOCOL_VERSION:
        return "protocol-too-new"
    if version < max(PROTOCOL_VERSION - 1, 1):
        return "protocol-too-old"
    return None


# --- the schema -------------------------------------------------------------------


MESSAGES: tuple[type[Strict], ...] = (
    Refusal,
    RegisterRequest,
    RegisterResponse,
    Heartbeat,
    Command,
    CommandRefusal,
    EventBatch,
    EventsAccepted,
    VerdictEnvelope,
    HistoryBatch,
    HistoryAccepted,
)
"""Every message of the protocol: the bodies of its requests and answers."""


def rendered_schema() -> str:
    """The JSON Schema of every message, exported from the models."""
    _, schema = models_json_schema(
        [(model, "validation") for model in MESSAGES],
        schema_generator=ContractSchema,
        ref_template="#/$defs/{model}",
    )
    return schema_text(schema, "agent protocol v1")


def main(argv: Sequence[str]) -> int:
    """``--export`` writes the protocol's schema to ``contract/schema/``."""
    parser = argparse.ArgumentParser(prog="python -m pridem.protocol")
    parser.add_argument("--export", action="store_true", required=True)
    parser.parse_args(argv)
    SCHEMA_DIR.mkdir(parents=True, exist_ok=True)
    target = SCHEMA_DIR / AGENT_PROTOCOL_SCHEMA
    target.write_text(rendered_schema(), encoding="utf-8")
    print(f"wrote {target}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
