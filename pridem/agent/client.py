"""The agent's way to the Panel (``PRIMER-PANEL-TZ-2`` 2, 3, 11; DM-141).

Every request is signed by the box's key (``pridem.identity.signed_headers``)
over the request's path with no query, carries the protocol's version in its
header and a body of contract 4 dumped by its model -- never ``exclude_none``
(contract 4, DM-189). An answer is read by its model too: what is not of the
contract is ``Unread`` and the agent goes on.

The base of the agent's paths (``agent_base``): the Panel the box registered
with plus ``/agent/v1/``. For a Panel over ``https`` that is ``agent_url`` of
the registration, held equal -- a port of ``--panel`` that ``agent_url``
cannot carry is a refusal to start, both values named (gate of DM-141). A
Panel over ``http`` is the loopback of tests (``panel_origin``): its base is
the Panel's own, port and all.

What the Panel answers is one of: done; ``Refused {code}`` -- its refusal of
contract 4; ``Unread {status}`` -- an answer not of the contract (a 422 to a
body it does not read, a 4xx with no refusal, a 2xx of another form);
``PanelDown {status}`` -- a 5xx; ``PanelUnreachable {cause}`` -- no answer.
"""

from collections.abc import Callable
from datetime import datetime
from typing import Literal
from urllib.parse import urlsplit

from pydantic import BaseModel, ValidationError

from pridem.identity import Registration, signed_headers
from pridem.protocol import (
    Command,
    CommandRefusal,
    CommandRefusalCode,
    EventBatch,
    EventsAccepted,
    Heartbeat,
    Refusal,
    RefusalCode,
    VerdictEnvelope,
)
from pridem.steps.identity import Answer, Requests

AGENT_PATH = "/agent/v1/"
REQUEST_TIMEOUT_S = 30.0
"""Every request but the long-poll."""
POLL_MARGIN_S = 10.0
"""The long-poll waits ``poll_s`` and this more for the Panel's answer."""


class BaseMismatch(Exception):
    """The Panel the box registered with and its ``agent_url`` part."""


def agent_base(registration: Registration) -> str:
    """Where the agent's paths begin (see the module)."""
    panel = registration.panel.rstrip("/")
    base = panel + AGENT_PATH
    if urlsplit(panel).scheme == "https" and base != registration.agent_url:
        raise BaseMismatch(
            f"the Panel {registration.panel} and its agent_url "
            f"{registration.agent_url} are not one address"
        )
    return base


class Refused(Exception):
    """The Panel's refusal of contract 4."""

    def __init__(self, code: RefusalCode, status: int) -> None:
        super().__init__(code)
        self.code: RefusalCode = code
        self.status = status


class Unread(Exception):
    """An answer of the Panel not of contract 4."""

    def __init__(self, status: int) -> None:
        super().__init__(status)
        self.status = status


class PanelDown(Exception):
    """The Panel answered 5xx."""

    def __init__(self, status: int) -> None:
        super().__init__(status)
        self.status = status


Method = Literal["GET", "POST"]


class PanelClient:
    """The signed requests of the agent."""

    def __init__(
        self,
        registration: Registration,
        seed: bytes,
        requests: Requests,
        now: Callable[[], datetime],
    ) -> None:
        self.base = agent_base(registration)
        self.box_id = registration.box_id
        self.poll_s = registration.poll_s
        self._seed = seed
        self._requests = requests
        self._now = now

    def _send(
        self, method: Method, where: str, message: BaseModel | None, timeout: float
    ) -> Answer:
        url = self.base + where
        body = b"" if message is None else message.model_dump_json().encode("utf-8")
        time = int(self._now().timestamp())
        headers: dict[str, str] = signed_headers(
            self._seed, self.box_id, method, urlsplit(url).path, body, time
        )
        if message is not None:
            headers["Content-Type"] = "application/json"
        answer = self._requests.request(method, url, body, headers, timeout)
        if answer.status >= 500:
            raise PanelDown(answer.status)
        if answer.status >= 400:
            try:
                refusal = Refusal.model_validate_json(answer.body)
            except ValidationError:
                raise Unread(answer.status) from None
            raise Refused(refusal.code, answer.status)
        return answer

    @staticmethod
    def _empty(answer: Answer) -> None:
        if answer.status != 204:
            raise Unread(answer.status)

    def heartbeat(self, beat: Heartbeat) -> None:
        """``POST heartbeat``: 204."""
        self._empty(self._send("POST", "heartbeat", beat, REQUEST_TIMEOUT_S))

    def next_command(self) -> Command | None:
        """``GET commands/next``: the command taken, or ``None`` (204)."""
        answer = self._send("GET", "commands/next", None, self.poll_s + POLL_MARGIN_S)
        if answer.status == 204:
            return None
        if answer.status != 200:
            raise Unread(answer.status)
        try:
            return Command.model_validate_json(answer.body)
        except ValidationError:
            raise Unread(answer.status) from None

    def refuse(self, command_id: str, code: CommandRefusalCode) -> None:
        """``POST commands/<id>/refusal``: 204."""
        refusal = CommandRefusal(code=code)
        where = f"commands/{command_id}/refusal"
        self._empty(self._send("POST", where, refusal, REQUEST_TIMEOUT_S))

    def events(self, run_id: str, batch: EventBatch) -> int:
        """``POST runs/<run_id>/events``: the last ``seq`` the Panel holds
        with no gap before it."""
        answer = self._send("POST", f"runs/{run_id}/events", batch, REQUEST_TIMEOUT_S)
        if answer.status != 200:
            raise Unread(answer.status)
        try:
            return EventsAccepted.model_validate_json(answer.body).last_seq
        except ValidationError:
            raise Unread(answer.status) from None

    def verdict(self, run_id: str, envelope: VerdictEnvelope) -> None:
        """``POST runs/<run_id>/verdict``: 204."""
        where = f"runs/{run_id}/verdict"
        self._empty(self._send("POST", where, envelope, REQUEST_TIMEOUT_S))
