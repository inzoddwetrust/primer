"""The steps of ``pridem register`` (DM-139): the box's key, then its
registration in the Panel by a one-time token (``PRIMER-PANEL-TZ-2`` 4).

``box_key`` mints the key when the box has none (``pridem.identity``); a key
in place is taken as it is, a damaged one refuses -- never fixed, never
minted over. A box registered with no key refuses too: a new key would not be
the one the Panel knows.

``register`` sends ``RegisterRequest`` of contract 4 to ``<panel>/agent/v1/
register``, unsigned -- the token is the proof (gate of DM-153) -- with the
protocol's version in its header, and keeps the answer in
``registration.json``. A box registered already refuses before any request
(``already``): the token of a second registration would be spent for nothing.
The Panel's refusals are the step's codes one to one; a Panel that does not
answer is ``unreachable {cause}``; any other answer -- a 201 that is not a
``RegisterResponse`` of contract 4 (an unknown field, a ``null``, an
``agent_url`` not of its form, intervals out of their bounds) or whose
``agent_url`` names another host than the Panel registered with (DM-189), the
Panel's own 422 to a body it does not read,
a 5xx, a refusal no registration gets -- is ``answer-unread {status}``. One
request, no repeat: the agent's repeats are its own (``PRIMER-PANEL-TZ-2``
10, DM-141).

The request goes from the host, straight: the egress proxy is the products'
way out, not the machine's. ``HttpTransport`` is ``http.client`` of the
standard library over TLS with the system's trust (``PRIMER-PANEL-TZ-2`` 1);
``http`` only to the loopback -- tests and tier 3 (``panel_origin``).

The point of no return of the plan is the Panel's 201 to ``register``: the
token is spent there. Before it the box changes by its key alone -- inert
until a registration names it, and kept when the Panel refuses: the next
registration sends the same public half. Nothing is undone in ``finally``.

KNOWN CEILING: a registration the Panel took and the box did not keep.
1. Mechanics: the Panel answers 201 and spends the token; the box dies, or
   its disk refuses, before ``registration.json`` is written. The box has its
   key and no ``box_id``; the token again is ``token-used``, a new one is
   ``name-taken`` -- the Panel has the server by its name. The box cannot get
   out of it alone.
2. Status: acknowledged by design.
3. Task: none on the box -- the fix is the Panel's (gate of DM-139: the
   dispatcher records it for the Panel's side).
4. Trigger: a box whose verdict of ``register`` is red with
   ``register:token-used`` or ``register:name-taken`` while the Panel lists a
   server of its name with the box's public half.
5. Agreed fix: the Panel answers a repeat of the same token with the same
   ``box_key_public`` by the same ``RegisterResponse``; the box's repeat then
   writes what it lost.
6. Rejected: writing ``registration.json`` before the answer (a file naming a
   ``box_id`` the Panel never gave); the box retrying a token on its own (the
   token is one-time, the repeat is the Panel's to make idempotent).
"""

import http.client
import socket
import ssl
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import ClassVar, Literal, Protocol
from urllib.parse import urlsplit

from pydantic import SecretStr, ValidationError

from pridem.identity import (
    KeyDamaged,
    RegistrationDamaged,
    key_path,
    load_seed,
    mint_key,
    present,
    public_key,
    read_registration,
    read_seed,
    registration_of,
    registration_path,
    write_registration,
)
from pridem.protocol import (
    PROTOCOL_HEADER,
    PROTOCOL_VERSION,
    Refusal,
    RefusalCode,
    RegisterRequest,
    RegisterResponse,
)
from pridem.steps.base import (
    CheckResult,
    Mode,
    Role,
    Step,
    StepContext,
    StepFailed,
    Verified,
    local_code,
)

MODES: frozenset[Mode] = frozenset({"command"})
DEFAULT_PANEL = "https://api.primer.team"
REGISTER_PATH = "/agent/v1/register"
TIMEOUT_S = 30.0
ANSWER_MAX = 64 * 1024
"""An answer of the Panel to a registration is a few hundred bytes; a longer
one is not of contract 4."""
LOOPBACK = frozenset({"127.0.0.1", "::1", "localhost"})

REFUSED: frozenset[RefusalCode] = frozenset(
    {
        "token-unknown",
        "token-used",
        "token-expired",
        "name-taken",
        "product-mismatch",
        "protocol-too-old",
        "protocol-too-new",
    }
)
"""The Panel's refusals of a registration (``PRIMER-PANEL-TZ-2`` 4, 11)."""


def panel_origin(value: str) -> str:
    """The Panel as an origin, ``https://<host>[:<port>]``, no trailing ``/``;
    ``http`` only to the loopback. ``ValueError`` otherwise."""
    parts = urlsplit(value)
    if (
        any(char.isspace() for char in value)
        or parts.scheme not in ("https", "http")
        or not parts.hostname
        or parts.path not in ("", "/")
        or parts.query
        or parts.fragment
        or parts.username is not None
        or parts.password is not None
    ):
        raise ValueError("the Panel is an origin: https://<host>[:<port>]")
    _ = parts.port  # a port that is not a number raises ValueError
    if parts.scheme == "http" and parts.hostname not in LOOPBACK:
        raise ValueError("http only to the loopback; the Panel is https")
    return value.rstrip("/")


Cause = Literal["dns", "refused", "timed-out", "tls", "reset"]


class PanelUnreachable(Exception):
    """The Panel gave no answer: ``cause`` says how it failed."""

    def __init__(self, cause: Cause) -> None:
        super().__init__(cause)
        self.cause: Cause = cause


@dataclass(frozen=True)
class Answer:
    """The Panel's answer: its status and at most ``ANSWER_MAX + 1`` bytes."""

    status: int
    body: bytes


class Transport(Protocol):
    """How a request reaches the Panel."""

    def post(self, url: str, body: bytes, headers: Mapping[str, str]) -> Answer:
        """``POST`` ``body`` to ``url``; the answer, or ``PanelUnreachable``."""
        ...


class Requests(Protocol):
    """How the agent's requests reach the Panel (DM-141): any method, a
    timeout of its own -- the long-poll waits longer than the rest."""

    def request(
        self,
        method: str,
        url: str,
        body: bytes,
        headers: Mapping[str, str],
        timeout: float,
    ) -> Answer:
        """``method`` ``url`` with ``body``; the answer, or
        ``PanelUnreachable``."""
        ...


class HttpTransport:
    """``http.client`` of the standard library: TLS with the system's trust
    for ``https``, plain for the loopback's ``http``."""

    def __init__(self, timeout: float = TIMEOUT_S) -> None:
        self.timeout = timeout

    def post(self, url: str, body: bytes, headers: Mapping[str, str]) -> Answer:
        return self.request("POST", url, body, headers, self.timeout)

    def request(
        self,
        method: str,
        url: str,
        body: bytes,
        headers: Mapping[str, str],
        timeout: float,
    ) -> Answer:
        parts = urlsplit(url)
        host = parts.hostname or ""
        connection = (
            http.client.HTTPSConnection(
                host,
                parts.port,
                timeout=timeout,
                context=ssl.create_default_context(),
            )
            if parts.scheme == "https"
            else http.client.HTTPConnection(host, parts.port, timeout=timeout)
        )
        try:
            connection.request(method, parts.path, body=body, headers=dict(headers))
            response = connection.getresponse()
            return Answer(response.status, response.read(ANSWER_MAX + 1))
        except socket.gaierror:
            raise PanelUnreachable("dns") from None
        except ssl.SSLError:
            raise PanelUnreachable("tls") from None
        except ConnectionRefusedError:
            raise PanelUnreachable("refused") from None
        except TimeoutError:
            raise PanelUnreachable("timed-out") from None
        except (OSError, http.client.HTTPException):
            raise PanelUnreachable("reset") from None
        finally:
            connection.close()


class BoxKey(Step):
    """The box's key: minted once, taken as it is after."""

    name = "box_key"
    title = "Mint the box's key"
    said = "key {public}"
    order = 1
    modes = MODES
    codes: ClassVar[dict[str, str]] = {
        "mint": "mint the box's key",
        "damaged": (
            "the box's key cannot be used ({cause}): it is neither fixed nor "
            "minted over"
        ),
        "missing-registered": (
            "the box is registered and its key is missing: a new key is not "
            "the one the Panel knows"
        ),
    }

    def __init__(self, root: Path, owner: int) -> None:
        self.root = root
        self.owner = owner

    def check(self, ctx: StepContext) -> CheckResult:
        try:
            seed = read_seed(self.root, self.owner)
        except KeyDamaged as damaged:
            raise StepFailed("damaged", {"cause": damaged.cause}) from None
        if seed is not None:
            return CheckResult(False)
        if present(registration_path(self.root)):
            raise StepFailed("missing-registered")
        return CheckResult(True, local_code("mint"))

    def act(self, ctx: StepContext, check: CheckResult) -> None:
        mint_key(self.root)

    def verify(self, ctx: StepContext, check: CheckResult) -> Verified:
        try:
            seed = load_seed(self.root, self.owner)
        except KeyDamaged as damaged:
            raise StepFailed("damaged", {"cause": damaged.cause}) from None
        return Verified(
            {
                "path": str(key_path(self.root)),
                "public": public_key(seed),
                "minted": check.needed,
            }
        )


@dataclass(frozen=True)
class Applicant:
    """What the box says of itself to the Panel: from its passport and the
    machine."""

    server_name: str
    role: Role
    product_repo: str
    machine_version: str


def _answered(answer: Answer) -> RegisterResponse:
    """The Panel's answer read: a ``RegisterResponse`` with 201, a refusal of
    a registration by its code, anything else ``answer-unread``."""
    unread = StepFailed("answer-unread", {"status": answer.status})
    if len(answer.body) > ANSWER_MAX:
        raise unread
    if answer.status == http.client.CREATED:
        try:
            return RegisterResponse.model_validate_json(answer.body)
        except ValidationError:
            raise unread from None
    try:
        refusal = Refusal.model_validate_json(answer.body)
    except ValidationError:
        raise unread from None
    if refusal.code not in REFUSED:
        raise unread
    raise StepFailed(refusal.code)


def _moment(at: datetime) -> str:
    return at.strftime("%Y-%m-%dT%H:%M:%SZ")


class Register(Step):
    """The box's registration in the Panel by a one-time token."""

    name = "register"
    title = "Register the box in the Panel"
    said = "box {box_id}"
    order = 2
    modes = MODES
    codes: ClassVar[dict[str, str]] = {
        "register": "register the box in the Panel {panel}",
        "already": (
            "the box is registered already as {box_id}: a token registers a box once"
        ),
        "registration-damaged": (
            "the box's registration (agent/registration.json) cannot be read"
        ),
        "token-unknown": "the Panel does not know the token",
        "token-used": "the token is used already: a token registers one box",
        "token-expired": "the token has expired: ask the Panel for a new one",
        "name-taken": "the Panel has a server of this name already",
        "product-mismatch": (
            "the product's repository is not the one of the token's project"
        ),
        "protocol-too-old": "the Panel no longer reads this machine's protocol",
        "protocol-too-new": "the Panel does not read this machine's protocol yet",
        "unreachable": "the Panel did not answer ({cause})",
        "answer-unread": "the Panel's answer is not of contract 4 (status {status})",
    }

    def __init__(
        self,
        root: Path,
        *,
        panel: str,
        token: str,
        applicant: Applicant,
        transport: Transport,
        owner: int,
        now: Callable[[], datetime],
    ) -> None:
        self.root = root
        self.panel = panel
        self.token = token
        self.applicant = applicant
        self.transport = transport
        self.owner = owner
        self.now = now

    def check(self, ctx: StepContext) -> CheckResult:
        try:
            registration = read_registration(self.root)
        except RegistrationDamaged:
            raise StepFailed("registration-damaged") from None
        if registration is not None:
            raise StepFailed("already", {"box_id": registration.box_id})
        return CheckResult(True, local_code("register", {"panel": self.panel}))

    def act(self, ctx: StepContext, check: CheckResult) -> None:
        seed = load_seed(self.root, self.owner)  # box_key read it back before
        asked = RegisterRequest(
            token=SecretStr(self.token),
            server_name=self.applicant.server_name,
            role=self.applicant.role,
            product_repo=self.applicant.product_repo,
            machine_version=self.applicant.machine_version,
            box_key_public=public_key(seed),
        )
        body = asked.model_dump_json(exclude_none=True).encode("utf-8")
        headers = {
            PROTOCOL_HEADER: str(PROTOCOL_VERSION),
            "Content-Type": "application/json",
        }
        try:
            answer = self.transport.post(self.panel + REGISTER_PATH, body, headers)
        except PanelUnreachable as unreachable:
            raise StepFailed("unreachable", {"cause": unreachable.cause}) from None
        registered = _answered(answer)
        if urlsplit(registered.agent_url).hostname != urlsplit(self.panel).hostname:
            raise StepFailed("answer-unread", {"status": answer.status})
        at = _moment(self.now())
        write_registration(self.root, registration_of(registered, self.panel, at))

    def verify(self, ctx: StepContext, check: CheckResult) -> Verified:
        try:
            registration = read_registration(self.root)
        except RegistrationDamaged:
            raise StepFailed("registration-damaged") from None
        if registration is None:  # written by act, read back: gone means unread
            raise StepFailed("registration-damaged")
        return Verified(
            {
                "box_id": registration.box_id,
                "agent_url": registration.agent_url,
                "panel": registration.panel,
                "registered_at": registration.registered_at,
            }
        )
