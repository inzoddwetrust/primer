"""A stand-in Panel for the tests of ``pridem register`` (DM-139).

``FakePanel`` is the Panel's side of the registration as ``primer-panel``
holds it at ``f503ef6`` (``app/agent/router.py``, ``box.py``,
``signature.py``), read and kept by sense, not by its code: the version's
header first, the body read strictly as contract 4 (the Panel's own 422
otherwise), the public half decoded as 32 raw bytes of an ed25519 key
(``cryptography``), then the token -- unknown, used, expired -- the server's
name free in the whole Panel and the product's repository the project's. A
registration that holds is 201 with a ``RegisterResponse``; a refusal is
``Refusal {code}`` with its status. Every request is kept as it came.

``ScriptedPanel`` answers whatever the test gives it, ``Unreachable`` never
answers. ``register`` runs the verb through the command line on a box at
``fs_root`` with its passport copy, the token in the environment and a strict
``FakeRunner``: the registration runs no command.
"""

import base64
import binascii
import io
import json
import os
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

import pytest
import yaml
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from passport_support import passport_example, section
from pydantic import ValidationError

from pridem.cli import run
from pridem.events import Json
from pridem.protocol import (
    PROTOCOL_HEADER,
    Refusal,
    RefusalCode,
    RegisterRequest,
    RegisterResponse,
    accepts,
)
from pridem.runner import FakeRunner
from pridem.steps.identity import Answer, Cause, PanelUnreachable, Transport
from pridem.steps.passport import PASSPORT_COPY
from pridem.verbs import VERBS
from pridem.verbs.register import TOKEN_ENV, make_register

TOKEN = "Tq3x0f9WmJr2bKcLz8vN1pYhA5sDuE7gR4tI6oPqVwX"  # noqa: S105 -- a test value
"""A token as the Panel mints it: ``secrets.token_urlsafe(32)``."""
OTHER_TOKEN = "nB7cX2vZ9mQ4wE6rT1yU8iO3pA5sD0fG7hJ2kL4zXcV"  # noqa: S105 -- a test value
NOW = datetime(2026, 11, 24, 12, 0, 0, tzinfo=UTC)
AGENT_URL = "https://api.primer.team/agent/v1/"

EXAMPLE = passport_example()
SERVER_NAME = str(section(EXAMPLE, "server")["name"])
ROLE = str(section(EXAMPLE, "server")["role"])
PRODUCT_REPO = str(section(EXAMPLE, "product")["repo"])

STATUS: dict[str, int] = {
    "signature-bad": 401,
    "clock-skew": 401,
    "box-unknown": 403,
    "protocol-too-old": 400,
    "protocol-too-new": 400,
    "token-unknown": 404,
    "token-used": 410,
    "token-expired": 410,
    "name-taken": 409,
    "product-mismatch": 409,
}
"""The Panel's status of each refusal (``primer-panel@f503ef6``,
``app/agent/box.py``)."""


@dataclass(frozen=True)
class Received:
    """A request as the Panel got it."""

    url: str
    body: bytes
    headers: dict[str, str]

    def json(self) -> dict[str, Json]:
        found: dict[str, Json] = json.loads(self.body)
        return found


def refused(code: RefusalCode) -> Answer:
    return Answer(STATUS[code], Refusal(code=code).model_dump_json().encode())


def _invalid() -> Answer:
    """The Panel's own error for a body it does not read: not a refusal."""
    return Answer(422, b'{"error":"invalid","message":"The request does not match"}')


@dataclass
class FakePanel:
    """The Panel's side of a registration (module docstring)."""

    repo: dict[str, str] = field(default_factory=lambda: {TOKEN: PRODUCT_REPO})
    """``token -> repository`` of the token's project."""
    expired: set[str] = field(default_factory=set)
    used: set[str] = field(default_factory=set)
    names: set[str] = field(default_factory=set)
    keys: dict[str, bytes] = field(default_factory=dict)
    """``box_id -> public half`` the Panel keeps."""
    received: list[Received] = field(default_factory=list)

    def post(self, url: str, body: bytes, headers: Mapping[str, str]) -> Answer:
        self.received.append(Received(url, body, dict(headers)))
        version = headers.get(PROTOCOL_HEADER, "")
        if not version.isascii() or not version.isdigit():
            return refused("protocol-too-old")
        too = accepts(int(version))
        if too is not None:
            return refused(too)
        try:
            asked = RegisterRequest.model_validate_json(body)
            raw = base64.b64decode(asked.box_key_public, validate=True)
        except (ValidationError, binascii.Error):
            return _invalid()
        if len(raw) != 32:
            return _invalid()
        Ed25519PublicKey.from_public_bytes(raw)
        if asked.token not in self.repo:
            return refused("token-unknown")
        if asked.token in self.used:
            return refused("token-used")
        if asked.token in self.expired:
            return refused("token-expired")
        if asked.server_name in self.names:
            return refused("name-taken")
        if asked.product_repo != self.repo[asked.token]:
            return refused("product-mismatch")
        box_id = f"box-{len(self.keys) + 1}"
        self.keys[box_id] = raw
        self.names.add(asked.server_name)
        self.used.add(asked.token)
        answer = RegisterResponse(
            box_id=box_id,
            agent_url=AGENT_URL,
            heartbeat_s=30,
            full_state_s=300,
            poll_s=60,
        )
        return Answer(201, answer.model_dump_json().encode())


@dataclass
class ScriptedPanel:
    """Answers ``answer`` to every request, and keeps what came."""

    answer: Answer
    received: list[Received] = field(default_factory=list)

    def post(self, url: str, body: bytes, headers: Mapping[str, str]) -> Answer:
        self.received.append(Received(url, body, dict(headers)))
        return self.answer


@dataclass
class Unreachable:
    """A Panel that never answers, by ``cause``."""

    cause: Cause = "refused"
    received: list[Received] = field(default_factory=list)

    def post(self, url: str, body: bytes, headers: Mapping[str, str]) -> Answer:
        self.received.append(Received(url, body, dict(headers)))
        raise PanelUnreachable(self.cause)


def box_root(fs_root: Path) -> Path:
    return fs_root / "opt" / "pridem"


def with_passport(fs_root: Path, data: Mapping[str, object] = EXAMPLE) -> None:
    """The box's passport copy, 0600, as ``fetch_passport`` leaves it."""
    copy = fs_root / PASSPORT_COPY
    copy.parent.mkdir(parents=True, exist_ok=True)
    copy.write_text(yaml.safe_dump(dict(data), sort_keys=False), encoding="utf-8")
    copy.chmod(0o600)


@dataclass(frozen=True)
class Ran:
    """A run of ``pridem register``: its exit code, stdout, stderr."""

    code: int
    out: str
    err: str

    def verdict(self) -> dict[str, Json]:
        found: dict[str, Json] = json.loads(self.out)
        return found

    def step(self, name: str) -> dict[str, Json]:
        steps = self.verdict()["steps"]
        assert isinstance(steps, list)
        for step in steps:
            if isinstance(step, dict) and step["name"] == name:
                return step
        raise AssertionError(f"no step {name}")

    def fact(self, name: str) -> dict[str, Json]:
        verify = self.step(name).get("verify")
        assert isinstance(verify, dict)
        return verify

    def reason(self, name: str) -> Json:
        reason = self.step(name).get("reason")
        return reason.get("code") if isinstance(reason, dict) else None


def register(
    fs_root: Path,
    monkeypatch: pytest.MonkeyPatch,
    panel: Transport,
    *,
    token: str | None = TOKEN,
    argv: tuple[str, ...] = (),
    owner: Callable[[], int] = os.geteuid,
    now: Callable[[], datetime] = lambda: NOW,
) -> Ran:
    """``pridem --json register`` on the box at ``fs_root``, the Panel
    ``panel``; no command may run (a strict empty ``FakeRunner``)."""
    if token is None:
        monkeypatch.delenv(TOKEN_ENV, raising=False)
    else:
        monkeypatch.setenv(TOKEN_ENV, token)
    verb = make_register(transport=lambda: panel, owner=owner, now=now)
    monkeypatch.setitem(VERBS, "register", verb)
    out, err = io.StringIO(), io.StringIO()
    with FakeRunner() as runner:
        code = run(
            ["--json", "register", *argv],
            root=box_root(fs_root),
            out=out,
            err=err,
            runner=runner,
            fs_root=fs_root,
        )
    return Ran(code, out.getvalue(), err.getvalue())
