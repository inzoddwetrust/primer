"""The probes of DM-189: contract 4's models stricter (REVIEW-0006, K8).

The registration's token is never printed and goes on the wire; ``agent_url``
is the Panel's own host by its form and by ``register``; the intervals have
bounds; ``seq`` rises inside a batch; the headers of a signed request have
one exception; a run of another box is a refusal of its own.
"""

import json
from collections.abc import Mapping
from pathlib import Path

import pytest
from identity_support import FakePanel, box_root, register, with_passport
from protocol_support import batch
from pydantic import ValidationError

from pridem import identity
from pridem.protocol import (
    BOX_HEADER,
    FULL_STATE_S,
    HEARTBEAT_S,
    PROTOCOL_HEADER,
    SIGNATURE_HEADER,
    TIME_HEADER,
    HeaderMissing,
    Refusal,
    RegisterRequest,
    RegisterResponse,
    rendered_schema,
    signed_headers,
)
from pridem.steps.identity import Answer

TOKEN = "Tq3x0f9WmJr2bKcLz8vN1pYhA5sDuE7gR4tI6oPqVwX"  # noqa: S105 -- a test value
ASKED = {
    "token": TOKEN,
    "server_name": "velo-dev",
    "role": "test",
    "product_repo": "git@github.com:a/velo.git",
    "machine_version": "0.1.9",
    "box_key_public": "AAAA",
}
ANSWER = {
    "box_id": "box-1",
    "agent_url": "https://api.primer.team/agent/v1/",
    "heartbeat_s": 30,
    "full_state_s": 300,
    "poll_s": 60,
}


def test_probe_DM_189_the_token_is_never_printed() -> None:
    """``repr``, ``str`` and the text of every kind of error leave the token
    out; the JSON form -- the wire -- carries it, and the other side reads it
    back. The pair: the token is in the message."""
    asked = RegisterRequest.model_validate(ASKED)
    assert asked.token.get_secret_value() == TOKEN
    for text in (repr(asked), str(asked), str(asked.model_dump())):
        assert TOKEN not in text
    wire = asked.model_dump_json()
    assert json.loads(wire)["token"] == TOKEN
    assert RegisterRequest.model_validate_json(wire) == asked
    spoiled = [
        {k: v for k, v in ASKED.items() if k != "role"},  # a field missing
        {**ASKED, "role": "staging"},  # a value of another form
        {**ASKED, "unknown": 1},  # a field the model does not know
        {**ASKED, "server_name": None},  # an explicit null
        {**ASKED, "token": TOKEN[:15]},  # the token itself too short
    ]
    for body in spoiled:
        with pytest.raises(ValidationError) as caught:
            RegisterRequest.model_validate_json(json.dumps(body))
        assert TOKEN not in str(caught.value) and TOKEN[:15] not in str(caught.value)


def _answering(agent_url: str) -> FakePanel:
    """A Panel that registers and answers ``agent_url`` on another host."""

    class Elsewhere(FakePanel):
        def post(self, url: str, body: bytes, headers: Mapping[str, str]) -> Answer:
            answer = super().post(url, body, headers)
            if answer.status != 201:
                return answer
            data = json.loads(answer.body)
            return Answer(201, json.dumps({**data, "agent_url": agent_url}).encode())

    return Elsewhere()


def test_probe_DM_189_agent_url_is_the_panel_s_own(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``agent_url`` is ``https`` to a host, no user, no port, at
    ``/agent/v1/``; and the host is the Panel's the box registered with: a
    well-formed address on another host is not kept. The pair: on its own
    host it is."""
    for good in ("https://api.primer.team/agent/v1/", "https://127.0.0.1/agent/v1/"):
        RegisterResponse.model_validate({**ANSWER, "agent_url": good})
    for bad in (
        "http://api.primer.team/agent/v1/",
        "https://api.primer.team:8443/agent/v1/",
        "https://user@api.primer.team/agent/v1/",
        "https://api.primer.team/agent/v2/",
        "https://api.primer.team/agent/v1/x",
        "https://API.primer.team/agent/v1/",
        "https://api.primer.team/agent/v1/?x=1",
    ):
        with pytest.raises(ValidationError):
            RegisterResponse.model_validate({**ANSWER, "agent_url": bad})
    with_passport(tmp_path)
    panel = _answering("https://evil.example/agent/v1/")
    ran = register(tmp_path, monkeypatch, panel)
    assert ran.code == 1 and ran.reason("register") == "register:answer-unread"
    assert identity.read_registration(box_root(tmp_path)) is None
    own = tmp_path / "own"
    with_passport(own)
    taken = register(own, monkeypatch, _answering("https://api.primer.team/agent/v1/"))
    assert taken.code == 0, taken.err
    assert identity.read_registration(box_root(own)) is not None


@pytest.mark.parametrize(
    ("field", "inside", "outside"),
    [
        ("heartbeat_s", (5, 60), (4, 61)),
        ("poll_s", (5, 85), (4, 86)),
        ("full_state_s", (60, 3600), (59, 3601)),
    ],
)
def test_probe_DM_189_intervals_have_bounds(
    field: str, inside: tuple[int, int], outside: tuple[int, int]
) -> None:
    """Each interval at both of its bounds is read; one past either is not.
    The bounds keep ``full_state_s`` no shorter than ``heartbeat_s``."""
    base = {**ANSWER, "heartbeat_s": 5, "full_state_s": 3600}
    for value in inside:
        RegisterResponse.model_validate({**base, field: value})
    for value in outside:
        with pytest.raises(ValidationError):
            RegisterResponse.model_validate({**base, field: value})
    assert HEARTBEAT_S[1] <= FULL_STATE_S[0]  # the full state never more often


def test_probe_DM_189_seq_rises_in_a_batch() -> None:
    """A batch whose ``seq`` rises is read, gaps allowed between its lines
    and between batches; a repeat or a fall anywhere in it -- the second
    line or the last -- is not."""
    batch([1, 2, 3])
    batch([4, 7, 9])  # gaps: the Panel holds the last seq with no gap before it
    for seqs in ([1, 1], [1, 2, 2], [3, 2], [1, 2, 3, 5, 4]):
        with pytest.raises(ValidationError, match="seq does not rise"):
            batch(seqs)


def _headers(**given: str) -> dict[str, str]:
    return {
        BOX_HEADER: "box-1",
        TIME_HEADER: "1764000000",
        SIGNATURE_HEADER: "c2lnbmF0dXJl",
        PROTOCOL_HEADER: "1",
        **given,
    }


def test_probe_DM_189_one_exception_for_the_headers() -> None:
    """Every header not of its form -- absent, a time that is no number, a
    signature that is not base64, an empty box -- is ``HeaderMissing``,
    never pydantic's ``ValidationError``; its text quotes no value. The
    pair: headers of their form are read."""
    read = signed_headers(_headers())
    assert (read.box, read.time, read.protocol) == ("box-1", 1764000000, 1)
    spoiled = [
        {k: v for k, v in _headers().items() if k != SIGNATURE_HEADER},
        _headers(**{TIME_HEADER: "soon"}),
        _headers(**{SIGNATURE_HEADER: "not base64!"}),
        _headers(**{BOX_HEADER: ""}),
    ]
    for headers in spoiled:
        with pytest.raises(HeaderMissing) as caught:
            signed_headers(headers)
        assert not isinstance(caught.value, ValidationError)
        assert "not base64!" not in str(caught.value)


def test_probe_DM_189_run_foreign_is_a_refusal() -> None:
    """A run of another box is ``run-foreign``, a code of the closed list in
    the exported schema. The pair: a code of no list is refused."""
    assert Refusal.model_validate_json('{"code": "run-foreign"}').code == "run-foreign"
    with pytest.raises(ValidationError):
        Refusal.model_validate_json('{"code": "run-of-someone"}')
    schema = json.loads(rendered_schema())
    assert "run-foreign" in schema["$defs"]["Refusal"]["properties"]["code"]["enum"]
