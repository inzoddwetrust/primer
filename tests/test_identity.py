"""``pridem register`` beyond its probes (DM-139): the grid of the gate.

The key: damaged by each cause -- refused, never fixed, never minted over; a
registered box without its key. The registration: there already (no
request), damaged. The Panel: each refusal of a registration by its code,
not answering by each cause, answers not of contract 4. The command line:
the token from the environment only, the passport copy, the Panel's origin.
The secret: the token reaches the Panel and nothing else. The signature of
the agent's requests (``signed_headers``) holds by the Panel's own check. One
registration goes the whole way through ``http.client`` to a server on the
loopback.
"""

import base64
import json
import os
import socket
import threading
from collections.abc import Iterator, Mapping
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from identity_support import (
    AGENT_URL,
    EXAMPLE,
    OTHER_TOKEN,
    PRODUCT_REPO,
    ROLE,
    SERVER_NAME,
    TOKEN,
    FakePanel,
    Ran,
    ScriptedPanel,
    Unreachable,
    box_root,
    refused,
    register,
    with_passport,
)
from passport_support import section

from pridem import __version__, identity
from pridem.protocol import (
    PROTOCOL_HEADER,
    RefusalCode,
    RegisterResponse,
    signed_headers,
    signing_string,
)
from pridem.steps.identity import (
    REFUSED,
    Answer,
    Cause,
    HttpTransport,
    PanelUnreachable,
    panel_origin,
)
from pridem.verbs import VERBS
from pridem.verbs.register import TOKEN_ENV

# --- helpers -------------------------------------------------------------------

SHORT = "short-15-chars!"
SIXTEEN = "sixteen-chars-ok"


@pytest.fixture
def fs_root(tmp_path: Path) -> Path:
    """A box with its passport copy and nothing of its identity."""
    with_passport(tmp_path)
    return tmp_path


def _key(fs_root: Path) -> Path:
    return identity.key_path(box_root(fs_root))


def _registration(fs_root: Path) -> Path:
    return identity.registration_path(box_root(fs_root))


def _plant_key(fs_root: Path, data: bytes, mode: int = 0o600) -> Path:
    path = _key(fs_root)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    path.chmod(mode)
    return path


def _registered(fs_root: Path, monkeypatch: pytest.MonkeyPatch) -> FakePanel:
    panel = FakePanel()
    first = register(fs_root, monkeypatch, panel)
    assert first.code == 0, first.err
    return panel


def _red(ran: Ran, step: str, code: str) -> None:
    assert ran.code == 1, ran.err
    assert ran.verdict()["result"] == "red"
    assert ran.reason(step) == code


# --- the key ---------------------------------------------------------------------


@pytest.mark.parametrize(
    ("data", "mode", "cause"),
    [
        (b"", 0o600, "size"),
        (b"k" * 31, 0o600, "size"),
        (b"k" * 33, 0o600, "size"),
        (b"k" * 32, 0o644, "mode"),
        (b"k" * 32, 0o400, "mode"),
    ],
)
def test_a_damaged_key_is_refused_never_fixed_nor_minted_over(
    fs_root: Path, monkeypatch: pytest.MonkeyPatch, data: bytes, mode: int, cause: str
) -> None:
    path = _plant_key(fs_root, data, mode)
    panel = FakePanel()
    ran = register(fs_root, monkeypatch, panel)
    _red(ran, "box_key", "box_key:damaged")
    assert ran.step("box_key")["reason"] == {"code": "box_key:damaged", "cause": cause}
    assert ran.step("register")["status"] == "skipped"
    assert path.read_bytes() == data and path.stat().st_mode & 0o777 == mode
    assert panel.received == [] and not _registration(fs_root).exists()


def test_a_key_of_another_owner_is_refused(
    fs_root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The owner is the machine's user; a test cannot ``chown`` on CI, so the
    machine's user is said to be another one."""
    path = _plant_key(fs_root, b"k" * 32)
    panel = FakePanel()
    ran = register(fs_root, monkeypatch, panel, owner=lambda: os.geteuid() + 1)
    _red(ran, "box_key", "box_key:damaged")
    assert ran.step("box_key")["reason"] == {
        "code": "box_key:damaged",
        "cause": "owner",
    }
    assert path.read_bytes() == b"k" * 32 and panel.received == []


@pytest.mark.parametrize("form", ["directory", "link to a key", "dangling link"])
def test_a_key_that_is_not_a_file_is_refused(
    fs_root: Path, monkeypatch: pytest.MonkeyPatch, form: str
) -> None:
    path = _key(fs_root)
    path.parent.mkdir(parents=True)
    if form == "directory":
        path.mkdir()
    else:
        target = fs_root / "elsewhere.key"
        if form == "link to a key":
            target.write_bytes(b"k" * 32)
            target.chmod(0o600)
        path.symlink_to(target)
    panel = FakePanel()
    ran = register(fs_root, monkeypatch, panel)
    assert ran.step("box_key")["reason"] == {
        "code": "box_key:damaged",
        "cause": "not-a-file",
    }
    assert panel.received == [] and path.is_symlink() == (form != "directory")


def test_a_registered_box_without_its_key_mints_none(
    fs_root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _registered(fs_root, monkeypatch)
    _key(fs_root).unlink()
    panel = FakePanel()
    ran = register(fs_root, monkeypatch, panel, token=OTHER_TOKEN)
    _red(ran, "box_key", "box_key:missing-registered")
    assert not _key(fs_root).exists() and panel.received == []


def test_the_key_and_its_directory_are_private(
    fs_root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _registered(fs_root, monkeypatch)
    agent = identity.agent_dir(box_root(fs_root))
    assert agent.stat().st_mode & 0o777 == 0o700
    for path in (_key(fs_root), _registration(fs_root)):
        found = path.stat()
        assert (found.st_mode & 0o777, found.st_uid) == (0o600, os.geteuid())


def test_minting_over_a_key_is_refused_by_the_file_system(
    fs_root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = box_root(fs_root)
    identity.mint_key(root)
    before = _key(fs_root).read_bytes()
    with pytest.raises(FileExistsError):
        identity.mint_key(root)
    assert _key(fs_root).read_bytes() == before
    assert [p.name for p in identity.agent_dir(root).iterdir()] == ["box.key"]


# --- the registration ------------------------------------------------------------


def test_a_registered_box_refuses_before_any_request(
    fs_root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    panel = _registered(fs_root, monkeypatch)
    kept = _registration(fs_root).read_bytes()
    ran = register(fs_root, monkeypatch, panel, token=OTHER_TOKEN)
    _red(ran, "register", "register:already")
    assert ran.step("register")["reason"] == {
        "code": "register:already",
        "box_id": "box-1",
    }
    assert len(panel.received) == 1 and _registration(fs_root).read_bytes() == kept
    assert ran.fact("box_key")["minted"] is False


_KEPT = (
    '{"box_id": "box-1", "agent_url": "https://api.primer.team/agent/v1/", '
    '"heartbeat_s": 30, "full_state_s": 300, "poll_s": 60, '
    '"panel": "https://api.primer.team", "registered_at": "2026-11-24T12:00:00Z"}'
)


@pytest.mark.parametrize(
    "text",
    ["", "{", '{"box_id": "x"}', "[]", _KEPT + " " * (64 * 1024)],
    ids=["empty", "cut", "short", "a list", "too big"],
)
def test_a_damaged_registration_refuses_before_any_request(
    fs_root: Path, monkeypatch: pytest.MonkeyPatch, text: str
) -> None:
    identity.mint_key(box_root(fs_root))  # the key is in place, the box's
    path = _registration(fs_root)
    path.write_text(text)
    panel = FakePanel()
    ran = register(fs_root, monkeypatch, panel)
    _red(ran, "register", "register:registration-damaged")
    assert panel.received == [] and path.read_text() == text


def test_the_registration_keeps_the_answer_the_panel_and_the_time(
    fs_root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ran = register(fs_root, monkeypatch, FakePanel())
    kept = json.loads(_registration(fs_root).read_text())
    assert kept == {
        "box_id": "box-1",
        "agent_url": AGENT_URL,
        "heartbeat_s": 30,
        "full_state_s": 300,
        "poll_s": 60,
        "panel": "https://api.primer.team",
        "registered_at": "2026-11-24T12:00:00Z",
    }
    assert ran.fact("register") == {
        "box_id": "box-1",
        "agent_url": AGENT_URL,
        "panel": "https://api.primer.team",
        "registered_at": "2026-11-24T12:00:00Z",
    }


def test_the_request_is_contract_4_from_the_passport_unsigned_with_its_version(
    fs_root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    panel = FakePanel()
    register(fs_root, monkeypatch, panel, argv=("--panel", "https://panel.test:8443"))
    [got] = panel.received
    assert got.url == "https://panel.test:8443/agent/v1/register"
    assert got.headers == {PROTOCOL_HEADER: "1", "Content-Type": "application/json"}
    seed = _key(fs_root).read_bytes()
    assert got.json() == {
        "token": TOKEN,
        "server_name": SERVER_NAME,
        "role": ROLE,
        "product_repo": PRODUCT_REPO,
        "machine_version": __version__,
        "box_key_public": identity.public_key(seed),
    }


def test_the_role_and_name_are_the_passport_s(
    fs_root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    data = json.loads(json.dumps(EXAMPLE, default=str))
    section(data, "server")["role"] = "prod"
    section(data, "server")["name"] = "aivis-prod"
    section(data, "product")["ref"] = "v1.0.0"
    with_passport(fs_root, data)
    panel = FakePanel()
    register(fs_root, monkeypatch, panel)
    sent = panel.received[0].json()
    assert (sent["role"], sent["server_name"]) == ("prod", "aivis-prod")


# --- the Panel's refusals and answers ---------------------------------------------


@pytest.mark.parametrize("code", sorted(REFUSED))
def test_each_refusal_of_a_registration_is_its_code(
    fs_root: Path, monkeypatch: pytest.MonkeyPatch, code: RefusalCode
) -> None:
    panel = ScriptedPanel(refused(code))
    ran = register(fs_root, monkeypatch, panel)
    _red(ran, "register", f"register:{code}")
    assert len(panel.received) == 1 and not _registration(fs_root).exists()
    assert _key(fs_root).is_file()  # the key stays: the next try sends it again


def test_the_refusals_of_a_registration_are_the_panel_s() -> None:
    assert REFUSED == {
        "token-unknown",
        "token-used",
        "token-expired",
        "name-taken",
        "product-mismatch",
        "protocol-too-old",
        "protocol-too-new",
    }


def test_name_taken_and_product_mismatch_by_the_panel_s_rules(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    panel = FakePanel(repo={TOKEN: PRODUCT_REPO, OTHER_TOKEN: PRODUCT_REPO})
    first, second = tmp_path / "a", tmp_path / "b"
    for root in (first, second):
        with_passport(root)
    assert register(first, monkeypatch, panel).code == 0
    _red(
        register(second, monkeypatch, panel, token=OTHER_TOKEN),
        "register",
        "register:name-taken",
    )
    third = tmp_path / "c"
    with_passport(third)
    other = FakePanel(repo={TOKEN: "git@github.com:aivis-one/other.git"})
    _red(register(third, monkeypatch, other), "register", "register:product-mismatch")


def _created(**fields: object) -> Answer:
    body = {
        "box_id": "box-1",
        "agent_url": AGENT_URL,
        "heartbeat_s": 30,
        "full_state_s": 300,
        "poll_s": 60,
        **fields,
    }
    return Answer(201, json.dumps(body).encode())


@pytest.mark.parametrize(
    "answer",
    [
        _created(extra=1),
        _created(box_id=None),
        _created(agent_url="http://api.primer.team/agent/v1/"),
        _created(heartbeat_s="30"),
        Answer(201, b""),
        Answer(201, b"<html>ok</html>"),
        Answer(200, _created().body),
        Answer(422, b'{"error":"invalid"}'),
        Answer(500, b"<html>Internal Server Error</html>"),
        refused("clock-skew"),
        refused("box-unknown"),
        Answer(410, b'{"code":"token-gone"}'),
        Answer(201, _created().body + b" " * (64 * 1024)),
    ],
)
def test_an_answer_not_of_contract_4_is_unread(
    fs_root: Path, monkeypatch: pytest.MonkeyPatch, answer: Answer
) -> None:
    ran = register(fs_root, monkeypatch, ScriptedPanel(answer))
    _red(ran, "register", "register:answer-unread")
    assert ran.step("register")["reason"] == {
        "code": "register:answer-unread",
        "status": answer.status,
    }
    assert not _registration(fs_root).exists()


def test_a_valid_answer_is_read(fs_root: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The pair of the unread answers: the same form, read."""
    ran = register(fs_root, monkeypatch, ScriptedPanel(_created()))
    assert ran.code == 0 and ran.fact("register")["box_id"] == "box-1"
    RegisterResponse.model_validate_json(_created().body)


@pytest.mark.parametrize("cause", ["dns", "refused", "timed-out", "tls", "reset"])
def test_a_panel_that_does_not_answer_is_unreachable_by_its_cause(
    fs_root: Path, monkeypatch: pytest.MonkeyPatch, cause: Cause
) -> None:
    panel = Unreachable(cause)
    ran = register(fs_root, monkeypatch, panel)
    assert ran.step("register")["reason"] == {
        "code": "register:unreachable",
        "cause": cause,
    }
    assert len(panel.received) == 1 and not _registration(fs_root).exists()


# --- the command line -------------------------------------------------------------


def test_no_token_refuses_before_the_lock(
    fs_root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    panel = FakePanel()
    ran = register(fs_root, monkeypatch, panel, token=None)
    assert (ran.code, ran.out) == (1, "")
    assert f"register: no token -- set {TOKEN_ENV}" in ran.err
    assert not (box_root(fs_root) / "history").exists()
    assert not identity.agent_dir(box_root(fs_root)).exists() and panel.received == []


def test_a_short_token_refuses_before_the_lock(
    fs_root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ran = register(fs_root, monkeypatch, FakePanel(), token=SHORT)
    assert ran.code == 1 and "shorter than 16" in ran.err
    assert not (box_root(fs_root) / "history").exists()


def test_a_token_of_16_is_taken(fs_root: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    panel = FakePanel(repo={SIXTEEN: PRODUCT_REPO})
    assert register(fs_root, monkeypatch, panel, token=SIXTEEN).code == 0


def test_no_passport_copy_refuses_before_the_lock(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    panel = FakePanel()
    ran = register(tmp_path, monkeypatch, panel)
    assert ran.code == 1 and "no passport copy" in ran.err
    assert not (box_root(tmp_path) / "history").exists() and panel.received == []


def test_the_token_is_not_an_option(
    fs_root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ran = register(fs_root, monkeypatch, FakePanel(), argv=("--token", TOKEN))
    assert ran.code == 1 and "unknown option --token" in ran.err


def test_the_token_reaches_the_panel_and_nothing_else(
    fs_root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The pair: the Panel got the token; the verdict, its args, the journal,
    the console have none of it."""
    panel = FakePanel()
    ran = register(fs_root, monkeypatch, panel)
    assert panel.received[0].json()["token"] == TOKEN
    verdict = ran.verdict()
    assert verdict["args"] == {"panel": "https://api.primer.team"}
    journal = box_root(fs_root) / str(verdict["log_ref"])
    for text in (ran.out, ran.err, journal.read_text(), *_history(fs_root)):
        assert TOKEN not in text
    assert _key(fs_root).read_bytes() not in journal.read_bytes()


class _Quoting:
    """A way to the Panel that fails with the request's body in its words."""

    def post(self, url: str, body: bytes, headers: Mapping[str, str]) -> Answer:
        raise RuntimeError(f"cannot send {body.decode()}")


def test_the_token_is_cleaned_from_an_error_s_words(
    fs_root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An error of the machine goes to the journal with its words (contract 2,
    ``exception``): the token in them is cleaned -- it is a secret of the run.
    The pair: the error's words are in the journal."""
    ran = register(fs_root, monkeypatch, _Quoting())
    assert ran.reason("register") == "exception"
    journal = (box_root(fs_root) / str(ran.verdict()["log_ref"])).read_text()
    assert "cannot send" in journal and "[redacted]" in journal
    for text in (ran.out, ran.err, journal, *_history(fs_root)):
        assert TOKEN not in text


def _history(fs_root: Path) -> list[str]:
    return [p.read_text() for p in (box_root(fs_root) / "history").iterdir()]


@pytest.mark.parametrize(
    ("given", "origin"),
    [
        ("https://api.primer.team", "https://api.primer.team"),
        ("https://api.primer.team/", "https://api.primer.team"),
        ("https://panel.test:8443", "https://panel.test:8443"),
        ("http://127.0.0.1:8080", "http://127.0.0.1:8080"),
        ("http://localhost:9", "http://localhost:9"),
        ("http://[::1]:8080", "http://[::1]:8080"),
    ],
)
def test_the_panel_is_an_origin(given: str, origin: str) -> None:
    assert panel_origin(given) == origin


@pytest.mark.parametrize(
    "given",
    [
        "http://api.primer.team",
        "http://10.0.0.1:8080",
        "ftp://api.primer.team",
        "api.primer.team",
        "https://",
        "https://api.primer.team/agent/v1",
        "https://api.primer.team?x=1",
        "https://api.primer.team#x",
        "https://user:pw@api.primer.team",
        "https://api.primer.team:port",
        "https://api.primer.team :8443",
    ],
)
def test_anything_else_is_not_the_panel(given: str) -> None:
    with pytest.raises(ValueError):
        panel_origin(given)


def test_a_panel_over_http_off_the_loopback_refuses_before_the_lock(
    fs_root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    panel = FakePanel()
    ran = register(fs_root, monkeypatch, panel, argv=("--panel", "http://panel.test"))
    assert ran.code == 1 and "invalid arguments" in ran.err and panel.received == []


def test_register_is_a_verb_of_the_box_with_a_verdict() -> None:
    verb = VERBS["register"]
    assert verb.verdict and verb.box and not verb.timer
    assert dict(verb.options) == {"--panel": ("panel", "value")}


# --- the signature of the agent's requests ----------------------------------------


def test_signed_headers_hold_by_the_panel_s_check(
    fs_root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """What the Panel does (``app/agent/signature.py``): the public half of
    the registration, ``signing_string`` in UTF-8, the signature base64."""
    panel = _registered(fs_root, monkeypatch)
    seed = _key(fs_root).read_bytes()
    body = b'{"measured_at":"2026-11-24T12:00:00Z"}'
    headers = identity.signed_headers(
        seed, "box-1", "post", "/agent/v1/heartbeat", body, 1764000000
    )
    read = signed_headers(headers)
    assert (read.box, read.time, read.protocol) == ("box-1", 1764000000, 1)
    public = Ed25519PublicKey.from_public_bytes(panel.keys["box-1"])
    signature = base64.b64decode(read.signature, validate=True)
    assert len(signature) == 64
    message = signing_string("POST", "/agent/v1/heartbeat", 1764000000, body)
    public.verify(signature, message.encode())
    for spoiled in (
        signing_string("POST", "/agent/v1/heartbeat", 1764000001, body),
        signing_string("POST", "/heartbeat", 1764000000, body),
        signing_string("POST", "/agent/v1/heartbeat", 1764000000, body + b" "),
    ):
        with pytest.raises(InvalidSignature):
            public.verify(signature, spoiled.encode())


def test_the_public_half_is_32_raw_bytes_of_the_key(
    fs_root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    panel = _registered(fs_root, monkeypatch)
    seed = _key(fs_root).read_bytes()
    raw = base64.b64decode(identity.public_key(seed), validate=True)
    assert len(raw) == 32 and raw == panel.keys["box-1"] and raw != seed


# --- the way to the Panel -----------------------------------------------------------


class _PanelHandler(BaseHTTPRequestHandler):
    """A Panel on the loopback: the registration's path and header, 201."""

    seen: list[tuple[str, str, dict[str, object]]] = []

    def do_POST(self) -> None:
        length = int(self.headers["Content-Length"])
        body = json.loads(self.rfile.read(length))
        self.seen.append((self.path, self.headers[PROTOCOL_HEADER], body))
        answer = _created().body
        self.send_response(201)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(answer)))
        self.end_headers()
        self.wfile.write(answer)

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002
        return


@pytest.fixture
def loopback_panel() -> Iterator[tuple[str, list[tuple[str, str, dict[str, object]]]]]:
    seen: list[tuple[str, str, dict[str, object]]] = []
    handler = type("Handler", (_PanelHandler,), {"seen": seen})
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}", seen
    finally:
        server.shutdown()
        server.server_close()


def test_a_registration_through_http_client_on_the_loopback(
    fs_root: Path,
    monkeypatch: pytest.MonkeyPatch,
    loopback_panel: tuple[str, list[tuple[str, str, dict[str, object]]]],
) -> None:
    origin, seen = loopback_panel
    ran = register(fs_root, monkeypatch, HttpTransport(), argv=("--panel", origin))
    assert ran.code == 0, ran.err
    [(path, version, body)] = seen
    assert (path, version, body["token"]) == ("/agent/v1/register", "1", TOKEN)
    assert json.loads(_registration(fs_root).read_text())["panel"] == origin


def test_a_closed_port_is_refused() -> None:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    with pytest.raises(PanelUnreachable) as caught:
        HttpTransport(timeout=5).post(
            f"http://127.0.0.1:{port}/agent/v1/register", b"{}", {}
        )
    assert caught.value.cause == "refused"


def test_a_name_that_does_not_resolve_is_dns() -> None:
    with pytest.raises(PanelUnreachable) as caught:
        HttpTransport(timeout=5).post("https://box.invalid/agent/v1/register", b"", {})
    assert caught.value.cause == "dns"
