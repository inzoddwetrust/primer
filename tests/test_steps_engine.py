"""The reader of the Engine API (DM-207) against a real unix socket: a
thread answers one request with the bytes a test gives it and keeps what was
asked. No docker, no command: the reader is the standard library alone.
"""

import json
import shutil
import socket
import tempfile
import threading
from collections.abc import Iterator
from pathlib import Path

import pytest

from pridem.steps.engine import (
    SOCKET,
    CacheRecord,
    EngineUnread,
    build_cache,
)


def _http(body: bytes, status: str = "200 OK") -> bytes:
    head = (
        f"HTTP/1.1 {status}\r\nContent-Type: application/json\r\n"
        f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n"
    )
    return head.encode() + body


def _answer(document: object) -> bytes:
    return _http(json.dumps(document).encode())


class Daemon:
    """A daemon's socket under a root short enough for a unix address
    (108 bytes: pytest's ``tmp_path`` is longer). It answers each connection
    with ``reply``; ``None`` -- it reads the request and says nothing."""

    def __init__(self) -> None:
        self.root = Path(tempfile.mkdtemp(prefix="dm207-", dir="/tmp"))  # noqa: S108
        path = self.root / SOCKET
        path.parent.mkdir(parents=True)
        self._server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._server.bind(str(path))
        self._server.listen(4)
        self.reply: bytes | None = b""
        self.asked: list[str] = []
        self._held: list[socket.socket] = []
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self) -> None:
        while True:
            try:
                peer, _ = self._server.accept()
            except OSError:
                return
            request = b""
            while b"\r\n\r\n" not in request:
                piece = peer.recv(4096)
                if not piece:
                    break
                request += piece
            self.asked.append(request.decode())
            if self.reply is None:
                self._held.append(peer)  # silent until the test ends
                continue
            peer.sendall(self.reply)
            peer.close()

    def close(self) -> None:
        self._server.shutdown(socket.SHUT_RDWR)  # wakes the thread's accept
        self._server.close()
        for peer in self._held:
            peer.close()
        self._thread.join(timeout=5)
        shutil.rmtree(self.root)


@pytest.fixture
def daemon() -> Iterator[Daemon]:
    made = Daemon()
    yield made
    made.close()


def test_the_records_are_read_in_bytes_by_one_get(daemon: Daemon) -> None:
    """Three records as the daemon of velo-dev gives them, other fields and
    all: their bytes and their two flags, nothing rounded. The request is one
    ``GET /system/df`` and nothing else."""
    daemon.reply = _answer(
        {
            "LayersSize": 5,
            "BuildCache": [
                {"ID": "a", "Size": 3_214_263_003, "InUse": False, "Shared": False},
                {"ID": "b", "Size": 236_958_336, "InUse": False, "Shared": True},
                {"ID": "c", "Size": 0, "InUse": True, "Shared": False},
            ],
        }
    )
    assert build_cache(daemon.root) == [
        CacheRecord(3_214_263_003, in_use=False, shared=False),
        CacheRecord(236_958_336, in_use=False, shared=True),
        CacheRecord(0, in_use=True, shared=False),
    ]
    [request] = daemon.asked
    assert request.splitlines()[0] == "GET /system/df HTTP/1.1"
    assert "Content-Length" not in request  # no body: it reads, never writes


@pytest.mark.parametrize("records", [None, []])
def test_a_cache_with_no_record_is_empty_not_unread(
    daemon: Daemon, records: object
) -> None:
    """Twin EMPTINESS: ``null`` is what the daemon writes for an empty list."""
    daemon.reply = _answer({"BuildCache": records})
    assert build_cache(daemon.root) == []


@pytest.mark.parametrize(
    "reply",
    [
        pytest.param(
            _http(b'{"message": "no"}', "500 Internal Server Error"), id="500"
        ),
        pytest.param(_http(b'{"BuildCache": []}', "404 Not Found"), id="404"),
        pytest.param(_http(b"not json"), id="not-json"),
        pytest.param(_http(b"[1, 2]"), id="not-an-object"),
        pytest.param(_answer({"Images": []}), id="no-BuildCache"),
        pytest.param(_answer({"BuildCache": {"a": 1}}), id="not-a-list"),
        pytest.param(_answer({"BuildCache": ["a"]}), id="record-not-an-object"),
        pytest.param(
            _answer({"BuildCache": [{"InUse": False, "Shared": False}]}),
            id="no-Size",
        ),
        pytest.param(
            _answer({"BuildCache": [{"Size": "1GB", "InUse": False, "Shared": False}]}),
            id="Size-a-text",
        ),
        pytest.param(
            _answer({"BuildCache": [{"Size": True, "InUse": False, "Shared": False}]}),
            id="Size-a-flag",
        ),
        pytest.param(
            _answer({"BuildCache": [{"Size": -1, "InUse": False, "Shared": False}]}),
            id="Size-negative",
        ),
        pytest.param(
            _answer({"BuildCache": [{"Size": 1.5, "InUse": False, "Shared": False}]}),
            id="Size-not-whole",
        ),
        pytest.param(
            _answer({"BuildCache": [{"Size": 1, "Shared": False}]}), id="no-InUse"
        ),
        pytest.param(
            _answer({"BuildCache": [{"Size": 1, "InUse": 0, "Shared": False}]}),
            id="InUse-a-number",
        ),
        pytest.param(
            _answer({"BuildCache": [{"Size": 1, "InUse": False}]}), id="no-Shared"
        ),
        pytest.param(b"what is this\r\n\r\n", id="not-http"),
        pytest.param(b"", id="closed-with-no-answer"),
        pytest.param(
            b"HTTP/1.1 200 OK\r\nContent-Length: 500\r\n\r\n{", id="answer-cut-short"
        ),
    ],
)
def test_an_answer_that_is_not_the_records_is_unread(
    daemon: Daemon, reply: bytes
) -> None:
    """Twin SHORTAGE: nothing is guessed from an answer that is not the
    records -- no record is taken for zero, no text for a number. The pair is
    the test above: the same socket with the records."""
    daemon.reply = reply
    with pytest.raises(EngineUnread):
        build_cache(daemon.root)


def test_a_record_beside_a_bad_one_is_not_half_a_measure(daemon: Daemon) -> None:
    """One record without its size among good ones: no sum of the rest."""
    good = {"Size": 7, "InUse": False, "Shared": False}
    daemon.reply = _answer({"BuildCache": [good, {"InUse": False, "Shared": False}]})
    with pytest.raises(EngineUnread):
        build_cache(daemon.root)


def test_no_daemon_is_an_os_error(tmp_path: Path) -> None:
    """No socket under the root: ``OSError``, which ``gc`` turns into
    ``not-started`` -- not an empty cache."""
    with pytest.raises(FileNotFoundError):
        build_cache(tmp_path)


def test_a_daemon_that_says_nothing_ends_at_the_timeout(daemon: Daemon) -> None:
    daemon.reply = None
    with pytest.raises(TimeoutError):
        build_cache(daemon.root, timeout=0.2)
    assert len(daemon.asked) == 1
