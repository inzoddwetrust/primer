"""The docker Engine API, read in process over the daemon's unix socket.

``gc`` holds the build cache to a budget of bytes (REVIEW-0006 B18), and the
docker CLI prints sizes rounded to four digits (``3.451GB``: a step of a
megabyte). The bytes themselves are in the Engine API: ``GET /system/df``,
its ``BuildCache`` -- one record per cache entry with ``Size``, ``InUse`` and
``Shared``. Measured on docker 29.1.3 (velo-dev, 26.11): 115 records,
3 451 221 339 bytes, where the CLI said ``3.451GB``.

The request is made with the standard library alone, by this process: no
other tool, no command of the runner. It reads and never writes.
"""

import http.client
import json
import socket
from dataclasses import dataclass
from pathlib import Path

SOCKET = Path("var/run/docker.sock")
"""The daemon's socket, under the root of the file system."""
TIMEOUT_S = 120.0
"""For the connection and for each read: the daemon walks its disk usage."""
ANSWER_LIMIT = 64 * 1024**2
"""The most bytes of an answer that are read."""
_DF = "/system/df"


class EngineUnread(ValueError):
    """The daemon answered what the measurement cannot be read from."""


@dataclass(frozen=True)
class CacheRecord:
    """One entry of the build cache, as the daemon counts it."""

    size: int
    in_use: bool
    shared: bool


class _UnixConnection(http.client.HTTPConnection):
    """HTTP over a unix socket; the host is a name for the header alone."""

    def __init__(self, path: Path, timeout: float) -> None:
        super().__init__("localhost", timeout=timeout)
        self._path = path

    def connect(self) -> None:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            sock.settimeout(self.timeout)
            sock.connect(str(self._path))
        except OSError:
            sock.close()
            raise
        self.sock = sock


def _get(path: Path, target: str, timeout: float) -> bytes:
    connection = _UnixConnection(path, timeout)
    try:
        connection.request("GET", target)
        answer = connection.getresponse()
        body = answer.read(ANSWER_LIMIT + 1)
    except http.client.HTTPException as error:
        raise EngineUnread(f"{target}: {type(error).__name__}") from error
    finally:
        connection.close()
    if answer.status != http.client.OK:
        raise EngineUnread(f"{target}: status {answer.status}")
    if len(body) > ANSWER_LIMIT:
        raise EngineUnread(f"{target}: more than {ANSWER_LIMIT} bytes")
    return body


def build_cache(root: Path, *, timeout: float = TIMEOUT_S) -> list[CacheRecord]:
    """The records of the build cache, by ``GET /system/df`` of the daemon
    whose socket is under ``root``. A daemon nobody can reach is an
    ``OSError``; an answer that is not the records -- another status, not
    JSON, no ``BuildCache``, a record without its ``Size`` in bytes or its two
    flags -- ``EngineUnread``. ``BuildCache: null`` is a cache with no record:
    what the daemon writes for an empty list."""
    body = _get(root / SOCKET, _DF, timeout)
    try:
        answer = json.loads(body)
    except ValueError as error:
        raise EngineUnread(f"{_DF}: not JSON") from error
    if not isinstance(answer, dict) or "BuildCache" not in answer:
        raise EngineUnread(f"{_DF}: no BuildCache")
    records = answer["BuildCache"]
    if records is None:
        return []
    if not isinstance(records, list):
        raise EngineUnread(f"{_DF}: BuildCache is not a list")
    found: list[CacheRecord] = []
    for record in records:
        if not isinstance(record, dict):
            raise EngineUnread(f"{_DF}: a record of BuildCache is not an object")
        size, in_use, shared = (record.get(k) for k in ("Size", "InUse", "Shared"))
        if (
            not isinstance(size, int)
            or isinstance(size, bool)
            or size < 0
            or not isinstance(in_use, bool)
            or not isinstance(shared, bool)
        ):
            raise EngineUnread(f"{_DF}: a record without Size, InUse and Shared")
        found.append(CacheRecord(size, in_use, shared))
    return found
