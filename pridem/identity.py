"""The box's identity (``PRIMER-PANEL-TZ-2`` 3, 4; DM-139): its key and its
registration in the Panel, and the signature of the agent's requests.

Both live in ``/opt/pridem/agent/`` (0700):

- ``box.key`` -- the seed of the box's ed25519 key, its 32 raw bytes, 0600,
  owned by the machine's user. It is minted once, by a link that never
  replaces a file already there (``atomic_write(exclusive=True)``): the Panel
  knows the box by its public half, and a key minted over it would be another
  box. A key that is not a regular file, not 32 bytes, not 0600 or not the
  machine's is damaged: refused, never fixed by ``chmod`` and never minted
  over (``KeyDamaged``).
- ``registration.json`` -- what the Panel answered the registration: the
  box's ``box_id``, where the agent goes (``agent_url``), its intervals, the
  Panel registered in and when. Written once, by the same link.

The Panel holds the public half alone (``PRIMER-PANEL-TZ-2`` 3): it reads
``box_key_public`` as the base64 of the key's 32 raw bytes, and a signature as
the base64 of its 64 raw bytes (gate of DM-153). A request of the agent is
signed over ``signing_string`` of contract 4 (``pridem.protocol``) in UTF-8 --
the bytes the Panel checks. The seed is never in a fact, a log, a reason or a
message: what leaves this module of it is the public half and signatures.
"""

import base64
import os
import stat
from pathlib import Path
from typing import Annotated, Literal

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)
from pydantic import Field, ValidationError

from pridem.contract import Strict
from pridem.files import atomic_write, private_dir
from pridem.protocol import (
    BOX_HEADER,
    PROTOCOL_HEADER,
    PROTOCOL_VERSION,
    SIGNATURE_HEADER,
    TIME_HEADER,
    RegisterResponse,
    signing_string,
)
from pridem.report.box_snapshot import Moment
from pridem.report.schema import Text

AGENT_DIR = "agent"
KEY_FILE = "box.key"
REGISTRATION_FILE = "registration.json"
KEY_BYTES = 32
MODE = 0o600
REGISTRATION_MAX = 64 * 1024
"""A registration is a few hundred bytes; a bigger file is not one."""

KeyCause = Literal["not-a-file", "size", "mode", "owner"]


class KeyDamaged(Exception):
    """The box's key is there and cannot be used: ``cause`` says why."""

    def __init__(self, cause: KeyCause) -> None:
        super().__init__(cause)
        self.cause: KeyCause = cause


class RegistrationDamaged(Exception):
    """``registration.json`` is there and cannot be read as a registration."""


class Registration(Strict):
    """``registration.json``: the Panel's answer to the registration, the
    Panel it came from and when."""

    box_id: Text
    agent_url: Annotated[str, Field(pattern=r"^https://[^\s]+/agent/v1/$")]
    heartbeat_s: Annotated[int, Field(ge=1)]
    full_state_s: Annotated[int, Field(ge=1)]
    poll_s: Annotated[int, Field(ge=1)]
    panel: Text
    registered_at: Moment


def agent_dir(root: Path) -> Path:
    """``/opt/pridem/agent`` of the box whose root is ``root``."""
    return root / AGENT_DIR


def key_path(root: Path) -> Path:
    return agent_dir(root) / KEY_FILE


def registration_path(root: Path) -> Path:
    return agent_dir(root) / REGISTRATION_FILE


def present(path: Path) -> bool:
    """Something is at ``path`` -- a dangling symlink included."""
    return path.is_symlink() or path.exists()


def load_seed(root: Path, owner: int) -> bytes:
    """The seed of the box's key; ``KeyDamaged`` when it cannot be used.
    The file is opened without following a link and judged by what was
    opened; no key at all is ``FileNotFoundError``."""
    path = key_path(root)
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError as error:
        if path.is_symlink():  # O_NOFOLLOW: ELOOP
            raise KeyDamaged("not-a-file") from error
        raise
    found = os.fstat(fd)
    if not stat.S_ISREG(found.st_mode):  # a directory, a FIFO: never read
        os.close(fd)
        raise KeyDamaged("not-a-file")
    with os.fdopen(fd, "rb") as file:
        if found.st_mode & 0o777 != MODE:
            raise KeyDamaged("mode")
        if found.st_uid != owner:
            raise KeyDamaged("owner")
        seed = file.read(KEY_BYTES + 1)
    if len(seed) != KEY_BYTES:
        raise KeyDamaged("size")
    return seed


def read_seed(root: Path, owner: int) -> bytes | None:
    """The seed, or ``None`` when the box has no key; ``KeyDamaged`` as
    ``load_seed``."""
    if not present(key_path(root)):
        return None
    return load_seed(root, owner)


def mint_key(root: Path) -> None:
    """Mint the box's key: a new seed, 0600, by a link that refuses a file
    already at its name (``FileExistsError``) -- a key is never replaced."""
    private_dir(agent_dir(root))
    seed = Ed25519PrivateKey.generate().private_bytes(
        Encoding.Raw, PrivateFormat.Raw, NoEncryption()
    )
    atomic_write(key_path(root), seed, MODE, exclusive=True)


def public_key(seed: bytes) -> str:
    """The public half of the key: base64 of its 32 raw bytes."""
    key = Ed25519PrivateKey.from_private_bytes(seed).public_key()
    return base64.b64encode(key.public_bytes(Encoding.Raw, PublicFormat.Raw)).decode()


def sign(seed: bytes, message: bytes) -> str:
    """The signature of ``message`` by the box's key: base64 of 64 bytes."""
    signature = Ed25519PrivateKey.from_private_bytes(seed).sign(message)
    return base64.b64encode(signature).decode()


def signed_headers(
    seed: bytes, box_id: str, method: str, path: str, body: bytes, time: int
) -> dict[str, str]:
    """The headers of a request of the agent signed by the box: its
    ``box_id``, the time (UTC seconds), the signature of ``signing_string``
    and the protocol's version (not signed, see ``pridem.protocol``). ``path``
    is the request's path as sent, ``/agent/v1/...`` with no query. The
    Panel's reader of these headers is ``pridem.protocol.signed_headers``."""
    message = signing_string(method, path, time, body).encode("utf-8")
    return {
        BOX_HEADER: box_id,
        TIME_HEADER: str(time),
        SIGNATURE_HEADER: sign(seed, message),
        PROTOCOL_HEADER: str(PROTOCOL_VERSION),
    }


def read_registration(root: Path) -> Registration | None:
    """The box's registration, or ``None`` when it has none;
    ``RegistrationDamaged`` when the file cannot be read as one."""
    path = registration_path(root)
    if not present(path):
        return None
    if path.is_symlink() or not path.is_file():
        raise RegistrationDamaged
    try:
        with path.open("rb") as file:
            raw = file.read(REGISTRATION_MAX + 1)
    except OSError:
        raise RegistrationDamaged from None
    if len(raw) > REGISTRATION_MAX:
        raise RegistrationDamaged
    try:
        return Registration.model_validate_json(raw)
    except ValidationError:
        raise RegistrationDamaged from None


def registration_of(answer: RegisterResponse, panel: str, at: str) -> Registration:
    """What the box keeps of the Panel's answer."""
    return Registration(
        box_id=answer.box_id,
        agent_url=answer.agent_url,
        heartbeat_s=answer.heartbeat_s,
        full_state_s=answer.full_state_s,
        poll_s=answer.poll_s,
        panel=panel,
        registered_at=at,
    )


def write_registration(root: Path, registration: Registration) -> None:
    """``registration.json``, 0600, by a link: never over another one."""
    private_dir(agent_dir(root))
    text = registration.model_dump_json(exclude_none=True)
    atomic_write(registration_path(root), text + "\n", MODE, exclusive=True)
