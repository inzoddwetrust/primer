"""The probes of DM-139: the box's key and its registration in the Panel by a
one-time token.

Each probe runs ``pridem --json register`` through the command line on a box
with its passport copy, against the Panel's side of contract 4 as
``primer-panel@f503ef6`` holds it (``identity_support.FakePanel``: the token
one-time, the key read as 32 raw bytes by ``cryptography``). The registration
runs no command: the ``FakeRunner`` is a strict empty scenario, and every
probe holds what did happen beside it -- the Panel's requests, the files on
the box, the verdict.
"""

import base64
import os
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from identity_support import (
    OTHER_TOKEN,
    TOKEN,
    FakePanel,
    box_root,
    register,
    with_passport,
)

from pridem import identity


def test_probe_DM_139_registered_key_0600_and_id_written(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A registration with a token: the key on the box, 32 bytes, 0600, the
    machine's; ``box_id`` and the agent's address written as the Panel
    answered; the public half the Panel keeps is the key's -- a signature of
    the box holds by it."""
    with_passport(tmp_path)
    panel = FakePanel()
    ran = register(tmp_path, monkeypatch, panel)
    assert ran.code == 0, ran.err
    assert ran.verdict()["result"] == "green"
    root = box_root(tmp_path)
    key = identity.key_path(root)
    found = os.lstat(key)
    assert (found.st_mode & 0o777, found.st_uid, found.st_size) == (
        0o600,
        os.geteuid(),
        32,
    )
    registration = identity.read_registration(root)
    assert registration is not None
    assert registration.box_id == "box-1" and list(panel.keys) == ["box-1"]
    assert registration.agent_url == "https://api.primer.team/agent/v1/"
    assert len(panel.received) == 1
    public = Ed25519PublicKey.from_public_bytes(panel.keys["box-1"])
    seed = key.read_bytes()
    public.verify(base64.b64decode(identity.sign(seed, b"box")), b"box")


def test_probe_DM_139_used_token_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A token registers one box: the same token from a second box is the
    Panel's ``token-used``, and the second box writes no registration; the
    first box asked again is refused by itself, with no request."""
    first, second = tmp_path / "first", tmp_path / "second"
    for root in (first, second):
        with_passport(root)
    panel = FakePanel()
    assert register(first, monkeypatch, panel).code == 0
    panel.names.clear()  # another server's name: the token alone refuses
    again = register(second, monkeypatch, panel)
    assert again.code == 1 and again.reason("register") == "register:token-used"
    assert identity.read_registration(box_root(second)) is None
    assert len(panel.received) == 2 and list(panel.keys) == ["box-1"]
    repeat = register(first, monkeypatch, panel)
    assert repeat.code == 1 and repeat.reason("register") == "register:already"
    assert len(panel.received) == 2


def test_probe_DM_139_foreign_token_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A token the Panel never issued is ``token-unknown``: no registration
    on the box, nothing kept by the Panel; the key minted stays for the next
    token."""
    with_passport(tmp_path)
    panel = FakePanel()
    ran = register(tmp_path, monkeypatch, panel, token=OTHER_TOKEN)
    assert ran.code == 1 and ran.verdict()["result"] == "red"
    assert ran.reason("register") == "register:token-unknown"
    root = box_root(tmp_path)
    assert identity.read_registration(root) is None
    assert len(panel.received) == 1 and panel.keys == {}
    assert identity.key_path(root).is_file()


def test_probe_DM_139_key_not_minted_twice(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The key minted by a registration the Panel refused is the key of the
    next one: the same bytes on the box, the same public half to the Panel,
    ``minted`` true once."""
    with_passport(tmp_path)
    panel = FakePanel()
    refused = register(tmp_path, monkeypatch, panel, token=OTHER_TOKEN)
    key = identity.key_path(box_root(tmp_path))
    minted = key.read_bytes()
    taken = register(tmp_path, monkeypatch, panel, token=TOKEN)
    assert taken.code == 0, taken.err
    assert key.read_bytes() == minted
    sent = {got.json()["box_key_public"] for got in panel.received}
    assert sent == {identity.public_key(minted)} and len(panel.received) == 2
    minted_by = [ran.fact("box_key")["minted"] for ran in (refused, taken)]
    assert minted_by == [True, False]
