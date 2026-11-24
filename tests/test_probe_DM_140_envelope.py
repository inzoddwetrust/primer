"""The probes of DM-140: the signed envelope of a verdict.

A box registers in the stand-in Panel of DM-139 (``identity_support``), and
its verdict in ``history/`` gets its envelope (``pridem.agent.envelope``). The
signature is checked as the Panel checks it at ``primer-panel@8feebe7``
(``app/agent/signature.py``), by ``cryptography`` with the public half the
Panel holds from the registration -- the Panel's bytes written out here as a
literal, not imported: the envelope goes through JSON as the agent sends it
and is read by contract 4's model as the Panel reads it.
"""

import base64
import hashlib
import json
import os
from pathlib import Path

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from identity_support import (
    OTHER_TOKEN,
    FakePanel,
    box_root,
    register,
    with_passport,
)

from pridem.agent.envelope import envelope
from pridem.protocol import VerdictEnvelope, verdict_bytes
from pridem.report.schema import Verdict


def _panel_s_bytes(verdict: Verdict) -> bytes:
    """``verdict_bytes`` of the Panel at ``8feebe7``, word for word."""
    dumped = verdict.model_dump(mode="json")
    text = json.dumps(dumped, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return text.encode()


def _registered(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> tuple[FakePanel, str]:
    """A registered box: the Panel holding its public half, and the run of its
    ``register`` -- the second verdict of ``history/``, after a refused one."""
    with_passport(tmp_path)
    panel = FakePanel()
    refused = register(tmp_path, monkeypatch, panel, token=OTHER_TOKEN)
    assert refused.code == 1, refused.err
    ran = register(tmp_path, monkeypatch, panel)
    assert ran.code == 0, ran.err
    return panel, str(ran.verdict()["run_id"])


def _sent(tmp_path: Path, run_id: str) -> VerdictEnvelope:
    """The envelope as the Panel receives it: through JSON, by the model."""
    built = envelope(box_root(tmp_path), run_id, owner=os.geteuid())
    return VerdictEnvelope.model_validate_json(built.model_dump_json())


def test_probe_DM_140_envelope_holds_by_the_box_key(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The envelope's signature holds by the box's public half the Panel got
    at registration, over the bytes the Panel computes from the verdict it
    reads; the signature is 64 bytes."""
    panel, run_id = _registered(tmp_path, monkeypatch)
    got = _sent(tmp_path, run_id)
    signature = base64.b64decode(got.signature, validate=True)
    assert len(signature) == 64
    public = Ed25519PublicKey.from_public_bytes(panel.keys["box-1"])
    public.verify(signature, _panel_s_bytes(got.verdict))
    assert got.verdict.run_id == run_id and got.signed_on_send is False


def test_probe_DM_140_one_byte_spoils_the_signature(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """One byte of the verdict changed -- anywhere in its bytes: a key, a value,
    a sign of the form -- and the signature no longer holds. The pair: it holds
    over the bytes as they are."""
    panel, run_id = _registered(tmp_path, monkeypatch)
    got = _sent(tmp_path, run_id)
    public = Ed25519PublicKey.from_public_bytes(panel.keys["box-1"])
    signature = base64.b64decode(got.signature)
    signed = _panel_s_bytes(got.verdict)
    public.verify(signature, signed)
    for at in range(0, len(signed), max(1, len(signed) // 40)):
        spoiled = bytearray(signed)
        spoiled[at] ^= 0x01
        with pytest.raises(InvalidSignature):
            public.verify(signature, bytes(spoiled))
    edited = got.verdict.model_dump(mode="json")
    edited["verb"] = "registes"  # one letter of the verdict, read back as JSON
    with pytest.raises(InvalidSignature):
        public.verify(signature, verdict_bytes(edited))


def test_probe_DM_140_envelope_verdict_is_the_history_s(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The verdict inside the envelope is the one of ``history/``: the same
    bytes of contract 4 as the file read by ``json.loads``; the file and the
    run's journal are as they were before the envelope."""
    _, run_id = _registered(tmp_path, monkeypatch)
    root = box_root(tmp_path)
    file = root / "history" / f"{run_id}.json"
    journal = root / "journal" / f"{run_id}.jsonl"
    before = [(hashlib.sha256(p.read_bytes()).hexdigest(), p.stat().st_mtime_ns)
              for p in (file, journal)]  # fmt: skip
    got = _sent(tmp_path, run_id)
    in_history = verdict_bytes(json.loads(file.read_text(encoding="utf-8")))
    assert verdict_bytes(got.verdict.model_dump(mode="json")) == in_history
    assert _panel_s_bytes(got.verdict) == in_history
    after = [(hashlib.sha256(p.read_bytes()).hexdigest(), p.stat().st_mtime_ns)
             for p in (file, journal)]  # fmt: skip
    assert after == before
