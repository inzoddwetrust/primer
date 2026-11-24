"""The envelope of a verdict beyond its probes (DM-140): the grid of the gate.

Verdicts are the machine's own: runs of ``register`` through the command
line against the stand-in Panel of DM-139 -- red before the registration,
green, with a command of the Panel -- and, where the grid needs a content no
cheap run gives (a word in Cyrillic, a moment), a verdict of such a run
changed through contract 2's model and written by ``Box.write_verdict``, as
the machine writes every verdict. The one hand-made file is the form of
another version of the machine (``verdict-reshaped``).
"""

import base64
import io
import json
import os
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from identity_support import (
    OTHER_TOKEN,
    TOKEN,
    FakePanel,
    Ran,
    box_root,
    register,
    with_passport,
)

from pridem import identity
from pridem.agent.envelope import CODES, EnvelopeRefused, envelope
from pridem.cli import run
from pridem.events import Json, Secrets
from pridem.protocol import VerdictEnvelope, verdict_bytes
from pridem.report.render import render_llm
from pridem.report.schema import Verdict
from pridem.runner import FakeRunner
from pridem.state import Box
from pridem.verbs.register import TOKEN_ENV
from pridem.verbs.report import machine_catalog

COMMAND = "6f1c2d8e-4b7a-4e0f-9a3d-2c5b8e1f7a90"

# --- helpers -------------------------------------------------------------------


def _build(fs_root: Path, run_id: str) -> VerdictEnvelope:
    return envelope(box_root(fs_root), run_id, owner=os.geteuid())


def _refused(fs_root: Path, run_id: str) -> EnvelopeRefused:
    with pytest.raises(EnvelopeRefused) as caught:
        _build(fs_root, run_id)
    assert caught.value.code in CODES
    return caught.value


def _holds(fs_root: Path, got: VerdictEnvelope) -> None:
    """The signature holds by the box's public half over the history file."""
    seed = identity.key_path(box_root(fs_root)).read_bytes()
    raw = base64.b64decode(identity.public_key(seed))
    file = box_root(fs_root) / "history" / f"{got.verdict.run_id}.json"
    found = json.loads(file.read_text(encoding="utf-8"))
    public = Ed25519PublicKey.from_public_bytes(raw)
    public.verify(base64.b64decode(got.signature), verdict_bytes(found))


def _history(fs_root: Path, run_id: str) -> Path:
    return box_root(fs_root) / "history" / f"{run_id}.json"


def _rewritten(fs_root: Path, run_id: str, new_id: str, **update: object) -> str:
    """The verdict ``run_id`` changed through the model and written as the
    machine writes every verdict, under ``new_id``."""
    box = Box(box_root(fs_root))
    verdict = box.read_verdict(run_id)
    changed = Verdict.model_validate(
        {
            **verdict.model_dump(mode="json"),
            **update,
            "run_id": new_id,
            "log_ref": f"journal/{new_id}.jsonl",
        }
    )
    with box.lock("test"):
        box.write_verdict(changed)
    return new_id


def _registered_after_a_refusal(
    fs_root: Path, monkeypatch: pytest.MonkeyPatch
) -> tuple[str, str]:
    """A refused registration, then a registration by the clock of the box:
    the two runs."""
    with_passport(fs_root)
    panel = FakePanel()
    before = register(fs_root, monkeypatch, panel, token=OTHER_TOKEN, now=_clock)
    taken = register(fs_root, monkeypatch, panel, token=TOKEN, now=_clock)
    assert taken.code == 0, taken.err
    return str(before.verdict()["run_id"]), str(taken.verdict()["run_id"])


def _clock() -> datetime:
    return datetime.now(UTC)


def _cli(fs_root: Path, monkeypatch: pytest.MonkeyPatch, *argv: str) -> Ran:
    monkeypatch.setenv(TOKEN_ENV, TOKEN)
    out, err = io.StringIO(), io.StringIO()
    code = run(
        list(argv),
        root=box_root(fs_root),
        out=out,
        err=err,
        runner=FakeRunner(),
        fs_root=fs_root,
    )
    return Ran(code, out.getvalue(), err.getvalue())


# --- signed_on_send ----------------------------------------------------------------


def test_signed_on_send_is_a_verdict_that_ended_before_the_registration(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A verdict that ended a second before ``registered_at`` -- signed on
    send; the verdict of ``register`` itself -- not. KNOWN CEILING of
    ``pridem.agent.envelope``: one that ended in the second the box
    registered in is marked as written with the key."""
    _, taken = _registered_after_a_refusal(tmp_path, monkeypatch)
    registration = identity.read_registration(box_root(tmp_path))
    assert registration is not None
    at = datetime.fromisoformat(registration.registered_at)
    a_second_before = _moment(at - timedelta(seconds=1))
    early = _rewritten(
        tmp_path,
        taken,
        "2026-11-24T12:00:00Z-0002",
        started=a_second_before,
        finished=a_second_before,
    )
    same = _rewritten(
        tmp_path,
        taken,
        "2026-11-24T12:00:00Z-0001",
        started=_moment(at),
        finished=_moment(at),
    )
    built = [_build(tmp_path, run_id) for run_id in (early, same, taken)]
    assert [got.signed_on_send for got in built] == [True, False, False]
    for got in built:
        _holds(tmp_path, got)


def _moment(at: datetime) -> str:
    return at.strftime("%Y-%m-%dT%H:%M:%SZ")


# --- the verdicts -------------------------------------------------------------------


def test_a_red_verdict_and_one_of_a_command_get_their_envelopes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    before, taken = _registered_after_a_refusal(tmp_path, monkeypatch)
    ran = _cli(tmp_path, monkeypatch, "--json", "--command", COMMAND, "register")
    commanded = str(ran.verdict()["run_id"])
    assert ran.verdict()["command"] == COMMAND and ran.verdict()["result"] == "red"
    for run_id in (before, taken, commanded):
        got = _build(tmp_path, run_id)
        _holds(tmp_path, got)
    assert _build(tmp_path, commanded).verdict.command == COMMAND


def test_a_verdict_in_cyrillic_is_signed_over_its_utf_8(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A project verb's argument in Cyrillic (``pridem verb set-setting
    value=привет``): the bytes carry it in UTF-8, not as ``\\u`` escapes."""
    _, taken = _registered_after_a_refusal(tmp_path, monkeypatch)
    word = _rewritten(
        tmp_path, taken, "2026-11-24T12:00:00Z-00a1", args={"value": "привет"}
    )
    got = _build(tmp_path, word)
    _holds(tmp_path, got)
    signed = verdict_bytes(got.verdict.model_dump(mode="json"))
    assert "привет".encode() in signed and b"\\u" not in signed


def test_the_report_is_what_report_llm_prints(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    before, _ = _registered_after_a_refusal(tmp_path, monkeypatch)
    printed = _cli(tmp_path, monkeypatch, "report", before, "--llm")
    assert printed.code == 0, printed.err
    got = _build(tmp_path, before)
    assert got.report_llm + "\n" == printed.out
    assert "the Panel does not know the token" in got.report_llm


def test_an_evicted_journal_is_a_report_with_none(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    before, _ = _registered_after_a_refusal(tmp_path, monkeypatch)
    (box_root(tmp_path) / "journal" / f"{before}.jsonl").unlink()
    printed = _cli(tmp_path, monkeypatch, "report", before, "--llm")
    got = _build(tmp_path, before)
    assert got.report_llm + "\n" == printed.out


def test_a_journal_with_a_damaged_header_is_a_report_with_none(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    before, _ = _registered_after_a_refusal(tmp_path, monkeypatch)
    journal = box_root(tmp_path) / "journal" / f"{before}.jsonl"
    journal.write_bytes(b"\xff not a header\n")
    got = _build(tmp_path, before)
    verdict = Box(box_root(tmp_path)).read_verdict(before)
    assert got.report_llm == render_llm(verdict, None, Secrets(()), machine_catalog())
    _holds(tmp_path, got)


def test_the_envelope_is_the_same_twice_and_writes_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _, taken = _registered_after_a_refusal(tmp_path, monkeypatch)
    root = box_root(tmp_path)
    seen = {
        p: (p.read_bytes(), p.stat().st_mtime_ns)
        for p in root.rglob("*")
        if p.is_file()
    }
    first, second = _build(tmp_path, taken), _build(tmp_path, taken)
    assert first == second
    after = {
        p: (p.read_bytes(), p.stat().st_mtime_ns)
        for p in root.rglob("*")
        if p.is_file()
    }
    assert after == seen


# --- the refusals -------------------------------------------------------------------


def test_a_box_not_registered_gets_no_envelope(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with_passport(tmp_path)
    ran = register(tmp_path, monkeypatch, FakePanel(), token=OTHER_TOKEN)
    assert identity.key_path(box_root(tmp_path)).is_file()  # the key, no registration
    assert _refused(tmp_path, str(ran.verdict()["run_id"])).code == "not-registered"


def test_a_damaged_registration_gets_no_envelope(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _, taken = _registered_after_a_refusal(tmp_path, monkeypatch)
    identity.registration_path(box_root(tmp_path)).write_text("{")
    assert _refused(tmp_path, taken).code == "registration-damaged"


def test_no_key_gets_no_envelope(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _, taken = _registered_after_a_refusal(tmp_path, monkeypatch)
    identity.key_path(box_root(tmp_path)).unlink()
    assert _refused(tmp_path, taken).code == "no-key"


def test_a_damaged_key_gets_no_envelope_before_the_verdict_is_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The order of the checks: the key before the verdict -- a damaged key
    and a damaged verdict are ``key-damaged``."""
    _, taken = _registered_after_a_refusal(tmp_path, monkeypatch)
    identity.key_path(box_root(tmp_path)).chmod(0o644)
    _history(tmp_path, taken).write_text("{")
    refused = _refused(tmp_path, taken)
    assert (refused.code, refused.params) == ("key-damaged", {"cause": "mode"})


@pytest.mark.parametrize(
    "run_id", ["2026-11-24T12:00:00Z-ffff", "../agent/registration", "x", ""]
)
def test_no_verdict_of_the_run_gets_no_envelope(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, run_id: str
) -> None:
    _registered_after_a_refusal(tmp_path, monkeypatch)
    assert _refused(tmp_path, run_id).code == "no-verdict"


@pytest.mark.parametrize(
    "content",
    [b"", b"\xff\xfe", b"{", b"[]", b'{"schema": 1}'],
    ids=["empty", "not utf-8", "cut", "a list", "not the model"],
)
def test_a_damaged_verdict_gets_no_envelope(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, content: bytes
) -> None:
    _, taken = _registered_after_a_refusal(tmp_path, monkeypatch)
    _history(tmp_path, taken).write_bytes(content)
    assert _refused(tmp_path, taken).code == "verdict-damaged"


def test_a_verdict_the_model_writes_otherwise_gets_no_envelope(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The form of another version of the machine: a ``float`` written as an
    integer (``"duration_s": 0``). The model reads it and dumps ``0.0``: the
    envelope would carry a verdict other than the file's -- none is built. The
    pair: the same file with ``0.0`` gets its envelope."""
    _, taken = _registered_after_a_refusal(tmp_path, monkeypatch)
    file = _history(tmp_path, taken)
    data = json.loads(file.read_text(encoding="utf-8"))
    data["steps"][0]["duration_s"] = 0
    file.write_text(json.dumps(data, indent=2), encoding="utf-8")
    Verdict.model_validate_json(file.read_text(encoding="utf-8"))  # the model reads it
    assert _refused(tmp_path, taken).code == "verdict-reshaped"
    data["steps"][0]["duration_s"] = 0.0
    file.write_text(json.dumps(data, indent=2), encoding="utf-8")
    _holds(tmp_path, _build(tmp_path, taken))


# --- the bytes ----------------------------------------------------------------------


def test_verdict_bytes_sort_every_level_with_no_spaces_in_utf_8() -> None:
    given: dict[str, Json] = {"b": {"d": 1, "c": [2, {"f": 3, "e": 4}]}, "a": "я"}
    expected = '{"a":"я","b":{"c":[2,{"e":4,"f":3}],"d":1}}'.encode()
    assert verdict_bytes(given) == expected


def test_sign_verdict_signs_the_bytes_of_the_contract(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _, taken = _registered_after_a_refusal(tmp_path, monkeypatch)
    seed = identity.key_path(box_root(tmp_path)).read_bytes()
    found = json.loads(_history(tmp_path, taken).read_text(encoding="utf-8"))
    assert identity.sign_verdict(seed, found) == identity.sign(
        seed, verdict_bytes(found)
    )
