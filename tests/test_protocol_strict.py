"""Contract 4 stricter beyond its probes (DM-189): the grid of the gate.

The models of every message walked as a graph -- an alias is written as it
is read, a secret hides the input of an error; contract 4's own optional
fields are left out of a dump, contract 2's ``null`` kept; a command carries
its term.
"""

import json
import typing
from pathlib import Path
from typing import ClassVar

import pytest
from identity_support import FakePanel, box_root, register, with_passport
from pydantic import BaseModel, ConfigDict, Field, SecretStr, ValidationError
from test_probe_DM_135_protocol import STATE

from pridem.contract import Strict
from pridem.protocol import (
    MESSAGES,
    Command,
    CommandRefusal,
    EventBatch,
    Heartbeat,
    VerdictEnvelope,
    rendered_schema,
    verdict_bytes,
)
from pridem.report.box_snapshot import BoxSnapshot
from pridem.report.schema import Verdict
from pridem.state import Box

# --- the graph of the models ------------------------------------------------------


def _models(root: object, seen: set[type[BaseModel]]) -> set[type[BaseModel]]:
    """Every model reachable from ``root`` through the fields' annotations."""
    if isinstance(root, type) and issubclass(root, BaseModel):
        if root in seen:
            return seen
        seen.add(root)
        for field in root.model_fields.values():
            _models(field.annotation, seen)
        return seen
    for arg in typing.get_args(root):
        _models(arg, seen)
    return seen


def _graph() -> set[type[BaseModel]]:
    found: set[type[BaseModel]] = set()
    for message in MESSAGES:
        _models(message, found)
    return found


def _alias_unwritten(models: set[type[BaseModel]]) -> list[str]:
    """The models that read an alias and do not write it."""
    return sorted(
        model.__name__
        for model in models
        if any(field.alias for field in model.model_fields.values())
        and not model.model_config.get("serialize_by_alias")
    )


def _secret_shown(models: set[type[BaseModel]]) -> list[str]:
    """The models with a ``SecretStr`` whose errors show their input."""
    return sorted(
        model.__name__
        for model in models
        if any(
            SecretStr in (field.annotation, *typing.get_args(field.annotation))
            for field in model.model_fields.values()
        )
        and not model.model_config.get("hide_input_in_errors")
    )


def test_every_model_of_the_protocol_writes_the_alias_it_reads() -> None:
    graph = _graph()
    assert {BoxSnapshot, Verdict} <= graph
    assert _alias_unwritten(graph) == []
    assert BoxSnapshot.model_fields["schema_"].alias == "schema"


def test_the_walk_finds_a_model_that_reads_an_alias_it_does_not_write() -> None:
    """The pair of the walk: a model planted with an alias and no
    ``serialize_by_alias`` is named."""

    class Planted(Strict):
        schema_: int = Field(alias="schema")

    class Written(Strict):
        model_config = ConfigDict(serialize_by_alias=True)
        schema_: int = Field(alias="schema")

    assert _alias_unwritten(_models(Planted, set())) == ["Planted"]
    assert _alias_unwritten(_models(Written, set())) == []


def test_every_secret_of_the_protocol_hides_the_input_of_its_errors() -> None:
    graph = _graph()
    assert any(m.__name__ == "RegisterRequest" for m in graph)
    assert _secret_shown(graph) == []

    class Planted(Strict):
        token: SecretStr

    assert _secret_shown({Planted}) == ["Planted"]


def test_the_box_state_writes_schema_by_its_alias() -> None:
    """``model_dump`` with no ``by_alias`` -- as the Panel dumped a full
    heartbeat (FIX DM-153) -- gives ``schema``, never ``schema_``; the
    state read back from it is the same."""
    state = BoxSnapshot.model_validate(STATE)
    dumped = state.model_dump(mode="json")
    assert dumped["schema"] == 1 and "schema_" not in dumped
    assert BoxSnapshot.model_validate(dumped) == state
    assert state.model_dump_json(by_alias=True) == state.model_dump_json()


# --- absent, not null -----------------------------------------------------------


def test_contract_4_s_own_optional_fields_are_left_out_of_a_dump() -> None:
    command = Command.model_validate(
        {
            "id": "cmd-1",
            "verb": "update",
            "args": {},
            "expires_at": "2026-11-24T10:10:00Z",
        }
    )
    assert "confirmed_at" not in command.model_dump(mode="json")
    assert Command.model_validate(command.model_dump(mode="json")) == command
    beat = Heartbeat.model_validate(
        {
            "measured_at": "2026-11-24T10:00:00Z",
            "machine_version": "0.1.9",
            "lock_open_by": [],
            "journals_without_verdict": [],
        }
    )
    dumped = beat.model_dump(mode="json")
    assert "state" not in dumped and "last_run_id" not in dumped
    assert Heartbeat.model_validate_json(beat.model_dump_json()) == beat
    with pytest.raises(ValidationError):
        Heartbeat.model_validate({**dumped, "state": None})


def test_contract_2_s_null_stays_in_an_envelope(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A verdict with ``errno: null`` (a command that did not start, contract
    2): the envelope dumps it, the other side reads it, and the bytes of the
    signature are the file's -- no ``exclude_none`` anywhere."""
    with_passport(tmp_path)
    ran = register(tmp_path, monkeypatch, FakePanel())
    run_id = str(ran.verdict()["run_id"])
    box = Box(box_root(tmp_path))
    data = box.read_verdict(run_id).model_dump(mode="json")
    step = data["steps"][1]
    step["status"] = "failed"
    step["reason"] = {
        "code": "command-not-started",
        "argv": ["docker", "ps"],
        "errno": None,
    }
    step.pop("verify", None)
    data.update(
        {
            "run_id": "2026-11-24T12:00:00Z-0e11",
            "log_ref": "journal/2026-11-24T12:00:00Z-0e11.jsonl",
            "exit_code": 1,
            "result": "red",
        }
    )
    verdict = Verdict.model_validate(data)
    with box.lock("test"):
        box.write_verdict(verdict)
    text = (box.history / f"{verdict.run_id}.json").read_text(encoding="utf-8")
    assert '"errno": null' in text
    envelope = VerdictEnvelope(
        verdict=verdict, signature="c2ln", report_llm="r", signed_on_send=False
    )
    wire = envelope.model_dump_json()
    assert '"errno":null' in wire
    back = VerdictEnvelope.model_validate_json(wire)
    assert verdict_bytes(back.verdict.model_dump(mode="json")) == verdict_bytes(
        json.loads(text)
    )


# --- a command and its term -------------------------------------------------------


COMMAND = {"id": "cmd-1", "verb": "destroy", "args": {"confirm": "velo-dev"}}


@pytest.mark.parametrize(
    ("given", "read"),
    [
        ({"expires_at": "2026-11-24T10:10:00Z"}, True),
        ({}, False),
        (
            {
                "expires_at": "2026-11-24T10:10:00Z",
                "confirmed_at": "2026-11-24T10:09:59Z",
            },
            True,
        ),
        (
            {
                "expires_at": "2026-11-24T10:10:00Z",
                "confirmed_at": "2026-11-24T10:10:00Z",
            },
            True,
        ),
        (
            {
                "expires_at": "2026-11-24T10:10:00Z",
                "confirmed_at": "2026-11-24T10:10:01Z",
            },
            False,
        ),
        ({"expires_at": None}, False),
    ],
)
def test_a_command_carries_its_term_and_a_confirmation_before_it(
    given: dict[str, object], read: bool
) -> None:
    body = json.dumps({**COMMAND, **given})
    if read:
        Command.model_validate_json(body)
    else:
        with pytest.raises(ValidationError):
            Command.model_validate_json(body)


def test_the_agent_refuses_an_expired_command_by_its_code() -> None:
    assert CommandRefusal.model_validate_json('{"code": "expired"}').code == "expired"


# --- the schema -----------------------------------------------------------------


def test_the_schema_says_the_token_is_a_secret_of_16_or_more() -> None:
    token = json.loads(rendered_schema())["$defs"]["RegisterRequest"]["properties"][
        "token"
    ]
    assert token == {
        "format": "password",
        "minLength": 16,
        "title": "Token",
        "type": "string",
        "writeOnly": True,
    }


# --- no explicit null in a dump (DM-141, part B) -------------------------------------


def _null_dumped(models: set[type[BaseModel]]) -> list[str]:
    """The fields that dump an explicit ``null``: ``None`` by default, no
    ``exclude_if``, not named in the model's ``NULLABLE`` (contract 2 keeps
    ``errno`` and ``ended_at`` null on purpose)."""
    found: list[str] = []
    for model in models:
        nullable: frozenset[str] = getattr(model, "NULLABLE", frozenset())
        for name, field in model.model_fields.items():
            if field.default is None and field.exclude_if is None:
                if name not in nullable:
                    found.append(f"{model.__name__}.{name}")
    return sorted(found)


def test_no_model_of_the_protocol_dumps_an_explicit_null() -> None:
    """The whole graph of ``MESSAGES`` -- the verdict, the box's state and the
    lines of a journal inside it."""
    graph = _graph()
    names = {model.__name__ for model in graph}
    assert {
        "Verdict",
        "BoxSnapshot",
        "StepFinishedLine",
        "KeyNeededNotice",
        "RecipientNeededNotice",
        "CommandNotStartedReason",
    } <= names
    assert _null_dumped(graph) == []


def test_the_walk_names_a_field_that_dumps_null() -> None:
    """The pair of the walk: a field ``None`` by default without
    ``exclude_if`` is named; with it, or named ``NULLABLE``, it is not."""

    class Planted(Strict):
        x: str | None = None

    class Left(Strict):
        x: str | None = Field(default=None, exclude_if=lambda v: v is None)

    class Named(Strict):
        NULLABLE: ClassVar[frozenset[str]] = frozenset({"x"})
        x: str | None = None

    assert _null_dumped({Planted, Left, Named}) == ["Planted.x"]


LINES = [
    '{"event": "header", "seq": 1, "at": "2026-11-25T10:00:00.000Z", '
    '"run_id": "2026-11-25T10:00:00Z-a3f9", "verb": "update", "mode": "deploy", '
    '"args": {}, "actor": {"type": "engineer", "via": "panel"}, '
    '"started": "2026-11-25T10:00:00Z", "composition_before": {"pridem": "0.1.10"}, '
    '"command": "cmd-1"}',
    '{"event": "step_started", "seq": 2, "at": "2026-11-25T10:00:00.001Z", '
    '"phase": "main", "stack": "pridem-host", "name": "provision_host", "order": 1, '
    '"started": "2026-11-25T10:00:00.001000Z"}',
    '{"event": "step_finished", "seq": 3, "at": "2026-11-25T10:00:01.000Z", '
    '"phase": "main", "stack": "pridem-host", "name": "provision_host", "order": 1, '
    '"status": "ok", "started": "2026-11-25T10:00:00.001000Z", "duration_s": 0.999, '
    '"verify": {"docker": "29.1.3"}}',
    '{"event": "notice", "seq": 4, "at": "2026-11-25T10:00:01.100Z", "notice": '
    '{"kind": "key_needed", "repo": "git@github.com:a/velo.git", '
    '"key": "ssh-ed25519 AAAA", "write": false, "wait_s": 30.0, "again": false}}',
    '{"event": "notice", "seq": 5, "at": "2026-11-25T10:00:01.200Z", "notice": '
    '{"kind": "recipient_needed", "key": "age1qyqszqgpqyqszqgp", "wait_s": 30.0}}',
    '{"event": "log", "seq": 6, "at": "2026-11-25T10:00:02.000Z", "phase": "main", '
    '"stack": "aivis", "name": "up", "stream": "stderr", "line": "no such service"}',
    '{"event": "step_finished", "seq": 7, "at": "2026-11-25T10:00:02.100Z", '
    '"phase": "main", "stack": "aivis", "name": "up", "order": 14, '
    '"status": "failed", "reason": {"code": "command-failed", '
    '"argv": ["docker", "compose", "up"], "exit_code": 1}}',
    '{"event": "run_finished", "seq": 8, "at": "2026-11-25T10:00:03.000Z", '
    '"exit_code": 1, "result": "red"}',
]
"""Lines of a journal as the machine writes them: steps ``ok`` and
``failed``, both notices with their optional fields absent, a line of log."""


def test_lines_of_a_journal_go_and_come_back_with_no_null() -> None:
    """The lines -> ``EventBatch`` -> its dump -> read strictly: the same
    batch, and no ``null`` on the wire."""
    body = '{"from_seq": 1, "events": [' + ", ".join(LINES) + "]}"
    batch = EventBatch.model_validate_json(body)
    wire = batch.model_dump_json()
    assert "null" not in wire
    assert EventBatch.model_validate_json(wire) == batch
    sent = json.loads(wire)["events"]
    for given, line in zip(LINES, sent, strict=True):
        written = json.loads(given)
        assert {k: v for k, v in line.items() if k in written} == written
