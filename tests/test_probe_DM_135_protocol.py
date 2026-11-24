"""The probes of DM-135: contract 4, the protocol of the agent.

Every message is read strictly -- a field the reader does not know is a
refusal -- and its version is the header's alone; the rule of versions takes
N and N-1. The samples are real: a verdict and a journal of a run of the
machine on the blank's box, the state of a box as ``pridem state`` makes it.
"""

import json
from collections.abc import Iterator

import pytest
from data_support import blank_box
from plan_support import Journal, ScriptedStep
from pydantic import ValidationError
from test_probe_DM_137_stream import _update

from pridem.contract import SCHEMA_DIR, Strict
from pridem.events import Json
from pridem.protocol import (
    AGENT_PROTOCOL_SCHEMA,
    MESSAGES,
    PROTOCOL_VERSION,
    Command,
    EventBatch,
    HeaderMissing,
    Heartbeat,
    RegisterRequest,
    VerdictEnvelope,
    accepts,
    rendered_schema,
    signed_headers,
    signing_string,
)

Body = dict[str, Json]

STATE: Body = {
    "schema": 1,
    "measured_at": "2026-11-24T10:00:00Z",
    "machine": {"version": "0.1.8"},
    "passport": {"unmeasured": "no-passport"},
    "lock_open_by": [],
    "journals_without_verdict": [],
    "stacks": [],
    "machine_stacks": {"unmeasured": "docker-unreachable"},
    "resources": {
        "disk": [{"path": "/", "space": {"total_bytes": 10, "free_bytes": 5}}],
        "memory": {"unmeasured": "meminfo-unreadable"},
        "swap": {"total_bytes": 0, "free_bytes": 0},
        "images": {"unmeasured": "docker-unreachable"},
    },
    "ssl": {"unmeasured": "no-passport"},
}
"""The state of a fresh box, as ``pridem state --json`` prints it."""


@pytest.fixture(scope="module")
def run(tmp_path_factory: pytest.TempPathFactory) -> Iterator[tuple[Body, list[Body]]]:
    """A run of the machine on the blank's box: its verdict and the lines of
    its journal, as the agent would read them."""
    root = tmp_path_factory.mktemp("box")
    blank_box(root)
    _, ref = _update(root, [ScriptedStep("first", 1, Journal())])
    home = root / "opt" / "pridem"
    lines = [json.loads(line) for line in (home / ref).read_text().splitlines()]
    verdict = json.loads((home / "history" / f"{lines[0]['run_id']}.json").read_text())
    yield verdict, lines


def _samples(verdict: Body, lines: list[Body]) -> dict[str, Body]:
    """A whole body of every message."""
    envelope: Body = {
        "verdict": verdict,
        "signature": "c2lnbmF0dXJl",
        "report_llm": "# update: green",
        "signed_on_send": False,
    }
    return {
        "Refusal": {"code": "token-used"},
        "RegisterRequest": {
            "token": "one-time-token",
            "server_name": "velo-dev",
            "role": "test",
            "product_repo": "git@github.com:a/velo.git",
            "machine_version": "0.1.8",
            "box_key_public": "ed25519 AAAA",
        },
        "RegisterResponse": {
            "box_id": "box-1",
            "agent_url": "https://api.primer.team/agent/v1/",
            "heartbeat_s": 30,
            "full_state_s": 300,
            "poll_s": 60,
        },
        "Heartbeat": {
            "measured_at": "2026-11-24T10:00:00Z",
            "machine_version": "0.1.8",
            "lock_open_by": [],
            "journals_without_verdict": [],
            "last_run_id": str(verdict["run_id"]),
            "state": STATE,
        },
        "Command": {
            "id": "cmd-1",
            "verb": "update",
            "args": {},
            "confirmed_at": "2026-11-24T10:00:00Z",
        },
        "CommandRefusal": {"code": "args-refused"},
        "EventBatch": {"from_seq": 1, "events": list[Json](lines)},
        "EventsAccepted": {"last_seq": len(lines)},
        "VerdictEnvelope": envelope,
        "HistoryBatch": {"envelopes": [envelope]},
        "HistoryAccepted": {"run_ids": [verdict["run_id"]]},
    }


NAMES = [model.__name__ for model in MESSAGES]
BY_NAME: dict[str, type[Strict]] = {model.__name__: model for model in MESSAGES}


# --- probes -----------------------------------------------------------------------


@pytest.mark.parametrize("name", NAMES)
def test_probe_DM_135_a_foreign_field_is_refused(
    run: tuple[Body, list[Body]], name: str
) -> None:
    """Every message, read from its JSON as the other side gets it: a field
    the reader does not know is a refusal. The pair: the same message without
    it is read."""
    body = _samples(*run)[name]
    model = BY_NAME[name]
    model.model_validate_json(json.dumps(body))
    with pytest.raises(ValidationError, match="extra_forbidden|Extra inputs"):
        model.model_validate_json(json.dumps({**body, "unknown_field": 1}))


def test_probe_DM_135_protocol_versions_n_and_n_minus_1() -> None:
    """The Panel reads ``PROTOCOL_VERSION`` and the one before it; older is
    ``protocol-too-old``, newer ``protocol-too-new``. Version 1 is the first:
    there is no version 0 -- the probe "N-1 is read" on the messages comes
    with version 2 (owner's word of 24.11)."""
    assert PROTOCOL_VERSION == 1
    assert accepts(1) is None
    assert accepts(0) == "protocol-too-old"
    assert accepts(2) == "protocol-too-new"


# --- around the probes ------------------------------------------------------------


REQUESTS = [
    "RegisterRequest",
    "Heartbeat",
    "CommandRefusal",
    "EventBatch",
    "VerdictEnvelope",
    "HistoryBatch",
]
"""The bodies of the requests a box sends."""


@pytest.mark.parametrize("name", REQUESTS)
def test_the_version_is_never_in_a_body(
    run: tuple[Body, list[Body]], name: str
) -> None:
    """The version of the protocol is the header's alone: a body that carries
    ``protocol_version`` is refused, as any foreign field."""
    body = _samples(*run)[name]
    with pytest.raises(ValidationError):
        BY_NAME[name].model_validate_json(json.dumps({**body, "protocol_version": 1}))


@pytest.mark.parametrize("name", NAMES)
def test_a_missing_field_or_an_explicit_null_is_refused(
    run: tuple[Body, list[Body]], name: str
) -> None:
    """Twin SHORTAGE: a body without its first field, or with a null in it."""
    body = _samples(*run)[name]
    first = next(iter(body))
    without = {key: value for key, value in body.items() if key != first}
    with pytest.raises(ValidationError):
        BY_NAME[name].model_validate_json(json.dumps(without))
    with pytest.raises(ValidationError):
        BY_NAME[name].model_validate_json(json.dumps({**body, first: None}))


def test_the_light_heartbeat_has_no_state(run: tuple[Body, list[Body]]) -> None:
    """The light heartbeat is the full one without ``state``; ``state`` is
    the form ``box-state.v1``, never a free object."""
    body = _samples(*run)["Heartbeat"]
    light = {key: value for key, value in body.items() if key != "state"}
    assert Heartbeat.model_validate_json(json.dumps(light)).state is None
    full = Heartbeat.model_validate_json(json.dumps(body))
    assert full.state is not None and full.state.machine.version == "0.1.8"
    broken = {**body, "state": {"schema": 1}}
    with pytest.raises(ValidationError):
        Heartbeat.model_validate_json(json.dumps(broken))


def test_an_event_is_a_line_of_the_journal(run: tuple[Body, list[Body]]) -> None:
    """Every line of a real journal -- the header, the steps, the end -- is an
    event of a batch; a line of no form of the journal is refused, and so is
    a ``from_seq`` that is not the first event's."""
    _, lines = run
    assert [line["event"] for line in lines][0] == "header"
    assert lines[-1]["event"] == "run_finished"
    batch = EventBatch.model_validate_json(json.dumps({"from_seq": 1, "events": lines}))
    assert [event.seq for event in batch.events] == list(range(1, len(lines) + 1))
    tail = EventBatch.model_validate_json(
        json.dumps({"from_seq": 2, "events": lines[1:]})
    )
    assert tail.events[0].seq == 2
    with pytest.raises(ValidationError, match="from_seq"):
        EventBatch.model_validate_json(json.dumps({"from_seq": 3, "events": lines[1:]}))
    odd = {**lines[1], "event": "something"}
    with pytest.raises(ValidationError):
        EventBatch.model_validate_json(json.dumps({"from_seq": 2, "events": [odd]}))
    empty = EventBatch.model_validate_json(json.dumps({"from_seq": 5, "events": []}))
    assert empty.events == []


def test_the_envelope_carries_contract_2s_verdict(run: tuple[Body, list[Body]]) -> None:
    """The verdict in the envelope is the model of contract 2, as
    ``history/`` holds it: a verdict that model refuses is refused here."""
    verdict, lines = run
    body = _samples(verdict, lines)["VerdictEnvelope"]
    read = VerdictEnvelope.model_validate_json(json.dumps(body))
    assert read.verdict.run_id == verdict["run_id"]
    broken = {**body, "verdict": {**verdict, "result": "yellow"}}
    with pytest.raises(ValidationError):
        VerdictEnvelope.model_validate_json(json.dumps(broken))
    as_text = {**body, "verdict": json.dumps(verdict)}
    with pytest.raises(ValidationError):
        VerdictEnvelope.model_validate_json(json.dumps(as_text))


@pytest.mark.parametrize(
    ("model", "field", "value"),
    [
        (RegisterRequest, "role", "staging"),
        (Command, "confirmed_at", "2026-11-24 10:00"),
    ],
)
def test_a_value_of_another_form_is_refused(
    run: tuple[Body, list[Body]], model: type[Strict], field: str, value: str
) -> None:
    body = _samples(*run)[model.__name__]
    with pytest.raises(ValidationError):
        model.model_validate_json(json.dumps({**body, field: value}))


def test_codes_are_a_closed_list(run: tuple[Body, list[Body]]) -> None:
    """A refusal or a command refusal with a code of no list is refused."""
    samples = _samples(*run)
    for name in ("Refusal", "CommandRefusal"):
        with pytest.raises(ValidationError):
            BY_NAME[name].model_validate_json(json.dumps({"code": "teapot"}))
        BY_NAME[name].model_validate_json(json.dumps(samples[name]))


def test_the_signing_string() -> None:
    """``method \\n path \\n time \\n sha256(body)`` -- the literal; the
    version's header is not in it."""
    got = signing_string("post", "/agent/v1/heartbeat", 1764000000, b'{"a":1}')
    assert got == (
        "POST\n/agent/v1/heartbeat\n1764000000\n"
        "015abd7f5cc57a2dd94b7590f04ad8084273905ee33ec5cebeae62276a97f862"
    )
    assert signing_string("GET", "/agent/v1/commands/next", 1, b"").endswith(
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    )


def test_the_signed_headers() -> None:
    """All four headers, any case: read. One missing, a time or a version
    that is not a whole number: ``HeaderMissing``."""
    headers = {
        "X-Primer-Box": "box-1",
        "x-primer-time": "1764000000",
        "X-Primer-Signature": "c2ln",
        "X-Primer-Protocol": "1",
    }
    read = signed_headers(headers)
    assert (read.box, read.time, read.protocol) == ("box-1", 1764000000, 1)
    for name in headers:
        with pytest.raises(HeaderMissing):
            signed_headers({k: v for k, v in headers.items() if k != name})
    for name, value in (("x-primer-time", "17.5"), ("X-Primer-Protocol", "one")):
        with pytest.raises(HeaderMissing):
            signed_headers({**headers, name: value})


def test_the_schema_on_disk_is_the_export_of_the_models() -> None:
    on_disk = (SCHEMA_DIR / AGENT_PROTOCOL_SCHEMA).read_text(encoding="utf-8")
    assert on_disk == rendered_schema(), "python -m pridem.protocol --export"
    names = set(json.loads(on_disk)["$defs"])
    assert {model.__name__ for model in MESSAGES} <= names
    assert {"Verdict", "BoxSnapshot", "HeaderLine", "RunFinishedLine"} <= names


def test_every_message_is_in_the_list() -> None:
    """Twin EMPTINESS: the list of messages is the module's models -- a
    message left out of it would be left out of the schema."""
    import pridem.protocol as protocol

    models = {
        value
        for value in vars(protocol).values()
        if isinstance(value, type)
        and issubclass(value, Strict)
        and value.__module__ == "pridem.protocol"
        and value.__name__ != "SignedHeaders"
    }
    assert models == set(MESSAGES)
