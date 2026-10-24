"""Contract 2 section 1 example as data and a verdict builder for tests (DM-4)."""

import copy
import json
from collections.abc import Mapping
from datetime import UTC, datetime

from pydantic import SecretStr

from pridem.events import Fact, Json, PlanOutcome, Secrets
from pridem.report.schema import Verdict, build_verdict

RUN_ID = "2026-10-15T10:42:07Z-a3f9"
STARTED = datetime(2026, 10, 15, 10, 42, 7, tzinfo=UTC)
FINISHED = datetime(2026, 10, 15, 10, 49, 19, tzinfo=UTC)
MARKER = "pridem-planted-secret-7c1e"
SECRETS = Secrets([SecretStr(MARKER)])

_EXAMPLE: dict[str, Json] = {
    "schema": 1,
    "run_id": RUN_ID,
    "verb": "deploy",
    "args": {"ref": "9a1c4e2"},
    "actor": {"type": "engineer", "via": "local"},
    "started": "2026-10-15T10:42:07Z",
    "finished": "2026-10-15T10:49:19Z",
    "exit_code": 0,
    "result": "green",
    "passport_version": 7,
    "composition_before": {
        "aivis": "8f0b21d",
        "comms": "3.0.0",
        "payments": "1.0.2",
        "pridem": "0.3.1",
    },
    "composition_after": {
        "aivis": "9a1c4e2",
        "comms": "3.0.0",
        "payments": "1.0.2",
        "pridem": "0.3.1",
    },
    "steps": [
        {
            "stack": "aivis",
            "name": "fetch_sources",
            "order": 4,
            "status": "ok",
            "started": "2026-10-15T10:42:08Z",
            "duration_s": 6.2,
            "verify": {"head": "9a1c4e2", "drift_discarded": []},
        },
        {
            "stack": "aivis",
            "name": "up_app",
            "order": 10,
            "status": "ok",
            "started": "2026-10-15T10:48:00Z",
            "duration_s": 18.0,
            "verify": {
                "image_id": "sha256:0f1e",
                "matches_fresh_build": True,
                "health": "ok",
                "ready": 200,
            },
        },
        {
            "stack": "aivis",
            "name": "tests",
            "order": 11,
            "status": "skipped",
            "reason": "role prod",
        },
    ],
    "report": {"failures": [], "incomplete": []},
    "junit": {"total": 1276, "failed": 0, "skipped": 3},
    "log_ref": f"journal/{RUN_ID}.jsonl",
}


def example() -> dict[str, Json]:
    """A fresh deep copy of the contract's example verdict."""
    return copy.deepcopy(_EXAMPLE)


def section(data: Mapping[str, Json], key: str) -> dict[str, Json]:
    value = data[key]
    assert isinstance(value, dict)
    return value


def items(data: Mapping[str, Json], key: str) -> list[Json]:
    value = data[key]
    assert isinstance(value, list)
    return value


def load(data: Mapping[str, Json]) -> Verdict:
    """Validate ``data`` the way ``history/`` is read: as JSON."""
    return Verdict.model_validate_json(json.dumps(data))


def build(
    outcome: PlanOutcome,
    *,
    verb: str = "deploy",
    args: Fact | None = None,
    failures: tuple[Fact, ...] = (),
    secrets: Secrets = SECRETS,
) -> Verdict:
    return build_verdict(
        outcome,
        run_id=RUN_ID,
        verb=verb,
        args={"ref": "9a1c4e2"} if args is None else args,
        actor={"type": "engineer", "via": "local"},
        started=STARTED,
        finished=FINISHED,
        passport_version=7,
        composition_before={"aivis": "8f0b21d", "pridem": "0.3.1"},
        composition_after={"aivis": "9a1c4e2", "pridem": "0.3.1"},
        secrets=secrets,
        failures=failures,
    )
