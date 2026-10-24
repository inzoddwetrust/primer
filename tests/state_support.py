"""Headers, verdicts and states for box tests (DM-7)."""

from datetime import UTC, datetime

from report_support import example, load

from pridem.events import Json, PlanMode
from pridem.report.schema import Verdict
from pridem.state import BoxState, JournalHeader

STARTED = datetime(2026, 10, 15, 10, 42, 7, tzinfo=UTC)
BEFORE = {"aivis": "8f0b21d", "comms": "3.0.0", "pridem": "0.3.1"}
AFTER = {"aivis": "9a1c4e2", "comms": "3.0.0", "pridem": "0.3.1"}


def run_id(n: int) -> str:
    return f"2026-10-15T10:42:{n:02d}Z-a3f9"


def header(
    run: str,
    *,
    args: dict[str, Json] | None = None,
    mode: PlanMode = "deploy",
    verb: str = "deploy",
) -> JournalHeader:
    return JournalHeader.model_validate(
        {
            "run_id": run,
            "verb": verb,
            "mode": mode,
            "args": {"ref": "9a1c4e2"} if args is None else args,
            "actor": {"type": "engineer", "via": "local"},
            "started": STARTED,
            "passport_version": 7,
            "composition_before": dict(BEFORE),
        }
    )


def verdict(run: str, *, verb: str = "deploy") -> Verdict:
    data = example()
    data["run_id"] = run
    data["log_ref"] = f"journal/{run}.jsonl"
    data["verb"] = verb
    if verb == "doctor":
        data["args"] = {}
        report = data["report"]
        assert isinstance(report, dict)
        report["doctor_diff"] = []
    return load(data)


def state(composition: dict[str, str] | None = None) -> BoxState:
    return BoxState(
        composition=dict(AFTER if composition is None else composition),
        passport_version=7,
        current={"aivis": "releases/9a1c4e2"},
        last_run={},
    )
