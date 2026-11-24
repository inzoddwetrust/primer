"""Batches of journal lines for the tests of contract 4 (DM-189).

A line is the form the machine's journal writes (``step_started``, DM-137):
only its ``seq`` changes from line to line, as the agent reads a journal and
sends it in batches.
"""

from pridem.events import Json
from pridem.protocol import EventBatch

LINE: dict[str, Json] = {
    "event": "step_started",
    "at": "2026-11-24T20:58:34.174Z",
    "phase": "main",
    "stack": "pridem-identity",
    "name": "box_key",
    "order": 1,
    "started": "2026-11-24T20:58:34.174071Z",
}


def batch(seqs: list[int]) -> EventBatch:
    """A batch of lines with ``seqs``, from the first of them."""
    events: list[Json] = [{**LINE, "seq": seq} for seq in seqs]
    return EventBatch.model_validate({"from_seq": seqs[0], "events": events})
