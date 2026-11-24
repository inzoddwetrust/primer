"""A refusal before execution, as ``--json`` prints it (DM-138).

A refusal is not a command: exit 1, no verdict (contract 2). The console gets
a line on stderr, as ever; with ``--json`` stdout gets this object too, for
the agent that ran the verb for the Panel's queue: what refused the run and
why, in a form a program reads. The codes are a closed list, one per refusal
that has a form; it grows with the cards that give a refusal its form.

``box-busy`` -- another command holds the box: ``holder`` is what the lock's
file says of it (its run, its verb, who ran it, since when, the Panel's
command), or ``holder_unread`` says why there is none to name: ``starting``
-- the lock was just taken and its file is being written; ``unreadable`` --
the file says something else. ``processes`` -- the processes that hold the
lock's descriptor now.

``python -m pridem.report.refusal --export`` writes its JSON Schema to
``contract/schema/cli-refusal.v1.json``.
"""

import argparse
import sys
from collections.abc import Sequence
from typing import Literal, Self

from pydantic import Field, TypeAdapter, model_validator

from pridem.contract import SCHEMA_DIR, ContractSchema, Strict, schema_text
from pridem.state import BoxBusy, LockHolder

CLI_REFUSAL_SCHEMA = "cli-refusal.v1.json"


class Refusal(Strict):
    """A refusal before execution (contract 2): its code, and what it knows."""

    refused: Literal["box-busy"]
    holder: LockHolder | None = Field(default=None, exclude_if=lambda v: v is None)
    holder_unread: Literal["starting", "unreadable"] | None = Field(
        default=None, exclude_if=lambda v: v is None
    )
    processes: list[str]

    @model_validator(mode="after")
    def _holder_or_why(self) -> Self:
        if (self.holder is None) == (self.holder_unread is None):
            raise ValueError("box-busy names its holder or why it cannot")
        return self


def busy(refused: BoxBusy) -> Refusal:
    """The refusal of a busy box, from what the lock said."""
    fields: dict[str, object] = {
        "refused": "box-busy",
        "processes": list(refused.processes),
    }
    if refused.holder is not None:  # one of the two, never a null
        fields["holder"] = refused.holder
    if refused.unread is not None:
        fields["holder_unread"] = refused.unread
    return Refusal.model_validate(fields)


def rendered(refusal: Refusal) -> str:
    """The refusal as ``--json`` prints it: one object."""
    return refusal.model_dump_json(by_alias=True)


def rendered_schema() -> str:
    return schema_text(
        TypeAdapter(Refusal).json_schema(
            mode="validation", schema_generator=ContractSchema
        ),
        "cli refusal v1",
    )


def main(argv: Sequence[str]) -> int:
    """``--export`` writes the schema of a refusal to ``contract/schema/``."""
    parser = argparse.ArgumentParser(prog="python -m pridem.report.refusal")
    parser.add_argument("--export", action="store_true", required=True)
    parser.parse_args(argv)
    SCHEMA_DIR.mkdir(parents=True, exist_ok=True)
    target = SCHEMA_DIR / CLI_REFUSAL_SCHEMA
    target.write_text(rendered_schema(), encoding="utf-8")
    print(f"wrote {target}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
