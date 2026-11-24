"""The state of a box, one form for the console and the Panel (DM-136).

``pridem state`` measures it and prints it; ``status`` prints it after its
verdict; the agent will send it in its heartbeat (DM-141). It is read, never
written: no lock, no journal, no verdict, nothing in ``history/``.

Every field is a fact measured on the box when the form was made
(``measured_at``) -- by docker, ``openssl``, ``/proc/meminfo``, ``statvfs``,
the files of the box -- and never from ``state.json``, which is a record, not
a ground (TZ 7.3). A part that could not be measured is ``{"unmeasured":
"<code>"}`` in its place, never a default value.

``python -m pridem.report.box_snapshot --export`` writes its JSON Schema to
``contract/schema/box-state.v1.json``.
"""

import argparse
import sys
from collections.abc import Sequence
from typing import Annotated, Literal

from pydantic import Field, TypeAdapter

from pridem.contract import SCHEMA_DIR, ContractSchema, Strict, schema_text

BOX_STATE_SCHEMA = "box-state.v1.json"

Moment = Annotated[str, Field(pattern=r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$")]
"""A moment in UTC to the second: ``2026-11-24T10:42:07Z``."""

Bytes = Annotated[int, Field(ge=0)]

UnmeasuredCode = Literal[
    "no-passport",
    "passport-unreadable",
    "docker-unreachable",
    "no-current",
    "primer-yaml-unreadable",
    "compose-unread",
    "path-missing",
    "meminfo-unreadable",
    "no-certificate",
    "certificate-unreadable",
    "renewed-by-passport",
]


class Unmeasured(Strict):
    """A part that was not measured, and why -- never a default value."""

    unmeasured: UnmeasuredCode


class Machine(Strict):
    version: str


class PassportPart(Strict):
    """The version of the box's passport copy; nothing else of it -- no
    value of ``asked`` -- is in the form."""

    version: Annotated[int, Field(ge=1)]


ContainerState = Literal[
    "running", "exited", "restarting", "paused", "created", "dead", "removing", "absent"
]
"""docker's ``State.Status`` of the container; ``absent`` -- the service is in
the compose of the current release and has no container."""

Health = Literal["healthy", "unhealthy", "starting", "none"]
"""docker's ``State.Health.Status``; ``none`` -- the container has no
healthcheck, or no container."""


class ServiceState(Strict):
    service: str
    state: ContainerState
    health: Health


class EntryPart(Strict):
    """An entry of a stack (``stacks.<entry>`` of its ``primer.yaml``): every
    service of the compose of its current release, by its container."""

    entry: str
    persistent: bool
    services: list[ServiceState] | Unmeasured


class StackPart(Strict):
    """A stack with the machine's mark on the box (``/opt/<stack>/.pridem``):
    the release ``current`` points to, and each of its entries."""

    stack: str
    release: str | Unmeasured
    entries: list[EntryPart] | Unmeasured


class MachineStackPart(Strict):
    """A stack of the machine's own (``pridem-edge``, ``pridem-egress``) by
    the containers that carry its label."""

    stack: str
    services: list[ServiceState]


class Space(Strict):
    total_bytes: Bytes
    free_bytes: Bytes


class Disk(Strict):
    path: str
    space: Space | Unmeasured


class Memory(Strict):
    total_bytes: Bytes
    available_bytes: Bytes


class Swap(Strict):
    """``total_bytes`` 0 -- the box has no swap."""

    total_bytes: Bytes
    free_bytes: Bytes


class Images(Strict):
    """docker's line ``Images`` of ``system df``: every image of the box."""

    count: Annotated[int, Field(ge=0)]
    bytes: Bytes
    reclaimable_bytes: Bytes


class Resources(Strict):
    disk: list[Disk]
    memory: Memory | Unmeasured
    swap: Swap | Unmeasured
    images: Images | Unmeasured


class DomainPart(Strict):
    """A domain of the passport, and whether the box's one certificate names
    it (a wildcard covers one label)."""

    domain: str
    covered: bool


class SslPart(Strict):
    """The one certificate nginx serves for every domain: its end, whether it
    signs itself, from when the machine renews it (``RENEW_BEFORE`` ahead of
    its end, the daily timer) -- in ``provided`` the passport brings a new
    one, never the machine."""

    mode: Literal["letsencrypt", "self-signed", "defer", "provided"]
    expires: Moment
    self_signed: bool
    renews_from: Moment | Unmeasured
    domains: list[DomainPart]


class BoxSnapshot(Strict):
    """The state of a box, measured at ``measured_at``.

    ``lock_open_by`` -- the processes that hold the file of the box's lock
    open, read from ``/proc``: an open file of the lock, not a test of
    ``flock`` (taking the lock, even for a moment, is a write). A command
    running, or a process it left behind -- never more.

    ``journals_without_verdict`` -- the journals in ``journal/`` that have no
    verdict in ``history/``. A run going on now and a run that died are not
    told apart: the lock keeps the name of a verb, not a ``run_id``. The
    next command under the lock (``recover``) gives a dead run its verdict.
    """

    schema_: Literal[1] = Field(alias="schema")
    measured_at: Moment
    machine: Machine
    passport: PassportPart | Unmeasured
    lock_open_by: list[str]
    journals_without_verdict: list[str]
    stacks: list[StackPart] | Unmeasured
    machine_stacks: list[MachineStackPart] | Unmeasured
    resources: Resources
    ssl: SslPart | Unmeasured


def rendered_schema() -> str:
    """The JSON Schema text of the box's state, exported from the model."""
    return schema_text(
        TypeAdapter(BoxSnapshot).json_schema(
            mode="validation", schema_generator=ContractSchema
        ),
        "box state v1",
    )


def main(argv: Sequence[str]) -> int:
    """``--export`` writes the schema of the box's state to ``contract/schema/``."""
    parser = argparse.ArgumentParser(prog="python -m pridem.report.box_snapshot")
    parser.add_argument("--export", action="store_true", required=True)
    parser.parse_args(argv)
    SCHEMA_DIR.mkdir(parents=True, exist_ok=True)
    target = SCHEMA_DIR / BOX_STATE_SCHEMA
    target.write_text(rendered_schema(), encoding="utf-8")
    print(f"wrote {target}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
