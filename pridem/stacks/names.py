"""The names of the machine's own stacks -- of its plans, its journal lines and
its docker objects -- one source of truth (DM-102).

Every one starts with ``pridem-``: the field ``stack`` of a verdict is shared
with a product's entries, and the facts of a run are keyed by ``(stack,
name)``. A product may not take ``pridem`` or the prefix (contract 3 rule 67),
so no entry of a product can be named as a stack of the machine -- and a
product's entry ``frontend``, ``backup`` or ``edge`` is its own.
"""

MACHINE_PREFIX = "pridem-"

PRIDEM = "pridem"
"""The machine itself -- the stack of its own journal lines (the clock):
its name, reserved whole (gate of DM-102)."""

HOST = "pridem-host"
PASSPORT = "pridem-passport"
NETWORK = "pridem-network"
TIMERS = "pridem-timers"
SOURCES = "pridem-sources"
DEPENDENCIES = "pridem-dependencies"
ROLLBACK = "pridem-rollback"
SERVICES = "pridem-services"
"""Deferred: becomes the entries of the services and ``SEAMS``."""
PRODUCT = "pridem-product"
"""Deferred: becomes the entries of the product and ``SEAMS``."""
SEAMS = "pridem-seams"
EDGE = "pridem-edge"
FRONTEND = "pridem-frontend"
FINALIZE = "pridem-finalize"
DESTROY = "pridem-destroy"
STOPPED = "pridem-stopped"
BOX = "pridem-box"
BACKUP = "pridem-backup"
SEED = "pridem-seed"
VERDICT = "pridem-verdict"
"""The stack of a journal line about the verdict itself (its build)."""

MACHINE_STACKS: frozenset[str] = frozenset(
    {
        HOST, PASSPORT, NETWORK, TIMERS, SOURCES, DEPENDENCIES, ROLLBACK,
        SERVICES, PRODUCT, SEAMS, EDGE, FRONTEND, FINALIZE, DESTROY, STOPPED,
        BOX, BACKUP, SEED, VERDICT,
    }
)  # fmt: skip

HOST_LABEL = "pridem-host"
"""``pridem.stack`` of the machine's networks."""
EDGE_LABEL = "pridem-edge"
"""``pridem.stack`` of the edge's objects (its compose project's name)."""
EGRESS_LABEL = "pridem-egress"
"""``pridem.stack`` of the egress proxy's objects (its compose project's name)."""
