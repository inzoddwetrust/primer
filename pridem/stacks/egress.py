"""The list of external hosts agreed with Primer (protocol 4.2; DM-64).

A product has no way out to the internet: the networks of its stacks are
internal (protocol 4.1). In transition it declares ``egress`` -- the hosts it
still reaches itself -- and the machine's proxy lets it reach exactly those. A
host of ``egress`` must be a row of this list for that product: ``pridem
check`` and the box (``build``, before anything is built) refuse any other by
the same function, ``unlisted`` (protocol 10.1).

The list is the machine's data, one for every instance, changed by a release of
the machine: a new host is a row by the owner's word, a channel that moved to
comms or to an external service loses its row. A host is a name (contract of
``egress``, ``stacks/schema.py``); a row of one product admits nothing to
another.
"""

from dataclasses import dataclass

from pridem.stacks.schema import Product


@dataclass(frozen=True)
class Listed:
    """One row: a host a product may reach, the channel it serves, and what
    ends it."""

    host: str
    product: str
    channel: str
    until: str


LISTING: tuple[Listed, ...] = (
    Listed("zoom.us", "velo", "Zoom", "velo-meet"),
    Listed("api.zoom.us", "velo", "Zoom", "velo-meet"),
    Listed("oauth.telegram.org", "velo", "sign-in in a browser (OIDC)", "comms v4.x"),
    Listed("claude.ai", "velo", "MCP: CIMD", "comms v4.x"),
    Listed("chatgpt.com", "velo", "MCP: CIMD", "comms v4.x"),
    Listed("api.github.com", "primer-blank", "tier 3 probe of the proxy", "permanent"),
)
"""First edition, 03.11, the owner's word (card DM-64); the hosts of velo were
taken by velo from its own code. The blank's row under its own name,
``primer-blank`` (contract 3 rule 32), 06.11, the owner's word (card DM-70)."""


UNLISTED = "{hosts} of egress are not in the list agreed with Primer for {product}"
"""The text of ``egress-unlisted``, for ``build`` and ``pridem check`` alike."""


def listed(product: str) -> frozenset[str]:
    """The hosts of ``LISTING`` for ``product``."""
    return frozenset(row.host for row in LISTING if row.product == product)


def unlisted(product: Product) -> list[str]:
    """The hosts of ``product.egress`` that are not rows of ``LISTING`` for this
    product, in the order of ``egress``; empty -- every host is agreed."""
    allowed = listed(product.name)
    return [host for host in product.egress if host not in allowed]
