"""Options of an instance (contract 3 rules 36-41, contract 1, protocol 5.2.3).

An option is a capability an instance turns on across editions: a channel of
comms, a module of the product, a channel on transition. A service declares
the options it knows, the product those its instances may have and those it
needs (``options_required``), the passport those on. An option of a service
the product does not declare is off on the product's instances.

A variable under ``when: <option>`` that is off holds the literal
``primer-switched-off``: nothing is asked, minted, derived or read from a seam
for it; a dependency under an option that is off is neither fetched nor
installed; a host of ``egress`` is open when it is a plain name or one of its
options is on. Code learns of an option only by its flag: the source
``passport``, key ``options.<option>`` -- ``true`` or ``false``.
"""

from collections.abc import Collection

from pridem.stacks.passport import Passport
from pridem.stacks.schema import Product, Service

LITERAL = "primer-switched-off"
"""The value of a variable of an option that is off -- one for every stack."""

FLAG = "options."
"""The prefix of a flag: the source ``passport``, key ``options.<option>``."""


def switched_on(passport: Passport) -> frozenset[str]:
    """The options on: the passport's. Each is one of the product's --
    ``seams_check`` refuses any other before the first ``act``
    (``option-outside-product``) -- so an option of a service the product
    does not declare is never on (rule 36)."""
    return frozenset(passport.options or ())


def off(when: str | None, on: Collection[str]) -> bool:
    """A variable or a dependency under ``when`` whose option is off."""
    return when is not None and when not in on


def off_keys(stack: Product | Service, on: Collection[str]) -> list[str]:
    """The keys of ``stack.env`` under an option that is off, in its order."""
    return [key for key, var in stack.env.items() if off(var.when, on)]


def flag(key: str, on: Collection[str]) -> str:
    """The value of the flag ``options.<option>``: ``true`` or ``false``."""
    return "true" if key.removeprefix(FLAG) in on else "false"


def open_hosts(product: Product, on: Collection[str]) -> list[str]:
    """The hosts of ``egress`` the proxy lets through: a plain name, or one
    with an option on (rule 40); in the order of ``egress``."""
    return [
        entry if isinstance(entry, str) else entry.host
        for entry in product.egress
        if isinstance(entry, str) or any(option in on for option in entry.when)
    ]
