"""Seams between the stacks of one box (TZ 7.1, 7.3; contract 3 rules 2, 13).

A seam is a ``provides`` of one stack and a ``seam`` variable of another. The
model allows two directions only: the product takes a seam ``from`` one of its
dependencies, a service takes a seam ``from: product`` (``_r13_seams``). What
a service provides is the value of the variable of the same name in its own
``env``, rendered for it, and it reaches the plan's memory after the
service's health (``SeamMemory.healthy``). What the product provides is a URL
from the passport (``ProvideUrl``: ``https://<domain><path>``) or a verb
(``ProvideVerb``, not a value): known before any health. So the order of
providers is the services of the edition, then the product, and no cycle can
be written; there is no cycle to look for.

A ``remote`` dependency is never a seam: the model refuses ``seam`` from it,
its values come from the passport as ``param`` and ``asked`` of the product.

``half_seams`` lists every seam with one end missing; a plan with one is
refused before its first ``act`` (``seams_check``).
"""

from collections.abc import Mapping

from pridem.stacks.passport import Passport
from pridem.stacks.schema import Product, ProvideUrl, ProvideVerb, Seam, Service

PRODUCT = "product"
"""The name a service's ``seam`` uses for the product."""


class SeamNotReady(Exception):
    """A seam was asked of a provider whose health has not been seen."""

    def __init__(self, provider: str, names: list[str]) -> None:
        self.provider = provider
        self.names = names
        super().__init__(f"{provider} is not healthy yet: {', '.join(names)}")


class DomainMissing(Exception):
    """A ``ProvideUrl`` names a domain the passport does not have."""

    def __init__(self, name: str) -> None:
        self.name = name
        super().__init__(f"domains.{name} is not in the passport")


def installed(product: Product, edition: str | None) -> list[str]:
    """The co-located dependencies the box installs, in the product's order.

    With ``editions`` declared, only the services of the passport's edition
    (contract 3 rule 11); a ``remote`` dependency is never installed (rule 13).
    """
    if product.editions:
        offer = product.editions.get(edition) if edition is not None else None
        chosen = set(offer.services) if offer is not None else set()
    else:
        chosen = set(product.dependencies)
    return [
        name
        for name, dependency in product.dependencies.items()
        if dependency.topology == "co-located" and name in chosen
    ]


def provider_order(product: Product, edition: str | None) -> list[str]:
    """Stacks in the order their seams are ready: services, then the product."""
    return [*installed(product, edition), product.name]


def half_seams(
    product: Product, services: Mapping[str, Service], edition: str | None
) -> list[str]:
    """Every seam of the box with one end missing, as ``<stack>.<NAME>: why``."""
    out: list[str] = []
    here = installed(product, edition)
    for key, var in product.env.items():
        if not isinstance(var, Seam) or var.from_ not in here:
            continue  # outside the edition: ``outside_edition``
        provider = services[var.from_]
        if key not in provider.provides:
            out.append(f"{product.name}.{key}: {var.from_} does not provide it")
    for name in here:
        service = services[name]
        for provided in service.provides:
            if provided not in service.env:
                out.append(f"{name}.{provided}: provided without an env key")
        for required in service.requires:
            offer = product.provides.get(required)
            if offer is None:
                out.append(f"{name}.{required}: the product does not provide it")
            elif isinstance(offer, ProvideVerb):
                out.append(f"{name}.{required}: the product provides a verb")
            if not isinstance(service.env.get(required), Seam):
                out.append(f"{name}.{required}: required, not a seam in env")
        for key, var in service.env.items():
            if isinstance(var, Seam) and key not in service.requires:
                out.append(f"{name}.{key}: a seam not in requires")
    return out


def outside_edition(product: Product, edition: str | None) -> list[str]:
    """Seams of the product from a co-located service the edition leaves out."""
    here = set(installed(product, edition))
    return [
        f"{product.name}.{key}: {var.from_}"
        for key, var in product.env.items()
        if isinstance(var, Seam)
        and product.dependencies[var.from_].topology == "co-located"
        and var.from_ not in here
    ]


def product_value(product: Product, passport: Passport, name: str) -> str:
    """The value of the product's ``provides`` ``name``: a URL from the passport."""
    offer = product.provides[name]
    if not isinstance(offer, ProvideUrl):
        raise ValueError(f"{name} is a verb of the product, not a value")
    domain = offer.from_.removeprefix("domains.")
    host = passport.domains.get(domain)
    if host is None:
        raise DomainMissing(domain)
    return f"https://{host}{offer.path}"


class SeamMemory:
    """Values of the services' ``provides`` for the time of one plan."""

    def __init__(self) -> None:
        self._values: dict[str, dict[str, str]] = {}

    def healthy(self, provider: str, values: Mapping[str, str]) -> None:
        """``provider`` passed its health: its ``provides`` are ready."""
        self._values[provider] = dict(values)

    def values(self, provider: str, names: list[str]) -> dict[str, str]:
        """The seams ``names`` of ``provider``; ``SeamNotReady`` before health."""
        ready = self._values.get(provider)
        if ready is None:
            raise SeamNotReady(provider, names)
        missing = [name for name in names if name not in ready]
        if missing:
            raise SeamNotReady(provider, missing)
        return {name: ready[name] for name in names}
