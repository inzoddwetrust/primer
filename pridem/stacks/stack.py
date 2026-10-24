"""A stack as an object, and the composition a verdict carries.

A stack is a unit described by its own ``primer.yaml`` -- a product or a
service; one class holds both, the kind is a field. Its name in a composition
is the ``name`` of its ``primer.yaml``; its value is the commit of a product or
the release version of a service from ``primer.lock``. A ``remote`` dependency
is not installed on the box, but the product works against it, so it enters
the composition under its dependency name with the version the lock pins
(contract 3 rule 13, section 5).

A composition (contract 2, ``Composition``) is every stack, ``pridem`` with the
machine's version, and every package of the passport under its slot with
``<repo>@<version>``, where ``<repo>`` is the base name of the package
repository without the account and ``.git`` (contract 3 rule 10): the owner of a
partner's repository never reaches the history. Names share one namespace; a
collision -- two stacks of one name, a stack or a slot named ``pridem``, a stack
named as a slot -- is refused, every collision in one refusal.
"""

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Literal

from pydantic import TypeAdapter

from pridem.report.schema import Composition
from pridem.stacks.lock import LockEntry
from pridem.stacks.passport import Package
from pridem.stacks.schema import Product, Service

MACHINE = "pridem"
_COMPOSITION: TypeAdapter[dict[str, str]] = TypeAdapter(Composition)


class CompositionCollision(ValueError):
    """Two parts of a composition claim one name."""

    def __init__(self, problems: Sequence[str]) -> None:
        self.problems = tuple(problems)
        super().__init__("composition names collide: " + "; ".join(self.problems))


@dataclass(frozen=True)
class Stack:
    """One deployable unit: a product or a service."""

    name: str
    kind: Literal["product", "service"]
    version: str
    remote: bool = False

    @classmethod
    def product(cls, yaml: Product, commit: str) -> "Stack":
        """The product at ``commit``."""
        return cls(yaml.name, "product", commit)

    @classmethod
    def service(cls, yaml: Service, pin: LockEntry) -> "Stack":
        """A co-located service at the release the lock pins."""
        return cls(yaml.name, "service", pin.version)

    @classmethod
    def remote_service(cls, dependency: str, pin: LockEntry) -> "Stack":
        """A remote dependency: not installed here, pinned by the lock."""
        return cls(dependency, "service", pin.version, remote=True)


def repo_name(repo: str) -> str:
    """``git@github.com:partner-x/velo-look.git`` -> ``velo-look``."""
    last = repo.rstrip("/").replace(":", "/").rsplit("/", 1)[-1]
    return last.removesuffix(".git")


def composition(
    stacks: Sequence[Stack], *, machine_version: str, packages: Mapping[str, Package]
) -> dict[str, str]:
    """The composition of a box; ``CompositionCollision`` names every clash."""
    problems: list[str] = []
    seen: set[str] = set()
    for stack in stacks:
        if stack.name in seen:
            problems.append(f"two stacks are named {stack.name!r}")
        seen.add(stack.name)
        if stack.name == MACHINE:
            problems.append(f"a stack is named {MACHINE!r}, the machine's key")
        if stack.name in packages:
            problems.append(f"stack {stack.name!r} has the name of a package slot")
    if MACHINE in packages:
        problems.append(f"a package slot is named {MACHINE!r}, the machine's key")
    if problems:
        raise CompositionCollision(problems)
    out = {stack.name: stack.version for stack in stacks}
    out[MACHINE] = machine_version
    for slot, package in packages.items():
        out[slot] = f"{repo_name(package.repo)}@{package.version}"
    return _COMPOSITION.validate_python(out)
