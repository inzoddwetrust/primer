"""Contract 3 section 5: ``primer.lock`` -- model and the check against ``primer.yaml``.

Rule 3: dependencies are ranges in ``primer.yaml``; ``primer.lock`` pins each to
a release: version ``X.Y.Z``, tag ``vX.Y.Z`` equal to it, commit sha. Remote
dependencies are pinned too (the machine compares the pin with ``/health.release``
of the live service). That tags exist and point at the commits is checked
against git later, not here.
"""

import re
from datetime import datetime
from pathlib import Path
from typing import Annotated

from packaging.specifiers import SpecifierSet
from packaging.version import Version
from pydantic import Field, TypeAdapter, ValidationError

from pridem.stacks.loader import (
    ContractError,
    Problem,
    field_problems,
    load_yaml_mapping,
)
from pridem.stacks.schema import (
    Name,
    Product,
    SchemaVersion,
    Strict,
    problem_at,
)

_COMMIT = re.compile(r"[0-9a-f]{7,40}")


class LockEntry(Strict):
    version: Annotated[str, Field(pattern=r"^\d+\.\d+\.\d+$")]
    tag: Name
    commit: Name


class Lock(Strict):
    schema_: SchemaVersion = Field(alias="schema")
    resolved_at: datetime
    dependencies: dict[Name, LockEntry] = {}


PRIMER_LOCK: TypeAdapter[Lock] = TypeAdapter(Lock)


def entry_problems(lock: Lock) -> list[Problem]:
    """Rule 3 within the lock: tag equals ``v{version}``; commit is a hex sha."""
    out: list[Problem] = []
    for name, entry in lock.dependencies.items():
        if entry.tag != f"v{entry.version}":
            out.append(
                problem_at(
                    ("dependencies", name, "tag"),
                    "R3.lock-tag",
                    f"tag {entry.tag!r} for version {entry.version!r}, "
                    f"expected 'v{entry.version}'",
                )
            )
        if not _COMMIT.fullmatch(entry.commit):
            out.append(
                problem_at(
                    ("dependencies", name, "commit"),
                    "R3.lock-commit",
                    repr(entry.commit),
                )
            )
    return out


def load_primer_lock(file: Path) -> Lock:
    """Load ``primer.lock``; raise ``ContractError`` with every problem."""
    data = load_yaml_mapping(file)
    try:
        lock = PRIMER_LOCK.validate_python(data)
    except ValidationError as error:
        raise ContractError(file, field_problems(data, error)) from error
    problems = entry_problems(lock)
    if problems:
        raise ContractError(file, problems)
    return lock


def check_lock(product: Product, lock: Lock) -> list[Problem]:
    """Rule 3 against ``primer.yaml``: same dependencies, versions in range."""
    out: list[Problem] = []
    declared, locked = set(product.dependencies), set(lock.dependencies)
    for name in sorted(declared - locked):
        out.append(
            problem_at(("dependencies", name), "R3.lock-set", f"{name!r} is not locked")
        )
    for name in sorted(locked - declared):
        out.append(
            problem_at(
                ("dependencies", name), "R3.lock-set", f"{name!r} is not a dependency"
            )
        )
    for name in sorted(declared & locked):
        version = lock.dependencies[name].version
        declared_range = product.dependencies[name].version
        if not SpecifierSet(declared_range).contains(Version(version)):
            out.append(
                problem_at(
                    ("dependencies", name, "version"),
                    "R3.lock-range",
                    f"{version} is outside {declared_range!r}",
                )
            )
    return out
