"""``primer-package.yaml``: what a data package of an instance says about itself.

A package (``skin``, ``texts``; contract 3 rule 10) is a repository tagged
``v<version>`` (passport rule 9). In the root of its directory -- the
repository root, or ``subpath`` -- lies ``primer-package.yaml``:
``{schema: 1, contract: "X.Y"}``, the version of the package contract it
follows; the product's ``packages.<name>.contract`` range must contain it. The
file has the form of every contract file (contract 3 rule 16).

``python -m pridem.stacks.package --export`` writes its JSON Schema to
``contract/schema/``.
"""

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Annotated

from pydantic import Field, TypeAdapter, ValidationError

from pridem.contract import (
    SCHEMA_DIR,
    ContractSchema,
    SchemaVersion,
    Strict,
    schema_text,
)
from pridem.stacks.loader import ContractError, Problem, field_problems, load_yaml_text

PACKAGE_FILE = "primer-package.yaml"
PRIMER_PACKAGE_SCHEMA = "primer-package.v1.json"


class PackageManifest(Strict):
    schema_: SchemaVersion = Field(alias="schema")
    contract: Annotated[str, Field(pattern=r"^\d+\.\d+$")]


PRIMER_PACKAGE: TypeAdapter[PackageManifest] = TypeAdapter(PackageManifest)


def _check(data: dict[str, object]) -> tuple[PackageManifest | None, list[Problem]]:
    try:
        return PRIMER_PACKAGE.validate_python(data), []
    except ValidationError as error:
        return None, field_problems(data, error)


def parse_primer_package(text: str, name: str) -> PackageManifest:
    """Check ``text`` taken from git; ``name`` names it in the error."""
    manifest, problems = _check(load_yaml_text(text, name))
    if problems or manifest is None:
        raise ContractError(Path(name), problems)
    return manifest


def rendered_schema() -> str:
    """The JSON Schema text of ``primer-package.yaml``, exported from the model."""
    return schema_text(
        PRIMER_PACKAGE.json_schema(mode="validation", schema_generator=ContractSchema),
        "primer-package.yaml v1",
    )


def main(argv: Sequence[str]) -> int:
    """``--export`` writes the package schema to ``contract/schema/``."""
    parser = argparse.ArgumentParser(prog="python -m pridem.stacks.package")
    parser.add_argument("--export", action="store_true", required=True)
    parser.parse_args(argv)
    target = SCHEMA_DIR / PRIMER_PACKAGE_SCHEMA
    target.write_text(rendered_schema(), encoding="utf-8")
    print(f"wrote {target}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
