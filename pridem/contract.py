"""The base every contract model stands on, and the one way schemas are exported.

``Strict`` is the only strictness base of the package: closed, strict, frozen,
an explicit null is an error and absence is not. The contracts of ``stacks/``
and the verdict of ``report/`` both build on it, so this module is a leaf and
imports nothing from ``pridem``.

A JSON Schema in ``contract/schema/`` is an export of a model, never a manuscript:
``schema_text`` serializes it with the title ``<contract> v1`` placed after the
model's own schema, so the title in the file is the argument and nothing else.
"""

import json
from pathlib import Path
from typing import Annotated, Literal

from pydantic import BaseModel, BeforeValidator, ConfigDict, model_validator
from pydantic.json_schema import GenerateJsonSchema, JsonSchemaValue
from pydantic_core import PydanticCustomError, core_schema

SCHEMA_DIR = Path(__file__).resolve().parents[1] / "contract" / "schema"

SECRET_MIN_LENGTH = 16
"""Shortest secret, in code points, as written: the passport's values (contract 1
rule 12) and every derived form ``Secrets`` cleans (contract 2 rule 2).

Secrets are cleaned out of a verdict by exact match; a short form would match
parts of a run id, a version or a time and the verdict could not be built.
"""


class Strict(BaseModel):
    """Closed, strict, frozen; an explicit null is an error, absence is not."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    @model_validator(mode="before")
    @classmethod
    def _no_explicit_null(cls, data: object) -> object:
        if isinstance(data, dict):
            nulls = sorted(str(key) for key, value in data.items() if value is None)
            if nulls:
                raise PydanticCustomError(
                    "null_forbidden",
                    "explicit null is not allowed (omit the key instead): {keys}",
                    {"keys": ", ".join(nulls)},
                )
        return data


def _exact_int(value: object) -> object:
    """Literal[1] alone accepts True and 1.0 (equality); the file must say 1."""
    if type(value) is not int:
        raise PydanticCustomError("int_type", "Input should be the integer 1")
    return value


SchemaVersion = Annotated[Literal[1], BeforeValidator(_exact_int)]


class ContractSchema(GenerateJsonSchema):
    """Optional fields are absent-or-typed; the models reject explicit null."""

    def nullable_schema(self, schema: core_schema.NullableSchema) -> JsonSchemaValue:
        return self.generate_inner(schema["schema"])

    def default_schema(self, schema: core_schema.WithDefaultSchema) -> JsonSchemaValue:
        generated = super().default_schema(schema)
        if "default" in generated and generated["default"] is None:
            del generated["default"]
        return generated


def schema_text(schema: JsonSchemaValue, title: str) -> str:
    """Serialize a JSON Schema the one way the repository keeps it.

    ``title`` comes after the model's schema: a model's own ``title`` (its
    class name) would otherwise win and the argument would be dead.
    """
    document = {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        **schema,
        "title": title,
    }
    return json.dumps(document, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
