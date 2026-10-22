"""Contract 3: ``primer.yaml`` of a stack -- models, contract rules, JSON Schema.

A file is checked in two layers. Field layer: the pydantic models, strict and
closed (an unknown key at any depth is an error), plus the fields the contract
names as forbidden (rule 1 ``value``/``fixed``, rule 5 ``file``, rule 9
``branch``), reported with their rule. Rule layer: cross-field rules of the
contract (rule 3 single-point pins, rule 4, 10, 11, 13 and the referential
checks), run only when the field layer is clean, each collecting every
violation. Every problem names the path in the file.

``python -m pridem.stacks.schema --export`` writes the JSON Schema of
``primer.yaml`` and ``primer.lock`` to ``contract/schema/``.
"""

import argparse
import json
import sys
from collections.abc import Callable, Sequence
from pathlib import Path, PurePosixPath
from typing import Annotated, Literal

from packaging.specifiers import InvalidSpecifier, Specifier, SpecifierSet
from pydantic import (
    AfterValidator,
    BaseModel,
    BeforeValidator,
    ConfigDict,
    Field,
    TypeAdapter,
    ValidationError,
    model_validator,
)
from pydantic.json_schema import GenerateJsonSchema, JsonSchemaValue
from pydantic_core import PydanticCustomError, core_schema

from pridem.stacks.loader import (
    ContractError,
    Problem,
    field_problems,
    load_yaml_mapping,
    render_path,
)

RULES = {
    "R1.value": (1, "values never live in primer.yaml, only sources"),
    "R3.single-point": (
        3,
        "a dependency is declared as a range; a pin (== or ===) is a lock "
        "around primer.lock",
    ),
    "R3.lock-set": (3, "primer.lock pins exactly the dependencies of primer.yaml"),
    "R3.lock-range": (3, "the locked version lies in the declared range"),
    "R3.lock-tag": (3, "a dependency is a release tag vX.Y.Z equal to its version"),
    "R3.lock-commit": (3, "the locked commit is a lowercase hex sha of 7-40 chars"),
    "R4.route-domain": (4, "a route is declared only for a name in host.domains"),
    "R5.file-seam": (5, "product data reaches a service through its API, not files"),
    "R9.branch": (9, "a service is installed from release tags only, no branch"),
    "R10.mount": (
        10,
        "a package mount is either service with an absolute container path or "
        "dependency with env; from is a relative subdirectory without ..",
    ),
    "R11.edition-services": (11, "the services of an edition are its dependencies"),
    "R11.edition-enum": (11, "enum: editions needs editions declared"),
    "R13.remote-seam": (13, "a remote dependency provides through the passport"),
    "S.seam-from": (0, "a seam names a stack this stack can be wired to"),
    "S.mount-dependency": (0, "a package mount names a declared dependency"),
}


def rule_message(code: str, detail: str) -> str:
    """The message of a contract-rule problem: rule number, rule text, detail."""
    number, text = RULES[code]
    head = f"contract rule {number}: {text}" if number else text
    return f"{head}: {detail}"


def _rule_error(code: str, detail: str) -> PydanticCustomError:
    return PydanticCustomError(
        code, "{message}", {"message": rule_message(code, detail)}
    )


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


def _specifier(value: str) -> str:
    if not value.strip():
        raise ValueError("an empty range would accept any version")
    try:
        SpecifierSet(value)
    except InvalidSpecifier as error:
        raise ValueError(f"not a version range: {value!r}") from error
    return value


def _relative_path(value: str) -> str:
    path = PurePosixPath(value)
    if not value or path.is_absolute() or ".." in path.parts:
        raise ValueError(
            f"must be a relative path inside the repo without ..: {value!r}"
        )
    return value


SchemaVersion = Annotated[Literal[1], BeforeValidator(_exact_int)]
Name = Annotated[str, Field(min_length=1)]
Command = Annotated[str, Field(min_length=1)]
UrlPath = Annotated[str, Field(pattern=r"^/")]
Port = Annotated[int, Field(ge=1, le=65535)]
Range = Annotated[str, AfterValidator(_specifier)]
RepoPath = Annotated[str, AfterValidator(_relative_path)]


class App(Strict):
    service: Name
    port: Port
    health: UrlPath
    ready: UrlPath


class Frontend(Strict):
    service: Name
    port: Port
    build_args: list[Name] = []


class Types(Strict):
    openapi: UrlPath
    out: RepoPath
    commit_as: Name


class Stack(Strict):
    compose: RepoPath
    app: App | None = None
    frontend: Frontend | None = None
    migrate: Command | None = None
    test: Command | None = None
    types: Types | None = None
    seeds: dict[Name, Command] = {}
    repo: Name | None = None
    persistent: bool = False


class Minted(Strict):
    source: Literal["minted"]


class Asked(Strict):
    source: Literal["asked"]


class Derived(Strict):
    source: Literal["derived"]
    run: Command


class Passport(Strict):
    source: Literal["passport"]
    key: Name
    enum: Literal["editions"] | None = None


class Seam(Strict):
    source: Literal["seam"]
    from_: Name = Field(alias="from")


def _no_values(value: object) -> object:
    """Rule 1 and rule 5 name fields that must not exist; say so with the rule."""
    if isinstance(value, dict):
        if "value" in value:
            raise _rule_error("R1.value", "'value' is not a source")
        if value.get("source") == "fixed":
            raise _rule_error("R1.value", "source 'fixed' does not exist")
        if value.get("source") == "file":
            raise _rule_error("R5.file-seam", "source 'file' does not exist")
    return value


EnvVar = Annotated[
    Annotated[
        Minted | Asked | Derived | Passport | Seam, Field(discriminator="source")
    ],
    BeforeValidator(_no_values),
]


class Dependency(Strict):
    repo: Name
    version: Range
    topology: Literal["co-located", "remote"] = "co-located"


def _no_branch(value: object) -> object:
    if isinstance(value, dict) and "branch" in value:
        raise _rule_error("R9.branch", "'branch' is not a field of a dependency")
    return value


DependencyEntry = Annotated[Dependency, BeforeValidator(_no_branch)]


class Edition(Strict):
    services: list[Name]


class ProvideUrl(Strict):
    from_: Name = Field(alias="from")
    path: UrlPath


class ProvideVerb(Strict):
    verb: Name


class Mount(Strict):
    """Checked as a whole by rule 10 in the rule layer."""

    service: Name | None = None
    dependency: Name | None = None
    from_: str | None = Field(default=None, alias="from")
    path: str | None = None
    env: Name | None = None


class Package(Strict):
    contract: Range
    validate_: Command = Field(alias="validate")
    mount: list[Mount] = Field(min_length=1)


class Route(Strict):
    to: Annotated[str, Field(pattern=r"^[^\s:]+:\d+$")]
    max_body: Annotated[str, Field(pattern=r"^\d+[kKmMgG]?$")] | None = None
    read_timeout: Annotated[str, Field(pattern=r"^\d+(ms|s|m|h)?$")] | None = None


class Headers(Strict):
    csp: Name | None = None


class ProductHost(Strict):
    domains: list[Name] = []
    routes: dict[Name, Route] = {}
    headers: Headers | None = None


class HostPort(Strict):
    proto: Literal["tcp", "udp"]
    port: Port


class ServiceHost(Strict):
    domains: list[Name] = []
    ports: list[HostPort] = []


class Verb(Strict):
    run: Command
    args: list[Name] = []
    roles: (
        Annotated[list[Literal["test", "prod", "preview"]], Field(min_length=1)] | None
    ) = None
    destructive: bool = False


class UpdateWindow(Strict):
    validate_: Command = Field(alias="validate")
    before: list[Command] = []
    after: list[Command] = []
    drops: list[Name] = []


class Report(Strict):
    health: UrlPath
    ready: UrlPath
    logs: Literal["json"]
    junit: bool


class _Stack(Strict):
    schema_: SchemaVersion = Field(alias="schema")
    name: Name
    stacks: Annotated[dict[Name, Stack], Field(min_length=1)]
    env: dict[Name, EnvVar] = {}
    report: Report


class Product(_Stack):
    kind: Literal["product"]
    dependencies: dict[Name, DependencyEntry] = {}
    editions: dict[Name, Edition] = {}
    provides: dict[Name, ProvideUrl | ProvideVerb] = {}
    replay: dict[Name, Command] = {}
    packages: dict[Name, Package] = {}
    host: ProductHost | None = None
    verbs: dict[Name, Verb] = {}


class Service(_Stack):
    kind: Literal["service"]
    provides: list[Name] = []
    requires: list[Name] = []
    update_window: UpdateWindow | None = None
    host: ServiceHost | None = None


PrimerYaml = Annotated[Product | Service, Field(discriminator="kind")]
PRIMER_YAML: TypeAdapter[Product | Service] = TypeAdapter(PrimerYaml)


def problem_at(path: Sequence[int | str], code: str, detail: str) -> Problem:
    """A contract-rule problem at ``path`` with the rule's number and text."""
    return Problem(render_path(path), code, rule_message(code, detail))


def _is_pin(specifier: Specifier) -> bool:
    """``==X`` and ``===X`` pin one version; ``==X.*`` is a range and stays."""
    if specifier.operator == "===":
        return True
    return specifier.operator == "==" and not specifier.version.endswith(".*")


def _r3_single_point(stack: Product | Service) -> list[Problem]:
    if not isinstance(stack, Product):
        return []
    out: list[Problem] = []
    for name, dependency in stack.dependencies.items():
        pins = sorted(str(s) for s in SpecifierSet(dependency.version) if _is_pin(s))
        if pins:
            out.append(
                problem_at(
                    ("dependencies", name, "version"),
                    "R3.single-point",
                    f"{', '.join(pins)} in {dependency.version!r}",
                )
            )
    return out


def _r4_route_domains(stack: Product | Service) -> list[Problem]:
    if not isinstance(stack, Product) or stack.host is None:
        return []
    return [
        problem_at(
            ("host", "routes", name),
            "R4.route-domain",
            f"{name!r} is not in host.domains",
        )
        for name in stack.host.routes
        if name not in stack.host.domains
    ]


def _mount_problems(path: tuple[int | str, ...], mount: Mount) -> list[Problem]:
    out: list[Problem] = []
    if (mount.service is None) == (mount.dependency is None):
        out.append(problem_at(path, "R10.mount", "exactly one of service, dependency"))
    if mount.service is not None:
        if mount.path is None:
            out.append(problem_at(path, "R10.mount", "a service mount needs path"))
        else:
            p = PurePosixPath(mount.path)
            if not p.is_absolute() or ".." in p.parts or str(p) != mount.path:
                out.append(
                    problem_at(
                        (*path, "path"),
                        "R10.mount",
                        f"path must be absolute and normalized: {mount.path!r}",
                    )
                )
        if mount.env is not None:
            out.append(
                problem_at((*path, "env"), "R10.mount", "env is for dependency mounts")
            )
    if mount.dependency is not None:
        if mount.env is None:
            out.append(problem_at(path, "R10.mount", "a dependency mount needs env"))
        if mount.path is not None:
            out.append(
                problem_at(
                    (*path, "path"), "R10.mount", "a dependency mount takes no path"
                )
            )
    if mount.from_ is not None:
        f = PurePosixPath(mount.from_)
        if (
            not mount.from_
            or f.is_absolute()
            or ".." in f.parts
            or str(f) != mount.from_
        ):
            out.append(
                problem_at(
                    (*path, "from"),
                    "R10.mount",
                    f"from must be a relative normalized subdirectory: {mount.from_!r}",
                )
            )
    return out


def _r10_mounts(stack: Product | Service) -> list[Problem]:
    if not isinstance(stack, Product):
        return []
    return [
        problem
        for name, package in stack.packages.items()
        for index, mount in enumerate(package.mount)
        for problem in _mount_problems(("packages", name, "mount", index), mount)
    ]


def _s_mount_dependency(stack: Product | Service) -> list[Problem]:
    if not isinstance(stack, Product):
        return []
    out: list[Problem] = []
    for name, package in stack.packages.items():
        for index, mount in enumerate(package.mount):
            if mount.dependency is None:
                continue
            path = ("packages", name, "mount", index, "dependency")
            dependency = stack.dependencies.get(mount.dependency)
            if dependency is None:
                out.append(
                    problem_at(
                        path,
                        "S.mount-dependency",
                        f"{mount.dependency!r} is not in dependencies",
                    )
                )
            elif dependency.topology == "remote":
                out.append(
                    problem_at(
                        path,
                        "R13.remote-seam",
                        f"{mount.dependency!r} is remote; "
                        "a package cannot be copied to another box",
                    )
                )
    return out


def _r11_editions(stack: Product | Service) -> list[Problem]:
    out: list[Problem] = []
    if isinstance(stack, Product):
        for edition, spec in stack.editions.items():
            for index, service in enumerate(spec.services):
                if service not in stack.dependencies:
                    out.append(
                        problem_at(
                            ("editions", edition, "services", index),
                            "R11.edition-services",
                            f"{service!r} is not in dependencies",
                        )
                    )
    has_editions = isinstance(stack, Product) and bool(stack.editions)
    for key, var in stack.env.items():
        if isinstance(var, Passport) and var.enum == "editions" and not has_editions:
            out.append(
                problem_at(
                    ("env", key, "enum"), "R11.edition-enum", "no editions declared"
                )
            )
    return out


def _r13_seams(stack: Product | Service) -> list[Problem]:
    out: list[Problem] = []
    for key, var in stack.env.items():
        if not isinstance(var, Seam):
            continue
        path = ("env", key, "from")
        if isinstance(stack, Service):
            if var.from_ != "product":
                out.append(
                    problem_at(
                        path,
                        "S.seam-from",
                        f"a service is wired to 'product', not {var.from_!r}",
                    )
                )
            continue
        dependency = stack.dependencies.get(var.from_)
        if dependency is None:
            out.append(
                problem_at(path, "S.seam-from", f"{var.from_!r} is not in dependencies")
            )
        elif dependency.topology == "remote":
            out.append(
                problem_at(
                    path,
                    "R13.remote-seam",
                    f"{var.from_!r} is remote; "
                    "its provides come as asked in the passport",
                )
            )
    return out


RULE_CHECKS: tuple[Callable[[Product | Service], list[Problem]], ...] = (
    _r3_single_point,
    _r4_route_domains,
    _r10_mounts,
    _s_mount_dependency,
    _r11_editions,
    _r13_seams,
)


def rule_problems(stack: Product | Service) -> list[Problem]:
    """Every contract-rule violation of a field-valid ``primer.yaml``."""
    return [problem for check in RULE_CHECKS for problem in check(stack)]


def load_primer_yaml(file: Path) -> Product | Service:
    """Load and check ``primer.yaml``; raise ``ContractError`` with every problem."""
    data = load_yaml_mapping(file)
    try:
        stack = PRIMER_YAML.validate_python(data)
    except ValidationError as error:
        raise ContractError(file, field_problems(data, error)) from error
    problems = rule_problems(stack)
    if problems:
        raise ContractError(file, problems)
    return stack


class ContractSchema(GenerateJsonSchema):
    """Optional fields are absent-or-typed; the models reject explicit null."""

    def nullable_schema(self, schema: core_schema.NullableSchema) -> JsonSchemaValue:
        return self.generate_inner(schema["schema"])

    def default_schema(self, schema: core_schema.WithDefaultSchema) -> JsonSchemaValue:
        generated = super().default_schema(schema)
        if "default" in generated and generated["default"] is None:
            del generated["default"]
        return generated


SCHEMA_DIR = Path(__file__).resolve().parents[2] / "contract" / "schema"
PRIMER_YAML_SCHEMA = "primer-yaml.v1.json"
PRIMER_LOCK_SCHEMA = "primer-lock.v1.json"


def schema_text(schema: JsonSchemaValue, title: str) -> str:
    """Serialize a JSON Schema the one way the repository keeps it."""
    document = {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": title,
        **schema,
    }
    return json.dumps(document, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def rendered_schemas() -> dict[str, str]:
    """File name -> JSON Schema text, exported from the models."""
    from pridem.stacks.lock import PRIMER_LOCK  # lock imports this module

    return {
        PRIMER_YAML_SCHEMA: schema_text(
            PRIMER_YAML.json_schema(mode="validation", schema_generator=ContractSchema),
            "primer.yaml v1",
        ),
        PRIMER_LOCK_SCHEMA: schema_text(
            PRIMER_LOCK.json_schema(mode="validation", schema_generator=ContractSchema),
            "primer.lock v1",
        ),
    }


def main(argv: Sequence[str]) -> int:
    """``--export`` writes the schemas to ``contract/schema/``."""
    parser = argparse.ArgumentParser(prog="python -m pridem.stacks.schema")
    parser.add_argument("--export", action="store_true", required=True)
    parser.parse_args(argv)
    SCHEMA_DIR.mkdir(parents=True, exist_ok=True)
    for name, text in rendered_schemas().items():
        (SCHEMA_DIR / name).write_text(text, encoding="utf-8")
        print(f"wrote {SCHEMA_DIR / name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
