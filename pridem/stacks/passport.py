"""Contract 1: the passport of a box -- model, rules checked on one passport, schema.

A passport is checked in two layers, as ``primer.yaml`` is. Field layer: the
models, strict and closed, plus the names rule 1 forbids (``minted``, the
composition, derived values), reported with their rule wherever the passport
would hold them, and rule 9 (a package is pinned to an exact version). Rule
layer, only when the field layer is clean: rule 4 (``product.ref`` by role),
rule 5 (``policies.tls`` exactly when ``ssl: provided``), rule 10
(``server.expires_at`` exactly on ``preview``); each collects every violation.

Rules that need other files are not here: rule 2 and the ``editions`` part of
rule 11 are composition checks, rule 3 is ``install``, rules 6 and 7 are steps.

Values of ``asked`` and ``tls`` are secrets: they are ``SecretStr`` in the
model, no message quotes them, and ``ContractError`` is raised outside
``except`` so no traceback prints pydantic's error with its input.

``python -m pridem.stacks.passport --export`` writes the JSON Schema of the
passport to ``contract/schema/``.
"""

import argparse
import re
import sys
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import Annotated, Literal

from pydantic import (
    AfterValidator,
    AwareDatetime,
    Field,
    SecretStr,
    TypeAdapter,
    ValidationError,
)
from pydantic_core import PydanticCustomError

from pridem.contract import (
    SCHEMA_DIR,
    ContractSchema,
    SchemaVersion,
    Strict,
    schema_text,
)
from pridem.stacks.loader import (
    ContractError,
    Problem,
    field_problems,
    load_yaml_mapping,
    render_path,
)
from pridem.stacks.schema import (
    Name,
    RepoPath,
)

RULES = {
    "R1.minted": (
        1,
        "minted secrets belong to their stack (env/minted.yaml), never to the passport",
    ),
    "R1.composition": (
        1,
        "the composition and exact versions of services live in primer.lock",
    ),
    "R1.derived": (1, "derived values (the box IP, values from asked) are never kept"),
    "R4.ref-branch": (4, "on role test product.ref is a branch"),
    "R4.ref-tag": (4, "on roles prod and preview product.ref is a release tag vX.Y.Z"),
    "R5.tls": (5, "policies.tls is present exactly when policies.ssl is provided"),
    "R9.package-version": (9, "a package is pinned to an exact version X.Y.Z"),
    "R10.expires": (
        10,
        "server.expires_at is required on role preview and forbidden on other roles",
    ),
}


def rule_message(code: str, detail: str) -> str:
    """The message of a passport-rule problem: rule number, rule text, detail."""
    number, text = RULES[code]
    return f"passport rule {number}: {text}: {detail}"


def problem_at(path: Sequence[int | str], code: str, detail: str) -> Problem:
    return Problem(render_path(path), code, rule_message(code, detail))


_HOST_LABEL = re.compile(r"[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?")
_RELEASE_TAG = re.compile(r"v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)")
_EXACT_VERSION = re.compile(r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)")
_COMMIT = re.compile(r"[0-9a-f]{7,40}")
_REF_FORBIDDEN = re.compile(r"[\x00-\x20\x7f~^:?*\[\\]")


def _host_name(value: str) -> str:
    labels = value.split(".")
    if (
        len(value) > 253
        or len(labels) < 2
        or not all(_HOST_LABEL.fullmatch(label) for label in labels)
    ):
        raise ValueError(f"not a host name (no scheme, path or port): {value!r}")
    return value


def _not_empty_secret(value: SecretStr) -> SecretStr:
    if not value.get_secret_value():
        raise ValueError("an asked value is empty; omit the key and install asks it")
    return value


def _pem(kind: str) -> Callable[[SecretStr], SecretStr]:
    def check(value: SecretStr) -> SecretStr:
        first = value.get_secret_value().lstrip().partition("\n")[0]
        if not (first.startswith("-----BEGIN ") and first.endswith(f"{kind}-----")):
            raise ValueError(f"not a PEM block of {kind}")
        return value

    return check


def _exact_version(value: str) -> str:
    if not _EXACT_VERSION.fullmatch(value):
        raise PydanticCustomError(
            "R9.package-version",
            "{message}",
            {"message": rule_message("R9.package-version", f"{value!r}")},
        )
    return value


HostName = Annotated[str, AfterValidator(_host_name)]
AskedValue = Annotated[SecretStr, AfterValidator(_not_empty_secret)]
ExactVersion = Annotated[
    str,
    AfterValidator(_exact_version),
    Field(json_schema_extra={"pattern": f"^{_EXACT_VERSION.pattern}$"}),
]


class Server(Strict):
    name: Annotated[str, Field(pattern=r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")]
    role: Literal["test", "prod", "preview"]
    os: Literal["ubuntu-24.04"]
    expires_at: AwareDatetime | None = None


class ProductRef(Strict):
    repo: Name
    ref: Name


class Access(Strict):
    mode: Literal["deploy-keys"]


class Tls(Strict):
    cert: Annotated[SecretStr, AfterValidator(_pem("CERTIFICATE"))]
    key: Annotated[SecretStr, AfterValidator(_pem("PRIVATE KEY"))]


class Gc(Strict):
    keep_releases: Annotated[int, Field(ge=1)]
    builder_cache_budget: Annotated[str, Field(pattern=r"^[1-9][0-9]*[KMG]$")]


class Backup(Strict):
    enabled: bool


class Timers(Strict):
    gc: Literal["daily"]


class Policies(Strict):
    ssl: Literal["letsencrypt", "self-signed", "defer", "provided"]
    tls: Tls | None = None
    gc: Gc
    backup: Backup
    timers: Timers


class Package(Strict):
    repo: Name
    version: ExactVersion
    subpath: RepoPath | None = None


class Cloud(Strict):
    """A socket: its fields arrive with the first provider; until then, empty."""


class Passport(Strict):
    schema_: SchemaVersion = Field(alias="schema")
    version: Annotated[int, Field(ge=1)]
    server: Server
    edition: Name | None = None
    product: ProductRef
    domains: dict[Name, HostName]
    access: Access
    asked: dict[Name, dict[Name, AskedValue]]
    policies: Policies
    packages: dict[Name, Package]
    cloud: Cloud


PASSPORT: TypeAdapter[Passport] = TypeAdapter(Passport)

# Rule 1 by the places a passport would hold the value; any other unknown key
# is a plain extra_forbidden. ``asked.<stack>.minted`` is matched by shape.
_R1_PATHS: dict[tuple[str, ...], str] = {
    ("minted",): "R1.minted",
    ("composition",): "R1.composition",
    ("lock",): "R1.composition",
    ("dependencies",): "R1.composition",
    ("product", "commit"): "R1.composition",
    ("ip",): "R1.derived",
    ("server", "ip"): "R1.derived",
}


def _r1_problems(data: Mapping[str, object]) -> list[Problem]:
    out: list[Problem] = []
    for path, code in _R1_PATHS.items():
        node: object = data
        for segment in path[:-1]:
            node = node.get(segment) if isinstance(node, Mapping) else None
        if isinstance(node, Mapping) and path[-1] in node:
            out.append(problem_at(path, code, f"{path[-1]!r} is not a passport field"))
    asked = data.get("asked")
    if isinstance(asked, Mapping):
        for stack, answers in asked.items():
            if isinstance(answers, Mapping) and "minted" in answers:
                out.append(
                    problem_at(
                        ("asked", str(stack), "minted"),
                        "R1.minted",
                        "'minted' is not an asked answer",
                    )
                )
    return out


def _under(path: str, roots: Sequence[Problem]) -> bool:
    return any(
        path == root.path or path.startswith((f"{root.path}.", f"{root.path}["))
        for root in roots
    )


def _is_branch(ref: str) -> bool:
    """A short git branch name, not a tag or a commit (subset of check-ref-format)."""
    if _RELEASE_TAG.fullmatch(ref) or _COMMIT.fullmatch(ref):
        return False
    if _REF_FORBIDDEN.search(ref) or ".." in ref or "@{" in ref or "//" in ref:
        return False
    if ref == "@" or ref.startswith(("-", "/")) or ref.endswith(("/", ".")):
        return False
    return not any(
        part.startswith(".") or part.endswith(".lock") for part in ref.split("/")
    )


def _r4_ref(passport: Passport) -> list[Problem]:
    role, ref = passport.server.role, passport.product.ref
    if role == "test":
        if _is_branch(ref):
            return []
        code = "R4.ref-branch"
    else:
        if _RELEASE_TAG.fullmatch(ref):
            return []
        code = "R4.ref-tag"
    return [problem_at(("product", "ref"), code, f"role {role} with ref {ref!r}")]


def _r5_tls(passport: Passport) -> list[Problem]:
    ssl, tls = passport.policies.ssl, passport.policies.tls
    if ssl == "provided" and tls is None:
        detail = "ssl is provided and tls is missing"
    elif ssl != "provided" and tls is not None:
        detail = f"ssl is {ssl} and tls is present"
    else:
        return []
    return [problem_at(("policies", "tls"), "R5.tls", detail)]


def _r10_expires(passport: Passport) -> list[Problem]:
    role, expires = passport.server.role, passport.server.expires_at
    if role == "preview" and expires is None:
        detail = "role preview without expires_at"
    elif role != "preview" and expires is not None:
        detail = f"role {role} with expires_at"
    else:
        return []
    return [problem_at(("server", "expires_at"), "R10.expires", detail)]


RULE_CHECKS: tuple[Callable[[Passport], list[Problem]], ...] = (
    _r4_ref,
    _r5_tls,
    _r10_expires,
)


def rule_problems(passport: Passport) -> list[Problem]:
    """Every rule violation of a field-valid passport."""
    return [problem for check in RULE_CHECKS for problem in check(passport)]


def _check(data: dict[str, object]) -> tuple[Passport | None, list[Problem]]:
    """Both layers; returns problems instead of raising, so nothing is chained."""
    forbidden = _r1_problems(data)
    try:
        passport = PASSPORT.validate_python(data)
    except ValidationError as error:
        fields = [
            p for p in field_problems(data, error) if not _under(p.path, forbidden)
        ]
        return None, forbidden + fields
    if forbidden:
        return None, forbidden
    return passport, rule_problems(passport)


def load_passport(file: Path) -> Passport:
    """Load and check a passport; raise ``ContractError`` with every problem."""
    passport, problems = _check(load_yaml_mapping(file))
    if problems or passport is None:
        raise ContractError(file, problems)
    return passport


PASSPORT_SCHEMA = "passport.v1.json"


def rendered_schema() -> str:
    """The JSON Schema text of the passport, exported from the model."""
    return schema_text(
        PASSPORT.json_schema(mode="validation", schema_generator=ContractSchema),
        "passport v1",
    )


def main(argv: Sequence[str]) -> int:
    """``--export`` writes the passport schema to ``contract/schema/``."""
    parser = argparse.ArgumentParser(prog="python -m pridem.stacks.passport")
    parser.add_argument("--export", action="store_true", required=True)
    parser.parse_args(argv)
    SCHEMA_DIR.mkdir(parents=True, exist_ok=True)
    target = SCHEMA_DIR / PASSPORT_SCHEMA
    target.write_text(rendered_schema(), encoding="utf-8")
    print(f"wrote {target}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
