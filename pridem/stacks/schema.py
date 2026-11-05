"""Contract 3: ``primer.yaml`` of a stack -- models, contract rules, JSON Schema.

A file is checked in two layers. Field layer: the pydantic models, strict and
closed (an unknown key at any depth is an error), plus the fields the contract
names as forbidden (rule 1 ``value``/``fixed``, rule 5 ``file``, rule 9
``branch``) and the object forms a bare string must not stand for (rule 17
seeds ``{run, when}``, rule 20 tests ``{run, target}``), reported with their
rule. Seed profiles are named by the stack; the machine knows none by name.
Rule layer: cross-field rules of the contract (rule 3 single-point pins, rule
4, 10, 11, 13 and the referential checks), run only when the field layer is
clean, each collecting every violation. Every problem names the path in the file.

A package slot (rule 10) is applied as the product declares: ``apply:
runtime`` (the default) mounts it by ``mount`` and checks it by ``validate``;
``apply: build`` puts it into the build context of a service at ``build[].path``
and is checked by the product's own build -- it has no ``mount`` and no
``validate`` (the owner's decision of 02.11).

``egress`` of a product (protocol 4.1, 4.2) -- the external hosts the product
still reaches itself, through the machine's proxy -- is a list of host names:
lowercase labels, at least two, the last not all digits; a pattern, a port, a
path, a scheme or an address is refused at the field layer (``S.egress-host``),
a host named twice in the rule layer (``S.egress-duplicate``). The proxy's
address reaches the product as ``HTTPS_PROXY`` and ``https_proxy``
(``PROXY_VARIABLES``), names of the machine: a key of the product's ``env`` with
either name is refused (``S.egress-env``). Whether a host is in the list agreed
with Primer is the machine's check, not the contract's (``stacks/egress.py``).
A service has no ``egress``: it reaches the internet itself.

``languages`` of a product (protocol 5.2.2) -- every language it has, the
codes of ``pridem.contract.Languages``: at least one, each once, lower case,
no region. An instance's subset and its default are the passport's; that they
are the product's is ``seams_check``'s. A service declares none: its languages
are its product's, given through ``env`` (source ``passport``, keys
``languages`` and ``default_language``).

The form D of protocol 4.5 is a pair: a service declares the kinds of data it
takes (``accepts: {<kind>: {validate, env}}``), a product the directory of its
repository it gives a dependency of each kind (``dependencies.<s>.data:
{<kind>: <path>}``). The path the data is at in the service's container is the
machine's, given under ``env``: a key of the service's ``env`` with that name is
refused (``S.accepts-env``); a remote dependency takes no data
(``R13.remote-data``). Whether a pair matches needs both files -- the plan's
``seams_check``. An entry of ``stacks`` named as a dependency is refused
(``S.entry-dependency``): ``-p <entry>`` and the alias ``<entry>-<service>``
would be the service's. ``host.routes`` of a service follow rule 4 as a
product's; that a co-located service has none is the plan's check too.

``python -m pridem.stacks.schema --export`` writes the JSON Schema of
``primer.yaml`` to ``contract/schema/``; ``pridem.stacks.lock`` exports its own.
"""

import argparse
import re
import sys
from collections.abc import Callable, Sequence
from pathlib import Path, PurePosixPath
from typing import Annotated, Literal

from packaging.specifiers import InvalidSpecifier, Specifier, SpecifierSet
from pydantic import (
    AfterValidator,
    BeforeValidator,
    Field,
    TypeAdapter,
    ValidationError,
)
from pydantic_core import PydanticCustomError

from pridem.contract import (
    SCHEMA_DIR,
    ContractSchema,
    Languages,
    SchemaVersion,
    Strict,
    schema_text,
)
from pridem.stacks.loader import (
    ContractError,
    Problem,
    field_problems,
    load_yaml_mapping,
    load_yaml_text,
    render_path,
)

RULES = {
    "R1.value": (1, "values never live in primer.yaml, only sources"),
    "R3.single-point": (
        3,
        "a range is half-open, lower bound inclusive and upper exclusive; "
        "==, === and <= pin one version around primer.lock",
    ),
    "R3.lock-set": (3, "primer.lock pins exactly the dependencies of primer.yaml"),
    "R3.lock-range": (3, "the locked version lies in the declared range"),
    "R3.lock-tag": (3, "a dependency is a release tag vX.Y.Z equal to its version"),
    "R3.lock-commit": (3, "the locked commit is a lowercase hex sha of 7-40 chars"),
    "R4.route-domain": (4, "a route is declared only for a name in host.domains"),
    "R5.file-seam": (5, "product data reaches a service through its API, not files"),
    "R9.branch": (9, "a service is installed from release tags only, no branch"),
    "R10.apply": (
        10,
        "apply: runtime mounts (mount and validate, no build); apply: build "
        "builds (build, no mount, no validate: the build is the check)",
    ),
    "R10.build": (
        10,
        "a build place is a service and a relative normalized path inside its "
        "build context, without ..; one place once",
    ),
    "R10.mount": (
        10,
        "a package mount is either service with an absolute container path or "
        "dependency with env; from is a relative subdirectory without ..",
    ),
    "R11.edition-services": (11, "the services of an edition are its dependencies"),
    "R11.edition-enum": (11, "enum: editions needs editions declared"),
    "R13.remote-seam": (13, "a remote dependency provides through the passport"),
    "R13.remote-data": (
        13,
        "a remote dependency is on another box: no data of the product is copied to it",
    ),
    "R17.seed-form": (17, "a seed profile is {run, when}, when is install or command"),
    "R20.test-form": (
        20,
        "tests are {run, target, services?}: run in the image built from target, "
        "with the services named -- neither the app nor the frontend -- up first",
    ),
    "S.seam-from": (0, "a seam names a stack this stack can be wired to"),
    "S.mount-dependency": (0, "a package mount names a declared dependency"),
    "S.entry-dependency": (
        0,
        "an entry of stacks is not named as a dependency: both would be one compose "
        "project and one alias on the network pridem",
    ),
    "S.accepts-env": (
        0,
        "protocol 4.5: the path of accepted data is the machine's variable, not a "
        "key of env",
    ),
    "S.egress-host": (
        0,
        "protocol 4.2: an egress host is a name -- lowercase labels, no pattern, "
        "port, path, scheme or address",
    ),
    "S.egress-duplicate": (0, "protocol 4.2: an egress host is named once"),
    "S.egress-env": (
        0,
        "protocol 4.2: the proxy's variables are the machine's, not keys of env",
    ),
}

PROXY_VARIABLES = ("HTTPS_PROXY", "https_proxy")
"""The names the proxy's address reaches a product's services under: both,
since curl and some clients read only the lowercase one."""


def rule_message(code: str, detail: str) -> str:
    """The message of a contract-rule problem: rule number, rule text, detail."""
    number, text = RULES[code]
    head = f"contract rule {number}: {text}" if number else text
    return f"{head}: {detail}"


def _rule_error(code: str, detail: str) -> PydanticCustomError:
    return PydanticCustomError(
        code, "{message}", {"message": rule_message(code, detail)}
    )


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


_HOST_LABEL = re.compile(r"[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?")


def _egress_host(value: str) -> str:
    """A host name, nothing more (protocol 4.2): ``*.zoom.us``, ``zoom.us:443``,
    ``zoom.us/x``, ``https://zoom.us``, ``1.2.3.4``, ``::1``, ``Zoom.us``,
    ``zoom.us.`` and ``zoom`` are refused."""
    labels = value.split(".")
    if (
        len(value) > 253
        or len(labels) < 2
        or not all(_HOST_LABEL.fullmatch(label) for label in labels)
        or labels[-1].isdigit()
    ):
        raise _rule_error("S.egress-host", f"{value!r}")
    return value


Name = Annotated[str, Field(min_length=1)]
EgressHost = Annotated[str, AfterValidator(_egress_host)]
Command = Annotated[str, Field(min_length=1)]
UrlPath = Annotated[str, Field(pattern=r"^/[A-Za-z0-9._~/-]*$")]
"""A path of an app: a plain one -- it goes into the nginx config of the box as
it is (``location =``), so a space, ``;`` or ``{`` is refused here, before any
step; ``path-unsafe`` of the rendering is the second line."""
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


def _object_form(code: str, form: str) -> BeforeValidator:
    """A bare string where the contract wants an object names the rule."""

    def check(value: object) -> object:
        if isinstance(value, str):
            raise _rule_error(code, f"a string is not {form}")
        return value

    return BeforeValidator(check)


# A seed profile (rule 17); the machine knows no profile by name.
class Seed(Strict):
    run: Command
    when: Literal["install", "command"]


# Tests of a stack (rule 20): ``run`` in a container of build target ``target``;
# ``services`` -- the services of the stack's compose the tests need, brought up
# before them without the application and the frontend.
class StackTest(Strict):
    run: Command
    target: Name
    services: Annotated[list[Name], Field(min_length=1)] | None = None


class Types(Strict):
    openapi: UrlPath
    out: RepoPath
    commit_as: Name


class Stack(Strict):
    compose: RepoPath
    app: App | None = None
    frontend: Frontend | None = None
    migrate: Command | None = None
    test: (
        Annotated[StackTest, _object_form("R20.test-form", "{run, target}")] | None
    ) = None
    types: Types | None = None
    seeds: dict[
        Name, Annotated[Seed, _object_form("R17.seed-form", "{run, when}")]
    ] = {}
    repo: Name | None = None
    persistent: bool = False


class Minted(Strict):
    source: Literal["minted"]


class Asked(Strict):
    source: Literal["asked"]


class Derived(Strict):
    source: Literal["derived"]
    run: Command


# A non-secret instance parameter: params.<stack>.<variable> of the passport.
class Param(Strict):
    source: Literal["param"]


class Passport(Strict):
    source: Literal["passport"]
    key: Name
    enum: Literal["editions"] | None = None


class Seam(Strict):
    source: Literal["seam"]
    from_: Name = Field(alias="from")


# The stack's own application on the network ``pridem``:
# ``http://<stack>-<app.service>:<app.port>`` (TZ 7.3); not a secret.
class Address(Strict):
    source: Literal["address"]


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
        Minted | Asked | Derived | Param | Passport | Seam | Address,
        Field(discriminator="source"),
    ],
    BeforeValidator(_no_values),
]


class Dependency(Strict):
    """``data`` -- the form D of protocol 4.5: a directory of the product's
    repository, by kind, copied to the service, which ``accepts`` that kind."""

    repo: Name
    version: Range
    topology: Literal["co-located", "remote"] = "co-located"
    data: dict[Name, RepoPath] = {}


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


class BuildPlace(Strict):
    """Where ``apply: build`` puts a package: ``path`` inside the build context
    of ``service`` (rule 10, the owner's decision of 02.11)."""

    service: Name
    path: str


class Package(Strict):
    """Checked as a whole by rule 10 in the rule layer: ``apply: runtime``
    mounts (``mount``, ``validate``), ``apply: build`` builds (``build``)."""

    contract: Range
    validate_: Command | None = Field(default=None, alias="validate")
    apply: Literal["runtime", "build"] = "runtime"
    mount: list[Mount] = []
    build: list[BuildPlace] = []


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
    """``routes`` -- of a service on its own box (protocol 4, form A); a
    co-located service has none (``seams_check``)."""

    domains: list[Name] = []
    routes: dict[Name, Route] = {}
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


class Accepted(Strict):
    """A kind of the product's data a service takes (protocol 4.5, 4.7):
    ``validate`` -- its command, ``<dir>`` the data's path in the container;
    ``env`` -- the variable the machine gives that path under."""

    validate_: Command = Field(alias="validate")
    env: Name


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
    egress: list[EgressHost] = []
    languages: Languages | None = None


class Service(_Stack):
    kind: Literal["service"]
    provides: list[Name] = []
    requires: list[Name] = []
    update_window: UpdateWindow | None = None
    host: ServiceHost | None = None
    accepts: dict[Name, Accepted] = {}


PrimerYaml = Annotated[Product | Service, Field(discriminator="kind")]
PRIMER_YAML: TypeAdapter[Product | Service] = TypeAdapter(PrimerYaml)


def problem_at(path: Sequence[int | str], code: str, detail: str) -> Problem:
    """A contract-rule problem at ``path`` with the rule's number and text."""
    return Problem(render_path(path), code, rule_message(code, detail))


def _is_pin(specifier: Specifier) -> bool:
    """``==X``, ``===X`` and ``<=X`` pin one version; ``==X.*`` is a range."""
    if specifier.operator in ("===", "<="):
        return True
    return specifier.operator == "==" and not specifier.version.endswith(".*")


def _range_pins(path: tuple[int | str, ...], declared: str) -> list[Problem]:
    """One rule-3 problem for the range at ``path`` naming every pin in it."""
    pins = sorted(str(s) for s in SpecifierSet(declared) if _is_pin(s))
    if not pins:
        return []
    return [problem_at(path, "R3.single-point", f"{', '.join(pins)} in {declared!r}")]


def _r3_single_point(stack: Product | Service) -> list[Problem]:
    if not isinstance(stack, Product):
        return []
    out: list[Problem] = []
    for name, dependency in stack.dependencies.items():
        out += _range_pins(("dependencies", name, "version"), dependency.version)
    for name, package in stack.packages.items():
        out += _range_pins(("packages", name, "contract"), package.contract)
    return out


def _r20_test_services(stack: Product | Service) -> list[Problem]:
    """``test.services`` names neither the application nor the frontend: the
    tests run without them (rule 20); each one once."""
    out: list[Problem] = []
    for entry, stage in stack.stacks.items():
        if stage.test is None or stage.test.services is None:
            continue
        own = {part.service for part in (stage.app, stage.frontend) if part}
        for index, name in enumerate(stage.test.services):
            path = ("stacks", entry, "test", "services", index)
            if name in own:
                detail = f"{name!r} is the app or the frontend"
                out.append(problem_at(path, "R20.test-form", detail))
            elif name in stage.test.services[:index]:
                out.append(problem_at(path, "R20.test-form", f"{name!r} twice"))
    return out


def _r4_route_domains(stack: Product | Service) -> list[Problem]:
    if stack.host is None:
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


def _r10_apply(stack: Product | Service) -> list[Problem]:
    """``runtime``: ``mount`` and ``validate``, no ``build``; ``build``:
    ``build``, no ``mount``, no ``validate``; every place's ``path`` relative,
    normalized, without ``..``; a ``(service, path)`` once in the product."""
    if not isinstance(stack, Product):
        return []
    out: list[Problem] = []
    seen: set[tuple[str, str]] = set()
    for name, package in sorted(stack.packages.items()):
        at = ("packages", name)
        if package.apply == "runtime":
            if not package.mount:
                out.append(problem_at(at, "R10.apply", "runtime needs mount"))
            if package.build:
                out.append(problem_at((*at, "build"), "R10.apply", "runtime builds no"))
            if package.validate_ is None:
                out.append(problem_at(at, "R10.apply", "runtime needs validate"))
        else:
            if not package.build:
                out.append(problem_at(at, "R10.apply", "build needs build"))
            if package.mount:
                out.append(problem_at((*at, "mount"), "R10.apply", "build mounts no"))
            if package.validate_ is not None:
                out.append(
                    problem_at((*at, "validate"), "R10.apply", "build has no validate")
                )
        for index, place in enumerate(package.build):
            where = (*at, "build", index)
            p = PurePosixPath(place.path)
            if (
                not place.path
                or p.is_absolute()
                or ".." in p.parts
                or str(p) != place.path
                or place.path == "."
            ):
                out.append(
                    problem_at(
                        (*where, "path"), "R10.build", f"not relative: {place.path!r}"
                    )
                )
            key = (place.service, place.path)
            if key in seen:
                out.append(problem_at(where, "R10.build", f"{key} twice"))
            seen.add(key)
    return out


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
                if service in spec.services[:index]:
                    out.append(
                        problem_at(
                            ("editions", edition, "services", index),
                            "R11.edition-services",
                            f"{service!r} is named twice",
                        )
                    )
                elif service not in stack.dependencies:
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


def _s_egress(stack: Product | Service) -> list[Problem]:
    if not isinstance(stack, Product):
        return []
    out: list[Problem] = []
    seen: set[str] = set()
    for index, host in enumerate(stack.egress):
        if host in seen:
            out.append(problem_at(("egress", index), "S.egress-duplicate", f"{host!r}"))
        seen.add(host)
    for key in stack.env:
        if key in PROXY_VARIABLES:
            out.append(
                problem_at(("env", key), "S.egress-env", f"{key!r} is the machine's")
            )
    return out


def _s_entries(stack: Product | Service) -> list[Problem]:
    """An entry of ``stacks`` named as a dependency; a remote dependency with
    ``data``; a service's ``accepts`` variable among its ``env`` keys."""
    out: list[Problem] = []
    if isinstance(stack, Product):
        for entry in stack.stacks:
            if entry in stack.dependencies:
                out.append(
                    problem_at(
                        ("stacks", entry),
                        "S.entry-dependency",
                        f"{entry!r} is a dependency",
                    )
                )
        for name, dependency in stack.dependencies.items():
            if dependency.topology == "remote" and dependency.data:
                out.append(
                    problem_at(
                        ("dependencies", name, "data"),
                        "R13.remote-data",
                        f"{name!r} is remote",
                    )
                )
    else:
        for kind, accepted in stack.accepts.items():
            if accepted.env in stack.env:
                out.append(
                    problem_at(
                        ("accepts", kind, "env"),
                        "S.accepts-env",
                        f"{accepted.env!r} is a key of env",
                    )
                )
    return out


RULE_CHECKS: tuple[Callable[[Product | Service], list[Problem]], ...] = (
    _r3_single_point,
    _r4_route_domains,
    _r10_mounts,
    _r10_apply,
    _s_mount_dependency,
    _r11_editions,
    _r13_seams,
    _s_egress,
    _s_entries,
    _r20_test_services,
)


def rule_problems(stack: Product | Service) -> list[Problem]:
    """Every contract-rule violation of a field-valid ``primer.yaml``."""
    return [problem for check in RULE_CHECKS for problem in check(stack)]


def _check(data: dict[str, object]) -> tuple[Product | Service | None, list[Problem]]:
    """Both layers; returns problems instead of raising, so nothing is chained.

    A ``ValidationError`` carries the file's values (``input_value``); raised
    inside ``except`` or ``from`` it, ``ContractError`` would print them in a
    traceback.
    """
    try:
        stack = PRIMER_YAML.validate_python(data)
    except ValidationError as error:
        return None, field_problems(data, error)
    return stack, rule_problems(stack)


def load_primer_yaml(file: Path) -> Product | Service:
    """Load and check ``primer.yaml``; raise ``ContractError`` with every problem."""
    stack, problems = _check(load_yaml_mapping(file))
    if problems or stack is None:
        raise ContractError(file, problems)
    return stack


def parse_primer_yaml(text: str, name: str) -> Product | Service:
    """Check ``text`` taken from git (``git show <ref>:<path>``); ``name`` names it."""
    found, problems = _check(load_yaml_text(text, name))
    if problems or found is None:
        raise ContractError(Path(name), problems)
    return found


PRIMER_YAML_SCHEMA = "primer-yaml.v1.json"


def rendered_schema() -> str:
    """The JSON Schema text of ``primer.yaml``, exported from the models."""
    return schema_text(
        PRIMER_YAML.json_schema(mode="validation", schema_generator=ContractSchema),
        "primer.yaml v1",
    )


def main(argv: Sequence[str]) -> int:
    """``--export`` writes the ``primer.yaml`` schema to ``contract/schema/``."""
    parser = argparse.ArgumentParser(prog="python -m pridem.stacks.schema")
    parser.add_argument("--export", action="store_true", required=True)
    parser.parse_args(argv)
    SCHEMA_DIR.mkdir(parents=True, exist_ok=True)
    target = SCHEMA_DIR / PRIMER_YAML_SCHEMA
    target.write_text(rendered_schema(), encoding="utf-8")
    print(f"wrote {target}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
