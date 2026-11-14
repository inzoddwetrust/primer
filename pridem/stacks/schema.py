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
refused (``S.accepts-env``). Whether a pair matches needs both files -- the plan's
``seams_check``. An entry of ``stacks`` named as a dependency is refused
(``S.entry-dependency``): ``-p <entry>`` and the alias ``<entry>-<service>``
would be the service's. ``host.routes`` of a service follow rule 4 as a
product's; that a co-located service has none is the plan's check too.

``python -m pridem.stacks.schema --export`` writes the JSON Schema of
``primer.yaml`` to ``contract/schema/``; ``pridem.stacks.lock`` exports its own.
"""

import argparse
import re
import shlex
import sys
from collections.abc import Callable, Sequence
from pathlib import Path, PurePosixPath
from typing import Annotated, Literal, Self

from packaging.specifiers import InvalidSpecifier, Specifier, SpecifierSet
from pydantic import (
    AfterValidator,
    BeforeValidator,
    Discriminator,
    Field,
    Tag,
    TypeAdapter,
    ValidationError,
    WithJsonSchema,
    model_validator,
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
    "R36.when-outside": (
        36,
        "when: names an option of the stack's own options",
    ),
    "R37.required-outside": (37, "options_required is a subset of options"),
    "R38.seam-when": (
        38,
        "a seam from a dependency under when: o is itself under when: o",
    ),
    "R38.flag-outside": (
        38,
        "a flag options.<o> of the passport names an option of the stack's options",
    ),
    "R41.edition-and-option": (
        41,
        "a service is chosen by an edition or by an option, not by both",
    ),
    "R11.edition-enum": (11, "enum: editions needs editions declared"),
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
    "S.option-name": (0, "an option is named ^[a-z][a-z0-9_]*$"),
    "S.name": (0, "a name is ^[a-z0-9][a-z0-9_-]{0,62}$"),
    "S.name-reserved": (
        0,
        "a name of the machine's is not a stack's, a dependency's or an entry's",
    ),
    "S.env-key": (0, "a key of env is ^[A-Za-z_][A-Za-z0-9_]*$"),
    "S.env-reserved": (
        0,
        "a key of env is none docker, compose, the process or the machine reads",
    ),
    "S.alias-collision": (0, "two entries of the product give one alias on pridem"),
    "S.expose-app": (
        0,
        "a point is not on the app nor a service a route goes to: they are on pridem",
    ),
    "S.endpoint-unknown": (0, "an address names a point its entry does not expose"),
    "S.command": (0, "a command is one or more words shlex can split"),
    "S.git-path": (
        0,
        "a path of primer.yaml, a package or the passport never goes through "
        ".git, in any case: the machine writes, copies and binds no repository's "
        "own files",
    ),
    "S.types-one": (0, "types are declared on one entry of the product at most"),
    "R23.generate": (23, "generate names both paths it is given: <openapi> and <out>"),
    "S.minted-length": (0, "a minted value is no shorter than 32 characters"),
    "S.job-service": (
        0,
        "a job is a one-off service of its entry: not the app, the frontend, a "
        "point, a route's or a test's service, nor another job's",
    ),
    "S.verb-service": (
        0,
        "a verb names its service, or its entry has an app to run it in",
    ),
    "S.verb-entry": (0, "a verb's entry is an entry of the same product"),
    "S.stop-service": (
        0,
        "stop_for_migrate is for an entry with migrate and an app, each service once",
    ),
    "S.option-duplicate": (0, "an option is named once"),
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


def through_git(value: str) -> bool:
    """A part of ``value`` is ``.git`` in any case (``.github``, ``.gitignore``
    are other names): a worktree's ``.git`` is a file git reads its config from
    -- written, it hands the machine's next ``git`` another repository and its
    hooks (DM-63 FIX). One test for every path of ``primer.yaml``, a package
    and the passport, and for the second line in the steps."""
    return any(part.lower() == ".git" for part in PurePosixPath(value).parts)


def _relative_path(value: str) -> str:
    path = PurePosixPath(value)
    if not value or path.is_absolute() or ".." in path.parts:
        raise ValueError(
            f"must be a relative path inside the repo without ..: {value!r}"
        )
    if through_git(value):
        raise _rule_error("S.git-path", repr(value))
    return value


_HOST_LABEL = re.compile(r"[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?")


_OPTION = re.compile(r"[a-z][a-z0-9_]*")


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


def _option(value: str) -> str:
    """An option of an instance (contract 3 rule 36): ``^[a-z][a-z0-9_]*$``."""
    if not _OPTION.fullmatch(value):
        raise _rule_error("S.option-name", f"{value!r}")
    return value


Name = Annotated[str, Field(min_length=1)]
"""A string that is not a name the machine builds paths or files from: a
repository address, a CSP, a key of the passport."""

_IDENT = re.compile(r"[a-z0-9][a-z0-9_-]{0,62}")
_ENV_KEY = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


def _ident(value: str) -> str:
    """A name the machine builds a path, an alias or a block of nginx from
    (DM-78): ``^[a-z0-9][a-z0-9_-]{0,62}$`` -- no dot, slash, space, newline."""
    if not _IDENT.fullmatch(value):
        raise _rule_error("S.name", "not ^[a-z0-9][a-z0-9_-]{0,62}$")
    return value


def _env_key(value: str) -> str:
    """A key of ``env``: a line of the stack's ``.env`` (DM-78)."""
    if not _ENV_KEY.fullmatch(value):
        raise _rule_error("S.env-key", "not ^[A-Za-z_][A-Za-z0-9_]*$")
    return value


Ident = Annotated[
    str,
    AfterValidator(_ident),
    WithJsonSchema({"type": "string", "pattern": f"^{_IDENT.pattern}$"}),
]
EnvKey = Annotated[
    str,
    AfterValidator(_env_key),
    WithJsonSchema({"type": "string", "pattern": f"^{_ENV_KEY.pattern}$"}),
]

RESERVED_ENV = frozenset(
    {
        "PATH",
        "HOME",
        "HOSTNAME",
        "LD_PRELOAD",
        "LD_LIBRARY_PATH",
        "PYTHONPATH",
        "PYTHONHOME",
        "PYTHONSTARTUP",
    }
)
"""Keys of ``env`` a container's process or the machine reads for itself."""
RESERVED_ENV_PREFIXES = ("COMPOSE_", "DOCKER_", "BUILDKIT_", "PRIMER_")
"""What compose reads from ``--env-file`` for itself, and the machine's own
build arguments."""
EgressHost = Annotated[str, AfterValidator(_egress_host)]
Option = Annotated[str, AfterValidator(_option)]


def _command(value: str) -> str:
    """A command of ``primer.yaml`` (``migrate``, ``test.run``, ``run`` of
    ``derived``, ``validate``, ``before``/``after``): the words ``shlex``
    splits it into, at least one -- refused here, not as a ``ValueError`` in
    the middle of a rollout (DM-77)."""
    try:
        words = shlex.split(value)
    except ValueError:
        raise _rule_error("S.command", "a quote is not closed") from None
    if not words:
        raise _rule_error("S.command", "no word")
    return value


Command = Annotated[str, Field(min_length=1), AfterValidator(_command)]
UrlPath = Annotated[str, Field(pattern=r"^/[A-Za-z0-9._~/-]*$")]
"""A path of an app: a plain one -- it goes into the nginx config of the box as
it is (``location =``), so a space, ``;`` or ``{`` is refused here, before any
step; ``path-unsafe`` of the rendering is the second line."""
Port = Annotated[int, Field(ge=1, le=65535)]
Range = Annotated[str, AfterValidator(_specifier)]
RepoPath = Annotated[str, AfterValidator(_relative_path)]


class App(Strict):
    service: Ident
    port: Port
    health: UrlPath
    ready: UrlPath


class Frontend(Strict):
    service: Ident
    port: Port


def _object_form(code: str, form: str) -> BeforeValidator:
    """A bare string where the contract wants an object names the rule."""

    def check(value: object) -> object:
        if isinstance(value, str):
            raise _rule_error(code, f"a string is not {form}")
        return value

    return BeforeValidator(check)


Roles = Annotated[list[Literal["test", "prod", "preview"]], Field(min_length=1)]
"""The roles of the box a verb or a seed is for (rule 15): one or more of
``test``, ``prod``, ``preview``; absent -- every role."""


# A seed profile (rule 17); the machine knows no profile by name. ``roles`` --
# the roles of the box it may run on, as a verb's (DM-22); the refusal of a seed
# outside them comes with the machine's running of seeds (DM-86).
class Seed(Strict):
    run: Command
    when: Literal["install", "command"]
    roles: Roles | None = None


class Job(Strict):
    """A job of the entry (contract 3 rule 24): a one-off service of its
    compose, run on every deploy of the entry after the services it depends
    on are healthy and before those that depend on it; it needs no
    healthcheck (DM-22)."""

    service: Ident


# Tests of a stack (rule 20): ``run`` in a container of build target ``target``;
# ``services`` -- the services of the stack's compose the tests need, brought up
# before them without the application and the frontend.
class StackTest(Strict):
    run: Command
    target: Ident
    services: Annotated[list[Ident], Field(min_length=1)] | None = None


# Types of the frontend (contract 3 rule 23): ``openapi`` prints the OpenAPI
# document to stdout, ``generate`` turns the file ``<openapi>`` into the file
# ``<out>`` -- paths the machine puts in; both run in a throwaway container of
# the release's app image with the app's environment. ``out`` is the one path
# a ``test`` box commits, as ``commit_as``; no ``generate``, no ``types``.
class Types(Strict):
    openapi: Command
    generate: Command
    out: RepoPath
    commit_as: Name

    @model_validator(mode="after")
    def _paths_given(self) -> Self:
        for mark in ("<openapi>", "<out>"):
            if mark not in self.generate:
                raise _rule_error("R23.generate", f"no {mark}")
        return self


_SCHEME = re.compile(r"[a-z][a-z0-9+.-]*")


def _scheme(value: str) -> str:
    if not _SCHEME.fullmatch(value):
        raise _rule_error("S.name", "a scheme is ^[a-z][a-z0-9+.-]*$")
    return value


class Expose(Strict):
    """A point of the stack (protocol 4.4, contract 3 rule 22): a channel
    beside its HTTP application -- a Redis stream, a store. ``scheme`` tells
    the machine what the point is; it is no part of the address."""

    service: Ident
    port: Annotated[int, Field(ge=1, le=65535)]
    scheme: Annotated[str, AfterValidator(_scheme)]


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
        Ident, Annotated[Seed, _object_form("R17.seed-form", "{run, when}")]
    ] = {}
    repo: Name | None = None
    persistent: bool = False
    expose: dict[Ident, Expose] = {}
    """The points of this entry, seen only by the pairs that declare them."""
    jobs: dict[Ident, Job] = {}
    """The one-off services of this entry's compose, by the job's name."""
    stop_for_migrate: list[Ident] = []
    """Services of this entry's compose stopped before its ``migrate`` acts --
    workers, consumers, the API too (protocol 6.3, contract 3 rule 35); ``up``
    brings them up after it (DM-22)."""


class _Var(Strict):
    """A variable of ``env``. ``when: <option>`` -- needed only when that option
    of the instance is on; off, its value is the literal ``primer-switched-off``
    (contract 3 rules 38-39)."""

    when: Option | None = None


MINTED_MIN = 32
"""The shortest ``minted`` value (contract 3 section 3)."""


def _minted_length(value: int) -> int:
    if value < MINTED_MIN:
        raise _rule_error("S.minted-length", f"{value} is shorter than {MINTED_MIN}")
    return value


class Minted(_Var):
    """``length`` -- the exact length of the value, of the machine's alphabet
    ``[A-Za-z0-9_-]``, no shorter than 32 (DM-22: a consumer that takes no
    longer one); absent -- ``token_urlsafe(32)``, 43 characters."""

    source: Literal["minted"]
    length: Annotated[int, AfterValidator(_minted_length)] | None = None


class Asked(_Var):
    source: Literal["asked"]


class Derived(_Var):
    source: Literal["derived"]
    run: Command


# A non-secret instance parameter: params.<stack>.<variable> of the passport.
class Param(_Var):
    source: Literal["param"]


class Passport(_Var):
    source: Literal["passport"]
    key: Name
    enum: Literal["editions"] | None = None


class Seam(_Var):
    source: Literal["seam"]
    from_: Ident = Field(alias="from")


# The stack's own application on the network ``pridem``:
# ``http://<stack>-<app.service>:<app.port>`` (TZ 7.3); not a secret. With
# ``endpoint`` -- a point of ``expose``: ``<alias>:<port>``, no scheme (rule
# 22); of the stack's own entry, or with ``stack`` of another entry of the
# product (DM-62).
class Address(_Var):
    source: Literal["address"]
    endpoint: Ident | None = None
    stack: Ident | None = None


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
    data: dict[Ident, RepoPath] = {}
    when: Option | None = None
    """Installed only when this option of the instance is on (rule 38)."""


def _no_branch(value: object) -> object:
    if isinstance(value, dict) and "branch" in value:
        raise _rule_error("R9.branch", "'branch' is not a field of a dependency")
    return value


DependencyEntry = Annotated[Dependency, BeforeValidator(_no_branch)]


class Edition(Strict):
    services: list[Ident]


class ProvideUrl(Strict):
    from_: Name = Field(alias="from")
    path: UrlPath


class ProvideVerb(Strict):
    verb: Ident


class ProvideAddress(Strict):
    """The address of a point of an entry of the product, given to a service
    (DM-62: ``velo-storage`` for comms): ``<alias>:<port>``."""

    stack: Ident
    endpoint: Ident


class Mount(Strict):
    """Checked as a whole by rule 10 in the rule layer."""

    service: Ident | None = None
    dependency: Ident | None = None
    from_: str | None = Field(default=None, alias="from")
    path: str | None = None
    env: EnvKey | None = None


class BuildPlace(Strict):
    """Where ``apply: build`` puts a package: ``path`` inside the build context
    of ``service`` (rule 10, the owner's decision of 02.11)."""

    service: Ident
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
    domains: list[Ident] = []
    routes: dict[Ident, Route] = {}
    headers: Headers | None = None


class HostPort(Strict):
    proto: Literal["tcp", "udp"]
    port: Port


class ServiceHost(Strict):
    """``routes`` -- of a service on its own box (protocol 4, form A); a
    co-located service has none (``seams_check``)."""

    domains: list[Ident] = []
    routes: dict[Ident, Route] = {}
    ports: list[HostPort] = []


class Verb(Strict):
    """A verb of the project (contract 3 rule 7, protocol 8.2): run by the
    machine in ``service`` of the stack's own entry -- by default its
    ``app`` -- with its ``args`` in their order; ``roles`` -- the roles it
    runs on; ``destructive`` -- it asks ``--confirm <server.name>`` on any
    role (protocol 1.11)."""

    run: Command
    args: list[Ident] = []
    roles: Roles | None = None
    destructive: bool = False
    service: Ident | None = None
    entry: Ident | None = None
    """The entry of the same product whose ``service`` runs the verb; absent --
    the product's own entry. A job of that entry runs as a one-off container
    (DM-86, pass 4b)."""


class UpdateWindow(Strict):
    validate_: Command = Field(alias="validate")
    before: list[Command] = []
    after: list[Command] = []
    drops: list[Ident] = []


class Accepted(Strict):
    """A kind of the product's data a service takes (protocol 4.5, 4.7):
    ``validate`` -- its command, ``<dir>`` the data's path in the container;
    ``env`` -- the variable the machine gives that path under."""

    validate_: Command = Field(alias="validate")
    env: EnvKey


class Report(Strict):
    health: UrlPath
    ready: UrlPath
    logs: Literal["json"]
    junit: bool


class EgressWhen(Strict):
    """A host of ``egress`` open when one of its options is on (rule 40)."""

    host: EgressHost
    when: Annotated[list[Option], Field(min_length=1)]


def _egress_form(value: object) -> str:
    """A mapping is the form ``{host, when}``; anything else is a host name --
    so a bad name is reported as a name, not as both forms."""
    return "when" if isinstance(value, dict) else "host"


EgressEntry = Annotated[
    Annotated[EgressHost, Tag("host")] | Annotated[EgressWhen, Tag("when")],
    Discriminator(_egress_form),
]


class _Stack(Strict):
    schema_: SchemaVersion = Field(alias="schema")
    name: Ident
    stacks: Annotated[dict[Ident, Stack], Field(min_length=1)]
    env: dict[EnvKey, EnvVar] = {}
    report: Report
    options: list[Option] = []
    """The options of an instance the stack knows (rule 36)."""


class Product(_Stack):
    kind: Literal["product"]
    dependencies: dict[Ident, DependencyEntry] = {}
    editions: dict[Ident, Edition] = {}
    provides: dict[EnvKey, ProvideUrl | ProvideVerb | ProvideAddress] = {}
    replay: dict[Ident, Command] = {}
    packages: dict[Ident, Package] = {}
    host: ProductHost | None = None
    verbs: dict[Ident, Verb] = {}
    egress: list[EgressEntry] = []
    languages: Languages | None = None
    options_required: list[Option] = []
    """The options an instance of the product does not work without (rule 37)."""


class Service(_Stack):
    kind: Literal["service"]
    provides: list[EnvKey] = []
    requires: list[EnvKey] = []
    update_window: UpdateWindow | None = None
    host: ServiceHost | None = None
    accepts: dict[Ident, Accepted] = {}


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


def _s_jobs(stack: Product | Service) -> list[Problem]:
    """A job's service runs once and exits (rule 24): it is none of the
    services the machine keeps running or reads live -- the app, the frontend,
    a point, a service a route goes to, a service the tests need -- and no two
    jobs share one (DM-22)."""
    out: list[Problem] = []
    routed = (
        {r.to.partition(":")[0] for r in stack.host.routes.values()}
        if stack.host is not None
        else set()
    )
    for entry, stage in stack.stacks.items():
        kept = {part.service for part in (stage.app, stage.frontend) if part}
        kept |= {point.service for point in stage.expose.values()}
        if stage.test is not None and stage.test.services is not None:
            kept |= set(stage.test.services)
        kept |= routed
        seen: dict[str, str] = {}
        for name, job in stage.jobs.items():
            at = ("stacks", entry, "jobs", name, "service")
            other = seen.setdefault(job.service, name)
            if job.service in kept:
                out.append(problem_at(at, "S.job-service", repr(job.service)))
            elif other != name:
                detail = f"{job.service!r} is the service of job {other!r} too"
                out.append(problem_at(at, "S.job-service", detail))
            elif job.service in stage.stop_for_migrate:
                detail = f"{job.service!r} is stopped for migrate: a job does not run"
                out.append(problem_at(at, "S.job-service", detail))
    return out


RESERVED_NAMES: frozenset[str] = frozenset(
    {
        # the machine's own directory and compose projects, /opt/<name> and -p
        "pridem",
        "pridem-edge",
        "pridem-egress",
        # the word a service's seam names its product by (from: product)
        "product",
        # the stacks of the machine's plans: the verdict keys a step by
        # (stack, name), and an entry of the same name would mix its facts
        "backup",
        "box",
        "dependencies",
        "destroy",
        "edge",
        "finalize",
        "frontend",
        "host",
        "network",
        "passport",
        "rollback",
        "rollback_check",
        "seams",
        "seed",
        "services",
        "sources",
        "stopped",
        "timers",
    }
)
"""The names no stack, dependency or entry takes (DM-93: R2-S6, S16, B27) --
one list, read by the schema; ``pridem-`` is reserved as a prefix too. A test
holds it against the plans' stacks the code builds."""
RESERVED_PREFIX = "pridem-"


def _reserved(name: str) -> bool:
    return name in RESERVED_NAMES or name.startswith(RESERVED_PREFIX)


def _s_reserved(stack: Product | Service) -> list[Problem]:
    """The stack's name, its dependencies and its entries are none of the
    machine's: ``/opt/pridem`` is the box, ``pridem-edge`` and
    ``pridem-egress`` its compose projects, ``product`` a seam's word, the
    plans' stacks the verdict's keys (DM-93)."""
    out: list[Problem] = []
    if _reserved(stack.name):
        out.append(problem_at(("name",), "S.name-reserved", stack.name))
    for name in stack.stacks:
        if _reserved(name):
            out.append(problem_at(("stacks", name), "S.name-reserved", name))
    if isinstance(stack, Product):
        for name in stack.dependencies:
            if _reserved(name):
                out.append(problem_at(("dependencies", name), "S.name-reserved", name))
    return out


def _s_verbs(stack: Product | Service) -> list[Problem]:
    """A verb runs in a service of an entry of the same product -- ``entry``,
    by default the product's own: a running service, or a job of that entry
    as a one-off container (DM-86, pass 4b); without ``service`` -- the
    entry's app, which it must have."""
    out: list[Problem] = []
    if not isinstance(stack, Product):
        return out  # a service declares no verbs (contract 3 section 2)
    for name, verb in stack.verbs.items():
        at = ("verbs", name)
        if verb.entry is not None and verb.entry not in stack.stacks:
            detail = f"{verb.entry!r} is no entry of {stack.name}"
            out.append(problem_at((*at, "entry"), "S.verb-entry", detail))
            continue
        chosen = stack.stacks.get(verb.entry or stack.name)
        if chosen is None:
            continue  # the verb verb refuses it: the product has no own entry
        if verb.service is None and chosen.app is None:
            out.append(problem_at(at, "S.verb-service", "no service and no app"))
    return out


def _s_stop(stack: Product | Service) -> list[Problem]:
    """``stop_for_migrate`` stops for a ``migrate`` the entry runs in its app
    -- without them it would mean nothing -- and names each service once
    (DM-22)."""
    out: list[Problem] = []
    for entry, stage in stack.stacks.items():
        path = ("stacks", entry, "stop_for_migrate")
        if stage.stop_for_migrate and (stage.migrate is None or stage.app is None):
            out.append(problem_at(path, "S.stop-service", "no migrate to stop for"))
        for index, name in enumerate(stage.stop_for_migrate):
            if name in stage.stop_for_migrate[:index]:
                out.append(
                    problem_at((*path, index), "S.stop-service", f"{name!r} twice")
                )
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
        elif through_git(mount.from_):
            out.append(problem_at((*path, "from"), "S.git-path", repr(mount.from_)))
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
            elif through_git(place.path):
                out.append(problem_at((*where, "path"), "S.git-path", repr(place.path)))
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


def _s_seam_from(stack: Product | Service) -> list[Problem]:
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
    return out


def _s_egress(stack: Product | Service) -> list[Problem]:
    if not isinstance(stack, Product):
        return []
    out: list[Problem] = []
    seen: set[str] = set()
    for index, host in enumerate(egress_hosts(stack)):
        if host in seen:
            out.append(problem_at(("egress", index), "S.egress-duplicate", f"{host!r}"))
        seen.add(host)
    for key in stack.env:
        if key in PROXY_VARIABLES:
            out.append(
                problem_at(("env", key), "S.egress-env", f"{key!r} is the machine's")
            )
    return out


def egress_hosts(product: Product) -> list[str]:
    """Every host ``egress`` declares, in its order, whatever its options."""
    return [e if isinstance(e, str) else e.host for e in product.egress]


def _duplicates(names: Sequence[str], path: tuple[str, ...]) -> list[Problem]:
    out: list[Problem] = []
    for index, name in enumerate(names):
        if name in names[:index]:
            out.append(problem_at((*path, index), "S.option-duplicate", f"{name!r}"))
    return out


def _env_reserved(stack: Product | Service) -> list[Problem]:
    """A key of ``env`` docker, compose, the container's process or the
    machine reads for itself (DM-78)."""
    return [
        problem_at(("env", key), "S.env-reserved", repr(key))
        for key in stack.env
        if key in RESERVED_ENV or key.startswith(RESERVED_ENV_PREFIXES)
    ]


def _points(stack: Product | Service) -> list[Problem]:
    """``expose`` and the addresses of points (DM-62): a point is not on the
    app nor on a service a route of its entry goes to -- they are on
    ``pridem``, any stack reaches them; an address and ``ProvideAddress``
    name a point the entry exposes; ``stack`` -- an entry of the product."""
    out: list[Problem] = []
    routed = (
        {r.to.partition(":")[0] for r in stack.host.routes.values()}
        if isinstance(stack, Product) and stack.host is not None
        else set()
    )
    for entry, stage in stack.stacks.items():
        on_pridem = {stage.app.service} if stage.app is not None else set()
        for name, point in stage.expose.items():
            if point.service in on_pridem or point.service in routed:
                at = ("stacks", entry, "expose", name)
                out.append(problem_at(at, "S.expose-app", repr(point.service)))

    def known(entry: str | None, endpoint: str) -> bool:
        stage = stack.stacks.get(entry if entry is not None else stack.name)
        return stage is not None and endpoint in stage.expose

    for key, var in stack.env.items():
        if not isinstance(var, Address):
            continue
        if var.stack is not None and (
            not isinstance(stack, Product) or var.endpoint is None
        ):
            out.append(problem_at(("env", key, "stack"), "S.endpoint-unknown", key))
        elif var.endpoint is not None and not known(var.stack, var.endpoint):
            out.append(problem_at(("env", key), "S.endpoint-unknown", key))
    if isinstance(stack, Product):
        for key, offer in stack.provides.items():
            if isinstance(offer, ProvideAddress) and not known(
                offer.stack, offer.endpoint
            ):
                out.append(problem_at(("provides", key), "S.endpoint-unknown", key))
    return out


def _aliases(stack: Product | Service) -> list[Problem]:
    """``<entry>-<service>`` of the app and the frontend of every entry is a
    name on the network ``pridem``: two pairs giving one name -- ``a-b`` +
    ``c`` and ``a`` + ``b-c`` -- would share an address (DM-78)."""
    if not isinstance(stack, Product):
        return []
    seen: dict[str, tuple[str, str]] = {}
    out: list[Problem] = []
    for entry, stage in stack.stacks.items():
        parts = [stage.app, stage.frontend, *stage.expose.values()]
        for part in parts:
            if part is None:
                continue
            pair = (entry, part.service)
            name = f"{entry}-{part.service}"
            other = seen.setdefault(name, pair)
            if other != pair:
                out.append(
                    problem_at(("stacks", entry), "S.alias-collision", repr(name))
                )
    return out


def _options(stack: Product | Service) -> list[Problem]:
    """Rules 36-38 and 41 within one file: options named once, ``when:`` and
    a flag ``options.<o>`` only of the stack's own options, ``options_required``
    within ``options``, a seam from a dependency under ``when: o`` itself
    under ``when: o``, a service chosen by an edition or by an option."""
    own = set(stack.options)
    out = _duplicates(stack.options, ("options",))

    def outside(path: tuple[str | int, ...], option: str | None) -> None:
        if option is not None and option not in own:
            out.append(problem_at(path, "R36.when-outside", f"{option!r}"))

    for key, var in stack.env.items():
        outside(("env", key, "when"), var.when)
        if isinstance(var, Passport) and var.key.startswith("options."):
            flag = var.key.removeprefix("options.")
            if flag not in own:
                out.append(
                    problem_at(("env", key, "key"), "R38.flag-outside", repr(flag))
                )
    if isinstance(stack, Product):
        out += _duplicates(stack.options_required, ("options_required",))
        for index, option in enumerate(stack.options_required):
            if option not in own:
                where = ("options_required", index)
                out.append(problem_at(where, "R37.required-outside", f"{option!r}"))
        for name, dependency in stack.dependencies.items():
            outside(("dependencies", name, "when"), dependency.when)
            if dependency.when is not None and any(
                name in spec.services for spec in stack.editions.values()
            ):
                at = ("dependencies", name, "when")
                out.append(problem_at(at, "R41.edition-and-option", f"{name!r}"))
        for index, entry in enumerate(stack.egress):
            for option in [] if isinstance(entry, str) else entry.when:
                outside(("egress", index, "when"), option)
        for key, var in stack.env.items():
            if not isinstance(var, Seam):
                continue
            provider = stack.dependencies.get(var.from_)
            if provider is not None and provider.when not in (None, var.when):
                out.append(
                    problem_at(
                        ("env", key, "when"),
                        "R38.seam-when",
                        f"{var.from_!r} is under when: {provider.when}",
                    )
                )
    return out


def _s_entries(stack: Product | Service) -> list[Problem]:
    """An entry of ``stacks`` named as a dependency; a service's ``accepts``
    variable among its ``env`` keys."""
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


def _s_types_one(stack: Product | Service) -> list[Problem]:
    """``types`` on one entry at most (DM-63 FIX): the step makes the types of
    one entry; a second would be left without a word."""
    declared = [name for name, stage in stack.stacks.items() if stage.types]
    if len(declared) < 2:
        return []
    return [
        problem_at(("stacks", name, "types"), "S.types-one", f"also on {declared[0]}")
        for name in declared[1:]
    ]


RULE_CHECKS: tuple[Callable[[Product | Service], list[Problem]], ...] = (
    _r3_single_point,
    _r4_route_domains,
    _r10_mounts,
    _r10_apply,
    _s_mount_dependency,
    _r11_editions,
    _s_seam_from,
    _s_egress,
    _env_reserved,
    _aliases,
    _points,
    _options,
    _s_entries,
    _r20_test_services,
    _s_jobs,
    _s_stop,
    _s_verbs,
    _s_types_one,
    _s_reserved,
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
