"""The environment of a stack (contract 3 section 3, rules 13, 18; TZ 7.3, 8).

Every variable of ``env`` has a source; this module turns the sources that need
no command into values and keeps the three files of a stack's environment
under ``/opt/<name>/env/`` (0700), ``<name>`` being the ``name`` of its
``primer.yaml``:

- ``minted.yaml`` (0600): the ``minted`` secrets, minted once by
  ``secrets.token_urlsafe(32)`` -- 43 characters of ``[A-Za-z0-9_-]``, safe in
  a URL, an env file and a command -- or, for a key with ``length``, exactly
  that many characters of the same alphabet (DM-22). A key is never minted
  again; a key the schema no longer has stays (the stack's data; ``destroy``
  removes it).
- ``.env`` (0600): every variable as ``KEY='value'`` -- a single-quoted value
  is taken as it is by compose's ``--env-file``, with no interpolation. A value
  with ``'`` or a line break cannot be written so: refused, by its key only.
  It is the environment of the release ``current`` names: only ``finalize``
  writes it, a copy of ``next.env``, with ``current`` (DM-68).
- ``next.env`` (0600), of the same form: the environment of the release a
  deploy puts on the box. ``render_env`` and ``derive_env`` write it, every
  compose command of the deploy's steps reads it; the release that runs reads
  ``.env``, as it was, until ``finalize``. So a step red before the point of no
  return leaves the running release its own environment, a new passport on
  the same commit too -- the release's name is the same, its file is not.
  ``env_file`` is the one place either path is made.

All three are written by ``atomic_write`` with 0600 (temp, fsync, rename, fsync of
the directory). A file found with another mode is refused, never
``chmod``-ed.

The source ``passport`` reads ``edition``, ``server.role``, ``domains.*``,
``languages`` -- the instance's languages, rendered by ``languages_value`` --
and ``default_language``.

``resolve`` answers every source but ``derived`` (a command in the stack's
container: the step runs it) and reports the fields the passport lacks
(``asked``, ``params``, a domain of ``host.domains``, ``edition``): those are
asked by ``install`` (contract 1 rule 3). ``param`` and ``address`` are not
secrets; ``asked`` and ``minted`` are, and so is a ``seam`` from a provider
whose variable is one -- the provider's step put it in the run's set first.
"""

import re
import secrets as token
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from pridem.events import Json
from pridem.files import atomic_write, private_dir
from pridem.stacks.loader import ContractError, load_yaml_mapping
from pridem.stacks.options import FLAG, LITERAL, flag, off_keys, switched_on
from pridem.stacks.passport import Passport
from pridem.stacks.schema import (
    Address,
    Asked,
    Derived,
    Minted,
    Param,
    Product,
    Seam,
    Service,
)
from pridem.stacks.schema import Passport as FromPassport
from pridem.stacks.seams import (
    PRODUCT,
    DomainMissing,
    SeamMemory,
    SeamNotReady,
    product_value,
)
from pridem.steps.base import StepFailed

ENV_DIR = "env"
MINTED_FILE = "minted.yaml"
ENV_FILE = ".env"
STAGED_FILE = "next.env"
MINT_BYTES = 32
"""``token_urlsafe(32)``: 43 characters of ``[A-Za-z0-9_-]`` (measured)."""

MINTED_FORM = re.compile(r"[A-Za-z0-9_-]{32,}")
MINT_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-"
"""The alphabet of ``token_urlsafe``, of a minted value of a given length too."""
_LINE = re.compile(r"([A-Za-z_][A-Za-z0-9_]*)='([^'\n\r]*)'")
_UNSAFE = ("'", "\n", "\r")
_PLACEHOLDER = re.compile(r"<.*>")

DERIVED_PLACEHOLDER = "<derived>"
"""What ``render_env`` writes for a ``derived`` key with no value of its own
yet: compose's ``${VAR:?}`` is satisfied for the build, ``placeholder`` knows
it, and ``derive_env`` replaces it before anything runs a container of the
stack."""

Stack = Product | Service


def own_entry(stack: Stack) -> str:
    """A stack's own entry: the one named as the stack, else the first -- the
    entry that renders the stack's env and whose ``app`` image derives it."""
    return stack.name if stack.name in stack.stacks else next(iter(stack.stacks))


def env_dir(root: Path, name: str) -> Path:
    return root / "opt" / name / ENV_DIR


def env_file(root: Path, name: str, *, staged: bool) -> Path:
    """The environment of stack ``name``: ``next.env`` of the deploy
    (``staged``) or ``.env`` of the release ``current`` names -- the one
    function every reader and writer of either goes by."""
    return env_dir(root, name) / (STAGED_FILE if staged else ENV_FILE)


def mint(length: int | None = None) -> str:
    """A new secret: ``token_urlsafe(32)``, or ``length`` characters of
    ``MINT_ALPHABET`` -- each drawn by ``secrets``, 6 bits apiece."""
    if length is None:
        return token.token_urlsafe(MINT_BYTES)
    return "".join(token.choice(MINT_ALPHABET) for _ in range(length))


def mode_of(path: Path) -> str:
    return oct(path.stat().st_mode & 0o777)


def write_private(path: Path, text: str) -> None:
    """``text`` to ``path`` (0600, directory 0700) by ``atomic_write``."""
    private_dir(path.parent)
    atomic_write(path, text, 0o600)


def private_mode(path: Path, code: str) -> None:
    """A file of the stack's environment must be 0600; it is never re-moded."""
    mode = mode_of(path)
    if mode != oct(0o600):
        raise StepFailed(code, {"path": str(path), "mode": mode})


def read_minted(path: Path) -> dict[str, str]:
    """The minted secrets of a stack; ``{}`` when it has none yet."""
    if not path.exists():
        return {}
    private_mode(path, "minted-mode")
    try:
        data = load_yaml_mapping(path)
    except ContractError:
        raise StepFailed("minted-damaged", {"path": str(path)}) from None
    out: dict[str, str] = {}
    for key, value in data.items():
        if not isinstance(value, str) or not MINTED_FORM.fullmatch(value):
            raise StepFailed("minted-damaged", {"path": str(path)})
        out[key] = value
    return out


def minted_text(values: Mapping[str, str]) -> str:
    return yaml.safe_dump(dict(values), sort_keys=False)


def safe(key: str, value: str) -> None:
    """A value an env file holds as it is; refused by its key, never quoted."""
    if any(mark in value for mark in _UNSAFE):
        raise StepFailed("env-unsafe", {"key": key})


def env_text(values: Mapping[str, str]) -> str:
    """The ``.env`` of a stack: ``KEY='value'`` per line, in schema order."""
    for key, value in values.items():
        safe(key, value)
    return "".join(f"{key}='{value}'\n" for key, value in values.items())


def parse_env(text: str) -> dict[str, str]:
    """``env_text`` read back; a line of another form is refused by number."""
    out: dict[str, str] = {}
    for number, line in enumerate(text.splitlines(), start=1):
        found = _LINE.fullmatch(line)
        if found is None:
            raise StepFailed("env-unreadable", {"line": number})
        out[found.group(1)] = found.group(2)
    return out


def placeholder(value: str) -> bool:
    """Empty, ``<…>`` whole, an unresolved ``${…}``, or the literal of an
    option that is off -- a value only on a key of such an option (contract 3
    rule 39; ``read_back`` admits it there)."""
    return (
        not value
        or bool(_PLACEHOLDER.fullmatch(value))
        or "${" in value
        or value == LITERAL
    )


def languages_value(codes: Sequence[str]) -> str:
    """The languages of an instance in ``env`` (protocol 5.2.2): the codes
    joined by commas, no spaces, in the passport's order -- ``en,ru,uk``. One
    function for every stack; the names of the variables are each stack's."""
    return ",".join(codes)


@dataclass
class Resolved:
    """What ``resolve`` found: values, secrets among them, what to ask, what
    to derive."""

    values: dict[str, str] = field(default_factory=dict)
    secrets: list[str] = field(default_factory=list)
    missing: list[str] = field(default_factory=list)
    derived: dict[str, str] = field(default_factory=dict)
    switched_off: list[str] = field(default_factory=list)
    """Fields of the passport (``asked.<stack>.<key>``, ``params.…``) of an
    option that is off and absent: ``install`` writes the literal there."""


def address(stack: Stack) -> str:
    """``http://<stack>-<app.service>:<app.port>`` on the network ``pridem``."""
    entry = stack.stacks.get(stack.name)
    if entry is None or entry.app is None:
        raise StepFailed("address-no-app", {"stack": stack.name})
    return f"http://{stack.name}-{entry.app.service}:{entry.app.port}"


def point_address(stack: Stack, entry: str, endpoint: str) -> str:
    """``<entry>-<service>:<port>`` of the point ``endpoint`` of ``entry``
    (contract 3 rule 22): the alias on every network of its pairs, no scheme
    -- the consumer builds its URL in its compose."""
    point = stack.stacks[entry].expose[endpoint]
    return f"{entry}-{point.service}:{point.port}"


def _from_passport(
    stack: Stack,
    product: Product,
    key: str,
    var: FromPassport,
    passport: Passport,
    out: Resolved,
) -> None:
    if var.key == "edition":
        if passport.edition is None:
            out.missing.append("edition")
            return
        if var.enum == "editions":
            editions = stack.editions if isinstance(stack, Product) else {}
            if passport.edition not in editions:
                raise StepFailed(
                    "edition-unknown", {"key": key, "edition": passport.edition}
                )
        out.values[key] = passport.edition
    elif var.key == "server.role":
        out.values[key] = passport.server.role
    elif var.key == "languages":
        if passport.languages is None:
            out.missing.append("languages")
        else:
            out.values[key] = languages_value(passport.languages)
    elif var.key == "default_language":
        if passport.default_language is None:
            out.missing.append("default_language")
        else:
            out.values[key] = passport.default_language
    elif var.key.startswith(FLAG):
        out.values[key] = flag(var.key, switched_on(passport))
    elif var.key.startswith("domains."):
        domain = var.key.removeprefix("domains.")
        host = passport.domains.get(domain)
        if host is None:
            out.missing.append(var.key)
        else:
            out.values[key] = host
    else:
        raise StepFailed("passport-key", {"key": key, "passport_key": var.key})


def resolve(
    stack: Stack,
    product: Product,
    passport: Passport,
    minted: Mapping[str, str],
    memory: SeamMemory,
) -> Resolved:
    """Every source of ``stack`` but ``derived``, in schema order.

    A key under an option that is off is the literal, its source unread
    (contract 3 rules 38-39): what the passport gives for it must be the
    literal (``option-value``), and absent, it is to be written there; the
    literal on any other key is refused (``option-literal``)."""
    out = Resolved()
    name = stack.name
    asked = passport.asked.get(name, {})
    params = passport.params.get(name, {})
    on = switched_on(passport)
    switched = set(off_keys(stack, on))
    given = {k: v.get_secret_value() for k, v in asked.items()}
    for kind, values in (("asked", given), ("params", params)):
        for key, value in values.items():
            if key in switched and value != LITERAL:
                raise StepFailed("option-value", {"key": f"{kind}.{name}.{key}"})
            if key not in switched and value == LITERAL:
                raise StepFailed("option-literal", {"key": f"{kind}.{name}.{key}"})
    seams: dict[str, list[str]] = {}
    for key, var in stack.env.items():
        if key in switched:
            out.values[key] = LITERAL
            if isinstance(var, Asked):
                out.secrets.append(LITERAL)  # as any value of asked
                if key not in asked:
                    out.switched_off.append(f"asked.{name}.{key}")
            elif isinstance(var, Param) and key not in params:
                out.switched_off.append(f"params.{name}.{key}")
        elif isinstance(var, Minted):
            out.values[key] = minted[key]
            out.secrets.append(minted[key])
        elif isinstance(var, Asked):
            if key in asked:
                value = asked[key].get_secret_value()
                out.values[key] = value
                out.secrets.append(value)
            else:
                out.missing.append(f"asked.{name}.{key}")
        elif isinstance(var, Param):
            if key in params:
                out.values[key] = params[key]
            else:
                out.missing.append(f"params.{name}.{key}")
        elif isinstance(var, FromPassport):
            _from_passport(stack, product, key, var, passport, out)
        elif isinstance(var, Address):
            out.values[key] = (
                address(stack)
                if var.endpoint is None
                else point_address(stack, var.stack or stack.name, var.endpoint)
            )
        elif isinstance(var, Derived):
            out.derived[key] = var.run
            out.values[key] = ""  # its place in the order; filled by the step
        elif isinstance(var, Seam):
            if var.from_ == PRODUCT:
                try:
                    out.values[key] = product_value(product, passport, key)
                except DomainMissing as missing:
                    out.missing.append(f"domains.{missing.name}")
            else:
                seams.setdefault(var.from_, []).append(key)
                out.values[key] = ""  # filled from the memory below
    for provider, names in seams.items():
        try:
            out.values.update(memory.values(provider, names))
        except SeamNotReady as error:
            raise StepFailed(
                "seam-before-health",
                {"from": error.provider, "names": list[Json](error.names)},
            ) from None
    host = stack.host
    for domain in host.domains if host is not None else []:
        if domain not in passport.domains and f"domains.{domain}" not in out.missing:
            out.missing.append(f"domains.{domain}")
    for key, value in out.values.items():
        if key not in out.derived:
            safe(key, value)
    return out
