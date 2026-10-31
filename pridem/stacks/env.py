"""The environment of a stack (contract 3 section 3, rules 13, 18; TZ 7.3, 8).

Every variable of ``env`` has a source; this module turns the sources that need
no command into values and keeps the two files of a stack's environment under
``/opt/<name>/env/`` (0700), ``<name>`` being the ``name`` of its
``primer.yaml``:

- ``minted.yaml`` (0600): the ``minted`` secrets, minted once by
  ``secrets.token_urlsafe(32)`` -- 43 characters of ``[A-Za-z0-9_-]``, safe in
  a URL, an env file and a command. A key is never minted again; a key the
  schema no longer has stays (the stack's data; ``destroy`` removes it).
- ``.env`` (0600): every variable as ``KEY='value'`` -- a single-quoted value
  is taken as it is by compose's ``--env-file``, with no interpolation. A value
  with ``'`` or a line break cannot be written so: refused, by its key only.

Both are written as a temporary 0600 file, fsync and rename. A file found
with another mode is refused, never ``chmod``-ed.

``resolve`` answers every source but ``derived`` (a command in the stack's
container: the step runs it) and reports the fields the passport lacks
(``asked``, ``params``, a domain of ``host.domains``, ``edition``): those are
asked by ``install`` (contract 1 rule 3). ``param`` and ``address`` are not
secrets; ``asked`` and ``minted`` are, and so is a ``seam`` from a provider
whose variable is one -- the provider's step put it in the run's set first.
"""

import os
import re
import secrets as token
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from pridem.events import Json
from pridem.stacks.loader import ContractError, load_yaml_mapping
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
MINT_BYTES = 32
"""``token_urlsafe(32)``: 43 characters of ``[A-Za-z0-9_-]`` (measured)."""

MINTED_FORM = re.compile(r"[A-Za-z0-9_-]{32,}")
_LINE = re.compile(r"([A-Za-z_][A-Za-z0-9_]*)='([^'\n\r]*)'")
_UNSAFE = ("'", "\n", "\r")
_PLACEHOLDER = re.compile(r"<.*>")

Stack = Product | Service


def env_dir(root: Path, name: str) -> Path:
    return root / "opt" / name / ENV_DIR


def mint() -> str:
    return token.token_urlsafe(MINT_BYTES)


def mode_of(path: Path) -> str:
    return oct(path.stat().st_mode & 0o777)


def _fsync_dir(directory: Path) -> None:
    fd = os.open(directory, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def write_private(path: Path, text: str) -> None:
    """``text`` to ``path`` (0600, directory 0700): temp, fsync, rename."""
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    temp = path.with_name(path.name + ".tmp")
    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp, path)
        _fsync_dir(path.parent)
    finally:
        temp.unlink(missing_ok=True)


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
    """Empty, ``<…>`` whole, or an unresolved ``${…}``."""
    return not value or bool(_PLACEHOLDER.fullmatch(value)) or "${" in value


@dataclass
class Resolved:
    """What ``resolve`` found: values, secrets among them, what to ask, what
    to derive."""

    values: dict[str, str] = field(default_factory=dict)
    secrets: list[str] = field(default_factory=list)
    missing: list[str] = field(default_factory=list)
    derived: dict[str, str] = field(default_factory=dict)


def address(stack: Stack) -> str:
    """``http://<stack>-<app.service>:<app.port>`` on the network ``pridem``."""
    entry = stack.stacks.get(stack.name)
    if entry is None or entry.app is None:
        raise StepFailed("address-no-app", {"stack": stack.name})
    return f"http://{stack.name}-{entry.app.service}:{entry.app.port}"


def _from_passport(
    stack: Stack, key: str, var: FromPassport, passport: Passport, out: Resolved
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
    """Every source of ``stack`` but ``derived``, in schema order."""
    out = Resolved()
    name = stack.name
    asked = passport.asked.get(name, {})
    params = passport.params.get(name, {})
    seams: dict[str, list[str]] = {}
    for key, var in stack.env.items():
        if isinstance(var, Minted):
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
            _from_passport(stack, key, var, passport, out)
        elif isinstance(var, Address):
            out.values[key] = address(stack)
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
