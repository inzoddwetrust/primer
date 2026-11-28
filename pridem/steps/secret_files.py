"""Secret files (DM-145): ``asked`` that reaches its container as a file.

A stack declares ``{source: asked, file: {path, services}}`` (contract 3); the
value is its ``asked`` in the passport, multi-line as a YAML block -- an age
key, an ssh key -- and it never goes in the env file, the container's
environment, the verdict or the journal. The machine writes one file per key
and service in the stack's ``env/files/`` (0700, root) -- 0600, owned by the
user the service runs as -- and the override binds it read-only at ``path``.

* **The name** is ``<KEY>@<service>@<token>``: a random token, new whenever
  the value changes -- never a hash of the value, which the verdict would
  carry to ``history/`` and the Panel forever. A new value is a new path: the
  service's configuration changes and ``up`` recreates it (a bind holds the
  inode; a file replaced in place would never reach the running container --
  the lesson of DM-81).
* **The owner** is the uid:gid of the service: ``user:`` of the service in
  compose (protocol 3.3), else ``USER`` of its image; a name is resolved in a
  throwaway container of the image, no network; ``user:`` a number with no
  entry in the image's ``/etc/passwd`` runs with group 0 (measured on tier 3);
  no user -- root. A name the image does not know -- ``file-owner``.
* ``check`` compares a file with the value itself: the machine knows the value
  and root reads the file. The fact names the key, the service, the path in
  the container, the uid and the mode -- never the value, never its hash.
"""

import os
import secrets
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

from pridem.events import Json
from pridem.files import atomic_write, private_dir
from pridem.stacks.env import ENV_DIR, file_keys, own_entry
from pridem.stacks.options import off_keys, switched_on
from pridem.stacks.passport import Passport
from pridem.stacks.schema import Asked
from pridem.steps.base import StepContext, StepFailed
from pridem.steps.compose import COMMAND_TIMEOUT_S, ComposeStack, out

FILES_DIR = "files"
MODE = 0o600


@dataclass(frozen=True)
class Wanted:
    """One file: the key, the service it goes to, its path there, its value."""

    key: str
    service: str
    path: str
    value: str


def files_dir(compose: ComposeStack) -> Path:
    """``/opt/<stack>/env/files``."""
    return compose.root / "opt" / compose.stack.name / ENV_DIR / FILES_DIR


def wanted(compose: ComposeStack, passport: Passport | None) -> list[Wanted]:
    """The files of the stack's own entry: every secret file of an option on,
    for each of its services (``app`` without the field). A value the passport
    lacks is ``render_env``'s refusal (``asked-file-missing``) before here."""
    stack = compose.stack
    if passport is None or compose.entry != own_entry(stack):
        return []
    off = set(off_keys(stack, switched_on(passport)))
    given = passport.asked.get(stack.name, {})
    out_: list[Wanted] = []
    for key in file_keys(stack):
        var = stack.env[key]
        if key in off or key not in given or not isinstance(var, Asked):
            continue
        if var.file is None:
            continue
        services = var.file.services or [compose.app_service or "app"]
        value = given[key].get_secret_value()
        out_ += [Wanted(key, service, var.file.path, value) for service in services]
    return out_


def matching(compose: ComposeStack, item: Wanted) -> Path | None:
    """The file of ``item`` already on disk with its value, or ``None``."""
    directory = files_dir(compose)
    if not directory.is_dir():
        return None
    for path in sorted(directory.glob(f"{item.key}@{item.service}@*")):
        if path.is_file() and not path.is_symlink():
            if path.read_bytes() == item.value.encode():
                return path
    return None


def new_path(compose: ComposeStack, item: Wanted) -> Path:
    """A new name for ``item``: a random token, nothing of the value."""
    token = secrets.token_hex(8)
    return files_dir(compose) / f"{item.key}@{item.service}@{token}"


def binds(chosen: Mapping[Wanted, Path]) -> dict[str, list[Json]]:
    """The override's read-only binds of the files, by service."""
    out_: dict[str, list[Json]] = {}
    for item, path in sorted(chosen.items(), key=lambda pair: str(pair[1])):
        bind: dict[str, Json] = {
            "type": "bind",
            "source": str(path),
            "target": item.path,
            "read_only": True,
        }
        out_.setdefault(item.service, []).append(bind)
    return out_


def _id(ctx: StepContext, image: str, *args: str) -> str | None:
    """``id <args>`` (or ``getent``) in a throwaway container of ``image``, no
    network: its one line, or ``None`` when it does not know the name."""
    code, lines = out(
        ctx,
        ["docker", "run", "--rm", "--network", "none", "--entrypoint", args[0],
         "--", image, *args[1:]],
        expect=(0, 1, 2),
        timeout=COMMAND_TIMEOUT_S,
    )  # fmt: skip
    return lines[0].strip() if code == 0 and lines else None


def owner(
    ctx: StepContext, service: str, image: str, document: Mapping[str, Json]
) -> tuple[int, int]:
    """The uid:gid ``service`` runs as: ``user:`` of compose, else ``USER`` of
    its image; a name resolved in the image; a number with no entry -- group
    0; nothing -- root."""
    services = document.get("services")
    body = services.get(service) if isinstance(services, dict) else None
    user = body.get("user") if isinstance(body, dict) else None
    if not isinstance(user, str) or not user:
        _, lines = out(
            ctx,
            ["docker", "image", "inspect", "-f", "{{.Config.User}}", "--", image],
            timeout=COMMAND_TIMEOUT_S,
        )
        user = lines[0].strip() if lines else ""
    if not user:
        return 0, 0
    name, _, group = user.partition(":")
    refused = StepFailed("file-owner", {"service": service})
    if name.isdigit():
        uid = int(name)
    else:
        found = _id(ctx, image, "id", "-u", name)
        if found is None or not found.isdigit():
            raise refused
        uid = int(found)
    if group:
        if group.isdigit():
            return uid, int(group)
        line = _id(ctx, image, "getent", "group", group)
        parts = line.split(":") if line else []
        if len(parts) < 3 or not parts[2].isdigit():
            raise refused
        return uid, int(parts[2])
    found = _id(ctx, image, "id", "-g", name)
    if found is not None and found.isdigit():
        return uid, int(found)
    if name.isdigit():
        return uid, 0  # a uid with no entry runs with group 0 (tier 3 measures)
    raise refused


def as_owned(path: Path) -> tuple[int, int, int]:
    """uid, gid and mode of ``path``, not following a link."""
    found = os.lstat(path)
    return found.st_uid, found.st_gid, found.st_mode & 0o777


def write(compose: ComposeStack, path: Path, value: str, uid: int, gid: int) -> None:
    """``value`` at ``path``, 0600, owned by ``uid:gid``: written whole
    (temp, fsync, rename) in the stack's ``env/files`` (0700)."""
    private_dir(files_dir(compose))
    if not path.exists() or path.read_bytes() != value.encode():
        atomic_write(path, value.encode(), MODE)
    os.chown(path, uid, gid)
    os.chmod(path, MODE)


def unnamed(root: Path, stack: str) -> list[Path]:
    """The secret files of ``stack`` no override of it names -- neither the
    running release's nor the deploy's: ``finalize`` takes them after the
    switch, when no container can still hold one (DM-145)."""
    directory = root / "opt" / stack / ENV_DIR / FILES_DIR
    if not directory.is_dir():
        return []
    overrides = root / "opt" / stack / "compose"
    named = (
        "".join(
            file.read_text(encoding="utf-8")
            for file in sorted(overrides.glob("*.yml"))
            if file.is_file()
        )
        if overrides.is_dir()
        else ""
    )
    return [file for file in sorted(directory.iterdir()) if str(file) not in named]
