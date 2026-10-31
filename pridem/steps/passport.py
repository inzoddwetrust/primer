"""The passport of the box (TZ section 6.2 items 1-2, contract 1 section 3).

``age_key`` mints the box's age pair under ``/opt/pridem/keys/age.key`` (0600)
and prints the public part: the owner adds it as a recipient of the box's
passport in the ops repository. A key already in place, 0600 and readable as
a key, needs no ``act``: every later run finds it. A key with another mode is
refused, never ``chmod``-ed: something changed it, and the step does not
guess what.

``fetch_passport`` brings the passport to ``/opt/pridem/passport.yaml``
(0600), a cache: the truth is the ops repository. From the ops repository the
file ``passports/<server>.yaml`` of the fetched commit is taken out of the
bare repository (``/opt/pridem/ops/git``) into a scratch directory with no
output, and ``sops`` decrypts it with the box's key straight into a temporary
file created 0600 beforehand: nothing of the passport passes through stdout,
so nothing of it reaches the console or the journal. sops gets its whole
environment from the machine, ``HOME`` included: with root's ``HOME`` it would
read root's ``~/.ssh`` as an identity. Until the box's key is a recipient sops
exits 128 and the step waits, printing the public part, up to
``RECIPIENT_WAIT_S``; 128 is also sops' code for a key file it cannot read,
so the key is read by ``age-keygen -y`` first and only then does 128 mean
"not a recipient". A passport given as a file (the first box of the Panel)
takes no ops repository and runs no command.

Fields missing from the passport are asked through ``ask`` -- only the leaves
of the schema with a fixed key; ``schema``, ``version`` and the open mappings
(``domains``, ``asked``, ``params``, ``packages``: their keys come from the
stacks' ``primer.yaml``) are never asked, and missing they are a red step.
Answers already in the local copy of the same version are reused, so a box
is asked once per version (contract 1 rule 3). Answers go to the local copy
only; the ops repository is the owner's. The version never changes here.

Nothing is written until the passport loads clean and names this server:
the copy is replaced by rename of the checked temporary file. ``check`` reads
only: ``git ls-remote`` against the head of the bare repository on disk and,
when they match, a decryption into a scratch file compared with the copy;
``fetch`` happens in ``act`` only, so ``doctor`` moves nothing.

The step does not write ``state.json`` (a first ``install`` has no composition
to write): it leaves ``Fetched`` and its fact, and ``with_passport`` gives the
writer of the state its passport version and ops commit. Its ``verify`` adds
the passport's secrets to the run's ``Secrets`` -- the one growing set the
sinks and the verdict hold -- so every later line of the run is cleaned of
them.
"""

import os
import shutil
import tempfile
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import ClassVar

import yaml
from pydantic import SecretStr, ValidationError

from pridem.events import Fact, Json, Secrets
from pridem.runner import OnLine, Stream
from pridem.stacks.loader import ContractError, load_yaml_mapping, render_path
from pridem.stacks.passport import PASSPORT, Passport, load_passport
from pridem.state import BoxState
from pridem.steps.base import (
    CheckResult,
    Mode,
    Step,
    StepContext,
    StepFailed,
    Verified,
    local_code,
)
from pridem.steps.git import KEYS, git_env, repo, run_git
from pridem.steps.keys import DeployKey
from pridem.steps.sources import Checkout, remote_target

AGE_KEY = KEYS / "age.key"
"""The box's age identity (contract 2 section 3, ``keys/``)."""

PASSPORT_COPY = Path("opt/pridem/passport.yaml")
"""The decrypted copy of the passport on the box (contract 1 section 3)."""

OPS_STACK = "pridem/ops"
"""``Checkout`` of the ops repository: ``/opt/pridem/ops/git``."""

RECIPIENT_WAIT_S = 1800
"""How long ``fetch_passport`` waits for the owner to add the box's key."""

NOT_RECIPIENT = 128
"""sops 3.13.3: the data key cannot be decrypted with the identities given."""

DAMAGED = (1, 25)
"""sops 3.13.3: not a sops file or bad YAML (1), a tampered value (25)."""

NEVER_ASKED = frozenset({("schema",), ("version",)})

ALL_MODES: frozenset[Mode] = frozenset({"install", "deploy", "reinstall"})

Ask = Callable[[str, Mapping[str, Json]], str | None]
"""``ask(field, schema)``: the answer for a missing field, ``None`` for none."""

Data = dict[str, object]


@dataclass
class Fetched:
    """What ``fetch_passport`` read back: the passport and the ops commit.

    The passport's secrets (``asked``, ``tls``) are in the run's ``Secrets``
    from ``verify`` of ``fetch_passport`` on: every later line, fact and the
    verdict are cleaned of them. ``render_env`` replaces ``passport`` when an
    answer of ``install`` is written to the local copy.
    """

    passport: Passport | None = None
    ops_commit: str | None = None


def with_passport(state: BoxState, fetched: Fetched) -> BoxState:
    """``state`` with the passport version and ops commit of ``fetched``."""
    if fetched.passport is None:
        raise RuntimeError("no passport fetched: fetch_passport did not run")
    fields: dict[str, object] = {
        "composition": state.composition,
        "passport_version": fetched.passport.version,
        "current": state.current,
        "last_run": state.last_run,
    }
    if fetched.ops_commit is not None:
        fields["ops_commit"] = fetched.ops_commit
    return BoxState.model_validate(fields)


def passport_secrets(passport: Passport) -> list[SecretStr]:
    """The known secrets of a passport: every ``asked`` value and ``tls``."""
    found = [value for stack in passport.asked.values() for value in stack.values()]
    tls = passport.policies.tls
    if tls is not None:
        found += [tls.cert, tls.key]
    return found


def _keep(ctx: StepContext, out: list[str]) -> OnLine:
    def keep(stream: Stream, line: str, cut: bool) -> None:
        ctx.on_line(stream, line, cut)
        if stream is Stream.STDOUT:
            out.append(line)

    return keep


def public_key(ctx: StepContext, key: Path) -> str | None:
    """The public part of ``key`` by ``age-keygen -y``; ``None`` if not a key."""
    out: list[str] = []
    result = ctx.runner.run(
        ["age-keygen", "-y", str(key)],
        expect=(0, 1),
        timeout=60,
        on_line=_keep(ctx, out),
    )
    return out[0].strip() if result.code == 0 and out else None


def _mode(path: Path) -> str:
    return oct(path.stat().st_mode & 0o777)


def _fsync_dir(directory: Path) -> None:
    fd = os.open(directory, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _empty_0600(path: Path) -> None:
    """``path`` empty and 0600, whatever was there and whatever the umask."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.fchmod(fd, 0o600)
    finally:
        os.close(fd)


class AgeKey(Step):
    """The box's age pair: minted once, never re-moded, never replaced."""

    name = "age_key"
    order = 1
    modes = ALL_MODES
    codes: ClassVar[dict[str, str]] = {
        "mint": "mint the box's age key",
        "key-mode": "the age key {path} is {mode}, not 0o600; it is left as it is",
        "key-unreadable": "the age key {path} cannot be read as an age key",
    }

    def __init__(self, root: Path = Path("/")) -> None:
        self.root = root

    @property
    def _key(self) -> Path:
        return self.root / AGE_KEY

    def _read(self, ctx: StepContext) -> str:
        """The public part of a key in place: 0600 and a key, or red."""
        mode = _mode(self._key)
        if mode != oct(0o600):
            raise StepFailed("key-mode", {"path": str(self._key), "mode": mode})
        public = public_key(ctx, self._key)
        if public is None:
            raise StepFailed("key-unreadable", {"path": str(self._key)})
        return public

    def check(self, ctx: StepContext) -> CheckResult:
        if not self._key.exists():
            return CheckResult(True, local_code("mint"))
        self._read(ctx)
        return CheckResult(False)

    def act(self, ctx: StepContext, check: CheckResult) -> None:
        keys = self._key.parent
        keys.mkdir(mode=0o700, parents=True, exist_ok=True)
        temp = self._key.with_name(self._key.name + ".tmp")
        temp.unlink(missing_ok=True)  # left by a run that died
        ctx.runner.run(["age-keygen", "-o", str(temp)], timeout=60, on_line=ctx.on_line)
        temp.chmod(0o600)
        os.replace(temp, self._key)
        _fsync_dir(keys)
        ctx.on_line(Stream.STDOUT, "age key of this box:", False)
        ctx.on_line(Stream.STDOUT, self._read(ctx), False)

    def verify(self, ctx: StepContext, check: CheckResult) -> Verified:
        public = self._read(ctx)
        return Verified(
            {"key": str(self._key), "key_mode": oct(0o600), "public_key": public}
        )


class _OpsKey(DeployKey):
    """The ops repository's deploy key, after the age key in the ladder."""

    order = 2


def _object(value: object) -> dict[str, Json]:
    """A mapping of the passport's JSON Schema; anything else is a broken schema."""
    if not isinstance(value, dict):
        raise TypeError(f"the passport schema has {type(value).__name__} for a node")
    return value


def _resolve(node: Mapping[str, Json], defs: Mapping[str, Json]) -> dict[str, Json]:
    """A schema node with ``$ref`` followed and an optional's ``null`` dropped."""
    while True:
        ref = node.get("$ref")
        if isinstance(ref, str):
            node = _object(defs[ref.rsplit("/", 1)[-1]])
            continue
        members = node.get("anyOf")
        if isinstance(members, list):
            chosen = [
                m for m in members if isinstance(m, dict) and m != {"type": "null"}
            ]
            node = chosen[0]
            continue
        return dict(node)


def schema_at(path: tuple[str, ...]) -> dict[str, Json]:
    """The passport's schema node at ``path``."""
    root = PASSPORT.json_schema(mode="validation")
    defs = _object(root.get("$defs", {}))
    node = _resolve(root, defs)
    for segment in path:
        properties = node.get("properties")
        if isinstance(properties, dict) and segment in properties:
            child = properties[segment]
        else:
            child = node.get("additionalProperties", {})
        node = _resolve(_object(child), defs)
    return node


def _leaves(path: tuple[str, ...]) -> list[tuple[str, ...]] | None:
    """The askable leaves under a missing ``path``; ``None`` if it is not askable.

    A fixed object is its required fields, recursively; an open mapping, an
    object with no required field, ``schema`` and ``version`` are not asked.
    """
    if path in NEVER_ASKED:
        return None
    node = schema_at(path)
    if node.get("type") != "object":
        return [path]
    properties = node.get("properties")
    required = node.get("required")
    if not isinstance(properties, dict) or not isinstance(required, list):
        return None
    if not required:
        return None
    out: list[tuple[str, ...]] = []
    for name in required:
        found = _leaves((*path, str(name)))
        if found is None:
            return None
        out += found
    return out


def _missing(data: Data) -> list[tuple[str, ...]]:
    """Paths of fields the passport's model reports missing, in its order."""
    try:
        PASSPORT.validate_python(data)
    except ValidationError as error:
        return [
            tuple(str(segment) for segment in item["loc"])
            for item in error.errors(include_url=False)
            if item["type"] == "missing"
        ]
    return []


def _get(data: object, path: tuple[str, ...]) -> tuple[bool, object]:
    node = data
    for segment in path:
        if not isinstance(node, dict) or segment not in node:
            return False, None
        node = node[segment]
    return True, node


def _put(data: Data, path: tuple[str, ...], value: object) -> None:
    node = data
    for segment in path[:-1]:
        child = node.setdefault(segment, {})
        if not isinstance(child, dict):
            return  # a wrong type here is the model's to report
        node = child
    node[path[-1]] = value


def _answer(text: str, schema: Mapping[str, Json]) -> object:
    """A typed value of an answer: YAML for a non-string leaf, as typed else."""
    if schema.get("type") in ("integer", "boolean", "number"):
        return yaml.safe_load(text)
    return text


def _problems(error: ContractError) -> list[Json]:
    """Where and which check, never what the file says."""
    return [f"{p.path or '<root>'} [{p.code}]" for p in error.problems]


def _load(file: Path) -> Data:
    try:
        return load_yaml_mapping(file)
    except ContractError as error:
        raise StepFailed("invalid", {"problems": _problems(error)}) from None


def _copy_data(copy: Path) -> Data | None:
    """The local copy as data; ``None`` when there is none or it does not read."""
    if not copy.is_file():
        return None
    try:
        return load_yaml_mapping(copy)
    except ContractError:
        return None  # a damaged cache is replaced, not trusted


def _write_checked(temp: Path, data: Data) -> Passport:
    """``data`` written to ``temp`` (0600) and loaded clean, or ``invalid``."""
    _empty_0600(temp)
    with temp.open("w", encoding="utf-8") as handle:
        yaml.safe_dump(data, handle, sort_keys=False, allow_unicode=True)
        handle.flush()
        os.fsync(handle.fileno())
    try:
        return load_passport(temp)
    except ContractError as error:
        raise StepFailed("invalid", {"problems": _problems(error)}) from None


def copy_data(root: Path) -> Data:
    """The local copy of the passport as data, values in the clear."""
    return _load(root / PASSPORT_COPY)


def rewrite_copy(root: Path, data: Data) -> Passport:
    """The local copy replaced by ``data`` once it loads clean (answers of
    ``install``, contract 1 rule 3); the version is the caller's to keep."""
    copy = root / PASSPORT_COPY
    temp = copy.with_name(copy.name + ".tmp")
    try:
        passport = _write_checked(temp, data)
        os.replace(temp, copy)
        _fsync_dir(copy.parent)
    finally:
        temp.unlink(missing_ok=True)
    return passport


@dataclass(frozen=True)
class OpsSource:
    """Where the passport lives: the ops repository and its branch."""

    address: str
    ref: str = "main"


class FetchPassport(Step):
    """The passport from the ops repository (``ops``) or from a file (``file``)."""

    name = "fetch_passport"
    order = 3
    modes = ALL_MODES
    codes: ClassVar[dict[str, str]] = {
        "fetch": "fetch passports/{server}.yaml from {repo}",
        "copy": "copy the passport from {file}",
        "no-ref": "the ops repository {repo} has no branch {ref}",
        "not-in-ops": "the ops repository has no {path} at {commit}",
        "not-recipient": (
            "passports/{server}.yaml is not encrypted for this box's key "
            "{public_key} after {wait_s} s"
        ),
        "damaged": (
            "{path} is not a sops file it can decrypt — sops exit code {exit_code}"
        ),
        "invalid": "the passport is rejected: {problems}",
        "name-mismatch": "the passport is for server {found}, not {expected}",
        "missing": "the passport lacks {fields} and they are not asked here",
        "no-answer": "no answer for {field}",
        "copy-mode": "the passport copy {path} is {mode}, not 0o600",
        "key-unreadable": "the age key {path} cannot be read as an age key",
    }

    def __init__(
        self,
        fetched: Fetched,
        root: Path = Path("/"),
        *,
        secrets: Secrets,
        server: str | None,
        ops: OpsSource | None = None,
        file: Path | None = None,
        ask: Ask | None = None,
        wait_s: float = RECIPIENT_WAIT_S,
        poll_s: float = 10.0,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        if (ops is None) == (file is None):
            raise ValueError("a passport comes from the ops repository or a file")
        if ops is not None and server is None:
            raise ValueError("the ops repository is read by the server's name")
        self.fetched = fetched
        self.root = root
        self.secrets = secrets
        self.server = server
        self.ops = ops
        self.file = file
        self.ask = ask
        self.wait_s = wait_s
        self.poll_s = poll_s
        self.clock = clock
        self.sleep = sleep

    # --- places ---------------------------------------------------------------

    @property
    def _copy(self) -> Path:
        return self.root / PASSPORT_COPY

    @property
    def _key(self) -> Path:
        return self.root / AGE_KEY

    @property
    def _path(self) -> str:
        return f"passports/{self.server}.yaml"

    @property
    def _ops(self) -> OpsSource:
        if self.ops is None:
            raise RuntimeError("the ops repository is used by a passport from a file")
        return self.ops

    def _checkout(self) -> Checkout:
        return Checkout(self.root, OPS_STACK, repo(self._ops.address))

    # --- the ops repository ---------------------------------------------------

    def _remote_head(self, ctx: StepContext) -> str:
        found = repo(self._ops.address)
        target = remote_target(ctx, self.root, found, self._ops.ref, tag=False)
        if target is None:
            raise StepFailed(
                "no-ref", {"repo": self._ops.address, "ref": self._ops.ref}
            )
        return target.commit

    def _bare_head(self, ctx: StepContext) -> str | None:
        """The branch's commit in the bare repository on disk, if any."""
        checkout = self._checkout()
        if not (checkout.bare / "HEAD").exists():
            return None
        code, lines = checkout.git(
            ctx,
            "rev-parse",
            "--verify",
            "--quiet",
            f"refs/heads/{self._ops.ref}",
            expect=(0, 1),
        )
        return lines[0] if code == 0 and lines else None

    def _decrypt(self, ctx: StepContext, commit: str, out: Path) -> int:
        """``passports/<server>.yaml`` of ``commit`` decrypted into ``out``
        (0600); sops' exit code: 0, or ``NOT_RECIPIENT``."""
        checkout = self._checkout()
        scratch = Path(tempfile.mkdtemp(prefix="cipher.", dir=checkout.home))
        try:
            (scratch / "tree").mkdir()  # git refuses a work tree that is not there
            env = {**git_env(self.root), "GIT_INDEX_FILE": str(scratch / "index")}
            code, _ = run_git(
                ctx,
                self.root,
                [
                    "--git-dir",
                    str(checkout.bare),
                    "--work-tree",
                    str(scratch / "tree"),
                    "checkout",
                    commit,
                    "--",
                    self._path,
                ],
                expect=(0, 1),
                env=env,
            )
            if code != 0:
                raise StepFailed("not-in-ops", {"path": self._path, "commit": commit})
            _empty_0600(out)
            result = ctx.runner.run(
                [
                    "sops",
                    "--decrypt",
                    "--input-type",
                    "yaml",
                    "--output-type",
                    "yaml",
                    "--output",
                    str(out),
                    str(scratch / "tree" / self._path),
                ],
                expect=(0, NOT_RECIPIENT, *DAMAGED),
                timeout=120,
                env=self._sops_env(),
                on_line=ctx.on_line,
            )
        finally:
            shutil.rmtree(scratch)
        if result.code in DAMAGED:
            raise StepFailed("damaged", {"path": self._path, "exit_code": result.code})
        return result.code

    def _sops_env(self) -> dict[str, str]:
        """sops' whole environment: the box's key, the machine's ``HOME``."""
        return {
            "PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
            "HOME": str(self.root / KEYS),
            "SOPS_AGE_KEY_FILE": str(self._key),
        }

    # --- the passport ---------------------------------------------------------

    def _compose(self, data: Data, *, asking: bool) -> tuple[Data, bool]:
        """``data`` with missing fields from the copy of the same version, then
        asked; whether something is still missing (``asking`` false only)."""
        copy = _copy_data(self._copy)
        if copy is not None and copy.get("version") == data.get("version"):
            for path in _missing(data):
                present, value = _get(copy, path)
                if present:
                    _put(data, path, value)
        missing = _missing(data)
        if not missing:
            return data, False
        leaves: list[tuple[str, ...]] = []
        fields = [render_path(path) for path in missing]
        for path in missing:
            found = _leaves(path)
            if found is None:
                raise StepFailed("missing", {"fields": list[Json](fields)})
            leaves += found
        if not asking:
            return data, True
        if self.ask is None:
            names = [render_path(leaf) for leaf in leaves]
            raise StepFailed("missing", {"fields": list[Json](names)})
        for leaf in leaves:
            schema = schema_at(leaf)
            answer = self.ask(render_path(leaf), schema)
            if not answer:
                raise StepFailed("no-answer", {"field": render_path(leaf)})
            _put(data, leaf, _answer(answer, schema))
        return data, False

    def _accept(self, temp: Path, data: Data) -> Passport:
        """``data`` written to ``temp`` (0600), loaded clean, for this server."""
        passport = _write_checked(temp, data)
        if self.server is not None and passport.server.name != self.server:
            raise StepFailed(
                "name-mismatch",
                {"expected": self.server, "found": passport.server.name},
            )
        return passport

    def _source(self, ctx: StepContext, temp: Path, commit: str | None) -> Data:
        """The passport's data: decrypted from ``commit`` or read from the file."""
        if self.file is not None:
            return _load(self.file)
        if commit is None:
            raise RuntimeError("the ops repository was not fetched")
        if self._decrypt(ctx, commit, temp) == NOT_RECIPIENT:
            raise _NotRecipient
        return _load(temp)

    # --- the step -------------------------------------------------------------

    def check(self, ctx: StepContext) -> CheckResult:
        previous = _copy_data(self._copy)
        data: dict[str, Json] = {}
        version = None if previous is None else previous.get("version")
        if isinstance(version, int):
            data["previous"] = version
        if self.file is not None:
            would = local_code("copy", {"file": str(self.file)})
        else:
            params: dict[str, Json] = {"server": self.server, "repo": self._ops.address}
            would = local_code("fetch", params)
        needed = CheckResult(True, would, data)
        if previous is None:
            return needed
        commit: str | None = None
        if self.ops is not None:
            commit = self._remote_head(ctx)
            if not self._key.exists() or self._bare_head(ctx) != commit:
                return needed
        scratch = self._copy.with_name(self._copy.name + ".check")
        try:
            composed, short = self._compose(
                self._source(ctx, scratch, commit), asking=False
            )
        except _NotRecipient:
            return needed
        finally:
            scratch.unlink(missing_ok=True)
        if short or composed != previous:
            return needed
        return CheckResult(False, None, data)

    def act(self, ctx: StepContext, check: CheckResult) -> None:
        self._copy.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        temp = self._copy.with_name(self._copy.name + ".tmp")
        try:
            commit = self._fetch(ctx) if self.ops is not None else None
            data = self._wait(ctx, temp, commit)
            composed, _ = self._compose(data, asking=True)
            self._accept(temp, composed)
            os.replace(temp, self._copy)
            _fsync_dir(self._copy.parent)
        finally:
            temp.unlink(missing_ok=True)

    def _fetch(self, ctx: StepContext) -> str:
        self._checkout().fetch(ctx)
        head = self._bare_head(ctx)
        if head is None:
            raise StepFailed(
                "no-ref", {"repo": self._ops.address, "ref": self._ops.ref}
            )
        return head

    def _wait(self, ctx: StepContext, temp: Path, commit: str | None) -> Data:
        """The passport's data; from the ops repository, once this box is a
        recipient -- fetched again on every poll, until ``wait_s``."""
        deadline = self.clock() + self.wait_s
        shown: str | None = None
        while True:
            try:
                return self._source(ctx, temp, commit)
            except _NotRecipient:
                pass
            if shown is None:
                # sops says 128 for an unreadable key too: only a key that
                # reads makes 128 mean "not a recipient"
                shown = public_key(ctx, self._key)
                if shown is None:
                    raise StepFailed("key-unreadable", {"path": str(self._key)})
                ctx.on_line(
                    Stream.STDOUT,
                    f"add the age key of this box as a recipient of {self._path}:",
                    False,
                )
                ctx.on_line(Stream.STDOUT, shown, False)
            if self.clock() >= deadline:
                raise StepFailed(
                    "not-recipient",
                    {"server": self.server, "public_key": shown, "wait_s": self.wait_s},
                )
            self.sleep(self.poll_s)
            commit = self._fetch(ctx)

    def verify(self, ctx: StepContext, check: CheckResult) -> Verified:
        mode = _mode(self._copy) if self._copy.exists() else "none"
        if mode != oct(0o600):
            raise StepFailed("copy-mode", {"path": str(self._copy), "mode": mode})
        try:
            passport = load_passport(self._copy)
        except ContractError as error:
            raise StepFailed("invalid", {"problems": _problems(error)}) from None
        if self.server is not None and passport.server.name != self.server:
            raise StepFailed(
                "name-mismatch",
                {"expected": self.server, "found": passport.server.name},
            )
        fact: Fact = {
            "source": "file" if self.file is not None else "ops",
            "server": passport.server.name,
            "version": passport.version,
            "copy_mode": mode,
        }
        previous = check.data.get("previous")
        if previous is not None:
            fact = {**fact, "previous": previous}
        commit: str | None = None
        if self.ops is not None:
            commit = self._bare_head(ctx)
            if commit is None:
                raise StepFailed(
                    "no-ref", {"repo": self._ops.address, "ref": self._ops.ref}
                )
            fact = {**fact, "ops_commit": commit}
        # before the fact leaves the step: from here on the run cleans them
        self.secrets.add(passport_secrets(passport))
        self.fetched.passport = passport
        self.fetched.ops_commit = commit
        return Verified(fact)


class _NotRecipient(Exception):
    """sops could not decrypt with the box's key: not a recipient yet."""


def passport_steps(
    root: Path,
    *,
    secrets: Secrets,
    server: str | None,
    ops: OpsSource | None = None,
    file: Path | None = None,
    ask: Ask | None = None,
    wait_s: float = RECIPIENT_WAIT_S,
    poll_s: float = 10.0,
) -> tuple[Fetched, list[Step]]:
    """The passport ladder: from the ops repository -- the age key, the ops
    repository's deploy key, the passport; from a file -- the passport only."""
    fetched = Fetched()
    fetch = FetchPassport(
        fetched,
        root,
        secrets=secrets,
        server=server,
        ops=ops,
        file=file,
        ask=ask,
        wait_s=wait_s,
        poll_s=poll_s,
    )
    if ops is None:
        return fetched, [fetch]
    key = _OpsKey(ops.address, root, name="ops_key", wait_s=wait_s, poll_s=poll_s)
    return fetched, [AgeKey(root), key, fetch]
