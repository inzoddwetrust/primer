"""The env steps (TZ 7.1, 7.3; contract 3 section 3, rules 13, 18).

``seams_check`` refuses a plan with a half seam, an edition the product does
not declare, data a service does not accept or routes of a co-located service
before the first ``act`` of a stack: the plan builder puts it ahead of the
services' ladders, once ``fetch_services`` has read their ``primer.yaml`` (the
edition decides which services are installed).

``render_env`` renders a stack's ``.env`` from its schema and reads it back.
Every secret enters the run's ``Secrets`` -- the one growing set the sinks and
the verdict hold -- before any line that could carry it: the passport's and
the minted ones in ``check``, an answer of ``install`` once it is written, a
``derived`` value as soon as its command ends. A secret never goes to an argv:
``derive`` gets the stack's other values through an env file (0600) that
``docker run`` reads, and its output is kept by the step -- stdout is the
value, nothing of it reaches the console or the journal; on a non-zero exit
only stderr is passed on.

``derive`` runs only in ``act``: ``check`` takes a ``derived`` value from the
``.env`` on disk and compares the rest. It runs ``docker run --rm --env-file
<file> <image> <run>`` in a throwaway container of the stack's image, not
``docker compose run``: compose
interpolates the whole file, and ``${VAR:?}`` of a variable not rendered yet
-- the derived one itself -- stops it. The image is an input: the build step
gives it (DM-18).

A missing ``asked``, ``params``, domain or ``edition`` is asked through
``ask`` (contract 1 rule 3, owner's decision of 27.10); with nobody to ask it
is red in ``check``, before ``act`` writes anything. An answer passes the
passport's model and goes to the local copy; the version does not change.
"""

import shlex
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import ClassVar

from pydantic import SecretStr

from pridem.contract import SECRET_MIN_LENGTH
from pridem.events import Json, Secrets
from pridem.runner import CommandFailed, Stream
from pridem.stacks.env import (
    ENV_FILE,
    MINTED_FILE,
    Resolved,
    env_dir,
    env_text,
    mint,
    minted_text,
    mode_of,
    parse_env,
    placeholder,
    private_mode,
    read_minted,
    resolve,
    safe,
    write_private,
)
from pridem.stacks.passport import Passport
from pridem.stacks.schema import Derived, Minted, Product, Service
from pridem.stacks.seams import (
    SeamMemory,
    half_seams,
    installed,
    outside_edition,
    provider_order,
    routes_on_co_located,
    unaccepted,
)
from pridem.steps.base import (
    CheckResult,
    Mode,
    Step,
    StepContext,
    StepFailed,
    Verified,
    local_code,
)
from pridem.steps.passport import (
    NO_PASSPORT,
    Ask,
    Fetched,
    copy_data,
    passport_secrets,
    rewrite_copy,
    schema_at,
)

ALL_MODES: frozenset[Mode] = frozenset({"install", "deploy", "reinstall"})
DERIVE_TIMEOUT_S = 300
DERIVE_ENV = "derive.env"


def _passport(fetched: Fetched) -> Passport:
    if fetched.passport is None:
        raise StepFailed("no-passport")
    return fetched.passport


class SeamsCheck(Step):
    """Every seam of the box has both ends, inside the edition; the edition is
    one of the product's; the data the product gives a service is a kind the
    service accepts; a co-located service has no routes. A co-located service
    the edition leaves out and the box still has (``/opt/<s>/current``) is not
    removed: the fact names it (``left``)."""

    name = "seams_check"
    order = 1
    modes = ALL_MODES
    codes: ClassVar[dict[str, str]] = {
        **NO_PASSPORT,
        "half-seam": "half seams: {seams}",
        "seam-outside-edition": "seams from services outside the edition: {seams}",
        "edition-unknown": "edition {edition} is not in editions",
        "routes-on-co-located": "co-located services declare routes: {services}",
        "data-not-accepted": "data the services do not accept: {data}",
    }

    def __init__(
        self,
        product: Product,
        services: Mapping[str, Service],
        fetched: Fetched,
        root: Path = Path("/"),
    ) -> None:
        self.product = product
        self.services = dict(services)
        self.fetched = fetched
        self.root = root

    def check(self, ctx: StepContext) -> CheckResult:
        edition = _passport(self.fetched).edition
        if (
            self.product.editions
            and edition is not None
            and edition not in self.product.editions
        ):
            raise StepFailed("edition-unknown", {"edition": edition})
        half = half_seams(self.product, self.services, edition)
        if half:
            raise StepFailed("half-seam", {"seams": list[Json](half)})
        outside = outside_edition(self.product, edition)
        if outside:
            raise StepFailed("seam-outside-edition", {"seams": list[Json](outside)})
        routed = routes_on_co_located(self.product, self.services, edition)
        if routed:
            raise StepFailed("routes-on-co-located", {"services": list[Json](routed)})
        refused = unaccepted(self.product, self.services, edition)
        if refused:
            raise StepFailed("data-not-accepted", {"data": list[Json](refused)})
        return CheckResult(False)

    def act(self, ctx: StepContext, check: CheckResult) -> None:
        raise RuntimeError("seams_check never acts")

    def verify(self, ctx: StepContext, check: CheckResult) -> Verified:
        edition = _passport(self.fetched).edition
        order = provider_order(self.product, edition)
        here = set(installed(self.product, edition))
        left = [
            name
            for name, dependency in self.product.dependencies.items()
            if dependency.topology == "co-located"
            and name not in here
            and (self.root / "opt" / name / "current").is_symlink()
        ]
        return Verified({"order": list[Json](order), "left": list[Json](left)})


def _put(data: dict[str, object], path: Sequence[str], value: object) -> None:
    node = data
    for segment in path[:-1]:
        child = node.setdefault(segment, {})
        if not isinstance(child, dict):
            raise StepFailed("invalid", {"problems": [f"{'.'.join(path)} [type]"]})
        node = child
    node[path[-1]] = value


class RenderEnv(Step):
    """``/opt/<name>/env/.env`` of one stack, rendered and read back."""

    name = "render_env"
    order = 2
    modes = ALL_MODES
    codes: ClassVar[dict[str, str]] = {
        **NO_PASSPORT,
        "render": "render the env of {stack}",
        "missing": "the passport lacks {fields} and nobody can be asked",
        "no-answer": "no answer for {field}",
        "invalid": "the answer is rejected: {problems}",
        "minted-mode": "{path} is {mode}, not 0o600; it is left as it is",
        "minted-damaged": "{path} is not a minted file of this machine",
        "env-mode": "{path} is {mode}, not 0o600; it is left as it is",
        "env-unsafe": "the value of {key} has a quote or a line break",
        "env-unreadable": "line {line} of the env file is not KEY='value'",
        "env-keys": "the env file lacks {missing} and has {extra} beyond the schema",
        "placeholder": "the env file holds placeholders for {keys}",
        "edition-unknown": "{key}: edition {edition} is not in editions",
        "passport-key": "{key}: the passport has no source {passport_key}",
        "address-no-app": "{stack} has no app of its own to give an address of",
        "seam-before-health": "{names} of {from} are asked before its health",
        "derive-no-image": "{key} is derived, and no image of the stack is given",
        "derive-failed": "deriving {key} failed — exit code {exit_code}",
        "derive-empty": "deriving {key} printed {lines} lines, not one value",
        "derive-short": "the derived {key} is shorter than 16 characters",
    }

    def __init__(
        self,
        stack: Product | Service,
        *,
        product: Product,
        fetched: Fetched,
        secrets: Secrets,
        memory: SeamMemory,
        root: Path = Path("/"),
        ask: Ask | None = None,
        image: str | None = None,
    ) -> None:
        self.stack = stack
        self.product = product
        self.fetched = fetched
        self.secrets = secrets
        self.memory = memory
        self.root = root
        self.ask = ask
        self.image = image
        self.rendered: dict[str, str] = {}
        self._derived: dict[str, str] = {}

    # --- places -----------------------------------------------------------------

    @property
    def _dir(self) -> Path:
        return env_dir(self.root, self.stack.name)

    @property
    def _env(self) -> Path:
        return self._dir / ENV_FILE

    @property
    def _minted(self) -> Path:
        return self._dir / MINTED_FILE

    def _minted_keys(self) -> list[str]:
        return [k for k, v in self.stack.env.items() if isinstance(v, Minted)]

    # --- sources ----------------------------------------------------------------

    def _known(self) -> tuple[dict[str, str], Resolved]:
        """Minted values on disk and every source but ``derived``; secrets
        among them enter the run's set here, before anything is printed."""
        passport = _passport(self.fetched)
        self.secrets.add(passport_secrets(passport))
        minted = read_minted(self._minted)
        self.secrets.add(SecretStr(value) for value in minted.values())
        unminted = {key: "" for key in self._minted_keys() if key not in minted}
        return minted, resolve(
            self.stack, self.product, passport, {**minted, **unminted}, self.memory
        )

    def _derive(self, ctx: StepContext, values: Mapping[str, str], key: str) -> str:
        """The value printed by ``run`` of ``key`` in the stack's container."""
        if self.image is None:
            raise StepFailed("derive-no-image", {"key": key})
        var = self.stack.env[key]
        if not isinstance(var, Derived):
            raise TypeError(f"{key} is not derived")
        command = shlex.split(var.run)
        known = {k: v for k, v in values.items() if k not in self._derivable()}
        env_file = self._dir / DERIVE_ENV
        lines: list[tuple[Stream, str, bool]] = []

        def keep(stream: Stream, line: str, cut: bool) -> None:
            lines.append((stream, line, cut))

        try:
            # the docker form of an env file: KEY=value, taken as it is
            write_private(env_file, "".join(f"{k}={v}\n" for k, v in known.items()))
            ctx.runner.run(
                [
                    "docker",
                    "run",
                    "--rm",
                    "--label",
                    f"pridem.stack={self.stack.name}",
                    "--env-file",
                    str(env_file),
                    self.image,
                    *command,
                ],
                timeout=DERIVE_TIMEOUT_S,
                on_line=keep,
            )
        except CommandFailed as error:
            for stream, line, cut in lines:
                if stream is Stream.STDERR:  # stdout may hold part of a value
                    ctx.on_line(stream, line, cut)
            raise StepFailed(
                "derive-failed", {"key": key, "exit_code": error.code}
            ) from None
        finally:
            env_file.unlink(missing_ok=True)
        out = [
            line.strip() for s, line, _ in lines if s is Stream.STDOUT and line.strip()
        ]
        if len(out) != 1:
            raise StepFailed("derive-empty", {"key": key, "lines": len(out)})
        value = out[0]
        if len(value) < SECRET_MIN_LENGTH:
            raise StepFailed("derive-short", {"key": key})
        self.secrets.add([SecretStr(value)])
        for stream, line, cut in lines:
            if stream is Stream.STDERR:  # cleaned of the value from here on
                ctx.on_line(stream, line, cut)
        safe(key, value)
        return value

    def _derivable(self) -> set[str]:
        return {k for k, v in self.stack.env.items() if isinstance(v, Derived)}

    def _values(self, ctx: StepContext, resolved: Resolved) -> dict[str, str]:
        values = dict(resolved.values)
        for key in resolved.derived:
            if key not in self._derived:
                self._derived[key] = self._derive(ctx, values, key)
            values[key] = self._derived[key]
        return values

    # --- the step ---------------------------------------------------------------

    def check(self, ctx: StepContext) -> CheckResult:
        needed = CheckResult(True, local_code("render", {"stack": self.stack.name}))
        if self._env.exists():
            private_mode(self._env, "env-mode")
        minted, resolved = self._known()
        if resolved.missing:
            if self.ask is None:
                raise StepFailed("missing", {"fields": list[Json](resolved.missing)})
            return needed
        if any(key not in minted for key in self._minted_keys()):
            return needed
        if not self._env.exists():
            return needed
        # ``check`` reads and runs nothing: ``derived`` values are taken from
        # the file as they are -- ``derive`` is a function of the stack's other
        # values, so the file is current when every other value matches -- and
        # recomputed only by ``act``
        present = self._env.read_text(encoding="utf-8")
        try:
            on_disk = parse_env(present)
        except StepFailed:  # a file of another form is rendered again
            return needed
        if any(key not in on_disk for key in resolved.derived):
            return needed
        held = {key: on_disk[key] for key in resolved.derived}
        if any(len(value) < SECRET_MIN_LENGTH for value in held.values()):
            return needed  # too short to be what derive gives: act derives it again
        self.secrets.add(SecretStr(value) for value in held.values())
        if env_text({**resolved.values, **held}) != present:
            return needed
        return CheckResult(False)

    def act(self, ctx: StepContext, check: CheckResult) -> None:
        minted, resolved = self._known()
        new = {key: mint() for key in self._minted_keys() if key not in minted}
        if resolved.missing:
            self._answer(resolved.missing)
        if new:
            self.secrets.add(SecretStr(value) for value in new.values())
            write_private(self._minted, minted_text({**minted, **new}))
        minted, resolved = self._known()
        if resolved.missing:
            raise StepFailed("missing", {"fields": list[Json](resolved.missing)})
        write_private(self._env, env_text(self._values(ctx, resolved)))

    def _answer(self, fields: list[str]) -> None:
        """Ask each missing field; the answers go to the local copy at once."""
        if self.ask is None:
            raise StepFailed("missing", {"fields": list[Json](fields)})
        data = copy_data(self.root)
        for field in fields:
            path = tuple(field.split("."))
            answer = self.ask(field, schema_at(path))
            if not answer:
                raise StepFailed("no-answer", {"field": field})
            _put(data, path, answer)
        passport = rewrite_copy(self.root, data)  # the model checks every answer
        self.secrets.add(passport_secrets(passport))
        self.fetched.passport = passport

    def verify(self, ctx: StepContext, check: CheckResult) -> Verified:
        if not self._env.exists():
            raise StepFailed(
                "env-keys", {"missing": list[Json](self.stack.env), "extra": []}
            )
        private_mode(self._env, "env-mode")
        if self._minted.exists():
            private_mode(self._minted, "minted-mode")
        values = parse_env(self._env.read_text(encoding="utf-8"))
        missing = [key for key in self.stack.env if key not in values]
        extra = [key for key in values if key not in self.stack.env]
        if missing or extra:
            raise StepFailed(
                "env-keys", {"missing": list[Json](missing), "extra": list[Json](extra)}
            )
        held = [key for key, value in values.items() if placeholder(value)]
        if held:
            raise StepFailed("placeholder", {"keys": list[Json](held)})
        self.rendered = values
        return Verified(
            {
                "path": str(self._env),
                "keys": len(values),
                "mode": mode_of(self._env),
                "dir_mode": mode_of(self._dir),
            }
        )

    def provided(self) -> dict[str, str]:
        """The stack's ``provides`` as read back, for ``SeamMemory.healthy``."""
        names = self.stack.provides if isinstance(self.stack, Service) else []
        return {name: self.rendered[name] for name in names}
