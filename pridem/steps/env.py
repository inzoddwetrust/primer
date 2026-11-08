"""The env steps (TZ 7.1, 7.3; contract 3 section 3, rules 13, 18).

``seams_check`` refuses a plan with a half seam, an edition the product does
not declare, languages of the instance that are not the product's (or are
missing where they are wanted, or a default out of them), data a service does
not accept or routes of a co-located service before the first ``act`` of a
stack: the plan builder puts it ahead of the
services' ladders, once ``fetch_services`` has read their ``primer.yaml`` (the
edition decides which services are installed).

``render_env`` renders a stack's ``.env`` from its schema and reads it back,
in two passes around ``build`` (DM-67). Before it (``render_env``), every
source but ``derived``; a ``derived`` key holds its value on disk when it
could be one -- the running release's -- else ``<derived>``, which satisfies
compose's ``${VAR:?}`` for the build and is no value of anything. After it
(``derive_env``, on the stack's own entry), ``derive`` runs in the ``app``
image of this run, ``.env`` is written once with every key and read back with
no placeholder left -- before ``packages``, ``data_copy``, ``tests``,
``migrate`` and ``up`` start a container of the stack, and before its
``provides`` reach the plan's memory after health. A stack with ``derived``
and no ``app`` in its own entry is refused by ``render_env``'s ``check``,
before the stack's first ``act``.

Every secret enters the run's ``Secrets`` -- the one growing set the sinks and
the verdict hold -- before any line that could carry it: the passport's and
the minted ones in ``check``, an answer of ``install`` once it is written, a
``derived`` value as soon as its command ends or is read from the file. A
secret never goes to an argv: ``derive`` gets the stack's other values through
an env file (0600) that ``docker run`` reads, and its output is kept by the
step -- stdout is the value, nothing of it reaches the console or the journal;
on a non-zero exit only stderr is passed on.

``derive`` runs only in ``act``: ``check`` of either pass reads files and
asks docker which image ``app`` runs on, and runs no container. It runs
``docker run --rm --env-file <file> <image> <run>`` in a throwaway container
of the stack's image, not ``docker compose run``: compose interpolates the
whole file.

A missing ``asked``, ``params``, domain or ``edition`` is asked through
``ask`` (contract 1 rule 3, owner's decision of 27.10); with nobody to ask it
is red in ``check``, before ``act`` writes anything. An answer passes the
passport's model and goes to the local copy; the version does not change.
"""

import shlex
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import ClassVar, Protocol

from pydantic import SecretStr

from pridem.contract import SECRET_MIN_LENGTH
from pridem.events import Json, Secrets
from pridem.runner import CommandFailed, Stream
from pridem.stacks.env import (
    DERIVED_PLACEHOLDER,
    ENV_FILE,
    MINTED_FILE,
    Resolved,
    env_dir,
    env_text,
    mint,
    minted_text,
    mode_of,
    own_entry,
    parse_env,
    placeholder,
    private_mode,
    read_minted,
    resolve,
    safe,
    write_private,
)
from pridem.stacks.options import LITERAL, off_keys, switched_on
from pridem.stacks.passport import Passport
from pridem.stacks.schema import Derived, Minted, Product, Service
from pridem.stacks.schema import Passport as FromPassport
from pridem.stacks.seams import (
    SeamMemory,
    half_seams,
    installed,
    outside_edition,
    provider_order,
    routes_on_co_located,
    seams_under_option,
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
from pridem.steps.compose import ComposeStack, running_image
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
NO_IMAGE = "{key} is derived, and no image of the stack is given"
OPTION_CODES: dict[str, str] = {
    "option-value": f"{{key}} is of an option that is off: its value is {LITERAL!r}",
    "option-literal": f"{{key}} is {LITERAL!r}, and its option is on or it has none",
}
READ_BACK_CODES: dict[str, str] = {
    "env-mode": "{path} is {mode}, not 0o600; it is left as it is",
    "env-unsafe": "the value of {key} has a quote or a line break",
    "env-unreadable": "line {line} of the env file is not KEY='value'",
    "env-keys": "the env file lacks {missing} and has {extra} beyond the schema",
    "placeholder": "the env file holds placeholders for {keys}",
}
DERIVE_TIMEOUT_S = 300
DERIVE_ENV = "derive.env"
LANGUAGE_KEYS = frozenset({"languages", "default_language"})
"""The keys of the source ``passport`` that are the instance's languages."""


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
        "languages-missing": "the passport lacks {fields}",
        "language-outside-product": "{languages} are not languages of the product",
        "default-language-outside": "the default {language} is not one of {languages}",
        "option-outside-product": "{options} are not options of the product",
        "option-required-off": "the product needs {options}, the passport has them off",
        "seam-option": "seams of a variable under an option the product takes "
        "without it: {seams}",
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
        self._languages(_passport(self.fetched), edition)
        on = self._options(_passport(self.fetched))
        half = half_seams(self.product, self.services, edition, on=on)
        if half:
            raise StepFailed("half-seam", {"seams": list[Json](half)})
        under = seams_under_option(self.product, self.services, edition, on=on)
        if under:
            raise StepFailed("seam-option", {"seams": list[Json](under)})
        outside = outside_edition(self.product, edition, on=on)
        if outside:
            raise StepFailed("seam-outside-edition", {"seams": list[Json](outside)})
        routed = routes_on_co_located(self.product, self.services, edition, on=on)
        if routed:
            raise StepFailed("routes-on-co-located", {"services": list[Json](routed)})
        refused = unaccepted(self.product, self.services, edition, on=on)
        if refused:
            raise StepFailed("data-not-accepted", {"data": list[Json](refused)})
        return CheckResult(False)

    def _options(self, passport: Passport) -> frozenset[str]:
        """The options of the instance (contract 3 rules 36-37): each one of
        the product's, each one the product needs on; the options on."""
        given = passport.options or []
        outside = [option for option in given if option not in self.product.options]
        if outside:
            raise StepFailed("option-outside-product", {"options": list[Json](outside)})
        missing = [o for o in self.product.options_required if o not in given]
        if missing:
            raise StepFailed("option-required-off", {"options": list[Json](missing)})
        return switched_on(passport)

    def _languages(self, passport: Passport, edition: str | None) -> None:
        """The instance's languages (protocol 5.2.2): wanted when the product
        declares ``languages`` or a stack of the box takes them from the
        passport, or the passport names some; a subset of the product's, the
        default one of them."""
        stacks: list[Product | Service] = [
            self.product,
            *(
                self.services[n]
                for n in installed(self.product, edition, on=switched_on(passport))
            ),
        ]
        taken = any(
            isinstance(var, FromPassport) and var.key in LANGUAGE_KEYS
            for stack in stacks
            for var in stack.env.values()
        )
        given = passport.languages is not None or passport.default_language is not None
        if not (self.product.languages is not None or taken or given):
            return
        languages, default = passport.languages, passport.default_language
        if languages is None or default is None:
            missing = [
                name
                for name, value in (
                    ("languages", languages),
                    ("default_language", default),
                )
                if value is None
            ]
            raise StepFailed("languages-missing", {"fields": list[Json](missing)})
        own = self.product.languages or []
        outside = [code for code in languages if code not in own]
        if outside:
            raise StepFailed(
                "language-outside-product", {"languages": list[Json](outside)}
            )
        if default not in languages:
            raise StepFailed(
                "default-language-outside",
                {"language": default, "languages": list[Json](languages)},
            )

    def act(self, ctx: StepContext, check: CheckResult) -> None:
        raise RuntimeError("seams_check never acts")

    def verify(self, ctx: StepContext, check: CheckResult) -> Verified:
        passport = _passport(self.fetched)
        edition, on = passport.edition, switched_on(passport)
        order = provider_order(self.product, edition, on=on)
        here = set(installed(self.product, edition, on=on))
        left = [
            name
            for name in self.product.dependencies
            if name not in here and (self.root / "opt" / name / "current").is_symlink()
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
    """``/opt/<n>/env/.env`` of one stack, rendered and read back: every source
    but ``derived``, whose keys hold the value on disk or ``<derived>`` until
    ``derive_env`` (below) puts the value of this run's image there."""

    name = "render_env"
    order = 2
    modes = ALL_MODES
    codes: ClassVar[dict[str, str]] = {
        **NO_PASSPORT,
        **READ_BACK_CODES,
        "render": "render the env of {stack}",
        "missing": "the passport lacks {fields} and nobody can be asked",
        "no-answer": "no answer for {field}",
        "invalid": "the answer is rejected: {problems}",
        "minted-mode": "{path} is {mode}, not 0o600; it is left as it is",
        "minted-damaged": "{path} is not a minted file of this machine",
        "edition-unknown": "{key}: edition {edition} is not in editions",
        "passport-key": "{key}: the passport has no source {passport_key}",
        "address-no-app": "{stack} has no app of its own to give an address of",
        "seam-before-health": "{names} of {from} are asked before its health",
        "derive-no-image": NO_IMAGE,
        **OPTION_CODES,
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
    ) -> None:
        self.stack = stack
        self.product = product
        self.fetched = fetched
        self.secrets = secrets
        self.memory = memory
        self.root = root
        self.ask = ask
        self.rendered: dict[str, str] = {}
        self.changed = True
        """Whether ``check`` found the file behind the schema, the passport,
        the minted values or the seams -- the inputs of ``derive``."""

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

    def _switched(self) -> list[str]:
        """The keys of an option that is off: the literal, nothing minted,
        derived or asked for them (contract 3 rules 38-39)."""
        return off_keys(self.stack, switched_on(_passport(self.fetched)))

    def _minted_keys(self) -> list[str]:
        off = set(self._switched())
        return [
            k
            for k, v in self.stack.env.items()
            if isinstance(v, Minted) and k not in off
        ]

    def _derivable(self) -> list[str]:
        off = set(self._switched())
        return [
            k
            for k, v in self.stack.env.items()
            if isinstance(v, Derived) and k not in off
        ]

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

    def _on_disk(self) -> dict[str, str] | None:
        """The values of ``.env`` as they are; ``None`` when there is no file
        or it is not of the machine's form."""
        if not self._env.exists():
            return None
        try:
            return parse_env(self._env.read_text(encoding="utf-8"))
        except StepFailed:  # a file of another form is rendered again
            return None

    def _held(self, on_disk: Mapping[str, str] | None) -> dict[str, str]:
        """What a ``derived`` key holds before ``derive_env``: its value on disk
        when it could be one -- the running release's -- else the placeholder.
        Held values are secrets."""
        held: dict[str, str] = {}
        for key in self._derivable():
            value = (on_disk or {}).get(key, "")
            held[key] = value if usable(value) else DERIVED_PLACEHOLDER
        self.secrets.add(SecretStr(v) for v in held.values() if usable(v))
        return held

    def _app_for_derive(self) -> None:
        """A stack with ``derived`` has an ``app`` in its own entry: ``derive``
        runs in that image. Refused here, before the stack's first ``act``."""
        derivable = self._derivable()
        if derivable and self.stack.stacks[own_entry(self.stack)].app is None:
            raise StepFailed("derive-no-image", {"key": derivable[0]})

    # --- the step ---------------------------------------------------------------

    def check(self, ctx: StepContext) -> CheckResult:
        result = self._check()
        self.changed = result.needed
        return result

    def _check(self) -> CheckResult:
        needed = CheckResult(True, local_code("render", {"stack": self.stack.name}))
        self._app_for_derive()
        if self._env.exists():
            private_mode(self._env, "env-mode")
        minted, resolved = self._known()
        if resolved.missing:
            if self.ask is None:
                raise StepFailed("missing", {"fields": list[Json](resolved.missing)})
            return needed
        if any(key not in minted for key in self._minted_keys()):
            return needed
        on_disk = self._on_disk()
        if on_disk is None:
            return needed
        # ``check`` reads and runs nothing; ``derived`` keys are compared as
        # ``act`` writes them -- the value on disk or the placeholder
        present = self._env.read_text(encoding="utf-8")
        if env_text({**resolved.values, **self._held(on_disk)}) != present:
            return needed
        return CheckResult(False)

    def act(self, ctx: StepContext, check: CheckResult) -> None:
        minted, resolved = self._known()
        new = {key: mint() for key in self._minted_keys() if key not in minted}
        if resolved.missing:
            self._answer(resolved.missing)
        if resolved.switched_off and self.ask is not None:
            self._switch_off(resolved.switched_off)
        if new:
            self.secrets.add(SecretStr(value) for value in new.values())
            write_private(self._minted, minted_text({**minted, **new}))
        minted, resolved = self._known()
        if resolved.missing:
            raise StepFailed("missing", {"fields": list[Json](resolved.missing)})
        held = self._held(self._on_disk())
        write_private(self._env, env_text({**resolved.values, **held}))

    def _switch_off(self, fields: list[str]) -> None:
        """``install`` writes the literal for each field of an option that is
        off, asking nothing (contract 1, additions 1.13)."""
        data = copy_data(self.root)
        for field in fields:
            _put(data, tuple(field.split(".")), LITERAL)
        passport = rewrite_copy(self.root, data)
        self.secrets.add(passport_secrets(passport))
        self.fetched.passport = passport

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

    def read_back(self, *, waiting: Sequence[str]) -> Verified:
        """``.env`` read back: 0600, exactly the schema's keys, no placeholder
        but ``<derived>`` on the keys of ``waiting``; the values become
        ``rendered``."""
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
        switched = set(self._switched())
        astray = [key for key in switched if values[key] != LITERAL]
        if astray:
            raise StepFailed("option-value", {"key": astray[0]})
        held = [
            key
            for key, value in values.items()
            if placeholder(value)
            and not (key in waiting and value == DERIVED_PLACEHOLDER)
            and not (key in switched and value == LITERAL)
        ]
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

    def verify(self, ctx: StepContext, check: CheckResult) -> Verified:
        return self.read_back(waiting=self._derivable())

    def provided(self) -> dict[str, str]:
        """The stack's ``provides`` as read back, for ``SeamMemory.healthy``."""
        names = self.stack.provides if isinstance(self.stack, Service) else []
        return {name: self.rendered[name] for name in names}


class AppImage(Protocol):
    """What ``derive_env`` takes from ``build`` of the stack's own entry."""

    @property
    def compose(self) -> ComposeStack: ...

    @property
    def app_image(self) -> str | None:
        """The ``app`` image of this commit, once ``build`` found exactly one
        -- in its ``check`` with nothing to build, or in its ``verify``."""
        ...

    @property
    def app_built(self) -> bool | None:
        """Whether the entry builds ``app``; ``None`` before ``build`` read
        its ``config``."""
        ...


class DeriveEnv(Step):
    """The ``derived`` values of one stack, computed in this run's image and
    written to ``.env``, which is read back with no placeholder left.

    ``check`` needs ``act`` when a ``derived`` value on disk could not be one
    (none, ``<derived>``, short), when ``render_env`` found the other values
    behind -- they are ``derive``'s input -- or when ``app`` runs on another
    image than ``build`` gives (a new commit, or a run that stopped after
    deriving and before ``up``). It reads ``.env`` and asks docker which image
    ``app`` runs on; it runs no container.
    """

    name = "derive_env"
    order = 8  # after build (7), before packages, data_copy (9) and the rest
    modes = ALL_MODES
    codes: ClassVar[dict[str, str]] = {
        **NO_PASSPORT,
        **READ_BACK_CODES,
        "derive": "derive {keys} of {stack}",
        "missing": "the passport lacks {fields} and nobody can be asked",
        "address-no-app": "{stack} has no app of its own to give an address of",
        "seam-before-health": "{names} of {from} are asked before its health",
        "derive-no-image": NO_IMAGE,
        "derive-failed": "deriving {key} failed — exit code {exit_code}",
        "derive-empty": "deriving {key} printed {lines} lines, not one value",
        "derive-short": "the derived {key} is shorter than 16 characters",
        **OPTION_CODES,
    }

    def __init__(self, render: RenderEnv, build: AppImage) -> None:
        self.render = render
        self.build = build
        self._image: str | None = None

    def _image_of_build(self) -> str:
        image = self.build.app_image
        if image is None or self.build.app_built is False:
            raise StepFailed("derive-no-image", {"key": self.render._derivable()[0]})
        return image

    def check(self, ctx: StepContext) -> CheckResult:
        render = self.render
        keys = render._derivable()
        params: dict[str, Json] = {"keys": list[Json](keys), "stack": render.stack.name}
        needed = CheckResult(True, local_code("derive", params))
        if not keys:  # every derived key is of an option off: nothing to derive
            return CheckResult(False)
        if self.build.app_built is False:
            raise StepFailed("derive-no-image", {"key": keys[0]})
        on_disk = render._on_disk() or {}
        values = {key: on_disk.get(key, "") for key in keys}
        if not all(usable(value) for value in values.values()):
            return needed
        render.secrets.add(SecretStr(value) for value in values.values())
        if render.changed:
            return needed
        image = self.build.app_image
        app = self.build.compose.app_service
        if image is None or app is None:
            return needed  # doctor before a build: the image is not known yet
        if running_image(ctx, self.build.compose, app) != image:
            return needed
        self._image = image
        return CheckResult(False)

    def act(self, ctx: StepContext, check: CheckResult) -> None:
        render = self.render
        image = self._image_of_build()
        _, resolved = render._known()
        if resolved.missing:
            raise StepFailed("missing", {"fields": list[Json](resolved.missing)})
        values = dict(resolved.values)
        known = {k: v for k, v in values.items() if k not in resolved.derived}
        for key in resolved.derived:
            values[key] = self._derive(ctx, known, key, image)
        write_private(render._env, env_text(values))  # one write, every key
        self._image = image

    def _derive(
        self, ctx: StepContext, known: Mapping[str, str], key: str, image: str
    ) -> str:
        """The value printed by ``run`` of ``key`` in the stack's container."""
        render = self.render
        var = render.stack.env[key]
        if not isinstance(var, Derived):
            raise TypeError(f"{key} is not derived")
        command = shlex.split(var.run)
        env_file = render._dir / DERIVE_ENV
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
                    f"pridem.stack={render.stack.name}",
                    "--env-file",
                    str(env_file),
                    image,
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
        render.secrets.add([SecretStr(value)])
        for stream, line, cut in lines:
            if stream is Stream.STDERR:  # cleaned of the value from here on
                ctx.on_line(stream, line, cut)
        safe(key, value)
        return value

    def verify(self, ctx: StepContext, check: CheckResult) -> Verified:
        verified = self.render.read_back(waiting=())
        fact: dict[str, Json] = {
            **verified.fact,
            "derived": list[Json](self.render._derivable()),
        }
        if self._image is not None:
            fact["image"] = self._image
        return Verified(fact)


def usable(value: str) -> bool:
    """A value ``derive`` could have printed: no placeholder, not short."""
    return not placeholder(value) and len(value) >= SECRET_MIN_LENGTH
