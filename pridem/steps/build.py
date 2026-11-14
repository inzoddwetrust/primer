"""``build``: the images of one stack entry at one commit (TZ 7.3; contract 3
rules 10, 11, 18-19).

``docker compose … build`` from the release, with two build arguments for
every service: ``PRIMER_RELEASE`` (tag or branch) and ``PRIMER_COMMIT`` (sha)
-- one image for every instance of a commit, but for a service a package is
built into (below); a ``build.args`` in the product's
compose would carry an instance's value and is refused before anything is
built. So is a compose that asks the host for more than the stack's trust
(``compose-forbidden``, every finding of ``steps.compose.forbidden``): the
check reads it, so ``doctor`` names it too; ``check`` also reads
``config --no-interpolate``, the only output that still names ``env_file``
and writes the variables as the file does: one that may be empty or has a
default (not ``${NAME:?}``) and one that is not a key of ``env`` are findings
of the same code. ``pridem check`` refuses by the same ``refusal``. A host of
a product's ``egress`` that is not a row of the list agreed with Primer for
that product is refused first, before any command (``egress-unlisted``;
``stacks/egress.py``): ``pridem check`` refuses it by the same ``unlisted``.
Images carry ``pridem.stack``, ``pridem.release``, ``pridem.commit`` and
``pridem.service`` from the machine's override (``steps/compose.py``), which
this step renders: the deploy's override (``<entry>.next.yml``), which
``check`` compares with what it renders and ``act`` writes and builds with.
Every later step of the deploy -- ``packages``, ``data_copy``, ``tests``,
``migrate``, ``up`` -- reads it; the override of the release ``current`` names
(``<entry>.yml``) changes only in ``finalize``, with ``current`` (DM-89), so a
red ``validate`` or a red step after it leaves the running release its own.

A package of ``apply: build`` (contract 3 rules 10, 11, 19; the owner's
decision of 02.11) is built into the image of its service: ``act`` writes the
service's context with the package in it out of the release
(``steps.packages.write_context``), and the override points the service's
``build`` there, with ``PRIMER_EDITION`` -- the passport's edition, one of
``editions`` -- as the third and last build argument, for that service alone,
and the labels of the image's key (``steps.packages.image_key``). So the image
of such a service is the commit's, the edition's and the packages': a new
version of a package or another edition makes another override and another
build on the same commit; the same ones make none. The product's
``config`` the step refuses by is read without the override: the machine's
own argument is never a ``build.args`` of the product. A package that fails the
product's build fails ``build``: the old image and its containers stay. Where a
package goes is checked against the compose of every entry of the product
(``package_places``): a service of another entry is that entry's.

A red build stops the plan: nothing has touched a running container -- the
build only makes images. ``check`` needs no ``act`` when every built service
has its image of this commit (and key) and the override is the rendered one.
The fact names every image and the ``app`` image. ``derive_env`` takes that
image for ``derive`` from the step itself (``app_image``): from ``verify``,
or from ``check`` when it found every image and nothing to build -- the one
lookup of ``image_of``, so ``doctor`` knows it too.

On a service's entry the override also carries the product's data the service
takes (form D, ``steps/services.py``): a read-only bind of its copy and the
variable with its path in the container, on the service's ``app``; it goes in
place only after the service's ``validate`` of it (``data_copy``).
"""

import os
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, replace
from pathlib import Path
from typing import ClassVar

from pridem.events import Json
from pridem.stacks.egress import UNLISTED, unlisted
from pridem.stacks.options import open_hosts, switched_on
from pridem.stacks.passport import Passport
from pridem.stacks.schema import Product, Service
from pridem.stacks.seams import Pair
from pridem.steps.base import (
    CheckResult,
    Mode,
    Step,
    StepContext,
    StepFailed,
    Verified,
    local_code,
)
from pridem.steps.compose import (
    BUILD_TIMEOUT_S,
    REFUSAL_CODES,
    ComposeStack,
    built_services,
    config,
    env_files,
    image_of,
    out,
    override_text,
    package_places,
    refusal,
    variables,
    write_override,
)
from pridem.steps.packages import (
    KEY_CODES,
    PackageMount,
    PackagePlace,
    build_places,
    context_dir,
    image_key,
    package_mounts,
    volumes,
    write_context,
)
from pridem.steps.passport import NO_PASSPORT, Fetched
from pridem.steps.services import DataItem, data_binds

ALL_MODES: frozenset[Mode] = frozenset({"install", "deploy", "reinstall"})


def build_args(compose: ComposeStack) -> list[str]:
    """The only build arguments a build gets (contract 3 rule 19)."""
    return [
        "--build-arg",
        f"PRIMER_RELEASE={compose.ref}",
        "--build-arg",
        f"PRIMER_COMMIT={compose.commit}",
    ]


@dataclass(frozen=True)
class Rendered:
    """What ``build`` renders for its entry: the built services, the override
    and, by service of ``apply: build``, its context and places."""

    built: list[str]
    text: str
    contexts: dict[str, tuple[Path, Path, list[PackagePlace]]]
    """service -> (the context in the release, the context with the packages,
    the places)."""


def copied_dockerfile(context: Path, dockerfile: str) -> str:
    """The ``Dockerfile`` of a context copied out of the release: relative,
    when it lies inside the context (as it usually does); else its absolute
    path in the release."""
    full = Path(os.path.realpath(os.path.join(context, dockerfile)))
    inside = Path(os.path.realpath(context))
    return str(full.relative_to(inside)) if full.is_relative_to(inside) else str(full)


class Build(Step):
    """The images of one stack entry: once per commit, and per edition and
    package versions for a service a package is built into."""

    name = "build"
    order = 7
    modes = ALL_MODES
    codes: ClassVar[dict[str, str]] = {
        **NO_PASSPORT,
        **KEY_CODES,
        "build": "build {services} of {entry} at {commit}",
        "path-outside": "{slot}: the package's path {from} leaves the package",
        **REFUSAL_CODES,
        "egress-unlisted": UNLISTED,
        "missing-release": "{slot}: {path} is not on the box",
        "no-image": "no image of {service} at {commit} after the build",
        "two-images": "{count} images of {service} at {commit}",
    }

    def __init__(
        self,
        stack: Product | Service,
        entry: str,
        *,
        release: Path,
        ref: str,
        commit: str,
        root: Path = Path("/"),
        fetched: Fetched | None = None,
        data: Sequence[DataItem] = (),
        points: Sequence[Pair] = (),
    ) -> None:
        """``data`` -- what the product gives this entry of a service (form D):
        its binds and variables go into the override (``data_copy``)."""
        self.compose = ComposeStack(
            stack, entry, release, ref, commit, root, staged=True
        )
        self.fetched = fetched
        self.data = list(data)
        self.points = list(points)  # the pairs of the box (DM-62)
        self.app_image: str | None = None
        """The ``app`` image of this commit, once one was found (see above)."""
        self.app_built: bool | None = None
        """Whether the entry builds ``app``; known once ``config`` is read."""

    def _passport(self) -> Passport | None:
        return None if self.fetched is None else self.fetched.passport

    def _proxied(self) -> bool:
        """The product has a host of ``egress`` open on this instance."""
        stack, passport = self.compose.stack, self._passport()
        if not isinstance(stack, Product) or not stack.egress:
            return False
        if passport is None:
            raise StepFailed("no-passport")
        return bool(open_hosts(stack, switched_on(passport)))

    def _mounts(self, services: set[str]) -> list[PackageMount]:
        """The packages' binds of this entry's services (DM-19, DM-61)."""
        stack = self.compose.stack
        if self.fetched is None or not isinstance(stack, Product):
            return []
        passport = self.fetched.passport
        if passport is None:
            raise StepFailed("no-passport")
        return package_mounts(stack, stack.name, passport, self.compose.root, services)

    def _places(self, services: set[str]) -> list[PackagePlace]:
        """The build places of this entry's services (``apply: build``)."""
        stack = self.compose.stack
        if not isinstance(stack, Product) or not any(
            place.service in services
            for package in stack.packages.values()
            for place in package.build
        ):
            return []
        passport = self._passport()
        if passport is None:
            raise StepFailed("no-passport")
        places = build_places(stack, stack.name, passport, self.compose.root, services)
        for place in places:
            if not place.source.is_dir():
                raise StepFailed(
                    "missing-release", {"slot": place.slot, "path": str(place.source)}
                )
        return places

    def _documents(
        self, ctx: StepContext, document: dict[str, Json]
    ) -> dict[str, Mapping[str, Json]]:
        """The ``config`` of every entry of the product, this one's given."""
        compose = self.compose
        found: dict[str, Mapping[str, Json]] = {compose.entry: document}
        if isinstance(compose.stack, Product):
            for entry in sorted(compose.stack.stacks):
                if entry != compose.entry:
                    other = replace(compose, entry=entry)
                    found[entry] = config(ctx, other)
        return found

    def _rendered(
        self, ctx: StepContext, raw: Mapping[str, Json], also: Sequence[str] = ()
    ) -> Rendered:
        """The built services, the override and the contexts; ``raw`` -- the
        product's ``config --no-interpolate``, every caller reads it (the build
        arguments are read there, ``refusal``); ``also`` -- findings of the
        caller, refused with those of ``forbidden`` and ``package_places`` in
        one code."""
        compose = self.compose
        document = config(ctx, compose)
        places_found = package_places(compose.stack, self._documents(ctx, document))
        refused = refusal(compose, document, raw, [*places_found, *also])
        if refused is not None:
            raise StepFailed(*refused)
        bodies = document.get("services")
        services = set(bodies) if isinstance(bodies, dict) else set()
        mounts = self._mounts(services)
        places = self._places(services)
        builds: dict[str, dict[str, Json]] = {}
        contexts: dict[str, tuple[Path, Path, list[PackagePlace]]] = {}
        # every service of a slot of apply: build, not every place: an optional
        # slot with no package has none, and its service still builds by its
        # key -- the labels up, migrate and tests find it by (DM-101)
        slotted = {
            place.service
            for declared in (
                compose.stack.packages.values()
                if isinstance(compose.stack, Product)
                else ()
            )
            if declared.apply == "build"
            for place in declared.build
            if place.service in services
        }
        for service in sorted(slotted):
            body = bodies.get(service) if isinstance(bodies, dict) else None
            build = body.get("build") if isinstance(body, dict) else None
            context = build.get("context") if isinstance(build, dict) else None
            if not isinstance(build, dict) or not isinstance(context, str):
                continue  # package_places has refused a service with no build
            source = Path(context)
            target = context_dir(
                compose.root, compose.stack.name, compose.entry, service
            )
            key = image_key(compose.stack, service, self._passport())
            given = str(build.get("dockerfile") or "Dockerfile")
            extra: dict[str, Json] = {
                "context": str(target),
                "dockerfile": copied_dockerfile(source, given),
                "labels": dict[str, Json](key),
            }
            if "pridem.edition" in key:
                extra["args"] = {"PRIMER_EDITION": key["pridem.edition"]}
            builds[service] = extra
            mine = [place for place in places if place.service == service]
            contexts[service] = (source, target, mine)
        binds = volumes(mounts)
        data_mounts, data_env = data_binds(self.data, compose.app_service)
        for service, more in data_mounts.items():
            binds[service] = [*binds.get(service, []), *more]
        text = override_text(
            compose,
            document,
            binds,
            builds,
            data_env,
            proxy=self._proxied(),
            points=self.points,
            references=raw,  # ${VAR} lives in --no-interpolate only (DM-62 FIX 2)
        )
        return Rendered(built_services(document), text, contexts)

    def _key(self, service: str) -> dict[str, str]:
        return image_key(self.compose.stack, service, self._passport())

    def check(self, ctx: StepContext) -> CheckResult:
        stack = self.compose.stack
        if isinstance(stack, Product) and (hosts := unlisted(stack)):
            raise StepFailed(
                "egress-unlisted", {"product": stack.name, "hosts": list[Json](hosts)}
            )
        uninterpolated = config(ctx, self.compose, interpolate=False)
        keys = self.compose.stack.env
        found = [*env_files(uninterpolated), *variables(uninterpolated, keys)]
        rendered = self._rendered(ctx, uninterpolated, found)
        app = self.compose.app_service
        self.app_image = None
        self.app_built = app is not None and app in rendered.built
        params: dict[str, Json] = {
            "entry": self.compose.entry,
            "commit": self.compose.commit,
            "services": list[Json](rendered.built),
        }
        needed = CheckResult(True, local_code("build", params))
        path = self.compose.override
        if not path.exists() or path.read_text(encoding="utf-8") != rendered.text:
            return needed
        app_ids: list[str] = []
        for service in rendered.built:
            ids = image_of(ctx, self.compose, service, self._key(service))
            if not ids:
                return needed
            if service == app:
                app_ids = ids
        if len(app_ids) == 1:
            self.app_image = app_ids[0]
        return CheckResult(False)

    def act(self, ctx: StepContext, check: CheckResult) -> None:
        rendered = self._rendered(ctx, config(ctx, self.compose, interpolate=False))
        for source, target, places in rendered.contexts.values():
            write_context(source, target, places)
        write_override(self.compose, rendered.text)
        out(
            ctx,
            self.compose.argv("build", *build_args(self.compose)),
            timeout=BUILD_TIMEOUT_S,
        )

    def verify(self, ctx: StepContext, check: CheckResult) -> Verified:
        # the same fact as check: the build arguments read where they show
        rendered = self._rendered(ctx, config(ctx, self.compose, interpolate=False))
        images: dict[str, Json] = {}
        for service in rendered.built:
            found = image_of(ctx, self.compose, service, self._key(service))
            if not found:
                raise StepFailed(
                    "no-image", {"service": service, "commit": self.compose.commit}
                )
            if len(found) > 1:
                raise StepFailed(
                    "two-images",
                    {
                        "service": service,
                        "commit": self.compose.commit,
                        "count": len(found),
                    },
                )
            images[service] = found[0]
        fact: dict[str, Json] = {
            "release": self.compose.ref,
            "commit": self.compose.commit,
            "images": images,
        }
        keys = {service: self._key(service) for service in rendered.contexts}
        if keys:
            fact["keys"] = {name: dict[str, Json](key) for name, key in keys.items()}
        app = self.compose.app_service
        self.app_built = app is not None and app in rendered.built
        self.app_image = None
        if app is not None and app in images:
            self.app_image = str(images[app])
            fact["app_image"] = images[app]
        return Verified(fact)
