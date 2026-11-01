"""``packages``: the instance's packages checked and validated before they
are mounted (contract 3 rule 10; TZ 8).

A package slot of the product (``packages.<slot>``) is filled by the
passport (``packages.<slot>: {repo, version, subpath}``), cloned by
``fetch_packages`` into ``/opt/<stack>/releases/<repo>@<version>``. Each
``mount`` element with ``service`` is a read-only bind of the package's
directory (``from`` -- a relative subdirectory: the loader refuses ``..`` and
an absolute one, rule 10) at ``path`` in that service of the stack's compose;
the machine's override carries it (``steps/compose.py``) and it takes effect
on ``up``. An element
with ``dependency`` (the form A' -- a copy into a service's release) is not
done here: DM-T-0078.

``check`` refuses, before anything is run: a directory that resolves out of
the package (a symlink of the package's repository), a service the compose
does not have, a package not on the box. ``act`` runs the
product's ``validate`` in a throwaway container of the service's new image
with the same mounts, ``<dir>`` replaced by the mount path: red -- the plan
stops before ``up``, nothing is switched.
"""

import shlex
from dataclasses import dataclass
from pathlib import Path
from typing import ClassVar

from pridem.events import Json
from pridem.stacks.passport import Passport
from pridem.stacks.schema import Product
from pridem.steps.base import (
    CheckResult,
    Mode,
    Step,
    StepContext,
    StepFailed,
    Verified,
    local_code,
)
from pridem.steps.compose import ComposeStack, config, image_of, out
from pridem.steps.passport import NO_PASSPORT, Fetched
from pridem.steps.sources import package_dir, package_release

ALL_MODES: frozenset[Mode] = frozenset({"install", "deploy", "reinstall"})
VALIDATE_TIMEOUT_S = 600


@dataclass(frozen=True)
class PackageMount:
    """One read-only bind of a package directory into a service."""

    slot: str
    release: str
    service: str
    source: Path
    path: str
    package: Path

    @property
    def volume(self) -> str:
        return f"{self.source}:{self.path}:ro"


def package_mounts(
    product: Product, stack: str, passport: Passport, root: Path
) -> list[PackageMount]:
    """The binds of the instance's packages; refused by name before ``act``.

    A package is where ``fetch_packages`` put it: ``package_dir`` of the stack,
    whatever the compose entry is called."""
    out_: list[PackageMount] = []
    for slot, declared in sorted(product.packages.items()):
        given = passport.packages.get(slot)
        if given is None:
            continue
        release = package_release(given)
        base = package_dir(root, stack, given)
        if given.subpath is not None:
            base = base / given.subpath
        for element in declared.mount:
            if element.dependency is not None:
                raise StepFailed(
                    "dependency-mount", {"slot": slot, "dependency": element.dependency}
                )
            if element.service is None or element.path is None:
                continue
            part = element.from_ or ""  # relative, normalized: the loader's R10
            source = base / part if part else base
            out_.append(
                PackageMount(slot, release, element.service, source, element.path, base)
            )
    return out_


def volumes(mounts: list[PackageMount]) -> dict[str, list[str]]:
    """The override's ``volumes`` by service."""
    found: dict[str, list[str]] = {}
    for mount in mounts:
        found.setdefault(mount.service, []).append(mount.volume)
    return found


class Packages(Step):
    """The instance's packages: in the release, mountable, validated."""

    name = "packages"
    order = 9
    modes = ALL_MODES
    codes: ClassVar[dict[str, str]] = {
        **NO_PASSPORT,
        "validate": "validate the packages {slots}",
        "path-outside": "{slot}: mount from {from} leaves the package",
        "dependency-mount": "{slot}: a copy into {dependency} is not done here (A')",
        "unknown-service": "{slot}: the compose has no service {service}",
        "missing-release": "{slot}: {path} is not on the box",
        "no-image": "{slot}: no image of {service} at {commit}",
    }

    def __init__(
        self,
        product: Product,
        entry: str,
        *,
        release: Path,
        ref: str,
        commit: str,
        fetched: Fetched,
        root: Path = Path("/"),
    ) -> None:
        self.product = product
        self.compose = ComposeStack(product, entry, release, ref, commit, root)
        self.fetched = fetched
        self.root = root

    def _mounts(self, ctx: StepContext) -> tuple[list[PackageMount], dict[str, Json]]:
        passport = self.fetched.passport
        if passport is None:
            raise StepFailed("no-passport")
        mounts = package_mounts(
            self.product, self.compose.stack.name, passport, self.root
        )
        if not mounts:
            return [], {}
        document = config(ctx, self.compose)
        services = document.get("services")
        known = services if isinstance(services, dict) else {}
        for mount in mounts:
            if mount.service not in known:
                raise StepFailed(
                    "unknown-service", {"slot": mount.slot, "service": mount.service}
                )
            if not mount.source.is_dir():
                raise StepFailed(
                    "missing-release", {"slot": mount.slot, "path": str(mount.source)}
                )
            # a symlink of the package must not lead out of it (the binds are
            # the package's own directory and nothing of the box beside it)
            if not mount.source.resolve().is_relative_to(mount.package.resolve()):
                raise StepFailed(
                    "path-outside",
                    {
                        "slot": mount.slot,
                        "from": str(mount.source.relative_to(mount.package)),
                    },
                )
        return mounts, known

    def check(self, ctx: StepContext) -> CheckResult:
        mounts, _ = self._mounts(ctx)
        if not mounts:
            return CheckResult(False)
        slots: list[Json] = list[Json](sorted({mount.slot for mount in mounts}))
        return CheckResult(True, local_code("validate", {"slots": slots}))

    def _image(
        self, ctx: StepContext, mount: PackageMount, known: dict[str, Json]
    ) -> str:
        found = image_of(ctx, self.compose, mount.service)
        if len(found) == 1:
            return found[0]
        body = known.get(mount.service)
        if isinstance(body, dict):
            image = body.get("image")
            if isinstance(image, str) and "build" not in body:
                return image
        raise StepFailed(
            "no-image",
            {
                "slot": mount.slot,
                "service": mount.service,
                "commit": self.compose.commit,
            },
        )

    def act(self, ctx: StepContext, check: CheckResult) -> None:
        mounts, known = self._mounts(ctx)
        labels = [
            word
            for key, value in self.compose.release_labels().items()
            for word in ("--label", f"{key}={value}")
        ]
        for slot in sorted({mount.slot for mount in mounts}):
            mine = [mount for mount in mounts if mount.slot == slot]
            first = mine[0]
            same = [mount for mount in mine if mount.service == first.service]
            command = shlex.split(
                self.product.packages[slot].validate_.replace("<dir>", first.path)
            )
            binds = [word for mount in same for word in ("-v", mount.volume)]
            out(
                ctx,
                [
                    "docker",
                    "run",
                    "--rm",
                    *labels,
                    *binds,
                    self._image(ctx, first, known),
                    *command,
                ],
                timeout=VALIDATE_TIMEOUT_S,
            )

    def verify(self, ctx: StepContext, check: CheckResult) -> Verified:
        mounts, _ = self._mounts(ctx)
        found: dict[str, Json] = {mount.slot: mount.release for mount in mounts}
        return Verified({"packages": found} if found else {"packages": "none"})
