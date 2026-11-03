"""``packages``: the instance's packages checked and validated before they
are mounted (contract 3 rule 10; TZ 8), and where a package built into an
image goes (``apply: build``).

A package belongs to the stack entry whose compose has its service: the
binds (``package_mounts``) and the build places (``build_places``) of an
entry are those of its own services; that a service is in no entry at all is
``build``'s finding (``steps.compose.package_places``), not this step's.

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
the package (a symlink of the package's repository), a package not on the box.
``act`` runs the product's ``validate`` in a throwaway container of the
service's new image (``image_key``) with the same mounts, ``<dir>`` replaced by
the mount path: red -- the plan stops before ``up``, nothing is switched.

``apply: build`` (the owner's decision of 02.11): ``build`` copies the build
context of the service out of the immutable release into
``/opt/<stack>/contexts/<entry>/<service>`` (``context_dir``) with the
package in place of ``path``, and builds from there with ``PRIMER_EDITION``.
Such a package has no ``validate``: the product's build is its check. The
image of that service is the commit's, the edition's and the packages'
(``image_key``: labels ``pridem.edition`` when the product declares
``editions``, ``pridem.package.<slot>=<repo>@<version>``); every step that
finds an image finds it by that key.
"""

import shlex
import shutil
from collections.abc import Collection
from dataclasses import dataclass
from pathlib import Path
from typing import ClassVar

from pridem.events import Json
from pridem.stacks.passport import Passport
from pridem.stacks.schema import Product, Service
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


@dataclass(frozen=True)
class PackagePlace:
    """A package put into the build context of a service (``apply: build``)."""

    slot: str
    release: str
    service: str
    source: Path
    path: str


KEY_CODES = {
    "package-missing": "{slot}: the passport gives no package of apply: build",
    "edition-missing": "the passport gives no edition for the build of {service}",
    "edition-unknown": "edition {edition} is not in editions",
}
"""The texts of ``image_key``'s and ``build_places``' codes, for every step
that finds an image by its key."""


def build_places(
    product: Product,
    stack: str,
    passport: Passport,
    root: Path,
    services: Collection[str],
) -> list[PackagePlace]:
    """The build places of ``services`` (one entry's), every package of
    ``apply: build`` given by the passport (``package-missing``): a service of
    that mode has no image without it."""
    out_: list[PackagePlace] = []
    for slot, declared in sorted(product.packages.items()):
        if declared.apply != "build":
            continue
        given = passport.packages.get(slot)
        if given is None:
            raise StepFailed("package-missing", {"slot": slot})
        base = package_dir(root, stack, given)
        if given.subpath is not None:
            base = base / given.subpath
        for place in declared.build:
            if place.service in services:
                out_.append(
                    PackagePlace(
                        slot, package_release(given), place.service, base, place.path
                    )
                )
    return out_


def image_key(
    stack: Product | Service, service: str, passport: Passport | None
) -> dict[str, str]:
    """The labels that tell the image of ``service`` beyond its commit: for a
    service a package of ``apply: build`` goes into, ``pridem.edition`` (when
    the product declares ``editions``) and ``pridem.package.<slot>`` --
    ``<repo>@<version>``; ``{}`` for every other service."""
    if not isinstance(stack, Product):
        return {}
    slots = [
        slot
        for slot, declared in sorted(stack.packages.items())
        if declared.apply == "build"
        and any(place.service == service for place in declared.build)
    ]
    if not slots:
        return {}
    if passport is None:
        raise StepFailed("no-passport")
    key: dict[str, str] = {}
    if stack.editions:
        edition = passport.edition
        if edition is None:
            raise StepFailed("edition-missing", {"service": service})
        if edition not in stack.editions:
            raise StepFailed("edition-unknown", {"edition": edition})
        key["pridem.edition"] = edition
    for slot in slots:
        given = passport.packages.get(slot)
        if given is None:
            raise StepFailed("package-missing", {"slot": slot})
        key[f"pridem.package.{slot}"] = package_release(given)
    return key


def context_dir(root: Path, stack: str, entry: str, service: str) -> Path:
    """The build context of ``service`` with its packages, out of the release."""
    return root / "opt" / stack / "contexts" / entry / service


def _ignore_git(directory: str, names: list[str]) -> set[str]:
    """Not the ``.git`` of a worktree: a release and a package are worktrees."""
    return {".git"} if ".git" in names else set()


def write_context(source: Path, target: Path, places: Collection[PackagePlace]) -> None:
    """``target``: a copy of the context ``source`` with each place's package in
    place of its ``path`` (a directory the repository has there is replaced
    whole), written in ``<target>.tmp`` and renamed; the release is never
    touched. Symlinks are copied as links: the build sees only the context."""
    temp = target.with_name(target.name + ".tmp")
    if temp.exists():  # left by a run that died
        shutil.rmtree(temp)
    target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    shutil.copytree(source, temp, symlinks=True, ignore=_ignore_git)
    for place in places:
        inside = temp / place.path
        if inside.is_symlink() or inside.is_file():
            inside.unlink()
        elif inside.exists():
            shutil.rmtree(inside)
        inside.parent.mkdir(parents=True, exist_ok=True)
        shutil.copytree(place.source, inside, symlinks=True, ignore=_ignore_git)
    if target.exists():
        shutil.rmtree(target)
    temp.rename(target)


def package_mounts(
    product: Product,
    stack: str,
    passport: Passport,
    root: Path,
    services: Collection[str] | None = None,
) -> list[PackageMount]:
    """The binds of the instance's packages of ``apply: runtime``; of
    ``services`` alone (one entry's) when given; refused by name before
    ``act``.

    A package is where ``fetch_packages`` put it: ``package_dir`` of the stack,
    whatever the compose entry is called."""
    out_: list[PackageMount] = []
    for slot, declared in sorted(product.packages.items()):
        given = passport.packages.get(slot)
        if given is None:  # a slot of apply: build has no mount (rule 10)
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
            if services is not None and element.service not in services:
                continue  # another entry's service: its stack binds it
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
        **KEY_CODES,
        "validate": "validate the packages {slots}",
        "path-outside": "{slot}: mount from {from} leaves the package",
        "dependency-mount": "{slot}: a copy into {dependency} is not done here (A')",
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
        if not package_mounts(
            self.product, self.compose.stack.name, passport, self.root
        ):
            return [], {}
        document = config(ctx, self.compose)
        services = document.get("services")
        known = services if isinstance(services, dict) else {}
        mounts = package_mounts(
            self.product, self.compose.stack.name, passport, self.root, known
        )
        for mount in mounts:
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
        key = image_key(self.product, mount.service, self.fetched.passport)
        found = image_of(ctx, self.compose, mount.service, key)
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
            # apply: runtime has validate (rule 10): package_mounts gives no other
            validate = self.product.packages[slot].validate_ or ""
            command = shlex.split(validate.replace("<dir>", first.path))
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
