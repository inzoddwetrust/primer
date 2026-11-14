"""The services of a product on its box (TZ 6.2 item 6, 7.1, 11; protocol 4,
4.3-4.7; contract 3 rules 11, 13, 21).

Each co-located service of the edition goes up by its own ladder before the
product, in the order of ``installed`` (``stacks/seams.py``): ``render_env ->
build -> data_copy -> stop_for_migrate -> migrate -> up``; ``up`` checks it
live (conformance, ``/health``) and only then puts its ``provides`` in the
plan's memory, so
the product's ``render_env`` -- and every step of the product after it -- waits
for every service. A service's tests are its CI's (protocol 7.4): none here.

``data_copy`` -- the form D of protocol 4.5. The product gives a service a
directory of its release (``dependencies.<s>.data.<kind>``) or the section of a
package (``packages.<slot>.mount`` with ``dependency: <s>``, the kind is the
slot); the service takes the kind (``accepts.<kind>: {validate, env}``;
``seams_check`` refuses a kind it does not take). The directory is copied to
``/opt/<service>/data/<product>@<release>/<kind>@<digest>`` -- outside the
service's release, a worktree ``sources`` resets; the
service gets it read-only at ``/primer/data/<kind>``, the path under the
variable ``env`` names, both by the machine's override (``build`` renders
them). A directory that is not there is ``data-missing``; one with a symlink
leading out of where it comes from is ``data-unsafe``, one holding a FIFO, a
socket or a device is ``data-special`` -- before anything is copied or opened.

The copy's directory is named by what it holds: ``<kind>@<digest>``, the
digest of ``tree`` of the source (DM-81). New data is a new directory, never
a directory replaced: a running container mounts the directory's inode, so a
directory replaced under it leaves the service on an empty, removed one and
``up`` never restarts it (one path, one configuration hash). A new path is a
new bind in the deploy's override, so ``up`` recreates the service on it --
after the green ``validate``, which comes first in the ladder.
The copy goes to ``<kind>@<digest>.tmp`` and is renamed to a name not taken;
a copy whose files are no longer the source's is not the machine's doing
(it writes only that way): ``copy-drift``, red. ``gc`` removes the copies no
container mounts but the newest of each kind.

``validate`` of the kind runs in a throwaway container of the service's new
image, the copy mounted, with no network, no capability and no pull
(``--network none --cap-drop ALL --pull never``) -- before the service's
``migrate``,
the point of no return: red (``validate-failed``) stops the plan before the
service and the product, and the running service stays on its old data and
its old image (protocol 4.5, 4.6: the machine joins no data). Green lets the
ladder go on to ``up``, which restarts the service on the deploy's override
(``<entry>.next.yml``, ``build``'s). The override of the release ``current``
names changes only in ``finalize`` (DM-89), as for the product's packages. A
copy is validated when it is new, and every copy when the service's
application is not on the deploy's configuration (another image, another
override): "the target image" of protocol 4.5. With nothing to copy and
nothing behind the step has nothing to do.

``seams_verify`` -- after the product's ``up``: every seam is held by the live
provider, not by a file. For a seam of the product from a service, the name is
among ``/health.seams.provides`` of that service; for a ``requires`` of a
service, among the product's; a stack that takes a seam says
``requires_satisfied: true``.
"""

import hashlib
import json
import os
import shlex
import shutil
import stat
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import ClassVar

from pridem.conformance.stack import observe
from pridem.events import Json
from pridem.runner import CommandFailed
from pridem.stacks.passport import Passport
from pridem.stacks.schema import Product, Seam, Service
from pridem.steps.base import (
    NO_NETWORK,
    NO_PULL,
    THROWAWAY,
    CheckResult,
    Mode,
    Step,
    StepContext,
    StepFailed,
    Verified,
    local_code,
)
from pridem.steps.compose import (
    ComposeStack,
    bind,
    image_of,
    mount_flag,
    out,
    stale,
)
from pridem.steps.sources import package_dir

ALL_MODES: frozenset[Mode] = frozenset({"install", "deploy", "reinstall"})
CONTAINER_DATA = "/primer/data"
"""Where a service finds the data of a kind: ``/primer/data/<kind>``."""
VALIDATE_TIMEOUT_S = 600
_TEMP = ".tmp"
DIGEST_LENGTH = 16
"""Hex digits of the copy's name ``<kind>@<digest>``."""


def data_home(root: Path, service: str) -> Path:
    """``/opt/<service>/data``: the copies of the product's data, by release."""
    return root / "opt" / service / "data"


@dataclass(frozen=True)
class DataItem:
    """One kind of the product's data for one service."""

    kind: str
    source: Path
    """The directory copied: in the product's release or a package's."""
    base: Path
    """Where ``source`` comes from: a symlink in it must not lead out of it."""
    home: Path
    """``/opt/<service>/data/<product>@<release>``: where the copies are."""
    env: str
    validate: str

    @property
    def target(self) -> Path:
        """The copy of what ``source`` holds now: ``<home>/<kind>@<digest>``."""
        return self.home / f"{self.kind}@{digest(tree(self.source))}"

    @property
    def container(self) -> str:
        return f"{CONTAINER_DATA}/{self.kind}"

    @property
    def volume(self) -> dict[str, Json]:
        """The override's bind, compose's long form (DM-86 FIX)."""
        return bind(self.target, self.container)

    @property
    def mount(self) -> list[str]:
        """The same bind for ``docker run`` (``--mount``, DM-86 FIX)."""
        return mount_flag(self.target, self.container)


def data_items(
    product: Product,
    service: Service,
    *,
    release_dir: Path,
    release: str,
    passport: Passport,
    root: Path,
) -> list[DataItem]:
    """The data the product gives ``service``, by kind; a package the passport
    does not give has no section to copy. A kind the service does not accept
    is ``seams_check``'s refusal: it is not here."""
    home = data_home(root, service.name) / f"{product.name}@{release}"
    found: list[DataItem] = []
    dependency = product.dependencies.get(service.name)
    given: dict[str, tuple[Path, Path]] = {}
    if dependency is not None:
        for kind, path in dependency.data.items():
            given[kind] = (release_dir / path, release_dir)
    for slot, declared in product.packages.items():
        package = passport.packages.get(slot)
        if package is None:
            continue
        base = package_dir(root, product.name, package)
        if package.subpath is not None:
            base = base / package.subpath
        for mount in declared.mount:
            if mount.dependency == service.name:
                given[slot] = (base / mount.from_ if mount.from_ else base, base)
    for kind, (source, base) in sorted(given.items()):
        accepted = service.accepts.get(kind)
        if accepted is None:
            continue
        found.append(
            DataItem(kind, source, base, home, accepted.env, accepted.validate_)
        )
    return found


def data_binds(
    items: Sequence[DataItem], service: str | None
) -> tuple[dict[str, list[Json]], dict[str, dict[str, str]]]:
    """The override's binds and variables of ``items`` on ``service`` (the
    service's ``app``)."""
    if service is None or not items:
        return {}, {}
    return (
        {service: [item.volume for item in items]},
        {service: {item.env: item.container for item in items}},
    )


def tree(path: Path) -> list[tuple[str, str, str]]:
    """What a directory holds: every path, its kind, and its digest or link.

    The kind is read by ``lstat`` and nothing but a regular file is opened:
    a FIFO, a socket or a device is ``special`` (``data-special`` refuses
    it), never read -- opening a FIFO waits for a writer forever. A file is
    read in blocks by ``file_digest``, never whole into memory, and opened
    with ``O_NOFOLLOW | O_NONBLOCK``: what is opened is the regular file
    ``lstat`` saw (``fstat`` says so) or ``special``."""
    found: list[tuple[str, str, str]] = []
    for entry in sorted(path.rglob("*")):
        name = str(entry.relative_to(path))
        mode = entry.lstat().st_mode
        if stat.S_ISLNK(mode):
            found.append((name, "link", str(entry.readlink())))
        elif stat.S_ISDIR(mode):
            found.append((name, "dir", ""))
        elif stat.S_ISREG(mode):
            found.append((name, *_file_digest(entry)))
        else:
            found.append((name, "special", ""))
    return found


def _file_digest(entry: Path) -> tuple[str, str]:
    """``("file", sha256)`` of a regular file; ``("special", "")`` if what
    opens is not one (swapped after ``lstat``)."""
    fd = os.open(entry, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as file:
        if not stat.S_ISREG(os.fstat(file.fileno()).st_mode):
            return "special", ""
        return "file", hashlib.file_digest(file, "sha256").hexdigest()


def digest(found: list[tuple[str, str, str]]) -> str:
    """The name of a copy holding ``found`` (``tree``): ``DIGEST_LENGTH`` hex
    digits of the sha256 of its JSON."""
    text = json.dumps(found, separators=(",", ":"))
    return hashlib.sha256(text.encode()).hexdigest()[:DIGEST_LENGTH]


def special(found: list[tuple[str, str, str]]) -> list[str]:
    """The paths of ``found`` that are neither file, directory nor link."""
    return [name for name, kind, _ in found if kind == "special"]


def _leaves(item: DataItem) -> list[str]:
    """Paths of ``item.source`` (itself included) leading out of ``item.base``."""
    base = item.base.resolve()
    out_: list[str] = []
    for entry in [item.source, *sorted(item.source.rglob("*"))]:
        if not entry.resolve().is_relative_to(base):
            out_.append(str(entry.relative_to(item.base)))
    return out_


def copy_tree(source: Path, target: Path) -> None:
    """``target``, a name not taken (``DataCopy`` copies only to a copy not
    there; one there with other files is ``copy-drift``): a copy of
    ``source`` written in ``<target>.tmp`` and renamed; symlinks stay links
    (``data-unsafe`` refused those that lead out). Nothing in place is ever
    replaced -- a directory a container mounts stays as it is. The copy's mtime is the
    time of the copy (``copytree`` gives it the source's): ``gc`` keeps the
    newest of a kind by it."""
    temp = target.with_name(target.name + _TEMP)
    if temp.exists():  # left by a run that died
        shutil.rmtree(temp)
    target.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    shutil.copytree(source, temp, symlinks=True)
    temp.rename(target)
    os.utime(target)


class DataCopy(Step):
    """The product's data in one service's own directory, validated by the
    service's new image before it restarts on it (form D)."""

    name = "data_copy"
    order = 9
    modes = ALL_MODES
    codes: ClassVar[dict[str, str]] = {
        "copy": "copy {kinds} of the product to {service} and validate them",
        "validate": "validate {kinds} of the product with the new {service}",
        "data-missing": "{service}.{kind}: {path} is not in the product",
        "data-unsafe": "{service}.{kind}: {paths} lead out of {base} or through .git",
        "data-special": "{service}.{kind}: {paths} are neither files, directories "
        "nor links",
        "copy-drift": "{service}.{kind}: {path} no longer holds what it was copied "
        "from",
        "validate-failed": "{service} refuses {kind} of the product: exit code "
        "{exit_code}",
    }

    def __init__(
        self,
        service: Service,
        entry: str,
        *,
        release: Path,
        ref: str,
        commit: str,
        items: Sequence[DataItem],
        root: Path = Path("/"),
    ) -> None:
        self.compose = ComposeStack(
            service, entry, release, ref, commit, root, staged=True
        )
        self.items = list(items)

    def _params(self, item: DataItem) -> dict[str, Json]:
        return {"service": self.compose.name, "kind": item.kind}

    def _sound(self) -> None:
        """Every source is there, stays inside where it comes from and holds
        no FIFO, socket or device; no copy has drifted."""
        for item in self.items:
            if not item.source.is_dir():
                raise StepFailed(
                    "data-missing", {**self._params(item), "path": str(item.source)}
                )
            leaving = _leaves(item)
            inside = (
                item.source.relative_to(item.base)
                if item.source.is_relative_to(item.base)
                else item.source
            )
            if any(part.lower() == ".git" for part in inside.parts):
                leaving = [*leaving, str(inside)]  # DM-63 FIX: never git's own
            if leaving:
                raise StepFailed(
                    "data-unsafe",
                    {
                        **self._params(item),
                        "paths": list[Json](leaving),
                        "base": str(item.base),
                    },
                )
            found = tree(item.source)
            odd = special(found)
            if odd:
                raise StepFailed(
                    "data-special", {**self._params(item), "paths": list[Json](odd)}
                )
            target = item.home / f"{item.kind}@{digest(found)}"
            if os.path.lexists(target) and (
                target.is_symlink() or not target.is_dir() or tree(target) != found
            ):
                raise StepFailed(
                    "copy-drift", {**self._params(item), "path": str(target)}
                )

    def _changed(self) -> list[DataItem]:
        """The items whose copy is not there yet."""
        return [item for item in self.items if not item.target.is_dir()]

    def check(self, ctx: StepContext) -> CheckResult:
        self._sound()
        changed = self._changed()
        kinds: list[Json] = list[Json](item.kind for item in self.items)
        if changed:
            params: dict[str, Json] = {
                "kinds": list[Json](item.kind for item in changed),
                "service": self.compose.name,
            }
            return CheckResult(True, local_code("copy", params), {"validate": True})
        if self.items:
            app = self.compose.app_service
            if app is not None and app in stale(ctx, self.compose):
                params = {"kinds": kinds, "service": self.compose.name}
                code = local_code("validate", params)
                return CheckResult(True, code, {"validate": True})
        return CheckResult(False)

    def act(self, ctx: StepContext, check: CheckResult) -> None:
        for item in self._changed():
            copy_tree(item.source, item.target)
        if check.data.get("validate") is True:
            self._validate(ctx)

    def _validate(self, ctx: StepContext) -> None:
        app = self.compose.app_service
        if app is None:
            raise RuntimeError("seams_check gives data only to a service with app")
        images = image_of(ctx, self.compose, app)
        if len(images) != 1:
            raise RuntimeError("build verified one image of the app before")
        labels = [
            word
            for key, value in self.compose.release_labels().items()
            for word in ("--label", f"{key}={value}")
        ]
        for item in self.items:
            command = shlex.split(item.validate.replace("<dir>", item.container))
            try:
                out(
                    ctx,
                    [
                        "docker",
                        "run",
                        "--rm",
                        *NO_NETWORK,
                        *THROWAWAY,
                        *NO_PULL,  # the image build verified in this run
                        *labels,
                        *item.mount,
                        "-e",
                        f"{item.env}={item.container}",
                        "--",  # the image is an operand, never an option (DM-93)
                        images[0],
                        *command,
                    ],
                    timeout=VALIDATE_TIMEOUT_S,
                )
            except CommandFailed as error:
                raise StepFailed(
                    "validate-failed", {**self._params(item), "exit_code": error.code}
                ) from None

    def verify(self, ctx: StepContext, check: CheckResult) -> Verified:
        self._sound()
        changed = self._changed()
        if changed:
            first = changed[0]
            raise StepFailed(
                "data-missing", {**self._params(first), "path": str(first.target)}
            )
        found: dict[str, Json] = {item.kind: str(item.target) for item in self.items}
        fact: dict[str, Json] = {"data": found} if found else {"data": "none"}
        return Verified(fact)


def _seams(body: bytes | None) -> tuple[list[str], bool] | None:
    """``seams`` of a ``/health`` body: provides and requires_satisfied."""
    if body is None:
        return None
    try:
        document = json.loads(body)
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None
    seams = document.get("seams") if isinstance(document, dict) else None
    if not isinstance(seams, dict):
        return None
    provides = seams.get("provides")
    satisfied = seams.get("requires_satisfied")
    if not isinstance(provides, list) or not isinstance(satisfied, bool):
        return None
    return [str(name) for name in provides], satisfied


class SeamsVerify(Step):
    """Every seam of the box is held by its live provider."""

    name = "seams_verify"
    order = 15
    modes = ALL_MODES
    codes: ClassVar[dict[str, str]] = {
        "provide-not-live": "{stack} does not provide {names} live",
        "requires-unsatisfied": "{stack} says its seams are not satisfied",
    }

    def __init__(
        self,
        product: Product,
        services: Mapping[str, Service],
        stacks: Mapping[str, ComposeStack],
    ) -> None:
        """``stacks`` -- the compose of the product and of each installed
        service, by name: what is observed."""
        self.product = product
        self.services = dict(services)
        self.stacks = dict(stacks)

    def _edges(self) -> list[tuple[str, str, str]]:
        """``(consumer, provider, name)`` of every seam of the box."""
        edges: list[tuple[str, str, str]] = []
        for key, var in self.product.env.items():
            if isinstance(var, Seam) and var.from_ in self.services:
                edges.append((self.product.name, var.from_, key))
        for name, service in self.services.items():
            for required in service.requires:
                edges.append((name, self.product.name, required))
        return edges

    def _live(
        self, ctx: StepContext, names: set[str]
    ) -> dict[str, tuple[list[str], bool] | None]:
        found: dict[str, tuple[list[str], bool] | None] = {}
        for name in sorted(names):
            compose = self.stacks[name]
            seen = observe(
                ctx,
                compose.stack,
                compose.entry,
                release=compose.release,
                project=compose.project,
                env_file=compose.env_file,
            )
            found[name] = _seams(seen.health)
        return found

    def _problems(self, ctx: StepContext) -> dict[str, Json]:
        edges = self._edges()
        live = self._live(ctx, {stack for edge in edges for stack in edge[:2]})
        missing: dict[str, list[str]] = {}
        for _, provider, name in edges:
            seen = live[provider]
            if seen is None or name not in seen[0]:
                missing.setdefault(provider, []).append(name)
        if missing:
            provider = min(missing)
            raise StepFailed(
                "provide-not-live",
                {"stack": provider, "names": list[Json](sorted(missing[provider]))},
            )
        for consumer in sorted({edge[0] for edge in edges}):
            seen = live[consumer]
            if seen is None or not seen[1]:
                raise StepFailed("requires-unsatisfied", {"stack": consumer})
        return {
            "seams": list[Json](
                f"{consumer}.{name} <- {provider}" for consumer, provider, name in edges
            )
        }

    def check(self, ctx: StepContext) -> CheckResult:
        self._problems(ctx)
        return CheckResult(False)  # it reads; it never acts

    def act(self, ctx: StepContext, check: CheckResult) -> None:
        raise AssertionError("seams_verify has no act")

    def verify(self, ctx: StepContext, check: CheckResult) -> Verified:
        fact = self._problems(ctx)
        seams = fact["seams"]
        return Verified({**fact, "count": len(seams) if isinstance(seams, list) else 0})
