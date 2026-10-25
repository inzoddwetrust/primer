"""Sources (TZ sections 6.2 items 3-4, 7.3, 7.4): every stack on its ref.

A stack lives in a bare repository ``/opt/<stack>/git``; what is built and run
is a worktree ``/opt/<stack>/releases/<id>`` -- ``<sha>`` for a branch (test),
``<tag>`` for a tag (prod, preview, every service). Nothing runs from
``releases/`` and nothing here touches ``current``: ``finalize`` switches it
after the gates. A release that drifted -- changed or untracked files, or a
``HEAD`` off the target (a moved tag) -- is reset to the target commit, and the
discarded paths are the fact ``drift_discarded``.

The configuration is the target commit's: ``primer.yaml`` and ``primer.lock``
are read with ``git show <commit>:<file>`` from the bare repository, never from
a worktree. A ref missing on the remote is found by ``git ls-remote`` in
``check``, before anything acts.

The steps of one stack ``sources``, in order: the root (``fetch_root``), the
lock against ``primer.yaml`` and against the tags (``check_lock``; a lock
``commit`` is a prefix of 7+ characters of the tag's commit), the services by
the lock's tags (``fetch_services``), the instance packages by the passport's
``v<version>`` tags (``fetch_packages``) with their ``primer-package.yaml``
contract checked against the product's range before a worktree is made. They
share what they read through one ``Resolved``.
"""

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import ClassVar

from packaging.specifiers import SpecifierSet
from packaging.version import Version

from pridem.events import Fact, Json
from pridem.stacks.loader import ContractError
from pridem.stacks.lock import Lock, check_lock, parse_primer_lock
from pridem.stacks.package import PACKAGE_FILE, parse_primer_package
from pridem.stacks.passport import Package
from pridem.stacks.schema import Product, Service, parse_primer_yaml
from pridem.steps.base import (
    CheckResult,
    Mode,
    Step,
    StepContext,
    StepFailed,
    Verified,
    local_code,
)
from pridem.steps.git import Repo, repo, run_git

ALL_MODES: frozenset[Mode] = frozenset({"install", "deploy", "reinstall"})


def _j(items: Sequence[str]) -> list[Json]:
    return list(items)


def _known[T](value: T | None, what: str) -> T:
    """What an earlier step of ``sources`` learned; missing only in a misbuilt plan."""
    if value is None:
        raise RuntimeError(f"{what} is not known: the sources steps run out of order")
    return value


@dataclass
class Resolved:
    """What the sources steps learn, in the order they learn it."""

    product: Product | None = None
    lock: Lock | None = None
    releases: dict[str, Path] = field(default_factory=dict)


@dataclass(frozen=True)
class Target:
    """A ref of a repository on the remote: its commit and the release dir id."""

    ref: str
    tag: bool
    commit: str

    @property
    def release(self) -> str:
        return self.ref if self.tag else self.commit


def remote_target(
    ctx: StepContext, root: Path, found: Repo, ref: str, tag: bool
) -> Target | None:
    """The commit of ``ref`` on the remote (``git ls-remote``); ``None`` if missing."""
    full = f"refs/tags/{ref}" if tag else f"refs/heads/{ref}"
    _, lines = run_git(ctx, root, ["ls-remote", found.url(), full, f"{full}^{{}}"])
    commits: dict[str, str] = {}
    for line in lines:
        commit, _, name = line.partition("\t")
        if name:
            commits[name] = commit
    peeled = commits.get(f"{full}^{{}}") or commits.get(full)
    return Target(ref, tag, peeled) if peeled else None


class Checkout:
    """A bare repository and its release worktrees under ``/opt/<stack>``."""

    def __init__(
        self, root: Path, stack: str, found: Repo, bare: Path | None = None
    ) -> None:
        self.root = root
        self.stack = stack
        self.repo = found
        self.home = root / "opt" / stack
        self.bare = bare or self.home / "git"
        self.releases = self.home / "releases"

    def git(
        self, ctx: StepContext, *args: str, expect: tuple[int, ...] = (0,)
    ) -> tuple[int, list[str]]:
        return run_git(ctx, self.root, ["-C", str(self.bare), *args], expect=expect)

    def fetch(self, ctx: StepContext) -> None:
        """The bare repository with every branch and tag of the remote."""
        if not (self.bare / "HEAD").exists():
            self.bare.parent.mkdir(parents=True, exist_ok=True)
            run_git(ctx, self.root, ["init", "--quiet", "--bare", str(self.bare)])
            self.git(ctx, "remote", "add", "origin", self.repo.url())
        else:
            self.git(ctx, "remote", "set-url", "origin", self.repo.url())
        self.git(
            ctx,
            "fetch",
            "--quiet",
            "--prune",
            "--tags",
            "--force",
            "origin",
            "+refs/heads/*:refs/heads/*",
        )

    def show(self, ctx: StepContext, commit: str, path: str) -> str | None:
        """``git show <commit>:<path>``: the target commit's file, or ``None``."""
        code, lines = self.git(ctx, "show", f"{commit}:{path}", expect=(0, 128))
        return "\n".join(lines) + "\n" if code == 0 else None

    def drift(self, ctx: StepContext, release: Path, commit: str) -> list[str] | None:
        """``None`` if the release is missing; else what differs from ``commit``."""
        if not (release / ".git").exists():
            return None
        _, head = run_git(ctx, self.root, ["-C", str(release), "rev-parse", "HEAD"])
        _, status = run_git(
            ctx,
            self.root,
            ["-C", str(release), "status", "--porcelain", "--untracked-files=all"],
        )
        paths = sorted({line[3:] for line in status if line.strip()})
        if head != [commit]:
            paths = sorted({*paths, "HEAD"})
        return paths

    def release_dir(self, target: Target) -> Path:
        return self.releases / target.release

    def materialize(self, ctx: StepContext, target: Target) -> None:
        """The release on ``target.commit``: added in ``.tmp`` and moved, or reset."""
        final = self.release_dir(target)
        temp = final.with_name(final.name + ".tmp")
        if temp.exists():  # left by a run that died
            self.git(ctx, "worktree", "remove", "--force", str(temp), expect=(0, 128))
        self.git(ctx, "worktree", "prune")
        if (final / ".git").exists():
            run_git(
                ctx,
                self.root,
                ["-C", str(final), "reset", "--quiet", "--hard", target.commit],
            )
            run_git(ctx, self.root, ["-C", str(final), "clean", "-q", "-fdx"])
            return
        self.releases.mkdir(parents=True, exist_ok=True)
        self.git(
            ctx, "worktree", "add", "--quiet", "--detach", str(temp), target.commit
        )
        self.git(ctx, "worktree", "move", str(temp), str(final))


def _verify_release(
    ctx: StepContext, checkout: Checkout, target: Target, fact: Fact
) -> Fact:
    drift = checkout.drift(ctx, checkout.release_dir(target), target.commit)
    if drift is None or drift:
        raise StepFailed(
            "release-off-target", {"release": str(checkout.release_dir(target))}
        )
    return {**fact, "head": target.commit, "release": target.release}


class _SourceStep(Step):
    modes = ALL_MODES

    def __init__(self, resolved: Resolved, root: Path = Path("/")) -> None:
        self.resolved = resolved
        self.root = root


class FetchRoot(_SourceStep):
    """The product: its release on the passport's ref, its config from that commit."""

    name = "fetch_root"
    order = 2
    codes: ClassVar[dict[str, str]] = {
        "fetch": "fetch {stack} at {ref}",
        "missing-ref": "{ref} is not on {repo}",
        "no-primer-yaml": "{ref} has no primer.yaml",
        "not-a-product": "primer.yaml of {ref} is not a product",
        "invalid-config": "{file} of {ref} breaks its contract: {codes}",
        "release-off-target": "{release} is not on the target commit after the reset",
    }

    def __init__(
        self,
        resolved: Resolved,
        root: Path = Path("/"),
        *,
        stack: str,
        address: str,
        ref: str,
        tag: bool,
    ) -> None:
        super().__init__(resolved, root)
        self.stack = stack
        self.checkout = Checkout(root, stack, repo(address))
        self.ref = ref
        self.tag = tag
        self.target: Target | None = None

    def check(self, ctx: StepContext) -> CheckResult:
        target = remote_target(ctx, self.root, self.checkout.repo, self.ref, self.tag)
        if target is None:
            raise StepFailed(
                "missing-ref", {"ref": self.ref, "repo": self.checkout.repo.address}
            )
        self.target = target
        drift = self.checkout.drift(
            ctx, self.checkout.release_dir(target), target.commit
        )
        if drift == [] and (self.checkout.bare / "HEAD").exists():
            self._read_config(ctx, target)
            return CheckResult(False, data={"drift": []})
        return CheckResult(
            True,
            local_code("fetch", {"stack": self.stack, "ref": self.ref}),
            {"drift": _j(drift or [])},
        )

    def _read_config(self, ctx: StepContext, target: Target) -> None:
        text = self.checkout.show(ctx, target.commit, "primer.yaml")
        if text is None:
            raise StepFailed("no-primer-yaml", {"ref": self.ref})
        try:
            config = parse_primer_yaml(text, f"primer.yaml@{target.commit}")
            lock_text = self.checkout.show(ctx, target.commit, "primer.lock")
            lock = (
                None
                if lock_text is None
                else parse_primer_lock(lock_text, f"primer.lock@{target.commit}")
            )
        except ContractError as error:
            codes = sorted({problem.code for problem in error.problems})
            raise StepFailed(
                "invalid-config",
                {"file": error.file.name, "ref": self.ref, "codes": _j(codes)},
            ) from None
        if not isinstance(config, Product) or isinstance(config, Service):
            raise StepFailed("not-a-product", {"ref": self.ref})
        self.resolved.product = config
        self.resolved.lock = lock
        self.resolved.releases[self.stack] = self.checkout.release_dir(target)

    def act(self, ctx: StepContext, check: CheckResult) -> None:
        target = _known(self.target, "the target")
        self.checkout.fetch(ctx)
        self._read_config(ctx, target)
        self.checkout.materialize(ctx, target)

    def verify(self, ctx: StepContext, check: CheckResult) -> Verified:
        target = _known(self.target, "the target")
        drift = [str(p) for p in check.data.get("drift", []) or []]  # type: ignore[union-attr]
        product = self.resolved.product
        fact: Fact = {"stack": self.stack, "drift_discarded": _j(drift)}
        fact = _verify_release(ctx, self.checkout, target, fact)
        return Verified({**fact, "config": product.name if product else ""})


class CheckLock(_SourceStep):
    """``primer.lock@target`` against ``primer.yaml@target`` and the services' tags."""

    name = "check_lock"
    order = 3
    codes: ClassVar[dict[str, str]] = {
        "lock-missing": "primer.lock is missing and the product has dependencies",
        "lock-range": "primer.lock breaks primer.yaml: {codes}",
        "lock-commit": "{service}: tag {tag} is {found}, the lock says {commit}",
        "missing-tag": "{service}: tag {tag} is not on {repo}",
    }

    def check(self, ctx: StepContext) -> CheckResult:
        return CheckResult(False)  # it reads; it never acts

    def act(self, ctx: StepContext, check: CheckResult) -> None:
        raise AssertionError("check_lock has no act")

    def verify(self, ctx: StepContext, check: CheckResult) -> Verified:
        product = _known(self.resolved.product, "primer.yaml")
        lock = self.resolved.lock
        if not product.dependencies:
            return Verified({"services": []})
        if lock is None:
            raise StepFailed("lock-missing")
        problems = check_lock(product, lock)
        if problems:
            raise StepFailed(
                "lock-range", {"codes": _j(sorted({p.code for p in problems}))}
            )
        pinned: list[Json] = []
        for name, dependency in product.dependencies.items():
            entry = lock.dependencies[name]
            found = repo(dependency.repo)
            target = remote_target(ctx, self.root, found, entry.tag, True)
            if target is None:
                raise StepFailed(
                    "missing-tag",
                    {"service": name, "tag": entry.tag, "repo": dependency.repo},
                )
            if len(entry.commit) < 7 or not target.commit.startswith(entry.commit):
                raise StepFailed(
                    "lock-commit",
                    {
                        "service": name,
                        "tag": entry.tag,
                        "found": target.commit,
                        "commit": entry.commit,
                    },
                )
            pinned.append({"service": name, "tag": entry.tag, "commit": target.commit})
        return Verified({"services": pinned})


class FetchServices(_SourceStep):
    """Every service of the product at its lock's tag, in ``/opt/<service>``."""

    name = "fetch_services"
    order = 4
    codes: ClassVar[dict[str, str]] = {
        "fetch": "fetch {services}",
        "release-off-target": "{release} is not on the target commit after the reset",
    }

    def _targets(self, ctx: StepContext) -> list[tuple[Checkout, Target]]:
        product, lock = self.resolved.product, self.resolved.lock
        if product is None or lock is None or not product.dependencies:
            return []
        out = []
        for name, dependency in product.dependencies.items():
            entry = lock.dependencies[name]
            found = repo(dependency.repo)
            target = _known(
                remote_target(ctx, self.root, found, entry.tag, True),
                f"tag {entry.tag}",
            )
            out.append((Checkout(self.root, name, found), target))
        return out

    def check(self, ctx: StepContext) -> CheckResult:
        stale = [
            checkout.stack
            for checkout, target in self._targets(ctx)
            if checkout.drift(ctx, checkout.release_dir(target), target.commit) != []
        ]
        if not stale:
            return CheckResult(False)
        return CheckResult(True, local_code("fetch", {"services": _j(stale)}))

    def act(self, ctx: StepContext, check: CheckResult) -> None:
        for checkout, target in self._targets(ctx):
            checkout.fetch(ctx)
            checkout.materialize(ctx, target)

    def verify(self, ctx: StepContext, check: CheckResult) -> Verified:
        done: list[Json] = []
        for checkout, target in self._targets(ctx):
            done.append(
                dict(_verify_release(ctx, checkout, target, {"stack": checkout.stack}))
            )
        return Verified({"services": done})


class FetchPackages(_SourceStep):
    """The instance's packages at ``v<version>``, their contract checked first."""

    name = "fetch_packages"
    order = 5
    codes: ClassVar[dict[str, str]] = {
        "fetch": "fetch {packages}",
        "undeclared": "the product declares no package slot {slots}",
        "missing-tag": "{slot}: tag {tag} is not on {repo}",
        "dir-clash": "{slots} would share the release directory {release}",
        "no-manifest": "{slot}: {path} is missing at {tag}",
        "contract": "{slot}: package contract {found} is outside {wanted}",
        "invalid-manifest": "{slot}: {path} at {tag} breaks its contract: {codes}",
    }

    def __init__(
        self,
        resolved: Resolved,
        root: Path = Path("/"),
        *,
        stack: str,
        packages: Mapping[str, Package],
    ) -> None:
        super().__init__(resolved, root)
        self.stack = stack
        self.packages = dict(packages)

    def _plan(self, ctx: StepContext) -> list[tuple[str, Checkout, Target, str]]:
        """(slot, checkout, target, manifest path) for every slot, contract checked."""
        product = _known(self.resolved.product, "primer.yaml")
        undeclared = sorted(set(self.packages) - set(product.packages))
        if undeclared:
            raise StepFailed("undeclared", {"slots": _j(undeclared)})
        dirs: dict[str, tuple[str, str]] = {}
        out = []
        for slot, package in sorted(self.packages.items()):
            found = repo(package.repo)
            tag = f"v{package.version}"
            release = f"{found.name}@{package.version}"
            other = dirs.setdefault(release, (found.path, slot))
            if other[0] != found.path:
                raise StepFailed(
                    "dir-clash", {"slots": _j([other[1], slot]), "release": release}
                )
            bare = self.root / "opt" / self.stack / "packages" / f"{found.alias}.git"
            checkout = Checkout(self.root, self.stack, found, bare=bare)
            target = remote_target(ctx, self.root, found, tag, True)
            if target is None:
                raise StepFailed(
                    "missing-tag", {"slot": slot, "tag": tag, "repo": package.repo}
                )
            target = Target(release, True, target.commit)
            path = (
                f"{package.subpath}/{PACKAGE_FILE}" if package.subpath else PACKAGE_FILE
            )
            out.append((slot, checkout, target, path))
        return out

    def _contract(
        self, ctx: StepContext, slot: str, checkout: Checkout, target: Target, path: str
    ) -> str:
        product = _known(self.resolved.product, "primer.yaml")
        text = checkout.show(ctx, target.commit, path)
        tag = f"v{target.ref.rsplit('@', 1)[1]}"
        if text is None:
            raise StepFailed("no-manifest", {"slot": slot, "path": path, "tag": tag})
        try:
            manifest = parse_primer_package(text, f"{path}@{tag}")
        except ContractError as error:
            codes = sorted({problem.code for problem in error.problems})
            raise StepFailed(
                "invalid-manifest",
                {"slot": slot, "path": path, "tag": tag, "codes": _j(codes)},
            ) from None
        wanted = product.packages[slot].contract
        if not SpecifierSet(wanted).contains(Version(manifest.contract)):
            raise StepFailed(
                "contract", {"slot": slot, "found": manifest.contract, "wanted": wanted}
            )
        return manifest.contract

    def check(self, ctx: StepContext) -> CheckResult:
        stale = [
            slot
            for slot, checkout, target, _ in self._plan(ctx)
            if checkout.drift(ctx, checkout.release_dir(target), target.commit) != []
        ]
        if not stale:
            return CheckResult(False)
        return CheckResult(True, local_code("fetch", {"packages": _j(stale)}))

    def act(self, ctx: StepContext, check: CheckResult) -> None:
        done: set[str] = set()
        for slot, checkout, target, path in self._plan(ctx):
            checkout.fetch(ctx)
            self._contract(ctx, slot, checkout, target, path)  # before any worktree
            if target.release not in done:
                checkout.materialize(ctx, target)
                done.add(target.release)

    def verify(self, ctx: StepContext, check: CheckResult) -> Verified:
        facts: list[Json] = []
        for slot, checkout, target, path in self._plan(ctx):
            contract = self._contract(ctx, slot, checkout, target, path)
            fact = _verify_release(
                ctx, checkout, target, {"slot": slot, "contract": contract}
            )
            facts.append(dict(fact))
        return Verified({"packages": facts})


def source_steps(
    root: Path,
    *,
    stack: str,
    address: str,
    ref: str,
    tag: bool,
    packages: Mapping[str, Package] | None = None,
) -> tuple[Resolved, list[Step]]:
    """The ``sources`` ladder a plan builder puts after ``host``."""
    resolved = Resolved()
    steps: list[Step] = [
        FetchRoot(resolved, root, stack=stack, address=address, ref=ref, tag=tag),
        CheckLock(resolved, root),
        FetchServices(resolved, root),
        FetchPackages(resolved, root, stack=stack, packages=packages or {}),
    ]
    return resolved, steps
