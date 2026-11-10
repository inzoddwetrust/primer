"""Sources (TZ sections 6.2 items 3-4, 7.3, 7.4): every stack on its ref.

A stack lives in a bare repository ``/opt/<stack>/git``; what is built and run
is a worktree ``/opt/<stack>/releases/<id>`` -- ``<sha>`` for a branch (test),
``<tag>`` for a tag (prod, preview, every service). Nothing runs from
``releases/`` and nothing here touches ``current``: ``finalize`` switches it
after the gates. A release that drifted -- changed or untracked files, or a
``HEAD`` off the target (a moved tag) -- is reset to the target commit, and the
discarded paths are the fact ``drift_discarded``. A file ``.gitignore`` names
is drift too (``status --ignored=matching``): a ``.env`` planted in a release
is in it as soon as compose reads the release; the reset removes it with the
nested repositories (``clean -ffdx``). A ``<release>.tmp`` a run left when it
died is taken off whatever it is -- a worktree still locked ``initializing``
(``worktree remove -f -f``) or a directory git does not know -- before the
release is added again.

The configuration is the target commit's: ``primer.yaml`` and ``primer.lock``
are read with ``git show <commit>:<file>`` from the bare repository, never from
a worktree. A ref missing on the remote is found by ``git ls-remote`` in
``check``, before anything acts. That the commit has no such file is
``git ls-tree <commit> -- <file>`` answering 0 with nothing; a repository that
cannot answer -- ``ls-tree`` 128 (the commit's tree) or 1 (a tree on the way),
or the file listed and ``show`` 128 -- is
``repo-damaged``, never "no file" (DM-81: both are 128 for ``git show``).

The steps of one stack ``sources``, in order: the root (``fetch_root``), the
lock against ``primer.yaml`` and against the tags of the services the box uses
(``check_lock``; a lock ``commit`` is a prefix of 7+ characters of the tag's
commit), the co-located services the box uses by the lock's tags, each with
its ``primer.yaml`` (``fetch_services``), the instance packages by the passport's
``v<version>`` tags (``fetch_packages``) with their ``primer-package.yaml``
contract checked against the product's range before a worktree is made. They
share what they read through one ``Resolved``.
"""

import os
import re
import shutil
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import ClassVar

from packaging.specifiers import SpecifierSet
from packaging.version import Version

from pridem.events import Fact, Json, strings
from pridem.files import atomic_write
from pridem.stacks.loader import ContractError
from pridem.stacks.lock import Lock, LockEntry, check_lock, parse_primer_lock
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
    services: dict[str, Service] = field(default_factory=dict)
    """``primer.yaml`` of each fetched service, from its lock tag's commit."""
    commits: dict[str, str] = field(default_factory=dict)
    """The full commit of each fetched service's tag."""
    releases: dict[str, Path] = field(default_factory=dict)
    tries: dict[str, str] = field(default_factory=dict)
    """``update --try <service>=<version>``: the version a test box runs in
    place of the lock's; ``check_lock`` puts it in ``lock``."""


@dataclass(frozen=True)
class Target:
    """A ref of a repository on the remote: its commit and the release dir id."""

    ref: str
    tag: bool
    commit: str

    @property
    def release(self) -> str:
        return self.ref if self.tag else self.commit


class RepoDamaged(Exception):
    """The bare repository cannot answer for ``path`` at a commit: a tree or a
    blob is missing or broken. Each step that reads a file names it in its
    own ``repo-damaged``."""

    def __init__(self, path: str) -> None:
        super().__init__(path)
        self.path = path


COMMIT = re.compile(r"[0-9a-f]{40}")
"""A commit as the machine takes it from a remote: 40 lower-case hex digits."""

NOT_A_COMMIT: dict[str, str] = {
    "not-a-commit": "{repo} answered {ref} with {commit}, not a 40-hex commit",
}
"""The code of every step that asks a remote for a commit: what the remote
answered is checked before it reaches a git command or a release path."""


def remote_target(
    ctx: StepContext, root: Path, found: Repo, ref: str, tag: bool
) -> Target | None:
    """The commit of ``ref`` on the remote (``git ls-remote``); ``None`` if missing.

    The answer is refused (``not-a-commit``) unless it is 40 hex digits: it
    becomes an argument of ``git show``, ``reset`` and ``worktree add`` and the
    name of a release directory.
    """
    full = f"refs/tags/{ref}" if tag else f"refs/heads/{ref}"
    _, lines = run_git(ctx, root, ["ls-remote", found.url(), full, f"{full}^{{}}"])
    commits: dict[str, str] = {}
    for line in lines:
        commit, _, name = line.partition("\t")
        if name:
            commits[name] = commit
    peeled = commits.get(f"{full}^{{}}") or commits.get(full)
    if not peeled:
        return None
    if COMMIT.fullmatch(peeled) is None:
        raise StepFailed(
            "not-a-commit",
            {"repo": found.address, "ref": full, "commit": peeled[:80]},
        )
    return Target(ref, tag, peeled)


def package_release(package: Package) -> str:
    """The release directory name of a package: ``<repo name>@<version>``."""
    return f"{repo(package.repo).name}@{package.version}"


def package_dir(root: Path, stack: str, package: Package) -> Path:
    """Where a package of ``stack`` is on the box: ``/opt/<stack>/releases/
    <name>@<version>``. ``fetch_packages`` puts it there, ``packages`` mounts it
    from there, ``gc`` keeps it by it -- this one function for all three."""
    return root / "opt" / stack / "releases" / package_release(package)


ADDRESS_KEY = "pridem.address"
"""The key of a bare repository's git config that holds its address."""


MARKER = ".pridem"
"""``/opt/<stack>/.pridem``: the machine's mark on the directory of a stack it
checked out, holding the stack's name (DM-76). ``destroy`` and ``gc`` take as
a stack only a directory with the mark whose name is the directory's: any
other directory of ``/opt`` -- a virtualenv ``env/``, a ``releases/`` of
someone else -- is not the machine's and is left alone."""


def mark(home: Path, stack: str) -> None:
    """The mark of ``home``, written once, atomically."""
    marker = home / MARKER
    if not marker.is_file():
        home.mkdir(parents=True, exist_ok=True)
        atomic_write(marker, f"{stack}\n", 0o644)


def marked(root: Path) -> tuple[list[Path], list[Path]]:
    """``/opt/<stack>`` with the machine's mark, and the directories whose
    mark names another stack -- neither the machine's nor anyone's to touch."""
    opt = root / "opt"
    mine: list[Path] = []
    astray: list[Path] = []
    if not opt.is_dir():
        return mine, astray
    for path in sorted(opt.iterdir()):
        marker = path / MARKER
        if path.is_dir() and marker.is_file():
            name = marker.read_text(encoding="utf-8").strip()
            (mine if name == path.name else astray).append(path)
    return mine, astray


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
        """The bare repository with every branch and tag of the remote; the
        stack's directory marked as the machine's (``MARKER``)."""
        if "/" not in self.stack:
            mark(self.home, self.stack)
        if not (self.bare / "HEAD").exists():
            self.bare.parent.mkdir(parents=True, exist_ok=True)
            run_git(ctx, self.root, ["init", "--quiet", "--bare", str(self.bare)])
            self.git(ctx, "remote", "add", "origin", self.repo.url())
        else:
            self.git(ctx, "remote", "set-url", "origin", self.repo.url())
        # the address as given: the remote holds the ssh alias, not the address
        # (``pridem/verbs/plans.py`` reads where a box's passport comes from)
        self.git(ctx, "config", ADDRESS_KEY, self.repo.address)
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
        """``git show <commit>:<path>``: the target commit's file, or ``None``
        when the commit has none; a repository that cannot say is
        ``RepoDamaged``."""
        # 1: a tree on the way to path is missing; 128: the commit's own tree
        code, listed = self.git(ctx, "ls-tree", commit, "--", path, expect=(0, 1, 128))
        if code != 0:
            raise RepoDamaged(path)
        if not [line for line in listed if line.strip()]:
            return None
        code, lines = self.git(ctx, "show", f"{commit}:{path}", expect=(0, 128))
        if code != 0:
            raise RepoDamaged(path)
        return "\n".join(lines) + "\n"

    def drift(self, ctx: StepContext, release: Path, commit: str) -> list[str] | None:
        """``None`` if the release is missing; else what differs from ``commit``."""
        if not (release / ".git").exists():
            return None
        _, head = run_git(ctx, self.root, ["-C", str(release), "rev-parse", "HEAD"])
        _, status = run_git(
            ctx,
            self.root,
            [
                "-C",
                str(release),
                "status",
                "--porcelain",
                "--untracked-files=all",
                "--ignored=matching",
            ],
        )
        paths = sorted({line[3:] for line in status if line.strip()})
        if head != [commit]:
            paths = sorted({*paths, "HEAD"})
        return paths

    def release_dir(self, target: Target) -> Path:
        return self.releases / target.release

    def _take_off(self, ctx: StepContext, temp: Path) -> None:
        """A ``.tmp`` a dead run left, removed whatever it is: a worktree of
        the bare repository -- locked ``initializing`` when ``worktree add``
        died, which only ``remove -f -f`` takes (DM-81) -- or anything else
        git does not know as one, removed as a path. A worktree whose
        directory is gone is still listed while it is locked, and ``worktree
        add`` refuses its path: the list is read every time, not only when
        the path is there."""
        _, listed = self.git(ctx, "worktree", "list", "--porcelain")
        if temp in _worktrees(listed):
            self.git(ctx, "worktree", "remove", "-f", "-f", str(temp))
        elif temp.is_dir() and not temp.is_symlink():
            shutil.rmtree(temp)
        elif os.path.lexists(temp):
            temp.unlink()

    def materialize(self, ctx: StepContext, target: Target) -> None:
        """The release on ``target.commit``: added in ``.tmp`` and moved, or reset."""
        final = self.release_dir(target)
        temp = final.with_name(final.name + ".tmp")
        self._take_off(ctx, temp)  # left by a run that died, if anything
        self.git(ctx, "worktree", "prune")
        if (final / ".git").exists():
            run_git(
                ctx,
                self.root,
                ["-C", str(final), "reset", "--quiet", "--hard", target.commit],
            )
            run_git(ctx, self.root, ["-C", str(final), "clean", "-q", "-ffdx"])
            return
        self.releases.mkdir(parents=True, exist_ok=True)
        self.git(
            ctx, "worktree", "add", "--quiet", "--detach", str(temp), target.commit
        )
        self.git(ctx, "worktree", "move", str(temp), str(final))


def _worktrees(lines: Sequence[str]) -> set[Path]:
    """The paths of ``git worktree list --porcelain``."""
    return {
        Path(line[len("worktree ") :]) for line in lines if line.startswith("worktree ")
    }


def _verify_release(
    ctx: StepContext, checkout: Checkout, target: Target, fact: Fact
) -> Fact:
    drift = checkout.drift(ctx, checkout.release_dir(target), target.commit)
    if drift is None or drift:
        raise StepFailed(
            "release-off-target", {"release": str(checkout.release_dir(target))}
        )
    return {**fact, "head": target.commit, "release": target.release}


Chosen = Callable[[Product], Sequence[str]]
"""The dependencies a box uses: those of its edition (``installed`` of
``stacks/seams.py``)."""


class _SourceStep(Step):
    modes = ALL_MODES

    def __init__(
        self, resolved: Resolved, root: Path = Path("/"), chosen: Chosen | None = None
    ) -> None:
        """``chosen`` -- the dependencies this box uses; ``None`` -- all of them."""
        self.resolved = resolved
        self.root = root
        self.chosen = chosen

    def _used(self, product: Product) -> list[str]:
        """The product's dependencies this box uses, in the product's order."""
        given = product.dependencies if self.chosen is None else self.chosen(product)
        names = set(given)
        return [name for name in product.dependencies if name in names]


class FetchRoot(_SourceStep):
    """The product: its release on the passport's ref, its config from that commit.

    The product's directory ``/opt/<stack>`` is named by its repository, its
    env and override by the ``name`` of its ``primer.yaml``: the two are one
    name, or the product is refused (``name-mismatch``) before its worktree is
    made -- in ``check`` on a box that has the commit, in ``act`` once fetched."""

    name = "fetch_root"
    order = 2
    codes: ClassVar[dict[str, str]] = {
        **NOT_A_COMMIT,
        "fetch": "fetch {stack} at {ref}",
        "missing-ref": "{ref} is not on {repo}",
        "no-primer-yaml": "{ref} has no primer.yaml",
        "repo-damaged": "the repository of {ref} cannot give {path}: a tree or a "
        "blob is missing",
        "not-a-product": "primer.yaml of {ref} is not a product",
        "name-mismatch": "the repository {stack} names its product {name} in "
        "primer.yaml",
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
        tag: bool | None,
    ) -> None:
        """``tag``: the ref is a tag, a branch, or -- ``None``, ``deploy <ref>``
        on a test box -- a tag if the remote has one of that name, else a
        branch."""
        super().__init__(resolved, root)
        self.stack = stack
        self.checkout = Checkout(root, stack, repo(address))
        self.ref = ref
        self.tag = tag
        self.target: Target | None = None

    def _target(self, ctx: StepContext) -> Target | None:
        kinds = (True, False) if self.tag is None else (self.tag,)
        for tag in kinds:
            found = remote_target(ctx, self.root, self.checkout.repo, self.ref, tag)
            if found is not None:
                return found
        return None

    def check(self, ctx: StepContext) -> CheckResult:
        target = self._target(ctx)
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

    def _show(self, ctx: StepContext, target: Target, path: str) -> str | None:
        try:
            return self.checkout.show(ctx, target.commit, path)
        except RepoDamaged as error:
            raise StepFailed(
                "repo-damaged", {"ref": self.ref, "path": error.path}
            ) from None

    def _read_config(self, ctx: StepContext, target: Target) -> None:
        text = self._show(ctx, target, "primer.yaml")
        if text is None:
            raise StepFailed("no-primer-yaml", {"ref": self.ref})
        try:
            config = parse_primer_yaml(text, f"primer.yaml@{target.commit}")
            lock_text = self._show(ctx, target, "primer.lock")
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
        if config.name != self.stack:
            raise StepFailed(
                "name-mismatch", {"stack": self.stack, "name": config.name}
            )
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
        drift = strings(check.data.get("drift"))
        product = self.resolved.product
        fact: Fact = {"stack": self.stack, "drift_discarded": _j(drift)}
        fact = _verify_release(ctx, self.checkout, target, fact)
        return Verified({**fact, "config": product.name if product else ""})


class CheckLock(_SourceStep):
    """``primer.lock@target`` against ``primer.yaml@target``, and the tags of the
    services the box uses (its edition's): the repository of a service the box
    does not use is never asked."""

    name = "check_lock"
    order = 3
    codes: ClassVar[dict[str, str]] = {
        **NOT_A_COMMIT,
        "lock-missing": "primer.lock is missing and the product has dependencies",
        "lock-range": "primer.lock breaks primer.yaml: {codes}",
        "lock-commit": "{service}: tag {tag} is {found}, the lock says {commit}",
        "missing-tag": "{service}: tag {tag} is not on {repo}",
        "try-off-test": "--try runs on a test box only; this one is {role}",
        "try-unknown": "--try {service}: the product has no such dependency",
    }

    def check(self, ctx: StepContext) -> CheckResult:
        return CheckResult(False)  # it reads; it never acts

    def _tried(self, ctx: StepContext, product: Product, lock: Lock) -> Lock:
        """``lock`` with the versions of ``--try``: a tried entry's commit is
        the tag's on the remote, the lock's commit no longer binds it."""
        tries = self.resolved.tries
        if not tries:
            return lock
        if ctx.role != "test":
            raise StepFailed("try-off-test", {"role": ctx.role})
        entries = dict(lock.dependencies)
        for name, version in sorted(tries.items()):
            dependency = product.dependencies.get(name)
            if dependency is None:
                raise StepFailed("try-unknown", {"service": name})
            tag = f"v{version}"
            target = remote_target(ctx, self.root, repo(dependency.repo), tag, True)
            if target is None:
                raise StepFailed(
                    "missing-tag",
                    {"service": name, "tag": tag, "repo": dependency.repo},
                )
            entries[name] = LockEntry(version=version, tag=tag, commit=target.commit)
        tried = lock.model_copy(update={"dependencies": entries})
        self.resolved.lock = tried
        return tried

    def act(self, ctx: StepContext, check: CheckResult) -> None:
        raise AssertionError("check_lock has no act")

    def verify(self, ctx: StepContext, check: CheckResult) -> Verified:
        product = _known(self.resolved.product, "primer.yaml")
        lock = self.resolved.lock
        if not product.dependencies:
            tries = sorted(self.resolved.tries)
            if tries and ctx.role != "test":
                raise StepFailed("try-off-test", {"role": ctx.role})
            if tries:  # a tried service the product does not have
                raise StepFailed("try-unknown", {"service": tries[0]})
            return Verified({"services": []})
        if lock is None:
            raise StepFailed("lock-missing")
        lock = self._tried(ctx, product, lock)
        problems = check_lock(product, lock)
        if problems:
            raise StepFailed(
                "lock-range", {"codes": _j(sorted({p.code for p in problems}))}
            )
        pinned: list[Json] = []
        for name in self._used(product):
            dependency = product.dependencies[name]
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
    """Every co-located service the box uses at its lock's tag, in
    ``/opt/<service>``, and its ``primer.yaml`` from that tag's commit.

    A service's directory is named by its key in ``dependencies``, its env by
    the ``name`` of its ``primer.yaml``: the two are one name, or the service
    is refused (``name-mismatch``) before its worktree is made. A ``remote``
    dependency is never fetched (rule 13), nor one the edition leaves out."""

    name = "fetch_services"
    order = 4
    codes: ClassVar[dict[str, str]] = {
        **NOT_A_COMMIT,
        "fetch": "fetch {services}",
        "release-off-target": "{release} is not on the target commit after the reset",
        "no-primer-yaml": "{service}: {tag} has no primer.yaml",
        "repo-damaged": "{service}: the repository of {tag} cannot give {path}: "
        "a tree or a blob is missing",
        "not-a-service": "{service}: primer.yaml of {tag} is not a service",
        "invalid-config": "{service}: {file} of {tag} breaks its contract: {codes}",
        "name-mismatch": "the dependency {service} names itself {name} in primer.yaml",
    }

    def _targets(self, ctx: StepContext) -> list[tuple[Checkout, Target]]:
        product, lock = self.resolved.product, self.resolved.lock
        if product is None or lock is None or not product.dependencies:
            return []
        out = []
        for name in self._used(product):
            dependency = product.dependencies[name]
            entry = lock.dependencies[name]
            found = repo(dependency.repo)
            target = _known(
                remote_target(ctx, self.root, found, entry.tag, True),
                f"tag {entry.tag}",
            )
            out.append((Checkout(self.root, name, found), target))
        return out

    def _read(self, ctx: StepContext, checkout: Checkout, target: Target) -> None:
        """``primer.yaml`` of the service at ``target``, from git."""
        params: dict[str, Json] = {"service": checkout.stack, "tag": target.ref}
        try:
            text = checkout.show(ctx, target.commit, "primer.yaml")
        except RepoDamaged as error:
            raise StepFailed("repo-damaged", {**params, "path": error.path}) from None
        if text is None:
            raise StepFailed("no-primer-yaml", params)
        try:
            config = parse_primer_yaml(text, f"primer.yaml@{target.commit}")
        except ContractError as error:
            codes = sorted({problem.code for problem in error.problems})
            raise StepFailed(
                "invalid-config",
                {**params, "file": error.file.name, "codes": _j(codes)},
            ) from None
        if not isinstance(config, Service):
            raise StepFailed("not-a-service", params)
        if config.name != checkout.stack:
            raise StepFailed(
                "name-mismatch", {"service": checkout.stack, "name": config.name}
            )
        self.resolved.services[checkout.stack] = config
        self.resolved.commits[checkout.stack] = target.commit
        self.resolved.releases[checkout.stack] = checkout.release_dir(target)

    def check(self, ctx: StepContext) -> CheckResult:
        stale = []
        for checkout, target in self._targets(ctx):
            if checkout.drift(ctx, checkout.release_dir(target), target.commit) != []:
                stale.append(checkout.stack)
            else:
                self._read(ctx, checkout, target)
        if not stale:
            return CheckResult(False)
        return CheckResult(True, local_code("fetch", {"services": _j(stale)}))

    def act(self, ctx: StepContext, check: CheckResult) -> None:
        for checkout, target in self._targets(ctx):
            checkout.fetch(ctx)
            self._read(ctx, checkout, target)  # before any worktree
            checkout.materialize(ctx, target)

    def verify(self, ctx: StepContext, check: CheckResult) -> Verified:
        done: list[Json] = []
        for checkout, target in self._targets(ctx):
            self._read(ctx, checkout, target)
            fact = _verify_release(ctx, checkout, target, {"stack": checkout.stack})
            done.append(dict(fact))
        return Verified({"services": done})


PACKAGE_CODES = {
    "no-manifest": "{slot}: {path} is missing at {tag}",
    "invalid-manifest": "{slot}: {path} at {tag} breaks its contract: {codes}",
    "contract": "{slot}: package contract {found} is outside {wanted}",
}
"""The texts of ``package_contract``'s codes, for every step that gives them."""


def package_contract(
    product: Product, slot: str, text: str | None, path: str, tag: str
) -> str:
    """The contract version of the package of ``slot``, read from the text of
    its ``primer-package.yaml`` (``None`` -- there is none), inside the
    product's range, or red (``no-manifest``, ``invalid-manifest``,
    ``contract``). One function for ``fetch_packages`` and ``pridem check``."""
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


class FetchPackages(_SourceStep):
    """The instance's packages at ``v<version>``, their contract checked first."""

    name = "fetch_packages"
    order = 5
    codes: ClassVar[dict[str, str]] = {
        **NOT_A_COMMIT,
        "fetch": "fetch {packages}",
        "undeclared": "the product declares no package slot {slots}",
        "missing-tag": "{slot}: tag {tag} is not on {repo}",
        "dir-clash": "{slots} would share the release directory {release}",
        "repo-damaged": "{slot}: the repository cannot give {path}: a tree or a "
        "blob is missing",
        **PACKAGE_CODES,
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
            release = package_release(package)
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
        try:
            text = checkout.show(ctx, target.commit, path)
        except RepoDamaged as error:
            raise StepFailed(
                "repo-damaged", {"slot": slot, "path": error.path}
            ) from None
        tag = f"v{target.ref.rsplit('@', 1)[1]}"
        return package_contract(product, slot, text, path, tag)

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
    tag: bool | None,
    packages: Mapping[str, Package] | None = None,
    tries: Mapping[str, str] | None = None,
    chosen: Chosen | None = None,
) -> tuple[Resolved, list[Step]]:
    """The ``sources`` ladder a plan builder puts after ``host``; ``chosen`` --
    the dependencies the box uses (``None`` -- every one)."""
    resolved = Resolved(tries=dict(tries or {}))
    steps: list[Step] = [
        FetchRoot(resolved, root, stack=stack, address=address, ref=ref, tag=tag),
        CheckLock(resolved, root, chosen),
        FetchServices(resolved, root, chosen),
        FetchPackages(resolved, root, stack=stack, packages=packages or {}),
    ]
    return resolved, steps
