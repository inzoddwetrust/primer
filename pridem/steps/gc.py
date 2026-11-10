"""``gc``: the box's clean-up by labels, measured before and after (TZ 7.3;
incident II).

``check`` measures -- ``docker system df`` by category (images, containers,
volumes, build cache), the releases of every stack in ``/opt/<stack>/releases``
and the size of ``journal/`` -- and decides what ``act`` removes:

- images: only those labelled ``pridem.commit``; never one whose commit is the
  current or the previous release of a stack, never one a container, running or
  stopped, was made from. Every image of such a commit is kept, of every
  edition and package version (KNOWN CEILING in ``check``, DM-61). An image
  without the label -- a base image of ``FROM``, nginx, certbot, postgres --
  is not even listed. The key is the commit: ``pridem.release`` holds the
  ref, on test a branch that every commit shares. An image with tags loses
  them all and goes with the last; one without goes by its ID;
- the build cache: ``docker builder prune --all --keep-storage <budget>`` when it
  is over ``policies.gc.builder_cache_budget`` (without ``--all`` docker prunes
  only dangling cache, which is never anything);
- releases: per stack ``policies.gc.keep_releases`` worktrees stay -- the
  current and any directory a container mounts, whatever the number, then the
  previous, then the newest by mtime. A worktree goes
  by ``git worktree remove`` in the bare repository it belongs to (the stack's
  or a package's), then ``worktree prune``. A package directory stays while a
  container mounts it, the passport names it (``package_dir``, the path
  ``fetch_packages`` and ``packages`` use) or the composition of the current or
  the previous release names it.
  ``<name>.tmp`` belongs to ``sources``;
- the product's data a service took (form D, ``steps/services.py``):
  ``/opt/<service>/data/<product>@<release>`` stays while a container mounts it
  or it is of the current or the previous release of the product, then the
  newest by mtime up to ``keep_releases``; the rest is removed whole. Inside
  one that stays, a copy ``<kind>@<digest>`` stays while a container mounts it
  or it is the newest of its kind by mtime (the copy of this run, validated
  or not); the other copies of the kind are removed (DM-81);
- journals: ``Box.evict_journals`` down to ``policies.gc.journal_budget``; the
  journal of the current run is never evicted;
- volumes: never. ``gc`` runs no volume command, and fewer volumes after than
  before is red.

The current release of a stack is the target of ``/opt/<stack>/current``, its
commit read from the worktree. The previous is named by the newest green verdict
in ``history/`` whose ``finalize`` put another release of the stack in
``current``; its commit comes from that verdict's ``fetch_root`` and
``fetch_services`` facts, else from its worktree. ``state.json`` is not read:
it is a record of the box, not a basis of decisions.

``verify`` measures again. What ``act`` removed and is still there -- an image,
a release, a journal it could evict, a build cache over budget that did not
shrink -- is red, ``gc:not-removed``. A number over budget after everything
allowed went -- the build cache, ``journal/`` holding the current journal alone,
more protected releases than ``keep_releases`` -- is ``incomplete {what: gc,
code: gc:over-budget}`` with the numbers, exit code 2. Sizes are docker's text
(decimal units) turned into bytes; budgets are the passport's (binary units).

The passport is the one ``fetch_passport`` read, else the box's copy. A
``check`` that cannot measure -- no passport, a copy that does not load, docker
or git refusing a command, output it cannot read -- has removed nothing:
``verify`` makes it ``incomplete {what: gc, code: gc:not-started}`` with the
cause, exit 2, so a ``gc`` that touched nothing never turns a green plan red. A
failure once a removal has begun stays red.

``gc`` writes under the box lock (``evict_journals`` checks it). It is no point
of no return: it removes only what neither the current nor the previous release
nor a container needs, so a restore never misses it.
"""

import json
import os
import re
import shutil
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import ClassVar

from pridem.events import Fact, Json
from pridem.report.schema import Verdict
from pridem.runner import CommandFailed, CommandNotStarted, CommandTimedOut
from pridem.stacks.loader import ContractError
from pridem.stacks.passport import Gc as GcPolicy
from pridem.stacks.passport import Passport, load_passport, size_bytes
from pridem.state import Box, VerdictDamaged
from pridem.steps.base import (
    CheckResult,
    Mode,
    Step,
    StepContext,
    StepFailed,
    Verified,
    local_code,
)
from pridem.steps.compose import out
from pridem.steps.git import run_git
from pridem.steps.passport import NO_PASSPORT, PASSPORT_COPY, Fetched
from pridem.steps.sources import marked, package_dir

GC_STACK = "box"
"""The stack name a plan builder gives the ``gc`` step in ``finally``."""

GC_MODES: frozenset[Mode] = frozenset({"install", "deploy", "reinstall", "gc"})
PRUNE_TIMEOUT_S = 1800
_CATEGORIES = {
    "Images": "images",
    "Containers": "containers",
    "Local Volumes": "volumes",
    "Build Cache": "build_cache",
}
_UNITS = {
    "B": 1,
    "kB": 1000,
    "KB": 1000,
    "MB": 1000**2,
    "GB": 1000**3,
    "TB": 1000**4,
    "PB": 1000**5,
}
_SIZE = re.compile(r"^([0-9]+(?:\.[0-9]+)?)\s*([kKMGTP]?B)$")
_TEMP = ".tmp"


class UnreadableOutput(ValueError):
    """docker printed what its measurement cannot be read from."""


def docker_size(text: str) -> int:
    """``1.234GB`` -> bytes: docker prints sizes in decimal units."""
    found = _SIZE.match(text.strip())
    if found is None:
        raise UnreadableOutput(f"not a docker size: {text!r}")
    return round(float(found[1]) * _UNITS[found[2]])


def system_df(ctx: StepContext) -> dict[str, Json]:
    """``docker system df`` by category: ``{count, bytes}``; a category docker
    did not print is zero."""
    _, lines = out(
        ctx, ["docker", "system", "df", "--format", "{{json .}}"], passed_on=False
    )
    found: dict[str, Json] = {
        name: {"count": 0, "bytes": 0} for name in _CATEGORIES.values()
    }
    for line in lines:
        if not line.strip():
            continue
        row = json.loads(line)
        if not isinstance(row, dict):
            raise UnreadableOutput(
                "docker system df printed a line that is not an object"
            )
        name = _CATEGORIES.get(str(row.get("Type")))
        if name is not None:
            count = str(row.get("TotalCount"))
            if not count.isdigit():
                raise UnreadableOutput(f"not a count of docker system df: {count!r}")
            found[name] = {
                "count": int(count),
                "bytes": docker_size(str(row.get("Size"))),
            }
    return found


def _number(df: Mapping[str, Json], category: str, key: str) -> int:
    part = df.get(category)
    value = part.get(key) if isinstance(part, dict) else None
    if not isinstance(value, int):
        raise UnreadableOutput(f"no {key} of {category} in the measurement")
    return value


def _lines(ctx: StepContext, argv: Sequence[str]) -> list[str]:
    _, lines = out(ctx, argv, passed_on=False)
    return sorted({line.strip() for line in lines if line.strip()})


def _inspect(ctx: StepContext, kind: str, ids: Sequence[str]) -> list[dict[str, Json]]:
    if not ids:
        return []
    _, lines = out(ctx, ["docker", kind, "inspect", *ids], passed_on=False)
    found = json.loads("\n".join(lines))
    if not isinstance(found, list):
        raise UnreadableOutput(f"docker {kind} inspect did not print a list")
    return [item for item in found if isinstance(item, dict)]


def labelled_images(ctx: StepContext) -> list[str]:
    """IDs of the images that carry ``pridem.commit``; no other image is listed."""
    return _lines(
        ctx,
        [
            "docker",
            "image",
            "ls",
            "--quiet",
            "--no-trunc",
            "--filter",
            "label=pridem.commit",
        ],
    )


def _dicts(value: Json | None) -> list[dict[str, Json]]:
    return (
        [item for item in value if isinstance(item, dict)]
        if isinstance(value, list)
        else []
    )


def _short(image: str) -> str:
    return image.removeprefix("sha256:")[:12]


def _strings(value: Json | None) -> list[str]:
    return (
        [item for item in value if isinstance(item, str)]
        if isinstance(value, list)
        else []
    )


@dataclass(frozen=True)
class _Release:
    stack: str
    path: Path
    bare: Path
    package: bool


@dataclass
class _Known:
    """What the box says of its releases: current, previous, their commits."""

    current: dict[str, Path]
    previous: dict[str, str]
    commits: set[str]
    names: set[str]
    """Composition values of the previous releases: their package directories."""
    damaged: int


def _finalized(verdict: Verdict) -> dict[str, str] | None:
    for step in verdict.steps:
        if (step.phase, step.name, step.status) == ("main", "finalize", "ok"):
            current = (step.verify or {}).get("current")
            if isinstance(current, dict):
                return {k: v for k, v in current.items() if isinstance(v, str)}
    return None


def _heads(verdict: Verdict) -> dict[tuple[str, str], str]:
    """``(stack, release) -> commit`` from the ``fetch_*`` facts of ``verdict``."""
    found: dict[tuple[str, str], str] = {}
    for step in verdict.steps:
        if step.status != "ok" or step.verify is None:
            continue
        facts: list[Json] = []
        if step.name == "fetch_root":
            facts = [step.verify]
        elif step.name == "fetch_services":
            services = step.verify.get("services")
            facts = services if isinstance(services, list) else []
        for fact in facts:
            if not isinstance(fact, dict):
                continue
            stack, release, head = (fact.get(k) for k in ("stack", "release", "head"))
            if (
                isinstance(stack, str)
                and isinstance(release, str)
                and isinstance(head, str)
            ):
                found[(stack, release)] = head
    return found


def _not_started(cause: str, command: str) -> CheckResult:
    """A check that failed before any removal: nothing is touched."""
    return CheckResult(False, data={"not_started": cause, "command": command})


def _copies_gone(release: Path, mounts: Sequence[Path]) -> list[Path]:
    """The copies ``<kind>@<digest>`` in ``release`` (a directory of one
    release of the product) that no container mounts and that are not the
    newest of their kind by mtime."""
    kinds: dict[str, list[Path]] = {}
    for path in sorted(release.iterdir()):
        if path.is_dir() and not path.is_symlink() and not path.name.endswith(_TEMP):
            kinds.setdefault(path.name.rpartition("@")[0], []).append(path)
    gone: list[Path] = []
    for copies in kinds.values():
        copies.sort(key=lambda p: (-p.stat().st_mtime, p.name))
        gone += [
            p
            for p in copies[1:]
            if not any(m.is_relative_to(p) or p.is_relative_to(m) for m in mounts)
        ]
    return gone


class Gc(Step):
    """Remove what the box no longer needs, by labels, and measure it."""

    name = "gc"
    order = 1
    modes = GC_MODES
    codes: ClassVar[dict[str, str]] = {
        **NO_PASSPORT,
        "clean": (
            "remove {images} images and the releases {releases}; prune the build "
            "cache: {build_cache}; evict journals: {journals}"
        ),
        "not-removed": "gc removed {objects} and they are still there",
        "not-started": "gc removed nothing: {cause} {command}",
        "volumes-changed": (
            "volumes went from {before} to {after}; gc never touches a volume"
        ),
        "over-budget": (
            "over budget: {over}; build cache {builder_cache_bytes} of "
            "{builder_cache_budget} bytes, journal/ {journal_bytes} of "
            "{journal_budget} bytes, releases {releases} with keep_releases "
            "{keep_releases}"
        ),
    }

    def __init__(
        self,
        *,
        box: Box,
        run_id: str,
        fetched: Fetched,
        root: Path = Path("/"),
    ) -> None:
        self.box = box
        self.run_id = run_id
        self.fetched = fetched
        self.root = root

    # --- the policy -------------------------------------------------------------

    def _passport(self) -> Passport:
        passport: Passport | None = self.fetched.passport
        if passport is None:
            copy = self.root / PASSPORT_COPY
            if not copy.is_file():
                raise StepFailed("no-passport")
            passport = load_passport(copy)
        return passport

    def _policy(self) -> GcPolicy:
        return self._passport().policies.gc

    # --- what the box holds -------------------------------------------------------

    def _stacks(self) -> list[str]:
        """The stacks with the machine's mark and releases (DM-76): another
        ``/opt/<x>/releases`` is not the machine's to collect."""
        mine, _ = marked(self.root)
        return sorted(home.name for home in mine if (home / "releases").is_dir())

    def _releases_dir(self, stack: str) -> Path:
        return self.root / "opt" / stack / "releases"

    def _head(self, ctx: StepContext, release: Path) -> str:
        _, lines = run_git(ctx, self.root, ["-C", str(release), "rev-parse", "HEAD"])
        return lines[0].strip()

    def _known(self, ctx: StepContext, stacks: Sequence[str]) -> _Known:
        current: dict[str, Path] = {}
        commits: set[str] = set()
        for stack in stacks:
            link = self.root / "opt" / stack / "current"
            if link.is_symlink():
                target = Path(os.readlink(link))
                current[stack] = target
                if (target / ".git").exists():
                    commits.add(self._head(ctx, target))
        previous: dict[str, str] = {}
        names: set[str] = set()
        made: set[str] = set()  # stacks whose current release's verdict is read
        damaged = 0
        for run_id in reversed(self.box.history_ids()):
            if not set(current) - set(previous) and set(current) <= made:
                break
            try:
                verdict = self.box.read_verdict(run_id)
            except VerdictDamaged:
                damaged += 1
                continue
            finalized = _finalized(verdict) if verdict.result == "green" else None
            if finalized is None:
                continue
            heads = _heads(verdict)
            for stack in sorted(set(current) - made):
                if finalized.get(stack) == current[stack].name:
                    made.add(stack)  # the packages of the current release
                    names.update(verdict.composition_after.values())
            for stack in sorted(set(current) - set(previous)):
                release = finalized.get(stack)
                if release is None or release == current[stack].name:
                    continue
                previous[stack] = release
                names.update(verdict.composition_after.values())
                head = heads.get((stack, release))
                path = self._releases_dir(stack) / release
                if head is None and (path / ".git").exists():
                    head = self._head(ctx, path)
                if head is not None:
                    commits.add(head)
        return _Known(current, previous, commits, names, damaged)

    def _releases(self, ctx: StepContext, stack: str) -> list[_Release]:
        found: list[_Release] = []
        directory = self._releases_dir(stack)
        packages = (self.root / "opt" / stack / "packages").resolve()
        for path in sorted(directory.iterdir()):
            if not path.is_dir() or path.name.endswith(_TEMP) or path.name[0] == ".":
                continue
            _, lines = run_git(
                ctx,
                self.root,
                [
                    "-C",
                    str(path),
                    "rev-parse",
                    "--path-format=absolute",
                    "--git-common-dir",
                ],
            )
            bare = Path(lines[0].strip())
            found.append(_Release(stack, path, bare, bare.resolve().parent == packages))
        return found

    # --- the step -----------------------------------------------------------------

    def check(self, ctx: StepContext) -> CheckResult:
        """What to remove; a measurement that fails before anything is removed
        is ``not-started`` in ``verify`` (exit 2), never red."""
        try:
            return self._check(ctx)
        except StepFailed as failed:
            if failed.reason.code != "no-passport":
                raise
            return _not_started("no-passport", "")
        except (CommandFailed, CommandNotStarted, CommandTimedOut) as error:
            cause = {
                CommandFailed: "command-failed",
                CommandNotStarted: "command-not-started",
                CommandTimedOut: "command-timed-out",
            }[type(error)]
            return _not_started(cause, " ".join(error.argv[:3]))
        except ContractError:
            return _not_started("passport-invalid", str(self.root / PASSPORT_COPY))
        except (UnreadableOutput, json.JSONDecodeError) as error:
            # what docker printed, not a fault of the machine: that one is red
            return _not_started("unreadable", type(error).__name__)
        except (OSError, IndexError) as error:
            # a release the measurement cannot read (gone under it, git printed
            # nothing): nothing is removed yet -- not-started, not a crash (DM-77)
            return _not_started("unreadable", type(error).__name__)

    def _check(self, ctx: StepContext) -> CheckResult:
        passport = self._passport()
        policy = passport.policies.gc
        packages = {
            package_dir(self.root, stack, package)
            for stack in self._stacks()
            for package in passport.packages.values()
        }
        df = system_df(ctx)
        stacks = self._stacks()
        known = self._known(ctx, stacks)
        containers = _inspect(
            ctx,
            "container",
            _lines(
                ctx, ["docker", "container", "ls", "--all", "--quiet", "--no-trunc"]
            ),
        )
        in_use = {str(c.get("Image")) for c in containers}
        mounts = [
            Path(str(m.get("Source")))
            for c in containers
            for m in _dicts(c.get("Mounts"))
            if m.get("Source")
        ]
        images: list[Json] = []
        for image in _inspect(ctx, "image", labelled_images(ctx)):
            config = image.get("Config")
            labels = config.get("Labels") if isinstance(config, dict) else None
            commit = labels.get("pridem.commit") if isinstance(labels, dict) else None
            ident = str(image.get("Id"))
            # KNOWN CEILING (DM-61): the images of one commit are kept whole.
            # 1. Mechanism: a service a package is built into (apply: build) has
            #    an image per edition and package versions on one commit
            #    (steps.packages.image_key); a new skin version on the same
            #    commit leaves the image of the old one, kept here by its
            #    commit until the commit is neither current nor previous.
            # 2. Status: acknowledged by design.
            # 3. Task: none -- no box changes package versions often enough on
            #    one commit to fill a disk before its next release.
            # 4. Trigger: the images of one commit and one service outnumber
            #    policies.gc.keep_releases + 1 (docker image ls by the labels
            #    pridem.commit and pridem.service).
            # 5. Agreed fix: of the current and the previous commit, remove an
            #    image whose key (pridem.edition, pridem.package.*) is not the
            #    current passport's and that no container uses.
            # 6. Rejected: removing by "no container uses it" alone removes the
            #    previous release's image, which gc never removes (passport
            #    rule 16); keying images by commit alone mixes the editions.
            if commit in known.commits or ident in in_use:
                continue
            images.append(
                {"id": ident, "tags": list[Json](_strings(image.get("RepoTags")))}
            )
        removed: list[Json] = []
        kept: dict[str, Json] = {}
        copies: list[Json] = [
            str(path)
            for stack in stacks
            for path in self._data_gone(stack, policy, known, mounts)
        ]
        for stack in stacks:
            held = [*mounts, *packages]  # mounted, or a package of the passport
            gone, stay = self._choose(ctx, stack, policy, known, held)
            removed += [
                {"stack": stack, "path": str(r.path), "bare": str(r.bare)} for r in gone
            ]
            kept[stack] = list[Json](stay)
        cache = _number(df, "build_cache", "bytes")
        prune = cache > size_bytes(policy.builder_cache_budget)
        journal = self._journal_bytes()
        evict = journal > size_bytes(policy.journal_budget)
        data: dict[str, Json] = {
            "before": {**df, "journal": {"bytes": journal}},
            "images": images,
            "releases": removed,
            "data": copies,
            "prune": prune,
            "evict": evict,
            "kept_releases": kept,
            "kept_commits": list[Json](sorted(known.commits)),
            "in_use": list[Json](sorted(_short(i) for i in in_use)),
            "history_damaged": known.damaged,
        }
        if not (images or removed or copies or prune or evict):
            return CheckResult(False, data=data)
        names: list[Json] = [
            f"{r['stack']}/{Path(str(r['path'])).name}" for r in _dicts(removed)
        ]
        names += [str(Path(str(p)).relative_to(self.root / "opt")) for p in copies]
        would = local_code(
            "clean",
            {
                "images": len(images),
                "releases": names,
                "build_cache": prune,
                "journals": evict,
            },
        )
        return CheckResult(True, would, data)

    def _choose(
        self,
        ctx: StepContext,
        stack: str,
        policy: GcPolicy,
        known: _Known,
        mounts: Sequence[Path],
    ) -> tuple[list[_Release], list[str]]:
        """The releases of ``stack`` to remove, and the names that stay."""

        def mounted(path: Path) -> bool:
            return any(m.is_relative_to(path) or path.is_relative_to(m) for m in mounts)

        current = known.current.get(stack)
        previous = known.previous.get(stack)
        gone: list[_Release] = []
        stay: list[_Release] = []
        others: list[_Release] = []
        for release in self._releases(ctx, stack):
            if release.package:
                if mounted(release.path) or release.path.name in known.names:
                    continue  # a package directory is not a release of the stack
                gone.append(release)
            elif release.path == current or mounted(release.path):
                stay.append(release)
            else:
                others.append(release)
        # the previous first, then the newest; the current and mounted ones hold
        # their slots whatever the number
        others.sort(
            key=lambda r: (
                r.path.name != previous,
                -r.path.stat().st_mtime,
                r.path.name,
            )
        )
        room = max(policy.keep_releases - len(stay), 0)
        stay += others[:room]
        gone += others[room:]
        names = sorted(r.path.name for r in stay)
        return gone, names

    def _data_gone(
        self, stack: str, policy: GcPolicy, known: _Known, mounts: Sequence[Path]
    ) -> list[Path]:
        """The copies of the product's data under ``/opt/<stack>/data`` to
        remove: a release's directory neither mounted nor of the product's
        current or previous release, beyond the newest ``keep_releases``; in
        a directory that stays, a copy of a kind neither mounted nor the
        newest of its kind."""
        home = self.root / "opt" / stack / "data"
        if not home.is_dir():
            return []
        stay: list[Path] = []
        others: list[Path] = []
        for path in sorted(home.iterdir()):
            if not path.is_dir() or path.name.endswith(_TEMP):
                continue
            product, _, release = path.name.rpartition("@")
            current = known.current.get(product)
            held = release in {
                None if current is None else current.name,
                known.previous.get(product),
            }
            mounted = any(m.is_relative_to(path) for m in mounts)
            (stay if held or mounted else others).append(path)
        others.sort(key=lambda p: (-p.stat().st_mtime, p.name))
        room = max(policy.keep_releases - len(stay), 0)
        return [*others[room:], *(c for p in stay for c in _copies_gone(p, mounts))]

    def _journal_files(self) -> list[Path]:
        return [
            *self.box.journals.glob("*.jsonl"),
            *self.box.journals.glob("*.jsonl.damaged"),
        ]

    def _journal_bytes(self) -> int:
        return sum(path.stat().st_size for path in self._journal_files())

    def act(self, ctx: StepContext, check: CheckResult) -> None:
        policy = self._policy()
        for image in _dicts(check.data.get("images")):
            tags = _strings(image.get("tags"))
            out(ctx, ["docker", "image", "rm", *(tags or [str(image["id"])])])
        bares: set[str] = set()
        for release in _dicts(check.data.get("releases")):
            bare = str(release["bare"])
            run_git(
                ctx,
                self.root,
                ["-C", bare, "worktree", "remove", "--force", str(release["path"])],
            )
            bares.add(bare)
        for bare in sorted(bares):
            run_git(ctx, self.root, ["-C", bare, "worktree", "prune"])
        for copy in _strings(check.data.get("data")):
            shutil.rmtree(copy)
        if check.data.get("prune"):
            out(
                ctx,
                [
                    "docker",
                    "builder",
                    "prune",
                    "--force",
                    "--all",
                    "--keep-storage",
                    str(size_bytes(policy.builder_cache_budget)),
                ],
                timeout=PRUNE_TIMEOUT_S,
            )
        if check.data.get("evict"):
            self.box.evict_journals(size_bytes(policy.journal_budget), self.run_id)

    def verify(self, ctx: StepContext, check: CheckResult) -> Verified:
        data = check.data
        cause = data.get("not_started")
        if isinstance(cause, str):
            command = str(data.get("command") or "")
            return Verified(
                {"gc": "not-started", "cause": cause, "command": command},
                incomplete=local_code(
                    "not-started", {"cause": cause, "command": command}
                ),
            )
        policy = self._policy()
        before = data.get("before")
        if not isinstance(before, dict):
            raise ValueError("gc verify needs the measurement of its check")
        after = system_df(ctx)
        journal = self._journal_bytes()
        cache_budget = size_bytes(policy.builder_cache_budget)
        journal_budget = size_bytes(policy.journal_budget)
        images = _dicts(data.get("images"))
        releases = _dicts(data.get("releases"))
        listed = set(labelled_images(ctx)) if images else set()
        fact: Fact = {
            "before": before,
            "after": {**after, "journal": {"bytes": journal}},
            "removed": {
                "images": [_short(str(i["id"])) for i in images],
                "releases": [
                    *(str(r["path"]) for r in releases),
                    *_strings(data.get("data")),
                ],
            },
            "kept": {
                "commits": data.get("kept_commits"),
                "in_use": data.get("in_use"),
                "releases": data.get("kept_releases"),
            },
            "budget": {
                "builder_cache": cache_budget,
                "journal": journal_budget,
                "keep_releases": policy.keep_releases,
            },
        }
        volumes = (
            _number(before, "volumes", "count"),
            _number(after, "volumes", "count"),
        )
        if volumes[1] < volumes[0]:
            raise StepFailed(
                "volumes-changed", {"before": volumes[0], "after": volumes[1]}, fact
            )
        still: list[str] = [_short(str(i["id"])) for i in images if i["id"] in listed]
        still += [str(r["path"]) for r in releases if Path(str(r["path"])).exists()]
        still += [p for p in _strings(data.get("data")) if Path(p).exists()]
        cache = (
            _number(before, "build_cache", "bytes"),
            _number(after, "build_cache", "bytes"),
        )
        if data.get("prune") and cache[1] >= cache[0]:
            still.append("build-cache")
        current = f"{self.run_id}.jsonl"
        if (
            data.get("evict")
            and journal > journal_budget
            and any(path.name != current for path in self._journal_files())
        ):
            still.append("journals")
        if still:
            raise StepFailed("not-removed", {"objects": list[Json](still)}, fact)
        over: list[str] = []
        if cache[1] > cache_budget:
            over.append("build-cache")
        if journal > journal_budget:
            over.append("journal")
        crowded: list[str] = []
        kept = data.get("kept_releases")
        for stack, names in kept.items() if isinstance(kept, dict) else []:
            if isinstance(names, list) and len(names) > policy.keep_releases:
                crowded.append(f"{stack}:{len(names)}")
        if crowded:
            over.append("releases")
        if not over:
            return Verified(fact)
        return Verified(
            fact,
            incomplete=local_code(
                "over-budget",
                {
                    "over": list[Json](over),
                    "builder_cache_bytes": cache[1],
                    "builder_cache_budget": cache_budget,
                    "journal_bytes": journal,
                    "journal_budget": journal_budget,
                    "releases": list[Json](crowded),
                    "keep_releases": policy.keep_releases,
                },
            ),
        )


def gc_steps(root: Path, *, box: Box, run_id: str, fetched: Fetched) -> list[Step]:
    """The ``gc`` a plan builder puts in ``finally`` of every plan, as stack
    ``GC_STACK``; the verb ``gc`` runs the same step as its whole plan."""
    return [Gc(box=box, run_id=run_id, fetched=fetched, root=root)]
