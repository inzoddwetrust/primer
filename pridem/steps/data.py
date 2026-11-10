"""The steps of the data verbs (DM-86, TZ 9.1, 12): ``db_dump``, and for
``db restore`` -- ``stop_for_restore``, ``db_restore``, ``start_restored``.

The database of an entry is the one ``DATABASE_URL`` of its app names in
``config`` (``steps/tests.py``: its host is the compose service, its user and
name are the live database's): the stack of the blank (TZ 2), Postgres.

``db_dump`` dumps it with ``pg_dump -Fc`` inside the database's container,
takes the file out with ``compose cp`` -- a dump is binary, and the runner
decodes and cuts lines -- and removes it from the container. The file goes to
``/opt/pridem/backups/<run_id>/<entry>.dump`` (0600, the directory 0700):
under ``/opt/pridem``, which ``destroy`` and ``reinstall`` leave, not under
``/opt/<stack>``, which they remove -- the move of a box (DM-87) stands on it.
It is written under ``<entry>.dump.partial`` and named only once its table of
contents is read back non-empty; the manifest ``<entry>.json`` -- ``stack,
entry, release, commit, alembic_head, bytes, sha256, toc`` (TZ 12) -- is
written last: a dump without a manifest is no dump. ``verify`` reads the file
and the manifest back: the same sha256 and size.

``db restore`` stops every service of the entry but the database
(``stop_for_restore``: the app's connections would hold ``--clean``), restores
with ``pg_restore --clean --if-exists --no-owner`` -- the point of no return
-- reads ``alembic current`` back against the manifest's head, and starts
again what it stopped (``start_restored``: the same containers on the same
release). A red step before ``db_restore`` acted -- ``start_stopped`` of
``finally`` starts them; once it acted, they stay stopped (the KNOWN CEILING
of ``StartStopped``, ``steps/migrate.py``).

KNOWN CEILING (DM-86, the keeping of dumps):
1. mechanics: ``/opt/pridem/backups/`` grows by a directory per ``backup`` and
   ``db dump``; nothing removes them -- not ``gc``, not ``destroy``;
2. status: acknowledged by design;
3. task: none -- the store of backups is phase 5 (TZ 12), no card yet;
4. trigger: phase 5 begins (the object store), or a box's disk is short by
   ``backups/`` (``gc``'s measure of the box names its size);
5. agreed form of the fix: a policy of the passport for keeping and the
   object store, by TZ 12;
6. rejected: ``gc`` removing old dumps by count -- the dump a move needs could
   be the one removed.
"""

import hashlib
import json
from collections.abc import Sequence
from pathlib import Path
from typing import ClassVar

from pridem.events import Json
from pridem.stacks.env import write_private
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
from pridem.steps.compose import COMMAND_TIMEOUT_S, ComposeStack, config, current, out
from pridem.steps.migrate import ALEMBIC, STOP_TIMEOUT_S, Stopped, running
from pridem.steps.tests import Database, database

COMMAND: frozenset[Mode] = frozenset({"command"})
BACKUPS = "backups"
DUMP_TIMEOUT_S = 3600
"""``pg_dump`` and ``pg_restore`` of a stack's database: an hour."""


def backups_dir(box_root: Path, run_id: str) -> Path:
    """``/opt/pridem/backups/<run_id>``."""
    return box_root / BACKUPS / run_id


def sha256_of(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def _found(
    ctx: StepContext, compose: ComposeStack
) -> tuple[Database, str, dict[str, Json]]:
    """The entry's database, the image of its service and ``config``."""
    app = compose.app_service
    if app is None:
        raise StepFailed("no-app", {"stack": compose.entry})
    document = config(ctx, compose)
    found = database(document, app)
    services = document.get("services")
    body = services.get(found.service) if isinstance(services, dict) else None
    image = body.get("image") if isinstance(body, dict) else None
    if not isinstance(image, str) or not image:
        raise StepFailed("no-database-image", {"service": found.service})
    return found, image, document


def _head(ctx: StepContext, compose: ComposeStack) -> str | None:
    """``alembic current`` of an entry that migrates; ``None`` -- it does not."""
    stage = compose.stack.stacks[compose.entry]
    if stage.migrate is None or compose.app_service is None:
        return None
    _, lines = out(
        ctx,
        compose.argv("run", "--rm", compose.app_service, *ALEMBIC, "current"),
        timeout=COMMAND_TIMEOUT_S,
    )
    heads = current(lines)
    return heads[0] if len(heads) == 1 else None


def _toc(ctx: StepContext, path: Path, image: str) -> int:
    """Entries of the dump's table of contents, by ``pg_restore --list`` of the
    database's image in a throwaway container -- no network, no capability, no
    pull; the file mounted read-only."""
    _, lines = out(
        ctx,
        [
            "docker",
            "run",
            "--rm",
            *NO_NETWORK,
            *THROWAWAY,
            *NO_PULL,
            "-v",
            f"{path}:/primer/db.dump:ro",
            image,
            "pg_restore",
            "--list",
            "/primer/db.dump",
        ],
        timeout=COMMAND_TIMEOUT_S,
    )
    return sum(1 for line in lines if line.strip() and not line.startswith(";"))


def read_manifest(path: Path) -> dict[str, Json] | None:
    """``<entry>.json`` beside a dump; ``None`` -- none, or not a mapping."""
    try:
        found = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return None
    return found if isinstance(found, dict) else None


class DbDump(Step):
    """The database of one entry, dumped to ``backups/<run_id>/<entry>.dump``."""

    name = "db_dump"
    order = 1
    modes = COMMAND
    codes: ClassVar[dict[str, str]] = {
        "dump": "dump the database of {stack}",
        "no-app": "{stack} has no app to take the database from",
        "no-database-url": "{service} has no DATABASE_URL to take the database from",
        "test-db-is-live": "the database {live} cannot be told from its test one",
        "no-database-image": "the database service {service} names no image",
        "database-down": "the database {service} of {stack} is not running",
        "dump-empty": "the dump of {stack} has no table of contents",
        "dump-drift": "the dump of {stack} at {path} is not what was written",
    }

    def __init__(self, compose: ComposeStack, *, directory: Path, run_id: str) -> None:
        self.compose = compose
        self.directory = directory
        self.run_id = run_id

    @property
    def path(self) -> Path:
        return self.directory / f"{self.compose.entry}.dump"

    @property
    def manifest(self) -> Path:
        return self.directory / f"{self.compose.entry}.json"

    def check(self, ctx: StepContext) -> CheckResult:
        found, image, _ = _found(ctx, self.compose)
        if not running(ctx, self.compose, [found.service]):
            raise StepFailed(
                "database-down", {"stack": self.compose.entry, "service": found.service}
            )
        data: dict[str, Json] = {
            "service": found.service,
            "user": found.user,
            "live": found.live,
            "image": image,
        }
        params: dict[str, Json] = {"stack": self.compose.entry}
        return CheckResult(True, local_code("dump", params), data)

    def act(self, ctx: StepContext, check: CheckResult) -> None:
        service, user, live, image = (
            str(check.data[k]) for k in ("service", "user", "live", "image")
        )
        # a path inside the database's container, not on the box
        inside = f"/tmp/pridem-{self.run_id}-{self.compose.entry}.dump"  # noqa: S108
        partial = self.directory / f"{self.compose.entry}.dump.partial"
        for place in (self.directory.parent, self.directory):
            place.mkdir(exist_ok=True, mode=0o700)
            place.chmod(0o700)
        exec_ = ("exec", "-T", service)
        out(
            ctx,
            self.compose.argv(*exec_, "pg_dump", "-U", user, "-Fc", "-f", inside, live),
            timeout=DUMP_TIMEOUT_S,
        )
        out(
            ctx,
            self.compose.argv("cp", f"{service}:{inside}", str(partial)),
            timeout=DUMP_TIMEOUT_S,
        )
        out(
            ctx,
            self.compose.argv(*exec_, "rm", "-f", inside),
            timeout=COMMAND_TIMEOUT_S,
        )
        partial.chmod(0o600)
        toc = _toc(ctx, partial, image)
        if toc == 0:
            raise StepFailed("dump-empty", {"stack": self.compose.entry})
        head = _head(ctx, self.compose)
        manifest: dict[str, Json] = {
            "stack": self.compose.stack.name,
            "entry": self.compose.entry,
            "release": self.compose.ref,
            "commit": self.compose.commit,
            "bytes": partial.stat().st_size,
            "sha256": sha256_of(partial),
            "toc": toc,
        }
        if head is not None:
            manifest["alembic_head"] = head
        partial.replace(self.path)
        write_private(self.manifest, json.dumps(manifest, indent=2) + "\n")

    def verify(self, ctx: StepContext, check: CheckResult) -> Verified:
        manifest = read_manifest(self.manifest)
        path = str(self.path)
        if manifest is None or not self.path.is_file():
            raise StepFailed("dump-drift", {"stack": self.compose.entry, "path": path})
        size, digest = self.path.stat().st_size, sha256_of(self.path)
        if manifest.get("sha256") != digest:  # the same digest, the same size
            raise StepFailed("dump-drift", {"stack": self.compose.entry, "path": path})
        fact: dict[str, Json] = {
            "stack": self.compose.entry,
            "path": path,
            "bytes": size,
            "sha256": digest,
            "toc": manifest.get("toc"),
        }
        if "alembic_head" in manifest:
            fact["alembic_head"] = manifest["alembic_head"]
        return Verified(fact)


class DbRestore(Step):
    """A dump of ``db_dump`` into the entry's database -- the point of no
    return of ``db restore``."""

    name = "db_restore"
    order = 2
    modes = COMMAND
    point_of_no_return = True
    codes: ClassVar[dict[str, str]] = {
        **{k: v for k, v in DbDump.codes.items() if k != "dump"},
        "restore": "restore {path} into the database of {stack}",
        "head-mismatch": "the database of {stack} is at {current}, the dump at {head}",
    }

    def __init__(
        self, compose: ComposeStack, *, path: Path, manifest: dict[str, Json]
    ) -> None:
        self.compose = compose
        self.path = path
        self.manifest = manifest
        self.acted = False
        """``act`` began: what ``stop_for_restore`` stopped stays stopped."""

    def check(self, ctx: StepContext) -> CheckResult:
        """The file is what its manifest says, before anything is written."""
        drift = {"stack": self.compose.entry, "path": str(self.path)}
        if not self.path.is_file():
            raise StepFailed("dump-drift", drift)
        if self.manifest.get("sha256") != sha256_of(self.path):
            raise StepFailed("dump-drift", drift)
        found, _, _ = _found(ctx, self.compose)
        data: dict[str, Json] = {
            "service": found.service,
            "user": found.user,
            "live": found.live,
        }
        return CheckResult(True, local_code("restore", drift), data)

    def act(self, ctx: StepContext, check: CheckResult) -> None:
        self.acted = True
        service, user, live = (str(check.data[k]) for k in ("service", "user", "live"))
        # a path inside the database's container, not on the box
        inside = f"/tmp/pridem-restore-{self.compose.entry}.dump"  # noqa: S108
        exec_ = ("exec", "-T", service)
        out(
            ctx,
            self.compose.argv("cp", str(self.path), f"{service}:{inside}"),
            timeout=DUMP_TIMEOUT_S,
        )
        restore = ("pg_restore", "--clean", "--if-exists", "--no-owner")
        out(
            ctx,
            self.compose.argv(*exec_, *restore, "-U", user, "-d", live, inside),
            timeout=DUMP_TIMEOUT_S,
        )
        out(
            ctx,
            self.compose.argv(*exec_, "rm", "-f", inside),
            timeout=COMMAND_TIMEOUT_S,
        )

    def verify(self, ctx: StepContext, check: CheckResult) -> Verified:
        fact: dict[str, Json] = {"stack": self.compose.entry, "path": str(self.path)}
        head = self.manifest.get("alembic_head")
        if isinstance(head, str):
            now = _head(ctx, self.compose)
            if now != head:
                params: dict[str, Json] = {
                    "stack": self.compose.entry,
                    "head": head,
                    "current": now or "none",
                }
                raise StepFailed("head-mismatch", params)
            fact["alembic_head"] = head
        return Verified(fact)


class StopForRestore(Step):
    """Every service of the entry but its database, stopped before
    ``db_restore``: the app's connections would hold ``--clean``."""

    name = "stop_for_restore"
    order = 1
    modes = COMMAND
    rechecked = False  # ``start_restored`` brings them back by design
    codes: ClassVar[dict[str, str]] = {
        **{k: v for k, v in DbDump.codes.items() if k != "dump"},
        "stop": "stop {services} of {stack} for its restore",
        "stop-failed": "{services} of {stack} still run after stop",
    }

    def __init__(self, restore: DbRestore, stopped: Stopped) -> None:
        self.restore = restore
        self.compose = restore.compose
        self.stopped = stopped
        self.services: list[str] = []

    def check(self, ctx: StepContext) -> CheckResult:
        found, _, document = _found(ctx, self.compose)
        services = document.get("services")
        names = sorted(services) if isinstance(services, dict) else []
        self.services = [name for name in names if name != found.service]
        live = running(ctx, self.compose, self.services)
        if not live:
            return CheckResult(False, None, {})
        params: dict[str, Json] = {
            "stack": self.compose.entry,
            "services": list[Json](live),
        }
        return CheckResult(True, local_code("stop", params), {"stop": list[Json](live)})

    def act(self, ctx: StepContext, check: CheckResult) -> None:
        stop = [str(name) for name in _list(check.data.get("stop"))]
        self.stopped.entries.append((self.compose, stop, self.restore))
        out(ctx, self.compose.argv("stop", *stop), timeout=STOP_TIMEOUT_S)

    def verify(self, ctx: StepContext, check: CheckResult) -> Verified:
        stop = [str(name) for name in _list(check.data.get("stop"))]
        still = running(ctx, self.compose, stop)
        if still:
            params: dict[str, Json] = {
                "stack": self.compose.entry,
                "services": list[Json](still),
            }
            raise StepFailed("stop-failed", params)
        return Verified({"stack": self.compose.entry, "stopped": list[Json](stop)})


class StartRestored(Step):
    """What ``stop_for_restore`` stopped, started again after a green
    ``db_restore``: the same containers, on the same release."""

    name = "start_restored"
    order = 3
    modes = COMMAND
    codes: ClassVar[dict[str, str]] = {
        "start": "start {services} of {stack} on the restored database",
        "start-failed": "{services} of {stack} do not run after start",
    }

    def __init__(self, compose: ComposeStack, stopped: Stopped) -> None:
        self.compose = compose
        self.stopped = stopped

    def _mine(self) -> list[str]:
        return [
            name
            for compose, services, _ in self.stopped.entries
            if compose.entry == self.compose.entry
            for name in services
        ]

    def check(self, ctx: StepContext) -> CheckResult:
        mine = self._mine()
        if not mine:
            return CheckResult(False, None, {})
        params: dict[str, Json] = {
            "stack": self.compose.entry,
            "services": list[Json](mine),
        }
        return CheckResult(True, local_code("start", params), {})

    def act(self, ctx: StepContext, check: CheckResult) -> None:
        out(ctx, self.compose.argv("start", *self._mine()), timeout=STOP_TIMEOUT_S)

    def verify(self, ctx: StepContext, check: CheckResult) -> Verified:
        mine = self._mine()
        down = sorted(set(mine) - set(running(ctx, self.compose, mine)))
        if down:
            params: dict[str, Json] = {
                "stack": self.compose.entry,
                "services": list[Json](down),
            }
            raise StepFailed("start-failed", params)
        return Verified({"stack": self.compose.entry, "started": list[Json](mine)})


def _list(value: Json) -> Sequence[Json]:
    return value if isinstance(value, list) else []


class BackupScope(Step):
    """What ``backup`` covers: the entries dumped and those without a
    database -- or, with ``policies.backup.enabled: false``, that nothing is
    (the verdict says why)."""

    name = "backup_scope"
    order = 1
    modes = COMMAND

    def __init__(self, fact: dict[str, Json]) -> None:
        self.fact = fact

    def check(self, ctx: StepContext) -> CheckResult:
        return CheckResult(False, None, {})

    def act(self, ctx: StepContext, check: CheckResult) -> None:
        raise AssertionError("backup_scope never acts")

    def verify(self, ctx: StepContext, check: CheckResult) -> Verified:
        return Verified(dict(self.fact))
