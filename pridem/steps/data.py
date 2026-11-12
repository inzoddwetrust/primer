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
import re
import shlex
from collections.abc import Sequence
from pathlib import Path
from typing import ClassVar, Protocol

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
from pridem.steps.compose import (
    COMMAND_TIMEOUT_S,
    ComposeStack,
    config,
    current,
    heads,
    mount_flag,
    out,
)
from pridem.steps.migrate import (
    ALEMBIC,
    IMAGE_CODES,
    MIGRATE_VERB_CODES,
    STOP_TIMEOUT_S,
    Acting,
    Stopped,
    running,
    unknown_head,
)
from pridem.steps.tests import Database, database

COMMAND: frozenset[Mode] = frozenset({"command"})
BACKUPS = "backups"
DUMP_TIMEOUT_S = 3600
"""``pg_dump`` and ``pg_restore`` of a stack's database: an hour."""


class Wiping(Acting, Protocol):
    """A step that writes over the entry's database: ``db_restore``,
    ``db_reset`` -- what ``stop_for_restore`` stops for, after its ``check``:
    a refusal of the step stops nothing (DM-86, pass 2)."""

    compose: ComposeStack

    def check(self, ctx: StepContext) -> CheckResult: ...


RESET_CODES: dict[str, str] = {
    "reset": "drop and make again the database of {stack}",
    "no-migrate": "{stack} has no migrate to bring the schema back",
    "database-name": "the database name {name} of {stack} is not a plain name",
    "not-reset": "the database of {stack} is the same one after the reset",
    "head-mismatch": "the database of {stack} is at {current}, the release at {head}",
}


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
            *mount_flag(path, "/primer/db.dump"),  # a run_id holds colons
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
            "commit": release_commit(ctx, self.compose),  # a service's: not its tag
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
    ``db_restore`` or ``db_reset``: the app's connections would hold
    ``--clean`` and ``DROP DATABASE``."""

    name = "stop_for_restore"
    order = 1
    modes = COMMAND
    rechecked = False  # ``start_restored`` brings them back by design
    codes: ClassVar[dict[str, str]] = {
        **{k: v for k, v in DbDump.codes.items() if k != "dump"},
        # what db_restore's and db_reset's checks refuse with, run here first
        **IMAGE_CODES,
        **RESET_CODES,
        "stop": "stop {services} of {stack} for its restore",
        "stop-failed": "{services} of {stack} still run after stop",
    }

    def __init__(self, restore: "Wiping", stopped: Stopped) -> None:
        self.restore = restore
        self.compose = restore.compose
        self.stopped = stopped
        self.services: list[str] = []

    def check(self, ctx: StepContext) -> CheckResult:
        self.restore.check(ctx)  # its refusal before anything is stopped
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
    """What ``stop_for_restore`` or ``stop_for_migrate`` stopped, started again
    after a green ``db_restore``, ``db_reset`` or ``db_migrate``: the same
    containers, on the same release -- ``compose start`` reads no override for
    their configuration."""

    name = "start_restored"
    order = 3
    modes = COMMAND
    codes: ClassVar[dict[str, str]] = {
        "start": "start {services} of {stack} again on its database",
        "start-failed": "{services} of {stack} do not run after start",
    }

    def __init__(
        self, compose: ComposeStack, stopped: Stopped, *, order: int = 3
    ) -> None:
        self.compose = compose
        self.stopped = stopped
        self.order = order  # after db_migrate (12) in db migrate's ladder

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


# --- pass 2: the image of a one-off container, db reset, db migrate, seeds -----------

SEED_TIMEOUT_S = 1800
_PG_NAME = re.compile(r"[A-Za-z0-9_]+")


def release_commit(ctx: StepContext, compose: ComposeStack) -> str:
    """The commit of the release ``current`` names: its worktree's ``HEAD`` --
    a service's release is named by its tag, not its commit (DM-86)."""
    _, lines = out(
        ctx,
        ["git", "-C", str(compose.release), "rev-parse", "HEAD"],
        timeout=COMMAND_TIMEOUT_S,
        passed_on=False,
    )
    found = [line.strip() for line in lines if line.strip()]
    return found[0] if found else ""


def run_image(document: dict[str, Json], compose: ComposeStack, service: str) -> str:
    """The image ``compose run <service>`` starts. Of a built service, the
    name the machine's override of the release gives it -- the override wins
    the merge, and its ``image`` is ``steps.compose.release_image``'s (DM-90);
    of any other, the one the product's ``config`` (``document``) names."""
    for found in (_override_services(compose), document.get("services")):
        body = found.get(service) if isinstance(found, dict) else None
        image = body.get("image") if isinstance(body, dict) else None
        if isinstance(image, str) and image:
            return image
    raise StepFailed("image-unread", {"stack": compose.entry, "image": service})


def _override_services(compose: ComposeStack) -> Json:
    """``services`` of the override ``compose`` reads (its JSON text)."""
    if not compose.override.is_file():
        return None
    document: Json = json.loads(compose.override.read_text(encoding="utf-8"))
    return document.get("services") if isinstance(document, dict) else None


def image_is_current(
    ctx: StepContext, compose: ComposeStack, document: dict[str, Json]
) -> str:
    """Outside a deploy, ``compose run --rm <app>`` takes the image by its name:
    the release's own since DM-90 (``steps.compose.release_image``), which a
    deploy of a new commit no longer takes over. A name is still a name --
    any ``docker tag`` or ``compose build`` outside the machine moves it --
    and a migration or a seed of other code on the release's database is what
    this refuses: the image's ``pridem.commit``, the fact, against the current
    release's commit -- red before anything is stopped (DM-86). A name with no
    image under it is ``image-unread``. Returns the commit."""
    app = compose.app_service
    if app is None:
        raise StepFailed("no-app", {"stack": compose.entry})
    image = run_image(document, compose, app)
    label = '{{index .Config.Labels "pridem.commit"}}'
    _, lines = out(
        ctx,
        ["docker", "image", "inspect", "-f", label, image],
        timeout=COMMAND_TIMEOUT_S,
        passed_on=False,
    )
    seen = next((line.strip() for line in lines if line.strip()), "")
    if not seen or seen == "<no value>":
        raise StepFailed("image-unread", {"stack": compose.entry, "image": image})
    commit = release_commit(ctx, compose)
    if seen != commit:
        params: dict[str, Json] = {
            "stack": compose.entry,
            "image_commit": seen,
            "release_commit": commit,
        }
        raise StepFailed("image-not-current", params)
    return commit


def _heads(ctx: StepContext, compose: ComposeStack) -> list[str]:
    """``alembic heads`` of the release's code, in its app's image, no deps."""
    app = compose.app_service or ""
    _, lines = out(
        ctx,
        compose.argv("run", "--rm", "--no-deps", app, *ALEMBIC, "heads"),
        timeout=COMMAND_TIMEOUT_S,
    )
    return heads_of(lines)


def heads_of(lines: Sequence[str]) -> list[str]:
    return heads(lines)


def _psql(ctx: StepContext, compose: ComposeStack, db: Database, sql: str) -> list[str]:
    _, lines = out(
        ctx,
        compose.argv(
            "exec",
            "-T",
            db.service,
            "psql",
            "-U",
            db.user,
            "-d",
            "postgres",
            "-tAc",
            sql,
        ),  # fmt: skip
        timeout=COMMAND_TIMEOUT_S,
    )
    return [line.strip() for line in lines if line.strip()]


def _oid(ctx: StepContext, compose: ComposeStack, db: Database) -> str:
    # the names are [A-Za-z0-9_] only: database() and _safe() refuse the rest
    sql = f"SELECT oid FROM pg_database WHERE datname = '{db.live}'"  # noqa: S608
    found = _psql(ctx, compose, db, sql)
    return found[0] if found else ""


def _safe(compose: ComposeStack, db: Database) -> None:
    for name in (db.live, db.user):
        if not _PG_NAME.fullmatch(name):
            raise StepFailed("database-name", {"stack": compose.entry, "name": name})


def _migrate_argv(compose: ComposeStack) -> list[str]:
    stage = compose.stack.stacks[compose.entry]
    if stage.migrate is None or compose.app_service is None:
        raise StepFailed("no-migrate", {"stack": compose.entry})
    return compose.argv("run", "--rm", compose.app_service, *shlex.split(stage.migrate))


class DbReset(Step):
    """The entry's database dropped and made again, then migrated to the head
    of its release -- the point of no return of ``db reset``."""

    name = "db_reset"
    order = 2
    modes = COMMAND
    point_of_no_return = True
    codes: ClassVar[dict[str, str]] = {
        **{k: v for k, v in DbDump.codes.items() if k != "dump"},
        **IMAGE_CODES,
        **RESET_CODES,
    }

    def __init__(self, compose: ComposeStack) -> None:
        self.compose = compose
        self.acted = False
        """``act`` began: what ``stop_for_restore`` stopped stays stopped."""

    def check(self, ctx: StepContext) -> CheckResult:
        found, _, document = _found(ctx, self.compose)
        _safe(self.compose, found)
        _migrate_argv(self.compose)
        image_is_current(ctx, self.compose, document)
        data: dict[str, Json] = {
            "service": found.service,
            "user": found.user,
            "live": found.live,
            "oid": _oid(ctx, self.compose, found),
            "head": _head(ctx, self.compose),
        }
        params: dict[str, Json] = {"stack": self.compose.entry}
        return CheckResult(True, local_code("reset", params), data)

    def _db(self, check: CheckResult) -> Database:
        service, user, live = (str(check.data[k]) for k in ("service", "user", "live"))
        return Database(service, user, live, "", "")

    def act(self, ctx: StepContext, check: CheckResult) -> None:
        self.acted = True
        db = self._db(check)
        _psql(ctx, self.compose, db, f'DROP DATABASE "{db.live}" WITH (FORCE)')
        _psql(ctx, self.compose, db, f'CREATE DATABASE "{db.live}" OWNER "{db.user}"')
        out(ctx, _migrate_argv(self.compose), timeout=DUMP_TIMEOUT_S)

    def verify(self, ctx: StepContext, check: CheckResult) -> Verified:
        db = self._db(check)
        before, now = str(check.data.get("oid") or ""), _oid(ctx, self.compose, db)
        if not now or now == before:
            raise StepFailed("not-reset", {"stack": self.compose.entry})
        head = check.data.get("head")
        current = _head(ctx, self.compose)
        if isinstance(head, str) and current != head:
            params: dict[str, Json] = {
                "stack": self.compose.entry,
                "head": head,
                "current": current or "none",
            }
            raise StepFailed("head-mismatch", params)
        fact: dict[str, Json] = {
            "stack": self.compose.entry,
            "oid_before": before,
            "oid_after": now,
        }
        if current is not None:
            fact["alembic_head"] = current
        return Verified(fact)


class DbMigrate(Step):
    """The entry's migrations on the image of its current release -- after a
    ``db restore`` of an older dump; the point of no return of ``db
    migrate``. Nothing to do when the database is at the code's head."""

    name = "db_migrate"
    order = 12
    modes = COMMAND
    point_of_no_return = True
    codes: ClassVar[dict[str, str]] = {**IMAGE_CODES, **MIGRATE_VERB_CODES}

    def __init__(self, compose: ComposeStack) -> None:
        self.compose = compose
        self.acted = False

    def check(self, ctx: StepContext) -> CheckResult:
        _migrate_argv(self.compose)
        image_is_current(ctx, self.compose, config(ctx, self.compose))
        found = _heads(ctx, self.compose)
        if len(found) != 1:
            params: dict[str, Json] = {
                "stack": self.compose.entry,
                "count": len(found),
                "heads": list[Json](found),
            }
            raise StepFailed("alembic-heads", params)
        now = _head(ctx, self.compose)
        data: dict[str, Json] = {"head": found[0]}
        if now == found[0]:
            return CheckResult(False, None, data)
        app = self.compose.app_service or ""
        show = self.compose.argv("run", "--rm", "--no-deps", app, *ALEMBIC, "show")
        if now is not None and unknown_head(ctx, [*show, now], now):
            raise StepFailed("db-ahead", {"entry": self.compose.entry, "head": now})
        params = {
            "stack": self.compose.entry,
            "current": now or "none",
            "head": found[0],
        }
        return CheckResult(True, local_code("migrate", params), data)

    def act(self, ctx: StepContext, check: CheckResult) -> None:
        self.acted = True
        out(ctx, _migrate_argv(self.compose), timeout=DUMP_TIMEOUT_S)

    def verify(self, ctx: StepContext, check: CheckResult) -> Verified:
        head = str(check.data.get("head"))
        now = _head(ctx, self.compose)
        if now != head:
            params: dict[str, Json] = {
                "stack": self.compose.entry,
                "head": head,
                "current": now or "none",
            }
            raise StepFailed("not-at-head", params)
        return Verified({"stack": self.compose.entry, "alembic_head": head})


def _seed_argv(compose: ComposeStack, run: str) -> list[str]:
    app = compose.app_service or ""
    return compose.argv("run", "--rm", app, *shlex.split(run))


class Seeds(Step):
    """The entry's seeds of ``when: install`` (contract 3 rule 17), on
    ``install`` and ``reinstall`` -- a new database needs its bootstrap -- in
    the order of ``primer.yaml``, after ``up``: a seed outside its ``roles``
    is not run and is named (DM-86)."""

    name = "seeds"
    order = 15
    modes: frozenset[Mode] = frozenset({"install", "reinstall"})

    def __init__(self, compose: ComposeStack) -> None:
        self.compose = compose
        stage = compose.stack.stacks[compose.entry]
        self.profiles = [
            (name, seed) for name, seed in stage.seeds.items() if seed.when == "install"
        ]

    def _split(self, ctx: StepContext) -> tuple[list[str], list[str]]:
        inside = [n for n, s in self.profiles if s.roles is None or ctx.role in s.roles]
        outside = [n for n, _ in self.profiles if n not in inside]
        return inside, outside

    def check(self, ctx: StepContext) -> CheckResult:
        inside, _ = self._split(ctx)
        if not inside:
            return CheckResult(False, None, {})
        params: dict[str, Json] = {
            "stack": self.compose.entry,
            "profiles": list[Json](inside),
        }
        return CheckResult(True, local_code("seed", params), {})

    codes: ClassVar[dict[str, str]] = {"seed": "seed {stack} with {profiles}"}

    def act(self, ctx: StepContext, check: CheckResult) -> None:
        inside, _ = self._split(ctx)
        seeds = dict(self.profiles)
        for name in inside:
            out(ctx, _seed_argv(self.compose, seeds[name].run), timeout=SEED_TIMEOUT_S)

    def verify(self, ctx: StepContext, check: CheckResult) -> Verified:
        inside, outside = self._split(ctx)
        ran = inside if check.needed else []
        return Verified(
            {
                "stack": self.compose.entry,
                "ran": list[Json](ran),
                "outside_role": list[Json](outside),
            }
        )


class SeedRun(Step):
    """One seed profile by the verb ``seed`` -- ``when: command`` -- in the
    app of the current release (DM-86)."""

    name = "seed"
    order = 4
    modes = COMMAND
    codes: ClassVar[dict[str, str]] = {
        **IMAGE_CODES,
        "no-app": "{stack} has no app to seed in",
        "seed": "seed {stack} with {profile}",
    }

    def __init__(self, compose: ComposeStack, profile: str, run: str) -> None:
        self.compose = compose
        self.profile = profile
        self.run = run

    def check(self, ctx: StepContext) -> CheckResult:
        image_is_current(ctx, self.compose, config(ctx, self.compose))
        params: dict[str, Json] = {"stack": self.compose.entry, "profile": self.profile}
        return CheckResult(True, local_code("seed", params), {})

    def act(self, ctx: StepContext, check: CheckResult) -> None:
        out(ctx, _seed_argv(self.compose, self.run), timeout=SEED_TIMEOUT_S)

    def verify(self, ctx: StepContext, check: CheckResult) -> Verified:
        return Verified({"stack": self.compose.entry, "profile": self.profile})


class SeedPlan(Step):
    """What ``seed`` would do without doing it: ``--dry-run`` (the command) and
    ``--list`` (every entry's profiles) -- no command runs (DM-86)."""

    order = 1
    modes = COMMAND

    def __init__(self, name: str, fact: dict[str, Json]) -> None:
        self.name = name
        self.fact = fact

    def check(self, ctx: StepContext) -> CheckResult:
        return CheckResult(False, None, {})

    def act(self, ctx: StepContext, check: CheckResult) -> None:
        raise AssertionError(f"{self.name} never acts")

    def verify(self, ctx: StepContext, check: CheckResult) -> Verified:
        return Verified(dict(self.fact))


# --- pass 3: a verb of the project ------------------------------------------------

VERB_TIMEOUT_S = 3600
"""A verb of the project: an hour -- the machine does not know what it does."""


class ProjectVerb(Step):
    """A verb of ``verbs`` (contract 3 rule 7, protocol 8.2): ``exec`` in the
    running container of its service -- the declared one, by default the
    app; the live container is the current release's, so no question of an
    image arises. Its code 0 is the fact: the machine runs it, knowing
    nothing of what it does (DM-86)."""

    name = "project_verb"
    order = 1
    modes = COMMAND
    codes: ClassVar[dict[str, str]] = {
        "verb": "run the verb {verb} in {service} of {stack}",
        "service-down": ("{service} of {stack} does not run; the verb {verb} needs it"),
    }

    def __init__(
        self, compose: ComposeStack, *, verb: str, service: str, argv: Sequence[str]
    ) -> None:
        self.compose = compose
        self.verb = verb
        self.service = service
        self.argv = list(argv)

    def check(self, ctx: StepContext) -> CheckResult:
        params: dict[str, Json] = {
            "stack": self.compose.entry,
            "service": self.service,
            "verb": self.verb,
        }
        if not running(ctx, self.compose, [self.service]):
            raise StepFailed("service-down", params)
        return CheckResult(True, local_code("verb", params), {})

    def act(self, ctx: StepContext, check: CheckResult) -> None:
        out(
            ctx,
            self.compose.argv("exec", "-T", self.service, *self.argv),
            timeout=VERB_TIMEOUT_S,
        )

    def verify(self, ctx: StepContext, check: CheckResult) -> Verified:
        return Verified({"verb": self.verb, "service": self.service, "exit_code": 0})
