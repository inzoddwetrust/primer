"""The data verbs (TZ 9.1, 12; DM-86): ``db dump <stack>``, ``db restore
<stack> <dump> --confirm <server.name>``, ``backup``.

``<stack>`` is an entry of a stack the box runs: ``state.json`` names the
stacks, ``primer.yaml`` of each one's ``current`` names its entries. Each verb
is a plan of mode ``command`` with its verdict, under the box's lock.

Refused before the run (exit 1, no verdict): an entry the box does not run, or
whose app has no ``DATABASE_URL`` in its compose file; ``db restore`` of a file
that is not a dump of ``db_dump`` for that entry (under
``/opt/pridem/backups/``, with its manifest); ``db restore`` without
``--confirm <server.name>`` on any role -- a verb that wipes data asks where
it is allowed (protocol 1.11 to 8.2, the owner's word 10.11); ``backup``
without the box's passport.
"""

import shlex
from pathlib import Path
from typing import Literal

import yaml

from pridem.contract import Strict
from pridem.events import Json
from pridem.plan import StackSteps
from pridem.stacks.loader import ContractError
from pridem.stacks.schema import Ident, Product, Service, load_primer_yaml
from pridem.state import Box
from pridem.steps.base import Step
from pridem.steps.compose import ComposeStack
from pridem.steps.data import (
    BACKUPS,
    BackupScope,
    DbDump,
    DbMigrate,
    DbReset,
    DbRestore,
    SeedPlan,
    SeedRun,
    StartRestored,
    StopForRestore,
    backups_dir,
    read_manifest,
)
from pridem.steps.finalize import current_link
from pridem.steps.migrate import StartStopped, StopForMigrate, Stopped
from pridem.verbs.base import Context, NoArgs, Refused, Verb
from pridem.verbs.run import Planned, Session, read_copy, run_plan_verb


class DbArgs(Strict):
    action: Literal["dump", "restore", "reset", "migrate"]
    stack: Ident
    dump: str | None = None
    confirm: str | None = None


def box_entries(ctx: Context) -> list[tuple[str, Product | Service]]:
    """Every stack ``state.json`` names, with its ``primer.yaml`` of
    ``current``: services first, the product last."""
    state = Box(ctx.root).read_state()
    found: list[tuple[str, Product | Service]] = []
    for stack in sorted(state.current if state is not None else ()):
        try:
            made = load_primer_yaml(current_link(ctx.fs_root, stack) / "primer.yaml")
        except (ContractError, OSError):
            continue
        found.append((stack, made))
    return sorted(found, key=lambda item: isinstance(item[1], Product))


def compose_of(
    ctx: Context, stack: str, made: Product | Service, entry: str
) -> ComposeStack:
    """The entry on its ``current`` release."""
    release = current_link(ctx.fs_root, stack).resolve()
    return ComposeStack(made, entry, release, release.name, release.name, ctx.fs_root)


def has_database_url(compose: ComposeStack) -> bool:
    """The app of the entry names ``DATABASE_URL`` in its compose file, as
    written -- read before the run, without docker."""
    app = compose.app_service
    if app is None:
        return False
    try:
        document = yaml.safe_load(compose.compose_file.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, yaml.YAMLError):
        return False
    services = document.get("services") if isinstance(document, dict) else None
    body = services.get(app) if isinstance(services, dict) else None
    env = body.get("environment") if isinstance(body, dict) else None
    if isinstance(env, dict):
        return "DATABASE_URL" in env
    if isinstance(env, list):
        return any(str(item).split("=", 1)[0] == "DATABASE_URL" for item in env)
    return False


def _target(ctx: Context, entry: str) -> ComposeStack:
    for stack, made in box_entries(ctx):
        if entry in made.stacks:
            compose = compose_of(ctx, stack, made, entry)
            if not has_database_url(compose):
                raise Refused(f"db: {entry} has no DATABASE_URL in its app")
            return compose
    raise Refused(f"db: the box runs no entry {entry}")


def _confirmed(ctx: Context, verb: str, confirm: str | None) -> None:
    """A verb that wipes data names the server, on any role."""
    passport = read_copy(ctx).passport
    if passport is None:
        raise Refused(f"{verb}: the box has no passport to confirm against")
    if confirm != passport.server.name:
        raise Refused(f"{verb}: --confirm {passport.server.name} to go on")


def _dump(
    ctx: Context, compose: ComposeStack, given: str
) -> tuple[Path, dict[str, Json]]:
    """A dump of ``db_dump`` for this entry, and its manifest."""
    home = (ctx.root / BACKUPS).resolve()
    path = Path(given).resolve()
    if home not in path.parents or path.name != f"{compose.entry}.dump":
        raise Refused(f"db restore: {given} is no dump of {compose.entry} in {home}")
    manifest = read_manifest(path.with_suffix(".json"))
    if manifest is None or not path.is_file():
        raise Refused(f"db restore: {given} has no manifest beside it")
    if (manifest.get("stack"), manifest.get("entry")) != (
        compose.stack.name,
        compose.entry,
    ):
        raise Refused(f"db restore: {given} is a dump of another entry")
    return path, manifest


def _given(args: DbArgs) -> dict[str, Json]:
    found: dict[str, Json] = {"stack": args.stack}
    if args.dump is not None:
        found["dump"] = args.dump
    if args.confirm is not None:
        found["confirm"] = args.confirm
    return found


def _db(args: Strict, ctx: Context) -> int:
    if not isinstance(args, DbArgs):
        raise TypeError("db takes DbArgs")
    compose = _target(ctx, args.stack)
    verb = f"db {args.action}"
    if args.action == "reset":
        return _reset(args, ctx, compose)
    if args.action == "migrate":
        return _migrate(args, ctx, compose)
    if args.action == "dump":
        if args.dump is not None or args.confirm is not None:
            raise Refused("db dump: takes the entry alone")

        def dump(session: Session) -> Planned:
            directory = backups_dir(session.box.root, session.run_id)
            step = DbDump(compose, directory=directory, run_id=session.run_id)
            return Planned([StackSteps(compose.entry, [step], root=True)])

        return run_plan_verb(
            ctx, verb=verb, mode="command", make=dump, args=_given(args)
        )
    if args.dump is None:
        raise Refused("db restore: names the dump to restore")
    path, manifest = _dump(ctx, compose, args.dump)
    _confirmed(ctx, verb, args.confirm)

    def restore(session: Session) -> Planned:
        stopped = Stopped()
        restoring = DbRestore(compose, path=path, manifest=manifest)
        steps: list[Step] = [
            StopForRestore(restoring, stopped),
            restoring,
            StartRestored(compose, stopped),
        ]
        return Planned(
            [StackSteps(compose.entry, steps, root=True)],
            finally_=[StackSteps("stopped", [StartStopped(stopped)])],
        )

    return run_plan_verb(
        ctx, verb=verb, mode="command", make=restore, args=_given(args)
    )


def _backup(args: Strict, ctx: Context) -> int:
    passport = read_copy(ctx).passport
    if passport is None:
        raise Refused("backup: the box has no passport to read its policy")
    if not passport.policies.backup.enabled:

        def off(session: Session) -> Planned:
            step = BackupScope({"policy": "disabled"})
            return Planned([StackSteps("backup", [step], root=True)])

        return run_plan_verb(ctx, verb="backup", mode="command", make=off)
    dumped: list[ComposeStack] = []
    without: list[str] = []
    for stack, made in box_entries(ctx):
        for entry in made.stacks:
            compose = compose_of(ctx, stack, made, entry)
            if has_database_url(compose):
                dumped.append(compose)
            else:
                without.append(entry)

    def every(session: Session) -> Planned:
        directory = backups_dir(session.box.root, session.run_id)
        stacks: list[StackSteps] = [
            StackSteps(c.entry, [DbDump(c, directory=directory, run_id=session.run_id)])
            for c in dumped
        ]
        scope: dict[str, Json] = {
            "dumped": [c.entry for c in dumped],
            "no_database": list[Json](without),
        }
        stacks.append(StackSteps("backup", [BackupScope(scope)], root=True))
        return Planned(stacks)

    return run_plan_verb(ctx, verb="backup", mode="command", make=every)


DB = Verb(
    "db",
    DbArgs,
    _db,
    positionals=("action", "stack", "dump"),
    options={"--confirm": ("confirm", "value")},
)
BACKUP = Verb("backup", NoArgs, _backup)


def _role(ctx: Context, verb: str) -> str:
    passport = read_copy(ctx).passport
    if passport is None:
        raise Refused(f"{verb}: the box has no passport to read its role")
    return passport.server.role


def _resettable(
    ctx: Context, verb: str, compose: ComposeStack, confirm: str | None
) -> None:
    """``db reset``: on the role ``test`` only, the server named on any role
    (protocol 1.11), an entry with ``migrate`` -- the schema comes back."""
    if _role(ctx, verb) != "test":
        raise Refused(f"{verb}: runs on the role test only")
    _confirmed(ctx, verb, confirm)
    if compose.stack.stacks[compose.entry].migrate is None:
        raise Refused(
            f"{verb}: {compose.entry} has no migrate to bring its schema back"
        )


def _reset_steps(compose: ComposeStack, stopped: Stopped) -> list[Step]:
    reset = DbReset(compose)
    return [StopForRestore(reset, stopped), reset, StartRestored(compose, stopped)]


def _reset(args: DbArgs, ctx: Context, compose: ComposeStack) -> int:
    if args.dump is not None:
        raise Refused("db reset: takes the entry and --confirm alone")
    _resettable(ctx, "db reset", compose, args.confirm)

    def make(session: Session) -> Planned:
        stopped = Stopped()
        return Planned(
            [StackSteps(compose.entry, _reset_steps(compose, stopped), root=True)],
            finally_=[StackSteps("stopped", [StartStopped(stopped)])],
        )

    return run_plan_verb(
        ctx, verb="db reset", mode="command", make=make, args=_given(args)
    )


def _migrate(args: DbArgs, ctx: Context, compose: ComposeStack) -> int:
    if args.dump is not None or args.confirm is not None:
        raise Refused("db migrate: takes the entry alone")
    if compose.stack.stacks[compose.entry].migrate is None:
        raise Refused(f"db migrate: {compose.entry} has no migrate")

    def make(session: Session) -> Planned:
        stopped = Stopped()
        migrating = DbMigrate(compose)
        steps: list[Step] = [
            StopForMigrate(migrating, stopped),
            migrating,
            StartRestored(compose, stopped, order=13),
        ]
        return Planned(
            [StackSteps(compose.entry, steps, root=True)],
            finally_=[StackSteps("stopped", [StartStopped(stopped)])],
        )

    return run_plan_verb(
        ctx, verb="db migrate", mode="command", make=make, args=_given(args)
    )


class SeedArgs(Strict):
    stack: Ident | None = None
    profile: Ident | None = None
    list_: bool = False
    dry_run: bool = False
    reset: bool = False
    confirm: str | None = None


def _seed_list(ctx: Context) -> dict[str, Json]:
    found: dict[str, Json] = {}
    for _, made in box_entries(ctx):
        for entry, stage in made.stacks.items():
            found[entry] = [
                {
                    "profile": name,
                    "when": seed.when,
                    **({"roles": list[Json](seed.roles)} if seed.roles else {}),
                }
                for name, seed in stage.seeds.items()
            ]
    return found


def _seed(args: Strict, ctx: Context) -> int:
    """``seed --list``; ``seed <stack> --profile <n> [--dry-run | --reset
    --confirm <server.name>]`` -- a profile of ``when: command`` (rule 17), in
    its roles; refused before the run otherwise (DM-86)."""
    if not isinstance(args, SeedArgs):
        raise TypeError("seed takes SeedArgs")
    if args.list_:
        if args.stack or args.profile or args.dry_run or args.reset or args.confirm:
            raise Refused("seed --list: takes nothing else")
        listed = _seed_list(ctx)

        def lists(session: Session) -> Planned:
            step = SeedPlan("seed_list", {"entries": listed})
            return Planned([StackSteps("seed", [step], root=True)])

        return run_plan_verb(
            ctx, verb="seed", mode="command", make=lists, args={"list": True}
        )
    if args.stack is None or args.profile is None:
        raise Refused("seed: names the entry and --profile, or --list")
    compose = _target(ctx, args.stack)
    seed = compose.stack.stacks[compose.entry].seeds.get(args.profile)
    if seed is None:
        raise Refused(f"seed: {compose.entry} has no profile {args.profile}")
    if seed.when != "command":
        raise Refused(f"seed: {args.profile} runs at install only (when: install)")
    role = _role(ctx, "seed")
    if seed.roles is not None and role not in seed.roles:
        raise Refused(f"seed: {args.profile} is not for the role {role}")
    if args.dry_run and (args.reset or args.confirm):
        raise Refused("seed --dry-run: runs nothing, so resets nothing")
    given: dict[str, Json] = {"stack": compose.entry, "profile": args.profile}
    if args.dry_run:
        app = compose.app_service or ""
        argv = compose.argv("run", "--rm", app, *shlex.split(seed.run))
        fact: dict[str, Json] = {
            "stack": compose.entry,
            "profile": args.profile,
            "service": app,
            "argv": list[Json](argv),
        }

        def dry(session: Session) -> Planned:
            step = SeedPlan("seed_dry_run", fact)
            return Planned([StackSteps(compose.entry, [step], root=True)])

        return run_plan_verb(
            ctx, verb="seed", mode="command", make=dry, args={**given, "dry_run": True}
        )
    if args.reset:
        _resettable(ctx, "seed --reset", compose, args.confirm)
    elif args.confirm is not None:
        raise Refused("seed: --confirm goes with --reset")
    run = SeedRun(compose, args.profile, seed.run)

    def make(session: Session) -> Planned:
        stopped = Stopped()
        steps: list[Step] = (
            [*_reset_steps(compose, stopped), run] if args.reset else [run]
        )
        finals = [StackSteps("stopped", [StartStopped(stopped)])] if args.reset else []
        return Planned([StackSteps(compose.entry, steps, root=True)], finally_=finals)

    if args.reset:
        given = {**given, "reset": True, "confirm": args.confirm or ""}
    return run_plan_verb(ctx, verb="seed", mode="command", make=make, args=given)


SEED = Verb(
    "seed",
    SeedArgs,
    _seed,
    positionals=("stack",),
    options={
        "--profile": ("profile", "value"),
        "--list": ("list_", "flag"),
        "--dry-run": ("dry_run", "flag"),
        "--reset": ("reset", "flag"),
        "--confirm": ("confirm", "value"),
    },
)
