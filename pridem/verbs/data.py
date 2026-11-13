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

import json
import shlex
import sys
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

import yaml
from pydantic import SecretStr

from pridem.contract import SECRET_MIN_LENGTH, Strict
from pridem.events import Json, Secrets
from pridem.plan import StackSteps
from pridem.runner import Interactive, RunnerError, Stream
from pridem.stacks.env import MINTED_FILE, read_minted
from pridem.stacks.loader import ContractError
from pridem.stacks.schema import Ident, Product, Service, load_primer_yaml
from pridem.state import Box
from pridem.steps.base import Step, StepFailed
from pridem.steps.compose import ComposeStack, verb_service
from pridem.steps.data import (
    BACKUPS,
    SERVICE_ACTIONS,
    BackupScope,
    DbDump,
    DbMigrate,
    DbReset,
    DbRestore,
    ProjectVerb,
    SeedPlan,
    SeedRun,
    StartRestored,
    StopForRestore,
    backups_dir,
    read_manifest,
)
from pridem.steps.finalize import current_link
from pridem.steps.gc import CONNECT_DIR
from pridem.steps.migrate import StartStopped, StopForMigrate, Stopped
from pridem.steps.passport import passport_secrets
from pridem.steps.tests import database
from pridem.verbs.base import Context, NoArgs, Refused, Verb
from pridem.verbs.run import Planned, Session, read_copy, run_plan_verb


class DbArgs(Strict):
    action: Literal["dump", "restore", "reset", "migrate", "connect"]
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
    if args.action == "connect":
        return _connect(args, ctx, compose)
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
    confirm = args.confirm

    def confirmed(box: Box) -> None:
        _confirmed(ctx, verb, confirm)  # the copy read under the lock (DM-24)

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
        ctx,
        verb=verb,
        mode="command",
        make=restore,
        args=_given(args),
        before=confirmed,
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
    confirm = args.confirm

    def resettable(box: Box) -> None:
        _resettable(ctx, "db reset", compose, confirm)  # under the lock (DM-24)

    def make(session: Session) -> Planned:
        stopped = Stopped()
        return Planned(
            [StackSteps(compose.entry, _reset_steps(compose, stopped), root=True)],
            finally_=[StackSteps("stopped", [StartStopped(stopped)])],
        )

    return run_plan_verb(
        ctx,
        verb="db reset",
        mode="command",
        make=make,
        args=_given(args),
        before=resettable,
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
    if args.dry_run and (args.reset or args.confirm):
        raise Refused("seed --dry-run: runs nothing, so resets nothing")
    given: dict[str, Json] = {"stack": compose.entry, "profile": args.profile}
    reset, confirm, profile, roles = args.reset, args.confirm, args.profile, seed.roles

    def seedable(box: Box) -> None:
        """The role and the confirmation under the lock (DM-24)."""
        role = _role(ctx, "seed")
        if roles is not None and role not in roles:
            raise Refused(f"seed: {profile} is not for the role {role}")
        if reset:
            _resettable(ctx, "seed --reset", compose, confirm)

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
            ctx,
            verb="seed",
            mode="command",
            make=dry,
            args={**given, "dry_run": True},
            before=seedable,
        )
    if not args.reset and args.confirm is not None:
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
    return run_plan_verb(
        ctx, verb="seed", mode="command", make=make, args=given, before=seedable
    )


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


# --- pass 3: a verb of the project ------------------------------------------------


class VerbArgs(Strict):
    name: Ident
    pairs: list[str] = []
    confirm: str | None = None


def box_secrets(ctx: Context) -> list[str]:
    """The known secrets of the box (contract 3 rule 7): ``asked`` and ``tls``
    of the passport, ``minted`` of every stack the box runs."""
    found: list[str] = []
    passport = read_copy(ctx).passport
    if passport is not None:
        found += [secret.get_secret_value() for secret in passport_secrets(passport)]
    state = Box(ctx.root).read_state()
    for stack in sorted(state.current if state is not None else ()):
        path = ctx.fs_root / "opt" / stack / "env" / MINTED_FILE
        try:
            found += list(read_minted(path).values())
        except (StepFailed, OSError):
            raise Refused(
                f"verb: the minted secrets of {stack} cannot be read"
            ) from None
    return [secret for secret in found if secret.strip()]


def _values(verb: str, declared: list[str], pairs: list[str]) -> dict[str, str]:
    """``<arg>=<value>`` of each declared argument, once, none other, none
    empty -- refused before the run otherwise."""
    given: dict[str, str] = {}
    for pair in pairs:
        name, sep, value = pair.partition("=")
        if not sep:
            raise Refused(f"verb {verb}: {pair!r} is not <arg>=<value>")
        if name not in declared:
            raise Refused(f"verb {verb}: no argument {name}")
        if name in given:
            raise Refused(f"verb {verb}: {name} is given twice")
        if not value:
            raise Refused(f"verb {verb}: {name} is empty")
        given[name] = value
    missing = [name for name in declared if name not in given]
    if missing:
        raise Refused(f"verb {verb}: {', '.join(missing)} not given")
    return given


def _verb(args: Strict, ctx: Context) -> int:
    """``verb <name> [<arg>=<value> ...] [--confirm <server.name>]``: a verb of
    the product, refused before the run when its name, arguments, role or
    confirmation do not hold, or an argument is a secret of the box (DM-86)."""
    if not isinstance(args, VerbArgs):
        raise TypeError("verb takes VerbArgs")
    products = [(stack, m) for stack, m in box_entries(ctx) if isinstance(m, Product)]
    if not products:
        raise Refused("verb: the box runs no product")
    stack, made = products[0]
    declared = made.verbs.get(args.name)
    if declared is None:
        raise Refused(f"verb: the product has no verb {args.name}")
    values = _values(args.name, list(declared.args), args.pairs)
    if not declared.destructive and args.confirm is not None:
        raise Refused(f"verb {args.name}: --confirm is for a destructive verb")
    name, confirm = args.name, args.confirm

    def allowed(box: Box) -> None:
        """The role, the confirmation and the box's secrets under the lock
        (DM-24): the copy and the minted files read now."""
        role = _role(ctx, "verb")
        if declared.roles is not None and role not in declared.roles:
            raise Refused(f"verb {name}: not for the role {role}")
        if declared.destructive:
            _confirmed(ctx, f"verb {name}", confirm)
        secrets = set(box_secrets(ctx))
        for key, value in values.items():
            if value in secrets or value.strip() in secrets:
                raise Refused(f"verb {name}: {key} is a secret of the box")

    service = verb_service(made, args.name)
    if service is None or made.name not in made.stacks:
        raise Refused(f"verb {args.name}: no service of the product's own entry")
    compose = compose_of(ctx, stack, made, made.name)
    argv = [*shlex.split(declared.run), *(values[name] for name in declared.args)]
    step = ProjectVerb(compose, verb=args.name, service=service, argv=argv)

    def make(session: Session) -> Planned:
        return Planned([StackSteps(made.name, [step], root=True)])

    given: dict[str, Json] = {"name": args.name}
    if values:
        given["args"] = dict[str, Json](values)
    if args.confirm is not None:
        given["confirm"] = args.confirm
    return run_plan_verb(
        ctx, verb="verb", mode="command", make=make, args=given, before=allowed
    )


VERB = Verb(
    "verb",
    VerbArgs,
    _verb,
    positionals=("name",),
    rest="pairs",
    options={"--confirm": ("confirm", "value")},
)


# --- pass 4: logs, start, stop, restart, db connect -----------------------------

LOGS_FOLLOW_S = 24 * 3600
"""``logs -f``: until Ctrl-C, or a day."""
LOGS_TIMEOUT_S = 300


class LogsArgs(Strict):
    stack: Ident
    words: list[str] = []
    """``[<service>] [<field>=<value> ...]``: a first word without ``=`` is the
    service; every other word is a filter."""
    follow: bool = False
    tail: str | None = None


def _filters(pairs: list[str]) -> dict[str, str]:
    """``<field>=<value>`` pairs of ``logs``; refused before the run otherwise."""
    found: dict[str, str] = {}
    for pair in pairs:
        name, sep, value = pair.partition("=")
        if not sep or not name:
            raise Refused(f"logs: {pair!r} is not <field>=<value>")
        found[name] = value
    return found


def matches(line: str, filters: dict[str, str]) -> bool:
    """A line of a JSON log whose every field named equals its value -- a
    number or a boolean compared by its JSON text (``status=500``, ``ok=true``);
    without filters every line."""
    if not filters:
        return True
    try:
        record = json.loads(line)
    except ValueError:
        return False
    if not isinstance(record, dict):
        return False
    for name, value in filters.items():
        if name not in record:
            return False
        seen = record[name]
        text = seen if isinstance(seen, str) else json.dumps(seen)
        if text != value:
            return False
    return True


def _entry(ctx: Context, entry: str) -> ComposeStack:
    for stack, made in box_entries(ctx):
        if entry in made.stacks:
            return compose_of(ctx, stack, made, entry)
    raise Refused(f"the box runs no entry {entry}")


def _logs(args: Strict, ctx: Context) -> int:
    """``logs <entry> [<service>] [-f] [--tail N] [<field>=<value> ...]``: the
    entry's logs through compose, filtered by the fields of each JSON line, the
    box's known secrets cleaned out of what is printed (contract 2 rule 2).
    No verdict and no lock, as ``report``: it reads, and ``-f`` lasts until
    Ctrl-C -- a lock would hold every deploy that long (DM-86)."""
    if not isinstance(args, LogsArgs):
        raise TypeError("logs takes LogsArgs")
    words = list(args.words)
    service = words.pop(0) if words and "=" not in words[0] else None
    filters = _filters(words)
    if args.tail is not None and not args.tail.isdigit():
        raise Refused("logs: --tail is a number of lines")
    compose = _entry(ctx, args.stack)
    secrets = Secrets(
        SecretStr(s) for s in box_secrets(ctx) if len(s) >= SECRET_MIN_LENGTH
    )
    argv = ["logs", "--no-color", "--no-log-prefix"]
    if args.follow:
        argv.append("-f")
    if args.tail is not None:
        argv += ["--tail", str(args.tail)]
    if service is not None:
        argv.append(service)
    dropped = 0

    def line(stream: Stream, text: str, cut: bool) -> None:
        nonlocal dropped
        if matches(text, filters):
            print(secrets.text(text), file=ctx.out, flush=True)
        elif filters:
            dropped += 1

    try:
        ctx.runner.run(
            compose.argv(*argv),
            timeout=LOGS_FOLLOW_S if args.follow else LOGS_TIMEOUT_S,
            on_line=line,
        )
    except KeyboardInterrupt:  # Ctrl-C ends -f: that is how it is meant to end
        pass
    except RunnerError as error:
        raise Refused(f"logs: {error}") from None
    if filters:
        print(f"logs: {dropped} line(s) not matching", file=ctx.err)
    return 0


def _action(action: str) -> Callable[[Strict, Context], int]:
    def run(args: Strict, ctx: Context) -> int:
        """``start|stop|restart [<entry> [<service>]]``: the services of the
        box's entries in order -- services, then the product, for ``start``
        and ``restart``; the reverse for ``stop`` (DM-86)."""
        if not isinstance(args, ServiceArgs):
            raise TypeError(f"{action} takes ServiceArgs")
        entries = [
            compose_of(ctx, stack, made, entry)
            for stack, made in box_entries(ctx)
            for entry in made.stacks
        ]
        if args.stack is not None:
            entries = [c for c in entries if c.entry == args.stack]
            if not entries:
                raise Refused(f"{action}: the box runs no entry {args.stack}")
        elif args.service is not None:
            raise Refused(f"{action}: a service is named with its entry")
        if action == "stop":
            entries.reverse()
        chosen = [args.service] if args.service is not None else None
        step = SERVICE_ACTIONS[action]

        def make(session: Session) -> Planned:
            stacks = [StackSteps(c.entry, [step(c, chosen)]) for c in entries]
            stacks[-1] = StackSteps(stacks[-1].name, stacks[-1].steps, root=True)
            return Planned(stacks)

        given: dict[str, Json] = {}
        if args.stack is not None:
            given["stack"] = args.stack
        if args.service is not None:
            given["service"] = args.service
        return run_plan_verb(ctx, verb=action, mode="command", make=make, args=given)

    return run


class ServiceArgs(Strict):
    stack: Ident | None = None
    service: Ident | None = None


LOGS = Verb(
    "logs",
    LogsArgs,
    _logs,
    positionals=("stack",),
    rest="words",
    options={"-f": ("follow", "flag"), "--tail": ("tail", "value")},
    verdict=False,  # it reads, as report: no verdict, no lock (DM-86)
)
START = Verb("start", ServiceArgs, _action("start"), positionals=("stack", "service"))
STOP = Verb("stop", ServiceArgs, _action("stop"), positionals=("stack", "service"))
RESTART = Verb(
    "restart", ServiceArgs, _action("restart"), positionals=("stack", "service")
)


READ_ONLY = "PGOPTIONS=-c default_transaction_read_only=on"
"""The session of ``db connect`` reads: every transaction read-only."""


def _connect(args: DbArgs, ctx: Context, compose: ComposeStack) -> int:
    """``db connect <entry> [--confirm <server.name>]``: ``psql`` in the
    database's container on this terminal, every transaction read-only, its
    log -- queries and their results -- kept on the box in
    ``/opt/pridem/connect/<time>-<entry>.log`` (0600), ``gc`` removing it after
    ``CONNECT_KEEP_DAYS``. On ``prod`` the server is named: the session shows
    people's data. No verdict and no lock, as ``logs``: a session lasts as long
    as its person wants (DM-86).

    KNOWN CEILING (DM-86, read-only):
    1. mechanics: ``default_transaction_read_only`` is the session's own
       setting -- ``SET default_transaction_read_only = off`` takes it off; it
       guards against a mistake, not against intent (a person at the box is
       root of it anyway); and the log holds the results of the queries -- on
       ``prod``, people's data, for ``CONNECT_KEEP_DAYS``;
    2. status: acknowledged by design;
    3. task: none -- a read-only role is the product's to give (protocol);
    4. trigger: a product declares a read-only role of its database;
    5. agreed form of the fix: connect as that role (``pg_read_all_data``);
    6. rejected: the machine making a role -- a write into the product's
       cluster, outside every migration."""
    if args.dump is not None:
        raise Refused("db connect: takes the entry and --confirm alone")
    passport = read_copy(ctx).passport
    if passport is None:
        raise Refused("db connect: the box has no passport to read its role")
    if passport.server.role == "prod":
        _confirmed(ctx, "db connect on prod", args.confirm)
    elif args.confirm is not None:
        raise Refused("db connect: --confirm is asked on prod only")
    runner = ctx.runner
    if not isinstance(runner, Interactive):
        raise Refused("db connect: this runner hands no terminal")
    app = compose.app_service or ""

    def lines_of(argv: list[str]) -> list[str]:
        got: list[str] = []
        runner.run(
            argv,
            timeout=LOGS_TIMEOUT_S,
            on_line=lambda s, line, c: got.append(line) if s is Stream.STDOUT else None,
        )
        return got

    try:
        document = json.loads(
            "".join(lines_of(compose.product_argv("config", "--format", "json")))
        )
        found = database(document, app)
        if not "".join(
            lines_of(compose.argv("ps", "--status", "running", "-q", found.service))
        ).strip():
            raise Refused(f"db connect: the database {found.service} does not run")
    except (RunnerError, ValueError, StepFailed) as error:
        raise Refused(f"db connect: the database cannot be found ({error})") from None
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    # a path inside the database's container, not on the box
    inside = f"/tmp/pridem-connect-{stamp}.log"  # noqa: S108
    home = ctx.root / CONNECT_DIR
    home.mkdir(exist_ok=True, mode=0o700)
    home.chmod(0o700)
    kept = home / f"{stamp}-{compose.entry}.log"
    tty = [] if sys.stdin.isatty() else ["-T"]  # no terminal: stdin is a file
    session = compose.argv(
        "exec", *tty, "-e", READ_ONLY, found.service,
        "psql", "-U", found.user, "-d", found.live, "-L", inside,
    )  # fmt: skip
    code = runner.interactive(session)
    try:
        lines_of(compose.argv("cp", f"{found.service}:{inside}", str(kept)))
        lines_of(compose.argv("exec", "-T", found.service, "rm", "-f", inside))
        kept.chmod(0o600)
    except (RunnerError, OSError) as error:
        print(f"db connect: the session's log was not kept ({error})", file=ctx.err)
        return 1
    print(f"db connect: psql ended with {code}; its log: {kept}", file=ctx.err)
    return 0 if code == 0 else 1
