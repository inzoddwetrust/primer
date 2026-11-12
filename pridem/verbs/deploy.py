"""The verbs that run the box's plan (TZ 9.1): ``install``, ``update``,
``deploy <ref>``, ``doctor``, ``reinstall``, ``rollback``, ``destroy``.

Each makes its plan itself (``pridem/verbs/plans.py``), prints the ladder as it
runs and ends with the verdict's summary line, or with the verdict under
``--json`` (the ladder then goes to stderr). ``update`` brings the box to its
passport and ``primer.yaml``; ``deploy <ref>`` does the same at another ref of
the product, and the next ``update`` -- like ``doctor`` -- goes by the
passport's ref again. ``doctor`` runs ``check`` of every step and acts on
nothing.

On a test box ``update`` and ``deploy`` refuse a commit of another task while
the stand is red (``stand``, ``steps/stand.py``; DM-24).

``rollback`` (TZ 10.6, 19; DM-24) goes back to the previous release -- the one
``gc`` keeps (``steps/history.py``) -- by the deploy plan of that release, with
``rollback_check`` before any step acts: migrations between the releases are a
refusal and ``{restore, needed}``. It is "the previous release": a second
``rollback`` goes forward again, back to the release the first one left. The
passport still names its own ref, which the next ``update`` brings back; the
console says so. On test the stand moves only by its branch: ``rollback`` is a
refusal that names the commit to revert and the branch.

Refused before the run (exit 1, no verdict): an option the verb does not take,
a passport source given twice or half, ``--try`` not ``<service>=<x.y.z>`` or a
service twice, and on a box whose passport says ``prod`` -- ``destroy`` and
``reinstall`` without ``--confirm <server.name>``; ``rollback`` on test, and
on prod without a current release or a previous green one. A passport file its
loader rejects is a message, never a traceback (``cli.py``).
"""

import os
from collections.abc import Callable
from pathlib import Path
from typing import Annotated

from pydantic import Field

from pridem.contract import Strict
from pridem.events import Json, PlanMode
from pridem.report.catalog import Catalog, say
from pridem.report.schema import Verdict
from pridem.stacks.passport import Passport, load_passport
from pridem.state import Box
from pridem.steps.finalize import current_link
from pridem.steps.git import repo
from pridem.steps.history import last_deployed, previous_releases
from pridem.steps.stand import ROLLBACK_CHECK
from pridem.verbs.base import Context, OptionKind, Refused, Verb
from pridem.verbs.plans import Wanted, deploy_plan, destroy_plan, source_of
from pridem.verbs.run import Planned, Session, read_copy, run_plan_verb

TRY = r"^[A-Za-z0-9][A-Za-z0-9._-]*=\d+\.\d+\.\d+$"
"""``--try <service>=<version>``: an exact version, never a range."""

SOURCE: dict[str, tuple[str, OptionKind]] = {
    "--passport": ("passport", "value"),
    "--ops": ("ops", "value"),
    "--server": ("server", "value"),
}


class SourceArgs(Strict):
    passport: str | None = None
    ops: str | None = None
    server: str | None = None


class UpdateArgs(SourceArgs):
    tries: list[Annotated[str, Field(pattern=TRY)]] = []


class DeployArgs(SourceArgs):
    ref: Annotated[str, Field(min_length=1)]


class ReinstallArgs(SourceArgs):
    new_secrets: bool = False
    confirm: str | None = None


class DestroyArgs(Strict):
    confirm: str | None = None


def _given(args: Strict) -> dict[str, Json]:
    """The verdict's ``args``: what was given, nothing defaulted."""
    found: dict[str, Json] = {}
    for name, value in args.model_dump().items():
        if value is None or value is False or value == []:
            continue
        found[name] = value
    return found


def _confirmed(passport: Passport | None, verb: str, confirm: str | None) -> None:
    """On prod a destructive verb names the server it destroys."""
    if passport is None or passport.server.role != "prod":
        return
    if confirm != passport.server.name:
        raise Refused(f"{verb} on prod: --confirm {passport.server.name} to go on")


def _tries(given: list[str]) -> dict[str, str]:
    found: dict[str, str] = {}
    for item in given:
        service, _, version = item.partition("=")
        if service in found:
            raise Refused(f"--try {service} is given twice")
        found[service] = version
    return found


def _plan_verb(name: str, mode: PlanMode) -> Callable[[Strict, Context], int]:
    """The run of a verb of the deploy plan."""

    def run(args: Strict, ctx: Context) -> int:
        if not isinstance(args, SourceArgs):
            raise TypeError(f"{name} takes SourceArgs")
        tries = _tries(args.tries) if isinstance(args, UpdateArgs) else {}
        copy = read_copy(ctx)
        file = Path(args.passport) if args.passport is not None else None
        preread = load_passport(file) if file is not None else copy.passport
        source = source_of(
            ctx.fs_root, copy, file=file, ops=args.ops, server=args.server
        )
        ref = args.ref if isinstance(args, DeployArgs) else None
        new_secrets = False
        before: Callable[[Box], None] | None = None
        if isinstance(args, ReinstallArgs):
            confirm = args.confirm

            def before(box: Box) -> None:
                """The role under the lock (DM-24): the copy read now."""
                _confirmed(read_copy(ctx).passport or preread, name, confirm)

            new_secrets = args.new_secrets
        wanted = Wanted(
            mode=name if name in ("install", "reinstall", "doctor") else "deploy",
            source=source,
            ref=ref,
            tries=tries,
            new_secrets=new_secrets,
        )

        def make(session: Session) -> Planned:
            return deploy_plan(session, ctx.fs_root, wanted, preread)

        return run_plan_verb(
            ctx,
            verb=name,
            mode=mode,
            make=make,
            args=_given(args),
            ladder=True,
            copy=copy,
            before=before,
        )

    return run


def _rollback(args: Strict, ctx: Context) -> int:
    """``rollback`` (TZ 10.6, 19; DM-24): on prod the previous release, on test
    a refusal that says how to roll back by the branch."""
    if not isinstance(args, SourceArgs):
        raise TypeError("rollback takes SourceArgs")
    copy = read_copy(ctx)
    file = Path(args.passport) if args.passport is not None else None
    preread = load_passport(file) if file is not None else copy.passport
    source = source_of(ctx.fs_root, copy, file=file, ops=args.ops, server=args.server)
    chosen: dict[str, str] = {}

    def before(box: Box) -> None:
        passport = read_copy(ctx).passport  # the role under the lock
        if passport is None:
            raise Refused("rollback: the box has no passport")
        stack = repo(passport.product.repo).name
        if passport.server.role == "test":
            deployed = last_deployed(box)
            what = deployed.sha if deployed is not None else "the commit to undo"
            raise Refused(
                "rollback on test moves the stand only by its branch: "
                f"git revert {what} on {passport.product.ref}, push it, "
                "then pridem update"
            )
        link = current_link(ctx.fs_root, stack)
        if not link.is_symlink():
            raise Refused(f"rollback: {stack} has no current release")
        current = Path(os.readlink(link)).name
        previous = previous_releases(box, {stack: current}).previous.get(stack)
        if previous is None:
            raise Refused(f"rollback: no previous green release of {stack}")
        chosen["ref"] = previous

    def make(session: Session) -> Planned:
        wanted = Wanted(mode="deploy", source=source, ref=chosen["ref"], rollback=True)
        return deploy_plan(session, ctx.fs_root, wanted, preread)

    def notes(verdict: Verdict, catalog: Catalog) -> list[str]:
        """The passport still naming the release rolled back from: the next
        ``update`` brings it back."""
        if verdict.result != "green":
            return []
        for step in verdict.steps:
            if step.name == ROLLBACK_CHECK and step.verify is not None:
                ref = step.verify.get("passport_ref")
                if isinstance(ref, str) and ref != chosen.get("ref"):
                    return [say(catalog, "@rollback.passport-ref", ref=ref)]
        return []

    return run_plan_verb(
        ctx,
        verb="rollback",
        mode="deploy",
        make=make,
        args=_given(args),
        ladder=True,
        copy=copy,
        before=before,
        notes=notes,
    )


def _destroy(args: Strict, ctx: Context) -> int:
    if not isinstance(args, DestroyArgs):
        raise TypeError("destroy takes DestroyArgs")
    copy = read_copy(ctx)
    confirm = args.confirm

    def before(box: Box) -> None:
        """The role under the lock (DM-24): the copy read now."""
        _confirmed(read_copy(ctx).passport, "destroy", confirm)

    def make(session: Session) -> Planned:
        return destroy_plan(session, ctx.fs_root)

    return run_plan_verb(
        ctx,
        verb="destroy",
        mode="destroy",
        make=make,
        args=_given(args),
        ladder=True,
        copy=copy,
        before=before,
    )


INSTALL = Verb("install", SourceArgs, _plan_verb("install", "install"), options=SOURCE)
UPDATE = Verb(
    "update",
    UpdateArgs,
    _plan_verb("update", "deploy"),
    options={**SOURCE, "--try": ("tries", "list")},
)
DEPLOY = Verb(
    "deploy",
    DeployArgs,
    _plan_verb("deploy", "deploy"),
    positionals=("ref",),
    options=SOURCE,
)
DOCTOR = Verb("doctor", SourceArgs, _plan_verb("doctor", "doctor"), options=SOURCE)
REINSTALL = Verb(
    "reinstall",
    ReinstallArgs,
    _plan_verb("reinstall", "reinstall"),
    options={
        **SOURCE,
        "--new-secrets": ("new_secrets", "flag"),
        "--confirm": ("confirm", "value"),
    },
)
ROLLBACK = Verb("rollback", SourceArgs, _rollback, options=SOURCE)
DESTROY = Verb(
    "destroy", DestroyArgs, _destroy, options={"--confirm": ("confirm", "value")}
)
