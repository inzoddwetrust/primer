"""``pridem self-update <tag> [--from <url>]``: the machine installs a release
of itself (DM-163; ``pridem/steps/self_update.py``).

A verb of the registry with its verdict, under the box's lock like every
other: one stack, ``pridem-machine`` -- ``release``, ``build``, ``schema``,
``switch``, ``agent_restart`` -- and its ``finally``, ``leftover``. Not
destructive: nothing of the product is touched, and a rollback is the same
verb with a lower tag. ``--from`` -- the release's ``install.sh`` by a
``file://`` or loopback ``http://`` address (tier 3); without it, the
machine's home (``RELEASES``).
"""

from collections.abc import Sequence
from typing import Annotated

from pydantic import AfterValidator

from pridem.contract import Strict
from pridem.events import Json
from pridem.plan import StackSteps
from pridem.stacks import names as machine
from pridem.steps.base import Step
from pridem.steps.self_update import (
    RELEASES,
    AgentRestart,
    Build,
    Leftover,
    Release,
    ReleaseOf,
    Schema,
    Switch,
    from_address,
)
from pridem.verbs.base import Context, Verb
from pridem.verbs.run import Planned, Session, run_plan_verb


class SelfUpdateArgs(Strict):
    """``tag`` -- the release; ``source`` -- ``--from``."""

    tag: str
    source: Annotated[str, AfterValidator(from_address)] | None = None


def _run(args: Strict, ctx: Context) -> int:
    if not isinstance(args, SelfUpdateArgs):
        raise TypeError("self-update takes SelfUpdateArgs")
    named = args.source is not None
    source = args.source or f"{RELEASES}/releases/download/{args.tag}/install.sh"

    def make(session: Session) -> Planned:
        release = Release(
            tag=args.tag,
            source=source,
            named=named,
            work=ctx.root / "tmp" / f"self-update-{session.run_id}",
        )
        steps: Sequence[Step] = [
            ReleaseOf(ctx.root, release),
            Build(ctx.root, release),
            Schema(ctx.root, release),
            Switch(ctx.root, release),
            AgentRestart(ctx.fs_root, release, ctx.command is not None),
        ]
        return Planned(
            [StackSteps(machine.MACHINE, steps, root=True)],
            finally_=[StackSteps(machine.MACHINE, [Leftover(ctx.root, release)])],
        )

    given: dict[str, Json] = {"tag": args.tag}
    if args.source is not None:
        given["from"] = args.source
    return run_plan_verb(ctx, verb="self-update", mode="command", make=make, args=given)


SELF_UPDATE = Verb(
    "self-update",
    SelfUpdateArgs,
    _run,
    positionals=("tag",),
    options={"--from": ("source", "value")},
    group="server",
)
