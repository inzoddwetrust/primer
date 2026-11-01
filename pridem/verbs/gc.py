"""``pridem gc``: the box's clean-up by labels as a verb (TZ 9.1), the same step
every plan runs in ``finally``; the daily timer of the box runs it too."""

from collections.abc import Sequence

from pridem.contract import Strict
from pridem.events import Secrets
from pridem.state import Box
from pridem.steps.base import Step
from pridem.steps.gc import GC_STACK, gc_steps
from pridem.steps.passport import Fetched
from pridem.verbs.base import Context, NoArgs, Verb
from pridem.verbs.run import run_plan_verb


def _run(args: Strict, ctx: Context) -> int:
    def steps(
        box: Box, run_id: str, fetched: Fetched, secrets: Secrets
    ) -> Sequence[Step]:
        return gc_steps(ctx.fs_root, box=box, run_id=run_id, fetched=fetched)

    return run_plan_verb(ctx, verb="gc", mode="gc", stack=GC_STACK, steps=steps)


GC = Verb("gc", NoArgs, _run, timer=True)
