"""``pridem agent install``: the agent of the box as a systemd service (DM-143).

A plan of the machine under the box lock with its verdict -- stack
``pridem-agent``, one step, ``agent_service`` (``pridem/steps/agent_service.py``)
-- read by ``pridem.cli`` beside ``pridem agent`` and, like it, no verb of
``VERBS``: the Panel's queue never gives it. ``install.sh`` runs it after
``pridem register`` (first contact, DM-143); a repeat sees the service as it
should be and changes nothing.
"""

from collections.abc import Sequence

from pridem.events import Secrets
from pridem.stacks import names as machine
from pridem.state import Box
from pridem.steps.agent_service import AgentService
from pridem.steps.base import Step
from pridem.steps.passport import Fetched
from pridem.verbs.base import Context
from pridem.verbs.run import one_stack, run_plan_verb

VERB = "agent install"


def install_service(ctx: Context) -> int:
    """The plan of ``pridem agent install``; its exit code."""

    def steps(
        box: Box, run_id: str, fetched: Fetched, secrets: Secrets
    ) -> Sequence[Step]:
        return [AgentService(ctx.root, ctx.fs_root)]

    return run_plan_verb(
        ctx, verb=VERB, mode="command", make=one_stack(machine.AGENT, steps)
    )
