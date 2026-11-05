"""``pridem ssl renew``: certbot renews what is due, under the box lock (TZ
9.1); the renewal timer of the box runs it. ``issue`` and ``status`` join
``action`` with the whole CLI."""

from collections.abc import Sequence
from typing import Literal

from pridem.contract import Strict
from pridem.events import Secrets
from pridem.state import Box
from pridem.steps.base import Step
from pridem.steps.passport import Fetched
from pridem.steps.ssl import SslRenew
from pridem.verbs.base import Context, Verb
from pridem.verbs.run import one_stack, run_plan_verb

SSL_STACK = "edge"


class SslArgs(Strict):
    action: Literal["renew"]


def _run(args: Strict, ctx: Context) -> int:
    if not isinstance(args, SslArgs):
        raise TypeError("ssl takes SslArgs")

    def steps(
        box: Box, run_id: str, fetched: Fetched, secrets: Secrets
    ) -> Sequence[Step]:
        return [SslRenew(fetched=fetched, secrets=secrets, root=ctx.fs_root)]

    return run_plan_verb(
        ctx, verb=f"ssl {args.action}", mode="renew", make=one_stack(SSL_STACK, steps)
    )


SSL = Verb("ssl", SslArgs, _run, positionals=("action",), timer=True)
