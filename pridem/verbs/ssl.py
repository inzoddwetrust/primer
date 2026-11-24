"""``pridem ssl renew``: certbot renews what is due, under the box lock (TZ
9.1); the renewal timer of the box runs it. ``pridem ssl status [--json]``:
the part ``ssl`` of the box's state (``pridem state``, DM-136) -- the mode,
the end of the one certificate, from when the machine renews it, each domain
of the passport and whether the certificate names it -- read, with no lock and
no verdict. ``issue`` joins ``action`` with the whole CLI."""

from collections.abc import Sequence
from typing import Literal

from pridem.contract import Strict
from pridem.events import Secrets, said
from pridem.stacks import names as machine
from pridem.state import Box
from pridem.steps.base import Step
from pridem.steps.passport import Fetched
from pridem.steps.ssl import SslRenew
from pridem.verbs.base import Context, Refused, Verb
from pridem.verbs.run import one_stack, run_plan_verb
from pridem.verbs.state import ssl_lines, ssl_part

SSL_STACK = machine.EDGE


class SslArgs(Strict):
    action: Literal["renew", "status"]


def _status(ctx: Context) -> int:
    """``ssl status``: read, as ``state`` -- no lock, no journal, no verdict."""
    if ctx.timer:
        raise Refused("ssl status is not run by a timer: --timer does not apply")
    ssl = ssl_part(ctx)
    if ctx.json:
        ctx.out.write(ssl.model_dump_json(indent=2) + "\n")
    else:
        said(ctx.out, "\n".join(ssl_lines(ssl)) + "\n")
    return 0


def _run(args: Strict, ctx: Context) -> int:
    if not isinstance(args, SslArgs):
        raise TypeError("ssl takes SslArgs")
    if args.action == "status":
        return _status(ctx)

    def steps(
        box: Box, run_id: str, fetched: Fetched, secrets: Secrets
    ) -> Sequence[Step]:
        return [SslRenew(fetched=fetched, secrets=secrets, root=ctx.fs_root)]

    return run_plan_verb(
        ctx, verb=f"ssl {args.action}", mode="renew", make=one_stack(SSL_STACK, steps)
    )


SSL = Verb("ssl", SslArgs, _run, positionals=("action",), timer=True)
