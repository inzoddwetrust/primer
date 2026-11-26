"""``pridem register [--panel <url>]``: the box's key and its registration in
the Panel by a one-time token (``PRIMER-PANEL-TZ-2`` 4, DM-139).

The token comes from the environment, ``PRIDEM_REGISTER_TOKEN``, never from
the command line: argv is anyone's to read in ``ps``, a root process's
environment is root's. It is a secret of the run (``Secrets``): never in the
verdict's ``args``, cleaned from the journal and the console. The request
tells the Panel the server's name, its role and the product's repository from
the box's passport copy -- a box without one, or without a token of a
secret's length, is refused before the lock, with no verdict.

Under the lock one stack, ``pridem-identity``: ``box_key``, then
``register`` (``pridem/steps/identity.py``). A verdict always: the agent and
the Panel read the registration's outcome from ``history/`` as any other.
Re-registering a registered box is not this verb's: ``register:already``.
"""

import os
from collections.abc import Callable, Sequence
from datetime import UTC, datetime
from typing import Annotated

from pydantic import AfterValidator, SecretStr

from pridem import __version__
from pridem.contract import SECRET_MIN_LENGTH, Strict
from pridem.events import Secrets
from pridem.stacks import names as machine
from pridem.state import Box
from pridem.steps.base import Step
from pridem.steps.identity import (
    DEFAULT_PANEL,
    Applicant,
    BoxKey,
    HttpTransport,
    Register,
    Transport,
    panel_origin,
)
from pridem.steps.passport import Fetched
from pridem.verbs.base import Context, Refused, Verb
from pridem.verbs.run import one_stack, read_copy, run_plan_verb

TOKEN_ENV = "PRIDEM_REGISTER_TOKEN"  # noqa: S105 -- the name of a variable


class RegisterArgs(Strict):
    """``--panel``: the Panel's origin."""

    panel: Annotated[str, AfterValidator(panel_origin)] = DEFAULT_PANEL


def make_register(
    transport: Callable[[], Transport] = HttpTransport,
    owner: Callable[[], int] = os.geteuid,
    now: Callable[[], datetime] = lambda: datetime.now(UTC),
) -> Verb:
    """The verb with its way to the Panel, the owner its files must have and
    its clock -- a test gives its own."""

    def _run(args: Strict, ctx: Context) -> int:
        if not isinstance(args, RegisterArgs):
            raise TypeError("register takes RegisterArgs")
        token = os.environ.get(TOKEN_ENV, "")
        if not token:
            raise Refused(
                f"register: no token -- set {TOKEN_ENV} to the one-time token "
                "of the Panel"
            )
        if len(token) < SECRET_MIN_LENGTH:
            raise Refused(
                f"register: {TOKEN_ENV} is shorter than {SECRET_MIN_LENGTH} "
                "characters: not a token of the Panel"
            )
        copy = read_copy(ctx)
        passport = copy.passport
        if passport is None:
            raise Refused(
                "register: the box has no passport copy -- the Panel is told "
                "the server's name, role and product from it; install first"
            )
        applicant = Applicant(
            server_name=passport.server.name,
            role=passport.server.role,
            product_repo=passport.product.repo,
            machine_version=__version__,
        )
        root = ctx.root

        def steps(
            box: Box, run_id: str, fetched: Fetched, secrets: Secrets
        ) -> Sequence[Step]:
            secrets.add([SecretStr(token)])  # before any line could carry it
            uid = owner()
            return [
                BoxKey(root, uid),
                Register(
                    root,
                    panel=args.panel,
                    token=token,
                    applicant=applicant,
                    transport=transport(),
                    owner=uid,
                    now=now,
                ),
            ]

        return run_plan_verb(
            ctx,
            verb="register",
            mode="command",
            make=one_stack(machine.IDENTITY, steps),
            args={"panel": args.panel},
            copy=copy,
        )

    return Verb(
        "register",
        RegisterArgs,
        _run,
        options={"--panel": ("panel", "value")},
        group="server",
    )


REGISTER = make_register()
