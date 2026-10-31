"""``migrate``: the stack's ``migrate`` on the new image, in a throwaway
container -- the point of no return (TZ 7.3; contract 3 section 1).

The stack is the blank's (TZ 2): its migrations are alembic's. ``check`` reads
the heads of the new image with ``python -m alembic heads`` in a throwaway
container that starts nothing else (``run --rm --no-deps``): more than one
head is red before anything is written. One head is compared with the
revision the running application reports (``/health.alembic_head``, TZ 11,
read by ``observe`` of DM-15): the same -- no ``act``, the point of no return
is not crossed; another, no answer, no running ``app`` (a first install) --
``act``. ``check`` starts no database.

``act`` runs the declared ``migrate`` in ``run --rm <app>`` -- its database
comes up by ``depends_on`` -- and ``verify`` reads ``alembic current`` back:
it must be the head. Once ``act`` has started, nothing automatic undoes it: a
red step after it ends the plan with "restore needed".
"""

import json
import shlex
from pathlib import Path
from typing import ClassVar

from pridem.conformance.stack import observe
from pridem.events import Json
from pridem.stacks.schema import Product, Service
from pridem.steps.base import (
    CheckResult,
    Mode,
    Step,
    StepContext,
    StepFailed,
    Verified,
    local_code,
)
from pridem.steps.compose import COMMAND_TIMEOUT_S, ComposeStack, current, heads, out

ALL_MODES: frozenset[Mode] = frozenset({"install", "deploy", "reinstall"})
MIGRATE_TIMEOUT_S = 1800
ALEMBIC = ("python", "-m", "alembic")


def running_head(ctx: StepContext, compose: ComposeStack) -> str | None:
    """``/health.alembic_head`` of the running app; ``None`` -- nothing said it."""
    seen = observe(
        ctx,
        compose.stack,
        compose.entry,
        release=compose.release,
        project=compose.project,
        env_file=compose.env_file,
    )
    if seen.health is None:
        return None
    try:
        document = json.loads(seen.health)
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None
    head = document.get("alembic_head") if isinstance(document, dict) else None
    return head if isinstance(head, str) else None


class Migrate(Step):
    """The stack's migrations, once, on the image of the new commit."""

    name = "migrate"
    order = 9
    modes = ALL_MODES
    point_of_no_return = True
    codes: ClassVar[dict[str, str]] = {
        "migrate": "migrate {stack} to {head}",
        "alembic-heads": "the migrations of {stack} have {count} heads: {heads}",
        "not-at-head": "the database of {stack} is at {current}, not at {head}",
    }

    def __init__(
        self,
        stack: Product | Service,
        entry: str,
        *,
        release: Path,
        ref: str,
        commit: str,
        root: Path = Path("/"),
    ) -> None:
        self.compose = ComposeStack(stack, entry, release, ref, commit, root)
        stage = stack.stacks[entry]
        if stage.migrate is None or stage.app is None:
            raise ValueError(f"{entry} has no migrate to run in an app container")
        self.command = shlex.split(stage.migrate)
        self.app = stage.app.service

    def _alembic(self, ctx: StepContext, *args: str, deps: bool) -> list[str]:
        throwaway = ["run", "--rm"] if deps else ["run", "--rm", "--no-deps"]
        _, lines = out(
            ctx,
            self.compose.argv(*throwaway, self.app, *ALEMBIC, *args),
            timeout=COMMAND_TIMEOUT_S,
        )
        return lines

    def check(self, ctx: StepContext) -> CheckResult:
        found = heads(self._alembic(ctx, "heads", deps=False))
        if len(found) > 1:
            raise StepFailed(
                "alembic-heads",
                {
                    "stack": self.compose.entry,
                    "count": len(found),
                    "heads": list[Json](found),
                },
            )
        if not found:
            return CheckResult(False, None, {"heads": 0})
        head = found[0]
        data: dict[str, Json] = {"head": head}
        if running_head(ctx, self.compose) == head:
            return CheckResult(False, None, data)
        params: dict[str, Json] = {"stack": self.compose.entry, "head": head}
        return CheckResult(True, local_code("migrate", params), data)

    def act(self, ctx: StepContext, check: CheckResult) -> None:
        out(
            ctx,
            self.compose.argv("run", "--rm", self.app, *self.command),
            timeout=MIGRATE_TIMEOUT_S,
        )

    def verify(self, ctx: StepContext, check: CheckResult) -> Verified:
        head = check.data.get("head")
        if not isinstance(head, str):
            return Verified({"alembic_heads": 0})
        now = current(self._alembic(ctx, "current", deps=True))
        if now != [head]:
            raise StepFailed(
                "not-at-head",
                {
                    "stack": self.compose.entry,
                    "head": head,
                    "current": ",".join(now) or "none",
                },
            )
        return Verified({"alembic_head": head})
