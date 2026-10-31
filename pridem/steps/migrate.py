"""``migrate``: the stack's ``migrate`` on the new image, in a throwaway
container -- the point of no return (TZ 7.3; contract 3 section 1).

The stack is the blank's (TZ 2): its migrations are alembic's. ``check`` reads
the heads of the image ``build`` made for this commit (found by its labels)
with ``docker run --rm <image> python -m alembic heads`` -- no compose, no
dependency, no network: the scripts of the image, nothing else. A stack that
declares ``migrate`` has a head: none read is red (``no-heads``), never "no
migration"; more than one is red too -- both before anything is written. One
head is compared with the
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
from pridem.steps.compose import (
    COMMAND_TIMEOUT_S,
    ComposeStack,
    current,
    heads,
    image_of,
    out,
)

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
        "no-heads": "no alembic head read from the image of {stack} in {lines} lines",
        "no-image": "no image of {service} at {commit}: build runs before migrate",
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

    def _heads(self, ctx: StepContext) -> tuple[list[str], int]:
        """Heads of the built image, by ``docker run`` on it; and the line count."""
        images = image_of(ctx, self.compose, self.app)
        if len(images) != 1:
            raise StepFailed(
                "no-image", {"service": self.app, "commit": self.compose.commit}
            )
        labels = [
            word
            for key, value in self.compose.release_labels().items()
            for word in ("--label", f"{key}={value}")
        ]
        _, lines = out(
            ctx,
            ["docker", "run", "--rm", *labels, images[0], *ALEMBIC, "heads"],
            timeout=COMMAND_TIMEOUT_S,
        )
        return heads(lines), len(lines)

    def _current(self, ctx: StepContext) -> list[str]:
        _, lines = out(
            ctx,
            self.compose.argv("run", "--rm", self.app, *ALEMBIC, "current"),
            timeout=COMMAND_TIMEOUT_S,
        )
        return current(lines)

    def check(self, ctx: StepContext) -> CheckResult:
        found, read = self._heads(ctx)
        if not found:
            raise StepFailed("no-heads", {"stack": self.compose.entry, "lines": read})
        if len(found) > 1:
            raise StepFailed(
                "alembic-heads",
                {
                    "stack": self.compose.entry,
                    "count": len(found),
                    "heads": list[Json](found),
                },
            )
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
            raise RuntimeError("migrate verifies after a check that read a head")
        now = self._current(ctx)
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
