"""``up``: the stack entry running on the new images, never by ``down`` (TZ
7.3, 11 item 8; contract 3 rules 4, 9).

``docker compose … up -d --no-build --wait`` with the machine's override: the
project's containers, volumes and network carry ``pridem.*`` labels, ``app``
joins the network ``pridem`` under ``<name>-<app.service>``. Compose recreates
only what changed -- on an update, the application; an unchanged database
stays. No ``down``, no ``rm``, no ``--remove-orphans``: they remove
containers.

``verify`` reads the fact back: the ``app`` container runs on the image built
for this commit, the stack passes conformance (DM-15: ``/health`` by its form,
``/ready`` 200, JSON logs, ``max_body``, no ``logging``), and ``/health`` says
the release and the commit the build got. Then the stack's ``provides`` reach
the plan's seam memory -- after its health (TZ 7.1). ``check`` needs no
``act`` when all of that already holds.
"""

import json
from pathlib import Path
from typing import ClassVar

from pridem.conformance.stack import (
    Observed,
    check_stack,
    observe,
    problems_param,
)
from pridem.events import Json
from pridem.stacks.schema import Product, Service
from pridem.stacks.seams import SeamMemory
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
    UP_WAIT_S,
    ComposeStack,
    image_of,
    out,
    running_image,
)
from pridem.steps.env import RenderEnv

ALL_MODES: frozenset[Mode] = frozenset({"install", "deploy", "reinstall"})


def _document(seen: Observed) -> dict[str, Json]:
    if seen.health is None:
        return {}
    try:
        document = json.loads(seen.health)
    except (UnicodeDecodeError, json.JSONDecodeError):
        return {}
    return document if isinstance(document, dict) else {}


class Up(Step):
    """One stack entry up on the images of this commit, checked live."""

    name = "up"
    order = 10
    modes = ALL_MODES
    codes: ClassVar[dict[str, str]] = {
        "up": "bring {stack} up at {commit}",
        "no-image": "no image of {service} at {commit}: build runs before up",
        "old-image": "{service} runs on {running}, not on {expected}",
        "conformance": "{stack} does not conform: {problems}",
        "release-mismatch": (
            "/health says {release} at {commit}, not {expected_release} at "
            "{expected_commit}"
        ),
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
        memory: SeamMemory | None = None,
        render: RenderEnv | None = None,
    ) -> None:
        self.compose = ComposeStack(stack, entry, release, ref, commit, root)
        self.memory = memory
        self.render = render

    def _expected(self, ctx: StepContext) -> str | None:
        """The image ``app`` must run on: the one built for this commit."""
        app = self.compose.app_service
        if app is None:
            return None
        found = image_of(ctx, self.compose, app)
        return found[0] if len(found) == 1 else None

    def _problems(self, ctx: StepContext) -> tuple[list[str], dict[str, Json]]:
        seen = observe(
            ctx,
            self.compose.stack,
            self.compose.entry,
            release=self.compose.release,
            project=self.compose.project,
            env_file=self.compose.env_file,
        )
        problems = [
            str(p)
            for p in problems_param(
                check_stack(self.compose.stack, self.compose.entry, seen)
            )
        ]
        return problems, _document(seen)

    def check(self, ctx: StepContext) -> CheckResult:
        params: dict[str, Json] = {
            "stack": self.compose.entry,
            "commit": self.compose.commit,
        }
        needed = CheckResult(True, local_code("up", params))
        app = self.compose.app_service
        if app is not None:
            expected = self._expected(ctx)
            if expected is None or running_image(ctx, self.compose, app) != expected:
                return needed
        problems, document = self._problems(ctx)
        if problems or not self._same_release(document):
            return needed
        return CheckResult(False)

    def _same_release(self, document: dict[str, Json]) -> bool:
        if self.compose.app_service is None:
            return True
        return (document.get("release"), document.get("commit")) == (
            self.compose.ref,
            self.compose.commit,
        )

    def act(self, ctx: StepContext, check: CheckResult) -> None:
        out(
            ctx,
            self.compose.argv(
                "up", "-d", "--no-build", "--wait", "--wait-timeout", str(UP_WAIT_S)
            ),
            timeout=UP_WAIT_S + 60,
        )

    def verify(self, ctx: StepContext, check: CheckResult) -> Verified:
        fact: dict[str, Json] = {"stack": self.compose.entry}
        app = self.compose.app_service
        if app is not None:
            expected = self._expected(ctx)
            if expected is None:
                raise StepFailed(
                    "no-image", {"service": app, "commit": self.compose.commit}
                )
            running = running_image(ctx, self.compose, app)
            if running != expected:
                raise StepFailed(
                    "old-image",
                    {
                        "service": app,
                        "expected": expected,
                        "running": running or "none",
                    },
                )
            fact["image"] = expected
        problems, document = self._problems(ctx)
        if problems:
            raise StepFailed(
                "conformance",
                {"stack": self.compose.entry, "problems": list[Json](problems)},
            )
        if not self._same_release(document):
            raise StepFailed(
                "release-mismatch",
                {
                    "release": str(document.get("release")),
                    "commit": str(document.get("commit")),
                    "expected_release": self.compose.ref,
                    "expected_commit": self.compose.commit,
                },
            )
        if app is not None:
            fact.update(
                {
                    "release": self.compose.ref,
                    "commit": self.compose.commit,
                    "health": "ok",
                    "ready": 200,
                }
            )
        if self.memory is not None and self.render is not None:
            self.memory.healthy(self.compose.stack.name, self.render.provided())
        return Verified(fact)
