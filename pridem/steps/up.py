"""``up``: the stack entry running on the new images, never by ``down`` (TZ
7.3, 11 item 8; contract 3 rules 4, 9).

``docker compose … up -d --no-build --wait`` with the machine's override: the
project's containers, volumes and network carry ``pridem.*`` labels, ``app``
joins the network ``pridem`` under ``<name>-<app.service>``. Compose recreates
only what changed -- on an update, the application; an unchanged database
stays. No ``down``, no ``rm``, no ``--remove-orphans``: they remove
containers.

``verify`` reads the fact back: the ``app`` container runs on the image built
for this commit, and so does every service of the entry a package is built
into, on the image of its key (``steps.packages.image_key``: edition and
package versions) -- on one commit only those change, so ``check`` acts when
any of them runs on another image (DM-61 FIX); every service of the entry
runs on its configuration -- the hash compose stamps on a container
(``com.docker.compose.config-hash``) is the one ``config --hash`` gives the
product's file with the override now; a package of another version (apply:
runtime) or another environment changes it on the same image (DM-58); the
stack passes
conformance (DM-15: ``/health`` by its form, ``/ready`` 200, JSON logs,
``max_body``, no ``logging``), and ``/health`` says
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
    Waiting,
    local_code,
    wait_until,
)
from pridem.steps.compose import (
    REFUSAL_CODES,
    UP_WAIT_S,
    ComposeStack,
    config,
    image_of,
    out,
    running_image,
    stale,
)
from pridem.steps.env import RenderEnv
from pridem.steps.packages import KEY_CODES, image_key
from pridem.steps.passport import NO_PASSPORT, Fetched

ALL_MODES: frozenset[Mode] = frozenset({"install", "deploy", "reinstall"})
READY = Waiting(deadline_s=120, poll_s=2)
"""How long ``verify`` reads the live checks again after ``up``: past the
healthcheck ``up --wait`` waited for (``UP_WAIT_S``), what is left is an
application without one -- a cold start of the server and its first
connections, well inside two minutes (DM-80)."""


def _document(seen: Observed) -> dict[str, Json]:
    if seen.health is None:
        return {}
    try:
        document = json.loads(seen.health)
    except (UnicodeDecodeError, json.JSONDecodeError):
        return {}
    return document if isinstance(document, dict) else {}


class Up(Step):
    """One stack entry up on the images of this commit and key, checked live."""

    name = "up"
    order = 13  # after egress (12): the application starts with its proxy ready
    modes = ALL_MODES
    codes: ClassVar[dict[str, str]] = {
        **REFUSAL_CODES,
        **NO_PASSPORT,
        **KEY_CODES,
        "up": "bring {stack} up at {commit}",
        "no-image": "no image of {service} at {commit}: build runs before up",
        "old-image": "{service} runs on {running}, not on {expected}",
        "old-config": "{service} runs on configuration {running}, not on {expected}",
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
        fetched: Fetched | None = None,
        waiting: Waiting = READY,
    ) -> None:
        self.compose = ComposeStack(stack, entry, release, ref, commit, root)
        self.fetched = fetched
        self.memory = memory
        self.render = render
        self.waiting = waiting

    def _watched(self, ctx: StepContext) -> list[str]:
        """The services whose image ``up`` checks: ``app``, and every service
        of this entry a package is built into (``apply: build``) -- on one
        commit only those get a new image, by a new version or edition. Which
        services the entry has is its ``config``, read only when the product
        builds a package in."""
        app = self.compose.app_service
        watched = [] if app is None else [app]
        stack = self.compose.stack
        places = (
            {place.service for slot in stack.packages.values() for place in slot.build}
            if isinstance(stack, Product)
            else set()
        )
        places.discard(app)
        if places:
            services = config(ctx, self.compose).get("services")
            known = set(services) if isinstance(services, dict) else set()
            watched += sorted(places & known)
        return watched

    def _expected(self, ctx: StepContext, service: str) -> str | None:
        """The image ``service`` must run on: the one built for this commit and,
        when a package is built into it, its key."""
        passport = None if self.fetched is None else self.fetched.passport
        key = image_key(self.compose.stack, service, passport)
        found = image_of(ctx, self.compose, service, key)
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
        for service in self._watched(ctx):
            expected = self._expected(ctx, service)
            if (
                expected is None
                or running_image(ctx, self.compose, service) != expected
            ):
                return needed
        if stale(ctx, self.compose):
            return needed
        problems, document = self._problems(ctx)
        if problems or not self._same_release(document):
            return needed
        self._provide()
        return CheckResult(False)

    def _provide(self) -> None:
        """The stack's ``provides`` to the plan's memory, read from its
        ``.env`` as ``render_env`` reads it back.

        ``check`` calls it only where it found nothing to do: the stack runs on
        this commit's image and configuration, and its live ``/health`` passed
        conformance -- the health rule 21 asks for. ``doctor`` runs ``check``
        alone, and a product's seam from this stack is resolved from the
        memory; without this its ``render_env`` is ``seam-before-health`` on
        every box (DM-59 FIX). In a run, ``verify`` puts the same values again.
        """
        if self.memory is not None and self.render is not None:
            self.render.read_back(waiting=())
            self.memory.healthy(self.compose.stack.name, self.render.provided())

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
        built: dict[str, Json] = {}
        for service in self._watched(ctx):
            expected = self._expected(ctx, service)
            if expected is None:
                raise StepFailed(
                    "no-image", {"service": service, "commit": self.compose.commit}
                )
            running = running_image(ctx, self.compose, service)
            if running != expected:
                raise StepFailed(
                    "old-image",
                    {
                        "service": service,
                        "expected": expected,
                        "running": running or "none",
                    },
                )
            if service == app:
                fact["image"] = expected
            else:
                built[service] = expected
        if built:
            fact["built"] = built
        behind = stale(ctx, self.compose)
        if behind:
            service = min(behind)
            expected, running = behind[service]
            raise StepFailed(
                "old-config",
                {"service": service, "expected": expected, "running": running},
            )
        # ``up --wait`` waited for a healthcheck the compose file declares; an
        # application without one may still be starting: its live checks are
        # read again until they pass or READY_WAIT_S ends (DM-80)
        seen: list[tuple[list[str], dict[str, Json]]] = []

        def conforms() -> bool:
            seen[:] = [self._problems(ctx)]
            problems, document = seen[0]
            return not problems and self._same_release(document)

        wait_until(ctx, conforms, self.waiting)
        problems, document = seen[0]
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
