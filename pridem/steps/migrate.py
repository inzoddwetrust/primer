"""``migrate``: the stack's ``migrate`` on the new image, in a throwaway
container -- the point of no return (TZ 7.3; contract 3 section 1).

The stack is the blank's (TZ 2): its migrations are alembic's. ``check`` reads
the heads of the image ``build`` made for this commit (found by its labels,
the key of ``steps.packages.image_key`` among them)
with ``docker run --rm --network none <image> python -m alembic heads`` -- no
compose, no dependency, no network: the scripts of the image, nothing else. A stack that
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

``stop_for_migrate`` (DM-22, protocol 6.3, contract 3 rule 35) runs just before
``migrate``, before the point of no return: the services of the entry's
``stop_for_migrate`` are stopped when -- and only when -- ``migrate`` will act
(its ``check`` is read), and ``verify`` reads that none of them runs. Stopping
is undone by ``start_stopped`` of ``finally``: a plan that ends before
``migrate`` started its ``act`` starts again what it stopped; once ``migrate``
acted, nothing is started -- see the KNOWN CEILING at ``StartStopped``. After
a green ``migrate`` the services come up by ``up`` of the entry, as every
service does.
"""

import json
import shlex
from dataclasses import dataclass, field
from pathlib import Path
from typing import ClassVar, Protocol

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
from pridem.steps.packages import KEY_CODES, image_key
from pridem.steps.passport import NO_PASSPORT, Fetched

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
    order = 12  # after stop_for_migrate (11, DM-22)
    modes = ALL_MODES
    point_of_no_return = True
    codes: ClassVar[dict[str, str]] = {
        **NO_PASSPORT,
        **KEY_CODES,
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
        fetched: Fetched | None = None,
    ) -> None:
        self.compose = ComposeStack(
            stack, entry, release, ref, commit, root, staged_env=True
        )
        self.fetched = fetched
        stage = stack.stacks[entry]
        if stage.migrate is None or stage.app is None:
            raise ValueError(f"{entry} has no migrate to run in an app container")
        self.command = shlex.split(stage.migrate)
        self.app = stage.app.service
        self.acted = False
        """``act`` has started: the point of no return of this entry is
        crossed, ``start_stopped`` starts nothing for it (DM-22)."""

    def _heads(self, ctx: StepContext) -> tuple[list[str], int]:
        """Heads of the built image, by ``docker run`` on it; and the line count."""
        passport = None if self.fetched is None else self.fetched.passport
        key = image_key(self.compose.stack, self.app, passport)
        images = image_of(ctx, self.compose, self.app, key)
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
            [
                "docker",
                "run",
                "--rm",
                "--network",
                "none",
                *labels,
                images[0],
                *ALEMBIC,
                "heads",
            ],
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
        self.acted = True
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


# --- stop_for_migrate ---------------------------------------------------------------

STOP_TIMEOUT_S = COMMAND_TIMEOUT_S + 60
"""``compose stop`` waits each service's ``stop_grace_period``."""


def running(ctx: StepContext, compose: ComposeStack, services: list[str]) -> list[str]:
    """Those of ``services`` with a running container, sorted."""
    found: list[str] = []
    for service in services:
        _, lines = out(
            ctx,
            compose.argv("ps", "--status", "running", "-q", service),
            timeout=COMMAND_TIMEOUT_S,
        )
        if any(line.strip() for line in lines):
            found.append(service)
    return sorted(found)


class Acting(Protocol):
    """The step services were stopped for: ``acted`` -- its ``act`` began
    (``migrate``; ``db_restore`` of DM-86)."""

    acted: bool


@dataclass
class Stopped:
    """What ``stop_for_migrate`` (or ``stop_for_restore``, DM-86) stopped in
    this run, entry by entry, with the step it stopped them for:
    ``start_stopped`` reads it."""

    entries: list[tuple[ComposeStack, list[str], Acting]] = field(default_factory=list)


class StopForMigrate(Step):
    """The services of ``stop_for_migrate``, stopped before ``migrate`` acts."""

    name = "stop_for_migrate"
    order = 11
    modes = ALL_MODES
    rechecked = False  # ``up`` brings the stopped back: the final check would
    # read them running and call the step red (DM-22 FIX, tier 3)
    codes: ClassVar[dict[str, str]] = {
        "stop": "stop {services} of {stack} for its migration",
        "stop-failed": "{services} of {stack} still run after stop",
    }

    def __init__(self, migrate: Migrate, stopped: Stopped) -> None:
        self.migrate = migrate
        self.compose = migrate.compose
        stage = self.compose.stack.stacks[self.compose.entry]
        self.services = list(stage.stop_for_migrate)
        self.stopped = stopped

    def check(self, ctx: StepContext) -> CheckResult:
        """Nothing to stop without a list, or when ``migrate`` has nothing to
        do -- its ``check`` decides, read here before it runs."""
        if not self.services or not self.migrate.check(ctx).needed:
            return CheckResult(False, None, {})
        params: dict[str, Json] = {
            "stack": self.compose.entry,
            "services": list[Json](self.services),
        }
        return CheckResult(True, local_code("stop", params), {"stop": True})

    def act(self, ctx: StepContext, check: CheckResult) -> None:
        # recorded before the command: a stop that fails half-way is started
        # again by ``start_stopped`` all the same
        self.stopped.entries.append((self.compose, self.services, self.migrate))
        out(
            ctx,
            self.compose.argv("stop", *self.services),
            timeout=STOP_TIMEOUT_S,
        )

    def verify(self, ctx: StepContext, check: CheckResult) -> Verified:
        if not check.data.get("stop"):
            return Verified({"stack": self.compose.entry, "stopped": []})
        still = running(ctx, self.compose, self.services)
        if still:
            params: dict[str, Json] = {
                "stack": self.compose.entry,
                "services": list[Json](still),
            }
            raise StepFailed("stop-failed", params)
        return Verified(
            {"stack": self.compose.entry, "stopped": list[Json](self.services)}
        )


class StartStopped(Step):
    """``finally``: what ``stop_for_migrate`` stopped, started again where the
    entry's ``migrate`` never began its ``act``.

    KNOWN CEILING (DM-22):
    1. mechanics: a red ``migrate`` -- or any red step after it -- leaves the
       services of ``stop_for_migrate`` stopped; the verdict names them in the
       fact of ``stop_for_migrate``, and nothing on the box starts them;
    2. status: acknowledged by design;
    3. task: DM-87 (the retries of ``migrate`` and the dump before it);
    4. trigger: DM-87 lands -- ``migrate`` is retried, the database dumped
       before it, ``install --restore`` exists;
    5. agreed form of the fix: three tries of ``migrate``, then ``install
       --restore`` (protocol 6.5);
    6. rejected: starting the old code again on a schema that may be half
       migrated -- worse than keeping it stopped.
    """

    name = "start_stopped"
    order = 1
    modes = ALL_MODES | {"command"}  # db restore stops too (DM-86)
    codes: ClassVar[dict[str, str]] = {
        "start": "start {services} of {stack} again: what they stopped for never acted",
        "start-failed": "{services} of {stack} do not run after start",
    }

    def __init__(self, stopped: Stopped) -> None:
        self.stopped = stopped

    def _due(self) -> list[tuple[ComposeStack, list[str]]]:
        return [
            (compose, services)
            for compose, services, step in self.stopped.entries
            if not step.acted
        ]

    def check(self, ctx: StepContext) -> CheckResult:
        due = self._due()
        if not due:
            return CheckResult(False, None, {})
        params: dict[str, Json] = {
            "stack": ", ".join(compose.entry for compose, _ in due),
            "services": [s for _, services in due for s in services],
        }
        return CheckResult(True, local_code("start", params), {"start": True})

    def act(self, ctx: StepContext, check: CheckResult) -> None:
        for compose, services in self._due():
            out(ctx, compose.argv("start", *services), timeout=STOP_TIMEOUT_S)

    def verify(self, ctx: StepContext, check: CheckResult) -> Verified:
        started: dict[str, Json] = {}
        for compose, services in self._due():
            down = sorted(set(services) - set(running(ctx, compose, services)))
            if down:
                params: dict[str, Json] = {
                    "stack": compose.entry,
                    "services": list[Json](down),
                }
                raise StepFailed("start-failed", params)
            started[compose.entry] = list[Json](services)
        return Verified({"started": started})
