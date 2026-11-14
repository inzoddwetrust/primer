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

An entry with ``jobs`` (contract 3 rule 24, DM-22) comes up in the order of
``depends_on`` of its compose: for each job, in that order, the services it
needs (all it depends on, through any but jobs) ``up --no-deps --wait``, then
the job ``run --rm --no-deps`` -- its output goes to the journal, a code but 0
is red and nothing after it runs; last, every service but the jobs ``up
--no-deps --wait``. No service depends on a job in compose (``forbidden``):
the order is the machine's, and compose would run the job again as a
dependency -- under ``--no-deps`` too, and in ``run --rm <app>`` of
``migrate`` (DM-22 FIX, measured on tier 3). A job runs whenever ``up`` of
its entry acts -- on a deploy that changes the entry: every service carries
``pridem.commit`` in its configuration, so a new commit acts, and so does a
changed environment (a value the passport puts in it), new data or a package;
the passport's number alone changes nothing in the entry (FIX 2). An update
with nothing changed does not act, and ``doctor`` -- which ``stale`` leaves
the jobs out of -- has nothing to say.
"""

import json
from collections.abc import Sequence
from pathlib import Path
from typing import ClassVar

from pridem.conformance.stack import (
    Observed,
    check_stack,
    observe,
    problems_param,
)
from pridem.events import Json
from pridem.runner import Stream
from pridem.stacks.schema import Product, Service
from pridem.stacks.seams import Pair, SeamMemory
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
    job_services,
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


INSPECT_FORMAT = "{{.Name}} {{len .Containers}}"
JOB_TIMEOUT_S = UP_WAIT_S + 60
"""A job's ``run``: as long as ``up`` may wait, and a minute."""


def _depends(body: Json) -> list[str]:
    """The services ``depends_on`` names in ``config`` (a mapping there)."""
    found = body.get("depends_on") if isinstance(body, dict) else None
    return sorted(found) if isinstance(found, dict) else []


def job_order(document: dict[str, Json], jobs: frozenset[str]) -> list[str]:
    """The jobs of ``document`` in the order of ``depends_on`` (compose has no
    cycle), each tie by name: of the services nothing still waits for, the
    first by name goes first."""
    services = document.get("services")
    graph = {
        name: set(_depends(body))
        for name, body in (services.items() if isinstance(services, dict) else ())
    }
    order: list[str] = []
    while graph:
        ready = sorted(name for name, needs in graph.items() if not needs & set(graph))
        if not ready:  # a cycle: compose refuses it before up runs
            break
        order.append(ready[0])
        del graph[ready[0]]
    return [name for name in order if name in jobs]


def needed_by(document: dict[str, Json], job: str, jobs: frozenset[str]) -> list[str]:
    """Every service but a job that ``job`` depends on, directly or through
    another such service, sorted; the jobs on its way ran before it."""
    services = document.get("services")
    graph = {
        name: _depends(body)
        for name, body in (services.items() if isinstance(services, dict) else ())
    }
    seen: set[str] = set()
    todo = list(graph.get(job, []))
    while todo:
        name = todo.pop()
        if name in seen or name in jobs:
            continue
        seen.add(name)
        todo += graph.get(name, [])
    return sorted(seen)


def _lines(ctx: StepContext, argv: list[str]) -> list[str]:
    found: list[str] = []

    def keep(stream: Stream, line: str, cut: bool) -> None:
        if stream is Stream.STDOUT and line.strip():
            found.append(line.strip())

    ctx.runner.run(argv, timeout=60, on_line=keep)
    return found


def _json_list(value: Json) -> list[Json]:
    return list(value) if isinstance(value, list) else []


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
    order = 14  # after egress (13): the application starts with its proxy ready
    modes = ALL_MODES
    codes: ClassVar[dict[str, str]] = {
        **REFUSAL_CODES,
        **NO_PASSPORT,
        **KEY_CODES,
        "up": "bring {entry} up at {commit}",
        "pair-networks": "remove {networks}: networks of pairs of {entry} no more",
        "pair-networks-left": "networks of pairs no more are still there: {networks}",
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
        points: Sequence[Pair] = (),
    ) -> None:
        self.compose = ComposeStack(
            stack, entry, release, ref, commit, root, staged=True
        )
        self.points = list(points)  # the pairs of the box (DM-62)
        self.fetched = fetched
        self.memory = memory
        self.render = render
        self.waiting = waiting
        self._ran: list[str] = []  # the jobs ``act`` ran, in order (DM-22)

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

    def _gone_pairs(self, ctx: StepContext) -> list[str]:
        """The networks of this provider's pairs that are no more: labelled
        ``pridem.point`` with its ``pridem.stack``, not among its pairs now,
        no container on them (DM-62). One still holding a container -- a
        consumer leaving in this very run, started after its provider -- is
        left to the next run. Only an entry that exposes points looks."""
        if not self.compose.stack.stacks[self.compose.entry].expose:
            return []
        mine = f"label=pridem.stack={self.compose.stack_labels()['pridem.stack']}"
        names = _lines(
            ctx,
            [
                "docker", "network", "ls", "--filter", mine,
                "--filter", "label=pridem.point", "--format", "{{.Name}}",
            ],
        )  # fmt: skip
        now = {p.network for p in self.points if p.provider == self.compose.entry}
        others = sorted(set(names) - now)
        if not others:
            return []
        held = _lines(
            ctx,
            ["docker", "network", "inspect", "--format", INSPECT_FORMAT, *others],
        )
        empty = {
            name
            for name, _, count in (line.partition(" ") for line in held)
            if count == "0"
        }
        return [name for name in others if name in empty]

    def _taken(self, ctx: StepContext, check: CheckResult) -> dict[str, Json]:
        """The networks ``act`` took, read back: none of them is still there;
        the fact says how many (``par0`` §10)."""
        gone = _json_list(check.data.get("gone"))
        if not gone:
            return {}
        left = self._gone_pairs(ctx)
        if left:
            raise StepFailed("pair-networks-left", {"networks": list[Json](left)})
        return {"pair_networks_removed": len(gone)}

    def check(self, ctx: StepContext) -> CheckResult:
        params: dict[str, Json] = {
            "entry": self.compose.entry,
            "commit": self.compose.commit,
        }
        gone = self._gone_pairs(ctx)
        needed = CheckResult(True, local_code("up", params), {"gone": list[Json](gone)})
        result = self._check(ctx, needed)
        if result.needed or not gone:
            return result
        pairs_only: dict[str, Json] = {
            "entry": self.compose.entry,
            "networks": list[Json](gone),
        }
        return CheckResult(
            True,
            local_code("pair-networks", pairs_only),
            {"gone": list[Json](gone), "up": False},
        )

    def _check(self, ctx: StepContext, needed: CheckResult) -> CheckResult:
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
        """The stack's ``provides`` to the plan's memory, read from the
        deploy's ``next.env`` as ``render_env`` reads it back (DM-68).

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

    def _up(self, ctx: StepContext, *services: str) -> None:
        argv = ["up", "-d", "--no-build", "--wait", "--wait-timeout", str(UP_WAIT_S)]
        if services:  # an entry with jobs names what comes up (DM-22)
            argv.append("--no-deps")
        out(ctx, self.compose.argv(*argv, operands=services), timeout=UP_WAIT_S + 60)

    def _with_jobs(self, ctx: StepContext, jobs: frozenset[str]) -> list[str]:
        """The jobs, each after what it needs; then every other service. The
        jobs run, in their order -- the fact of ``verify``."""
        document = config(ctx, self.compose)
        ran: list[str] = []
        for job in job_order(document, jobs):
            needed = needed_by(document, job, jobs)
            if needed:
                self._up(ctx, *needed)
            out(
                ctx,
                self.compose.argv("run", "--rm", "--no-deps", operands=(job,)),
                timeout=JOB_TIMEOUT_S,
            )
            ran.append(job)
        services = document.get("services")
        rest = sorted(set(services) - jobs) if isinstance(services, dict) else []
        if rest:  # an entry of jobs alone has nothing to keep running
            self._up(ctx, *rest)
        return ran

    def act(self, ctx: StepContext, check: CheckResult) -> None:
        self._ran = []
        if check.data.get("up", True):
            jobs = job_services(self.compose)
            if jobs:
                self._ran = self._with_jobs(ctx, jobs)
            else:
                self._up(ctx)
        gone = [str(name) for name in _json_list(check.data.get("gone"))]
        if gone:  # exactly the ones check found (DM-62)
            out(ctx, ["docker", "network", "rm", *gone])

    def verify(self, ctx: StepContext, check: CheckResult) -> Verified:
        fact: dict[str, Json] = {"stack": self.compose.entry, **self._taken(ctx, check)}
        if self._ran:  # each one's code 0, read by the runner (DM-22)
            fact["jobs"] = list[Json](self._ran)
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
