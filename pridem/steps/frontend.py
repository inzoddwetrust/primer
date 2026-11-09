"""``frontend``: the product's front answers on its domain (TZ 6.2 item 6).

The front is built with the stack (``build``, DM-18) and its packages are
validated and mounted before ``up`` (``packages``); this step closes the front
of the plan by its live answer: ``https://<frontend domain>/`` asked on the box
itself. 200 -- nothing to do: nginx reaches the front through its resolver
(``set $upstream``), a recreated container is picked up without a reload, and
a changed config is the ``nginx`` step's to test and reload (DM-17). Anything
else -- nginx is reloaded after its config test, and the front must answer 200
then. The status is what counts, never curl's exit code: without ``-f`` it is
0 on a 502 too. The domain is the passport's for the route that goes to a
stack's declared ``frontend``; a product without one has nothing to ask.
"""

from pathlib import Path
from typing import ClassVar

from pridem.events import Json
from pridem.stacks.routes import targets
from pridem.stacks.schema import Product
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
from pridem.steps.compose import out
from pridem.steps.passport import NO_PASSPORT, Fetched
from pridem.steps.ssl import reload_nginx

ALL_MODES: frozenset[Mode] = frozenset({"install", "deploy", "reinstall"})
CURL_TIMEOUT_S = 15
READY = Waiting(deadline_s=60, poll_s=2)
"""How long ``verify`` asks the front again after the reload: nginx answers at
once, the front's container may still be starting (DM-80)."""


class Frontend(Step):
    """The front, reloaded and answering 200 on its domain."""

    name = "frontend"
    order = 1
    modes = ALL_MODES
    codes: ClassVar[dict[str, str]] = {
        **NO_PASSPORT,
        "reload": "reload nginx: the front of {domain} answers {status}",
        "not-200": "https://{domain}/ answers {status}",
        "config-invalid": "nginx -t is red in {where}; nothing reloaded",
    }

    def __init__(
        self,
        product: Product,
        *,
        fetched: Fetched,
        root: Path = Path("/"),
        waiting: Waiting = READY,
    ) -> None:
        self.product = product
        self.fetched = fetched
        self.root = root
        self.waiting = waiting

    def _domain(self) -> str | None:
        passport = self.fetched.passport
        if passport is None:
            raise StepFailed("no-passport")
        for route, target in targets(self.product).items():
            stage = self.product.stacks[target.entry]
            front = stage.frontend
            if front is not None and (front.service, front.port) == (
                target.service,
                target.port,
            ):
                return passport.domains.get(route)
        return None

    def check(self, ctx: StepContext) -> CheckResult:
        domain = self._domain()
        if domain is None:
            return CheckResult(False)
        status = self._status(ctx, domain)
        if status == "200":
            return CheckResult(False)
        return CheckResult(
            True, local_code("reload", {"domain": domain, "status": status})
        )

    def _status(self, ctx: StepContext, domain: str) -> str:
        """The HTTP status the front answers on the box; ``000`` -- no answer."""
        body = self.root / "opt" / "pridem" / "edge" / "frontend-probe"
        body.parent.mkdir(parents=True, exist_ok=True)
        try:
            _, lines = out(
                ctx,
                [
                    "curl",
                    "-k",
                    "-sS",
                    "--max-time",
                    str(CURL_TIMEOUT_S),
                    "--resolve",
                    f"{domain}:443:127.0.0.1",
                    "-o",
                    str(body),
                    "-w",
                    "%{http_code}",
                    f"https://{domain}/",
                ],
                expect=(0, 7, 28, 35, 52, 56),
            )
        finally:
            body.unlink(missing_ok=True)
        return lines[-1].strip() if lines else "000"

    def act(self, ctx: StepContext, check: CheckResult) -> None:
        reload_nginx(ctx, self.root)

    def verify(self, ctx: StepContext, check: CheckResult) -> Verified:
        domain = self._domain()
        if domain is None:
            return Verified({"frontend": "none"})
        seen: list[str] = []

        def answers() -> bool:
            seen[:] = [self._status(ctx, domain)]
            return seen[0] == "200"

        if not wait_until(ctx, answers, self.waiting):
            raise StepFailed("not-200", {"domain": domain, "status": seen[0]})
        result: dict[str, Json] = {"domain": domain, "status": 200}
        return Verified(result)
