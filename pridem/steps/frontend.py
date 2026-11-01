"""``frontend``: the product's front answers on its domain (TZ 6.2 item 6).

The front is built with the stack (``build``, DM-18) and its packages are
validated and mounted before ``up`` (``packages``); this step closes the front
of the plan: nginx reloads after its config test (the packages may have
replaced what the front serves), then ``https://<frontend domain>/`` asked on
the box itself answers 200. The domain is the passport's for the route that
goes to a stack's declared ``frontend``; a product without one has nothing to
ask.
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
    local_code,
)
from pridem.steps.compose import out
from pridem.steps.passport import NO_PASSPORT, Fetched
from pridem.steps.ssl import reload_nginx

ALL_MODES: frozenset[Mode] = frozenset({"install", "deploy", "reinstall"})
CURL_TIMEOUT_S = 15


class Frontend(Step):
    """The front, reloaded and answering 200 on its domain."""

    name = "frontend"
    order = 1
    modes = ALL_MODES
    codes: ClassVar[dict[str, str]] = {
        **NO_PASSPORT,
        "reload": "reload nginx for the front of {domain}",
        "not-200": "https://{domain}/ answers {status}",
        "config-invalid": "nginx -t is red in {where}; nothing reloaded",
    }

    def __init__(
        self, product: Product, *, fetched: Fetched, root: Path = Path("/")
    ) -> None:
        self.product = product
        self.fetched = fetched
        self.root = root

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
        return CheckResult(True, local_code("reload", {"domain": domain}))

    def act(self, ctx: StepContext, check: CheckResult) -> None:
        reload_nginx(ctx, self.root)

    def verify(self, ctx: StepContext, check: CheckResult) -> Verified:
        domain = self._domain()
        if domain is None:
            return Verified({"frontend": "none"})
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
        status = lines[-1].strip() if lines else "000"
        if status != "200":
            raise StepFailed("not-200", {"domain": domain, "status": status})
        result: dict[str, Json] = {"domain": domain, "status": 200}
        return Verified(result)
