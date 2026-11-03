"""``nginx``: the box's nginx from ``host.routes`` (TZ 7.3; contract 3 rules
4, 15).

The config is rendered (``stacks/routes.py``) and compared with the live file
``/opt/pridem/edge/nginx/pridem.conf`` normalized -- comments and blanks are not
drift; a domain is. ``doctor`` shows the diff of the normalized texts.

A new config is tested before it is put in place: written to a candidate
directory and checked by ``nginx -t`` in a throwaway container of the same
image, the candidate mounted where the live config would be. Red -- the live
file is untouched and nothing is reloaded. Green -- the live file is replaced
atomically, then the running nginx reloads (``exec -T nginx nginx -s reload``),
or ``up -d nginx`` starts it. At no moment does a broken config lie where a
restarting nginx would read it.

On a ``preview`` box the secret of the link is minted once
(``/opt/pridem/keys/preview-link``, 0600) and enters the run's ``Secrets``
before anything that could carry it: the config holds it and is 0600.
"""

from pathlib import Path
from typing import ClassVar

from pydantic import SecretStr

from pridem.events import Json, Secrets
from pridem.stacks.env import MINTED_FORM, mint
from pridem.stacks.routes import drift, normalized, render
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
from pridem.steps.edge import (
    NGINX_IMAGE,
    STACK_LABEL,
    argv,
    candidate_dir,
    certs_dir,
    compose_file,
    compose_text,
    live_config,
    mode_of,
    write_file,
)
from pridem.steps.git import KEYS
from pridem.steps.passport import NO_PASSPORT, Fetched

ALL_MODES: frozenset[Mode] = frozenset({"install", "deploy", "reinstall"})
PREVIEW_SECRET = KEYS / "preview-link"
DIFF_LINES = 60


class Nginx(Step):
    """The box's nginx: rendered, tested aside, then put in place and reloaded."""

    name = "nginx"
    order = 2
    modes = ALL_MODES
    codes: ClassVar[dict[str, str]] = {
        **NO_PASSPORT,
        "render": "render nginx for {routes} routes: {diff}",
        "config-invalid": "nginx -t is red in {where}; nothing reloaded",
        "route-target-unknown": "route {route} goes to {to}, which no stack declares",
        "route-ambiguous": "route {route} goes to {to}, declared by {stacks}",
        "domain-missing": "the passport has no domain for route {route}",
        "header-unsafe": "the value of {header} has a quote, a $ or a line break",
        "path-unsafe": "the path {path} of the app of {route} is not a plain path",
        "secret-damaged": "{path} is not a preview secret of this machine",
        "drift": "the live config differs from the rendered one: {diff}",
        "not-running": "nginx is not running",
    }

    def __init__(
        self,
        product: Product,
        *,
        fetched: Fetched,
        secrets: Secrets,
        root: Path = Path("/"),
    ) -> None:
        self.product = product
        self.fetched = fetched
        self.secrets = secrets
        self.root = root

    # --- inputs --------------------------------------------------------------------

    def _preview(self) -> bool:
        passport = self.fetched.passport
        if passport is None:
            raise StepFailed("no-passport")
        return passport.server.role == "preview"

    def _secret(self, *, mint_if_absent: bool) -> str | None:
        if not self._preview():
            return None
        path = self.root / PREVIEW_SECRET
        if not path.exists():
            if not mint_if_absent:
                return None
            value = mint()
            self.secrets.add([SecretStr(value)])
            write_file(path, value.encode("ascii"), 0o600)
            return value
        value = path.read_text(encoding="ascii").strip()
        if mode_of(path) != oct(0o600) or not MINTED_FORM.fullmatch(value):
            raise StepFailed("secret-damaged", {"path": str(path)})
        self.secrets.add([SecretStr(value)])
        return value

    def _rendered(self, secret: str | None) -> str:
        passport = self.fetched.passport
        if passport is None:
            raise StepFailed("no-passport")
        return render(self.product, passport, secret)

    def _live(self) -> str | None:
        path = live_config(self.root)
        return path.read_text(encoding="utf-8") if path.exists() else None

    def _running(self, ctx: StepContext) -> bool:
        _, ids = out(ctx, argv(self.root, "ps", "-q", "nginx"), passed_on=False)
        return any(line.strip() for line in ids)

    def _routes(self) -> int:
        host = self.product.host
        return len(host.routes) if host is not None else 0

    # --- the step ------------------------------------------------------------------

    def check(self, ctx: StepContext) -> CheckResult:
        if self._preview() and not (self.root / PREVIEW_SECRET).exists():
            diff: list[Json] = ["(the preview secret is not minted yet)"]
        else:
            text = self._rendered(self._secret(mint_if_absent=False))
            diff = list[Json](drift(self._live(), text)[:DIFF_LINES])
        same_compose = compose_file(self.root).exists() and compose_file(
            self.root
        ).read_text(encoding="utf-8") == compose_text(self.root)
        if not diff and same_compose and self._running(ctx):
            return CheckResult(False)
        params: dict[str, Json] = {"routes": self._routes(), "diff": diff}
        return CheckResult(True, local_code("render", params))

    def act(self, ctx: StepContext, check: CheckResult) -> None:
        text = self._rendered(self._secret(mint_if_absent=True))
        write_file(compose_file(self.root), compose_text(self.root).encode(), 0o644)
        candidate = candidate_dir(self.root) / live_config(self.root).name
        try:
            write_file(candidate, text.encode("utf-8"), 0o600)
            labels = [
                w for k, v in STACK_LABEL.items() for w in ("--label", f"{k}={v}")
            ]
            code, _ = out(
                ctx,
                [
                    "docker",
                    "run",
                    "--rm",
                    *labels,
                    "-v",
                    f"{candidate_dir(self.root)}:/etc/nginx/conf.d:ro",
                    "-v",
                    f"{certs_dir(self.root)}:/etc/pridem/certs:ro",
                    NGINX_IMAGE,
                    "nginx",
                    "-t",
                ],
                expect=(0, 1),
            )
        finally:
            candidate.unlink(missing_ok=True)
        if code != 0:
            raise StepFailed("config-invalid", {"where": "the candidate"})
        running = self._running(ctx)
        write_file(live_config(self.root), text.encode("utf-8"), 0o600)
        if running:
            out(ctx, argv(self.root, "exec", "-T", "nginx", "nginx", "-s", "reload"))
        else:
            out(ctx, argv(self.root, "up", "-d", "nginx"))

    def verify(self, ctx: StepContext, check: CheckResult) -> Verified:
        text = self._rendered(self._secret(mint_if_absent=False))
        live = self._live()
        if live is None or normalized(live) != normalized(text):
            diff = list[Json](drift(live, text)[:DIFF_LINES])
            raise StepFailed("drift", {"diff": diff})
        if not self._running(ctx):
            raise StepFailed("not-running")
        code, _ = out(
            ctx, argv(self.root, "exec", "-T", "nginx", "nginx", "-t"), expect=(0, 1)
        )
        if code != 0:
            raise StepFailed("config-invalid", {"where": "running nginx"})
        return Verified(
            {
                "config": str(live_config(self.root)),
                "routes": self._routes(),
                "mode": mode_of(live_config(self.root)),
                "preview": self._preview(),
            }
        )
