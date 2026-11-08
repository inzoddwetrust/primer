"""``nginx``: the box's nginx from ``host.routes`` (TZ 7.3; contract 3 rules
4, 15).

The config is rendered (``stacks/routes.py``) and compared with the live file
``/opt/pridem/edge/nginx/pridem.conf`` normalized -- comments and blanks are not
drift; a domain is. ``doctor`` shows the diff of the normalized texts.

A new config is tested before it is put in place: written to a candidate
directory and checked by ``nginx -t`` in a throwaway container of the same
image, the candidate mounted where the live config would be. Red -- the live
file is untouched and nothing is reloaded. Green -- the live file is replaced
atomically, then the running nginx reloads (``exec -T nginx nginx -s reload``)
when its container is on the edge's compose as rendered, or ``up -d nginx``
creates it anew: no container yet, another compose file (``compose_text`` of
this machine), or a container compose did not make from the file on disk --
its label ``com.docker.compose.config-hash`` is not ``config --hash nginx`` of
the file (the form of DM-58). A reload never applies a compose: a new image or
network of nginx is a new container. At no moment does a broken config lie
where a restarting nginx would read it.

``verify`` reads the container back: running, the live config the rendered
one and green by ``nginx -t``, on the image ``NGINX_IMAGE``, on the networks
``pridem`` and ``pridem-edge_default``, with the hash of the file on disk.

On a ``preview`` box the secret of the link is minted once
(``/opt/pridem/keys/preview-link``, 0600) and enters the run's ``Secrets``
before anything that could carry it: the config holds it and is 0600.
"""

import json
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
from pridem.steps.compose import NETWORK, out
from pridem.steps.edge import (
    NGINX_IMAGE,
    PROJECT,
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
NETWORKS = (NETWORK, f"{PROJECT}_default")
"""The networks the nginx container is on: the shared one and its project's."""
HASH_LABEL = "com.docker.compose.config-hash"
INSPECT = (
    '{"image": {{json .Config.Image}}, "labels": {{json .Config.Labels}}, '
    '"networks": {{json .NetworkSettings.Networks}}}'
)


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
        "container": (
            "the nginx container is on {image} and {networks}, hash {hash}; "
            "the edge wants {want_image} and {want_networks}, hash {want_hash}"
        ),
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
        try:
            value = path.read_text(encoding="ascii").strip()
        except UnicodeDecodeError:  # not ASCII: not a secret this machine minted
            value = ""
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

    def _running(self, ctx: StepContext) -> str | None:
        """The id of the running nginx container, if there is one."""
        _, ids = out(ctx, argv(self.root, "ps", "-q", "nginx"), passed_on=False)
        found = [line.strip() for line in ids if line.strip()]
        return found[0] if found else None

    def _hash(self, ctx: StepContext) -> str:
        """``config --hash nginx`` of the edge's compose file on disk."""
        _, lines = out(
            ctx, argv(self.root, "config", "--hash", "nginx"), passed_on=False
        )
        for line in lines:
            service, _, value = line.strip().partition(" ")
            if service == "nginx" and value:
                return value
        return ""

    def _seen(self, ctx: StepContext, container: str) -> tuple[str, list[str], str]:
        """The image, networks and compose hash of the container, read back."""
        _, lines = out(
            ctx, ["docker", "inspect", "--format", INSPECT, container], passed_on=False
        )
        try:
            raw = json.loads("".join(lines))
        except ValueError:
            raw = None
        if not isinstance(raw, dict):
            return "", [], ""
        image = raw.get("image")
        labels = raw.get("labels")
        networks = raw.get("networks")
        found = labels.get(HASH_LABEL) if isinstance(labels, dict) else None
        return (
            image if isinstance(image, str) else "",
            sorted(networks) if isinstance(networks, dict) else [],
            found if isinstance(found, str) else "",
        )

    def _applied(self, ctx: StepContext, container: str) -> bool:
        """The container is compose's of the file on disk."""
        return self._seen(ctx, container)[2] == self._hash(ctx)

    def _same_compose(self) -> bool:
        path = compose_file(self.root)
        return path.exists() and path.read_text(encoding="utf-8") == compose_text(
            self.root
        )

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
        if not diff and self._same_compose():
            container = self._running(ctx)
            if container is not None and self._applied(ctx, container):
                return CheckResult(False)
        params: dict[str, Json] = {"routes": self._routes(), "diff": diff}
        return CheckResult(True, local_code("render", params))

    def act(self, ctx: StepContext, check: CheckResult) -> None:
        text = self._rendered(self._secret(mint_if_absent=True))
        same_compose = self._same_compose()
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
        container = self._running(ctx)
        reload = (
            same_compose and container is not None and self._applied(ctx, container)
        )
        write_file(live_config(self.root), text.encode("utf-8"), 0o600)
        if reload:
            out(ctx, argv(self.root, "exec", "-T", "nginx", "nginx", "-s", "reload"))
        else:  # a new container reads the new config as it starts
            out(ctx, argv(self.root, "up", "-d", "nginx"))

    def verify(self, ctx: StepContext, check: CheckResult) -> Verified:
        text = self._rendered(self._secret(mint_if_absent=False))
        live = self._live()
        if live is None or normalized(live) != normalized(text):
            diff = list[Json](drift(live, text)[:DIFF_LINES])
            raise StepFailed("drift", {"diff": diff})
        container = self._running(ctx)
        if container is None:
            raise StepFailed("not-running")
        code, _ = out(
            ctx, argv(self.root, "exec", "-T", "nginx", "nginx", "-t"), expect=(0, 1)
        )
        if code != 0:
            raise StepFailed("config-invalid", {"where": "running nginx"})
        image, networks, found = self._seen(ctx, container)
        want = self._hash(ctx)
        if image != NGINX_IMAGE or not set(NETWORKS) <= set(networks) or found != want:
            raise StepFailed(
                "container",
                {
                    "image": image,
                    "networks": list[Json](networks),
                    "hash": found,
                    "want_image": NGINX_IMAGE,
                    "want_networks": list[Json](NETWORKS),
                    "want_hash": want,
                },
            )
        return Verified(
            {
                "config": str(live_config(self.root)),
                "routes": self._routes(),
                "mode": mode_of(live_config(self.root)),
                "preview": self._preview(),
                "image": image,
                "networks": list[Json](networks),
            }
        )
