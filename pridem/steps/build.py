"""``build``: the images of one stack entry at one commit (TZ 7.3; contract 3
rules 18-19).

``docker compose … build`` from the release, with exactly two build
arguments: ``PRIMER_RELEASE`` (tag or branch) and ``PRIMER_COMMIT`` (sha) --
one image for every instance of a commit; a ``build.args`` in the product's
compose would carry an instance's value and is refused before anything is
built. Images carry ``pridem.stack``, ``pridem.release``, ``pridem.commit`` and
``pridem.service`` from the machine's override (``steps/compose.py``), which
this step writes.

A red build stops the plan: nothing has touched a running container -- the
build only makes images. ``check`` needs no ``act`` when every built service
has its image of this commit and the override is the rendered one. The fact
names every image and the ``app`` image, which ``render_env`` gets for
``derive``.
"""

from pathlib import Path
from typing import ClassVar

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
    BUILD_TIMEOUT_S,
    ComposeStack,
    built_services,
    config,
    image_of,
    out,
    override_text,
    write_override,
)

ALL_MODES: frozenset[Mode] = frozenset({"install", "deploy", "reinstall"})


def build_args(compose: ComposeStack) -> list[str]:
    """The only build arguments a build gets (contract 3 rule 19)."""
    return [
        "--build-arg",
        f"PRIMER_RELEASE={compose.ref}",
        "--build-arg",
        f"PRIMER_COMMIT={compose.commit}",
    ]


class Build(Step):
    """The images of one stack entry, built once per commit."""

    name = "build"
    order = 8
    modes = ALL_MODES
    codes: ClassVar[dict[str, str]] = {
        "build": "build {services} of {stack} at {commit}",
        "instance-args": "the compose of {stack} gives build arguments to {services}",
        "no-image": "no image of {service} at {commit} after the build",
        "two-images": "{count} images of {service} at {commit}",
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

    def _rendered(self, ctx: StepContext) -> tuple[list[str], str]:
        document = config(ctx, self.compose)
        services = document.get("services")
        if isinstance(services, dict):
            given = sorted(
                name
                for name, body in services.items()
                if isinstance(body, dict)
                and isinstance(build := body.get("build"), dict)
                and build.get("args")
            )
            if given:
                raise StepFailed(
                    "instance-args",
                    {"stack": self.compose.entry, "services": list[Json](given)},
                )
        return built_services(document), override_text(self.compose, document)

    def check(self, ctx: StepContext) -> CheckResult:
        built, text = self._rendered(ctx)
        params: dict[str, Json] = {
            "stack": self.compose.entry,
            "commit": self.compose.commit,
            "services": list[Json](built),
        }
        needed = CheckResult(True, local_code("build", params))
        path = self.compose.override
        if not path.exists() or path.read_text(encoding="utf-8") != text:
            return needed
        if any(not image_of(ctx, self.compose, service) for service in built):
            return needed
        return CheckResult(False)

    def act(self, ctx: StepContext, check: CheckResult) -> None:
        _, text = self._rendered(ctx)
        write_override(self.compose, text)
        out(
            ctx,
            self.compose.argv("build", *build_args(self.compose)),
            timeout=BUILD_TIMEOUT_S,
        )

    def verify(self, ctx: StepContext, check: CheckResult) -> Verified:
        built, _ = self._rendered(ctx)
        images: dict[str, Json] = {}
        for service in built:
            found = image_of(ctx, self.compose, service)
            if not found:
                raise StepFailed(
                    "no-image", {"service": service, "commit": self.compose.commit}
                )
            if len(found) > 1:
                raise StepFailed(
                    "two-images",
                    {
                        "service": service,
                        "commit": self.compose.commit,
                        "count": len(found),
                    },
                )
            images[service] = found[0]
        fact: dict[str, Json] = {
            "release": self.compose.ref,
            "commit": self.compose.commit,
            "images": images,
        }
        app = self.compose.app_service
        if app is not None and app in images:
            fact["app_image"] = images[app]
        return Verified(fact)
