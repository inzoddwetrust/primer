"""``types``: the frontend's API types from the running app's OpenAPI (TZ
7.3, 9.1 ``gen-types``; contract 3 ``stacks.*.types``).

The step reads ``types.openapi`` from the app on the network ``pridem`` and
turns it into the text of ``types.out`` with a ``Generator``. On a ``test``
box a text that differs from the release's file is committed by the bot
(``commit_as``) to the branch the box follows (``product.ref``): one commit,
exactly one path -- ``types.out`` -- and the trailer
``Primer-Machine: types <run_id>``; the push goes to ``push_to``, the
repository's write address, whose key is given to git through its
environment, never through an argv. Nothing else of the repository is ever
written. On ``prod`` (and ``preview``) the text must equal the release's file:
a difference is red -- a release without regenerated types.

KNOWN CEILING (DM-19).

1. Mechanics: contract 3 declares ``types: {openapi, out, commit_as}`` and no
   command that makes ``out`` from the OpenAPI document; the machine knows no
   command of a product it was not told. Without a ``Generator`` the step is
   red ``types:generator-unknown`` before ``act`` for every stack with
   ``types``; a stack without ``types`` is untouched.
2. Status: acknowledged by design.
3. Task: none yet -- a change of contract 3; DM-8 (velo) declares its
   generator once the contract has the field.
4. Trigger: contract 3 names the command that generates the types.
5. Agreed fix: ``Generator`` built from that command of ``primer.yaml`` (run
   in a throwaway container of the stack's image, the OpenAPI document as
   its input), handed to this step by the plan builder.
6. Rejected: a generator built into the machine -- the machine runs the
   commands a product declares, it carries none of its own.
"""

import shutil
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import ClassVar

from pridem.conformance.stack import BodyTooBig, app_address, http_get
from pridem.events import Json
from pridem.files import PathOutside, resolve_inside
from pridem.stacks.schema import Product, Service
from pridem.steps.base import (
    CheckResult,
    Mode,
    Role,
    Step,
    StepContext,
    StepFailed,
    Verified,
    local_code,
)
from pridem.steps.compose import ComposeStack
from pridem.steps.git import git_env, run_git

ALL_MODES: frozenset[Mode] = frozenset({"install", "deploy", "reinstall"})
TRAILER = "Primer-Machine: types"

Generator = Callable[[bytes], bytes]
"""The OpenAPI document of the running app -> the text of ``types.out``."""


OPENAPI_LIMIT = 16 * 1024 * 1024
"""The most of the app's OpenAPI document read (DM-81), as of a junit."""


class Types(Step):
    """The types of a stack: committed on test, checked elsewhere."""

    name = "types"
    order = 1
    modes = ALL_MODES
    codes: ClassVar[dict[str, str]] = {
        "commit": "commit {path} to {branch}",
        "path-outside": "{path} of types goes through a symlink or leaves the tree",
        "generator-unknown": "no command generates the types of {stack}",
        "openapi-unreachable": "the app answers no {path}",
        "openapi-empty": "the app's {path} is empty",
        "openapi-too-big": "the app's {path} is over {limit} bytes",
        "stale": "{path} of the release is not what the app's API gives",
        "more-than-types": "the types commit would change {paths}",
        "not-pushed": "{branch} of the repository is not at the types commit",
    }

    def __init__(
        self,
        stack: Product | Service,
        entry: str,
        *,
        release: Path,
        ref: str,
        commit: str,
        role: Role,
        branch: str,
        run_id: str,
        push_to: str,
        git_dir: Path,
        root: Path = Path("/"),
        generator: Generator | None = None,
        env: Mapping[str, str] | None = None,
    ) -> None:
        self.compose = ComposeStack(stack, entry, release, ref, commit, root)
        self.types = stack.stacks[entry].types
        self.role = role
        self.branch = branch
        self.run_id = run_id
        self.push_to = push_to
        self.git_dir = git_dir
        self.generator = generator
        self.env = dict(env) if env is not None else None
        self.pushed: str | None = None

    def _generated(self, ctx: StepContext) -> bytes:
        if self.types is None:
            raise RuntimeError("no types: the step is not asked")
        if self.generator is None:
            raise StepFailed("generator-unknown", {"stack": self.compose.entry})
        stage = self.compose.stack.stacks[self.compose.entry]
        if stage.app is None:
            raise StepFailed("openapi-unreachable", {"path": self.types.openapi})
        own = self.compose.product_argv()
        _, address = app_address(ctx, own, stage.app.service)
        try:
            got = (
                http_get(
                    address, stage.app.port, self.types.openapi, limit=OPENAPI_LIMIT
                )
                if address
                else None
            )
        except BodyTooBig:
            raise StepFailed(
                "openapi-too-big", {"path": self.types.openapi, "limit": OPENAPI_LIMIT}
            ) from None
        if got is None or got[0] != 200:
            raise StepFailed("openapi-unreachable", {"path": self.types.openapi})
        if not got[1].strip():
            raise StepFailed("openapi-empty", {"path": self.types.openapi})
        return self.generator(got[1])

    def _released(self) -> bytes | None:
        if self.types is None:
            return None
        file = self.compose.release / self.types.out
        return file.read_bytes() if file.is_file() else None

    def check(self, ctx: StepContext) -> CheckResult:
        if self.types is None:
            return CheckResult(False)
        text = self._generated(ctx)
        if text == self._released():
            return CheckResult(False)
        if self.role != "test":
            raise StepFailed("stale", {"path": self.types.out})
        params: dict[str, Json] = {"path": self.types.out, "branch": self.branch}
        return CheckResult(True, local_code("commit", params))

    def _git(self, ctx: StepContext, *args: str) -> list[str]:
        _, lines = run_git(ctx, self.compose.root, list(args), env=self.env)
        return lines

    def act(self, ctx: StepContext, check: CheckResult) -> None:
        if self.types is None:
            raise RuntimeError("no types: nothing to commit")
        text = self._generated(ctx)
        work = self.compose.root / "opt" / self.compose.name / "types-work"
        shutil.rmtree(work, ignore_errors=True)
        bare = str(self.git_dir)
        self._git(ctx, "--git-dir", bare, "worktree", "prune")
        self._git(
            ctx,
            "--git-dir",
            bare,
            "worktree",
            "add",
            "--detach",
            str(work),
            f"refs/heads/{self.branch}",
        )
        try:
            try:  # the product's tree: a symlink in out would lead root's write
                target = resolve_inside(work, self.types.out)
            except PathOutside:
                raise StepFailed("path-outside", {"path": self.types.out}) from None
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(text)
            here = ["-C", str(work)]
            self._git(ctx, *here, "add", "--", self.types.out)
            changed = self._git(ctx, *here, "diff", "--cached", "--name-only")
            if changed != [self.types.out]:
                raise StepFailed("more-than-types", {"paths": list[Json](changed)})
            who = self.types.commit_as
            base = self.env if self.env is not None else git_env(self.compose.root)
            bot = {
                **base,
                "GIT_AUTHOR_NAME": who,
                "GIT_AUTHOR_EMAIL": f"{who}@pridem.invalid",
                "GIT_COMMITTER_NAME": who,
                "GIT_COMMITTER_EMAIL": f"{who}@pridem.invalid",
            }
            run_git(
                ctx,
                self.compose.root,
                [
                    *here,
                    "commit",
                    "--quiet",
                    "-m",
                    f"Regenerate {self.types.out}",
                    "-m",
                    f"{TRAILER} {self.run_id}",
                ],
                env=bot,
            )
            [head] = self._git(ctx, *here, "rev-parse", "HEAD")
            self._git(
                ctx, *here, "push", self.push_to, f"HEAD:refs/heads/{self.branch}"
            )
            self.pushed = head.strip()
        finally:
            self._git(
                ctx, "--git-dir", bare, "worktree", "remove", "--force", str(work)
            )

    def verify(self, ctx: StepContext, check: CheckResult) -> Verified:
        if self.types is None:
            return Verified({"types": "none"})
        if self.pushed is None:
            return Verified({"types": "current", "path": self.types.out})
        lines = self._git(ctx, "ls-remote", self.push_to, f"refs/heads/{self.branch}")
        found = lines[0].split()[0] if lines else ""
        if found != self.pushed:
            raise StepFailed("not-pushed", {"branch": self.branch})
        return Verified(
            {"types": "committed", "path": self.types.out, "commit": self.pushed}
        )
