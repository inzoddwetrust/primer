"""``types``: the frontend's API types, made by the product's commands (TZ 7.3,
9.1 ``gen-types``; contract 3 rule 23).

``types.openapi`` prints the OpenAPI document to stdout; ``types.generate``
turns the file ``<openapi>`` into the file ``<out>`` -- paths the machine puts
in. Both run in a throwaway container of the release's app image with the
app's environment, as ``migrate`` does: ``compose run --rm --no-deps -T <app>``
on the deploy's files. The schema is never read over HTTP. The document is
kept to ``OPENAPI_LIMIT`` and must be a JSON object; ``generate`` gets a
directory of the host (``/opt/<stack>/types-run``) mounted at
``/primer/types`` with ``openapi.json`` in it, and writes ``out`` there; the
machine takes that file without following a link, to ``OPENAPI_LIMIT``, and
compares it with the release's ``types.out``.

On a ``test`` box a different text is committed by ``commit_as`` on top of the
deployed commit -- never the branch's head of the moment -- to the branch the
box follows: one commit, exactly one path, ``types.out``. Its message is a
subject, a blank line and one paragraph of trailers: every ``Task`` of the
deployed commit, one line each, and ``Primer-Machine: types <run_id>`` last --
the paragraph git reads trailers from, so ``stand`` (DM-24) sees the deployed
commit's task in the types commit the next ``update`` deploys. The push goes
to the repository's address through the write key's alias (``<alias>-write``,
``write_key``), never with ``--force``, and ``--porcelain``: a ref the remote
moved meanwhile is ``behind`` (the next deploy of the new head makes the
types), ssh's own failure ``unreachable``, any other refusal ``write-refused``.
On ``prod`` and ``preview`` a difference is ``stale``.

The step runs after ``finalize`` (DM-63): a red deploy pushes nothing, and the
release is out and running by then. So any refusal of the step is left undone
-- an ``incomplete`` entry, never a red verdict: a red one would block the
stand by its task (DM-24) for a types commit that did not land, not for the
product's code. ``check`` names the refusal as what it would do, so ``doctor``
shows it; ``act`` leaves it; ``verify`` reports it ``incomplete``.
"""

import json
import os
import shlex
import shutil
import stat
from collections.abc import Mapping
from pathlib import Path
from typing import ClassVar

from pridem.events import Code, Json
from pridem.files import PathOutside, resolve_inside
from pridem.runner import Stream
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
from pridem.steps.git import Repo, git_env, repo, run_git
from pridem.steps.keys import SSH_OWN

ALL_MODES: frozenset[Mode] = frozenset({"install", "deploy", "reinstall"})
TRAILER = "Primer-Machine: types"
TASKS = "--format=%(trailers:key=Task,valueonly,separator=%x00)"
"""The values of the deployed commit's ``Task`` trailers, NUL-separated."""
OPENAPI_LIMIT = 16 * 1024 * 1024
"""The most of the OpenAPI document and of the generated types taken."""
MOUNT = "/primer/types"
"""Where ``generate`` finds ``openapi.json`` and writes ``out``."""
TIMEOUT_S = 600


def _took(produced: Path) -> bytes:
    """The file ``generate`` wrote: opened without following a link and checked
    on the descriptor -- the container wrote the directory in this very run
    (as the junit of ``tests``, DM-78)."""
    try:  # O_NONBLOCK: a FIFO put there would hold the open for ever
        fd = os.open(produced, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError:
        raise StepFailed("generate-missing", {"path": str(produced)}) from None
    except OSError:  # ELOOP: the name is a symlink
        raise StepFailed("generate-unsafe", {"cause": "symlink"}) from None
    found = os.fstat(fd)
    cause = None
    if not stat.S_ISREG(found.st_mode):
        cause = "not-a-file"
    elif found.st_size > OPENAPI_LIMIT:
        cause = "too-big"
    if cause is not None:
        os.close(fd)
        raise StepFailed("generate-unsafe", {"cause": cause})
    with os.fdopen(fd, "rb") as source:
        return source.read(OPENAPI_LIMIT + 1)


class Types(Step):
    """The types of a stack: committed on test, checked elsewhere; after
    ``finalize``, so whatever is refused is left undone."""

    name = "types"
    order = 4  # in the root stack: after final_check, finalize, write_key
    modes = ALL_MODES
    codes: ClassVar[dict[str, str]] = {
        "commit": "commit {path} to {branch}",
        "path-outside": "{path} of types goes through a symlink or leaves the tree",
        "openapi-failed": "the app's openapi command ended with {exit}",
        "openapi-not-json": "the app's openapi command printed no JSON object",
        "openapi-too-big": "the app's openapi command printed over {limit} bytes",
        "generate-failed": "the types' generate command ended with {exit}",
        "generate-missing": "the types' generate command wrote no {path}",
        "generate-unsafe": "the file the generate command wrote is not taken: {cause}",
        "stale": "{path} of the release is not what the app's API gives",
        "more-than-types": "the types commit would change {paths}",
        "behind": "{branch} moved on the remote meanwhile: the next deploy makes "
        "the types",
        "unreachable": "ssh does not reach {repo}",
        "write-refused": "{repo} refused the push of the types with the write key",
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
        env: Mapping[str, str] | None = None,
    ) -> None:
        self.compose = ComposeStack(
            stack, entry, release, ref, commit, root, staged=True
        )
        self.types = stack.stacks[entry].types
        self.role = role
        self.branch = branch
        self.run_id = run_id
        self.writer: Repo = repo(push_to, write=True)
        self.git_dir = git_dir
        self.env = dict(env) if env is not None else None
        self.pushed: str | None = None
        self.left: Code | None = None
        """What the step refused: left undone, reported ``incomplete``."""

    @property
    def _app(self) -> str:
        app = self.compose.app_service
        if app is None:
            raise RuntimeError("types without an app: the loader refuses it")
        return app

    def _run(
        self, ctx: StepContext, words: list[str], *extra: str
    ) -> tuple[int, bytes]:
        """``compose run`` of the app with ``words``: its code and stdout, kept to
        ``OPENAPI_LIMIT`` (a line in pieces is joined back)."""
        argv = self.compose.argv("run", "--rm", "--no-deps", "-T", *extra, self._app)
        lines: list[str] = []
        size = 0
        joining = False
        over = False

        def keep(stream: Stream, line: str, cut: bool) -> None:
            nonlocal size, joining, over
            if stream is not Stream.STDOUT:
                ctx.on_line(stream, line, cut)
                return
            size += len(line.encode()) + (0 if joining else 1)
            if size > OPENAPI_LIMIT:
                over = True
            elif joining and lines:
                lines[-1] += line
            else:
                lines.append(line)
            joining = cut

        result = ctx.runner.run(
            [*argv, *words],
            expect=tuple(range(256)),
            timeout=TIMEOUT_S,
            on_line=keep,
        )
        if over:
            raise StepFailed("openapi-too-big", {"limit": OPENAPI_LIMIT})
        return result.code, "\n".join(lines).encode()

    def _openapi(self, ctx: StepContext) -> bytes:
        if self.types is None:
            raise RuntimeError("no types: the step is not asked")
        code, printed = self._run(ctx, shlex.split(self.types.openapi))
        if code != 0:
            raise StepFailed("openapi-failed", {"exit": code})
        try:
            document = json.loads(printed)
        except ValueError:
            raise StepFailed("openapi-not-json") from None
        if not isinstance(document, dict):
            raise StepFailed("openapi-not-json")
        return printed

    def _generated(self, ctx: StepContext) -> bytes:
        """``generate`` on the app's OpenAPI document: the text of ``out``."""
        if self.types is None:
            raise RuntimeError("no types: the step is not asked")
        document = self._openapi(ctx)
        host = self.compose.root / "opt" / self.compose.name / "types-run"
        shutil.rmtree(host, ignore_errors=True)
        host.mkdir(parents=True)
        try:
            host.chmod(0o777)  # the command runs as the image's user, not root
            (host / "openapi.json").write_bytes(document)
            paths = {"<openapi>": f"{MOUNT}/openapi.json", "<out>": f"{MOUNT}/out"}
            words = []
            for word in shlex.split(self.types.generate):
                for placeholder, path in paths.items():
                    word = word.replace(placeholder, path)
                words.append(word)
            code, _ = self._run(ctx, words, "-v", f"{host}:{MOUNT}")
            if code != 0:
                raise StepFailed("generate-failed", {"exit": code})
            return _took(host / "out")
        finally:
            shutil.rmtree(host, ignore_errors=True)

    def _released(self) -> bytes | None:
        if self.types is None:
            return None
        file = self.compose.release / self.types.out
        return file.read_bytes() if file.is_file() else None

    def _leave(self, error: StepFailed) -> CheckResult:
        """A refusal left undone: what ``doctor`` shows, ``verify`` reports."""
        self.left = error.reason
        return CheckResult(True, error.reason, {"left": True})

    def check(self, ctx: StepContext) -> CheckResult:
        if self.types is None:
            return CheckResult(False)
        self.left = None
        try:
            text = self._generated(ctx)
        except StepFailed as error:
            return self._leave(error)
        if text == self._released():
            return CheckResult(False)
        if self.role != "test":
            return self._leave(StepFailed("stale", {"path": self.types.out}))
        params: dict[str, Json] = {"path": self.types.out, "branch": self.branch}
        return CheckResult(True, local_code("commit", params))

    def _git(self, ctx: StepContext, *args: str) -> list[str]:
        _, lines = run_git(ctx, self.compose.root, list(args), env=self.env)
        return lines

    def _message(self, ctx: StepContext) -> list[str]:
        """``-m`` subject, ``-m`` the one paragraph of trailers: the deployed
        commit's ``Task`` values, then the machine's."""
        bare = ["--git-dir", str(self.git_dir)]
        lines = self._git(ctx, *bare, "log", "-1", TASKS, self.compose.commit, "--")
        tasks = [task for task in "\n".join(lines).split("\0") if task.strip()]
        trailers = [*(f"Task: {task.strip()}" for task in tasks)]
        trailers.append(f"{TRAILER} {self.run_id}")
        out = self.types.out if self.types is not None else ""
        return ["-m", f"Regenerate {out}", "-m", "\n".join(trailers)]

    def act(self, ctx: StepContext, check: CheckResult) -> None:
        if self.types is None:
            raise RuntimeError("no types: nothing to commit")
        if check.data.get("left") is True:
            return  # refused: left undone, verify says so
        try:
            self._commit(ctx)
        except StepFailed as error:
            self.left = error.reason

    def _commit(self, ctx: StepContext) -> None:
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
            self.compose.commit,  # on top of what was deployed, not the branch
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
                [*here, "commit", "--quiet", *self._message(ctx)],
                env=bot,
            )
            [head] = self._git(ctx, *here, "rev-parse", "HEAD")
            self._push(ctx, here)
            self.pushed = head.strip()
        finally:
            self._git(
                ctx, "--git-dir", bare, "worktree", "remove", "--force", str(work)
            )

    def _push(self, ctx: StepContext, here: list[str]) -> None:
        """Without ``--force``; ``--porcelain``: a refused ref is a line
        ``!<TAB><src>:<dst><TAB>[rejected] ...`` on stdout and code 1."""
        errors: list[str] = []
        code, lines = run_git(
            ctx,
            self.compose.root,
            [
                *here,
                "push",
                "--porcelain",
                self.writer.url(),
                f"HEAD:refs/heads/{self.branch}",
            ],
            env=self.env,
            expect=(0, 1, 128),
            stderr=errors,
        )
        if code == 0:
            return
        if code == 1 and any(
            line.startswith("!") and "[rejected]" in line for line in lines
        ):
            raise StepFailed("behind", {"branch": self.branch})
        if any(line.startswith(SSH_OWN) for line in errors):
            raise StepFailed("unreachable", {"repo": self.writer.address})
        raise StepFailed("write-refused", {"repo": self.writer.address})

    def verify(self, ctx: StepContext, check: CheckResult) -> Verified:
        if self.types is None:
            return Verified({"types": "none"})
        if self.left is None and self.pushed is not None:
            lines = self._git(
                ctx, "ls-remote", self.writer.url(), f"refs/heads/{self.branch}"
            )
            found = lines[0].split()[0] if lines else ""
            if found != self.pushed:
                self.left = local_code("not-pushed", {"branch": self.branch})
        if self.left is not None:
            return Verified(
                {"types": "left", "path": self.types.out, "left": self.left.code},
                incomplete=self.left,
            )
        if self.pushed is None:
            return Verified({"types": "current", "path": self.types.out})
        return Verified(
            {"types": "committed", "path": self.types.out, "commit": self.pushed}
        )
