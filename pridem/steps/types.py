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
-- an ``incomplete`` entry, never a red verdict (``LeftUndone``): a red one
would block the stand by its task (DM-24) for a types commit that did not
land, not for the product's code. A deployed tag is no branch: nothing to
push to (``not-a-branch``).

``check`` runs no command of the product and writes nothing (DM-63 FIX):
``/opt/<stack>/types.checked`` holds the deployed commit whose types the
machine found the release's or committed itself; the same commit -- nothing to
do, another -- ``generate``: the types of that commit are not checked yet,
which is all ``doctor`` can say without a container. ``act`` makes them once
and compares; ``verify`` reads the push back and writes the mark, atomically,
the deployed commit in it. A step left undone writes no mark: the next deploy
checks again.
"""

import json
import os
import shlex
import shutil
import stat
from collections.abc import Mapping
from pathlib import Path
from typing import ClassVar

from pridem.events import Json
from pridem.files import PathOutside, atomic_write, resolve_inside
from pridem.runner import Stream
from pridem.stacks.schema import Product, Service
from pridem.steps.base import (
    CheckResult,
    LeftUndone,
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
CHECK_REF = "refs/pridem/types-check"
"""Where ``verify`` fetches the remote's branch to read the push back."""


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


class Types(LeftUndone, Step):
    """The types of a stack: committed on test, checked elsewhere; after
    ``finalize``, so whatever is refused is left undone."""

    name = "types"
    order = 4  # in the root stack: after final_check, finalize, write_key
    modes = ALL_MODES
    codes: ClassVar[dict[str, str]] = {
        "generate": "make the types of {commit} and compare them with {path}",
        "path-outside": "{path} of types goes through a symlink, .git or out of "
        "the tree",
        "openapi-failed": "the app's openapi command ended with {exit}",
        "openapi-not-json": "the app's openapi command printed no JSON object",
        "openapi-too-big": "the app's openapi command printed over {limit} bytes",
        "generate-failed": "the types' generate command ended with {exit}",
        "generate-missing": "the types' generate command wrote no {path}",
        "generate-unsafe": "the file the generate command wrote is not taken: {cause}",
        "stale": "{path} of the release is not what the app's API gives",
        "not-a-branch": "the types differ and {ref} is a tag: nothing to push to",
        "same-in-git": "{path} differs only in what git normalizes: nothing to commit",
        "more-than-types": "the types commit would change {paths}",
        "behind": "{branch} moved on the remote meanwhile: the next deploy makes "
        "the types",
        "unreachable": "ssh does not reach {repo}",
        "write-refused": "{repo} refused the push of the types with the write key",
        "not-pushed": "{branch} of the repository does not hold the types commit",
        "failed": "the types were not made: {error}",
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
        branch: str | None,
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
        """The branch the box follows; ``None`` -- the deployed ref is a tag."""
        self.run_id = run_id
        self.writer: Repo = repo(push_to, write=True)
        self.git_dir = git_dir
        self.env = dict(env) if env is not None else None
        self.pushed: str | None = None
        self.moved_on: str | None = None
        self.current = False

    @property
    def _app(self) -> str:
        app = self.compose.app_service
        if app is None:
            raise RuntimeError("types without an app: the loader refuses it")
        return app

    @property
    def mark(self) -> Path:
        """The deployed commit whose types are checked (DM-63 FIX)."""
        return self.compose.root / "opt" / self.compose.name / "types.checked"

    def _run(
        self, ctx: StepContext, words: list[str], *extra: str, keep: bool = True
    ) -> tuple[int, bytes]:
        """``compose run`` of the app with ``words``: its code and, ``keep``, its
        stdout to ``OPENAPI_LIMIT`` (a line in pieces joined back); without,
        the stdout goes to the run's sinks, as stderr does."""
        argv = self.compose.argv(
            "run", "--rm", "--no-deps", "-T", *extra, operands=(self._app,)
        )
        lines: list[str] = []
        size = 0
        joining = False
        over = False

        def take(stream: Stream, line: str, cut: bool) -> None:
            nonlocal size, joining, over
            if stream is not Stream.STDOUT or not keep:
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
            on_line=take,
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
            code, _ = self._run(ctx, words, "-v", f"{host}:{MOUNT}", keep=False)
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

    def _marked(self) -> str | None:
        try:
            return self.mark.read_text(encoding="utf-8").strip()
        except OSError:
            return None

    def check(self, ctx: StepContext) -> CheckResult:
        """No command of the product, no write: the mark of the deployed
        commit, or ``generate``."""
        if self.types is None:
            return CheckResult(False)
        if self._marked() == self.compose.commit:
            return CheckResult(False)
        params: dict[str, Json] = {
            "commit": self.compose.commit,
            "path": self.types.out,
        }
        return CheckResult(True, local_code("generate", params))

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
        self.left = None
        self._guard(lambda: self._make(ctx))

    def _make(self, ctx: StepContext) -> None:
        """The types made once, compared, committed on test."""
        if self.types is None:
            raise RuntimeError("no types: nothing to make")
        text = self._generated(ctx)
        if text == self._released():
            self.current = True
            return
        if self.role != "test":
            raise StepFailed("stale", {"path": self.types.out})
        if self.branch is None:
            raise StepFailed("not-a-branch", {"ref": self.compose.ref})
        self._commit(ctx, text, self.branch)

    def _commit(self, ctx: StepContext, text: bytes, branch: str) -> None:
        if self.types is None:
            raise RuntimeError("no types: nothing to commit")
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
            try:  # the product's tree: a symlink or .git in out leads root's write
                target = resolve_inside(work, self.types.out)
            except PathOutside:
                raise StepFailed("path-outside", {"path": self.types.out}) from None
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(text)
            here = ["-C", str(work)]
            self._git(ctx, *here, "add", "--", self.types.out)
            changed = self._git(ctx, *here, "diff", "--cached", "--name-only")
            if not changed:  # git normalizes what differs (text=auto, CRLF)
                raise StepFailed("same-in-git", {"path": self.types.out})
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
            self._push(ctx, here, branch)
            self.pushed = head.strip()
        finally:  # never raises: a clean-up must not hide what happened
            run_git(
                ctx,
                self.compose.root,
                ["--git-dir", bare, "worktree", "remove", "--force", str(work)],
                env=self.env,
                expect=tuple(range(256)),
            )

    def _push(self, ctx: StepContext, here: list[str], branch: str) -> None:
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
                f"HEAD:refs/heads/{branch}",
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
            raise StepFailed("behind", {"branch": branch})
        if any(line.startswith(SSH_OWN) for line in errors):
            raise StepFailed("unreachable", {"repo": self.writer.address})
        raise StepFailed("write-refused", {"repo": self.writer.address})

    def _confirm(self, ctx: StepContext) -> None:
        """The push read back: the branch's head is the types commit, or holds
        it -- someone pushed on top meanwhile (``moved_on``, DM-63 FIX); then
        the mark, the deployed commit in it."""
        if self.pushed is not None and self.branch is not None:
            branch = self.branch
            lines = self._git(
                ctx, "ls-remote", self.writer.url(), f"refs/heads/{branch}"
            )
            found = lines[0].split()[0] if lines else ""
            if found != self.pushed:
                self._holds(ctx, branch)
                self.moved_on = found
        if self.pushed is not None or self.current:
            atomic_write(self.mark, self.compose.commit + "\n", 0o644)

    def _holds(self, ctx: StepContext, branch: str) -> None:
        """The remote's branch descends from the types commit, or
        ``not-pushed``: fetched into a ref of the machine's own, removed
        after."""
        bare = ["--git-dir", str(self.git_dir)]
        try:
            self._git(
                ctx,
                *bare,
                "fetch",
                "--quiet",
                self.writer.url(),
                f"+refs/heads/{branch}:{CHECK_REF}",
            )
            code, _ = run_git(
                ctx,
                self.compose.root,
                [*bare, "merge-base", "--is-ancestor", str(self.pushed), CHECK_REF],
                env=self.env,
                expect=(0, 1),
            )
            if code != 0:
                raise StepFailed("not-pushed", {"branch": branch})
        finally:
            run_git(
                ctx,
                self.compose.root,
                [*bare, "update-ref", "-d", CHECK_REF],
                env=self.env,
                expect=tuple(range(256)),
            )

    def verify(self, ctx: StepContext, check: CheckResult) -> Verified:
        if self.types is None:
            return Verified({"types": "none"})
        if not check.needed:
            return Verified({"types": "current", "path": self.types.out})
        if self.left is None:
            self._guard(lambda: self._confirm(ctx))
        if self.left is not None:
            return Verified(
                {"types": "left", "path": self.types.out, "left": self.left.code},
                incomplete=self.left,
            )
        if self.pushed is None:
            return Verified({"types": "current", "path": self.types.out})
        fact: dict[str, Json] = {
            "types": "committed",
            "path": self.types.out,
            "commit": self.pushed,
        }
        if self.moved_on is not None:
            fact["moved_on"] = self.moved_on
        return Verified(fact)
