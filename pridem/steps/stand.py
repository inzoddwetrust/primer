"""The stand and the roll-back: two guards before a deploy acts (DM-24).

``stand`` -- a red stand blocks the stand (TZ 9.3). It runs in ``update`` and
``deploy`` on a box of the role ``test``, right after ``fetch_root``: the task
of the target commit is known only once the commit is fetched, and nothing but
the bare repository and ``releases/`` has changed by then. ``check`` reads the
block from ``history/`` (``steps/history.py``) and compares tasks: the task is
the set of values of the git trailer ``Task`` of a commit (``git log
--format=%(trailers:key=Task,valueonly)``) -- a ``Task:`` in the subject, or
in a last line with no blank line before it, is no trailer to git and so none
to the machine. The empty set is a task too: a stand red by a commit without a
trailer takes a commit without one (a revert without a trailer), and refuses
one with a trailer. A commit of another task is refused by a red verdict of
this step: ``stand:blocked {task, sha}``, ``stand:blocked-untasked {sha}``, or
``stand:blocked-unknown {sha}`` when the bare repository no longer holds the
blocking commit (``install`` or ``reinstall`` go on: they are not refused, and
their green clears the block). That refusal changes nothing on the stand and
never decides the block itself.

``rollback_check`` -- ``rollback`` on prod goes to the previous release; the
database goes only forward (TZ 10.6). Before any step of any stack acts, it
measures every entry that migrates: the alembic head of the target release's
image against the head the running application reports (``/health``). Another
head -- migrations between the releases -- is ``rollback_check:migrated
{entries}``, and the verdict says ``{restore, needed}``: only a restore of a
dump brings an older schema back. An image the box no longer has, or a head the
running application does not say, cannot be measured and is refused as well.
Its fact names ``passport_ref``: the ref the passport still names, which the
next ``update`` brings back.
"""

from collections.abc import Sequence
from pathlib import Path
from typing import ClassVar

from pridem.events import Fact, Json
from pridem.state import Box
from pridem.steps.base import CheckResult, Mode, Step, StepContext, StepFailed, Verified
from pridem.steps.git import run_git
from pridem.steps.history import STAND, stand_block
from pridem.steps.migrate import Migrate, running_head
from pridem.steps.sources import FetchRoot

DEPLOY: frozenset[Mode] = frozenset({"deploy"})

TRAILER = "--format=%(trailers:key=Task,valueonly,separator=%x2C)"
"""The values of the commit's ``Task`` trailers, comma-separated."""

MISSING = 128
"""``git log`` of an object the repository does not hold."""


def tasks(
    ctx: StepContext, root: Path, bare: Path, sha: str, *, held: bool = True
) -> frozenset[str] | None:
    """The values of the ``Task`` trailers of ``sha``; ``None`` -- the
    repository does not hold it (asked only when ``held`` is ``False``)."""
    code, lines = run_git(
        ctx,
        root,
        ["-C", str(bare), "log", "-1", TRAILER, sha, "--"],
        expect=(0,) if held else (0, MISSING),
    )
    if code == MISSING:
        return None
    values = ",".join(lines).split(",")
    return frozenset(value.strip() for value in values if value.strip())


class Stand(Step):
    """A red stand refuses a deploy of another task (TZ 9.3)."""

    name = STAND
    order = 2  # the phase of fetch_root, right after it in its stack
    modes = DEPLOY
    codes: ClassVar[dict[str, str]] = {
        "blocked": "the stand is red by {task} at {sha}: a deploy of another "
        "task would not be judged fairly -- deploy a commit of {task}, or revert "
        "it on the branch",
        "blocked-untasked": "the stand is red at {sha}, a commit without a Task "
        "trailer: only a commit without one goes on it -- revert it on the branch",
        "blocked-unknown": "the stand is red at {sha}, which the repository no "
        "longer holds: install or reinstall the box to go on",
    }

    def __init__(self, fetch: FetchRoot, box: Box, root: Path) -> None:
        self.fetch = fetch
        self.box = box
        self.root = root

    def check(self, ctx: StepContext) -> CheckResult:
        target = self.fetch.target
        if target is None:
            raise RuntimeError("stand checks after fetch_root found its target")
        block = stand_block(self.box)
        if block is None:
            return CheckResult(False, data={"blocked": False})
        bare = self.fetch.checkout.bare
        theirs = tasks(ctx, self.root, bare, block.sha, held=False)
        if theirs is None:
            raise StepFailed("blocked-unknown", {"sha": block.sha})
        mine = tasks(ctx, self.root, bare, target.commit)
        if mine != theirs:
            if not theirs:
                raise StepFailed("blocked-untasked", {"sha": block.sha})
            raise StepFailed(
                "blocked", {"task": ",".join(sorted(theirs)), "sha": block.sha}
            )
        data: dict[str, Json] = {"blocked": True, "sha": block.sha}
        if theirs:
            data["task"] = ",".join(sorted(theirs))
        return CheckResult(False, data=data)

    def act(self, ctx: StepContext, check: CheckResult) -> None:
        raise RuntimeError("stand never acts")

    def verify(self, ctx: StepContext, check: CheckResult) -> Verified:
        fact: Fact = dict(check.data)
        return Verified(fact)


ROLLBACK_CHECK = "rollback_check"


class RollbackCheck(Step):
    """``rollback`` refuses before any act when the database moved forward."""

    name = ROLLBACK_CHECK
    order = 1
    modes = DEPLOY
    codes: ClassVar[dict[str, str]] = {
        **{
            key: text
            for key, text in Migrate.codes.items()
            if key not in ("migrate", "not-at-head")
        },
        "no-image": "no image of {service} at {commit}: the roll-back goes to the "
        "image gc keeps for the previous release",
        "migrated": "migrations ran between the releases on {entries}: the "
        "database goes only forward -- a restore of a dump brings it back",
        "head-unread": "{entry} does not say its alembic head: the roll-back "
        "cannot measure it",
    }

    def __init__(self, migrates: Sequence[Migrate], passport_ref: str) -> None:
        self.migrates = list(migrates)
        self.passport_ref = passport_ref

    def check(self, ctx: StepContext) -> CheckResult:
        heads: dict[str, Json] = {}
        moved: list[Json] = []
        for migrate in self.migrates:
            entry = migrate.compose.entry
            head = migrate.target_head(ctx)
            live = running_head(ctx, migrate.compose)
            if live is None:
                raise StepFailed("head-unread", {"entry": entry})
            if live != head:
                moved.append(entry)
            heads[entry] = head
        if moved:
            raise StepFailed("migrated", {"entries": moved})
        return CheckResult(False, data={"heads": heads})

    def act(self, ctx: StepContext, check: CheckResult) -> None:
        raise RuntimeError("rollback_check never acts")

    def verify(self, ctx: StepContext, check: CheckResult) -> Verified:
        return Verified(
            {"heads": check.data.get("heads", {}), "passport_ref": self.passport_ref}
        )
