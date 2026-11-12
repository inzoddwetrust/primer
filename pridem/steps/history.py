"""What the box's ``history/`` says of its releases and its stand (TZ 7.3).

Decisions about releases are taken from ``history/``, never from
``state.json``: a record of the box, not a basis of decisions. Two readers
share this module, so that they never disagree:

- ``previous_releases`` -- the previous release of each stack: the newest green
  verdict whose ``finalize`` put another release of the stack in ``current``.
  ``gc`` keeps that release's images and worktree; ``rollback`` on prod goes
  back to it (DM-24), so the release it goes to is one ``gc`` kept.
- ``stand_block`` -- a red stand blocks the stand (TZ 9.3, DM-24): the newest
  verdict of a deploy (``install``, ``reinstall``, ``update``, ``deploy``) that
  says which commit of the root stack it put on the stand decides; red -- the
  stand is blocked by that commit. A verdict with no such commit (a ref the
  remote has not, a run cut before ``fetch_root``) put no code on the stand and
  is passed over, as is a ``deploy`` refused by ``stand`` itself: counting the
  refusal would hand the block to the task it refused.

A damaged verdict is passed over and counted; history is append-only, so it
stays where it is.
"""

from collections.abc import Mapping
from dataclasses import dataclass, field

from pridem.report.schema import Verdict
from pridem.state import Box, VerdictDamaged

DEPLOYS = frozenset({"install", "reinstall", "update", "deploy"})
"""The verbs whose verdicts put a commit of the root stack on the stand."""

STAND = "stand"
"""The name of the step that refuses a deploy on a blocked stand."""


def finalized(verdict: Verdict) -> dict[str, str] | None:
    """``stack -> release`` that ``finalize`` of ``verdict`` put in ``current``;
    ``None`` when it did not."""
    for step in verdict.steps:
        if (step.phase, step.name, step.status) == ("main", "finalize", "ok"):
            current = (step.verify or {}).get("current")
            if isinstance(current, dict):
                return {k: v for k, v in current.items() if isinstance(v, str)}
    return None


@dataclass
class Releases:
    """The previous release of each stack and the verdicts that named them."""

    previous: dict[str, str] = field(default_factory=dict)
    """``stack -> release``: the release ``current`` named before this one."""
    previous_verdicts: dict[str, Verdict] = field(default_factory=dict)
    """``stack -> verdict`` whose ``finalize`` put the previous release there."""
    current_verdicts: list[Verdict] = field(default_factory=list)
    """Verdicts whose ``finalize`` put the current release of a stack there."""
    damaged: int = 0
    """Verdicts read and found damaged on the way."""


def previous_releases(box: Box, current: Mapping[str, str]) -> Releases:
    """The previous release of each stack of ``current`` (``stack -> release``
    that ``/opt/<stack>/current`` names), newest verdict first; the reading
    stops once every stack has its previous and its current's verdict."""
    found = Releases()
    made: set[str] = set()  # stacks whose current release's verdict is read
    for run_id in reversed(box.history_ids()):
        if not set(current) - set(found.previous) and set(current) <= made:
            break
        try:
            verdict = box.read_verdict(run_id)
        except VerdictDamaged:
            found.damaged += 1
            continue
        switched = finalized(verdict) if verdict.result == "green" else None
        if switched is None:
            continue
        for stack in sorted(set(current) - made):
            if switched.get(stack) == current[stack]:
                made.add(stack)
                found.current_verdicts.append(verdict)
        for stack in sorted(set(current) - set(found.previous)):
            release = switched.get(stack)
            if release is None or release == current[stack]:
                continue
            found.previous[stack] = release
            found.previous_verdicts[stack] = verdict
    return found


def target_commit(verdict: Verdict) -> str | None:
    """The commit of the root stack ``verdict`` fetched (``fetch_root``)."""
    for step in verdict.steps:
        if step.name != "fetch_root" or step.status != "ok" or step.verify is None:
            continue
        head = step.verify.get("head")
        if isinstance(head, str):
            return head
    return None


def _refused_by_stand(verdict: Verdict) -> bool:
    return any(s.name == STAND and s.status == "failed" for s in verdict.steps)


@dataclass(frozen=True)
class Deployed:
    """The deploy that decides the stand: its run, its commit and its colour."""

    run_id: str
    sha: str
    red: bool


def last_deployed(box: Box) -> Deployed | None:
    """The newest verdict of a deploy that put a commit of the root stack on
    the stand; ``None`` -- there is none."""
    for run_id in reversed(box.history_ids()):
        try:
            verdict = box.read_verdict(run_id)
        except VerdictDamaged:
            continue
        if verdict.verb not in DEPLOYS or _refused_by_stand(verdict):
            continue
        sha = target_commit(verdict)
        if sha is None:
            continue
        return Deployed(run_id, sha, verdict.result == "red")
    return None


def stand_block(box: Box) -> Deployed | None:
    """The red deploy that blocks the stand; ``None`` -- the stand is free."""
    deployed = last_deployed(box)
    return deployed if deployed is not None and deployed.red else None
