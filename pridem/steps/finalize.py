"""The end of a plan: the final check, then ``finalize`` (TZ 7.3).

``final_check`` is a marker: the plan, not the step, calls ``verify`` of every
green step of the run once more (``plan.py``); one red fails it, and
``finalize`` after it does not run.

``finalize`` switches ``current`` of every stack to its release --
``/opt/<stack>/current`` is a symlink replaced atomically (a temporary symlink
and ``rename``) -- and writes ``state.json``, the only writer of it in a plan:
the composition, the passport's version and ops commit, ``current``. A red
gate anywhere before stops the plan before this step: ``current`` still names
the release that ran. The final check runs before the switch: a release that
did not pass it is never recorded as current (the containers it runs on are
up; ``doctor`` shows ``current`` behind them).
"""

import os
from collections.abc import Mapping
from pathlib import Path
from typing import ClassVar

from pridem.events import Json
from pridem.state import Box, BoxState
from pridem.steps.base import (
    CheckResult,
    Mode,
    Step,
    StepContext,
    StepFailed,
    Verified,
    local_code,
)
from pridem.steps.passport import Fetched

ALL_MODES: frozenset[Mode] = frozenset({"install", "deploy", "reinstall"})


class FinalCheck(Step):
    """Marker of the final check; the plan does its work."""

    name = "final_check"
    order = 1
    modes = ALL_MODES
    final_check = True
    codes: ClassVar[dict[str, str]] = {
        "red": "the final check is red at {stack} {step}: {reason}",
    }

    def check(self, ctx: StepContext) -> CheckResult:
        return CheckResult(False)  # doctor asks; the plan never runs it in a run

    def act(self, ctx: StepContext, check: CheckResult) -> None:
        raise RuntimeError("the plan does the final check")

    def verify(self, ctx: StepContext, check: CheckResult) -> Verified:
        raise RuntimeError("the plan does the final check")


def current_link(root: Path, stack: str) -> Path:
    return root / "opt" / stack / "current"


class Finalize(Step):
    """``current`` of every stack and ``state.json``, after the final check."""

    name = "finalize"
    order = 2
    modes = ALL_MODES
    codes: ClassVar[dict[str, str]] = {
        "switch": "switch current of {stacks}",
        "not-switched": "current of {stack} names {found}, not {release}",
        "state": "state.json does not name {stack} at {release}",
    }

    def __init__(
        self,
        *,
        releases: Mapping[str, Path],
        composition: Mapping[str, str],
        box: Box,
        fetched: Fetched,
        root: Path = Path("/"),
    ) -> None:
        self.releases = dict(releases)
        self.composition = dict(composition)
        self.box = box
        self.fetched = fetched
        self.root = root

    def _wanted(self) -> dict[str, str]:
        return {stack: release.name for stack, release in self.releases.items()}

    def _state(self) -> BoxState:
        passport = self.fetched.passport
        if passport is None:
            raise RuntimeError("no passport: fetch_passport runs before finalize")
        old = self.box.read_state()
        fields: dict[str, object] = {
            "composition": self.composition,
            "passport_version": passport.version,
            "current": self._wanted(),
            "last_run": old.last_run if old is not None else {},
        }
        if self.fetched.ops_commit is not None:
            fields["ops_commit"] = self.fetched.ops_commit
        return BoxState.model_validate(fields)

    def _behind(self) -> list[str]:
        behind = []
        for stack, release in sorted(self.releases.items()):
            link = current_link(self.root, stack)
            if not link.is_symlink() or Path(os.readlink(link)) != release:
                behind.append(stack)
        return behind

    def check(self, ctx: StepContext) -> CheckResult:
        behind = self._behind()
        state = self.box.read_state()
        same = state is not None and (
            state.composition,
            state.current,
        ) == (self.composition, self._wanted())
        if not behind and same:
            return CheckResult(False)
        stacks: list[Json] = list[Json](behind or sorted(self.releases))
        return CheckResult(True, local_code("switch", {"stacks": stacks}))

    def act(self, ctx: StepContext, check: CheckResult) -> None:
        for stack, release in sorted(self.releases.items()):
            link = current_link(self.root, stack)
            link.parent.mkdir(parents=True, exist_ok=True)
            temp = link.with_name(".current.tmp")
            temp.unlink(missing_ok=True)
            os.symlink(release, temp)
            os.replace(temp, link)  # never a moment without current
        self.box.write_state(self._state())

    def verify(self, ctx: StepContext, check: CheckResult) -> Verified:
        for stack, release in sorted(self.releases.items()):
            link = current_link(self.root, stack)
            found = os.readlink(link) if link.is_symlink() else "none"
            if Path(found) != release:
                raise StepFailed(
                    "not-switched",
                    {"stack": stack, "found": found, "release": str(release)},
                )
        state = self.box.read_state()
        wanted = self._wanted()
        for stack, name in wanted.items():
            if state is None or state.current.get(stack) != name:
                raise StepFailed("state", {"stack": stack, "release": name})
        current: dict[str, Json] = dict[str, Json](wanted)
        return Verified({"current": current, "state": "written"})
