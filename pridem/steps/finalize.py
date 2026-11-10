"""The end of a plan: the final check, then ``finalize`` (TZ 7.3).

``final_check`` is a marker: the plan, not the step, calls ``verify`` of every
green step of the run once more (``plan.py``); one red fails it, and
``finalize`` after it does not run.

``finalize`` switches ``current`` of every stack to its release --
``/opt/<stack>/current`` is a symlink replaced atomically (a temporary symlink
and ``rename``, then fsync of the directory) -- and writes ``state.json``, the
only writer of it in a plan: the composition, the passport's version and ops
commit, ``current``. A red gate anywhere before stops the plan before this
step: ``current`` still names the release that ran. The final check runs
before the switch: a release that did not pass it is never recorded as
current (the containers it runs on are up; ``doctor`` shows ``current`` behind
them). ``check`` acts whenever ``state.json`` is not the state this run
would write -- the passport's version and ops commit too: a new passport on
the same releases is applied by the run, and ``state.json`` says so (DM-81);
``verify`` reads both back (``state-passport``).

With ``current`` go the environment (DM-68) and the overrides (DM-89): a
deploy's steps run on ``env/next.env`` and ``compose/<entry>.next.yml``, the
release that runs keeps ``env/.env`` and ``compose/<entry>.yml`` until this
step copies the deploy's over them, stack by stack, right after its
``current`` -- every entry of the stack's ``primer.yaml`` (``entries``), no
file found by name. ``check`` acts when one of them is not the deploy's;
``verify`` reads them back (``env``, ``override``).
"""

import os
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import ClassVar

from pridem.events import Json
from pridem.files import atomic_write, fsync_dir
from pridem.stacks.env import env_file, write_private
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
from pridem.steps.compose import override_file
from pridem.steps.passport import NO_PASSPORT, Fetched

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
        **NO_PASSPORT,
        "switch": "switch current of {stacks}",
        "not-switched": "current of {stack} names {found}, not {release}",
        "state": "state.json does not name {stack} at {release}",
        "state-passport": "state.json does not name passport v{passport_version} "
        "from {ops_commit}",
        "env": "env/.env of {stack} is not the environment of its release",
        "override": "the override of {stack} {entry} is not the one of its release",
    }

    def __init__(
        self,
        *,
        releases: Mapping[str, Path],
        entries: Mapping[str, Sequence[str]],
        composition: Mapping[str, str],
        box: Box,
        fetched: Fetched,
        root: Path = Path("/"),
    ) -> None:
        self.releases = dict(releases)
        self.entries = {stack: list(entries[stack]) for stack in releases}
        """The entries of each stack's ``primer.yaml``: their overrides go
        with ``current``."""
        self.composition = dict(composition)
        self.box = box
        self.fetched = fetched
        self.root = root

    def _wanted(self) -> dict[str, str]:
        return {stack: release.name for stack, release in self.releases.items()}

    def _state(self) -> BoxState:
        passport = self.fetched.passport
        if passport is None:
            raise StepFailed("no-passport")
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

    def _env_behind(self) -> list[str]:
        """The stacks whose ``.env`` is not the deploy's ``next.env`` -- or
        is missing, or has none to be."""
        behind = []
        for stack in sorted(self.releases):
            staged = env_file(self.root, stack, staged=True)
            running = env_file(self.root, stack, staged=False)
            if not (staged.is_file() and running.is_file()) or (
                staged.read_bytes() != running.read_bytes()
            ):
                behind.append(stack)
        return behind

    def _overrides_behind(self) -> list[tuple[str, str]]:
        """The entries whose override is not the deploy's -- or is missing,
        or has none to be."""
        behind = []
        for stack in sorted(self.releases):
            for entry in self.entries[stack]:
                staged = override_file(self.root, stack, entry, staged=True)
                running = override_file(self.root, stack, entry, staged=False)
                if not (staged.is_file() and running.is_file()) or (
                    staged.read_bytes() != running.read_bytes()
                ):
                    behind.append((stack, entry))
        return behind

    def check(self, ctx: StepContext) -> CheckResult:
        overrides = {stack for stack, _ in self._overrides_behind()}
        behind = sorted({*self._behind(), *self._env_behind(), *overrides})
        state = self.box.read_state()
        passport = self.fetched.passport
        same = (
            state is not None
            and passport is not None
            and (
                state.composition,
                state.current,
                state.passport_version,
                state.ops_commit,
            )
            == (
                self.composition,
                self._wanted(),
                passport.version,
                self.fetched.ops_commit,
            )
        )
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
            fsync_dir(link.parent)  # the switch survives a power loss
            # KNOWN CEILING (DM-68, DM-89): current, .env and the overrides
            # are several names, switched one after another, in this order.
            # 1. A run cut between them leaves the new release under current
            #    with the old release's .env or overrides: a variable it lacks
            #    fails loudly on ${VAR:?}; a value it changed, an old bind of
            #    a package or of a service's data, an old label run silently
            #    old on the next compose command of current, until the next
            #    run.
            # 2. Status: acknowledged by design.
            # 3. Task: none -- a window of a few writes on one disk, which the
            #    next run closes (``check``: .env or an override behind ->
            #    act).
            # 4. Trigger: a run seen with the old environment or override
            #    after a cut finalize.
            # 5. Fix agreed: the files switched at once, behind one symlink.
            # 6. Rejected: .env or an override before current -- the old
            #    release on the new values, the very defect of DM-68 and
            #    DM-89.
            staged = env_file(self.root, stack, staged=True)
            running = env_file(self.root, stack, staged=False)
            write_private(running, staged.read_text(encoding="utf-8"))
            for entry in self.entries[stack]:
                staged = override_file(self.root, stack, entry, staged=True)
                running = override_file(self.root, stack, entry, staged=False)
                atomic_write(running, staged.read_bytes(), 0o644)
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
        env = self._env_behind()
        if env:
            raise StepFailed("env", {"stack": env[0]})
        overrides = self._overrides_behind()
        if overrides:
            stack, entry = overrides[0]
            raise StepFailed("override", {"stack": stack, "entry": entry})
        state = self.box.read_state()
        wanted = self._wanted()
        for stack, name in wanted.items():
            if state is None or state.current.get(stack) != name:
                raise StepFailed("state", {"stack": stack, "release": name})
        passport = self.fetched.passport
        if passport is None:
            raise StepFailed("no-passport")
        ops = self.fetched.ops_commit
        if state is None or (state.passport_version, state.ops_commit) != (
            passport.version,
            ops,
        ):
            raise StepFailed(
                "state-passport",
                {"passport_version": passport.version, "ops_commit": ops or "none"},
            )
        current: dict[str, Json] = dict[str, Json](wanted)
        return Verified(
            {
                "current": current,
                "state": "written",
                "passport_version": passport.version,
                "env": list[Json](sorted(self.releases)),
                "override": [
                    f"{stack}/{entry}"
                    for stack in sorted(self.releases)
                    for entry in self.entries[stack]
                ],
            }
        )
