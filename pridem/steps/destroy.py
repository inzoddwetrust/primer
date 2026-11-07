"""``destroy``: what the machine put on the box, taken off it (TZ 7.1, 8;
protocol 3.6). The verb ``destroy`` is this ladder; ``reinstall`` runs it
before the ``install`` ladder, in one plan.

What stays, by design: ``history/`` and ``journal/`` (a verdict lives forever),
``keys/`` (the box's age key is a recipient of its passport, the deploy keys are
in the repositories), the passport's copy, ``env/minted.yaml`` of every stack
(a minted secret is minted once: the database of a persistent volume opens with
it; ``reinstall --new-secrets`` removes it) and the volumes of every stack
entry with ``persistent: true`` -- named in the fact of ``remove_objects``.
Everything else goes, in this order:

- ``remove_objects`` -- the point of no return: every container, network,
  volume and image labelled ``pridem.stack`` (the stacks', the edge's, the
  proxy's, the machine's networks), but the persistent volumes, chosen by
  their label ``pridem.stack=<entry>``. An entry is persistent when
  ``primer.yaml`` of ``current`` of a stack ``state.json`` names says so, or
  ``/opt/pridem/kept-volumes.json`` -- written before the first ``docker rm``
  and kept by ``forget_state`` -- names its volume: a repeat after a failure
  and the next ``destroy`` know what stays. A labelled volume whose entry
  neither source names refuses the step before anything is removed
  (``persistent-unknown``): a volume of people's files is never removed by
  guess; where the sources differ, persistent wins. ``--new-secrets`` with a
  volume kept refuses too (``new-secrets-kept``): a new password against the
  old data;
- ``remove_files`` -- ``/opt/<stack>`` of every stack with the machine's mark
  (``/opt/<stack>/.pridem``, ``steps/sources.py``), but ``env/minted.yaml``
  and, while it stays, the mark; ``/opt/pridem/edge`` and
  ``/opt/pridem/egress``. A directory without the mark is not the machine's
  and is left alone; one whose mark names another stack refuses
  (``foreign-marker``), already in ``remove_objects``, before the point of no
  return;
- ``remove_timers`` -- the box's own timers and their services;
- ``forget_state`` -- ``state.json``, last: until here it names what is on the
  box.

``verify`` of each step reads the box back; on a box with nothing to remove
every ``check`` says so and nothing acts.
"""

import json
import shutil
from collections.abc import Iterable
from pathlib import Path
from typing import ClassVar

from pridem.events import Json, strings
from pridem.files import atomic_write
from pridem.stacks.loader import ContractError
from pridem.stacks.schema import load_primer_yaml
from pridem.state import STATE, Box
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
from pridem.steps.edge import STACK_LABEL as EDGE_LABEL
from pridem.steps.egress import STACK_LABEL as EGRESS_LABEL
from pridem.steps.finalize import current_link
from pridem.steps.host import STACK_LABEL as HOST_LABEL
from pridem.steps.host import _installed
from pridem.steps.sources import MARKER, marked
from pridem.steps.timers import UNIT_DIR

MODES: frozenset[Mode] = frozenset({"destroy", "reinstall"})
STACK = "destroy"
LABEL = "label=pridem.stack"
MINTED = Path("env") / "minted.yaml"
TIMERS = ("pridem-gc.timer", "pridem-ssl-renew.timer")
UNITS = (*TIMERS, "pridem-gc.service", "pridem-ssl-renew.service")
KEPT = "kept-volumes.json"
"""``/opt/pridem/kept-volumes.json``: the volumes ``destroy`` keeps and their
entries, ``{"schema": 1, "volumes": {volume: entry}}``."""
MACHINE_DIRS = ("edge", "egress")
"""The machine's own stacks' directories under ``/opt/pridem``."""
MACHINE_ENTRIES = frozenset(
    label["pridem.stack"] for label in (EDGE_LABEL, EGRESS_LABEL, HOST_LABEL)
)
"""The ``pridem.stack`` of the machine's own stacks -- the edge, the proxy,
the host's networks: no record of a product names them, and their volumes
(the edge's ACME webroot) are the machine's, not people's -- they go."""


def _j(items: Iterable[str]) -> list[Json]:
    return list[Json](sorted(items))


def _lines(ctx: StepContext, argv: list[str]) -> list[str]:
    _, lines = out(ctx, argv, passed_on=False)
    return sorted({line.strip() for line in lines if line.strip()})


class _Objects:
    """The labelled docker objects of the box, as ``docker`` lists them."""

    def __init__(self, ctx: StepContext) -> None:
        self.containers = _lines(ctx, ["docker", "ps", "-aq", "--filter", LABEL])
        self.networks = _lines(
            ctx,
            ["docker", "network", "ls", "--filter", LABEL, "--format", "{{.Name}}"],
        )
        volumes = _lines(
            ctx,
            [
                "docker",
                "volume",
                "ls",
                "--filter",
                LABEL,
                "--format",
                '{{.Name}}\t{{.Label "pridem.stack"}}',
            ],
        )
        self.volumes = dict(line.partition("\t")[::2] for line in volumes)
        """volume -> its ``pridem.stack``."""
        self.images = _lines(
            ctx, ["docker", "image", "ls", "-q", "--no-trunc", "--filter", LABEL]
        )


def _entries(root: Path, box: Box) -> tuple[set[str], set[str]]:
    """The entries of every stack ``state.json`` names, by ``primer.yaml`` of
    its ``current``: the persistent ones and the others -- with the
    machine's own stacks (``MACHINE_ENTRIES``) among the others. A stack
    whose release cannot be read gives neither -- its volumes stay
    unplaced."""
    persistent: set[str] = set()
    others: set[str] = set(MACHINE_ENTRIES)
    state = box.read_state()
    for stack in state.current if state is not None else ():
        try:
            config = load_primer_yaml(current_link(root, stack) / "primer.yaml")
        except (ContractError, OSError):
            continue
        for name, entry in config.stacks.items():
            (persistent if entry.persistent else others).add(name)
    return persistent, others


def read_kept(box: Box) -> dict[str, str]:
    """``kept-volumes.json``: volume -> entry; none -- an empty mapping."""
    path = box.root / KEPT
    if not path.is_file():
        return {}
    document = json.loads(path.read_text(encoding="utf-8"))
    return {str(k): str(v) for k, v in dict(document.get("volumes", {})).items()}


def _foreign(root: Path) -> None:
    """A directory of ``/opt`` whose mark names another stack: refused."""
    _, astray = marked(root)
    if astray:
        raise StepFailed("foreign-marker", {"paths": _j(str(p) for p in astray)})


class RemoveObjects(Step):
    """Every labelled docker object but the persistent volumes."""

    name = "remove_objects"
    order = 1
    modes = MODES
    point_of_no_return = True
    codes: ClassVar[dict[str, str]] = {
        "remove": (
            "remove {containers} containers, {networks} networks, {volumes} "
            "volumes, {images} images; keep {kept}"
        ),
        "persistent-unknown": (
            "volumes {volumes} cannot be told persistent or not: no entry of a "
            "readable primer.yaml of current nor kept-volumes.json names them"
        ),
        "new-secrets-kept": (
            "--new-secrets with volumes kept {volumes}: a new password against "
            "their data"
        ),
        "foreign-marker": "the mark of {paths} names another stack",
        "left": "still on the box: {objects}",
    }

    def __init__(
        self, *, box: Box, root: Path = Path("/"), new_secrets: bool = False
    ) -> None:
        self.box = box
        self.root = root
        self.new_secrets = new_secrets

    def _seen(self, ctx: StepContext) -> tuple[_Objects, list[str]] | None:
        """The objects and the volumes kept; ``None`` without docker. Every
        refusal of the ladder that can come before the point of no return
        comes here, in ``check``."""
        _foreign(self.root)
        if not _installed(ctx, "docker.io"):
            return None
        seen = _Objects(ctx)
        persistent, others = _entries(self.root, self.box)
        known = read_kept(self.box)
        kept: list[str] = []
        unknown: list[str] = []
        for name, entry in seen.volumes.items():
            if name in known or entry in persistent:
                kept.append(name)  # persistent wins where the sources differ
            elif entry not in others:
                unknown.append(name)
        if unknown:
            raise StepFailed("persistent-unknown", {"volumes": _j(unknown)})
        if kept and self.new_secrets:
            raise StepFailed("new-secrets-kept", {"volumes": _j(kept)})
        return seen, sorted(kept)

    def check(self, ctx: StepContext) -> CheckResult:
        found = self._seen(ctx)
        if found is None:
            return CheckResult(False, data={"docker": False})
        seen, kept = found
        gone = [name for name in seen.volumes if name not in kept]
        if not (seen.containers or seen.networks or gone or seen.images):
            return CheckResult(False, data={"kept": _j(kept)})
        params: dict[str, Json] = {
            "containers": len(seen.containers),
            "networks": len(seen.networks),
            "volumes": len(gone),
            "images": len(seen.images),
            "kept": _j(kept),
        }
        return CheckResult(True, local_code("remove", params), {"kept": _j(kept)})

    def act(self, ctx: StepContext, check: CheckResult) -> None:
        found = self._seen(ctx)
        if found is None:
            return
        seen, kept = found
        gone = sorted(name for name in seen.volumes if name not in kept)
        # what stays is written before the first removal: a repeat after a
        # failure, and the next destroy, still know it (forget_state keeps it)
        document = {"schema": 1, "volumes": {name: seen.volumes[name] for name in kept}}
        atomic_write(self.box.root / KEPT, json.dumps(document, indent=2) + "\n", 0o600)
        if seen.containers:
            out(ctx, ["docker", "rm", "-f", *seen.containers])
        if gone:
            out(ctx, ["docker", "volume", "rm", *gone])
        if seen.networks:
            out(ctx, ["docker", "network", "rm", *seen.networks])
        if seen.images:
            out(ctx, ["docker", "image", "rm", "-f", *seen.images])

    def verify(self, ctx: StepContext, check: CheckResult) -> Verified:
        if check.data.get("docker") is False and not _installed(ctx, "docker.io"):
            return Verified({"docker": "absent"})
        seen = _Objects(ctx)
        kept = sorted(seen.volumes)
        expected = strings(check.data.get("kept"))
        left = [*seen.containers, *seen.networks, *seen.images]
        left += [name for name in kept if name not in expected]
        if left:
            raise StepFailed("left", {"objects": _j(left)})
        return Verified(
            {"containers": 0, "networks": 0, "images": 0, "kept_volumes": _j(kept)}
        )


def machine_stacks(root: Path) -> list[Path]:
    """``/opt/<stack>`` of every stack with the machine's mark."""
    mine, _ = marked(root)
    return mine


class RemoveFiles(Step):
    """``/opt/<stack>`` but ``env/minted.yaml``; the edge's and the proxy's."""

    name = "remove_files"
    order = 2
    modes = MODES
    codes: ClassVar[dict[str, str]] = {
        "remove": "remove {paths}",
        "left": "still on the box: {paths}",
        "foreign-marker": "the mark of {paths} names another stack",
    }

    def __init__(self, *, root: Path = Path("/"), new_secrets: bool = False) -> None:
        self.root = root
        self.new_secrets = new_secrets

    def _doomed(self) -> list[Path]:
        """What is to go: every path but the minted secrets kept."""
        doomed: list[Path] = []
        for home in machine_stacks(self.root):
            for path in sorted(home.iterdir()):
                if path.name == MARKER:
                    continue  # it goes with the directory, or stays with minted
                if path.name == MINTED.parts[0] and not self.new_secrets:
                    doomed += [
                        p for p in sorted(path.iterdir()) if p.name != MINTED.name
                    ]
                else:
                    doomed.append(path)
        pridem = self.root / "opt" / "pridem"
        doomed += [pridem / name for name in MACHINE_DIRS if (pridem / name).exists()]
        return doomed

    def check(self, ctx: StepContext) -> CheckResult:
        _foreign(self.root)
        doomed = self._doomed()
        if not doomed:
            return CheckResult(False)
        paths = _j(str(path) for path in doomed)
        return CheckResult(True, local_code("remove", {"paths": paths}))

    def act(self, ctx: StepContext, check: CheckResult) -> None:
        for path in self._doomed():
            if path.is_dir() and not path.is_symlink():
                shutil.rmtree(path)
            else:
                path.unlink()
        for home in machine_stacks(self.root):
            if all(path.name == MARKER for path in home.rglob("*")):
                shutil.rmtree(home)  # nothing of the stack left but its mark

    def verify(self, ctx: StepContext, check: CheckResult) -> Verified:
        left = self._doomed()
        if left:
            raise StepFailed("left", {"paths": _j(str(path) for path in left)})
        kept = [
            str(home / MINTED)
            for home in machine_stacks(self.root)
            if (home / MINTED).is_file()
        ]
        return Verified({"kept_minted": _j(kept), "new_secrets": self.new_secrets})


class RemoveTimers(Step):
    """The box's own timers and their services."""

    name = "remove_timers"
    order = 3
    modes = MODES
    codes: ClassVar[dict[str, str]] = {
        "remove": "remove {units}",
        "left": "still on the box: {units}",
    }

    def __init__(self, *, root: Path = Path("/")) -> None:
        self.root = root

    def _present(self) -> list[str]:
        return [unit for unit in UNITS if (self.root / UNIT_DIR / unit).exists()]

    def check(self, ctx: StepContext) -> CheckResult:
        present = self._present()
        if not present:
            return CheckResult(False)
        return CheckResult(True, local_code("remove", {"units": _j(present)}))

    def act(self, ctx: StepContext, check: CheckResult) -> None:
        timers = [unit for unit in TIMERS if unit in self._present()]
        if timers:
            out(ctx, ["systemctl", "disable", "--now", *timers])
        for unit in self._present():
            (self.root / UNIT_DIR / unit).unlink()
        out(ctx, ["systemctl", "daemon-reload"])

    def verify(self, ctx: StepContext, check: CheckResult) -> Verified:
        present = self._present()
        if present:
            raise StepFailed("left", {"units": _j(present)})
        return Verified({"units": []})


class ForgetState(Step):
    """``state.json``, last: the box has no composition left."""

    name = "forget_state"
    order = 4
    modes = MODES
    codes: ClassVar[dict[str, str]] = {
        "forget": "remove state.json",
        "left": "state.json is still on the box",
    }

    def __init__(self, *, box: Box) -> None:
        self.box = box

    def _path(self) -> Path:
        return self.box.root / STATE

    def check(self, ctx: StepContext) -> CheckResult:
        if not self._path().exists():
            return CheckResult(False)
        return CheckResult(True, local_code("forget"))

    def act(self, ctx: StepContext, check: CheckResult) -> None:
        self.box.remove_state()

    def verify(self, ctx: StepContext, check: CheckResult) -> Verified:
        if self._path().exists():
            raise StepFailed("left")
        return Verified({"state": "absent"})


def destroy_steps(root: Path, *, box: Box, new_secrets: bool = False) -> list[Step]:
    """The ``destroy`` ladder, as stack ``STACK``."""
    return [
        RemoveObjects(box=box, root=root, new_secrets=new_secrets),
        RemoveFiles(root=root, new_secrets=new_secrets),
        RemoveTimers(root=root),
        ForgetState(box=box),
    ]
