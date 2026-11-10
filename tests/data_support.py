"""A box that runs the blank -- ``state.json`` with its ``current``, the
release on disk, the passport's copy -- for the data verbs (DM-86)."""

import shutil
from datetime import UTC, datetime
from pathlib import Path

import yaml
from passport_support import passport_example, section

from pridem.state import Box, BoxState
from pridem.steps.passport import PASSPORT_COPY

FIXTURE = Path(__file__).parent / "fixtures" / "check" / "blank"
SHA = "0e82be562d186afc933b8779d91dddcae4278cea"
STACK = "blank"


def blank_box(
    fs_root: Path,
    *,
    role: str = "test",
    name: str = "tier1-box",
    backup: bool = True,
) -> Box:
    """``fs_root`` as a box: ``/opt/blank/current`` -> its release (the blank of
    ``tests/fixtures/check``), ``state.json`` naming it, the passport's copy."""
    release = fs_root / "opt" / STACK / "releases" / SHA
    shutil.copytree(FIXTURE, release)
    (fs_root / "opt" / STACK / "current").symlink_to(release)
    box = Box(fs_root / "opt" / "pridem")
    box.root.mkdir(parents=True, exist_ok=True)
    with box.lock("setup"):
        box.write_state(
            BoxState(
                composition={STACK: SHA[:7], "pridem": "0.0.0"},
                passport_version=1,
                current={STACK: f"releases/{SHA}"},
                last_run={},
            )
        )
    data = passport_example()
    section(data, "server")["role"] = role
    section(data, "server")["name"] = name
    section(data, "policies", "backup")["enabled"] = backup
    if role in ("prod", "preview"):  # passport rule 4: a release tag there
        section(data, "product")["ref"] = "v1.0.0"
    if role == "preview":  # passport rule 10
        section(data, "server")["expires_at"] = datetime(2027, 1, 1, tzinfo=UTC)
    copy = fs_root / PASSPORT_COPY
    copy.parent.mkdir(parents=True, exist_ok=True)
    copy.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
    copy.chmod(0o600)
    return box
