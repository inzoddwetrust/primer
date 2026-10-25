"""Tier 3 probes (DM-16): pridem as install.sh put it on a clean runner.

``.github/workflows/tier3.yml`` runs these as root after ``install.sh``; tier 1
does not collect them (``testpaths`` is ``tests``). The machine is called as
the installed binary, through ``SubprocessRunner`` like any other command. The
file runs in order: the first probe needs a box no command has touched.
"""

import fcntl
import json
import os
import re
import stat
from pathlib import Path

from pridem.runner import Stream, SubprocessRunner

BOX = Path("/opt/pridem")
PRIDEM = "/usr/local/bin/pridem"


def _pridem(*args: str) -> tuple[int, list[str], list[str]]:
    out: list[str] = []
    err: list[str] = []

    def keep(stream: Stream, line: str, cut: bool) -> None:
        (out if stream is Stream.STDOUT else err).append(line)

    result = SubprocessRunner().run(
        [PRIDEM, *args], expect=(0, 1, 2), timeout=120, on_line=keep
    )
    return result.code, out, err


def _mode(path: Path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


def test_probe_DM_16_status_on_a_fresh_box_is_green() -> None:
    assert not (BOX / "history").exists(), "the box is not fresh"
    code, out, _ = _pridem("version")
    assert code == 0 and len(out) == 1
    version = re.fullmatch(r"pridem (\d+\.\d+\.\d+)", out[0])
    assert version is not None, out
    code, out, err = _pridem("--json", "status")
    assert code == 0, err
    verdict = json.loads("\n".join(out))
    assert (verdict["verb"], verdict["result"], verdict["exit_code"]) == (
        "status",
        "green",
        0,
    )
    assert verdict["steps"] == [] and "passport_version" not in verdict
    assert verdict["composition_before"] == {"pridem": version.group(1)}
    assert verdict["composition_after"] == verdict["composition_before"]
    assert [p.name for p in (BOX / "history").iterdir()] == [
        f"{verdict['run_id']}.json"
    ]


def test_probe_DM_16_box_files_are_private_on_the_runner() -> None:
    code, _, err = _pridem("status")
    assert code == 0, err
    assert _mode(BOX) == 0o700  # FIX DM-16: install.sh makes the home root's alone
    for directory in (BOX / "history", BOX / "journal"):
        assert _mode(directory) == 0o700, directory
        files = list(directory.iterdir())
        assert len(files) == 2, files  # two status runs
        for file in files:
            assert _mode(file) == 0o600, file
            # written as temp + os.link + unlink: one name left per file
            assert file.stat().st_nlink == 1, file
    assert _mode(BOX / "lock") == 0o600
    # flock works on the runner's file system: a held lock refuses status
    with open(BOX / "lock", "rb") as held:
        fcntl.flock(held.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        code, out, err = _pridem("status")
        fcntl.flock(held.fileno(), fcntl.LOCK_UN)
    assert code == 1 and out == [] and any("busy" in line for line in err), err
    assert len(list((BOX / "history").iterdir())) == 2
    assert os.geteuid() == 0  # the box is root's; the probe ran as root
