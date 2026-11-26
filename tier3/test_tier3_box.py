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


STEPS = re.compile(r"^(1/6|2/6|3/6|4/6|5/6|6/6|2-4/6) ")
RUN = Path("/tmp/tier3")  # noqa: S108 -- the workflow's own directory (tier3.yml)
LOG = Path("/var/log/pridem-install.log")


def test_tier3_install_sh_shows_its_own_lines_alone() -> None:
    """DM-112: the screen of ``install.sh`` on this runner (the workflow kept
    it, ``tee``) -- its own lines, 1/6 to 6/6, nothing of apt, git or pip;
    their lines are in the install's log, 0600. Measured into the run's
    output (par0 14.3): the screen and the log's size.

    Changed by DM-143, on the dispatcher's word 26.11: ``install.sh`` has a
    sixth step, the agent; the workflow runs it with no token, and the
    sixth line says so."""
    screen = (RUN / "install.out").read_text(encoding="utf-8").splitlines()
    print("DM-112 measure:", {"screen": screen, "log_bytes": LOG.stat().st_size})
    assert [line.split(" ", 1)[0] for line in screen] == [
        "1/6",
        "2/6",
        "3/6",
        "4/6",
        "5/6",
        "6/6",
    ]
    assert all(STEPS.match(line) for line in screen), screen
    assert screen[-1] == (
        "6/6 agent: not registered -- no PRIDEM_REGISTER_TOKEN; "
        "the machine works without the Panel"
    )
    assert _mode(LOG) == 0o600
    assert "1/6 host" in LOG.read_text(encoding="utf-8")


def test_tier3_install_sh_refused_shows_why_the_tail_and_the_log() -> None:
    """DM-112: ``install.sh`` of a tag its repository has not -- the clone
    fails five times: the screen says why, the log's last lines and its path;
    the machine installed before is left as it was (the target of that tag is
    another directory). Changed by DM-143, on the dispatcher's word 26.11: six
    steps, not five."""
    script = (RUN / "install.sh").read_text(encoding="utf-8")
    tag = re.search(r'^TAG="(v[0-9.]+)"$', script, re.M)
    assert tag is not None
    broken = RUN / "install-v9.9.9.sh"
    broken.write_text(script.replace(f'TAG="{tag[1]}"', 'TAG="v9.9.9"', 1))
    seen: dict[Stream, list[str]] = {Stream.STDOUT: [], Stream.STDERR: []}
    result = SubprocessRunner().run(
        ["bash", str(broken)],
        timeout=600,
        expect=(1,),
        on_line=lambda s, line, cut: seen[s].append(line),
    )
    print("DM-112 measure:", seen)
    assert result.code == 1
    assert [line.split(" ", 1)[0] for line in seen[Stream.STDOUT]] == ["1/6", "2/6"]
    errors = seen[Stream.STDERR]
    assert errors[0].startswith("install.sh: cannot clone "), errors
    assert errors[1] == f"--- the last lines of {LOG} ---", errors
    assert errors[-1] == f"Full log: {LOG}", errors
    code, out, _ = _pridem("version")
    assert code == 0 and out == [f"pridem {tag[1][1:]}"], out
