"""Tier 3 probe (DM-10): ``primer-blank`` fetched over ssh on a clean runner.

The deploy key comes from the CI secret ``PRIMER_BLANK_DEPLOY_KEY``: the
workflow writes it to a 0600 file and passes only the file's path through
``sudo --preserve-env=PRIMER_DEPLOY_KEY_FILE``. The probe puts the key where
the machine keeps keys, so the ceremony finds key and access and does not act.
The plan is built in the machine's venv, as for the host steps.

GitHub's host keys (DM-52): the machine's copy is what ``ssh-keyscan github.com``
reads on the runner, and its fingerprints are what GitHub publishes in
``api.github.com/meta`` -- the DSA fingerprint, of a key GitHub closed down,
aside -- asked with the workflow's own token, through a 0600 header file whose
path alone passes ``sudo``. The clone trusts nothing on first
use: no ``github.com`` line lands in the machine's ``known_hosts``. With the
machine's copy emptied and GitHub's real keys planted in
``/etc/ssh/ssh_known_hosts``, ssh still refuses GitHub -- the global file is not
read for it -- and with the copy back it answers again.
"""

import base64
import hashlib
import json
import os
import shutil
from pathlib import Path

from pridem.report.schema import Verdict
from pridem.runner import Stream, SubprocessRunner
from pridem.steps.git import KEYS, git_env, repo
from pridem.steps.keys import GITHUB_HOST_KEYS, PINNED

PYTHON = "/opt/pridem/current/venv/bin/python"
ADDRESS = "git@github.com:inzoddwetrust/primer-blank.git"
SCRIPT = """
import sys
from datetime import UTC, datetime
from pathlib import Path
from secrets import token_hex
from pridem import __version__
from pridem.events import ConsoleSink, Secrets
from pridem.plan import Plan, StackSteps
from pridem.report.schema import build_verdict
from pridem.runner import SubprocessRunner
from pridem.state import Box
from pridem.steps.keys import DeployKey
from pridem.steps.sources import source_steps

root, address = Path("/"), sys.argv[1]
_, steps = source_steps(root, stack="blank", address=address, ref="main", tag=False)
box, secrets = Box(Path("/opt/pridem")), Secrets(())
key_step = DeployKey(address, root, wait_s=30)
with box.lock("tier3-sources"):
    started = datetime.now(UTC).replace(microsecond=0)
    outcome = Plan(
        [StackSteps("sources", [key_step, *steps], root=True)],
        mode="install", role="test", runner=SubprocessRunner(),
        sink=ConsoleSink(sys.stdout, secrets),
    ).run()
    verdict = build_verdict(
        outcome, run_id=f"{started:%Y-%m-%dT%H:%M:%SZ}-{token_hex(2)}",
        verb="install", args={}, actor={"type": "machine", "via": "local"},
        started=started, finished=datetime.now(UTC).replace(microsecond=0),
        passport_version=None, composition_before={"pridem": __version__},
        composition_after={"pridem": __version__}, secrets=secrets,
    )
    box.write_verdict(verdict)
print("VERDICT " + verdict.model_dump_json())
sys.exit(int(verdict.exit_code))  # the exit code is the verdict's, as a verb's
"""


def _run(argv: list[str], expect: tuple[int, ...] = (0, 1, 2)) -> tuple[int, list[str]]:
    lines: list[str] = []

    def keep(stream: Stream, line: str, cut: bool) -> None:
        lines.append(line)

    runner = SubprocessRunner()
    return runner.run(argv, expect=expect, timeout=900, on_line=keep).code, lines


def _fingerprint(key: str) -> str:
    """``<type> <base64>`` -> its SHA256 fingerprint as ``/meta`` publishes it:
    base64 of the digest of the key blob, no padding, no ``SHA256:`` prefix."""
    blob = base64.b64decode(key.split()[1])
    return base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip("=")


def _stdout(argv: list[str]) -> list[str]:
    lines: list[str] = []

    def keep(stream: Stream, line: str, cut: bool) -> None:
        if stream is Stream.STDOUT:
            lines.append(line)

    SubprocessRunner().run(argv, timeout=120, on_line=keep)
    return lines


def _ls_remote(url: str) -> tuple[int, list[str]]:
    """``git ls-remote`` with the machine's environment: its ssh_config, its keys."""
    lines: list[str] = []

    def keep(stream: Stream, line: str, cut: bool) -> None:
        lines.append(line)

    result = SubprocessRunner().run(
        ["git", "ls-remote", "--heads", url],
        expect=(0, 128),
        timeout=120,
        env=git_env(Path("/")),
        on_line=keep,
    )
    return result.code, lines


def _plan() -> tuple[Verdict, list[str]]:
    code, lines = _run([PYTHON, "-c", SCRIPT, ADDRESS])
    [line] = [line for line in lines if line.startswith("VERDICT ")]
    verdict = Verdict.model_validate_json(line.removeprefix("VERDICT "))
    assert int(verdict.exit_code) == code, lines
    return verdict, lines


def test_probe_DM_10_blank_is_fetched_by_ref_over_ssh() -> None:
    source = Path(os.environ["PRIMER_DEPLOY_KEY_FILE"])
    assert source.stat().st_size > 0, "the CI secret PRIMER_BLANK_DEPLOY_KEY is empty"
    keys = Path("/") / KEYS
    keys.mkdir(mode=0o700, parents=True, exist_ok=True)
    key = keys / repo(ADDRESS).alias
    shutil.copyfile(source, key)
    key.chmod(0o600)
    # FIX DM-10: a key without access made the ceremony wait KEY_WAIT_S (1800 s)
    # past the probe's timeout and the reason was lost; the probe now waits 30 s
    # and first proves the secret is a private key ssh can read
    code, public = _run(["ssh-keygen", "-y", "-f", str(key)], expect=(0, 255))
    assert code == 0, f"the secret is not a private key ssh reads: {public}"
    verdict, lines = _plan()
    assert verdict.result == "green", (public, lines)
    by = {step.name: step for step in verdict.steps}
    fetched = by["fetch_root"].verify or {}
    assert fetched["config"] == "blank" and fetched["release"] == fetched["head"]
    release = Path("/opt/blank/releases") / str(fetched["head"])
    assert (release / "primer.yaml").exists()
    assert not Path("/opt/blank/current").exists()  # releases/ is inert
    assert "MARKER" not in "".join(lines) and "PRIVATE KEY" not in "".join(lines)
    # the second run acts on nothing: the release is clean and on target
    again, _ = _plan()
    assert again.result == "green"
    assert (again.steps[1].verify or {})["drift_discarded"] == []

    # GitHub's host keys (DM-52): the copy is what github.com serves ...
    scanned = _stdout(["ssh-keyscan", "-t", "ed25519,ecdsa,rsa", "github.com"])
    served = {
        line.split(None, 1)[1] for line in scanned if line.startswith("github.com ")
    }
    assert served == set(GITHUB_HOST_KEYS), scanned
    # ... and what GitHub publishes
    header = os.environ["PRIMER_GITHUB_API_HEADER_FILE"]
    meta = json.loads(
        "\n".join(
            _stdout(
                [
                    "curl",
                    "--fail",
                    "--show-error",
                    "--no-progress-meter",
                    "--header",
                    f"@{header}",
                    "https://api.github.com/meta",
                ]
            )
        )
    )
    published = {
        value
        for name, value in meta["ssh_key_fingerprints"].items()
        if name != "SHA256_DSA"  # GitHub's DSA key is gone; no key line pins it
    }
    assert published == {_fingerprint(key) for key in GITHUB_HOST_KEYS}, published
    # the clone trusted nothing on first use
    keys = Path("/") / KEYS
    accepted = keys / "known_hosts"
    lines = accepted.read_text().splitlines() if accepted.exists() else []
    assert not [line for line in lines if "github.com" in line], lines
    config = (keys / "ssh_config").read_text()
    assert (
        "StrictHostKeyChecking yes" in config and "GlobalKnownHostsFile none" in config
    )
    # GitHub's real keys in the global file do not stand in for the machine's copy
    url = repo(ADDRESS).url()
    pinned, global_file = keys / PINNED, Path("/etc/ssh/ssh_known_hosts")
    saved = pinned.read_text()
    had_global = global_file.exists()
    before = global_file.read_text() if had_global else ""
    try:
        pinned.write_text("")
        global_file.write_text(
            before + "".join(f"github.com {k}\n" for k in GITHUB_HOST_KEYS)
        )
        code, said = _ls_remote(url)
        assert code == 128 and "Host key verification failed" in "\n".join(said), said
    finally:
        pinned.write_text(saved)
        if had_global:
            global_file.write_text(before)
        else:
            global_file.unlink()
    # the pair: the copy back, GitHub answers
    code, said = _ls_remote(url)
    assert code == 0, said
