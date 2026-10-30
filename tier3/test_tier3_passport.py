"""Tier 3 probe (DM-13): the box decrypts its passport from a test ops repository.

The ops repository is a fixture: ``tier3/fixtures/ops`` committed into a bare
repository reached by ``file://`` (no deploy key; ssh is DM-10's probe). Its
``passports/tier3-box.yaml`` is encrypted for the test age key, whose private
part is the CI secret ``PRIMER_TIER3_AGE_KEY``: the workflow writes it to a
0600 file and passes only the path through ``sudo
--preserve-env=PRIMER_AGE_KEY_FILE``, and the probe puts it where the machine
keeps its age key, so ``age_key`` finds it and does not act.
``passports/tier3-other.yaml`` is encrypted for a key that was thrown away:
fetching it is red, ``not-recipient``, with the box's public key. The plan runs
in the machine's venv against the installed package; on red and on timeout the
probe prints every line it collected.
"""

import os
import shutil
from pathlib import Path

from pridem.report.schema import StepCode, Verdict
from pridem.runner import CommandTimedOut, Stream, SubprocessRunner
from pridem.steps.passport import AGE_KEY, PASSPORT_COPY

PYTHON = "/opt/pridem/current/venv/bin/python"
FIXTURE = Path(__file__).parent / "fixtures" / "ops"
SECRETS = ("tier3-invented-telegram-token", "tier3-invented-other-token-1")
SCRIPT = """
import sys
from datetime import UTC, datetime
from pathlib import Path
from secrets import token_hex
from pydantic import SecretStr
from pridem import __version__
from pridem.events import ConsoleSink, Secrets
from pridem.plan import Plan, StackSteps
from pridem.report.catalog import ENGLISH, with_steps
from pridem.report.schema import build_verdict
from pridem.runner import SubprocessRunner
from pridem.state import Box
from pridem.steps.passport import OpsSource, passport_steps

root, address, server = Path("/"), sys.argv[1], sys.argv[2]
fetched, steps = passport_steps(
    root, server=server, ops=OpsSource(address), wait_s=5, poll_s=2
)
box, secrets = Box(Path("/opt/pridem")), Secrets(())
with box.lock("tier3-passport"):
    started = datetime.now(UTC).replace(microsecond=0)
    outcome = Plan(
        [StackSteps("passport", steps, root=True)],
        mode="install", role="test", runner=SubprocessRunner(),
        sink=ConsoleSink(sys.stdout, secrets),
    ).run()
    version = fetched.passport.version if fetched.passport is not None else None
    verdict = build_verdict(
        outcome, run_id=f"{started:%Y-%m-%dT%H:%M:%SZ}-{token_hex(2)}",
        verb="install", args={}, actor={"type": "machine", "via": "local"},
        started=started, finished=datetime.now(UTC).replace(microsecond=0),
        passport_version=version, composition_before={"pridem": __version__},
        composition_after={"pridem": __version__}, secrets=secrets,
        catalog=with_steps(ENGLISH, [(step.name, step.codes) for step in steps]),
    )
    box.write_verdict(verdict)
print("OPS_COMMIT " + str(fetched.ops_commit))
print("VERDICT " + verdict.model_dump_json())
sys.exit(int(verdict.exit_code))  # the exit code is the verdict's, as a verb's
"""


def _out(argv: list[str], env: dict[str, str] | None = None) -> str:
    out: list[str] = []

    def keep(stream: Stream, line: str, cut: bool) -> None:
        if stream is Stream.STDOUT:
            out.append(line)

    SubprocessRunner().run(argv, env=env, timeout=120, on_line=keep)
    return "\n".join(out).strip()


def _git(*args: str) -> str:
    env = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "HOME": "/nonexistent",
        "GIT_AUTHOR_NAME": "t",
        "GIT_AUTHOR_EMAIL": "t@example.org",
        "GIT_COMMITTER_NAME": "t",
        "GIT_COMMITTER_EMAIL": "t@example.org",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_NOSYSTEM": "1",
    }
    return _out(["git", *args], env)


def _ops_repository(tmp: Path) -> tuple[str, str]:
    """The fixture committed on ``main`` of a bare repository; (address, head)."""
    work = tmp / "ops-work"
    shutil.copytree(FIXTURE, work)
    _git("-C", str(work), "init", "-q", "-b", "main")
    _git("-C", str(work), "add", "-A")
    _git("-C", str(work), "commit", "-q", "-m", "passports")
    bare = tmp / "ops.git"
    _git("clone", "-q", "--bare", str(work), str(bare))
    return f"file://{bare}", _git("-C", str(bare), "rev-parse", "main")


def _plan(address: str, server: str) -> tuple[Verdict, str, list[str]]:
    lines: list[str] = []

    def keep(stream: Stream, line: str, cut: bool) -> None:
        lines.append(line)

    try:
        SubprocessRunner().run(
            [PYTHON, "-c", SCRIPT, address, server],
            expect=(0, 1, 2),
            timeout=300,
            on_line=keep,
        )
    except CommandTimedOut:
        raise AssertionError("\n".join(lines)) from None
    verdicts = [line for line in lines if line.startswith("VERDICT ")]
    assert len(verdicts) == 1, "\n".join(lines)
    [commit] = [line for line in lines if line.startswith("OPS_COMMIT ")]
    verdict = Verdict.model_validate_json(verdicts[0].removeprefix("VERDICT "))
    return verdict, commit.removeprefix("OPS_COMMIT "), lines


def _place_key() -> str:
    source = Path(os.environ["PRIMER_AGE_KEY_FILE"])
    assert source.stat().st_size > 1, "the CI secret PRIMER_TIER3_AGE_KEY is empty"
    key = Path("/") / AGE_KEY
    key.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    shutil.copyfile(source, key)
    key.chmod(0o600)
    return _out(["age-keygen", "-y", str(key)])


def test_tier3_box_decrypts_its_passport_from_the_ops_repository(
    tmp_path: Path,
) -> None:
    public = _place_key()
    address, head = _ops_repository(tmp_path)

    verdict, commit, lines = _plan(address, "tier3-box")

    printed = "\n".join(lines)
    assert verdict.result == "green", printed
    assert verdict.passport_version == 3, printed
    assert commit == head, printed
    facts = {step.name: step.verify or {} for step in verdict.steps}
    assert facts["age_key"]["public_key"] == public, printed  # no new key minted
    assert facts["fetch_passport"]["ops_commit"] == head, printed
    assert facts["fetch_passport"]["version"] == 3, printed
    copy = Path("/") / PASSPORT_COPY
    assert oct(copy.stat().st_mode & 0o777) == oct(0o600)
    assert SECRETS[0] in copy.read_text(encoding="utf-8")  # decrypted, not empty
    assert not any(secret in printed for secret in SECRETS), printed


def test_tier3_passport_not_for_this_box_is_red_with_its_key(tmp_path: Path) -> None:
    public = _place_key()
    address, _ = _ops_repository(tmp_path)

    verdict, _, lines = _plan(address, "tier3-other")

    printed = "\n".join(lines)
    assert verdict.result == "red", printed
    [failed] = [step for step in verdict.steps if step.status == "failed"]
    assert failed.name == "fetch_passport", printed
    assert isinstance(failed.reason, StepCode), printed
    reason = failed.reason.model_dump()
    assert reason["code"] == "fetch_passport:not-recipient", printed
    assert reason["public_key"] == public, printed
    assert not any(secret in printed for secret in SECRETS), printed
