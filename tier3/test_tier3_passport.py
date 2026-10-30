"""Tier 3 probe (DM-13): the box mints its age key and decrypts its passport.

Nothing comes from outside the run. The box's age pair is minted by the
machine's own ceremony (``age_key`` alone, first plan); the probe reads the
public part from that step's fact and encrypts an invented test passport for
it with ``sops`` in the run; the ops repository is a bare repository the probe
commits that file to, reached by ``file://`` (no deploy key; ssh is DM-10's
probe). The second plan is the whole ladder: ``age_key`` finds the key and
does not act, ``fetch_passport`` decrypts with it. A passport encrypted in the
run for a key minted and thrown away at once is red, ``not-recipient``, with
the box's public key. The plans run in the machine's venv against the
installed package; on red and on timeout the probe prints every line it
collected.
"""

import os
from pathlib import Path

import yaml

from pridem.report.schema import StepCode, Verdict
from pridem.runner import CommandTimedOut, Stream, SubprocessRunner
from pridem.steps.passport import AGE_KEY, PASSPORT_COPY

PYTHON = "/opt/pridem/current/venv/bin/python"
KEY_ONLY = "-"
SECRETS = ("tier3-invented-telegram-token", "tier3-invented-other-token-1")
SCRIPT = """
import sys
from datetime import UTC, datetime
from pathlib import Path
from secrets import token_hex
from pridem import __version__
from pridem.events import ConsoleSink, Secrets
from pridem.plan import Plan, StackSteps
from pridem.report.catalog import ENGLISH, with_steps
from pridem.report.schema import build_verdict
from pridem.runner import SubprocessRunner
from pridem.state import Box
from pridem.steps.passport import AgeKey, Fetched, OpsSource, passport_steps

root, address, server = Path("/"), sys.argv[1], sys.argv[2]
if address == "-":  # the ceremony alone: mint the box's key, print its public part
    fetched, steps = Fetched(), [AgeKey(root)]
else:
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
GIT_ENV = {
    "PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
    "HOME": "/nonexistent",
    "GIT_AUTHOR_NAME": "t",
    "GIT_AUTHOR_EMAIL": "t@example.org",
    "GIT_COMMITTER_NAME": "t",
    "GIT_COMMITTER_EMAIL": "t@example.org",
    "GIT_CONFIG_GLOBAL": os.devnull,
    "GIT_CONFIG_NOSYSTEM": "1",
}


def _out(argv: list[str], env: dict[str, str] | None = None) -> str:
    out: list[str] = []

    def keep(stream: Stream, line: str, cut: bool) -> None:
        if stream is Stream.STDOUT:
            out.append(line)

    SubprocessRunner().run(argv, env=env, timeout=120, on_line=keep)
    return "\n".join(out).strip()


def _git(*args: str) -> str:
    return _out(["git", *args], GIT_ENV)


def _passport(server: str, secret: str) -> dict[str, object]:
    """An invented passport for ``server``; its one secret is ``secret``."""
    return {
        "schema": 1,
        "version": 3,
        "server": {"name": server, "role": "test", "os": "ubuntu-24.04"},
        "product": {"repo": "file:///tmp/tier3/no-product.git", "ref": "main"},
        "domains": {"frontend": "tier3.example.org"},
        "access": {"mode": "deploy-keys"},
        "asked": {"comms": {"TELEGRAM_BOT_TOKEN": secret}},
        "params": {"comms": {"SUPPORT_LANGUAGE": "ru"}},
        "policies": {
            "ssl": "self-signed",
            "gc": {
                "keep_releases": 2,
                "builder_cache_budget": "3G",
                "journal_budget": "200M",
            },
            "backup": {"enabled": False},
            "timers": {"gc": "daily"},
        },
        "packages": {},
        "cloud": {},
    }


def _encrypt(tmp: Path, data: dict[str, object], public: str) -> str:
    """``data`` encrypted by sops for ``public``; the plaintext does not stay."""
    plain = tmp / "plain.yaml"
    plain.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
    env = {**GIT_ENV, "HOME": str(tmp)}
    try:
        return _out(["sops", "--encrypt", "--age", public, str(plain)], env) + "\n"
    finally:
        plain.unlink()


def _thrown_away_public(tmp: Path) -> str:
    """The public part of a key minted here and deleted at once."""
    key = tmp / "thrown.key"
    try:
        SubprocessRunner().run(
            ["age-keygen", "-o", str(key)],
            timeout=60,
            on_line=lambda stream, line, cut: None,
        )
        return _out(["age-keygen", "-y", str(key)])
    finally:
        key.unlink(missing_ok=True)


def _ops_repository(tmp: Path, passports: dict[str, str]) -> tuple[str, str]:
    """``passports/<name>.yaml`` committed on ``main`` of a bare repository;
    (address, head)."""
    work = tmp / "ops-work"
    (work / "passports").mkdir(parents=True)
    for name, text in passports.items():
        (work / "passports" / f"{name}.yaml").write_text(text, encoding="utf-8")
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


def _box_public() -> tuple[str, bool]:
    """The box's public key by the machine's ceremony; whether it was minted."""
    key = Path("/") / AGE_KEY
    absent = not key.exists()
    verdict, _, lines = _plan(KEY_ONLY, "-")
    printed = "\n".join(lines)
    assert verdict.result == "green", printed
    [step] = verdict.steps
    public = (step.verify or {})["public_key"]
    assert isinstance(public, str) and public.startswith("age1"), printed
    assert oct(key.stat().st_mode & 0o777) == oct(0o600), printed
    assert _out(["age-keygen", "-y", str(key)]) == public, printed
    console = [line for line in lines if not line.startswith("VERDICT ")]
    assert any(public in line for line in console), printed  # what the owner adds
    return public, absent


def test_tier3_box_decrypts_its_passport_from_the_ops_repository(
    tmp_path: Path,
) -> None:
    public, _ = _box_public()
    text = _encrypt(tmp_path, _passport("tier3-box", SECRETS[0]), public)
    address, head = _ops_repository(tmp_path, {"tier3-box": text})

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
    public, _ = _box_public()
    other = _thrown_away_public(tmp_path)
    assert other != public
    text = _encrypt(tmp_path, _passport("tier3-other", SECRETS[1]), other)
    address, _ = _ops_repository(tmp_path, {"tier3-other": text})

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
