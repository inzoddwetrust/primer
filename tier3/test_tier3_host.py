"""Tier 3 probes (DM-12): the host steps on the runner, as root.

The plan is built in the machine's own venv (``/opt/pridem/current``) by a short
script: the host ladder, the real ``SubprocessRunner``, the box's lock and a
real verdict in ``history/``. There is no verb for it yet (DM-45). The dpkg
lock is planted the way ``apt`` takes it -- an ``fcntl`` lock (``lockf``) on
``/var/lib/dpkg/lock-frontend``; ``flock`` is a different lock ``apt`` does
not see (Input-0001 III). Runs after ``test_tier3_box.py``: it needs a box
the first probes found fresh.
"""

import fcntl
import threading
from pathlib import Path

from pridem.report.schema import Verdict
from pridem.runner import Stream, SubprocessRunner

PYTHON = "/opt/pridem/current/venv/bin/python"
FRONTEND = Path("/var/lib/dpkg/lock-frontend")
DOMAIN = "tier3.pridem.test"
SCRIPT = """
import json, sys
from secrets import token_hex as secrets_token
from datetime import UTC, datetime
from pathlib import Path
from pridem import __version__
from pridem.events import ConsoleSink, Secrets
from pridem.plan import Plan, StackSteps
from pridem.report.schema import build_verdict
from pridem.runner import SubprocessRunner
from pridem.state import Box
from pridem.steps.host import HOST_PACKAGES, host_steps, ProvisionHost

extra, lock_timeout = sys.argv[1].split(",") if sys.argv[1] else [], int(sys.argv[2])
main, final = host_steps(domains=[sys.argv[3]], lock_timeout_s=lock_timeout)
main[2] = ProvisionHost(packages=(*HOST_PACKAGES, *extra), lock_timeout_s=lock_timeout)
box = Box(Path("/opt/pridem"))
secrets = Secrets(())
with box.lock("tier3-host"):
    started = datetime.now(UTC).replace(microsecond=0)
    outcome = Plan(
        [StackSteps("host", main, root=True)], mode="install", role="test",
        runner=SubprocessRunner(), sink=ConsoleSink(sys.stdout, secrets),
        finally_=[StackSteps("host", final, root=True)],
    ).run()
    verdict = build_verdict(
        outcome,
        run_id=f"{started:%Y-%m-%dT%H:%M:%SZ}-{secrets_token(2)}",
        verb="install", args={}, actor={"type": "machine", "via": "local"},
        started=started, finished=datetime.now(UTC).replace(microsecond=0),
        passport_version=None, composition_before={"pridem": __version__},
        composition_after={"pridem": __version__}, secrets=secrets,
    )
    box.write_verdict(verdict)
print("VERDICT " + verdict.model_dump_json())
"""


def _run(argv: list[str], timeout: float = 1800) -> tuple[int, list[str]]:
    lines: list[str] = []

    def keep(stream: Stream, line: str, cut: bool) -> None:
        lines.append(line)

    runner = SubprocessRunner()
    result = runner.run(argv, expect=(0, 1, 2), timeout=timeout, on_line=keep)
    return result.code, lines


def _public_ip() -> str:
    answers = set()
    for url in ("https://api.ipify.org", "https://checkip.amazonaws.com"):
        code, lines = _run(["curl", "-fsS", "--max-time", "10", url], timeout=30)
        assert code == 0 and lines, url
        answers.add(lines[0].strip())
    assert len(answers) == 1, answers
    return answers.pop()


def _hosts(ip: str) -> None:
    hosts = Path("/etc/hosts")
    text = hosts.read_text()
    if DOMAIN not in text:
        hosts.write_text(text + f"{ip} {DOMAIN}\n")


def _plan(extra: str, lock_timeout: int) -> tuple[Verdict, list[str]]:
    code, lines = _run([PYTHON, "-c", SCRIPT, extra, str(lock_timeout), DOMAIN])
    [line] = [line for line in lines if line.startswith("VERDICT ")]
    verdict = Verdict.model_validate_json(line.removeprefix("VERDICT "))
    assert int(verdict.exit_code) == code, (code, lines)
    return verdict, lines


def _held(seconds: float) -> threading.Timer:
    """Hold the dpkg frontend lock as apt does (fcntl), released after ``seconds``."""
    handle = FRONTEND.open("w")
    fcntl.lockf(handle, fcntl.LOCK_EX)

    def release() -> None:
        fcntl.lockf(handle, fcntl.LOCK_UN)
        handle.close()

    timer = threading.Timer(seconds, release)
    timer.start()
    return timer


def test_probe_DM_12_host_steps_on_a_clean_runner() -> None:
    _hosts(_public_ip())
    verdict, lines = _plan("", 600)
    assert verdict.result == "green", lines
    names = [step.name for step in verdict.steps]
    assert names == [
        "preflight",
        "wait_host_quiet",
        "provision_host",
        "daemon_json",
        "ensure_network",
        "locale",
        "restore_timers",
    ]
    assert verdict.report.dns is not None and verdict.report.dns[0].domain == DOMAIN
    code, driver = _run(["docker", "info", "--format", "{{.LoggingDriver}}"])
    assert (code, driver) == (0, ["local"])
    assert _run(["docker", "network", "inspect", "pridem"])[0] == 0
    # the second run on the ready host is green too, and acts on nothing it set
    again, _ = _plan("", 600)
    assert again.result == "green"


def _absent(package: str) -> None:
    """``package`` is not installed, so ``provision_host`` must run ``apt``.

    FIX DM-12: the runner image already had the packages the probes asked for
    (``jq``, ``tree``), ``check`` found nothing missing and ``apt`` never met the
    planted lock -- the waiting probe passed without waiting.
    """
    if _installed(package):
        _run(["apt-get", "-o", "DPkg::Lock::Timeout=600", "purge", "-y", package])
    assert not _installed(package), package


def _installed(package: str) -> bool:
    code, status = _run(["dpkg-query", "-W", "-f=${Status}", package], timeout=30)
    return code == 0 and status == ["install ok installed"]


def test_probe_DM_12_planted_dpkg_lock_waits_then_passes() -> None:
    _absent("sl")
    timer = _held(10)
    try:
        verdict, lines = _plan("sl", 120)
    finally:
        timer.join()
    assert verdict.result == "green", lines
    assert _installed("sl")


def test_probe_DM_12_planted_dpkg_lock_over_timeout_is_red_without_checkmark() -> None:
    _absent("cowsay")
    timer = _held(60)
    try:
        verdict, lines = _plan("cowsay", 5)
    finally:
        timer.join()
    assert verdict.result == "red", lines
    provision = [step for step in verdict.steps if step.name == "provision_host"]
    assert provision[0].status == "failed"
    assert not any(line.startswith("✓ host · provision_host") for line in lines)
    assert not _installed("cowsay")
