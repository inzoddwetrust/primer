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
import json
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
sys.exit(int(verdict.exit_code))  # the exit code is the verdict's, as a verb's
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


DOCKER_CE = ("docker-ce", "docker-ce-cli", "containerd.io")
"""Docker's own packages, as a host prepared by hand has them (DM-190, E12)."""
DOCKER_REPO = Path("/etc/apt/sources.list.d/dm190-docker.list")
DOCKER_KEY = Path("/etc/apt/keyrings/dm190-docker.asc")


def _states() -> dict[str, str]:
    """``dpkg-query`` of docker-ce and docker.io: what each says, as it says it."""
    found: dict[str, str] = {}
    for package in ("docker-ce", "docker.io"):
        code, status = _run(["dpkg-query", "-W", "-f=${Status}", package], timeout=30)
        found[package] = " ".join(status) if code == 0 else f"exit {code}"
    return found


def test_tier3_provision_host_on_a_host_with_docker_ce() -> None:
    """DM-190, E12 -- a measure, not a probe: a host whose docker is Docker's
    own (``docker-ce`` from download.docker.com, as one prepared by hand
    has it), and ``provision_host`` on it, which installs ``docker.io``.
    Printed: ``dpkg-query`` of both before and after, and the verdict's
    reason if the step is red. Nothing asserted on what it says (par0 14.3).
    Then the host is as the probes after it find it: Docker's packages and
    its source gone, ``provision_host`` of the next probe installs as ever."""
    DOCKER_KEY.parent.mkdir(parents=True, exist_ok=True)
    code, _ = _run(
        ["curl", "-fsSL", "-o", str(DOCKER_KEY),
         "https://download.docker.com/linux/ubuntu/gpg"],
        timeout=120,
    )  # fmt: skip
    assert code == 0, "Docker's key"
    DOCKER_REPO.write_text(
        f"deb [arch=amd64 signed-by={DOCKER_KEY}] "
        "https://download.docker.com/linux/ubuntu noble stable\n"
    )
    apt = ["apt-get", "-o", "DPkg::Lock::Timeout=600"]
    try:
        assert _run([*apt, "update"])[0] == 0
        code, lines = _run([*apt, "install", "-y", *DOCKER_CE])
        assert code == 0, lines[-20:]
        before = _states()
        _hosts(_public_ip())
        verdict, lines = _plan("", 600)
        [provision] = [s for s in verdict.steps if s.name == "provision_host"]
        after = _states()
        print(
            "DM-190 E12 measure:",
            json.dumps(
                {
                    "before": before,
                    "after": after,
                    "provision_host": provision.status,
                    "reason": provision.reason and provision.reason.model_dump(),
                    "result": verdict.result,
                }
            ),
        )
    finally:
        _run([*apt, "purge", "-y", *DOCKER_CE])
        DOCKER_REPO.unlink(missing_ok=True)
        DOCKER_KEY.unlink(missing_ok=True)
        _run([*apt, "update"])


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
    for network in ("pridem", "pridem-egress"):  # internal, read back (DM-64)
        inspect = ["docker", "network", "inspect", "--format", "{{.Internal}}", network]
        assert _run(inspect) == (0, ["true"]), network
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
    """Changed by DM-107 (on the dispatcher's word at the gate): a line of the
    console has its time and no stack of the machine -- the step's line is looked
    for by its mark and name; the pair: the red mark is there.

    Changed by DM-107 FIX 2 (on the dispatcher's word): the script's plan attaches
    its catalog to the console now, so the step is said by its title, Install host
    packages -- the red mark is there, the green one not, as before."""
    _absent("cowsay")
    timer = _held(60)
    try:
        verdict, lines = _plan("cowsay", 5)
    finally:
        timer.join()
    assert verdict.result == "red", lines
    provision = [step for step in verdict.steps if step.name == "provision_host"]
    assert provision[0].status == "failed"
    assert not any("✓ Install host packages" in line for line in lines)
    assert any("✗ Install host packages" in line for line in lines), lines
    assert not _installed("cowsay")


POLICY_SCRIPT = """
import json, sys
from pathlib import Path
from pridem.plan import Plan, StackSteps
from pridem.runner import SubprocessRunner
from pridem.stacks.passport import load_passport
from pridem.steps.host_policy import Memory, Swap
from pridem.steps.passport import Fetched

class Sink:
    def emit(self, event):
        pass

fetched = Fetched(passport=load_passport(Path(sys.argv[1])))
floor = float(sys.argv[2])
memory = Memory(min_memory_gib=floor) if floor else Memory()
outcome = Plan(
    [StackSteps("pridem-host-policy", [Swap(fetched=fetched), memory], root=True)],
    mode="install", role="test", runner=SubprocessRunner(), sink=Sink(),
).run()
print("OUTCOME " + json.dumps({"code": int(outcome.code),
    "incomplete": [i.reason.code for i in outcome.incomplete], "steps": [
    {"name": r.name, "status": r.status, "verify": r.verify,
     "reason": r.reason.as_json() if r.reason is not None else None}
    for r in outcome.steps
]}))
"""
"""``swap`` and ``memory`` of ``pridem-host-policy`` alone, on the runner as on a
box (DM-132); ``argv[2]`` -- a floor of memory planted for the refusal, or 0."""
SWAPFILE = "/opt/pridem/host/swapfile"


def _policy_passport(tmp: Path, swap: str | None) -> Path:
    data = {
        "schema": 1,
        "version": 1,
        "server": {"name": "tier3-host", "role": "test", "os": "ubuntu-24.04"},
        "product": {"repo": "file:///srv/tier3/primer-blank.git", "ref": "main"},
        "domains": {"api": "api.tier3-host.test"},
        "access": {"mode": "deploy-keys"},
        "asked": {},
        "params": {},
        "policies": {
            "ssl": "self-signed",
            "gc": {
                "keep_releases": 2,
                "builder_cache_budget": "3G",
                "journal_budget": "200M",
            },
            "backup": {"enabled": False},
            "timers": {"gc": "daily"},
            **({"host": {"swap": swap}} if swap is not None else {}),
        },
        "packages": {},
        "cloud": {},
    }
    tmp.mkdir(parents=True, exist_ok=True)
    file = tmp / "passport.yaml"
    file.write_text(json.dumps(data), encoding="utf-8")  # JSON is YAML
    return file


def _policy(passport: Path, floor: float = 0) -> dict[str, object]:
    code, lines = _run([PYTHON, "-c", POLICY_SCRIPT, str(passport), str(floor)])
    [line] = [line for line in lines if line.startswith("OUTCOME ")]
    found = json.loads(line.removeprefix("OUTCOME "))
    assert isinstance(found, dict), lines
    print("DM-132 measure:", json.dumps(found))
    return found


def _swaps() -> list[str]:
    code, lines = _run(["swapon", "--show=NAME,TYPE,SIZE", "--bytes", "--noheadings"])
    assert code == 0, lines
    return [line for line in lines if line.strip()]


def test_probe_DM_132_swap_on_the_box_and_memory_refused(tmp_path: Path) -> None:
    """DM-132 on the runner. Measured first and printed (par0 14.3): the swap
    the runner has, its memory, sshd and root's keys. FIX: without
    ``policies.host`` the stack is green and its swap a fact. Then: a swap switched on
    is kept -- no file of the machine; with none on (the test, not the
    machine, switches the runner's off), the machine makes its own of the
    passport's size, in ``/etc/fstab`` once, and the repeat makes nothing.
    ``memory`` with a floor planted above any runner's memory is refused with
    its numbers -- the floor is planted, the runner's memory is real."""
    sshd = Path("/usr/sbin/sshd").exists()
    keys = Path("/root/.ssh/authorized_keys")
    said: tuple[int, list[str]] = (-1, [])
    if sshd:  # any exit: 255 is sshd refusing (a missing /run/sshd), measured
        lines: list[str] = []
        result = SubprocessRunner().run(
            ["sshd", "-T", "-C", "user=root,host=localhost,addr=127.0.0.1"],
            expect=tuple(range(256)),
            timeout=60,
            on_line=lambda stream, line, cut: lines.append(line),
        )
        said = (result.code, lines)
    login = [x for x in said[1] if x.startswith(("passwordauth", "kbdinteractive"))]
    measure = {
        "swaps": _swaps(),
        "meminfo": [
            line
            for line in Path("/proc/meminfo").read_text().splitlines()
            if line.startswith(("MemTotal", "SwapTotal"))
        ],
        "sshd": sshd,
        "sshd_T": [said[0], *login],
        "root_keys": keys.is_file() and bool(keys.read_text().strip()),
    }
    print("DM-132 runner:", json.dumps(measure))
    # FIX: no policies.host, as every passport of tier 3 -- green, the swap of
    # the runner a fact (its hoster's agent puts it in no fstab)
    bare = _policy(_policy_passport(tmp_path / "bare", None))
    assert bare["code"] == 0, bare
    steps = bare["steps"]
    assert isinstance(steps, list)
    [swap] = [step for step in steps if step["name"] == "swap"]
    assert swap["status"] == "ok" and swap["verify"]["wanted"] == "none", bare
    passport = _policy_passport(tmp_path, "1G")
    before = _swaps()
    if before:  # a swap on is kept: no file of the machine
        kept = _policy(passport)
        # with the field a swap in no fstab is exit 2, named (DM-132 FIX)
        words = Path("/etc/fstab").read_text().split()
        lost = [line.split()[0] for line in before if line.split()[0] not in words]
        wanted = (2, ["swap:foreign-not-in-fstab"]) if lost else (0, [])
        assert (kept["code"], kept["incomplete"]) == wanted, kept
        assert not Path(SWAPFILE).exists()
        assert _swaps() == before
        _run(["swapoff", "-a"])  # the test's hand, never the machine's
    assert _swaps() == []
    made = _policy(passport)
    assert made["code"] == 0, made
    assert any(line.split()[0] == SWAPFILE for line in _swaps()), _swaps()
    fstab = Path("/etc/fstab").read_text()
    assert fstab.count(f"{SWAPFILE} none swap sw 0 0") == 1, fstab
    again = _policy(passport)
    assert again["code"] == 0, again
    assert Path("/etc/fstab").read_text() == fstab
    refused = _policy(passport, floor=10**6)
    steps = refused["steps"]
    assert isinstance(steps, list)
    [memory] = [step for step in steps if step["name"] == "memory"]
    assert memory["status"] == "failed", refused
    assert memory["reason"]["code"] == "memory:memory-low", refused
