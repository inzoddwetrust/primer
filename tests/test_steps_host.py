"""Host steps (DM-12) on a strict ``FakeRunner``: every command a step runs is
in the scenario, in order, and nothing else. Host files live under a temporary
``root``; the ``FakeRunner`` answers the commands.
"""

import json
from datetime import UTC, datetime
from itertools import count
from pathlib import Path

from plan_support import ListSink
from report_support import SECRETS

from pridem.events import PlanOutcome
from pridem.plan import Plan, StackSteps
from pridem.report.codes import ExitCode
from pridem.report.schema import build_verdict
from pridem.runner import FakeCall, FakeRunner, Stream
from pridem.steps.base import Step
from pridem.steps.host import (
    APT_LOCK_TIMEOUT_S,
    ECHO_SERVICES,
    HOST_PACKAGES,
    PAUSED,
    DaemonJson,
    EnsureNetwork,
    Locale,
    Preflight,
    ProvisionHost,
    RestoreTimers,
    WaitHostQuiet,
    host_steps,
)

IP = "203.0.113.7"
OK = "install ok installed"


def out(*lines: str) -> tuple[tuple[Stream, str], ...]:
    return tuple((Stream.STDOUT, line) for line in lines)


def call(*argv: str, code: int = 0, lines: tuple[str, ...] = ()) -> FakeCall:
    return FakeCall(argv, code=code, lines=out(*lines))


def dpkg(package: str, installed: bool = True) -> FakeCall:
    if installed:
        return call("dpkg-query", "-W", "-f=${Status}", package, lines=(OK,))
    return call("dpkg-query", "-W", "-f=${Status}", package, code=1)


def active(unit: str, on: bool) -> FakeCall:
    return call("systemctl", "is-active", unit, code=0 if on else 3)


def box(tmp_path: Path, lang: str = "C.UTF-8") -> Path:
    (tmp_path / "etc" / "default").mkdir(parents=True)
    (tmp_path / "etc" / "os-release").write_text('ID=ubuntu\nVERSION_ID="24.04"\n')
    (tmp_path / "etc" / "default" / "locale").write_text(f"LANG={lang}\n")
    return tmp_path


def run(
    steps: list[Step], calls: list[FakeCall], finally_: list[Step] | None = None
) -> PlanOutcome:
    runner = FakeRunner(*calls)
    ticks = count()
    with runner:
        plan = Plan(
            [StackSteps("host", steps, root=True)],
            mode="install",
            role="test",
            runner=runner,
            sink=ListSink(),
            finally_=[StackSteps("host", finally_ or [], root=True)]
            if finally_
            else (),
            clock=lambda: float(next(ticks)),
            now=lambda: datetime(2026, 10, 25, tzinfo=UTC),
        )
        return plan.run()


def preflight_calls(
    domains: dict[str, str] | None = None, docker: bool = True
) -> list[FakeCall]:
    calls = [call("id", "-u", lines=("0",)), dpkg("docker.io", docker)]
    if docker:
        calls.append(
            call(
                "docker",
                "version",
                "--format",
                "{{.Server.Version}}",
                lines=("27.5.1",),
            )
        )
    if domains is not None:
        calls += [
            call("curl", "-fsS", "--max-time", "10", url, lines=(IP,))
            for url in ECHO_SERVICES
        ]
        calls += [
            call("getent", "ahostsv4", name, lines=(f"{ip}   STREAM {name}",))
            for name, ip in domains.items()
        ]
    return calls


def ready_calls() -> list[FakeCall]:
    """A ready host: every check finds the fact, every verify reads it back."""
    quiet = [
        active(unit, False) for unit in ("apt-daily.timer", "apt-daily-upgrade.timer")
    ]
    quiet += [
        active(unit, False)
        for unit in ("apt-daily.service", "apt-daily-upgrade.service")
    ]
    quiet += [
        active(unit, False)
        for unit in ("apt-daily.service", "apt-daily-upgrade.service")
    ]
    packages = [dpkg(p) for p in HOST_PACKAGES]
    provision = [*packages, *packages, active("docker", True)]
    provision.append(
        call("docker", "version", "--format", "{{.Server.Version}}", lines=("27.5.1",))
    )
    info = call("docker", "info", "--format", "{{.LoggingDriver}}", lines=("local",))
    inspect = call(
        "docker",
        "network",
        "inspect",
        "--format",
        "{{.Name}}",
        "pridem",
        lines=("pridem",),
    )
    return [*preflight_calls(), *quiet, *provision, info, inspect, inspect]


def ready(tmp_path: Path) -> Path:
    root = box(tmp_path)
    (root / "etc" / "docker").mkdir()
    (root / "etc" / "docker" / "daemon.json").write_text(
        json.dumps({"log-driver": "local"})
    )
    return root


def test_probe_DM_12_second_run_calls_no_act(tmp_path: Path) -> None:
    """A ready host: all checks green, no act -- the strict scenario holds only
    check and verify commands. The pair: a host without the network acts."""
    root = ready(tmp_path)
    main, final = host_steps(root, min_free_gib=0)
    outcome = run(main, ready_calls(), final)
    assert outcome.code is ExitCode.OK, outcome.steps
    assert [r.status for r in outcome.steps] == ["ok"] * 6

    missing = ready_calls()
    inspect = missing[-2]
    absent = FakeCall(inspect.argv, code=1)
    create = call(
        "docker", "network", "create", "--label", "pridem.stack=host", "pridem"
    )
    missing[-2:] = [absent, create, inspect]
    main, final = host_steps(root, min_free_gib=0)
    assert run(main, missing, final).code is ExitCode.OK


def test_probe_DM_12_dns_mismatch_is_red_before_any_act(tmp_path: Path) -> None:
    root = box(tmp_path)
    wrong = preflight_calls({"app.example.org": "198.51.100.9"})
    outcome = run(
        [Preflight(root, domains=["app.example.org"], min_free_gib=0), _NeverActs()],
        wrong,
    )
    assert outcome.code is ExitCode.FAILED
    first, after = outcome.steps
    assert first.reason is not None and first.reason.code == "preflight:dns-mismatch"
    assert first.verify["dns"] == [
        {"domain": "app.example.org", "resolves_to": ["198.51.100.9"], "expected": IP}
    ]
    assert after.status == "skipped"  # nothing acted after preflight
    # the pair: the domain points here -- the plan goes on
    right = preflight_calls({"app.example.org": IP})
    outcome = run(
        [Preflight(root, domains=["app.example.org"], min_free_gib=0), _NeverActs()],
        right,
    )
    assert [r.status for r in outcome.steps] == ["ok", "ok"]


def test_echo_services_must_agree(tmp_path: Path) -> None:
    root = box(tmp_path)
    calls = preflight_calls()
    calls += [
        call("curl", "-fsS", "--max-time", "10", ECHO_SERVICES[0], lines=(IP,)),
        call(
            "curl",
            "-fsS",
            "--max-time",
            "10",
            ECHO_SERVICES[1],
            lines=("198.51.100.1",),
        ),
    ]
    outcome = run([Preflight(root, domains=["a.example.org"], min_free_gib=0)], calls)
    reason = outcome.steps[0].reason
    assert reason is not None and reason.code == "preflight:public-ip-unknown"


def test_probe_DM_12_disk_below_threshold_is_red(tmp_path: Path) -> None:
    root = box(tmp_path)
    outcome = run(
        [Preflight(root, min_free_gib=10**9)], [call("id", "-u", lines=("0",))]
    )
    reason = outcome.steps[0].reason
    assert reason is not None and reason.code == "preflight:disk-low"
    # the pair: enough disk is green
    assert run([Preflight(root, min_free_gib=0)], preflight_calls()).code is ExitCode.OK


def test_probe_DM_12_apt_always_passes_lock_timeout(tmp_path: Path) -> None:
    root = box(tmp_path)
    timeout = f"DPkg::Lock::Timeout={APT_LOCK_TIMEOUT_S}"
    before = [dpkg(p, p != "docker.io") for p in HOST_PACKAGES]
    apt = [
        call("apt-get", "-o", timeout, "update"),
        call(
            "apt-get",
            "-o",
            timeout,
            "install",
            "-y",
            "--no-install-recommends",
            "docker.io",
        ),
    ]
    after = [dpkg(p) for p in HOST_PACKAGES]
    tail = [
        active("docker", True),
        call("docker", "version", "--format", "{{.Server.Version}}", lines=("27.5.1",)),
    ]
    runner = FakeRunner(*before, *apt, *after, *tail)
    with runner:
        outcome = Plan(
            [StackSteps("host", [ProvisionHost(root)], root=True)],
            mode="install",
            role="test",
            runner=runner,
            sink=ListSink(),
        ).run()
    # the strict scenario was consumed: every apt-get ran with the timeout
    assert outcome.code is ExitCode.OK
    assert len(apt) == 2 and all(c.argv[1:3] == ("-o", timeout) for c in apt)


def test_probe_DM_12_paused_timers_restored_in_finally(tmp_path: Path) -> None:
    """Timers stopped for the run are recorded first and started in finally --
    after a failure too. The pair: a quiet host records nothing, restores nothing."""
    root = box(tmp_path)
    check = [active("apt-daily.timer", True), active("apt-daily-upgrade.timer", False)]
    check += [
        active(u, False) for u in ("apt-daily.service", "apt-daily-upgrade.service")
    ]
    act = [dpkg("cloud-init", False), call("systemctl", "stop", "apt-daily.timer")]
    act += [
        active(u, False) for u in ("apt-daily.service", "apt-daily-upgrade.service")
    ]
    verify = [active("apt-daily.timer", False)]
    verify += [
        active(u, False) for u in ("apt-daily.service", "apt-daily-upgrade.service")
    ]
    restore = [
        call("systemctl", "start", "apt-daily.timer"),
        active("apt-daily.timer", True),
    ]
    outcome = run(
        [WaitHostQuiet(root), _Fails()],
        [*check, *act, *verify, *restore],
        [RestoreTimers(root)],
    )
    assert outcome.code is ExitCode.FAILED
    assert [r.name for r in outcome.finally_] == ["restore_timers"]
    assert outcome.finally_[0].verify == {
        "restored": ["apt-daily.timer"],
        "record": False,
    }
    assert not (root / PAUSED).exists()

    quiet = [active(u, False) for u in ("apt-daily.timer", "apt-daily-upgrade.timer")]
    quiet += [
        active(u, False) for u in ("apt-daily.service", "apt-daily-upgrade.service")
    ] * 2
    outcome = run([WaitHostQuiet(root)], quiet, [RestoreTimers(root)])
    assert outcome.code is ExitCode.OK and outcome.finally_[0].verify == {
        "restored": [],
        "record": False,
    }


def test_a_record_left_by_a_dead_run_is_restored(tmp_path: Path) -> None:
    root = box(tmp_path)
    (root / PAUSED).parent.mkdir(parents=True)
    (root / PAUSED).write_text(json.dumps(["apt-daily-upgrade.timer"]))
    calls = [
        call("systemctl", "start", "apt-daily-upgrade.timer"),
        active("apt-daily-upgrade.timer", True),
    ]
    outcome = run([RestoreTimers(root)], calls)
    assert outcome.code is ExitCode.OK and not (root / PAUSED).exists()


def test_probe_DM_12_package_verify_reads_dpkg_not_exit_code(tmp_path: Path) -> None:
    """apt-get exits 0 and the package is not there: verify is red."""
    root = box(tmp_path)
    timeout = f"DPkg::Lock::Timeout={APT_LOCK_TIMEOUT_S}"
    before = [dpkg(p, p != "docker.io") for p in HOST_PACKAGES]
    apt = [
        call("apt-get", "-o", timeout, "update"),
        call(
            "apt-get",
            "-o",
            timeout,
            "install",
            "-y",
            "--no-install-recommends",
            "docker.io",
        ),
    ]
    after = [
        dpkg(p, p != "docker.io") for p in HOST_PACKAGES
    ]  # apt said 0, dpkg says no
    outcome = run([ProvisionHost(root)], [*before, *apt, *after])
    reason = outcome.steps[0].reason
    assert reason is not None
    assert reason.as_json() == {
        "code": "provision_host:package-missing",
        "packages": ["docker.io"],
    }
    # the pair: dpkg says installed -- green
    good = [dpkg(p) for p in HOST_PACKAGES]
    tail = [
        active("docker", True),
        call("docker", "version", "--format", "{{.Server.Version}}", lines=("27.5.1",)),
    ]
    assert run([ProvisionHost(root)], [*before, *apt, *good, *tail]).code is ExitCode.OK


def test_daemon_json_keeps_other_keys(tmp_path: Path) -> None:
    root = box(tmp_path)
    (root / "etc" / "docker").mkdir()
    (root / "etc" / "docker" / "daemon.json").write_text(
        json.dumps({"data-root": "/srv/docker"})
    )
    calls = [
        call("systemctl", "restart", "docker"),
        call("docker", "info", "--format", "{{.LoggingDriver}}", lines=("local",)),
    ]
    assert run([DaemonJson(root)], calls).code is ExitCode.OK
    config = json.loads((root / "etc" / "docker" / "daemon.json").read_text())
    assert config == {"data-root": "/srv/docker", "log-driver": "local"}


def test_locale_is_set_to_utf8_and_read_back(tmp_path: Path) -> None:
    root = box(tmp_path, lang="POSIX")
    calls = [call("update-locale", "LANG=C.UTF-8")]
    outcome = run([Locale(root)], calls)
    reason = outcome.steps[0].reason  # the fake did not write the file: verify reads it
    assert reason is not None and reason.code == "locale:not-utf8"
    (root / "etc" / "default" / "locale").write_text("LANG=C.UTF-8\n")
    assert run([Locale(root)], []).code is ExitCode.OK


def test_network_is_created_with_the_machine_label(tmp_path: Path) -> None:
    inspect = ("docker", "network", "inspect", "--format", "{{.Name}}", "pridem")
    calls = [
        FakeCall(inspect, code=1),
        call("docker", "network", "create", "--label", "pridem.stack=host", "pridem"),
        call(*inspect, lines=("pridem",)),
    ]
    assert run([EnsureNetwork(tmp_path)], calls).code is ExitCode.OK


def test_report_dns_comes_from_the_dns_key_of_any_step(tmp_path: Path) -> None:
    """Not the step's name: a step called otherwise with a dns fact fills report.dns."""
    root = box(tmp_path)
    step = Preflight(root, domains=["app.example.org"], min_free_gib=0)
    step.name = "domain_check"
    outcome = run([step], preflight_calls({"app.example.org": IP}))
    verdict = build_verdict(
        outcome,
        run_id="2026-10-25T00:00:00Z-a3f9",
        verb="install",
        args={},
        actor={"type": "engineer", "via": "local"},
        started=datetime(2026, 10, 25, tzinfo=UTC),
        finished=datetime(2026, 10, 25, tzinfo=UTC),
        passport_version=None,
        composition_before={"pridem": "0.0.0"},
        composition_after={"pridem": "0.0.0"},
        secrets=SECRETS,
    )
    assert verdict.report.dns is not None
    assert [d.model_dump() for d in verdict.report.dns] == [
        {"domain": "app.example.org", "resolves_to": [IP], "expected": IP}
    ]


class _NeverActs(Step):
    """A step after preflight: acting would be a command the scenario does not have."""

    name = "after"
    order = 9
    modes = frozenset({"install", "deploy", "reinstall"})

    def check(self, ctx):  # type: ignore[no-untyped-def]
        from pridem.steps.base import CheckResult, local_code

        return CheckResult(True, local_code("do"))

    def act(self, ctx, check):  # type: ignore[no-untyped-def]
        """Acting leaves the step ``ok``; skipped means it never acted."""

    def verify(self, ctx, check):  # type: ignore[no-untyped-def]
        from pridem.steps.base import Verified

        return Verified({"after": True})

    codes = {"do": "act"}


class _Fails(_NeverActs):
    name = "fails"

    def check(self, ctx):  # type: ignore[no-untyped-def]
        from pridem.steps.base import StepFailed

        raise StepFailed("boom")

    codes = {"boom": "boom", "do": "act"}


def test_a_domain_with_an_extra_address_is_a_mismatch(tmp_path: Path) -> None:
    """FIX DM-12: the box's IP among others is not enough -- an extra A record (an
    old box after a move) sends traffic and the ACME check elsewhere."""
    root = box(tmp_path)
    calls = preflight_calls()
    calls += [
        call("curl", "-fsS", "--max-time", "10", url, lines=(IP,))
        for url in ECHO_SERVICES
    ]
    old = "198.51.100.9"
    calls.append(
        call(
            "getent",
            "ahostsv4",
            "app.example.org",
            lines=(f"{IP}   STREAM app.example.org", f"{old}   STREAM app.example.org"),
        )
    )
    outcome = run([Preflight(root, domains=["app.example.org"], min_free_gib=0)], calls)
    step = outcome.steps[0]
    assert step.reason is not None and step.reason.code == "preflight:dns-mismatch"
    assert step.verify["dns"] == [
        {"domain": "app.example.org", "resolves_to": sorted([IP, old]), "expected": IP}
    ]
    # the pair: one record, on the box -- green
    one = preflight_calls({"app.example.org": IP})
    outcome = run([Preflight(root, domains=["app.example.org"], min_free_gib=0)], one)
    assert outcome.code is ExitCode.OK
