"""``timers`` (DM-20): the ``gc`` and renewal units the machine writes.

Files are real, in ``tmp``; ``systemctl`` follows a strict script.
"""

from itertools import count
from pathlib import Path

from env_support import box, passport_data
from plan_support import ListSink

from pridem.events import Code, PlanOutcome
from pridem.plan import Plan, StackSteps
from pridem.report.codes import ExitCode
from pridem.runner import FakeCall, FakeRunner, Stream
from pridem.steps.passport import Fetched
from pridem.steps.timers import UNIT_DIR, timer_steps, unit_files

TIMERS = ("pridem-gc.timer", "pridem-ssl-renew.timer")


def answer(question: str, timer: str, state: str) -> FakeCall:
    code = {"enabled": 0, "active": 0, "disabled": 1, "inactive": 3}[state]
    return FakeCall(
        ("systemctl", question, timer), code=code, lines=((Stream.STDOUT, state),)
    )


UNITS = (
    "pridem-gc.service",
    "pridem-gc.timer",
    "pridem-ssl-renew.service",
    "pridem-ssl-renew.timer",
)


def loaded(*stale: str) -> list[FakeCall]:
    """``NeedDaemonReload`` of every unit, ``yes`` for ``stale`` (DM-80)."""
    return [
        FakeCall(
            ("systemctl", "show", "-p", "NeedDaemonReload", "--value", unit),
            lines=((Stream.STDOUT, "yes" if unit in stale else "no"),),
        )
        for unit in UNITS
    ]


def up() -> list[FakeCall]:
    """Both timers enabled and active, as ``check`` and ``verify`` ask."""
    return [
        call
        for timer in TIMERS
        for call in (
            answer("is-enabled", timer, "enabled"),
            answer("is-active", timer, "active"),
        )
    ]


def start(*, reload: bool = True) -> list[FakeCall]:
    calls = [FakeCall(("systemctl", "daemon-reload"))] if reload else []
    return [
        *calls,
        FakeCall(("systemctl", "enable", *TIMERS)),
        FakeCall(("systemctl", "restart", *TIMERS)),
    ]


def run(root: Path, fetched: Fetched, runner: FakeRunner) -> PlanOutcome:
    ticks = count()
    return Plan(
        [StackSteps("timers", timer_steps(root, fetched=fetched), root=True)],
        mode="install",
        role="test",
        runner=runner,
        sink=ListSink(),
        clock=lambda: float(next(ticks)),
    ).run()


def test_a_fresh_box_gets_both_timers(tmp_path: Path) -> None:
    root, fetched = box(tmp_path, passport_data())
    with FakeRunner(
        *loaded(),
        answer("is-enabled", TIMERS[0], "disabled"),
        answer("is-enabled", TIMERS[1], "disabled"),
        *start(),
        *loaded(),
        *up(),
    ) as runner:
        outcome = run(root, fetched, runner)
    assert outcome.code is ExitCode.OK, outcome.steps
    assert fetched.passport is not None
    for name, text in unit_files(fetched.passport).items():
        path = root / UNIT_DIR / name
        assert path.read_text(encoding="utf-8") == text
        assert oct(path.stat().st_mode & 0o777) == oct(0o644)
    gc = (root / UNIT_DIR / "pridem-gc.service").read_text(encoding="utf-8")
    assert "ExecStart=/usr/local/bin/pridem --timer gc\n" in gc
    renew = (root / UNIT_DIR / "pridem-ssl-renew.service").read_text(encoding="utf-8")
    assert "ExecStart=/usr/local/bin/pridem --timer ssl renew\n" in renew
    timer = (root / UNIT_DIR / "pridem-gc.timer").read_text(encoding="utf-8")
    assert "OnCalendar=daily\nPersistent=true\n" in timer  # gc: no random delay
    assert "WantedBy=timers.target" in timer
    # DM-54: the renewal starts up to an hour late at random, so boxes do not
    # all ask Let's Encrypt at midnight
    timer = (root / UNIT_DIR / "pridem-ssl-renew.timer").read_text(encoding="utf-8")
    assert "OnCalendar=daily\nRandomizedDelaySec=1h\nPersistent=true\n" in timer
    assert outcome.steps[0].verify == {
        "timers": [
            {"timer": TIMERS[0], "runs": "pridem gc", "on_calendar": "daily"},
            {"timer": TIMERS[1], "runs": "pridem ssl renew", "on_calendar": "daily"},
        ]
    }
    assert not [p for p in (root / UNIT_DIR).iterdir() if p.name.startswith(".")]


def test_the_same_timers_are_left_as_they_are(tmp_path: Path) -> None:
    root, fetched = box(tmp_path, passport_data())
    assert fetched.passport is not None
    for name, text in unit_files(fetched.passport).items():
        (root / UNIT_DIR).mkdir(parents=True, exist_ok=True)
        (root / UNIT_DIR / name).write_text(text, encoding="utf-8")
    # check, verify: nothing written
    with FakeRunner(*loaded(), *up(), *loaded(), *up()) as runner:
        outcome = run(root, fetched, runner)
    assert outcome.code is ExitCode.OK, outcome.steps


def test_a_changed_unit_is_written_and_reloaded(tmp_path: Path) -> None:
    root, fetched = box(tmp_path, passport_data())
    assert fetched.passport is not None
    (root / UNIT_DIR).mkdir(parents=True)
    for name, text in unit_files(fetched.passport).items():
        (root / UNIT_DIR / name).write_text(text, encoding="utf-8")
    stale = root / UNIT_DIR / "pridem-gc.timer"
    stale.write_text("[Timer]\nOnCalendar=weekly\n", encoding="utf-8")
    other = root / UNIT_DIR / "apt-daily.timer"
    other.write_text("not ours\n", encoding="utf-8")
    with FakeRunner(*loaded(), *up(), *start(), *loaded(), *up()) as runner:
        outcome = run(root, fetched, runner)
    assert outcome.code is ExitCode.OK, outcome.steps
    assert "OnCalendar=daily" in stale.read_text(encoding="utf-8")
    assert other.read_text(encoding="utf-8") == "not ours\n"


def test_a_timer_systemd_did_not_enable_is_red(tmp_path: Path) -> None:
    root, fetched = box(tmp_path, passport_data())
    with FakeRunner(
        *loaded(),
        answer("is-enabled", TIMERS[0], "disabled"),
        answer("is-enabled", TIMERS[1], "disabled"),
        *start(),
        *loaded(),
        answer("is-enabled", TIMERS[0], "disabled"),
    ) as runner:
        outcome = run(root, fetched, runner)
    assert outcome.steps[0].reason == Code(
        "timers:not-enabled", {"timer": TIMERS[0], "state": "disabled"}
    )
    # an enabled timer that does not run is red too
    root, fetched = box(tmp_path / "inactive", passport_data())
    with FakeRunner(
        *loaded(),
        answer("is-enabled", TIMERS[0], "disabled"),
        answer("is-enabled", TIMERS[1], "disabled"),
        *start(),
        *loaded(),
        answer("is-enabled", TIMERS[0], "enabled"),
        answer("is-active", TIMERS[0], "inactive"),
    ) as runner:
        outcome = run(root, fetched, runner)
    assert outcome.steps[0].reason == Code(
        "timers:not-active", {"timer": TIMERS[0], "state": "inactive"}
    )


def test_without_a_passport_the_timers_refuse(tmp_path: Path) -> None:
    with FakeRunner() as runner:
        outcome = run(tmp_path, Fetched(), runner)
    assert outcome.steps[0].reason == Code("timers:no-passport")


# --- DM-80: after docker and the network; systemd holding an older text -------


def test_each_service_starts_after_docker_and_the_network(tmp_path: Path) -> None:
    _, fetched = box(tmp_path, passport_data())
    assert fetched.passport is not None
    for name, text in unit_files(fetched.passport).items():
        if name.endswith(".service"):
            unit = text.split("[Service]")[0]
            assert "Wants=network-online.target\n" in unit, name
            assert "After=docker.service network-online.target\n" in unit, name


def _written(root: Path, fetched: Fetched) -> None:
    assert fetched.passport is not None
    (root / UNIT_DIR).mkdir(parents=True, exist_ok=True)
    for name, text in unit_files(fetched.passport).items():
        (root / UNIT_DIR / name).write_text(text, encoding="utf-8")


def test_files_right_and_systemd_wrong_get_a_reload(tmp_path: Path) -> None:
    """A run that died between the write and the reload leaves every file as
    rendered and systemd on the older text: ``daemon-reload`` without a write."""
    root, fetched = box(tmp_path, passport_data())
    _written(root, fetched)
    before = {p.name: p.stat().st_mtime_ns for p in (root / UNIT_DIR).iterdir()}
    with FakeRunner(
        *loaded("pridem-gc.service"),
        *up(),
        *loaded("pridem-gc.service"),  # act asks again: nothing was written
        *start(),
        *loaded(),
        *up(),
    ) as runner:
        outcome = run(root, fetched, runner)
    assert outcome.code is ExitCode.OK, outcome.steps
    after = {p.name: p.stat().st_mtime_ns for p in (root / UNIT_DIR).iterdir()}
    assert after == before


def test_systemd_still_on_an_older_text_after_the_reload_is_red(
    tmp_path: Path,
) -> None:
    root, fetched = box(tmp_path, passport_data())
    _written(root, fetched)
    with FakeRunner(
        *loaded("pridem-ssl-renew.timer"),
        *up(),
        *loaded("pridem-ssl-renew.timer"),
        *start(),
        *loaded("pridem-ssl-renew.timer"),
    ) as runner:
        outcome = run(root, fetched, runner)
    assert outcome.steps[0].reason == Code(
        "timers:not-loaded", {"unit": "pridem-ssl-renew.timer"}
    )
