"""``doctor`` is empty after a green deploy on a box whose apt timers are on
(DM-105; ``par0`` 14.4: a new form -- the test "``doctor`` is empty" on it).

``wait_host_quiet`` pauses the apt timers and waits for apt for the time of a
run; ``restore_timers`` in ``finally`` starts them again (``for_the_run``).
That pause is no difference of the box from its passport: on a live Ubuntu
the timers are always on (measured on velo-dev), and ``doctor`` said so on
every box. Commands are literal.
"""

from itertools import count
from pathlib import Path

from plan_support import Journal, ListSink, ScriptedStep
from test_steps_host import active, box

from pridem.plan import Plan, StackSteps
from pridem.report.catalog import ENGLISH, Value, text, with_steps
from pridem.report.codes import ExitCode
from pridem.runner import FakeCall, FakeRunner
from pridem.steps.base import Step
from pridem.steps.host import APT_SERVICES, APT_TIMERS, PAUSED, WaitHostQuiet


def _doctor(root: Path, calls: list[FakeCall], *more: Step):  # type: ignore[no-untyped-def]
    ticks = count()
    with FakeRunner(*calls) as runner:
        return Plan(
            [StackSteps("pridem-host", [WaitHostQuiet(root), *more], root=True)],
            mode="doctor",
            role="test",
            runner=runner,
            sink=ListSink(),
            clock=lambda: float(next(ticks)),
        ).run()


def _apt(timers_on: bool, busy: bool) -> list[FakeCall]:
    """What ``wait_host_quiet.check`` asks: the timers, then the services."""
    return [
        *(active(timer, timers_on) for timer in APT_TIMERS),
        *(active(service, busy) for service in APT_SERVICES),
    ]


def test_doctor_after_a_green_deploy_with_apt_timers_on_is_empty(
    tmp_path: Path,
) -> None:
    """The apt timers on, apt idle -- and on, apt at work: code 0, no
    difference, no record (a green ``check`` writes none in ``doctor``). The
    pair: another step of the host that would act is a difference."""
    root = box(tmp_path)
    for busy in (False, True):
        outcome = _doctor(root, _apt(True, busy))
        assert (outcome.code, outcome.doctor_diff, outcome.steps) == (
            ExitCode.OK,
            (),
            (),
        )
    acting = ScriptedStep("provision_host", 3, Journal(), modes=frozenset({"deploy"}))
    outcome = _doctor(root, _apt(True, False), acting)
    assert outcome.code is ExitCode.INCOMPLETE
    assert [(d.name, d.reason.code) for d in outcome.doctor_diff] == [
        ("provision_host", "provision_host:do")
    ]


def test_a_refusal_of_the_step_s_check_is_still_red_in_doctor(tmp_path: Path) -> None:
    """``for_the_run`` silences what the step would do, never what it
    refuses: a broken record of paused timers is ``paused-broken`` in
    ``doctor`` as in a run."""
    root = box(tmp_path)
    record = root / PAUSED
    record.parent.mkdir(parents=True)
    record.write_text("{", encoding="utf-8")

    class Reads(WaitHostQuiet):
        """``wait_host_quiet`` whose check reads the record first, as its
        ``verify`` does -- the refusal a check of the class gives."""

        def check(self, ctx):  # type: ignore[no-untyped-def]
            from pridem.steps.host import _paused

            _paused(self.root)
            return super().check(ctx)

    ticks = count()
    with FakeRunner() as runner:
        outcome = Plan(
            [StackSteps("pridem-host", [Reads(root)], root=True)],
            mode="doctor",
            role="test",
            runner=runner,
            sink=ListSink(),
            clock=lambda: float(next(ticks)),
        ).run()
    [failed] = outcome.steps
    assert failed.reason is not None
    assert failed.reason.code == "wait_host_quiet:paused-broken"


def _steps(base: type) -> list[type]:
    found: list[type] = []
    subs: list[type] = base.__subclasses__()
    for sub in subs:
        found.append(sub)
        found += _steps(sub)
    return found


def test_for_the_run_is_on_the_pause_of_the_host_alone() -> None:
    """The census of the gate (F1, F2): only ``wait_host_quiet`` pauses the
    host for the time of a run and has ``finally`` give it back;
    ``stop_for_migrate`` goes with a migration -- a real difference."""
    import pridem.verbs  # noqa: F401 -- every verb: every step a plan has

    flagged = sorted(
        getattr(step, "name", "?")
        for step in _steps(Step)
        if step.__module__.startswith("pridem.")  # the machine's, not a test's
        and getattr(step, "for_the_run", False)
    )
    assert flagged == ["wait_host_quiet"]


def test_an_empty_list_is_said_none() -> None:
    """Velo-dev's difference read ``stop apt-daily.timer apt-daily-upgrade.timer
    and wait for `` -- an empty list said as nothing. It is ``none``: no text
    ends on a dangling preposition. The pair: a list says its items."""
    catalog = with_steps(ENGLISH, [("wait_host_quiet", WaitHostQuiet.codes)])
    timers: list[Value] = ["apt-daily.timer", "apt-daily-upgrade.timer"]
    said = text(catalog, "wait_host_quiet:pause", {"timers": timers, "services": []})
    assert said == "stop apt-daily.timer apt-daily-upgrade.timer and wait for none"
    busy = text(
        catalog,
        "wait_host_quiet:pause",
        {"timers": [], "services": ["apt-daily.service"]},
    )
    assert busy == "stop none and wait for apt-daily.service"
