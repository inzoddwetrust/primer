"""Every wait of a step ends on a signal (DM-45): the four loops that sleep
until something happens -- the host's apt, the deploy key's access, the
passport's recipient, the proxy's log -- ask the command's interrupt around
each sleep and stop with ``Interrupted``; the pair: with no signal the same
wait runs to its deadline and is red by its own code.
"""

import signal
from collections.abc import Callable
from itertools import count
from pathlib import Path

import pytest
from passport_support import passport_example

from pridem.events import Secrets
from pridem.interrupt import Interrupt, Interrupted
from pridem.runner import FakeCall, FakeRunner
from pridem.stacks.passport import PASSPORT
from pridem.stacks.schema import PRIMER_YAML, Product
from pridem.steps import host, keys, passport
from pridem.steps.base import CheckResult, StepContext, StepFailed, Waiting
from pridem.steps.egress import STATE_FORMAT, Egress
from pridem.steps.frontend import Frontend
from pridem.steps.host import WaitHostQuiet
from pridem.steps.keys import DeployKey
from pridem.steps.passport import Fetched, FetchPassport, _NotRecipient

Wait = Callable[[StepContext], object]


def _ctx(runner: FakeRunner, interrupt: Interrupt) -> StepContext:
    return StepContext(runner, "install", "test", "x", lambda *_: None, interrupt)


def _host(tmp: Path, sleep: Callable[[float], None], mp: pytest.MonkeyPatch) -> Wait:
    # the wait asks whether apt is at work, ``activating`` included (DM-80)
    mp.setattr(host, "_busy", lambda ctx, unit: True)
    mp.setattr(host, "_installed", lambda ctx, package: False)
    ticks = count()
    step = WaitHostQuiet(
        tmp, timeout_s=3, poll_s=1, clock=lambda: float(next(ticks)), sleep=sleep
    )
    return lambda ctx: step.act(ctx, CheckResult(False, data={"timers": []}))


def _key(tmp: Path, sleep: Callable[[float], None], mp: pytest.MonkeyPatch) -> Wait:
    mp.setattr(keys, "has_access", lambda ctx, root, found: False)
    ticks = count()
    step = DeployKey(
        "git@github.com:o/r.git",
        tmp,
        wait_s=3,
        poll_s=1,
        clock=lambda: float(next(ticks)),
        sleep=sleep,
    )
    key = tmp / "opt/pridem/keys" / step.repo.alias
    key.parent.mkdir(parents=True)
    key.write_text("private\n")
    key.with_name(key.name + ".pub").write_text("ssh-ed25519 AAAA\n")
    return lambda ctx: step.act(ctx, CheckResult(False))


def _passport(
    tmp: Path, sleep: Callable[[float], None], mp: pytest.MonkeyPatch
) -> Wait:
    ticks = count()
    step = FetchPassport(
        Fetched(),
        tmp,
        secrets=Secrets(()),
        server="box",
        ops=passport.OpsSource("file:///ops.git"),
        wait_s=3,
        poll_s=1,
        sleep=sleep,
    )
    step.clock = lambda: float(next(ticks))

    def not_yet(*args: object) -> object:
        raise _NotRecipient

    mp.setattr(step, "_source", not_yet)
    mp.setattr(step, "_fetch", lambda ctx: "c" * 40)
    mp.setattr(passport, "public_key", lambda ctx, key: "age1box")
    return lambda ctx: step._wait(ctx, tmp / "t", None)


def _proxy(tmp: Path, sleep: Callable[[float], None], mp: pytest.MonkeyPatch) -> Wait:
    ticks = count()

    made = PRIMER_YAML.validate_python(
        {
            "schema": 1,
            "name": "blank",
            "kind": "product",
            "stacks": {"blank": {"compose": "c.yml"}},
            "env": {},
            "egress": ["api.github.com"],
            "report": {"health": "/h", "ready": "/r", "logs": "json", "junit": True},
        }
    )
    assert isinstance(made, Product)
    step = Egress(
        made,
        fetched=Fetched(passport=PASSPORT.validate_python(passport_example())),
        root=tmp,
        ready_s=3,
        poll_s=1,
        clock=lambda: float(next(ticks)),
        sleep=sleep,
    )
    return lambda ctx: step._logged(ctx, "c0ffee")


def _ready(tmp: Path, sleep: Callable[[float], None], mp: pytest.MonkeyPatch) -> Wait:
    """The proxy that does not answer yet after it was recreated."""
    ticks = count()
    made = PRIMER_YAML.validate_python(
        {
            "schema": 1,
            "name": "blank",
            "kind": "product",
            "stacks": {"blank": {"compose": "c.yml"}},
            "env": {},
            "egress": ["api.github.com"],
            "report": {"health": "/h", "ready": "/r", "logs": "json", "junit": True},
        }
    )
    assert isinstance(made, Product)
    step = Egress(
        made,
        fetched=Fetched(passport=PASSPORT.validate_python(passport_example())),
        root=tmp,
        answer=lambda address, port, host: None,
        ready_s=3,
        poll_s=1,
        clock=lambda: float(next(ticks)),
        sleep=sleep,
    )
    return lambda ctx: step._first_answer(ctx, "172.30.0.2", "c0ffee")


def _front(tmp: Path, sleep: Callable[[float], None], mp: pytest.MonkeyPatch) -> Wait:
    """DM-80: ``frontend`` reads the front again until it answers 200; the
    wait is ``wait_until``, the one ``up`` waits by too."""
    mp.setattr(Frontend, "_domain", lambda self: "blank.example.org")
    mp.setattr(Frontend, "_status", lambda self, ctx, domain: "502")
    ticks = count()
    made = PRIMER_YAML.validate_python(
        {
            "schema": 1,
            "name": "blank",
            "kind": "product",
            "stacks": {"blank": {"compose": "c.yml"}},
            "env": {},
            "report": {"health": "/h", "ready": "/r", "logs": "json", "junit": True},
        }
    )
    assert isinstance(made, Product)
    step = Frontend(
        made,
        fetched=Fetched(),
        root=tmp,
        waiting=Waiting(3, 1, clock=lambda: float(next(ticks)), sleep=sleep),
    )
    return lambda ctx: step.verify(ctx, CheckResult(False))


WAITS = {
    "frontend": _front,
    "host": _host,
    "key": _key,
    "passport": _passport,
    "proxy-log": _proxy,
    "proxy-ready": _ready,
}
LOGS = FakeCall(("docker", "logs", "c0ffee"))
DIAGNOSIS = (
    FakeCall(("docker", "inspect", "-f", STATE_FORMAT, "c0ffee"), code=1),
    FakeCall(("docker", "logs", "--tail", "40", "c0ffee"), code=1),
)
"""What a proxy wait that reached its deadline reads for its fact (DM-45 FIX)."""


@pytest.mark.parametrize("name", sorted(WAITS))
def test_a_signal_ends_every_wait_of_a_step(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, name: str
) -> None:
    interrupt = Interrupt()
    interrupt.watch()
    wait = WAITS[name](
        tmp_path, lambda _: interrupt.receive(signal.SIGTERM), monkeypatch
    )
    runner = FakeRunner(*([LOGS] if name == "proxy-log" else []))
    with pytest.raises(Interrupted):
        wait(_ctx(runner, interrupt))
    # the pair: no signal -- the wait runs to its deadline, red by its code
    quiet = Interrupt()
    quiet.watch()
    wait = WAITS[name](tmp_path / "pair", lambda _: None, monkeypatch)
    proxy = name in ("proxy-log", "proxy-ready")
    runner = FakeRunner(
        *([LOGS] * 3 if name == "proxy-log" else []), *(DIAGNOSIS if proxy else ())
    )
    with pytest.raises(StepFailed):
        wait(_ctx(runner, quiet))
    runner.assert_consumed()  # DM-45 FIX: the diagnosis read at the deadline


def test_a_signal_ends_the_wait_for_a_refused_host(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """DM-84: the wait for a host of the list a fresh proxy still refuses
    ends on a signal. The pair: no signal -- the wait runs to its deadline
    and gives the refusal back to ``verify`` (which is red by it)."""
    asked: list[str] = []
    on_answer: list[Callable[[], None]] = []

    def wait_of(sleep: Callable[[float], None]) -> Wait:
        ticks = count()
        made = PRIMER_YAML.validate_python(
            {
                "schema": 1,
                "name": "blank",
                "kind": "product",
                "stacks": {"blank": {"compose": "c.yml"}},
                "env": {},
                "egress": ["api.github.com"],
                "report": {
                    "health": "/h",
                    "ready": "/r",
                    "logs": "json",
                    "junit": True,
                },
            }
        )
        assert isinstance(made, Product)

        def refuses(address: str, port: int, host: str) -> int:
            if len(asked) >= 20:  # a wait with no deadline: red, not a hang
                raise AssertionError("asked past any deadline")
            asked.append(host)
            for hook in on_answer:
                hook()
            return 403

        step = Egress(
            made,
            fetched=Fetched(passport=PASSPORT.validate_python(passport_example())),
            root=tmp_path,
            answer=refuses,
            ready_s=3,
            poll_s=1,
            clock=lambda: float(next(ticks)),
            sleep=sleep,
        )
        return lambda ctx: step._allowed_answer(ctx, "172.30.0.2", "api.github.com")

    interrupt = Interrupt()
    interrupt.watch()
    wait = wait_of(lambda _: interrupt.receive(signal.SIGTERM))
    with pytest.raises(Interrupted):
        wait(_ctx(FakeRunner(), interrupt))
    assert asked == ["api.github.com"]
    # the signal comes during a probe: the wait ends before it sleeps
    asked.clear()
    early = Interrupt()
    early.watch()
    slept: list[float] = []
    on_answer.append(lambda: early.receive(signal.SIGTERM))
    with pytest.raises(Interrupted):
        wait_of(slept.append)(_ctx(FakeRunner(), early))
    assert (asked, slept) == (["api.github.com"], [])
    on_answer.clear()
    asked.clear()
    quiet = Interrupt()
    quiet.watch()
    assert wait_of(lambda _: None)(_ctx(FakeRunner(), quiet)) == 403
    assert len(asked) > 1
