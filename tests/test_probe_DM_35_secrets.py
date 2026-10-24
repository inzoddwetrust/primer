"""Probes DM-35: no way for a secret into a verdict through runner error text
or through a passport secret short enough to match the verdict's own text.
"""

import shlex
import sys
import traceback
from pathlib import Path

import pytest
from passport_support import (
    everything_printed,
    passport_example,
    passport_problems,
    rejection,
    section,
    write_passport,
)
from plan_support import Journal, ScriptedStep, plan

from pridem import runner
from pridem.events import Code
from pridem.plan import StackSteps
from pridem.runner import (
    CommandFailed,
    CommandTimedOut,
    FakeCall,
    FakeRunner,
    RunnerError,
    Stream,
    SubprocessRunner,
)
from pridem.stacks.passport import load_passport

OUTPUT = "output-marker-5e0b"
PY = sys.executable


class _Lines:
    def __init__(self) -> None:
        self.seen: list[tuple[Stream, str]] = []

    def __call__(self, stream: Stream, line: str) -> None:
        self.seen.append((stream, line))


def _shown(error: RunnerError) -> str:
    """Everything a person, a log or a wrapping step could take from the error."""
    return "\n".join(
        [
            str(error),
            repr(error),
            *map(str, error.args),
            *traceback.format_exception(error),
        ]
    )


def test_probe_DM_35_runner_error_text_carries_no_output(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """DM-42 (contract 2 v1.6): reasons and incomplete entries are codes with
    parameters, not phrases; the data changed form only, each assertion keeps
    its strength.
    """
    monkeypatch.setattr(runner, "KILL_GRACE_SECONDS", 1.0)
    failing = [PY, "-c", f"import sys; print('{OUTPUT}'.upper()); sys.exit(3)"]
    hanging = [
        PY,
        "-c",
        f"import time; print('{OUTPUT}'.upper(), flush=True); time.sleep(60)",
    ]
    shown_output = OUTPUT.upper()

    with pytest.raises(CommandFailed) as failed:
        SubprocessRunner().run(failing, timeout=30.0, on_line=_Lines())
    with pytest.raises(CommandTimedOut) as timed_out:
        SubprocessRunner().run(hanging, timeout=1.0, on_line=_Lines())
    with FakeRunner(
        FakeCall(("make", "up"), code=2, lines=((Stream.STDERR, shown_output),)),
        FakeCall(
            ("make", "wait"), lines=((Stream.STDOUT, shown_output),), outcome="timeout"
        ),
    ) as fake:
        with pytest.raises(CommandFailed) as fake_failed:
            fake.run(["make", "up"], timeout=5.0, on_line=_Lines())
        with pytest.raises(CommandTimedOut) as fake_timed_out:
            fake.run(["make", "wait"], timeout=5.0, on_line=_Lines())

    cases: list[tuple[RunnerError, str, tuple[tuple[Stream, str], ...]]] = [
        (
            failed.value,
            f"command failed: {shlex.join(failing)}: exit code 3",
            failed.value.tail,
        ),
        (
            timed_out.value,
            f"command timed out after 1.0 s: {shlex.join(hanging)}",
            timed_out.value.tail,
        ),
        (
            fake_failed.value,
            "command failed: make up: exit code 2",
            fake_failed.value.tail,
        ),
        (
            fake_timed_out.value,
            "command timed out after 5.0 s: make wait",
            fake_timed_out.value.tail,
        ),
    ]
    for error, text, tail in cases:
        assert shown_output not in _shown(error), text
        assert str(error) == text
        assert any(line == shown_output for _, line in tail), text

    # the plan's reason is the error's code with the command, one form for both
    # (DM-42, contract 2 v1.6: a code with parameters instead of the text)
    up = ScriptedStep("up", 1, Journal(), act_argv=["make", "up"])
    wait = ScriptedStep("wait", 2, Journal(), act_argv=["make", "wait"])
    with FakeRunner(
        FakeCall(("make", "up"), code=2, lines=((Stream.STDERR, shown_output),)),
    ) as fake:
        reasons = [plan([StackSteps("a", [up], True)], runner=fake)[0].run()]
    with FakeRunner(
        FakeCall(
            ("make", "wait"), lines=((Stream.STDOUT, shown_output),), outcome="timeout"
        ),
    ) as fake:
        reasons.append(plan([StackSteps("a", [wait], True)], runner=fake)[0].run())
    assert [outcome.steps[0].reason for outcome in reasons] == [
        Code("command-failed", {"argv": ["make", "up"], "exit_code": 2}),
        Code("command-timed-out", {"argv": ["make", "wait"], "timeout_s": 10.0}),
    ]
    assert all(shown_output not in str(outcome.steps[0].reason) for outcome in reasons)


def test_probe_DM_35_short_secret_is_rejected(tmp_path: Path) -> None:
    short = "short-secret-15"
    assert len(short) == 15
    data = passport_example()
    section(data, "asked", "comms")["TELEGRAM_BOT_TOKEN"] = short
    section(data, "policies").update(ssl="provided", tls={"cert": short, "key": short})
    assert passport_problems(tmp_path, data) == [
        ("asked.comms.TELEGRAM_BOT_TOKEN", "R12.secret-length"),
        ("policies.tls.cert", "R12.secret-length"),
        ("policies.tls.key", "R12.secret-length"),
    ]
    error = rejection(write_passport(tmp_path, data))
    assert error is not None and short not in everything_printed(error)
    assert all("passport rule 12" in p.message for p in error.problems)

    data = passport_example()
    section(data, "asked", "comms")["TELEGRAM_BOT_TOKEN"] = short + "6"
    assert passport_problems(tmp_path, data) == []

    example = load_passport(write_passport(tmp_path, passport_example()))
    values = [v.get_secret_value() for a in example.asked.values() for v in a.values()]
    assert len(values) == 5 and min(map(len, values)) >= 16
