"""Probe DM-1: a planted failure turns the suite red.

With ``PRIDEM_PLANTED=1`` this test fails on purpose (the plant). Without the
variable, it re-runs itself through the runner with the plant switched on and
expects that run to exit with code 1 and to carry the plant marker, so a
mutation that disarms the plant turns this test red in every ordinary run. Any
other value of the variable is a misconfiguration and fails loudly instead of
being ignored.

CI never sets the variable on push; a manual ``workflow_dispatch`` with the
``planted`` input sets it and is the live check on the server.
"""

import os
import sys

import pytest

from pridem.runner import Stream, SubprocessRunner

_VARIABLE = "PRIDEM_PLANTED"
_MARKER = "PRIDEM_PLANTED_FAILURE"
_NODE_ID = f"{__file__}::test_probe_DM_1_planted_failure_reddens"
_TIMEOUT_SECONDS = 120.0


def test_probe_DM_1_planted_failure_reddens() -> None:
    value = os.environ.get(_VARIABLE, "")
    if value == "1":
        pytest.fail(f"{_MARKER}: planted failure, this run must be red")
    elif value != "":
        pytest.fail(f"{_VARIABLE} must be unset, empty or '1', got {value!r}")
    else:
        stdout: list[str] = []

        def collect(stream: Stream, line: str) -> None:
            if stream is Stream.STDOUT:
                stdout.append(line)

        SubprocessRunner().run(
            [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", _NODE_ID],
            expect=(1,),
            timeout=_TIMEOUT_SECONDS,
            env={**os.environ, _VARIABLE: "1"},
            on_line=collect,
        )
        assert any(_MARKER in line for line in stdout), "\n".join(stdout)
