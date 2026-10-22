"""Probe DM-1: a planted failure turns the suite red.

With ``PRIDEM_PLANTED=1`` this test fails on purpose (the plant). Without the
variable, it re-runs itself in a subprocess with the plant switched on and
requires that run to be red and to carry the plant marker, so a mutation that
disarms the plant turns this test red in every ordinary run. Any other value of
the variable is a misconfiguration and fails loudly instead of being ignored.

CI never sets the variable on push; a manual ``workflow_dispatch`` with the
``planted`` input sets it and is the live check on the server.
"""

import os
import subprocess
import sys

import pytest

_VARIABLE = "PRIDEM_PLANTED"
_MARKER = "PRIDEM_PLANTED_FAILURE"
_NODE_ID = f"{__file__}::test_probe_DM_1_planted_failure_reddens"


def test_probe_DM_1_planted_failure_reddens() -> None:
    value = os.environ.get(_VARIABLE, "")
    if value == "1":
        pytest.fail(f"{_MARKER}: planted failure, this run must be red")
    elif value != "":
        pytest.fail(f"{_VARIABLE} must be unset, empty or '1', got {value!r}")
    else:
        # runner appears in DM-5; this test pins tooling, not machine behaviour
        planted = subprocess.run(  # noqa: S603
            [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", _NODE_ID],
            env={**os.environ, _VARIABLE: "1"},
            capture_output=True,
            text=True,
            check=False,
        )
        output = planted.stdout + planted.stderr
        assert planted.returncode == 1, output
        assert _MARKER in planted.stdout, output
