"""Tier 3 probe (DM-15): ``primer-blank`` after ``up`` passes conformance.

The machine has no ``up`` step yet (DM-18), so the probe's harness brings the
blank up the way the machine will: the ``.env`` rendered by the machine
(``render_env``, as ``test_tier3_render_env.py`` does), the app image built
with ``PRIMER_RELEASE`` and ``PRIMER_COMMIT`` (contract 3 rule 19), the
stack's ``migrate`` in a throwaway container, ``up -d app``, and the app
attached to the network ``pridem`` with the alias ``blank-app`` (TZ 7.3). The
frontend is not built: conformance does not look at it.

Then ``observe`` and ``check_stack`` run in the machine's venv against the
installed package: no problem. The same observation is checked a second time
against the blank's ``primer.yaml`` with ``max_body: 2M`` planted: exactly one
problem, ``max-body`` -- a green that could not be red would prove nothing.

The file runs after ``test_tier3_render_env.py`` and ``test_tier3_host.py``
(pytest takes a directory's files by name): docker is on the runner only
after the host steps.
"""

import json
import shlex
import time
from pathlib import Path

from test_tier3_render_env import (
    BLANK_COMMIT,
    ENV,
    PYTHON,
    _blank,
    _passport,
    _plan,
)

from pridem.runner import CommandTimedOut, Stream, SubprocessRunner
from pridem.stacks.schema import load_primer_yaml

HEALTHY_WAIT_S = 180
SCRIPT = """
import json, sys
from pathlib import Path
from pridem.conformance.stack import check_stack, observe, problems_param
from pridem.runner import SubprocessRunner
from pridem.stacks.schema import load_primer_yaml
from pridem.steps.base import StepContext

release, env_file, planted = Path(sys.argv[1]), Path(sys.argv[2]), Path(sys.argv[3])
stack = load_primer_yaml(release / "primer.yaml")
ctx = StepContext(
    runner=SubprocessRunner(), mode="install", role="test", stack="blank",
    on_line=lambda stream, line, cut: None,
)
seen = observe(ctx, stack, "blank", release=release, project="blank", env_file=env_file)
print("PROBLEMS " + json.dumps(problems_param(check_stack(stack, "blank", seen))))
other = load_primer_yaml(planted)
print("PLANTED " + json.dumps(problems_param(check_stack(other, "blank", seen))))
"""


def _run(argv: list[str], timeout: float = 900) -> list[str]:
    lines: list[str] = []

    def keep(stream: Stream, line: str, cut: bool) -> None:
        lines.append(line)

    try:
        SubprocessRunner().run(argv, timeout=timeout, on_line=keep)
    except CommandTimedOut:
        raise AssertionError("\n".join(lines)) from None
    return lines


def _healthy(container: str) -> None:
    """Wait for compose's own healthcheck of the app (it asks ``/ready``)."""
    status = ""
    for _ in range(HEALTHY_WAIT_S // 3):
        [status] = _run(
            ["docker", "inspect", "-f", "{{.State.Health.Status}}", container], 30
        )
        if status == "healthy":
            return
        time.sleep(3)
    raise AssertionError(f"the app is {status} after {HEALTHY_WAIT_S} s")


def test_tier3_blank_after_up_passes_conformance(tmp_path: Path) -> None:
    checkout, passport = _blank(tmp_path), _passport(tmp_path)
    verdict, lines = _plan(checkout, passport)
    assert verdict.result == "green", "\n".join(lines)
    stack = load_primer_yaml(checkout / "primer.yaml")
    migrate = stack.stacks["blank"].migrate
    assert migrate is not None
    compose = [
        "docker",
        "compose",
        "-p",
        "blank",
        "--env-file",
        str(ENV),
        "-f",
        str(checkout / "docker-compose.yml"),
    ]
    _run(["docker", "network", "create", "pridem"], 60)
    _run(
        [
            *compose,
            "build",
            "--build-arg",
            "PRIMER_RELEASE=tier3",
            "--build-arg",
            f"PRIMER_COMMIT={BLANK_COMMIT}",
            "app",
        ]
    )
    _run([*compose, "run", "--rm", "app", *shlex.split(migrate)], 300)
    _run([*compose, "up", "-d", "app"], 300)
    [container] = _run([*compose, "ps", "-q", "app"], 60)
    _run(
        ["docker", "network", "connect", "--alias", "blank-app", "pridem", container],
        60,
    )
    _healthy(container)
    planted = tmp_path / "planted-primer.yaml"
    text = (checkout / "primer.yaml").read_text(encoding="utf-8")
    assert text.count("max_body: 1M") == 1
    planted.write_text(text.replace("max_body: 1M", "max_body: 2M"), encoding="utf-8")

    out = _run([PYTHON, "-c", SCRIPT, str(checkout), str(ENV), str(planted)], 300)

    printed = "\n".join(out)
    [problems] = [line for line in out if line.startswith("PROBLEMS ")]
    [found] = [line for line in out if line.startswith("PLANTED ")]
    assert json.loads(problems.removeprefix("PROBLEMS ")) == [], printed
    assert json.loads(found.removeprefix("PLANTED ")) == [
        "max-body route=api max_body=2M max_upload_mb=1"
    ], printed
