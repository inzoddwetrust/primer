"""Tier 3 probe (DM-18, DM-15): ``primer-blank`` built, migrated and brought up
by the machine's steps on a clean runner, and conforming.

Nothing comes from outside the run but ``primer-blank`` itself (https, a
pinned commit). One plan in the machine's venv: ``ensure_network`` (host),
``fetch_passport`` from a file written here, then the blank's ladder --
``seams_check``, ``render_env``, ``build``, ``migrate``, ``up`` (whose
``verify`` is conformance DM-15 and ``/health`` reporting the release and
the commit the build got). The plan runs twice: the second is green and
recreates no container.

Then docker itself is asked: every container, volume and network of the
project ``blank`` and every image built for it carries the ``pridem.*``
labels -- the release ones on images and containers, the stack one alone on
volumes and the network. Last, the same live observation is checked against
the blank's ``primer.yaml`` with ``max_body: 2M`` planted: exactly one
problem, ``max-body`` -- a green that could not be red would prove nothing.

The file runs after ``test_tier3_host.py``, ``test_tier3_passport.py`` and
``test_tier3_render_env.py`` (pytest takes a directory's files by name):
docker is on the runner only after the host steps.
"""

import json
from pathlib import Path

from test_tier3_render_env import BLANK_COMMIT, PYTHON, _blank, _passport

from pridem.report.schema import Verdict
from pridem.runner import CommandTimedOut, Stream, SubprocessRunner

REF = "main"
PLAN = """
import sys
from datetime import UTC, datetime
from pathlib import Path
from secrets import token_hex
from pridem import __version__
from pridem.events import ConsoleSink, Secrets
from pridem.plan import Plan, StackSteps
from pridem.report.catalog import ENGLISH, with_steps
from pridem.report.schema import build_verdict
from pridem.runner import SubprocessRunner
from pridem.stacks.schema import load_primer_yaml
from pridem.stacks.seams import SeamMemory
from pridem.state import Box
from pridem.steps.build import Build
from pridem.steps.env import RenderEnv, SeamsCheck
from pridem.steps.host import EnsureNetwork
from pridem.steps.migrate import Migrate
from pridem.steps.passport import passport_steps
from pridem.steps.up import Up

root, checkout, passport = Path("/"), Path(sys.argv[1]), Path(sys.argv[2])
ref, commit = sys.argv[3], sys.argv[4]
blank = load_primer_yaml(checkout / "primer.yaml")
box, secrets, memory = Box(Path("/opt/pridem")), Secrets(()), SeamMemory()
fetched, first = passport_steps(root, secrets=secrets, server=None, file=passport)
render = RenderEnv(blank, product=blank, fetched=fetched, secrets=secrets,
                   memory=memory, root=root)
parts = {"release": checkout, "ref": ref, "commit": commit, "root": root}
ladder = [
    SeamsCheck(blank, {}, fetched), render,
    Build(blank, "blank", **parts), Migrate(blank, "blank", **parts),
    Up(blank, "blank", **parts, memory=memory, render=render),
]
host = [EnsureNetwork()]
with box.lock("tier3-up"):
    started = datetime.now(UTC).replace(microsecond=0)
    outcome = Plan(
        [StackSteps("host", host), StackSteps("passport", first),
         StackSteps("blank", ladder, root=True)],
        mode="install", role="test", runner=SubprocessRunner(),
        sink=ConsoleSink(sys.stdout, secrets),
    ).run()
    every = [*host, *first, *ladder]
    verdict = build_verdict(
        outcome, run_id=f"{started:%Y-%m-%dT%H:%M:%SZ}-{token_hex(2)}",
        verb="install", args={}, actor={"type": "machine", "via": "local"},
        started=started, finished=datetime.now(UTC).replace(microsecond=0),
        passport_version=fetched.passport.version if fetched.passport else None,
        composition_before={"pridem": __version__},
        composition_after={"pridem": __version__}, secrets=secrets,
        catalog=with_steps(ENGLISH, [(step.name, step.codes) for step in every]),
    )
    box.write_verdict(verdict)
print("VERDICT " + verdict.model_dump_json())
sys.exit(int(verdict.exit_code))
"""
PLANTED = """
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
ENV = "/opt/blank/env/.env"


def _run(
    argv: list[str], timeout: float = 120, expect: tuple[int, ...] = (0,)
) -> list[str]:
    lines: list[str] = []

    def keep(stream: Stream, line: str, cut: bool) -> None:
        lines.append(line)

    try:
        SubprocessRunner().run(argv, expect=expect, timeout=timeout, on_line=keep)
    except CommandTimedOut:
        raise AssertionError("\n".join(lines)) from None
    return lines


def _plan(checkout: Path, passport: Path) -> tuple[Verdict, str]:
    lines = _run(
        [PYTHON, "-c", PLAN, str(checkout), str(passport), REF, BLANK_COMMIT],
        timeout=3600,
        expect=(0, 1, 2),
    )
    printed = "\n".join(lines)
    verdicts = [line for line in lines if line.startswith("VERDICT ")]
    assert len(verdicts) == 1, printed
    return Verdict.model_validate_json(verdicts[0].removeprefix("VERDICT ")), printed


def _labels(kind: str, name: str) -> dict[str, str]:
    [text] = _run(["docker", kind, "inspect", "-f", "{{json .Labels}}", name])
    found = json.loads(text) or {}
    assert isinstance(found, dict)
    return found


def _app() -> str:
    [container] = _run(
        [
            "docker",
            "ps",
            "-q",
            "--filter",
            "label=com.docker.compose.project=blank",
            "--filter",
            "label=com.docker.compose.service=app",
        ]
    )
    return container


def test_tier3_blank_is_built_migrated_up_and_conforms(tmp_path: Path) -> None:
    checkout, passport = _blank(tmp_path), _passport(tmp_path)

    verdict, printed = _plan(checkout, passport)

    assert verdict.result == "green", printed
    facts = {step.name: step.verify or {} for step in verdict.steps}
    assert (facts["up"]["release"], facts["up"]["commit"]) == (REF, BLANK_COMMIT), (
        printed
    )
    assert facts["up"]["image"] == facts["build"]["app_image"], printed
    assert "alembic_head" in facts["migrate"], printed
    container = _app()

    again, printed = _plan(checkout, passport)  # the same commit: nothing recreated

    assert again.result == "green", printed
    assert _app() == container, printed

    release = {
        "pridem.stack": "blank",
        "pridem.release": REF,
        "pridem.commit": BLANK_COMMIT,
    }
    project = "label=com.docker.compose.project=blank"
    containers = _run(["docker", "ps", "-a", "-q", "--filter", project])
    assert len(containers) == 3  # app, frontend, postgres; throwaways are gone
    for name in containers:
        [text] = _run(["docker", "inspect", "-f", "{{json .Config.Labels}}", name])
        labels = json.loads(text)
        assert {k: labels.get(k) for k in release} == release, name
    volumes = _run(["docker", "volume", "ls", "-q", "--filter", project])
    assert volumes
    for name in volumes:
        labels = _labels("volume", name)
        assert labels.get("pridem.stack") == "blank" and "pridem.release" not in labels
    network = _labels("network", "blank_default")
    assert network.get("pridem.stack") == "blank" and "pridem.release" not in network
    images = sorted(
        set(
            _run(
                [
                    "docker",
                    "image",
                    "ls",
                    "-q",
                    "--no-trunc",
                    "--filter",
                    "label=pridem.stack=blank",
                ]
            )
        )
    )
    assert len(images) == 2, images  # app and frontend; postgres is pulled
    for image in images:
        [text] = _run(
            ["docker", "image", "inspect", "-f", "{{json .Config.Labels}}", image]
        )
        labels = json.loads(text)
        assert {k: labels.get(k) for k in release} == release, image
        assert labels.get("pridem.service") in ("app", "frontend")

    planted = tmp_path / "planted-primer.yaml"
    text = (checkout / "primer.yaml").read_text(encoding="utf-8")
    assert text.count("max_body: 1M") == 1
    planted.write_text(text.replace("max_body: 1M", "max_body: 2M"), encoding="utf-8")
    out = _run([PYTHON, "-c", PLANTED, str(checkout), ENV, str(planted)], timeout=300)
    shown = "\n".join(out)
    [problems] = [line for line in out if line.startswith("PROBLEMS ")]
    [found] = [line for line in out if line.startswith("PLANTED ")]
    assert json.loads(problems.removeprefix("PROBLEMS ")) == [], shown
    assert json.loads(found.removeprefix("PLANTED ")) == [
        "max-body route=api max_body=2M max_upload_mb=1"
    ], shown
