"""Tier 3 probe (DM-19): the whole ``install`` of ``primer-blank``, one plan.

The last file of the directory by name: the host steps, the passport (a
file), the sources -- from a ``file://`` mirror of the blank at its pinned
commit, so no key of CI is needed --, the blank's ladder (``seams_check``,
``render_env``, ``build``, ``packages``, ``tests``, ``migrate``, ``up``),
``types``, the edge (``tls_files``, ``nginx``, ``ssl``), ``frontend``, the
final check and ``finalize``. Earlier probes of the run brought parts of the
blank up; this plan finds what they left and does the rest: the tests run in
``blank_test`` from the test target, ``current`` names the release,
``state.json`` is written by ``finalize``. The live database keeps its head;
the junit of the tests reaches the verdict through ``TestReport``.
"""

import json
from pathlib import Path

from test_tier3_render_env import BLANK_COMMIT, PYTHON, _blank, _passport
from test_tier3_up import _journal_tail, _run

from pridem.report.schema import Verdict

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
from pridem.state import Box, JournalHeader
from pridem.steps.build import Build
from pridem.steps.env import RenderEnv, SeamsCheck
from pridem.steps.finalize import FinalCheck, Finalize
from pridem.steps.frontend import Frontend
from pridem.steps.host import host_steps
from pridem.steps.migrate import Migrate
from pridem.steps.nginx import Nginx
from pridem.steps.packages import Packages
from pridem.steps.passport import passport_steps
from pridem.steps.sources import source_steps
from pridem.steps.ssl import Ssl, TlsFiles
from pridem.steps.tests import TestReport, Tests
from pridem.steps.types import Types
from pridem.steps.up import Up

root, checkout, passport, mirror, commit = (
    Path("/"), Path(sys.argv[1]), Path(sys.argv[2]), sys.argv[3], sys.argv[4]
)
blank = load_primer_yaml(checkout / "primer.yaml")
release = Path("/opt/blank/releases") / commit
box, secrets = Box(Path("/opt/pridem")), Secrets(())
memory, report = SeamMemory(), TestReport()
host, final = host_steps(root)
fetched, first = passport_steps(root, secrets=secrets, server=None, file=passport)
_, sources = source_steps(
    root, stack="blank", address=f"file://{mirror}", ref="main", tag=False
)
render = RenderEnv(
    blank, product=blank, fetched=fetched, secrets=secrets, memory=memory, root=root
)
parts = {"release": release, "ref": "main", "commit": commit, "root": root}
ladder = [
    SeamsCheck(blank, {}, fetched), render,
    Build(blank, "blank", **parts, fetched=fetched),
    Packages(blank, "blank", **parts, fetched=fetched),
    Tests(blank, "blank", **parts, report=report, secrets=secrets),
    Migrate(blank, "blank", **parts),
    Up(blank, "blank", **parts, memory=memory, render=render),
]
types = [Types(blank, "blank", **parts, role="test", branch="main", run_id="tier3",
               push_to=f"file://{mirror}", git_dir=Path("/opt/blank/git"))]
edge = [
    TlsFiles(blank, fetched=fetched, root=root),
    Nginx(blank, fetched=fetched, secrets=secrets, root=root),
    Ssl(blank, fetched=fetched, secrets=secrets, root=root),
]
front = [Frontend(blank, fetched=fetched, root=root)]
tail = [
    FinalCheck(),
    Finalize(
        releases={"blank": release},
        composition={"blank": commit, "pridem": __version__},
        box=box, fetched=fetched, root=root,
    ),
]

class Both:
    def __init__(self, *sinks):
        self.sinks = sinks
    def emit(self, event):
        for sink in self.sinks:
            sink.emit(event)

with box.lock("tier3-install"):
    started = datetime.now(UTC).replace(microsecond=0)
    run_id = f"{started:%Y-%m-%dT%H:%M:%SZ}-{token_hex(2)}"
    journal = box.open_journal(
        JournalHeader(run_id=run_id, verb="install", mode="install", args={},
                      actor={"type": "machine", "via": "local"}, started=started,
                      composition_before={"pridem": __version__}),
        secrets,
    )
    try:
        outcome = Plan(
            [StackSteps("host", host), StackSteps("passport", first),
             StackSteps("sources", sources), StackSteps("blank", ladder),
             StackSteps("types", types), StackSteps("edge", edge),
             StackSteps("frontend", front), StackSteps("finalize", tail, root=True)],
            mode="install", role="test", runner=SubprocessRunner(),
            sink=Both(ConsoleSink(sys.stdout, secrets), journal),
            finally_=[StackSteps("host", final)],
        ).run()
    finally:
        journal.close()
    every = [*host, *first, *sources, *ladder, *types, *edge, *front, *tail, *final]
    verdict = build_verdict(
        outcome, run_id=run_id, verb="install", args={},
        actor={"type": "machine", "via": "local"}, started=started,
        finished=datetime.now(UTC).replace(microsecond=0),
        passport_version=fetched.passport.version if fetched.passport else None,
        composition_before={"pridem": __version__},
        composition_after={"blank": commit, "pridem": __version__}, secrets=secrets,
        catalog=with_steps(ENGLISH, [(step.name, step.codes) for step in every]),
        failures=report.failures, junit=report.junit,
    )
    box.write_verdict(verdict)
print("VERDICT " + verdict.model_dump_json())
sys.exit(int(verdict.exit_code))
"""


def test_tier3_the_whole_install_of_the_blank(tmp_path: Path) -> None:
    checkout, passport = _blank(tmp_path), _passport(tmp_path)
    mirror = tmp_path / "blank-mirror.git"
    _run(["git", "clone", "-q", "--mirror", str(checkout), str(mirror)])
    _run(
        ["git", "--git-dir", str(mirror), "update-ref", "refs/heads/main", BLANK_COMMIT]
    )

    lines = _run(
        [PYTHON, "-c", PLAN, str(checkout), str(passport), str(mirror), BLANK_COMMIT],
        timeout=3600,
        expect=(0, 1, 2),
    )

    printed = "\n".join(lines)
    [line] = [x for x in lines if x.startswith("VERDICT ")]
    verdict = Verdict.model_validate_json(line.removeprefix("VERDICT "))
    if verdict.result != "green":
        printed += _journal_tail(verdict)
    assert verdict.result == "green", printed
    facts = {(s.stack, s.name): s.verify or {} for s in verdict.steps}
    tests = facts[("blank", "tests")]
    assert tests["test_db"] == "blank_test" and tests["target"] == "test", printed
    junit = tests["junit"]
    assert isinstance(junit, dict), printed
    total, failed = junit["total"], junit["failed"]
    assert isinstance(total, int) and total > 0 and failed == 0, printed
    assert verdict.junit is not None and verdict.junit.total == total, printed
    verified = facts[("finalize", "final_check")]["verified"]
    assert isinstance(verified, int) and verified > 10, printed
    release = f"/opt/blank/releases/{BLANK_COMMIT}"
    assert str(Path("/opt/blank/current").readlink()) == release, printed
    state = json.loads(Path("/opt/pridem/state.json").read_text())
    assert state["current"] == {"blank": Path(release).name}, state
    assert state["composition"]["blank"] == BLANK_COMMIT, state
    # the live database kept its head; the tests had their own
    compose = [
        "docker",
        "compose",
        "-p",
        "blank",
        "--env-file",
        "/opt/blank/env/.env",
        "-f",
        f"{release}/docker-compose.yml",
    ]
    head = _run(
        [
            *compose,
            "exec",
            "-T",
            "postgres",
            "psql",
            "-U",
            "blank",
            "-d",
            "blank",
            "-tAc",
            "SELECT version_num FROM alembic_version",
        ]
    )
    assert [x.strip() for x in head if x.strip()] == ["0001"], head
    test_db = _run(
        [
            *compose,
            "exec",
            "-T",
            "postgres",
            "psql",
            "-U",
            "blank",
            "-d",
            "postgres",
            "-tAc",
            "SELECT 1 FROM pg_database WHERE datname = 'blank_test'",
        ]
    )
    assert "1" in [x.strip() for x in test_db], test_db
