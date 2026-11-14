"""A verdict always, and the operator's tools on ordinary edges (DM-92).

- R2-B1: the terminal goes away (an ssh session dropped) in the middle of a
  step -- a live pty, its master closed: SIGHUP stops the step, ``finally``
  runs, the verdict is written, the console falls silent, the exit is 1;
- the fallback of the verdict: a run whose verdict the model refuses gets one
  all the same -- red, ``run/unbuildable {type}``, what could be taken, and the
  error in its journal;
- R2-B2: ``doctor`` on a box with work to do has its verdict -- a code of what
  ``act`` would do takes neither ``stack`` nor ``name``;
- R2-E3: a signal outside a plan is the refusal ``interrupted``, never a
  traceback; ``logs -f`` ends by it with 0.
"""

import io
import json
import re
import sys
from pathlib import Path
from typing import ClassVar

import pytest
from data_support import FIXTURE, STACK, blank_box
from plan_support import Journal, ListSink, ScriptedStep
from services_support import TAG, git, remotes
from test_verbs_admin import _logs, _out
from test_verbs_project import _box

from pridem.cli import run
from pridem.events import Code
from pridem.plan import Plan, StackSteps
from pridem.report.codes import LOCAL_CODE, ExitCode
from pridem.report.schema import Failure
from pridem.runner import FakeCall, FakeRunner, Stream, SubprocessRunner
from pridem.stacks.passport import Package as PassportPackage
from pridem.state import Box
from pridem.steps.base import CheckResult, StepContext, StepFailed, local_code
from pridem.steps.compose import out
from pridem.steps.sources import source_steps
from pridem.steps.tests import read_junit
from pridem.verbs import deploy as deploy_verbs
from pridem.verbs.report import machine_catalog
from pridem.verbs.run import Planned, Session

HUNG = """
import sys
sys.path.insert(0, {tests!r})
from pathlib import Path
from data_support import blank_box
from plan_support import Journal, ScriptedStep
from pridem.cli import run
from pridem.interrupt import Interrupt
from pridem.plan import StackSteps
from pridem.verbs import deploy as deploy_verbs
from pridem.verbs.run import Planned

class Waiting(ScriptedStep):
    def act(self, ctx, check):
        print("waiting", flush=True)
        ctx.interrupt.sleep(30)

def make(*_):
    steps = [ScriptedStep("first", 1, Journal()), Waiting("waits", 2, Journal())]
    gc = ScriptedStep("gc", 1, Journal())
    return Planned(
        [StackSteps("blank", steps, root=True)], finally_=[StackSteps("box", [gc])]
    )

fs = Path({fs!r})
blank_box(fs)
deploy_verbs.deploy_plan = make
interrupt = Interrupt()
with interrupt.install():
    code = run(["update"], root=fs / "opt" / "pridem", fs_root=fs, interrupt=interrupt)
Path({said!r}).write_text(str(code))
raise SystemExit(code)
"""


TERMINAL = """
import json, os, pty, sys, time
pid, master = pty.fork()
if pid == 0:  # pridem on a terminal
    os.execv(sys.executable, [sys.executable, "-c", sys.argv[1]])
seen = b""
deadline = time.monotonic() + 30
while b"waiting" not in seen and time.monotonic() < deadline:
    seen += os.read(master, 1024)
os.close(master)  # the ssh session drops
_, status = os.waitpid(pid, 0)
print(json.dumps({
    "first": b"first" in seen,
    "exited": os.WIFEXITED(status),
    "code": os.WEXITSTATUS(status) if os.WIFEXITED(status) else -os.WTERMSIG(status),
}))
"""


def test_the_terminal_gone_mid_step_is_a_verdict(tmp_path: Path) -> None:
    """R2-B1, measured on a live pty: the master closes while a step waits --
    SIGHUP stops the step (``interrupted``), ``finally`` runs, the verdict is
    in ``history/`` with no ``journal/write-failed``, and the process exits 1
    (not killed by SIGHUP, not 120 for a console it could not flush). The pair:
    before the master closes the console prints. The terminal is a script run
    by the runner (the fence: no process but by the runner)."""
    said = tmp_path / "code"
    script = HUNG.format(
        tests=str(Path(__file__).parent), fs=str(tmp_path / "box"), said=str(said)
    )
    lines: list[str] = []
    SubprocessRunner().run(
        [sys.executable, "-c", TERMINAL, script],
        timeout=60,
        on_line=lambda s, line, c: lines.append(line) if s is Stream.STDOUT else None,
    )
    measured = json.loads(lines[-1])
    assert measured == {"first": True, "exited": True, "code": 1}, measured
    assert said.read_text() == "1"
    box = Box(tmp_path / "box" / "opt" / "pridem")
    [verdict] = [box.read_verdict(r) for r in box.history_ids()]
    statuses = {(s.phase, s.name): s.status for s in verdict.steps}
    assert statuses[("main", "waits")] == "failed"
    assert statuses[("finally", "gc")] == "ok"
    assert [i.what for i in verdict.report.incomplete] == []


class Unlisted(ScriptedStep):
    """A step whose refusal has no text in the catalog: the model refuses the
    verdict (contract 2 rule 6), the stand-in of any such refusal."""

    def act(self, ctx: StepContext, check: CheckResult) -> None:
        raise StepFailed("unlisted")


def test_a_verdict_the_model_refuses_is_a_fallback_verdict(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A run whose verdict is refused: red, ``run/unbuildable {type}``, every
    step the model takes on its own -- the step it refuses left out -- and the
    error in the run's journal. The pair: the same plan with a listed code is
    the verdict itself."""

    def make(session: Session, *_: object) -> Planned:
        steps = [ScriptedStep("first", 1, Journal()), Unlisted("broken", 2, Journal())]
        return Planned([StackSteps("blank", steps, root=True)])

    blank_box(tmp_path)
    monkeypatch.setattr(deploy_verbs, "deploy_plan", make)
    out, err = io.StringIO(), io.StringIO()
    with FakeRunner() as runner:
        code = run(
            ["--json", "update"],
            root=tmp_path / "opt" / "pridem",
            out=out,
            err=err,
            runner=runner,
            fs_root=tmp_path,
        )
    verdict = json.loads(out.getvalue())
    assert code == 1 and verdict["result"] == "red"
    assert verdict["report"]["incomplete"] == [
        {"what": "run", "code": "unbuildable", "type": "ValueError"}
    ]
    assert [s["name"] for s in verdict["steps"]] == ["first"]
    journal = (tmp_path / "opt" / "pridem" / verdict["log_ref"]).read_text()
    last = json.loads(journal.splitlines()[-1])
    assert (last["stack"], last["name"]) == ("verdict", "build")
    assert "no text in the catalog" in last["line"]


class Fetching(ScriptedStep):
    """``fetch_root`` with something to fetch: its code with ``entry``."""

    codes: ClassVar[dict[str, str]] = {
        **ScriptedStep.codes,
        "fetch": "fetch {entry} at {ref}",
    }

    def check(self, ctx: StepContext) -> CheckResult:
        return CheckResult(True, local_code("fetch", {"entry": "aivis", "ref": "main"}))


def test_doctor_with_work_to_do_has_its_verdict(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """R2-B2: ``doctor`` where ``fetch_root`` would fetch -- code 2, the entry
    ``{stack, name, code, entry, ref}``; a code with ``stack`` is refused where
    it is made (``CheckResult``), never at the verdict."""

    def make(session: Session, *_: object) -> Planned:
        step = Fetching("fetch_root", 1, Journal())
        return Planned([StackSteps("sources", [step], root=True)])

    blank_box(tmp_path)
    monkeypatch.setattr(deploy_verbs, "deploy_plan", make)
    out = io.StringIO()
    with FakeRunner() as runner:
        code = run(
            ["--json", "doctor"],
            root=tmp_path / "opt" / "pridem",
            out=out,
            err=io.StringIO(),
            runner=runner,
            fs_root=tmp_path,
        )
    verdict = json.loads(out.getvalue())
    assert code == 2
    assert verdict["report"]["doctor_diff"] == [
        {
            "stack": "sources",
            "name": "fetch_root",
            "code": "fetch_root:fetch",
            "entry": "aivis",
            "ref": "main",
        }
    ]
    for taken in ("stack", "name"):
        with pytest.raises(ValueError, match="does not take"):
            CheckResult(True, Code("fetch", {taken: "aivis"}))


def test_a_signal_outside_a_plan_is_a_refusal(tmp_path: Path) -> None:
    """R2-E3: ``check`` stopped by a signal in its first command -- the refusal
    ``interrupted``, exit 1, no traceback."""
    copy = tmp_path / "blank"
    import shutil

    shutil.copytree(FIXTURE, copy)
    stopped = FakeCall(("docker", "compose", "version"), outcome="interrupted")
    with FakeRunner(stopped) as runner:
        code, _, err = _out(tmp_path, ["check", str(copy)], runner)
    assert (code, err) == (1, "pridem: interrupted\n")


def test_logs_follow_ends_by_a_signal_with_0(tmp_path: Path) -> None:
    """``logs -f`` ends by Ctrl-C with 0 (DM-86) -- under the command's
    interrupt the runner raises ``Interrupted``, not ``KeyboardInterrupt``
    (measured, DM-92: it was a traceback)."""
    cs = _box(tmp_path)
    follow = _logs(cs, "-f")
    stopped = FakeCall(follow.argv, outcome="interrupted")
    with FakeRunner(stopped) as runner:
        code, _, err = _out(tmp_path, ["logs", STACK, "-f"], runner)
    assert code == 0, err


JUNITS = {
    "a test with no name": (
        '<testsuite><testcase><failure message="m">x</failure></testcase></testsuite>',
        ("unnamed", 1),
    ),
    "line 0": (
        '<testsuite><testcase classname="a.b" name="t" line="0">'
        '<failure message="m"/></testcase></testsuite>',
        ("a.b.t", 1),
    ),
    "a negative line": (
        '<testsuite><testcase classname="a.b" name="t" line="-3">'
        '<failure message="m"/></testcase></testsuite>',
        ("a.b.t", 1),
    ),
    "a line that is a word": (
        '<testsuite><testcase classname="a.b" name="t" line="abc">'
        '<failure message="m"/></testcase></testsuite>',
        ("a.b.t", 1),
    ),
    "a named test at its line": (
        '<testsuite><testcase classname="a.b" name="t" line="7">'
        '<failure message="m"/></testcase></testsuite>',
        ("a.b.t", 7),
    ),
}


@pytest.mark.parametrize("case", sorted(JUNITS))
def test_a_junit_of_the_product_is_a_failure_the_verdict_takes(
    tmp_path: Path, case: str
) -> None:
    """R2-E1 (measured): an empty name, a line that is no line -- each was a
    verdict refused or an exception of the step; now a failure the model
    takes. The pair: a named test keeps its line."""
    text, (test, line) = JUNITS[case]
    path = tmp_path / "junit.xml"
    path.write_text(text, encoding="utf-8")
    [failure] = read_junit(path).failures
    assert (failure["test"], failure["line"]) == (test, line)
    Failure.model_validate(failure)


def test_a_junit_that_is_not_xml_is_the_step_s_code(tmp_path: Path) -> None:
    """R2-E5: a broken file is ``junit-unreadable``, not ``exception
    ParseError``."""
    path = tmp_path / "junit.xml"
    path.write_text("<testsuite><testcase", encoding="utf-8")
    with pytest.raises(StepFailed) as refused:
        read_junit(path)
    assert refused.value.reason == Code("junit-unreadable", {"path": str(path)})


def test_every_code_of_every_step_is_a_local_code_with_its_class_s_name() -> None:
    """R2-E9 and R2-E16, the class: every code a step class gives is by
    ``LOCAL_CODE`` (``not-ubuntu-24.04`` was not: ``preflight`` died making it),
    and the key steps give theirs by the class's own name -- the report's
    catalog has ``deploy_key:*`` and ``ops_key:*``."""
    catalog = machine_catalog()
    steps = {key for key in catalog if ":" in key and not key.startswith("@")}
    assert {
        "deploy_key:no-access",
        "ops_key:no-access",
        "preflight:not-ubuntu",
    } <= steps
    off = sorted(k for k in steps if not re.fullmatch(LOCAL_CODE, k.split(":", 1)[1]))
    assert off == []


def test_a_line_longer_than_the_runner_s_limit_is_whole(tmp_path: Path) -> None:
    """R2-E4 (measured): a ``config`` JSON of 70 000 characters comes from the
    runner in two pieces; ``out`` gives it back whole, as JSON. The pair: short
    lines are lines."""
    document = {"services": {"app": {"environment": {"BIG": "x" * 70000}}}}
    code = f"import json; print(json.dumps({document!r})); print('short')"
    ctx = StepContext(SubprocessRunner(), "deploy", "test", "blank", lambda *_: None)
    _, lines = out(ctx, [sys.executable, "-c", code])
    assert json.loads(lines[0]) == document and lines[1:] == ["short"]


def _git(*argv: str, cwd: Path | None = None) -> None:
    env = {
        "PATH": "/usr/bin:/bin",
        "HOME": "/nonexistent",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_AUTHOR_NAME": "t",
        "GIT_AUTHOR_EMAIL": "t@t",
        "GIT_COMMITTER_NAME": "t",
        "GIT_COMMITTER_EMAIL": "t@t",
    }
    SubprocessRunner().run(
        ["git", *argv], timeout=60, env=env, cwd=cwd, on_line=lambda *_: None
    )


@pytest.mark.parametrize("given", [False, True])
def test_doctor_with_a_new_commit_on_the_branch_is_a_difference(
    tmp_path: Path, given: bool
) -> None:
    """R2-B18 (DM-92 FIX; review 0003, measured with real git): installed at
    one commit, the branch moves on -- ``doctor``: ``fetch_root`` would fetch,
    and ``fetch_packages``, which reads ``primer.yaml`` of the target, answers by
    its own code -- the passport's packages to fetch -- or nothing without
    them; never ``exception RuntimeError`` (with or without a package: its
    ``_plan`` read ``primer.yaml`` first). The pair: ``install`` before it."""
    import shutil

    work, bare, root = tmp_path / "work", tmp_path / "blank.git", tmp_path / "box"
    shutil.copytree(FIXTURE, work)
    _git("init", "-q", "-b", "main", str(work))
    _git("add", "-A", cwd=work)
    _git("commit", "-qm", "one", cwd=work)
    _git("clone", "-q", "--bare", str(work), str(bare))
    root.mkdir()

    def plan(mode: str) -> Plan:
        packages = (
            {"skin": PassportPackage(repo="file:///nowhere/skin.git", version="1.0.0")}
            if given and mode == "doctor"
            else {}
        )
        _, steps = source_steps(
            root,
            stack="blank",
            address=f"file://{bare}",
            ref="main",
            tag=False,
            packages=packages,
        )
        return Plan(
            [StackSteps("sources", steps, root=True)],
            mode=mode,  # type: ignore[arg-type]
            role="test",
            runner=SubprocessRunner(),
            sink=ListSink(),
        )

    assert plan("install").run().code is ExitCode.OK
    _git("commit", "-q", "--allow-empty", "-m", "two", cwd=work)
    _git("push", "-q", str(bare), "main", cwd=work)
    doctor = plan("doctor").run()
    assert doctor.code is ExitCode.INCOMPLETE, doctor.steps
    assert [r for r in doctor.steps if r.status == "failed"] == []
    diff = {(d.name, d.reason.code) for d in doctor.doctor_diff}
    expected = {("fetch_root", "fetch_root:fetch")}
    if given:
        expected.add(("fetch_packages", "fetch_packages:fetch"))
    assert diff == expected


def test_doctor_with_a_service_tag_the_remote_lost_is_its_code(tmp_path: Path) -> None:
    """DM-92 FIX, the class of R2-B18 (the gate): ``check_lock`` checks the
    tags of the lock in its ``verify``, which ``doctor`` does not run; a tag the
    remote no longer holds reached ``fetch_services.check`` as an exception
    (``_known``). Now -- its own code, literally. The pair: ``install`` while the
    tag is there is green."""
    remotes(tmp_path)
    root = tmp_path / "box"

    def plan(mode: str) -> Plan:
        _, steps = source_steps(
            root,
            stack="aivis",
            address=f"file://{tmp_path}/aivis.git",
            ref="main",
            tag=False,
        )
        return Plan(
            [StackSteps("sources", steps, root=True)],
            mode=mode,  # type: ignore[arg-type]
            role="test",
            runner=SubprocessRunner(),
            sink=ListSink(),
        )

    assert plan("install").run().code is ExitCode.OK
    git(tmp_path / "comms.git", "tag", "-d", TAG)
    doctor = plan("doctor").run()
    [failed] = [r for r in doctor.steps if r.status == "failed"]
    assert failed.name == "fetch_services"
    assert failed.reason == Code(
        "fetch_services:missing-tag",
        {"service": "comms", "tag": "v1.0.0", "repo": f"file://{tmp_path}/comms.git"},
    )
