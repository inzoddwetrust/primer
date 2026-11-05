"""The box's verbs (DM-45): the source of the passport, the plan builder's
refs, options refused before a run, ``report``, and what the verdict says of
the box beside the plan -- a journal in quarantine, a journal that did not
close."""

import io
from collections.abc import Mapping, Sequence
from pathlib import Path

import pytest
from passport_support import passport_example, section, write_passport
from plan_support import Journal, ScriptedStep, plan
from state_support import header, run_id

from pridem.cli import run
from pridem.events import Secrets
from pridem.plan import Deferred, Stack, StackSteps
from pridem.report.codes import ExitCode
from pridem.report.schema import Verdict
from pridem.runner import (
    CommandNotStarted,
    FakeCall,
    FakeRunner,
    OnLine,
    Result,
    SubprocessRunner,
)
from pridem.stacks.passport import load_passport
from pridem.state import Box, JournalSink
from pridem.steps.passport import PASSPORT_COPY, Fetched
from pridem.steps.sources import FetchRoot
from pridem.verbs.base import Refused
from pridem.verbs.plans import Source, Wanted, deploy_plan, ops_address, source_of
from pridem.verbs.run import Session

NO_SECRETS = Secrets(())


class Refusing:
    """A runner that starts nothing: every command is ``not started``."""

    def __init__(self) -> None:
        self.argvs: list[tuple[str, ...]] = []

    def run(
        self,
        argv: Sequence[str],
        *,
        expect: tuple[int, ...] = (0,),
        timeout: float,
        cwd: Path | None = None,
        env: Mapping[str, str] | None = None,
        on_line: OnLine,
    ) -> Result:
        self.argvs.append(tuple(argv))
        raise CommandNotStarted(tuple(argv), "refused by the test")


def _passport(tmp: Path, role: str = "test", name: str = "aivis-test") -> Path:
    data = passport_example()
    section(data, "server").update({"role": role, "name": name})
    if role != "test":  # contract 1 rule 4: a release tag there
        section(data, "product")["ref"] = "v1.0.0"
    tmp.mkdir(parents=True, exist_ok=True)
    return write_passport(tmp, data)


def _cli(
    tmp: Path, argv: list[str], runner: object | None = None
) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    code = run(
        argv,
        root=tmp / "opt" / "pridem",
        out=out,
        err=err,
        runner=Refusing() if runner is None else runner,  # type: ignore[arg-type]
        fs_root=tmp,
    )
    return code, out.getvalue(), err.getvalue()


def _history(tmp: Path) -> list[Path]:
    history = tmp / "opt" / "pridem" / "history"
    return sorted(history.iterdir()) if history.exists() else []


# --- the passport's source -----------------------------------------------------------


def test_the_source_is_as_given_else_the_boxs(tmp_path: Path) -> None:
    copy = Fetched(passport=load_passport(_passport(tmp_path / "p")))
    none = Fetched()
    file = tmp_path / "x.yaml"
    assert source_of(tmp_path, none, file=file, ops=None, server=None) == Source(
        file=file
    )
    assert source_of(tmp_path, none, file=None, ops="git@h:o/ops.git", server="b") == (
        Source(ops="git@h:o/ops.git", server="b")
    )
    for given in ({"ops": "a", "server": None}, {"ops": None, "server": "b"}):
        with pytest.raises(Refused, match="go together"):
            source_of(tmp_path, none, file=None, **given)
    with pytest.raises(Refused, match="one source"):
        source_of(tmp_path, none, file=file, ops="a", server="b")
    with pytest.raises(Refused, match="where is the passport"):
        source_of(tmp_path, none, file=None, ops=None, server=None)
    # a box installed from a file: its copy
    assert source_of(tmp_path, copy, file=None, ops=None, server=None) == Source(
        file=tmp_path / PASSPORT_COPY
    )


def test_a_box_of_an_ops_repository_names_its_address_and_server(
    tmp_path: Path,
) -> None:
    """The address is read from the git config git itself wrote (``pridem.
    address`` beside the ssh alias of the remote); the server is the copy's."""
    bare = tmp_path / "opt" / "pridem" / "ops" / "git"
    runner = SubprocessRunner()
    lines: list[str] = []

    def keep(stream: object, line: str, cut: bool) -> None:
        lines.append(line)

    runner.run(
        ["git", "init", "--quiet", "--bare", str(bare)], timeout=30, on_line=keep
    )
    for args in (
        ["remote", "add", "origin", "pridem-github.com-o-ops:o/ops.git"],
        ["config", "pridem.address", "git@github.com:o/ops.git"],
    ):
        runner.run(["git", "-C", str(bare), *args], timeout=30, on_line=keep)
    assert ops_address(tmp_path) == "git@github.com:o/ops.git"
    copy = Fetched(passport=load_passport(_passport(tmp_path / "p", name="box-1")))
    assert source_of(tmp_path, copy, file=None, ops=None, server=None) == Source(
        ops="git@github.com:o/ops.git", server="box-1"
    )
    # the pair: no bare repository -- no address
    assert ops_address(tmp_path / "other") is None


# --- the refs of the plan ------------------------------------------------------------


def _sources(tmp: Path, role: str, wanted: Wanted) -> tuple[FetchRoot, dict[str, str]]:
    """The ``fetch_root`` the plan makes once the passport is read."""
    box = Box(tmp / "opt" / "pridem")
    file = _passport(tmp / "p", role=role)
    planned = deploy_plan(Session(box, "r1", Fetched(), NO_SECRETS), tmp, wanted, None)
    assert planned.fetched is not None
    planned.fetched.passport = load_passport(file)
    [sources] = [
        s for s in planned.stacks if isinstance(s, Deferred) and s.name == "sources"
    ]
    made = sources.build()
    assert made is not None
    [fetch] = [step for step in made[0].steps if isinstance(step, FetchRoot)]
    return fetch, fetch.resolved.tries


@pytest.mark.parametrize(
    ("role", "ref", "want_ref", "tag"),
    [
        ("test", None, "main", False),  # update, doctor: the passport's branch
        ("test", "v1.2.0", "v1.2.0", None),  # deploy <ref> on test: tag, else branch
        ("prod", None, "v1.0.0", True),  # prod: the passport's ref is a tag
        ("prod", "v1.2.0", "v1.2.0", True),
    ],
)
def test_the_ref_is_deploys_else_the_passports(
    tmp_path: Path, role: str, ref: str | None, want_ref: str, tag: bool | None
) -> None:
    """``deploy <ref>`` targets its ref; ``update`` and ``doctor`` the
    passport's -- so after ``deploy`` of another ref, ``doctor`` shows the
    box off its passport (the gate's answer, Р-Ж)."""
    wanted = Wanted(mode="deploy", source=Source(file=tmp_path / "x"), ref=ref)
    fetch, _ = _sources(tmp_path, role, wanted)
    assert (fetch.ref, fetch.tag) == (want_ref, tag)


def test_tries_reach_the_lock_of_the_sources(tmp_path: Path) -> None:
    wanted = Wanted(
        mode="deploy", source=Source(file=tmp_path / "x"), tries={"comms": "3.2.0"}
    )
    _, tries = _sources(tmp_path, "test", wanted)
    assert tries == {"comms": "3.2.0"}


def test_a_deferred_stack_not_known_yet_is_a_difference_in_doctor() -> None:
    """``doctor`` does not fetch: the steps of a new target are unknown -- one
    entry ``ladder:unresolved``, code 2, not red; in a run the same is red."""
    journal = Journal()
    stacks: list[Stack] = [
        StackSteps("host", [ScriptedStep("a", 1, journal, needed=False)]),
        Deferred("product", lambda: None, after="fetch_root", root=True),
    ]
    doctor, _ = plan(stacks, "doctor")
    outcome = doctor.run()
    assert outcome.code is ExitCode.INCOMPLETE
    assert [(i.stack, i.name, i.reason.code) for i in outcome.doctor_diff] == [
        ("product", "ladder", "ladder:unresolved")
    ]
    assert outcome.doctor_diff[0].reason.params == {"after": "fetch_root"}
    deploy, _ = plan(stacks, "deploy")
    assert deploy.run().code is ExitCode.FAILED


# --- refused before the run --------------------------------------------------------


@pytest.mark.parametrize(
    ("argv", "says"),
    [
        (["update", "--nope"], "unknown option --nope"),
        (["update", "--try", "comms"], "invalid arguments"),
        (["update", "--try", "comms=^3"], "invalid arguments"),
        (["update", "--try", "comms=3.1.0", "--try", "comms=3.2.0"], "given twice"),
        (["update", "--passport"], "needs a value"),
        (["doctor", "--ops", "git@h:o/ops.git"], "go together"),
        (["install"], "where is the passport"),
        (["deploy"], "invalid arguments"),
    ],
)
def test_a_wrong_command_line_is_refused_before_the_run(
    tmp_path: Path, argv: list[str], says: str
) -> None:
    runner = Refusing()
    code, out, err = _cli(tmp_path, argv, runner)
    assert (code, out) == (1, "") and says in err, err
    assert runner.argvs == [] and _history(tmp_path) == []


def test_destroy_on_prod_names_the_server(tmp_path: Path) -> None:
    """On a box whose passport says prod, ``destroy`` and ``reinstall`` run
    only with ``--confirm <server.name>``; the pair: with it, and on test with
    nothing, the run happens (a verdict)."""
    copy = tmp_path / PASSPORT_COPY
    copy.parent.mkdir(parents=True)
    copy.write_text(
        _passport(tmp_path / "p", role="prod", name="velo-prod").read_text()
    )
    for argv in (
        ["destroy"],
        ["destroy", "--confirm", "velo-test"],
        ["reinstall", "--confirm", "nope"],
    ):
        code, _, err = _cli(tmp_path, argv)
        assert code == 1 and "--confirm velo-prod" in err, (argv, err)
    assert _history(tmp_path) == []
    code, _, err = _cli(tmp_path, ["destroy", "--confirm", "velo-prod"])
    assert err == "" and len(_history(tmp_path)) == 1


# --- report --------------------------------------------------------------------------


def test_report_reads_a_stored_run_and_writes_no_verdict(tmp_path: Path) -> None:
    code, _, _ = _cli(tmp_path, ["destroy"])
    [stored] = _history(tmp_path)
    run_ = stored.stem
    code, out, _ = _cli(tmp_path, ["report", run_])
    assert code == 0 and "destroy" in out and out.startswith("#")
    code, out, _ = _cli(tmp_path, ["report", run_, "--json"])
    assert Verdict.model_validate_json(out).run_id == run_
    code, llm, _ = _cli(tmp_path, ["report", run_, "--llm"])
    assert code == 0 and llm and llm != out
    assert len(_history(tmp_path)) == 1  # no verdict of report's own
    code, _, err = _cli(tmp_path, ["report", "2026-01-01T00:00:00Z-0000"])
    assert code == 1 and "no verdict" in err


# --- what the verdict says beside the plan -------------------------------------------


DPKG = ("dpkg-query", "-W", "-f=${Status}", "docker.io")


def _clean() -> FakeRunner:
    """``destroy`` of a box with no docker and nothing on it: green."""
    return FakeRunner(FakeCall(DPKG), FakeCall(DPKG))


def _quarantined_journal(tmp: Path) -> str:
    box = Box(tmp / "opt" / "pridem")
    run = run_id(1)
    with box.lock("dying"):
        box.open_journal(header(run), NO_SECRETS).close()
    path = box.journals / f"{run}.jsonl"
    path.write_text("{not a header\n")
    return run


@pytest.mark.parametrize("verb", [["destroy"], ["status"]])
def test_a_quarantined_journal_is_in_the_verdict_of_the_command_that_found_it(
    tmp_path: Path, verb: list[str]
) -> None:
    run = _quarantined_journal(tmp_path)
    code, out, _ = _cli(
        tmp_path, ["--json", *verb], _clean() if verb != ["status"] else None
    )
    entries = [
        i.model_dump() for i in Verdict.model_validate_json(out).report.incomplete
    ]
    assert {"what": "journal", "code": "quarantined", "run_id": run} in entries
    assert code == ExitCode.INCOMPLETE
    # once: the next command does not find it again
    code, out, _ = _cli(
        tmp_path, ["--json", *verb], _clean() if verb != ["status"] else None
    )
    entries = [
        i.model_dump() for i in Verdict.model_validate_json(out).report.incomplete
    ]
    assert not [e for e in entries if e["what"] == "journal"]


def test_a_journal_that_does_not_close_is_write_failed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    real = JournalSink.close

    def full(self: JournalSink) -> None:
        real(self)
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(JournalSink, "close", full)
    code, out, _ = _cli(tmp_path, ["--json", "destroy"], _clean())
    verdict = Verdict.model_validate_json(out)
    assert [i.model_dump() for i in verdict.report.incomplete] == [
        {"what": "journal", "code": "write-failed"}
    ]
    assert code == ExitCode.INCOMPLETE
    # a journal whose writes failed too: one entry, never two
    real_emit = JournalSink.emit

    def lost(self: JournalSink, event: object) -> None:
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(JournalSink, "emit", lost)
    code, out, _ = _cli(tmp_path, ["--json", "destroy"], _clean())
    verdict = Verdict.model_validate_json(out)
    assert [i.model_dump() for i in verdict.report.incomplete] == [
        {"what": "journal", "code": "write-failed"}
    ]
    monkeypatch.setattr(JournalSink, "emit", real_emit)
    monkeypatch.setattr(JournalSink, "close", real)  # the pair: it closes
    code, out, _ = _cli(tmp_path, ["--json", "destroy"], _clean())
    assert Verdict.model_validate_json(out).report.incomplete == []


@pytest.mark.parametrize("signalled", [True, False])
def test_a_deferred_stack_after_a_signal_is_not_made(signalled: bool) -> None:
    """A signal at the end of a stack's last step stops the ladder between
    stacks: the deferred stack after it is never made (its ``build`` would
    read what the stopped plan left half done); the pair: with no signal it
    is made and runs."""
    journal = Journal()
    made: list[str] = []

    def entries() -> list[StackSteps]:
        made.append("built")
        return [StackSteps("blank", [ScriptedStep("up", 1, journal)])]

    last = ScriptedStep(
        "a", 1, journal, signal_in="verify" if signalled else None, signal_stops=False
    )
    stacks: list[Stack] = [
        StackSteps("host", [last]),
        Deferred("product", entries, after="fetch_root"),
        StackSteps("finalize", [ScriptedStep("f", 1, journal)], root=True),
    ]
    outcome = plan(stacks)[0].run()
    assert (made == []) is signalled, made
    assert outcome.interrupted is signalled


@pytest.mark.parametrize("mode", ["install", "deploy", "doctor", "reinstall"])
def test_the_machine_makes_the_whole_ladder_of_protocol_6(
    tmp_path: Path, mode: str
) -> None:
    """The stacks in protocol 6's order -- the dependencies (keys, lock,
    fetch) and the services' ladders before the product's (DM-46), ``types``,
    the edge, ``frontend`` and ``finalize`` made once the target is read --
    ``finally``
    the host's timers and ``gc``; ``reinstall`` destroys after the passport is
    read and before anything is installed."""
    box = Box(tmp_path / "opt" / "pridem")
    wanted = Wanted(mode=mode, source=Source(file=tmp_path / "x"))
    planned = deploy_plan(
        Session(box, "r1", Fetched(), NO_SECRETS), tmp_path, wanted, None
    )
    names = [stack.name for stack in planned.stacks]
    middle = ["destroy"] if mode == "reinstall" else []
    assert names == [
        "host",
        "passport",
        *middle,
        "timers",
        "sources",
        "dependencies",
        "services",
        "product",
        "types",
        "edge",
        "frontend",
        "finalize",
    ]
    assert [s.name for s in planned.stacks if s.root] == ["finalize"]
    assert [stack.name for stack in planned.finally_] == ["host", "box"]
    deferred = {s.name for s in planned.stacks if isinstance(s, Deferred)}
    assert deferred == {
        "sources",
        "dependencies",
        "services",
        "product",
        "types",
        "edge",
        "frontend",
        "finalize",
    }
