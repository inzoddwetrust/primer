"""Probes DM-45: the box's verbs make their plan themselves and print it, the
verdict's JSON is contract 2's, a rejected contract file is a message with no
traceback, a signal is a flag after which ``finally`` runs, and one session
runs one plan with one journal.

The plan of the verbs is ``pridem/verbs/plans.py``; here it is replaced by a
plan of scripted steps (``_fake_plan``) -- a deferred stack among them -- so
the probes read what the verbs, the runner of the plan and the console do with
any plan, with no box under them.
"""

import io
import json
import os
import signal
from collections.abc import Callable
from pathlib import Path

import pytest
import yaml
from contract_support import example, node
from passport_support import passport_example, section, write_passport
from plan_support import Journal, ScriptedStep, plan
from state_support import header, run_id

from pridem.cli import run
from pridem.events import Secrets
from pridem.interrupt import Interrupt
from pridem.plan import Deferred, RunRefused, StackSteps
from pridem.report.codes import ExitCode
from pridem.report.schema import Verdict
from pridem.runner import FakeRunner
from pridem.state import Box, JournalTaken
from pridem.steps.base import CheckResult, StepContext
from pridem.verbs import deploy as deploy_verbs
from pridem.verbs.plans import Wanted
from pridem.verbs.run import Planned, Session

MARKER = "MK45-c0de"
SECRET = f"{MARKER}-long-enough-secret"


def _passport(tmp: Path, **server: str) -> Path:
    data = passport_example()
    section(data, "server").update({"role": "test", **server})
    return write_passport(tmp, data)


def _fake_plan(
    journal: Journal, *, extra: list[ScriptedStep] | None = None
) -> Callable[[Session, Path, Wanted, object], Planned]:
    """A plan of scripted steps in the shape of the machine's: a known stack, a
    deferred one made while the plan runs, a root one, and a ``finally``."""

    def make(
        session: Session, fs_root: Path, wanted: Wanted, preread: object
    ) -> Planned:
        def entries() -> list[StackSteps]:
            return [
                StackSteps(
                    "blank",
                    [ScriptedStep("build", 1, journal), ScriptedStep("up", 2, journal)],
                )
            ]

        return Planned(
            [
                StackSteps("host", [ScriptedStep("preflight", 1, journal)]),
                Deferred("product", entries, after="fetch_root"),
                StackSteps(
                    "finalize",
                    [ScriptedStep("finalize", 1, journal), *(extra or [])],
                    root=True,
                ),
            ],
            [StackSteps("box", [ScriptedStep("gc", 1, journal)])],
        )

    return make


def _cli(tmp: Path, argv: list[str], **kw: object) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    code = run(
        argv,
        root=tmp / "opt" / "pridem",
        out=out,
        err=err,
        runner=FakeRunner(),
        fs_root=tmp,
        **kw,  # type: ignore[arg-type]
    )
    return code, out.getvalue(), err.getvalue()


def test_probe_DM_45_doctor_prints_full_plan_without_act(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``doctor`` runs ``check`` of every step of the plan -- the deferred
    stack's too, made while it runs -- prints a line for each step that would
    act, in the ladder's order, and acts on nothing; the pair: ``deploy`` of
    the same plan calls ``act`` of every step."""
    journal = Journal()
    monkeypatch.setattr(deploy_verbs, "deploy_plan", _fake_plan(journal))
    file = _passport(tmp_path)
    code, out, _ = _cli(tmp_path, ["doctor", "--passport", str(file)])
    assert code == ExitCode.INCOMPLETE
    lines = out.splitlines()
    assert lines[:4] == [
        "- host · preflight — would do preflight",
        "- blank · build — would do build",
        "- blank · up — would do up",
        "- finalize · finalize — would do finalize",
    ]
    assert [entry.rpartition(":")[2] for entry in journal] == ["check"] * 4
    # the pair: deploy acts on every step of the same plan, then verifies
    journal.clear()
    code, _, _ = _cli(tmp_path, ["deploy", "main", "--passport", str(file)])
    assert code == ExitCode.OK
    acted = [entry for entry in journal if entry.endswith(":act")]
    assert acted == [
        "host/preflight:act",
        "blank/build:act",
        "blank/up:act",
        "finalize/finalize:act",
        "box/gc:act",
    ]


@pytest.mark.parametrize("where", ["before", "after"])
def test_probe_DM_45_json_output_matches_verdict_schema(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, where: str
) -> None:
    """``--json``, before the verb or after it: stdout is one object of
    contract 2 -- the model of the verdict reads it whole, and the box's
    ``history/`` holds the same -- and the ladder went to stderr; the pair:
    without ``--json`` the ladder and the summary line are on stdout."""
    journal = Journal()
    monkeypatch.setattr(deploy_verbs, "deploy_plan", _fake_plan(journal))
    file = _passport(tmp_path)
    argv = ["update", "--passport", str(file)]
    argv = ["--json", *argv] if where == "before" else [*argv, "--json"]
    code, out, err = _cli(tmp_path, argv)
    assert code == ExitCode.OK
    verdict = Verdict.model_validate_json(out)
    assert (verdict.verb, verdict.exit_code, verdict.result) == ("update", 0, "green")
    stored = tmp_path / "opt" / "pridem" / "history" / f"{verdict.run_id}.json"
    assert json.loads(stored.read_text()) == json.loads(out)
    assert verdict.args == {"passport": str(file)}
    assert "blank · build" in err and "blank · build" not in out
    # the pair: no --json -- the ladder and the summary line, on stdout
    code, out, err = _cli(tmp_path, ["update", "--passport", str(file)])
    assert code == ExitCode.OK and err == ""
    assert "blank · build" in out and not out.lstrip().startswith("{")


def test_probe_DM_45_contract_error_prints_no_traceback(tmp_path: Path) -> None:
    """A contract file its loader rejects -- the passport of ``install`` with
    a marker in ``asked``, ``primer.yaml`` of ``check`` with a marker in
    ``env.*.value`` -- is a message on stderr naming the rule: no traceback,
    no marker in stdout or stderr. The pair: the message is there, with the
    rule's code."""
    data = passport_example()
    section(data, "server")["role"] = "test"
    section(data, "asked", "comms")["TELEGRAM_BOT_TOKEN"] = MARKER  # too short
    bad = write_passport(tmp_path, data)
    code, out, err = _cli(tmp_path, ["install", "--passport", str(bad)])
    assert code == 1
    assert "Traceback" not in out + err and MARKER not in out + err
    assert err.startswith("pridem: ") and "R12.secret-length" in err
    assert not (tmp_path / "opt" / "pridem" / "history").exists()  # before the run
    # primer.yaml through ``check``: the value of a variable is not a field
    repo = tmp_path / "repo"
    repo.mkdir()
    product = example("product.yaml")
    node(product, "env")["SECRET_KEY"] = {"source": "minted", "value": SECRET}
    (repo / "primer.yaml").write_text(yaml.safe_dump(product))
    code, out, err = _cli(tmp_path, ["check", str(repo)])
    assert code == 1
    assert "Traceback" not in out + err and MARKER not in out + err
    assert "R1.value" in out + err


class _Kill(ScriptedStep):
    """Sends ``SIGINT`` to this very process in its ``act``: a real signal,
    taken by the handler ``pridem`` installs."""

    def act(self, ctx: StepContext, check: CheckResult) -> None:
        super().act(ctx, check)
        os.kill(os.getpid(), signal.SIGINT)


def test_probe_DM_45_signal_sets_the_flag_and_finally_runs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A real SIGINT under the command's handler: no exception -- the flag is
    set, the step that got it finishes, the rest of ``main`` is skipped
    ``after-interrupt``, ``finally`` runs, and the verdict is written (exit
    1). The pair: with no signal the same plan runs every step."""
    journal = Journal()
    killer = _Kill("finalize_mark", 2, journal)
    tail = ScriptedStep("finalize_tail", 3, journal)
    monkeypatch.setattr(
        deploy_verbs, "deploy_plan", _fake_plan(journal, extra=[killer, tail])
    )
    file = _passport(tmp_path)
    interrupt = Interrupt()
    with interrupt.install():
        code, out, _ = _cli(
            tmp_path, ["--json", "update", "--passport", str(file)], interrupt=interrupt
        )
    assert interrupt.received == [signal.SIGINT]
    assert code == ExitCode.FAILED
    verdict = Verdict.model_validate_json(out)
    steps = {(s.phase, s.stack, s.name): s for s in verdict.steps}
    assert steps[("main", "finalize", "finalize_mark")].status == "ok"
    skipped = steps[("main", "finalize", "finalize_tail")]
    assert skipped.status == "skipped" and skipped.reason is not None
    assert skipped.reason.code == "after-interrupt"
    assert steps[("finally", "box", "gc")].status == "ok"
    assert "box/gc:verify" in journal
    # the pair: no signal, every step runs
    journal.clear()
    monkeypatch.setattr(
        deploy_verbs,
        "deploy_plan",
        _fake_plan(journal, extra=[ScriptedStep("finalize_tail", 3, journal)]),
    )
    code, _, _ = _cli(tmp_path, ["update", "--passport", str(file)])
    assert code == ExitCode.OK and "finalize/finalize_tail:verify" in journal


def test_probe_DM_45_second_run_in_a_session_is_refused(tmp_path: Path) -> None:
    """One run, one journal: a plan that ran refuses a second ``run`` before
    any event and any command, and a hold of the box lock that opened its
    journal refuses a second before writing anything. The pair: the first
    run did run, the first journal is there."""
    journal = Journal()
    runner = FakeRunner()
    once, sink = plan([StackSteps("box", [ScriptedStep("a", 1, journal)], root=True)])
    once.run()
    events = list(sink.events)
    assert events and "box/a:verify" in journal  # the pair: it ran
    with runner, pytest.raises(RunRefused):
        once.run()
    assert sink.events == events and runner.calls == []
    box = Box(tmp_path)
    with box.lock("probe"):
        box.open_journal(header(run_id(1)), Secrets(())).close()
        with pytest.raises(JournalTaken):
            box.open_journal(header(run_id(2)), Secrets(()))
    assert sorted(path.name for path in (tmp_path / "journal").iterdir()) == [
        f"{run_id(1)}.jsonl"
    ]
