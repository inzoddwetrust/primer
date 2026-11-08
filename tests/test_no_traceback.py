"""DM-77: no input, file or child command takes a plan or the CLI down with a
traceback -- the plan reaches ``finally`` and its verdict, the CLI answers by a
code with no value."""

import io
import json
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

import pytest
from compose_support import stdout
from plan_support import Journal, ScriptedStep, plan

from pridem import cli
from pridem.events import ShortSecret, cut_ctx
from pridem.plan import Deferred, Stack, StackSteps
from pridem.report.catalog import ENGLISH, text
from pridem.report.codes import ExitCode
from pridem.report.schema import RUN_ID
from pridem.stacks.stack import CompositionCollision
from pridem.state import (
    Box,
    HistoryExists,
    JournalDamaged,
    JournalTaken,
    RunIdTaken,
    StateDamaged,
    VerdictDamaged,
)
from pridem.steps.base import StepFailed
from pridem.verbs import VERBS
from pridem.verbs.check import MANIFEST_LIMIT, _manifest

NOW = datetime(2026, 11, 8, 12, 0, 0, tzinfo=UTC)


# --- the plan ---------------------------------------------------------------------


def _ladder(
    journal: Journal, build: object
) -> tuple[list[Stack], list[StackSteps], list[StackSteps]]:
    stacks: list[Stack] = [
        StackSteps("host", [ScriptedStep("migrate", 1, journal)]),
        Deferred("product", build, after="fetch_root", root=True),  # type: ignore[arg-type]
    ]
    restore = [StackSteps("restore", [ScriptedStep("back", 1, journal)])]
    finally_ = [StackSteps("finally", [ScriptedStep("tidy", 1, journal)])]
    return stacks, restore, finally_


def test_probe_DM_77_a_ladder_that_cannot_be_built_still_ends_the_plan() -> None:
    """``Deferred.build`` raises: the stack is one red step ``ladder`` --
    ``exception {type}``, only the class -- the plan brings the old back (it
    has not reached a point of no return), runs ``finally`` and gives its
    verdict. The pair: a ladder that
    builds runs as it does."""
    journal = Journal()

    def broken() -> None:
        raise OSError(5, "Input/output error", "/opt/x/primer.yaml")

    stacks, restore, finally_ = _ladder(journal, broken)
    made, _ = plan(stacks, "deploy", restore=restore, finally_=finally_)
    outcome = made.run()
    assert outcome.code is ExitCode.FAILED
    [ladder] = [s for s in outcome.steps if s.name == "ladder"]
    assert ladder.status == "failed" and ladder.reason is not None
    assert (ladder.reason.code, ladder.reason.params) == (
        "exception",
        {"type": "OSError"},
    )
    # before the point of no return: the old is brought back, then finally
    assert "restore/back:act" in journal and "finally/tidy:act" in journal, journal
    # the pair
    journal = Journal()
    good = [StackSteps("product", [ScriptedStep("up", 1, journal)])]
    stacks, restore, finally_ = _ladder(journal, lambda: good)
    made, _ = plan(stacks, "deploy", restore=restore, finally_=finally_)
    assert made.run().code is ExitCode.OK


# --- the CLI ----------------------------------------------------------------------


@pytest.mark.parametrize(
    ("error", "says"),
    [
        (
            OSError(28, "No space left on device", "/opt/pridem/x"),
            "os-error: ENOSPC /opt/pridem/x",
        ),
        (PermissionError(13, "denied"), "os-error: EACCES"),
        (StateDamaged("input_value='hunter2-secret-0000'"), "state-damaged:"),
        (VerdictDamaged("input_value='hunter2-secret-0000'"), "verdict-damaged:"),
        (JournalDamaged("input_value='hunter2-secret-0000'"), "journal-damaged:"),
        (CompositionCollision("hunter2-secret-0000"), "composition-collision:"),
        (ShortSecret("hunter2-secret-0000"), "short-secret:"),
        (RunIdTaken("x"), "run-id-taken:"),
        (HistoryExists("x"), "run-id-taken:"),
        (JournalTaken("x"), "run-id-taken:"),
    ],
    ids=lambda v: type(v).__name__ if isinstance(v, BaseException) else "",
)
def test_a_machine_error_is_a_code_not_a_traceback(
    error: Exception, says: str, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Each error of the table: exit 1, ``pridem: <code>: …`` and no value."""

    def raises(args: object, ctx: object) -> int:
        raise error

    monkeypatch.setitem(VERBS, "status", replace(VERBS["status"], run=raises))
    err = io.StringIO()
    assert cli.run(["status"], root=tmp_path, err=err, out=io.StringIO()) == 1
    written = err.getvalue()
    assert written.startswith(f"pridem: {says}"), written
    assert "hunter2" not in written


def test_an_error_of_no_table_keeps_its_traceback(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A defect of the machine is seen: not caught."""

    def raises(args: object, ctx: object) -> int:
        raise KeyError("a defect")

    monkeypatch.setitem(VERBS, "status", replace(VERBS["status"], run=raises))
    with pytest.raises(KeyError):
        cli.run(["status"], root=tmp_path, err=io.StringIO(), out=io.StringIO())


# --- a log line, the report, the run id ------------------------------------------


def test_a_line_with_a_huge_integer_passes_as_it_is() -> None:
    line = '{"ctx": ' + "9" * 5000 + "}"
    assert cut_ctx(line) == line


def test_a_code_with_no_words_is_said_as_it_is() -> None:
    """An old verdict's code of a removed step: no ``KeyError``."""
    said = text(ENGLISH, "remote_check:not-reachable", {"service": "meet"})
    assert "remote_check:not-reachable" in said and "service=meet" in said


def test_a_run_id_is_ascii_digits() -> None:
    assert RUN_ID.fullmatch("2026-11-08T12:00:00Z-a3f9")
    assert not RUN_ID.fullmatch("٢٠٢٦-11-08T12:00:00Z-a3f9")


def test_a_run_id_taken_in_history_is_drawn_again(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A verdict of history/ under the first token -- a journal cut long ago --
    and the next draw is free: the run takes that one."""
    box = Box(tmp_path)
    box.history.mkdir(parents=True)
    tokens = iter(["a3f9", "a3f9", "b001"])
    monkeypatch.setattr("pridem.state.token.token_hex", lambda n: next(tokens))
    (box.history / "2026-11-08T12:00:00Z-a3f9.json").write_text("{}")
    assert box.new_run_id(NOW) == "2026-11-08T12:00:00Z-b001"
    monkeypatch.setattr("pridem.state.token.token_hex", lambda n: "a3f9")
    with pytest.raises(RunIdTaken):
        box.new_run_id(NOW)


# --- pridem check: the manifest ---------------------------------------------------


def test_a_manifest_that_is_no_file_or_too_big_is_a_code(tmp_path: Path) -> None:
    (tmp_path / "dir").mkdir()
    with pytest.raises(StepFailed) as refused:
        _manifest("skin", tmp_path / "dir")
    assert refused.value.reason.params == {"slot": "skin", "cause": "not-a-file"}
    big = tmp_path / "big"
    big.write_bytes(b"a" * (MANIFEST_LIMIT + 1))
    with pytest.raises(StepFailed) as refused:
        _manifest("skin", big)
    assert refused.value.reason.params == {"slot": "skin", "cause": "too-big"}
    exact = tmp_path / "exact"
    exact.write_bytes(b"a" * MANIFEST_LIMIT)
    assert _manifest("skin", exact) == "a" * MANIFEST_LIMIT
    assert _manifest("skin", tmp_path / "none") is None
    assert json.dumps(refused.value.reason.params)


@pytest.mark.parametrize(
    ("outcome", "lines", "cause"),
    [
        ("timeout", (), "timed-out"),
        ("not_started", (), "not-started"),
        ("exit", ("not json",), "not-json"),
    ],
)
def test_a_compose_config_with_no_answer_is_a_code(
    tmp_path: Path,
    outcome: Literal["exit", "timeout", "not_started"],
    lines: tuple[str, ...],
    cause: str,
) -> None:
    """``pridem check``: ``docker compose config`` times out, does not start or
    prints no JSON -- ``compose:config-unread``, not a traceback."""
    from test_probe_DM_57_check import _reason, check, config_call, repo, version_call

    root = repo(tmp_path)
    good = config_call(root, {}, raw=True)
    broken = replace(good, outcome=outcome, code=0, lines=stdout(*lines))
    code, verdict, _ = check(root, [version_call(), broken])
    assert code == 1
    assert _reason(verdict, "blank/compose") == {
        "code": "compose:config-unread",
        "stack": "blank",
        "cause": cause,
    }


@pytest.mark.parametrize(
    "command", ["", "   ", "python -c 'x"], ids=["empty", "blank", "quote"]
)
def test_a_command_shlex_cannot_split_is_refused_by_the_loader(
    tmp_path: Path, command: str
) -> None:
    from contract_support import yaml_problems
    from env_support import product_data

    data = product_data({})
    data["stacks"]["aivis"]["migrate"] = command  # type: ignore[index]
    found = yaml_problems(tmp_path, data)
    assert found == [("stacks.aivis.migrate", "S.command")] or found == [
        ("stacks.aivis.migrate", "string_too_short")
    ], found
    if command:
        assert found == [("stacks.aivis.migrate", "S.command")]


def test_a_key_certbot_wrote_not_in_ascii_is_key_damaged(tmp_path: Path) -> None:
    from pridem.events import Secrets
    from pridem.steps.edge import letsencrypt_dir
    from pridem.steps.ssl import CERT_NAME, _copy_issued

    live = letsencrypt_dir(tmp_path) / "live" / CERT_NAME
    live.mkdir(parents=True)
    (live / "privkey.pem").write_bytes(b"-----BEGIN \xff KEY-----\n")
    (live / "fullchain.pem").write_bytes(b"cert\n")
    with pytest.raises(StepFailed) as refused:
        _copy_issued(tmp_path, Secrets(()))
    assert refused.value.reason.code == "key-damaged"
    assert refused.value.reason.params == {"path": str(live / "privkey.pem")}


def test_a_measurement_of_gc_that_cannot_read_is_not_started(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``OSError`` and ``IndexError`` of the measurement: nothing removed, the
    cause named -- not a traceback, not ``exception``."""
    from pridem.steps.gc import Gc
    from pridem.steps.passport import Fetched

    step = Gc(
        box=Box(tmp_path / "pridem"), run_id="r", fetched=Fetched(), root=tmp_path
    )
    for error in (OSError(2, "gone"), IndexError("no line")):

        def raises(ctx: object, error: Exception = error) -> object:
            raise error

        monkeypatch.setattr(step, "_check", raises)
        found = step.check(None)  # type: ignore[arg-type]
        assert found.data == {
            "not_started": "unreadable",
            "command": type(error).__name__,
        }


def test_a_journal_says_when_the_clock_went_back() -> None:
    from pridem.verbs.run import finished_at

    said: list[object] = []

    class Sink:
        def emit(self, event: object) -> None:
            said.append(event)

    ahead = datetime(2099, 1, 1, tzinfo=UTC)
    assert finished_at(ahead, Sink()) == ahead  # type: ignore[arg-type]
    [line] = said
    assert "clock-back" in line.line  # type: ignore[attr-defined]
    said.clear()
    past = datetime(2000, 1, 1, tzinfo=UTC)
    assert finished_at(past, Sink()) >= past  # type: ignore[arg-type]
    assert said == []


def test_derive_env_with_every_key_of_an_option_off_has_nothing_to_do(
    tmp_path: Path,
) -> None:
    """``keys[0]`` of an empty list was an ``IndexError``: every ``derived`` of
    the stack under an option off -- nothing to derive, even with the image
    not built."""
    from env_support import box, derive, passport_data, render
    from test_options import _stack

    made = _stack(tmp_path)
    root, fetched = box(tmp_path, passport_data(params={"aivis": {"PLAIN": "p"}}))
    step = derive(render(made, root, fetched), root, built=False)
    assert step.render._derivable() == []
    assert step.check(None).needed is False  # type: ignore[arg-type]


def test_a_preview_secret_not_in_ascii_is_secret_damaged(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``UnicodeDecodeError`` of the file was ``exception``: now the step's own
    ``secret-damaged`` with the path. The pair: a minted secret is read."""
    from env_support import product

    from pridem.events import Secrets
    from pridem.steps.nginx import PREVIEW_SECRET, Nginx
    from pridem.steps.passport import Fetched

    step = Nginx(
        product(tmp_path, {}), fetched=Fetched(), secrets=Secrets(()), root=tmp_path
    )
    monkeypatch.setattr(step, "_preview", lambda: True)
    path = tmp_path / PREVIEW_SECRET
    path.parent.mkdir(parents=True)
    path.write_bytes(b"\xff" * 32)
    path.chmod(0o600)
    with pytest.raises(StepFailed) as refused:
        step._secret(mint_if_absent=False)
    assert refused.value.reason.code == "secret-damaged"
    assert refused.value.reason.params == {"path": str(path)}
    path.unlink()
    minted = step._secret(mint_if_absent=True)
    assert minted is not None and step._secret(mint_if_absent=False) == minted
