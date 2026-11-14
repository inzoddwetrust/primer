"""DM-94: the dump before ``db restore``, ``db_restore`` and ``backup`` on the
edges -- each row of REVIEW-0002/0003 a test red on ``ca20615``.

R2-S7/R3-S7: the live database is dumped first, in a stack before the
entry's; a red dump stops everything before anything is stopped. R2-E13:
``db_restore`` reads that the database runs. R2-E14: ``backup`` refuses a
stack or a compose it cannot read. R2-E15: a dump or a restore that fails
leaves no file in the container and no ``.partial`` on the box; a clean-up
that fails is a line of the journal and never the step's cause.
"""

from collections.abc import Mapping, Sequence
from dataclasses import replace
from pathlib import Path

import pytest
from data_support import STACK, blank_box
from plan_support import ListSink
from test_verbs_data import (
    INSURANCE_RUN,
    RUN_ID,
    Copying,
    _a_dump,
    _cli,
    _verdict,
    compose,
    config_call,
    dump_calls,
    inside,
    insured,  # noqa: F401 -- the fixture
    plan,
    running_call,
)

from pridem.events import Code
from pridem.plan import Plan, StackSteps
from pridem.runner import CommandFailed, FakeCall, OnLine, Result
from pridem.steps.data import DbDump, DbRestore, backups_dir, read_manifest


def _insurance_dir(fs_root: Path) -> Path:
    return backups_dir(fs_root / "opt" / "pridem", INSURANCE_RUN)


# --- R2-S7 / R3-S7: the dump before the restore ----------------------------------


@pytest.mark.usefixtures("insured")
def test_a_red_insurance_dump_stops_everything_before_anything_stops(
    tmp_path: Path,
) -> None:
    """``pg_dump`` of the live database fails: ``db_dump`` red, and nothing
    of the entry's stack runs -- no ``stop``, no ``pg_restore`` (the strict
    script holds neither), nothing to start again."""
    blank_box(tmp_path, name="box-1")
    path = _a_dump(tmp_path)
    cs = compose(tmp_path)
    red = dump_calls(cs, _insurance_dir(tmp_path), code=1, run_id=INSURANCE_RUN)
    with Copying(*red) as runner:
        code, out, _ = _cli(
            tmp_path, ["db", "restore", STACK, str(path), "--confirm", "box-1"], runner
        )
    verdict = _verdict(out)
    assert code == 1
    assert [(s.stack, s.name, s.status) for s in verdict.steps[:4]] == [
        ("backup", "db_dump", "failed"),
        (STACK, "stop_for_restore", "skipped"),
        (STACK, "db_restore", "skipped"),
        (STACK, "start_restored", "skipped"),
    ]
    assert verdict.steps[4].verify == {"started": {}}
    assert not verdict.report.incomplete


def test_the_way_back_is_said_before_pg_restore(tmp_path: Path) -> None:
    """``db_restore`` names the insurance dump in the console before the first
    command of the restore, and in its fact."""
    blank_box(tmp_path, name="box-1")
    path = _a_dump(tmp_path)
    manifest = read_manifest(path.with_suffix(".json"))
    assert manifest is not None
    cs = compose(tmp_path)
    back = tmp_path / "back.dump"
    step = DbRestore(cs, path=path, manifest=manifest, insurance=back)
    seen: list[str] = []

    class Watching(Copying):
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
            seen.append("command: " + " ".join(argv))
            return super().run(
                argv, expect=expect, timeout=timeout, cwd=cwd, env=env, on_line=on_line
            )

    from env_support import context

    restore_inside = f"/tmp/pridem-restore-{STACK}.dump"  # noqa: S108
    calls = [
        config_call(cs),
        running_call(cs, "postgres", "c-pg"),
        FakeCall(tuple(cs.argv("cp", operands=(
            str(path), f"postgres:{restore_inside}")))),
        FakeCall(tuple(cs.argv("exec", "-T", operands=(
            "postgres", "pg_restore", "--clean", "--if-exists", "--no-owner",
            "--single-transaction", "--exit-on-error", "-U", "blank", "-d", "blank",
            restore_inside,
        )))),
        FakeCall(tuple(cs.argv("exec", "-T", operands=(
            "postgres", "rm", "-f", restore_inside)))),
    ]  # fmt: skip
    with Watching(*calls) as runner:
        ctx = replace(
            context(runner), on_line=lambda stream, line, cut: seen.append(line)
        )
        check = step.check(ctx)
        step.act(ctx, check)
    said = f"pridem: the database before the restore: {back}"
    assert said in seen
    assert seen.index(said) < min(
        i
        for i, line in enumerate(seen)
        if line.startswith("command:") and " cp " in line
    )


# --- R2-E13: the database runs ----------------------------------------------------


@pytest.mark.usefixtures("insured")
def test_a_database_that_does_not_run_is_refused_before_anything_stops(
    tmp_path: Path,
) -> None:
    """``db restore`` on a database that does not run: refused by the first
    step, ``db_dump``, before anything is stopped. ``db_restore`` reads it
    too, on its own step."""
    blank_box(tmp_path, name="box-1")
    path = _a_dump(tmp_path)
    cs = compose(tmp_path)
    with Copying(config_call(cs), running_call(cs, "postgres")) as runner:
        code, out, _ = _cli(
            tmp_path, ["db", "restore", STACK, str(path), "--confirm", "box-1"], runner
        )
    verdict = _verdict(out)
    assert verdict.steps[0].reason is not None
    assert verdict.steps[0].reason.model_dump() == {
        "code": "db_dump:database-down",
        "stack": STACK,
        "service": "postgres",
    }
    assert [s.status for s in verdict.steps[1:4]] == ["skipped"] * 3
    manifest = read_manifest(path.with_suffix(".json"))
    assert manifest is not None
    step = DbRestore(cs, path=path, manifest=manifest)
    with Copying(config_call(cs), running_call(cs, "postgres")) as runner:
        outcome = plan([step], runner)
    assert outcome.steps[0].reason == Code(
        "db_restore:database-down", {"stack": STACK, "service": "postgres"}
    )


# --- R2-E14: backup sees every stack ----------------------------------------------


def test_backup_refuses_a_stack_it_cannot_read(tmp_path: Path) -> None:
    """A ``primer.yaml`` of ``current`` that cannot be read: refused, not a
    green ``dumped: []``. A compose that cannot be read: refused, not ``no
    database``. Nothing runs (the empty script)."""
    blank_box(tmp_path)
    release = (tmp_path / "opt" / STACK / "current").resolve()
    (release / "primer.yaml").write_text("schema: [\n")
    with Copying() as runner:
        code, out, err = _cli(tmp_path, ["backup"], runner)
    assert code == 1 and f"primer.yaml of {STACK} cannot be read" in err, err
    other = tmp_path / "other"
    other.mkdir()
    blank_box(other)
    release = (other / "opt" / STACK / "current").resolve()
    (release / "docker-compose.yml").write_text("services: [\n")
    with Copying() as runner:
        code, out, err = _cli(other, ["backup"], runner)
    assert code == 1 and f"the compose of {STACK} cannot be read" in err, err


# --- R2-E15: a dump that fails leaves nothing -------------------------------------


class Failing(Copying):
    """The strict script, a command of which fails (exit 1) by its words."""

    def __init__(self, *calls: FakeCall, fails: str) -> None:
        super().__init__(*calls)
        self.fails = fails

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
        if self.fails in argv:
            if 1 in expect:
                return Result(tuple(argv), 1)
            raise CommandFailed(tuple(argv), 1, expect, ())
        return super().run(
            argv, expect=expect, timeout=timeout, cwd=cwd, env=env, on_line=on_line
        )


@pytest.mark.parametrize("fails", ["pg_dump", "cp"])
def test_a_dump_that_fails_leaves_no_file_anywhere(tmp_path: Path, fails: str) -> None:
    """``pg_dump`` or ``cp`` fails: ``rm -f`` of the file in the container ran
    (the strict script holds it last), and no ``.partial`` on the box."""
    box = blank_box(tmp_path)
    cs = compose(tmp_path)
    directory = backups_dir(box.root, RUN_ID)
    step = DbDump(cs, directory=directory, run_id=RUN_ID)
    rm = FakeCall(tuple(cs.argv("exec", "-T", operands=("postgres", "rm", "-f",
                                                        inside()))))  # fmt: skip
    calls = [config_call(cs), running_call(cs, "postgres", "c-pg")]
    if fails == "cp":
        calls.append(
            FakeCall(
                tuple(
                    cs.argv(
                        "exec",
                        "-T",
                        operands=(
                            "postgres",
                            "pg_dump",
                            "-U",
                            "blank",
                            "-Fc",
                            "-f",
                            inside(),
                            "blank",
                        ),
                    )
                )
            )  # fmt: skip
        )
    with Failing(*calls, rm, fails=fails) as runner:
        outcome = plan([step], runner)
    assert outcome.steps[0].reason is not None
    assert outcome.steps[0].reason.code == "command-failed"
    assert not (directory / f"{STACK}.dump.partial").exists()
    assert not (directory / f"{STACK}.dump").exists()


def test_an_empty_dump_leaves_no_partial(tmp_path: Path) -> None:
    box = blank_box(tmp_path)
    cs = compose(tmp_path)
    directory = backups_dir(box.root, RUN_ID)
    step = DbDump(cs, directory=directory, run_id=RUN_ID)
    with Copying(*dump_calls(cs, directory, toc=(";", "; nothing"))) as runner:
        outcome = plan([step], runner)
    assert outcome.steps[0].reason is not None
    assert outcome.steps[0].reason.code == "db_dump:dump-empty"
    assert not (directory / f"{STACK}.dump.partial").exists()


def test_a_restore_that_fails_leaves_no_file_in_the_container(tmp_path: Path) -> None:
    blank_box(tmp_path, name="box-1")
    path = _a_dump(tmp_path)
    manifest = read_manifest(path.with_suffix(".json"))
    assert manifest is not None
    cs = compose(tmp_path)
    step = DbRestore(cs, path=path, manifest=manifest)
    restore_inside = f"/tmp/pridem-restore-{STACK}.dump"  # noqa: S108
    rm = FakeCall(tuple(cs.argv("exec", "-T", operands=(
        "postgres", "rm", "-f", restore_inside))))  # fmt: skip
    calls = [
        config_call(cs),
        running_call(cs, "postgres", "c-pg"),
        FakeCall(
            tuple(cs.argv("cp", operands=(str(path), f"postgres:{restore_inside}")))
        ),
        rm,
    ]
    with Failing(*calls, fails="pg_restore") as runner:
        outcome = plan([step], runner)
    assert outcome.steps[0].reason is not None
    assert outcome.steps[0].reason.code == "command-failed"


class BothFail(Copying):
    """``pg_dump`` fails, and so does ``rm`` in the container after it."""

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
        if "-Fc" in argv or "rm" in argv:
            if 1 in expect:
                return Result(tuple(argv), 1)
            raise CommandFailed(tuple(argv), 1, expect, ())
        return super().run(
            argv, expect=expect, timeout=timeout, cwd=cwd, env=env, on_line=on_line
        )


def test_a_clean_up_that_fails_is_said_and_hides_nothing(tmp_path: Path) -> None:
    """``pg_dump`` fails, then ``rm`` in the container fails too: the step is
    red by ``pg_dump`` -- its own cause -- and the journal has the file left,
    with its path and why."""
    box = blank_box(tmp_path)
    cs = compose(tmp_path)
    directory = backups_dir(box.root, RUN_ID)
    step = DbDump(cs, directory=directory, run_id=RUN_ID)
    sink = ListSink()
    with BothFail(config_call(cs), running_call(cs, "postgres", "c-pg")) as runner:
        outcome = Plan(
            [StackSteps(STACK, [step], root=True)],
            mode="command",
            role="test",
            runner=runner,
            sink=sink,
        ).run()
    reason = outcome.steps[0].reason
    assert reason is not None and reason.code == "command-failed"
    assert "pg_dump" in str(reason.params["argv"]), reason
    said = f"pridem: {inside()} left in postgres: rm exited 1"
    assert said in [line.line for line in sink.lines()], sink.lines()
