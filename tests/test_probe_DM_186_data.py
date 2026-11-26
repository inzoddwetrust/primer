"""Probes of DM-186, part A (REVIEW-0006 K5: S5, B16, E11, B13, B14), tier 1:
a strict ``FakeRunner`` and the real file system.

- S5: what ``compose cp`` brings out of a container is the box's only as a
  regular file -- a link (``docker cp`` brings a link out as a link, measured
  with docker 29.1.3) or a directory is removed without being followed, and
  nothing else on the box changes; in ``db dump`` and in ``db connect`` alike.
- B16: a revision of alembic is a line ``Rev: <id>`` of ``current --verbose``
  under its header; any other output is ``alembic-unread``, never a revision.
- E11: a dump read back is kept when ``alembic current`` fails after it.
- B13: an empty database dumps to no entry, and that is a dump (``toc: 0``).
- B14: ``migrate`` reads its ``check`` once a run, and with no ``/health`` the
  database's own revision is read before the point of no return.
"""

import os
from collections.abc import Callable, Iterator, Mapping, Sequence
from pathlib import Path

import pytest
from compose_support import (
    APP_IMAGE,
    CURRENT_HEADER,
    HEAD,
    LiveApp,
    alembic_call,
    current_lines,
    heads_call,
    health,
    image_call,
    live,
    observe_calls,
    show_call,
    stdout,
)
from compose_support import compose as migrate_compose
from compose_support import run as run_entry
from data_support import STACK, blank_box
from plan_support import Journal, ScriptedStep
from test_verbs_admin import _connect_calls, _freeze, _out, _Stamped
from test_verbs_data import (
    RUN_ID,
    compose,
    dump_calls,
    git_call,
    head_call,
    plan,
)

from pridem.events import Code
from pridem.interrupt import Interrupt
from pridem.report.codes import ExitCode
from pridem.runner import FakeCall, FakeRunner, OnLine, Result
from pridem.steps.base import StepContext, StepFailed
from pridem.steps.compose import ComposeStack, current
from pridem.steps.data import DbDump, _head, backups_dir, own_copy
from pridem.steps.gc import CONNECT_DIR
from pridem.steps.migrate import Migrate

Make = Callable[[Path], None]


class _BringsOut(FakeRunner):
    """The strict script; ``compose cp`` out of a container leaves ``make``'s
    entry at the box's end -- a link, a directory -- as ``docker cp`` does."""

    def __init__(self, *calls: FakeCall, make: Make) -> None:
        super().__init__(*calls)
        self.make = make

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
        found = super().run(
            argv, expect=expect, timeout=timeout, cwd=cwd, env=env, on_line=on_line
        )
        if "cp" in argv and not argv[-1].startswith("postgres:"):
            self.make(Path(argv[-1]))
        return found


class _StampedOut(_Stamped):
    """``db connect``'s script, its log brought out as ``make`` says."""

    def __init__(self, *calls: FakeCall, stamp: str, make: Make) -> None:
        super().__init__(*calls, stamp=stamp)
        self.make = make

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
        found = FakeRunner.run(
            self,
            argv,
            expect=expect,
            timeout=timeout,
            cwd=cwd,
            env=env,
            on_line=on_line,
        )
        if "cp" in argv and not argv[-1].startswith("postgres:"):
            self.make(Path(argv[-1]))
        return found


def _outside(tmp: Path) -> Path:
    """A file of the box the container must not reach: 0644, its content."""
    secret = tmp / "host-file"
    secret.write_bytes(b"of the host\n")
    secret.chmod(0o644)
    return secret


def _shapes(secret: Path) -> dict[str, Make]:
    def link_out(path: Path) -> None:
        os.symlink(secret, path)

    def link_in(path: Path) -> None:
        os.symlink("/tmp/pridem-real-in-the-container", path)  # noqa: S108

    def directory(path: Path) -> None:
        path.mkdir()
        (path / "inner").symlink_to(secret)

    return {"link-out": link_out, "link-in": link_in, "directory": directory}


@pytest.fixture
def app() -> Iterator[LiveApp]:
    yield from live()


# --- S5 ---------------------------------------------------------------------------


def test_probe_DM_186_S5_a_link_from_the_container_changes_nothing_on_the_host(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``db dump`` and ``db connect``: the file ``compose cp`` brings out is a
    link out of the container, a link into it, a directory -- refused
    (``container-file`` / the log not kept), the entry removed without being
    followed, the host's file the same bytes and the same mode 0644. The
    pair: a regular file -- the dump, 0600."""
    secret = _outside(tmp_path)
    for shape, make in _shapes(secret).items():
        root = tmp_path / shape
        box = blank_box(root)
        cs = compose(root)
        directory = backups_dir(box.root, RUN_ID)
        partial = directory / f"{STACK}.dump.partial"
        step = DbDump(cs, directory=directory, run_id=RUN_ID)
        calls = dump_calls(cs, directory)[:-1]  # refused before the table of contents
        with _BringsOut(*calls, make=make) as runner:
            outcome = plan([step], runner)
        assert outcome.steps[0].reason == Code(
            "db_dump:container-file", {"stack": STACK, "path": str(partial)}
        ), shape
        assert not os.path.lexists(partial), shape
        assert sorted(p.name for p in directory.iterdir()) == [], shape
        assert secret.read_bytes() == b"of the host\n", shape
        assert secret.stat().st_mode & 0o777 == 0o644, shape
    # db connect: the session's log the same way
    stamp = _freeze(monkeypatch)
    root = tmp_path / "connect"
    blank_box(root, name="box-1")
    cs = compose(root)
    kept = root / "opt" / "pridem" / CONNECT_DIR / f"{stamp}-{STACK}.log"
    with _StampedOut(
        *_connect_calls(cs, kept), stamp=stamp, make=_shapes(secret)["link-out"]
    ) as runner:
        code, _, err = _out(root, ["db", "connect", STACK], runner)
    assert code == 1 and "the session's log was not kept" in err, err
    assert not os.path.lexists(kept)
    assert secret.read_bytes() == b"of the host\n"
    assert secret.stat().st_mode & 0o777 == 0o644
    # the pair: a regular file is taken, 0600, its digest from the descriptor
    plain = tmp_path / "plain"
    plain.write_bytes(b"PGDMP")
    plain.chmod(0o644)
    owned = own_copy(plain)
    assert owned is not None and owned[0] == 5
    assert plain.stat().st_mode & 0o777 == 0o600


# --- B16 --------------------------------------------------------------------------


def test_probe_DM_186_B16_a_word_on_stdout_is_no_revision(tmp_path: Path) -> None:
    """One word on stdout -- the product's ``print("ok")`` -- is no revision:
    no header of alembic's -- ``alembic-unread``; the header alone -- no
    revision (an empty database); a revision's docstring, indented -- not one.
    The pair: ``Rev: <id> (head)`` -- that revision."""
    assert current(["ok"]) is None
    assert current([]) is None
    assert current([CURRENT_HEADER]) == []
    assert current([CURRENT_HEADER, "    Rev: 0001"]) == []
    assert current(list(current_lines(f"{HEAD} (head)"))) == [HEAD]
    box = blank_box(tmp_path)
    cs = compose(tmp_path)
    del box
    said = FakeCall(head_call(cs).argv, lines=stdout("ok"))
    with FakeRunner(said) as runner:
        ctx = StepContext(runner, "command", "test", "x", lambda *_: None, Interrupt())
        with pytest.raises(StepFailed) as failed:
            _head(ctx, cs)
    assert failed.value.reason == Code("alembic-unread", {"stack": STACK})


# --- E11, B13 ---------------------------------------------------------------------


@pytest.mark.parametrize("current_said", ["failed", "a word"])
def test_probe_DM_186_E11_a_dump_outlives_an_unread_revision(
    tmp_path: Path, current_said: str
) -> None:
    """The dump is read back, then ``alembic current`` fails (or says no
    revision in alembic's form): the dump and its manifest are kept -- no
    ``alembic_head`` -- and the step says ``incomplete head-unread``. The
    pair, B13: an empty database -- ``toc: 0``, a dump, green."""
    box = blank_box(tmp_path)
    cs = compose(tmp_path)
    directory = backups_dir(box.root, RUN_ID)
    step = DbDump(cs, directory=directory, run_id=RUN_ID)
    unread = (
        FakeCall(head_call(cs).argv, lines=stdout("Traceback"), code=1)
        if current_said == "failed"
        else FakeCall(head_call(cs).argv, lines=stdout("ok"))
    )
    with _BringsOut(*dump_calls(cs, directory), unread, git_call(cs), make=_dump) as r:
        outcome = plan([step], r)
    path = directory / f"{STACK}.dump"
    assert outcome.code is ExitCode.INCOMPLETE, outcome.steps
    assert [e.reason for e in outcome.incomplete] == [
        Code("db_dump:head-unread", {"stack": STACK, "path": str(path)})
    ]
    assert path.read_bytes() == b"PGDMP\x00dump"
    manifest = (directory / f"{STACK}.json").read_text()
    assert '"sha256"' in manifest and "alembic_head" not in manifest


def _dump(path: Path) -> None:
    path.write_bytes(b"PGDMP\x00dump")


def test_probe_DM_186_B13_an_empty_database_is_a_dump(tmp_path: Path) -> None:
    """``pg_restore --list`` of the dump of an empty database reads no entry
    (PostgreSQL 16, measured): named, ``toc: 0``, green -- it was
    ``dump-empty`` and a restore after a failed first migration had no
    insurance to take."""
    box = blank_box(tmp_path)
    cs = compose(tmp_path)
    directory = backups_dir(box.root, RUN_ID)
    step = DbDump(cs, directory=directory, run_id=RUN_ID)
    calls = [*dump_calls(cs, directory, toc=(";",)), head_call(cs, None), git_call(cs)]
    with _BringsOut(*calls, make=_dump) as runner:
        outcome = plan([step], runner)
    assert outcome.code is ExitCode.OK, outcome.steps
    assert outcome.steps[0].verify["toc"] == 0
    assert (directory / f"{STACK}.dump").exists()


# --- B14 --------------------------------------------------------------------------


def _migrate(root: Path, port: int) -> Migrate:
    cs = migrate_compose(root, port)
    return Migrate(
        cs.stack, cs.entry, release=cs.release, ref=cs.ref, commit=cs.commit, root=root
    )


def _ahead(cs: ComposeStack) -> FakeCall:
    """``alembic current --verbose`` of a database at 0009, a revision the
    code does not hold: exit 255 and alembic's line (alembic 1.14, measured)."""
    return FakeCall(
        alembic_call(cs, "current", deps=True).argv,
        lines=stdout(
            CURRENT_HEADER, "FAILED: Can't locate revision identified by '0009'"
        ),
        code=255,
    )


def test_probe_DM_186_B14_a_silent_health_keeps_db_ahead(
    tmp_path: Path, app: LiveApp
) -> None:
    """No app answers ``/health``; the database is at 0009, which the code does
    not hold: ``check`` of a plan that acts reads the database's own revision
    -- ``db-ahead`` before the point of no return, which the plan crosses
    when ``act`` begins: nothing migrated, no restore asked (it said
    ``restore/needed``). The pair: ``/health`` answers -- the
    revision is its, no ``alembic current`` either, and ``check`` is read
    once a run: asked again, no command."""
    cs = migrate_compose(tmp_path, app.port)
    silent = [
        image_call(cs, "app", APP_IMAGE),
        *heads_call(cs, APP_IMAGE, f"{HEAD} (head)"),
        *observe_calls(cs, running=False),
    ]
    after = ScriptedStep("up", 13, Journal(), fact={})
    migrate = _migrate(tmp_path, app.port)
    with FakeRunner(*silent, _ahead(cs)) as runner:
        outcome, _ = run_entry([migrate, after], runner)
    assert outcome.steps[0].reason == Code(
        "migrate:db-ahead", {"entry": "blank", "head": "0009"}
    )
    assert not outcome.needs_restore and not migrate.acted
    # the pair: /health answers 0000 -- its revision, no alembic current
    app.health = health(alembic_head="0000")
    answering = [
        image_call(cs, "app", APP_IMAGE),
        *heads_call(cs, APP_IMAGE, f"{HEAD} (head)"),
        *observe_calls(cs),
        image_call(cs, "app", APP_IMAGE),
        *show_call(cs, APP_IMAGE, "0000", known=True),
    ]
    migrate = _migrate(tmp_path, app.port)
    with FakeRunner(*answering) as runner:
        ctx = StepContext(runner, "deploy", "test", "x", lambda *_: None, Interrupt())
        first = migrate.check(ctx)
        assert migrate.check(ctx) is first  # one check a run: no command again
    assert first.needed


def test_a_file_put_in_place_between_the_look_and_the_change_is_not_followed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """S5, the input of the handoff "replaced between ``fstat`` and
    ``fchmod``": right after ``fstat`` the entry becomes a link to the host's
    file -- the change goes to the descriptor opened before, the host's file
    keeps its mode."""
    secret = _outside(tmp_path)
    taken = tmp_path / "taken.dump"
    taken.write_bytes(b"PGDMP")
    real_fstat = os.fstat

    def swapping(fd: int) -> os.stat_result:
        found = real_fstat(fd)
        taken.unlink()
        taken.symlink_to(secret)  # in place of the file, after the look
        return found

    monkeypatch.setattr(os, "fstat", swapping)  # the module's os is this one
    owned = own_copy(taken)
    monkeypatch.undo()
    assert owned is not None and owned[0] == 5
    assert secret.stat().st_mode & 0o777 == 0o644
    assert secret.read_bytes() == b"of the host\n"


def test_doctor_brings_no_database_up(tmp_path: Path, app: LiveApp) -> None:
    """The condition of the gate's answer: ``doctor`` never brings the
    database up -- with ``/health`` silent, its ``check`` reads no ``alembic
    current`` (no ``run --rm``, which would start the database by
    ``depends_on``): the strict script has none, and ``doctor`` says what a
    deploy would do."""
    cs = migrate_compose(tmp_path, app.port)
    silent = [
        image_call(cs, "app", APP_IMAGE),
        *heads_call(cs, APP_IMAGE, f"{HEAD} (head)"),
        *observe_calls(cs, running=False),
    ]
    with FakeRunner(*silent) as runner:
        doctor, _ = run_entry([_migrate(tmp_path, app.port)], runner, mode="doctor")
    assert [d.reason.code for d in doctor.doctor_diff] == ["migrate:migrate"]
