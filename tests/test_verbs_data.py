"""The data verbs, pass 1 of DM-86: ``db dump``, ``db restore``, ``backup``;
and the first item -- a job among several ``depends_on``."""

import io
import json
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from itertools import count
from pathlib import Path

import pytest
from data_support import SHA, STACK, blank_box
from plan_support import ListSink

from pridem.cli import run as cli
from pridem.events import Code, Json, PlanOutcome
from pridem.plan import Plan, StackSteps
from pridem.report.codes import ExitCode
from pridem.report.schema import Verdict
from pridem.runner import FakeCall, FakeRunner, OnLine, Result, Stream
from pridem.stacks.schema import load_primer_yaml
from pridem.state import Box
from pridem.steps.base import Step
from pridem.steps.compose import ComposeStack, forbidden
from pridem.steps.data import BackupScope, DbDump, backups_dir, sha256_of
from pridem.verbs.data import box_entries, has_database_url

RUN_ID = "2026-11-10T21:00:00Z-ab12"
IMAGE = "postgres:16-alpine@sha256:" + "f" * 64
HEAD = "0001"
CONFIG: dict[str, Json] = {
    "name": STACK,
    "services": {
        "app": {
            "environment": {
                "DATABASE_URL": "postgresql+asyncpg://blank:pw@postgres:5432/blank"
            },
            "depends_on": {"postgres": {"condition": "service_healthy"}},
        },
        "frontend": {"environment": {"API_BASE_URL": "x"}},
        "postgres": {"image": IMAGE},
    },
}
TOC = (
    ";",
    "; Archive created at 2026-11-10",
    "215; 1259 16386 TABLE public app_settings blank",
    "3330; 0 16386 TABLE DATA public app_settings blank",
)


def lines(*items: str) -> tuple[tuple[Stream, str], ...]:
    return tuple((Stream.STDOUT, item) for item in items)


def compose(fs_root: Path) -> ComposeStack:
    release = (fs_root / "opt" / STACK / "current").resolve()
    made = load_primer_yaml(release / "primer.yaml")
    return ComposeStack(made, STACK, release, release.name, release.name, fs_root)


class Copying(FakeRunner):
    """A strict script that also does what ``compose cp`` does: writes the
    dump on the box (``content``), or reads nothing back into a container."""

    def __init__(self, *calls: FakeCall, content: bytes = b"PGDMP\x00dump") -> None:
        super().__init__(*calls)
        self.content = content

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
            Path(argv[-1]).write_bytes(self.content)
        return found


def config_call(cs: ComposeStack, document: Mapping[str, Json] = CONFIG) -> FakeCall:
    return FakeCall(
        tuple(cs.product_argv("config", "--format", "json")),
        lines=lines(json.dumps(document)),
    )


def running_call(cs: ComposeStack, service: str, *ids: str) -> FakeCall:
    argv = cs.argv("ps", "--status", "running", "-q", operands=(service,))
    return FakeCall(tuple(argv), lines=lines(*ids))


def inside(entry: str = STACK, run_id: str = RUN_ID) -> str:
    return f"/tmp/pridem-{run_id}-{entry}.dump"  # noqa: S108 -- in the container


def dump_calls(
    cs: ComposeStack,
    directory: Path,
    *,
    toc: Sequence[str] = TOC,
    code: int = 0,
    run_id: str = RUN_ID,
) -> list[FakeCall]:
    partial = directory / f"{STACK}.dump.partial"
    calls = [
        config_call(cs),
        running_call(cs, "postgres", "c-pg"),
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
                        inside(STACK, run_id),
                        "blank",
                    ),
                )
            ),  # fmt: skip
            code=code,
        ),
    ]
    rm = FakeCall(
        tuple(
            cs.argv(
                "exec", "-T", operands=("postgres", "rm", "-f", inside(STACK, run_id))
            )
        )
    )
    if code:  # DM-94: the file in the container goes, the dump red or green
        return [*calls, rm]
    return [
        *calls,
        FakeCall(
            tuple(
                cs.argv(
                    "cp",
                    operands=(
                        f"postgres:{inside(STACK, run_id)}",
                        str(partial),
                    ),
                )
            )
        ),
        FakeCall(
            tuple(
                cs.argv(
                    "exec",
                    "-T",
                    operands=(
                        "postgres",
                        "rm",
                        "-f",
                        inside(STACK, run_id),
                    ),
                )
            )
        ),
        FakeCall(
            (
                "docker",
                "run",
                "--rm",
                "--network",
                "none",
                "--cap-drop",
                "ALL",
                "--pull",
                "never",
                "--mount",
                f"type=bind,source={partial},target=/primer/db.dump,readonly",
                "--",
                IMAGE,
                "pg_restore",
                "--list",
                "/primer/db.dump",
            ),  # fmt: skip
            lines=lines(*toc),
        ),
    ]


def git_call(cs: ComposeStack, commit: str = SHA) -> FakeCall:
    """The commit of the current release: its worktree's ``HEAD`` (DM-86,
    pass 2: a service's release is named by its tag)."""
    argv = ("git", "-C", str(cs.release), "rev-parse", "HEAD")
    return FakeCall(argv, lines=lines(commit))


def head_call(cs: ComposeStack, head: str = HEAD) -> FakeCall:
    argv = cs.argv(
        "run",
        "--rm",
        operands=(
            "app",
            "python",
            "-m",
            "alembic",
            "current",
        ),
    )
    return FakeCall(tuple(argv), lines=lines(f"{head} (head)"))


def plan(
    steps: list[Step], runner: FakeRunner, final: Sequence[Step] = ()
) -> PlanOutcome:
    ticks = count()
    return Plan(
        [StackSteps(STACK, steps, root=True)],
        mode="command",
        role="test",
        runner=runner,
        sink=ListSink(),
        clock=lambda: float(next(ticks)),
        now=lambda: datetime(2026, 11, 10, tzinfo=UTC),
        finally_=[StackSteps("stopped", list(final))] if final else (),
    ).run()


def dumped(tmp_path: Path) -> tuple[ComposeStack, Path, DbDump]:
    """A green ``db_dump`` on the box of ``tmp_path``."""
    box = blank_box(tmp_path)
    cs = compose(tmp_path)
    directory = backups_dir(box.root, RUN_ID)
    step = DbDump(cs, directory=directory, run_id=RUN_ID)
    commit = "c" * 40  # the worktree's HEAD, not the release directory's name
    with Copying(*dump_calls(cs, directory), head_call(cs), git_call(cs, commit)) as r:
        outcome = plan([step], r)
    assert outcome.code is ExitCode.OK, outcome.steps
    return cs, directory, step


# --- the first item -------------------------------------------------------------------


def test_a_job_among_several_dependencies_is_named_not_only_the_first(
    tmp_path: Path,
) -> None:
    """DM-86, first item (acceptance of DM-22): ``app`` on ``postgres`` and
    ``init``, the job not first -- found. The pair: ``app`` on ``postgres``
    alone."""
    from compose_support import HEALTHCHECK
    from test_probe_DM_22_forms import _released, jobbed

    healthy: dict[str, Json] = {"image": "a@sha256:x", "healthcheck": HEALTHCHECK}
    on_both: dict[str, Json] = {
        **healthy,
        "depends_on": {"postgres": {}, "init": {}},
    }
    job: dict[str, Json] = {"image": "j@sha256:x"}
    cs = _released(tmp_path, jobbed())
    document: dict[str, Json] = {
        "services": {"app": on_both, "postgres": healthy, "init": job}
    }
    needs = on_both["depends_on"]
    assert isinstance(needs, dict) and list(needs)[0] == "postgres"  # job not first
    assert forbidden(cs, document) == ["app: depends on job init"]
    alone: dict[str, Json] = {**healthy, "depends_on": {"postgres": {}}}
    assert (
        forbidden(cs, {"services": {"app": alone, "postgres": healthy, "init": job}})
        == []
    )


# --- db dump -------------------------------------------------------------------------


def test_db_dump_writes_the_dump_and_its_manifest_under_the_box(tmp_path: Path) -> None:
    """The dump under ``/opt/pridem/backups/<run_id>/`` (0600, the directories
    0700) -- not under ``/opt/<stack>``, which ``destroy`` removes; the
    manifest beside it; nothing partial left; the fact read back."""
    cs, directory, step = dumped(tmp_path)
    box_root = tmp_path / "opt" / "pridem"
    assert directory == box_root / "backups" / RUN_ID
    path = directory / f"{STACK}.dump"
    assert path.read_bytes() == b"PGDMP\x00dump"
    assert path.stat().st_mode & 0o777 == 0o600
    assert directory.stat().st_mode & 0o777 == 0o700
    assert (box_root / "backups").stat().st_mode & 0o777 == 0o700
    assert not (directory / f"{STACK}.dump.partial").exists()
    manifest = json.loads((directory / f"{STACK}.json").read_text())
    assert manifest == {
        "stack": STACK,
        "entry": STACK,
        "release": SHA,
        "commit": "c" * 40,
        "bytes": len(b"PGDMP\x00dump"),
        "sha256": sha256_of(path),
        "toc": 2,
        "alembic_head": HEAD,
    }
    assert not (tmp_path / "opt" / STACK / "backups").exists()


def test_an_empty_table_of_contents_is_red_and_no_dump_is_named(tmp_path: Path) -> None:
    """Twin LACK: ``pg_restore --list`` reads no entry -- ``dump-empty``; no
    ``<entry>.dump`` and no manifest: a dump without its manifest is none."""
    box = blank_box(tmp_path)
    cs = compose(tmp_path)
    directory = backups_dir(box.root, RUN_ID)
    step = DbDump(cs, directory=directory, run_id=RUN_ID)
    with Copying(*dump_calls(cs, directory, toc=(";", "; nothing"))) as runner:
        outcome = plan([step], runner)
    assert outcome.steps[0].reason == Code("db_dump:dump-empty", {"stack": STACK})
    assert not (directory / f"{STACK}.dump").exists()
    assert not (directory / f"{STACK}.json").exists()


def test_a_red_pg_dump_leaves_no_dump(tmp_path: Path) -> None:
    box = blank_box(tmp_path)
    cs = compose(tmp_path)
    directory = backups_dir(box.root, RUN_ID)
    step = DbDump(cs, directory=directory, run_id=RUN_ID)
    with Copying(*dump_calls(cs, directory, code=1)) as runner:
        outcome = plan([step], runner)
    assert outcome.steps[0].reason is not None
    assert outcome.steps[0].reason.code == "command-failed"
    assert not (directory / f"{STACK}.dump").exists()
    assert not (directory / f"{STACK}.json").exists()


def test_a_database_that_does_not_run_is_red_before_the_dump(tmp_path: Path) -> None:
    box = blank_box(tmp_path)
    cs = compose(tmp_path)
    step = DbDump(cs, directory=backups_dir(box.root, RUN_ID), run_id=RUN_ID)
    with Copying(config_call(cs), running_call(cs, "postgres")) as runner:
        outcome = plan([step], runner)  # no pg_dump in the script
    assert outcome.steps[0].reason == Code(
        "db_dump:database-down", {"stack": STACK, "service": "postgres"}
    )


def test_verify_reads_the_dump_back(tmp_path: Path) -> None:
    """A dump that changed after it was written -- ``dump-drift``: the fact is
    the file as it is, not as ``act`` remembers it. The pair: as written --
    green."""
    from env_support import context

    from pridem.steps.base import CheckResult, StepFailed

    cs, directory, step = dumped(tmp_path)
    with FakeRunner() as runner:
        fact = step.verify(context(runner), CheckResult(False)).fact
    assert fact["sha256"] == sha256_of(directory / f"{STACK}.dump")
    for changed in (b"PGDMP\x00dumq", b"PGDMP\x00dump+"):  # the content; the size
        (directory / f"{STACK}.dump").write_bytes(changed)
        with FakeRunner() as runner, pytest.raises(StepFailed) as raised:
            step.verify(context(runner), CheckResult(False))
        assert raised.value.reason.code == "dump-drift"


# --- db restore ----------------------------------------------------------------------


def _cli(fs_root: Path, argv: list[str], runner: FakeRunner) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    code = cli(
        ["--json", *argv],
        root=fs_root / "opt" / "pridem",
        out=out,
        err=err,
        runner=runner,
        fs_root=fs_root,
    )
    return code, out.getvalue(), err.getvalue()


def _restore_calls(
    cs: ComposeStack, path: Path, *, stop_code: int = 0, head: str = HEAD
) -> list[FakeCall]:
    restore_inside = f"/tmp/pridem-restore-{STACK}.dump"  # noqa: S108 -- the container
    calls = [
        config_call(cs),  # db_restore's check, before anything is stopped
        running_call(cs, "postgres", "c-pg"),  # DM-94: the database runs
        config_call(cs),
        running_call(cs, "app", "c-app"),
        running_call(cs, "frontend", "c-front"),
        FakeCall(
            tuple(
                cs.argv(
                    "stop",
                    operands=(
                        "app",
                        "frontend",
                    ),
                )
            ),
            code=stop_code,
        ),
    ]
    if stop_code:
        return [
            *calls,
            FakeCall(
                tuple(
                    cs.argv(
                        "start",
                        operands=(
                            "app",
                            "frontend",
                        ),
                    )
                )
            ),
            running_call(cs, "app", "c-app"),
            running_call(cs, "frontend", "c-front"),
        ]
    calls += [
        running_call(cs, "app"),
        running_call(cs, "frontend"),
        config_call(cs),
        running_call(cs, "postgres", "c-pg"),
        FakeCall(
            tuple(
                cs.argv(
                    "cp",
                    operands=(
                        str(path),
                        f"postgres:{restore_inside}",
                    ),
                )
            )
        ),
        FakeCall(
            tuple(
                cs.argv(
                    "exec",
                    "-T",
                    operands=(
                        "postgres",
                        "pg_restore",
                        "--clean",
                        "--if-exists",
                        "--no-owner",
                        "--single-transaction",
                        "--exit-on-error",
                        "-U",
                        "blank",
                        "-d",
                        "blank",
                        restore_inside,
                    ),
                )
            )  # fmt: skip
        ),
        FakeCall(
            tuple(
                cs.argv(
                    "exec",
                    "-T",
                    operands=(
                        "postgres",
                        "rm",
                        "-f",
                        restore_inside,
                    ),
                )
            )
        ),
        head_call(cs, head),
    ]
    if head != HEAD:
        return calls
    return [
        *calls,
        FakeCall(
            tuple(
                cs.argv(
                    "start",
                    operands=(
                        "app",
                        "frontend",
                    ),
                )
            )
        ),
        running_call(cs, "app", "c-app"),
        running_call(cs, "frontend", "c-front"),
    ]


def _verdict(out: str) -> Verdict:
    return Verdict.model_validate_json(out)


INSURANCE_RUN = "2026-11-14T00:00:00Z-cd34"
"""The run id of a ``db restore`` of the tests: its insurance dump goes to
``backups/<INSURANCE_RUN>/``, beside the dump it restores (``RUN_ID``)."""


@pytest.fixture
def insured(monkeypatch: pytest.MonkeyPatch) -> None:
    """``db restore`` runs as ``INSURANCE_RUN``."""
    monkeypatch.setattr(Box, "new_run_id", lambda self, now: INSURANCE_RUN)


def insurance_calls(fs_root: Path, cs: ComposeStack) -> list[FakeCall]:
    """The dump of the live database ``db restore`` takes first (DM-94)."""
    directory = backups_dir(fs_root / "opt" / "pridem", INSURANCE_RUN)
    calls = dump_calls(cs, directory, run_id=INSURANCE_RUN)
    return [*calls, head_call(cs), git_call(cs)]


def insurance_path(fs_root: Path) -> Path:
    directory = backups_dir(fs_root / "opt" / "pridem", INSURANCE_RUN)
    return directory / f"{STACK}.dump"


@pytest.mark.parametrize("role", ["test", "preview", "prod"])
def test_db_restore_asks_the_server_s_name_on_any_role(
    tmp_path: Path, role: str, insured: None
) -> None:
    """Protocol 1.11 to 8.2 (gate DM-86): a verb that wipes data asks where
    it is allowed -- no ``--confirm`` or another name: refused before the
    run, nothing ran (an empty script). The pair: the box's name -- it runs.

    Changed by DM-94: the live database is dumped first (``db_dump`` of the
    stack ``backup``), and ``db_restore`` names that dump (``insurance``)."""
    blank_box(tmp_path, role=role, name="box-1")
    path = _a_dump(tmp_path)
    for confirm in ([], ["--confirm", "box-2"]):
        with FakeRunner() as runner:
            code, out, err = _cli(
                tmp_path, ["db", "restore", STACK, str(path), *confirm], runner
            )
        assert (code, out) == (1, ""), err
        assert "--confirm box-1" in err
    cs = compose(tmp_path)
    with Copying(*insurance_calls(tmp_path, cs), *_restore_calls(cs, path)) as runner:
        code, out, err = _cli(
            tmp_path, ["db", "restore", STACK, str(path), "--confirm", "box-1"], runner
        )
    verdict = _verdict(out)
    assert code == 0, verdict.steps
    names = [(s.name, s.status) for s in verdict.steps]
    assert names == [
        ("db_dump", "ok"),
        ("stop_for_restore", "ok"),
        ("db_restore", "ok"),
        ("start_restored", "ok"),
        ("start_stopped", "ok"),
    ]
    assert verdict.steps[2].verify == {
        "stack": STACK,
        "path": str(path),
        "insurance": str(insurance_path(tmp_path)),
        "alembic_head": HEAD,
    }
    assert verdict.steps[4].verify == {"started": {}}


def _a_dump(fs_root: Path, entry: str = STACK, run_id: str = RUN_ID) -> Path:
    """A dump of ``db_dump`` on the box, written by hand: the file and its
    manifest."""
    directory = backups_dir(fs_root / "opt" / "pridem", run_id)
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / f"{entry}.dump"
    path.write_bytes(b"PGDMP\x00dump")
    manifest: dict[str, Json] = {
        "stack": STACK,
        "entry": entry,
        "release": SHA,
        "commit": SHA,
        "bytes": path.stat().st_size,
        "sha256": sha256_of(path),
        "toc": 2,
        "alembic_head": HEAD,
    }
    (directory / f"{entry}.json").write_text(json.dumps(manifest))
    return path


def test_db_restore_takes_a_dump_of_db_dump_for_that_entry_alone(
    tmp_path: Path,
) -> None:
    """Refused before the run: a file out of ``backups/``; one named for
    another entry; one without its manifest; a manifest of another entry. The
    pair is the test above."""
    blank_box(tmp_path, name="box-1")
    outside = tmp_path / "blank.dump"
    outside.write_bytes(b"x")
    path = _a_dump(tmp_path)
    other = path.with_name("other.dump")
    other.write_bytes(b"x")
    bare = _a_dump(tmp_path, run_id="2026-11-10T22:00:00Z-cd34")
    bare.with_suffix(".json").unlink()
    foreign = _a_dump(tmp_path, run_id="2026-11-10T23:00:00Z-ef56")
    manifest = json.loads(foreign.with_suffix(".json").read_text())
    manifest["entry"] = "storage"
    foreign.with_suffix(".json").write_text(json.dumps(manifest))
    alien = _a_dump(tmp_path, run_id="2026-11-10T23:30:00Z-ab78")
    manifest = json.loads(alien.with_suffix(".json").read_text())
    manifest["stack"] = "velo"  # the same entry name, another product's
    alien.with_suffix(".json").write_text(json.dumps(manifest))
    for given, said in (
        (outside, "is no dump of blank"),
        (other, "is no dump of blank"),
        (bare, "has no manifest"),
        (foreign, "of another entry"),
        (alien, "of another entry"),
    ):
        with FakeRunner() as runner:
            code, out, err = _cli(
                tmp_path,
                ["db", "restore", STACK, str(given), "--confirm", "box-1"],
                runner,
            )
        assert (code, out) == (1, ""), given
        assert said in err, err


def test_a_restored_head_other_than_the_dump_s_is_red_past_the_point(
    tmp_path: Path, insured: None
) -> None:
    """The database is at another head than the manifest's after
    ``pg_restore`` -- ``head-mismatch``, restore needed; nothing is started
    again (the KNOWN CEILING of ``StartStopped``): no ``start`` in the
    script."""
    blank_box(tmp_path, name="box-1")
    path = _a_dump(tmp_path)
    cs = compose(tmp_path)  # DM-94: the insurance dump first
    calls = [*insurance_calls(tmp_path, cs), *_restore_calls(cs, path, head="0002")]
    with Copying(*calls) as runner:
        code, out, _ = _cli(
            tmp_path, ["db", "restore", STACK, str(path), "--confirm", "box-1"], runner
        )
    verdict = _verdict(out)
    assert code == 1
    restore = verdict.steps[2]
    assert restore.reason is not None
    assert restore.reason.model_dump() == {
        "code": "db_restore:head-mismatch",
        "stack": STACK,
        "head": HEAD,
        "current": "0002",
    }
    assert [i.code for i in verdict.report.incomplete] == ["needed"]
    assert verdict.steps[4].verify == {"started": {}}


def test_a_red_stop_crosses_no_point_and_finally_starts_what_it_stopped(
    tmp_path: Path, insured: None
) -> None:
    """Changed by DM-94: the insurance dump comes first."""
    blank_box(tmp_path, name="box-1")
    path = _a_dump(tmp_path)
    cs = compose(tmp_path)
    calls = [*insurance_calls(tmp_path, cs), *_restore_calls(cs, path, stop_code=1)]
    with Copying(*calls) as runner:
        code, out, _ = _cli(
            tmp_path, ["db", "restore", STACK, str(path), "--confirm", "box-1"], runner
        )
    verdict = _verdict(out)
    assert code == 1
    assert verdict.steps[1].reason is not None
    assert verdict.steps[1].reason.code == "command-failed"
    assert [s.status for s in verdict.steps[2:4]] == ["skipped", "skipped"]
    assert not verdict.report.incomplete
    assert verdict.steps[4].verify == {"started": {STACK: ["app", "frontend"]}}


def test_a_dump_changed_since_its_manifest_is_red_before_the_restore(
    tmp_path: Path, insured: None
) -> None:
    """``db_restore`` reads the file against its manifest before ``act`` --
    and, since pass 2, before ``stop_for_restore`` stops anything: its check
    runs first there. ``dump-drift``, nothing stopped, the point not crossed.

    Changed by DM-86 pass 2: the drift was red at ``db_restore`` after the
    services were stopped and ``finally`` started them again; now nothing is
    stopped (the script has no ``stop`` and no ``start``)."""
    blank_box(tmp_path, name="box-1")
    path = _a_dump(tmp_path)
    path.write_bytes(b"PGDMP\x00changed")
    cs = compose(tmp_path)  # DM-94: the insurance dump first
    with Copying(*insurance_calls(tmp_path, cs)) as runner:
        code, out, _ = _cli(
            tmp_path, ["db", "restore", STACK, str(path), "--confirm", "box-1"], runner
        )
    verdict = _verdict(out)
    assert verdict.steps[1].reason is not None
    assert verdict.steps[1].reason.code == "stop_for_restore:dump-drift"
    assert [s.status for s in verdict.steps[2:4]] == ["skipped", "skipped"]
    assert not verdict.report.incomplete
    assert verdict.steps[4].verify == {"started": {}}


# --- backup and the entries of the box ------------------------------------------


def test_backup_with_the_policy_off_dumps_nothing_and_says_so(tmp_path: Path) -> None:
    """``policies.backup.enabled: false``: green, the fact names the policy,
    no command (the empty script). The pair: on -- the entry is dumped (the
    plan below)."""
    blank_box(tmp_path, backup=False)
    with FakeRunner() as runner:
        code, out, _ = _cli(tmp_path, ["backup"], runner)
    verdict = _verdict(out)
    assert code == 0
    assert [(s.stack, s.name, s.verify) for s in verdict.steps] == [
        ("backup", "backup_scope", {"policy": "disabled"})
    ]


def _service(fs_root: Path, name: str, with_database: bool) -> None:
    """A service stack on the box beside the blank, its compose with or
    without ``DATABASE_URL``."""
    release = fs_root / "opt" / name / "releases" / "v1.0.0"
    release.mkdir(parents=True)
    (fs_root / "opt" / name / "current").symlink_to(release)
    primer = {
        "schema": 1,
        "name": name,
        "kind": "service",
        "stacks": {
            name: {
                "compose": "docker-compose.yml",
                "app": {"service": "app", "port": 8000, "health": "/h", "ready": "/r"},
            }
        },
        "env": {},
        "report": {"health": "/h", "ready": "/r", "logs": "json", "junit": True},
    }
    import yaml

    (release / "primer.yaml").write_text(yaml.safe_dump(primer))
    env = ["DATABASE_URL=postgresql://s:p@db:5432/s"] if with_database else ["X=1"]
    compose_doc = {"services": {"app": {"image": "a", "environment": env}}}
    (release / "docker-compose.yml").write_text(yaml.safe_dump(compose_doc))

    box = Box(fs_root / "opt" / "pridem")
    state = box.read_state()
    assert state is not None
    with box.lock("setup"):
        box.write_state(
            state.model_copy(
                update={"current": {**state.current, name: "releases/v1.0.0"}}
            )
        )


def test_backup_dumps_the_services_before_the_product_and_names_the_rest(
    tmp_path: Path,
) -> None:
    """Services first, the product last (the order of the box's ladder); an
    entry without ``DATABASE_URL`` -- in the fact of ``backup_scope``, no step.
    The list form of ``environment`` counts too."""
    blank_box(tmp_path)
    _service(tmp_path, "comms", with_database=True)
    _service(tmp_path, "payments", with_database=False)
    from pridem.verbs.base import Context

    ctx = Context(
        root=tmp_path / "opt" / "pridem",
        out=io.StringIO(),
        err=io.StringIO(),
        fs_root=tmp_path,
    )
    entries = [(stack, made.name) for stack, made in box_entries(ctx)]
    assert entries == [("comms", "comms"), ("payments", "payments"), (STACK, STACK)]

    class Refusing(FakeRunner):
        def run(self, argv: Sequence[str], **kw: object) -> Result:
            from pridem.runner import CommandNotStarted

            raise CommandNotStarted(tuple(argv), "refused by the test")

    code, out, _ = _cli(tmp_path, ["backup"], Refusing())
    verdict = _verdict(out)
    assert [s.stack for s in verdict.steps] == ["comms", STACK, "backup"]
    assert verdict.steps[-1].status == "skipped"  # after the red comms dump
    del code


def test_db_dump_of_an_entry_without_a_database_or_unknown_is_refused(
    tmp_path: Path,
) -> None:
    blank_box(tmp_path)
    _service(tmp_path, "payments", with_database=False)
    for entry, said in (("payments", "no DATABASE_URL"), ("ghost", "runs no entry")):
        with FakeRunner() as runner:
            code, out, err = _cli(tmp_path, ["db", "dump", entry], runner)
        assert (code, out) == (1, "")
        assert said in err


def test_has_database_url_reads_the_compose_file_of_the_entry(tmp_path: Path) -> None:
    blank_box(tmp_path)
    cs = compose(tmp_path)
    assert has_database_url(cs)
    cs.compose_file.write_text("services: {app: {environment: {X: '1'}}}\n")
    assert not has_database_url(cs)


def test_backup_scope_says_what_it_was_given() -> None:
    from env_support import context

    from pridem.steps.base import CheckResult

    step = BackupScope({"dumped": [STACK], "no_database": []})
    with FakeRunner() as runner:
        assert step.check(context(runner)).needed is False
        assert step.verify(context(runner), CheckResult(False)).fact == {
            "dumped": [STACK],
            "no_database": [],
        }


# --- FIX: a path of the box goes to docker as --mount, never -v -----------------------


def test_a_bind_goes_to_docker_as_mount_whatever_its_path_holds() -> None:
    """DM-86 FIX (tier 3: ``-v`` split ``<run_id>`` at its colons, ``too many
    colons``): ``--mount`` takes the path whole; a comma or a quote is quoted
    the CSV way docker reads it. The pair: ``readonly`` only when asked."""
    from pridem.steps.compose import bind, mount_flag

    path = Path("/opt/pridem/backups/2026-11-10T22:27:14Z-b05b/primer-blank.dump")
    assert mount_flag(path, "/primer/db.dump") == [
        "--mount",
        f"type=bind,source={path},target=/primer/db.dump,readonly",
    ]
    assert mount_flag("/a,b", '/c"d', read_only=False) == [
        "--mount",
        'type=bind,"source=/a,b","target=/c""d"',
    ]
    assert bind("/a:b", "/c:d") == {
        "type": "bind",
        "source": "/a:b",
        "target": "/c:d",
        "read_only": True,
    }
