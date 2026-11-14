"""``tests`` (DM-19): the test target's image, ``<live>_test``, junit, the
role. docker is a strict script; what the script cannot do itself -- write
the image id file of ``docker build`` and the junit of the test run -- the
runner does at the moment the command is called."""

import json
from collections.abc import Mapping, Sequence
from pathlib import Path

import pytest
from compose_support import ENTRY, REF, SHA, compose, stdout
from plan_support import ListSink

from pridem.events import Code, Json, PlanOutcome, Secrets
from pridem.plan import Plan, StackSteps
from pridem.report.codes import ExitCode
from pridem.runner import FakeCall, FakeRunner, OnLine, Result
from pridem.stacks.schema import PRIMER_YAML, Product
from pridem.steps.base import Role, Step, StepFailed
from pridem.steps.tests import TestReport, Tests, database

MINTED = "invented-minted-password-000000000000001"
IID = "sha256:" + "7" * 64
GREEN = """<testsuites><testsuite name="pytest" tests="2">
<testcase classname="tests.test_health" name="test_ok"/>
<testcase classname="tests.test_db" name="test_db"/>
</testsuite></testsuites>"""
RED = """<testsuites><testsuite name="pytest" tests="2">
<testcase classname="tests.test_health" name="test_ok"/>
<testcase classname="tests.test_db" name="test_db" line="12">
<failure message="assert 1 == 2">tests/test_db.py:12: AssertionError</failure>
</testcase></testsuite></testsuites>"""


def product(
    *,
    junit: bool = True,
    run: str = "python -m pytest tests/ --junitxml=/tmp/out/junit.xml",
) -> Product:
    made = PRIMER_YAML.validate_python(
        {
            "schema": 1,
            "name": "blank",
            "kind": "product",
            "stacks": {
                "blank": {
                    "compose": "docker-compose.yml",
                    "app": {
                        "service": "app",
                        "port": 8000,
                        "health": "/health",
                        "ready": "/ready",
                    },
                    "migrate": "python -m alembic upgrade head",
                    "test": {"run": run, "target": "test"},
                }
            },
            "env": {},
            "report": {
                "health": "/health",
                "ready": "/ready",
                "logs": "json",
                "junit": junit,
            },
        }
    )
    assert isinstance(made, Product)
    return made


def document(root: Path, live: str = "app") -> dict[str, Json]:
    url = f"postgresql+asyncpg://blank:{MINTED}@postgres:5432/{live}"
    return {
        "services": {
            "app": {
                "build": {
                    "context": str(root / "release" / "backend"),
                    "dockerfile": "Dockerfile",
                },
                "environment": {"DATABASE_URL": url},
            },
            "postgres": {"image": "postgres@sha256:x"},
        },
        "networks": {"default": {"name": "blank_default"}},
    }


class Effects(FakeRunner):
    """Writes what docker would: the image id file, the junit."""

    def __init__(self, junit: str | None, *calls: FakeCall) -> None:
        super().__init__(*calls)
        self.junit = junit
        self.argvs: list[tuple[str, ...]] = []
        self.env_files: list[str] = []

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
        words = list(argv)
        if "--iidfile" in words:
            Path(words[words.index("--iidfile") + 1]).write_text(IID)
        if "--env-file" in words and words[:2] == ["docker", "run"]:
            self.env_files.append(
                Path(words[words.index("--env-file") + 1]).read_text()
            )
            # the junit bind is a --mount (DM-86 FIX): source=<host>,target=...
            host = [w for w in words if w.endswith(",target=/tmp/out")]
            if host and self.junit is not None:
                source = host[0].split(",")[1].removeprefix("source=")
                (Path(source) / "junit.xml").write_text(self.junit)
        return super().run(
            argv, expect=expect, timeout=timeout, cwd=cwd, env=env, on_line=on_line
        )


def script(
    root: Path, *, code: int = 0, exists: bool = False, live: str = "app"
) -> list[FakeCall]:
    cs = compose(root)
    config = FakeCall(
        tuple(cs.product_argv("config", "--format", "json")),
        lines=stdout(json.dumps(document(root, live))),
    )
    home = root / "opt" / "blank" / "tests" / SHA
    labels = [
        "--label",
        f"pridem.stack={ENTRY}",
        "--label",
        f"pridem.release={REF}",
        "--label",
        f"pridem.commit={SHA}",
        "--label",
        "pridem.service=app-test",
    ]
    test_db = f"{live}_test"
    return [
        config,  # check
        config,  # act
        # DM-81: a running database is never recreated by the tests
        FakeCall(
            tuple(
                cs.argv(
                    "up",
                    "-d",
                    "--no-build",
                    "--no-recreate",
                    "--wait",
                    operands=("postgres",),
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
                        "psql",
                        "-U",
                        "blank",
                        "-d",
                        "postgres",
                        "-tAc",
                        f"SELECT 1 FROM pg_database WHERE datname = '{test_db}'",  # noqa: S608
                    ),
                )
            ),
            lines=stdout("1") if exists else (),
        ),
        *(
            []
            if exists
            else [
                FakeCall(
                    tuple(
                        cs.argv(
                            "exec",
                            "-T",
                            operands=(
                                "postgres",
                                "createdb",
                                "-U",
                                "blank",
                                test_db,
                            ),
                        )
                    )
                )
            ]
        ),
        FakeCall(
            (
                "docker",
                "build",
                "--target",
                "test",
                "--iidfile",
                str(home / "image.id"),
                "-t",
                f"blank-app-test:{SHA[:12]}",
                "--build-arg",
                f"PRIMER_RELEASE={REF}",
                "--build-arg",
                f"PRIMER_COMMIT={SHA}",
                *labels,
                "-f",
                str(root / "release" / "backend" / "Dockerfile"),
                str(root / "release" / "backend"),
            )
        ),
        FakeCall(
            (
                "docker",
                "run",
                "--rm",
                *labels,
                "--network",
                "blank_default",
                "--env-file",
                str(home / "test.env"),
                "--mount",  # never -v (DM-86 FIX)
                f"type=bind,source={home / 'junit'},target=/tmp/out",
                "--",
                IID,
                "python",
                "-m",
                "pytest",
                "tests/",
                "--junitxml=/tmp/out/junit.xml",
            ),
            code=code,
        ),
        config,  # verify
    ]


def step(root: Path, report: TestReport | None = None, **made: object) -> Tests:
    cs = compose(root)
    return Tests(
        product(**made),  # type: ignore[arg-type]
        ENTRY,
        release=cs.release,
        ref=REF,
        commit=SHA,
        report=report or TestReport(),
        secrets=Secrets(()),
        root=root,
    )


def run(steps: Sequence[Step], runner: FakeRunner, role: Role = "test") -> PlanOutcome:
    return Plan(
        [StackSteps(ENTRY, steps, root=True)],
        mode="install",
        role=role,
        runner=runner,
        sink=ListSink(),
    ).run()


# --- probes ---------------------------------------------------------------------


def test_probe_DM_19_live_db_never_touched_by_tests(tmp_path: Path) -> None:
    runner = Effects(GREEN, *script(tmp_path))
    with runner:
        outcome = run([step(tmp_path)], runner)
    assert outcome.code is ExitCode.OK, outcome.steps
    # the live database "app" is not a word of any command
    assert not [a for a in runner.argvs if "app" in a]
    assert not [a for a in runner.argvs if any(MINTED in w for w in a)]
    # the pair: the tests got the test database, through the env file
    [env] = runner.env_files
    assert (
        env
        == f"DATABASE_URL=postgresql+asyncpg://blank:{MINTED}@postgres:5432/app_test\n"
    )
    assert outcome.steps[0].verify == {
        "test_db": "app_test",
        "target": "test",
        "junit": {"total": 2, "failed": 0, "skipped": 0},
    }
    # the fence itself: a name that cannot be a test database is refused
    with pytest.raises(StepFailed) as refused:
        url = "postgresql://blank:p@postgres/app-live"
        database({"services": {"app": {"environment": {"DATABASE_URL": url}}}}, "app")
    assert refused.value.reason.code == "test-db-is-live"


def test_probe_DM_19_tests_run_from_the_test_target_not_the_runtime_image(
    tmp_path: Path,
) -> None:
    runner = Effects(GREEN, *script(tmp_path))
    with runner:
        run([step(tmp_path)], runner)
    [build] = [a for a in runner.argvs if a[:2] == ("docker", "build")]
    assert build[build.index("--target") + 1] == "test"
    # the image has the machine's name, beside compose's (DM-50 fix 2)
    assert build[build.index("-t") + 1] == f"blank-app-test:{SHA[:12]}"
    [test] = [a for a in runner.argvs if a[:2] == ("docker", "run")]
    assert IID in test  # the image of the test target, built here
    assert not [a for a in runner.argvs if "compose" in a and "build" in a]


@pytest.mark.parametrize("role", ["prod", "preview"])
def test_probe_DM_19_tests_skipped_on_prod_with_role_code(
    tmp_path: Path, role: Role
) -> None:
    with FakeRunner() as runner:  # nothing runs at all
        outcome = run([step(tmp_path)], runner, role=role)
    [record] = outcome.steps
    assert (record.status, record.reason) == ("skipped", Code("role", {"role": role}))
    # the pair: on test they run
    runner = Effects(GREEN, *script(tmp_path))
    with runner:
        outcome = run([step(tmp_path)], runner, role="test")
    assert outcome.steps[0].status == "ok"


# --- the rest -------------------------------------------------------------------


def test_red_tests_stop_with_their_failures(tmp_path: Path) -> None:
    report = TestReport()
    calls = script(tmp_path, code=1)[:-1]  # no verify after a red act
    runner = Effects(RED, *calls)
    with runner:
        outcome = run([step(tmp_path, report)], runner)
    assert outcome.steps[0].reason == Code("tests:failed", {"total": 2, "failed": 1})
    assert report.junit == {"total": 2, "failed": 1, "skipped": 0}
    [failure] = report.failures
    assert (failure["test"], failure["file"], failure["line"], failure["message"]) == (
        "tests.test_db.test_db",
        "tests/test_db.py",
        12,
        "assert 1 == 2",
    )


def test_no_junit_or_no_tests_is_red(tmp_path: Path) -> None:
    with Effects(None, *script(tmp_path)[:-1]) as runner:
        outcome = run([step(tmp_path)], runner)
    assert outcome.steps[0].reason is not None
    assert outcome.steps[0].reason.code == "tests:junit-missing"
    empty = '<testsuites><testsuite name="pytest" tests="0"/></testsuites>'
    with Effects(empty, *script(tmp_path / "e")[:-1]) as runner:
        outcome = run([step(tmp_path / "e")], runner)
    assert outcome.steps[0].reason == Code("tests:no-tests")


def test_junit_without_a_path_is_red_before_act(tmp_path: Path) -> None:
    cs = compose(tmp_path)
    config = FakeCall(
        tuple(cs.product_argv("config", "--format", "json")),
        lines=stdout(json.dumps(document(tmp_path))),
    )
    with FakeRunner(config) as runner:
        outcome = run([step(tmp_path, run="python -m pytest tests/")], runner)
    assert outcome.steps[0].reason == Code("tests:junit-path-unknown")


def test_the_same_commit_passed_needs_no_act(tmp_path: Path) -> None:
    runner = Effects(GREEN, *script(tmp_path))
    with runner:
        run([step(tmp_path)], runner)
    cs = compose(tmp_path)
    config = FakeCall(
        tuple(cs.product_argv("config", "--format", "json")),
        lines=stdout(json.dumps(document(tmp_path))),
    )
    with FakeRunner(config, config) as again:  # check and verify only
        outcome = run([step(tmp_path)], again)
    assert outcome.code is ExitCode.OK


def test_the_home_of_the_tests_found_wider_is_made_0700(tmp_path: Path) -> None:
    """DM-80: the tests' directory (image id, junit) is 0700 whatever it was
    found as; the junit directory inside stays 0777 for the image's user."""
    home = tmp_path / "opt" / "blank" / "tests" / SHA
    home.mkdir(parents=True)
    home.chmod(0o755)
    runner = Effects(GREEN, *script(tmp_path))
    with runner:
        outcome = run([step(tmp_path)], runner)
    assert outcome.code is ExitCode.OK, outcome.steps
    assert home.stat().st_mode & 0o777 == 0o700
