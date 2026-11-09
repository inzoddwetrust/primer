"""``tests``: the stack's tests before its migrations, in their own database
and their own image (TZ 2, 6.2 item 6, 7.3; contract 3 rule 20).

The stack is the blank's (TZ 2): the database is Postgres, named in the
``DATABASE_URL`` of the ``app`` service -- its host is the compose service of
the database, its path the live database. The tests get ``<live>_test`` in
the same server; a name that is the live one, or does not end in ``_test``, is
refused before a single command reaches the database (the fence). The live
database is never named in any command of this step.

The database service is brought up first by the same compose command as
``up`` -- the machine's override, its labels on the container and the volume
-- because on a first install nothing runs yet; with it, the services
``test.services`` names (rule 20: Redis, a queue), never the application or
the frontend (the loader refuses those names, a name the compose does not
have is ``test-service-unknown``); compose does not recreate a running one.
``<live>_test`` is created when it is not there.

The tests run from the build target ``test.target`` of the ``app`` service's
Dockerfile, built here with the release's two build arguments, the machine's
labels and the machine's name ``<project>-<app>-test:<commit12>`` beside the
names compose gives the working images: the working image carries no tests
(rule 20). The
container gets the test database's ``DATABASE_URL`` through an env file
(0600) -- the password is a secret, never in argv -- and writes its junit to
a directory of the host mounted where ``--junitxml=`` of ``test.run`` points.

Red tests stop the plan before the point of no return (``migrate``): the
live database and the running containers are untouched. The junit of a
commit that passed stays on the box: the same commit again needs no ``act``.
On ``prod`` and ``preview`` the plan skips the step with the code ``role``.
"""

import os
import shlex
import shutil
import stat
import xml.etree.ElementTree as ElementTree
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import ClassVar
from urllib.parse import urlsplit, urlunsplit

from pydantic import SecretStr

from pridem.events import Json, Secrets
from pridem.files import private_dir
from pridem.stacks.schema import Product, Service
from pridem.steps.base import (
    CheckResult,
    Mode,
    Role,
    Step,
    StepContext,
    StepFailed,
    Verified,
    local_code,
)
from pridem.steps.build import build_args, copied_dockerfile
from pridem.steps.compose import (
    BUILD_TIMEOUT_S,
    REFUSAL_CODES,
    ComposeStack,
    config,
    out,
)
from pridem.steps.packages import KEY_CODES, context_dir, image_key
from pridem.steps.passport import NO_PASSPORT, Fetched

ALL_MODES: frozenset[Mode] = frozenset({"install", "deploy", "reinstall"})
TEST_ROLES: frozenset[Role] = frozenset({"test"})
TESTS_TIMEOUT_S = 3600
JUNIT_FILE = "junit.xml"
_NAME = "abcdefghijklmnopqrstuvwxyz0123456789_"


@dataclass
class TestReport:
    """What ``tests`` read from junit: for the verdict's ``junit`` and
    ``report.failures`` (the plan builder hands them to ``build_verdict``)."""

    __test__ = False  # not a pytest class

    junit: dict[str, int] | None = None
    failures: list[dict[str, Json]] = field(default_factory=list)


@dataclass(frozen=True)
class Database:
    """The live database of a stack and the one the tests get."""

    service: str
    user: str
    live: str
    test: str
    test_url: str


def database(document: dict[str, Json], app: str) -> Database:
    """From ``DATABASE_URL`` of ``app`` in ``config``; the fence is here."""
    services = document.get("services")
    body = services.get(app) if isinstance(services, dict) else None
    env = body.get("environment") if isinstance(body, dict) else None
    url = env.get("DATABASE_URL") if isinstance(env, dict) else None
    if not isinstance(url, str) or not url:
        raise StepFailed("no-database-url", {"service": app})
    parts = urlsplit(url)
    live = parts.path.lstrip("/")
    test = f"{live}_test"
    if not parts.hostname or not parts.username or not live:
        raise StepFailed("no-database-url", {"service": app})
    if test == live or not test.endswith("_test") or set(test) - set(_NAME):
        raise StepFailed("test-db-is-live", {"live": live, "test": test})
    test_url = urlunsplit(parts._replace(path=f"/{test}"))
    return Database(parts.hostname, parts.username, live, test, test_url)


def junit_dir(run: str) -> str | None:
    """The directory ``--junitxml=`` of ``test.run`` writes to."""
    for word in shlex.split(run):
        if word.startswith("--junitxml="):
            return str(PurePosixPath(word.removeprefix("--junitxml=")).parent)
    return None


def read_junit(path: Path) -> TestReport:
    """Totals and failures of a junit file the stack's tests wrote."""
    # The file is written by the stack's own tests on this box; expat bounds
    # entity expansion, no network is reached.
    tree = ElementTree.parse(path)  # noqa: S314
    root = tree.getroot()
    suites = [root] if root.tag == "testsuite" else list(root.iter("testsuite"))
    total = failed = skipped = 0
    failures: list[dict[str, Json]] = []
    for suite in suites:
        for case in suite.iter("testcase"):
            total += 1
            bad = case.find("failure")
            if bad is None:
                bad = case.find("error")
            if case.find("skipped") is not None:
                skipped += 1
            elif bad is not None:
                failed += 1
                classname = case.get("classname", "")
                text = bad.text or ""
                frames = list[Json](
                    line.strip()
                    for line in text.splitlines()
                    if ".py:" in line and not line.strip().startswith("/usr")
                )[:20]
                failures.append(
                    {
                        "test": f"{classname}.{case.get('name', '')}".strip("."),
                        "file": case.get("file") or classname.replace(".", "/") + ".py",
                        "line": int(case.get("line") or 1) or 1,
                        "message": bad.get("message")
                        or (text.splitlines()[0] if text.strip() else ""),
                        "traceback_project_frames": frames,
                        "request_ids": [],
                    }
                )
    return TestReport({"total": total, "failed": failed, "skipped": skipped}, failures)


JUNIT_LIMIT = 16 * 1024 * 1024
"""The most a junit file of the tests may take (DM-78)."""


def _take_junit(produced: Path, kept: Path) -> None:
    """Copy the junit the test container wrote: opened without following a
    symlink and checked on the open descriptor -- the container writes the
    directory in this very run, so a check of the path and a later open are
    not the same file (DM-78)."""
    try:  # O_NONBLOCK: a FIFO put there would hold the open for ever
        fd = os.open(produced, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError:  # ELOOP: the name is a symlink
        raise StepFailed(
            "junit-unsafe", {"path": str(produced), "cause": "symlink"}
        ) from None
    found = os.fstat(fd)  # on the descriptor: what was opened is what is read
    cause = None
    if not stat.S_ISREG(found.st_mode):
        cause = "not-a-file"
    elif found.st_size > JUNIT_LIMIT:
        cause = "too-big"
    if cause is not None:
        os.close(fd)
        raise StepFailed("junit-unsafe", {"path": str(produced), "cause": cause})
    with os.fdopen(fd, "rb") as source:
        kept.write_bytes(source.read(JUNIT_LIMIT + 1))


class Tests(Step):
    """The stack's tests, from the test target, in ``<live>_test``."""

    __test__ = False  # not a pytest class
    name = "tests"
    order = 10
    modes = ALL_MODES
    roles = TEST_ROLES
    codes: ClassVar[dict[str, str]] = {
        **REFUSAL_CODES,
        **NO_PASSPORT,
        **KEY_CODES,
        "run": "run the tests of {stack} at {commit} in {test_db}",
        "no-database-url": "{service} has no DATABASE_URL to take the database from",
        "test-db-is-live": "the test database {test} would be the live {live}",
        "junit-path-unknown": "report.junit is on and the test run has no --junitxml=",
        "junit-missing": "the tests wrote no junit at {path}",
        "junit-unsafe": "the junit at {path} is not taken: {cause}",
        "no-tests": "the tests ran no test",
        "failed": "{failed} of {total} tests failed",
        "no-test": "{stack} declares no test or no app",
        "test-service-unknown": "test.services of {stack} names {services}, "
        "not services of its compose",
    }

    def __init__(
        self,
        stack: Product | Service,
        entry: str,
        *,
        release: Path,
        ref: str,
        commit: str,
        report: TestReport,
        secrets: Secrets,
        root: Path = Path("/"),
        fetched: Fetched | None = None,
    ) -> None:
        self.compose = ComposeStack(stack, entry, release, ref, commit, root)
        self.fetched = fetched
        stage = stack.stacks[entry]
        if stage.test is None or stage.app is None:
            raise ValueError(f"{entry} declares no test or no app")
        self.run = stage.test.run
        self.target = stage.test.target
        self.services = list(stage.test.services or [])
        self.app = stage.app.service
        self.junit = stack.report.junit
        self.report = report
        self.secrets = secrets
        self.image: str | None = None

    @property
    def image_name(self) -> str:
        """The machine's name of the test image, beside the names compose gives:
        ``<project>-<app>-test:<commit12>``."""
        return f"{self.compose.project}-{self.app}-test:{self.compose.commit[:12]}"

    @property
    def _home(self) -> Path:
        return (
            self.compose.root
            / "opt"
            / self.compose.name
            / "tests"
            / self.compose.commit
        )

    def _database(self, ctx: StepContext) -> tuple[Database, dict[str, Json]]:
        document = config(ctx, self.compose)
        found = database(document, self.app)
        self.secrets.add([SecretStr(found.test_url)])
        services = document.get("services")
        known = set(services) if isinstance(services, dict) else set()
        unknown = [name for name in self.services if name not in known]
        if unknown:
            raise StepFailed(
                "test-service-unknown",
                {"stack": self.compose.entry, "services": list[Json](unknown)},
            )
        if self.junit and junit_dir(self.run) is None:
            raise StepFailed("junit-path-unknown")
        return found, document

    def check(self, ctx: StepContext) -> CheckResult:
        found, _ = self._database(ctx)
        params: dict[str, Json] = {
            "stack": self.compose.entry,
            "commit": self.compose.commit,
            "test_db": found.test,
        }
        passed = self._home / "passed"
        if passed.is_file() and (self._home / JUNIT_FILE).is_file():
            self.report.junit = read_junit(self._home / JUNIT_FILE).junit
            return CheckResult(False)
        return CheckResult(True, local_code("run", params))

    def act(self, ctx: StepContext, check: CheckResult) -> None:
        found, document = self._database(ctx)
        self._database_up(ctx, found)
        self.image = self._build(ctx, document)
        self._run(ctx, found, document)

    def _database_up(self, ctx: StepContext, found: Database) -> None:
        compose = self.compose
        wanted = [found.service, *(s for s in self.services if s != found.service)]
        out(ctx, compose.argv("up", "-d", "--no-build", "--wait", *wanted))
        # the name is [a-z0-9_] only: database() refuses anything else
        sql = f"SELECT 1 FROM pg_database WHERE datname = '{found.test}'"  # noqa: S608
        _, lines = out(
            ctx,
            compose.argv(
                "exec",
                "-T",
                found.service,
                "psql",
                "-U",
                found.user,
                "-d",
                "postgres",
                "-tAc",
                sql,
            ),
        )
        if "1" not in [line.strip() for line in lines]:
            out(
                ctx,
                compose.argv(
                    "exec",
                    "-T",
                    found.service,
                    "createdb",
                    "-U",
                    found.user,
                    found.test,
                ),
            )

    def _build(self, ctx: StepContext, document: dict[str, Json]) -> str:
        services = document.get("services")
        body = services.get(self.app) if isinstance(services, dict) else None
        build = body.get("build") if isinstance(body, dict) else None
        if not isinstance(build, dict) or not isinstance(build.get("context"), str):
            raise StepFailed("no-test", {"stack": self.compose.entry})
        context = Path(str(build["context"]))
        given = str(build.get("dockerfile") or "Dockerfile")
        dockerfile = context / given
        passport = None if self.fetched is None else self.fetched.passport
        key = image_key(self.compose.stack, self.app, passport)
        edition: list[str] = []
        if key:  # a package is built into app: the context build wrote, as build
            built = context_dir(
                self.compose.root, self.compose.stack.name, self.compose.entry, self.app
            )
            dockerfile = built / copied_dockerfile(context, given)
            context = built
            if "pridem.edition" in key:
                edition = ["--build-arg", f"PRIMER_EDITION={key['pridem.edition']}"]
        private_dir(self._home)
        iidfile = self._home / "image.id"
        iidfile.unlink(missing_ok=True)
        labels = {**self.compose.release_labels(), "pridem.service": f"{self.app}-test"}
        out(
            ctx,
            [
                "docker",
                "build",
                "--target",
                self.target,
                "--iidfile",
                str(iidfile),
                "-t",
                self.image_name,
                *build_args(self.compose),
                *edition,
                *[w for k, v in labels.items() for w in ("--label", f"{k}={v}")],
                "-f",
                str(dockerfile),
                str(context),
            ],
            timeout=BUILD_TIMEOUT_S,
        )
        return iidfile.read_text(encoding="ascii").strip()

    def _network(self, document: dict[str, Json]) -> str:
        networks = document.get("networks")
        default = networks.get("default") if isinstance(networks, dict) else None
        name = default.get("name") if isinstance(default, dict) else None
        return name if isinstance(name, str) else f"{self.compose.project}_default"

    def _run(
        self, ctx: StepContext, found: Database, document: dict[str, Json]
    ) -> None:
        if self.image is None:
            raise RuntimeError("the test image is built before the tests run")
        home = self._home
        (home / "passed").unlink(missing_ok=True)
        junit_host = home / "junit"
        shutil.rmtree(junit_host, ignore_errors=True)
        junit_host.mkdir()
        junit_host.chmod(0o777)  # the tests run as the image's user, not root
        env_file = home / "test.env"
        fd = os.open(env_file, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(f"DATABASE_URL={found.test_url}\n")
        target = junit_dir(self.run)
        mount = ["-v", f"{junit_host}:{target}"] if target is not None else []
        labels = [
            w
            for k, v in {
                **self.compose.release_labels(),
                "pridem.service": f"{self.app}-test",
            }.items()
            for w in ("--label", f"{k}={v}")
        ]
        try:
            code, _ = out(
                ctx,
                [
                    "docker",
                    "run",
                    "--rm",
                    *labels,
                    "--network",
                    self._network(document),
                    "--env-file",
                    str(env_file),
                    *mount,
                    self.image,
                    *shlex.split(self.run),
                ],
                expect=(0, 1),
                timeout=TESTS_TIMEOUT_S,
            )
        finally:
            env_file.unlink(missing_ok=True)
        produced = junit_host / JUNIT_FILE
        if self.junit:
            if not os.path.lexists(produced):
                raise StepFailed("junit-missing", {"path": str(produced)})
            _take_junit(produced, home / JUNIT_FILE)
            report = read_junit(home / JUNIT_FILE)
            self.report.junit, self.report.failures = report.junit, report.failures
            totals = report.junit or {}
            if totals.get("total", 0) == 0:
                raise StepFailed("no-tests")
            if code != 0 or totals.get("failed", 0):
                raise StepFailed(
                    "failed",
                    {
                        "total": totals.get("total", 0),
                        "failed": totals.get("failed", 0),
                    },
                )
        elif code != 0:
            raise StepFailed("failed", {"total": 0, "failed": 1})
        (home / "passed").write_text(self.compose.commit + "\n", encoding="ascii")

    def verify(self, ctx: StepContext, check: CheckResult) -> Verified:
        found, _ = self._database(ctx)
        passed = self._home / "passed"
        if not passed.is_file():
            raise StepFailed("failed", {"total": 0, "failed": 0})
        fact: dict[str, Json] = {"test_db": found.test, "target": self.target}
        if self.report.junit is not None:
            fact["junit"] = dict[str, Json](self.report.junit)
        return Verified(fact)
