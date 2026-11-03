"""Tier 3 probe (DM-19, DM-50, DM-20): the whole ``install`` of ``primer-blank``.

One plan installs the blank on a clean runner -- the host steps, the passport
(a file), the timers, the sources (a ``file://`` mirror of the blank at its
pinned commit, so no key of CI is needed), the blank's ladder (``seams_check``,
``render_env``, ``build``, ``packages``, ``tests``, ``migrate``, ``egress``,
``up``),
``types``, the edge (``tls_files``, ``nginx``, ``ssl``), ``frontend``, the
final check and ``finalize``, ``gc`` in ``finally`` -- and the same plan runs a
second time, then once as ``doctor``. The blank is built and brought up once in
the whole tier 3: every check of it lives here (DM-50), against what that one
install left:

- the env: modes, keys, the minted password -- the same on the second run,
  never printed --, ``docker compose config`` byte for byte;
- the build, migrations, up: labels on every container, volume, network and
  image, ``release``/``commit`` in ``/health``, nothing recreated by the
  second run, conformance, a planted ``max_body: 2M`` -- exactly ``max-body``;
- the routes: by ``Host`` on localhost, 301 to https, HSTS and ``nosniff``, a
  stranger ``Host`` gets no page;
- the tests in ``blank_test`` from the test target, ``current``,
  ``state.json``, the live database's head;
- docker (DM-53): the second run does not restart it; ``daemon_json`` alone in
  ``deploy``, on a ``daemon.json`` planted without the log driver, writes it
  again, restarts nothing and the app keeps its container;
- ``gc`` (DM-20): green in ``finally`` of both runs; a planted image labelled
  with a foreign commit goes when the ``gc`` timer's service runs, the
  unlabelled images, the release's own and the volumes stay; the renewal
  timer's service is green on the self-signed box; both timers are enabled and
  active.

The probe of DM-64 and the build mode of DM-61 run next, on the box the
install left. DM-64: the blank reaches
nothing outside the box; a release of it with ``egress`` reaches its host
through the machine's proxy and no other; the release after it, without
``egress``, has no proxy left. DM-61: a copy of the blank builds a skin
package of a local repository into its frontend -- a new version rebuilds on
the same commit, a skin its build refuses is red with the old one served,
another edition is another image. Both deploy through the same mirror.

Two short checks need no install: what a single-quoted value is to compose,
and that the tags certbot and squid are pinned by still name the pinned
digests. The file
runs after ``test_tier3_host.py`` (pytest takes a directory's files by
name): docker is on the runner only after the host steps.
"""

import json
import os
import shutil
from pathlib import Path

import pytest
import yaml

from pridem.report.schema import Verdict
from pridem.runner import CommandTimedOut, Stream, SubprocessRunner
from pridem.steps.compose import PROXY_URL as PROXY
from pridem.steps.edge import CERTBOT_IMAGE
from pridem.steps.egress import SQUID_IMAGE

PYTHON = "/opt/pridem/current/venv/bin/python"
BLANK = "https://github.com/inzoddwetrust/primer-blank.git"
BLANK_COMMIT = "0e82be562d186afc933b8779d91dddcae4278cea"
REF = "main"
RELEASE = f"/opt/blank/releases/{BLANK_COMMIT}"
ENV = Path("/opt/blank/env/.env")
MINTED = Path("/opt/blank/env/minted.yaml")
FRONTEND = "tier3-env.test"
API = "api.tier3-env.test"
JOURNAL_TAIL = 120
PLANTED_COMMIT = "f" * 40
PLANTED_IMAGE = "pridem-planted:dm20"
URL_SAFE = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-")
EGRESS_HOST = "api.github.com"
"""The blank's row of the list agreed with Primer (DM-64)."""
OTHER_HOST = "github.com"
"""A host the runner reaches directly and the blank's list does not name."""
GIT_ENV = {
    "PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
    "HOME": "/nonexistent",
    "GIT_CONFIG_GLOBAL": os.devnull,
    "GIT_CONFIG_NOSYSTEM": "1",
}
PLAN = """
import json
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
from pridem.stacks.passport import load_passport
from pridem.stacks.schema import load_primer_yaml
from pridem.stacks.seams import SeamMemory
from pridem.state import Box, JournalHeader
from pridem.steps.build import Build
from pridem.steps.egress import Egress
from pridem.steps.env import RenderEnv, SeamsCheck
from pridem.steps.finalize import FinalCheck, Finalize
from pridem.steps.frontend import Frontend
from pridem.steps.gc import GC_STACK, gc_steps
from pridem.steps.host import host_steps
from pridem.steps.migrate import Migrate
from pridem.steps.nginx import Nginx
from pridem.steps.packages import Packages
from pridem.steps.passport import passport_steps
from pridem.steps.sources import source_steps
from pridem.steps.ssl import Ssl, TlsFiles
from pridem.steps.tests import TestReport, Tests
from pridem.steps.timers import timer_steps
from pridem.steps.types import Types
from pridem.steps.up import Up

root, checkout, passport, mirror, commit, mode = (
    Path("/"), Path(sys.argv[1]), Path(sys.argv[2]), sys.argv[3], sys.argv[4],
    sys.argv[5],
)
blank = load_primer_yaml(checkout / "primer.yaml")
release = Path("/opt/blank/releases") / commit
box, secrets = Box(Path("/opt/pridem")), Secrets(())
memory, report = SeamMemory(), TestReport()
host, final = host_steps(root)
fetched, first = passport_steps(root, secrets=secrets, server=None, file=passport)
timers = timer_steps(root, fetched=fetched)
_, sources = source_steps(
    root, stack="blank", address=f"file://{mirror}", ref="main", tag=False,
    packages=load_passport(passport).packages,
)
render = RenderEnv(
    blank, product=blank, fetched=fetched, secrets=secrets, memory=memory, root=root
)
parts = {"release": release, "ref": "main", "commit": commit, "root": root}
ladder = [
    SeamsCheck(blank, {}, fetched), render,
    Build(blank, "blank", **parts, fetched=fetched),
    Packages(blank, "blank", **parts, fetched=fetched),
    Tests(blank, "blank", **parts, report=report, secrets=secrets, fetched=fetched),
    Migrate(blank, "blank", **parts, fetched=fetched),
    Egress(blank, root=root),
    Up(blank, "blank", **parts, memory=memory, render=render, fetched=fetched),
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
        JournalHeader(run_id=run_id, verb=mode, mode=mode, args={},
                      actor={"type": "machine", "via": "local"}, started=started,
                      composition_before={"pridem": __version__}),
        secrets,
    )
    clean = gc_steps(root, box=box, run_id=run_id, fetched=fetched)
    try:
        outcome = Plan(
            [StackSteps("host", host), StackSteps("passport", first),
             StackSteps("timers", timers),
             StackSteps("sources", sources), StackSteps("blank", ladder),
             StackSteps("types", types), StackSteps("edge", edge),
             StackSteps("frontend", front), StackSteps("finalize", tail, root=True)],
            mode=mode, role="test", runner=SubprocessRunner(),
            sink=Both(ConsoleSink(sys.stdout, secrets), journal),
            finally_=[StackSteps("host", final), StackSteps(GC_STACK, clean)],
        ).run()
    finally:
        journal.close()
    if mode == "doctor":  # what doctor would do, and what it found red
        print("DIFF " + json.dumps([item.reason.code for item in outcome.doctor_diff]))
        failed = [r.reason.code for r in outcome.steps if r.reason is not None]
        print("FAILED " + json.dumps(failed))
        sys.exit(0)
    every = [*host, *first, *timers, *sources, *ladder, *types, *edge, *front, *tail,
             *final, *clean]
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
DAEMON_JSON_DEPLOY = """
import json
from pathlib import Path
from pridem.plan import Plan, StackSteps
from pridem.runner import SubprocessRunner
from pridem.steps.host import DaemonJson

class Sink:
    def emit(self, event):
        pass

outcome = Plan(
    [StackSteps("host", [DaemonJson(Path("/"))], root=True)],
    mode="deploy", role="test", runner=SubprocessRunner(), sink=Sink(),
).run()
print("OUTCOME " + json.dumps({"code": int(outcome.code)}))
"""
"""``daemon_json`` alone in ``deploy`` on the installed box (DM-53)."""

PLANTED = """
import json, sys
from pathlib import Path
from pridem.conformance.stack import check_stack, observe, problems_param
from pridem.runner import SubprocessRunner
from pridem.stacks.schema import load_primer_yaml
from pridem.steps.base import StepContext

release, env_file, planted = Path(sys.argv[1]), Path(sys.argv[2]), Path(sys.argv[3])
stack = load_primer_yaml(release / "primer.yaml")
ctx = StepContext(
    runner=SubprocessRunner(), mode="install", role="test", stack="blank",
    on_line=lambda stream, line, cut: None,
)
seen = observe(ctx, stack, "blank", release=release, project="blank", env_file=env_file)
print("PROBLEMS " + json.dumps(problems_param(check_stack(stack, "blank", seen))))
other = load_primer_yaml(planted)
print("PLANTED " + json.dumps(problems_param(check_stack(other, "blank", seen))))
"""


def _run(
    argv: list[str],
    timeout: float = 120,
    expect: tuple[int, ...] = (0,),
    env: dict[str, str] | None = None,
) -> list[str]:
    """Every line of ``argv``, stdout and stderr; on a timeout, all of them."""
    lines: list[str] = []

    def keep(stream: Stream, line: str, cut: bool) -> None:
        lines.append(line)

    try:
        SubprocessRunner().run(
            argv, expect=expect, timeout=timeout, env=env, on_line=keep
        )
    except CommandTimedOut:
        raise AssertionError("\n".join(lines)) from None
    return lines


def _docker_started() -> str:
    """When the running docker daemon started: changes on every restart."""
    [line] = _stdout(
        ["systemctl", "show", "docker", "--property", "ActiveEnterTimestampMonotonic"]
    )
    return line


def _stdout(argv: list[str], timeout: float = 300) -> list[str]:
    out: list[str] = []

    def keep(stream: Stream, line: str, cut: bool) -> None:
        if stream is Stream.STDOUT:
            out.append(line)

    SubprocessRunner().run(argv, timeout=timeout, on_line=keep)
    return out


def _blank(tmp: Path) -> Path:
    checkout = tmp / "blank"
    _run(["git", "clone", "-q", BLANK, str(checkout)], 300, env=GIT_ENV)
    _run(["git", "-C", str(checkout), "checkout", "-q", BLANK_COMMIT], env=GIT_ENV)
    return checkout


def _passport(
    tmp: Path,
    *,
    version: int = 1,
    edition: str = "core",
    packages: dict[str, dict[str, str]] | None = None,
) -> Path:
    data = {
        "schema": 1,
        "version": version,
        "server": {"name": "tier3-env", "role": "test", "os": "ubuntu-24.04"},
        "edition": edition,
        "product": {"repo": BLANK, "ref": REF},
        "domains": {"frontend": FRONTEND, "api": API},
        "access": {"mode": "deploy-keys"},
        "asked": {},
        "params": {},
        "policies": {
            "ssl": "self-signed",
            "gc": {
                "keep_releases": 2,
                "builder_cache_budget": "3G",
                "journal_budget": "200M",
            },
            "backup": {"enabled": False},
            "timers": {"gc": "daily"},
        },
        "packages": packages or {},
        "cloud": {},
    }
    file = tmp / f"passport-{version}.yaml"
    file.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
    return file


def _verdicts(verb: str) -> Verdict:
    """The one verdict of ``verb`` in the box's history."""
    found = [
        Verdict.model_validate_json(path.read_text(encoding="utf-8"))
        for path in sorted(Path("/opt/pridem/history").glob("*.json"))
    ]
    [one] = [v for v in found if v.verb == verb]
    return one


def _journal_tail(verdict: Verdict) -> str:
    """The end of the run's journal: the console shows no command output."""
    if verdict.log_ref is None:  # a verb of the box always keeps one
        return "\n(the verdict names no journal)"
    journal = Path("/opt/pridem") / verdict.log_ref
    if not journal.is_file():
        return f"\n(no journal at {journal})"
    tail = journal.read_text(encoding="utf-8").splitlines()[-JOURNAL_TAIL:]
    return "\n--- journal tail ---\n" + "\n".join(tail)


def _install(
    checkout: Path,
    passport: Path,
    mirror: Path,
    commit: str = BLANK_COMMIT,
    mode: str = "install",
) -> tuple[Verdict, str]:
    lines = _run(
        [
            PYTHON,
            "-c",
            PLAN,
            str(checkout),
            str(passport),
            str(mirror),
            commit,
            mode,
        ],
        timeout=3600,
        expect=(0, 1, 2),
    )
    printed = "\n".join(lines)
    [line] = [x for x in lines if x.startswith("VERDICT ")]
    verdict = Verdict.model_validate_json(line.removeprefix("VERDICT "))
    if verdict.result != "green":
        printed += _journal_tail(verdict)
    return verdict, printed


def _env() -> dict[str, str]:
    out: dict[str, str] = {}
    for line in ENV.read_text(encoding="utf-8").splitlines():
        key, _, quoted = line.partition("=")
        assert quoted.startswith("'") and quoted.endswith("'"), key
        out[key] = quoted[1:-1]
    return out


def _config(compose_file: Path, env_file: Path) -> dict[str, dict[str, str]]:
    """``environment`` of every service as compose interpolates it."""
    text = "\n".join(
        _stdout(
            [
                "docker",
                "compose",
                "-p",
                "blank",
                "--env-file",
                str(env_file),
                "-f",
                str(compose_file),
                "config",
                "--format",
                "json",
            ]
        )
    )
    services = json.loads(text)["services"]
    return {name: service.get("environment", {}) for name, service in services.items()}


def _labels(kind: str, name: str) -> dict[str, str]:
    [text] = _stdout(["docker", kind, "inspect", "-f", "{{json .Labels}}", name])
    found = json.loads(text) or {}
    assert isinstance(found, dict)
    return found


def _app() -> str:
    [container] = _stdout(
        [
            "docker",
            "ps",
            "-q",
            "--filter",
            "label=com.docker.compose.project=blank",
            "--filter",
            "label=com.docker.compose.service=app",
        ]
    )
    return container


def _curl(tmp: Path, url: str, host: str) -> tuple[str, str]:
    """``(status, headers)`` of one request; ``000`` -- no answer."""
    headers = tmp / "headers.txt"
    headers.unlink(missing_ok=True)
    lines = _run(
        [
            "curl",
            "-k",
            "-sS",
            "--max-time",
            "10",
            "-H",
            f"Host: {host}",
            "-D",
            str(headers),
            "-o",
            str(tmp / "body"),
            "-w",
            "%{http_code} %{redirect_url}",
            url,
        ],
        expect=(0, 52, 35, 56),
    )
    text = headers.read_text(encoding="latin-1") if headers.exists() else ""
    return (lines[-1] if lines else "000"), text.lower()


@pytest.fixture(scope="module")
def mirror(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """The blank's mirror the sources fetch from: one for the whole install and
    for the deploys of DM-64, which push their own commits to it."""
    return tmp_path_factory.mktemp("mirror") / "blank-mirror.git"


def test_tier3_the_whole_install_of_the_blank(tmp_path: Path, mirror: Path) -> None:
    checkout, passport = _blank(tmp_path), _passport(tmp_path)
    _run(["git", "clone", "-q", "--mirror", str(checkout), str(mirror)])
    _run(
        ["git", "--git-dir", str(mirror), "update-ref", "refs/heads/main", BLANK_COMMIT]
    )

    verdict, printed = _install(checkout, passport, mirror)

    # the install (R1, W1)
    assert verdict.result == "green", printed
    facts = {(s.stack, s.name): s.verify or {} for s in verdict.steps}
    # the env (R2-R8)
    assert oct(ENV.stat().st_mode & 0o777) == oct(0o600), printed
    assert oct(ENV.parent.stat().st_mode & 0o777) == oct(0o700), printed
    assert oct(MINTED.stat().st_mode & 0o777) == oct(0o600), printed
    env = _env()
    assert sorted(env) == ["API_BASE_URL", "EDITION", "POSTGRES_PASSWORD"], printed
    password = env["POSTGRES_PASSWORD"]
    assert len(password) >= 32 and set(password) <= URL_SAFE, printed
    assert (env["EDITION"], env["API_BASE_URL"]) == ("core", API), printed
    assert password not in printed  # neither the console nor the verdict
    # build, migrate, up (U1-U3)
    up, build = facts[("blank", "up")], facts[("blank", "build")]
    assert (up["release"], up["commit"]) == (REF, BLANK_COMMIT), printed
    assert up["image"] == build["app_image"], printed
    assert facts[("blank", "migrate")].get("alembic_head") == "0001", printed
    # the tests, the final check, current, state.json (DM-19)
    tests = facts[("blank", "tests")]
    assert tests["test_db"] == "blank_test" and tests["target"] == "test", printed
    junit = tests["junit"]
    assert isinstance(junit, dict), printed
    total, failed = junit["total"], junit["failed"]
    assert isinstance(total, int) and total > 0 and failed == 0, printed
    assert verdict.junit is not None and verdict.junit.total == total, printed
    verified = facts[("finalize", "final_check")]["verified"]
    assert isinstance(verified, int) and verified > 10, printed
    assert str(Path("/opt/blank/current").readlink()) == RELEASE, printed
    state = json.loads(Path("/opt/pridem/state.json").read_text())
    assert state["current"] == {"blank": BLANK_COMMIT}, state
    assert state["composition"]["blank"] == BLANK_COMMIT, state
    container = _app()
    started = _docker_started()

    # the second run (R9, U4): the same password, nothing recreated, not printed
    again, printed_again = _install(checkout, passport, mirror)
    # ... and docker not restarted: daemon.json already as drawn (DM-53)
    assert _docker_started() == started, printed_again

    assert again.result == "green", printed_again
    assert _env()["POSTGRES_PASSWORD"] == password
    assert password not in printed_again
    assert _app() == container, printed_again

    # doctor on an unchanged box: nothing to do (TZ 7.1; DM-51)
    out = _run(
        [
            PYTHON,
            "-c",
            PLAN,
            str(checkout),
            str(passport),
            str(mirror),
            BLANK_COMMIT,
            "doctor",
        ],
        timeout=1800,
    )
    [diff] = [x for x in out if x.startswith("DIFF ")]
    [red] = [x for x in out if x.startswith("FAILED ")]
    assert json.loads(diff.removeprefix("DIFF ")) == [], out
    assert json.loads(red.removeprefix("FAILED ")) == [], out

    # compose config byte for byte (R10)
    compose_file = Path(RELEASE) / "docker-compose.yml"
    config = _config(compose_file, ENV)
    assert config["app"]["DATABASE_URL"] == (
        f"postgresql+asyncpg://blank:{password}@postgres:5432/blank"
    )
    assert config["app"]["EDITION"] == "core"
    assert config["frontend"]["API_BASE_URL"] == API
    assert config["postgres"]["POSTGRES_PASSWORD"] == password

    # labels (U5-U8)
    release = {
        "pridem.stack": "blank",
        "pridem.release": REF,
        "pridem.commit": BLANK_COMMIT,
    }
    project = "label=com.docker.compose.project=blank"
    containers = _stdout(["docker", "ps", "-a", "-q", "--filter", project])
    assert len(containers) == 3  # app, frontend, postgres; throwaways are gone
    for name in containers:
        [text] = _stdout(["docker", "inspect", "-f", "{{json .Config.Labels}}", name])
        labels = json.loads(text)
        assert {k: labels.get(k) for k in release} == release, name
    volumes = _stdout(["docker", "volume", "ls", "-q", "--filter", project])
    assert volumes
    for name in volumes:
        labels = _labels("volume", name)
        assert labels.get("pridem.stack") == "blank" and "pridem.release" not in labels
    network = _labels("network", "blank_default")
    assert network.get("pridem.stack") == "blank" and "pridem.release" not in network
    by_service: dict[str, list[str]] = {}
    images = sorted(
        set(
            _stdout(
                [
                    "docker",
                    "image",
                    "ls",
                    "-q",
                    "--no-trunc",
                    "--filter",
                    "label=pridem.stack=blank",
                ]
            )
        )
    )
    for image in images:
        [text] = _stdout(
            ["docker", "image", "inspect", "-f", "{{json .Config.Labels}}", image]
        )
        labels = json.loads(text)
        assert {k: labels.get(k) for k in release} == release, image
        by_service.setdefault(labels.get("pridem.service", ""), []).append(image)
    # one image each of app and frontend, and the tests' image (DM-19); postgres
    # is pulled, not built
    assert sorted(by_service) == ["app", "app-test", "frontend"], by_service
    assert all(len(found) == 1 for found in by_service.values()), by_service

    # conformance of the live blank, and a planted max_body on the same look (U9)
    planted = tmp_path / "planted-primer.yaml"
    text = (checkout / "primer.yaml").read_text(encoding="utf-8")
    assert text.count("max_body: 1M") == 1
    planted.write_text(text.replace("max_body: 1M", "max_body: 2M"), encoding="utf-8")
    seen = _run([PYTHON, "-c", PLANTED, RELEASE, str(ENV), str(planted)], timeout=300)
    shown = "\n".join(seen)
    [problems] = [x for x in seen if x.startswith("PROBLEMS ")]
    [found] = [x for x in seen if x.startswith("PLANTED ")]
    assert json.loads(problems.removeprefix("PROBLEMS ")) == [], shown
    assert json.loads(found.removeprefix("PLANTED ")) == [
        "max-body route=api max_body=2M max_upload_mb=1"
    ], shown

    # the routes by Host (W2-W5)
    front, front_headers = _curl(tmp_path, "https://localhost/", FRONTEND)
    assert front.startswith("200"), front
    assert "strict-transport-security: max-age=31536000" in front_headers
    assert "x-content-type-options: nosniff" in front_headers
    # /health and /ready are not seen from outside (protocol 9.3, FIX 3 of
    # DM-55): nginx answers 404 itself -- the app answers /health 200 -- and
    # the rest of the route is proxied (FastAPI's /openapi.json of the blank)
    for closed in ("/health", "/ready"):
        api, _ = _curl(tmp_path, f"https://localhost{closed}", API)
        assert api.startswith("404"), (closed, api)
    api, _ = _curl(tmp_path, "https://localhost/openapi.json", API)
    assert api.startswith("200"), api
    plain, _ = _curl(tmp_path, "http://localhost/", FRONTEND)
    assert plain == f"301 https://{FRONTEND}/", plain
    stranger, _ = _curl(tmp_path, "https://localhost/", "nobody.example.org")
    assert not stranger.startswith("200"), stranger

    # the live database kept its head; the tests had their own
    compose = [
        "docker",
        "compose",
        "-p",
        "blank",
        "--env-file",
        str(ENV),
        "-f",
        str(compose_file),
    ]
    head = _stdout(
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
    test_db = _stdout(
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

    # daemon_json in deploy (DM-53): a daemon.json without the log driver on a
    # box that runs is written again, docker is not restarted, the app lives on
    daemon_json = Path("/etc/docker/daemon.json")
    planted = json.loads(daemon_json.read_text(encoding="utf-8"))
    planted.pop("log-driver")
    daemon_json.write_text(json.dumps(planted), encoding="utf-8")
    seen = _run([PYTHON, "-c", DAEMON_JSON_DEPLOY], timeout=300)
    [outcome] = [x for x in seen if x.startswith("OUTCOME ")]
    assert json.loads(outcome.removeprefix("OUTCOME ")) == {"code": 0}, seen
    assert json.loads(daemon_json.read_text(encoding="utf-8"))["log-driver"] == "local"
    assert _docker_started() == started, seen
    assert _app() == container, seen

    # gc (DM-20): in finally of both runs, by its timer, by labels only
    for run in (verdict, again):
        [gc] = [s for s in run.steps if (s.phase, s.name) == ("finally", "gc")]
        assert gc.status == "ok" and gc.verify is not None, run.steps
        assert {"before", "after", "removed", "kept"} <= set(gc.verify), gc.verify
    every_image = set(_stdout(["docker", "image", "ls", "-q", "--no-trunc"]))
    unlabelled = every_image - set(images)
    assert unlabelled, every_image  # postgres, nginx: pulled, never labelled
    volumes_before = sorted(_stdout(["docker", "volume", "ls", "-q"]))
    assert volumes_before
    [nginx] = _stdout(
        [
            "docker",
            "ps",
            "-q",
            "--filter",
            "label=com.docker.compose.project=pridem-edge",
            "--filter",
            "label=com.docker.compose.service=nginx",
        ]
    )
    _run(
        [
            "docker",
            "commit",
            "--pause=false",
            "--change",
            "LABEL pridem.stack=planted",
            "--change",
            f"LABEL pridem.commit={PLANTED_COMMIT}",
            nginx,
            PLANTED_IMAGE,
        ]
    )
    [planted_id] = _stdout(
        ["docker", "image", "inspect", "-f", "{{.Id}}", PLANTED_IMAGE]
    )
    _run(["systemctl", "start", "pridem-gc.service"], timeout=1800)
    by_timer = _verdicts("gc")
    assert (by_timer.result, by_timer.actor.type, by_timer.actor.via) == (
        "green",
        "machine",
        "timer",
    ), _journal_tail(by_timer)
    [step] = by_timer.steps
    removed = (step.verify or {}).get("removed")
    assert isinstance(removed, dict), step
    assert removed["images"] == [planted_id.removeprefix("sha256:")[:12]], removed
    left = set(_stdout(["docker", "image", "ls", "-q", "--no-trunc"]))
    assert planted_id not in left
    assert unlabelled | set(images) <= left, left
    assert sorted(_stdout(["docker", "volume", "ls", "-q"])) == volumes_before
    # the renewal by its timer: self-signed, so certbot is not called
    _run(["systemctl", "start", "pridem-ssl-renew.service"], timeout=900)
    renewed = _verdicts("ssl renew")
    assert (renewed.result, renewed.actor.via) == ("green", "timer"), _journal_tail(
        renewed
    )
    assert [s.name for s in renewed.steps] == ["ssl_renew"], renewed.steps
    assert (renewed.steps[0].verify or {}).get("mode") == "self-signed", renewed.steps
    for timer in ("pridem-gc.timer", "pridem-ssl-renew.timer"):
        assert _stdout(["systemctl", "is-enabled", timer]) == ["enabled"], timer
        assert _stdout(["systemctl", "is-active", timer]) == ["active"], timer
    # DM-54: the renewal timer has its random delay in the unit and in what
    # systemd loaded; gc has none
    renew_unit = _stdout(["systemctl", "cat", "pridem-ssl-renew.timer"])
    assert "RandomizedDelaySec=1h" in renew_unit, renew_unit
    gc_unit = _stdout(["systemctl", "cat", "pridem-gc.timer"])
    assert not [line for line in gc_unit if "RandomizedDelaySec" in line], gc_unit
    loaded = ["systemctl", "show", "--property", "RandomizedDelayUSec"]
    assert _stdout([*loaded, "pridem-ssl-renew.timer"]) == ["RandomizedDelayUSec=1h"]
    assert _stdout([*loaded, "pridem-gc.timer"]) == ["RandomizedDelayUSec=0"]


REACH = """
import json, os, socket, sys, urllib.error, urllib.request
allowed, other, address = sys.argv[1:4]
def direct(host):
    try:
        socket.create_connection((host, 443), timeout=5).close()
        return "reached"
    except OSError as error:
        return type(error).__name__
def via(host):
    try:
        urllib.request.urlopen(f"https://{host}/", timeout=30)
        return "reached"
    except urllib.error.HTTPError:
        return "reached"  # the host answered, whatever it said
    except (urllib.error.URLError, OSError) as error:
        return "not reached: " + str(getattr(error, "reason", error))
print("REACH " + json.dumps({
    "HTTPS_PROXY": os.environ.get("HTTPS_PROXY"),
    "https_proxy": os.environ.get("https_proxy"),
    "direct_allowed": direct(allowed),
    "direct_address": direct(address),
    "via_allowed": via(allowed),
    "via_other": via(other),
}))
"""
"""Run in the blank's app: what it reaches, directly and through its proxy."""


def _reach() -> dict[str, str | None]:
    """What the blank's app reaches: ``EGRESS_HOST`` and an address of
    ``OTHER_HOST`` directly, both hosts through ``HTTPS_PROXY`` when it has one."""
    [address] = _stdout(["getent", "ahostsv4", OTHER_HOST])[:1]
    ip = address.split()[0]
    lines = _run(
        ["docker", "exec", _app(), "python", "-c", REACH, EGRESS_HOST, OTHER_HOST, ip],
        timeout=180,
    )
    [line] = [x for x in lines if x.startswith("REACH ")]
    found = json.loads(line.removeprefix("REACH "))
    assert isinstance(found, dict)
    return found


def _internal(network: str) -> str:
    [value] = _stdout(["docker", "network", "inspect", "-f", "{{.Internal}}", network])
    return value


def _proxies() -> list[str]:
    return _stdout(
        ["docker", "ps", "-a", "-q", "--filter", "label=pridem.stack=egress"]
    )


def _git(*args: str) -> list[str]:
    identity = ["-c", "user.name=tier3", "-c", "user.email=tier3@pridem.invalid"]
    return _stdout(["git", *identity, *args])


def test_probe_DM_64_product_reaches_only_its_egress_hosts(
    tmp_path: Path, mirror: Path
) -> None:
    """The blank -- on the box the whole install left -- reaches nothing outside
    the box; a release of it with ``egress: [api.github.com]`` reaches that host
    through the machine's proxy and not ``github.com``, and still nothing
    directly; the release after it, without ``egress``, has no proxy left
    (protocol 4.1, 4.2). The pair: the host of ``egress`` is reached."""
    assert Path("/opt/blank/current").is_symlink(), "the whole install runs first"
    passport = _passport(tmp_path)
    # the blank without egress: every network internal, no proxy, no way out
    for network in ("pridem", "pridem-egress", "blank_default"):
        assert _internal(network) == "true", network
    assert _proxies() == []
    before = _reach()
    assert before["HTTPS_PROXY"] is None and before["https_proxy"] is None, before
    for key in ("direct_allowed", "direct_address", "via_allowed", "via_other"):
        assert before[key] != "reached", before

    # a release with egress
    [base] = _stdout(["git", "--git-dir", str(mirror), "rev-parse", "refs/heads/main"])
    copy = tmp_path / "blank-egress"
    _run(["git", "clone", "-q", str(mirror), str(copy)], env=GIT_ENV)
    primer = copy / "primer.yaml"
    text = primer.read_text(encoding="utf-8")
    assert "egress" not in text
    primer.write_text(text + f"egress:\n  - {EGRESS_HOST}\n", encoding="utf-8")
    _git("-C", str(copy), "commit", "-q", "-am", "DM-64: egress of the blank")
    [commit] = _git("-C", str(copy), "rev-parse", "HEAD")
    _git("-C", str(copy), "push", "-q", str(mirror), "HEAD:refs/heads/main")
    verdict, printed = _install(copy, passport, mirror, commit, "deploy")
    assert verdict.result == "green", printed
    facts = {(s.stack, s.name): s.verify or {} for s in verdict.steps}
    egress = facts[("blank", "egress")]
    assert egress["hosts"] == [EGRESS_HOST], egress
    allowed = egress["allowed"]
    assert isinstance(allowed, dict) and allowed[EGRESS_HOST] != 403, egress
    assert len(_proxies()) == 1
    after = _reach()
    assert after["HTTPS_PROXY"] == after["https_proxy"] == PROXY, after
    assert after["via_allowed"] == "reached", after  # the pair
    other = after["via_other"]
    assert isinstance(other, str) and other.startswith("not reached"), after
    assert "403" in other, after  # refused by the proxy itself
    assert after["direct_allowed"] != "reached", after
    assert after["direct_address"] != "reached", after
    # doctor on that box: nothing to do
    out = _run(
        [PYTHON, "-c", PLAN, str(copy), str(passport), str(mirror), commit, "doctor"],
        timeout=1800,
    )
    [diff] = [x for x in out if x.startswith("DIFF ")]
    [red] = [x for x in out if x.startswith("FAILED ")]
    assert json.loads(diff.removeprefix("DIFF ")) == [], out
    assert json.loads(red.removeprefix("FAILED ")) == [], out
    # the routes still answer: nginx publishes through its own network
    api, _ = _curl(tmp_path, "https://localhost/openapi.json", API)
    assert api.startswith("200"), api

    # the release after it, without egress: the proxy is gone, no way out still
    _run(["git", "--git-dir", str(mirror), "update-ref", "refs/heads/main", base])
    _run(["git", "-C", str(copy), "checkout", "-q", base], env=GIT_ENV)
    back, printed = _install(copy, passport, mirror, base, "deploy")
    assert back.result == "green", printed
    facts = {(s.stack, s.name): s.verify or {} for s in back.steps}
    assert facts[("blank", "egress")] == {"hosts": [], "proxy": "absent"}, facts
    assert _proxies() == []
    assert not Path("/opt/pridem/egress/squid.conf").exists()
    last = _reach()
    assert last["HTTPS_PROXY"] is None, last
    for key in ("direct_allowed", "direct_address", "via_allowed", "via_other"):
        assert last[key] != "reached", last


SKIN_DOCKERFILE_CHECK = """COPY . .
RUN test -f public/skin/skin.css
ARG PRIMER_EDITION
RUN test -n "$PRIMER_EDITION" && printf '%s' "$PRIMER_EDITION" > public/edition.txt
"""
"""What the blank's copy of DM-61 adds to the build stage of its frontend: the
skin is checked by the build -- none, and the build fails -- and the edition
the build got is served at ``/edition.txt``."""


EDITIONS_LINE = 'EDITIONS: dict[str, tuple[str, ...]] = {"core": ()}\n'
EDITIONS_FULL = 'EDITIONS: dict[str, tuple[str, ...]] = {"core": (), "full": ()}\n'
"""The blank's backend table of editions (``backend/app/editions.py``) and
the one of the DM-61 copy, which declares ``full`` in ``primer.yaml`` too."""


def _app_health() -> dict[str, object]:
    """``/health`` of the blank's app, read inside its container: nginx closes
    it on the public routes (protocol 9.3)."""
    read = "import urllib.request; print(urllib.request.urlopen("
    read += "'http://127.0.0.1:8000/health', timeout=5).read().decode())"
    [line] = _stdout(["docker", "exec", _app(), "python", "-c", read])
    found = json.loads(line)
    assert isinstance(found, dict)
    return found


def _skin_repository(tmp: Path) -> Path:
    """A skin package, three tags: ``v1.0.0`` (``one``), ``v1.1.0`` (``two``)
    and ``v1.2.0`` with no ``skin.css`` -- the build of the blank refuses it."""
    work = tmp / "skin-work"
    work.mkdir()
    _git("init", "-q", str(work))
    (work / "primer-package.yaml").write_text('schema: 1\ncontract: "1.0"\n')
    for tag, text in (("v1.0.0", "one"), ("v1.1.0", "two"), ("v1.2.0", None)):
        skin = work / "skin.css"
        if text is None:
            skin.unlink()
        else:
            skin.write_text(text)
        _git("-C", str(work), "add", "-A")
        _git("-C", str(work), "commit", "-q", "-m", tag)
        _git("-C", str(work), "tag", tag)
    bare = tmp / "skin.git"
    _run(["git", "clone", "-q", "--bare", str(work), str(bare)], env=GIT_ENV)
    return bare


def _body(path: str, host: str) -> str:
    lines = _stdout(
        [
            "curl",
            "-k",
            "-sS",
            "--max-time",
            "10",
            "-H",
            f"Host: {host}",
            f"https://localhost{path}",
        ]
    )
    return "\n".join(lines)


def _frontend_images() -> dict[str, str]:
    """The images of the blank's frontend by their key: ``<edition> <package>``."""
    ids = _stdout(
        [
            "docker",
            "image",
            "ls",
            "-q",
            "--no-trunc",
            "--filter",
            "label=pridem.service=frontend",
            "--filter",
            "label=pridem.stack=blank",
            "--filter",
            "label=pridem.edition",
        ]
    )
    found: dict[str, str] = {}
    for image in sorted(set(ids)):
        [text] = _stdout(
            ["docker", "image", "inspect", "-f", "{{json .Config.Labels}}", image]
        )
        labels = json.loads(text)
        found[f"{labels['pridem.edition']} {labels['pridem.package.skin']}"] = image
    return found


def test_tier3_build_mode_of_the_blank(tmp_path: Path, mirror: Path) -> None:
    """DM-61 on the box the install left: a copy of the blank builds a skin
    into its frontend (``apply: build``); a new version of the skin rebuilds on
    the same commit; a skin its build refuses is red and the old one stays
    served; another edition is another image."""
    assert Path("/opt/blank/current").is_symlink(), "the whole install runs first"
    skin = _skin_repository(tmp_path)

    def passport(version: int, tag: str, edition: str = "core") -> Path:
        package = {"skin": {"repo": f"file://{skin}", "version": tag}}
        return _passport(tmp_path, version=version, edition=edition, packages=package)

    # the copy: a second edition, the skin built into frontend, checked there
    [base] = _stdout(["git", "--git-dir", str(mirror), "rev-parse", "refs/heads/main"])
    copy = tmp_path / "blank-skin"
    _run(["git", "clone", "-q", str(mirror), str(copy)], env=GIT_ENV)
    _run(["git", "-C", str(copy), "checkout", "-q", base], env=GIT_ENV)
    primer = copy / "primer.yaml"
    text = primer.read_text(encoding="utf-8")
    text = text.replace(
        "  core: { services: [] }\n",
        "  core: { services: [] }\n  full: { services: [] }\n",
    )
    text += (
        'packages:\n  skin:\n    contract: ">=1,<2"\n    apply: build\n'
        "    build:\n      - { service: frontend, path: public/skin }\n"
    )
    primer.write_text(text, encoding="utf-8")
    dockerfile = copy / "frontend" / "Dockerfile"
    body = dockerfile.read_text(encoding="utf-8")
    assert body.count("COPY . .\n") == 1
    dockerfile.write_text(body.replace("COPY . .\n", SKIN_DOCKERFILE_CHECK))
    # the backend's own table of editions knows full too (protocol: the table
    # "edition -> modules" is the product's; the backend refuses another)
    editions = copy / "backend" / "app" / "editions.py"
    table = editions.read_text(encoding="utf-8")
    assert table.count(EDITIONS_LINE) == 1
    editions.write_text(table.replace(EDITIONS_LINE, EDITIONS_FULL))
    _git("-C", str(copy), "commit", "-q", "-am", "DM-61: the skin built into frontend")
    [commit] = _git("-C", str(copy), "rev-parse", "HEAD")
    _git("-C", str(copy), "push", "-q", str(mirror), "HEAD:refs/heads/main")

    # version 1.0.0, edition core: built with the skin
    first, printed = _install(copy, passport(2, "1.0.0"), mirror, commit, "deploy")
    assert first.result == "green", printed
    facts = {(s.stack, s.name): s.verify or {} for s in first.steps}
    keys = facts[("blank", "build")]["keys"]
    assert keys == {
        "frontend": {"pridem.edition": "core", "pridem.package.skin": "skin@1.0.0"}
    }, keys
    assert _body("/skin/skin.css", FRONTEND) == "one"
    assert _body("/edition.txt", FRONTEND) == "core"
    assert _app_health()["edition"] == "core"
    images = facts[("blank", "build")]["images"]
    assert isinstance(images, dict)

    # version 1.1.0 on the same commit: frontend rebuilt, app the same image
    second, printed = _install(copy, passport(3, "1.1.0"), mirror, commit, "deploy")
    assert second.result == "green", printed
    facts = {(s.stack, s.name): s.verify or {} for s in second.steps}
    again = facts[("blank", "build")]["images"]
    assert isinstance(again, dict)
    assert again["frontend"] != images["frontend"], (images, again)
    assert again["app"] == images["app"], (images, again)
    assert _body("/skin/skin.css", FRONTEND) == "two"

    # the same version again: no build (the step has nothing to do)
    same, printed = _install(copy, passport(3, "1.1.0"), mirror, commit, "deploy")
    assert same.result == "green", printed
    [build] = [s for s in same.steps if (s.stack, s.name) == ("blank", "build")]
    assert build.status == "ok" and build.verify is not None, build
    assert build.verify["images"] == again, (again, build.verify)

    # version 1.2.0 has no skin.css: the build is red, version 1.1.0 stays
    bad, printed = _install(copy, passport(4, "1.2.0"), mirror, commit, "deploy")
    assert bad.result != "green", printed
    [red] = [s for s in bad.steps if s.status == "failed"]
    assert (red.stack, red.name) == ("blank", "build"), bad.steps
    assert _body("/skin/skin.css", FRONTEND) == "two"

    # edition full, version 1.1.0: another image beside core's
    full, printed = _install(
        copy, passport(5, "1.1.0", "full"), mirror, commit, "deploy"
    )
    assert full.result == "green", printed
    assert _body("/edition.txt", FRONTEND) == "full"
    # the pair on the backend: EDITION of the passport reached app
    assert _app_health()["edition"] == "full"
    found = _frontend_images()
    assert {"core skin@1.1.0", "full skin@1.1.0"} <= set(found), found
    assert found["core skin@1.1.0"] != found["full skin@1.1.0"]
    # doctor on that box: nothing to do
    out = _run(
        [
            PYTHON,
            "-c",
            PLAN,
            str(copy),
            str(passport(5, "1.1.0", "full")),
            str(mirror),
            commit,
            "doctor",
        ],
        timeout=1800,
    )
    [diff] = [x for x in out if x.startswith("DIFF ")]
    [failed] = [x for x in out if x.startswith("FAILED ")]
    assert json.loads(diff.removeprefix("DIFF ")) == [], out
    assert json.loads(failed.removeprefix("FAILED ")) == [], out


def _check(directory: Path) -> tuple[int, dict[str, object]]:
    """``pridem --json check`` of ``directory``: its exit code and verdict."""
    out: list[str] = []

    def keep(stream: Stream, line: str, cut: bool) -> None:
        if stream is Stream.STDOUT:
            out.append(line)

    done = SubprocessRunner().run(
        ["/usr/local/bin/pridem", "--json", "check", str(directory)],
        expect=(0, 1, 2),
        timeout=300,
        on_line=keep,
    )
    verdict = json.loads("\n".join(out))
    assert isinstance(verdict, dict)
    return done.code, verdict


def test_tier3_check_of_the_blank_and_of_a_planted_copy(tmp_path: Path) -> None:
    """DM-57: ``pridem check`` of the blank's repository with the real
    ``docker compose`` -- after the whole install, whose ``provision_host``
    put docker back on the runner (tier 3 removes the runner's own first) --
    is green; a copy with ``privileged`` on its app is red by name."""
    _stdout(["docker", "compose", "version"])  # the precondition, said loudly
    checkout = _blank(tmp_path)
    code, verdict = _check(checkout)
    assert (code, verdict["result"]) == (0, "green"), verdict
    planted = tmp_path / "planted"
    shutil.copytree(checkout, planted, ignore=shutil.ignore_patterns(".git"))
    compose = planted / "docker-compose.yml"
    text = compose.read_text(encoding="utf-8")
    assert text.count("\n  app:\n") == 1
    compose.write_text(text.replace("\n  app:\n", "\n  app:\n    privileged: true\n"))
    code, verdict = _check(planted)
    assert (code, verdict["result"]) == (1, "red"), verdict
    found = json.dumps(verdict["steps"])
    assert "compose:compose-forbidden" in found and "app: privileged" in found, found


def test_tier3_compose_takes_a_single_quoted_value_as_it_is(tmp_path: Path) -> None:
    """R11: what a single-quoted value is to compose's ``--env-file``."""
    checkout = _blank(tmp_path)
    literal = 'a$b ${HOME} #d "e" \\f'  # no "$$": config may print "$" as "$$"
    env_file = tmp_path / "measure.env"
    env_file.write_text(
        f"POSTGRES_PASSWORD='{literal}'\nEDITION='core'\nAPI_BASE_URL='{API}'\n",
        encoding="utf-8",
    )
    config = _config(checkout / "docker-compose.yml", env_file)
    # ``config`` writes a literal "$" back as "$$" to keep its output a valid
    # compose file; an interpolated ``${HOME}`` would not come back at all
    assert config["postgres"]["POSTGRES_PASSWORD"].replace("$$", "$") == literal


@pytest.mark.parametrize("image", [CERTBOT_IMAGE, SQUID_IMAGE])
def test_tier3_certbot_tag_has_the_pinned_digest(image: str) -> None:
    """W6 (DM-49): the tag ``CERTBOT_IMAGE`` names still points at its digest;
    so does the tag of ``SQUID_IMAGE``, the proxy of DM-64. Not so -- red with
    the tag's digests as measured, for the next pin."""
    tag, _, digest = image.partition("@")
    repository = tag.rpartition(":")[0]
    _run(["docker", "pull", "-q", tag], timeout=300)
    digests = json.loads(
        "\n".join(
            _stdout(["docker", "image", "inspect", "-f", "{{json .RepoDigests}}", tag])
        )
    )
    assert f"{repository}@{digest}" in digests, (tag, digests)
