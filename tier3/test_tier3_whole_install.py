"""Tier 3 probe (DM-19, DM-50): the whole ``install`` of ``primer-blank``.

One plan installs the blank on a clean runner -- the host steps, the passport
(a file), the sources (a ``file://`` mirror of the blank at its pinned
commit, so no key of CI is needed), the blank's ladder (``seams_check``,
``render_env``, ``build``, ``packages``, ``tests``, ``migrate``, ``up``),
``types``, the edge (``tls_files``, ``nginx``, ``ssl``), ``frontend``, the
final check and ``finalize`` -- and the same plan runs a second time, then
once as ``doctor``. The blank is built and brought up once in the whole tier
3: every check of it lives here (DM-50), against what that one install left:

- the env: modes, keys, the minted password -- the same on the second run,
  never printed --, ``docker compose config`` byte for byte;
- the build, migrations, up: labels on every container, volume, network and
  image, ``release``/``commit`` in ``/health``, nothing recreated by the
  second run, conformance, a planted ``max_body: 2M`` -- exactly ``max-body``;
- the routes: by ``Host`` on localhost, 301 to https, HSTS and ``nosniff``, a
  stranger ``Host`` gets no page;
- the tests in ``blank_test`` from the test target, ``current``,
  ``state.json``, the live database's head.

Two short checks need no install: what a single-quoted value is to compose,
and the digest certbot is to be pinned by (printed, not asserted). The file
runs after ``test_tier3_host.py`` (pytest takes a directory's files by
name): docker is on the runner only after the host steps.
"""

import json
import os
import warnings
from pathlib import Path

import yaml

from pridem.report.schema import Verdict
from pridem.runner import CommandTimedOut, Stream, SubprocessRunner
from pridem.steps.edge import CERTBOT_TAG

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
URL_SAFE = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-")
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
from pridem.stacks.schema import load_primer_yaml
from pridem.stacks.seams import SeamMemory
from pridem.state import Box, JournalHeader
from pridem.steps.build import Build
from pridem.steps.env import RenderEnv, SeamsCheck
from pridem.steps.finalize import FinalCheck, Finalize
from pridem.steps.frontend import Frontend
from pridem.steps.host import host_steps
from pridem.steps.migrate import Migrate
from pridem.steps.nginx import Nginx
from pridem.steps.packages import Packages
from pridem.steps.passport import passport_steps
from pridem.steps.sources import source_steps
from pridem.steps.ssl import Ssl, TlsFiles
from pridem.steps.tests import TestReport, Tests
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
_, sources = source_steps(
    root, stack="blank", address=f"file://{mirror}", ref="main", tag=False
)
render = RenderEnv(
    blank, product=blank, fetched=fetched, secrets=secrets, memory=memory, root=root
)
parts = {"release": release, "ref": "main", "commit": commit, "root": root}
ladder = [
    SeamsCheck(blank, {}, fetched), render,
    Build(blank, "blank", **parts, fetched=fetched),
    Packages(blank, "blank", **parts, fetched=fetched),
    Tests(blank, "blank", **parts, report=report, secrets=secrets),
    Migrate(blank, "blank", **parts),
    Up(blank, "blank", **parts, memory=memory, render=render),
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
    try:
        outcome = Plan(
            [StackSteps("host", host), StackSteps("passport", first),
             StackSteps("sources", sources), StackSteps("blank", ladder),
             StackSteps("types", types), StackSteps("edge", edge),
             StackSteps("frontend", front), StackSteps("finalize", tail, root=True)],
            mode=mode, role="test", runner=SubprocessRunner(),
            sink=Both(ConsoleSink(sys.stdout, secrets), journal),
            finally_=[StackSteps("host", final)],
        ).run()
    finally:
        journal.close()
    if mode == "doctor":  # what doctor would do, and what it found red
        print("DIFF " + json.dumps([item.reason.code for item in outcome.doctor_diff]))
        failed = [r.reason.code for r in outcome.steps if r.reason is not None]
        print("FAILED " + json.dumps(failed))
        sys.exit(0)
    every = [*host, *first, *sources, *ladder, *types, *edge, *front, *tail, *final]
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


def _passport(tmp: Path) -> Path:
    data = {
        "schema": 1,
        "version": 1,
        "server": {"name": "tier3-env", "role": "test", "os": "ubuntu-24.04"},
        "edition": "core",
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
        "packages": {},
        "cloud": {},
    }
    file = tmp / "passport.yaml"
    file.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
    return file


def _journal_tail(verdict: Verdict) -> str:
    """The end of the run's journal: the console shows no command output."""
    journal = Path("/opt/pridem") / verdict.log_ref
    if not journal.is_file():
        return f"\n(no journal at {journal})"
    tail = journal.read_text(encoding="utf-8").splitlines()[-JOURNAL_TAIL:]
    return "\n--- journal tail ---\n" + "\n".join(tail)


def _install(checkout: Path, passport: Path, mirror: Path) -> tuple[Verdict, str]:
    lines = _run(
        [
            PYTHON,
            "-c",
            PLAN,
            str(checkout),
            str(passport),
            str(mirror),
            BLANK_COMMIT,
            "install",
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


def test_tier3_the_whole_install_of_the_blank(tmp_path: Path) -> None:
    checkout, passport = _blank(tmp_path), _passport(tmp_path)
    mirror = tmp_path / "blank-mirror.git"
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

    # the second run (R9, U4): the same password, nothing recreated, not printed
    again, printed_again = _install(checkout, passport, mirror)

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
    api, _ = _curl(tmp_path, "https://localhost/health", API)
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


def test_tier3_prints_the_digest_certbot_is_to_be_pinned_by() -> None:
    """W6: printed, not asserted -- KNOWN CEILING on ``CERTBOT_IMAGE``."""
    _run(["docker", "pull", "-q", CERTBOT_TAG], timeout=300)
    digests = _stdout(
        ["docker", "image", "inspect", "-f", "{{json .RepoDigests}}", CERTBOT_TAG]
    )
    version = _run(["docker", "run", "--rm", CERTBOT_TAG, "--version"], timeout=120)
    # a warning, so the run's summary shows it whatever pytest captures
    warnings.warn(
        f"CERTBOT {CERTBOT_TAG} digests={digests} version={version}", stacklevel=1
    )
