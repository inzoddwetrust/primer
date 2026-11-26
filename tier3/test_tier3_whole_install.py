"""Tier 3 probe (DM-19, DM-50, DM-20, DM-45): the whole cycle of ``primer-blank``
by the machine's CLI.

``pridem install --passport <file>`` installs the blank on a clean runner with
the plan the machine makes itself (DM-45) -- the host steps, the passport (a
file), the timers, the sources (a ``file://`` mirror of the blank at its pinned
commit, ``/srv/tier3/primer-blank.git`` -- named as the repository, as
``fetch_root`` takes it on a real box (DM-70) -- so no key of CI is needed), the blank's
ladder (``seams_check``, ``render_env``, ``build``, ``packages``, ``tests``,
``migrate``, ``egress``, ``up``), ``types``, the edge (``tls_files``,
``nginx``, ``ssl``), ``frontend``, the final check and ``finalize``, ``gc`` in
``finally``; ``pridem update`` runs it a second time, ``pridem doctor`` finds
nothing to do, and ``pridem destroy`` -- the last test of the file -- takes it
off the box. Every command is ``--json``: the verdict on stdout, the ladder on
stderr. The blank is built and brought up once in the whole tier 3: every
check of it lives here (DM-50), against what that one install left:

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
another edition is another image. Both deploy through the same mirror, by
``pridem update`` of a passport of their own; the log of the machine's proxy
is printed (the measure of DM-45) and its line of the refused sentinel is in
the fact of ``egress``.

DM-46 runs after them, on the same box -- its stage B last: two instances of
the blank with their own languages, a third with a language the product has
not red before any act. Stage A first, on the blank's own service
``primer-blank-service`` (DM-59), which every edition of the blank installs
from its ``file://`` mirror at the pinned tag: the service goes up by its own
ladder before the product, the product's ``profile/`` copied to it and
validated by its image; a profile it refuses is red with both left running;
an edition that leaves it out installs nothing of it. Right after the whole
install, the machine's conformance takes the ``/health`` of both (DM-66:
``details``, ``ctx``, ``degraded``). After ``destroy``, the probe of DM-59:
the blank without its service on a clean box, then with it -- the product
holds the values of the service's seams.

Two short checks need no install: what a single-quoted value is to compose,
and that the tags certbot and squid are pinned by still name the pinned
digests. The file
runs after ``test_tier3_host.py`` (pytest takes a directory's files by
name): docker is on the runner only after the host steps.
"""

import base64
import hashlib
import json
import os
import re
import shutil
import signal
import threading
import time
import warnings
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import ClassVar
from urllib.parse import urlsplit

import pytest
import yaml
from conftest import SERVICE_MIRROR, SERVICE_PINS
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from groups import NEEDS_BOX

from pridem.conformance.stack import check_health, check_logs
from pridem.protocol import (
    PROTOCOL_HEADER,
    EventBatch,
    Heartbeat,
    Refusal,
    RegisterRequest,
    RegisterResponse,
    VerdictEnvelope,
    signed_headers,
    signing_string,
    verdict_bytes,
)
from pridem.report.schema import Verdict
from pridem.runner import (
    CommandNotStarted,
    CommandTimedOut,
    RunnerError,
    Stream,
    SubprocessRunner,
    clean_env,
)
from pridem.steps.compose import PROXY_URL as PROXY
from pridem.steps.edge import CERTBOT_IMAGE, live_config
from pridem.steps.egress import SQUID_IMAGE
from pridem.steps.engine import build_cache
from pridem.steps.gc import reclaimable_size
from pridem.verbs.register import TOKEN_ENV

PYTHON = "/opt/pridem/current/venv/bin/python"
PRIDEM = "/usr/local/bin/pridem"
"""The machine as the owner runs it: every install, update, doctor and destroy
here is a command of its CLI, the plan is the machine's own (DM-45)."""
BLANK = "https://github.com/inzoddwetrust/primer-blank.git"
# the blank's stack is named by its repository (contract 3 rule 32, DM-70): every
# name of it on the box -- /opt/<stack>, the compose project, labels, keys of
# state.json and of the verdict -- is this one, and the mirror is named as the
# repository, so fetch_root takes it with no detour
STACK = "primer-blank"
OPT = Path(f"/opt/{STACK}")
MIRROR = Path(f"/srv/tier3/{STACK}.git")
"""The blank's ``file://`` mirror the passport names: the machine fetches from
it with no key of CI, and names the product's directory by it -- ``primer-blank``."""
BLANK_COMMIT = "754f8562c35495d97f3916d096034860adb9c346"
FILES = "primer-blank-files"
"""The persistent entry of the blank (DM-86): its volume outlives destroy."""
FILES_VOLUME = f"{FILES}_files"
MARK = "dm86-persistent"
# the blank's service (DM-59): its file:// mirror is made by tier3/conftest.py
# before the first test of the session -- every plan of the blank reads its lock
SERVICE = "primer-blank-service"
SERVICE_ENV = Path(f"/opt/{SERVICE}/env/.env")
SEAMS = ("SERVICE_API_URL", "SERVICE_TOKEN", "SERVICE_KEY")
# the blank's published packages (DM-58): public, cloned over https by the
# test, given to the machine as file:// mirrors; each tag's commit is pinned
PACKAGES_OWNER = "VELO2026-app"
PACKAGE_PINS: dict[str, dict[str, str]] = {
    "primer-blank-skin": {
        "v1.0.0": "f45fdc9f0b1986437391e52cdcfbfdc85e10f4af",
        "v1.1.0": "2256ce3beaae51409838a122f64a4a27811ddbde",
    },
    "primer-blank-texts": {"v1.0.0": "fefb50b44d3d5fb2f92fe63e75148b156fbbd9e8"},
    "primer-blank-brand": {"v1.0.0": "c40b5ffa2f75744d74d4359703e87c78fa273dab"},
}
REF = "main"
RELEASE = f"{OPT}/releases/{BLANK_COMMIT}"
ENV = OPT / "env" / ".env"
MINTED = OPT / "env" / "minted.yaml"
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
    runner=SubprocessRunner(), mode="install", role="test", stack=stack.name,
    on_line=lambda stream, line, cut: None,
)
seen = observe(
    ctx, stack, stack.name, release=release, project=stack.name, env_file=env_file
)
print("PROBLEMS " + json.dumps(problems_param(check_stack(stack, stack.name, seen))))
other = load_primer_yaml(planted)
print("PLANTED " + json.dumps(problems_param(check_stack(other, stack.name, seen))))
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
    languages: tuple[str, ...] = ("en", "ru"),
    default_language: str = "en",
    options: list[str] | None = None,
    params: dict[str, dict[str, str]] | None = None,
    asked: dict[str, dict[str, str]] | None = None,
    cache_budget: str = "3G",
    ssl: str = "self-signed",
    tls: tuple[str, str] | None = None,
) -> Path:
    """A passport of the box; the blank declares ``languages: [en, ru]`` since
    ``BLANK_COMMIT`` 2e7580f, and an instance names its own (DM-46)."""
    data = {
        "schema": 1,
        "version": version,
        "server": {"name": "tier3-env", "role": "test", "os": "ubuntu-24.04"},
        "edition": edition,
        "languages": list(languages),
        "default_language": default_language,
        "product": {"repo": f"file://{MIRROR}", "ref": REF},
        "domains": {"frontend": FRONTEND, "api": API},
        "access": {"mode": "deploy-keys"},
        "asked": asked or {},
        "params": params or {},
        **({"options": options} if options is not None else {}),
        "policies": {
            "ssl": ssl,
            **({"tls": {"cert": tls[0], "key": tls[1]}} if tls is not None else {}),
            "gc": {
                "keep_releases": 2,
                "builder_cache_budget": cache_budget,
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


def _pridem(*args: str, timeout: float = 3600) -> tuple[int, list[str], list[str]]:
    """A command of the machine's CLI: its exit code, stdout and stderr."""
    out: list[str] = []
    err: list[str] = []

    def keep(stream: Stream, line: str, cut: bool) -> None:
        (out if stream is Stream.STDOUT else err).append(line)

    try:
        result = SubprocessRunner().run(
            [PRIDEM, *args], expect=(0, 1, 2), timeout=timeout, on_line=keep
        )
    except CommandTimedOut:
        raise AssertionError("\n".join([*err, *out])) from None
    return result.code, out, err


def _verdict_of(*args: str) -> tuple[Verdict, str]:
    """``pridem --json <args>``: the verdict on stdout, the ladder on stderr --
    printed with the journal's tail when the run is not green."""
    code, out, err = _pridem("--json", *args)
    printed = "\n".join(err)
    try:
        verdict = Verdict.model_validate_json("\n".join(out))
    except ValueError:
        raise AssertionError(f"exit {code}\n{printed}\n" + "\n".join(out)) from None
    assert int(verdict.exit_code) == code, printed
    if verdict.result != "green":
        printed += _journal_tail(verdict)
    return verdict, printed


def _install(passport: Path, verb: str = "install") -> tuple[Verdict, str]:
    """``pridem install`` or ``pridem update`` of the passport ``passport``;
    the blank is what the mirror's ``main`` holds."""
    return _verdict_of(verb, "--passport", str(passport))


def _doctor(passport: Path) -> tuple[object, object, Verdict]:
    """``(diff, failed, verdict)`` of ``pridem doctor``: the codes of what it
    would do and of the checks that are red."""
    verdict, printed = _verdict_of("doctor", "--passport", str(passport))
    diff = [item.code for item in verdict.report.doctor_diff or []]
    failed = [s.reason.code for s in verdict.steps if s.status == "failed" and s.reason]
    return diff, failed, verdict


def _env(path: Path = ENV) -> dict[str, str]:
    out: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
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
                STACK,
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
            f"label=com.docker.compose.project={STACK}",
            "--filter",
            "label=com.docker.compose.service=app",
        ]
    )
    return container


def _report_config_hashes() -> None:
    """Diagnostic, no colour (DM-58): what ``config --hash`` of the blank's
    file with the machine's override prints, next to the hash compose stamped
    on each running container -- ``up`` and ``packages`` decide by their
    equality, so the form is measured into the run's output before anything
    asserts on it (par0 14.3)."""
    release = OPT / "current"
    hashes = _stdout(
        [
            "docker",
            "compose",
            "-p",
            STACK,
            "--env-file",
            str(ENV),
            "-f",
            str(release / "docker-compose.yml"),
            "-f",
            f"{OPT}/compose/{STACK}.yml",
            "config",
            "--hash",
            "*",
        ]
    )
    ids = _stdout(
        ["docker", "ps", "-q", "--filter", f"label=com.docker.compose.project={STACK}"]
    )
    labels = _stdout(
        [
            "docker",
            "inspect",
            "-f",
            '{{index .Config.Labels "com.docker.compose.service"}} '
            '{{index .Config.Labels "com.docker.compose.config-hash"}}',
            *ids,
        ]
    )
    warnings.warn(
        f"DM-58 diagnostic: config --hash {sorted(hashes)}; "
        f"labels of the running containers {sorted(labels)}",
        stacklevel=2,
    )


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
    """The blank's mirror the sources fetch from, at ``BLANK_COMMIT``: made here
    once, for whichever group runs first on this runner (DM-73: each group is
    a runner of its own), and pushed to by the tests that deploy copies. The
    mirror of the blank's service is the session's (``tier3/conftest.py``)."""
    MIRROR.parent.mkdir(parents=True, exist_ok=True)
    if not (MIRROR / "HEAD").is_file():
        checkout = _blank(tmp_path_factory.mktemp("mirror"))
        _run(["git", "clone", "-q", "--mirror", str(checkout), str(MIRROR)])
        main = ["update-ref", "refs/heads/main", BLANK_COMMIT]
        _run(["git", "--git-dir", str(MIRROR), *main])
    return MIRROR


def _install_at_pin(tmp: Path) -> None:
    """The blank installed at its pin -- the preparation of a group whose
    tests need it (``NEEDS_BOX``), not a test: the assertions of the whole
    install stay in its own test (group ``b``)."""
    verdict, printed = _install(_passport(tmp))
    # where the preparation of a group goes, step by step (DM-125, par0 14.3)
    spent = [(s.stack, s.name, round(s.duration_s or 0.0, 1)) for s in verdict.steps]
    print("DM-125 measure:", sorted(spent, key=lambda step: -step[2]))
    assert verdict.result == "green", printed


@pytest.fixture(scope="module", autouse=True)
def _group_box(
    request: pytest.FixtureRequest,
    mirror: Path,
    tmp_path_factory: pytest.TempPathFactory,
) -> None:
    """The groups of ``NEEDS_BOX`` start with the blank installed (DM-73)."""
    group = request.config.getoption("--tier3-group")
    if group in NEEDS_BOX and not (OPT / "current").is_symlink():
        _install_at_pin(tmp_path_factory.mktemp("group-box"))


@pytest.fixture(autouse=True)
def _mirror_back_at_the_pin() -> Iterator[None]:
    """After every test, ``main`` of the blank's mirror is ``BLANK_COMMIT``
    again, whatever the test pushed and wherever it stopped (DM-69, item 8):
    a test red before its own return leaves its neighbour the pin, not its
    copy (the stand of DM-70: one cause, two red tests)."""
    yield
    if (MIRROR / "HEAD").is_file():
        _run(
            [
                "git",
                "--git-dir",
                str(MIRROR),
                "update-ref",
                "refs/heads/main",
                BLANK_COMMIT,
            ]
        )


def test_tier3_the_whole_install_of_the_blank(tmp_path: Path, mirror: Path) -> None:
    """The first of group ``b``: the install of the blank on a clean box.

    Changed by DM-73: the mirror at the pin is the fixture's (``mirror``) --
    the preparation of the mirror is in the fixture, the groups of tier 3
    (DM-73)."""
    checkout, passport = _blank(tmp_path), _passport(tmp_path)

    verdict, printed = _install(passport)
    # DM-132: what policies.host found on the runner, measured, not asserted
    host = [(s.name, s.status, s.verify) for s in verdict.steps]
    print(
        "DM-132 measure:",
        [h for h in host if h[0] in ("swap", "memory", "password_login")],
    )

    # the install (R1, W1)
    assert verdict.result == "green", printed
    _report_config_hashes()
    facts = {(s.stack, s.name): s.verify or {} for s in verdict.steps}
    # the env (R2-R8)
    assert oct(ENV.stat().st_mode & 0o777) == oct(0o600), printed
    assert oct(ENV.parent.stat().st_mode & 0o777) == oct(0o700), printed
    assert oct(MINTED.stat().st_mode & 0o777) == oct(0o600), printed
    env = _env()
    assert sorted(env) == [
        "API_BASE_URL",
        "DEFAULT_LANGUAGE",
        "EDITION",
        "LANGUAGES",
        "POSTGRES_PASSWORD",
        "SERVICE_API_URL",
        "SERVICE_KEY",
        "SERVICE_TOKEN",
    ], printed
    password = env["POSTGRES_PASSWORD"]
    assert len(password) >= 32 and set(password) <= URL_SAFE, printed
    assert (env["EDITION"], env["API_BASE_URL"]) == ("core", API), printed
    assert (env["LANGUAGES"], env["DEFAULT_LANGUAGE"]) == ("en,ru", "en"), printed
    assert password not in printed  # neither the console nor the verdict
    # the console for a person (DM-107): titles, no fact in JSON, no whole
    # commit; status and logs measured into the run's output (par0 14.3)
    steps = [line for line in printed.splitlines() if line.startswith("[")]
    assert any("✓ Check the server" in line for line in steps), printed
    assert not any("{" in line for line in steps), printed
    assert not re.search(r"\b[0-9a-f]{40}\b", "\n".join(steps)), printed
    code, said_status, _ = _pridem("status")
    _, said_logs, _ = _pridem("logs", STACK, "--tail", "3")
    print("DM-107 measure:", {"status": said_status, "logs": said_logs})
    assert code == 0 and any(
        STACK in line and "running" in line for line in said_status
    )
    assert said_logs and not any(
        re.match(r"^\d{4}-\d\d-\d\dT", line) for line in said_logs
    )
    # build, migrate, up (U1-U3)
    up, build = facts[(STACK, "up")], facts[(STACK, "build")]
    assert (up["release"], up["commit"]) == (REF, BLANK_COMMIT), printed
    assert up["image"] == build["app_image"], printed
    assert facts[(STACK, "migrate")].get("alembic_head") == "0001", printed
    # the tests, the final check, current, state.json (DM-19)
    tests = facts[(STACK, "tests")]
    assert tests["test_db"] == "blank_test" and tests["target"] == "test", printed
    junit = tests["junit"]
    assert isinstance(junit, dict), printed
    total, failed = junit["total"], junit["failed"]
    assert isinstance(total, int) and total > 0 and failed == 0, printed
    assert verdict.junit is not None and verdict.junit.total == total, printed
    verified = facts[("pridem-finalize", "final_check")]["verified"]
    assert isinstance(verified, int) and verified > 10, printed
    assert str((OPT / "current").readlink()) == RELEASE, printed
    state = json.loads(Path("/opt/pridem/state.json").read_text())
    # the name (DM-70): the stack is the repository's, fetch_root took the
    # blank's primer.yaml with no detour, and nothing went under the old name
    assert facts[("pridem-sources", "fetch_root")]["config"] == STACK, printed
    assert OPT.is_dir() and not Path("/opt/blank").exists(), printed
    # the service of every edition (DM-59): by its tag, the lock's
    assert state["current"] == {STACK: BLANK_COMMIT, SERVICE: "v1.0.0"}, state
    assert state["composition"][STACK] == BLANK_COMMIT, state
    assert state["composition"][SERVICE] == "v1.0.0", state
    container = _app()
    started = _docker_started()

    # the second run (R9, U4), ``update``: the same password, nothing
    # recreated, not printed
    again, printed_again = _install(passport, "update")
    # ... and docker not restarted: daemon.json already as drawn (DM-53)
    assert _docker_started() == started, printed_again

    assert again.result == "green", printed_again
    assert _env()["POSTGRES_PASSWORD"] == password
    assert password not in printed_again
    assert _app() == container, printed_again

    # doctor on an unchanged box: nothing to do (TZ 7.1; DM-51)
    diff, red, doctor = _doctor(passport)
    assert (diff, red) == ([], []), doctor.model_dump_json()

    # compose config byte for byte (R10)
    compose_file = Path(RELEASE) / "docker-compose.yml"
    config = _config(compose_file, ENV)
    assert config["app"]["DATABASE_URL"] == (
        f"postgresql+asyncpg://blank:{password}@postgres:5432/blank"
    )
    assert config["app"]["EDITION"] == "core"
    assert config["frontend"]["API_BASE_URL"] == API
    assert config["frontend"]["LANGUAGES"] == "en,ru"
    assert config["frontend"]["DEFAULT_LANGUAGE"] == "en"
    assert config["postgres"]["POSTGRES_PASSWORD"] == password

    # labels (U5-U8)
    release = {
        "pridem.stack": STACK,
        "pridem.release": REF,
        "pridem.commit": BLANK_COMMIT,
    }
    project = f"label=com.docker.compose.project={STACK}"
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
        assert labels.get("pridem.stack") == STACK and "pridem.release" not in labels
    network = _labels("network", f"{STACK}_default")
    assert network.get("pridem.stack") == STACK and "pridem.release" not in network
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
                    f"label=pridem.stack={STACK}",
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
        STACK,
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


def _health_of(container: str) -> dict[str, object]:
    """``/health`` of an app, read inside its container: nginx closes it on
    the public routes (protocol 9.3)."""
    read = "import urllib.request; print(urllib.request.urlopen("
    read += "'http://127.0.0.1:8000/health', timeout=5).read().decode())"
    [line] = _stdout(["docker", "exec", container, "python", "-c", read])
    found = json.loads(line)
    assert isinstance(found, dict)
    return found


def _started_line(container: str) -> tuple[dict[str, object], list[str]]:
    """The ``app.started`` line of a container's log and every line of it --
    uvicorn's own lines are JSON too: the log config is the app's."""
    lines = _stdout(["docker", "logs", container])
    started = [json.loads(x) for x in lines if '"app.started"' in x]
    assert started, lines[-20:]
    return started[-1], lines


def test_tier3_the_new_health_of_the_blank_and_its_service() -> None:
    """DM-59 on the box the install left: the machine's conformance takes the
    ``/health`` of DM-66 -- ``details``, ``ctx`` in the log, and ``degraded``
    with the last revision measured when the database falls -- from the blank
    and from its service, which has no database (``alembic_head`` null).

    Changed by DM-70: the blank's ``/health`` and its log say the stack's own
    name, ``primer-blank`` -- conformance checks only that it is not empty."""
    assert (OPT / "current").is_symlink(), "the whole install runs first"
    blank, service = _app(), _container(SERVICE, "app")
    body = _health_of(blank)
    assert body["status"] == "ok" and body["details"] == {"script_head": "0001"}, body
    # the stack's own name (DM-70): conformance does not compare it, this does
    assert body["service"] == STACK, body
    assert body["seams"] == {
        "provides": ["PRODUCT_WEBHOOK_URL"],
        "requires_satisfied": True,
    }, body
    assert (
        check_health(json.dumps(body).encode(), migrate=True, stack_name=STACK) == []
    ), body
    theirs = _health_of(service)
    assert (theirs["alembic_head"], theirs["status"]) == (None, "ok"), theirs
    assert theirs["details"] == {"provides": 3, "profile": True}, theirs
    assert theirs["seams"] == {"provides": list(SEAMS), "requires_satisfied": True}
    assert (
        check_health(json.dumps(theirs).encode(), migrate=False, stack_name=SERVICE)
        == []
    ), theirs
    # ctx: the start of each names what it started with -- names, no values
    started, lines = _started_line(blank)
    assert started["ctx"] == {"edition": "core", "script_head": "0001"}, started
    assert started["service"] == STACK, started
    assert check_logs(lines, stack_name=STACK) == [], lines[-5:]
    started, lines = _started_line(service)
    assert started["ctx"] == {"edition": "core", "provides": list(SEAMS)}, started
    assert check_logs(lines, stack_name=SERVICE) == [], lines[-5:]
    # degraded: the blank's database stopped -- /health still 200, db error,
    # the revision measured before; conformance names it degraded, nothing else
    postgres = _container(STACK, "postgres")
    _run(["docker", "stop", postgres], 120)
    try:
        down = _health_of(blank)
        assert down["status"] == "degraded", down
        assert down["checks"] == {"db": "error", "schema": "error"}, down
        assert down["alembic_head"] == "0001", down
        found = check_health(json.dumps(down).encode(), migrate=True, stack_name=STACK)
        assert [p.code for p in found] == ["health-degraded"], found
    finally:
        _run(["docker", "start", postgres], 120)
    for _ in range(60):
        if _health_of(blank)["status"] == "ok":
            break
        time.sleep(1)
    assert _health_of(blank)["status"] == "ok"


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
        ["docker", "ps", "-a", "-q", "--filter", "label=pridem.stack=pridem-egress"]
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
    assert (OPT / "current").is_symlink(), "the whole install runs first"
    passport = _passport(tmp_path)
    # the blank without egress: every network internal, no proxy, no way out
    for network in ("pridem", "pridem-egress", f"{STACK}_default"):
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
    verdict, printed = _install(passport, "update")
    assert verdict.result == "green", printed
    facts = {(s.stack, s.name): s.verify or {} for s in verdict.steps}
    egress = facts[(STACK, "egress")]
    assert egress["hosts"] == [EGRESS_HOST], egress
    allowed = egress["allowed"]
    assert isinstance(allowed, dict) and allowed[EGRESS_HOST] != 403, egress
    assert len(_proxies()) == 1
    # DM-45: the proxy's access log, measured -- printed, then the fact read
    [proxy] = _proxies()
    logged = _run(["docker", "logs", "--tail", "40", proxy])
    warnings.warn("squid log:\n" + "\n".join(logged), stacklevel=1)
    line = egress["log"]
    assert isinstance(line, str) and line.startswith("pridem-egress host="), egress
    assert "/" not in line.partition(" host=")[2], line  # no path, ever
    after = _reach()
    assert after["HTTPS_PROXY"] == after["https_proxy"] == PROXY, after
    assert after["via_allowed"] == "reached", after  # the pair
    other = after["via_other"]
    assert isinstance(other, str) and other.startswith("not reached"), after
    assert "403" in other, after  # refused by the proxy itself
    assert after["direct_allowed"] != "reached", after
    assert after["direct_address"] != "reached", after
    # doctor on that box: nothing to do
    diff, red, doctor = _doctor(passport)
    assert (diff, red) == ([], []), doctor.model_dump_json()
    # the routes still answer: nginx publishes through its own network
    api, _ = _curl(tmp_path, "https://localhost/openapi.json", API)
    assert api.startswith("200"), api

    # the release after it, without egress: the proxy is gone, no way out still
    _run(["git", "--git-dir", str(mirror), "update-ref", "refs/heads/main", base])
    _run(["git", "-C", str(copy), "checkout", "-q", base], env=GIT_ENV)
    back, printed = _install(passport, "update")
    assert back.result == "green", printed
    facts = {(s.stack, s.name): s.verify or {} for s in back.steps}
    assert facts[(STACK, "egress")] == {"hosts": [], "proxy": "absent"}, facts
    assert _proxies() == []
    assert not Path("/opt/pridem/egress/squid.conf").exists()
    # DM-106: the proxy's own network went with it (``rm`` then ``down``)
    nets = _stdout(["docker", "network", "ls", "--format", "{{.Name}}"])
    print("DM-106 measure: networks after the proxy", nets)
    assert "pridem-egress_default" not in nets, nets
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


RUNTIME_SKIN = """  skin:
    contract: ">=1,<2"
    apply: runtime
    validate: validate-skin <dir>
    mount:
      - { service: frontend, path: /srv/skin }
"""
BUILD_SKIN = """  skin:
    contract: ">=1,<2"
    apply: build
    build:
      - { service: frontend, path: public/skin }
"""
EDITIONS_LINE = 'EDITIONS: dict[str, tuple[str, ...]] = {"core": ()}\n'
EDITIONS_FULL = 'EDITIONS: dict[str, tuple[str, ...]] = {"core": (), "full": ()}\n'
"""The blank's backend table of editions (``backend/app/editions.py``) and
the one of the DM-61 copy, which declares ``full`` in ``primer.yaml`` too."""


def _app_health() -> dict[str, object]:
    """``/health`` of the blank's app."""
    return _health_of(_app())


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


def _image_labels(image: str) -> dict[str, str]:
    [text] = _stdout(
        ["docker", "image", "inspect", "-f", "{{json .Config.Labels}}", image]
    )
    labels = json.loads(text)
    assert isinstance(labels, dict)
    return {str(k): str(v) for k, v in labels.items()}


def _report_old_image(image: str) -> None:
    """Diagnostic, no colour (DM-61 FIX 3): once compose moved the tag of
    frontend to another image, is the old one still on the box, and does
    ``docker image ls`` -- what ``image_of`` reads -- still list it? The answer
    goes to the report: it decides whether the KNOWN CEILING of ``gc`` holds."""
    alive = (
        SubprocessRunner()
        .run(
            ["docker", "image", "inspect", image],
            expect=(0, 1),
            timeout=60,
            on_line=lambda stream, line, cut: None,
        )
        .code
        == 0
    )
    listed = image in _stdout(
        [
            "docker",
            "image",
            "ls",
            "-q",
            "--no-trunc",
            "--filter",
            "label=pridem.service=frontend",
        ]
    )
    warnings.warn(
        f"DM-61 diagnostic: the old image {image} of frontend (edition core) "
        f"after the build of edition full: inspect={'alive' if alive else 'gone'}, "
        f"image ls={'listed' if listed else 'not listed'}",
        stacklevel=2,
    )


def test_tier3_build_mode_of_the_blank(tmp_path: Path, mirror: Path) -> None:
    """DM-61 on the box the install left: a copy of the blank builds a skin
    into its frontend (``apply: build``); a new version of the skin rebuilds on
    the same commit; a skin its build refuses is red and the old one stays
    served; another edition is another image.

    DM-58: the blank declares its own slots ``skin`` and ``texts`` (apply:
    runtime) since ``BLANK_COMMIT`` f164903, so the copy turns the slot
    ``skin`` it has into one built into frontend -- ``RUNTIME_SKIN`` replaced
    by ``BUILD_SKIN``, once -- instead of adding a second ``packages``; the
    passports here give no texts, so that slot mounts nothing."""
    assert (OPT / "current").is_symlink(), "the whole install runs first"
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
    # the blank's service is in every edition (DM-59, contract 3 rule 41)
    core = "  core: { services: [primer-blank-service] }\n"
    assert text.count(core) == 1
    text = text.replace(core, core + "  full: { services: [primer-blank-service] }\n")
    assert text.count(RUNTIME_SKIN) == 1
    text = text.replace(RUNTIME_SKIN, BUILD_SKIN)
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
    first, printed = _install(passport(2, "1.0.0"), "update")
    assert first.result == "green", printed
    facts = {(s.stack, s.name): s.verify or {} for s in first.steps}
    keys = facts[(STACK, "build")]["keys"]
    assert keys == {
        "frontend": {"pridem.edition": "core", "pridem.package.skin": "skin@1.0.0"}
    }, keys
    assert _body("/skin/skin.css", FRONTEND) == "one"
    assert _body("/edition.txt", FRONTEND) == "core"
    assert _app_health()["edition"] == "core"
    images = facts[(STACK, "build")]["images"]
    assert isinstance(images, dict)

    # version 1.1.0 on the same commit: frontend rebuilt, app the same image
    second, printed = _install(passport(3, "1.1.0"), "update")
    assert second.result == "green", printed
    facts = {(s.stack, s.name): s.verify or {} for s in second.steps}
    again = facts[(STACK, "build")]["images"]
    assert isinstance(again, dict)
    assert again["frontend"] != images["frontend"], (images, again)
    assert again["app"] == images["app"], (images, again)
    assert _body("/skin/skin.css", FRONTEND) == "two"

    # the same version again: no build (the step has nothing to do)
    same, printed = _install(passport(3, "1.1.0"), "update")
    assert same.result == "green", printed
    [build] = [s for s in same.steps if (s.stack, s.name) == (STACK, "build")]
    assert build.status == "ok" and build.verify is not None, build
    assert build.verify["images"] == again, (again, build.verify)

    # version 1.2.0 has no skin.css: the build is red, version 1.1.0 stays
    bad, printed = _install(passport(4, "1.2.0"), "update")
    assert bad.result != "green", printed
    [red] = [s for s in bad.steps if s.status == "failed"]
    assert (red.stack, red.name) == (STACK, "build"), bad.steps
    assert _body("/skin/skin.css", FRONTEND) == "two"

    # edition full, version 1.1.0: an image of its own, not core's
    full, printed = _install(passport(5, "1.1.0", "full"), "update")
    assert full.result == "green", printed
    assert _body("/edition.txt", FRONTEND) == "full"
    # the pair on the backend: EDITION of the passport reached app
    assert _app_health()["edition"] == "full"
    facts = {(s.stack, s.name): s.verify or {} for s in full.steps}
    built = facts[(STACK, "build")]["images"]
    assert isinstance(built, dict)
    assert built["frontend"] != again["frontend"], (again, built)
    labels = _image_labels(str(built["frontend"]))
    assert (labels["pridem.edition"], labels["pridem.package.skin"]) == (
        "full",
        "skin@1.1.0",
    ), labels
    _report_old_image(str(again["frontend"]))

    # back to edition core, version 1.1.0: green, core again on both sides --
    # from a living image or a build from the cache, whichever docker keeps
    back, printed = _install(passport(6, "1.1.0"), "update")
    assert back.result == "green", printed
    facts = {(s.stack, s.name): s.verify or {} for s in back.steps}
    assert facts[(STACK, "build")]["keys"] == {
        "frontend": {"pridem.edition": "core", "pridem.package.skin": "skin@1.1.0"}
    }, facts[(STACK, "build")]
    assert _body("/edition.txt", FRONTEND) == "core"
    assert _body("/skin/skin.css", FRONTEND) == "two"
    assert _app_health()["edition"] == "core"
    # doctor on that box: nothing to do
    diff, failed, doctor = _doctor(passport(6, "1.1.0"))
    assert (diff, failed) == ([], []), doctor.model_dump_json()


BLUE = "--color-brand-primary: #1a73e8;"
GREEN = "--color-brand-primary: #0b8043;"
MAGENTA = "--color-brand-primary: #c2185b;"
TEXTS = {
    "en": {
        "title": "Primer Blank",
        "config_error": "Settings are not available:",
        "api_label": "Server:",
    },
    "ru": {"title": "Праймер — болванка"},
}
BRAND_TEXTS = {
    "en": {"title": "Blank by Brand", "api_label": "Brand API:"},
    "ru": {"title": "Болванка бренда"},
}


@pytest.fixture(scope="module")
def published(tmp_path_factory: pytest.TempPathFactory) -> dict[str, Path]:
    """The blank's published packages (DM-58), mirrored over https: the
    machine fetches them from ``file://`` (it clones by ssh with a key alone,
    DM-10). Every tag's commit is its pin; a tag that names another commit is
    red with the one it names."""
    where = tmp_path_factory.mktemp("published")
    mirrors: dict[str, Path] = {}
    for name, tags in PACKAGE_PINS.items():
        bare = where / f"{name}.git"
        address = f"https://github.com/{PACKAGES_OWNER}/{name}.git"
        _run(["git", "clone", "-q", "--mirror", address, str(bare)], 300, env=GIT_ENV)
        for tag, pin in tags.items():
            [found] = _git("--git-dir", str(bare), "rev-parse", f"{tag}^{{commit}}")
            assert found == pin, f"{name} {tag} names {found}, pinned {pin}"
        mirrors[name] = bare
    return mirrors


def _service_image(service: str) -> str:
    """The image ID of the running container of ``service`` of the blank."""
    [container] = _stdout(
        [
            "docker",
            "ps",
            "-q",
            "--filter",
            f"label=com.docker.compose.project={STACK}",
            "--filter",
            f"label=com.docker.compose.service={service}",
        ]
    )
    [image] = _stdout(["docker", "inspect", "-f", "{{.Image}}", container])
    return image


def _texts() -> object:
    return json.loads(_body("/texts.json", FRONTEND))


def _packages_fact(verdict: Verdict) -> object:
    [step] = [s for s in verdict.steps if (s.stack, s.name) == (STACK, "packages")]
    return (step.verify or {}).get("packages")


def _broken_skin(tmp: Path, skin: Path) -> Path:
    """``v1.2.0`` of the skin, here only (a released tag is never moved): the
    logo of ``v1.0.0`` with a script -- ``validate-skin`` refuses it."""
    work = tmp / "broken-skin"
    _run(["git", "clone", "-q", str(skin), str(work)], env=GIT_ENV)
    _git("-C", str(work), "checkout", "-q", "-B", "broken", "v1.0.0")
    logo = work / "assets" / "logo.svg"
    logo.write_text(logo.read_text(encoding="utf-8") + "<script>x()</script>\n")
    _git("-C", str(work), "commit", "-q", "-am", "a script in the logo")
    _git("-C", str(work), "tag", "v1.2.0")
    bare = tmp / "broken" / "primer-blank-skin.git"
    _run(["git", "clone", "-q", "--bare", str(work), str(bare)], env=GIT_ENV)
    return bare


def test_probe_DM_58_skin_version_switch_needs_no_rebuild(
    tmp_path: Path, mirror: Path, published: dict[str, Path]
) -> None:
    """DM-58 on the box the earlier tests left: the blank at ``BLANK_COMMIT``
    with the published skin and texts (apply: runtime). ``v1.0.0`` -> ``v1.1.0``
    -> back: the running frontend keeps its image and shows the other color;
    ``doctor`` is empty; a skin ``validate-skin`` refuses is red and the look
    stays. The texts by language: ``ru`` of the package gives the title alone,
    the page takes the rest from its built-in ``ru``."""
    assert (OPT / "current").is_symlink(), "the whole install runs first"
    _run(
        ["git", "--git-dir", str(mirror), "update-ref", "refs/heads/main", BLANK_COMMIT]
    )
    skin, texts = published["primer-blank-skin"], published["primer-blank-texts"]

    def passport(version: int, skin_repo: Path, tag: str) -> Path:
        packages = {
            "skin": {"repo": f"file://{skin_repo}", "version": tag},
            "texts": {"repo": f"file://{texts}", "version": "1.0.0"},
        }
        return _passport(tmp_path, version=version, packages=packages)

    def deploy(file: Path) -> tuple[Verdict, str]:
        return _install(file, "update")

    first, printed = deploy(passport(10, skin, "1.0.0"))
    assert first.result == "green", printed
    _report_config_hashes()
    assert _packages_fact(first) == {
        "skin": "primer-blank-skin@1.0.0",
        "texts": "primer-blank-texts@1.0.0",
    }, printed
    assert BLUE in _body("/skin.css", FRONTEND)
    assert _texts() == TEXTS
    image = _service_image("frontend")

    # v1.1.0: the same image, the other color
    second, printed = deploy(passport(11, skin, "1.1.0"))
    assert second.result == "green", printed
    assert _packages_fact(second) == {
        "skin": "primer-blank-skin@1.1.0",
        "texts": "primer-blank-texts@1.0.0",
    }, printed
    css = _body("/skin.css", FRONTEND)
    assert GREEN in css and BLUE not in css, css
    assert _service_image("frontend") == image

    # back to v1.0.0
    back, printed = deploy(passport(12, skin, "1.0.0"))
    assert back.result == "green", printed
    assert BLUE in _body("/skin.css", FRONTEND)
    assert _service_image("frontend") == image
    assert _doctor(passport(12, skin, "1.0.0"))[:2] == ([], [])

    # a skin validate-skin refuses: red at packages, the look stays
    broken = _broken_skin(tmp_path, skin)
    bad, printed = deploy(passport(13, broken, "1.2.0"))
    assert bad.result != "green", printed
    [red] = [s for s in bad.steps if s.status == "failed"]
    assert (red.stack, red.name) == (STACK, "packages"), bad.steps
    css = _body("/skin.css", FRONTEND)
    assert BLUE in css and GREEN not in css, css
    assert _service_image("frontend") == image
    assert _texts() == TEXTS


def test_tier3_both_slots_from_one_brand_package_by_subpath(
    tmp_path: Path, mirror: Path, published: dict[str, Path]
) -> None:
    """DM-58: both slots of the blank from ``primer-blank-brand`` at one tag,
    each by its ``subpath`` -- the brand's color and texts."""
    assert (OPT / "current").is_symlink(), "the whole install runs first"
    _run(
        ["git", "--git-dir", str(mirror), "update-ref", "refs/heads/main", BLANK_COMMIT]
    )
    brand = f"file://{published['primer-blank-brand']}"
    packages = {
        "skin": {"repo": brand, "version": "1.0.0", "subpath": "skin"},
        "texts": {"repo": brand, "version": "1.0.0", "subpath": "texts"},
    }
    file = _passport(tmp_path, version=14, packages=packages)
    verdict, printed = _install(file, "update")
    assert verdict.result == "green", printed
    assert _packages_fact(verdict) == {
        "skin": "primer-blank-brand@1.0.0",
        "texts": "primer-blank-brand@1.0.0",
    }, printed
    css = _body("/skin.css", FRONTEND)
    assert MAGENTA in css and BLUE not in css, css
    assert _texts() == BRAND_TEXTS
    assert _doctor(file)[:2] == ([], [])


def test_tier3_reinstall_keeps_the_persistent_volume(tmp_path: Path) -> None:
    """DM-86, pass 3, in group b after every test but the cache's budget (FIX
    of DM-126, which runs on the box it leaves): a mark on the volume of the
    persistent entry ``primer-blank-files``; ``reinstall`` -- green, its
    ``destroy``
    names the volume kept, and the stack comes up again on it: the mark is
    there. The database of the blank's own entry is new (not persistent):
    its test rows are gone, the seed of ``install`` is back."""
    assert (OPT / "current").is_symlink(), "the whole install runs first"
    files = _container(FILES, "files")
    _stdout(["docker", "exec", files, "sh", "-c", f"echo {MARK} > /srv/files/mark"])
    _psql("INSERT INTO app_settings (key, value) VALUES ('dm86-gone', 'x')")
    # DM-110, on the dispatcher's word: the owner's decision of 17.11 --
    # reinstall confirms the server's name on any role
    verdict, printed = _verdict_of(
        "reinstall",
        "--passport",
        str(_passport(tmp_path, version=15)),
        "--confirm",
        "tier3-env",
    )
    assert verdict.result == "green", printed
    facts = {(s.stack, s.name): s.verify or {} for s in verdict.steps}
    assert facts[("pridem-destroy", "remove_objects")]["kept_volumes"] == [FILES_VOLUME]
    files = _container(FILES, "files")
    assert _stdout(["docker", "exec", files, "cat", "/srv/files/mark"]) == [MARK]
    assert _psql("SELECT value FROM app_settings WHERE key = 'dm86-gone'") == []
    assert _psql("SELECT key FROM app_settings WHERE key = 'installed_at'") == [
        "installed_at"
    ]


def _cache_line() -> dict[str, str]:
    """The line ``Build Cache`` of ``docker system df``, as docker prints it."""
    rows = [
        json.loads(line)
        for line in _stdout(["docker", "system", "df", "--format", "{{json .}}"])
        if line.strip()
    ]
    [row] = [row for row in rows if row.get("Type") == "Build Cache"]
    return {str(key): str(value) for key, value in row.items()}


def test_tier3_gc_trims_the_build_cache_to_the_budget(tmp_path: Path) -> None:
    """FIX of DM-126 (owner's decision of 22.11), the last of group ``b``, on
    the box ``reinstall`` left: a passport whose ``builder_cache_budget`` is
    ``1M``. The budget is of the cache no image holds (``Reclaimable`` of the
    line ``Build Cache``); the box has more of it than that -- else this test
    proves nothing and is red on its first assertion. ``update``: green, its
    ``gc`` measured the cache over the budget before and not over it after,
    and docker says the same after the run. Before the FIX the prune removed
    less than it had to in one call, and ``verify`` read ``Size``, which the
    images' own layers keep over any small budget.

    Measured into the run's output first (par0 14.3): docker's line before
    and after, the cache in the fact of ``gc``."""
    assert (OPT / "current").is_symlink(), "the whole install runs first"
    budget = 1024**2
    before = _cache_line()
    print("FIX DM-126 measure: the cache before", before)
    assert reclaimable_size(before["Reclaimable"]) > budget, (
        f"the box holds no cache of its own over the budget: {before}"
    )
    passport = _passport(tmp_path, version=16, cache_budget="1M")
    verdict, printed = _install(passport, "update")
    after = _cache_line()
    [gc] = [s for s in verdict.steps if (s.phase, s.name) == ("finally", "gc")]
    fact = gc.verify or {}
    measured = {
        when: (fact.get(when) or {}).get("build_cache")  # type: ignore[union-attr]
        for when in ("before", "after")
    }
    print("FIX DM-126 measure: the cache after", after, "the fact of gc", measured)
    assert verdict.result == "green", printed
    assert gc.status == "ok", gc
    was, now = measured["before"], measured["after"]
    assert isinstance(was, dict) and isinstance(now, dict), measured
    assert isinstance(was["reclaimable"], int) and was["reclaimable"] > budget, was
    assert isinstance(now["reclaimable"], int) and now["reclaimable"] <= budget, now
    assert reclaimable_size(after["Reclaimable"]) <= budget, after


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
        f"POSTGRES_PASSWORD='{literal}'\nEDITION='core'\nAPI_BASE_URL='{API}'\n"
        "LANGUAGES='en,ru'\nDEFAULT_LANGUAGE='en'\n"
        # the blank's seams from its service (DM-59): compose needs every one
        "SERVICE_API_URL='http://primer-blank-service-app:8000'\n"
        "SERVICE_TOKEN='measure-service-token-00000000000001'\n"
        "SERVICE_KEY='sk_measure-service-key-0000000000001'\n",
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


PANEL_PROXY = "pridem-dm146-proxy"
PANEL_PROXY_PORT = 3146
CONNECT_SCRIPT = """\
import selectors, socket, sys
host, port, proxy, proxy_port = sys.argv[1], sys.argv[2], sys.argv[3], int(sys.argv[4])
conn = socket.create_connection((proxy, proxy_port), 10)
first = f"CONNECT {host}:{port} HTTP/1.1\\r\\n"
conn.sendall((first + f"Host: {host}:{port}\\r\\n\\r\\n").encode())
head = b""
while b"\\r\\n\\r\\n" not in head:
    more = conn.recv(1)
    if not more:
        sys.exit("the proxy closed")
    head += more
if head.split()[1] != b"200":
    sys.exit("the proxy said " + head.split(b"\\r\\n")[0].decode())
sel = selectors.DefaultSelector()
sel.register(sys.stdin.buffer, selectors.EVENT_READ)
sel.register(conn, selectors.EVENT_READ)
while True:
    for key, _ in sel.select():
        if key.fileobj is conn:
            data = conn.recv(65536)
            if not data:
                sys.exit(0)
            sys.stdout.buffer.write(data)
            sys.stdout.buffer.flush()
        else:
            data = sys.stdin.buffer.read1(65536)
            if not data:
                conn.shutdown(socket.SHUT_WR)
                sel.unregister(sys.stdin.buffer)
            else:
                conn.sendall(data)
"""
"""ssh's ProxyCommand through an HTTP CONNECT proxy, the way git of the Panel
goes out (DM-146): a Python script, not a shell file."""


def _connect(host: str, port: int) -> tuple[str, bytes]:
    """``CONNECT host:port`` to the Panel's proxy on the runner: its status
    line and the first bytes after it."""
    import socket

    request = f"CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n"
    with socket.create_connection(("127.0.0.1", PANEL_PROXY_PORT), 15) as conn:
        conn.sendall(request.encode("ascii"))
        head = b""
        while b"\r\n\r\n" not in head:
            more = conn.recv(1)
            if not more:
                break
            head += more
        status = head.split(b"\r\n")[0].decode(errors="replace")
        after = b""
        if " 200 " in f"{status} ":
            conn.settimeout(15)
            after = conn.recv(64)
    return status, after


def test_tier3_the_panel_s_host_through_the_machine_s_proxy(tmp_path: Path) -> None:
    """DM-146, on the runner after the machine's host steps (group a): the
    machine's proxy -- its image ``SQUID_IMAGE``, its config rendered for the
    rows of ``primer-panel`` -- lets ``CONNECT ssh.github.com:443`` through,
    and ssh through it reaches GitHub, the way git of the Panel goes; not
    ``github.com``, not port 22. And a process on the box's host -- the agent
    -- goes out without the machine in the way. Measured into the run's log
    first (par0 14.3).

    FIX: the host's way out is any HTTP answer of ``api.github.com`` (a
    status, not ``000``) and the banner of ``ssh.github.com:443`` -- not a
    200, which GitHub's limit per address decides.

    DM-188 FIX, the dispatcher's word: the window of docker-proxy before squid
    listens. ``docker run -d`` returns before squid listens, and docker-proxy
    takes the connection all the same and ends it in ``EOF`` or a reset; the
    loop retried an ``OSError`` alone, so an ``EOF`` passed for the answer of
    ``ssh.github.com:443`` (an empty status line) and the probe was red by
    chance. Now one wait for squid's status line before the first request
    (``_ready``); the assertions are as they were."""
    import socket

    from pridem.stacks.egress import listed
    from pridem.steps.egress import (
        CONTAINER_CONFIG,
        SQUID_COMMAND,
        SQUID_IMAGE,
        SQUID_USER,
        config_text,
    )

    config = tmp_path / "squid.conf"
    config.write_text(config_text(sorted(listed("primer-panel"))), encoding="utf-8")
    config.chmod(0o644)
    script = tmp_path / "connect.py"
    script.write_text(CONNECT_SCRIPT, encoding="utf-8")
    _run(["docker", "pull", "-q", SQUID_IMAGE], timeout=300)
    _run(["docker", "rm", "-f", PANEL_PROXY], expect=tuple(range(256)))
    _run(
        ["docker", "run", "-d", "--name", PANEL_PROXY, "--user", SQUID_USER,
         "--label", "pridem.test=DM-146",
         "-p", f"127.0.0.1:{PANEL_PROXY_PORT}:3128",
         "-v", f"{config}:{CONTAINER_CONFIG}:ro",
         "--entrypoint", "/usr/sbin/squid", "--", SQUID_IMAGE, *SQUID_COMMAND],
    )  # fmt: skip
    try:
        ready = _ready(PANEL_PROXY_PORT, "ready.pridem-dm146.invalid")
        status: dict[str, tuple[str, bytes]] = {}
        status["ssh.github.com:443"] = _connect("ssh.github.com", 443)
        status["github.com:443"] = _connect("github.com", 443)
        status["ssh.github.com:22"] = _connect("ssh.github.com", 22)
        ssh = _run(
            ["ssh", "-T", "-p", "443",
             "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=no",
             "-o", "UserKnownHostsFile=/dev/null",
             "-o", f"ProxyCommand=python3 {script} %h %p 127.0.0.1 {PANEL_PROXY_PORT}",
             "git@ssh.github.com"],
            expect=tuple(range(256)), timeout=60,
        )  # fmt: skip
        log = _run(["docker", "logs", PANEL_PROXY], expect=tuple(range(256)))
    finally:
        _run(["docker", "rm", "-f", PANEL_PROXY], expect=tuple(range(256)))
    # the agent: a process of the box's host, straight out
    host_https = _run(
        ["curl", "-sS", "-o", "/dev/null", "-w", "%{http_code}",
         "https://api.github.com"],
        expect=tuple(range(256)), timeout=60,
    )  # fmt: skip
    with socket.create_connection(("ssh.github.com", 443), 15) as direct:
        banner = direct.recv(64)
    rules = {
        "iptables": _run(["iptables", "-S"], expect=tuple(range(256))),
        "nft": _run(["nft", "list", "ruleset"], expect=tuple(range(256))),
    }
    print(
        "DM-146 measure:",
        {"ready": ready, "proxy": status, "ssh": ssh[-3:], "log": log[-6:],
         "host https": host_https, "host ssh banner": banner, "rules": rules},
    )  # fmt: skip
    line, after = status["ssh.github.com:443"]
    assert " 200 " in f"{line} " and after.startswith(b"SSH-2.0-"), status
    assert " 403 " in f"{status['github.com:443'][0]} ", status
    assert " 403 " in f"{status['ssh.github.com:22'][0]} ", status
    assert any("Permission denied (publickey)" in line for line in ssh), ssh
    # out is any HTTP answer -- a status, not 000 (no connection): GitHub's
    # anonymous API says 403 to a runner's shared address over its hourly limit,
    # and the code is the environment's, not the way out's (FIX)
    [code] = host_https[-1:]
    assert re.fullmatch(r"[1-5][0-9][0-9]", code), host_https
    assert banner.startswith(b"SSH-2.0-"), banner
    for lines in rules.values():
        assert not any("pridem" in line for line in lines), rules


# --- DM-188 (S11): the proxy refuses a name off its list before resolving it ---

DNS_PROXY = "pridem-dm188-proxy"
DNS_PROXY_PORT = 3188
READY_S = 60.0
"""How long the probe waits for squid to answer through docker's port."""


class _Resolver:
    """A resolver on the runner that answers every question NXDOMAIN and keeps
    the names it was asked: squid's lookups, seen where they go (DM-188).
    UDP on port 53 of ``address`` -- the gateway of docker's ``bridge``, which
    the probe's squid is given by ``--dns``.

    FIX: the socket is read with a timeout and the thread stops on a flag --
    a ``close`` alone does not wake a ``recvfrom`` blocked in another thread,
    and the port stayed bound (measured: a second resolver in the same
    process failed with ``Address already in use``)."""

    def __init__(self, address: str) -> None:
        import socket

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind((address, 53))
        self.sock.settimeout(0.2)
        self.lock = threading.Lock()
        self.asked: list[str] = []
        self.stopped = threading.Event()
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def _serve(self) -> None:
        while not self.stopped.is_set():
            try:
                data, peer = self.sock.recvfrom(512)
            except TimeoutError:
                continue
            labels, at = [], 12
            while at < len(data) and data[at]:
                size = data[at]
                labels.append(data[at + 1 : at + 1 + size].decode(errors="replace"))
                at += 1 + size
            with self.lock:
                self.asked.append(".".join(labels).lower())
            # the header back as an answer (QR, RD, RA), NXDOMAIN, the question
            reply = data[:2] + b"\x81\x83" + data[4:6] + bytes(6) + data[12 : at + 5]
            self.sock.sendto(reply, peer)

    def names(self) -> list[str]:
        with self.lock:
            return list(self.asked)

    def close(self) -> None:
        self.stopped.set()
        self.thread.join(5)
        self.sock.close()


def _answer(port: int, request: str) -> str:
    """``request`` to a proxy on the runner: its status line, ``EOF`` when the
    connection closed without one, or the error -- never raised: an outcome
    is a fact for the log, the probe decides what it means (DM-188 FIX)."""
    import socket

    try:
        with socket.create_connection(("127.0.0.1", port), 10) as conn:
            conn.settimeout(60)
            conn.sendall(request.encode("ascii"))
            line = conn.makefile("rb").readline(256)
    except OSError as error:
        return repr(error)
    return line.decode(errors="replace").strip() or "EOF"


def _connect_request(host: str) -> str:
    return f"CONNECT {host}:443 HTTP/1.1\r\nHost: {host}:443\r\n\r\n"


def _ready(port: int, host: str) -> list[str]:
    """Until squid answers through docker's port: the outcomes on the way,
    each one once in a row. One wait, before the first request of the probe.

    docker returns from ``run -d`` before squid listens, and docker-proxy
    takes the connection all the same: in that window a request ends in
    ``EOF`` or ``ConnectionResetError``, never ``Connection refused``
    (measured with docker 29.1.3 and squid 6.6: the first look ends either
    way, the next one, 50 ms later, has squid's status line). The request is
    ``GET`` of a name off the list: refused by the first rule of either order
    -- ``deny !egress`` or ``deny !CONNECT`` -- with no lookup."""
    seen: list[str] = []
    deadline = time.monotonic() + READY_S
    while True:
        got = _answer(port, f"GET http://{host}/ HTTP/1.1\r\nHost: {host}\r\n\r\n")
        if not seen or seen[-1] != got:
            seen.append(got)
        if got.startswith("HTTP/") or time.monotonic() >= deadline:
            return seen
        time.sleep(0.1)


def _proxy_log() -> list[str]:
    """``docker logs`` of the probe's proxy, whatever state it is in."""
    return _run(["docker", "logs", DNS_PROXY], expect=tuple(range(256)))


def _group_elapsed_s() -> float:
    """Seconds since this pytest process started: the group's time so far."""
    fields = Path("/proc/self/stat").read_text().rpartition(")")[2].split()
    started = int(fields[19]) / os.sysconf("SC_CLK_TCK")  # field 22: starttime
    return float(Path("/proc/uptime").read_text().split()[0]) - started


def test_probe_DM_188_an_unlisted_name_is_never_resolved_by_the_proxy(
    tmp_path: Path,
) -> None:
    """DM-188 (REVIEW-0006, S11), on the runner after the machine's host steps
    (group a): the machine's proxy -- its image ``SQUID_IMAGE``, its config
    ``config_text`` -- refuses ``CONNECT`` to a name off its list without a
    lookup of that name: ``deny !egress`` is its first rule. squid is given a
    resolver of the probe's (``--dns``: its config is the machine's, untouched)
    that keeps every name it is asked; the names are new on every run, so no
    cache answers for them.

    What it asserts, and only that: the name off the list is not looked up --
    in pair with squid's own log line of that name (the request reached squid
    and was decided: a silence of the resolver means something). Its selftest,
    in the same run: the order before DM-188 (the planted defect -- ``deny
    !egress`` taken out) must make the resolver hear the name off the list; a
    resolver that hears nothing of it cannot see a lookup at all, and the probe
    is red with that fact, never green. The pair in both orders: the resolver
    hears the name of the list (``private`` is a ``dst``) -- by the resolver,
    not by an HTTP status.

    FIX (tier 3 #164, group a red, green again on a rerun): the readiness loop
    retried only an ``OSError``, and docker-proxy answers the window before
    squid listens with ``EOF`` as often as with a reset -- an ``EOF`` passed for
    the answer to the name off the list, and the next request, the listed
    name's, fell into the same window: ``ConnectionResetError``. Now one wait
    for squid's status line before the first request (``_ready``), every
    outcome is recorded and never raised, statuses are not asserted, and the
    measure -- squid's version, the names heard, every outcome, ``docker logs``
    of the proxy, the group's time -- is printed in ``finally``, before any
    assertion and on any failure (par0 14.3)."""
    from pridem.steps.egress import (
        CONTAINER_CONFIG,
        SQUID_COMMAND,
        SQUID_USER,
        config_text,
    )

    [inet] = [
        line
        for line in _stdout(["ip", "-4", "-o", "addr", "show", "docker0"])
        if " inet " in line
    ]
    gateway = inet.split(" inet ")[1].split("/")[0]
    _run(["docker", "pull", "-q", SQUID_IMAGE], timeout=300)
    version = _run(
        ["docker", "run", "--rm", "--entrypoint", "/usr/sbin/squid", SQUID_IMAGE, "-v"]
    )
    token = os.urandom(4).hex()
    listed = f"listed-{token}.pridem-dm188.invalid"
    text = config_text([listed])
    planted = text.replace("http_access deny !egress\n", "", 1)
    assert text.count("http_access deny !egress\n") == 1 and planted != text
    measured: dict[str, dict[str, object]] = {}
    resolver = _Resolver(gateway)
    try:
        for order, config_body in (("DM-188", text), ("planted", planted)):
            unlisted = f"unlisted-{order.lower()}-{token}.pridem-dm188.invalid"
            ready = f"ready-{order.lower()}-{token}.pridem-dm188.invalid"
            entry: dict[str, object] = {"unlisted": unlisted}
            measured[order] = entry
            before = len(resolver.names())  # what this order's squid asked
            config = tmp_path / f"{order}.conf"
            config.write_text(config_body, encoding="utf-8")
            config.chmod(0o644)
            _run(["docker", "rm", "-f", DNS_PROXY], expect=tuple(range(256)))
            _run(
                ["docker", "run", "-d", "--name", DNS_PROXY, "--user", SQUID_USER,
                 "--label", "pridem.test=DM-188", "--dns", gateway,
                 "-p", f"127.0.0.1:{DNS_PROXY_PORT}:3128",
                 "-v", f"{config}:{CONTAINER_CONFIG}:ro",
                 "--entrypoint", "/usr/sbin/squid", "--", SQUID_IMAGE, *SQUID_COMMAND],
            )  # fmt: skip
            try:
                entry["ready"] = _ready(DNS_PROXY_PORT, ready)
                entry["unlisted status"] = _answer(
                    DNS_PROXY_PORT, _connect_request(unlisted)
                )
                entry["listed status"] = _answer(
                    DNS_PROXY_PORT, _connect_request(listed)
                )
                for _ in range(50):  # squid writes the line when it is done
                    if any(f"host={unlisted} " in x for x in _proxy_log()):
                        break
                    time.sleep(0.1)
            finally:
                logs = _proxy_log()
                entry["state"] = _run(
                    ["docker", "inspect", "-f", "{{json .State}}", DNS_PROXY],
                    expect=tuple(range(256)),
                )
                entry["log"] = logs[-30:]
                _run(["docker", "rm", "-f", DNS_PROXY], expect=tuple(range(256)))
            heard = resolver.names()[before:]
            entry["heard"] = heard
            entry["heard unlisted"] = unlisted in heard
            entry["heard listed"] = listed in heard
            entry["logged unlisted"] = any(f"host={unlisted} " in x for x in logs)
    finally:
        resolver.close()
        warnings.warn(
            f"DM-188 measure: squid {version[:1]}, resolver {gateway}:53, "
            f"{json.dumps(measured, indent=1, default=str)}",
            stacklevel=1,
        )
        warnings.warn(f"group time so far: {_group_elapsed_s():.0f} s", stacklevel=1)
    # the selftest: the order before DM-188 makes squid ask for the name
    assert measured["planted"]["heard unlisted"] is True, (
        "the resolver heard nothing of a name off the list under the planted "
        f"order: the probe cannot see squid's lookups -- {measured['planted']}"
    )
    for order in ("DM-188", "planted"):  # the pair: the listed name is looked up
        assert measured[order]["heard listed"] is True, (order, measured[order])
    # the probe: squid decided on the name off the list without asking for it
    found = measured["DM-188"]
    assert found["logged unlisted"] is True, found  # it reached squid
    assert found["heard unlisted"] is False, found


def _container(project: str, service: str) -> str:
    [container] = _stdout(
        [
            "docker",
            "ps",
            "-q",
            "--no-trunc",
            "--filter",
            f"label=com.docker.compose.project={project}",
            "--filter",
            f"label=com.docker.compose.service={service}",
        ]
    )
    return container


def _volumes() -> dict[str, bool]:
    """Every volume on the box, and whether docker made it anonymous."""
    found: dict[str, bool] = {}
    for name in _stdout(["docker", "volume", "ls", "-q"]):
        labels = _stdout(
            ["docker", "volume", "inspect", "-f", "{{json .Labels}}", name]
        )
        found[name] = "com.docker.volume.anonymous" in "".join(labels)
    return found


def _box_db_head() -> str | None:
    """The head of the blank's database on the box, as ``alembic_version``
    holds it; ``None`` -- no database running, or no head yet, or no docker
    at all: a clean runner of group d before its first install has none (tier
    3 takes the runner's own docker off before the bootstrap) -- FIX 2."""
    try:
        running = _stdout(
            ["docker", "ps", "-q",
             "--filter", f"label=com.docker.compose.project={STACK}",
             "--filter", "label=com.docker.compose.service=postgres"]
        )  # fmt: skip
    except CommandNotStarted:
        return None  # no docker on the box: no database either
    if len(running) != 1:
        return None
    said: list[str] = []
    result = SubprocessRunner().run(
        ["docker", "exec", running[0], "psql", "-U", "blank", "-d", "blank",
         "-tAc", "SELECT version_num FROM alembic_version"],
        expect=(0, 1),
        timeout=60,
        on_line=lambda stream, line, cut: said.append(line)
        if stream is Stream.STDOUT
        else None,
    )  # fmt: skip
    heads = [line.strip() for line in said if line.strip()]
    return heads[0] if result.code == 0 and len(heads) == 1 else None


def _copy_of_blank(tmp: Path, mirror: Path, name: str) -> Path:
    """A clone of the mirror at ``BLANK_COMMIT`` -- with the migrations the
    box has taken its database to: a copy is code that knows its database's
    head, or ``migrate`` refuses it as ``db-ahead``, rightly (DM-24). Measured,
    not assumed: before the stop for migrate the database is at ``0001`` and
    a copy gets nothing; after it, at ``0002``, and every copy carries
    ``REVISION`` (DM-86 FIX of pass 4b -- the class, not one copy)."""
    copy = tmp / name
    _run(["git", "clone", "-q", str(mirror), str(copy)], env=GIT_ENV)
    _run(["git", "-C", str(copy), "checkout", "-q", BLANK_COMMIT], env=GIT_ENV)
    head = _box_db_head()
    if head == "0002":
        versions = copy / "backend" / "migrations" / "versions"
        (versions / REVISION_FILE).write_text(REVISION, encoding="utf-8")
    elif head not in (None, "0001"):
        raise AssertionError(f"the box's database is at {head}: no copy knows it")
    return copy


def _replace_once(file: Path, old: str, new: str) -> None:
    """``old`` -> ``new`` in ``file``, exactly once (par0 14.3)."""
    text = file.read_text(encoding="utf-8")
    assert text.count(old) == 1, (file, old)
    file.write_text(text.replace(old, new), encoding="utf-8")


def _push(copy: Path, mirror: Path, message: str) -> None:
    _git("-C", str(copy), "add", "-A")
    _git("-C", str(copy), "commit", "-q", "-m", message)
    _git("-C", str(copy), "push", "-q", "--force", str(mirror), "HEAD:refs/heads/main")


def _blank_without_service(tmp: Path, mirror: Path, step: int) -> None:
    """The blank with an edition that leaves its service out, consistent as a
    whole (par0 14.3): not in the edition, its seams not in ``env``, their
    variables not in compose; the dependency and its lock stay."""
    copy = _copy_of_blank(tmp, mirror, f"alone-{step}")
    primer = copy / "primer.yaml"
    _replace_once(
        primer,
        "  core: { services: [primer-blank-service] }",
        "  core: { services: [] }",
    )
    compose = copy / "docker-compose.yml"
    for key in SEAMS:
        text = primer.read_text(encoding="utf-8").splitlines(keepends=True)
        lines = [line for line in text if line.startswith(f"  {key}:")]
        assert len(lines) == 1, (key, lines)
        _replace_once(primer, lines[0], "")
        _replace_once(compose, f"      {key}: ${{{key}:?}}\n", "")
    _push(copy, mirror, f"DM-59: the blank without its service, step {step}")


def _blank_with_a_refused_profile(tmp: Path, mirror: Path, step: int) -> None:
    """The blank whose ``profile/`` the service's ``validate`` refuses: no
    ``ok`` in it, a file of its own so the directory stays."""
    copy = _copy_of_blank(tmp, mirror, f"refused-{step}")
    (copy / "profile" / "ok").unlink()
    (copy / "profile" / "kinds.yaml").write_text(f"step: {step}\n", encoding="utf-8")
    _push(copy, mirror, f"DM-59: a profile the service refuses, step {step}")


def _at_blank_commit(mirror: Path) -> None:
    _run(
        ["git", "--git-dir", str(mirror), "update-ref", "refs/heads/main", BLANK_COMMIT]
    )


def test_tier3_a_service_of_the_edition_goes_up_before_the_product(
    tmp_path: Path, mirror: Path
) -> None:
    """DM-46 stage A on the blank's own service (DM-59), on the box the
    earlier tests left. ``primer-blank-service`` is in every edition of the
    blank: it goes up by its own ladder (``render_env -> build -> derive_env
    -> data_copy``, then ``up``) before the product does, the product's
    ``profile/`` copied to it and validated by its image; a profile its
    ``validate`` refuses is red with the service and the product left running
    as they were; an edition that leaves it out installs nothing of it and
    names it as ``left``; ``doctor`` is empty on each green box.

    Changed by DM-126 (owner's decision of 19.11; by the dispatcher's word,
    before the change): the ladder is in two halves. It asserted every step
    of the service, ``up`` among them, before the product's ``render_env``;
    now the service's steps up to ``data_copy`` stand before it, the
    product's tests before the first ``migrate`` and before the service's
    ``up``, and the product's ``up`` after the service's.

    Changed by DM-59: the service was a copy of the blank as ``notes``; it is
    the blank's published service now, which the blank depends on in every
    edition -- the same assertions, on it."""
    assert (OPT / "current").is_symlink(), "the whole install runs first"

    # the blank at its pin: the service before the product, its profile
    _at_blank_commit(mirror)
    core = _passport(tmp_path, version=20)
    database = _database_state()
    green, printed = _install(core, "update")
    # DM-81: the database as the tests of this update left it -- a measure
    # in the run's log (par0 14.3), not an assertion: the tests step brings
    # it up with --no-recreate
    warnings.warn(
        f"DM-81 database before the update: {database}; after: {_database_state()}",
        stacklevel=1,
    )
    assert green.result == "green", printed
    order = [(s.stack, s.name) for s in green.steps if s.phase == "main"]
    for name in ("render_env", "build", "derive_env", "data_copy"):
        assert order.index((SERVICE, name)) < order.index((STACK, "render_env"))
    # DM-126: the product's tests before the first migrate, its up after the
    # service's
    assert order.index((STACK, "tests")) < order.index((STACK, "migrate")), order
    assert order.index((STACK, "tests")) < order.index((SERVICE, "up")), order
    assert order.index((SERVICE, "up")) < order.index((STACK, "up")), order
    facts = {(s.stack, s.name): s.verify or {} for s in green.steps}
    data = facts[(SERVICE, "data_copy")]["data"]
    assert isinstance(data, dict) and set(data) == {"profile"}, data
    copied = Path(str(data["profile"]))
    assert (copied / "ok").is_file() and copied.is_relative_to(f"/opt/{SERVICE}/data")
    # DM-81: the copy is named by what it holds, and it is what the app mounts
    assert copied.name.startswith("profile@"), copied
    assert facts[(SERVICE, "up")]["release"] == "v1.0.0", facts[(SERVICE, "up")]
    assert Path(f"/opt/{SERVICE}/current").resolve() == Path(
        f"/opt/{SERVICE}/releases/v1.0.0"
    )
    running = _container(SERVICE, "app")
    assert _data_source(running) == str(copied)
    inside = _stdout(["docker", "exec", running, "ls", "/primer/data/profile"])
    assert "ok" in inside, inside
    env = _stdout(["docker", "exec", running, "printenv", "PROFILE_DIR"])
    assert env == ["/primer/data/profile"], env
    diff, failed, doctor = _doctor(core)
    assert (diff, failed) == ([], []), doctor.model_dump_json()

    # a profile the service refuses: red at its validate, the service and the
    # product as they were -- the same containers, the old copy mounted
    product = _container(STACK, "app")
    _blank_with_a_refused_profile(tmp_path, mirror, step=2)
    bad, printed = _install(_passport(tmp_path, version=21), "update")
    assert bad.result != "green", printed
    [red] = [s for s in bad.steps if s.status == "failed"]
    assert (red.stack, red.name) == (SERVICE, "data_copy"), bad.steps
    assert red.reason is not None
    assert red.reason.code == "data_copy:validate-failed", red.reason
    assert _container(SERVICE, "app") == running
    assert _container(STACK, "app") == product
    inside = _stdout(["docker", "exec", running, "ls", "/primer/data/profile"])
    assert "ok" in inside, inside
    # DM-81: the running service still mounts the copy it was validated on;
    # the refused copy is there, bound by nothing that runs
    assert _data_source(running) == str(copied)
    assert (copied / "ok").is_file()

    # an edition without it: not touched, named as left
    _blank_without_service(tmp_path, mirror, step=3)
    alone = _passport(tmp_path, version=22)
    back, printed = _install(alone, "update")
    assert back.result == "green", printed
    assert not any(s.stack == SERVICE for s in back.steps), back.steps
    facts = {(s.stack, s.name): s.verify or {} for s in back.steps}
    assert facts[("pridem-seams", "seams_check")]["left"] == [SERVICE], facts
    assert _container(SERVICE, "app") == running
    diff, failed, doctor = _doctor(alone)
    assert (diff, failed) == ([], []), doctor.model_dump_json()


def _data_source(container: str) -> str:
    """The host directory ``container`` mounts at ``/primer/data/profile``."""
    [mounts] = _stdout(["docker", "inspect", "-f", "{{json .Mounts}}", container])
    found = [
        str(m["Source"])
        for m in json.loads(mounts)
        if m.get("Destination") == "/primer/data/profile"
    ]
    assert len(found) == 1, mounts
    return found[0]


def _database_state() -> str:
    """The blank's database container: its id, image and start time, or
    ``none``."""
    found = _stdout(
        [
            "docker", "ps", "-a", "-q", "--no-trunc",
            "--filter", f"label=com.docker.compose.project={STACK}",
            "--filter", "label=com.docker.compose.service=postgres",
        ]
    )  # fmt: skip
    if not found:
        return "none"
    fmt = "{{.Id}} {{.Image}} {{.State.StartedAt}} {{.State.Status}}"
    return " ".join(_stdout(["docker", "inspect", "-f", fmt, *found]))


def _containers_of(project: str) -> list[str]:
    """The IDs of every container of ``project``, running or not, sorted."""
    return sorted(
        _stdout(
            [
                "docker",
                "ps",
                "-a",
                "-q",
                "--no-trunc",
                "--filter",
                f"label=com.docker.compose.project={project}",
            ]
        )
    )


def test_tier3_two_instances_with_their_own_languages(
    tmp_path: Path, mirror: Path
) -> None:
    """DM-46 stage B on the box the earlier tests left: the blank at
    ``BLANK_COMMIT`` declares ``languages: [en, ru]``; one instance turns on
    ``[en]`` with ``en`` by default, the next ``[en, ru]`` with ``ru`` -- the
    frontend serves each its own ``/config.json`` from ``LANGUAGES`` and
    ``DEFAULT_LANGUAGE``; a third passport naming ``uk`` is red in
    ``seams_check`` before any ``act`` of a stack: the IDs of the blank's
    containers are the same before and after, and the page still serves the
    second instance's languages. ``doctor`` is empty on each green box."""
    assert (OPT / "current").is_symlink(), "the whole install runs first"
    _run(
        ["git", "--git-dir", str(mirror), "update-ref", "refs/heads/main", BLANK_COMMIT]
    )
    seen: dict[str, object] = {}
    for version, languages, default in ((30, ("en",), "en"), (31, ("en", "ru"), "ru")):
        passport = _passport(
            tmp_path, version=version, languages=languages, default_language=default
        )
        verdict, printed = _install(passport, "update")
        assert verdict.result == "green", printed
        env = _env()
        assert (env["LANGUAGES"], env["DEFAULT_LANGUAGE"]) == (
            ",".join(languages),
            default,
        ), printed
        served = json.loads(_body("/config.json", FRONTEND))
        assert served == {
            "apiBaseUrl": f"https://{API}",
            "languages": ",".join(languages),
            "defaultLanguage": default,
        }, served
        seen[",".join(languages)] = served
        diff, failed, doctor = _doctor(passport)
        assert (diff, failed) == ([], []), doctor.model_dump_json()
    assert len(seen) == 2  # two instances, two configurations of one image

    # uk is not a language of the product: red before any act of a stack
    before = _containers_of(STACK)
    assert before, "the blank runs"
    third = _passport(
        tmp_path, version=32, languages=("en", "uk"), default_language="en"
    )
    red, printed = _install(third, "update")
    assert red.result != "green", printed
    [failed] = [s for s in red.steps if s.status == "failed"]
    assert (failed.stack, failed.name) == ("pridem-seams", "seams_check"), red.steps
    assert failed.reason is not None
    assert failed.reason.code == "seams_check:language-outside-product", failed
    assert failed.reason.model_dump()["languages"] == ["uk"], failed.reason
    acted = [s.name for s in red.steps if s.stack == STACK and s.status == "ok"]
    assert acted == [], acted
    assert _containers_of(STACK) == before
    assert json.loads(_body("/config.json", FRONTEND))["languages"] == "en,ru"


OPTION_FILE = "/run/primer/probe.key"
"""The secret file of ``app`` under the option ``probe`` (DM-181)."""
OPTION_FILE_VALUE = "pridem-planted-option-file-181\nits second line\n"


def _blank_with_an_option(tmp: Path, mirror: Path) -> None:
    """The blank with an option of its own, consistent as a whole (par0 14.3):
    ``options: [probe]``, a variable ``PROBE_URL`` under ``when: probe`` in
    ``env`` and in the compose of ``app``, and a secret file ``AGE_KEY`` of
    ``app`` under it (DM-181: no line of the env file, compose names it
    nowhere); no host of ``egress`` (DM-62)."""
    copy = _copy_of_blank(tmp, mirror, "options")
    primer = copy / "primer.yaml"
    _replace_once(
        primer,
        "  SERVICE_API_URL:",
        "  PROBE_URL:         { source: param, when: probe }\n"
        "  AGE_KEY:           { source: asked, when: probe, file: { path: "
        f"{OPTION_FILE} }} }}\n"
        "  SERVICE_API_URL:",
    )
    text = primer.read_text(encoding="utf-8")
    primer.write_text(text + "options: [probe]\n", encoding="utf-8")
    _replace_once(
        copy / "docker-compose.yml",
        "      SERVICE_API_URL: ${SERVICE_API_URL:?}\n",
        "      SERVICE_API_URL: ${SERVICE_API_URL:?}\n"
        "      PROBE_URL: ${PROBE_URL:?}\n",
    )
    _push(copy, mirror, "DM-69: the blank with an option")


TYPES_OUT = "frontend/src/api/generated.ts"
DUMP_OPENAPI = """\
\"\"\"The blank's OpenAPI document to stdout: the copy's ``types.openapi``.\"\"\"

import json
import sys

from app.main import create_app

json.dump(create_app().app.openapi(), sys.stdout)
"""
GEN_TYPES = """\
\"\"\"The copy's frontend types from an OpenAPI file: ``types.generate`` (DM-63).\"\"\"

import json
import sys

source, target = sys.argv[1], sys.argv[2]
with open(source, encoding="utf-8") as file:
    paths = sorted(json.load(file)["paths"])
with open(target, "w", encoding="utf-8") as file:
    file.write("// generated by the machine from the app's OpenAPI\\n")
    file.write("export const PATHS = " + json.dumps(paths) + " as const;\\n")
"""


def _blank_with_types(tmp: Path, mirror: Path, name: str, route: bool) -> str:
    """The blank with ``types`` (DM-63), consistent as a whole (par0 14.3): the
    two commands in the app's package -- its image copies ``app/`` -- and the
    entry's ``types``; ``route`` -- one more route, an API that changed. The
    commit carries ``Task: DM-63``; its sha comes back."""
    copy = _copy_of_blank(tmp, mirror, name)
    (copy / "backend" / "app" / "dump_openapi.py").write_text(DUMP_OPENAPI)
    (copy / "backend" / "app" / "gen_types.py").write_text(GEN_TYPES)
    _replace_once(
        copy / "primer.yaml",
        "    migrate:  python -m alembic upgrade head\n",
        "    migrate:  python -m alembic upgrade head\n"
        "    types:    { openapi: python -m app.dump_openapi, generate: python -m"
        f" app.gen_types <openapi> <out>, out: {TYPES_OUT}, commit_as: blank-bot }}\n",
    )
    if route:
        _replace_once(
            copy / "backend" / "app" / "main.py",
            "    wrapped = report.install(app)\n",
            '    @app.get("/dm63")\n'
            "    async def dm63() -> dict[str, str]:\n"
            '        return {"dm": "63"}\n\n'
            "    wrapped = report.install(app)\n",
        )
    _push(copy, mirror, f"DM-63: the blank with types ({name})\n\nTask: DM-63")
    [sha] = _git("--git-dir", str(mirror), "rev-parse", "refs/heads/main")
    return sha


def _types_fact(verdict: Verdict) -> dict[str, object]:
    [step] = [s for s in verdict.steps if s.name == "types"]
    assert step.status == "ok" and step.verify is not None, step
    return dict(step.verify)


def test_tier3_types_are_made_by_the_products_commands(
    tmp_path: Path, mirror: Path
) -> None:
    """DM-63, on the box of its group: a copy of the blank with ``types``. An
    update makes the types by the copy's commands in a throwaway container of
    its app and commits ``out`` alone on top of the deployed commit, into the
    mirror, with the deployed commit's ``Task`` and the machine's trailer --
    after ``finalize``. The next update deploys that commit: nothing to commit.
    An API that changed -- one more route -- is a new types commit naming it."""
    assert (OPT / "current").is_symlink(), "the group's box is installed"
    copy = _blank_with_types(tmp_path, mirror, "types", route=False)
    verdict, printed = _install(_passport(tmp_path, version=60), "update")
    assert verdict.result == "green", printed
    fact = _types_fact(verdict)
    assert fact["types"] == "committed", fact
    [made] = _git("--git-dir", str(mirror), "rev-parse", "refs/heads/main")
    assert fact["commit"] == made
    assert _git("--git-dir", str(mirror), "rev-parse", f"{made}^") == [copy]
    changed = _git("--git-dir", str(mirror), "show", "--name-only", "--format=", made)
    assert [line for line in changed if line] == [TYPES_OUT]
    body = _git("--git-dir", str(mirror), "log", "-1", "--format=%B", made)
    assert body[:3] == [f"Regenerate {TYPES_OUT}", "", "Task: DM-63"], body
    assert body[3].startswith("Primer-Machine: types "), body
    tasks = "--format=%(trailers:key=Task,valueonly,separator=%x2C)"
    assert _git("--git-dir", str(mirror), "log", "-1", tasks, made) == ["DM-63"]
    text = _git("--git-dir", str(mirror), "show", f"{made}:{TYPES_OUT}")
    assert text[0] == "// generated by the machine from the app's OpenAPI", text
    assert '"/dm63"' not in text[1], text

    # the types commit deployed: nothing to commit
    verdict, printed = _install(_passport(tmp_path, version=61), "update")
    assert verdict.result == "green", printed
    assert _types_fact(verdict)["types"] == "current", verdict.steps
    assert _git("--git-dir", str(mirror), "rev-parse", "refs/heads/main") == [made]

    # an API that changed: a new types commit, the new route in it
    changed_api = _blank_with_types(tmp_path, mirror, "types-route", route=True)
    verdict, printed = _install(_passport(tmp_path, version=62), "update")
    assert verdict.result == "green", printed
    fact = _types_fact(verdict)
    assert fact["types"] == "committed", fact
    assert _git("--git-dir", str(mirror), "rev-parse", f"{fact['commit']}^") == [
        changed_api
    ]
    text = _git("--git-dir", str(mirror), "show", f"{fact['commit']}:{TYPES_OUT}")
    assert '"/dm63"' in text[1], text


BLANK_FIRST_REVISION_PATH = (
    "backend/migrations/versions/2026_10_25_0001_app_settings.py"
)
"""The blank's first revision: ``alembic heads`` loads every revision module,
never ``env.py`` (FIX 2, measured with alembic 1.20.1, the blank's pin)."""
REFUSING_REVISION = """\
import os

if not os.environ.get("DATABASE_URL"):  # as comms' revisions do (DM-124)
    raise SystemExit("blank: startup refused -- DATABASE_URL is required.")

"""


def test_tier3_alembic_runs_with_the_apps_environment(
    tmp_path: Path, mirror: Path
) -> None:
    """DM-124, on the box of its group: a copy of the blank whose first alembic
    revision refuses to load without ``DATABASE_URL`` -- empty or absent --
    as comms' do. An update -- green: ``stop_for_migrate`` and ``migrate`` read
    the head with the app's environment, and the migration ran. Measured into
    the run's log first (par0 14.3), on the image of the fact of ``build`` of
    the update: its ``ENV``, where alembic's scripts are, the refusal in the
    revision module, and the whole output of ``alembic heads`` without the
    environment -- which refuses, with the line that says why.

    FIX: the image of the pair is ``app_image`` of the fact of ``build`` of the
    update, run by its id -- not a name the test makes: group e names its
    images with the key of the build. FIX 2: the refusal is in a revision
    module, not ``env.py`` -- ``alembic heads`` never loads ``env.py``."""
    assert (OPT / "current").is_symlink(), "the group's box is installed"
    copy = _copy_of_blank(tmp_path, mirror, "env-alembic")
    revision = copy / BLANK_FIRST_REVISION_PATH
    revision.write_text(
        REFUSING_REVISION + revision.read_text(encoding="utf-8"), encoding="utf-8"
    )
    _push(copy, mirror, "DM-124: alembic's revisions refuse without DATABASE_URL")
    verdict, printed = _install(_passport(tmp_path, version=63), "update")
    # the image of the pair is the one the machine found and ran -- the fact of
    # build of this update -- never a name the test makes (FIX: group e names
    # its images with the key of the build, <commit12>-<key12>, DM-90/101)
    [build] = [s for s in verdict.steps if s.stack == STACK and s.name == "build"]
    image = str((build.verify or {}).get("app_image") or "")
    measured: dict[str, object] = {"image": image, "build": build.verify}
    bare: list[str] = []
    if image:
        inside = ["docker", "run", "--rm", "--network", "none", "--", image]
        measured["env"] = _run(
            ["docker", "image", "inspect", "-f", "{{json .Config.Env}}", image]
        )
        measured["script_location"] = _run(
            [*inside, "grep", "-n", "script_location", "/app/alembic.ini"],
            expect=tuple(range(256)),
        )
        measured["refusal"] = _run(
            [
                *inside,
                "grep",
                "-n",
                "DATABASE_URL",
                f"/app/{BLANK_FIRST_REVISION_PATH.removeprefix('backend/')}",
            ],
            expect=tuple(range(256)),
        )
        bare = _run(
            [*inside, "python", "-m", "alembic", "heads"], expect=tuple(range(256))
        )
        measured["without the environment"] = bare
    print("DM-124 measure:", measured)
    assert verdict.result == "green", printed
    assert image.startswith("sha256:"), build.verify
    facts = {s.name: s for s in verdict.steps if s.stack == STACK}
    assert facts["migrate"].status == "ok", facts["migrate"]
    assert any("DATABASE_URL is required" in line for line in bare), bare
    assert not (OPT / "env" / "alembic.env").exists()


SECRET_FILE_PATH = "/run/primer/age.key"  # noqa: S105 -- a path, not a secret
PLANTED_FILE_VALUE = "\n".join(
    [
        "pridem-tier3-planted-file-secret-145",
        "the second line of the planted secret file",
        "  an indented third line, then a short tail",
        "tail",
        "",
    ]
)
"""A planted multi-line value of no real key's form (DM-145)."""
READER_WITH_A_UID = """\
  reader:
    build:
      context: ./backend
      target: runtime
    user: "4242"
    command: ["python", "-m", "http.server", "7003"]
    healthcheck:
      test: ["CMD", "python", "-c", "open('/run/primer/age.key').read()"]
      interval: 10s
      timeout: 5s
      retries: 3
      start_period: 5s
    restart: unless-stopped
"""
"""A second service of the copy, under a uid its image has no entry for."""


def test_tier3_a_secret_file_in_the_live_container(
    tmp_path: Path, mirror: Path
) -> None:
    """DM-145 on the box of its group: a copy of the blank whose ``AGE_KEY`` is a
    secret file for ``app`` (``USER blank`` of the image) and ``reader``
    (``user: "4242"`` in compose, no entry in the image). Measured into the
    run's log first (par0 14.3): the user each service runs as, the owner and
    the mode of the file each sees, its sha256 read by each process against
    the value, a read by another uid, the containers' environment. Then: each
    file is the value byte for byte, 0600, owned by its process; the value is
    in no container's environment and not in the verdict."""
    import hashlib

    assert (OPT / "current").is_symlink(), "the group's box is installed"
    copy = _copy_of_blank(tmp_path, mirror, "secret-file")
    _replace_once(
        copy / "docker-compose.yml",
        "  postgres:\n",
        READER_WITH_A_UID + "  postgres:\n",
    )
    _replace_once(
        copy / "primer.yaml",
        "env:\n",
        "env:\n  AGE_KEY: { source: asked, file: { path: "
        f"{SECRET_FILE_PATH}, services: [app, reader] }} }}\n",
    )
    _push(copy, mirror, "DM-145: a secret file for two services")
    passport = _passport(
        tmp_path, version=64, asked={"primer-blank": {"AGE_KEY": PLANTED_FILE_VALUE}}
    )
    verdict, printed = _install(passport, "update")
    wanted = hashlib.sha256(PLANTED_FILE_VALUE.encode()).hexdigest()
    seen: dict[str, object] = {}
    for service in ("app", "reader"):
        running = _container(STACK, service)
        inside = ["docker", "exec", running]
        seen[service] = {
            "id": _run([*inside, "id"], expect=tuple(range(256))),
            "stat": _run(
                [*inside, "stat", "-c", "%u %g %a", SECRET_FILE_PATH],
                expect=tuple(range(256)),
            ),  # fmt: skip
            "sha256": _run(
                [*inside, "sha256sum", SECRET_FILE_PATH], expect=tuple(range(256))
            ),  # fmt: skip
            "other uid": _run(
                ["docker", "exec", "--user", "65534", running, "cat", SECRET_FILE_PATH],
                expect=tuple(range(256)),
            )[-1:],
            "env": _stdout(
                ["docker", "inspect", "-f", "{{json .Config.Env}}", running]
            ),
        }
    print("DM-145 measure:", seen)
    assert verdict.result == "green", printed
    for service in ("app", "reader"):
        found = seen[service]
        assert isinstance(found, dict)
        assert found["sha256"][0].split()[0] == wanted, (service, found)
        owner, group, mode = found["stat"][0].split()
        assert mode == "600", (service, found)
        assert f"uid={owner}(" in found["id"][0] or f"uid={owner} " in found["id"][0], (
            found
        )
        assert "Permission denied" in " ".join(found["other uid"]), found
        env = " ".join(found["env"])
        lines = [line for line in PLANTED_FILE_VALUE.splitlines() if len(line) >= 16]
        assert all(line not in env for line in lines), found
    reader = seen["reader"]
    assert isinstance(reader, dict) and reader["stat"][0].split()[:2] == ["4242", "0"]
    dumped = verdict.model_dump_json()
    assert all(line not in dumped for line in PLANTED_FILE_VALUE.splitlines()
               if len(line) >= 16)  # fmt: skip


def test_tier3_an_option_off_is_the_literal_and_on_the_value(
    tmp_path: Path, mirror: Path
) -> None:
    """DM-69 on the box the earlier tests left: a copy of the blank with the
    option ``probe``. The passport without it -- ``PROBE_URL`` is the literal
    in ``.env`` and in the app's container; with it -- the value. ``doctor``
    is empty on each green box.

    Changed by DM-181: the copy has a secret file ``AGE_KEY`` under the same
    option. Off -- the install and ``doctor`` are green (``render_env`` looked
    the file's key up in the env file: ``KeyError``) and ``app`` has no file at
    its path; on -- the file is the passport's value, byte for byte.

    Changed by DM-62 (by the owner's word, 09.11): no host of ``egress`` --
    on some runners ``api.github.com`` inside a container is ``127.0.0.2``
    and the proxy refuses it, rightly (DM-84). The proxy on tier 3 is held by
    the probe of DM-64, a host opened by an option -- by tier 1
    (``open_hosts``)."""
    assert (OPT / "current").is_symlink(), "the whole install runs first"
    _blank_with_an_option(tmp_path, mirror)
    off = _passport(tmp_path, version=50)
    verdict, printed = _install(off, "update")
    assert verdict.result == "green", printed
    assert _env()["PROBE_URL"] == "primer-switched-off", printed
    held = _stdout(["docker", "exec", _app(), "printenv", "PROBE_URL"])
    assert held == ["primer-switched-off"]
    assert _option_file() == ["absent"], printed
    diff, failed, doctor = _doctor(off)
    assert (diff, failed) == ([], []), doctor.model_dump_json()

    # the pair: the option on
    value = "https://probe.example.org/x"
    on = _passport(
        tmp_path,
        version=51,
        options=["probe"],
        params={STACK: {"PROBE_URL": value}},
        asked={STACK: {"AGE_KEY": OPTION_FILE_VALUE}},
    )
    verdict, printed = _install(on, "update")
    assert verdict.result == "green", printed
    assert _env()["PROBE_URL"] == value
    held = _stdout(["docker", "exec", _app(), "printenv", "PROBE_URL"])
    assert held == [value]
    wanted = hashlib.sha256(OPTION_FILE_VALUE.encode()).hexdigest()
    assert _option_file() == [f"{wanted}  {OPTION_FILE}"], printed
    diff, failed, doctor = _doctor(on)
    assert (diff, failed) == ([], []), doctor.model_dump_json()


def _option_file() -> list[str]:
    """``sha256sum`` of the secret file of the option in ``app``, or
    ``absent``."""
    path = OPTION_FILE
    script = f"if test -e {path}; then sha256sum {path}; else echo absent; fi"
    return _stdout(["docker", "exec", _app(), "sh", "-c", script])


ISOLATION_RUN = (
    'python -c "import socket, errno; s = socket.socket(); s.settimeout(5); '
    "c = s.connect_ex(('1.1.1.1', 443)); "
    "print('isolated-' + (errno.errorcode.get(c) or 'connected').lower()"
    " + '-dm79-probe')\""
)
"""A ``derive`` that tries the internet by address (no DNS on the way) and
prints what it got: ``isolated-enetunreach-dm79-probe`` with no network."""


def _host_config(project: str, service: str) -> dict[str, object]:
    container = _container(project, service)
    [line] = _stdout(["docker", "inspect", "-f", "{{json .HostConfig}}", container])
    found = json.loads(line)
    assert isinstance(found, dict)
    return found


def _caps(value: object) -> list[str]:
    """A list of ``HostConfig`` as sorted names, ``CAP_`` taken off; ``null``
    is none."""
    if value is None:
        return []
    assert isinstance(value, list), value
    return sorted(str(item).removeprefix("CAP_") for item in value)


def test_tier3_product_derive_reaches_nothing(tmp_path: Path, mirror: Path) -> None:
    """DM-79 on the box the earlier tests left: a copy of the blank with a
    ``derived`` key whose command connects to ``1.1.1.1:443`` from the
    product's image -- the value derived is the error of a container with no
    network (``ENETUNREACH``), in this run's image; the copy also declares
    ``egress`` so that the proxy runs. The confinement of nginx and the proxy
    is read off docker (``HostConfig``) and goes to the run's output (par0
    14.3): no capability but nginx's four, ``no-new-privileges``, a limit on
    processes, the host's ``local`` log driver. ``doctor`` is empty."""
    assert (OPT / "current").is_symlink(), "the whole install runs first"
    copy = _copy_of_blank(tmp_path, mirror, "isolation")
    primer = copy / "primer.yaml"
    _replace_once(
        primer,
        "  SERVICE_API_URL:",
        # a JSON string is a YAML double-quoted scalar
        f"  ISOLATION_PROBE: {{ source: derived, run: {json.dumps(ISOLATION_RUN)} }}\n"
        "  SERVICE_API_URL:",
    )
    text = primer.read_text(encoding="utf-8")
    primer.write_text(text + f"egress:\n  - {EGRESS_HOST}\n", encoding="utf-8")
    _push(copy, mirror, "DM-79: the blank derives from a container with no network")
    passport = _passport(tmp_path, version=55)
    verdict, printed = _install(passport, "update")
    assert verdict.result == "green", printed
    assert _env()["ISOLATION_PROBE"] == "isolated-enetunreach-dm79-probe"
    facts = {(s.stack, s.name): s.verify or {} for s in verdict.steps}
    assert (
        facts[(STACK, "derive_env")]["image"] == facts[(STACK, "build")]["app_image"]
    ), facts[(STACK, "derive_env")]
    assert facts[(STACK, "egress")]["hosts"] == [EGRESS_HOST], facts
    nginx = _host_config("pridem-edge", "nginx")
    proxy = _host_config("pridem-egress", "proxy")
    warnings.warn(f"DM-79 HostConfig nginx: {json.dumps(nginx)}", stacklevel=1)
    warnings.warn(f"DM-79 HostConfig proxy: {json.dumps(proxy)}", stacklevel=1)
    for found in (nginx, proxy):  # the names with or without CAP_ (unmeasured)
        assert _caps(found["CapDrop"]) == ["ALL"], found
        assert _caps(found["SecurityOpt"]) == ["no-new-privileges:true"], found
        assert found["PidsLimit"] == 256, found
        log = found["LogConfig"]
        assert isinstance(log, dict) and log["Type"] == "local", found
    assert _caps(nginx["CapAdd"]) == ["CHOWN", "NET_BIND_SERVICE", "SETGID", "SETUID"]
    assert _caps(proxy["CapAdd"]) == [], proxy
    diff, failed, doctor = _doctor(passport)
    assert (diff, failed) == ([], []), doctor.model_dump_json()


POINT_TAG = "v1.1.0"
"""The tag of the copy of the service with a point (DM-62): pushed to the
service's mirror beside ``v1.0.0``, which stays."""


def _service_with_a_point(tmp: Path) -> str:
    """A copy of the service at ``v1.0.0`` with a point of its own, consistent
    as a whole (par0 14.3): a second compose service ``point`` -- the same
    build, ``python -m http.server 7000`` -- the point ``probe`` on it in
    ``expose``, its address ``POINT_ADDRESS`` in ``env`` and ``provides`` --
    and in the app's environment and its ``/health.seams.provides``, as its
    three seams are (DM-62 FIX). Tagged ``POINT_TAG``; the commit back."""
    copy = tmp / "service-point"
    _run(["git", "clone", "-q", str(SERVICE_MIRROR), str(copy)], env=GIT_ENV)
    _run(["git", "-C", str(copy), "checkout", "-q", "v1.0.0"], env=GIT_ENV)
    compose = copy / "docker-compose.yml"
    compose.write_text(
        compose.read_text(encoding="utf-8") + "  point:\n"
        "    build:\n"
        "      context: ./backend\n"
        "      target: runtime\n"
        '    command: ["python", "-m", "http.server", "7000"]\n'
        "    healthcheck:\n"
        '      test: ["CMD", "python", "-c", "import urllib.request; '
        "urllib.request.urlopen('http://127.0.0.1:7000/', timeout=3)\"]\n"
        "      interval: 10s\n"
        "      timeout: 5s\n"
        "      retries: 3\n"
        "      start_period: 5s\n"
        "    restart: unless-stopped\n",
        encoding="utf-8",
    )
    primer = copy / "primer.yaml"
    _replace_once(
        primer,
        "    app: { service: app, port: 8000, health: /health, ready: /ready }\n",
        "    app: { service: app, port: 8000, health: /health, ready: /ready }\n"
        "    expose: { probe: { service: point, port: 7000, scheme: http } }\n",
    )
    _replace_once(
        primer,
        "  PRODUCT_WEBHOOK_URL: { source: seam, from: product }\n",
        "  PRODUCT_WEBHOOK_URL: { source: seam, from: product }\n"
        "  POINT_ADDRESS:       { source: address, endpoint: probe }\n",
    )
    _replace_once(
        primer,
        "provides: [SERVICE_API_URL, SERVICE_TOKEN, SERVICE_KEY]",
        "provides: [SERVICE_API_URL, SERVICE_TOKEN, SERVICE_KEY, POINT_ADDRESS]",
    )
    # the service says the new seam of itself as of its three (par0 14.3:
    # the copy consistent as a whole -- seams_verify reads /health.seams)
    _replace_once(
        copy / "docker-compose.yml",
        "      PRODUCT_WEBHOOK_URL: ${PRODUCT_WEBHOOK_URL:?}\n",
        "      PRODUCT_WEBHOOK_URL: ${PRODUCT_WEBHOOK_URL:?}\n"
        "      POINT_ADDRESS: ${POINT_ADDRESS:?}\n",
    )
    _replace_once(
        copy / "backend" / "app" / "config.py",
        '    key: str = Field(validation_alias="SERVICE_KEY", default="")\n',
        '    key: str = Field(validation_alias="SERVICE_KEY", default="")\n'
        '    point: str = Field(validation_alias="POINT_ADDRESS", default="")\n',
    )
    _replace_once(
        copy / "backend" / "app" / "main.py",
        '    "SERVICE_KEY": "key",\n',
        '    "SERVICE_KEY": "key",\n    "POINT_ADDRESS": "point",\n',
    )
    _git("-C", str(copy), "add", "-A")
    _git("-C", str(copy), "commit", "-q", "-m", "DM-62: a point")
    _git("-C", str(copy), "tag", "-f", POINT_TAG)
    _git(
        "-C",
        str(copy),
        "push",
        "-q",
        "--force",
        str(SERVICE_MIRROR),
        f"refs/tags/{POINT_TAG}",
    )
    return _stdout(["git", "-C", str(copy), "rev-parse", "HEAD"])[0]


def _blank_taking_the_point(tmp: Path, mirror: Path, commit: str) -> None:
    """The blank takes the point's address by a seam, gives it to ``app``,
    and locks the service at ``POINT_TAG``."""
    copy = _copy_of_blank(tmp, mirror, "point")
    _replace_once(
        copy / "primer.yaml",
        "  SERVICE_API_URL:   { source: seam, from: primer-blank-service }",
        "  POINT_ADDRESS:     { source: seam, from: primer-blank-service }\n"
        "  SERVICE_API_URL:   { source: seam, from: primer-blank-service }",
    )
    _replace_once(
        copy / "docker-compose.yml",
        "      SERVICE_API_URL: ${SERVICE_API_URL:?}\n",
        "      SERVICE_API_URL: ${SERVICE_API_URL:?}\n"
        "      POINT_ADDRESS: ${POINT_ADDRESS:?}\n",
    )
    _replace_once(
        copy / "primer.lock",
        f'{{ version: "1.0.0", tag: v1.0.0, commit: {SERVICE_PINS["v1.0.0"]} }}',
        f'{{ version: "1.1.0", tag: {POINT_TAG}, commit: {commit} }}',
    )
    _push(copy, mirror, "DM-62: the blank takes the point")


REACH_POINT = (
    "import sys, urllib.request\n"
    "try:\n"
    "    urllib.request.urlopen('http://' + sys.argv[1] + '/', timeout=5)\n"
    "    print('reached')\n"
    "except Exception as error:\n"
    "    print(type(error).__name__ + ': ' + str(error))\n"
)
"""Prints ``reached`` or the class and the text of what stopped it -- the
assertion reads what is printed, ``docker exec`` does not fail (DM-62 FIX 2)."""


def _point_diagnosis(address: str) -> None:
    """Into the run's log when the app does not reach the point (par0 14.3,
    as DM-58 and DM-59): the networks and aliases of ``app`` and ``point``,
    the state and the tail of the log of ``point``, the name resolved from
    inside ``app``."""
    point = _container(SERVICE, "point")
    seen: list[str] = []
    for name in (_app(), point):
        networks = _stdout(
            [
                "docker",
                "inspect",
                "--format",
                "{{json .NetworkSettings.Networks}}",
                name,
            ]
        )
        seen.append(f"{name} networks: {networks}")
    state = _stdout(["docker", "inspect", "--format", "{{json .State}}", point])
    logs = SubprocessRunner().run(
        ["docker", "logs", "--tail", "40", point],
        expect=(0, 1),
        timeout=60,
        on_line=lambda stream, line, cut: seen.append(f"point log: {line}"),
    )
    host = address.partition(":")[0]
    resolved = SubprocessRunner().run(
        ["docker", "exec", _app(), "getent", "hosts", host],
        expect=(0, 1, 2),
        timeout=60,
        on_line=lambda stream, line, cut: seen.append(f"getent {host}: {line}"),
    )
    seen += [
        f"point state: {state}",
        f"logs exit {logs.code}",
        f"getent exit {resolved.code}",
    ]
    warnings.warn("\n".join(seen), stacklevel=2)


def test_tier3_only_the_declared_consumer_reaches_a_point(
    tmp_path: Path, mirror: Path
) -> None:
    """DM-62 on the box the earlier tests left: the service opens a point on a
    second compose service, the blank takes its address by a seam. The app
    reaches it by ``<alias>:<port>``; a container on ``pridem`` -- any stack
    that declared nothing -- does not; the point's service is on no network
    but its pair's and its own. ``doctor`` is empty."""
    assert (OPT / "current").is_symlink(), "the whole install runs first"
    commit = _service_with_a_point(tmp_path)
    _blank_taking_the_point(tmp_path, mirror, commit)
    passport = _passport(tmp_path, version=60)
    verdict, printed = _install(passport, "update")
    assert verdict.result == "green", printed
    address = _env()["POINT_ADDRESS"]
    assert address == f"{SERVICE}-point:7000", address
    reached = _stdout(["docker", "exec", _app(), "python", "-c", REACH_POINT, address])
    if reached != ["reached"]:
        _point_diagnosis(address)
    assert reached == ["reached"]
    image = _stdout(["docker", "inspect", "--format", "{{.Image}}", _app()])[0]
    outsider = _stdout(
        [
            "docker", "run", "--rm", "--network", "pridem",
            "--label", "pridem.probe=dm-62", image,
            "python", "-c", REACH_POINT, address,
        ]
    )  # fmt: skip
    # read by what it printed, as the app (DM-62 FIX 2): not reached
    assert outsider and outsider != ["reached"], outsider
    point = _container(SERVICE, "point")
    networks = _stdout(
        ["docker", "inspect", "--format", "{{json .NetworkSettings.Networks}}", point]
    )
    attached = set(json.loads(networks[0]))
    assert "pridem" not in attached, attached
    assert any(name.startswith("pridem-pt-") for name in attached), attached
    diff, failed, doctor = _doctor(passport)
    assert (diff, failed) == ([], []), doctor.model_dump_json()


READER_TAG = "v1.2.0"
"""The tag of the copy of the service with a second reader of its data
(DM-100): pushed to the service's mirror beside ``v1.0.0``, which stays."""


def _service_with_a_reader(tmp: Path) -> str:
    """A copy of the service at ``v1.0.0`` whose profile two services read,
    consistent as a whole (par0 14.3): a second compose service ``reader`` --
    the same build, healthy only while ``PROFILE_DIR`` names a directory with
    files -- and ``accepts.profile.services: [app, reader]``. Tagged
    ``READER_TAG``; the commit back."""
    copy = tmp / "service-reader"
    _run(["git", "clone", "-q", str(SERVICE_MIRROR), str(copy)], env=GIT_ENV)
    _run(["git", "-C", str(copy), "checkout", "-q", "v1.0.0"], env=GIT_ENV)
    compose = copy / "docker-compose.yml"
    compose.write_text(
        compose.read_text(encoding="utf-8") + "  reader:\n"
        "    build:\n"
        "      context: ./backend\n"
        "      target: runtime\n"
        '    command: ["python", "-m", "http.server", "7001"]\n'
        "    healthcheck:\n"
        '      test: ["CMD", "python", "-c", "import os; '
        "assert os.listdir(os.environ['PROFILE_DIR'])\"]\n"
        "      interval: 10s\n"
        "      timeout: 5s\n"
        "      retries: 3\n"
        "      start_period: 5s\n"
        "    restart: unless-stopped\n",
        encoding="utf-8",
    )
    _replace_once(
        copy / "primer.yaml",
        "    env: PROFILE_DIR\n",
        "    env: PROFILE_DIR\n    services: [app, reader]\n",
    )
    _git("-C", str(copy), "add", "-A")
    _git("-C", str(copy), "commit", "-q", "-m", "DM-100: a second reader")
    _git("-C", str(copy), "tag", "-f", READER_TAG)
    _git(
        "-C",
        str(copy),
        "push",
        "-q",
        "--force",
        str(SERVICE_MIRROR),
        f"refs/tags/{READER_TAG}",
    )
    [commit] = _git("-C", str(copy), "rev-parse", "HEAD")
    return commit


def _blank_on_the_reader(tmp: Path, mirror: Path, commit: str) -> None:
    """The blank at its pin, the service locked at ``READER_TAG``."""
    copy = _copy_of_blank(tmp, mirror, "reader")
    _replace_once(
        copy / "primer.lock",
        f'{{ version: "1.0.0", tag: v1.0.0, commit: {SERVICE_PINS["v1.0.0"]} }}',
        f'{{ version: "1.2.0", tag: {READER_TAG}, commit: {commit} }}',
    )
    _push(copy, mirror, "DM-100: the blank on the service's second reader")


HOLD_THE_LOCK = [
    "sh",
    "-c",
    "setsid flock -x /opt/pridem/lock sleep 120 </dev/null >/dev/null 2>&1 & echo $!",
]
"""A process that takes the box's lock and keeps it, as a run does: the pid of
the leader of its own group (``setsid``) -- ``flock`` and its ``sleep``, which
holds the lock's descriptor too."""


def _home_files() -> dict[str, bytes]:
    """The machine's home but its passport copy: ``history/``, ``journal/``,
    the lock, ``state.json``."""
    home = Path("/opt/pridem")
    return {
        str(path.relative_to(home)): path.read_bytes()
        for name in ("history", "journal")
        for path in sorted((home / name).iterdir())
    } | {
        name: (home / name).read_bytes()
        for name in ("lock", "state.json")
        if (home / name).is_file()
    }


def test_tier3_state_of_the_box_with_its_lock_held() -> None:
    """DM-136, the last of group ``f``, on the box the blank's installs left:
    another process holds the box's lock. ``pridem --json state`` answers,
    exit 0, and the machine's home -- ``history/``, ``journal/``, the lock,
    ``state.json`` -- is byte for byte what it was. The state names the
    process, each stack with the machine's mark and each entry of the
    ``primer.yaml`` of its ``current``, every resource measured, and the
    self-signed certificate with its end as ``openssl`` reads it. ``ssl
    status`` names each domain of the passport.

    Measured into the run's output first (par0 14.3): the whole form, the
    console of ``state`` and ``ssl status``, the time of each call."""
    assert (OPT / "current").is_symlink(), "the blank's install runs first"
    before = _home_files()
    [pid] = _stdout(HOLD_THE_LOCK)
    try:
        started = time.monotonic()
        code, out, err = _pridem("--json", "state")
        spent = time.monotonic() - started
        console = _pridem("state")
        started = time.monotonic()
        ssl = _pridem("ssl", "status")
        ssl_spent = time.monotonic() - started
    finally:
        _stdout(["kill", "--", f"-{pid}"])  # flock and its sleep: the group
    print("DM-136 measure: state", {"seconds": round(spent, 2), "form": out})
    print("DM-136 measure: console", console[1], "ssl status", ssl[1])
    print("DM-136 measure: ssl status seconds", round(ssl_spent, 2))
    assert (code, err) == (0, []), err
    assert _home_files() == before
    state = json.loads("\n".join(out))
    assert any(f"pid {pid} " in holder for holder in state["lock_open_by"]), state
    marked = sorted(
        home.name for home in Path("/opt").iterdir() if (home / ".pridem").is_file()
    )
    stacks = {stack["stack"]: stack for stack in state["stacks"]}
    assert sorted(stacks) == marked, (marked, stacks)
    for name in (STACK, SERVICE):
        release = Path(f"/opt/{name}/current").resolve()
        declared = yaml.safe_load((release / "primer.yaml").read_text())["stacks"]
        assert stacks[name]["release"] == release.name
        entries = {entry["entry"]: entry for entry in stacks[name]["entries"]}
        assert sorted(entries) == sorted(declared), (declared, entries)
        for entry in entries.values():
            assert isinstance(entry["services"], list) and entry["services"], entry
    blank = {entry["entry"]: entry for entry in stacks[STACK]["entries"]}
    assert blank[FILES]["persistent"] is True
    resources = state["resources"]
    for part in (resources["memory"], resources["swap"], resources["images"]):
        assert "unmeasured" not in part, resources
    assert all("unmeasured" not in disk["space"] for disk in resources["disk"])
    ends = _stdout(
        ["openssl", "x509", "-in", "/opt/pridem/edge/certs/fullchain.pem",
         "-noout", "-enddate"]
    )  # fmt: skip
    end = datetime.strptime(
        " ".join(ends[0].split("=", 1)[1].split()), "%b %d %H:%M:%S %Y %Z"
    ).strftime("%Y-%m-%dT%H:%M:%SZ")
    assert state["ssl"]["mode"] == "self-signed", state["ssl"]
    assert state["ssl"]["expires"] == end and state["ssl"]["self_signed"] is True
    copy = yaml.safe_load(Path("/opt/pridem/passport.yaml").read_text())
    domains = sorted(set(copy["domains"].values()))
    assert [d["domain"] for d in state["ssl"]["domains"]] == domains
    assert ssl[0] == 0, ssl
    assert all(any(domain in line for line in ssl[1]) for domain in domains), ssl


def test_tier3_every_listed_service_reads_the_data(
    tmp_path: Path, mirror: Path
) -> None:
    """DM-100 on the box the earlier tests left: the service's profile goes to
    both services of ``accepts.profile.services`` -- ``app`` and ``reader``
    mount the same copy, read-only, and both have ``PROFILE_DIR``; ``reader``
    is healthy only so. Measured into the run's log first (par0 14.3):
    ``.Mounts`` and the variable of both."""
    assert (OPT / "current").is_symlink(), "the whole install runs first"
    commit = _service_with_a_reader(tmp_path)
    _blank_on_the_reader(tmp_path, mirror, commit)
    verdict, printed = _install(_passport(tmp_path, version=70), "update")
    seen = []
    for name in ("app", "reader"):
        running = _container(SERVICE, name)
        [mounts] = _stdout(["docker", "inspect", "-f", "{{json .Mounts}}", running])
        env = _stdout(["docker", "exec", running, "printenv", "PROFILE_DIR"])
        seen.append(f"{name}: mounts {mounts}; PROFILE_DIR {env}")
    warnings.warn("DM-100 " + " | ".join(seen), stacklevel=1)
    assert verdict.result == "green", printed
    app = _data_source(_container(SERVICE, "app"))
    reader = _data_source(_container(SERVICE, "reader"))
    assert app == reader and Path(app).name.startswith("profile@"), (app, reader)
    for name in ("app", "reader"):
        running = _container(SERVICE, name)
        [mounts] = _stdout(["docker", "inspect", "-f", "{{json .Mounts}}", running])
        [data] = [
            m for m in json.loads(mounts) if m["Destination"] == "/primer/data/profile"
        ]
        assert data["RW"] is False, data
        env = _stdout(["docker", "exec", running, "printenv", "PROFILE_DIR"])
        assert env == ["/primer/data/profile"], (name, env)


STORE_TAG = "v1.3.0"
"""The tag of the copy of the service that takes a point of the product
(DM-23, velo-dev 19.11): pushed beside ``v1.0.0``, which stays."""
STORE = """\
  store:
    build:
      context: ./backend
      target: runtime
    command: ["python", "-m", "http.server", "7002"]
    healthcheck:
      test:
        - CMD
        - python
        - -c
        - "import socket as s; s.create_connection(('127.0.0.1', 7002), 3)"
      interval: 10s
      timeout: 5s
      retries: 3
      start_period: 5s
    restart: unless-stopped
"""


def _service_taking_a_point(tmp: Path) -> str:
    """A copy of the service at ``v1.0.0`` that takes ``STORE_ADDRESS``, the
    point ``files`` of the product's entry -- comms and ``velo-storage`` on
    velo-dev: its app names the variable, so it joins the pair's network.
    Tagged ``STORE_TAG``; the commit back."""
    copy = tmp / "service-store"
    _run(["git", "clone", "-q", str(SERVICE_MIRROR), str(copy)], env=GIT_ENV)
    _run(["git", "-C", str(copy), "checkout", "-q", "v1.0.0"], env=GIT_ENV)
    _replace_once(
        copy / "primer.yaml",
        "  PRODUCT_WEBHOOK_URL: { source: seam, from: product }\n",
        "  PRODUCT_WEBHOOK_URL: { source: seam, from: product }\n"
        "  STORE_ADDRESS:       { source: seam, from: product }\n",
    )
    _replace_once(
        copy / "primer.yaml",
        "requires: [PRODUCT_WEBHOOK_URL]\n",
        "requires: [PRODUCT_WEBHOOK_URL, STORE_ADDRESS]\n",
    )
    _replace_once(
        copy / "docker-compose.yml",
        "      PRODUCT_WEBHOOK_URL: ${PRODUCT_WEBHOOK_URL:?}\n",
        "      PRODUCT_WEBHOOK_URL: ${PRODUCT_WEBHOOK_URL:?}\n"
        "      STORE_ADDRESS: ${STORE_ADDRESS:?}\n",
    )
    _git("-C", str(copy), "add", "-A")
    _git("-C", str(copy), "commit", "-q", "-m", "DM-23: the service takes a point")
    _git("-C", str(copy), "tag", "-f", STORE_TAG)
    _git(
        "-C", str(copy), "push", "-q", "--force", str(SERVICE_MIRROR),
        f"refs/tags/{STORE_TAG}",
    )  # fmt: skip
    [commit] = _git("-C", str(copy), "rev-parse", "HEAD")
    return commit


def _blank_giving_a_point(tmp: Path, mirror: Path, commit: str) -> None:
    """The blank at its pin with a point ``files`` on its entry -- a service
    ``store`` -- given to its service as ``STORE_ADDRESS``; the service locked
    at ``STORE_TAG``. Consistent as a whole (par0 14.3)."""
    copy = _copy_of_blank(tmp, mirror, "store")
    compose = copy / "docker-compose.yml"
    text = compose.read_text(encoding="utf-8")
    _replace_once(compose, "  postgres:\n", STORE + "  postgres:\n")
    assert compose.read_text(encoding="utf-8") != text
    _replace_once(
        copy / "primer.yaml",
        "    migrate:  python -m alembic upgrade head\n",
        "    migrate:  python -m alembic upgrade head\n"
        "    expose:   { files: { service: store, port: 7002, scheme: http } }\n",
    )
    _replace_once(
        copy / "primer.yaml",
        "provides:                             # what the product gives its service\n",
        "provides:                             # what the product gives its service\n"
        "  STORE_ADDRESS: { stack: primer-blank, endpoint: files }\n",
    )
    _replace_once(
        copy / "primer.lock",
        f'{{ version: "1.0.0", tag: v1.0.0, commit: {SERVICE_PINS["v1.0.0"]} }}',
        f'{{ version: "1.3.0", tag: {STORE_TAG}, commit: {commit} }}',
    )
    # FIX: the app says what it provides in /health (seams.provides), and the
    # machine checks it live (seams_verify) -- the new seam goes there too, and
    # into the blank's own tests of /health, which the step tests runs
    _replace_once(
        copy / "backend" / "app" / "main.py",
        'PROVIDES = ["PRODUCT_WEBHOOK_URL"]\n',
        'PROVIDES = ["PRODUCT_WEBHOOK_URL", "STORE_ADDRESS"]\n',
    )
    health = copy / "backend" / "tests" / "test_health.py"
    text = health.read_text(encoding="utf-8")
    pinned = '"provides": ["PRODUCT_WEBHOOK_URL"],'
    assert text.count(pinned) == 2, text.count(pinned)
    health.write_text(
        text.replace(pinned, '"provides": ["PRODUCT_WEBHOOK_URL", "STORE_ADDRESS"],'),
        encoding="utf-8",
    )
    _push(copy, mirror, "DM-23: the blank gives its service a point")


def test_tier3_a_service_takes_a_point_of_the_product(
    tmp_path: Path, mirror: Path
) -> None:
    """DM-23 (velo-dev 19.11) on the box the earlier tests left: the service
    takes a point of the product's entry -- its ladder runs before the
    product's. The network of the pair is made by ``pair_networks`` before
    any stack; the update is green; the service's app is on that network, the
    product's ``store`` too. Measured into the run's log first (par0 14.3):
    the order of the steps and the network as docker has it."""
    assert (OPT / "current").is_symlink(), "the whole install runs first"
    commit = _service_taking_a_point(tmp_path)
    _blank_giving_a_point(tmp_path, mirror, commit)
    verdict, printed = _install(_passport(tmp_path, version=71), "update")
    order = [(s.stack, s.name) for s in verdict.steps]
    names = [
        line
        for line in _run(
            [
                "docker",
                "network",
                "ls",
                "--filter",
                "label=pridem.point",
                "--format",
                "{{.Name}}",
            ],
        )  # fmt: skip
        if line.startswith("pridem-pt-")
    ]
    seen = {
        name: _run(
            [
                "docker",
                "network",
                "inspect",
                "--format",
                "{{.Internal}} {{json .Labels}}",
                name,
            ],
        )  # fmt: skip
        for name in names
    }
    app = _container(STACK, "app")
    [health] = _stdout(
        ["docker", "exec", app, "python", "-c",
         "import urllib.request as u; "
         "print(u.urlopen('http://127.0.0.1:8000/health').read().decode())"],
    )  # fmt: skip
    print(
        "DM-23 measure:",
        {"order": order, "networks": seen, "seams": json.loads(health).get("seams")},
    )
    assert verdict.result == "green", printed
    made = order.index(("pridem-points", "pair_networks"))
    first_service = order.index((SERVICE, "render_env"))
    assert made < first_service, order
    [network] = [
        name
        for name, lines in seen.items()
        if '"pridem.point":"primer-blank/files"' in lines[0]
        and '"pridem.consumer":"primer-blank-service"' in lines[0]
    ]
    assert seen[network][0].startswith("true "), seen[network]
    for stack, service in ((SERVICE, "app"), (STACK, "store")):
        running = _container(stack, service)
        [attached] = _stdout(
            ["docker", "inspect", "-f", "{{json .NetworkSettings.Networks}}", running]
        )
        assert network in json.loads(attached), (stack, service, attached)


JOB_RUN = (
    'python -c "import datetime; '
    "open('/tmp/runs', 'a').write(datetime.datetime.now().isoformat() + chr(10))\""
)
"""The job of the copy: a line in its volume per run, the time of the run."""


def _blank_with_a_job(tmp: Path, mirror: Path, name: str, run: str) -> None:
    """The blank with a job, consistent as a whole (par0 14.3): a service
    ``init`` of the app's image, no healthcheck, no ``restart``, on
    ``postgres`` healthy; no service depends on it in compose -- the machine
    runs it before them (DM-22 FIX: ``depends_on`` on it made compose run it
    again, measured); ``jobs: {init}`` in the entry; the job's volume at
    ``/tmp`` -- the image's ``/tmp`` is 1777, so the user ``blank`` writes
    there."""
    copy = _copy_of_blank(tmp, mirror, name)
    _replace_once(
        copy / "primer.yaml",
        "    migrate:  python -m alembic upgrade head\n",
        "    migrate:  python -m alembic upgrade head\n"
        "    jobs:     { init: { service: init } }\n",
    )
    compose = copy / "docker-compose.yml"
    _replace_once(
        compose,
        "\n  postgres:\n",
        "\n  init:\n"
        "    build:\n      context: ./backend\n      target: runtime\n"
        f"    command: {json.dumps(run)}\n"
        "    volumes:\n      - jobs:/tmp\n"
        "    depends_on:\n      postgres: { condition: service_healthy }\n"
        "\n  postgres:\n",
    )
    _replace_once(
        compose, "volumes:\n  pgdata: {}\n", "volumes:\n  pgdata: {}\n  jobs: {}\n"
    )
    _push(copy, mirror, f"DM-22: the blank with a job ({name})")


def _runs() -> list[str]:
    """The lines the job wrote, read from its volume by the image of
    ``postgres`` -- on the box already, no network."""
    [image] = _stdout(
        ["docker", "inspect", "-f", "{{.Config.Image}}", _container(STACK, "postgres")]
    )
    return _stdout(
        ["docker", "run", "--rm", "--network", "none", "-v",
         f"{STACK}_jobs:/v", image, "cat", "/v/runs"]
    )  # fmt: skip


def _job_containers() -> list[str]:
    """Every container compose made for ``init``, running or not: name,
    ``oneoff``, restart policy -- measured into the journal (DM-22 FIX)."""
    found = _stdout(
        ["docker", "ps", "-a", "-q", "--no-trunc",
         "--filter", f"label=com.docker.compose.project={STACK}",
         "--filter", "label=com.docker.compose.service=init"]
    )  # fmt: skip
    form = (
        '{{.Name}} oneoff={{index .Config.Labels "com.docker.compose.oneoff"}} '
        "restart={{.HostConfig.RestartPolicy.Name}} state={{.State.Status}}"
    )
    return _stdout(["docker", "inspect", "-f", form, *found]) if found else []


def _started(service: str) -> str:
    [at] = _stdout(
        ["docker", "inspect", "-f", "{{.State.StartedAt}}", _container(STACK, service)]
    )
    return at


def _up_fact(verdict: Verdict) -> dict[str, object]:
    [up] = [s for s in verdict.steps if (s.stack, s.name) == (STACK, "up")]
    return dict(up.verify or {})


def test_tier3_a_job_runs_before_its_dependent_on_every_deploy(
    tmp_path: Path, mirror: Path
) -> None:
    """DM-22, contract 3 rule 24, on the box the earlier tests left: a copy of
    the blank with the job ``init``. A deploy that acts runs it once, after
    ``postgres`` and before the app -- a line in its volume, ``up`` names it,
    ``doctor`` is empty; the next deploy -- a new commit of the copy -- runs
    it again; an update with nothing changed -- not (the reading of "every
    deploy" at the gate: a deploy that changes the entry -- commit,
    environment, data, package -- and not the passport's number alone, FIX
    2). The pair: the job exits 1 -- red ``up``, the app the same container.
    Measured into the journal of the run (par0 14.3): when ``postgres``, the
    job and the app started -- compose 2.40 under
    ``--no-deps --wait`` and ``run --rm``."""
    assert (OPT / "current").is_symlink(), "the whole install runs first"
    _blank_with_a_job(tmp_path, mirror, "job", JOB_RUN)
    first = _passport(tmp_path, version=40)
    verdict, printed = _install(first, "update")
    assert verdict.result == "green", printed
    runs = _runs()
    print("DM-22 measure:", {"postgres": _started("postgres"), "job": runs,
                             "app": _started("app"),
                             "job containers": _job_containers()})  # fmt: skip
    assert _up_fact(verdict).get("jobs") == ["init"], verdict.steps
    assert len(runs) == 1, runs
    diff, failed, doctor = _doctor(first)
    assert (diff, failed) == ([], []), doctor.model_dump_json()

    # FIX 2: a new commit of the copy (the same files, a commit of its own);
    # the passport's number alone changes nothing in the entry
    _blank_with_a_job(tmp_path, mirror, "job-again", JOB_RUN)
    second = _passport(tmp_path, version=41)
    verdict, printed = _install(second, "update")
    assert verdict.result == "green", printed
    assert _up_fact(verdict).get("jobs") == ["init"], verdict.steps
    assert len(_runs()) == 2

    verdict, printed = _install(second, "update")  # nothing changed
    assert verdict.result == "green", printed
    assert "jobs" not in _up_fact(verdict), verdict.steps
    assert len(_runs()) == 2
    diff, failed, doctor = _doctor(second)
    assert (diff, failed) == ([], []), doctor.model_dump_json()

    # the pair: the job exits 1 -- red, the app not brought up anew
    app = _container(STACK, "app")
    _blank_with_a_job(tmp_path, mirror, "job-red", 'python -c "raise SystemExit(1)"')
    red, printed = _install(_passport(tmp_path, version=42), "update")
    assert red.result != "green", printed
    [failed_step] = [s for s in red.steps if s.status == "failed"]
    assert (failed_step.stack, failed_step.name) == (STACK, "up"), red.steps
    assert failed_step.reason is not None
    assert failed_step.reason.code == "command-failed", failed_step.reason
    assert "init" in failed_step.reason.model_dump()["argv"], failed_step.reason
    assert _container(STACK, "app") == app
    # DM-90: the new commit was built before the red step; a compose command of
    # the release current names takes the image of its own commit, by the name
    # its override gives it -- never the new build's, never pulled
    current = (OPT / "current").resolve()
    config = json.loads(
        "\n".join(
            _stdout(
                [
                    "docker", "compose", "-p", STACK, "--env-file", str(ENV),
                    "-f", str(current / "docker-compose.yml"),
                    "-f", f"{OPT}/compose/{STACK}.yml",
                    "config", "--format", "json",
                ]
            )
        )
    )  # fmt: skip
    body = config["services"]["app"]
    label = '{{index .Config.Labels "pridem.commit"}}'
    [commit] = _stdout(["docker", "image", "inspect", "-f", label, body["image"]])
    warnings.warn(
        f"DM-90 current {current.name[:12]}: app image {body['image']}, "
        f"pull_policy {body.get('pull_policy')}, its commit {commit[:12]}",
        stacklevel=1,
    )
    assert body["image"] == f"{STACK}-app:{current.name[:12]}", body["image"]
    assert body.get("pull_policy") == "never", body
    assert commit == current.name, (commit, current.name)


REVISION_FILE = "2026_11_10_0002_dm22.py"
REVISION = """\"\"\"dm22 probe

Revision ID: 0002
Revises: 0001
\"\"\"

import sqlalchemy as sa
from alembic import op

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("app_settings", sa.Column("dm22", sa.Text(), nullable=True))


def downgrade() -> None:
    op.drop_column("app_settings", "dm22")
"""
"""A migration of the copy: the head moves, so ``migrate`` acts."""


def _blank_stopping_for_migrate(tmp: Path, mirror: Path) -> None:
    """The blank with ``stop_for_migrate: [frontend]`` and a new revision,
    consistent as a whole (par0 14.3): ``frontend`` depends on nothing, the
    app's ``run --rm`` of ``migrate`` does not bring it back; the revision
    after ``0001``, in the image's migrations."""
    copy = _copy_of_blank(tmp, mirror, "stop")
    _replace_once(
        copy / "primer.yaml",
        "    migrate:  python -m alembic upgrade head\n",
        "    migrate:  python -m alembic upgrade head\n"
        "    stop_for_migrate: [frontend]\n",
    )
    versions = copy / "backend" / "migrations" / "versions"
    (versions / REVISION_FILE).write_text(REVISION, encoding="utf-8")
    _push(copy, mirror, "DM-22: the blank stops its frontend for migrate")


def test_tier3_services_stopped_for_migrate_come_back(
    tmp_path: Path, mirror: Path
) -> None:
    """DM-22, protocol 6.3, contract 3 rule 35: a copy of the blank with
    ``stop_for_migrate: [frontend]`` and a new head. The run stops
    ``frontend`` before ``migrate`` (the step's fact; ``stop_for_migrate``
    stands before ``migrate`` in the verdict), ``migrate`` moves the head,
    ``up`` brings ``frontend`` back -- running, started after the run
    began; ``doctor`` is empty. Measured into the journal of the run (par0
    14.3): ``frontend`` started before and after."""
    assert (OPT / "current").is_symlink(), "the whole install runs first"
    before = _started("frontend")
    _blank_stopping_for_migrate(tmp_path, mirror)
    passport = _passport(tmp_path, version=43)
    verdict, printed = _install(passport, "update")
    assert verdict.result == "green", printed
    after = _started("frontend")
    print("DM-22 measure:", {"frontend before": before, "frontend after": after})
    names = [s.name for s in verdict.steps if s.stack == STACK]
    assert names.index("stop_for_migrate") + 1 == names.index("migrate"), names
    facts = {(s.stack, s.name): s.verify or {} for s in verdict.steps}
    assert facts[(STACK, "stop_for_migrate")]["stopped"] == ["frontend"], facts
    assert facts[(STACK, "migrate")]["alembic_head"] == "0002", facts
    assert _container(STACK, "frontend")  # running again
    assert after > before, (before, after)
    diff, failed, doctor = _doctor(passport)
    assert (diff, failed) == ([], []), doctor.model_dump_json()


def _psql(sql: str) -> list[str]:
    """``psql`` in the blank's database, its rows printed bare."""
    pg = _container(STACK, "postgres")
    return _stdout(
        ["docker", "exec", pg, "psql", "-U", "blank", "-d", "blank", "-tAc", sql]
    )


def test_tier3_a_dump_of_the_blank_restores_what_was_in_it() -> None:
    """DM-86, pass 1, on the box the earlier tests left: a row in
    ``app_settings``; ``db dump`` -- the dump and its manifest under
    ``/opt/pridem/backups/<run_id>/`` (0600), its table of contents read
    back; the row deleted; ``db restore --confirm <server.name>`` -- the row
    back, the app running, the head of the manifest; DM-94 -- the live
    database dumped first, named in the fact, and its restore gives the
    database before (the row gone again). ``backup`` -- green with
    the policy of this box's passport off: the fact says so, no new directory
    of dumps (FIX 2). Measured into the journal (par0
    14.3): the modes of the dump's file and directory, the manifest."""
    assert (OPT / "current").is_symlink(), "the whole install runs first"
    _psql("DELETE FROM app_settings WHERE key = 'dm86'")
    _psql("INSERT INTO app_settings (key, value) VALUES ('dm86', 'kept')")
    verdict, printed = _verdict_of("db", "dump", STACK)
    assert verdict.result == "green", printed
    [dump] = [s for s in verdict.steps if s.name == "db_dump"]
    path = Path(str((dump.verify or {})["path"]))
    manifest = json.loads(path.with_suffix(".json").read_text(encoding="utf-8"))
    print(
        "DM-86 measure:",
        {
            "file": oct(path.stat().st_mode & 0o777),
            "directory": oct(path.parent.stat().st_mode & 0o777),
            "manifest": manifest,
            "fact": dump.verify,
        },
    )
    assert path.parent.parent == Path("/opt/pridem/backups"), path
    assert path.stat().st_mode & 0o777 == 0o600
    assert int(manifest["toc"]) > 0 and manifest["entry"] == STACK, manifest

    _psql("DELETE FROM app_settings WHERE key = 'dm86'")
    assert _psql("SELECT value FROM app_settings WHERE key = 'dm86'") == []
    verdict, printed = _verdict_of(
        "db", "restore", STACK, str(path), "--confirm", "tier3-env"
    )
    assert verdict.result == "green", printed
    assert _psql("SELECT value FROM app_settings WHERE key = 'dm86'") == ["kept"]
    facts = {s.name: s.verify or {} for s in verdict.steps}
    assert facts["db_restore"].get("alembic_head") == manifest.get("alembic_head")
    assert facts["start_restored"]["started"] == ["app", "frontend"], facts
    assert _container(STACK, "app")

    # DM-94: the live database was dumped first -- the way back. Restoring it
    # gives the database as it was before the restore: the row deleted again
    insurance = Path(str(facts["db_dump"]["path"]))
    print("DM-94 measure:", {"insurance": str(insurance), "fact": facts["db_restore"]})
    assert facts["db_restore"]["insurance"] == str(insurance), facts
    assert insurance.is_file() and insurance.with_suffix(".json").is_file()
    assert insurance.parent != path.parent, (insurance, path)
    verdict, printed = _verdict_of(
        "db", "restore", STACK, str(insurance), "--confirm", "tier3-env"
    )
    assert verdict.result == "green", printed
    assert _psql("SELECT value FROM app_settings WHERE key = 'dm86'") == []
    assert _container(STACK, "app")

    # FIX 2: the passport of this box says policies.backup.enabled: false --
    # green with no command and the fact, no new directory under backups/
    # (the policy on is held by tier 1; the dump on a live database -- above)
    before = sorted(Path("/opt/pridem/backups").iterdir())
    verdict, printed = _verdict_of("backup")
    assert verdict.result == "green", printed
    [scope] = [s for s in verdict.steps if s.name == "backup_scope"]
    assert scope.verify == {"policy": "disabled"}, scope.verify
    assert sorted(Path("/opt/pridem/backups").iterdir()) == before


def test_tier3_a_restore_that_fails_half_way_leaves_the_database_as_it_was() -> None:
    """DM-93 (R2-S7), after the dump test: a dump; then, in the live
    database, a row the dump has not and a view on ``app_settings``. The
    restore fails half-way: one transaction, stopped at the first error -- the
    restore is red, and the row and the view are there: the database as it
    was. Measured into the journal first (par0 14.3): how long the restore
    took, its reason, the lines of ``pg_restore``.

    Changed by DM-186 FIX (S9): ``db_restore`` restores into a new database,
    so the view in the live one no longer stops it -- the old way to fail
    half-way (the ``DROP TABLE`` of ``pg_restore --clean`` under a view) is
    gone. It fails half-way here by a table ``app_settings`` the test puts in
    ``template1`` -- the new database is made from it, so the ``CREATE TABLE``
    of the dump fails after the first ones. Now also: the new database is
    dropped, ``db_swap`` never acts (no restore asked), ``finally`` starts the
    stopped services again -- no ``start`` by the test; ``template1`` is put
    back."""
    assert (OPT / "current").is_symlink(), "the whole install runs first"
    verdict, printed = _verdict_of("db", "dump", STACK)
    assert verdict.result == "green", printed
    [dump] = [s for s in verdict.steps if s.name == "db_dump"]
    path = str((dump.verify or {})["path"])
    _psql("INSERT INTO app_settings (key, value) VALUES ('dm93-after', 'kept')")
    _psql("CREATE VIEW dm93_v AS SELECT key FROM app_settings")
    _psql_on("template1", "CREATE TABLE app_settings (key text)")
    try:
        started = time.monotonic()
        verdict, printed = _verdict_of(
            "db", "restore", STACK, path, "--confirm", "tier3-env"
        )
        took = round(time.monotonic() - started, 1)
    finally:  # template1 as it was, whatever the restore did
        _psql_on("template1", "DROP TABLE IF EXISTS app_settings")
    [restore] = [s for s in verdict.steps if s.name == "db_restore"]
    journal = Path("/opt/pridem") / str(verdict.log_ref)
    said = [
        json.loads(line).get("line")
        for line in journal.read_text(encoding="utf-8").splitlines()
        if '"db_restore"' in line and '"log"' in line
    ]
    facts = {s.name: (s.status, s.verify) for s in verdict.steps}
    print(
        "DM-93 measure:",
        {"seconds": took, "reason": restore.reason, "said": said[-6:], "steps": facts},
    )
    assert verdict.result == "red", printed
    assert restore.reason is not None and restore.reason.code == "command-failed"
    assert _psql("SELECT value FROM app_settings WHERE key = 'dm93-after'") == ["kept"]
    assert _psql("SELECT to_regclass('public.dm93_v')") == ["dm93_v"]
    names = _psql_on("postgres", "SELECT datname FROM pg_database ORDER BY 1")
    assert "pridem_restore_new" not in names, names
    assert facts["db_swap"][0] == "skipped", facts
    assert not verdict.report.incomplete  # no restore asked: nothing crossed
    assert _container(STACK, "app")  # started again by finally

    _psql("DROP VIEW dm93_v")
    _psql("DELETE FROM app_settings WHERE key = 'dm93-after'")


def test_tier3_a_reset_of_the_blank_makes_its_database_new() -> None:
    """DM-86, pass 2, on the box the earlier tests left. The install of the
    group seeded ``bootstrap`` (``when: install``): ``installed_at`` is there.
    Measured into the journal first (par0 14.3): the image ``compose run app``
    starts and its commit, the commit of ``current``. ``db reset --confirm
    <server.name>`` -- another database (OID), at the same head, the app
    running, the seeded and the test's rows gone. ``seed --list`` -- green;
    ``seed --profile bootstrap`` -- refused, it runs at install only; ``db
    migrate`` -- green, nothing to do.

    Changed by DM-90 FIX (by the dispatcher's word, before the change): the
    image of the measure is the one ``config --images`` of the release names,
    ``<entry>-app:<commit12>`` since DM-90 -- not compose's own name of
    before, ``<entry>-app``, which no image has any more."""
    assert (OPT / "current").is_symlink(), "the whole install runs first"
    assert _psql("SELECT key FROM app_settings WHERE key = 'installed_at'") == [
        "installed_at"
    ]
    _psql("INSERT INTO app_settings (key, value) VALUES ('dm86-reset', 'x')")
    project = [
        *("docker", "compose", "-p", STACK, "--env-file", str(OPT / "env" / ".env")),
        *("-f", str(OPT / "current" / "docker-compose.yml")),
        *("-f", str(OPT / "compose" / f"{STACK}.yml")),
    ]
    images = _stdout([*project, "config", "--images"])
    label = '{{index .Config.Labels "pridem.commit"}}'
    [app] = [image for image in images if image.startswith(f"{STACK}-app:")]
    [built] = _stdout(["docker", "image", "inspect", "-f", label, app])
    [head] = _stdout(["git", "-C", str(OPT / "current"), "rev-parse", "HEAD"])
    print("DM-86 measure:", {"config --images": images, "app image commit": built,
                             "current": head})  # fmt: skip

    verdict, printed = _verdict_of("db", "reset", STACK, "--confirm", "tier3-env")
    assert verdict.result == "green", printed
    facts = {s.name: s.verify or {} for s in verdict.steps}
    reset = facts["db_reset"]
    print("DM-86 measure:", {"reset": reset})
    assert reset["oid_before"] != reset["oid_after"], reset
    assert _psql("SELECT count(*) FROM app_settings") == ["0"]
    assert _container(STACK, "app")

    verdict, printed = _verdict_of("seed", "--list")
    assert verdict.result == "green", printed
    code, out, err = _pridem("seed", STACK, "--profile", "bootstrap")
    assert code == 1 and "install only" in "\n".join(err), (out, err)

    verdict, printed = _verdict_of("db", "migrate", STACK)
    assert verdict.result == "green", printed
    [migrate] = [s for s in verdict.steps if s.name == "db_migrate"]
    assert migrate.verify == {"stack": STACK, "alembic_head": reset["alembic_head"]}


def _psql_on(database: str, sql: str) -> list[str]:
    """``psql`` of the blank's user in ``database`` of its postgres."""
    pg = _container(STACK, "postgres")
    return _stdout(
        ["docker", "exec", pg, "psql", "-U", "blank", "-d", database, "-tAc", sql]
    )


def _tables() -> list[str]:
    return _psql(
        "SELECT tablename FROM pg_tables WHERE schemaname = 'public' ORDER BY 1"
    )


def test_probe_DM_186_S9_an_older_dump_restores_the_database_it_was() -> None:
    """DM-186, S9, group c after the chain of data: a dump; then a table a
    newer migration would make (``dm186_later``) and a row; ``db restore`` of
    the dump -- the tables are the dump's, the newer one gone (``pg_restore
    --clean`` over the live database left it), no ``pridem_restore_new`` or
    ``_old`` left, the app running.

    Measured into the run's log first (par0 14.3, the gate's answer): the
    rights of the blank's user (``CREATEDB``), the PostgreSQL of the blank's
    image, what ``ALTER DATABASE ... RENAME`` does beside a session held in
    the database (PostgreSQL 16 of the sandbox: it waits 5 s, then refuses),
    and that compose's ``ps`` takes two ``--status``."""
    assert (OPT / "current").is_symlink(), "the whole install runs first"
    pg = _container(STACK, "postgres")
    measured: dict[str, object] = {
        "role": _psql(
            "SELECT rolsuper, rolcreatedb FROM pg_roles WHERE rolname = 'blank'"
        ),
        "version": _psql("SHOW server_version"),
    }
    _psql_on("postgres", "DROP DATABASE IF EXISTS dm186_probe WITH (FORCE)")
    _psql_on("postgres", "DROP DATABASE IF EXISTS dm186_probe_x WITH (FORCE)")
    _psql_on("postgres", "CREATE DATABASE dm186_probe")
    _run(["docker", "exec", "-d", pg, "psql", "-U", "blank", "-d", "dm186_probe",
          "-c", "SELECT pg_sleep(12)"])  # fmt: skip
    time.sleep(1)
    started = time.monotonic()
    said = _run(
        ["docker", "exec", pg, "psql", "-U", "blank", "-d", "postgres", "-tAc",
         "ALTER DATABASE dm186_probe RENAME TO dm186_probe_x"],
        expect=(0, 1),
    )  # fmt: skip
    measured["rename beside a session"] = {
        "said": said[-2:],
        "s": round(time.monotonic() - started, 1),
    }
    _psql_on("postgres", "DROP DATABASE IF EXISTS dm186_probe WITH (FORCE)")
    _psql_on("postgres", "DROP DATABASE IF EXISTS dm186_probe_x WITH (FORCE)")
    project = [
        *("docker", "compose", "-p", STACK, "--env-file", str(OPT / "env" / ".env")),
        *("-f", str(OPT / "current" / "docker-compose.yml")),
        *("-f", str(OPT / "compose" / f"{STACK}.yml")),
    ]
    measured["ps running+restarting"] = _stdout(
        [*project, "ps", "--status", "running", "--status", "restarting", "-q", "app"]
    )
    before = _tables()
    measured["tables"] = before
    warnings.warn(f"DM-186 S9 measure: {measured}", stacklevel=1)

    verdict, printed = _verdict_of("db", "dump", STACK)
    assert verdict.result == "green", printed
    [dump] = [s for s in verdict.steps if s.name == "db_dump"]
    path = str((dump.verify or {})["path"])
    _psql("CREATE TABLE dm186_later (id int)")
    _psql("INSERT INTO dm186_later VALUES (1)")
    assert "dm186_later" in _tables()
    verdict, printed = _verdict_of(
        "db", "restore", STACK, path, "--confirm", "tier3-env"
    )
    facts = {s.name: s.verify or {} for s in verdict.steps}
    warnings.warn(f"DM-186 S9 restore: {facts}", stacklevel=1)
    warnings.warn(f"group time so far: {_group_elapsed_s():.0f} s", stacklevel=1)
    assert verdict.result == "green", printed
    assert _tables() == before
    names = _psql_on("postgres", "SELECT datname FROM pg_database ORDER BY 1")
    assert "pridem_restore_new" not in names and "pridem_restore_old" not in names
    assert facts["db_swap"]["database"] == "blank", facts
    assert _container(STACK, "app")


def test_probe_DM_186_B12_a_reset_is_green_ahead_of_and_behind_the_code() -> None:
    """DM-186, B12, group c: the database at a revision the code does not
    hold (ahead), then with none (behind) -- ``db reset`` green both times, at
    the code's head; it was refused ahead (``alembic current`` failed in its
    check) and red behind (the new database compared with the old
    revision)."""
    heads: list[str] = []
    for state in ("ahead", "behind"):
        if state == "ahead":
            _psql("UPDATE alembic_version SET version_num = '9999dm186'")
        else:
            _psql("DELETE FROM alembic_version")
        seen = _psql("SELECT coalesce(max(version_num), 'none') FROM alembic_version")
        verdict, printed = _verdict_of("db", "reset", STACK, "--confirm", "tier3-env")
        facts = {s.name: s.verify or {} for s in verdict.steps}
        warnings.warn(f"DM-186 B12 {state}: {seen}, {facts}", stacklevel=1)
        assert verdict.result == "green", printed
        heads.append(str(facts["db_reset"]["alembic_head"]))
        assert _psql("SELECT version_num FROM alembic_version") == [heads[-1]]
    assert heads[0] == heads[1] != "9999dm186"
    assert _container(STACK, "app")


class _RegisterPanel(BaseHTTPRequestHandler):
    """The Panel's side of a registration on the runner's loopback (DM-139):
    contract 4 read strictly, the public half 32 raw bytes, one token
    (``_TOKEN``), used once."""

    used: ClassVar[set[str]] = set()
    received: ClassVar[list[dict[str, object]]] = []

    def do_POST(self) -> None:
        raw = self.rfile.read(int(self.headers["Content-Length"]))
        self.received.append(
            {"path": self.path, "protocol": self.headers[PROTOCOL_HEADER]}
        )
        asked = RegisterRequest.model_validate_json(raw)
        assert len(base64.b64decode(asked.box_key_public, validate=True)) == 32
        token = asked.token.get_secret_value()
        if token != _TOKEN:
            self._answer(404, Refusal(code="token-unknown").model_dump_json())
        elif token in self.used:
            self._answer(410, Refusal(code="token-used").model_dump_json())
        else:
            self.used.add(token)
            answer = RegisterResponse(
                box_id="tier3-box",
                agent_url="https://127.0.0.1/agent/v1/",
                heartbeat_s=30,
                full_state_s=300,
                poll_s=60,
            )
            self._answer(201, answer.model_dump_json())

    def _answer(self, status: int, body: str) -> None:
        data = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002
        return


_TOKEN = "tier3-one-time-token-of-the-panel-dm139"  # noqa: S105 -- a test value
_FOREIGN = "tier3-a-token-the-panel-never-issued"  # noqa: S105 -- a test value


def _register(origin: str, token: str) -> tuple[Verdict, str, float]:
    """``pridem --json register --panel <origin>`` with ``token`` in the
    environment: the verdict, the console, the seconds it took."""
    out: list[str] = []
    err: list[str] = []

    def keep(stream: Stream, line: str, cut: bool) -> None:
        (out if stream is Stream.STDOUT else err).append(line)

    began = time.monotonic()
    result = SubprocessRunner().run(
        [PRIDEM, "--json", "register", "--panel", origin],
        expect=(0, 1),
        timeout=120,
        env={**clean_env(), TOKEN_ENV: token},
        on_line=keep,
    )
    spent = round(time.monotonic() - began, 2)
    verdict = Verdict.model_validate_json("\n".join(out))
    assert int(verdict.exit_code) == result.code, err
    return verdict, "\n".join(err), spent


def _step_code(verdict: Verdict, name: str) -> object:
    [step] = [s for s in verdict.steps if s.name == name]
    return step.reason.model_dump().get("code") if step.reason is not None else None


def test_probe_DM_139_register_on_the_runner() -> None:
    """DM-139, the last of group ``c``, on the box its install left: the box
    registers in a Panel of contract 4 on the loopback (``_RegisterPanel``).
    A token the Panel never issued -- ``register:token-unknown``, no
    registration, the key minted 0600; the Panel's token -- green, the same
    key (not minted again), ``box_id`` written 0600; the token again --
    ``register:already``, no request. The token is in no verdict and no
    journal. Measured into the run's journal (par0 14.3): what the Panel got
    and the time of each registration.

    Changed by DM-189, on the dispatcher's word 24.11: the Panel on the
    loopback answers ``agent_url`` on its own host, ``https://127.0.0.1/agent/
    v1/`` -- ``register`` holds the host of ``agent_url`` and of ``--panel``
    the same; it reads the token, a ``SecretStr`` now, by its value."""
    agent = Path("/opt/pridem/agent")
    assert Path("/opt/pridem/passport.yaml").is_file(), "the install runs first"
    assert not agent.exists(), "no registration before this probe"
    received: list[dict[str, object]] = []
    handler = type("Panel", (_RegisterPanel,), {"used": set(), "received": received})
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    origin = f"http://127.0.0.1:{server.server_address[1]}"
    try:
        foreign, printed, spent_foreign = _register(origin, _FOREIGN)
        assert _step_code(foreign, "register") == "register:token-unknown", printed
        key = agent / "box.key"
        minted = key.read_bytes()
        assert not (agent / "registration.json").exists()

        taken, printed, spent_taken = _register(origin, _TOKEN)
        assert taken.result == "green", printed
        found = os.lstat(key)
        assert (found.st_mode & 0o777, found.st_uid, found.st_size) == (0o600, 0, 32)
        assert key.read_bytes() == minted
        kept = json.loads((agent / "registration.json").read_text(encoding="utf-8"))
        assert kept["box_id"] == "tier3-box", kept
        assert (agent / "registration.json").stat().st_mode & 0o777 == 0o600
        assert agent.stat().st_mode & 0o777 == 0o700

        again, printed, spent_again = _register(origin, _TOKEN)
        assert _step_code(again, "register") == "register:already", printed
    finally:
        server.shutdown()
        server.server_close()
    print("DM-139 measure:", {"received": received, "seconds": [
        spent_foreign, spent_taken, spent_again]})  # fmt: skip
    assert received == [{"path": "/agent/v1/register", "protocol": "1"}] * 2
    for verdict in (foreign, taken, again):
        assert verdict.log_ref is not None
        journal = (Path("/opt/pridem") / verdict.log_ref).read_text(encoding="utf-8")
        assert _TOKEN not in journal and _FOREIGN not in journal
        assert _TOKEN not in verdict.model_dump_json()


class _AgentPanel(BaseHTTPRequestHandler):
    """The Panel's side of the agent on the runner's loopback (DM-141): every
    request's signature checked by the box's public half, one command
    (``status``) given with its term, the lines kept by run and ``seq``, a
    verdict checked over its JSON object as the envelope carries it -- by
    ``runs/<id>/verdict`` or in a batch of ``history`` (the Panel at
    ``29b3e35``).

    Changed by DM-144, on the dispatcher's word 26.11: a signature that does
    not hold is the Panel's refusal, ``401 signature-bad`` of contract 4, not
    a handler that dies with the connection -- a planted wrong signature is
    then a refusal the probe can see; the key a verdict is checked by is one
    method (``_verdict_key``), for a Panel that checks it by another. On a
    signature that holds nothing changed."""

    public: ClassVar[bytes] = b""
    queue: ClassVar[list[dict[str, object]]] = []
    seen: ClassVar[list[tuple[str, str, int]]] = []
    lines: ClassVar[dict[str, dict[int, dict[str, object]]]] = {}
    verdicts: ClassVar[dict[str, tuple[bool, str | None, str]]] = {}
    beats: ClassVar[list[bool]] = []

    def _any(self) -> None:
        body = self.rfile.read(int(self.headers.get("Content-Length") or 0))
        status, answer = self._answer(body)
        self.seen.append((self.command, self.path, status))
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(answer)))
        self.end_headers()
        self.wfile.write(answer)

    do_GET = do_POST = _any  # noqa: N815

    def _verdict_key(self) -> bytes:
        """The key a verdict's envelope is checked by: the box's."""
        return self.public

    def _keep(self, raw: dict[str, object]) -> str:
        envelope = VerdictEnvelope.model_validate(raw)
        try:
            Ed25519PublicKey.from_public_bytes(self._verdict_key()).verify(
                base64.b64decode(envelope.signature),
                verdict_bytes(raw["verdict"]),  # type: ignore[arg-type]
            )
            verified = True
        except InvalidSignature:
            verified = False
        verdict = envelope.verdict
        self.verdicts.setdefault(
            verdict.run_id, (verified, verdict.command, verdict.actor.via)
        )
        return verdict.run_id

    def _answer(self, body: bytes) -> tuple[int, bytes]:
        signed = signed_headers(dict(self.headers.items()))
        message = signing_string(self.command, self.path, signed.time, body)
        try:
            Ed25519PublicKey.from_public_bytes(self.public).verify(
                base64.b64decode(signed.signature), message.encode()
            )
        except InvalidSignature:
            return 401, Refusal(code="signature-bad").model_dump_json().encode()
        where = self.path.removeprefix("/agent/v1/")
        if where == "heartbeat":
            self.beats.append(Heartbeat.model_validate_json(body).state is not None)
            return 204, b""
        if where == "commands/next":
            if not self.queue:
                time.sleep(1)  # the Panel holds a long-poll (queue.py): a short one
                return 204, b""
            return 200, json.dumps(self.queue.pop(0)).encode()
        if where.endswith("/events"):
            run_id = where.split("/")[1]
            batch = EventBatch.model_validate_json(body)
            held = self.lines.setdefault(run_id, {})
            for line in batch.events:
                held.setdefault(line.seq, line.model_dump(mode="json"))
            last = 0
            while last + 1 in held:
                last += 1
            return 200, json.dumps({"last_seq": last}).encode()
        if where.endswith("/verdict"):
            self._keep(json.loads(body))
            return 204, b""
        if where == "history":
            held_runs = [self._keep(raw) for raw in json.loads(body)["envelopes"]]
            return 200, json.dumps({"run_ids": held_runs}).encode()
        return 404, b""

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002
        return


def _agent_panel(
    port: int, queue: list[dict[str, object]]
) -> tuple[type[_AgentPanel], ThreadingHTTPServer]:
    """The Panel's side of the agent on the loopback at ``port``: the box's
    public half from its key."""
    seed = Path("/opt/pridem/agent/box.key").read_bytes()
    public = Ed25519PrivateKey.from_private_bytes(seed).public_key()
    handler = type(
        "Panel",
        (_AgentPanel,),
        {
            "public": public.public_bytes(Encoding.Raw, PublicFormat.Raw),
            "queue": queue,
            "seen": [],
            "lines": {},
            "verdicts": {},
            "beats": [],
        },
    )
    server = ThreadingHTTPServer(("127.0.0.1", port), handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return handler, server


def _panel_port() -> int:
    registration = json.loads(Path("/opt/pridem/agent/registration.json").read_text())
    origin = urlsplit(registration["panel"])
    assert origin.scheme == "http" and origin.hostname == "127.0.0.1"
    return origin.port or 80


@contextmanager
def _an_agent() -> Iterator[list[str]]:
    """``pridem agent``, a real process, until the block ends (SIGTERM)."""
    said: list[str] = []
    ended: list[BaseException] = []

    def agent() -> None:
        try:
            SubprocessRunner().run(
                ["sh", "-c", f"echo $$; exec {PRIDEM} agent"],
                timeout=900,
                on_line=lambda stream, line, cut: said.append(line),
            )
        except RunnerError as error:
            ended.append(error)

    thread = threading.Thread(target=agent, daemon=True)
    thread.start()
    began = time.monotonic()
    while not said:
        assert time.monotonic() - began < 30, "the agent never started"
        time.sleep(0.1)
    try:
        yield said
    finally:
        os.kill(int(said[0]), signal.SIGTERM)
        thread.join(120)
        assert not thread.is_alive(), ("the agent did not stop", said)
        assert ended == [], ended


def _waited(test: Callable[[], bool], what: str, said: list[str]) -> float:
    began = time.monotonic()
    while not test():
        assert time.monotonic() - began < 300, (what, said)
        time.sleep(0.5)
    return round(time.monotonic() - began, 1)


def test_probe_DM_141_agent_on_the_runner() -> None:
    """DM-141, after the registration of DM-139 in group ``c``: ``pridem
    agent`` -- a real process -- against the Panel's side on the loopback, at
    the address the box registered with. The Panel gives one command,
    ``status``; the agent runs it as the console would (``pridem --json
    --command``); every line of its journal reaches the Panel by ``seq`` with
    no gap, the verdict arrives naming the command and its signature holds by
    the box's public half; the first heartbeat is the full one. SIGTERM stops
    the agent. Measured into the run's journal (``warnings.warn``): the
    requests and the time to the verdict.

    Changed by DM-141 part B (the same card): the agent sends the box's
    history too -- the Panel keeps verdicts by run, ``history`` answered; the
    command's verdict is the one naming it."""
    expires = (datetime.now(UTC) + timedelta(minutes=10)).strftime("%Y-%m-%dT%H:%M:%SZ")
    command: dict[str, object] = {
        "id": "cmd-1",
        "verb": "status",
        "args": {},
        "expires_at": expires,
    }
    handler, server = _agent_panel(_panel_port(), [command])
    try:
        with _an_agent() as said:
            spent = _waited(
                lambda: any(v[1] == "cmd-1" for v in handler.verdicts.values()),
                "no verdict of the command",
                said,
            )
    finally:
        server.shutdown()
        server.server_close()
    warnings.warn(
        f"DM-141 measure: verdict in {spent} s; requests {handler.seen}; "
        f"agent said {said}",
        stacklevel=1,
    )
    [run_id] = [r for r, v in handler.verdicts.items() if v[1] == "cmd-1"]
    assert all(verified for verified, _, _ in handler.verdicts.values())
    journal = Path("/opt/pridem/journal") / f"{run_id}.jsonl"
    written = journal.read_text(encoding="utf-8").splitlines()
    assert sorted(handler.lines[run_id]) == list(range(1, len(written) + 1))
    assert all(status != 404 for _, _, status in handler.seen), handler.seen
    assert handler.beats and handler.beats[0], handler.beats


def test_probe_DM_141_no_verdict_lost_on_the_runner() -> None:
    """DM-141 part B, after part A in group ``c``: the Panel away, the
    console's ``pridem --json status`` runs as ever; the Panel back at the
    same address, the agent sends that run -- its lines by ``seq`` with no
    gap, its verdict holding by the box's key, the actor the console. A new
    agent on the box sends nothing again: the cursor is on the box. Measured
    into the run's journal: the time the Panel was away and to the verdict."""
    port = _panel_port()
    handler, server = _agent_panel(port, [])
    with _an_agent() as said:
        _waited(lambda: len(handler.beats) > 0, "no heartbeat", said)
        server.shutdown()
        server.server_close()
        away = time.monotonic()
        result = SubprocessRunner().run(
            [PRIDEM, "--json", "status"], expect=(0,), timeout=300,
            on_line=lambda stream, line, cut: None,
        )  # fmt: skip
        assert result.code == 0
        run_id = max(p.stem for p in Path("/opt/pridem/history").glob("*.json"))
        time.sleep(5)
        handler, server = _agent_panel(port, [])
        try:
            spent = _waited(lambda: run_id in handler.verdicts, "not sent", said)
        finally:
            gone = round(time.monotonic() - away, 1)
    try:
        verified, command, via = handler.verdicts[run_id]
        assert verified and command is None and via == "local"
        journal = Path("/opt/pridem/journal") / f"{run_id}.jsonl"
        written = journal.read_text(encoding="utf-8").splitlines()
        assert sorted(handler.lines[run_id]) == list(range(1, len(written) + 1))
        handler.seen.clear()
        with _an_agent() as again:
            _waited(lambda: len(handler.beats) > 1, "no heartbeat again", again)
        sent = [s for s in handler.seen if "/runs/" in s[1] or "history" in s[1]]
        assert sent == [], sent
    finally:
        server.shutdown()
        server.server_close()
    warnings.warn(
        f"DM-141 part B measure: the Panel away {gone} s, the verdict "
        f"{spent} s after it was back; agent said {said}",
        stacklevel=1,
    )


def test_tier3_a_project_verb_runs_in_its_service(tmp_path: Path, mirror: Path) -> None:
    """DM-86, pass 3, on the box the earlier tests left: ``set-setting`` --
    destructive -- without ``--confirm`` is refused and writes nothing; with
    the box's name it writes its row, in ``app``; ``count-settings`` runs in
    ``postgres`` (``exec`` in the live container), its output in the
    journal. The pair: a copy of the blank whose ``count-settings`` is for
    ``prod`` alone -- refused on this box of ``test``; the copy carries the
    revision 0002 the box's database is at (FIX). Measured into the
    journal (par0 14.3): the lines ``count-settings`` printed."""
    assert (OPT / "current").is_symlink(), "the whole install runs first"
    _psql("DELETE FROM app_settings WHERE key = 'dm86-verb'")
    code, out, err = _pridem("verb", "set-setting", "key=dm86-verb", "value=v")
    assert code == 1 and "--confirm" in "\n".join(err), (out, err)
    assert _psql("SELECT value FROM app_settings WHERE key = 'dm86-verb'") == []
    verdict, printed = _verdict_of(
        "verb", "set-setting", "key=dm86-verb", "value=v", "--confirm", "tier3-env"
    )
    assert verdict.result == "green", printed
    assert _psql("SELECT value FROM app_settings WHERE key = 'dm86-verb'") == ["v"]
    assert verdict.steps[0].verify == {
        "verb": "set-setting",
        "service": "app",
        "exit_code": 0,
    }
    verdict, printed = _verdict_of("verb", "count-settings")
    assert verdict.result == "green", printed
    [count] = _psql("SELECT count(*) FROM app_settings")
    journal = Path("/opt/pridem") / str(verdict.log_ref)
    said = [
        json.loads(line).get("line")
        for line in journal.read_text(encoding="utf-8").splitlines()
        if '"project_verb"' in line and '"log"' in line
    ]
    print("DM-86 measure:", {"count-settings said": said, "count": count})
    assert verdict.steps[0].verify == {
        "verb": "count-settings",
        "service": "postgres",
        "exit_code": 0,
    }
    assert count in said, said

    # the copy carries the revision the box's database is at -- the helper
    # measures it (FIX of pass 4b; it was written here by the FIX of B2)
    copy = _copy_of_blank(tmp_path, mirror, "verb-role")
    _replace_once(copy / "primer.yaml", "    roles: [test]\n", "    roles: [prod]\n")
    _push(copy, mirror, "DM-86: count-settings for prod alone")
    verdict, printed = _install(_passport(tmp_path, version=45), "update")
    assert verdict.result == "green", printed
    code, out, err = _pridem("verb", "count-settings")
    assert code == 1 and "not for the role test" in "\n".join(err), (out, err)


def test_tier3_logs_restart_stop_start_and_a_read_only_session() -> None:
    """DM-86, pass 4, on the box the earlier tests left. ``logs`` of the app
    with ``level=info``: every printed line a JSON object with that field
    (measured first: the first lines unfiltered); ``restart`` of the blank --
    green, the app a new start; ``stop`` of its frontend -- not running,
    ``start`` -- running again. ``db connect`` with its stdin from a pipe (no
    terminal: ``-T``) -- a ``SELECT`` answered, a ``CREATE TABLE`` refused by
    the read-only transaction; the session's log kept on the box, 0600."""
    assert (OPT / "current").is_symlink(), "the whole install runs first"
    code, out, err = _pridem("logs", STACK, "app", "--tail", "50")
    print("DM-86 measure: logs", {"code": code, "first": out[:3], "err": err[-2:]})
    assert code == 0 and out, (out, err)
    code, out, err = _pridem("logs", STACK, "app", "--tail", "200", "level=info")
    assert code == 0, err
    assert out and all(json.loads(line)["level"] == "info" for line in out), out

    before = _started("app")
    verdict, printed = _verdict_of("restart", STACK)
    assert verdict.result == "green", printed
    assert _started("app") != before
    verdict, printed = _verdict_of("stop", STACK, "frontend")
    assert verdict.result == "green", printed
    assert _stdout(
        ["docker", "ps", "-q", "--filter", f"label=com.docker.compose.project={STACK}",
         "--filter", "label=com.docker.compose.service=frontend"]
    ) == []  # fmt: skip
    verdict, printed = _verdict_of("start", STACK, "frontend")
    assert verdict.result == "green", printed
    assert _container(STACK, "frontend")

    session = (
        "printf '%s\\n' 'SELECT 1 AS dm86_seen;' 'CREATE TABLE dm86x (i int);' "
        f"| {PRIDEM} db connect {STACK}"
    )
    said: list[str] = []
    result = SubprocessRunner().run(
        ["/bin/sh", "-c", session],
        expect=(0, 1),
        timeout=300,
        on_line=lambda stream, line, cut: said.append(line),
    )
    print("DM-86 measure: db connect", {"code": result.code, "said": said[-8:]})
    assert result.code == 0, said
    [log] = sorted(Path("/opt/pridem/connect").glob(f"*-{STACK}.log"))[-1:]
    text = log.read_text(encoding="utf-8")
    print("DM-86 measure: the session's log", text[-800:])
    assert "dm86_seen" in text
    assert log.stat().st_mode & 0o777 == 0o600
    assert _psql("SELECT to_regclass('public.dm86x')") == [""]


ASKED_TAG = "v1.2.0"
BOT_TOKEN = "dm86-asked-" + "q" * 24
"""The service's ``asked`` value its seam gives the product (pass 4b)."""


DM183_VERB = """\
  dm183-env:                          # DM-183: prints the app's environment
    run: env
    service: app
"""


def test_tier3_a_command_plan_prints_no_secret_of_the_box(
    tmp_path: Path, mirror: Path
) -> None:
    """DM-183, the last of group ``g``, on the box the earlier tests left: a
    copy of the blank with a verb that prints the app's environment -- the
    database's password, minted by the machine, in it. Its journal and its
    verdict hold no minted value of the box; the pair: the environment's
    plain part (``PATH=``) is there. Measured into the run's output first
    (par0 14.3): the number of lines the verb printed, never a value."""
    assert (OPT / "current").is_symlink(), "the whole install runs first"
    copy = _copy_of_blank(tmp_path, mirror, "dm183-env")
    _replace_once(copy / "primer.yaml", "  set-setting:", DM183_VERB + "  set-setting:")
    _push(copy, mirror, "DM-183: a verb that prints the app's environment")
    verdict, printed = _install(_passport(tmp_path, version=46), "update")
    assert verdict.result == "green", printed
    verdict, printed = _verdict_of("verb", "dm183-env")
    assert verdict.result == "green", printed
    journal = (Path("/opt/pridem") / str(verdict.log_ref)).read_text(encoding="utf-8")
    history = (Path("/opt/pridem") / "history" / f"{verdict.run_id}.json").read_text()
    minted = [
        str(value)
        for value in yaml.safe_load(MINTED.read_text(encoding="utf-8")).values()
    ]
    said = [
        json.loads(line).get("line")
        for line in journal.splitlines()
        if '"project_verb"' in line and '"log"' in line
    ]
    print("DM-183 measure:", {"lines the verb printed": len(said)})
    assert minted, "the blank mints its database's password"
    for value in minted:
        assert value not in journal and value not in history  # never printed
    assert any(str(line).startswith("PATH=") for line in said), len(said)


JOB_ONCE = "files-init"
JOB_ONCE_MARK = "/srv/files/dm126-init"


def _blank_with_a_job_that_fails_once(tmp: Path, mirror: Path) -> None:
    """The blank, consistent as a whole: in the entry ``primer-blank-files``
    the job ``files-init`` (the image the entry already runs, the volume
    ``files``, no healthcheck, on ``files`` healthy) -- its first run leaves a
    mark on the volume and exits 1, every later one finds the mark and exits
    0. The entry's only other service is the one the job needs: it is up
    before the job fails. And the measure of the builder: a test that fails,
    kept out of the build's context by ``Dockerfile.dockerignore`` alone --
    the file BuildKit reads in place of ``.dockerignore`` and the classic
    builder does not read at all."""
    copy = _copy_of_blank(tmp, mirror, "job-once")
    _replace_once(
        copy / "primer.yaml",
        "    persistent: true\n",
        f"    persistent: true\n    jobs: {{ init: {{ service: {JOB_ONCE} }} }}\n",
    )
    image = (
        "postgres:16-alpine@sha256:"
        "f4610795587492cd4fb887c2dc3de301b813278bb6f616992061141b5f15ac36"
    )
    run = f"test -e {JOB_ONCE_MARK} || {{ touch {JOB_ONCE_MARK}; exit 1; }}"
    _replace_once(
        copy / "deploy" / "files-compose.yml",
        "\nvolumes:\n",
        f"  {JOB_ONCE}:\n"
        f"    image: {image}\n"
        f"    command: {json.dumps(['sh', '-c', run])}\n"
        "    volumes:\n      - files:/srv/files\n"
        "    depends_on:\n      files: { condition: service_healthy }\n"
        "\nvolumes:\n",
    )
    backend = copy / "backend"
    (backend / "tests" / PLANTED_TEST).write_text(PLANTED_TEST_BODY, encoding="utf-8")
    ignored = (backend / ".dockerignore").read_text(encoding="utf-8")
    (backend / "Dockerfile.dockerignore").write_text(
        ignored + f"tests/{PLANTED_TEST}\n", encoding="utf-8"
    )
    _push(copy, mirror, "DM-126: a job that fails once; Dockerfile.dockerignore")


def _files_up(verdict: Verdict) -> dict[str, object]:
    [up] = [s for s in verdict.steps if (s.stack, s.name) == (FILES, "up")]
    return dict(up.verify or {})


def test_tier3_a_failed_job_runs_on_the_repeat(tmp_path: Path, mirror: Path) -> None:
    """DM-126, on the box the earlier tests left: a copy of the blank whose
    entry ``primer-blank-files`` has a job that fails on its first run. The
    update is red at ``up`` of that entry by the job's command -- its service
    ``files`` up already, on the new commit's configuration. The same update
    again: the job runs, alone -- the fact of ``up`` names it, ``files`` is
    the container the red update left, not made anew -- and the box is
    green; before DM-126 the repeat was green without the job. The pair: one
    more update with nothing changed runs no job, and ``doctor`` is empty.

    The builder, measured into the run's output first (par0 14.3): what the
    plugin says of itself (the fact of ``provision_host``), the lines of
    ``build`` in the journal that name provenance or bake, the totals of the
    tests. Then asserted: the tests of the copy are green -- the test that
    fails is kept out of the context by ``Dockerfile.dockerignore`` alone, so
    the image of the tests was built by BuildKit."""
    assert (OPT / "current").is_symlink(), "the whole install runs first"
    _blank_with_a_job_that_fails_once(tmp_path, mirror)
    passport = _passport(tmp_path, version=48)
    red, printed = _install(passport, "update")
    facts = {(s.stack, s.name): s.verify or {} for s in red.steps}
    journal = Path("/opt/pridem") / str(red.log_ref)
    built = [
        line[:300]
        for line in journal.read_text(encoding="utf-8").splitlines()
        if '"build"' in line and ("provenance" in line or "bake" in line)
    ]
    host = facts.get(("pridem-host", "provision_host"), {})
    tests = facts.get((STACK, "tests"), {})
    print(
        "DM-126 measure: the builder",
        {"buildx": host.get("buildx"), "docker": host.get("docker"),
         "build lines": built[:4], "tests": tests.get("junit"),
         "app image": facts.get((STACK, "build"), {}).get("app_image")},
    )  # fmt: skip
    assert host.get("buildx"), host
    junit = tests.get("junit")
    assert isinstance(junit, dict), printed
    total, failed_tests = junit["total"], junit["failed"]
    assert isinstance(total, int) and total > 0 and failed_tests == 0, (
        f"the planted test ran: Dockerfile.dockerignore was not read\n{printed}"
    )
    assert red.result == "red", printed
    [failed] = [s for s in red.steps if s.status == "failed"]
    assert (failed.stack, failed.name) == (FILES, "up"), red.steps
    assert failed.reason is not None
    assert failed.reason.code == "command-failed", failed.reason
    assert JOB_ONCE in failed.reason.model_dump()["argv"], failed.reason
    assert not [i for i in red.report.incomplete if i.what == "restore"], printed
    # the red update made ``files`` anew before the job -- a new commit is
    # another configuration; the repeat finds it up and must leave it
    files = _container(FILES, "files")

    again, printed = _install(passport, "update")  # the same commit, repeated
    print("DM-126 measure: the repeat", _files_up(again))
    assert again.result == "green", printed
    assert _files_up(again).get("jobs") == [JOB_ONCE], again.steps
    assert _container(FILES, "files") == files
    # the pair: the job ended well -- nothing to run, nothing to say
    idle, printed = _install(passport, "update")
    assert idle.result == "green", printed
    assert "jobs" not in _files_up(idle), idle.steps
    diff, failed_checks, doctor = _doctor(passport)
    assert (diff, failed_checks) == ([], []), doctor.model_dump_json()


SAMPLE_SEEDS = """\
async def sample(engine: AsyncEngine) -> None:
    \"\"\"Two rows of the profile sample, each with a fresh value.\"\"\"
    async with engine.begin() as conn:
        await conn.execute(
            text(
                "INSERT INTO app_settings (key, value) SELECT k, md5(random()::text) "
                "FROM (VALUES ('sample-a'), ('sample-b')) AS v(k) "
                "ON CONFLICT (key) DO NOTHING"
            )
        )


async def sample_reset_only(engine: AsyncEngine) -> None:
    \"\"\"The rows of the profile sample taken back, nothing else.\"\"\"
    async with engine.begin() as conn:
        await conn.execute(text("DELETE FROM app_settings WHERE key LIKE 'sample-%'"))


async def sample_reset(engine: AsyncEngine) -> None:
    \"\"\"The rows of the profile sample taken back and seeded again.\"\"\"
    await sample_reset_only(engine)
    await sample(engine)


async def reset_all(engine: AsyncEngine) -> None:
    \"\"\"The rows of every profile run by command taken back.\"\"\"
    await sample_reset_only(engine)


PROFILES: dict[str, Callable[[AsyncEngine], Coroutine[None, None, None]]] = {
    "bootstrap": bootstrap,
    "sample": sample,
    "sample-reset": sample_reset,
    "sample-reset-only": sample_reset_only,
    "reset-all": reset_all,
}
"""
"""The blank's ``app/seed.py`` in the copy of DM-133: a profile run by command,
``sample``, and the three commands that take seeds back -- the product's own.
``demo`` is not taken: the blank's tests use it as a name it does not know."""


def _blank_with_seed_resets(tmp: Path, mirror: Path) -> None:
    """The blank, consistent as a whole (par0 14.3): ``primer.yaml`` declares
    the profile ``sample`` with ``reset`` and ``reset_only`` and the entry's
    ``seeds_reset_all``; ``app/seed.py`` -- where the product reads them --
    knows each command."""
    copy = _copy_of_blank(tmp, mirror, "seed-resets")
    _replace_once(
        copy / "primer.yaml",
        "      bootstrap: { run: python -m app.seed bootstrap, when: install }\n",
        "      bootstrap: { run: python -m app.seed bootstrap, when: install }\n"
        "      sample:\n"
        "        run: python -m app.seed sample\n"
        "        reset: python -m app.seed sample-reset\n"
        "        reset_only: python -m app.seed sample-reset-only\n"
        "        when: command\n"
        "    seeds_reset_all: python -m app.seed reset-all\n",
    )
    _replace_once(
        copy / "backend" / "app" / "seed.py",
        "PROFILES: dict[str, Callable[[AsyncEngine], "
        "Coroutine[None, None, None]]] = {\n"
        '    "bootstrap": bootstrap,\n'
        "}\n",
        SAMPLE_SEEDS,
    )
    _push(copy, mirror, "DM-133: a seed profile with the product's resets")


def _settings() -> dict[str, str]:
    """Every row of the blank's ``app_settings``, by key."""
    rows = _psql("SELECT key || '=' || value FROM app_settings ORDER BY key")
    return dict(row.split("=", 1) for row in rows)


def _blank_oid() -> str:
    [oid] = _psql("SELECT oid FROM pg_database WHERE datname = 'blank'")
    return oid


def _seed_verdict(*flags: str) -> tuple[Verdict, str]:
    return _verdict_of("seed", STACK, *flags)


def test_tier3_seed_resets_run_the_products_commands(
    tmp_path: Path, mirror: Path
) -> None:
    """DM-133 (owner's decision of 23.11), on the box the earlier tests left:
    a copy of the blank whose profile ``sample`` declares ``reset`` and
    ``reset_only`` and whose entry declares ``seeds_reset_all``. ``update``,
    then ``seed --profile sample``: its rows are there. Then, each with
    ``--confirm <server.name>``: ``--reset`` -- the rows made again (other
    values); ``--reset-only`` -- gone; seeded again, ``--reset-all`` -- gone.
    Every time: one step ``seed_reset`` of its mode, every other row of the
    database as it was, the same database (OID), the same container of
    ``app`` -- the machine wiped nothing and stopped nothing. Measured into
    the run's output first (par0 14.3): the rows, the OID, the container."""
    assert (OPT / "current").is_symlink(), "the whole install runs first"
    _blank_with_seed_resets(tmp_path, mirror)
    deployed, printed = _install(_passport(tmp_path, version=49), "update")
    assert deployed.result == "green", printed
    seeded, printed = _seed_verdict("--profile", "sample")
    assert seeded.result == "green", printed
    _psql("INSERT INTO app_settings (key, value) VALUES ('dm133-other', 'kept')")
    oid, app = _blank_oid(), _container(STACK, "app")
    before = _settings()
    others = {
        key: value for key, value in before.items() if not key.startswith("sample-")
    }
    print("DM-133 measure: before", {"rows": before, "oid": oid, "app": app})
    assert {"sample-a", "sample-b"} <= set(before), before
    try:
        for flags, mode, sampled in (
            (("--profile", "sample", "--reset"), "reset", True),
            (("--profile", "sample", "--reset-only"), "reset-only", False),
            (("--reset-all",), "reset-all", False),
        ):
            if mode == "reset-all":
                again, printed = _seed_verdict("--profile", "sample")
                assert again.result == "green", printed
            verdict, printed = _seed_verdict(*flags, "--confirm", "tier3-env")
            after = _settings()
            print(f"DM-133 measure: {mode}", {
                "rows": after, "oid": _blank_oid(), "app": _container(STACK, "app"),
                "steps": [(s.name, s.status, s.verify) for s in verdict.steps],
            })  # fmt: skip
            assert verdict.result == "green", printed
            assert [(s.name, (s.verify or {}).get("mode")) for s in verdict.steps] == [
                ("seed_reset", mode)
            ], verdict.steps
            mine = {
                key: value for key, value in after.items() if key.startswith("sample-")
            }
            if sampled:
                assert set(mine) == {"sample-a", "sample-b"}, after
                assert all(mine[key] != before[key] for key in mine), (before, after)
            else:
                assert mine == {}, after
            rest = {k: v for k, v in after.items() if not k.startswith("sample-")}
            assert rest == others, (others, after)
            assert _blank_oid() == oid
            assert _container(STACK, "app") == app
    finally:
        _psql("DELETE FROM app_settings WHERE key = 'dm133-other'")


def _service_giving_its_asked(tmp: Path) -> str:
    """A copy of the service at ``v1.0.0`` whose ``SERVICE_BOT_TOKEN`` --
    source ``asked`` -- is in ``provides``, consistent as a whole (par0
    14.3): ``primer.yaml``, its compose, ``config.py`` and ``PROVIDES`` of
    ``main.py`` (``seams_verify`` reads ``/health.seams.provides``). Tagged
    ``ASKED_TAG``; the commit back."""
    copy = tmp / "service-asked"
    _run(["git", "clone", "-q", str(SERVICE_MIRROR), str(copy)], env=GIT_ENV)
    _run(["git", "-C", str(copy), "checkout", "-q", "v1.0.0"], env=GIT_ENV)
    primer = copy / "primer.yaml"
    _replace_once(
        primer,
        "  PRODUCT_WEBHOOK_URL: { source: seam, from: product }\n",
        "  PRODUCT_WEBHOOK_URL: { source: seam, from: product }\n"
        "  SERVICE_BOT_TOKEN:   { source: asked }\n",
    )
    _replace_once(
        primer,
        "provides: [SERVICE_API_URL, SERVICE_TOKEN, SERVICE_KEY]",
        "provides: [SERVICE_API_URL, SERVICE_TOKEN, SERVICE_KEY, SERVICE_BOT_TOKEN]",
    )
    _replace_once(
        copy / "docker-compose.yml",
        "      PRODUCT_WEBHOOK_URL: ${PRODUCT_WEBHOOK_URL:?}\n",
        "      PRODUCT_WEBHOOK_URL: ${PRODUCT_WEBHOOK_URL:?}\n"
        "      SERVICE_BOT_TOKEN: ${SERVICE_BOT_TOKEN:?}\n",
    )
    _replace_once(
        copy / "backend" / "app" / "config.py",
        '    key: str = Field(validation_alias="SERVICE_KEY", default="")\n',
        '    key: str = Field(validation_alias="SERVICE_KEY", default="")\n'
        '    bot_token: str = Field(validation_alias="SERVICE_BOT_TOKEN", '
        'default="")\n',
    )
    _replace_once(
        copy / "backend" / "app" / "main.py",
        '    "SERVICE_KEY": "key",\n',
        '    "SERVICE_KEY": "key",\n    "SERVICE_BOT_TOKEN": "bot_token",\n',
    )
    _git("-C", str(copy), "add", "-A")
    _git("-C", str(copy), "commit", "-q", "-m", "DM-86: a seam from asked")
    _git("-C", str(copy), "tag", "-f", ASKED_TAG)
    _git(
        "-C", str(copy), "push", "-q", "--force", str(SERVICE_MIRROR),
        f"refs/tags/{ASKED_TAG}",
    )  # fmt: skip
    return _stdout(["git", "-C", str(copy), "rev-parse", "HEAD"])[0]


def _blank_with_a_verb_on_a_job_and_the_asked_seam(
    tmp: Path, mirror: Path, commit: str
) -> None:
    """The blank, consistent as a whole: the seam ``SERVICE_BOT_TOKEN`` from
    the service, in the app's environment, the lock at ``ASKED_TAG``; in the
    entry ``primer-blank-files`` the job ``files-list`` (the image of the
    registry the entry already runs, the volume ``files``, no healthcheck);
    the verb ``files-list`` on that job by ``entry``, for ``test``."""
    copy = _copy_of_blank(tmp, mirror, "verb-job")
    primer = copy / "primer.yaml"
    _replace_once(
        primer,
        "  SERVICE_KEY:       { source: seam, from: primer-blank-service }",
        "  SERVICE_BOT_TOKEN: { source: seam, from: primer-blank-service }\n"
        "  SERVICE_KEY:       { source: seam, from: primer-blank-service }",
    )
    _replace_once(
        primer,
        "    persistent: true\n",
        "    persistent: true\n    jobs: { list: { service: files-list } }\n",
    )
    _replace_once(
        primer,
        "  count-settings:",
        "  files-list:\n"
        '    run: "ls -1 /srv/files"\n'
        "    entry: primer-blank-files\n"
        "    service: files-list\n"
        "    roles: [test]\n"
        "  count-settings:",
    )
    _replace_once(
        copy / "docker-compose.yml",
        "      SERVICE_KEY: ${SERVICE_KEY:?}\n",
        "      SERVICE_KEY: ${SERVICE_KEY:?}\n"
        "      SERVICE_BOT_TOKEN: ${SERVICE_BOT_TOKEN:?}\n",
    )
    files = copy / "deploy" / "files-compose.yml"
    image = (
        "postgres:16-alpine@sha256:"
        "f4610795587492cd4fb887c2dc3de301b813278bb6f616992061141b5f15ac36"
    )
    _replace_once(
        files,
        "\nvolumes:\n",
        "  files-list:\n"
        f"    image: {image}\n"
        '    command: ["true"]\n'
        "    volumes:\n      - files:/srv/files\n"
        "\nvolumes:\n",
    )
    _replace_once(
        copy / "primer.lock",
        f'{{ version: "1.0.0", tag: v1.0.0, commit: {SERVICE_PINS["v1.0.0"]} }}',
        f'{{ version: "1.2.0", tag: {ASKED_TAG}, commit: {commit} }}',
    )
    _push(copy, mirror, "DM-86: a verb on a job of another entry, a seam from asked")


def test_tier3_a_verb_on_a_job_of_another_entry_and_a_seam_from_asked(
    tmp_path: Path, mirror: Path
) -> None:
    """DM-86, pass 4b, last before ``destroy`` (after it only ``destroy`` and
    ``destroy --all`` run -- no passport is deployed over the lock at
    ``ASKED_TAG``). The service gives the product its ``asked`` value by a
    seam: ``update`` green, ``seams_verify`` names the seam, the app has the
    value in its environment, neither the journal nor the verdict has it.
    The verb ``files-list`` on the job of ``primer-blank-files``: a one-off
    container that lists the mark on the volume ``files``; no container of
    the job left. Measured into the journal first (par0 14.3): the lines of
    ``ls``, the seams of ``seams_verify``."""
    assert (OPT / "current").is_symlink(), "the whole install runs first"
    commit = _service_giving_its_asked(tmp_path)
    _blank_with_a_verb_on_a_job_and_the_asked_seam(tmp_path, mirror, commit)
    passport = _passport(
        tmp_path, version=46, asked={SERVICE: {"SERVICE_BOT_TOKEN": BOT_TOKEN}}
    )
    verdict, printed = _install(passport, "update")
    assert verdict.result == "green", printed
    seams = {(s.stack, s.name): s.verify or {} for s in verdict.steps}[
        ("pridem-seams", "seams_verify")
    ]
    print("DM-86 measure: seams", seams.get("seams"))
    named = seams.get("seams")
    assert isinstance(named, list), seams
    assert f"{STACK}.SERVICE_BOT_TOKEN <- {SERVICE}" in named, seams
    app = _container(STACK, "app")
    assert _stdout(["docker", "exec", app, "printenv", "SERVICE_BOT_TOKEN"]) == [
        BOT_TOKEN
    ]
    journal = Path("/opt/pridem") / str(verdict.log_ref)
    assert BOT_TOKEN not in journal.read_text(encoding="utf-8")
    assert BOT_TOKEN not in verdict.model_dump_json()

    files = _container(FILES, "files")
    _stdout(["docker", "exec", files, "sh", "-c", "echo x > /srv/files/dm86-4b-mark"])
    verdict, printed = _verdict_of("verb", "files-list")
    assert verdict.result == "green", printed
    assert verdict.steps[0].verify == {
        "verb": "files-list",
        "service": "files-list",
        "exit_code": 0,
        "entry": FILES,
        "oneoff": True,
    }
    run_journal = Path("/opt/pridem") / str(verdict.log_ref)
    said = [
        json.loads(line).get("line")
        for line in run_journal.read_text(encoding="utf-8").splitlines()
        if '"project_verb"' in line and '"log"' in line
    ]
    print("DM-86 measure: files-list said", said)
    assert "dm86-4b-mark" in said, said
    left = _stdout(
        ["docker", "ps", "-aq", "--filter", f"label=com.docker.compose.project={FILES}",
         "--filter", "label=com.docker.compose.service=files-list"]
    )  # fmt: skip
    assert left == [], left


PROFILED = """\
  dm182-hidden:
    image: postgres:16-alpine
    privileged: true
    healthcheck: { test: ["CMD", "true"] }
    profiles: [never]
"""
"""A privileged service behind a profile (DM-182, S2): ``config`` without
``--profile`` hides it; ``compose run`` or ``COMPOSE_PROFILES`` would start
it."""


DM207_MOVED = "dm207-planted:moved"
DM207_HELD = "dm207-planted:held"
DM207_CONTAINER = "dm207-planted-held"


def _dm207_commit(container: str, mark: str, tag: str) -> str:
    """An image committed from ``container`` under ``tag``, told from every
    other by ``mark``; its ID."""
    _run(
        [
            "docker",
            "commit",
            "--pause=false",
            "--change",
            f"LABEL dm207={mark}",
            container,
            tag,
        ]  # fmt: skip
    )
    [ident] = _stdout(["docker", "image", "inspect", "-f", "{{.Id}}", tag])
    return ident


def _dm207_there(image: str) -> bool:
    done = SubprocessRunner().run(
        ["docker", "image", "inspect", "-f", "{{.Id}}", image],
        expect=(0, 1),
        timeout=60,
        on_line=lambda stream, line, cut: None,
    )
    return done.code == 0


def test_tier3_gc_removes_a_dangling_image_and_measures_the_cache_in_bytes(
    tmp_path: Path,
) -> None:
    """DM-207, in group ``h`` before the pair of ``destroy``, on the box the
    earlier tests left. Two images lose their tag to a second commit under
    the same name -- the way a build of the same tag leaves one: ``loose``,
    which no container holds, and ``held``, which a container that never ran
    was made from. ``pridem gc``: its step is ok; ``loose`` is gone and the
    fact names it (``removed.dangling``); ``held`` is there, and so is every
    image the
    box had before that the fact does not name -- the images of the running
    containers, of the releases, postgres and nginx with no label of the
    machine's. The build cache in the fact is the bytes the Engine API gives,
    read here the same way after the run; the fact holds the free bytes of
    the disk before and after.

    Measured into the run's output first (par0 14.3): what docker 29 lists as
    dangling, with ``--all`` and without, the two images as ``inspect`` gives
    them, docker's own line of the build cache, the fact of ``gc``."""
    assert (OPT / "current").is_symlink(), "the whole install runs first"
    [nginx] = _stdout(
        [
            "docker",
            "ps",
            "-q",
            "--filter",
            "label=com.docker.compose.project=pridem-edge",
            "--filter",
            "label=com.docker.compose.service=nginx",
        ]  # fmt: skip
    )
    dangling = ["docker", "image", "ls", "-q", "--no-trunc",
                "--filter", "dangling=true"]  # fmt: skip
    try:
        loose = _dm207_commit(nginx, "loose", DM207_MOVED)
        _dm207_commit(nginx, "over-loose", DM207_MOVED)  # the tag moves off it
        held = _dm207_commit(nginx, "held", DM207_HELD)
        _run(["docker", "create", "--name", DM207_CONTAINER, DM207_HELD])
        _dm207_commit(nginx, "over-held", DM207_HELD)
        listed = set(_stdout(dangling))
        every = set(_stdout(["docker", "image", "ls", "-q", "--no-trunc"]))
        with_all = set(_stdout(["docker", "image", "ls", "-a", "-q", "--no-trunc"]))
        containers = sorted(_stdout(["docker", "ps", "-aq", "--no-trunc"]))
        used = set(_stdout(["docker", "inspect", "-f", "{{.Image}}", *containers]))
        print(
            "DM-207 measure: loose", loose, "held", held,
            "| dangling=true lists loose:", loose in listed, "held:", held in listed,
            "| image ls lists loose:", loose in every, "with -a:", loose in with_all,
            "| dangling", sorted(listed),
            "| inspect loose",
            _stdout(["docker", "image", "inspect", "-f",
                     "{{json .RepoTags}} {{json .RepoDigests}}", loose]),
            "| docker's line of the cache", _cache_line(),
        )  # fmt: skip
        assert loose in listed, (
            "docker does not list as dangling the image a second commit took "
            f"the tag off: this test proves nothing -- {sorted(listed)}"
        )
        assert held in used and loose not in used, used
        before = every | with_all | listed | used
        verdict, printed = _verdict_of("gc")
        [step] = verdict.steps
        fact = step.verify or {}
        print("DM-207 measure: the fact of gc", json.dumps(fact, default=str))
        assert step.status == "ok" and verdict.result != "red", printed
        removed = fact["removed"]
        assert isinstance(removed, dict), fact
        went, images = removed["dangling"], removed["images"]
        assert isinstance(went, list) and isinstance(images, list), removed
        assert loose.removeprefix("sha256:")[:12] in went, removed
        assert not _dm207_there(loose), "the dangling image is still on the box"
        # the needed ones: held by its container, and everything gc did not name
        assert _dm207_there(held), "gc took an image a container was made from"
        named = {str(image) for image in images}
        kept = {i for i in before if i.removeprefix("sha256:")[:12] not in named}
        assert used <= kept and len(kept) > len(used), (used, kept)
        gone = sorted(i for i in kept if not _dm207_there(i))
        assert gone == [], f"gc removed images its fact does not name: {gone}"
        # the cache: the bytes of the Engine API, as this test reads them now
        records = build_cache(Path("/"))
        after = fact["after"]
        assert isinstance(after, dict), fact
        cache = after["build_cache"]
        assert cache == {
            "count": len(records),
            "bytes": sum(r.size for r in records),
            "reclaimable": sum(r.size for r in records if not (r.in_use or r.shared)),
        }, (cache, _cache_line())
        assert isinstance(fact["prune_calls"], int), fact
        for when in ("before", "after"):
            measured = fact[when]
            assert isinstance(measured, dict), fact
            disk = measured["disk"]
            assert isinstance(disk, dict), measured
            free = disk["free_bytes"]
            assert isinstance(free, int) and free > 0, measured
    finally:
        every_code = tuple(range(256))
        _run(["docker", "rm", "-f", DM207_CONTAINER], expect=every_code)
        for image in (DM207_MOVED, DM207_HELD):
            _run(["docker", "image", "rm", image], expect=every_code)
        planted = ["docker", "image", "ls", "-a", "-q", "--no-trunc",
                   "--filter", "label=dm207"]  # fmt: skip
        for image in _stdout(planted):
            _run(["docker", "image", "rm", image], expect=every_code)
        warnings.warn(f"group time so far: {_group_elapsed_s():.0f} s", stacklevel=1)


def test_tier3_a_privileged_service_behind_a_profile_never_comes_up(
    tmp_path: Path, mirror: Path
) -> None:
    """DM-182, in group ``h`` before the pair of ``destroy``, on the box the
    earlier tests left: a copy of the blank whose compose holds a privileged
    service behind a profile. ``update`` is red at ``build`` --
    ``compose-forbidden`` naming the service -- before anything is built; no
    container of it exists, and the containers that ran are the ones that
    run. Measured into the run's output first (par0 14.3): the verdict's
    steps and the containers."""
    assert (OPT / "current").is_symlink(), "the whole install runs first"
    copy = _copy_of_blank(tmp_path, mirror, "dm182-profiled")
    _replace_once(copy / "docker-compose.yml", "services:\n", "services:\n" + PROFILED)
    _push(copy, mirror, "DM-182: a privileged service behind a profile")
    running = _services_of(STACK)
    red, printed = _install(_passport(tmp_path, version=50), "update")
    steps = [(s.stack, s.name, s.status) for s in red.steps if s.phase == "main"]
    print("DM-182 measure:", steps, "containers", _services_of(STACK))
    assert red.result == "red", printed
    [failed] = [s for s in red.steps if s.status == "failed"]
    assert (failed.stack, failed.name) == (STACK, "build"), red.steps
    assert failed.reason is not None
    assert failed.reason.code == "build:compose-forbidden", failed.reason
    assert "dm182-hidden: privileged" in failed.reason.model_dump()["found"]
    assert "dm182-hidden" not in _services_of(STACK)
    assert _services_of(STACK) == running


def test_tier3_destroy_takes_the_blank_off_the_box() -> None:
    """The last of the cycle (DM-45): ``pridem destroy`` -- every container,
    network, volume and image labelled ``pridem.stack`` gone but the volume of
    the persistent entry ``primer-blank-files``, which stays with what it
    held, ``/opt/primer-blank`` down to its mark and ``minted.yaml``, the
    edge's and the proxy's directories gone, the timers gone, ``state.json``
    gone; ``history/`` and the passport's copy stay. The pair: ``destroy``
    again has nothing to do and is green.

    Changed by DM-76 (by the dispatcher's word, before the change): the
    machine's mark stays while the directory holds its secret.

    Changed by DM-86, pass 3 (by the dispatcher's word, before the change):
    the blank has a persistent stack -- ``kept_volumes`` names its volume, and
    a mark written on it before ``destroy`` is read from it after."""
    assert (OPT / "current").is_symlink(), "the install runs first"
    files = _container(FILES, "files")
    [image] = _stdout(["docker", "inspect", "-f", "{{.Config.Image}}", files])
    _stdout(["docker", "exec", files, "sh", "-c", f"echo {MARK} > /srv/files/mark"])
    before = _volumes()
    print("DM-106 measure: volumes before destroy", before)
    # DM-106 FIX: who holds each anonymous volume, made when; the container of
    # files, its mounts, made when -- if the class comes back, the next red is
    # not blind (the dispatcher's word: the measure stays)
    for volume in (v for v, anon in before.items() if anon):
        holders = _stdout(["docker", "ps", "-a", "--filter", f"volume={volume}", "-q"])
        created = _stdout(
            ["docker", "volume", "inspect", "-f", "{{.CreatedAt}}", volume]
        )
        print(
            "DM-106 measure: anonymous",
            volume,
            {"held by": holders, "created": created},
        )
    mounted = _stdout(
        ["docker", "inspect", "-f", "{{.Created}} {{json .Mounts}}", files]
    )
    print("DM-106 measure: the container of files", mounted)
    # DM-110, on the dispatcher's word: the owner's decision of 17.11 --
    # destroy confirms the server's name on any role
    verdict, printed = _verdict_of("destroy", "--confirm", "tier3-env")
    assert verdict.result == "green", printed
    after = _volumes()
    print("DM-106 measure: volumes after destroy", after)
    # DM-106: the anonymous volume of the service files (postgres:16-alpine
    # declares VOLUME /var/lib/postgresql/data) went with its container
    assert [v for v, anon in after.items() if anon] == [], after
    facts = {(s.stack, s.name): s.verify or {} for s in verdict.steps}
    kept = facts[("pridem-destroy", "remove_objects")]["kept_volumes"]
    assert kept == [FILES_VOLUME], facts
    for kind in ("ps -aq", "network ls -q", "volume ls -q", "image ls -q"):
        left = _stdout(["docker", *kind.split(), "--filter", "label=pridem.stack"])
        assert left == ([FILES_VOLUME] if kind == "volume ls -q" else []), (kind, left)
    read = ["docker", "run", "--rm", "--network", "none",
            "--mount", f"type=volume,source={FILES_VOLUME},target=/v", "--", image,
            "cat", "/v/mark"]  # fmt: skip
    assert _stdout(read) == [MARK]
    assert sorted(str(p) for p in OPT.rglob("*")) == [
        str(OPT / ".pridem"),
        str(OPT / "env"),
        str(MINTED),
    ]
    for gone in ("/opt/pridem/edge", "/opt/pridem/egress", "/opt/pridem/state.json"):
        assert not Path(gone).exists(), gone
    assert not Path("/etc/systemd/system/pridem-gc.timer").exists()
    assert Path("/opt/pridem/passport.yaml").is_file()
    assert any(Path("/opt/pridem/history").glob("*.json"))
    again, printed = _verdict_of("destroy", "--confirm", "tier3-env")
    assert again.result == "green", printed


PLANTED_TEST = "test_planted_dm_126.py"
PLANTED_TEST_BODY = """\
def test_planted_dm_126() -> None:
    raise AssertionError("planted by DM-126")
"""
"""A test of the blank's backend that fails, whatever the box."""


def _blank_with_a_red_test(tmp: Path, mirror: Path) -> None:
    """The blank with one more test, which fails: nothing else of it changes."""
    copy = _copy_of_blank(tmp, mirror, "red-test")
    planted = copy / "backend" / "tests" / PLANTED_TEST
    planted.write_text(PLANTED_TEST_BODY, encoding="utf-8")
    _push(copy, mirror, "DM-126: the blank with a red test")


def _services_of(project: str) -> list[str]:
    """The compose services of every container of ``project``, running or
    not, sorted."""
    label = '{{.Label "com.docker.compose.service"}}'
    found = _stdout(
        ["docker", "ps", "-a", "--format", label,
         "--filter", f"label=com.docker.compose.project={project}"]
    )  # fmt: skip
    return sorted(found)


def _labelled(kind: str) -> list[str]:
    """What docker lists of ``kind`` under the machine's label."""
    return _stdout(["docker", *kind.split(), "--filter", "label=pridem.stack"])


def test_tier3_red_tests_stop_before_any_migrate(tmp_path: Path, mirror: Path) -> None:
    """DM-126, the first of group ``d``, on a clean box: a first install of
    the blank whose tests are red. The verdict is red at ``tests`` of the
    product with one failed test; the service's environment was whole before
    the product rendered its own; no ``stop_for_migrate``, ``migrate``,
    ``up`` or ``seeds`` of any stack began; no restore is needed; no
    container of the service, none of the product's app or frontend; no
    ``current``, no ``state.json``. The pair is the probe of DM-59, next in
    the group: the same ladder, green, goes through ``migrate`` and ``up``.
    Measured into the run's output first (par0 14.3): the steps of the
    verdict with their status, the containers the red install left."""
    assert not (OPT / "current").exists(), "a clean box"
    _blank_with_a_red_test(tmp_path, mirror)
    red, printed = _install(_passport(tmp_path, version=30))
    ladder = [(s.stack, s.name, s.status) for s in red.steps if s.phase == "main"]
    left = {project: _services_of(project) for project in (STACK, SERVICE, FILES)}
    print("DM-126 measure: the red install", ladder, "containers", left)
    assert red.result == "red", printed
    [failed] = [s for s in red.steps if s.status == "failed"]
    assert (failed.stack, failed.name) == (STACK, "tests"), printed
    assert failed.reason is not None and failed.reason.code == "tests:failed", printed
    assert failed.reason.model_dump()["failed"] == 1, failed.reason
    order = [(stack, name) for stack, name, _ in ladder]
    assert order.index((SERVICE, "derive_env")) < order.index((STACK, "render_env"))
    assert order.index((STACK, "render_env")) < order.index((STACK, "tests")), order
    late = ("stop_for_migrate", "migrate", "up", "seeds")
    begun = [step for step in ladder if step[1] in late and step[2] != "skipped"]
    assert begun == [], begun
    assert not [i for i in red.report.incomplete if i.what == "restore"], printed
    assert left[SERVICE] == [], left
    assert "app" not in left[STACK] and "frontend" not in left[STACK], left
    assert not (OPT / "current").exists()
    assert not Path("/opt/pridem/state.json").exists()


def test_tier3_destroy_after_an_interrupted_install() -> None:
    """DM-126, on the box the red install left: no ``state.json``, no
    ``current``, a release on the disk and a labelled volume of the product
    (the database the tests ran in). ``destroy`` takes it all: green, no
    volume kept, nothing labelled left, ``/opt/primer-blank`` down to its
    mark and ``minted.yaml`` -- the volume's entry is named by ``primer.yaml``
    of the release on the disk. Before DM-126 this was
    ``persistent-unknown``. The pair of the persistent side is
    ``test_tier3_destroy_takes_the_blank_off_the_box`` (group ``c``)."""
    assert not Path("/opt/pridem/state.json").exists(), "the red install runs first"
    assert not (OPT / "current").exists()
    releases = sorted(path.name for path in (OPT / "releases").iterdir())
    before = _labelled("volume ls -q")
    print("DM-126 measure: before destroy", {"releases": releases, "volumes": before})
    assert releases and f"{STACK}_pgdata" in before, (releases, before)
    verdict, printed = _verdict_of("destroy", "--confirm", "tier3-env")
    assert verdict.result == "green", printed
    facts = {(s.stack, s.name): s.verify or {} for s in verdict.steps}
    assert facts[("pridem-destroy", "remove_objects")]["kept_volumes"] == [], facts
    for kind in ("ps -aq", "network ls -q", "volume ls -q", "image ls -q"):
        assert _labelled(kind) == [], kind
    assert sorted(str(p) for p in OPT.rglob("*")) == [
        str(OPT / ".pridem"),
        str(OPT / "env"),
        str(MINTED),
    ]


def test_probe_DM_59_product_gets_the_seams_of_its_service_after_health(
    tmp_path: Path, mirror: Path
) -> None:
    """DM-59 on the box ``destroy`` left -- clean of every stack. The pair
    first: the blank in an edition without its service installs nothing of
    it -- no release, no container, none of its seams in the product's env.
    Then the blank at its pin: the service's environment is whole -- its
    ``derive_env`` done -- before the product renders its env; the product's
    tests run before the first ``migrate`` and before the service goes up,
    and the product goes up after the service; the product's container holds
    the values of the service's three seams -- its address, its minted token
    and the key its ``derive`` computed in the service's own image -- equal
    to what the service's env holds; ``seams_verify`` reads both ends live.
    The time of both installs goes to the run's output (par0 14.3).

    Changed by DM-126 (owner's decision of 19.11, which takes back the one of
    31.10; by the dispatcher's word, before the change): it asserted "the
    service goes up, healthy, before the product renders its env". A seam is
    ready with the provider's environment now -- two halves of the ladder,
    the tests of the product before the point of no return; the values the
    product holds are asserted as before."""
    assert not (OPT / "current").exists(), "destroy runs first"

    _blank_without_service(tmp_path, mirror, step=10)
    started = time.monotonic()
    alone, printed = _install(_passport(tmp_path, version=40))
    without = time.monotonic() - started
    assert alone.result == "green", printed
    assert not any(s.stack == SERVICE for s in alone.steps), alone.steps
    assert not Path(f"/opt/{SERVICE}/current").exists()
    assert _containers_of(SERVICE) == []
    assert not set(SEAMS) & set(_env()), sorted(_env())

    _at_blank_commit(mirror)
    started = time.monotonic()
    green, printed = _install(_passport(tmp_path, version=41), "update")
    with_service = time.monotonic() - started
    warnings.warn(
        f"DM-59 timing: install without the service {without:.0f} s, "
        f"update with it {with_service:.0f} s",
        stacklevel=1,
    )
    assert green.result == "green", printed
    order = [(s.stack, s.name) for s in green.steps if s.phase == "main"]
    assert order.index((SERVICE, "derive_env")) < order.index((STACK, "render_env"))
    assert order.index((STACK, "tests")) < order.index((STACK, "migrate")), order
    assert order.index((STACK, "tests")) < order.index((SERVICE, "up")), order
    assert order.index((SERVICE, "up")) < order.index((STACK, "up")), order
    assert order.index((SERVICE, "derive_env")) < order.index((SERVICE, "up")), order
    facts = {(s.stack, s.name): s.verify or {} for s in green.steps}
    assert (
        facts[(SERVICE, "derive_env")]["image"]
        == facts[(SERVICE, "build")]["app_image"]
    ), facts[(SERVICE, "derive_env")]
    theirs, ours = _env(SERVICE_ENV), _env()
    assert theirs["SERVICE_API_URL"] == f"http://{SERVICE}-app:8000", theirs.keys()
    assert theirs["SERVICE_KEY"].startswith("sk_") and len(theirs["SERVICE_KEY"]) == 43
    assert theirs["PRODUCT_WEBHOOK_URL"] == f"https://{API}/internal/service/webhook"
    product = _app()
    for key in SEAMS:
        assert ours[key] == theirs[key], key  # values, not names
        held = _stdout(["docker", "exec", product, "printenv", key])
        assert held == [theirs[key]], key
    edges = facts[("pridem-seams", "seams_verify")]["seams"]
    assert isinstance(edges, list), edges
    for key in SEAMS:
        assert f"{STACK}.{key} <- {SERVICE}" in edges, edges
    assert f"{SERVICE}.PRODUCT_WEBHOOK_URL <- {STACK}" in edges, edges
    assert _health_of(_container(SERVICE, "app"))["seams"] == {
        "provides": list(SEAMS),
        "requires_satisfied": True,
    }
    for key in SEAMS:  # the values never reach the console or the verdict
        assert theirs[key] not in printed, key


HOOK = """#!/bin/sh
# DM-24: a git hook that leaves a process with the box lock's descriptor
[ "$1" = committed ] || exit 0
setsid sleep 20 </dev/null >/dev/null 2>&1 &
left=$!
echo $left > "{held}"
# DM-201: $! is setsid's pid until it execs sleep -- wait for the name
for _ in $(seq 100); do
  [ "$(cat /proc/$left/comm 2>/dev/null)" = sleep ] && break
  sleep 0.05
done
touch "{marker}"
sleep 20
"""

KILLED = """
"$1" install --passport "$2" >"$3/install.out" 2>&1 &
pid=$!
for _ in $(seq 1800); do [ -e "$3/marker" ] && break; sleep 0.1; done
if [ ! -e "$3/marker" ]; then
  echo "hook: not called"; kill -9 $pid; exit 0
fi
echo "hook: called"
journal=$(ls -t /opt/pridem/journal/*.jsonl | head -n 1)
echo "journal: $(tail -n 1 "$journal")"
echo "run: $(basename "$journal" .jsonl)"
kill -9 $pid
wait $pid 2>/dev/null
"$1" status >"$3/busy.out" 2>&1
echo "busy exit: $?"
cat "$3/busy.out"
"""


def test_probe_DM_24_sigkill_leaves_the_lock_to_the_grandchild(
    tmp_path: Path, mirror: Path
) -> None:
    """DM-24 (05.11): ``pridem`` killed outright (SIGKILL) while a command of
    it runs -- ``git fetch`` of ``fetch_root``, whose hook left a process with
    the box lock's descriptor. The command's leader dies with ``pridem``
    (``pdeathsig``); what it left holds the box: the next command is refused,
    ``BoxBusy`` naming the processes. Once they are gone the next command
    runs, and ``recover`` gives the killed run its red verdict
    (``run/no-verdict``). The last of group ``a``: it leaves the box half
    installed and the mirror's ``main`` on a commit of its own -- the order
    matters, no test of the group runs after it. Measured into the run's output
    (par0 14.3): that git called the hook, the journal's last line then (the
    step in progress), the refusal as printed, the holders.

    FIX: ``fetch_root`` fetches only a commit whose release the box has not --
    the probe of DM-10, earlier in group ``a``, leaves ``BLANK_COMMIT`` there,
    so the probe deploys a commit of its own the box has not fetched.

    Changed by DM-201, on the dispatcher's word 26.11: the window of ``exec``
    -- ``$!`` of the hook is the pid of ``setsid`` until it execs ``sleep``
    under the same pid, so the hook waits for ``/proc/<pid>/comm`` to be
    ``sleep`` (5 s at most) before its marker. What the probe holds is as it
    was: the refusal names ``pid <left> (sleep)``."""
    bare = OPT / "git"
    work = tmp_path / "dm24"
    hooks = work / "hooks"
    hooks.mkdir(parents=True)
    held, marker = work / "held", work / "marker"
    hook = hooks / "reference-transaction"
    hook.write_text(HOOK.format(held=held, marker=marker), encoding="utf-8")
    hook.chmod(0o755)
    if not (bare / "HEAD").is_file():  # the bare repository DM-10 left, or a new one
        _run(["git", "init", "--quiet", "--bare", str(bare)], env=GIT_ENV)
        _run(
            [
                "git",
                "--git-dir",
                str(bare),
                "remote",
                "add",
                "origin",
                f"file://{mirror}",
            ]
        )
    # a commit the box has not fetched: fetch_root acts, git fetch moves a ref
    copy = _copy_of_blank(tmp_path, mirror, "dm24-unfetched")
    _git("-C", str(copy), "commit", "-q", "--allow-empty", "-m", "DM-24: unfetched")
    _git("-C", str(copy), "push", "-q", "--force", str(mirror), "HEAD:refs/heads/main")
    try:
        _run(["git", "--git-dir", str(bare), "config", "core.hooksPath", str(hooks)])
        seen = _run(
            ["sh", "-c", KILLED, "scene", PRIDEM, str(_passport(tmp_path)), str(work)],
            timeout=1200,
        )
        print("DM-24 measure:", seen)
        assert seen[0] == "hook: called", seen
        assert seen[1].startswith("journal: ") and '"fetch_root"' in seen[1], seen
        assert seen[2].startswith("run: "), seen
        run = seen[2].removeprefix("run: ")  # the killed run: its journal's name
        assert "busy exit: 1" in seen, seen
        refusal = "\n".join(seen)
        assert "the box is busy" in refusal and "held by pid" in refusal, seen
        left = int(held.read_text().strip())
        assert f"pid {left} (sleep)" in refusal, seen
        deadline_at = time.monotonic() + 60
        while True:  # the processes left end by themselves (20 s)
            code, _, err = _pridem("status")
            if code != 1 or time.monotonic() > deadline_at:
                break
            time.sleep(2)
        assert code in (0, 2), err
    finally:
        _run(
            ["git", "--git-dir", str(bare), "config", "--unset", "core.hooksPath"],
            expect=(0, 5),
        )
    # FIX 2: history/ of group a holds the installs of earlier tests too -- the
    # verdict is the killed run's, by its run_id
    verdict = Path("/opt/pridem/history") / f"{run}.json"
    install = Verdict.model_validate_json(verdict.read_text(encoding="utf-8"))
    assert (install.run_id, install.verb) == (run, "install")
    assert install.result == "red"
    [entry] = install.report.incomplete
    assert (entry.what, entry.code) == ("run", "no-verdict"), entry


def test_tier3_destroy_all_wipes_the_persistent_volume() -> None:
    """DM-86, pass 4, after ``destroy``: the volume of ``primer-blank-files``
    stayed. ``destroy --all`` without ``--confirm`` -- refused, the volume
    there; with the server's name -- green, the volume gone and named wiped,
    ``kept-volumes.json`` gone."""
    assert not (OPT / "current").exists(), "destroy runs first"
    assert _stdout(["docker", "volume", "ls", "-q", "--filter", f"name={FILES_VOLUME}"])
    code, out, err = _pridem("destroy", "--all")
    assert code == 1 and "--confirm tier3-env" in "\n".join(err), (out, err)
    assert _stdout(["docker", "volume", "ls", "-q", "--filter", f"name={FILES_VOLUME}"])
    verdict, printed = _verdict_of("destroy", "--all", "--confirm", "tier3-env")
    assert verdict.result == "green", printed
    facts = {(s.stack, s.name): s.verify or {} for s in verdict.steps}
    assert facts[("pridem-destroy", "remove_objects")]["wiped_volumes"] == [
        FILES_VOLUME
    ]
    assert (
        _stdout(["docker", "volume", "ls", "-q", "--filter", f"name={FILES_VOLUME}"])
        == []
    )
    assert not Path("/opt/pridem/kept-volumes.json").exists()
    # DM-106: no volume of the machine's stacks is left, anonymous included
    left = _volumes()
    print("DM-106 measure: volumes after destroy --all", left)
    assert left == {}, left


GOLDEN_DOCKERFILE_CHECK = """COPY . .
RUN test ! -e public/skin/skin.css
ARG PRIMER_EDITION
RUN test -n "$PRIMER_EDITION" && mkdir -p public \\
    && printf '%s' "$PRIMER_EDITION" > public/edition.txt
"""
"""What the copy of DM-101 adds to the build stage of its frontend: no skin's
copy in the context -- one there and the build fails -- and the edition the
golden build got, served at ``/edition.txt``."""


def test_tier3_optional_build_slot_without_a_package_serves_the_repository_s_front(
    tmp_path: Path, mirror: Path
) -> None:
    """DM-101 on the box the install left: a copy of the blank whose slot
    ``skin`` is built into frontend and ``optional``; the passport names no
    skin. The update is green: the build had no copy of a package in its
    context (the copy's Dockerfile refuses one) and got the edition; the key
    is ``skin: absent``, the fact of ``packages`` too; the page serves the
    repository's front; ``doctor`` is empty. Measured into the run's output
    (par0 14.3): the key and the fact."""
    assert (OPT / "current").is_symlink(), "the whole install runs first"
    copy = _copy_of_blank(tmp_path, mirror, "golden")
    primer = copy / "primer.yaml"
    golden = BUILD_SKIN.replace(
        "    apply: build\n", "    apply: build\n    optional: true\n"
    )
    assert golden.count("optional: true") == 1
    _replace_once(primer, RUNTIME_SKIN, golden)
    _replace_once(
        copy / "frontend" / "Dockerfile", "COPY . .\n", GOLDEN_DOCKERFILE_CHECK
    )
    _push(copy, mirror, "DM-101: the skin of the blank built in and optional")
    passport = _passport(tmp_path, version=70)
    verdict, printed = _install(passport, "update")
    assert verdict.result == "green", printed
    facts = {(s.stack, s.name): s.verify or {} for s in verdict.steps}
    keys = facts[(STACK, "build")]["keys"]
    packages = _packages_fact(verdict)
    print("DM-101 measure:", {"keys": keys, "packages": packages})
    assert keys == {
        "frontend": {"pridem.edition": "core", "pridem.package.skin": "absent"}
    }, keys
    assert packages == {"skin": "absent"}, packages
    assert _body("/edition.txt", FRONTEND) == "core"
    diff, failed, _ = _doctor(passport)
    assert (diff, failed) == ([], []), (diff, failed)


def test_tier3_an_entry_named_frontend_is_the_product_s_own(
    tmp_path: Path, mirror: Path
) -> None:
    """DM-102, last of its group: a copy of the blank with a second entry named
    ``frontend`` -- a word of the machine's plans before DM-102, the
    product's own now. ``update`` green; the verdict holds the entry's
    ``(frontend, up)`` and the machine's ``(pridem-frontend, frontend)``, two
    keys, two facts, none mixed with the other."""
    assert (OPT / "current").is_symlink(), "the whole install runs first"
    copy = _copy_of_blank(tmp_path, mirror, "frontend-entry")
    _replace_once(
        copy / "primer.yaml",
        "  primer-blank-files:",
        "  frontend:\n    compose: deploy/frontend-compose.yml\n  primer-blank-files:",
    )
    image = (
        "postgres:16-alpine@sha256:"
        "f4610795587492cd4fb887c2dc3de301b813278bb6f616992061141b5f15ac36"
    )
    (copy / "deploy" / "frontend-compose.yml").write_text(
        "services:\n"
        "  idle:\n"
        f"    image: {image}\n"
        '    command: ["sh", "-c", "while sleep 3600; do :; done"]\n'
        "    healthcheck:\n"
        '      test: ["CMD", "true"]\n'
        "      interval: 5s\n",
        encoding="utf-8",
    )
    _push(copy, mirror, "DM-102: an entry named frontend")
    verdict, printed = _install(_passport(tmp_path, version=90), "update")
    assert verdict.result == "green", printed
    facts = {(s.stack, s.name): s.verify or {} for s in verdict.steps}
    print("DM-102 measure:", sorted(k for k in facts if "frontend" in k[0]))
    assert facts[("frontend", "up")]["stack"] == "frontend", facts
    assert "domain" in facts[("pridem-frontend", "frontend")], facts
    assert _container("frontend", "idle")


APT_TIMERS = ("apt-daily.timer", "apt-daily-upgrade.timer")


def _timers_state() -> list[str]:
    """``is-enabled`` and ``is-active`` of each apt timer, as systemctl says."""
    said = []
    for timer in APT_TIMERS:
        enabled = _run(["systemctl", "is-enabled", timer], expect=(0, 1, 4))
        running = _run(["systemctl", "is-active", timer], expect=(0, 3, 4))
        said.append(f"{timer}: {' '.join(enabled) or '-'} / {' '.join(running) or '-'}")
    return said


COMMAND_HOOK = """#!/bin/sh
# DM-138: git fetch of fetch_root waits here, the run holding the box
[ "$1" = committed ] || exit 0
touch "{marker}"
sleep 20
"""

COMMANDED = """
"$1" --json --command c-138 update --passport "$2" >"$3/update.out" 2>"$3/update.err" &
pid=$!
for _ in $(seq 1800); do [ -e "$3/marker" ] && break; sleep 0.1; done
if [ ! -e "$3/marker" ]; then
  echo "hook: not called"; wait $pid; exit 0
fi
echo "hook: called"
echo "journal: $(basename "$(ls -t /opt/pridem/journal/*.jsonl | head -n 1)" .jsonl)"
"$1" --json --command c-139 status >"$3/busy.out" 2>"$3/busy.err"
echo "busy exit: $?"
wait $pid
echo "update exit: $?"
"""


def test_tier3_a_command_runs_and_a_busy_box_names_it(
    tmp_path: Path, mirror: Path
) -> None:
    """DM-138, in group ``o`` (DM-208: out of ``d``), on the box the test
    before it left: ``pridem --json --command c-138 update`` -- the
    call of the agent -- waits in ``fetch_root`` on a git hook. Meanwhile
    ``pridem --json --command c-139 status`` is refused: exit 1, on stdout
    the object ``box-busy`` naming the run of the update (its journal), verb
    ``update``, command ``c-138``, the Panel as its actor; no verdict of the
    refused status. The update then ends: its verdict and its journal's header
    carry ``c-138``. Measured into the run's output first (par0 14.3): the
    scene's lines, the refusal, the verdict."""
    assert (OPT / "current").is_symlink(), "the group's box is installed"
    bare = OPT / "git"
    work = tmp_path / "dm138"
    hooks = work / "hooks"
    hooks.mkdir(parents=True)
    hook = hooks / "reference-transaction"
    hook.write_text(COMMAND_HOOK.format(marker=work / "marker"), encoding="utf-8")
    hook.chmod(0o755)
    copy = _copy_of_blank(tmp_path, mirror, "dm138-unfetched")
    _git("-C", str(copy), "commit", "-q", "--allow-empty", "-m", "DM-138: unfetched")
    _git("-C", str(copy), "push", "-q", "--force", str(mirror), "HEAD:refs/heads/main")
    history = Path("/opt/pridem/history")
    before = {p.name for p in history.iterdir()}
    _run(["git", "--git-dir", str(bare), "config", "core.hooksPath", str(hooks)])
    try:
        seen = _run(
            [
                "sh",
                "-c",
                COMMANDED,
                "scene",
                PRIDEM,
                str(_passport(tmp_path, version=47)),
                str(work),
            ],
            timeout=1200,
        )
    finally:
        _run(["git", "--git-dir", str(bare), "config", "--unset", "core.hooksPath"])
    refused = (work / "busy.out").read_text(encoding="utf-8")
    printed = (work / "update.out").read_text(encoding="utf-8")
    print("DM-138 measure:", seen, "refusal:", refused, "verdict:", printed[:2000])
    assert seen[0] == "hook: called", seen
    run_id = seen[1].removeprefix("journal: ")
    assert "busy exit: 1" in seen and "update exit: 0" in seen, seen
    refusal = json.loads(refused)
    assert refusal["refused"] == "box-busy", refusal
    assert refusal["holder"]["run_id"] == run_id, refusal
    assert refusal["holder"]["verb"] == "update", refusal
    assert refusal["holder"]["command"] == "c-138", refusal
    assert refusal["holder"]["actor"] == {"type": "engineer", "via": "panel"}
    verdict = Verdict.model_validate_json(printed)
    assert (verdict.run_id, verdict.command) == (run_id, "c-138")
    header = json.loads(
        Path(f"/opt/pridem/journal/{run_id}.jsonl").read_text().splitlines()[0]
    )
    assert header["command"] == "c-138", header
    assert {p.name for p in history.iterdir()} - before == {f"{run_id}.json"}


def test_tier3_every_journal_has_its_seq_and_its_end() -> None:
    """DM-137, in group ``d`` before its last test (the apt timers on, which
    must stay last), on the box its installs, ``destroy`` and ``status``
    left: every journal of ``journal/`` is a stream
    -- each line's ``seq`` its number, from 1, no gap, an ``at`` to the
    millisecond. A run with its verdict in ``history/`` ends with
    ``run_finished`` whose ``exit_code`` and ``result`` are the verdict's; a
    journal without a verdict has no end. Measured into the run's output first
    (par0 14.3): the journals, their last lines, the verdicts."""
    home = Path("/opt/pridem")
    journals = sorted((home / "journal").glob("*.jsonl"))
    seen: dict[str, object] = {}
    for path in journals:
        lines = [json.loads(line) for line in path.read_text().splitlines()]
        verdict_file = home / "history" / f"{path.stem}.json"
        verdict = (
            json.loads(verdict_file.read_text()) if verdict_file.is_file() else None
        )
        seen[path.stem] = {
            "lines": len(lines),
            "last": lines[-1] if lines else None,
            "verdict": verdict and (verdict["exit_code"], verdict["result"]),
        }
    print("DM-137 measure: journals", json.dumps(seen))
    assert journals, "the group ran plans on this box"
    for path in journals:
        lines = [json.loads(line) for line in path.read_text().splitlines()]
        assert [line["seq"] for line in lines] == list(range(1, len(lines) + 1)), path
        assert all(
            re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z", line["at"])
            for line in lines
        ), path
        verdict_file = home / "history" / f"{path.stem}.json"
        ends = [line for line in lines if line["event"] == "run_finished"]
        if verdict_file.is_file():
            verdict = json.loads(verdict_file.read_text())
            assert ends == [lines[-1]], path
            assert (lines[-1]["exit_code"], lines[-1]["result"]) == (
                verdict["exit_code"],
                verdict["result"],
            ), path
        else:
            assert ends == [], path


ROOT_FRONTEND = """    build:
      context: .
      dockerfile: frontend/Dockerfile
"""
"""The copy of DM-127: the blank's frontend built from the repository's root,
as velo's is."""

ROOT_DOCKERFILE = (
    (
        "COPY package.json package-lock.json ./\n",
        "COPY frontend/package.json frontend/package-lock.json ./\n",
    ),
    ("COPY . .\n", "COPY frontend/ .\nRUN test -f public/skin/skin.css\n"),
    (
        "COPY nginx/package.js nginx/validate.js ",
        "COPY frontend/nginx/package.js frontend/nginx/validate.js ",
    ),
    ("COPY src/texts/ ", "COPY frontend/src/texts/ "),
    ("COPY nginx/default.conf.template ", "COPY frontend/nginx/default.conf.template "),
)
"""The frontend's Dockerfile read from the root: every COPY of the context
under ``frontend/``; the skin checked by the build, as in DM-61."""


def test_tier3_doctor_is_empty_with_the_apt_timers_on(tmp_path: Path) -> None:
    """DM-105 on the box group ``d`` left: the apt timers on, as on a live
    Ubuntu (velo-dev) -- after a green ``update``, ``doctor`` is code 0 with no
    difference: the pause of ``wait_host_quiet`` is for the time of a run. The
    last of group ``d``: a timer of ``Persistent=true`` may start
    ``apt-daily.service`` at once and hold ``dpkg`` for what would come after.
    Measured into the run's output (par0 14.3): the timers' state on the
    runner before, after starting them and after the test's ``finally``."""
    assert (OPT / "current").is_symlink(), "group d installs first"
    passport = _passport(tmp_path, version=42)
    verdict, printed = _install(passport, "update")
    assert verdict.result == "green", printed
    print("DM-105 measure, before:", _timers_state())
    try:
        _run(["systemctl", "unmask", *APT_TIMERS], expect=(0, 1))
        started = _run(["systemctl", "start", *APT_TIMERS], expect=(0, 1, 5))
        state = _timers_state()
        print("DM-105 measure, started:", started, state)
        # the pair: the timers do run -- a doctor with none on proves nothing
        assert all(line.endswith(" / active") for line in state), state
        diff, failed, doctor = _doctor(passport)
        assert (diff, failed) == ([], []), (diff, failed)
        assert doctor.exit_code == 0, doctor.result
    finally:
        _run(["systemctl", "stop", *APT_TIMERS], expect=(0, 5))
        _run(["systemctl", "mask", *APT_TIMERS], expect=(0, 1))
        print("DM-105 measure, after:", _timers_state())


ROOT_FRONTEND = """    build:
      context: .
      dockerfile: frontend/Dockerfile
"""
"""The copy of DM-127: the blank's frontend built from the repository's root,
as velo's is."""

ROOT_DOCKERFILE = (
    (
        "COPY package.json package-lock.json ./\n",
        "COPY frontend/package.json frontend/package-lock.json ./\n",
    ),
    ("COPY . .\n", "COPY frontend/ .\nRUN test -f public/skin/skin.css\n"),
    (
        "COPY nginx/package.js nginx/validate.js ",
        "COPY frontend/nginx/package.js frontend/nginx/validate.js ",
    ),
    ("COPY src/texts/ ", "COPY frontend/src/texts/ "),
    ("COPY nginx/default.conf.template ", "COPY frontend/nginx/default.conf.template "),
)
"""The frontend's Dockerfile read from the root: every COPY of the context
under ``frontend/``; the skin checked by the build, as in DM-61."""


def test_tier3_a_skin_built_into_a_frontend_built_from_the_root(
    tmp_path: Path, mirror: Path
) -> None:
    """DM-127 (review 0004, finding 5): a copy of the blank whose frontend is
    built from the repository's root, as velo's is, the skin built into it at
    ``frontend/public/skin`` -- the path of the context, where its build reads
    it: the update is green and the frontend serves the skin. What DM-61
    holds of a build with a package is its, not this probe's."""
    assert (OPT / "current").is_symlink(), "the whole install runs first"
    skin = _skin_repository(tmp_path)
    copy = _copy_of_blank(tmp_path, mirror, "root-context")
    primer = copy / "primer.yaml"
    rooted = BUILD_SKIN.replace("path: public/skin", "path: frontend/public/skin")
    assert rooted.count("frontend/public/skin") == 1
    _replace_once(primer, RUNTIME_SKIN, rooted)
    _replace_once(
        copy / "docker-compose.yml",
        "    build:\n      context: ./frontend\n",
        ROOT_FRONTEND,
    )
    for old, new in ROOT_DOCKERFILE:
        _replace_once(copy / "frontend" / "Dockerfile", old, new)
    _push(copy, mirror, "DM-127: the frontend built from the root, the skin into it")
    package = {"skin": {"repo": f"file://{skin}", "version": "1.0.0"}}
    verdict, printed = _install(
        _passport(tmp_path, version=80, packages=package), "update"
    )
    assert verdict.result == "green", printed
    facts = {(s.stack, s.name): s.verify or {} for s in verdict.steps}
    print("DM-127 measure:", facts.get((STACK, "build")))
    assert _body("/skin/skin.css", FRONTEND) == "one"


SSE_EVENTS = 5
"""DM-147: the copy's stream -- five server-sent events a second apart."""
SSE_ROUTE = '    api:      { to: "app:8000", max_body: 1M }\n'
SSE_PATHS = (
    '    api:      { to: "app:8000", max_body: 1M,\n'
    '                paths: { "/sse/": { read_timeout: 120s, buffering: false } } }\n'
)
SSE_APP = '''
    from fastapi.responses import StreamingResponse

    async def _ticks() -> AsyncIterator[bytes]:
        for n in range(5):
            yield f"data: {n}\\n\\n".encode()
            await asyncio.sleep(1)

    @app.get("/sse/events")
    @app.get("/events")
    async def events() -> StreamingResponse:
        """DM-147 (tier 3): one stream under the path /sse/ and outside it."""
        return StreamingResponse(_ticks(), media_type="text/event-stream")

    return wrapped
'''
SSE_CLIENT = """
import http.client, json, ssl, sys, time
host, port, tls, name, path = sys.argv[1:6]
if tls == "tls":
    context = ssl._create_unverified_context()
    conn = http.client.HTTPSConnection(host, int(port), context=context, timeout=60)
else:
    conn = http.client.HTTPConnection(host, int(port), timeout=60)
start = time.monotonic()
conn.request("GET", path, headers={"Host": name, "Accept-Encoding": "gzip"})
resp = conn.getresponse()
times = []
while chunk := resp.read1(65536):
    times += [round(time.monotonic() - start, 2)] * chunk.count(b"data:")
print(json.dumps({"status": resp.status,
                  "encoding": resp.getheader("Content-Encoding"),
                  "times": times}))
"""
"""Reads a stream and says when each event came: the same code at the app, on
the network ``pridem``'s side, and through nginx of the machine."""


def _sse_times(argv: list[str]) -> dict[str, object]:
    [line] = [x for x in _stdout(argv, timeout=120) if x.startswith("{")]
    found = json.loads(line)
    assert isinstance(found, dict), line
    return found


def _in_parts(leg: dict[str, object]) -> bool:
    times = leg["times"]
    assert isinstance(times, list) and len(times) == SSE_EVENTS, leg
    return bool(times[0] < 1.5 and times[-1] - times[0] >= 3)


def test_probe_DM_147_sse_arrives_in_parts_through_the_path(
    tmp_path: Path, mirror: Path
) -> None:
    """DM-147: a copy of the blank with one stream of server-sent events -- at
    ``/sse/events``, under the path ``/sse/`` of the route ``api`` with
    ``buffering: false``, and at ``/events``, outside it. Measured first and
    printed (par0 14.3): (a) at the app itself, inside its container -- the
    harness: the app sends in parts; (b) through nginx of the machine under
    the path -- in parts; (c) outside it -- at the end, all at once: the knob,
    not the app or nginx alone, makes (b). Over https, as the box serves: a
    measure of nginx 1.24 at DM-147's gate had (c) in parts over plain http
    and at the end over TLS. The long ``read_timeout`` is held by its literal
    in tier 1: a pause over 60 s is not spent here."""
    assert (OPT / "current").is_symlink(), "the group's install runs first"
    copy = _copy_of_blank(tmp_path, mirror, "sse")
    _replace_once(copy / "primer.yaml", SSE_ROUTE, SSE_PATHS)
    main = copy / "backend" / "app" / "main.py"
    _replace_once(main, "import hmac\n", "import asyncio\nimport hmac\n")
    _replace_once(main, "\n    return wrapped\n", SSE_APP)
    _push(copy, mirror, "DM-147: a stream under the path /sse/ and outside it")
    verdict, printed = _install(_passport(tmp_path, version=81), "update")
    assert verdict.result == "green", printed
    config = live_config(Path("/")).read_text(encoding="utf-8")
    sse = config[config.index("location /sse/ {") :]
    sse = sse[: sse.index("  }")]
    assert "proxy_buffering off;" in sse and "proxy_read_timeout 120s;" in sse, sse

    host = ["python3", "-c", SSE_CLIENT, "localhost", "443", "tls", API]
    app = ["docker", "exec", _app(), "python", "-c", SSE_CLIENT]
    legs = {
        "app": _sse_times([*app, "127.0.0.1", "8000", "plain", API, "/events"]),
        "path": _sse_times([*host, "/sse/events"]),
        "outside": _sse_times([*host, "/events"]),
    }
    print("DM-147 measure:", json.dumps(legs))
    assert {leg["status"] for leg in legs.values()} == {200}, legs
    assert legs["path"]["encoding"] is None, legs  # gzip_types has no event-stream
    assert _in_parts(legs["app"]), legs
    assert _in_parts(legs["path"]), legs
    # the pair: the same stream outside the path comes at the end, all at once
    times = legs["outside"]["times"]
    assert isinstance(times, list) and len(times) == SSE_EVENTS, legs
    assert times[0] >= times[-1] - 0.5 and times[-1] >= 3, legs


# --- DM-185: what nginx serves is the file; renew leaves a CA's certificate ----

TLS_NAMES = (FRONTEND, API)
TLS_DIR = Path("/opt/pridem/edge/certs")
PASSPORT_COPY_FILE = Path("/opt/pridem/passport.yaml")


def _tls_self_signed(tmp: Path, name: str, days: int) -> tuple[str, str]:
    """A self-signed pair over the box's names, ``days`` long."""
    key, crt = tmp / f"{name}.key", tmp / f"{name}.crt"
    _run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
         "-keyout", str(key), "-out", str(crt), "-days", str(days),
         "-subj", f"/CN={name}",
         "-addext", "subjectAltName=" + ",".join(f"DNS:{n}" for n in TLS_NAMES)],
    )  # fmt: skip
    return crt.read_text(), key.read_text()


def _tls_ca_issued(tmp: Path, days: int) -> tuple[str, str]:
    """A leaf a throwaway CA signed over the box's names: issuer != subject."""
    ca_key, ca_crt = tmp / "ca.key", tmp / "ca.crt"
    _run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
         "-keyout", str(ca_key), "-out", str(ca_crt), "-days", "30",
         "-subj", "/CN=DM-185 Test CA"],
    )  # fmt: skip
    key, csr, crt, ext = (tmp / n for n in ("leaf.key", "leaf.csr", "leaf.crt", "x"))
    _run(
        ["openssl", "req", "-newkey", "rsa:2048", "-nodes", "-keyout", str(key),
         "-out", str(csr), "-subj", f"/CN={FRONTEND}"],
    )  # fmt: skip
    ext.write_text("subjectAltName=" + ",".join(f"DNS:{n}" for n in TLS_NAMES) + "\n")
    _run(
        ["openssl", "x509", "-req", "-in", str(csr), "-CA", str(ca_crt),
         "-CAkey", str(ca_key), "-CAcreateserial", "-out", str(crt),
         "-days", str(days), "-extfile", str(ext)],
    )  # fmt: skip
    return crt.read_text(), key.read_text()


def _tls_place(cert: str, key: str) -> None:
    """The pair into nginx's files, as an older machine left it: no reload."""
    (TLS_DIR / "privkey.pem").write_text(key)
    (TLS_DIR / "privkey.pem").chmod(0o600)
    (TLS_DIR / "fullchain.pem").write_text(cert)


def _tls_reload() -> None:
    from pridem.steps.edge import argv as edge_argv

    _run(edge_argv(Path("/"), "exec", "-T", "nginx", "nginx", "-s", "reload"))


def _tls_seen(seconds: float) -> list[tuple[float, str | None]]:
    """What nginx serves on 443 for the box's name, each change, for
    ``seconds``: the measure of the old workers after a reload."""
    from pridem.steps.ssl import served_once

    seen: list[tuple[float, str | None]] = []
    started = time.monotonic()
    while time.monotonic() - started < seconds:
        got = served_once(FRONTEND, 443)
        if not seen or seen[-1][1] != got:
            seen.append((round(time.monotonic() - started, 3), got and got[:12]))
        time.sleep(0.01)
    return seen


def _tls_step(verdict: Verdict, name: str) -> dict[str, object]:
    [step] = [s for s in verdict.steps if s.name == name]
    return {"status": step.status, "reason": step.reason, "verify": step.verify}


def test_probe_DM_185_served_is_the_file_after_renew(tmp_path: Path) -> None:
    """DM-185, group i, on its self-signed box: a self-signed pair of ten days
    is what nginx serves; ``ssl renew`` signs it again, reloads nginx, and
    reads back from 443 that nginx serves the new file -- not the old.

    Measured into the run's log first (par0 14.3): that 443 answers TLS from
    the runner's host; a pair written without a reload is not served (B6);
    the sequence of what nginx serves for 1 s after ``nginx -s reload`` (the
    old workers, measured on nginx 1.24 of the sandbox)."""
    from pridem.steps.ssl import file_fingerprint, served_once

    assert (OPT / "current").is_symlink(), "the group's box is installed"
    root = Path("/")
    measured: dict[str, object] = {"443 before": served_once(FRONTEND, 443)}
    measured["file before"] = file_fingerprint(root)
    old = _tls_self_signed(tmp_path, "ten-days", 10)
    _tls_place(*old)
    measured["written, not reloaded"] = served_once(FRONTEND, 443)
    measured["the file now"] = file_fingerprint(root)
    _tls_reload()
    measured["after a reload, 1 s"] = _tls_seen(1.0)
    ten_days = file_fingerprint(root)
    verdict, printed = _verdict_of("ssl", "renew")
    renew = _tls_step(verdict, "ssl_renew")
    measured["renew"] = renew
    measured["served after"] = served_once(FRONTEND, 443)
    warnings.warn(f"DM-185 renew measure: {measured}", stacklevel=1)
    assert measured["443 before"] is not None, "443 answers TLS on the host"
    assert measured["written, not reloaded"] == measured["file before"]  # B6
    assert verdict.result == "green", printed
    fact = renew["verify"]
    assert isinstance(fact, dict)
    assert fact["served"] == file_fingerprint(root) != ten_days
    assert fact["renew_due"] is False and fact["self_signed"] is True
    assert served_once(FRONTEND, 443) == file_fingerprint(root)


def test_probe_DM_185_served_is_the_file_after_provided_changes(
    tmp_path: Path,
) -> None:
    """DM-185, group i: the passport switches the box to ``provided`` with a
    pair A -- ``update``: nginx serves A; then a pair B -- ``update``: nginx
    serves B, reloaded by ``tls_files`` though nginx's config did not change
    (B6). The pair: the files are the passport's each time."""
    from pridem.steps.ssl import file_fingerprint, served_once

    root = Path("/")
    a = _tls_self_signed(tmp_path, "pair-a", 90)
    b = _tls_self_signed(tmp_path, "pair-b", 90)
    seen: dict[str, object] = {}
    for version, (cert, key) in ((185, a), (186, b)):
        passport = _passport(tmp_path, version=version, ssl="provided", tls=(cert, key))
        verdict, printed = _install(passport, "update")
        seen[f"v{version}"] = {
            "result": verdict.result,
            "tls_files": _tls_step(verdict, "tls_files"),
            "served": served_once(FRONTEND, 443),
            "file": file_fingerprint(root),
        }
        warnings.warn(f"DM-185 provided measure: {seen}", stacklevel=1)
        assert verdict.result == "green", printed
        assert (TLS_DIR / "fullchain.pem").read_text() == cert
        assert served_once(FRONTEND, 443) == file_fingerprint(root)
    assert seen["v185"] != seen["v186"]


def test_probe_DM_185_a_bad_provided_pair_leaves_the_working_one(
    tmp_path: Path,
) -> None:
    """DM-185, group i, after the box went ``provided``: a passport whose
    certificate is not of its key -- ``update`` red at
    ``tls_files:provided-pair-mismatch``; the pair on disk and what nginx
    serves are what they were (B29)."""
    from pridem.steps.ssl import served_once

    before = (
        (TLS_DIR / "fullchain.pem").read_text(),
        (TLS_DIR / "privkey.pem").read_text(),
    )
    served = served_once(FRONTEND, 443)
    cert, _ = _tls_self_signed(tmp_path, "other", 90)
    passport = _passport(tmp_path, version=187, ssl="provided", tls=(cert, before[1]))
    verdict, printed = _install(passport, "update")
    files = _tls_step(verdict, "tls_files")
    warnings.warn(f"DM-185 bad pair measure: {files}, {verdict.result}", stacklevel=1)
    assert verdict.result == "red", printed
    reason = files["reason"]
    assert reason is not None and reason.code == "tls_files:provided-pair-mismatch"  # type: ignore[attr-defined]
    after = (
        (TLS_DIR / "fullchain.pem").read_text(),
        (TLS_DIR / "privkey.pem").read_text(),
    )
    assert after == before
    assert served_once(FRONTEND, 443) == served


def test_probe_DM_185_renew_leaves_a_ca_certificate(tmp_path: Path) -> None:
    """DM-185, group i, the last of it: the box's copy of the passport says
    ``letsencrypt``, certbot has no lineage, and nginx serves a certificate a
    CA issued with ten days left -- ``ssl renew`` does not sign over it (B7):
    exit 2, ``no-lineage``; the file and what nginx serves are what they
    were. Measured first: the mode ``ssl status`` reads from the copy."""
    from pridem.steps.ssl import file_fingerprint, served_once

    root = Path("/")
    copy = yaml.safe_load(PASSPORT_COPY_FILE.read_text(encoding="utf-8"))
    copy["policies"]["ssl"] = "letsencrypt"
    copy["policies"].pop("tls", None)
    PASSPORT_COPY_FILE.write_text(yaml.safe_dump(copy, sort_keys=False))
    PASSPORT_COPY_FILE.chmod(0o600)
    assert not Path("/opt/pridem/edge/letsencrypt/live/pridem").exists()
    cert, key = _tls_ca_issued(tmp_path, 10)
    _tls_place(cert, key)
    _tls_reload()
    _tls_seen(1.0)  # the old workers gone
    served = served_once(FRONTEND, 443)
    code, out, _ = _pridem("--json", "ssl", "status")
    verdict, printed = _verdict_of("ssl", "renew")
    measured = {
        "status": out,
        "code": code,
        "renew": _tls_step(verdict, "ssl_renew"),
        "incomplete": verdict.report.incomplete,
    }
    warnings.warn(f"DM-185 CA measure: {measured}", stacklevel=1)
    warnings.warn(f"group time so far: {_group_elapsed_s():.0f} s", stacklevel=1)
    assert verdict.result == "incomplete", printed
    [entry] = verdict.report.incomplete or []
    assert entry.code == "ssl_renew:no-lineage", entry
    assert (TLS_DIR / "fullchain.pem").read_text() == cert
    assert served_once(FRONTEND, 443) == served == file_fingerprint(root)


# --- DM-143: first contact -- one command installs the machine and its agent -----

FIRST_TOKEN = "tier3-first-contact-token-dm143"  # noqa: S105 -- a test value
INSTALL_SH = Path("/tmp/tier3/install.sh")  # noqa: S108 -- tier3.yml writes it there
"""``install.sh`` of this run, its pins in place (``tier3.yml``)."""
AGENT_UNIT = "pridem-agent.service"


class _FirstContactPanel(_AgentPanel):
    """The Panel of the first contact on the runner's loopback: the
    registration (one token, used once, the box's public half kept for the
    agent's signatures) and the agent's requests after it (``_AgentPanel``)."""

    used: ClassVar[set[str]] = set()

    def _answer(self, body: bytes) -> tuple[int, bytes]:
        if self.path != "/agent/v1/register":
            return super()._answer(body)
        asked = RegisterRequest.model_validate_json(body)
        token = asked.token.get_secret_value()
        if token != FIRST_TOKEN:
            return 404, Refusal(code="token-unknown").model_dump_json().encode()
        if token in self.used:
            return 410, Refusal(code="token-used").model_dump_json().encode()
        self.used.add(token)
        type(self).public = base64.b64decode(asked.box_key_public)
        answer = RegisterResponse(
            box_id="tier3-first-contact",
            agent_url="https://127.0.0.1/agent/v1/",
            heartbeat_s=5,
            full_state_s=60,
            poll_s=5,
        )
        return 201, answer.model_dump_json().encode()


@pytest.fixture(scope="module")
def first_contact() -> Iterator[tuple[type[_FirstContactPanel], str]]:
    """The Panel of the first contact for the probes of DM-143, and its origin;
    after them the agent's service is stopped and removed -- the box keeps no
    service of a test."""
    handler = type(
        "Panel",
        (_FirstContactPanel,),
        {"used": set(), "queue": [], "seen": [], "lines": {}, "verdicts": {},
         "beats": []},
    )  # fmt: skip
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        yield handler, f"http://127.0.0.1:{server.server_address[1]}"
    finally:
        _run(["systemctl", "disable", "--now", AGENT_UNIT], expect=(0, 1, 5))
        Path("/etc/systemd/system", AGENT_UNIT).unlink(missing_ok=True)
        _run(["systemctl", "daemon-reload"])
        server.shutdown()
        server.server_close()


def _first_contact(**env: str) -> tuple[int, list[str], list[str]]:
    """``bash install.sh`` of this run as the Panel's command runs it, with
    ``env`` added to a clean environment: exit, screen, refusal."""
    screen: list[str] = []
    refusal: list[str] = []

    def keep(stream: Stream, line: str, cut: bool) -> None:
        (screen if stream is Stream.STDOUT else refusal).append(line)

    result = SubprocessRunner().run(
        ["bash", str(INSTALL_SH)],
        expect=(0, 1),
        timeout=600,
        env={**clean_env(), **env},
        on_line=keep,
    )
    return result.code, screen, refusal


def _unit_says(prop: str) -> str:
    [line] = _stdout(["systemctl", "show", "-p", prop, "--value", AGENT_UNIT])
    return line.strip()


def _beats_after(handler: type[_FirstContactPanel], count: int) -> float:
    """Seconds until the Panel has more than ``count`` heartbeats."""
    began = time.monotonic()
    while len(handler.beats) <= count:
        assert time.monotonic() - began < 120, ("no heartbeat", handler.seen)
        time.sleep(0.5)
    return round(time.monotonic() - began, 1)


def test_probe_DM_143_no_token_installs_the_machine_and_says_why() -> None:
    """``install.sh`` with no token on a box with its product: the machine as
    it was, the sixth step says why there is no registration, no service, no
    ``agent/``. Measured into the run's journal (``warnings.warn``): systemd
    on this runner -- what the probes of DM-143 stand on (par0 14.3)."""
    measured = {
        "pid1": Path("/proc/1/comm").read_text().strip(),
        "systemd": _stdout(["systemctl", "--version"])[0],
        "state": _run(["systemctl", "is-system-running"], expect=(0, 1)),
    }
    warnings.warn(f"DM-143 measure: {measured}", stacklevel=1)
    assert measured["pid1"] == "systemd"
    code, screen, refusal = _first_contact()
    assert code == 0, refusal
    assert screen[-1] == (
        "6/6 agent: not registered -- no PRIDEM_REGISTER_TOKEN; "
        "the machine works without the Panel"
    )
    assert not Path("/opt/pridem/agent/registration.json").exists()
    assert not Path("/etc/systemd/system", AGENT_UNIT).exists()


def test_probe_DM_143_one_command_installs_registers_and_runs_the_agent(
    first_contact: tuple[type[_FirstContactPanel], str],
) -> None:
    """The Panel's command on a box with its product: the machine stands, the
    box is registered in the Panel, the agent runs as a service and the
    Panel hears its heartbeat -- signed by the key the registration gave. The
    token is on no line of the screen and of the install's log."""
    handler, origin = first_contact
    began = time.monotonic()
    code, screen, refusal = _first_contact(
        PRIDEM_REGISTER_TOKEN=FIRST_TOKEN, PRIDEM_PANEL=origin
    )
    assert code == 0, (screen, refusal)
    assert screen[-1] == "6/6 agent: registered; its service runs"
    [version] = _stdout([PRIDEM, "version"])
    assert version.startswith("pridem ")
    registration = json.loads(
        Path("/opt/pridem/agent/registration.json").read_text(encoding="utf-8")
    )
    assert registration["box_id"] == "tier3-first-contact"
    assert _unit_says("ActiveState") == "active"
    heard = _beats_after(handler, 0)
    log = Path("/var/log/pridem-install.log").read_text(encoding="utf-8")
    for text in (*screen, *refusal, log):
        assert FIRST_TOKEN not in text
    warnings.warn(
        f"DM-143 measure: the command {round(time.monotonic() - began, 1)} s, "
        f"the first heartbeat {heard} s after it; screen {screen}",
        stacklevel=1,
    )


def test_probe_DM_143_the_agent_service_survives_a_restart(
    first_contact: tuple[type[_FirstContactPanel], str],
) -> None:
    """``systemctl restart`` -- a new process, heard again; ``kill -9`` of
    the agent -- systemd starts it again (``Restart=always``), heard again. A
    reboot is not made on a runner: what systemd starts on boot is read
    instead -- the unit enabled, ``WantedBy=multi-user.target``, and
    ``multi-user.target`` wanting it."""
    handler, _ = first_contact
    first = _unit_says("MainPID")
    _run(["systemctl", "restart", AGENT_UNIT])
    second = _unit_says("MainPID")
    assert second not in ("0", first) and _unit_says("ActiveState") == "active"
    _beats_after(handler, len(handler.beats))
    os.kill(int(second), signal.SIGKILL)
    began = time.monotonic()
    while _unit_says("MainPID") in ("0", second):
        assert time.monotonic() - began < 60, "systemd did not start it again"
        time.sleep(0.5)
    again = round(time.monotonic() - began, 1)
    assert _unit_says("ActiveState") == "active"
    _beats_after(handler, len(handler.beats))
    assert _stdout(["systemctl", "is-enabled", AGENT_UNIT]) == ["enabled"]
    unit = Path("/etc/systemd/system", AGENT_UNIT).read_text(encoding="utf-8")
    assert "WantedBy=multi-user.target\n" in unit and "Restart=always\n" in unit
    wanted = _stdout(
        ["systemctl", "list-dependencies", "--plain", "--no-pager", "multi-user.target"]
    )
    assert any(line.strip() == AGENT_UNIT for line in wanted), wanted
    warnings.warn(
        f"DM-143 measure: started again {again} s after kill -9", stacklevel=1
    )


def test_probe_DM_143_a_used_token_is_refused(
    first_contact: tuple[type[_FirstContactPanel], str],
) -> None:
    """The token of a registration the Panel took, again on a box without its
    registration (the box died between the Panel's answer and its file,
    DM-139): ``register:token-used``, ``install.sh`` refuses with why, and
    no service starts."""
    handler, origin = first_contact
    _run(["systemctl", "stop", AGENT_UNIT])
    registration = Path("/opt/pridem/agent/registration.json")
    registration.rename(registration.with_suffix(".kept"))
    try:
        code, _, refusal = _first_contact(
            PRIDEM_REGISTER_TOKEN=FIRST_TOKEN, PRIDEM_PANEL=origin
        )
    finally:
        registration.with_suffix(".kept").rename(registration)
    assert code == 1
    assert refusal[0] == "install.sh: the box is not registered: see above"
    assert any("token is used already" in line for line in refusal), refusal
    assert _unit_says("ActiveState") != "active"
    assert ("POST", "/agent/v1/register", 410) in handler.seen


# --- DM-144: the agent against the test Panel -- a planted defect, the Panel away
#     in the middle of a run -----------------------------------------------------


class _LosingPanel(_AgentPanel):
    """A Panel that never holds the line ``LOST`` of a run -- as if the agent
    had skipped that ``seq``: its answer stops before it."""

    LOST: ClassVar[int] = 2

    def _answer(self, body: bytes) -> tuple[int, bytes]:
        status, answer = super()._answer(body)
        if status == 200 and self.path.endswith("/events"):
            held = self.lines[self.path.split("/")[4]]
            held.pop(self.LOST, None)
            last = 0
            while last + 1 in held:
                last += 1
            return 200, json.dumps({"last_seq": last}).encode()
        return status, answer


class _ForeignVerdictPanel(_AgentPanel):
    """A Panel that checks a verdict's envelope by another key than the
    box's -- as if the box had signed the verdict with a key not its own; its
    requests hold as they are."""

    foreign: ClassVar[bytes] = (
        Ed25519PrivateKey.generate()
        .public_key()
        .public_bytes(Encoding.Raw, PublicFormat.Raw)
    )

    def _verdict_key(self) -> bytes:
        return self.foreign


class _AwayPanel(_AgentPanel):
    """A Panel that goes away from a run the moment it gives its command:
    ``503`` to every ``runs/...`` and ``history`` until the test brings it
    back (``away`` false)."""

    away: ClassVar[bool] = False
    unanswered: ClassVar[list[str]] = []

    def _answer(self, body: bytes) -> tuple[int, bytes]:
        late = self.path.startswith("/agent/v1/runs/") or self.path.endswith("/history")
        if self.away and late:
            self.unanswered.append(self.path)
            return 503, b""
        status, answer = super()._answer(body)
        if self.path.endswith("/commands/next") and status == 200:
            type(self).away = True
        return status, answer


@pytest.fixture(scope="module")
def registered_port() -> Iterator[int]:
    """The box of this group registered in a Panel on the loopback: the port
    every round of DM-144 serves its Panel on."""
    handler = type(
        "Panel",
        (_FirstContactPanel,),
        {"used": set(), "queue": [], "seen": [], "lines": {}, "verdicts": {},
         "beats": []},
    )  # fmt: skip
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    port = server.server_address[1]
    try:
        result = SubprocessRunner().run(
            [PRIDEM, "register", "--panel", f"http://127.0.0.1:{port}"],
            timeout=120,
            env={**clean_env(), "PRIDEM_REGISTER_TOKEN": FIRST_TOKEN},
            on_line=lambda stream, line, cut: None,
        )
        assert result.code == 0
    finally:
        server.shutdown()
        server.server_close()
    yield port


def _round(
    port: int,
    base: type[_AgentPanel],
    command_id: str,
    until: Callable[[type[_AgentPanel]], bool],
    wait_s: float,
    public: bytes | None = None,
) -> tuple[type[_AgentPanel], list[str], float]:
    """One round of ``pridem agent`` against a Panel of ``base`` on ``port``
    that gives ``status`` as ``command_id``: until ``until`` holds or
    ``wait_s`` is over. The Panel, what the agent said, the seconds."""
    seed = Path("/opt/pridem/agent/box.key").read_bytes()
    own = Ed25519PrivateKey.from_private_bytes(seed).public_key()
    expires = (datetime.now(UTC) + timedelta(minutes=10)).strftime("%Y-%m-%dT%H:%M:%SZ")
    command: dict[str, object] = {
        "id": command_id,
        "verb": "status",
        "args": {},
        "expires_at": expires,
    }
    handler = type(
        "Panel",
        (base,),
        {
            "public": public or own.public_bytes(Encoding.Raw, PublicFormat.Raw),
            "queue": [command],
            "seen": [],
            "lines": {},
            "verdicts": {},
            "beats": [],
        },
    )
    server = ThreadingHTTPServer(("127.0.0.1", port), handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    began = time.monotonic()
    try:
        with _an_agent() as said:
            while time.monotonic() - began < wait_s and not until(handler):
                time.sleep(0.5)
    finally:
        server.shutdown()
        server.server_close()
    return handler, said, round(time.monotonic() - began, 1)


def _agent_round(handler: type[_AgentPanel], command_id: str) -> list[str]:
    """The problems of a round, by evidence the Panel holds: none only with a
    verdict of the command, verified by the box's key, its journal of two lines
    or more held by ``seq`` from the first to the last, and no request
    refused. The pair of every probe of DM-144: a planted defect names
    itself here."""
    problems: list[str] = []
    refused = sorted({code for _, _, code in handler.seen if 400 <= code < 500})
    if 401 in refused:
        problems.append("signature-bad")
    problems += [f"refused {code}" for code in refused if code != 401]
    runs = [run for run, kept in handler.verdicts.items() if kept[1] == command_id]
    if not runs:
        return [*problems, "no verdict"]
    [run] = runs
    if not handler.verdicts[run][0]:
        problems.append("verdict not verified")
    journal = Path("/opt/pridem/journal") / f"{run}.jsonl"
    written = len(journal.read_text(encoding="utf-8").splitlines())
    if written < 2:
        problems.append("too few lines")
    held = sorted(handler.lines.get(run, {}))
    if held != list(range(1, written + 1)):
        gap = next((seq for seq in range(1, written + 1) if seq not in held), None)
        problems.append(
            f"seq gap after {gap - 1}" if gap is not None else "seq past the journal"
        )
    return problems


def _a_verdict_of(command_id: str) -> Callable[[type[_AgentPanel]], bool]:
    return lambda panel: any(kept[1] == command_id for kept in panel.verdicts.values())


def test_probe_DM_144_a_planted_defect_reddens_the_agent_s_checks(
    registered_port: int,
) -> None:
    """The checks of the agent against the Panel, with their planted defects
    (par0 9: a check that cannot go red is no check). The Panel as it should
    be: no problem. A Panel that knows another key -- the box's signature does
    not hold: ``signature-bad``, and no verdict. A Panel that loses ``seq`` 2
    -- a stream with a gap: ``seq gap after 1``, the verdict itself verified.
    A Panel that checks the verdict by another key -- the verdict arrives:
    ``verdict not verified``.
    Measured into the run's journal first (par0 14.3): what the agent does on
    ``401`` -- its lines, alive to the end of the round."""
    right, _, spent_right = _round(
        registered_port,
        _AgentPanel,
        "cmd-144-right",
        _a_verdict_of("cmd-144-right"),
        120,
    )
    foreign = Ed25519PrivateKey.generate().public_key()
    wrong, said, spent_wrong = _round(
        registered_port,
        _AgentPanel,
        "cmd-144-foreign",
        lambda panel: len([s for s in panel.seen if s[2] == 401]) >= 3,
        30,
        public=foreign.public_bytes(Encoding.Raw, PublicFormat.Raw),
    )
    warnings.warn(
        f"DM-144 measure: the agent on 401 -- {said}; requests {wrong.seen}",
        stacklevel=1,
    )
    losing, _, spent_losing = _round(
        registered_port, _LosingPanel, "cmd-144-gap", _a_verdict_of("cmd-144-gap"), 120
    )
    forged, _, _ = _round(
        registered_port,
        _ForeignVerdictPanel,
        "cmd-144-forged",
        _a_verdict_of("cmd-144-forged"),
        120,
    )
    warnings.warn(
        f"DM-144 measure: rounds {spent_right} s, {spent_wrong} s, {spent_losing} s",
        stacklevel=1,
    )
    assert _agent_round(right, "cmd-144-right") == []
    found = _agent_round(wrong, "cmd-144-foreign")
    assert found == ["signature-bad", "no verdict"], found
    assert not any("Traceback" in line for line in said), said
    assert _agent_round(losing, "cmd-144-gap") == ["seq gap after 1"]
    assert _agent_round(forged, "cmd-144-forged") == ["verdict not verified"]


def test_probe_DM_144_the_panel_away_in_the_middle_of_a_run(
    registered_port: int,
) -> None:
    """The Panel gives ``status`` and goes away from it that moment: ``503``
    to its lines, its verdict and ``history``. The run goes on; the agent's
    tries meet ``503``. The Panel back, the run reaches it whole -- every line
    by ``seq``, the verdict verified: no problem left."""

    def back_after_a_try(panel: type[_AgentPanel]) -> bool:
        assert issubclass(panel, _AwayPanel)
        if panel.unanswered:
            panel.away = False  # the Panel is back once the agent met it away
        return _a_verdict_of("cmd-144-away")(panel)

    panel, said, spent = _round(
        registered_port, _AwayPanel, "cmd-144-away", back_after_a_try, 120
    )
    assert issubclass(panel, _AwayPanel)
    warnings.warn(
        f"DM-144 measure: the Panel away mid-run, met at {panel.unanswered}; "
        f"the verdict in {spent} s; said {said}",
        stacklevel=1,
    )
    assert any("/runs/" in path for path in panel.unanswered), panel.unanswered
    assert _agent_round(panel, "cmd-144-away") == []


# --- DM-163: self-update -- the machine of this run to a release the probe makes --


class _VersionPanel(_FirstContactPanel):
    """The Panel of the first contact that keeps the machine's version of
    every heartbeat."""

    versions: ClassVar[list[str]] = []

    def _answer(self, body: bytes) -> tuple[int, bytes]:
        if self.path == "/agent/v1/heartbeat":
            self.versions.append(Heartbeat.model_validate_json(body).machine_version)
        return super()._answer(body)


def _release_after(version: str) -> tuple[str, str]:
    """A release of the machine above this run's: the same code with its
    version raised, committed and tagged in a repository of its own, its
    wheel built, its ``install.sh`` rendered with its pins -- as
    ``release.yml`` does. Its tag and the address of its ``install.sh``."""
    major, minor, patch = version.split(".")
    new = f"{major}.{minor}.{int(patch) + 100}"
    tag = f"v{new}"
    work = Path("/tmp/tier3/self-update")  # noqa: S108 -- tier3.yml's directory
    shutil.rmtree(work, ignore_errors=True)
    clone, bare = work / "clone", Path("/tmp/tier3/primer-next.git")  # noqa: S108
    shutil.rmtree(bare, ignore_errors=True)
    _run(["git", "clone", "--quiet", "/tmp/tier3/primer.git", str(clone)])  # noqa: S108
    init = clone / "pridem" / "__init__.py"
    init.write_text(init.read_text().replace(f'"{version}"', f'"{new}"'))
    who = ["-c", "user.name=tier3", "-c", "user.email=tier3@primer.invalid"]
    _run(["git", "-C", str(clone), *who, "commit", "--quiet", "-am", f"release {tag}"])
    _run(["git", "-C", str(clone), "tag", tag])
    [commit] = _stdout(["git", "-C", str(clone), "rev-parse", "HEAD"])
    _run(["git", "clone", "--quiet", "--bare", str(clone), str(bare)])
    dist = work / "dist"
    _run(
        ["/tmp/build/bin/python", "-m", "pip", "wheel", "--no-deps",  # noqa: S108
         "--no-build-isolation", "--no-index", "-w", str(dist), str(clone)],
    )  # fmt: skip
    wheel = dist / f"pridem-{new}-py3-none-any.whl"
    sha = hashlib.sha256(wheel.read_bytes()).hexdigest()
    script = (clone / "install.sh").read_text()
    for pin, value in (
        ("@PRIDEM_TAG@", tag),
        ("@PRIDEM_COMMIT@", commit.strip()),
        ("@PRIDEM_WHEEL_SHA256@", sha),
        ("@PRIDEM_REPO@", "file:///tmp/tier3/primer-next"),
        ("@PRIDEM_WHEEL_URL@", f"file://{wheel}"),
    ):
        assert script.count(pin) == 1, pin
        script = script.replace(pin, value)
    (work / "install.sh").write_text(script)
    return tag, f"file://{work / 'install.sh'}"


def test_probe_DM_163_self_update_from_the_panel() -> None:
    """DM-163, group ``p``: the box registered in a Panel on the loopback,
    its agent a service; the Panel gives ``self-update <N>`` -- N a release
    the probe makes of this run's code with a higher version. The agent runs
    it, sends its verdict green and ends; systemd starts the new machine:
    ``pridem version`` is N, ``current`` is ``versions/vN``, and the next
    heartbeats say N. Measured into the run's journal: the times and what the
    agent said."""
    [said] = _stdout([PRIDEM, "version"])
    before = said.split()[1]
    began = time.monotonic()
    tag, source = _release_after(before)
    made = round(time.monotonic() - began, 1)
    handler: type[_VersionPanel] = type(
        "Panel",
        (_VersionPanel,),
        {"used": set(), "queue": [], "seen": [], "lines": {}, "verdicts": {},
         "beats": [], "versions": []},
    )  # fmt: skip
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    origin = f"http://127.0.0.1:{server.server_address[1]}"
    try:
        result = SubprocessRunner().run(
            [PRIDEM, "register", "--panel", origin],
            timeout=120,
            env={**clean_env(), "PRIDEM_REGISTER_TOKEN": FIRST_TOKEN},
            on_line=lambda stream, line, cut: None,
        )
        assert result.code == 0
        _run([PRIDEM, "agent", "install"])
        _beats_after(handler, 0)
        expires = (datetime.now(UTC) + timedelta(minutes=10)).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )
        handler.queue.append(
            {"id": "cmd-163", "verb": "self-update", "expires_at": expires,
             "args": {"tag": tag, "source": source}}
        )  # fmt: skip
        asked = time.monotonic()
        new = tag[1:]
        while new not in handler.versions:
            assert time.monotonic() - asked < 420, (handler.seen, handler.versions)
            time.sleep(1)
        updated = round(time.monotonic() - asked, 1)
    finally:
        _run(["systemctl", "disable", "--now", AGENT_UNIT], expect=(0, 1, 5))
        Path("/etc/systemd/system", AGENT_UNIT).unlink(missing_ok=True)
        _run(["systemctl", "daemon-reload"])
        server.shutdown()
        server.server_close()
    warnings.warn(
        f"DM-163 measure: the release made in {made} s, the agent on it "
        f"{updated} s after the command; versions heard {handler.versions}",
        stacklevel=1,
    )
    [(verified, command, _)] = [
        kept for kept in handler.verdicts.values() if kept[1] == "cmd-163"
    ]
    assert verified
    assert _stdout([PRIDEM, "version"]) == [f"pridem {new}"]
    assert Path("/opt/pridem/current").resolve() == Path("/opt/pridem/versions", tag)
    assert handler.versions[0] == before and handler.versions[-1] == new
