"""Tier 3 probe (DM-14): the ``.env`` of ``primer-blank`` on a clean runner.

Nothing comes from outside the run but ``primer-blank`` itself, cloned over
https at a pinned commit (a public repository; no secret of CI). The passport
is a file written here; the plan -- ``fetch_passport`` from that file,
``seams_check``, ``render_env`` of the blank -- runs twice in the machine's
venv against the installed package. Then ``docker compose config`` reads the
blank's compose file with the rendered ``--env-file``: every value it
interpolates is the ``.env`` value byte for byte, the minted password inside
``DATABASE_URL`` too. A second ``config`` over a hand-made env file measures
what a single-quoted value is to compose: taken as it is, ``$``, ``#``,
spaces and double quotes included.

The file runs after ``test_tier3_host.py`` (pytest takes the files of a
directory by name): ``docker compose`` is on the runner only after the host
steps.
"""

import json
import os
from pathlib import Path

import yaml

from pridem.report.schema import Verdict
from pridem.runner import CommandTimedOut, Stream, SubprocessRunner

PYTHON = "/opt/pridem/current/venv/bin/python"
BLANK = "https://github.com/inzoddwetrust/primer-blank.git"
BLANK_COMMIT = "0e82be562d186afc933b8779d91dddcae4278cea"
ENV = Path("/opt/blank/env/.env")
MINTED = Path("/opt/blank/env/minted.yaml")
API = "api.tier3-env.test"
SCRIPT = """
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
from pridem.state import Box
from pridem.steps.env import RenderEnv, SeamsCheck
from pridem.steps.passport import passport_steps

root, checkout, passport = Path("/"), Path(sys.argv[1]), Path(sys.argv[2])
blank = load_primer_yaml(checkout / "primer.yaml")
box, secrets = Box(Path("/opt/pridem")), Secrets(())
fetched, first = passport_steps(root, secrets=secrets, server=None, file=passport)
steps = [
    SeamsCheck(blank, {}, fetched),
    RenderEnv(blank, product=blank, fetched=fetched, secrets=secrets,
              memory=SeamMemory(), root=root),
]
with box.lock("tier3-render-env"):
    started = datetime.now(UTC).replace(microsecond=0)
    outcome = Plan(
        [StackSteps("passport", first), StackSteps("blank", steps, root=True)],
        mode="install", role="test", runner=SubprocessRunner(),
        sink=ConsoleSink(sys.stdout, secrets),
    ).run()
    version = fetched.passport.version if fetched.passport is not None else None
    verdict = build_verdict(
        outcome, run_id=f"{started:%Y-%m-%dT%H:%M:%SZ}-{token_hex(2)}",
        verb="install", args={}, actor={"type": "machine", "via": "local"},
        started=started, finished=datetime.now(UTC).replace(microsecond=0),
        passport_version=version, composition_before={"pridem": __version__},
        composition_after={"pridem": __version__}, secrets=secrets,
        catalog=with_steps(
            ENGLISH, [(step.name, step.codes) for step in [*first, *steps]]
        ),
    )
    box.write_verdict(verdict)
print("VERDICT " + verdict.model_dump_json())
sys.exit(int(verdict.exit_code))  # the exit code is the verdict's, as a verb's
"""
GIT_ENV = {
    "PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
    "HOME": "/nonexistent",
    "GIT_CONFIG_GLOBAL": os.devnull,
    "GIT_CONFIG_NOSYSTEM": "1",
}


def _lines(argv: list[str], env: dict[str, str] | None = None) -> list[str]:
    out: list[str] = []

    def keep(stream: Stream, line: str, cut: bool) -> None:
        if stream is Stream.STDOUT:
            out.append(line)

    SubprocessRunner().run(argv, env=env, timeout=300, on_line=keep)
    return out


def _blank(tmp: Path) -> Path:
    checkout = tmp / "blank"
    _lines(["git", "clone", "-q", BLANK, str(checkout)], GIT_ENV)
    _lines(["git", "-C", str(checkout), "checkout", "-q", BLANK_COMMIT], GIT_ENV)
    return checkout


def _passport(tmp: Path) -> Path:
    data = {
        "schema": 1,
        "version": 1,
        "server": {"name": "tier3-env", "role": "test", "os": "ubuntu-24.04"},
        "edition": "core",
        "product": {"repo": BLANK, "ref": "main"},
        "domains": {"frontend": "tier3-env.test", "api": API},
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


def _plan(checkout: Path, passport: Path) -> tuple[Verdict, list[str]]:
    lines: list[str] = []

    def keep(stream: Stream, line: str, cut: bool) -> None:
        lines.append(line)

    try:
        SubprocessRunner().run(
            [PYTHON, "-c", SCRIPT, str(checkout), str(passport)],
            expect=(0, 1, 2),
            timeout=300,
            on_line=keep,
        )
    except CommandTimedOut:
        raise AssertionError("\n".join(lines)) from None
    verdicts = [line for line in lines if line.startswith("VERDICT ")]
    assert len(verdicts) == 1, "\n".join(lines)
    return Verdict.model_validate_json(verdicts[0].removeprefix("VERDICT ")), lines


def _env() -> dict[str, str]:
    out: dict[str, str] = {}
    for line in ENV.read_text(encoding="utf-8").splitlines():
        key, _, quoted = line.partition("=")
        assert quoted.startswith("'") and quoted.endswith("'"), line.partition("=")[0]
        out[key] = quoted[1:-1]
    return out


def _config(checkout: Path, env_file: Path) -> dict[str, dict[str, str]]:
    """``environment`` of every service as compose interpolates it."""
    text = "\n".join(
        _lines(
            [
                "docker",
                "compose",
                "-p",
                "blank",
                "--env-file",
                str(env_file),
                "-f",
                str(checkout / "docker-compose.yml"),
                "config",
                "--format",
                "json",
            ]
        )
    )
    services = json.loads(text)["services"]
    return {name: service.get("environment", {}) for name, service in services.items()}


def test_tier3_blank_env_is_rendered_read_back_and_kept(tmp_path: Path) -> None:
    checkout, passport = _blank(tmp_path), _passport(tmp_path)

    verdict, lines = _plan(checkout, passport)

    printed = "\n".join(lines)
    assert verdict.result == "green", printed
    assert oct(ENV.stat().st_mode & 0o777) == oct(0o600), printed
    assert oct(ENV.parent.stat().st_mode & 0o777) == oct(0o700), printed
    assert oct(MINTED.stat().st_mode & 0o777) == oct(0o600), printed
    env = _env()
    assert sorted(env) == ["API_BASE_URL", "EDITION", "POSTGRES_PASSWORD"], printed
    password = env["POSTGRES_PASSWORD"]
    assert len(password) >= 32, printed
    assert set(password) <= set(
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-"
    ), printed
    assert (env["EDITION"], env["API_BASE_URL"]) == ("core", API), printed
    assert password not in printed, printed  # neither console nor verdict

    again, lines = _plan(checkout, passport)  # the second install keeps it

    assert again.result == "green", "\n".join(lines)
    assert _env()["POSTGRES_PASSWORD"] == password
    assert password not in "\n".join(lines)

    config = _config(checkout, ENV)
    assert config["app"]["DATABASE_URL"] == (
        f"postgresql+asyncpg://blank:{password}@postgres:5432/blank"
    )
    assert config["app"]["EDITION"] == "core"
    assert config["frontend"]["API_BASE_URL"] == API
    assert config["postgres"]["POSTGRES_PASSWORD"] == password


def test_tier3_compose_takes_a_single_quoted_value_as_it_is(tmp_path: Path) -> None:
    checkout = _blank(tmp_path)
    literal = 'a$b ${HOME} #d "e" \\f'  # no "$$": config may print "$" as "$$"
    env_file = tmp_path / "measure.env"
    env_file.write_text(
        f"POSTGRES_PASSWORD='{literal}'\nEDITION='core'\nAPI_BASE_URL='{API}'\n",
        encoding="utf-8",
    )
    config = _config(checkout, env_file)
    # ``config`` writes a literal "$" back as "$$" to keep its output a valid
    # compose file; an interpolated ``${HOME}`` would not come back at all
    assert config["postgres"]["POSTGRES_PASSWORD"].replace("$$", "$") == literal
