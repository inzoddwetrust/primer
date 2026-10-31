"""``render_env`` (DM-14): every source of a stack's env, the ``.env`` read
back, no secret in an argv, every secret in the run's set before a line.

``derive`` runs on a strict ``FakeRunner``: the scripted ``docker run`` is the
contract with the container; a wrapper reads the env file the moment the
command is called, so "the value reached the command" is a fact of the file,
not of the script.
"""

import os
import re
from collections.abc import Mapping, Sequence
from pathlib import Path
from urllib.parse import urlsplit

import pytest
import yaml
from env_support import (
    COMMS_REPO,
    IMAGE,
    STDERR,
    STDOUT,
    box,
    context,
    env_of,
    minted_of,
    passport_data,
    printed,
    product,
    read_env,
    render,
    run,
    service,
)

from pridem.events import Json, Secrets
from pridem.report.catalog import ENGLISH, with_steps
from pridem.report.codes import ExitCode
from pridem.report.schema import build_verdict
from pridem.runner import FakeCall, FakeRunner, OnLine, Result
from pridem.stacks.env import env_text, parse_env, write_private
from pridem.stacks.seams import SeamMemory
from pridem.state import JournalSink
from pridem.steps.base import CheckResult, StepFailed
from pridem.steps.passport import PASSPORT_COPY

ASKED = "invented-telegram-token-0001"
DERIVED = "https://t.me/invented_bot_000000005"
URL_SAFE = re.compile(r"[A-Za-z0-9_-]{32,}")
DERIVE_ARGV = (
    "docker",
    "run",
    "--rm",
    "--label",
    "pridem.stack=comms",
    "--env-file",
)


def comms_env(*, derived: bool = False) -> dict[str, object]:
    env: dict[str, object] = {
        "SECRET_KEY": {"source": "minted"},
        "TELEGRAM_BOT_TOKEN": {"source": "asked"},
        "SUPPORT_LANGUAGE": {"source": "param"},
    }
    if derived:
        env["TELEGRAM_BOT_URL"] = {"source": "derived", "run": "comms derive bot-url"}
    return env


def comms_passport(**change: object) -> dict[str, object]:
    return passport_data(
        asked=change.get("asked", {"comms": {"TELEGRAM_BOT_TOKEN": ASKED}}),  # type: ignore[arg-type]
        params=change.get("params", {"comms": {"SUPPORT_LANGUAGE": "ru"}}),  # type: ignore[arg-type]
    )


def derive_call(
    env_file: Path, code: int = 0, lines: Sequence[tuple[object, str]] = ()
) -> FakeCall:
    return FakeCall(
        (*DERIVE_ARGV, str(env_file), IMAGE, "comms", "derive", "bot-url"),
        code=code,
        lines=tuple(lines),  # type: ignore[arg-type]
    )


class Reading(FakeRunner):
    """Reads ``--env-file`` at the moment ``docker run`` is called."""

    def __init__(self, *calls: FakeCall) -> None:
        super().__init__(*calls)
        self.files: list[str] = []
        self.argvs: list[tuple[str, ...]] = []

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
        if "--env-file" in argv:
            file = Path(argv[list(argv).index("--env-file") + 1])
            self.files.append(file.read_text(encoding="utf-8"))
            self.files.append(oct(file.stat().st_mode & 0o777))
        return super().run(
            argv, expect=expect, timeout=timeout, cwd=cwd, env=env, on_line=on_line
        )


def comms_box(tmp: Path, **change: object):  # type: ignore[no-untyped-def]
    made = product(tmp, {}, dependencies={"comms": COMMS_REPO})
    comms = service(tmp, comms_env(derived=bool(change.pop("derived", False))))
    root, fetched = box(tmp, comms_passport(**change))
    return made, comms, root, fetched


# --- probes ---------------------------------------------------------------------


def test_probe_DM_14_rerun_keeps_minted(tmp_path: Path) -> None:
    made, comms, root, fetched = comms_box(tmp_path)
    assert run([render(comms, root, fetched, product=made)], FakeRunner())[0].code is (
        ExitCode.OK
    )
    first = minted_of(root, "comms").read_bytes()
    secret = read_env(root, "comms")["SECRET_KEY"]

    outcome, _ = run([render(comms, root, fetched, product=made)], FakeRunner())

    assert outcome.code is ExitCode.OK
    assert minted_of(root, "comms").read_bytes() == first
    assert read_env(root, "comms")["SECRET_KEY"] == secret
    # the pair: a new minted variable is minted alone, the old one stays
    grown = service(tmp_path, {**comms_env(), "OTHER_KEY": {"source": "minted"}})
    assert run([render(grown, root, fetched, product=made)], FakeRunner())[0].code is (
        ExitCode.OK
    )
    minted = yaml.safe_load(minted_of(root, "comms").read_text())
    assert minted["SECRET_KEY"] == secret and URL_SAFE.fullmatch(minted["OTHER_KEY"])


def test_probe_DM_14_minted_is_url_and_env_file_safe(tmp_path: Path) -> None:
    made = product(tmp_path, {})
    env = {f"KEY_{n}": {"source": "minted"} for n in range(64)}
    blank = product(tmp_path, env)
    root, fetched = box(tmp_path, passport_data())
    assert run([render(blank, root, fetched, product=made)], FakeRunner())[0].code is (
        ExitCode.OK
    )
    values = read_env(root, "aivis")
    assert len(values) == 64 and all(URL_SAFE.fullmatch(v) for v in values.values())
    # the pair: a URL built of the password comes back whole
    for password in values.values():
        url = urlsplit(f"postgresql+asyncpg://blank:{password}@postgres:5432/blank")
        assert (url.username, url.password, url.hostname) == (
            "blank",
            password,
            "postgres",
        )
    assert parse_env(env_text(values)) == values


def test_probe_DM_14_missing_asked_is_red_before_act(tmp_path: Path) -> None:
    made, comms, root, fetched = comms_box(tmp_path, asked={})

    outcome, _ = run([render(comms, root, fetched, product=made)], FakeRunner())

    [step] = outcome.steps
    assert step.reason is not None
    assert (step.reason.code, step.reason.params) == (
        "render_env:missing",
        {"fields": ["asked.comms.TELEGRAM_BOT_TOKEN"]},
    )
    assert not (root / "opt" / "comms").exists()  # nothing minted, nothing rendered
    # the refusal is the check's, not the act's: check alone says it
    with pytest.raises(StepFailed) as refused:
        render(comms, root, fetched, product=made).check(context(FakeRunner()))
    assert refused.value.reason.code == "missing"
    # the pair: with someone to ask, the answer is written and rendered
    asked: list[str] = []

    def ask(field: str, schema: Mapping[str, Json]) -> str | None:
        asked.append(field)
        return ASKED

    secrets = Secrets(())
    step_ = render(comms, root, fetched, product=made, ask=ask, secrets=secrets)
    outcome, sink = run([step_], FakeRunner())
    assert outcome.code is ExitCode.OK, outcome.steps
    assert asked == ["asked.comms.TELEGRAM_BOT_TOKEN"]
    assert read_env(root, "comms")["TELEGRAM_BOT_TOKEN"] == ASKED
    copy = yaml.safe_load((root / PASSPORT_COPY).read_text())
    assert copy["asked"]["comms"]["TELEGRAM_BOT_TOKEN"] == ASKED
    assert copy["version"] == 7  # an answer never changes the version
    assert secrets.text(ASKED) == "[redacted]" and ASKED not in printed(sink)


def test_probe_DM_14_derived_runs_in_container_and_fails_on_nonzero(
    tmp_path: Path,
) -> None:
    made, comms, root, fetched = comms_box(tmp_path, derived=True)
    env_file = root / "opt" / "comms" / "env" / "derive.env"

    with Reading(derive_call(env_file, lines=[(STDOUT, DERIVED)])) as runner:
        outcome, _ = run(
            [render(comms, root, fetched, product=made, image=IMAGE)], runner
        )

    assert outcome.code is ExitCode.OK, outcome.steps
    assert read_env(root, "comms")["TELEGRAM_BOT_URL"] == DERIVED
    assert not env_file.exists()  # the env file of derive does not stay
    # non-zero: red with the code, stdout never passed on, stderr passed on
    env_of(root, "comms").unlink()
    call = derive_call(
        env_file, code=3, lines=[(STDOUT, "half-a-value"), (STDERR, "no token")]
    )
    with Reading(call) as runner:
        outcome, sink = run(
            [render(comms, root, fetched, product=made, image=IMAGE)], runner
        )
    [step] = outcome.steps
    assert step.reason is not None
    assert (step.reason.code, step.reason.params) == (
        "render_env:derive-failed",
        {"key": "TELEGRAM_BOT_URL", "exit_code": 3},
    )
    assert "half-a-value" not in printed(sink) and "no token" in printed(sink)
    assert not env_of(root, "comms").exists()


def test_probe_DM_14_verify_reads_env_back(tmp_path: Path) -> None:
    made, comms, root, fetched = comms_box(tmp_path)
    step = render(comms, root, fetched, product=made)
    outcome, _ = run([step], FakeRunner())
    assert outcome.steps[0].verify == {
        "path": str(env_of(root, "comms")),
        "keys": 3,
        "mode": oct(0o600),
        "dir_mode": oct(0o700),
    }
    good = env_of(root, "comms").read_text()

    def verify_with(text: str, mode: int = 0o600) -> tuple[str, Mapping[str, Json]]:
        write_private(env_of(root, "comms"), text)
        env_of(root, "comms").chmod(mode)
        with pytest.raises(StepFailed) as failed:
            step.verify(context(FakeRunner()), CheckResult(False))
        return failed.value.reason.code, failed.value.reason.params

    planted = re.sub(r"SUPPORT_LANGUAGE='[^']*'", "SUPPORT_LANGUAGE='<language>'", good)
    assert verify_with(planted) == ("placeholder", {"keys": ["SUPPORT_LANGUAGE"]})
    assert verify_with(good.replace("ru'", "${LANG}'")) == (
        "placeholder",
        {"keys": ["SUPPORT_LANGUAGE"]},
    )
    lost = "".join(
        line + "\n" for line in good.splitlines() if "SECRET_KEY" not in line
    )
    assert verify_with(lost) == ("env-keys", {"missing": ["SECRET_KEY"], "extra": []})
    assert verify_with(good, 0o644)[0] == "env-mode"
    assert verify_with(good + "EXTRA='x'\n")[0] == "env-keys"
    assert verify_with(good + "EXTRA=x\n")[0] == "env-unreadable"


def test_probe_DM_14_remote_seam_comes_from_passport_not_plan(tmp_path: Path) -> None:
    meet = {
        "repo": "git@github.com:acme/meet.git",
        "version": ">=1,<2",
        "topology": "remote",
    }
    env = {"MEET_URL": {"source": "param"}, "MEET_JWT_SECRET": {"source": "asked"}}
    made = product(tmp_path, env, dependencies={"meet": meet})
    jwt = "invented-meet-jwt-secret-0001"
    root, fetched = box(
        tmp_path,
        passport_data(
            asked={"aivis": {"MEET_JWT_SECRET": jwt}},
            params={"aivis": {"MEET_URL": "https://meet.example.org"}},
        ),
    )
    memory = SeamMemory()  # meet never reports health here

    outcome, _ = run([render(made, root, fetched, memory=memory)], FakeRunner())

    assert outcome.code is ExitCode.OK, outcome.steps
    assert read_env(root, "aivis") == {
        "MEET_URL": "https://meet.example.org",
        "MEET_JWT_SECRET": jwt,
    }
    with pytest.raises(Exception, match="not healthy"):
        memory.values("meet", ["MEET_URL"])  # the plan's memory holds nothing of it
    # the pair: a co-located seam does wait for health
    local = product(
        tmp_path,
        {"COMMS_API_URL": {"source": "seam", "from": "comms"}},
        dependencies={"comms": COMMS_REPO},
    )
    outcome, _ = run([render(local, root, fetched, memory=memory)], FakeRunner())
    assert outcome.steps[0].reason is not None
    assert outcome.steps[0].reason.code == "render_env:seam-before-health"


def test_probe_DM_14_secret_never_in_argv(tmp_path: Path) -> None:
    made, comms, root, fetched = comms_box(tmp_path, derived=True)
    env_file = root / "opt" / "comms" / "env" / "derive.env"
    runner = Reading(derive_call(env_file, lines=[(STDOUT, DERIVED)]))

    with runner:
        outcome, _ = run(
            [render(comms, root, fetched, product=made, image=IMAGE)], runner
        )

    assert outcome.code is ExitCode.OK, outcome.steps
    minted = yaml.safe_load(minted_of(root, "comms").read_text())["SECRET_KEY"]
    argvs = " ".join(" ".join(argv) for argv in runner.argvs)
    assert runner.argvs and not [m for m in (ASKED, minted, DERIVED) if m in argvs]
    # the pair: the values reached the command through its env file (0600)
    [content, mode] = runner.files
    assert f"TELEGRAM_BOT_TOKEN={ASKED}\n" in content
    assert f"SECRET_KEY={minted}\n" in content
    assert mode == oct(0o600)


# --- sources and refusals -------------------------------------------------------


def test_derived_value_is_cleaned_from_journal_and_verdict(tmp_path: Path) -> None:
    made, comms, root, fetched = comms_box(tmp_path, derived=True)
    env_file = root / "opt" / "comms" / "env" / "derive.env"
    secrets = Secrets(())
    journal = tmp_path / "journal.jsonl"
    journal.touch()
    sink = JournalSink(journal, secrets)
    call = derive_call(env_file, lines=[(STDOUT, DERIVED), (STDERR, f"made {DERIVED}")])
    step = render(comms, root, fetched, product=made, image=IMAGE, secrets=secrets)
    with Reading(call) as runner:
        outcome, seen = run([step], runner, sink=sink)
    sink.close()
    assert outcome.code is ExitCode.OK, outcome.steps
    text = journal.read_text()
    assert DERIVED not in text and "made [redacted]" in text  # stderr went, cleaned
    verdict = build_verdict(
        outcome,
        run_id="2026-10-31T00:00:00Z-ab12",
        verb="install",
        args={},
        actor={"type": "machine", "via": "local"},
        started=outcome.steps[0].started,  # type: ignore[arg-type]
        finished=outcome.steps[0].started,  # type: ignore[arg-type]
        passport_version=7,
        composition_before={"pridem": "0.0.0"},
        composition_after={"pridem": "0.0.0"},
        secrets=secrets,
        catalog=with_steps(ENGLISH, [(step.name, step.codes)]),
    )
    assert DERIVED not in verdict.model_dump_json()
    assert read_env(root, "comms")["TELEGRAM_BOT_URL"] == DERIVED  # it is rendered


@pytest.mark.parametrize(
    ("lines", "code"),
    [
        ((), "derive-empty"),
        (((STDOUT, "a"), (STDOUT, "b")), "derive-empty"),
        (((STDOUT, "short"),), "derive-short"),
    ],
)
def test_derive_must_print_one_value(
    tmp_path: Path, lines: Sequence[tuple[object, str]], code: str
) -> None:
    made, comms, root, fetched = comms_box(tmp_path, derived=True)
    env_file = root / "opt" / "comms" / "env" / "derive.env"
    with Reading(derive_call(env_file, lines=lines)) as runner:
        outcome, _ = run(
            [render(comms, root, fetched, product=made, image=IMAGE)], runner
        )
    assert outcome.steps[0].reason is not None
    assert outcome.steps[0].reason.code == f"render_env:{code}"


def test_derive_without_an_image_is_red(tmp_path: Path) -> None:
    made, comms, root, fetched = comms_box(tmp_path, derived=True)
    outcome, _ = run([render(comms, root, fetched, product=made)], FakeRunner())
    assert outcome.steps[0].reason is not None
    assert outcome.steps[0].reason.code == "render_env:derive-no-image"


def test_passport_sources(tmp_path: Path) -> None:
    env = {
        "EDITION": {"source": "passport", "key": "edition", "enum": "editions"},
        "ROLE": {"source": "passport", "key": "server.role"},
        "API_BASE_URL": {"source": "passport", "key": "domains.api"},
    }
    made = product(tmp_path, env, editions={"full": {"services": []}}, domains=["api"])
    root, fetched = box(tmp_path, passport_data(domains={"api": "api.example.org"}))
    assert run([render(made, root, fetched)], FakeRunner())[0].code is ExitCode.OK
    assert read_env(root, "aivis") == {
        "EDITION": "full",
        "ROLE": "test",
        "API_BASE_URL": "api.example.org",
    }
    other = product(tmp_path, env, editions={"core": {"services": []}}, domains=["api"])
    outcome, _ = run([render(other, root, fetched)], FakeRunner())
    assert outcome.steps[0].reason is not None
    assert outcome.steps[0].reason.code == "render_env:edition-unknown"
    odd = product(tmp_path, {"X": {"source": "passport", "key": "product.repo"}})
    outcome, _ = run([render(odd, root, fetched)], FakeRunner())
    assert outcome.steps[0].reason is not None
    assert outcome.steps[0].reason.code == "render_env:passport-key"


def test_missing_domain_and_param_are_asked_and_checked(tmp_path: Path) -> None:
    env = {
        "API_BASE_URL": {"source": "passport", "key": "domains.api"},
        "SUPPORT_LANGUAGE": {"source": "param"},
    }
    made = product(tmp_path, env, domains=["api", "frontend"])
    root, fetched = box(tmp_path, passport_data(domains={"frontend": "a.example.org"}))
    answers = {"domains.api": "api.example.org", "params.aivis.SUPPORT_LANGUAGE": "ru"}
    asked: list[str] = []

    def ask(field: str, schema: Mapping[str, Json]) -> str | None:
        asked.append(field)
        return answers[field]

    outcome, _ = run([render(made, root, fetched, ask=ask)], FakeRunner())
    assert outcome.code is ExitCode.OK, outcome.steps
    assert asked == ["domains.api", "params.aivis.SUPPORT_LANGUAGE"]
    assert (
        fetched.passport is not None
        and fetched.passport.domains["api"] == "api.example.org"
    )
    # an answer the passport's model refuses: red, the copy as it was
    root2, fetched2 = box(
        tmp_path / "2", passport_data(domains={"frontend": "a.example.org"})
    )
    before = (root2 / PASSPORT_COPY).read_bytes()
    answers["domains.api"] = "API.Example.org"
    outcome, _ = run([render(made, root2, fetched2, ask=ask)], FakeRunner())
    assert outcome.steps[0].reason is not None
    assert outcome.steps[0].reason.code == "render_env:invalid"
    assert (root2 / PASSPORT_COPY).read_bytes() == before


def test_a_short_asked_answer_is_refused_and_never_known(tmp_path: Path) -> None:
    made, comms, root, fetched = comms_box(tmp_path, asked={})
    secrets = Secrets(())
    step = render(
        comms, root, fetched, product=made, ask=lambda f, s: "short", secrets=secrets
    )
    outcome, _ = run([step], FakeRunner())
    assert outcome.steps[0].reason is not None
    assert outcome.steps[0].reason.code == "render_env:invalid"
    assert secrets.text("short") == "short"  # a refused answer is no secret of the run
    empty = render(comms, root, fetched, product=made, ask=lambda f, s: "")
    outcome, _ = run([empty], FakeRunner())
    assert outcome.steps[0].reason is not None
    assert outcome.steps[0].reason.code == "render_env:no-answer"


def test_a_value_with_a_quote_is_refused_by_its_key(tmp_path: Path) -> None:
    made, comms, root, fetched = comms_box(
        tmp_path, params={"comms": {"SUPPORT_LANGUAGE": "r'u"}}
    )
    outcome, _ = run([render(comms, root, fetched, product=made)], FakeRunner())
    assert outcome.steps[0].reason is not None
    assert (outcome.steps[0].reason.code, outcome.steps[0].reason.params) == (
        "render_env:env-unsafe",
        {"key": "SUPPORT_LANGUAGE"},
    )
    assert not env_of(root, "comms").exists()


@pytest.mark.parametrize("name", ["minted", "env"])
def test_a_file_that_is_not_0600_is_refused_not_remoded(
    tmp_path: Path, name: str
) -> None:
    made, comms, root, fetched = comms_box(tmp_path)
    assert run([render(comms, root, fetched, product=made)], FakeRunner())[0].code is (
        ExitCode.OK
    )
    file = minted_of(root, "comms") if name == "minted" else env_of(root, "comms")
    file.chmod(0o644)
    outcome, _ = run([render(comms, root, fetched, product=made)], FakeRunner())
    assert outcome.steps[0].reason is not None
    assert outcome.steps[0].reason.code == f"render_env:{name}-mode"
    assert oct(file.stat().st_mode & 0o777) == oct(0o644)


def test_the_same_env_again_needs_no_act_and_doctor_sees_drift(tmp_path: Path) -> None:
    made, comms, root, fetched = comms_box(tmp_path)
    run([render(comms, root, fetched, product=made)], FakeRunner())
    outcome, _ = run(
        [render(comms, root, fetched, product=made)], FakeRunner(), mode="doctor"
    )
    assert outcome.doctor_diff == ()
    write_private(env_of(root, "comms"), env_of(root, "comms").read_text() + "\n")
    outcome, _ = run(
        [render(comms, root, fetched, product=made)], FakeRunner(), mode="doctor"
    )
    assert [item.reason.code for item in outcome.doctor_diff] == ["render_env:render"]


def test_write_private_is_0600_whatever_the_umask(tmp_path: Path) -> None:
    old = os.umask(0o000)
    try:
        write_private(tmp_path / "env" / ".env", "A='b'\n")
    finally:
        os.umask(old)
    assert oct((tmp_path / "env" / ".env").stat().st_mode & 0o777) == oct(0o600)
    assert oct((tmp_path / "env").stat().st_mode & 0o777) == oct(0o700)
