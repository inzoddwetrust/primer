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
from dataclasses import replace
from datetime import UTC, datetime
from itertools import count
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
    derive,
    env_of,
    load,
    minted_of,
    passport_data,
    printed,
    product,
    read_env,
    render,
    run,
    running_calls,
    service,
    service_data,
)
from plan_support import ListSink

from pridem.events import Json, Secrets
from pridem.plan import Plan, StackSteps
from pridem.report.catalog import ENGLISH, with_steps
from pridem.report.codes import ExitCode
from pridem.report.schema import build_verdict
from pridem.runner import FakeCall, FakeRunner, OnLine, Result
from pridem.stacks.env import DERIVED_PLACEHOLDER, env_text, parse_env, write_private
from pridem.stacks.schema import Product, Service
from pridem.state import JournalSink
from pridem.steps.base import CheckResult, StepFailed
from pridem.steps.env import DeriveEnv, RenderEnv
from pridem.steps.finalize import FinalCheck
from pridem.steps.passport import PASSPORT_COPY, Fetched

ASKED = "invented-telegram-token-0001"
DERIVED = "https://t.me/invented_bot_000000005"
DERIVED_NEW = "https://t.me/invented_bot_000000006"
OLD_IMAGE = "sha256:" + "1" * 64
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


def passes(
    comms: Service,
    root: Path,
    fetched: Fetched,
    made: Product,
    *,
    secrets: Secrets | None = None,
) -> tuple[RenderEnv, DeriveEnv]:
    """The two passes of comms' env: ``render_env`` and ``derive_env``."""
    first = render(comms, root, fetched, product=made, secrets=secrets)
    return first, derive(first, root)


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
    """Changed by DM-67: ``derive`` runs in the run's image after ``build``, in
    the step ``derive_env``; its codes are ``derive_env``'s."""
    made, comms, root, fetched = comms_box(tmp_path, derived=True)
    env_file = root / "opt" / "comms" / "env" / "derive.env"

    with Reading(derive_call(env_file, lines=[(STDOUT, DERIVED)])) as runner:
        outcome, _ = run(passes(comms, root, fetched, made), runner)

    assert outcome.code is ExitCode.OK, outcome.steps
    assert read_env(root, "comms")["TELEGRAM_BOT_URL"] == DERIVED
    assert not env_file.exists()  # the env file of derive does not stay
    # non-zero: red with the code, stdout never passed on, stderr passed on
    env_of(root, "comms").unlink()
    call = derive_call(
        env_file, code=3, lines=[(STDOUT, "half-a-value"), (STDERR, "no token")]
    )
    with Reading(call) as runner:
        outcome, sink = run(passes(comms, root, fetched, made), runner)
    [_, step] = outcome.steps
    assert step.reason is not None
    assert (step.reason.code, step.reason.params) == (
        "derive_env:derive-failed",
        {"key": "TELEGRAM_BOT_URL", "exit_code": 3},
    )
    assert "half-a-value" not in printed(sink) and "no token" in printed(sink)
    # the env stays as render_env wrote it: the placeholder, never half a value
    assert read_env(root, "comms")["TELEGRAM_BOT_URL"] == DERIVED_PLACEHOLDER


@pytest.mark.parametrize("ends", ["exit-3", "timeout"])
def test_the_env_file_of_derive_goes_when_the_command_fails(
    tmp_path: Path, ends: str
) -> None:
    """DM-54: ``derive.env`` holds the stack's values only while its command
    runs -- it is there, 0600, when ``docker run`` starts, and gone after a
    non-zero exit or a timeout as after a success."""
    made, comms, root, fetched = comms_box(tmp_path, derived=True)
    env_file = root / "opt" / "comms" / "env" / "derive.env"
    call = derive_call(env_file, code=3)
    if ends == "timeout":
        call = replace(call, code=0, outcome="timeout")
    with Reading(call) as runner:
        outcome, _ = run(passes(comms, root, fetched, made), runner)
    [_, step] = outcome.steps
    assert step.status == "failed" and step.reason is not None
    assert step.reason.code == (
        "derive_env:derive-failed" if ends == "exit-3" else "command-timed-out"
    )
    assert len(runner.files) == 2 and runner.files[1] == oct(0o600)
    assert f"TELEGRAM_BOT_TOKEN={ASKED}\n" in runner.files[0]
    assert not env_file.exists()


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


def test_probe_DM_14_secret_never_in_argv(tmp_path: Path) -> None:
    made, comms, root, fetched = comms_box(tmp_path, derived=True)
    env_file = root / "opt" / "comms" / "env" / "derive.env"
    runner = Reading(derive_call(env_file, lines=[(STDOUT, DERIVED)]))

    with runner:
        outcome, _ = run(passes(comms, root, fetched, made), runner)

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
    steps = passes(comms, root, fetched, made, secrets=secrets)
    with Reading(call) as runner:
        outcome, seen = run(steps, runner, sink=sink)
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
        catalog=with_steps(ENGLISH, [(step.name, step.codes) for step in steps]),
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
        outcome, _ = run(passes(comms, root, fetched, made), runner)
    assert outcome.steps[1].reason is not None
    assert outcome.steps[1].reason.code == f"derive_env:{code}"
    assert read_env(root, "comms")["TELEGRAM_BOT_URL"] == DERIVED_PLACEHOLDER


@pytest.mark.parametrize(
    ("image", "built"), [(None, True), (IMAGE, False)], ids=["no-image", "not-built"]
)
def test_derive_without_an_image_is_red(
    tmp_path: Path, image: str | None, built: bool
) -> None:
    """Twin LACK: ``build`` found no ``app`` image, or the entry does not build
    ``app`` (``image:`` alone) -- red, no container run."""
    made, comms, root, fetched = comms_box(tmp_path, derived=True)
    first = render(comms, root, fetched, product=made)
    steps = [first, derive(first, root, image=image, built=built)]
    outcome, _ = run(steps, FakeRunner())
    assert outcome.steps[0].reason is None
    assert outcome.steps[1].reason is not None
    assert outcome.steps[1].reason.code == "derive_env:derive-no-image"


def test_a_stack_with_derived_and_no_app_is_red_before_act(tmp_path: Path) -> None:
    """Twin LACK: no ``app`` in the own entry -- no image to derive in;
    ``render_env`` refuses in ``check``: nothing of the stack is written."""
    made = product(tmp_path, {}, dependencies={"comms": COMMS_REPO})
    data = service_data(comms_env(derived=True))
    stacks = data["stacks"]
    assert isinstance(stacks, dict)
    del stacks["comms"]["app"]
    comms = load(tmp_path, data)
    root, fetched = box(tmp_path, comms_passport())
    outcome, _ = run([render(comms, root, fetched, product=made)], FakeRunner())
    assert outcome.steps[0].reason is not None
    assert outcome.steps[0].reason.code == "render_env:derive-no-image"
    assert not (root / "opt" / "comms").exists()


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


def test_answers_go_to_a_copy_that_is_0600(tmp_path: Path) -> None:
    """DM-54: the copy rewritten with the answers is 0600 whatever mode it was
    found with -- the mode ``fetch_passport`` requires of it."""
    env = {"API_BASE_URL": {"source": "passport", "key": "domains.api"}}
    made = product(tmp_path, env, domains=["api"])
    root, fetched = box(tmp_path, passport_data(domains={}))
    (root / PASSPORT_COPY).chmod(0o644)

    def ask(field: str, schema: Mapping[str, Json]) -> str | None:
        return "api.example.org"

    outcome, _ = run([render(made, root, fetched, ask=ask)], FakeRunner())
    assert outcome.code is ExitCode.OK, outcome.steps
    copy = root / PASSPORT_COPY
    assert "api.example.org" in copy.read_text()
    assert oct(copy.stat().st_mode & 0o777) == oct(0o600)


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


# --- DM-53: check reads, it never runs derive ----------------------------------


def _green(tmp: Path) -> tuple[Path, Fetched, Product, Service, Path]:
    """A box where ``render_env`` and ``derive_env`` of comms went green."""
    made, comms, root, fetched = comms_box(tmp, derived=True)
    env_file = root / "opt" / "comms" / "env" / "derive.env"
    with Reading(derive_call(env_file, lines=[(STDOUT, DERIVED)])) as runner:
        outcome, _ = run(passes(comms, root, fetched, made), runner)
    assert outcome.code is ExitCode.OK, outcome.steps
    return root, fetched, made, comms, env_file


@pytest.mark.parametrize("held", ["missing", "short", "placeholder"])
def test_a_derived_value_the_file_lacks_or_holds_short_is_derived_again(
    tmp_path: Path, held: str
) -> None:
    """DM-55 FIX, DM-67: a derived value in ``.env`` is taken only when it
    could be one -- a file without the key, with a value shorter than
    ``SECRET_MIN_LENGTH`` or with ``<derived>`` needs ``act`` (``doctor``
    names it and asks docker nothing), and ``derive_env`` derives it again."""
    root, fetched, made, comms, env_file = _green(tmp_path)
    env = env_of(root, "comms")
    values = parse_env(env.read_text())
    if held == "missing":
        del values["TELEGRAM_BOT_URL"]
    else:
        values["TELEGRAM_BOT_URL"] = "short" if held == "short" else "<derived>"
    write_private(env, env_text(values))
    with Reading() as runner:
        outcome, _ = run(passes(comms, root, fetched, made), runner, mode="doctor")
    codes = [item.reason.code for item in outcome.doctor_diff]
    expected = ["derive_env:derive"]
    if held != "placeholder":  # render_env writes the placeholder in its place
        expected.insert(0, "render_env:render")
    assert codes == expected and runner.argvs == []
    with Reading(derive_call(env_file, lines=[(STDOUT, DERIVED)])) as runner:
        outcome, _ = run(passes(comms, root, fetched, made), runner)
    assert outcome.code is ExitCode.OK, outcome.steps
    assert read_env(root, "comms")["TELEGRAM_BOT_URL"] == DERIVED


def test_check_takes_derived_values_from_the_file_and_runs_no_container(
    tmp_path: Path,
) -> None:
    """Twin REPEAT: the same env and ``app`` on this run's image -- ``derive``
    does not run, in a run and in doctor; docker is only asked which image
    ``app`` runs on. The pair: a key gone -- ``act`` derives again."""
    root, fetched, made, comms, env_file = _green(tmp_path)
    secrets = Secrets(())
    steps = passes(comms, root, fetched, made, secrets=secrets)
    with Reading(*running_calls(steps[1], IMAGE)) as runner:
        outcome, _ = run(steps, runner)
    assert outcome.code is ExitCode.OK, outcome.steps
    assert all(step.reason is None for step in outcome.steps)
    assert ("docker", "run") not in [a[:2] for a in runner.argvs]
    assert secrets.text(DERIVED) == "[redacted]"  # read from the file, cleaned
    steps = passes(comms, root, fetched, made)
    with Reading(*running_calls(steps[1], IMAGE)) as runner:
        outcome, _ = run(steps, runner, mode="doctor")
    assert outcome.doctor_diff == ()
    # the pair: another value of the stack changed -- act derives again
    env = env_of(root, "comms")
    lines = env.read_text().splitlines(keepends=True)
    write_private(env, "".join(lines[1:]))  # a key gone: the file is not current
    with Reading(derive_call(env_file, lines=[(STDOUT, DERIVED)])) as runner:
        outcome, _ = run(passes(comms, root, fetched, made), runner)
    assert outcome.code is ExitCode.OK, outcome.steps
    assert [a[:2] for a in runner.argvs] == [("docker", "run")]
    assert read_env(root, "comms")["TELEGRAM_BOT_URL"] == DERIVED


@pytest.mark.parametrize("running", [OLD_IMAGE, None], ids=["old-image", "none"])
def test_app_on_another_image_derives_again(
    tmp_path: Path, running: str | None
) -> None:
    """Р4, the image: the same env, but ``app`` runs on another image than
    ``build`` gives (a new commit) or does not run -- ``derive`` again, on the
    run's image."""
    root, fetched, made, comms, env_file = _green(tmp_path)
    steps = passes(comms, root, fetched, made)
    calls = [
        *running_calls(steps[1], running),
        derive_call(env_file, lines=[(STDOUT, DERIVED_NEW)]),
    ]
    with Reading(*calls) as runner:
        outcome, _ = run(steps, runner)
    assert outcome.code is ExitCode.OK, outcome.steps
    assert read_env(root, "comms")["TELEGRAM_BOT_URL"] == DERIVED_NEW
    assert outcome.steps[1].verify["image"] == IMAGE


def test_another_input_of_derive_derives_again(tmp_path: Path) -> None:
    """Р4, the inputs: the passport gives another token on the same image --
    ``render_env`` rewrites the others and keeps the old derived value until
    ``derive_env`` derives it from the new token."""
    root, _, made, comms, env_file = _green(tmp_path)
    other = "invented-telegram-token-0002"
    _, fetched = box(
        tmp_path, comms_passport(asked={"comms": {"TELEGRAM_BOT_TOKEN": other}})
    )
    steps = passes(comms, root, fetched, made)
    seen: list[str] = []

    class Watching(Reading):
        def run(self, argv, **kwargs):  # type: ignore[no-untyped-def]
            seen.append(read_env(root, "comms")["TELEGRAM_BOT_URL"])
            return super().run(argv, **kwargs)

    with Watching(derive_call(env_file, lines=[(STDOUT, DERIVED_NEW)])) as runner:
        outcome, _ = run(steps, runner)
    assert outcome.code is ExitCode.OK, outcome.steps
    assert seen == [DERIVED]  # before derive: the old value, not the placeholder
    assert f"TELEGRAM_BOT_TOKEN={other}\n" in runner.files[0]
    assert read_env(root, "comms")["TELEGRAM_BOT_URL"] == DERIVED_NEW


# --- DM-67: the two passes ------------------------------------------------------


def test_two_derived_keys_one_red_leaves_the_env_as_render_env_wrote_it(
    tmp_path: Path,
) -> None:
    """Twin REPEAT and LACK: two ``derived`` keys, the second ``derive`` red --
    ``.env`` is written once, after every key, so it still holds the
    placeholders; ``derive.env`` is gone; the first key's value is a secret
    of the run all the same."""
    made = product(tmp_path, {}, dependencies={"comms": COMMS_REPO})
    env = comms_env(derived=True)
    env["TELEGRAM_BOT_NAME"] = {"source": "derived", "run": "comms derive bot-name"}
    comms = service(tmp_path, env)
    root, fetched = box(tmp_path, comms_passport())
    env_file = root / "opt" / "comms" / "env" / "derive.env"
    second = replace(
        derive_call(env_file, code=3),
        argv=(*DERIVE_ARGV, str(env_file), IMAGE, "comms", "derive", "bot-name"),
    )
    secrets = Secrets(())
    steps = passes(comms, root, fetched, made, secrets=secrets)
    with Reading(derive_call(env_file, lines=[(STDOUT, DERIVED)]), second) as runner:
        outcome, _ = run(steps, runner)
    assert outcome.steps[1].reason is not None
    assert outcome.steps[1].reason.params == {
        "key": "TELEGRAM_BOT_NAME",
        "exit_code": 3,
    }
    held = read_env(root, "comms")
    assert held["TELEGRAM_BOT_URL"] == held["TELEGRAM_BOT_NAME"] == DERIVED_PLACEHOLDER
    assert not env_file.exists()
    assert DERIVED not in runner.files[2]  # the second derive got no derived value
    assert secrets.text(DERIVED) == "[redacted]"


def test_the_final_check_reads_both_passes_green(tmp_path: Path) -> None:
    """``final_check`` verifies ``render_env`` again after ``derive_env``: the
    real value is there, and the provides are the derived ones."""
    made, comms, root, fetched = comms_box(tmp_path, derived=True)
    env_file = root / "opt" / "comms" / "env" / "derive.env"
    steps = passes(comms, root, fetched, made)
    ticks = count()
    with Reading(derive_call(env_file, lines=[(STDOUT, DERIVED)])) as runner:
        outcome = Plan(
            [StackSteps("comms", steps), StackSteps("end", [FinalCheck()], root=True)],
            mode="install",
            role="test",
            runner=runner,
            sink=ListSink(),
            clock=lambda: float(next(ticks)),
            now=lambda: datetime(2026, 11, 5, tzinfo=UTC),
        ).run()
    assert outcome.code is ExitCode.OK, outcome.steps
    assert outcome.steps[-1].verify == {"verified": 2}
    assert steps[0].rendered["TELEGRAM_BOT_URL"] == DERIVED


def test_derive_env_gives_the_provides_their_derived_value(tmp_path: Path) -> None:
    """D7: ``render_env``'s read back holds ``<derived>``; ``derive_env``'s
    holds the value -- what ``up`` hands the plan's memory after health."""
    made, _, root, fetched = comms_box(tmp_path)
    comms = service(tmp_path, comms_env(derived=True), provides=["TELEGRAM_BOT_URL"])
    env_file = root / "opt" / "comms" / "env" / "derive.env"
    first, second = passes(comms, root, fetched, made)
    with Reading(derive_call(env_file, lines=[(STDOUT, DERIVED)])) as runner:
        outcome, _ = run([first], runner)
        assert first.provided() == {"TELEGRAM_BOT_URL": DERIVED_PLACEHOLDER}
        outcome, _ = run([second], runner)
    assert outcome.code is ExitCode.OK, outcome.steps
    assert first.provided() == {"TELEGRAM_BOT_URL": DERIVED}
