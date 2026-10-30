"""The passport steps (DM-13) on real ``age``, ``sops`` and ``git``.

The ops repository is a bare repository in ``tmp_path`` reached by
``file://``; passports are encrypted by ``sops`` for age keys minted here, so
"not a recipient", a tampered file and a passport for another server are what
sops and the loader say, not what a script says. The box is ``tmp_path/box``.
Every command goes through a runner that records argv and environment and
then runs it. A file passport runs on an empty strict ``FakeRunner``: no
command at all.
"""

import os
from collections.abc import Callable, Mapping, Sequence
from datetime import UTC, datetime
from itertools import count
from pathlib import Path

import pytest
import yaml
from passport_support import passport_example
from plan_support import ListSink
from state_support import state

from pridem.events import Json, PlanOutcome, Secrets
from pridem.plan import Plan, StackSteps
from pridem.report.catalog import ENGLISH, with_steps
from pridem.report.codes import ExitCode
from pridem.report.schema import Verdict, build_verdict
from pridem.runner import FakeRunner, OnLine, Result, Runner, Stream, SubprocessRunner
from pridem.state import Box, BoxState
from pridem.steps.base import Mode, Step
from pridem.steps.git import KEYS
from pridem.steps.passport import (
    AGE_KEY,
    PASSPORT_COPY,
    AgeKey,
    Ask,
    Fetched,
    FetchPassport,
    OpsSource,
    passport_steps,
    with_passport,
)

SERVER = "box-one"
SECRET_VALUES = {
    "comms": {
        "TELEGRAM_BOT_TOKEN": "invented-telegram-token-0001",
        "MAILGUN_API_KEY": "invented-mailgun-key-000002",
    },
    "payments": {"STRIPE_SECRET_KEY": "invented-stripe-key-0000003"},
    "aivis": {"MEET_JWT_SECRET": "invented-meet-secret-000004"},
}
SECRETS = [value for stack in SECRET_VALUES.values() for value in stack.values()]
GIT_ENV = {
    "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
    "HOME": "/nonexistent",
    "LANG": "C.UTF-8",
    "GIT_AUTHOR_NAME": "t",
    "GIT_AUTHOR_EMAIL": "t@example.org",
    "GIT_COMMITTER_NAME": "t",
    "GIT_COMMITTER_EMAIL": "t@example.org",
    "GIT_CONFIG_GLOBAL": os.devnull,
    "GIT_CONFIG_NOSYSTEM": "1",
}

Data = dict[str, object]


class Recording:
    """Runs every command for real and keeps its argv and environment."""

    def __init__(self) -> None:
        self.calls: list[tuple[tuple[str, ...], Mapping[str, str] | None]] = []
        self._runner = SubprocessRunner()

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
        self.calls.append((tuple(argv), env))
        return self._runner.run(
            argv, expect=expect, timeout=timeout, cwd=cwd, env=env, on_line=on_line
        )

    def programs(self) -> list[str]:
        return [argv[0] for argv, _ in self.calls]

    def has(self, *words: str) -> bool:
        return any(all(word in argv for word in words) for argv, _ in self.calls)


def _out(argv: list[str], env: Mapping[str, str] | None = None) -> str:
    out: list[str] = []

    def keep(stream: Stream, line: str, cut: bool) -> None:
        if stream is Stream.STDOUT:
            out.append(line)

    SubprocessRunner().run(argv, env=env, timeout=60, on_line=keep)
    return "\n".join(out)


def git(cwd: Path, *args: str) -> str:
    return _out(["git", "-C", str(cwd), *args], GIT_ENV)


def mint(path: Path) -> str:
    """An age key at ``path`` (0600); its public part."""
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    SubprocessRunner().run(
        ["age-keygen", "-o", str(path)],
        timeout=60,
        on_line=lambda stream, line, cut: None,
    )
    path.chmod(0o600)
    return _out(["age-keygen", "-y", str(path)])


def box_key(root: Path) -> str:
    return mint(root / AGE_KEY)


def passport(version: int = 7, server: str = SERVER) -> Data:
    data = passport_example()
    data["version"] = version
    server_part = data["server"]
    assert isinstance(server_part, dict)
    server_part["name"] = server
    data["asked"] = {stack: dict(values) for stack, values in SECRET_VALUES.items()}
    return data


def encrypt(tmp: Path, data: Data, *publics: str) -> str:
    plain = tmp / "plain.yaml"
    plain.write_text(yaml.safe_dump(data, sort_keys=False))
    try:
        return _out(["sops", "--encrypt", "--age", ",".join(publics), str(plain)])
    finally:
        plain.unlink()


class Ops:
    """A bare ops repository with ``passports/`` on ``main``."""

    def __init__(self, tmp: Path) -> None:
        self.tmp = tmp
        self.work = tmp / "ops-work"
        self.bare = tmp / "ops.git"
        self.work.mkdir()
        git(self.work, "init", "-q", "-b", "main")
        self.address = f"file://{self.bare}"

    def put(self, name: str, text: str) -> str:
        """Commit ``passports/<name>.yaml`` and push it; the new head."""
        file = self.work / "passports" / f"{name}.yaml"
        file.parent.mkdir(exist_ok=True)
        file.write_text(text)
        git(self.work, "add", "-A")
        git(self.work, "commit", "-q", "--allow-empty", "-m", f"{name}")
        if not self.bare.exists():
            git(self.tmp, "clone", "-q", "--bare", str(self.work), str(self.bare))
        else:
            git(self.work, "push", "-q", str(self.bare), "main")
        return git(self.work, "rev-parse", "HEAD")


def run(
    steps: Sequence[Step], runner: Runner, mode: str = "install"
) -> tuple[PlanOutcome, ListSink]:
    ticks = count()
    sink = ListSink()
    outcome = Plan(
        [StackSteps("passport", steps, root=True)],
        mode=mode,  # type: ignore[arg-type]
        role="test",
        runner=runner,
        sink=sink,
        clock=lambda: float(next(ticks)),
        now=lambda: datetime(2026, 10, 27, tzinfo=UTC),
    ).run()
    return outcome, sink


def ops_steps(
    root: Path,
    ops: Ops,
    *,
    server: str = SERVER,
    ask: Ask | None = None,
    wait_s: float = 0,
    sleep: Callable[[float], None] = lambda s: None,
) -> tuple[Fetched, list[Step]]:
    fetched = Fetched()
    fetch = FetchPassport(
        fetched,
        root,
        server=server,
        ops=OpsSource(ops.address),
        ask=ask,
        wait_s=wait_s,
        poll_s=1,
        clock=iter(range(10**6)).__next__,
        sleep=sleep,
    )
    return fetched, [AgeKey(root), fetch]


def file_steps(
    root: Path, file: Path, *, ask: Ask | None = None, server: str | None = SERVER
) -> tuple[Fetched, list[Step]]:
    fetched = Fetched()
    return fetched, [FetchPassport(fetched, root, server=server, file=file, ask=ask)]


def write_file(tmp: Path, data: Data, name: str = "given.yaml") -> Path:
    file = tmp / name
    file.write_text(yaml.safe_dump(data, sort_keys=False))
    return file


def failed(outcome: PlanOutcome) -> tuple[str, Mapping[str, Json]]:
    [record] = [r for r in outcome.steps if r.status == "failed"]
    assert record.reason is not None
    return record.reason.code, record.reason.params


def fact(outcome: PlanOutcome, name: str) -> Mapping[str, Json]:
    [record] = [r for r in outcome.steps if r.name == name]
    assert record.status == "ok", record.reason
    return record.verify


def mode_of(path: Path) -> str:
    return oct(path.stat().st_mode & 0o777)


def printed(sink: ListSink) -> str:
    return "\n".join(event.line for event in sink.lines())


def verdict_of(
    outcome: PlanOutcome, steps: Sequence[Step], fetched: Fetched
) -> Verdict:
    return build_verdict(
        outcome,
        run_id="2026-10-27T00:00:00Z-ab12",
        verb="install",
        args={},
        actor={"type": "machine", "via": "local"},
        started=datetime(2026, 10, 27, tzinfo=UTC),
        finished=datetime(2026, 10, 27, tzinfo=UTC),
        passport_version=None if fetched.passport is None else fetched.passport.version,
        composition_before={"pridem": "0.0.0"},
        composition_after={"pridem": "0.0.0"},
        secrets=Secrets(()),
        catalog=with_steps(ENGLISH, [(step.name, step.codes) for step in steps]),
    )


def never_ask(field: str, schema: Mapping[str, Json]) -> str | None:
    raise AssertionError(f"asked {field} of a complete passport")


# --- probes ---------------------------------------------------------------------


def test_probe_DM_13_passport_not_for_this_key_is_red_with_reason(
    tmp_path: Path,
) -> None:
    root = tmp_path / "box"
    public = box_key(root)
    other = mint(tmp_path / "owner.key")
    ops = Ops(tmp_path)
    ops.put(SERVER, encrypt(tmp_path, passport(), other))

    _, steps = ops_steps(root, ops)
    outcome, sink = run(steps, Recording())

    code, params = failed(outcome)
    assert code == "fetch_passport:not-recipient"
    assert params == {"server": SERVER, "public_key": public, "wait_s": 0}
    assert public in printed(sink)  # the owner is shown what to add
    assert not (root / PASSPORT_COPY).exists()
    # the pair: encrypted for the box as well, the same step is green
    ops.put(SERVER, encrypt(tmp_path, passport(), other, public))
    _, steps = ops_steps(root, ops)
    outcome, _ = run(steps, Recording())
    assert outcome.code is ExitCode.OK, outcome.steps


def test_probe_DM_13_verdict_version_is_the_passport_field_ops_commit_in_state(
    tmp_path: Path,
) -> None:
    root = tmp_path / "box"
    public = box_key(root)
    ops = Ops(tmp_path)
    ops.put("someone-else", "x: 1\n")  # history longer than one commit
    head = ops.put(SERVER, encrypt(tmp_path, passport(version=9), public))
    assert git(ops.bare, "rev-list", "--count", "main") == "2"
    assert state().passport_version != 9  # the version comes from the passport

    fetched, steps = ops_steps(root, ops)
    outcome, _ = run(steps, Recording())

    assert outcome.code is ExitCode.OK, outcome.steps
    assert fact(outcome, "fetch_passport")["version"] == 9
    assert fact(outcome, "fetch_passport")["ops_commit"] == head
    verdict = verdict_of(outcome, steps, fetched)
    assert verdict.passport_version == 9
    box = Box(tmp_path / "pridem")
    with box.lock("probe"):
        box.write_state(with_passport(state(), fetched))
        written = box.read_state()
    assert written is not None
    assert (written.passport_version, written.ops_commit) == (9, head)


def test_probe_DM_13_file_path_bypasses_ops_repo(tmp_path: Path) -> None:
    root = tmp_path / "box"
    given = write_file(tmp_path, passport(version=4))

    fetched, steps = file_steps(root, given)
    with FakeRunner() as runner:  # no command may run
        outcome, _ = run(steps, runner)

    assert outcome.code is ExitCode.OK, outcome.steps
    assert fact(outcome, "fetch_passport")["source"] == "file"
    assert "ops_commit" not in fact(outcome, "fetch_passport")
    assert mode_of(root / PASSPORT_COPY) == oct(0o600)
    assert fetched.passport is not None and fetched.ops_commit is None
    recorded = with_passport(state(), fetched)
    assert "ops_commit" not in recorded.model_dump_json()
    # the pair: from the ops repository the same passport takes git and sops
    public = box_key(root)
    ops = Ops(tmp_path)
    ops.put(SERVER, encrypt(tmp_path, passport(version=4), public))
    recording = Recording()
    _, steps = ops_steps(root, ops)
    outcome, _ = run(steps, recording)
    assert outcome.code is ExitCode.OK, outcome.steps
    assert {"git", "sops"} <= set(recording.programs())


def test_probe_DM_13_install_asks_only_missing_fields(tmp_path: Path) -> None:
    root = tmp_path / "box"
    data = passport(version=5)
    product = data["product"]
    policies = data["policies"]
    assert isinstance(product, dict) and isinstance(policies, dict)
    del product["repo"]
    del policies["backup"]
    given = write_file(tmp_path, data)
    asked: list[str] = []
    answers = {
        "product.repo": "git@github.com:acme/app.git",
        "policies.backup.enabled": "false",
    }

    def ask(field: str, schema: Mapping[str, Json]) -> str | None:
        asked.append(field)
        return answers[field]

    _, steps = file_steps(root, given, ask=ask)
    outcome, _ = run(steps, FakeRunner())

    assert outcome.code is ExitCode.OK, outcome.steps
    assert asked == ["product.repo", "policies.backup.enabled"]
    copy = yaml.safe_load((root / PASSPORT_COPY).read_text())
    assert copy["product"]["repo"] == "git@github.com:acme/app.git"
    assert copy["policies"]["backup"] == {"enabled": False}
    assert copy["version"] == 5  # answers never change the version
    # the same version again: the answers come from the copy, nothing is asked
    _, steps = file_steps(root, given, ask=never_ask)
    outcome, _ = run(steps, FakeRunner())
    assert outcome.code is ExitCode.OK, outcome.steps
    # the pair: a complete passport -- not one question
    _, steps = file_steps(
        tmp_path / "box2", write_file(tmp_path, passport(), "full.yaml"), ask=never_ask
    )
    outcome, _ = run(steps, FakeRunner())
    assert outcome.code is ExitCode.OK, outcome.steps


def test_probe_DM_13_private_key_mode_0600_or_refuse(tmp_path: Path) -> None:
    root = tmp_path / "box"
    box_key(root)
    key = root / AGE_KEY
    key.chmod(0o644)
    before = key.read_bytes()
    ops = Ops(tmp_path)
    ops.put(SERVER, "x: 1\n")

    _, steps = ops_steps(root, ops)
    recording = Recording()
    outcome, _ = run(steps, recording)

    code, params = failed(outcome)
    assert code == "age_key:key-mode"
    assert params == {"path": str(key), "mode": oct(0o644)}
    assert mode_of(key) == oct(0o644) and key.read_bytes() == before
    assert recording.calls == []  # refused before any command
    # the pair: 0600 is used as it is, no new key
    key.chmod(0o600)
    recording = Recording()
    outcome, _ = run([AgeKey(root)], recording)
    assert fact(outcome, "age_key")["key_mode"] == oct(0o600)
    assert key.read_bytes() == before
    assert not recording.has("-o")


# --- the age key ----------------------------------------------------------------


def test_age_key_is_minted_once_and_its_public_part_printed(tmp_path: Path) -> None:
    root = tmp_path / "box"
    recording = Recording()
    outcome, sink = run([AgeKey(root)], recording)
    key = root / AGE_KEY
    public = fact(outcome, "age_key")["public_key"]
    assert isinstance(public, str) and public.startswith("age1")
    assert public in printed(sink)
    assert mode_of(key) == oct(0o600) and mode_of(key.parent) == oct(0o700)
    assert recording.has("age-keygen", "-o")
    first = key.read_bytes()
    recording = Recording()
    outcome, sink = run([AgeKey(root)], recording)
    assert fact(outcome, "age_key")["public_key"] == public
    assert key.read_bytes() == first and not recording.has("-o")
    assert "age key of this box:" not in printed(sink)  # nothing to add again


def test_age_key_that_is_not_a_key_is_red(tmp_path: Path) -> None:
    root = tmp_path / "box"
    key = root / AGE_KEY
    key.parent.mkdir(parents=True)
    key.write_text("")
    key.chmod(0o600)
    outcome, _ = run([AgeKey(root)], Recording())
    assert failed(outcome) == ("age_key:key-unreadable", {"path": str(key)})
    assert key.read_text() == ""


# --- fetching -------------------------------------------------------------------


def test_waits_until_the_owner_adds_the_box(tmp_path: Path) -> None:
    root = tmp_path / "box"
    public = box_key(root)
    owner = mint(tmp_path / "owner.key")
    ops = Ops(tmp_path)
    ops.put(SERVER, encrypt(tmp_path, passport(), owner))
    polls: list[float] = []

    def owner_adds_the_box(seconds: float) -> None:
        polls.append(seconds)
        ops.put(SERVER, encrypt(tmp_path, passport(), owner, public))

    fetched, steps = ops_steps(root, ops, wait_s=100, sleep=owner_adds_the_box)
    outcome, sink = run(steps, Recording())
    assert outcome.code is ExitCode.OK, outcome.steps
    assert polls == [1]
    assert public in printed(sink)
    assert fetched.ops_commit == git(ops.bare, "rev-parse", "main")


def test_no_value_of_the_passport_leaves_the_step(tmp_path: Path) -> None:
    root = tmp_path / "box"
    public = box_key(root)
    ops = Ops(tmp_path)
    ops.put(SERVER, encrypt(tmp_path, passport(), public))
    recording = Recording()
    fetched, steps = ops_steps(root, ops)
    outcome, sink = run(steps, recording)
    seen = printed(sink) + verdict_of(outcome, steps, fetched).model_dump_json()
    seen += repr(recording.calls)
    assert not [secret for secret in SECRETS if secret in seen]
    assert outcome.code is ExitCode.OK, outcome.steps
    # the pair: the copy holds them all
    copy = (root / PASSPORT_COPY).read_text()
    assert all(secret in copy for secret in SECRETS)


def test_sops_runs_with_the_machines_whole_environment(tmp_path: Path) -> None:
    root = tmp_path / "box"
    public = box_key(root)
    ops = Ops(tmp_path)
    ops.put(SERVER, encrypt(tmp_path, passport(), public))
    recording = Recording()
    _, steps = ops_steps(root, ops)
    run(steps, recording)
    [env] = [env for argv, env in recording.calls if argv[0] == "sops"]
    assert env is not None
    assert env["HOME"] == str(root / KEYS)  # never root's ~/.ssh
    assert env["SOPS_AGE_KEY_FILE"] == str(root / AGE_KEY)
    assert set(env) == {"PATH", "LANG", "LC_ALL", "HOME", "SOPS_AGE_KEY_FILE"}
    sops = [argv for argv, _ in recording.calls if argv[0] == "sops"][0]
    assert "--output" in sops and str(root / AGE_KEY) not in sops


@pytest.mark.parametrize(
    ("change", "code"),
    [
        ("server", "name-mismatch"),
        ("rule", "invalid"),
        ("absent", "not-in-ops"),
        ("tampered", "damaged"),
        ("plain", "damaged"),
    ],
)
def test_a_bad_passport_leaves_the_copy_as_it_was(
    tmp_path: Path, change: str, code: str
) -> None:
    root = tmp_path / "box"
    public = box_key(root)
    ops = Ops(tmp_path)
    ops.put(SERVER, encrypt(tmp_path, passport(version=7), public))
    _, steps = ops_steps(root, ops)
    assert run(steps, Recording())[0].code is ExitCode.OK
    copy = (root / PASSPORT_COPY).read_bytes()
    bad = passport(version=8)
    if change == "server":
        bad = passport(version=8, server="box-two")
    if change == "rule":
        product = bad["product"]
        assert isinstance(product, dict)
        product["ref"] = "v1.0.0"  # a tag on test: rule 4
    text = encrypt(tmp_path, bad, public)
    if change == "tampered":
        text = text.replace("data:", "data:A", 1)
    if change == "plain":
        text = yaml.safe_dump(bad)
    if change == "absent":
        (ops.work / "passports" / f"{SERVER}.yaml").unlink()
        git(ops.work, "add", "-A")
        ops.put("other-box", "x: 1\n")
    else:
        ops.put(SERVER, text)

    _, steps = ops_steps(root, ops)
    outcome, _ = run(steps, Recording())

    assert failed(outcome)[0] == f"fetch_passport:{code}"
    assert (root / PASSPORT_COPY).read_bytes() == copy
    assert mode_of(root / PASSPORT_COPY) == oct(0o600)
    assert not list((root / PASSPORT_COPY).parent.glob("passport.yaml.*"))


def test_a_new_version_replaces_the_copy_and_names_the_previous(tmp_path: Path) -> None:
    root = tmp_path / "box"
    public = box_key(root)
    ops = Ops(tmp_path)
    ops.put(SERVER, encrypt(tmp_path, passport(version=7), public))
    _, steps = ops_steps(root, ops)
    first = run(steps, Recording())[0]
    assert "previous" not in fact(first, "fetch_passport")
    ops.put(SERVER, encrypt(tmp_path, passport(version=8), public))
    fetched, steps = ops_steps(root, ops)
    outcome, _ = run(steps, Recording())
    assert fact(outcome, "fetch_passport")["previous"] == 7
    assert fact(outcome, "fetch_passport")["version"] == 8
    assert fetched.passport is not None and fetched.passport.version == 8


def test_the_same_passport_again_needs_no_act(tmp_path: Path) -> None:
    root = tmp_path / "box"
    public = box_key(root)
    ops = Ops(tmp_path)
    ops.put(SERVER, encrypt(tmp_path, passport(), public))
    _, steps = ops_steps(root, ops)
    run(steps, Recording())
    recording = Recording()
    _, steps = ops_steps(root, ops)
    outcome, _ = run(steps, recording)
    assert outcome.code is ExitCode.OK, outcome.steps
    assert not recording.has("fetch")
    assert recording.has("ls-remote") and recording.has("sops", "--decrypt")


def test_doctor_moves_no_head_of_the_ops_repository(tmp_path: Path) -> None:
    root = tmp_path / "box"
    public = box_key(root)
    ops = Ops(tmp_path)
    first = ops.put(SERVER, encrypt(tmp_path, passport(version=7), public))
    _, steps = ops_steps(root, ops)
    run(steps, Recording())
    bare = root / "opt" / "pridem" / "ops" / "git"
    second = ops.put(SERVER, encrypt(tmp_path, passport(version=8), public))

    _, steps = ops_steps(root, ops)
    outcome, _ = run(steps, Recording(), mode="doctor")

    assert [item.reason.code for item in outcome.doctor_diff] == [
        "fetch_passport:fetch"
    ]
    assert git(bare, "rev-parse", "main") == first
    # the pair: install moves it
    _, steps = ops_steps(root, ops)
    run(steps, Recording())
    assert git(bare, "rev-parse", "main") == second


def test_missing_open_mapping_is_red_without_a_question(tmp_path: Path) -> None:
    data = passport()
    del data["domains"]
    _, steps = file_steps(tmp_path / "box", write_file(tmp_path, data), ask=never_ask)
    outcome, _ = run(steps, FakeRunner())
    assert failed(outcome) == ("fetch_passport:missing", {"fields": ["domains"]})


def test_missing_fields_without_ask_are_red_with_the_list(tmp_path: Path) -> None:
    data = passport()
    server_part = data["server"]
    assert isinstance(server_part, dict)
    del server_part["role"]
    _, steps = file_steps(tmp_path / "box", write_file(tmp_path, data))
    outcome, _ = run(steps, FakeRunner())
    assert failed(outcome) == ("fetch_passport:missing", {"fields": ["server.role"]})
    assert not (tmp_path / "box" / PASSPORT_COPY).exists()


def test_an_empty_answer_is_red(tmp_path: Path) -> None:
    data = passport()
    product = data["product"]
    assert isinstance(product, dict)
    del product["repo"]
    _, steps = file_steps(
        tmp_path / "box", write_file(tmp_path, data), ask=lambda field, schema: ""
    )
    outcome, _ = run(steps, FakeRunner())
    assert failed(outcome) == ("fetch_passport:no-answer", {"field": "product.repo"})


def test_box_state_reads_without_the_ops_commit() -> None:
    raw = state().model_dump_json()
    assert "ops_commit" not in raw
    assert BoxState.model_validate_json(raw).ops_commit is None


def test_passport_steps_from_a_file_are_the_fetch_only(tmp_path: Path) -> None:
    _, steps = passport_steps(tmp_path, server=None, file=tmp_path / "p.yaml")
    assert [step.name for step in steps] == ["fetch_passport"]
    _, steps = passport_steps(tmp_path, server=SERVER, ops=OpsSource("file:///x"))
    assert [step.name for step in steps] == ["age_key", "ops_key", "fetch_passport"]
    modes: set[Mode] = {"install", "deploy", "reinstall"}
    assert all(step.modes == modes for step in steps)


def test_sops_128_with_a_key_that_does_not_read_is_not_waited_for(
    tmp_path: Path,
) -> None:
    root = tmp_path / "box"
    owner = mint(tmp_path / "owner.key")
    ops = Ops(tmp_path)
    ops.put(SERVER, encrypt(tmp_path, passport(), owner))
    key = root / AGE_KEY
    key.parent.mkdir(parents=True)
    key.write_text("not a key\n")
    key.chmod(0o600)
    fetched = Fetched()
    fetch = FetchPassport(
        fetched, root, server=SERVER, ops=OpsSource(ops.address), wait_s=100
    )
    outcome, _ = run([fetch], Recording())
    assert failed(outcome) == ("fetch_passport:key-unreadable", {"path": str(key)})


class _ModeAfterSops(Recording):
    """Notes the mode of sops' ``--output`` file the moment sops is done."""

    def __init__(self) -> None:
        super().__init__()
        self.modes: list[str] = []

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
        result = super().run(
            argv, expect=expect, timeout=timeout, cwd=cwd, env=env, on_line=on_line
        )
        if argv[0] == "sops":
            self.modes.append(mode_of(Path(argv[list(argv).index("--output") + 1])))
        return result


def test_the_decrypted_file_is_0600_from_the_start(tmp_path: Path) -> None:
    root = tmp_path / "box"
    public = box_key(root)
    ops = Ops(tmp_path)
    ops.put(SERVER, encrypt(tmp_path, passport(), public))
    old = os.umask(0o022)
    try:
        runner = _ModeAfterSops()
        _, steps = ops_steps(root, ops)
        outcome, _ = run(steps, runner)
    finally:
        os.umask(old)
    assert outcome.code is ExitCode.OK, outcome.steps
    assert runner.modes == [oct(0o600)]
