"""DM-145: secret files -- ``asked`` that reaches its container as a file.

The probes: the value is nowhere but its file (not the env file, the
override, the file's name, the argv, the journal or the verdict); a
multi-line value arrives byte for byte; a foreign path or ``..`` is refused
by the loader. The rest: who owns the file (``user:`` of compose, else the
image's), one file per service, ``check`` and the read back, the compose
finding, the console's refusal. Planted values have no real key's form.
"""

import json
import os
from collections.abc import Mapping
from pathlib import Path

import pytest
from compose_support import (
    APP_IMAGE,
    CONFIG,
    FRONT_IMAGE,
    blank,
    build_call,
    config_call,
    image_call,
    raw_config_call,
    run,
    stdout,
)
from env_support import box, context, passport_data
from pydantic import ValidationError

from pridem.events import Json
from pridem.report.codes import ExitCode
from pridem.runner import FakeCall, FakeRunner
from pridem.stacks.env import env_keys, env_text, resolve
from pridem.stacks.schema import PRIMER_YAML, Product, rule_problems
from pridem.stacks.seams import SeamMemory
from pridem.steps import secret_files
from pridem.steps.base import StepFailed
from pridem.steps.build import Build
from pridem.steps.compose import ComposeStack, variables
from pridem.steps.passport import Fetched

MARKER = "pridem-planted-file-secret-145a"
VALUE = f"{MARKER}\nthe second line of the planted value\nshort tail\n"
PATH = "/run/primer/age.key"
ME = f"{os.getuid()}:{os.getgid()}"


def _product(file: Mapping[str, Json] | None = None) -> Product:
    data = blank().model_dump(by_alias=True, exclude_none=True)
    data["env"] = {"AGE_KEY": {"source": "asked", "file": dict(file or {"path": PATH})}}
    made = PRIMER_YAML.validate_python(data)
    assert isinstance(made, Product)
    return made


def _setup(tmp: Path, value: str = VALUE) -> tuple[Build, ComposeStack, Fetched]:
    stack = _product()
    root, fetched = box(tmp, passport_data(asked={"blank": {"AGE_KEY": value}}))
    cs = ComposeStack(stack, "blank", root / "release", "main", "c" * 40, root,
                      staged=True)  # fmt: skip
    (root / "release").mkdir(parents=True, exist_ok=True)
    cs.env_file.parent.mkdir(parents=True, exist_ok=True)
    cs.env_file.write_text("")
    build = Build(stack, "blank", release=cs.release, ref=cs.ref, commit=cs.commit,
                  root=root, fetched=fetched)  # fmt: skip
    return build, cs, fetched


def _user(cs: ComposeStack, user: str = ME) -> FakeCall:
    argv = ("docker", "image", "inspect", "-f", "{{.Config.User}}", "--", APP_IMAGE)
    return FakeCall(argv, lines=stdout(user))


def _green(cs: ComposeStack) -> list[FakeCall]:
    return [
        raw_config_call(cs),
        config_call(cs),  # check: no override yet
        raw_config_call(cs),
        config_call(cs),  # act
        build_call(cs),
        image_call(cs, "app", APP_IMAGE),  # act: the user app runs as
        _user(cs),
        raw_config_call(cs),
        config_call(cs),  # verify
        image_call(cs, "app", APP_IMAGE),
        image_call(cs, "frontend", FRONT_IMAGE),
        image_call(cs, "app", APP_IMAGE),  # verify: the file read back
        _user(cs),
    ]


def _files(cs: ComposeStack) -> list[Path]:
    return sorted(secret_files.files_dir(cs).glob("*"))


# --- probes ---------------------------------------------------------------------


def test_probe_DM_145_a_secret_file_is_nowhere_but_its_file(tmp_path: Path) -> None:
    """The planted value -- whole and line by line -- is in its file and
    nowhere else: not in the env file's values, the override, the file's
    name, any argv, the journal or the verdict. The file is 0600, its
    owner the user the service runs as, bound read-only at its path."""
    build, cs, fetched = _setup(tmp_path)
    assert fetched.passport is not None
    resolved = resolve(cs.stack, cs.stack, fetched.passport, {}, SeamMemory())  # type: ignore[arg-type]
    assert resolved.files == {"AGE_KEY": VALUE}
    assert "AGE_KEY" not in resolved.values and "AGE_KEY" not in env_keys(cs.stack)
    assert MARKER not in env_text(resolved.values)
    script = _green(cs)
    with FakeRunner(*script) as runner:
        outcome, sink = run([build], runner)
    assert outcome.code is ExitCode.OK, outcome.steps
    [file] = _files(cs)
    assert file.read_bytes() == VALUE.encode()
    assert secret_files.as_owned(file) == (os.getuid(), os.getgid(), 0o600)
    lines = [line for line in VALUE.splitlines() if len(line) >= 16]
    for text in (
        file.name,
        cs.override.read_text(),
        json.dumps([list(call.argv) for call in script]),
        json.dumps([str(event) for event in sink.events]),
        json.dumps(outcome.steps[0].verify),
    ):
        assert all(line not in text for line in [MARKER, *lines]), text[:200]
    override = json.loads(cs.override.read_text())
    assert {
        "type": "bind",
        "source": str(file),
        "target": PATH,
        "read_only": True,
    } in override["services"]["app"]["volumes"]
    assert outcome.steps[0].verify["secret_files"] == [
        {
            "key": "AGE_KEY",
            "service": "app",
            "path": PATH,
            "uid": os.getuid(),
            "gid": os.getgid(),
            "mode": "0600",
            "matches": True,
        }
    ]


@pytest.mark.parametrize(
    "value",
    [VALUE, VALUE.rstrip("\n"), f"{MARKER}\n\n  indented line of it\n\n"],
    ids=["trailing-newline", "none", "blank-and-indented-lines"],
)
def test_probe_DM_145_a_multiline_value_arrives_byte_for_byte(
    tmp_path: Path, value: str
) -> None:
    build, cs, _ = _setup(tmp_path, value)
    with FakeRunner(*_green(cs)) as runner:
        outcome, _ = run([build], runner)
    assert outcome.code is ExitCode.OK, outcome.steps
    [file] = _files(cs)
    assert file.read_bytes() == value.encode()


@pytest.mark.parametrize(
    "path",
    ["run/primer/age.key", "/run/../etc/key", "/run/./key", "/primer/data/key",
     "/run/.git/key", "/"],
)  # fmt: skip
def test_probe_DM_145_a_foreign_path_or_dotdot_is_refused_by_the_loader(
    path: str,
) -> None:
    with pytest.raises(ValidationError, match="S.secret-file"):
        _product({"path": path})
    assert _product({"path": "/run/primer/ok.key"}).env["AGE_KEY"] is not None


# --- the form ---------------------------------------------------------------------


def test_one_path_twice_and_a_file_seam_are_refused() -> None:
    data = blank().model_dump(by_alias=True, exclude_none=True)
    data["env"] = {
        "A_KEY": {"source": "asked", "file": {"path": PATH}},
        "B_KEY": {"source": "asked", "file": {"path": PATH}},
    }
    made = PRIMER_YAML.validate_python(data)
    assert "S.secret-file" in [p.code for p in rule_problems(made)]
    data["env"] = {"A_KEY": {"source": "asked", "file": {"path": PATH}}}
    data["provides"] = {"A_KEY": {"verb": "replay"}}
    made = PRIMER_YAML.validate_python(data)
    assert "S.secret-file" in [p.code for p in rule_problems(made)]
    for services in (list[Json](), list[Json](["app", "app"])):
        with pytest.raises(ValidationError, match="S.secret-file"):
            _product({"path": PATH, "services": services})


def test_a_file_is_only_a_form_of_asked() -> None:
    data = blank().model_dump(by_alias=True, exclude_none=True)
    for source in ("minted", "param", "derived"):
        extra = {"run": "x derive"} if source == "derived" else {}
        data["env"] = {"K_KEY": {"source": source, **extra, "file": {"path": PATH}}}
        with pytest.raises(ValidationError):
            PRIMER_YAML.validate_python(data)


def test_compose_naming_a_secret_file_is_a_finding() -> None:
    document: dict[str, Json] = {
        "services": {"app": {"environment": {"K": "${AGE_KEY:?}"}}}
    }
    assert variables(document, ["OTHER"], ["AGE_KEY"]) == [
        "app: AGE_KEY is a secret file, not a variable"
    ]


def test_a_secret_file_the_passport_lacks_is_never_asked(tmp_path: Path) -> None:
    from env_support import render

    stack = _product()
    root, fetched = box(tmp_path, passport_data(asked={}))
    step = render(stack, root, fetched, ask=lambda field, schema: "single line value!!")
    with pytest.raises(StepFailed) as refused:
        step.check(context(FakeRunner()))
    assert refused.value.reason.code == "asked-file-missing"
    assert refused.value.reason.params == {"key": "asked.blank.AGE_KEY"}


def test_an_option_off_has_no_file(tmp_path: Path) -> None:
    data = blank().model_dump(by_alias=True, exclude_none=True)
    data["options"] = ["meet"]
    data["env"] = {
        "AGE_KEY": {"source": "asked", "when": "meet", "file": {"path": PATH}}
    }
    stack = PRIMER_YAML.validate_python(data)
    _, fetched = box(tmp_path, passport_data(
        asked={"blank": {"AGE_KEY": "primer-switched-off"}}, options=[]))  # fmt: skip
    cs = ComposeStack(stack, "blank", tmp_path, "main", "c" * 40, tmp_path)
    assert secret_files.wanted(cs, fetched.passport) == []
    assert fetched.passport is not None and isinstance(stack, Product)
    resolved = resolve(stack, stack, fetched.passport, {}, SeamMemory())
    assert "AGE_KEY" not in resolved.values and "AGE_KEY" not in resolved.files


def test_each_service_gets_its_own_file(tmp_path: Path) -> None:
    stack = _product({"path": PATH, "services": ["app", "worker"]})
    cs = ComposeStack(stack, "blank", Path("/r"), "main", "c" * 40, Path("/"))
    passport = box(tmp_path, passport_data(
        asked={"blank": {"AGE_KEY": VALUE}}))[1].passport  # fmt: skip
    found = secret_files.wanted(cs, passport)
    assert [(w.key, w.service) for w in found] == [
        ("AGE_KEY", "app"),
        ("AGE_KEY", "worker"),
    ]
    paths = {w: secret_files.new_path(cs, w) for w in found}
    binds = secret_files.binds(paths)
    assert sorted(binds) == ["app", "worker"]
    assert binds["app"] != binds["worker"]


# --- the owner ----------------------------------------------------------------------


def _run_id(image: str, *args: str, code: int = 0, line: str = "") -> FakeCall:
    argv = ("docker", "run", "--rm", "--network", "none", "--entrypoint", args[0],
            "--", image, *args[1:])  # fmt: skip
    return FakeCall(argv, code=code, lines=stdout(line) if line else ())


def _inspect(image: str, user: str) -> FakeCall:
    argv = ("docker", "image", "inspect", "-f", "{{.Config.User}}", "--", image)
    return FakeCall(argv, lines=stdout(user))


@pytest.mark.parametrize(
    ("compose_user", "calls", "found"),
    [
        ("1000", [_run_id("img", "id", "-g", "1000", line="1000")], (1000, 1000)),
        ("1000:2000", [], (1000, 2000)),
        ("4242", [_run_id("img", "id", "-g", "4242", code=1)], (4242, 0)),
        ("blank", [_run_id("img", "id", "-u", "blank", line="1000"),
                   _run_id("img", "id", "-g", "blank", line="1000")], (1000, 1000)),
        ("blank:staff", [_run_id("img", "id", "-u", "blank", line="1000"),
                         _run_id("img", "getent", "group", "staff",
                                 line="staff:x:50:")], (1000, 50)),
        (None, [_inspect("img", "blank"),
                _run_id("img", "id", "-u", "blank", line="1000"),
                _run_id("img", "id", "-g", "blank", line="1000")], (1000, 1000)),
        (None, [_inspect("img", "")], (0, 0)),
    ],
    ids=["uid", "uid-gid", "uid-no-entry", "name", "name-group", "image", "root"],
)  # fmt: skip
def test_the_owner_is_the_user_the_service_runs_as(
    compose_user: str | None, calls: list[FakeCall], found: tuple[int, int]
) -> None:
    """``user:`` of compose wins over the image's ``USER``; a name is read in
    the image; a uid with no entry has group 0."""
    body: dict[str, Json] = {"image": "img"}
    if compose_user is not None:
        body["user"] = compose_user
    with FakeRunner(*calls) as runner:
        assert (
            secret_files.owner(
                context(runner), "app", "img", {"services": {"app": body}}
            )
            == found
        )


def test_a_name_the_image_does_not_know_is_refused() -> None:
    calls = [_run_id("img", "id", "-u", "ghost", code=1)]
    with FakeRunner(*calls) as runner, pytest.raises(StepFailed) as refused:
        secret_files.owner(context(runner), "app", "img",
                           {"services": {"app": {"user": "ghost"}}})  # fmt: skip
    assert refused.value.reason.code == "file-owner"


# --- check ----------------------------------------------------------------------


def test_a_file_not_as_written_makes_build_act_again(tmp_path: Path) -> None:
    """A green build, then the file's mode changed by hand: ``check`` sees it
    and asks to act. The pair: as written -- nothing to do."""
    build, cs, _ = _setup(tmp_path)
    with FakeRunner(*_green(cs)) as runner:
        run([build], runner)
    [file] = _files(cs)
    again = [
        raw_config_call(cs),
        config_call(cs),
        image_call(cs, "app", APP_IMAGE),
        image_call(cs, "frontend", FRONT_IMAGE),
        image_call(cs, "app", APP_IMAGE),
        _user(cs),
    ]
    with FakeRunner(*again) as runner:
        assert not build.check(context(runner)).needed
    file.chmod(0o644)
    with FakeRunner(*again) as runner:
        assert build.check(context(runner)).needed
    assert CONFIG is not None


def test_a_new_value_is_a_new_path(tmp_path: Path) -> None:
    """The value changed: a new file under a new name -- the bind changes and
    the service is recreated; the file of the old value is left to
    ``finalize``. The same value: the same file, the same name."""
    build, cs, fetched = _setup(tmp_path)
    with FakeRunner(*_green(cs)) as runner:
        run([build], runner)
    [first] = _files(cs)
    item = secret_files.wanted(cs, fetched.passport)[0]
    changed = secret_files.Wanted(item.key, item.service, item.path, VALUE + "more\n")
    assert secret_files.matching(cs, item) == first
    assert secret_files.matching(cs, changed) is None
    assert secret_files.new_path(cs, changed) != first


def test_the_file_is_given_to_the_user_of_its_service(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The owner the image says (``4242:4343``) is what the file is given --
    the call to ``chown`` taken literally, no real ``chown``: the real owner
    is measured on tier 3 (``stat`` in ``app`` and ``reader``)."""
    given: list[tuple[str, int, int]] = []
    monkeypatch.setattr(
        os,
        "chown",
        lambda path, uid, gid: given.append((str(path), uid, gid)),
    )
    build, cs, _ = _setup(tmp_path)
    script = [
        call if "{{.Config.User}}" not in call.argv else _user(cs, "4242:4343")
        for call in _green(cs)
    ]
    with FakeRunner(*script) as runner:
        outcome, _ = run([build], runner)
    assert outcome.steps[0].reason is not None  # verify reads 4242:4343 back
    assert outcome.steps[0].reason.code == "build:secret-file"
    [file] = _files(cs)
    assert given == [(str(file), 4242, 4343)]


def test_finalize_takes_the_files_no_override_names(tmp_path: Path) -> None:
    """After the switch: a file no override of the stack names is taken, one
    an override names stays; the fact counts them. One left -- red
    ``secret-files``, by number."""
    from env_support import context as ctx_of
    from test_steps_finalize import finalize

    from pridem.state import Box

    pridem = Box(tmp_path / "pridem")
    step, _ = finalize(tmp_path, pridem)
    files = tmp_path / "opt" / "blank" / "env" / "files"
    files.mkdir(parents=True)
    named = files / "AGE_KEY@app@aaaa"
    stale = files / "AGE_KEY@app@bbbb"
    for file in (named, stale):
        file.write_text("x" * 20)
    override = tmp_path / "opt" / "blank" / "compose" / "blank.next.yml"
    override.write_text(f'{{"services": {{"app": {{"volumes": ["{named}"]}}}}}}')
    with pridem.lock("t"):
        check = step.check(ctx_of(FakeRunner()))
        assert check.needed
        step.act(ctx_of(FakeRunner()), check)
        fact = step.verify(ctx_of(FakeRunner()), check).fact
    assert named.exists() and not stale.exists()
    assert fact["secret_files_removed"] == 1
    stale.write_text("x" * 20)
    with pridem.lock("t"), pytest.raises(StepFailed) as left:
        step.verify(ctx_of(FakeRunner()), check)
    assert left.value.reason.code == "secret-files"
    assert left.value.reason.params == {"stack": "blank", "count": 1}
