"""Probe DM-57: ``pridem check`` names every violation of a project's
repository, by the machine's own functions, with no box and nothing written.

The repository is ``fixtures/check/blank`` -- ``primer.yaml`` and the compose
file of ``primer-blank@0e82be5`` -- copied per test. ``docker compose`` is a
strict ``FakeRunner``: ``version``, then ``config --no-interpolate`` and
``config``, each with no ``--env-file``, in an environment of ``PATH``,
``HOME``, ``COMPOSE_DISABLE_ENV_FILE`` and a stand-in for every key of
``env``; their output is the measured one of the blank
(``fixtures/compose/blank-config*.json``, paths ``/r/...`` in the repository).
"""

import io
import json
import os
import shutil
from pathlib import Path

import pytest
import yaml
from compose_support import in_release, stdout

from pridem.cli import run
from pridem.events import Json
from pridem.runner import FakeCall, FakeRunner
from pridem.stacks.schema import PRIMER_YAML, Product
from pridem.steps.compose import ComposeStack, refusal, variables
from pridem.verbs import VERBS

FIXTURES = Path(__file__).parent / "fixtures"
BLANK = json.loads((FIXTURES / "compose" / "blank-config.json").read_text())
RAW = json.loads((FIXTURES / "compose" / "blank-config-raw.json").read_text())
ENV_KEYS = ("API_BASE_URL", "EDITION", "POSTGRES_PASSWORD")


def made_blank() -> Product:
    data = yaml.safe_load((FIXTURES / "check" / "blank" / "primer.yaml").read_text())
    stack = PRIMER_YAML.validate_python(data)
    assert isinstance(stack, Product)
    return stack


def repo(tmp_path: Path) -> Path:
    root = tmp_path / "blank"
    shutil.copytree(FIXTURES / "check" / "blank", root)
    return root


def _env(keys: tuple[str, ...] = ENV_KEYS) -> dict[str, str]:
    return {
        "PATH": os.environ.get("PATH", ""),
        "HOME": os.environ.get("HOME", ""),
        "COMPOSE_DISABLE_ENV_FILE": "true",
        **dict.fromkeys(keys, "1"),
    }


def version_call() -> FakeCall:
    return FakeCall(
        ("docker", "compose", "version"), lines=stdout("Docker Compose 2.40.3")
    )


def config_call(
    root: Path,
    document: dict[str, Json],
    *,
    raw: bool,
    keys: tuple[str, ...] = ENV_KEYS,
    code: int = 0,
) -> FakeCall:
    argv = ["docker", "compose", "-p", "blank", "-f", str(root / "docker-compose.yml")]
    argv += ["config", "--format", "json", *(["--no-interpolate"] if raw else [])]
    return FakeCall(
        tuple(argv),
        code=code,
        lines=stdout(json.dumps(in_release(document, root))),
        env=_env(keys),
    )


def green_calls(
    root: Path, raw: dict[str, Json] = RAW, document: dict[str, Json] = BLANK
) -> list[FakeCall]:
    return [
        version_call(),
        config_call(root, raw, raw=True),
        config_call(root, document, raw=False),
    ]


def check(
    root: Path, calls: list[FakeCall], *extra: str
) -> tuple[int, dict[str, Json], str]:
    out, err = io.StringIO(), io.StringIO()
    with FakeRunner(*calls) as runner:
        code = run(
            ["--json", "check", str(root), *extra], out=out, err=err, runner=runner
        )
    verdict = json.loads(out.getvalue()) if out.getvalue() else {}
    return code, verdict, err.getvalue()


def _steps(verdict: dict[str, Json]) -> dict[str, dict[str, Json]]:
    steps = verdict["steps"]
    assert isinstance(steps, list)
    return {f"{s['stack']}/{s['name']}": s for s in steps if isinstance(s, dict)}


def _reason(verdict: dict[str, Json], key: str) -> dict[str, Json]:
    reason = _steps(verdict)[key]["reason"]
    assert isinstance(reason, dict)
    return reason


def _with(document: dict[str, Json], service: str, **body: Json) -> dict[str, Json]:
    changed = json.loads(json.dumps(document))
    changed["services"][service].update(body)
    assert isinstance(changed, dict)
    return changed


def _yaml(root: Path, change: dict[str, object]) -> None:
    path = root / "primer.yaml"
    data = yaml.safe_load(path.read_text())
    data.update(change)
    path.write_text(yaml.safe_dump(data, sort_keys=False))


# --- probe ------------------------------------------------------------------------


def test_probe_DM_57_check_names_every_violation_of_a_product_repo(
    tmp_path: Path,
) -> None:
    """Every kind of violation, planted one at a time into the blank, is red
    with its name; the pair: the blank itself is green, exit 0. DM-57 FIX: the
    build arguments are planted in both outputs of ``config``, as it prints a
    mapping -- ``refusal`` reads them in ``--no-interpolate`` since."""
    root = repo(tmp_path / "pair")
    code, verdict, _ = check(root, green_calls(root))
    assert (code, verdict["result"]) == (0, "green")
    assert all(s["status"] == "ok" for s in _steps(verdict).values())

    def planted(name: str) -> Path:
        return repo(tmp_path / name)

    # primer.yaml: a path of the app that reads as more than a path
    root = planted("path")
    text = (root / "primer.yaml").read_text().replace("/ready", "/ready; deny all", 1)
    (root / "primer.yaml").write_text(text)
    code, verdict, _ = check(root, [])
    reason = _reason(verdict, "blank/primer_yaml")
    assert code == 1 and reason["code"] == "primer_yaml:invalid"
    assert "stacks.blank.app.ready" in json.dumps(reason["problems"])

    # primer.lock: a dependency and no lock
    root = planted("lock")
    _yaml(
        root,
        {
            "dependencies": {
                "comms": {
                    "repo": "git@github.com:aivis-one/comms.git",
                    "version": ">=3.0,<4",
                }
            }
        },
    )
    code, verdict, _ = check(root, green_calls(root))
    assert code == 1
    assert _reason(verdict, "blank/primer_lock")["code"] == "primer_lock:lock-missing"

    # compose: a key off the list, an env_file, a loose variable, build args
    cases: list[tuple[str, list[FakeCall], str, list[Json]]] = []
    root = planted("privileged")
    cases.append(
        (
            "privileged",
            green_calls(root, document=_with(BLANK, "app", privileged=True)),
            "compose:compose-forbidden",
            ["app: privileged"],
        )
    )
    root = planted("env-file")
    raw = _with(RAW, "app", env_file=[{"path": str(root / "x.env"), "required": True}])
    cases.append(
        (
            "env-file",
            green_calls(root, raw=raw),
            "compose:compose-forbidden",
            ["app: env_file"],
        )
    )
    root = planted("variable")
    raw = _with(RAW, "app", environment={"EDITION": "$EDITION", "X": "${OTHER:?}"})
    loose = [version_call(), config_call(root, raw, raw=True)]
    cases.append(
        (
            "variable",
            loose,
            "compose:compose-forbidden",
            ["app: $EDITION is not ${EDITION:?}", "app: OTHER is not a key of env"],
        )
    )
    for name, calls, wanted, found in cases:
        root = tmp_path / name / "blank"
        code, verdict, _ = check(root, calls)
        reason = _reason(verdict, "blank/compose")
        assert (code, reason["code"], reason["found"]) == (1, wanted, found), name
    root = planted("args")  # in both outputs, as config prints a mapping
    build: dict[str, Json] = {"context": "/r/backend", "args": {"A": "1"}}
    document = _with(BLANK, "app", build=build)
    raw = _with(RAW, "app", build=build)
    code, verdict, _ = check(root, green_calls(root, raw=raw, document=document))
    assert _reason(verdict, "blank/compose") == {
        "code": "compose:instance-args",
        "stack": "blank",
        "services": ["app"],
    }

    # packages: the contract of a given package outside the slot's range
    root = planted("package")
    _yaml(
        root,
        {
            "packages": {
                "skin": {
                    "contract": ">=1,<2",
                    "validate": "v <dir>",
                    "mount": [{"service": "frontend", "path": "/srv/skin"}],
                }
            }
        },
    )
    package = tmp_path / "skin"
    package.mkdir()
    (package / "primer-package.yaml").write_text('schema: 1\ncontract: "2.0"\n')
    code, verdict, _ = check(root, green_calls(root), f"skin={package}")
    reason = _reason(verdict, "blank/packages")
    assert (code, reason["code"], reason["found"]) == (1, "packages:contract", "2.0")


# --- the verdict ------------------------------------------------------------------


def test_the_verdict_has_the_form_of_contract_2_with_no_journal(tmp_path: Path) -> None:
    root = repo(tmp_path)
    code, verdict, _ = check(root, green_calls(root))
    assert code == 0
    assert "log_ref" not in verdict and "passport_version" not in verdict
    assert verdict["verb"] == "check" and verdict["actor"] == {
        "type": "machine",
        "via": "local",
    }
    assert verdict["composition_before"] == verdict["composition_after"]
    composition = verdict["composition_before"]
    assert isinstance(composition, dict) and list(composition) == ["pridem"]
    assert [(s["name"], s["order"]) for s in _steps(verdict).values()] == [
        ("primer_yaml", 1),
        ("primer_lock", 2),
        ("compose", 3),
        ("packages", 4),
    ]
    assert not list(tmp_path.rglob("*.jsonl")) and not (tmp_path / "opt").exists()


def test_check_is_the_only_verb_without_a_box() -> None:
    assert not VERBS["check"].box and VERBS["check"].verdict


# --- primer.yaml and primer.lock -------------------------------------------------


def test_no_primer_yaml_or_not_yaml_is_red_and_the_rest_skipped(tmp_path: Path) -> None:
    root = repo(tmp_path / "none")
    (root / "primer.yaml").unlink()
    code, verdict, _ = check(root, [])
    assert (
        code == 1
        and _reason(verdict, "blank/primer_yaml")["code"]
        == "primer_yaml:no-primer-yaml"
    )
    assert {
        s["status"] for k, s in _steps(verdict).items() if k != "blank/primer_yaml"
    } == {"skipped"}
    root = repo(tmp_path / "broken")
    (root / "primer.yaml").write_text("schema: [1\n")
    code, verdict, _ = check(root, [])
    assert (
        code == 1
        and _reason(verdict, "blank/primer_yaml")["code"] == "primer_yaml:invalid"
    )


def test_a_lock_is_checked_against_the_ranges(tmp_path: Path) -> None:
    dependency = {
        "comms": {"repo": "git@github.com:aivis-one/comms.git", "version": ">=3.0,<4"}
    }
    for version, code_wanted in (("3.1.0", None), ("4.0.0", "primer_lock:lock-range")):
        root = repo(tmp_path / version)
        _yaml(root, {"dependencies": dependency})
        (root / "primer.lock").write_text(
            "schema: 1\nresolved_at: 2026-11-03T00:00:00Z\ndependencies:\n"
            f'  comms: {{version: "{version}", tag: v{version}, commit: b27c57c}}\n'
        )
        code, verdict, _ = check(root, green_calls(root))
        step = json.loads(json.dumps(_steps(verdict)["blank/primer_lock"]))
        if code_wanted is None:
            assert code == 0 and step["verify"]["tags"].startswith("not checked")
        else:
            assert code == 1 and step["reason"]["code"] == code_wanted


# --- compose -----------------------------------------------------------------------


def test_no_compose_binary_is_incomplete_and_compose_skipped(tmp_path: Path) -> None:
    root = repo(tmp_path)
    missing = FakeCall(("docker", "compose", "version"), outcome="not_started")
    code, verdict, _ = check(root, [missing])
    assert (code, verdict["result"]) == (2, "incomplete")
    report = json.loads(json.dumps(verdict["report"]))
    assert report["incomplete"] == [{"what": "compose", "code": "compose:not-found"}]
    assert _steps(verdict)["blank/compose"]["status"] == "skipped"
    plugin_missing = FakeCall(("docker", "compose", "version"), code=1)
    assert check(root, [plugin_missing])[0] == 2


def test_a_compose_file_that_is_not_there_or_config_that_fails(tmp_path: Path) -> None:
    root = repo(tmp_path / "gone")
    (root / "docker-compose.yml").unlink()
    code, verdict, _ = check(root, [version_call()])
    assert (
        code == 1 and _reason(verdict, "blank/compose")["code"] == "compose:no-compose"
    )
    root = repo(tmp_path / "fails")
    code, verdict, _ = check(
        root, [version_call(), config_call(root, RAW, raw=True, code=15)]
    )
    assert _reason(verdict, "blank/compose") == {
        "code": "compose:config-failed",
        "stack": "blank",
        "exit_code": 15,
    }


@pytest.mark.parametrize(
    ("written", "found"),
    [
        ("${EDITION:?}", []),
        ("${EDITION:?the edition}", []),
        ("$$EDITION", []),
        ("$EDITION", ["app: $EDITION is not ${EDITION:?}"]),
        ("${EDITION}", ["app: ${EDITION} is not ${EDITION:?}"]),
        ("${EDITION?}", ["app: ${EDITION?} is not ${EDITION:?}"]),
        ("${EDITION?no}", ["app: ${EDITION?no} is not ${EDITION:?}"]),
        ("${EDITION:-core}", ["app: ${EDITION:-core} is not ${EDITION:?}"]),
        ("${EDITION-core}", ["app: ${EDITION-core} is not ${EDITION:?}"]),
        ("${EDITION:+x}", ["app: ${EDITION:+x} is not ${EDITION:?}"]),
        ("${STRANGER:?}", ["app: STRANGER is not a key of env"]),
        (
            "$STRANGER",
            [
                "app: $STRANGER is not ${STRANGER:?}",
                "app: STRANGER is not a key of env",
            ],
        ),
    ],
)
def test_a_variable_is_required_and_a_key_of_env(
    written: str, found: list[str]
) -> None:
    """Protocol 3.4: ``${NAME:?}`` -- with or without a message -- and nothing
    else; ``$$`` is a dollar. The same function names them for ``build``."""
    document: dict[str, Json] = {"services": {"app": {"environment": {"X": written}}}}
    assert variables(document, ENV_KEYS) == found


def test_variables_outside_services_are_named_by_their_section() -> None:
    document: dict[str, Json] = {
        "name": "$NOT_READ",
        "x-anchor": {"a": "$NOT_READ_EITHER"},
        "volumes": {"data": {"driver_opts": {"device": "$WHERE"}}},
    }
    assert variables(document, ENV_KEYS) == [
        "volumes.data: $WHERE is not ${WHERE:?}",
        "volumes.data: WHERE is not a key of env",
    ]


# --- packages ----------------------------------------------------------------------


def _skin(root: Path) -> None:
    _yaml(
        root,
        {
            "packages": {
                "skin": {
                    "contract": ">=1,<2",
                    "validate": "v <dir>",
                    "mount": [{"service": "frontend", "path": "/srv/skin"}],
                }
            }
        },
    )


def test_packages_not_given_are_skipped_and_named(tmp_path: Path) -> None:
    root = repo(tmp_path)
    _skin(root)
    code, verdict, _ = check(root, green_calls(root))
    step = _steps(verdict)["blank/packages"]
    assert code == 0 and step["status"] == "skipped"
    assert step["reason"] == {"code": "packages:not-given", "slots": ["skin"]}


def test_a_given_package_is_checked_by_the_machines_function(tmp_path: Path) -> None:
    root = repo(tmp_path)
    _skin(root)
    package = tmp_path / "skin"
    package.mkdir()
    code, verdict, _ = check(root, green_calls(root), f"skin={package}")
    assert (
        code == 1
        and _reason(verdict, "blank/packages")["code"] == "packages:no-manifest"
    )
    (package / "primer-package.yaml").write_text('schema: 1\ncontract: "1.4"\n')
    code, verdict, _ = check(root, green_calls(root), f"skin={package}")
    assert code == 0
    assert _steps(verdict)["blank/packages"]["verify"] == {
        "slots": [{"slot": "skin", "contract": "1.4"}]
    }


@pytest.mark.parametrize("extra", ["skin", "skin=", "=dir", "nope=."])
def test_a_wrong_package_argument_is_refused_before_anything(
    tmp_path: Path, extra: str
) -> None:
    root = repo(tmp_path)
    _skin(root)
    code, verdict, err = check(root, [], extra)
    assert (code, verdict) == (1, {}) and err.startswith("pridem: check:")


def test_a_directory_that_is_not_one_is_refused(tmp_path: Path) -> None:
    code, verdict, err = check(tmp_path / "nowhere", [])
    assert (code, verdict) == (1, {}) and "not a directory" in err


def test_the_readme_shows_a_pinned_check_with_no_secret() -> None:
    """DM-57 item 6: the README's workflow installs the machine by its release
    tag with the sha256 of its wheel and lock, runs ``pridem check`` and uses
    no secret and no value."""
    text = (Path(__file__).resolve().parents[1] / "README.md").read_text()
    block = text.split("## `pridem check` in a project's CI", 1)[1]
    workflow = block.split("```yaml\n", 1)[1].split("```", 1)[0]
    loaded = yaml.safe_load(workflow)
    run = "\n".join(
        str(step.get("run", "")) for step in loaded["jobs"]["check"]["steps"]
    )
    assert "pridem check ." in run and run.count("sha256sum -c --strict") == 2
    assert "releases/download/$PRIDEM_TAG/" in run and "--require-hashes" in run
    assert (
        "secrets." not in workflow and "first tag of the machine is issued by" in block
    )


@pytest.mark.parametrize("given", [".", "blank"])
def test_a_relative_directory_is_checked_by_its_absolute_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, given: str
) -> None:
    """``pridem check .`` (DM-58): the directory is resolved first -- the
    verdict names its first step by the directory's name, which ``.`` has
    not, and compose reads the file by its absolute path. ``.`` from inside
    the repository and a relative path from beside it give the verdict of
    the absolute path."""
    root = repo(tmp_path).resolve()
    monkeypatch.chdir(root if given == "." else root.parent)
    code, verdict, err = check(Path(given), green_calls(root))
    assert (code, err) == (0, ""), err
    assert _steps(verdict)["blank/primer_yaml"]["status"] == "ok"


# --- build.args in any form (FIX) -----------------------------------------------

ARGS_FORMS: list[tuple[str, Json, Json]] = [
    # (form in the file, its build.args in --no-interpolate, in config) --
    # measured with compose 2.27.0 and 2.40.3; ``None`` -- no key
    ("{}", {}, None),
    ("[]", None, None),
    ("{A: x}", {"A": "x"}, {"A": "x"}),
    ("{A: ${VAR:?}}", {"A": "${VAR:?}"}, {"A": "v"}),
    ("{A: null}", {}, None),
    ("[A=x]", ["A=x"], {"A": "x"}),
    ("[SET] set", None, {"SET": "s"}),
    ("[UNSET] unset", None, None),
]


def _build(args: Json, key: bool) -> dict[str, Json]:
    build: dict[str, Json] = {"context": "/r/backend"}
    if key:
        build["args"] = args
    app: dict[str, Json] = {"image": "app:1", "build": build}
    app["healthcheck"] = {"test": ["CMD", "true"]}  # protocol 3.4 (DM-22)
    return {"services": {"app": app}}


@pytest.mark.parametrize(("form", "raw", "printed"), ARGS_FORMS)
def test_build_args_in_any_form_are_refused(
    tmp_path: Path, form: str, raw: Json, printed: Json
) -> None:
    """Protocol 3.4: no ``build.args`` in any form. ``refusal`` reads them in
    ``config --no-interpolate`` by the key -- its value there is ``{}``,
    ``null``, a mapping or a list -- where ``config`` drops some forms (no key
    in ``printed``: the velo form ``[UNSET]`` among them). The pair: a build
    with no ``args`` passes."""
    cs = ComposeStack(made_blank(), "blank", tmp_path, "check", "", tmp_path)
    document = in_release(_build(printed, printed is not None), tmp_path)
    found = refusal(cs, document, in_release(_build(raw, True), tmp_path))
    assert found == ("instance-args", {"stack": "blank", "services": ["app"]}), form
    plain = in_release(_build(None, False), tmp_path)
    assert refusal(cs, plain, plain) is None


def test_build_args_of_every_service_are_named(tmp_path: Path) -> None:
    cs = ComposeStack(made_blank(), "blank", tmp_path, "check", "", tmp_path)
    raw: dict[str, Json] = {
        "services": {
            "web": {"build": {"context": "/r/w", "args": None}},
            "app": {"build": {"context": "/r/a", "args": {}}},
            "db": {"image": "postgres:16"},
        }
    }
    assert refusal(cs, {}, raw) == (
        "instance-args",
        {"stack": "blank", "services": ["app", "web"]},
    )


def test_check_names_the_velo_form_of_build_args(tmp_path: Path) -> None:
    """``args: [VITE_API_BASE_URL]`` with no such value: ``config`` drops the
    key, ``--no-interpolate`` keeps it (``null``) -- ``pridem check`` is red."""
    root = repo(tmp_path)
    raw = _with(RAW, "frontend", build={"context": "/r/frontend", "args": None})
    code, verdict, _ = check(root, green_calls(root, raw=raw))
    assert code == 1
    assert _reason(verdict, "blank/compose") == {
        "code": "compose:instance-args",
        "stack": "blank",
        "services": ["frontend"],
    }
