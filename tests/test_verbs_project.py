"""DM-86, pass 3: the verbs of the project -- ``verb <name> [<arg>=<value>
...] [--confirm <server.name>]`` in the declared service of the product's own
entry; and the volumes of a ``persistent`` entry through ``destroy`` and
``reinstall``."""

import json
from pathlib import Path

import pytest
import yaml
from data_support import STACK, blank_box
from passport_support import section
from test_verbs_data import _cli, _verdict, compose, running_call

from pridem.events import Json
from pridem.runner import FakeCall, FakeRunner
from pridem.stacks.schema import PRIMER_YAML, Product, rule_problems
from pridem.steps.compose import ComposeStack, forbidden
from pridem.steps.passport import PASSPORT_COPY

MINTED = "m" * 43
ASKED = "<secret: 16+ chars>"
TLS_CERT = "-----BEGIN CERTIFICATE-----\nAAAAtier1certAAAA\n-----END CERTIFICATE-----\n"
TLS_KEY = "-----BEGIN PRIVATE KEY-----\nAAAAtier1keyAAAAA\n-----END PRIVATE KEY-----\n"
VERBS: dict[str, Json] = {
    "set-setting": {
        "run": "python -m app.cli set-setting",
        "args": ["key", "value"],
        "destructive": True,
    },
    "count-settings": {
        "run": "psql -U blank -d blank -tAc 'SELECT count(*) FROM app_settings'",
        "service": "postgres",
        "roles": ["test"],
    },
}


def _box(
    fs_root: Path, role: str = "test", verbs: dict[str, Json] = VERBS
) -> ComposeStack:
    """The blank's box with ``verbs``, a minted secret and a passport with
    ``asked`` and ``tls``."""
    blank_box(fs_root, role=role, name="box-1")
    release = (fs_root / "opt" / STACK / "current").resolve()
    primer = yaml.safe_load((release / "primer.yaml").read_text())
    primer["verbs"] = verbs
    (release / "primer.yaml").write_text(yaml.safe_dump(primer, sort_keys=False))
    minted = fs_root / "opt" / STACK / "env" / "minted.yaml"
    minted.parent.mkdir(parents=True, exist_ok=True)
    minted.write_text(yaml.safe_dump({"POSTGRES_PASSWORD": MINTED}))
    minted.chmod(0o600)
    copy = fs_root / PASSPORT_COPY
    data = yaml.safe_load(copy.read_text())
    policies = section(data, "policies")
    policies["ssl"] = "provided"
    policies["tls"] = {"cert": TLS_CERT, "key": TLS_KEY}
    copy.write_text(yaml.safe_dump(data, sort_keys=False))
    return compose(fs_root)


def _exec(cs: ComposeStack, service: str, *argv: str, code: int = 0) -> FakeCall:
    """The command as docker gets it, written out (par0 14.2): ``docker
    compose ... exec -T <service> <run> <values>``."""
    return FakeCall(tuple(cs.argv("exec", "-T", service, *argv)), code=code)


SET = ("python", "-m", "app.cli", "set-setting")


# --- probes ------------------------------------------------------------------------


def test_probe_DM_22_project_verb_outside_role_is_refused(tmp_path: Path) -> None:
    """``count-settings`` is for ``test``: on ``preview`` -- refused, nothing
    ran (an empty script); on ``test`` -- it runs in its service."""
    _box(tmp_path, role="preview")
    with FakeRunner() as runner:
        code, out, err = _cli(tmp_path, ["verb", "count-settings"], runner)
    assert (code, out) == (1, "") and "not for the role preview" in err
    other = tmp_path / "test"
    other.mkdir()
    cs = _box(other)
    count = (
        "psql",
        "-U",
        "blank",
        "-d",
        "blank",
        "-tAc",
        "SELECT count(*) FROM app_settings",
    )
    calls = [running_call(cs, "postgres", "c-pg"), _exec(cs, "postgres", *count)]
    with FakeRunner(*calls) as runner:
        code, out, _ = _cli(other, ["verb", "count-settings"], runner)
    verdict = _verdict(out)
    assert code == 0
    assert verdict.steps[0].verify == {
        "verb": "count-settings",
        "service": "postgres",
        "exit_code": 0,
    }


@pytest.mark.parametrize(
    ("pairs", "said"),
    [
        (["key=a"], "value not given"),
        (["key=a", "value=b", "other=c"], "no argument other"),
        (["key=a", "key=b", "value=c"], "key is given twice"),
        (["key=", "value=b"], "key is empty"),
        (["key=a", "b"], "'b' is not <arg>=<value>"),
    ],
    ids=["missing", "unknown", "twice", "empty", "positional"],
)
def test_probe_DM_22_project_verb_bad_args_refused_before_run(
    tmp_path: Path, pairs: list[str], said: str
) -> None:
    """Refused before the run: nothing ran (an empty script), no verdict. The
    pair is the destructive probe: both arguments, each once -- it runs."""
    _box(tmp_path)
    argv = ["verb", "set-setting", *pairs, "--confirm", "box-1"]
    with FakeRunner() as runner:
        code, out, err = _cli(tmp_path, argv, runner)
    assert (code, out) == (1, ""), err
    assert said in err


@pytest.mark.parametrize(
    "secret",
    [ASKED, TLS_CERT, TLS_KEY, MINTED, f"  {MINTED} "],
    ids=["asked", "tls-cert", "tls-key", "minted", "minted-padded"],
)
def test_probe_DM_22_project_verb_secret_arg_refused_before_run(
    tmp_path: Path, secret: str
) -> None:
    """Contract 3 rule 7: an argument equal to a known secret of the box --
    ``asked``, ``tls``, ``minted`` -- refused before the run; the refusal names
    the argument, not its value; no command, no verdict, no journal. The
    pair: an ordinary value runs."""
    cs = _box(tmp_path)
    argv = ["verb", "set-setting", "key=k", f"value={secret}", "--confirm", "box-1"]
    with FakeRunner() as runner:
        code, out, err = _cli(tmp_path, argv, runner)
    assert (code, out) == (1, "")
    assert "value is a secret of the box" in err
    assert secret.strip() not in err
    assert not (tmp_path / "opt" / "pridem" / "journal").exists() or not any(
        secret.strip() in p.read_text()
        for p in (tmp_path / "opt" / "pridem" / "journal").iterdir()
    )
    calls = [running_call(cs, "app", "c-app"), _exec(cs, "app", *SET, "k", "plain")]
    with FakeRunner(*calls) as runner:
        code, out, _ = _cli(
            tmp_path,
            ["verb", "set-setting", "key=k", "value=plain", "--confirm", "box-1"],
            runner,
        )
    assert code == 0, _verdict(out).steps


def test_probe_DM_22_destructive_verb_asks_the_server_s_name_on_any_role(
    tmp_path: Path,
) -> None:
    """Protocol 1.11 to 8.2: ``set-setting`` is destructive. On ``test``
    without ``--confirm`` -- refused, nothing ran; another name -- refused;
    the box's name -- it runs in ``app`` (the default service), the values in
    the order of ``args`` whatever the order given."""
    cs = _box(tmp_path)
    for confirm in ([], ["--confirm", "box-2"]):
        with FakeRunner() as runner:
            code, out, err = _cli(
                tmp_path, ["verb", "set-setting", "key=k", "value=v", *confirm], runner
            )
        assert (code, out) == (1, "") and "--confirm box-1" in err
    calls = [running_call(cs, "app", "c-app"), _exec(cs, "app", *SET, "k", "v")]
    with FakeRunner(*calls) as runner:
        code, out, _ = _cli(
            tmp_path,
            ["verb", "set-setting", "value=v", "key=k", "--confirm", "box-1"],
            runner,
        )
    verdict = _verdict(out)
    assert code == 0
    assert verdict.args == {
        "name": "set-setting",
        "args": {"value": "v", "key": "k"},
        "confirm": "box-1",
    }
    assert verdict.steps[0].verify == {
        "verb": "set-setting",
        "service": "app",
        "exit_code": 0,
    }


# --- the rest ------------------------------------------------------------------------


def test_a_verb_whose_service_does_not_run_is_red_before_it_runs(
    tmp_path: Path,
) -> None:
    cs = _box(tmp_path)
    with FakeRunner(running_call(cs, "postgres")) as runner:
        code, out, _ = _cli(tmp_path, ["verb", "count-settings"], runner)
    reason = _verdict(out).steps[0].reason
    assert code == 1 and reason is not None
    assert reason.model_dump() == {
        "code": "project_verb:service-down",
        "stack": STACK,
        "service": "postgres",
        "verb": "count-settings",
    }


def test_a_red_verb_is_red_with_its_command(tmp_path: Path) -> None:
    cs = _box(tmp_path)
    count = (
        "psql",
        "-U",
        "blank",
        "-d",
        "blank",
        "-tAc",
        "SELECT count(*) FROM app_settings",
    )
    calls = [
        running_call(cs, "postgres", "c-pg"),
        _exec(cs, "postgres", *count, code=2),
    ]
    with FakeRunner(*calls) as runner:
        code, out, _ = _cli(tmp_path, ["verb", "count-settings"], runner)
    reason = _verdict(out).steps[0].reason
    assert code == 1 and reason is not None and reason.code == "command-failed"


@pytest.mark.parametrize(
    ("argv", "said"),
    [
        (["verb", "ghost"], "no verb ghost"),
        (["verb", "count-settings", "--confirm", "box-1"], "for a destructive verb"),
    ],
)
def test_the_verb_verb_refuses_before_the_run(
    tmp_path: Path, argv: list[str], said: str
) -> None:
    _box(tmp_path)
    with FakeRunner() as runner:
        code, out, err = _cli(tmp_path, argv, runner)
    assert (code, out) == (1, "") and said in err


def test_the_minted_secrets_of_every_stack_of_the_box_count(tmp_path: Path) -> None:
    """``minted`` of a service on the box is as much a secret as the
    product's (gate: V10d)."""
    from test_verbs_data import _service

    _box(tmp_path)
    _service(tmp_path, "comms", with_database=True)
    other = "s" * 43
    minted = tmp_path / "opt" / "comms" / "env" / "minted.yaml"
    minted.parent.mkdir(parents=True)
    minted.write_text(yaml.safe_dump({"COMMS_TOKEN": other}))
    minted.chmod(0o600)
    argv = ["verb", "set-setting", "key=k", f"value={other}", "--confirm", "box-1"]
    with FakeRunner() as runner:
        code, out, err = _cli(tmp_path, argv, runner)
    assert (code, out) == (1, "") and "value is a secret of the box" in err


# --- the loader and compose ---------------------------------------------------


def _product(verbs: dict[str, Json], **entry: Json) -> dict[str, Json]:
    return {
        "schema": 1,
        "name": STACK,
        "kind": "product",
        "stacks": {
            STACK: {
                "compose": "docker-compose.yml",
                "app": {"service": "app", "port": 8000, "health": "/h", "ready": "/r"},
                **entry,
            }
        },
        "env": {},
        "verbs": verbs,
        "report": {"health": "/h", "ready": "/r", "logs": "json", "junit": True},
    }


def test_a_verb_runs_in_no_job_and_needs_an_app_when_it_names_no_service() -> None:
    made = PRIMER_YAML.validate_python(
        _product(
            {"v": {"run": "x", "service": "init"}}, jobs={"init": {"service": "init"}}
        )
    )
    assert [p.code for p in rule_problems(made)] == ["S.verb-service"]
    raw = _product({"v": {"run": "x"}})
    stacks = raw["stacks"]
    assert isinstance(stacks, dict)
    stage = stacks[STACK]
    assert isinstance(stage, dict)
    del stage["app"]
    assert [p.code for p in rule_problems(PRIMER_YAML.validate_python(raw))] == [
        "S.verb-service"
    ]
    fine = PRIMER_YAML.validate_python(_product({"v": {"run": "x", "service": "db"}}))
    assert rule_problems(fine) == []


def test_a_verb_whose_service_is_not_in_compose_is_named(tmp_path: Path) -> None:
    from compose_support import HEALTHCHECK

    made = PRIMER_YAML.validate_python(
        _product({"v": {"run": "x", "service": "ghost"}, "w": {"run": "y"}})
    )
    assert isinstance(made, Product)
    cs = ComposeStack(made, STACK, tmp_path / "r", "main", "0" * 40, tmp_path)
    cs.release.mkdir()
    healthy: dict[str, Json] = {"image": "a@sha256:x", "healthcheck": HEALTHCHECK}
    assert forbidden(cs, {"services": {"app": healthy}}) == [
        "verbs.v: no service ghost"
    ]
    assert forbidden(cs, {"services": {"app": healthy, "ghost": healthy}}) == []


# --- persistent --------------------------------------------------------------------


@pytest.mark.parametrize("mode", ["destroy", "reinstall"])
def test_probe_DM_22_persistent_volumes_survive_destroy_and_reinstall(
    tmp_path: Path, mode: str
) -> None:
    """Contract 3 rule 14: the volume of the ``persistent`` entry ``storage``
    is never named to ``docker volume rm`` -- by ``destroy`` and by the
    ``destroy`` of ``reinstall`` alike -- and the fact names it kept. The
    pair: the other entry's volume is removed."""
    from itertools import count

    from plan_support import ListSink
    from test_steps_destroy import box_with_release, docker, listed

    from pridem.plan import Plan, StackSteps
    from pridem.report.codes import ExitCode
    from pridem.steps.destroy import destroy_steps

    root, box = box_with_release(tmp_path, {"storage"})
    seen = listed(("c1",), ("pridem",), ("files\tstorage", "db\taivis"), ("sha256:1",))
    script = [
        docker(),
        *seen,
        docker(),
        *seen,
        FakeCall(("docker", "rm", "-f", "c1")),
        FakeCall(("docker", "volume", "rm", "db")),  # never "files"
        FakeCall(("docker", "network", "rm", "pridem")),
        FakeCall(("docker", "image", "rm", "-f", "sha256:1")),
        *listed(volumes=("files\tstorage",)),
    ]
    ticks = count()
    with box.lock(mode), FakeRunner(*script) as runner:
        outcome = Plan(
            [StackSteps("destroy", destroy_steps(root, box=box), root=True)],
            mode=mode,  # type: ignore[arg-type]
            role="test",
            runner=runner,
            sink=ListSink(),
            clock=lambda: float(next(ticks)),
        ).run()
    assert outcome.code is ExitCode.OK, outcome.steps
    assert outcome.steps[0].verify is not None
    assert outcome.steps[0].verify["kept_volumes"] == ["files"]
    kept = json.loads((box.root / "kept-volumes.json").read_text())
    assert kept["volumes"] == {"files": "storage"}
