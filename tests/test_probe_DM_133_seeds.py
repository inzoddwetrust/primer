"""The probes of DM-133: seeds are taken back by the product's commands.

Owner's decision of 23.11: seeding and taking seeds back are the product's;
the machine runs its commands, checks the role and the server's name, keeps the
trace, and touches no data itself. ``seed --reset`` was ``db reset`` of the
whole database and then the seed; now it is the profile's ``reset``. A command
the product did not declare is refused, never a wipe.

- ``seed --profile <n> --reset`` -- the profile's ``reset`` (its data back and
  seeded again);
- ``seed --profile <n> --reset-only`` -- the profile's ``reset_only``;
- ``seed --reset-all`` -- the entry's ``seeds_reset_all``, on the roles of
  every profile.
"""

from pathlib import Path

import pytest
from data_support import STACK
from test_verbs_data import _cli, _verdict, config_call
from test_verbs_seeds_and_reset import _command_call, _with_seeds, image_calls

from pridem.events import Json
from pridem.report.codes import ExitCode
from pridem.runner import FakeCall, FakeRunner
from pridem.stacks.loader import ContractError
from pridem.stacks.schema import PRIMER_YAML, rule_problems
from pridem.steps.compose import ComposeStack
from pridem.steps.data import SeedReset

CONFIRM = ("--confirm", "box-1")
"""The server's name of ``blank_box``."""

RESET = "python -m app.seed demo --reset"
RESET_ONLY = "python -m app.seed demo --reset-only"
RESET_ALL = "python -m app.seed demo --reset-all"


def _seeds(**fields: str) -> dict[str, Json]:
    """``demo`` -- a profile of ``when: command`` with ``fields`` (``reset``,
    ``reset_only``); ``bootstrap`` -- of ``when: install``."""
    return {
        "demo": {"run": "python -m app.seed demo", "when": "command", **fields},
        "bootstrap": {"run": "python -m app.seed bootstrap", "when": "install"},
    }


def _with(
    root: Path,
    seeds: dict[str, Json],
    *,
    role: str = "test",
    reset_all: str | None = None,
) -> ComposeStack:
    """A box of the blank whose entry has ``seeds`` and, if given,
    ``seeds_reset_all``."""
    import yaml

    cs = _with_seeds(root, role, seeds)
    if reset_all is not None:
        release = (root / "opt" / STACK / "current").resolve()
        primer = yaml.safe_load((release / "primer.yaml").read_text())
        primer["stacks"][STACK]["seeds_reset_all"] = reset_all
        (release / "primer.yaml").write_text(yaml.safe_dump(primer, sort_keys=False))
    return cs


def _running(cs: ComposeStack, *tail: str) -> list[FakeCall]:
    """The whole script of one command of the product: the release's image
    asked first (``check``), then ``python -m app.seed demo <tail>``. The
    script is strict: a ``psql``, an ``alembic``, a ``stop`` or a ``start``
    -- what a wipe of the database runs -- would be an unplanned command."""
    return [config_call(cs), *image_calls(cs), _command_call(cs, *tail)]


# --- probes ---------------------------------------------------------------------


def test_probe_DM_133_reset_runs_the_products_command(tmp_path: Path) -> None:
    """``--reset``: one step ``seed_reset`` runs the profile's ``reset`` in a
    one-off container of the app -- no ``psql``, no ``alembic``, no service
    stopped or started (the strict script holds none), no ``db_reset``, no
    ``seed`` after it: the product's command seeds again itself. The fact
    names the mode and the profile. The pair: ``seed`` alone runs ``run``."""
    cs = _with(tmp_path, _seeds(reset=RESET))
    argv = ["seed", STACK, "--profile", "demo", "--reset", *CONFIRM]
    with FakeRunner(*_running(cs, "--reset")) as runner:
        code, out, _ = _cli(tmp_path, argv, runner)
    verdict = _verdict(out)
    assert code == 0, verdict.steps
    assert [(s.name, s.status) for s in verdict.steps] == [("seed_reset", "ok")]
    assert verdict.steps[0].verify == {
        "stack": STACK,
        "mode": "reset",
        "profile": "demo",
    }
    assert verdict.args == {
        "stack": STACK,
        "profile": "demo",
        "reset": True,
        "confirm": "box-1",
    }
    # the pair: seed alone -- the profile's run, the step seed
    with FakeRunner(*_running(cs)) as runner:
        code, out, _ = _cli(tmp_path, ["seed", STACK, "--profile", "demo"], runner)
    assert code == 0
    assert [s.name for s in _verdict(out).steps] == ["seed"]


def test_probe_DM_133_no_reset_refuses_and_never_wipes(tmp_path: Path) -> None:
    """A profile without ``reset`` -- ``--reset`` is refused before the run:
    exit 1, no verdict, no command at all (an empty strict script), and the
    refusal says where each thing is: the whole database -- ``pridem db
    reset``; the seeds -- the field to declare. The same for ``--reset-only``
    without ``reset_only`` and ``--reset-all`` without ``seeds_reset_all``.
    The pair is the probe above: the same profile with ``reset`` runs it."""
    _with(tmp_path, _seeds())
    for flags, field in (
        (["--profile", "demo", "--reset"], "reset"),
        (["--profile", "demo", "--reset-only"], "reset_only"),
        (["--reset-all"], "seeds_reset_all"),
    ):
        with FakeRunner() as runner:
            code, out, err = _cli(tmp_path, ["seed", STACK, *flags, *CONFIRM], runner)
        assert (code, out) == (1, ""), err
        assert f"declares no {field}" in err, err
        assert f"pridem db reset {STACK}" in err, err
        assert f"declare {field} in primer.yaml" in err, err
    history = tmp_path / "opt" / "pridem" / "history"
    assert not history.exists() or list(history.iterdir()) == []


def test_probe_DM_133_reset_only_runs_the_products_command(tmp_path: Path) -> None:
    """``--reset-only``: the profile's ``reset_only``, one step
    ``seed_reset`` of mode ``reset-only`` -- not its ``reset``, nothing
    after it, nothing wiped. The pair: ``--reset`` of the same profile runs
    the other command."""
    cs = _with(tmp_path, _seeds(reset=RESET, reset_only=RESET_ONLY))
    argv = ["seed", STACK, "--profile", "demo", "--reset-only", *CONFIRM]
    with FakeRunner(*_running(cs, "--reset-only")) as runner:
        code, out, _ = _cli(tmp_path, argv, runner)
    verdict = _verdict(out)
    assert code == 0, verdict.steps
    assert [s.name for s in verdict.steps] == ["seed_reset"]
    assert verdict.steps[0].verify == {
        "stack": STACK,
        "mode": "reset-only",
        "profile": "demo",
    }
    assert verdict.args["reset_only"] is True
    reset = ["seed", STACK, "--profile", "demo", "--reset", *CONFIRM]
    with FakeRunner(*_running(cs, "--reset")) as runner:
        code, out, _ = _cli(tmp_path, reset, runner)
    assert code == 0
    assert _verdict(out).steps[0].verify["mode"] == "reset"  # type: ignore[index]


def test_probe_DM_133_reset_all_runs_the_products_command(tmp_path: Path) -> None:
    """``--reset-all``: the entry's ``seeds_reset_all``, one step
    ``seed_reset`` of mode ``reset-all`` with no profile in its fact,
    nothing wiped. The pair: with ``--profile`` it is refused -- the command
    is the entry's, not a profile's."""
    cs = _with(tmp_path, _seeds(), reset_all=RESET_ALL)
    argv = ["seed", STACK, "--reset-all", *CONFIRM]
    with FakeRunner(*_running(cs, "--reset-all")) as runner:
        code, out, _ = _cli(tmp_path, argv, runner)
    verdict = _verdict(out)
    assert code == 0, verdict.steps
    assert [s.name for s in verdict.steps] == ["seed_reset"]
    assert verdict.steps[0].verify == {"stack": STACK, "mode": "reset-all"}
    assert verdict.args == {"stack": STACK, "reset_all": True, "confirm": "box-1"}
    with FakeRunner() as runner:
        code, out, err = _cli(
            tmp_path,
            ["seed", STACK, "--profile", "demo", "--reset-all", *CONFIRM],
            runner,
        )
    assert (code, out) == (1, "") and "no --profile" in err


# --- around the probes -----------------------------------------------------------


@pytest.mark.parametrize(
    ("roles", "role", "allowed"),
    [
        pytest.param({"demo": ["test"]}, "test", True, id="one-profile-in"),
        pytest.param({"demo": ["test"]}, "prod", False, id="one-profile-out"),
        pytest.param(
            {"demo": ["test", "prod"], "staff": ["prod", "preview"]},
            "prod",
            True,
            id="both-allow",
        ),
        pytest.param(
            {"demo": ["test", "prod"], "staff": ["prod", "preview"]},
            "test",
            False,
            id="the-second-refuses",
        ),
        pytest.param(
            {"demo": ["test", "prod"], "staff": ["prod", "preview"]},
            "preview",
            False,
            id="the-first-refuses",
        ),
        pytest.param({"demo": None, "staff": None}, "preview", True, id="no-roles"),
        pytest.param({}, "prod", True, id="no-profiles"),
    ],
)
def test_reset_all_runs_on_the_roles_of_every_profile(
    tmp_path: Path, roles: dict[str, list[str] | None], role: str, allowed: bool
) -> None:
    """``--reset-all`` takes back the data of every profile: it runs on a role
    each of them allows -- as strict as the strictest; a profile without
    ``roles`` allows every role; an entry without profiles -- every role.
    Refused under the lock with no command run; allowed -- the command runs."""
    seeds: dict[str, Json] = {
        name: {
            "run": f"python -m app.seed {name}",
            "when": "command",
            **({"roles": list[Json](given)} if given is not None else {}),
        }
        for name, given in roles.items()
    }
    cs = _with(tmp_path, seeds, role=role, reset_all=RESET_ALL)
    argv = ["seed", STACK, "--reset-all", *CONFIRM]
    script = _running(cs, "--reset-all") if allowed else []
    with FakeRunner(*script) as runner:
        code, out, err = _cli(tmp_path, argv, runner)
    if allowed:
        assert code == 0, err
    else:
        assert (code, out) == (1, "") and f"not for the role {role}" in err, err


@pytest.mark.parametrize(
    ("argv", "said"),
    [
        (["--profile", "demo", "--reset", "--reset-only"], "one reset at a time"),
        (["--reset-all", "--profile", "demo", "--reset"], "one reset at a time"),
        (["--profile", "demo", "--reset-only", "--dry-run"], "resets nothing"),
        (["--reset-all", "--dry-run"], "resets nothing"),
        (["--profile", "demo", "--reset"], "--confirm <server.name>"),
        (["--reset-all"], "--confirm <server.name>"),
        (["--profile", "demo", "--confirm", "box-1"], "goes with --reset"),
        (["--profile", "bootstrap", "--reset"], "install only"),
    ],
)
def test_resets_are_refused_before_the_run(
    tmp_path: Path, argv: list[str], said: str
) -> None:
    """Refused before the run, nothing ran: two resets at once, a reset with
    ``--dry-run``, a reset without ``--confirm``, ``--confirm`` without a
    reset, a profile of ``when: install``."""
    _with(tmp_path, _seeds(reset=RESET, reset_only=RESET_ONLY), reset_all=RESET_ALL)
    full = ["seed", STACK, *argv]
    if "--confirm" not in argv and said not in ("--confirm <server.name>",):
        full = [*full, *CONFIRM]
    with FakeRunner() as runner:
        code, out, err = _cli(tmp_path, full, runner)
    assert (code, out) == (1, ""), err
    assert said in err, err


@pytest.mark.parametrize("flag", ["--reset", "--reset-only", "--reset-all"])
def test_a_reset_names_the_server(tmp_path: Path, flag: str) -> None:
    """Every reset is destructive: another server's name is refused under
    the lock, nothing ran."""
    _with(tmp_path, _seeds(reset=RESET, reset_only=RESET_ONLY), reset_all=RESET_ALL)
    profile = [] if flag == "--reset-all" else ["--profile", "demo"]
    argv = ["seed", STACK, *profile, flag, "--confirm", "box-2"]
    with FakeRunner() as runner:
        code, out, err = _cli(tmp_path, argv, runner)
    assert (code, out) == (1, "") and "--confirm box-1 to go on" in err, err


def test_a_reset_outside_the_profiles_roles_is_refused(tmp_path: Path) -> None:
    """``--reset`` and ``--reset-only`` run on the roles of their profile:
    ``prod`` outside ``[test]`` -- refused, nothing ran. The pair -- inside
    -- is the probe."""
    seeds = _seeds(reset=RESET, reset_only=RESET_ONLY)
    demo = seeds["demo"]
    assert isinstance(demo, dict)
    demo["roles"] = ["test"]
    _with(tmp_path, seeds, role="prod")
    for flag in ("--reset", "--reset-only"):
        with FakeRunner() as runner:
            code, out, err = _cli(
                tmp_path, ["seed", STACK, "--profile", "demo", flag, *CONFIRM], runner
            )
        assert (code, out) == (1, "") and "not for the role prod" in err, err


def test_a_red_reset_is_past_the_point_of_no_return(tmp_path: Path) -> None:
    """The product's reset exits 1: red by its command, and a restore is
    needed -- what it took back may be gone. The step is the point of no
    return."""
    cs = _with(tmp_path, _seeds(reset=RESET))
    red = [
        *_running(cs, "--reset")[:-1],
        FakeCall(_command_call(cs, "--reset").argv, code=1),
    ]
    argv = ["seed", STACK, "--profile", "demo", "--reset", *CONFIRM]
    with FakeRunner(*red) as runner:
        code, out, _ = _cli(tmp_path, argv, runner)
    verdict = _verdict(out)
    assert verdict.exit_code == ExitCode.FAILED
    [step] = verdict.steps
    assert step.status == "failed" and step.reason is not None
    assert step.reason.code == "command-failed", step.reason
    assert [i.what for i in verdict.report.incomplete] == ["restore"]


def test_a_reset_on_an_image_of_another_release_never_runs(tmp_path: Path) -> None:
    """The app's image is not of the current release (a red deploy since):
    ``seed_reset:image-not-current`` before the product's command -- the
    script has no command of it."""
    cs = _with(tmp_path, _seeds(reset=RESET))
    other = [config_call(cs), *image_calls(cs, commit="0" * 40)]
    argv = ["seed", STACK, "--profile", "demo", "--reset", *CONFIRM]
    with FakeRunner(*other) as runner:
        code, out, _ = _cli(tmp_path, argv, runner)
    [step] = _verdict(out).steps
    assert step.reason is not None
    assert step.reason.code == "seed_reset:image-not-current", step.reason
    assert not _verdict(out).report.incomplete  # nothing acted: no restore


def _product(seeds: dict[str, Json], **entry: Json) -> dict[str, Json]:
    return {
        "schema": 1,
        "name": STACK,
        "kind": "product",
        "stacks": {
            STACK: {
                "compose": "docker-compose.yml",
                "app": {"service": "app", "port": 8000, "health": "/h", "ready": "/r"},
                "seeds": seeds,
                **entry,
            }
        },
        "env": {},
        "report": {"health": "/h", "ready": "/r", "logs": "json", "junit": True},
    }


@pytest.mark.parametrize("field", ["reset", "reset_only"])
def test_a_reset_of_an_install_profile_is_refused_by_the_loader(field: str) -> None:
    """``reset`` or ``reset_only`` on a profile of ``when: install`` --
    ``R17.seed-reset``: the verb never runs such a profile, so nothing would
    run its reset. The pair: the same field on ``when: command`` loads."""
    install = _product(
        {"bootstrap": {"run": "python -m app.seed b", "when": "install", field: RESET}}
    )
    problems = rule_problems(PRIMER_YAML.validate_python(install))
    assert [(p.code, p.path) for p in problems] == [
        ("R17.seed-reset", f"stacks.{STACK}.seeds.bootstrap.{field}")
    ]
    command = _product(
        {"demo": {"run": "python -m app.seed demo", "when": "command", field: RESET}}
    )
    assert rule_problems(PRIMER_YAML.validate_python(command)) == []


@pytest.mark.parametrize(
    ("where", "value"),
    [
        ("reset", ""),
        ("reset_only", "a 'b"),
        ("seeds_reset_all", ""),
    ],
)
def test_a_reset_command_has_the_form_of_run(
    tmp_path: Path, where: str, value: str
) -> None:
    """Twin SHORTAGE: an empty command or one ``shlex`` cannot split is
    refused by the loader, as ``run``."""
    from pridem.stacks.schema import load_primer_yaml

    seeds: dict[str, Json] = {
        "demo": {"run": "python -m app.seed demo", "when": "command"}
    }
    entry: dict[str, Json] = {}
    if where == "seeds_reset_all":
        entry["seeds_reset_all"] = value
    else:
        demo = seeds["demo"]
        assert isinstance(demo, dict)
        demo[where] = value
    import yaml

    file = tmp_path / "primer.yaml"
    file.write_text(yaml.safe_dump(_product(seeds, **entry)))
    with pytest.raises(ContractError):
        load_primer_yaml(file)


@pytest.mark.parametrize(
    ("mode", "profile", "text"),
    [
        ("reset", "demo", "take back the seed demo of {stack} and seed it again"),
        ("reset-only", "demo", "take back the seed demo of {stack}"),
        ("reset-all", None, "take back every seed of {stack}"),
    ],
)
def test_check_says_by_its_mode_what_it_would_take_back(
    tmp_path: Path, mode: str, profile: str | None, text: str
) -> None:
    """The code of ``check`` -- what ``doctor`` and the console say -- is the
    mode's own, with the profile where there is one, and has its text."""
    from env_support import context

    cs = _with(tmp_path, _seeds())
    step = SeedReset(cs, mode, "python -m app.seed demo", profile)  # type: ignore[arg-type]
    with FakeRunner(config_call(cs), *image_calls(cs)) as runner:
        found = step.check(context(runner))
    assert found.needed and found.would is not None
    named = {} if profile is None else {"profile": profile}
    assert (found.would.code, dict(found.would.params)) == (
        mode,  # the plan names it seed_reset:<mode>
        {"entry": STACK, **named},
    )
    assert step.codes[mode].format(entry=STACK, profile=profile) == text.format(
        stack=STACK
    )


def test_a_reset_all_step_has_no_profile_and_a_profile_step_has_one() -> None:
    """The step's own guard: ``reset-all`` takes no profile, the others need
    one -- a fact without its profile is never built."""
    with pytest.raises(ValueError):
        SeedReset(None, "reset", RESET)  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        SeedReset(None, "reset-all", RESET_ALL, "demo")  # type: ignore[arg-type]
