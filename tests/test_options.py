"""Options of an instance (DM-69; contract 3 rules 36-41, contract 1).

Three levels: a service declares the options it knows, the product those its
instances may have and those it needs, the passport those on. A variable under
``when:`` of an option that is off holds the literal; a dependency under it is
not installed; a host of ``egress`` under it is closed.
"""

from pathlib import Path

import pytest
from contract_support import yaml_problems
from env_support import (
    COMMS_REPO,
    box,
    derive,
    passport_data,
    product,
    product_data,
    read_env,
    render,
    run,
    service,
)
from passport_support import passport_example

from pridem.events import Secrets
from pridem.runner import FakeRunner
from pridem.stacks.env import placeholder
from pridem.stacks.options import LITERAL, flag, open_hosts, switched_on
from pridem.stacks.passport import PASSPORT
from pridem.stacks.schema import Product
from pridem.stacks.seams import (
    installed,
    outside_edition,
    seams_under_option,
)
from pridem.steps.base import StepFailed
from pridem.steps.build import Build
from pridem.steps.compose import OverrideHandoff
from pridem.steps.egress import Egress
from pridem.steps.env import SeamsCheck
from pridem.steps.passport import Fetched

ON = "invented-asked-value-on-0001"


def _passport(**change: object) -> object:
    return PASSPORT.validate_python({**passport_example(), **change})


# --- the loader ---------------------------------------------------------------


def test_when_names_an_option_of_its_own_stack(tmp_path: Path) -> None:
    """``when:`` of a variable, a dependency, a host -- only of ``options``."""
    data = product_data(
        {"A": {"source": "asked", "when": "meet"}, "B": {"source": "param"}},
        dependencies={"pay": {**COMMS_REPO, "when": "pay"}},
        options=["meet"],
    )
    data["egress"] = [{"host": "meet.example.org", "when": ["meet", "zoom"]}]
    assert yaml_problems(tmp_path, data) == [
        ("dependencies.pay.when", "R36.when-outside"),
        ("egress[0].when", "R36.when-outside"),
    ]
    data["options"] = ["meet", "pay", "zoom"]
    assert yaml_problems(tmp_path, data) == []  # the pair


def test_options_required_is_a_subset_and_names_are_once(tmp_path: Path) -> None:
    data = product_data({}, options=["meet", "meet"], options_required=["pay"])
    assert yaml_problems(tmp_path, data) == [
        ("options[1]", "S.option-duplicate"),
        ("options_required[0]", "R37.required-outside"),
    ]
    data["options"] = ["Meet"]
    assert ("options[0]", "S.option-name") in yaml_problems(tmp_path, data)


def test_a_seam_from_a_dependency_under_when_carries_it(tmp_path: Path) -> None:
    deps = {"pay": {**COMMS_REPO, "when": "pay"}}
    seam = {"source": "seam", "from": "pay"}
    data = product_data({"PAY_URL": seam}, dependencies=deps, options=["pay"])
    assert yaml_problems(tmp_path, data) == [("env.PAY_URL.when", "R38.seam-when")]
    data = product_data(
        {"PAY_URL": {**seam, "when": "pay"}}, dependencies=deps, options=["pay"]
    )
    assert yaml_problems(tmp_path, data) == []


def test_a_flag_names_an_option_of_its_stack(tmp_path: Path) -> None:
    """Hole 1 of the gate: ``options.<o>`` of the passport only for an option
    the stack declares."""
    flagged = {"MEET_ENABLED": {"source": "passport", "key": "options.zoom"}}
    data = product_data(flagged, options=["meet"])
    assert yaml_problems(tmp_path, data) == [
        ("env.MEET_ENABLED.key", "R38.flag-outside")
    ]


def test_a_service_by_edition_or_by_option_not_both(tmp_path: Path) -> None:
    data = product_data(
        {},
        dependencies={"comms": {**COMMS_REPO, "when": "chat"}},
        editions={"core": {"services": ["comms"]}},
        options=["chat"],
    )
    assert yaml_problems(tmp_path, data) == [
        ("dependencies.comms.when", "R41.edition-and-option")
    ]


def test_egress_is_a_name_or_a_host_with_options(tmp_path: Path) -> None:
    data = product_data({}, options=["meet"])
    data["egress"] = [
        "api.github.com",
        {"host": "meet.example.org", "when": ["meet"]},
        {"host": "api.github.com", "when": ["meet"]},
    ]
    assert yaml_problems(tmp_path, data) == [("egress[2]", "S.egress-duplicate")]
    data["egress"] = ["Bad.Host"]
    assert yaml_problems(tmp_path, data) == [("egress[0]", "S.egress-host")]


def test_passport_options_are_named_once_by_the_form() -> None:
    for options, code in (
        (["a", "a"], "R17.option-duplicate"),
        (["A"], "R17.option-name"),
    ):
        with pytest.raises(Exception, match=code):
            PASSPORT.validate_python({**passport_example(), "options": options})


# --- the options on ---------------------------------------------------------


def test_an_option_the_product_does_not_declare_is_off(tmp_path: Path) -> None:
    """The passport's options are on; one the product does not declare is
    refused before any act (``option-outside-product``, below), so an option
    of a service alone is never on."""
    passport = PASSPORT.validate_python({**passport_example(), "options": ["meet"]})
    assert switched_on(passport) == frozenset({"meet"})
    assert flag("options.meet", {"meet"}) == "true"
    assert flag("options.telegram", {"meet"}) == "false"


def test_open_hosts_are_names_and_hosts_of_an_option_on(tmp_path: Path) -> None:
    data = product_data({}, options=["meet", "zoom"])
    data["egress"] = [
        "api.github.com",
        {"host": "meet.example.org", "when": ["meet", "zoom"]},
    ]
    from env_support import load

    made = load(tmp_path, data)
    assert isinstance(made, Product)
    assert open_hosts(made, frozenset()) == ["api.github.com"]
    assert open_hosts(made, {"zoom"}) == ["api.github.com", "meet.example.org"]


def test_a_dependency_under_an_option_is_installed_when_it_is_on(
    tmp_path: Path,
) -> None:
    deps = {"comms": COMMS_REPO, "pay": {**COMMS_REPO, "when": "pay"}}
    made = product(tmp_path, {}, dependencies=deps, options=["pay"])
    assert installed(made, None, on=frozenset()) == ["comms"]
    assert installed(made, None, on={"pay"}) == ["comms", "pay"]


# --- seams_check ------------------------------------------------------------


def _check(tmp: Path, made: Product, services: dict, options: list[str] | None):  # type: ignore[no-untyped-def,type-arg]
    root, fetched = box(tmp, passport_data(edition=None, options=options))
    outcome, _ = run([SeamsCheck(made, services, fetched, root)], FakeRunner())
    return outcome.steps[0]


@pytest.mark.parametrize(
    ("options", "code"),
    [
        (["zoom"], "seams_check:option-outside-product"),
        ([], "seams_check:option-required-off"),
        (None, "seams_check:option-required-off"),
    ],
    ids=["outside", "required-off", "no-field"],
)
def test_options_of_the_passport_are_checked_before_any_act(
    tmp_path: Path, options: list[str] | None, code: str
) -> None:
    made = product(tmp_path, {}, options=["meet"], options_required=["meet"])
    step = _check(tmp_path, made, {}, options)
    assert step.reason is not None and step.reason.code == code
    # the pair: the required option on -- green
    assert _check(tmp_path / "on", made, {}, ["meet"]).reason is None


def test_a_seam_of_a_variable_under_an_option(tmp_path: Path) -> None:
    """Added 06.11: the consumer under ``when: o`` or with ``o`` required."""
    for sub in ("bare", "a", "under", "req"):
        (tmp_path / sub).mkdir()
    comms = service(
        tmp_path,
        {"BOT_URL": {"source": "derived", "run": "x", "when": "telegram"}},
        provides=["BOT_URL"],
        options=["telegram"],
    )
    seam = {"source": "seam", "from": "comms"}
    deps = {"comms": COMMS_REPO}
    bare = product(
        tmp_path / "bare", {"BOT_URL": seam}, dependencies=deps, options=["telegram"]
    )
    assert seams_under_option(bare, {"comms": comms}, None, on=frozenset()) == [
        "aivis.BOT_URL: comms under when: telegram"
    ]
    step = _check(tmp_path / "a", bare, {"comms": comms}, ["telegram"])
    assert step.reason is not None and step.reason.code == "seams_check:seam-option"
    under = product(
        tmp_path / "under",
        {"BOT_URL": {**seam, "when": "telegram"}},
        dependencies=deps,
        options=["telegram"],
    )
    required = product(
        tmp_path / "req",
        {"BOT_URL": seam},
        dependencies=deps,
        options=["telegram"],
        options_required=["telegram"],
    )
    for made in (under, required):  # the pair: both forms are taken
        assert seams_under_option(made, {"comms": comms}, None, on=frozenset()) == []


def test_a_seam_from_a_service_under_an_option_is_not_outside_the_edition(
    tmp_path: Path,
) -> None:
    deps = {"comms": COMMS_REPO, "pay": {**COMMS_REPO, "when": "pay"}}
    env = {"PAY_URL": {"source": "seam", "from": "pay", "when": "pay"}}
    made = product(
        tmp_path,
        env,
        dependencies=deps,
        editions={"core": {"services": ["comms"]}},
        options=["pay"],
    )
    assert outside_edition(made, "core", on=frozenset()) == []


# --- render_env -------------------------------------------------------------


SOURCES = {
    "ASKED": {"source": "asked", "when": "meet"},
    "PARAM": {"source": "param", "when": "meet"},
    "MINTED": {"source": "minted", "when": "meet"},
    "DERIVED": {"source": "derived", "run": "x", "when": "meet"},
    "ADDRESS": {"source": "address", "when": "meet"},
    "ROLE": {"source": "passport", "key": "server.role", "when": "meet"},
    "FLAG": {"source": "passport", "key": "options.meet"},
    "PLAIN": {"source": "param"},
}


def _stack(tmp: Path) -> Product:
    data = product_data(SOURCES, options=["meet"])
    data["stacks"]["aivis"]["app"] = {  # type: ignore[index]
        "service": "app",
        "port": 8000,
        "health": "/h",
        "ready": "/r",
    }
    from env_support import load

    made = load(tmp, data)
    assert isinstance(made, Product)
    return made


def test_every_source_of_an_option_off_is_the_literal(tmp_path: Path) -> None:
    """Off: nothing asked, minted, derived or read -- the literal on every
    key under the option, the flag ``false``; ``install`` writes the literal
    for the passport's absent fields."""
    made = _stack(tmp_path)
    root, fetched = box(tmp_path, passport_data(params={"aivis": {"PLAIN": "p"}}))
    asked: list[str] = []

    def ask(field: str, schema: object) -> str:
        asked.append(field)
        return "x"

    step = render(made, root, fetched, ask=ask)
    outcome, _ = run([step], FakeRunner())
    assert outcome.steps[0].reason is None, outcome.steps
    env = read_env(root, "aivis")
    for key in ("ASKED", "PARAM", "MINTED", "DERIVED", "ADDRESS", "ROLE"):
        assert env[key] == LITERAL, key
    assert (env["FLAG"], env["PLAIN"]) == ("false", "p")
    assert asked == []
    assert not (root / "opt" / "aivis" / "env" / "minted.yaml").exists()
    copy = fetched.passport
    assert copy is not None
    assert copy.asked["aivis"]["ASKED"].get_secret_value() == LITERAL
    assert copy.params["aivis"]["PARAM"] == LITERAL
    assert derive(step, root).build is not None and step._derivable() == []


def test_an_option_on_takes_every_source(tmp_path: Path) -> None:
    """The pair: on -- the values, the flag ``true``, ``minted`` minted."""
    made = _stack(tmp_path)
    data = passport_data(
        asked={"aivis": {"ASKED": ON}},
        params={"aivis": {"PARAM": "a param", "PLAIN": "p"}},
        options=["meet"],
    )
    root, fetched = box(tmp_path, data)
    step = render(made, root, fetched)
    outcome, _ = run([step], FakeRunner())
    assert outcome.steps[0].reason is None, outcome.steps
    env = read_env(root, "aivis")
    assert (env["ASKED"], env["PARAM"], env["FLAG"]) == (ON, "a param", "true")
    assert env["ADDRESS"] == "http://aivis-app:8000"
    assert len(env["MINTED"]) >= 32 and env["MINTED"] != LITERAL
    assert step._derivable() == ["DERIVED"]


@pytest.mark.parametrize(
    ("options", "asked", "code"),
    [
        (None, {"ASKED": ON}, "render_env:option-value"),
        (["meet"], {"ASKED": LITERAL}, "render_env:option-literal"),
    ],
    ids=["value-on-off", "literal-on-on"],
)
def test_the_pair_option_and_literal_is_checked(
    tmp_path: Path, options: list[str] | None, asked: dict[str, str], code: str
) -> None:
    made = _stack(tmp_path)
    data = passport_data(
        asked={"aivis": asked}, params={"aivis": {"PLAIN": "p"}}, options=options
    )
    root, fetched = box(tmp_path, data)
    outcome, _ = run([render(made, root, fetched)], FakeRunner())
    assert outcome.steps[0].reason is not None
    assert outcome.steps[0].reason.code == code


def test_the_literal_on_a_key_without_when_is_a_placeholder(tmp_path: Path) -> None:
    """Hole 2 of the gate: ``placeholder`` knows the literal; ``read_back``
    takes it on a key of an option off only (contract 3 rule 39), and a key of
    an option off holds nothing else."""
    assert placeholder(LITERAL)
    made = _stack(tmp_path)
    root, fetched = box(tmp_path, passport_data(params={"aivis": {"PLAIN": "p"}}))
    step = render(made, root, fetched)
    run([step], FakeRunner())
    assert step.read_back(waiting=()).fact["keys"] == len(SOURCES)
    env_file = root / "opt" / "aivis" / "env" / ".env"
    text = env_file.read_text()
    env_file.write_text(text.replace("PLAIN='p'", f"PLAIN='{LITERAL}'"))
    with pytest.raises(StepFailed) as refused:
        step.read_back(waiting=())
    assert refused.value.args[0] == "placeholder"
    env_file.write_text(text.replace(f"PARAM='{LITERAL}'", "PARAM='a value'"))
    with pytest.raises(StepFailed) as astray:
        step.read_back(waiting=())
    assert astray.value.args[0] == "option-value"


def test_the_literal_of_asked_is_a_secret(tmp_path: Path) -> None:
    """As any value of ``asked`` (handoff, prohibitions): the literal the
    passport holds enters the run's secrets."""
    made = _stack(tmp_path)
    data = passport_data(
        asked={"aivis": {"ASKED": LITERAL}}, params={"aivis": {"PLAIN": "p"}}
    )
    root, fetched = box(tmp_path, data)
    secrets = Secrets(())
    run([render(made, root, fetched, secrets=secrets)], FakeRunner())
    assert secrets.text(LITERAL) == "[redacted]"


# --- egress -------------------------------------------------------------------


def _with_meet(tmp: Path) -> Product:
    data = product_data({}, options=["meet"])
    data["egress"] = [{"host": "meet.example.org", "when": ["meet"]}]
    from env_support import load

    made = load(tmp, data)
    assert isinstance(made, Product)
    return made


@pytest.mark.parametrize(
    ("options", "hosts", "proxied"),
    [(None, [], False), (["meet"], ["meet.example.org"], True)],
    ids=["off", "on"],
)
def test_the_proxy_opens_the_hosts_of_options_on(
    tmp_path: Path, options: list[str] | None, hosts: list[str], proxied: bool
) -> None:
    """Rule 40: a host of an option off is closed -- no row in squid's list,
    and with no host open no proxy and no ``HTTPS_PROXY`` in the override."""
    made = _with_meet(tmp_path)
    passport = PASSPORT.validate_python(
        {**passport_example(), **({"options": options} if options else {})}
    )
    fetched = Fetched(passport=passport)
    assert Egress(made, fetched=fetched, root=tmp_path).hosts == hosts
    build = Build(
        made,
        "aivis",
        release=tmp_path / "r",
        ref="main",
        commit="0" * 40,
        root=tmp_path,
        handoff=OverrideHandoff(),
        fetched=fetched,
    )
    assert build._proxied() is proxied
