"""Probes DM-47: the models load files written by primer.yaml 1.13 and passport 1.8.

Each probe pairs the contract's own example, which loads, with the old or wrong
form of the same field, which is refused with the rule it breaks.
"""

from pathlib import Path

from contract_support import FIXTURES, example, node, yaml_messages, yaml_problems
from passport_support import (
    EXAMPLE,
    passport_example,
    passport_messages,
    passport_problems,
    section,
)
from pydantic import SecretStr

from pridem.events import Secrets
from pridem.stacks.passport import load_passport
from pridem.stacks.schema import Param, Product, Service, load_primer_yaml


def test_probe_DM_47_contract_examples_load(tmp_path: Path) -> None:
    product = load_primer_yaml(FIXTURES / "product.yaml")
    service = load_primer_yaml(FIXTURES / "service.yaml")
    passport = load_passport(EXAMPLE)
    assert isinstance(product, Product) and isinstance(service, Service)
    aivis = product.stacks["aivis"]
    assert {name: (seed.run, seed.when) for name, seed in aivis.seeds.items()} == {
        "bootstrap": ("python -m app.seed bootstrap", "install"),
        "demo": ("python -m app.seed demo", "command"),
    }
    assert aivis.test is not None and aivis.test.target == "test"
    assert isinstance(product.env["SUPPORT_LANGUAGE"], Param)
    assert service.stacks["comms"].test is not None
    assert passport.params["aivis"]["SUPPORT_LANGUAGE"] == "ru"
    # the two examples describe one box: the param of stack aivis is in params.aivis
    assert product.name == "aivis" and set(passport.params) == {"aivis"}

    data = example("product.yaml")
    node(data, "stacks", "aivis", "seeds")["demo"] = "python -m app.seed demo"
    node(data, "stacks", "aivis")["test"] = "python -m pytest"
    assert yaml_problems(tmp_path, data) == [
        ("stacks.aivis.test", "R20.test-form"),
        ("stacks.aivis.seeds.demo", "R17.seed-form"),
    ]
    messages = yaml_messages(tmp_path, data)
    assert any("contract rule 17" in m and "{run, when}" in m for m in messages)
    assert any("contract rule 20" in m and "{run, target}" in m for m in messages)


def test_seed_and_test_objects_are_closed(tmp_path: Path) -> None:
    data = example("product.yaml")
    node(data, "stacks", "aivis", "seeds", "demo")["when"] = "update"
    del node(data, "stacks", "aivis", "test")["target"]
    assert yaml_problems(tmp_path, data) == [
        ("stacks.aivis.test.target", "missing"),
        ("stacks.aivis.seeds.demo.when", "literal_error"),
    ]
    data = example("product.yaml")
    del node(data, "stacks", "aivis", "seeds", "bootstrap")["when"]
    assert yaml_problems(tmp_path, data) == [
        ("stacks.aivis.seeds.bootstrap.when", "missing")
    ]


def test_seed_profiles_are_any_names(tmp_path: Path) -> None:
    """The machine knows no profile by name (rule 17)."""
    data = example("product.yaml")
    node(data, "stacks", "aivis")["seeds"] = {
        "partner-demo-2026": {"run": "python -m app.seed x", "when": "command"}
    }
    assert yaml_problems(tmp_path, data) == []


def test_frontend_build_args_are_gone(tmp_path: Path) -> None:
    """Rule 19: a build carries no instance values; the field no longer exists."""
    data = example("product.yaml")
    node(data, "stacks", "aivis", "frontend")["build_args"] = ["API_BASE_URL"]
    assert yaml_problems(tmp_path, data) == [
        ("stacks.aivis.frontend.build_args", "extra_forbidden")
    ]


def test_probe_DM_47_params_are_not_secrets_and_domains_are_lowercase(
    tmp_path: Path,
) -> None:
    long_param = "public-client-id-0123456789abcdef"
    data = passport_example()
    section(data, "params", "aivis")["CLIENT_ID"] = long_param
    section(data, "params")["comms"] = {"LANG": "ru"}
    assert passport_problems(tmp_path, data) == []
    passport = load_passport(EXAMPLE)
    assert passport.params["aivis"]["SUPPORT_LANGUAGE"] == "ru"
    secret_values = [
        value for stack in passport.asked.values() for value in stack.values()
    ]
    secrets = Secrets(secret_values)
    assert secrets.text("lang=ru meet=https://meet.aivis…") == (
        "lang=ru meet=https://meet.aivis…"
    )
    assert secrets.text(long_param) == long_param
    assert all(not isinstance(v, SecretStr) for v in passport.params["aivis"].values())

    data = passport_example()
    section(data, "domains")["api"] = "API-test.aivis.one"
    assert passport_problems(tmp_path, data) == [
        ("domains.api", "R15.domain-lowercase")
    ]
    assert any("passport rule 15" in m for m in passport_messages(tmp_path, data))
    section(data, "domains")["api"] = "api-test.aivis.one/v1"
    assert passport_problems(tmp_path, data) == [("domains.api", "value_error")]


def test_params_are_required_strings(tmp_path: Path) -> None:
    data = passport_example()
    del data["params"]
    assert passport_problems(tmp_path, data) == [("params", "missing")]
    data = passport_example()
    section(data, "params", "aivis")["TELEGRAM_ID"] = 12345
    assert passport_problems(tmp_path, data) == [
        ("params.aivis.TELEGRAM_ID", "string_type")
    ]
    data = passport_example()
    data["params"] = {}
    assert passport_problems(tmp_path, data) == []
