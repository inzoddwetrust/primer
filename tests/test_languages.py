"""The languages of an instance (DM-46 stage B; protocol 5.2.2) and the
product's name against its repository's.

``primer.yaml`` of a product declares every language it has, the passport an
instance's subset and its default; ``seams_check`` checks them before the
first ``act``; every stack gets them through ``env`` (source ``passport``) by
one rendering -- codes joined by commas, in the passport's order. ``pridem
check`` refuses the form of a product's ``languages`` by the loader.
"""

import json
from pathlib import Path

import pytest
import yaml
from contract_support import example, yaml_problems
from env_support import (
    COMMS_REPO,
    box,
    load,
    passport_data,
    product_data,
    read_env,
    render,
    run,
    service_data,
)
from passport_support import passport_example, passport_problems
from services_support import remote, run_stacks
from test_probe_DM_57_check import _reason, check, repo

from pridem.plan import StackSteps
from pridem.report.codes import ExitCode
from pridem.runner import FakeRunner
from pridem.stacks.env import languages_value
from pridem.stacks.schema import Product, Service
from pridem.steps.env import SeamsCheck
from pridem.steps.sources import source_steps

LANGUAGES = {"source": "passport", "key": "languages"}
DEFAULT = {"source": "passport", "key": "default_language"}


# --- the form ---------------------------------------------------------------------


@pytest.mark.parametrize(
    ("languages", "found"),
    [
        (["en"], []),
        (["en", "ru", "uk", "haw"], []),
        ([], [("languages", "too_short")]),
        (["en-GB"], [("languages[0]", "string_pattern_mismatch")]),
        (["EN"], [("languages[0]", "string_pattern_mismatch")]),
        (["e"], [("languages[0]", "string_pattern_mismatch")]),
        (["en", "ru", "en"], [("languages", "value_error")]),
    ],
)
def test_a_products_languages_are_codes_once_each(
    tmp_path: Path, languages: list[str], found: list[tuple[str, str]]
) -> None:
    data = example("product.yaml")
    data["languages"] = languages
    assert yaml_problems(tmp_path, data) == found


def test_a_service_declares_no_languages(tmp_path: Path) -> None:
    """A service's languages are its product's: the field is not a service's."""
    data = example("service.yaml")
    data["languages"] = ["en"]
    assert yaml_problems(tmp_path, data) == [("languages", "extra_forbidden")]


@pytest.mark.parametrize(
    ("change", "found"),
    [
        ({"languages": ["en", "ru"], "default_language": "ru"}, []),
        ({}, []),
        ({"languages": ["en-GB"]}, [("languages[0]", "string_pattern_mismatch")]),
        ({"languages": ["en", "en"]}, [("languages", "value_error")]),
        ({"languages": []}, [("languages", "too_short")]),
        ({"default_language": "RU"}, [("default_language", "string_pattern_mismatch")]),
    ],
)
def test_a_passports_languages_are_codes_once_each(
    tmp_path: Path, change: dict[str, object], found: list[tuple[str, str]]
) -> None:
    data = passport_example()
    data.update(change)
    assert passport_problems(tmp_path, data) == found


def test_pridem_check_refuses_the_form_of_a_products_languages(tmp_path: Path) -> None:
    """``pridem check`` of a repository reads ``primer.yaml`` by the loader: a
    region is refused there, before any command."""
    root = repo(tmp_path)
    path = root / "primer.yaml"
    data = yaml.safe_load(path.read_text())
    data["languages"] = ["en", "en-GB"]
    path.write_text(yaml.safe_dump(data, sort_keys=False))
    code, verdict, _ = check(root, [])
    reason = _reason(verdict, "blank/primer_yaml")
    assert code == 1 and reason["code"] == "primer_yaml:invalid", reason
    assert "languages[1]" in json.dumps(reason)


# --- env --------------------------------------------------------------------------


def test_the_languages_render_in_the_passports_order_with_commas() -> None:
    assert languages_value(["uk", "en", "ru"]) == "uk,en,ru"
    assert languages_value(["en"]) == "en"


def test_every_stack_gets_the_languages_by_its_own_names(tmp_path: Path) -> None:
    """The product under ``LANGUAGES``, comms under its own names: the same
    rendering, the passport's order, no spaces."""
    made = load(
        tmp_path,
        {
            **product_data({"LANGUAGES": LANGUAGES, "DEFAULT_LANGUAGE": DEFAULT}),
            "languages": ["en", "ru", "uk"],
        },
    )
    assert isinstance(made, Product)
    comms = load(
        tmp_path,
        service_data({"COMMS_LANGUAGES": LANGUAGES, "COMMS_DEFAULT": DEFAULT}),
    )
    assert isinstance(comms, Service)
    data = passport_data()
    data.update({"languages": ["uk", "en"], "default_language": "en"})
    root, fetched = box(tmp_path, data)
    for stack in (made, comms):
        outcome, _ = run([render(stack, root, fetched, product=made)], FakeRunner())
        assert outcome.code is ExitCode.OK, outcome.steps
    assert read_env(root, "aivis") == {"LANGUAGES": "uk,en", "DEFAULT_LANGUAGE": "en"}
    assert read_env(root, "comms") == {
        "COMMS_LANGUAGES": "uk,en",
        "COMMS_DEFAULT": "en",
    }


# --- seams_check ------------------------------------------------------------------


def _check(
    tmp: Path,
    *,
    declared: list[str] | None,
    passport: dict[str, object],
    taken: bool = False,
) -> tuple[str | None, dict[str, object]]:
    """``seams_check`` of a product declaring ``declared`` (``None`` -- no
    ``languages``), comms taking the languages when ``taken``; its code and
    parameters, ``None`` when green."""
    data = product_data({}, dependencies={"comms": COMMS_REPO})
    if declared is not None:
        data["languages"] = declared
    made = load(tmp, data)
    assert isinstance(made, Product)
    comms = load(tmp, service_data({"LANGUAGES": LANGUAGES} if taken else {}))
    assert isinstance(comms, Service)
    root, fetched = box(tmp, {**passport_data(edition=None), **passport})
    outcome, _ = run([SeamsCheck(made, {"comms": comms}, fetched, root)], FakeRunner())
    [step] = outcome.steps
    if step.reason is None:
        return None, {}
    return step.reason.code, dict(step.reason.params)


@pytest.mark.parametrize(
    ("declared", "passport", "taken", "code", "params"),
    [
        (
            ["en", "ru"],
            {"languages": ["ru"], "default_language": "ru"},
            False,
            None,
            {},
        ),
        (
            ["en", "ru"],
            {"languages": ["en", "ru"], "default_language": "ru"},
            True,
            None,
            {},
        ),
        (None, {}, False, None, {}),
        (
            ["en", "ru"],
            {},
            False,
            "seams_check:languages-missing",
            {"fields": ["languages", "default_language"]},
        ),
        (
            ["en", "ru"],
            {"languages": ["en"]},
            False,
            "seams_check:languages-missing",
            {"fields": ["default_language"]},
        ),
        (
            ["en", "ru"],
            {"default_language": "en"},
            False,
            "seams_check:languages-missing",
            {"fields": ["languages"]},
        ),
        (
            None,
            {},
            True,
            "seams_check:languages-missing",
            {"fields": ["languages", "default_language"]},
        ),
        (
            ["en", "ru"],
            {"languages": ["en", "uk", "de"], "default_language": "en"},
            False,
            "seams_check:language-outside-product",
            {"languages": ["uk", "de"]},
        ),
        (
            None,
            {"languages": ["en"], "default_language": "en"},
            False,
            "seams_check:language-outside-product",
            {"languages": ["en"]},
        ),
        (
            ["en", "ru"],
            {"languages": ["en"], "default_language": "ru"},
            False,
            "seams_check:default-language-outside",
            {"language": "ru", "languages": ["en"]},
        ),
    ],
)
def test_seams_check_checks_the_instances_languages(
    tmp_path: Path,
    declared: list[str] | None,
    passport: dict[str, object],
    taken: bool,
    code: str | None,
    params: dict[str, object],
) -> None:
    """Wanted when the product declares languages, a stack takes them or the
    passport names some; the passport's list a subset of the product's, its
    default one of the list -- red before any ``act``."""
    assert _check(tmp_path, declared=declared, passport=passport, taken=taken) == (
        code,
        params,
    )


# --- the product's name -----------------------------------------------------------


@pytest.mark.parametrize(("name", "code"), [("aivis-next", "fetch_root:name-mismatch")])
def test_a_product_named_unlike_its_repository_is_refused(
    tmp_path: Path, name: str, code: str
) -> None:
    """``/opt/<repository>`` holds the releases, ``/opt/<name>`` the env and the
    override: one product, two directories -- refused before the worktree; the
    pair: the same name is fetched."""
    for case, called in (("a", name), ("b", "aivis")):
        tmp = tmp_path / case
        tmp.mkdir()
        data = example("product.yaml")
        data.update({"name": called, "dependencies": {}, "editions": {}})
        data.pop("packages")
        env = data["env"]
        assert isinstance(env, dict)
        for key in [k for k, v in env.items() if v.get("source") == "seam"]:
            env.pop(key)
        env.pop("EDITION")
        data.pop("provides")
        data.pop("replay")
        stacks = data["stacks"]
        assert isinstance(stacks, dict)
        stacks[called] = stacks.pop("aivis")
        remote(tmp, "aivis", {"primer.yaml": yaml.safe_dump(data)}, tag=None)
        _, steps = source_steps(
            tmp / "box",
            stack="aivis",
            address=f"file://{tmp}/aivis.git",
            ref="main",
            tag=False,
        )
        outcome = run_stacks([StackSteps("sources", steps)])
        by = {record.name: record for record in outcome.steps}
        releases = tmp / "box" / "opt" / "aivis" / "releases"
        if called == name:
            reason = by["fetch_root"].reason
            assert reason is not None and reason.code == code
            assert dict(reason.params) == {"stack": "aivis", "name": name}
            assert not releases.exists()
        else:
            assert outcome.code is ExitCode.OK, outcome.steps
            assert len(list(releases.iterdir())) == 1
