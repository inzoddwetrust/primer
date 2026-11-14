"""DM-100: the data of form D to every service of ``accepts.<kind>.services``.

Each service of the list gets the same bind of the copy (read-only) and the
same variable in the override; without the field, ``app`` alone. A name
compose does not have is a finding of ``forbidden``; an empty list, a name
twice or jobs alone -- ``S.accepts-services``. Expected binds are literal
(``par0`` 14.2).
"""

import json
from dataclasses import replace
from pathlib import Path

import pytest
from compose_support import SHA
from pydantic import ValidationError
from test_steps_services import ACCEPTS, _item, _service

from pridem.events import Json
from pridem.runner import FakeCall, FakeRunner
from pridem.stacks.schema import Accepted, rule_problems
from pridem.steps.compose import ComposeStack, forbidden, override_text, stale
from pridem.steps.services import data_binds

LISTED = ("comms-app", "comms-worker", "comms-consumer")
DOCUMENT: dict[str, Json] = {
    "services": {
        "comms-app": {"image": "a"},
        "comms-worker": {"image": "a"},
        "comms-consumer": {"image": "a"},
        "comms-redis": {"image": "r"},
    }
}


def _rendered(tmp: Path, services: tuple[str, ...]) -> dict[str, dict[str, Json]]:
    item = replace(_item(tmp), services=services)
    mounts, env = data_binds([item], "comms-app")
    tmp.mkdir(parents=True, exist_ok=True)
    compose = ComposeStack(_service(tmp), "comms", tmp / "r", "v1.0.0", SHA, tmp)
    rendered = json.loads(
        override_text(
            compose, DOCUMENT, mounts, None, env, proxy=False, references=DOCUMENT
        )
    )
    found = rendered["services"]
    assert isinstance(found, dict)
    return found


def test_probe_DM_100_every_listed_service_gets_the_data(tmp_path: Path) -> None:
    """Three services in the list: each gets the bind of the copy, read-only,
    at ``/primer/data/profile``, and ``PROFILE_DIR`` naming it; ``comms-redis``,
    not listed, gets neither. The pair: no field -- ``comms-app`` alone."""
    target = str(_item(tmp_path).target)
    bind = {
        "type": "bind",
        "source": target,
        "target": "/primer/data/profile",
        "read_only": True,
    }
    services = _rendered(tmp_path, LISTED)
    for name in LISTED:
        assert services[name]["volumes"] == [bind], name
        assert services[name]["environment"] == {
            "PROFILE_DIR": "/primer/data/profile"
        }, name
    assert "volumes" not in services["comms-redis"]
    assert "environment" not in services["comms-redis"]

    # the pair: without the field, the app alone
    services = _rendered(tmp_path, ())
    assert services["comms-app"]["volumes"] == [bind]
    for name in ("comms-worker", "comms-consumer", "comms-redis"):
        assert "volumes" not in services[name], name
        assert "environment" not in services[name], name


def test_a_list_without_the_app_is_exactly_the_list(tmp_path: Path) -> None:
    services = _rendered(tmp_path, ("comms-worker",))
    assert "volumes" in services["comms-worker"]
    assert "volumes" not in services["comms-app"]


def test_two_kinds_go_each_to_its_own_list(tmp_path: Path) -> None:
    profile = replace(_item(tmp_path), services=("comms-app", "comms-worker"))
    texts = replace(
        _item(tmp_path, "texts"), env="TEXTS_DIR", services=("comms-consumer",)
    )
    mounts, env = data_binds([profile, texts], "comms-app")
    assert env == {
        "comms-app": {"PROFILE_DIR": "/primer/data/profile"},
        "comms-worker": {"PROFILE_DIR": "/primer/data/profile"},
        "comms-consumer": {"TEXTS_DIR": "/primer/data/texts"},
    }
    assert sorted(mounts) == ["comms-app", "comms-consumer", "comms-worker"]


def test_new_data_makes_every_listed_service_another_configuration(
    tmp_path: Path,
) -> None:
    """New data is a new copy, a new path: the override part of every listed
    service changes -- the configuration ``stale`` hashes -- and of none other.
    The pair: the same data -- the same parts."""
    old = _rendered(tmp_path / "a", LISTED)
    (tmp_path / "a" / "aivis-release" / "profile-dir").mkdir(parents=True)
    (tmp_path / "a" / "aivis-release" / "profile-dir" / "k").write_text("new\n")
    new = _rendered(tmp_path / "a", LISTED)
    assert [n for n in LISTED if old[n] != new[n]] == list(LISTED)
    assert old["comms-redis"] == new["comms-redis"]
    assert _rendered(tmp_path / "a", LISTED) == new


def test_stale_names_every_listed_service_whose_configuration_changed(
    tmp_path: Path,
) -> None:
    """``up`` decides by ``stale``, service by service (DM-61 FIX): the three
    listed ones on another configuration are each named, the one unchanged
    is not -- not the app alone."""
    compose = ComposeStack(_service(tmp_path), "comms", tmp_path / "r", "v1", SHA,
                           tmp_path)  # fmt: skip
    from compose_support import hash_calls

    running = {name: "old" for name in LISTED} | {"comms-redis": "same"}
    expected = {name: "new" for name in LISTED} | {"comms-redis": "same"}
    calls = hash_calls(compose, running, expected)
    from env_support import context

    with FakeRunner(*calls) as runner:
        found = stale(context(runner), compose)
    assert sorted(found) == sorted(LISTED)


# --- the form ---------------------------------------------------------------------


@pytest.mark.parametrize(
    ("services", "why"),
    [([], "empty"), (["comms-app", "comms-app"], "twice")],
)
def test_an_empty_list_or_a_name_twice_is_refused(
    services: list[str], why: str
) -> None:
    with pytest.raises(ValidationError) as refused:
        Accepted.model_validate(
            {"validate": "comms validate <dir>", "env": "P", "services": services}
        )
    assert "S.accepts-services" in str(refused.value) and why in str(refused.value)
    assert Accepted.model_validate(
        {"validate": "comms validate <dir>", "env": "P", "services": ["comms-app"]}
    ).services == ["comms-app"]


def test_a_list_of_jobs_alone_is_refused(tmp_path: Path) -> None:
    """A job runs again only when ``up`` acts by a service that is no job: jobs
    alone would never read new data. The pair: a job beside a service."""
    comms = _service(tmp_path, accepts=ACCEPTS)
    stage = comms.stacks["comms"]
    from pridem.stacks.schema import Job

    with_job = stage.model_copy(update={"jobs": {"init": Job(service="comms-init")}})
    accepted = comms.accepts["profile"]
    alone = comms.model_copy(
        update={
            "stacks": {"comms": with_job},
            "accepts": {
                "profile": accepted.model_copy(update={"services": ["comms-init"]})
            },
        }
    )
    codes = [p.code for p in rule_problems(alone)]
    assert "S.accepts-services" in codes
    beside = alone.model_copy(
        update={
            "accepts": {
                "profile": accepted.model_copy(
                    update={"services": ["comms-init", "comms-app"]}
                )
            }
        }
    )
    assert "S.accepts-services" not in [p.code for p in rule_problems(beside)]


def test_a_listed_service_compose_has_not_is_a_finding(tmp_path: Path) -> None:
    """``forbidden`` of the service's own entry, in ``build`` and ``pridem
    check`` alike: ``accepts.profile: no service comms-worker``. The pair: a
    list compose has -- no such finding."""
    comms = _service(tmp_path, accepts=ACCEPTS)
    accepted = comms.accepts["profile"]
    listed = comms.model_copy(
        update={
            "accepts": {
                "profile": accepted.model_copy(
                    update={"services": ["comms-app", "comms-worker"]}
                )
            }
        }
    )
    release = tmp_path / "r"
    release.mkdir()
    compose = ComposeStack(listed, "comms", release, "v1.0.0", SHA, tmp_path)
    document: dict[str, Json] = {"services": {"comms-app": {"image": "a"}}}
    found = forbidden(compose, document)
    assert "accepts.profile: no service comms-worker" in found
    document = {
        "services": {"comms-app": {"image": "a"}, "comms-worker": {"image": "a"}}
    }
    found = forbidden(compose, document)
    assert not [f for f in found if f.startswith("accepts.")]


def test_validate_runs_once_in_the_app_image(tmp_path: Path) -> None:
    """Three services read the data; ``validate`` runs once, in the app's
    image -- not once per service (the strict scenario of ``FakeRunner``
    holds exactly one)."""
    from compose_support import image_call, run
    from test_probe_DM_81_data import _validate
    from test_steps_services import IMAGE, _copy

    step, compose, item = _copy(tmp_path)
    step.items = [replace(item, services=LISTED)]
    script = [
        image_call(compose, "comms-app", IMAGE),
        _validate(compose, step.items[0], 0),
    ]
    with FakeRunner(*script) as runner:
        outcome, _ = run([step], runner)
    assert outcome.steps[0].status == "ok", outcome.steps
    assert FakeCall is not None


def test_a_package_slot_goes_to_its_list_too(tmp_path: Path) -> None:
    """A package section for a service (``mount.dependency``) is data of form D
    with the slot for its kind: ``accepts.<slot>.services`` names its readers
    as for any kind. The pair: the product's kind without the field -- none
    named, the app's."""
    from env_support import COMMS_REPO, box, passport_data
    from test_steps_services import _product

    from pridem.steps.services import data_items

    made = _product(
        tmp_path,
        dependencies={"comms": {**COMMS_REPO, "data": {"profile": "comms-profile"}}},
        packages={
            "texts": {
                "contract": ">=1,<2",
                "validate": "v <dir>",
                "mount": [{"dependency": "comms", "from": "comms", "env": "OV"}],
            }
        },
    )
    texts = {"validate": "t <dir>", "env": "OV", "services": ["comms-consumer"]}
    comms = _service(tmp_path, accepts={**ACCEPTS, "texts": texts})
    data = passport_data()
    data["packages"] = {"texts": {"repo": "git@github.com:p/t.git", "version": "1.0.0"}}
    root, fetched = box(tmp_path, data)
    assert fetched.passport is not None
    items = data_items(
        made,
        comms,
        release_dir=tmp_path / "rel",
        release="v2",
        passport=fetched.passport,
        root=root,
    )
    by_kind = {item.kind: item.services for item in items}
    assert by_kind == {"profile": (), "texts": ("comms-consumer",)}
