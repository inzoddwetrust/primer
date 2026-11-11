"""DM-90: the image of a release by its own name, never pulled.

Each test is a row of the grid of the card's gate. Every expected name is a
literal, as docker gets it, not the code's template again (``par0`` 14.2).
"""

import json
from dataclasses import replace
from pathlib import Path

import pytest
from compose_support import CONFIG, OLD_SHA, compose
from test_steps_gc import IMAGES as GC_IMAGES
from test_steps_gc import (
    GitReal,
    df,
    fact,
    image,
    kept_world,
    listed,
    run_gc,
)

from pridem.events import Json
from pridem.report.codes import ExitCode
from pridem.runner import FakeCall
from pridem.steps.base import StepFailed
from pridem.steps.compose import override_text, release_image, write_override
from pridem.steps.data import run_image

KEY = {"pridem.edition": "full", "pridem.package.skin": "velo-look@1.4.2"}


def _services(text: str) -> dict[str, dict[str, Json]]:
    services = json.loads(text)["services"]
    assert isinstance(services, dict)
    return services


def test_the_name_of_a_release_image_is_its_commit_and_its_key(tmp_path: Path) -> None:
    """``<entry>-<service>:<commit12>``; keyed by an edition and packages built
    into it, ``-<key12>`` -- each part of the key its own name."""
    cs = compose(tmp_path)
    assert release_image(cs, "app", {}) == "blank-app:0e82be562d18"
    old = replace(cs, commit=OLD_SHA)
    assert release_image(old, "app", {}) == "blank-app:111111111111"
    assert (
        release_image(cs, "frontend", KEY) == "blank-frontend:0e82be562d18-0c7cc15a28ed"
    )
    edition = {**KEY, "pridem.edition": "core"}
    assert release_image(cs, "frontend", edition) == (
        "blank-frontend:0e82be562d18-57d8d25eb22b"
    )
    package = {**KEY, "pridem.package.skin": "velo-look@1.5.0"}
    assert release_image(cs, "frontend", package) == (
        "blank-frontend:0e82be562d18-0c6d4b9e8c65"
    )


def test_every_built_service_gets_its_release_name_and_is_never_pulled(
    tmp_path: Path,
) -> None:
    """In the override: ``image`` and ``pull_policy: never`` on every service
    with a ``build``; a service of a registry image keeps its own, with
    neither. A key the build of a package gives goes into the name."""
    cs = compose(tmp_path)
    builds: dict[str, dict[str, Json]] = {
        "frontend": {"context": "/c", "labels": dict[str, Json](KEY)}
    }
    services = _services(
        override_text(cs, CONFIG, builds=builds, proxy=False, references=CONFIG)
    )
    assert services["app"]["image"] == "blank-app:0e82be562d18"
    assert services["app"]["pull_policy"] == "never"
    assert services["frontend"]["image"] == "blank-frontend:0e82be562d18-0c7cc15a28ed"
    assert services["frontend"]["pull_policy"] == "never"
    assert "image" not in services["postgres"]
    assert "pull_policy" not in services["postgres"]


def test_the_deploys_override_and_the_running_ones_name_their_own_commits(
    tmp_path: Path,
) -> None:
    deploy = compose(tmp_path)
    running = replace(compose(tmp_path, commit=OLD_SHA), staged=False)
    for cs in (deploy, running):
        write_override(cs, override_text(cs, CONFIG, proxy=False, references=CONFIG))
    assert _services(deploy.override.read_text())["app"]["image"] == (
        "blank-app:0e82be562d18"
    )
    assert _services(running.override.read_text())["app"]["image"] == (
        "blank-app:111111111111"
    )


def test_a_verb_runs_the_image_its_release_names_not_the_products(
    tmp_path: Path,
) -> None:
    """``compose run`` of a verb takes the image of the release's override --
    it wins the merge, over an ``image`` the product names next to its
    ``build`` (the machine names a release's image); a service of a registry
    image, the one the product names. An override that names none and a
    product that names none: ``image-unread``."""
    running = replace(compose(tmp_path, commit=OLD_SHA), staged=False)
    write_override(
        running, override_text(running, CONFIG, proxy=False, references=CONFIG)
    )
    product: dict[str, Json] = json.loads(json.dumps(CONFIG))
    services = product["services"]
    assert isinstance(services, dict)
    app = services["app"]
    assert isinstance(app, dict)
    app["image"] = "acme/blank:latest"
    assert run_image(product, running, "app") == "blank-app:111111111111"
    assert run_image(product, running, "postgres") == "postgres@sha256:x"
    running.override.write_text('{"services": {}}')
    del app["image"]
    with pytest.raises(StepFailed) as unread:
        run_image(product, running, "app")
    assert unread.value.reason.code == "image-unread"


def test_gc_removes_an_image_by_every_tag_it_has(tmp_path: Path) -> None:
    """An image of an old commit has two names after DM-90 -- compose's own of
    before and the release's: ``gc`` removes it by both, in one command."""
    world, _, _ = kept_world(tmp_path)
    old = image(3, world.commits[0], ["blank-app:latest", "blank-app:111111111111"])
    rm = ("docker", "image", "rm", "blank-app:latest", "blank-app:111111111111")
    with GitReal(
        df(),
        *listed([], kind="container"),
        *listed([old], kind="image"),
        FakeCall(rm),
        df(),
        FakeCall(GC_IMAGES),
    ) as runner:
        outcome, _ = run_gc(world, runner)
    assert outcome.code is ExitCode.OK, outcome.steps
    removed = fact(outcome)["removed"]
    assert isinstance(removed, dict)
    assert isinstance(removed["images"], list) and len(removed["images"]) == 1
