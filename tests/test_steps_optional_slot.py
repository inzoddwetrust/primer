"""An optional slot of ``apply: build`` (DM-101; the owner's word on velo's
letter of 13.11).

``packages.<slot>: {apply: build, optional: true}`` -- a passport that names no
package for it builds the service as its repository has it (the "golden"
build): the context is the release's copy with no package in it, the image's
key says ``pridem.package.<slot>: absent``, ``PRIMER_EDITION`` goes to the
build as to any build of the slot, and the fact of ``packages`` names the slot
``absent``. Without ``optional`` a passport with no package is
``package-missing``, as before. ``build_places``, ``image_key`` and the fact
decide by one function, ``build_slots``.
"""

from pathlib import Path

import pytest
from compose_support import ENTRY, REF, SHA, placed
from test_steps_build_mode import (
    APP_IMAGE,
    FRONT_IMAGE,
    _drop,
    at,
    build,
    build_call,
    compose,
    config_call,
    first_build,
    image_call,
    key_of,
    made,
    override,
    product_data,
    run,
    skin_box,
)

from pridem.events import Code
from pridem.report.codes import ExitCode
from pridem.runner import FakeRunner
from pridem.stacks.schema import Product
from pridem.steps.base import StepContext, StepFailed
from pridem.steps.compose import release_image
from pridem.steps.packages import (
    ABSENT,
    Packages,
    build_places,
    build_slots,
    context_dir,
    image_key,
)
from pridem.steps.passport import Fetched
from pridem.steps.up import Up

ABSENT_KEY = {"pridem.package.skin": ABSENT, "pridem.edition": "full"}


def optional(**extra: object) -> Product:
    """The blank with its skin built into ``frontend``, ``optional``."""
    data = product_data()
    packages = data["packages"]
    assert isinstance(packages, dict)
    packages["skin"]["optional"] = True
    for slot, package in extra.items():
        packages[slot] = package
    return made(data)


def _packages(root: Path, stack: Product, fetched: Fetched) -> Packages:
    return Packages(
        stack,
        ENTRY,
        release=root / "release",
        ref=REF,
        commit=SHA,
        fetched=fetched,
        root=root,
    )


def test_probe_DM_101_optional_build_slot_without_a_package(tmp_path: Path) -> None:
    """``optional: true``, the passport names no skin: the build is green from
    a context with no copy of a package -- the repository's own
    ``public/skin`` -- with the key ``skin: absent`` and the edition; ``up``
    finds the image by that key; the fact of ``packages`` is ``skin: absent``.
    The pair: the same passport without ``optional`` -- ``package-missing``."""
    stack = optional()
    root, fetched = skin_box(tmp_path, version=None)
    cs = compose(root, stack)
    with FakeRunner(*first_build(cs, ABSENT_KEY)) as runner:
        outcome = run([build(root, stack, fetched)], runner)
    assert outcome.code is ExitCode.OK, outcome.steps
    target = context_dir(root, "blank", ENTRY, "frontend")
    assert (target / "public" / "skin" / "built-in.css").read_text() == "old"
    assert sorted(p.name for p in (target / "public" / "skin").iterdir()) == [
        "built-in.css"
    ]
    front = at(override(cs), "services", "frontend", "build")
    assert isinstance(front, dict)
    assert front["context"] == str(target)
    assert front["args"] == {"PRIMER_EDITION": "full"}
    assert at(front, "labels", "pridem.package.skin") == "absent"
    up = Up(
        stack,
        ENTRY,
        release=cs.release,
        ref=REF,
        commit=SHA,
        root=root,
        fetched=fetched,
    )
    with FakeRunner(image_call(cs, "frontend", ABSENT_KEY, FRONT_IMAGE)) as runner:
        ctx = StepContext(runner, "install", "test", ENTRY, _drop)
        assert up._expected(ctx, "frontend") == FRONT_IMAGE
    with FakeRunner(config_call(cs)) as runner:
        ctx = StepContext(runner, "install", "test", ENTRY, _drop)
        fact = _packages(root, stack, fetched).verify(ctx, None)  # type: ignore[arg-type]
    assert fact.fact == {"packages": {"skin": "absent"}}
    # the pair: no optional, no package
    strict = made(product_data())
    with FakeRunner(config_call(cs, raw=True), config_call(cs)) as runner:
        refused = run([build(root, strict, fetched)], runner)
    assert refused.steps[0].reason == Code("build:package-missing", {"slot": "skin"})


def test_a_package_and_no_package_are_two_images_of_one_commit(tmp_path: Path) -> None:
    """``was a package -> no package`` on the same commit: another key, another
    release image -- the build and ``up`` act; and back. ``absent`` is never a
    package's value (``<repo>@<version>`` always has an ``@``)."""
    stack = optional()
    root, with_skin = skin_box(tmp_path / "with")
    _, without = skin_box(tmp_path / "without", version=None)
    cs = compose(root, stack)
    given = image_key(stack, "frontend", with_skin.passport)
    absent = image_key(stack, "frontend", without.passport)
    assert given == key_of() and absent == ABSENT_KEY
    assert release_image(cs, "frontend", given) != release_image(cs, "frontend", absent)
    assert "@" in given["pridem.package.skin"] and "@" not in ABSENT
    # the box built with the skin; the passport drops it: no image of the
    # new key -- a build
    with FakeRunner(*first_build(cs, given)) as runner:
        assert run([build(root, stack, with_skin)], runner).code is ExitCode.OK
    placed(cs)
    script = [
        config_call(cs, raw=True),
        config_call(cs),  # the override differs (another key): build
        config_call(cs, raw=True),
        config_call(cs),
        build_call(cs),
        config_call(cs, raw=True),
        config_call(cs),
        image_call(cs, "app", {}, APP_IMAGE),
        image_call(cs, "frontend", absent, FRONT_IMAGE),
    ]
    with FakeRunner(*script) as runner:
        outcome = run([build(root, stack, without)], runner)
    assert outcome.code is ExitCode.OK, outcome.steps


def test_an_optional_slot_beside_a_given_one(tmp_path: Path) -> None:
    """Two slots of ``apply: build`` into ``frontend``: ``brand`` given,
    ``skin`` optional and absent -- the context has the brand's package, the
    key both slots."""
    brand = {
        "contract": ">=1,<2",
        "apply": "build",
        "build": [{"service": "frontend", "path": "public/brand"}],
    }
    stack = optional(brand=brand)
    root, fetched = skin_box(tmp_path, version=None)
    assert fetched.passport is not None
    fetched.passport = fetched.passport.model_copy(
        update={"packages": {"brand": with_package(root)}}
    )
    key = image_key(stack, "frontend", fetched.passport)
    assert key == {
        "pridem.edition": "full",
        "pridem.package.brand": "velo-look@1.4.2",
        "pridem.package.skin": ABSENT,
    }
    places = build_places(stack, "blank", fetched.passport, root, {"frontend"})
    assert [p.slot for p in places] == ["brand"]


def with_package(root: Path) -> object:
    """A passport package of the skin's repository, its release on the box."""
    _, fetched = skin_box(root / "pkg")
    assert fetched.passport is not None
    return fetched.passport.packages["skin"]


@pytest.mark.parametrize("version", [None, "1.4.2"])
@pytest.mark.parametrize("is_optional", [True, False])
def test_build_places_and_the_key_decide_alike(
    tmp_path: Path, version: str | None, is_optional: bool
) -> None:
    """One decision (``build_slots``): ``build_places`` and ``image_key``
    refuse together, take a package together, or both see none -- a place
    exactly when the key names a package."""
    stack = optional() if is_optional else made(product_data())
    root, fetched = skin_box(tmp_path, version=version)
    passport = fetched.passport
    assert passport is not None
    outcomes: list[object] = []
    for decide in (
        lambda: build_slots(stack, passport),
        lambda: build_places(stack, "blank", passport, root, {"frontend"}),
        lambda: image_key(stack, "frontend", passport),
    ):
        try:
            outcomes.append(decide())
        except StepFailed as refused:
            outcomes.append(refused.reason)
    if version is None and not is_optional:
        refusal = Code("package-missing", {"slot": "skin"})
        assert outcomes == [refusal, refusal, refusal]
        return
    slots, places, key = outcomes
    assert (
        isinstance(slots, dict) and isinstance(places, list) and isinstance(key, dict)
    )
    assert (
        (slots["skin"] is None)
        == (places == [])
        == (key["pridem.package.skin"] == ABSENT)
    )


def test_doctor_after_a_green_deploy_without_a_package_is_empty(tmp_path: Path) -> None:
    """``par0`` 14.4: the box built without the skin; ``doctor`` finds the
    image of the key ``absent`` and the override in place -- nothing to do."""
    stack = optional()
    root, fetched = skin_box(tmp_path, version=None)
    cs = compose(root, stack)
    with FakeRunner(*first_build(cs, ABSENT_KEY)) as runner:
        assert run([build(root, stack, fetched)], runner).code is ExitCode.OK
    placed(cs)
    same = [
        config_call(cs, raw=True),
        config_call(cs),
        image_call(cs, "app", {}, APP_IMAGE),
        image_call(cs, "frontend", ABSENT_KEY, FRONT_IMAGE),
    ]
    with FakeRunner(*same) as runner:
        ctx = StepContext(runner, "deploy", "test", ENTRY, _drop)
        assert not build(root, stack, fetched).check(ctx).needed


def test_optional_on_a_runtime_slot_is_taken_and_mounts_nothing() -> None:
    """``optional`` on ``apply: runtime`` says nothing (the gate): the loader
    takes it; such a slot without a package mounts nothing, as before."""
    data = product_data(apply="runtime")
    packages = data["packages"]
    assert isinstance(packages, dict)
    packages["skin"]["optional"] = True
    assert made(data).packages["skin"].optional is True
