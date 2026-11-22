"""A package's place in its build context, and its repository's key (DM-127).

The path of a ``build`` place is the context's (contract 3 rule 10); a place
under a directory the context has not is a package no build reads -- velo's
``public/skin`` with the repository's root as its context: a green build with
no skin (review 0004, finding 5). ``package_places`` -- one function for
``build`` and ``pridem check`` -- finds it. A package of the passport from a
repository over ssh has its key, as a product's or a service's, in a stack of
its slot (contract 1 section 9; finding 4).
"""

import json
from pathlib import Path

from compose_support import in_release
from history_support import deploy_verbs_box
from test_steps_build_mode import STORAGE, VELO, made, velo_data

from pridem.events import Json
from pridem.steps.compose import package_places
from pridem.steps.keys import DeployKey


def _root_context() -> dict[str, Json]:
    document = json.loads(json.dumps(VELO))
    document["services"]["frontend"]["build"] = {
        "context": "/r/.",
        "dockerfile": "frontend/Dockerfile",
    }
    return dict(document)


ROOT_CONTEXT = _root_context()
"""velo's form: the frontend built from the repository's root."""


def test_a_place_under_no_directory_of_its_context_is_a_finding(tmp_path: Path) -> None:
    """P2: the root as context, ``public/skin``, no ``public/`` in the
    repository -- a finding; the pair: ``frontend/public/skin`` where
    ``frontend/public`` is -- none."""
    (tmp_path / "frontend" / "public").mkdir(parents=True)
    velo = in_release(ROOT_CONTEXT, tmp_path)
    wrong = made(velo_data())  # its place is public/skin
    assert package_places(wrong, {"velo": velo, "velo-storage": STORAGE}) == [
        "frontend: packages.skin.build (public: no such directory in its context)"
    ]
    data = velo_data()
    packages = data["packages"]
    assert isinstance(packages, dict)
    packages["skin"]["build"] = [
        {"service": "frontend", "path": "frontend/public/skin"}
    ]
    assert package_places(made(data), {"velo": velo, "velo-storage": STORAGE}) == []


def test_the_place_is_the_context_s_not_the_repository_s(tmp_path: Path) -> None:
    """P1: the context ``frontend/``, ``public/skin``: the directory is
    ``frontend/public`` -- the repository's ``public/`` is not looked at."""
    (tmp_path / "frontend" / "public").mkdir(parents=True)
    velo = in_release(VELO, tmp_path)  # frontend from /r/frontend
    assert (
        package_places(made(velo_data()), {"velo": velo, "velo-storage": STORAGE}) == []
    )


def test_a_box_checks_the_places_of_the_packages_it_has(tmp_path: Path) -> None:
    """On a box the places of the passport's packages alone: an optional slot
    with no package builds as the repository has it (DM-101) -- no finding for
    its place; ``pridem check`` (no passport) -- every place."""
    velo = in_release(ROOT_CONTEXT, tmp_path)
    stack = made(velo_data())
    documents = {"velo": velo, "velo-storage": STORAGE}
    assert package_places(stack, documents, set()) == []
    assert package_places(stack, documents, {"skin"}) != []
    assert package_places(stack, documents) != []


def test_a_package_from_its_repository_has_its_key(tmp_path: Path) -> None:
    """K1, K2: the passport's packages from ``git@github.com:partner-x/...``
    -- a stack of each slot before ``pridem-sources``, its key of the
    package's address, the product's and the other packages' addresses its
    others (no alias clash); the pair: the product's key, as before."""
    sources = deploy_verbs_box(tmp_path, "update", "test")
    built = sources.build()  # type: ignore[union-attr]
    assert built is not None
    names = [part.name for part in built]
    assert names == ["pridem-package-skin", "pridem-package-texts", "pridem-sources"]
    keys = {part.name: part.steps[0] for part in built[:2]}
    for key in keys.values():
        assert isinstance(key, DeployKey)
        assert key.repo.address == "git@github.com:partner-x/velo-look.git"
        assert "git@github.com:aivis-one/aivis.git" in key.others
    product_key = built[2].steps[0]
    assert isinstance(product_key, DeployKey)
    assert product_key.repo.address == "git@github.com:aivis-one/aivis.git"


def test_pridem_check_finds_the_place_its_context_has_not(tmp_path: Path) -> None:
    """P3 (review 0004, finding 22): ``pridem check`` of a velo-like
    repository built from its root, ``public/skin`` declared, no ``public/``
    -- the compose of ``velo`` is red with the finding; the pair: with
    ``public/`` -- green."""
    import io

    import yaml
    from compose_support import stdout
    from test_probe_DM_57_check import _env, version_call

    from pridem.cli import run as cli
    from pridem.runner import FakeCall, FakeRunner

    def check(root: Path) -> dict[str, dict[str, Json]]:
        (root / "deploy").mkdir(parents=True)
        (root / "primer.yaml").write_text(yaml.safe_dump(velo_data()))
        (root / "docker-compose.yml").write_text("services: {}\n")
        (root / "deploy" / "storage-compose.yml").write_text("services: {}\n")
        calls: list[FakeCall] = [version_call()]
        for entry, file, document in (
            ("velo", "docker-compose.yml", ROOT_CONTEXT),
            ("velo-storage", "deploy/storage-compose.yml", STORAGE),
        ):
            for raw in (True, False):
                argv = ["docker", "compose", "-p", entry, "-f", str(root / file)]
                argv += ["config", "--format", "json"]
                argv += ["--no-interpolate"] if raw else []
                calls.append(
                    FakeCall(
                        tuple(argv),
                        lines=stdout(json.dumps(in_release(document, root))),
                        env=_env(()),
                    )
                )
        out, err = io.StringIO(), io.StringIO()
        with FakeRunner(*calls) as runner:
            cli(["--json", "check", str(root)], out=out, err=err, runner=runner)
        verdict = json.loads(out.getvalue())
        return {s["stack"]: s for s in verdict["steps"] if s["name"] == "compose"}

    red = check(tmp_path / "wrong")
    reason = red["velo"]["reason"]
    assert isinstance(reason, dict)
    assert reason["code"] == "compose:compose-forbidden"
    assert reason["found"] == [
        "frontend: packages.skin.build (public: no such directory in its context)"
    ]
    (tmp_path / "right" / "public").mkdir(parents=True)
    assert check(tmp_path / "right")["velo"]["status"] == "ok"


def test_a_golden_build_is_not_refused_for_a_place_it_does_not_fill(
    tmp_path: Path,
) -> None:
    """P2b: on a box the passport gives no package for an optional slot whose
    place is under no directory of the context -- the build is green as the
    repository has it (DM-101): only a package the box puts in is checked."""
    from test_steps_build_mode import (
        build,
        compose,
        first_build,
        product_data,
        run,
        skin_box,
    )
    from test_steps_optional_slot import ABSENT_KEY

    from pridem.report.codes import ExitCode
    from pridem.runner import FakeRunner

    data = product_data()
    packages = data["packages"]
    assert isinstance(packages, dict)
    packages["skin"]["optional"] = True
    packages["skin"]["build"] = [{"service": "frontend", "path": "nowhere/skin"}]
    nowhere = made(data)
    root, fetched = skin_box(tmp_path, version=None)
    cs = compose(root, nowhere)
    with FakeRunner(*first_build(cs, ABSENT_KEY)) as runner:
        outcome = run([build(root, nowhere, fetched)], runner)
    assert outcome.code is ExitCode.OK, outcome.steps
