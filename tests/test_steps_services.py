"""Services in the plan (DM-46): the rules of the form D and of the services'
tests in ``primer.yaml``, ``seams_check`` of the composition, ``data_copy``,
``seams_verify``, ``fetch_services`` reading a service's ``primer.yaml``, the
machine's override for a service's data, ``tests`` with ``test.services`` and
``gc`` of the copies."""

import json
import os
from collections.abc import Iterator
from pathlib import Path

import pytest
import yaml
from compose_support import (
    CONFIG,
    SHA,
    LiveApp,
    compose,
    health,
    image_call,
    log_line,
    observe_calls,
    stdout,
)
from contract_support import example, yaml_problems
from env_support import (
    COMMS_REPO,
    box,
    context,
    load,
    passport_data,
    product_data,
    run,
)
from env_support import service_data as base_service_data
from services_support import comms_data, deferred, git, planned, remote, run_stacks
from test_steps_build import green_build

from pridem.events import Json, Secrets
from pridem.plan import StackSteps
from pridem.report.codes import ExitCode
from pridem.runner import FakeCall, FakeRunner
from pridem.stacks.passport import Gc as GcPolicy
from pridem.stacks.schema import Product, Service
from pridem.stacks.seams import given_kinds, unaccepted
from pridem.state import Box
from pridem.steps.base import StepFailed
from pridem.steps.build import Build
from pridem.steps.compose import (
    RUNNING_HASH_FORMAT,
    ComposeStack,
    OverrideHandoff,
    override_text,
)
from pridem.steps.env import SeamsCheck
from pridem.steps.finalize import Finalize
from pridem.steps.gc import Gc, _Known
from pridem.steps.passport import Fetched
from pridem.steps.services import (
    DataCopy,
    DataItem,
    SeamsVerify,
    data_binds,
    data_items,
    digest,
    tree,
)
from pridem.steps.sources import source_steps
from pridem.steps.tests import TestReport, Tests

IMAGE = "sha256:" + "c" * 64


@pytest.fixture
def two_apps() -> Iterator[tuple[LiveApp, LiveApp]]:
    first, second = LiveApp(), LiveApp()
    try:
        yield first, second
    finally:
        first.close()
        second.close()


def _product(tmp: Path, **parts: object) -> Product:
    data = product_data({}, dependencies={"comms": COMMS_REPO})
    data.update(parts)
    made = load(tmp, data)
    assert isinstance(made, Product)
    return made


def _service(tmp: Path, **parts: object) -> Service:
    data = base_service_data({})
    data.update(parts)
    made = load(tmp, data)
    assert isinstance(made, Service)
    return made


ACCEPTS = {"profile": {"validate": "comms validate --profile <dir>", "env": "PD"}}


# --- primer.yaml ------------------------------------------------------------------


def test_an_entry_named_as_a_dependency_is_refused(tmp_path: Path) -> None:
    data = example("product.yaml")
    stacks = data["stacks"]
    assert isinstance(stacks, dict)
    assert yaml_problems(tmp_path, data) == []
    stacks["comms"] = {"compose": "c.yml"}
    assert yaml_problems(tmp_path, data) == [("stacks.comms", "S.entry-dependency")]


def test_the_path_variable_of_accepted_data_is_the_machines(tmp_path: Path) -> None:
    data = example("service.yaml")
    data["accepts"] = {"profile": {"validate": "v <dir>", "env": "PROFILE_DIR"}}
    assert yaml_problems(tmp_path, data) == []
    env = data["env"]
    assert isinstance(env, dict)
    env["PROFILE_DIR"] = {"source": "minted"}
    assert yaml_problems(tmp_path, data) == [("accepts.profile.env", "S.accepts-env")]


@pytest.mark.parametrize(
    ("services", "found"),
    [
        (["redis"], []),
        (["redis", "queue"], []),
        ([], [("stacks.aivis.test.services", "too_short")]),
        (["app"], [("stacks.aivis.test.services[0]", "R20.test-form")]),
        (["frontend"], [("stacks.aivis.test.services[0]", "R20.test-form")]),
        (["redis", "redis"], [("stacks.aivis.test.services[1]", "R20.test-form")]),
    ],
)
def test_test_services_are_neither_app_nor_frontend_once_each(
    tmp_path: Path, services: list[str], found: list[tuple[str, str]]
) -> None:
    data = example("product.yaml")
    stacks = data["stacks"]
    assert isinstance(stacks, dict)
    stacks["aivis"]["test"]["services"] = services
    assert yaml_problems(tmp_path, data) == found


def test_a_service_named_twice_in_an_edition_is_refused(tmp_path: Path) -> None:
    data = example("product.yaml")
    editions = data["editions"]
    assert isinstance(editions, dict)
    editions["core"] = {"services": ["comms", "comms"]}
    assert yaml_problems(tmp_path, data) == [
        ("editions.core.services[1]", "R11.edition-services")
    ]


# --- the composition --------------------------------------------------------------


def test_given_kinds_are_the_data_and_the_packages_sections(tmp_path: Path) -> None:
    made = _product(
        tmp_path,
        dependencies={"comms": {**COMMS_REPO, "data": {"profile": "p"}}},
        packages={
            "texts": {
                "contract": ">=1,<2",
                "validate": "v <dir>",
                "mount": [{"dependency": "comms", "from": "comms", "env": "OV"}],
            }
        },
    )
    assert given_kinds(made, "comms") == {"profile": None, "texts": "OV"}
    assert given_kinds(made, "payments") == {}


@pytest.mark.parametrize(
    ("accepts", "found"),
    [
        (ACCEPTS, []),
        ({}, ["comms.profile: not accepted"]),
        ({"texts": ACCEPTS["profile"]}, ["comms.profile: not accepted"]),
    ],
)
def test_seams_check_refuses_data_a_service_does_not_accept(
    tmp_path: Path, accepts: dict[str, object], found: list[str]
) -> None:
    made = _product(
        tmp_path, dependencies={"comms": {**COMMS_REPO, "data": {"profile": "p"}}}
    )
    comms = _service(tmp_path, accepts=accepts)
    assert unaccepted(made, {"comms": comms}, None, on=frozenset()) == found
    root, fetched = box(tmp_path, passport_data(edition=None))
    outcome, _ = run([SeamsCheck(made, {"comms": comms}, fetched, root)], FakeRunner())
    [step] = outcome.steps
    if found:
        assert step.reason is not None
        assert step.reason.code == "seams_check:data-not-accepted"
        assert step.reason.params["data"] == found
    else:
        assert step.status == "ok"


def test_a_package_section_goes_under_the_services_own_variable(
    tmp_path: Path,
) -> None:
    packages = {
        "texts": {
            "contract": ">=1,<2",
            "validate": "v <dir>",
            "mount": [{"dependency": "comms", "from": "comms", "env": "OV"}],
        }
    }
    made = _product(tmp_path, packages=packages)
    taken = {"texts": {"validate": "c <dir>", "env": "OTHER"}}
    comms = _service(tmp_path, accepts=taken)
    assert unaccepted(made, {"comms": comms}, None, on=frozenset()) == [
        "comms.texts: OV, the service takes OTHER"
    ]
    comms = _service(tmp_path, accepts={"texts": {"validate": "c <dir>", "env": "OV"}})
    assert unaccepted(made, {"comms": comms}, None, on=frozenset()) == []


def test_seams_check_refuses_routes_of_a_co_located_service(tmp_path: Path) -> None:
    made = _product(tmp_path)
    routed = _service(
        tmp_path,
        host={"domains": ["mail"], "routes": {"mail": {"to": "comms-app:8000"}}},
    )
    root, fetched = box(tmp_path, passport_data(edition=None))
    outcome, _ = run([SeamsCheck(made, {"comms": routed}, fetched, root)], FakeRunner())
    [step] = outcome.steps
    assert step.reason is not None
    assert step.reason.code == "seams_check:routes-on-co-located"
    assert step.reason.params["services"] == ["comms"]
    # the pair: the same service without routes passes
    plain = _service(tmp_path, host={"domains": ["mail"]})
    outcome, _ = run([SeamsCheck(made, {"comms": plain}, fetched, root)], FakeRunner())
    assert outcome.code is ExitCode.OK


def test_seams_check_refuses_an_edition_the_product_does_not_declare(
    tmp_path: Path,
) -> None:
    made = _product(tmp_path, editions={"core": {"services": ["comms"]}})
    comms = _service(tmp_path)
    root, fetched = box(tmp_path, passport_data(edition="gold"))
    outcome, _ = run([SeamsCheck(made, {"comms": comms}, fetched, root)], FakeRunner())
    [step] = outcome.steps
    assert step.reason is not None
    assert step.reason.code == "seams_check:edition-unknown"
    assert step.reason.params == {"edition": "gold"}
    root, fetched = box(tmp_path / "pair", passport_data(edition="core"))
    outcome, _ = run([SeamsCheck(made, {"comms": comms}, fetched, root)], FakeRunner())
    assert outcome.code is ExitCode.OK


def test_a_service_the_edition_leaves_out_is_named_not_removed(tmp_path: Path) -> None:
    deps = {
        "comms": COMMS_REPO,
        "payments": {"repo": "git@github.com:acme/payments.git", "version": ">=1,<2"},
    }
    editions = {"core": {"services": ["comms"]}, "full": {"services": list(deps)}}
    made = _product(tmp_path, dependencies=deps, editions=editions)
    comms = _service(tmp_path)
    root, fetched = box(tmp_path, passport_data(edition="core"))
    home = root / "opt" / "payments"
    (home / "releases" / "v1.0.0").mkdir(parents=True)
    (home / "current").symlink_to("releases/v1.0.0")
    outcome, _ = run([SeamsCheck(made, {"comms": comms}, fetched, root)], FakeRunner())
    [step] = outcome.steps
    assert step.verify == {"order": ["comms", "aivis"], "left": ["payments"]}
    assert (home / "current").is_symlink()
    # the pair: a service the box never installed is not named
    (home / "current").unlink()
    outcome, _ = run([SeamsCheck(made, {"comms": comms}, fetched, root)], FakeRunner())
    assert outcome.steps[0].verify["left"] == []


# --- fetch_services ---------------------------------------------------------------


def _sources(tmp: Path, comms: dict[str, object]) -> list[str]:
    remote(tmp, "comms", {"primer.yaml": yaml.safe_dump(comms)})
    head = git(tmp / "comms.git", "rev-parse", "v1.0.0^{commit}")[0]
    data = example("product.yaml")
    data["dependencies"] = {
        "comms": {"repo": f"file://{tmp}/comms.git", "version": ">=1,<2"}
    }
    data["editions"] = {"core": {"services": ["comms"]}}
    env = data["env"]
    assert isinstance(env, dict)
    env.pop("PAYMENTS_API_URL")
    data.pop("packages")
    text = (
        "schema: 1\nresolved_at: 2026-11-05T00:00:00Z\ndependencies:\n"
        # quoted: a prefix of digits, or like 1e12345, would be a number
        f"  comms: {{version: '1.0.0', tag: v1.0.0, commit: '{head[:7]}'}}\n"
    )
    remote(
        tmp,
        "aivis",
        {"primer.yaml": yaml.safe_dump(data), "primer.lock": text},
        tag=None,
    )
    _, steps = source_steps(
        tmp / "box",
        stack="aivis",
        address=f"file://{tmp}/aivis.git",
        ref="main",
        tag=False,
    )
    outcome = run_stacks([StackSteps("sources", steps)])
    return [r.reason.code for r in outcome.steps if r.reason is not None]


@pytest.mark.parametrize(
    ("change", "code"),
    [
        ({"name": "comms-next"}, "fetch_services:name-mismatch"),
        ({"kind": "product"}, "fetch_services:invalid-config"),
    ],
)
def test_fetch_services_reads_the_services_primer_yaml(
    tmp_path: Path, change: dict[str, object], code: str
) -> None:
    """A service whose ``name`` is not its key in ``dependencies`` is refused
    before its worktree (its env would be under another directory); the pair:
    the right one is read and its release made."""
    assert _sources(tmp_path / "a", {**comms_data(), **change})[:1] == [code]
    assert not (tmp_path / "a" / "box" / "opt" / "comms" / "releases").exists()
    assert _sources(tmp_path / "b", comms_data()) == []
    release = tmp_path / "b" / "box" / "opt" / "comms" / "releases" / "v1.0.0"
    assert (release / "primer.yaml").is_file()


def test_a_dependency_that_is_a_product_is_refused(tmp_path: Path) -> None:
    """A dependency's ``primer.yaml`` that is a valid product, not a service."""
    data = example("product.yaml")
    data.update({"name": "comms", "dependencies": {}, "editions": {}})
    data.pop("packages")
    env = data["env"]
    assert isinstance(env, dict)
    for key in [k for k, v in env.items() if v.get("source") == "seam"]:
        env.pop(key)
    env.pop("EDITION")
    data.pop("provides")
    data.pop("replay")
    assert _sources(tmp_path, data)[:1] == ["fetch_services:not-a-service"]


# --- the override of a service's data ---------------------------------------------


def _item(root: Path, kind: str = "profile") -> DataItem:
    source = root / "aivis-release" / f"{kind}-dir"
    return DataItem(
        kind,
        source,
        root / "aivis-release",
        root / "opt" / "comms" / "data" / "aivis@v2",
        "PROFILE_DIR",
        "comms validate --profile <dir>",
    )


def test_the_override_carries_a_services_data_on_its_app(tmp_path: Path) -> None:
    item = _item(tmp_path)
    mounts, env = data_binds([item], "comms-app")
    assert mounts == {  # compose's long form (DM-86 FIX)
        "comms-app": [
            {
                "type": "bind",
                "source": str(item.target),
                "target": "/primer/data/profile",
                "read_only": True,
            }
        ]
    }
    assert env == {"comms-app": {"PROFILE_DIR": "/primer/data/profile"}}
    comms = _service(tmp_path)
    compose = ComposeStack(
        comms, "comms", tmp_path / "r", "v1.0.0", SHA, tmp_path, staged_env=True
    )
    document: dict[str, Json] = {
        "services": {"comms-app": {"image": "x"}, "comms-redis": {"image": "r"}}
    }
    rendered = json.loads(
        override_text(
            compose, document, mounts, None, env, proxy=False, references=document
        )
    )
    app = rendered["services"]["comms-app"]
    assert app["volumes"] == mounts["comms-app"]
    assert app["environment"] == {"PROFILE_DIR": "/primer/data/profile"}
    assert "environment" not in rendered["services"]["comms-redis"]
    # the pair: no data -- neither binds nor variables
    assert data_binds([], "comms-app") == ({}, {})


def test_data_items_take_the_product_dir_and_the_package_section(
    tmp_path: Path,
) -> None:
    made = _product(
        tmp_path,
        dependencies={"comms": {**COMMS_REPO, "data": {"profile": "comms-profile"}}},
        packages={
            "texts": {
                "contract": ">=1,<2",
                "validate": "v <dir>",
                "mount": [
                    {"dependency": "comms", "from": "comms", "env": "OV"},
                    {"service": "app", "path": "/srv/t"},
                ],
            }
        },
    )
    comms = _service(
        tmp_path,
        accepts={**ACCEPTS, "texts": {"validate": "t <dir>", "env": "OV"}},
    )
    data = passport_data()
    data["packages"] = {"texts": {"repo": "git@github.com:p/t.git", "version": "1.0.0"}}
    root, fetched = box(tmp_path, data)
    assert fetched.passport is not None
    release = tmp_path / "rel"
    items = data_items(
        made,
        comms,
        release_dir=release,
        release="v2",
        passport=fetched.passport,
        root=root,
    )
    home = root / "opt" / "comms" / "data" / "aivis@v2"
    assert [(i.kind, i.source, i.home, i.env) for i in items] == [
        ("profile", release / "comms-profile", home, "PD"),
        (
            "texts",
            root / "opt" / "aivis" / "releases" / "t@1.0.0" / "comms",
            home,
            "OV",
        ),
    ]
    # DM-81: the copy is named by what its source holds (nothing here yet)
    empty = digest([])
    assert [i.target for i in items] == [
        home / f"profile@{empty}",
        home / f"texts@{empty}",
    ]
    # the pair: a passport without the package has no section to copy
    root, fetched = box(tmp_path / "no", passport_data())
    assert fetched.passport is not None
    items = data_items(
        made,
        comms,
        release_dir=release,
        release="v2",
        passport=fetched.passport,
        root=root,
    )
    assert [i.kind for i in items] == ["profile"]


# --- data_copy --------------------------------------------------------------------


def _copy(tmp: Path) -> tuple[DataCopy, ComposeStack, DataItem]:
    comms = _service(tmp, accepts=ACCEPTS)
    root = tmp / "box"
    release = root / "opt" / "comms" / "releases" / "v1.0.0"
    release.mkdir(parents=True)
    item = _item(tmp)
    item.source.mkdir(parents=True)
    (item.source / "kinds.yaml").write_text("kinds: [a]\n")
    handoff = OverrideHandoff()
    step = DataCopy(
        comms,
        "comms",
        release=release,
        ref="v1.0.0",
        commit=SHA,
        items=[item],
        handoff=handoff,
        root=root,
    )
    return (
        step,
        ComposeStack(comms, "comms", release, "v1.0.0", SHA, root, staged_env=True),
        item,
    )


def _hashes(compose: ComposeStack, running: str) -> list[FakeCall]:
    """``stale`` of the service: ``config --hash``, ``ps -q``, the labels."""
    return [
        FakeCall(
            tuple(compose.argv("config", "--hash", "*")),
            lines=stdout(f"comms-app {'a' * 64}"),
        ),
        FakeCall(tuple(compose.argv("ps", "-q")), lines=stdout("c-app")),
        FakeCall(
            ("docker", "inspect", "-f", RUNNING_HASH_FORMAT, "c-app"),
            lines=stdout(f"comms-app {running}"),
        ),
    ]


def test_data_copy_refuses_a_directory_that_is_not_there(tmp_path: Path) -> None:
    step, _, item = _copy(tmp_path)
    (item.source / "kinds.yaml").unlink()
    item.source.rmdir()
    outcome, _ = run([step], FakeRunner())
    [record] = outcome.steps
    assert record.reason is not None and record.reason.code == "data_copy:data-missing"
    assert not item.target.exists()


def test_data_copy_refuses_a_symlink_out_of_the_product(tmp_path: Path) -> None:
    step, _, item = _copy(tmp_path)
    (item.source / "leak").symlink_to("/etc")
    outcome, _ = run([step], FakeRunner())
    [record] = outcome.steps
    assert record.reason is not None and record.reason.code == "data_copy:data-unsafe"
    assert record.reason.params["paths"] == ["profile-dir/leak"]
    assert not item.target.exists()
    # the pair: a link inside the product is copied as a link
    (item.source / "leak").unlink()
    (item.source / "same").symlink_to("kinds.yaml")
    assert step.check(context(FakeRunner())).needed


def test_an_unchanged_copy_on_a_service_on_its_configuration_needs_nothing(
    tmp_path: Path,
) -> None:
    """``doctor`` stays empty on a box whose service runs on its copy; the pair
    -- the service off its configuration (a new image): validated again."""
    step, compose, item = _copy(tmp_path)
    item.target.parent.mkdir(parents=True)
    (item.target).mkdir()
    (item.target / "kinds.yaml").write_text("kinds: [a]\n")
    assert tree(item.target) == tree(item.source)
    with FakeRunner(*_hashes(compose, "a" * 64)) as runner:
        check = step.check(context(runner))
    assert not check.needed
    with FakeRunner(*_hashes(compose, "b" * 64)) as runner:
        check = step.check(context(runner))
    assert check.needed and check.data == {"validate": True}
    assert check.would is not None and check.would.code == "validate"


def test_changed_data_is_a_new_copy_and_the_old_one_stays(tmp_path: Path) -> None:
    """Changed by DM-79: the validate of the data drops every capability and never
    pulls the image of this run.

    Changed by DM-81 (was ``test_a_changed_copy_is_copied_again_and_validated``):
    a copy is never replaced -- a running container mounts its inode, and one
    replaced under it leaves the service on an empty directory. Changed data
    is a new copy, named by what it holds, validated there; the old copy, which
    the running service mounts, is as it was."""
    step, compose, item = _copy(tmp_path)
    old = item.home / "profile@0123456789abcdef"
    old.mkdir(parents=True)
    (old / "kinds.yaml").write_text("kinds: [old]\n")
    labels = [
        word
        for key, value in compose.release_labels().items()
        for word in ("--label", f"{key}={value}")
    ]
    validate = FakeCall(
        (
            "docker",
            "run",
            "--rm",
            "--network",
            "none",
            "--cap-drop",
            "ALL",
            "--pull",
            "never",
            *labels,
            "--mount",  # never -v: it splits at a colon (DM-86 FIX)
            f"type=bind,source={item.target},target={item.container},readonly",
            "-e",
            "PROFILE_DIR=/primer/data/profile",
            IMAGE,
            "comms",
            "validate",
            "--profile",
            "/primer/data/profile",
        )
    )
    with FakeRunner(image_call(compose, "comms-app", IMAGE), validate) as runner:
        outcome, _ = run([step], runner)
    assert outcome.code is ExitCode.OK, outcome.steps
    assert (item.target / "kinds.yaml").read_text() == "kinds: [a]\n"
    assert item.target != old and item.target.name.startswith("profile@")
    assert (old / "kinds.yaml").read_text() == "kinds: [old]\n"
    assert not item.target.with_name(item.target.name + ".tmp").exists()


# --- seams_verify -----------------------------------------------------------------


def _verify(
    tmp: Path, product_app: LiveApp, comms_app: LiveApp
) -> tuple[SeamsVerify, list[FakeCall]]:
    product_env = {"COMMS_API_URL": {"source": "seam", "from": "comms"}}
    data = product_data(
        product_env,
        dependencies={"comms": COMMS_REPO},
        provides={"PRODUCT_WEBHOOK_URL": {"from": "domains.api", "path": "/w"}},
    )
    stacks = data["stacks"]
    assert isinstance(stacks, dict)
    stacks["aivis"]["app"].update(
        {"port": product_app.port, "health": "/health", "ready": "/ready"}
    )
    made = load(tmp, data)
    assert isinstance(made, Product)
    sdata = base_service_data(
        {
            "COMMS_API_URL": {"source": "address"},
            "PRODUCT_WEBHOOK_URL": {"source": "seam", "from": "product"},
        },
        provides=["COMMS_API_URL"],
        requires=["PRODUCT_WEBHOOK_URL"],
    )
    sstacks = sdata["stacks"]
    assert isinstance(sstacks, dict)
    sstacks["comms"]["app"]["port"] = comms_app.port
    comms = load(tmp, sdata)
    assert isinstance(comms, Service)
    root = tmp / "box"
    stacks_of = {
        "aivis": ComposeStack(
            made, "aivis", root / "a", "main", SHA, root, staged_env=True
        ),
        "comms": ComposeStack(
            comms, "comms", root / "c", "v1.0.0", SHA, root, staged_env=True
        ),
    }
    step = SeamsVerify(made, {"comms": comms}, stacks_of)
    calls = [
        *_observe(stacks_of["aivis"], "app"),
        *_observe(stacks_of["comms"], "comms-app"),
    ]
    return step, calls


def _observe(compose: ComposeStack, app: str) -> list[FakeCall]:
    """``observe_calls`` of the blank's ``app``, its last word -- the service
    of ``ps`` and ``logs`` -- the stack's own app, its log line named by the
    stack (DM-72)."""
    own = len(compose.product_argv())
    fixed = []
    for call in observe_calls(compose, logs=(log_line(compose.stack.name),)):
        argv = call.argv
        if len(argv) > own and argv[own] in ("ps", "logs") and argv[-1] == "app":
            argv = (*argv[:-1], app)
        fixed.append(FakeCall(argv, lines=call.lines))
    return fixed


@pytest.mark.parametrize(
    ("product_seams", "comms_seams", "code"),
    [
        (
            {"provides": ["PRODUCT_WEBHOOK_URL"], "requires_satisfied": True},
            {"provides": ["COMMS_API_URL"], "requires_satisfied": True},
            None,
        ),
        (
            {"provides": ["PRODUCT_WEBHOOK_URL"], "requires_satisfied": True},
            {"provides": [], "requires_satisfied": True},
            "seams_verify:provide-not-live",
        ),
        (
            {"provides": [], "requires_satisfied": True},
            {"provides": ["COMMS_API_URL"], "requires_satisfied": True},
            "seams_verify:provide-not-live",
        ),
        (
            {"provides": ["PRODUCT_WEBHOOK_URL"], "requires_satisfied": True},
            {"provides": ["COMMS_API_URL"], "requires_satisfied": False},
            "seams_verify:requires-unsatisfied",
        ),
        (
            {"provides": ["PRODUCT_WEBHOOK_URL"], "requires_satisfied": False},
            {"provides": ["COMMS_API_URL"], "requires_satisfied": True},
            "seams_verify:requires-unsatisfied",
        ),
    ],
)
def test_seams_are_read_from_the_live_providers(
    tmp_path: Path,
    two_apps: tuple[LiveApp, LiveApp],
    product_seams: dict[str, Json],
    comms_seams: dict[str, Json],
    code: str | None,
) -> None:
    """A seam the rendered file holds but the live provider does not say is
    red; so is a consumer that says its seams are not satisfied."""
    product_app, comms_app = two_apps
    product_app.health = health(seams=product_seams, service="aivis")
    comms_app.health = health(seams=comms_seams, service="comms")
    step, calls = _verify(tmp_path, product_app, comms_app)
    runner = FakeRunner(*calls, *calls)  # check, then verify
    outcome, _ = run([step], runner)
    [record] = outcome.steps
    if code is None:
        assert outcome.code is ExitCode.OK, record
        assert record.verify["seams"] == [
            "aivis.COMMS_API_URL <- comms",
            "comms.PRODUCT_WEBHOOK_URL <- aivis",
        ]
        runner.assert_consumed()
    else:
        assert record.reason is not None and record.reason.code == code


# --- tests with test.services -----------------------------------------------------


def test_test_services_come_up_with_the_database(tmp_path: Path) -> None:
    """A service ``test.services`` names that the compose has not is refused
    before a command reaches the database; the pair: it comes up with it."""
    data = example("product.yaml")
    stacks = data["stacks"]
    assert isinstance(stacks, dict)
    stacks["aivis"]["test"]["services"] = ["redis"]
    made = load(tmp_path, data)
    assert isinstance(made, Product)
    root = tmp_path / "box"
    step = Tests(
        made,
        "aivis",
        release=root / "r",
        ref="main",
        commit=SHA,
        report=TestReport(),
        secrets=Secrets(()),
        root=root,
    )
    compose = ComposeStack(
        made, "aivis", root / "r", "main", SHA, root, staged_env=True
    )
    document = json.loads(json.dumps(CONFIG))
    document["services"]["app"]["environment"] = {
        "DATABASE_URL": "postgresql://u:p@postgres:5432/aivis"
    }
    config = FakeCall(
        tuple(compose.product_argv("config", "--format", "json")),
        lines=stdout(json.dumps(document)),
    )
    with FakeRunner(config) as runner, pytest.raises(StepFailed) as refused:
        step._database(context(runner))
    assert refused.value.reason.code == "test-service-unknown"
    assert refused.value.reason.params["services"] == ["redis"]
    document["services"]["redis"] = {"image": "redis"}
    config = FakeCall(config.argv, lines=stdout(json.dumps(document)))
    up = FakeCall(
        tuple(
            compose.argv(
                "up", "-d", "--no-build", "--no-recreate", "--wait", "postgres", "redis"
            )
        )
    )
    exists = FakeCall(
        tuple(
            compose.argv(
                "exec",
                "-T",
                "postgres",
                "psql",
                "-U",
                "u",
                "-d",
                "postgres",
                "-tAc",
                "SELECT 1 FROM pg_database WHERE datname = 'aivis_test'",
            )
        ),
        lines=stdout("1"),
    )
    with FakeRunner(config, up, exists) as runner:
        found, _ = step._database(context(runner))
        step._database_up(context(runner), found)


# --- gc of the copies -------------------------------------------------------------


def test_gc_keeps_mounted_current_previous_copies_then_the_newest(
    tmp_path: Path,
) -> None:
    home = tmp_path / "opt" / "comms" / "data"
    names = ["aivis@cur", "aivis@prev", "aivis@mounted", "aivis@old", "aivis@new"]
    for index, name in enumerate(names):
        (home / name).mkdir(parents=True)
        os.utime(home / name, (index, index))
    (home / "aivis@x.tmp").mkdir()
    box_ = Box(tmp_path / "opt" / "pridem")
    step = Gc(box=box_, run_id="r", fetched=Fetched(), root=tmp_path)
    known = _Known(
        current={"aivis": Path("/opt/aivis/releases/cur")},
        previous={"aivis": "prev"},
        commits=set(),
        names=set(),
        damaged=0,
    )
    mounts = [home / "aivis@mounted" / "profile"]
    policy = GcPolicy(keep_releases=4, builder_cache_budget="1G", journal_budget="1M")
    gone = step._data_gone("comms", policy, known, mounts)
    assert gone == [home / "aivis@old"]
    policy = GcPolicy(keep_releases=1, builder_cache_budget="1G", journal_budget="1M")
    gone = step._data_gone("comms", policy, known, mounts)
    assert sorted(gone) == [home / "aivis@new", home / "aivis@old"]


# --- the ladder of a service ------------------------------------------------------


def test_a_services_ladder_validates_its_data_before_the_point_of_no_return(
    tmp_path: Path,
) -> None:
    """``render_env -> build -> [derive_env] -> data_copy -> stop_for_migrate ->
    migrate -> up``: a
    red ``validate`` stops the ladder before ``migrate``; no tests on the
    product's box (protocol 7.4).

    Changed by DM-67: comms has a ``derived`` value, so ``derive_env`` follows
    its ``build``; payments has none and no such step.

    Changed by DM-22: ``stop_for_migrate`` stands before every ``migrate``,
    before the point of no return -- with no list it has nothing to do."""
    made, _ = planned(tmp_path, "full")
    ladders = {
        s.name: [step.name for step in s.steps] for s in deferred(made, "services")
    }
    assert ladders["comms"] == [
        "render_env",
        "build",
        "derive_env",
        "data_copy",
        "stop_for_migrate",
        "migrate",
        "up",
    ]
    assert ladders["payments"] == [
        "render_env",
        "build",
        "data_copy",
        "stop_for_migrate",
        "migrate",
        "up",
    ]
    assert list(ladders)[:3] == ["seams", "comms", "payments"]


def test_a_product_with_derived_gets_derive_env_after_its_build(
    tmp_path: Path,
) -> None:
    """DM-67: the product's own entry with a ``derived`` value -- ``derive_env``
    right after its ``build``, holding that very ``build``; the pair: without
    one, the product's ladder has no such step."""
    env: dict[str, object] = {
        "API_SIGNING_KEY": {"source": "derived", "run": "python -m app derive key"}
    }
    made, _ = planned(tmp_path / "with", "core", product_env=env)
    [own, *_] = deferred(made, "product")
    names = [step.name for step in own.steps]
    assert names[:3] == ["render_env", "build", "derive_env"]
    assert own.steps[2].build is own.steps[1]  # type: ignore[attr-defined]
    made, _ = planned(tmp_path / "without", "core")
    [own, *_] = deferred(made, "product")
    assert "derive_env" not in [step.name for step in own.steps]


@pytest.mark.parametrize(
    ("editions", "edition"),
    [({}, "full"), ({"core": {"services": ["comms"]}}, None)],
)
def test_seams_check_takes_an_edition_only_where_the_product_has_editions(
    tmp_path: Path, editions: dict[str, object], edition: str | None
) -> None:
    """No ``editions`` -- the passport's edition is not the product's question;
    none in the passport -- ``render_env`` asks it (contract 1 rule 3)."""
    made = _product(tmp_path, editions=editions)
    root, fetched = box(tmp_path, passport_data(edition=edition))
    comms = _service(tmp_path)
    outcome, _ = run([SeamsCheck(made, {"comms": comms}, fetched, root)], FakeRunner())
    assert outcome.code is ExitCode.OK, outcome.steps


def test_an_empty_directory_is_copied_too(tmp_path: Path) -> None:
    """The service gets the directory it takes even when it is empty: a bind of
    a path that is not there would be made by docker, as root, empty.

    Changed by DM-79: the validate of the data drops every capability and never
    pulls the image of this run."""
    step, compose, item = _copy(tmp_path)
    (item.source / "kinds.yaml").unlink()
    labels = [
        word
        for key, value in compose.release_labels().items()
        for word in ("--label", f"{key}={value}")
    ]
    validate = FakeCall(
        (
            "docker",
            "run",
            "--rm",
            "--network",
            "none",
            "--cap-drop",
            "ALL",
            "--pull",
            "never",
            *labels,
            "--mount",  # never -v: it splits at a colon (DM-86 FIX)
            f"type=bind,source={item.target},target={item.container},readonly",
            "-e",
            "PROFILE_DIR=/primer/data/profile",
            IMAGE,
            "comms",
            "validate",
            "--profile",
            "/primer/data/profile",
        )
    )
    with FakeRunner(image_call(compose, "comms-app", IMAGE), validate) as runner:
        outcome, _ = run([step], runner)
    assert outcome.code is ExitCode.OK, outcome.steps
    assert item.target.is_dir() and tree(item.target) == []


def test_build_puts_a_services_data_into_the_override(tmp_path: Path) -> None:
    """The bind of the copy and its variable go into the candidate override of
    the entry's ``app``; the pair: without data, the override of before."""
    cs = compose(tmp_path)
    item = _item(tmp_path)
    build = Build(
        cs.stack,
        cs.entry,
        release=cs.release,
        ref=cs.ref,
        commit=cs.commit,
        root=tmp_path,
        handoff=OverrideHandoff(),
        data=[item],
    )
    with FakeRunner(*green_build(tmp_path)) as runner:
        outcome, _ = run([build], runner)
    assert outcome.code is ExitCode.OK, outcome.steps
    mounts, env = data_binds([item], "app")
    assert cs.candidate().override.read_text() == override_text(
        cs, CONFIG, mounts, None, env, proxy=False, references=CONFIG
    )
    assert cs.candidate().override.read_text() != override_text(
        cs, CONFIG, proxy=False, references=CONFIG
    )


def test_finalize_makes_the_services_current_with_the_product(tmp_path: Path) -> None:
    """``current`` and the composition name every installed service at its
    tag beside the product: ``gc`` and ``destroy`` read them."""
    made, root = planned(tmp_path, "full")
    [stack] = deferred(made, "finalize")
    [final] = [step for step in stack.steps if isinstance(step, Finalize)]
    releases = root / "opt"
    assert final.releases["comms"] == releases / "comms" / "releases" / "v1.0.0"
    assert final.releases["payments"] == releases / "payments" / "releases" / "v1.0.0"
    assert {k: v for k, v in final.composition.items() if k != "pridem"} == {
        "aivis": final.releases["aivis"].name,
        "comms": "v1.0.0",
        "payments": "v1.0.0",
    }
