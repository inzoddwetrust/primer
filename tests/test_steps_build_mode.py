"""DM-61: a package of ``apply: build`` is built into the image of its service
-- a context with the package out of the release, ``PRIMER_EDITION``, the
image's key -- and a new version of the package or another edition makes a new
build on the same commit, the same ones none. Where a package goes is the
product's, not one compose's; the names the machine gives on its networks are
not a product's service's.

The commands are a strict ``FakeRunner`` scenario; the compose ``config`` is
the blank's (``compose_support.CONFIG``), its contexts in the release.
"""

import io
import json
from collections.abc import Mapping, Sequence
from pathlib import Path

import pytest
import yaml
from compose_support import CONFIG, ENTRY, REF, SHA, in_release, stdout
from env_support import box, passport_data
from plan_support import ListSink
from test_probe_DM_57_check import _env, version_call

from pridem.cli import run as cli
from pridem.events import Code, Json, PlanOutcome, Secrets
from pridem.plan import Plan, StackSteps
from pridem.report.codes import ExitCode
from pridem.runner import FakeCall, FakeRunner, OnLine, Result, Stream
from pridem.stacks.schema import PRIMER_YAML, Product, Service, _check
from pridem.steps.base import Step, StepContext
from pridem.steps.build import Build, copied_dockerfile
from pridem.steps.compose import (
    ComposeStack,
    forbidden,
    package_places,
    refusal,
    reserved,
)
from pridem.steps.migrate import Migrate
from pridem.steps.packages import (
    context_dir,
    image_key,
    package_mounts,
    write_context,
)
from pridem.steps.passport import Fetched
from pridem.steps.tests import TestReport, Tests
from pridem.steps.up import Up

APP_IMAGE = "sha256:" + "a" * 64
FRONT_IMAGE = "sha256:" + "f" * 64
SKIN = "git@github.com:partner/velo-look.git"


def product_data(
    *,
    service: str = "frontend",
    editions: bool = True,
    apply: str = "build",
) -> dict[str, object]:
    """The blank with a skin built into ``service`` at ``public/skin``."""
    package: dict[str, object] = {"contract": ">=1,<2", "apply": apply}
    if apply == "build":
        package["build"] = [{"service": service, "path": "public/skin"}]
    else:
        package["validate"] = "validate-skin <dir>"
        package["mount"] = [{"service": service, "path": "/srv/skin"}]
    data: dict[str, object] = {
        "schema": 1,
        "name": "blank",
        "kind": "product",
        "stacks": {
            "blank": {
                "compose": "docker-compose.yml",
                "app": {"service": "app", "port": 8000, "health": "/h", "ready": "/r"},
                "frontend": {"service": "frontend", "port": 80},
                "migrate": "python -m alembic upgrade head",
                "test": {"run": "pytest", "target": "test"},
            }
        },
        "env": {},
        "packages": {"skin": package},
        "report": {"health": "/h", "ready": "/r", "logs": "json", "junit": True},
    }
    if editions:
        data["editions"] = {"core": {"services": []}, "full": {"services": []}}
    return data


def made(data: Mapping[str, object]) -> Product:
    stack = PRIMER_YAML.validate_python(data)
    assert isinstance(stack, Product)
    return stack


def problems(data: Mapping[str, object]) -> list[tuple[str, str]]:
    _, found = _check(dict(data))
    return [(p.path, p.code) for p in found]


def skin_box(
    tmp: Path, version: str | None = "1.4.2", edition: str | None = "full"
) -> tuple[Path, Fetched]:
    """A box with the release of the blank (contexts ``backend``, ``frontend``
    with a skin of its own in ``public/skin``) and the skin's package."""
    data = passport_data(edition=edition)
    if version is not None:
        data["packages"] = {"skin": {"repo": SKIN, "version": version}}
    root, fetched = box(tmp, data)
    release = root / "release"
    for context in ("backend", "frontend"):
        (release / context).mkdir(parents=True, exist_ok=True)
        (release / context / "Dockerfile").write_text(f"FROM {context}\n")
    (release / "frontend" / "public" / "skin").mkdir(parents=True)
    (release / "frontend" / "public" / "skin" / "built-in.css").write_text("old")
    if version is not None:
        package = root / "opt" / ENTRY / "releases" / f"velo-look@{version}"
        package.mkdir(parents=True)
        (package / "skin.css").write_text(version)
        (package / ".git").write_text("gitdir: elsewhere\n")
    return root, fetched


def compose(root: Path, stack: Product, entry: str = ENTRY) -> ComposeStack:
    return ComposeStack(stack, entry, root / "release", REF, SHA, root)


def config_call(
    cs: ComposeStack, document: Mapping[str, Json] = CONFIG, *, raw: bool = False
) -> FakeCall:
    args = ["config", "--format", "json", *(["--no-interpolate"] if raw else [])]
    return FakeCall(
        tuple(cs.product_argv(*args)),
        lines=stdout(json.dumps(in_release(document, cs.release))),
    )


def image_call(
    cs: ComposeStack, service: str, key: Mapping[str, str], *ids: str
) -> FakeCall:
    filters = [
        f"label=pridem.stack={cs.entry}",
        f"label=pridem.commit={cs.commit}",
        f"label=pridem.service={service}",
        *(f"label={k}={v}" for k, v in sorted(key.items())),
    ]
    argv = ["docker", "image", "ls", "--quiet", "--no-trunc"]
    argv += [word for found in filters for word in ("--filter", found)]
    return FakeCall(tuple(argv), lines=stdout(*ids))


def build_call(cs: ComposeStack, code: int = 0) -> FakeCall:
    argv = cs.argv(
        "build",
        "--build-arg",
        f"PRIMER_RELEASE={cs.ref}",
        "--build-arg",
        f"PRIMER_COMMIT={cs.commit}",
    )
    return FakeCall(tuple(argv), code=code, lines=stdout("built"))


def key_of(version: str = "1.4.2", edition: str | None = "full") -> dict[str, str]:
    key = {"pridem.package.skin": f"velo-look@{version}"}
    if edition is not None:
        key["pridem.edition"] = edition
    return key


def verify_calls(cs: ComposeStack, key: Mapping[str, str]) -> list[FakeCall]:
    return [
        config_call(cs),
        image_call(cs, "app", {}, APP_IMAGE),
        image_call(cs, "frontend", key, FRONT_IMAGE),
    ]


def first_build(cs: ComposeStack, key: Mapping[str, str]) -> list[FakeCall]:
    """No override yet: check reads, act builds, verify finds by the key."""
    return [
        config_call(cs, raw=True),
        config_call(cs),
        config_call(cs),
        build_call(cs),
        *verify_calls(cs, key),
    ]


def build(root: Path, stack: Product, fetched: Fetched, entry: str = ENTRY) -> Build:
    return Build(
        stack,
        entry,
        release=root / "release",
        ref=REF,
        commit=SHA,
        root=root,
        fetched=fetched,
    )


def run(steps: list[Step], runner: FakeRunner) -> PlanOutcome:
    return Plan(
        [StackSteps(ENTRY, steps, root=True)],
        mode="install",
        role="test",
        runner=runner,
        sink=ListSink(),
    ).run()


def override(cs: ComposeStack) -> dict[str, Json]:
    loaded = json.loads(cs.override.read_text())
    assert isinstance(loaded, dict)
    return loaded


def at(value: object, *keys: str) -> object:
    for key in keys:
        assert isinstance(value, dict), key
        value = value[key]
    return value


def builds(text: str) -> int:
    return text.count("build")


# --- probe -------------------------------------------------------------------------


def test_probe_DM_61_build_mode_rebuilds_on_package_version_only(
    tmp_path: Path,
) -> None:
    """A new version of the package, or another edition, is a build of the
    service on the same commit; the same version and edition are none (the
    pair: no build command in the scenario)."""
    stack = made(product_data())
    root, fetched = skin_box(tmp_path)
    cs = compose(root, stack)
    with FakeRunner(*first_build(cs, key_of())) as runner:
        assert run([build(root, stack, fetched)], runner).code is ExitCode.OK

    # the same version and edition: no build -- the scenario has none
    same = [
        config_call(cs, raw=True),
        config_call(cs),
        image_call(cs, "app", {}, APP_IMAGE),
        image_call(cs, "frontend", key_of(), FRONT_IMAGE),
        *verify_calls(cs, key_of()),
    ]
    with FakeRunner(*same) as runner:
        outcome = run([build(root, stack, fetched)], runner)
    assert outcome.code is ExitCode.OK, outcome.steps
    assert outcome.steps[0].verify is not None

    # a new version of the skin on the same commit: a build
    root2, fetched2 = skin_box(tmp_path / "next", version="1.4.3")
    cs2 = compose(root2, stack)
    cs2.override.parent.mkdir(parents=True, exist_ok=True)
    cs2.override.write_text(cs.override.read_text())  # the old version's
    script = [
        config_call(cs2, raw=True),
        config_call(cs2),  # the override differs: build
        config_call(cs2),
        build_call(cs2),
        *verify_calls(cs2, key_of("1.4.3")),
    ]
    with FakeRunner(*script) as runner:
        outcome = run([build(root2, stack, fetched2)], runner)
    assert outcome.code is ExitCode.OK, outcome.steps
    assert at(override(cs2), "services", "frontend", "build", "labels") == {
        "pridem.stack": ENTRY,
        "pridem.release": REF,
        "pridem.commit": SHA,
        "pridem.service": "frontend",
        **key_of("1.4.3"),
    }

    # another edition, the same version: a build
    root3, fetched3 = skin_box(tmp_path / "core", edition="core")
    cs3 = compose(root3, stack)
    cs3.override.parent.mkdir(parents=True, exist_ok=True)
    cs3.override.write_text(cs.override.read_text())  # the edition full's
    script = [
        config_call(cs3, raw=True),
        config_call(cs3),
        config_call(cs3),
        build_call(cs3),
        *verify_calls(cs3, key_of(edition="core")),
    ]
    with FakeRunner(*script) as runner:
        outcome = run([build(root3, stack, fetched3)], runner)
    assert outcome.code is ExitCode.OK, outcome.steps
    assert at(override(cs3), "services", "frontend", "build", "args") == {
        "PRIMER_EDITION": "core"
    }


def test_same_override_but_no_image_of_the_key_builds(tmp_path: Path) -> None:
    """The override is not enough: no image of the key -- a build."""
    stack = made(product_data())
    root, fetched = skin_box(tmp_path)
    cs = compose(root, stack)
    with FakeRunner(*first_build(cs, key_of())) as runner:
        run([build(root, stack, fetched)], runner)
    script = [
        config_call(cs, raw=True),
        config_call(cs),
        image_call(cs, "app", {}, APP_IMAGE),
        image_call(cs, "frontend", key_of()),  # none of this key
        config_call(cs),
        build_call(cs),
        *verify_calls(cs, key_of()),
    ]
    with FakeRunner(*script) as runner:
        assert run([build(root, stack, fetched)], runner).code is ExitCode.OK


# --- the schema of a slot ----------------------------------------------------------


def test_a_slot_is_runtime_by_default_and_build_when_declared() -> None:
    assert problems(product_data()) == []
    assert problems(product_data(apply="runtime")) == []
    data = product_data(apply="runtime")
    skin = at(data, "packages", "skin")
    assert isinstance(skin, dict)
    del skin["apply"]
    assert made(data).packages["skin"].apply == "runtime"


@pytest.mark.parametrize(
    ("change", "found"),
    [
        ({"build": []}, [("packages.skin", "R10.apply")]),
        (
            {"mount": [{"service": "frontend", "path": "/srv/skin"}]},
            [("packages.skin.mount", "R10.apply")],
        ),
        ({"validate": "check <dir>"}, [("packages.skin.validate", "R10.apply")]),
        (
            {"build": [{"service": "frontend", "path": "../x"}]},
            [("packages.skin.build[0].path", "R10.build")],
        ),
        (
            {"build": [{"service": "frontend", "path": "/srv/skin"}]},
            [("packages.skin.build[0].path", "R10.build")],
        ),
        (
            {"build": [{"service": "frontend", "path": "."}]},
            [("packages.skin.build[0].path", "R10.build")],
        ),
        (
            {"build": [{"service": "frontend", "path": "a//b"}]},
            [("packages.skin.build[0].path", "R10.build")],
        ),
        (
            {"build": [{"service": "frontend", "path": "public/skin"}] * 2},
            [("packages.skin.build[1]", "R10.build")],
        ),
    ],
)
def test_a_build_slot_is_refused_by_rule_10(
    change: dict[str, object], found: list[tuple[str, str]]
) -> None:
    data = product_data()
    skin = at(data, "packages", "skin")
    assert isinstance(skin, dict)
    skin.update(change)
    assert problems(data) == found


@pytest.mark.parametrize(
    ("change", "found"),
    [
        ({"mount": []}, [("packages.skin", "R10.apply")]),
        (
            {"build": [{"service": "frontend", "path": "public/skin"}]},
            [("packages.skin.build", "R10.apply")],
        ),
        ({"validate": None}, [("packages.skin", "R10.apply")]),
    ],
)
def test_a_runtime_slot_is_refused_by_rule_10(
    change: dict[str, object], found: list[tuple[str, str]]
) -> None:
    data = product_data(apply="runtime")
    skin = at(data, "packages", "skin")
    assert isinstance(skin, dict)
    skin.update(change)
    if skin.get("validate") is None:
        skin.pop("validate")
    assert problems(data) == found


# --- the build -----------------------------------------------------------------------


def test_the_package_is_built_from_a_context_out_of_the_release(tmp_path: Path) -> None:
    stack = made(product_data())
    root, fetched = skin_box(tmp_path)
    cs = compose(root, stack)
    with FakeRunner(*first_build(cs, key_of())) as runner:
        outcome = run([build(root, stack, fetched)], runner)
    assert outcome.code is ExitCode.OK, outcome.steps
    target = context_dir(root, "blank", ENTRY, "frontend")
    assert target == root / "opt" / "blank" / "contexts" / "blank" / "frontend"
    # the copy: the Dockerfile, the package in place of public/skin, no .git
    assert (target / "Dockerfile").read_text() == "FROM frontend\n"
    assert (target / "public" / "skin" / "skin.css").read_text() == "1.4.2"
    assert not (target / "public" / "skin" / "built-in.css").exists()
    assert not (target / "public" / "skin" / ".git").exists()
    assert not target.with_name("frontend.tmp").exists()
    # the release is untouched
    skin = root / "release" / "frontend" / "public" / "skin"
    assert sorted(path.name for path in skin.iterdir()) == ["built-in.css"]
    # the override: the context, its Dockerfile, the edition, the key
    front = at(override(cs), "services", "frontend", "build")
    assert isinstance(front, dict)
    assert front["context"] == str(target)
    assert front["dockerfile"] == "Dockerfile"
    assert front["args"] == {"PRIMER_EDITION": "full"}
    assert at(front, "labels", "pridem.edition") == "full"
    assert at(front, "labels", "pridem.package.skin") == "velo-look@1.4.2"
    # the pair: app has none of it, only the labels of its commit
    app = at(override(cs), "services", "app", "build")
    assert app == {
        "labels": {
            "pridem.stack": ENTRY,
            "pridem.release": REF,
            "pridem.commit": SHA,
            "pridem.service": "app",
        }
    }
    fact = outcome.steps[0].verify
    assert fact is not None and fact["keys"] == {"frontend": key_of()}


def test_without_editions_no_edition_goes_to_the_build(tmp_path: Path) -> None:
    stack = made(product_data(editions=False))
    root, fetched = skin_box(tmp_path)
    cs = compose(root, stack)
    with FakeRunner(*first_build(cs, key_of(edition=None))) as runner:
        outcome = run([build(root, stack, fetched)], runner)
    assert outcome.code is ExitCode.OK, outcome.steps
    front = at(override(cs), "services", "frontend", "build")
    assert isinstance(front, dict)
    assert "args" not in front
    labels = at(front, "labels")
    assert isinstance(labels, dict) and "pridem.edition" not in labels


@pytest.mark.parametrize(
    ("version", "edition", "code"),
    [
        (None, "full", Code("build:package-missing", {"slot": "skin"})),
        ("1.4.2", None, Code("build:edition-missing", {"service": "frontend"})),
        ("1.4.2", "gold", Code("build:edition-unknown", {"edition": "gold"})),
    ],
)
def test_the_build_needs_the_package_and_an_edition_of_editions(
    tmp_path: Path, version: str | None, edition: str | None, code: Code
) -> None:
    stack = made(product_data())
    root, fetched = skin_box(tmp_path, version=version, edition=edition)
    cs = compose(root, stack)
    with FakeRunner(config_call(cs, raw=True), config_call(cs)) as runner:
        outcome = run([build(root, stack, fetched)], runner)
    assert outcome.steps[0].reason == code
    assert not cs.override.exists()


def test_a_package_not_on_the_box_is_red_before_the_build(tmp_path: Path) -> None:
    stack = made(product_data())
    root, fetched = skin_box(tmp_path)
    package = root / "opt" / ENTRY / "releases" / "velo-look@1.4.2"
    for path in package.iterdir():
        path.unlink()
    package.rmdir()
    cs = compose(root, stack)
    with FakeRunner(config_call(cs, raw=True), config_call(cs)) as runner:
        outcome = run([build(root, stack, fetched)], runner)
    assert outcome.steps[0].reason == Code(
        "build:missing-release", {"slot": "skin", "path": str(package)}
    )


def test_a_failed_build_leaves_the_running_image(tmp_path: Path) -> None:
    """The product's build is the package's check: red, and nothing switched
    -- no ``up`` in the scenario, the step is red."""
    stack = made(product_data())
    root, fetched = skin_box(tmp_path)
    cs = compose(root, stack)
    script = [config_call(cs, raw=True), config_call(cs), config_call(cs)]
    with FakeRunner(*script, build_call(cs, code=1)) as runner:
        outcome = run([build(root, stack, fetched)], runner)
    assert outcome.code is not ExitCode.OK
    reason = outcome.steps[0].reason
    assert reason is not None and reason.code == "command-failed"
    argv = at(reason.params, "argv")
    assert isinstance(argv, list) and "build" in argv


def test_the_product_config_is_read_without_the_override(tmp_path: Path) -> None:
    """``PRIMER_EDITION`` is the machine's build argument, in its override: the
    ``config`` refused by is the product's alone, so ``instance-args`` never
    meets it (the strict scenario holds ``product_argv``, no second ``-f``)."""
    stack = made(product_data())
    root, fetched = skin_box(tmp_path)
    cs = compose(root, stack)
    with FakeRunner(*first_build(cs, key_of())) as runner:
        run([build(root, stack, fetched)], runner)
    assert at(override(cs), "services", "frontend", "build", "args") == {
        "PRIMER_EDITION": "full"
    }
    document = in_release(CONFIG, cs.release)
    assert refusal(cs, document) is None
    assert str(cs.override) not in cs.product_argv("config")
    # the pair: build.args in the product's own compose is still refused
    front = at(document, "services", "frontend", "build")
    assert isinstance(front, dict)
    front["args"] = {"PRIMER_EDITION": "full"}
    assert refusal(cs, document) == (
        "instance-args",
        {"stack": ENTRY, "services": ["frontend"]},
    )


def test_a_dockerfile_inside_the_context_is_relative_else_absolute(
    tmp_path: Path,
) -> None:
    context = tmp_path / "release" / "frontend"
    context.mkdir(parents=True)
    assert copied_dockerfile(context, "Dockerfile") == "Dockerfile"
    assert copied_dockerfile(context, "docker/front.Dockerfile") == (
        "docker/front.Dockerfile"
    )
    outside = tmp_path / "release" / "docker" / "front.Dockerfile"
    assert copied_dockerfile(context, "../docker/front.Dockerfile") == str(outside)
    assert copied_dockerfile(context, str(outside)) == str(outside)


def test_a_context_left_by_a_dead_run_is_replaced_whole(tmp_path: Path) -> None:
    source = tmp_path / "release" / "frontend"
    (source / "public").mkdir(parents=True)
    (source / "Dockerfile").write_text("FROM x\n")
    target = tmp_path / "contexts" / "frontend"
    target.with_name("frontend.tmp").mkdir(parents=True)
    (target.with_name("frontend.tmp") / "stale").write_text("x")
    target.mkdir()
    (target / "older").write_text("x")
    write_context(source, target, [])
    assert sorted(path.name for path in target.iterdir()) == ["Dockerfile", "public"]
    assert not target.with_name("frontend.tmp").exists()


# --- the consumers of the image --------------------------------------------------


def test_the_key_is_the_service_s_alone(tmp_path: Path) -> None:
    stack = made(product_data())
    _, fetched = skin_box(tmp_path)
    assert image_key(stack, "frontend", fetched.passport) == key_of()
    assert image_key(stack, "app", fetched.passport) == {}  # the pair
    service = PRIMER_YAML.validate_python(
        {
            "schema": 1,
            "name": "comms",
            "kind": "service",
            "stacks": {"comms": {"compose": "c.yml"}},
            "report": {"health": "/h", "ready": "/r", "logs": "json", "junit": True},
        }
    )
    assert isinstance(service, Service)
    assert image_key(service, "frontend", fetched.passport) == {}


def test_up_and_migrate_find_the_image_of_app_by_its_key(tmp_path: Path) -> None:
    """A package built into ``app``: ``up`` and ``migrate`` ask for the image
    of the key -- the strict scenario holds the filter, two editions' images
    of one commit are never confused."""
    stack = made(product_data(service="app"))
    root, fetched = skin_box(tmp_path)
    cs = compose(root, stack)
    up = Up(
        stack,
        ENTRY,
        release=cs.release,
        ref=REF,
        commit=SHA,
        root=root,
        fetched=fetched,
    )
    with FakeRunner(image_call(cs, "app", key_of(), APP_IMAGE)) as runner:
        ctx = StepContext(runner, "install", "test", ENTRY, _drop)
        assert up._expected(ctx) == APP_IMAGE
    migrate = Migrate(
        stack,
        ENTRY,
        release=cs.release,
        ref=REF,
        commit=SHA,
        root=root,
        fetched=fetched,
    )
    labels = [
        word for k, v in cs.release_labels().items() for word in ("--label", f"{k}={v}")
    ]
    heads = FakeCall(
        (
            "docker",
            "run",
            "--rm",
            "--network",
            "none",
            *labels,
            APP_IMAGE,
            "python",
            "-m",
            "alembic",
            "heads",
        ),
        lines=stdout("0001 (head)"),
    )
    with FakeRunner(image_call(cs, "app", key_of(), APP_IMAGE), heads) as runner:
        ctx = StepContext(runner, "install", "test", ENTRY, _drop)
        assert migrate._heads(ctx)[0] == ["0001"]


def test_tests_build_from_the_context_with_the_edition(tmp_path: Path) -> None:
    """A package built into ``app``: the test image is built from the context
    ``build`` wrote, with ``PRIMER_EDITION`` -- what the app is built from."""
    stack = made(product_data(service="app"))
    root, fetched = skin_box(tmp_path)
    cs = compose(root, stack)
    step = Tests(
        stack,
        ENTRY,
        release=cs.release,
        ref=REF,
        commit=SHA,
        report=TestReport(),
        secrets=Secrets(()),
        root=root,
        fetched=fetched,
    )
    built = context_dir(root, "blank", ENTRY, "app")
    labels = {**cs.release_labels(), "pridem.service": "app-test"}
    iid = step._home / "image.id"

    class Writes(FakeRunner):
        """``docker build`` writes its ``--iidfile``; the fake does it too."""

        def run(
            self,
            argv: Sequence[str],
            *,
            expect: tuple[int, ...] = (0,),
            timeout: float,
            cwd: Path | None = None,
            env: Mapping[str, str] | None = None,
            on_line: OnLine,
        ) -> Result:
            result = super().run(
                argv, expect=expect, timeout=timeout, cwd=cwd, env=env, on_line=on_line
            )
            iid.write_text("sha256:" + "7" * 64)
            return result

    call = FakeCall(
        (
            "docker",
            "build",
            "--target",
            "test",
            "--iidfile",
            str(iid),
            "-t",
            step.image_name,
            "--build-arg",
            f"PRIMER_RELEASE={REF}",
            "--build-arg",
            f"PRIMER_COMMIT={SHA}",
            "--build-arg",
            "PRIMER_EDITION=full",
            *[w for k, v in labels.items() for w in ("--label", f"{k}={v}")],
            "-f",
            str(built / "Dockerfile"),
            str(built),
        )
    )
    document = in_release(CONFIG, cs.release)
    with Writes(call) as runner:
        ctx = StepContext(runner, "install", "test", ENTRY, _drop)
        assert step._build(ctx, document) == "sha256:" + "7" * 64


def _drop(stream: Stream, line: str, cut: bool) -> None:
    pass


# --- packages by stacks ----------------------------------------------------------


def velo_data(skin_service: str = "frontend") -> dict[str, object]:
    """A velo-like product: entries ``velo`` and ``velo-storage``, the skin built
    into a service of ``velo``."""
    data = product_data(service=skin_service)
    data["name"] = "velo"
    stacks = data["stacks"]
    assert isinstance(stacks, dict)
    velo = stacks.pop("blank")
    stacks["velo"] = velo
    stacks["velo-storage"] = {"compose": "deploy/storage-compose.yml"}
    data["host"] = {
        "domains": ["frontend"],
        "routes": {"frontend": {"to": "frontend:80"}},
    }
    data["dependencies"] = {
        "comms": {"repo": "git@github.com:a/comms.git", "version": ">=4,<5"}
    }
    return data


def no_lock(data: dict[str, object]) -> dict[str, object]:
    """The velo-like product without dependencies: a repository needs no lock."""
    data.pop("dependencies")
    return data


VELO: dict[str, Json] = json.loads(
    json.dumps(CONFIG)
    .replace("blank_default", "velo_default")
    .replace("blank_pgdata", "velo_pgdata")
    .replace('"name": "blank"', '"name": "velo"')
)
STORAGE: dict[str, Json] = {
    "name": "velo-storage",
    "services": {
        "storage": {"image": "minio@sha256:x", "networks": {"default": None}},
        "velo-storage-init": {"image": "minio-mc@sha256:x"},
    },
    "networks": {"default": {"name": "velo-storage_default"}},
}


def test_a_package_belongs_to_the_stack_its_service_is_in(tmp_path: Path) -> None:
    """Two stacks, the skin in ``velo``: green for both; the service in none:
    a finding for both (the pair)."""
    stack = made(velo_data())
    velo = VELO
    assert package_places(stack, {"velo": velo, "velo-storage": STORAGE}) == []
    nowhere = made(velo_data(skin_service="web"))
    assert package_places(nowhere, {"velo": velo, "velo-storage": STORAGE}) == [
        "web: packages.skin.build (no such service)"
    ]
    # a build place on a service with no build of its own
    image_only = made(velo_data(skin_service="storage"))
    assert package_places(image_only, {"velo": velo, "velo-storage": STORAGE}) == [
        "storage: packages.skin.build (no build)"
    ]


def test_build_of_the_other_stack_reads_every_compose_and_is_green(
    tmp_path: Path,
) -> None:
    """``build`` of ``velo-storage``: the skin's service is in ``velo`` -- no
    finding, no context, no bind; ``velo``'s compose read beside its own."""
    stack = made(velo_data())
    root, fetched = skin_box(tmp_path)
    storage = compose(root, stack, "velo-storage")
    velo = compose(root, stack, "velo")
    other = config_call(velo, VELO)
    script = [
        config_call(storage, STORAGE, raw=True),
        config_call(storage, STORAGE),
        other,
        config_call(storage, STORAGE),
        other,
        build_call(storage),
        config_call(storage, STORAGE),
        other,
    ]
    with FakeRunner(*script) as runner:
        outcome = run([build(root, stack, fetched, "velo-storage")], runner)
    assert outcome.code is ExitCode.OK, outcome.steps
    rendered = override(storage)
    services = rendered["services"]
    assert isinstance(services, dict) and sorted(services) == [
        "storage",
        "velo-storage-init",
    ]
    assert not context_dir(root, "velo", "velo-storage", "frontend").exists()


def test_a_runtime_package_is_bound_by_the_stack_its_service_is_in(
    tmp_path: Path,
) -> None:
    """``apply: runtime`` in ``velo``'s frontend: ``velo-storage`` binds
    nothing of it, ``velo`` binds it (the pair)."""
    stack = made(velo_runtime())
    root, fetched = skin_box(tmp_path)
    passport = fetched.passport
    assert passport is not None
    storage = package_mounts(stack, "velo", passport, root, {"storage"})
    assert storage == []
    velo = package_mounts(stack, "velo", passport, root, {"app", "frontend"})
    assert [(m.slot, m.service) for m in velo] == [("skin", "frontend")]


def velo_runtime() -> dict[str, object]:
    data = velo_data()
    data["packages"] = {
        "skin": {
            "contract": ">=1,<2",
            "validate": "validate-skin <dir>",
            "mount": [{"service": "frontend", "path": "/srv/skin"}],
        }
    }
    return data


def test_build_names_a_service_in_no_stack(tmp_path: Path) -> None:
    stack = made(velo_data(skin_service="web"))
    root, fetched = skin_box(tmp_path)
    storage = compose(root, stack, "velo-storage")
    velo = compose(root, stack, "velo")
    script = [
        config_call(storage, STORAGE, raw=True),
        config_call(storage, STORAGE),
        config_call(velo, VELO),
    ]
    with FakeRunner(*script) as runner:
        outcome = run([build(root, stack, fetched, "velo-storage")], runner)
    assert outcome.steps[0].reason == Code(
        "build:compose-forbidden",
        {
            "stack": "velo-storage",
            "found": ["web: packages.skin.build (no such service)"],
        },
    )


# --- reserved names ------------------------------------------------------------------


def test_names_the_machine_gives_are_reserved(tmp_path: Path) -> None:
    stack = made(velo_data())
    exact, prefixes = reserved(stack, "velo-storage")
    assert exact == {"velo-app", "velo-frontend"}  # app and the route of velo
    assert prefixes == ("pridem-", "comms-")
    cs = compose(tmp_path, stack, "velo-storage")
    (tmp_path / "release").mkdir()
    # the velo-like pair: velo-storage-init of velo-storage is green
    assert forbidden(cs, STORAGE) == []
    planted = json.loads(json.dumps(STORAGE))
    planted["services"]["pridem-cache"] = {"image": "redis@sha256:x"}
    planted["services"]["velo-app"] = {"image": "x@sha256:x"}
    planted["services"]["comms-worker"] = {"image": "x@sha256:x"}
    planted["services"]["velo-frontend"] = {"image": "x@sha256:x"}
    planted["services"]["velo-postgres"] = {"image": "x@sha256:x"}  # no alias
    assert forbidden(cs, planted) == [
        "comms-worker: name reserved",
        "pridem-cache: name reserved",
        "velo-app: name reserved",
        "velo-frontend: name reserved",
    ]


def test_an_entry_s_own_aliases_are_not_reserved_for_it(tmp_path: Path) -> None:
    stack = made(velo_data())
    exact, _ = reserved(stack, "velo")
    assert exact == frozenset()  # velo-storage has no app and no route
    service = PRIMER_YAML.validate_python(
        {
            "schema": 1,
            "name": "comms",
            "kind": "service",
            "stacks": {"comms": {"compose": "c.yml"}},
            "report": {"health": "/h", "ready": "/r", "logs": "json", "junit": True},
        }
    )
    assert isinstance(service, Service)
    assert reserved(service, "comms") == (frozenset(), ())


# --- pridem check -----------------------------------------------------------------


def test_check_reads_every_compose_before_it_refuses(tmp_path: Path) -> None:
    """``pridem check`` of a velo-like repository: two stacks, the skin in
    one -- green; the other way round, the service in none -- both red."""

    def repository(data: Mapping[str, object], where: Path) -> Path:
        (where / "deploy").mkdir(parents=True)
        (where / "primer.yaml").write_text(yaml.safe_dump(dict(data)))
        (where / "docker-compose.yml").write_text("services: {}\n")
        (where / "deploy" / "storage-compose.yml").write_text("services: {}\n")
        return where

    def calls(root: Path) -> list[FakeCall]:
        out: list[FakeCall] = [version_call()]
        for entry, file, document in (
            ("velo", "docker-compose.yml", VELO),
            ("velo-storage", "deploy/storage-compose.yml", STORAGE),
        ):
            for raw in (True, False):
                argv = ["docker", "compose", "-p", entry, "-f", str(root / file)]
                argv += ["config", "--format", "json"]
                argv += ["--no-interpolate"] if raw else []
                out.append(
                    FakeCall(
                        tuple(argv),
                        lines=stdout(json.dumps(in_release(document, root))),
                        env=_env(()),
                    )
                )
        return out

    def check(root: Path) -> tuple[int, dict[str, Json]]:
        out, err = io.StringIO(), io.StringIO()
        with FakeRunner(*calls(root)) as runner:
            code = cli(["--json", "check", str(root)], out=out, err=err, runner=runner)
        return code, json.loads(out.getvalue())

    def composes(verdict: dict[str, Json]) -> dict[str, dict[str, Json]]:
        steps = verdict["steps"]
        assert isinstance(steps, list)
        return {
            str(step["stack"]): step
            for step in steps
            if isinstance(step, dict) and step["name"] == "compose"
        }

    _, verdict = check(repository(no_lock(velo_data()), tmp_path / "green"))
    found = composes(verdict)
    assert sorted(found) == ["velo", "velo-storage"]
    assert all(step["status"] == "ok" for step in found.values()), found
    code, verdict = check(repository(no_lock(velo_data("web")), tmp_path / "red"))
    assert code == 1
    finding = ["web: packages.skin.build (no such service)"]
    for entry, step in composes(verdict).items():
        assert at(step, "reason", "found") == finding, (entry, step)
