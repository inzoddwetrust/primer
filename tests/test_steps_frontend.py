"""``packages`` and ``frontend`` (DM-19): package binds that stay in the
package, ``validate`` on the new image before ``up``, the front's 200."""

import json
from pathlib import Path

import pytest
import yaml
from compose_support import (
    CONFIG,
    ENTRY,
    HASHES,
    REF,
    SHA,
    hash_calls,
    in_release,
    stdout,
)
from compose_support import config_call as compose_config
from compose_support import raw_config_call as compose_raw_config
from edge_support import DOMAINS, Mixed, exec_call, passport, product
from env_support import box, passport_data
from plan_support import ListSink

from pridem.events import Code, Json, PlanOutcome
from pridem.plan import Plan, StackSteps
from pridem.report.codes import ExitCode
from pridem.runner import FakeCall, FakeRunner
from pridem.stacks.loader import ContractError
from pridem.stacks.schema import Product, load_primer_yaml
from pridem.steps.base import Step
from pridem.steps.build import Build
from pridem.steps.compose import ComposeStack, override_text, package_places
from pridem.steps.frontend import Frontend
from pridem.steps.packages import Packages, package_mounts, volumes
from pridem.steps.passport import Fetched
from pridem.steps.sources import package_dir

FRONT_IMAGE = "sha256:" + "f" * 64


def skin_product(mount_from: str | None = "css") -> dict[str, object]:
    mount: dict[str, object] = {"service": "frontend", "path": "/srv/skin"}
    if mount_from is not None:
        mount["from"] = mount_from
    return {
        "schema": 1,
        "name": "blank",
        "kind": "product",
        "stacks": {
            "blank": {
                "compose": "docker-compose.yml",
                "app": {"service": "app", "port": 8000, "health": "/h", "ready": "/r"},
                "frontend": {"service": "frontend", "port": 80},
            }
        },
        "env": {},
        "packages": {
            "skin": {
                "contract": ">=1,<2",
                "validate": "validate-skin <dir>",
                "mount": [mount],
            }
        },
        "report": {"health": "/h", "ready": "/r", "logs": "json", "junit": True},
    }


def made(tmp: Path, data: dict[str, object]) -> Product:
    file = tmp / "primer.yaml"
    file.write_text(yaml.safe_dump(data))
    stack = load_primer_yaml(file)
    assert isinstance(stack, Product)
    return stack


def skin_box(tmp: Path) -> tuple[Path, Fetched, Path]:
    data = passport_data()
    data["packages"] = {
        "skin": {"repo": "git@github.com:partner/velo-look.git", "version": "1.4.2"}
    }
    root, fetched = box(tmp, data)
    package = root / "opt" / ENTRY / "releases" / "velo-look@1.4.2"
    (package / "css").mkdir(parents=True)
    return root, fetched, package


def packages(root: Path, fetched: Fetched, stack: Product) -> Packages:
    return Packages(
        stack,
        ENTRY,
        release=root / "release",
        ref=REF,
        commit=SHA,
        fetched=fetched,
        root=root,
    )


def config_call(root: Path, stack: Product) -> FakeCall:
    cs = ComposeStack(stack, ENTRY, root / "release", REF, SHA, root)
    return FakeCall(
        tuple(cs.product_argv("config", "--format", "json")),
        lines=stdout(json.dumps(CONFIG)),
    )


def run(steps: list[Step], runner: FakeRunner) -> PlanOutcome:
    return Plan(
        [StackSteps(ENTRY, steps, root=True)],
        mode="install",
        role="test",
        runner=runner,
        sink=ListSink(),
    ).run()


# --- probe ----------------------------------------------------------------------


@pytest.mark.parametrize("bad", ["../etc", "/etc"])
def test_probe_DM_19_package_mount_rejects_paths_outside_release(
    tmp_path: Path, bad: str
) -> None:
    with pytest.raises(ContractError):  # .. and an absolute from: the loader
        made(tmp_path, skin_product(bad))
    # a symlink of the package that leads out of it: the step, before act
    stack = made(tmp_path, skin_product("css"))
    root, fetched, package = skin_box(tmp_path)
    (package / "css").rmdir()
    (package / "css").symlink_to(tmp_path / "elsewhere", target_is_directory=True)
    (tmp_path / "elsewhere").mkdir()
    with FakeRunner(config_call(root, stack)) as runner:  # no validate runs
        outcome = run([packages(root, fetched, stack)], runner)
    assert outcome.steps[0].reason == Code(
        "packages:path-outside", {"slot": "skin", "from": "css"}
    )
    # the pair: the package's own directory is bound read-only into the service
    root2, fetched2, package2 = skin_box(tmp_path / "ok")
    assert fetched2.passport is not None
    mounts = package_mounts(stack, ENTRY, fetched2.passport, root2)
    cs = ComposeStack(stack, ENTRY, root2 / "release", REF, SHA, root2)
    rendered = json.loads(override_text(cs, CONFIG, volumes(mounts)))
    assert rendered["services"]["frontend"]["volumes"] == [
        f"{package2 / 'css'}:/srv/skin:ro"
    ]


# --- the rest -------------------------------------------------------------------


def test_red_validate_stops_before_anything_is_switched(tmp_path: Path) -> None:
    stack = made(tmp_path, skin_product("css"))
    root, fetched, package = skin_box(tmp_path)
    cs = ComposeStack(stack, ENTRY, root / "release", REF, SHA, root)
    labels = (
        "--label",
        "pridem.stack=blank",
        "--label",
        "pridem.release=main",
        "--label",
        f"pridem.commit={SHA}",
    )
    validate = FakeCall(
        (
            "docker",
            "run",
            "--rm",
            *labels,
            "-v",
            f"{package / 'css'}:/srv/skin:ro",
            FRONT_IMAGE,
            "validate-skin",
            "/srv/skin",
        ),
        code=3,
    )
    image = FakeCall(
        (
            "docker",
            "image",
            "ls",
            "--quiet",
            "--no-trunc",
            "--filter",
            "label=pridem.stack=blank",
            "--filter",
            f"label=pridem.commit={SHA}",
            "--filter",
            "label=pridem.service=frontend",
        ),
        lines=stdout(FRONT_IMAGE),
    )
    later = config_call(root, stack)
    with FakeRunner(
        later, *hash_calls(cs, running={}), later, image, validate
    ) as runner:
        outcome = run([packages(root, fetched, stack)], runner)
    assert outcome.steps[0].reason is not None
    assert outcome.steps[0].reason.code == "command-failed"
    assert cs.override.exists() is False  # nothing switched


@pytest.mark.parametrize("build", [True, False])
def test_an_image_named_in_compose_is_used_only_without_build(
    tmp_path: Path, build: bool
) -> None:
    """DM-54 (the condition kept when its ``type: ignore`` went): no image of
    the commit carries the service's label -- a service that is built has no
    image to validate (``no-image``); one that only names an image validates
    that image."""
    stack = made(tmp_path, skin_product("css"))
    root, fetched, package = skin_box(tmp_path)
    cs = ComposeStack(stack, ENTRY, root / "release", REF, SHA, root)
    front: dict[str, Json] = {"image": "front:1", "networks": {"default": None}}
    if build:
        front["build"] = {"context": "/r/frontend", "dockerfile": "Dockerfile"}
    services = CONFIG["services"]
    assert isinstance(services, dict)
    document = {**CONFIG, "services": {**services, "frontend": front}}
    config = FakeCall(
        tuple(cs.product_argv("config", "--format", "json")),
        lines=stdout(json.dumps(document)),
    )
    labels = (
        "label=pridem.stack=blank",
        "--filter",
        f"label=pridem.commit={SHA}",
        "--filter",
        "label=pridem.service=frontend",
    )
    none = FakeCall(
        ("docker", "image", "ls", "--quiet", "--no-trunc", "--filter", *labels)
    )
    calls = [config, *hash_calls(cs, running={}), config, none]
    if not build:
        validate = (
            "docker",
            "run",
            "--rm",
            *("--label", "pridem.stack=blank", "--label", "pridem.release=main"),
            *("--label", f"pridem.commit={SHA}"),
            *("-v", f"{package / 'css'}:/srv/skin:ro"),
            *("front:1", "validate-skin", "/srv/skin"),
        )
        calls += [FakeCall(validate, code=3)]
    with FakeRunner(*calls) as runner:
        outcome = run([packages(root, fetched, stack)], runner)
    reason = outcome.steps[0].reason
    assert reason is not None
    if build:
        assert reason == Code(
            "packages:no-image",
            {"slot": "skin", "service": "frontend", "commit": SHA},
        )
    else:  # the named image reached validate (which says no here)
        assert reason.code == "command-failed"


def test_build_refuses_a_package_for_a_service_the_compose_lacks(
    tmp_path: Path,
) -> None:
    """DM-55: a package mounted into a service the compose does not have would
    drop out of the override unseen; ``build`` refuses it in ``check``, before
    anything is built. The pair: with the service, the package is no finding."""
    stack = made(tmp_path, skin_product("css"))
    root, fetched, _ = skin_box(tmp_path)
    cs = ComposeStack(stack, ENTRY, root / "release", REF, SHA, root)
    services = CONFIG["services"]
    assert isinstance(services, dict)
    lacking = {
        **CONFIG,
        "services": {k: v for k, v in services.items() if k != "frontend"},
    }
    step = Build(
        stack,
        ENTRY,
        release=cs.release,
        ref=REF,
        commit=SHA,
        root=root,
        fetched=fetched,
    )
    script = [compose_raw_config(cs, lacking), compose_config(cs, lacking)]
    with FakeRunner(*script) as runner:  # nothing is built
        outcome = run([step], runner)
    assert outcome.steps[0].reason == Code(
        "build:compose-forbidden",
        {"stack": ENTRY, "found": ["frontend: packages.skin.mount (no such service)"]},
    )
    whole = in_release(CONFIG, cs.release)  # the pair: a compose with frontend
    assert package_places(stack, {ENTRY: whole}) == []


def test_a_dependency_mount_is_not_done_here(tmp_path: Path) -> None:
    data = skin_product()
    data["dependencies"] = {
        "comms": {"repo": "git@github.com:a/comms.git", "version": ">=3,<4"}
    }
    data["packages"] = {
        "texts": {
            "contract": ">=1,<2",
            "validate": "v <dir>",
            "mount": [
                {"dependency": "comms", "from": "comms", "env": "PROFILE_OVERLAY_DIR"}
            ],
        }
    }
    stack = made(tmp_path, data)
    root, fetched = box(
        tmp_path / "b",
        {
            **passport_data(),
            "packages": {
                "texts": {"repo": "git@github.com:p/t.git", "version": "1.0.0"}
            },
        },
    )
    assert fetched.passport is not None
    with pytest.raises(Exception, match="dependency-mount"):
        package_mounts(stack, ENTRY, fetched.passport, root)


def _curl(root: Path) -> tuple[str, ...]:
    return (
        "curl",
        "-k",
        "-sS",
        "--max-time",
        "15",
        "--resolve",
        f"{DOMAINS['frontend']}:443:127.0.0.1",
        "-o",
        str(root / "opt" / "pridem" / "edge" / "frontend-probe"),
        "-w",
        "%{http_code}",
        f"https://{DOMAINS['frontend']}/",
    )


def test_probe_DM_51_frontend_needs_no_reload_when_config_and_front_are_live(
    tmp_path: Path,
) -> None:
    root, fetched = passport(tmp_path)
    step = Frontend(product(), fetched=fetched, root=root)
    live = [FakeCall(_curl(root), lines=stdout("200"))] * 2  # check, verify
    with Mixed(*live) as runner:  # no nginx -t, no reload
        outcome = run([step], runner)
    assert outcome.code is ExitCode.OK, outcome.steps
    assert outcome.steps[0].verify == {"domain": DOMAINS["frontend"], "status": 200}
    # the pair: a front that does not answer 200 -- reload, then verify again;
    # curl exits 0 on a 502 too: the status decides, not the exit code
    down = [
        FakeCall(_curl(root), lines=stdout("502")),
        exec_call(root, "nginx", "-t"),
        exec_call(root, "nginx", "-s", "reload"),
        FakeCall(_curl(root), lines=stdout("200")),
    ]
    with Mixed(*down) as runner:
        outcome = run([step], runner)
    assert outcome.code is ExitCode.OK, outcome.steps


def test_front_answers_200_or_the_step_is_red(tmp_path: Path) -> None:
    """DM-51: a front still not 200 after the reload is red by its status."""
    root, fetched = passport(tmp_path)
    step = Frontend(product(), fetched=fetched, root=root)
    bad = [
        FakeCall(_curl(root), lines=stdout("502")),
        exec_call(root, "nginx", "-t"),
        exec_call(root, "nginx", "-s", "reload"),
        FakeCall(_curl(root), lines=stdout("502")),
    ]
    with Mixed(*bad) as runner:
        outcome = run([step], runner)
    assert outcome.steps[0].reason == Code(
        "frontend:not-200", {"domain": DOMAINS["frontend"], "status": "502"}
    )


# --- DM-53: a package is where fetch_packages put it, whatever the entry --------


def test_a_package_is_mounted_from_the_stack_dir_not_the_entry(tmp_path: Path) -> None:
    data = skin_product("css")
    stacks = data["stacks"]
    assert isinstance(stacks, dict)
    data["stacks"] = {"web": stacks["blank"]}  # the compose entry is not the stack
    stack = made(tmp_path, data)
    root, fetched, package = skin_box(tmp_path / "box")  # /opt/blank/releases/...
    assert fetched.passport is not None
    given = fetched.passport.packages["skin"]
    assert package == package_dir(root, "blank", given)  # fetch_packages' place
    cs = ComposeStack(stack, "web", root / "release", REF, SHA, root)
    step = Packages(
        stack,
        "web",
        release=root / "release",
        ref=REF,
        commit=SHA,
        fetched=fetched,
        root=root,
    )
    config = FakeCall(
        tuple(cs.product_argv("config", "--format", "json")),
        lines=stdout(json.dumps(CONFIG)),
    )
    with FakeRunner(config, *hash_calls(cs, running={})) as runner:
        outcome = Plan(
            [StackSteps("web", [step], root=True)],
            mode="doctor",
            role="test",
            runner=runner,
            sink=ListSink(),
        ).run()
    [item] = outcome.doctor_diff  # found and would validate: not missing-release
    assert item.reason.code == "packages:validate"
    mounts = package_mounts(stack, stack.name, fetched.passport, root)
    assert [m.source for m in mounts] == [package / "css"]


def _doctor(step: Step, *calls: FakeCall) -> list[str]:
    """The codes ``doctor`` would act on, ``calls`` its whole script."""
    with FakeRunner(*calls) as runner:
        outcome = Plan(
            [StackSteps(ENTRY, [step], root=True)],
            mode="doctor",
            role="test",
            runner=runner,
            sink=ListSink(),
        ).run()
    assert outcome.code is not ExitCode.FAILED, outcome.steps
    return [item.reason.code for item in outcome.doctor_diff]


def test_packages_validate_only_when_a_service_they_mount_into_is_behind(
    tmp_path: Path,
) -> None:
    """DM-58: the package step decides by the configuration of the services
    it mounts into (``stale``). frontend on its hash -- nothing to validate,
    ``doctor`` empty; frontend behind (another version: another bind, another
    hash) or not running -- validate; only app behind -- not the packages'
    business."""
    stack = made(tmp_path, skin_product("css"))
    root, fetched, _ = skin_box(tmp_path)
    cs = ComposeStack(stack, ENTRY, root / "release", REF, SHA, root)
    step = packages(root, fetched, stack)
    config = config_call(root, stack)
    assert _doctor(step, config, *hash_calls(cs)) == []
    behind = {**HASHES, "frontend": "1" * 64}
    assert _doctor(step, config, *hash_calls(cs, running=behind)) == [
        "packages:validate"
    ]
    gone = {name: value for name, value in HASHES.items() if name != "frontend"}
    assert _doctor(step, config, *hash_calls(cs, running=gone)) == ["packages:validate"]
    app_only = {**HASHES, "app": "1" * 64}
    assert _doctor(step, config, *hash_calls(cs, running=app_only)) == []


def test_a_runtime_slot_without_a_package_is_green_with_no_mount(
    tmp_path: Path,
) -> None:
    """The pair of ``build:package-missing`` (DM-61, test_steps_build_mode):
    a slot applied at run time that the passport does not fill is the
    product's own look -- nothing mounted, nothing validated, green."""
    stack = made(tmp_path, skin_product("css"))
    root, fetched = box(tmp_path / "plain", passport_data())
    assert fetched.passport is not None and not fetched.passport.packages
    assert package_mounts(stack, ENTRY, fetched.passport, root) == []
    with FakeRunner() as runner:  # no config, no hash, no validate
        outcome = run([packages(root, fetched, stack)], runner)
    assert outcome.code is ExitCode.OK, outcome.steps
    assert outcome.steps[0].verify == {"packages": "none"}
