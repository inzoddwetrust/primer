"""``packages`` and ``frontend`` (DM-19): package binds that stay in the
package, ``validate`` on the new image before ``up``, the front's 200."""

import json
from pathlib import Path

import pytest
import yaml
from compose_support import CONFIG, ENTRY, REF, SHA, stdout
from edge_support import DOMAINS, Mixed, exec_call, passport, product
from env_support import box, passport_data
from plan_support import ListSink

from pridem.events import Code, PlanOutcome
from pridem.plan import Plan, StackSteps
from pridem.report.codes import ExitCode
from pridem.runner import FakeCall, FakeRunner
from pridem.stacks.loader import ContractError
from pridem.stacks.schema import Product, load_primer_yaml
from pridem.steps.base import Step
from pridem.steps.compose import ComposeStack, override_text
from pridem.steps.frontend import Frontend
from pridem.steps.packages import Packages, package_mounts, volumes
from pridem.steps.passport import Fetched

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
    with FakeRunner(later, later, image, validate) as runner:
        outcome = run([packages(root, fetched, stack)], runner)
    assert outcome.steps[0].reason is not None
    assert outcome.steps[0].reason.code == "command-failed"
    assert cs.override.exists() is False  # nothing switched


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


def test_front_answers_200_or_the_step_is_red(tmp_path: Path) -> None:
    root, fetched = passport(tmp_path)
    step = Frontend(product(), fetched=fetched, root=root)
    curl = (
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
    ok = [
        exec_call(root, "nginx", "-t"),
        exec_call(root, "nginx", "-s", "reload"),
        FakeCall(curl, lines=stdout("200")),
    ]
    with Mixed(*ok) as runner:
        outcome = run([step], runner)
    assert outcome.code is ExitCode.OK
    bad = [
        exec_call(root, "nginx", "-t"),
        exec_call(root, "nginx", "-s", "reload"),
        FakeCall(curl, lines=stdout("502")),
    ]
    with Mixed(*bad) as runner:
        outcome = run([step], runner)
    assert outcome.steps[0].reason == Code(
        "frontend:not-200", {"domain": DOMAINS["frontend"], "status": "502"}
    )
