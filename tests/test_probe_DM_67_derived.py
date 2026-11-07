"""The probe of DM-67: a service's ``derived`` seam, computed in this run's
image after ``build``, reaches the product (contract 3 section 3, rule 21).

The ladders are the plan builder's (``deploy_plan`` through
``services_support.planned``): ``seams_check``, then comms' own entry --
``render_env -> build -> derive_env -> data_copy -> up`` -- on a strict
``FakeRunner``, its app answering over real HTTP (``LiveApp``), then the
product's ``render_env``, which takes the seam from the plan's memory.
"""

from datetime import UTC, datetime
from itertools import count
from pathlib import Path

from compose_support import (
    CONTAINER,
    LiveApp,
    config_call,
    hash_calls,
    health,
    image_call,
    log_line,
    raw_config_call,
    stdout,
)
from env_support import read_env
from plan_support import ListSink
from services_support import deferred, planned

from pridem.events import Json
from pridem.plan import Plan, StackSteps
from pridem.report.codes import ExitCode
from pridem.runner import FakeCall, FakeRunner
from pridem.steps.build import Build
from pridem.steps.compose import ComposeStack
from pridem.steps.env import DeriveEnv, RenderEnv

ASKED = "invented-telegram-token-0067"
BOT_URL = "https://t.me/invented_bot_000000067"
IMAGE = "sha256:" + "6" * 64
APP = "comms-app"
HASH = "c" * 64
REPORT = {"health": "/health", "ready": "/ready", "logs": "json", "junit": True}
NETWORKS_FORMAT = "{{json .NetworkSettings.Networks}}"
CONFIG: dict[str, Json] = {
    "name": "comms",
    "services": {
        "comms-app": {
            "build": {"context": "/r/", "dockerfile": "Dockerfile"},
            "networks": {"default": None},
        }
    },
    "networks": {"default": {"name": "comms_default"}},
}


def comms(port: int) -> dict[str, object]:
    """comms of contract 3 section 2, its bot URL derived from its token."""
    return {
        "schema": 1,
        "name": "comms",
        "kind": "service",
        "stacks": {
            "comms": {
                "compose": "deploy/docker-compose.yml",
                "app": {
                    "service": "comms-app",
                    "port": port,
                    "health": "/health",
                    "ready": "/ready",
                },
            }
        },
        "env": {
            "COMMS_API_URL": {"source": "address"},
            "COMMS_SERVICE_TOKEN": {"source": "minted"},
            "TELEGRAM_BOT_TOKEN": {"source": "asked"},
            "TELEGRAM_BOT_URL": {"source": "derived", "run": "comms derive bot-url"},
            "PRODUCT_WEBHOOK_URL": {"source": "seam", "from": "product"},
        },
        "provides": ["COMMS_API_URL", "COMMS_SERVICE_TOKEN", "TELEGRAM_BOT_URL"],
        "requires": ["PRODUCT_WEBHOOK_URL"],
        "report": {
            "health": "/health",
            "ready": "/ready",
            "logs": "json",
            "junit": True,
        },
    }


def script(cs: ComposeStack, env_dir: Path) -> list[FakeCall]:
    """Every command of comms' ladder on ``install``, in its order."""
    derive = FakeCall(
        (
            "docker",
            "run",
            "--rm",
            "--label",
            "pridem.stack=comms",
            "--env-file",
            str(env_dir / "derive.env"),
            IMAGE,
            "comms",
            "derive",
            "bot-url",
        ),
        lines=stdout(BOT_URL),
    )
    ps_app = FakeCall(tuple(cs.argv("ps", "-q", "comms-app")), lines=stdout(CONTAINER))
    inspect = FakeCall(
        ("docker", "inspect", "-f", "{{.Image}}", CONTAINER), lines=stdout(IMAGE)
    )
    own = cs.product_argv()
    networks = '{"pridem": {"IPAddress": "127.0.0.1"}}'
    return [
        # build: check (no override yet), act, verify
        raw_config_call(cs, CONFIG),
        config_call(cs, CONFIG),
        raw_config_call(cs, CONFIG),
        config_call(cs, CONFIG),
        FakeCall(
            tuple(
                cs.candidate().argv(
                    "build",
                    "--build-arg",
                    f"PRIMER_RELEASE={cs.ref}",
                    "--build-arg",
                    f"PRIMER_COMMIT={cs.commit}",
                )
            ),
            lines=stdout("built"),
        ),
        raw_config_call(cs, CONFIG),
        config_call(cs, CONFIG),
        image_call(cs, "comms-app", IMAGE),
        # derive_env: the placeholder on disk -- derive on the build's image
        derive,
        # up: check -- nothing runs yet
        image_call(cs, "comms-app", IMAGE),
        FakeCall(tuple(cs.argv("ps", "-q", "comms-app"))),
        FakeCall(
            tuple(cs.argv("up", "-d", "--no-build", "--wait", "--wait-timeout", "300"))
        ),
        # up: verify -- the image, the configuration, conformance
        image_call(cs, "comms-app", IMAGE),
        ps_app,
        inspect,
        *hash_calls(cs, expected={"comms-app": HASH}),
        config_call(cs, CONFIG),
        FakeCall((*own, "ps", "-q", "comms-app"), lines=stdout(CONTAINER)),
        FakeCall(
            (
                "docker",
                "inspect",
                "-f",
                "{{json .NetworkSettings.Networks}}",
                CONTAINER,
            ),
            lines=stdout(networks),
        ),
        FakeCall(
            (
                *own,
                "logs",
                "--no-color",
                "--no-log-prefix",
                "--tail",
                "50",
                "comms-app",
            ),
            lines=stdout(log_line("comms")),
        ),
    ]


def test_probe_DM_67_service_derived_seam_reaches_the_product(tmp_path: Path) -> None:
    """comms derives ``TELEGRAM_BOT_URL`` in the image its ``build`` made in
    this run, after the build and before ``up``; the product's env holds that
    value, taken as a seam after comms' health. The pair: the product's env
    contains it, and no ``derive-no-image`` anywhere in the run.

    Changed by DM-72 (by the dispatcher's word, before the change): the log
    line of the scenario names its stack ``comms``; conformance compares
    ``service`` with the stack's name (protocol 9.4, DM-72)."""
    app = LiveApp()
    try:
        made, root = planned(
            tmp_path,
            "core",
            comms=comms(app.port),
            asked={"comms": {"TELEGRAM_BOT_TOKEN": ASKED}},
        )
        services = {s.name: s for s in deferred(made, "services")}
        ladder = services["comms"].steps
        assert [step.name for step in ladder] == [
            "render_env",
            "build",
            "derive_env",
            "data_copy",
            "up",
        ]
        build, derive = ladder[1], ladder[2]
        assert isinstance(build, Build) and isinstance(derive, DeriveEnv)
        assert derive.build is build  # the image comes from this run's build
        cs = build.compose
        app.health = health(service="comms", release=cs.ref, commit=cs.commit)
        app.health["alembic_head"] = None
        product = deferred(made, "product")[0]
        render = product.steps[0]
        assert isinstance(render, RenderEnv) and product.name == "aivis"
        ticks = count()
        with FakeRunner(*script(cs, root / "opt" / "comms" / "env")) as runner:
            outcome = Plan(
                [
                    services["seams"],
                    services["comms"],
                    StackSteps("aivis", [render]),
                    StackSteps("root", [], root=True),
                ],
                mode="install",
                role="test",
                runner=runner,
                sink=ListSink(),
                clock=lambda: float(next(ticks)),
                now=lambda: datetime(2026, 11, 5, tzinfo=UTC),
            ).run()
    finally:
        app.close()
    assert outcome.code is ExitCode.OK, outcome.steps
    facts = {(r.stack, r.name): r.verify for r in outcome.steps}
    assert facts[("comms", "build")]["app_image"] == IMAGE
    assert facts[("comms", "derive_env")]["image"] == IMAGE
    assert read_env(root, "comms")["TELEGRAM_BOT_URL"] == BOT_URL
    # the pair: the product's env holds the value comms derived
    assert read_env(root, "aivis")["TELEGRAM_BOT_URL"] == BOT_URL
    assert not [
        r for r in outcome.steps if r.reason and "derive-no-image" in r.reason.code
    ]
