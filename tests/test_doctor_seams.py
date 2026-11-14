"""``doctor`` of a product with a seam from a live service (DM-59 FIX).

``doctor`` runs ``check`` alone. The seams of a service reach the plan's
memory from its ``up``: in a run from ``verify``, in ``doctor`` from
``check`` where it found the service running on this commit and its live
``/health`` conforming -- the values read from the service's ``.env``. The
ladders are the plan builder's, on a box the DM-67 probe's install left.
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
from plan_support import ListSink
from services_support import deferred, planned
from test_probe_DM_67_derived import (
    APP,
    ASKED,
    CONFIG,
    HASH,
    IMAGE,
    NETWORKS_FORMAT,
    comms,
    script,
)

from pridem.events import PlanOutcome
from pridem.plan import Plan, StackSteps
from pridem.report.codes import ExitCode
from pridem.runner import FakeCall, FakeRunner
from pridem.steps.build import Build
from pridem.steps.compose import ComposeStack


def _plan(
    tmp: Path, port: int, mode: str, calls: list[FakeCall], *, again: bool
) -> tuple[PlanOutcome, ComposeStack]:
    """``mode`` of comms and the product's ``render_env`` on ``tmp/box``."""
    made, root = planned(
        tmp,
        "core",
        comms=comms(port),
        asked={"comms": {"TELEGRAM_BOT_TOKEN": ASKED}},
        again=again,
    )
    services = {s.name: s for s in deferred(made, "services")}
    build = services["comms"].steps[1]
    assert isinstance(build, Build)
    render = deferred(made, "product")[0].steps[0]
    ticks = count()
    given = calls or script(build.compose, root / "opt" / "comms" / "env")
    with FakeRunner(*given) as runner:
        outcome = Plan(
            [
                services["seams"],
                services["comms"],
                StackSteps("aivis", [render]),
                StackSteps("root", [], root=True),
            ],
            mode=mode,  # type: ignore[arg-type]
            role="test",
            runner=runner,
            sink=ListSink(),
            clock=lambda: float(next(ticks)),
            now=lambda: datetime(2026, 11, 6, tzinfo=UTC),
        ).run()
    return outcome, build.compose


def _doctor_calls(cs: ComposeStack) -> list[FakeCall]:
    """Every command of ``doctor`` on comms' ladder, nothing to do: the
    checks of ``build``, ``derive_env`` and ``up`` read docker and the app."""
    ps_app = FakeCall(
        tuple(cs.argv("ps", "-q", operands=(APP,))), lines=stdout(CONTAINER)
    )
    inspect = FakeCall(
        ("docker", "inspect", "-f", "{{.Image}}", CONTAINER), lines=stdout(IMAGE)
    )
    own = cs.product_argv()
    networks = '{"pridem": {"IPAddress": "127.0.0.1"}}'
    return [
        raw_config_call(cs, CONFIG),
        config_call(cs, CONFIG),
        image_call(cs, APP, IMAGE),
        ps_app,
        inspect,
        image_call(cs, APP, IMAGE),
        ps_app,
        inspect,
        *hash_calls(cs, expected={APP: HASH}),
        config_call(cs, CONFIG),
        FakeCall((*own, "ps", "-q", APP), lines=stdout(CONTAINER)),
        FakeCall(
            ("docker", "inspect", "-f", NETWORKS_FORMAT, CONTAINER),
            lines=stdout(networks),
        ),
        FakeCall(
            (*own, "logs", "--no-color", "--no-log-prefix", "--tail", "50", APP),
            lines=stdout(log_line("comms")),
        ),
    ]


def test_doctor_of_a_product_with_a_seam_from_a_healthy_service_is_empty(
    tmp_path: Path,
) -> None:
    """The service runs on this commit and its /health conforms: ``doctor``
    finds nothing to do -- the product's ``render_env`` takes the seams. The
    pair: the service not healthy (``degraded``) -- ``up`` names it, nothing
    reaches the memory, and the product's ``render_env`` is the honest
    ``seam-before-health``."""
    app = LiveApp()
    try:
        made, _ = planned(
            tmp_path,
            "core",
            comms=comms(app.port),
            asked={"comms": {"TELEGRAM_BOT_TOKEN": ASKED}},
        )
        build = {s.name: s for s in deferred(made, "services")}["comms"].steps[1]
        assert isinstance(build, Build)
        app.health = health(
            service="comms", release=build.compose.ref, commit=build.compose.commit
        )
        app.health["alembic_head"] = None
        installed, cs = _plan(tmp_path, app.port, "install", [], again=True)
        assert installed.code is ExitCode.OK, installed.steps

        doctor, _ = _plan(tmp_path, app.port, "doctor", _doctor_calls(cs), again=True)
        assert doctor.code is ExitCode.OK, (doctor.steps, doctor.doctor_diff)
        assert doctor.doctor_diff == () and not [
            r for r in doctor.steps if r.status == "failed"
        ]

        # the pair: degraded -- up has something to do, the seams are not ready
        app.health["status"] = "degraded"
        doctor, _ = _plan(tmp_path, app.port, "doctor", _doctor_calls(cs), again=True)
    finally:
        app.close()
    diff = [(d.stack, d.name) for d in doctor.doctor_diff]
    assert ("comms", "up") in diff, doctor.doctor_diff
    [failed] = [r for r in doctor.steps if r.status == "failed"]
    assert (failed.stack, failed.name) == ("aivis", "render_env"), doctor.steps
    assert failed.reason is not None
    assert failed.reason.code == "render_env:seam-before-health", failed.reason
