"""``doctor`` of a product with a seam from a live service (DM-59 FIX).

``doctor`` runs ``check`` alone. The seams of a service reach the plan's
memory with its environment (DM-126; it was from its ``up``, after health):
in a run from ``verify`` of the step that reads ``next.env`` back with no
placeholder left, in ``doctor`` from that step's ``check`` where it found
nothing to do -- the values read from the service's ``next.env``. The
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
from pridem.plan import Deferred, Plan, StackSteps
from pridem.report.codes import ExitCode
from pridem.runner import FakeCall, FakeRunner
from pridem.stacks.env import DERIVED_PLACEHOLDER, env_text, parse_env, write_private
from pridem.steps.build import Build
from pridem.steps.compose import ComposeStack
from pridem.steps.env import usable


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
    services = {s.name: s for s in deferred(made, "pridem-services")}
    build = services["comms"].steps[1]
    assert isinstance(build, Build)
    product = deferred(made, "pridem-product")
    render = product[0].steps[0]
    [later] = [s for s in product if s.name == "comms"]  # from up on (DM-126)
    ticks = count()
    given = calls or script(build.compose, root / "opt" / "comms" / "env")
    with FakeRunner(*given) as runner:
        outcome = Plan(
            [
                services["pridem-seams"],
                services["comms"],
                StackSteps("aivis", [render]),
                # a second half of an entry is made by a deferred stack
                Deferred("pridem-product", lambda: [later], after="fetch_root"),
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
    pair: the service's environment is not whole -- a ``derived`` value still
    to be computed: ``derive_env`` names it, nothing reaches the memory, and
    the product's ``render_env`` is the honest ``seam-before-health``.

    Changed by DM-126 (owner's decision of 19.11): a seam is ready with the
    provider's environment, not its health. A service that is ``degraded``
    no longer holds the product's ``render_env`` back -- ``up`` still names
    it -- so the pair is the environment that is not ready."""
    app = LiveApp()
    try:
        made, _ = planned(
            tmp_path,
            "core",
            comms=comms(app.port),
            asked={"comms": {"TELEGRAM_BOT_TOKEN": ASKED}},
        )
        build = {s.name: s for s in deferred(made, "pridem-services")}["comms"].steps[1]
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

        # degraded: up has something to do, and the seams are ready all the same
        app.health["status"] = "degraded"
        doctor, _ = _plan(tmp_path, app.port, "doctor", _doctor_calls(cs), again=True)
        diff = [(d.stack, d.name) for d in doctor.doctor_diff]
        assert diff == [("comms", "up")], doctor.doctor_diff
        assert not [r for r in doctor.steps if r.status == "failed"], doctor.steps
        app.health["status"] = "ok"

        # the pair: a derived value not computed -- the env is not ready
        env = cs.env_file
        values = parse_env(env.read_text(encoding="utf-8"))
        assert usable(values["TELEGRAM_BOT_URL"])
        values["TELEGRAM_BOT_URL"] = DERIVED_PLACEHOLDER
        write_private(env, env_text(values))
        calls = _doctor_calls(cs)
        del calls[3:5]  # derive_env asks docker nothing: the value is to derive
        doctor, _ = _plan(tmp_path, app.port, "doctor", calls, again=True)
    finally:
        app.close()
    diff = [(d.stack, d.name) for d in doctor.doctor_diff]
    assert diff == [("comms", "derive_env")], doctor.doctor_diff
    [failed] = [r for r in doctor.steps if r.status == "failed"]
    assert (failed.stack, failed.name) == ("aivis", "render_env"), doctor.steps
    assert failed.reason is not None
    assert failed.reason.code == "render_env:seam-before-health", failed.reason
