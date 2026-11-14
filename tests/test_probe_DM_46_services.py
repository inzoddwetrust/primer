"""The probes of DM-46: services in the plan (protocol 4, 4.3-4.6; contract 3
rules 11, 13)."""

from dataclasses import replace
from datetime import UTC, datetime
from itertools import count
from pathlib import Path

import pytest
from compose_support import SHA, image_call, stdout
from env_support import context
from env_support import service as service_stack
from plan_support import Journal, ListSink, ScriptedStep
from services_support import deferred, planned

from pridem.events import Json
from pridem.plan import Plan, StackSteps
from pridem.report.codes import ExitCode
from pridem.runner import FakeCall, FakeRunner
from pridem.stacks.seams import SeamMemory
from pridem.steps.base import StepFailed
from pridem.steps.compose import ComposeStack, write_override
from pridem.steps.env import RenderEnv
from pridem.steps.services import DataCopy, DataItem


def _ladder(stacks: list[StackSteps]) -> list[tuple[str, str]]:
    return [(stack.name, step.name) for stack in stacks for step in stack.steps]


def test_probe_DM_46_edition_installs_only_its_services(tmp_path: Path) -> None:
    """``core`` leaves ``payments`` out: no key, no tag asked of its remote, no
    clone, no ladder; the pair: ``full`` installs it."""
    made, root = planned(tmp_path / "core", "core", gone=["payments"])
    keys = [s.name for s in deferred(made, "dependencies")]
    ladders = _ladder(deferred(made, "services"))
    assert keys == ["comms", "dependencies"]
    assert ("comms", "up") in ladders
    assert not any(stack == "payments" for stack, _ in ladders)
    assert not (root / "opt" / "payments").exists()
    assert (root / "opt" / "comms" / "releases" / "v1.0.0" / "primer.yaml").is_file()
    # the pair: full installs payments, by the same ladder
    made, root = planned(tmp_path / "full", "full")
    assert [s.name for s in deferred(made, "dependencies")] == [
        "comms",
        "payments",
        "dependencies",
    ]
    ladders = _ladder(deferred(made, "services"))
    assert ("payments", "up") in ladders
    assert (root / "opt" / "payments" / "releases" / "v1.0.0").is_dir()


def test_probe_DM_46_product_waits_for_all_provides(tmp_path: Path) -> None:
    """Every service of the edition is up -- its provides in the memory after
    its health -- before the product renders its env; the product cannot
    render before (``seam-before-health``); the pair: with them, it does."""
    made, _ = planned(tmp_path, "full")
    order = _ladder([*deferred(made, "services"), *deferred(made, "product")])
    first = order.index(("aivis", "render_env"))
    ups = [order.index((name, "up")) for name in ("comms", "payments")]
    assert all(up < first for up in ups)
    assert order[first + 1 :] and ("aivis", "up") in order[first + 1 :]
    # the product's env before the service's health is refused by name
    render = next(
        step
        for stack in deferred(made, "product")
        for step in stack.steps
        if stack.name == "aivis" and step.name == "render_env"
    )
    assert isinstance(render, RenderEnv)
    memory: SeamMemory = render.memory
    with pytest.raises(StepFailed) as early:
        render.check(context(FakeRunner()))
    assert early.value.reason.code == "seam-before-health"
    memory.healthy(
        "comms",
        {
            "COMMS_API_URL": "http://comms-comms-app:8000",
            "COMMS_SERVICE_TOKEN": "t" * 43,
            "TELEGRAM_BOT_URL": "https://t.me/bot",
        },
    )
    assert render.check(context(FakeRunner())).needed  # from the live seams now


# --- data_copy -----------------------------------------------------------------


def _data_copy(tmp: Path) -> tuple[DataCopy, ComposeStack, DataItem]:
    comms = service_stack(tmp, {})
    root = tmp / "box"
    release = root / "opt" / "comms" / "releases" / "v1.0.0"
    release.mkdir(parents=True)
    product = tmp / "aivis-release"
    (product / "comms-profile").mkdir(parents=True)
    (product / "comms-profile" / "kinds.yaml").write_text("kinds: [new]\n")
    item = DataItem(
        "profile",
        product / "comms-profile",
        product,
        root / "opt" / "comms" / "data" / "aivis@v2" / "profile",
        "PROFILE_DIR",
        "comms validate --profile <dir>",
    )
    step = DataCopy(
        comms,
        "comms",
        release=release,
        ref="v1.0.0",
        commit=SHA,
        items=[item],
        root=root,
    )
    compose = ComposeStack(comms, "comms", release, "v1.0.0", SHA, root, staged=True)
    # the override the running service is on; the deploy's, build's of this run
    write_override(replace(compose, staged=False), "old\n")
    write_override(compose, "new\n")
    return step, compose, item


def _validate_call(compose: ComposeStack, item: DataItem, code: int) -> FakeCall:
    labels: list[str] = []
    for key, value in compose.release_labels().items():
        labels += ["--label", f"{key}={value}"]
    return FakeCall(
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
            f"PROFILE_DIR={item.container}",
            "--",
            "sha256:" + "c" * 64,
            "comms",
            "validate",
            "--profile",
            item.container,
        ),
        code=code,
        lines=stdout("checked"),
    )


def _plan(step: DataCopy, runner: FakeRunner, after: ScriptedStep) -> Plan:
    ticks = count()
    return Plan(
        [StackSteps("comms", [step, after], root=True)],
        mode="install",
        role="test",
        runner=runner,
        sink=ListSink(),
        clock=lambda: float(next(ticks)),
        now=lambda: datetime(2026, 11, 5, tzinfo=UTC),
    )


@pytest.mark.parametrize("code", [1, 0])
def test_probe_DM_46_overlay_validate_failure_leaves_old_running(
    tmp_path: Path, code: int
) -> None:
    """A red ``validate`` of the new profile by the new image: the override on
    disk stays the one the running service is on, the service is not
    restarted (``up`` never runs); the pair -- green: the ladder goes on to
    ``up``, on the deploy's override.

    Changed by DM-89 (by the dispatcher's word, before the change): the
    override goes in place in ``finalize`` with ``current`` and ``.env``, not
    in ``data_copy``; the deploy's (``<entry>.next.yml``) is what ``up`` reads,
    and it stays for ``finalize``.

    Changed by DM-79 (``_validate_call``; by the dispatcher's word, before the change):
    throwaway containers drop every capability; an image of this run is never
    pulled."""
    step, compose, item = _data_copy(tmp_path)
    runner = FakeRunner(
        image_call(compose, "comms-app", "sha256:" + "c" * 64),
        _validate_call(compose, item, code),
    )
    journal = Journal()
    up = ScriptedStep("up", 13, journal)
    outcome = _plan(step, runner, up).run()
    runner.assert_consumed()
    by = {record.name: record for record in outcome.steps}
    running = replace(compose, staged=False)
    assert running.override.read_text() == "old\n"  # red or green: finalize's
    if code:
        assert by["data_copy"].reason is not None
        assert by["data_copy"].reason.code == "data_copy:validate-failed"
        assert by["up"].status == "skipped" and journal == []
    else:
        assert outcome.code is ExitCode.OK, outcome.steps
        assert compose.override.read_text() == "new\n"
        assert by["up"].status == "ok"
        fact: Json = by["data_copy"].verify["data"]
        assert fact == {"profile": str(item.target)}
    assert item.target.is_dir()  # the copy is made in either case, inert
