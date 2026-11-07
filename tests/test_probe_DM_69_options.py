"""The probes of DM-69: options of an instance on the plan builder's ladders
(``services_support.planned``: ``deploy_plan`` with real git).

The product ``aivis`` declares ``options: [telegram, pay]``; ``payments`` is a
dependency under ``when: pay`` (in no edition, rule 41), its remote removed
when ``pay`` is off -- any command that asked it would fail; a key of the
product ``PAY_KEY`` is ``minted`` under ``when: pay``; ``egress`` opens
``api.github.com`` under ``pay``. ``comms`` knows ``telegram`` and takes its
bot token under ``when: telegram``.
"""

from pathlib import Path

from env_support import read_env
from services_support import comms_data, deferred, planned, run_stacks

from pridem.plan import StackSteps
from pridem.report.codes import ExitCode
from pridem.stacks.options import LITERAL
from pridem.stacks.schema import Product, Seam
from pridem.steps.egress import Egress
from pridem.steps.env import RenderEnv

BOT = "invented-bot-token-of-telegram-0069"
MAILGUN = "invented-mailgun-key-000000000069"


def _optional(data: dict[str, object]) -> None:
    deps = data["dependencies"]
    assert isinstance(deps, dict)
    deps["payments"]["when"] = "pay"
    data["editions"] = {
        "core": {"services": ["comms"]},
        "full": {"services": ["comms"]},
    }
    data["options"] = ["telegram", "pay"]
    env = data["env"]
    assert isinstance(env, dict)
    env["PAY_KEY"] = {"source": "minted", "when": "pay"}
    data["egress"] = [{"host": "api.github.com", "when": ["pay"]}]


def _comms() -> dict[str, object]:
    data = comms_data()
    data["options"] = ["telegram"]
    env = data["env"]
    assert isinstance(env, dict)
    env["TELEGRAM_BOT_TOKEN"] = {"source": "asked", "when": "telegram"}
    return data


def _box(tmp: Path, options: list[str], token: str, *, gone: tuple[str, ...] = ()):  # type: ignore[no-untyped-def]
    return planned(
        tmp,
        "core",
        gone=gone,
        comms=_comms(),
        asked={"comms": {"TELEGRAM_BOT_TOKEN": token, "MAILGUN_API_KEY": MAILGUN}},
        product_patch=_optional,
        options=options,
    )


def _render(made, root: Path):  # type: ignore[no-untyped-def]
    """``seams_check`` and comms' ``render_env``, then the product's with the
    seams of comms in the plan's memory, as ``up`` of comms would put them."""
    services = {s.name: s for s in deferred(made, "services")}
    outcome = run_stacks(
        [services["seams"], StackSteps("comms", [services["comms"].steps[0]])]
    )
    assert outcome.code is ExitCode.OK, outcome.steps
    own = deferred(made, "product")[0]
    render = own.steps[0]
    assert isinstance(render, RenderEnv) and isinstance(render.stack, Product)
    seams = [k for k, v in render.stack.env.items() if isinstance(v, Seam)]
    render.memory.healthy("comms", {k: f"value-of-{k.lower()}" for k in seams})
    outcome = run_stacks([StackSteps("aivis", [render])])
    assert outcome.code is ExitCode.OK, outcome.steps
    [egress] = [step for step in own.steps if isinstance(step, Egress)]
    return services, egress


def test_probe_DM_69_switched_off_option_takes_the_literal_and_leaves_its_service_out(
    tmp_path: Path,
) -> None:
    """``telegram`` and ``pay`` off: comms' token and the product's key under
    them are the literal in ``.env``; ``payments`` is neither asked of its
    remote nor installed; the host of ``pay`` is closed. The pair: both on --
    the values are real, ``payments`` is fetched and has its ladder, the host
    is open."""
    made, root = _box(tmp_path / "off", [], LITERAL, gone=("payments",))
    services, egress = _render(made, root)
    assert [s.name for s in deferred(made, "dependencies")] == ["comms", "dependencies"]
    assert "payments" not in services
    assert not (root / "opt" / "payments").exists()
    assert read_env(root, "comms")["TELEGRAM_BOT_TOKEN"] == LITERAL
    assert read_env(root, "aivis")["PAY_KEY"] == LITERAL
    assert egress.hosts == []

    # the pair: both options on
    made, root = _box(tmp_path / "on", ["telegram", "pay"], BOT)
    services, egress = _render(made, root)
    assert [s.name for s in deferred(made, "dependencies")] == [
        "comms",
        "payments",
        "dependencies",
    ]
    assert "payments" in services
    assert (root / "opt" / "payments" / "releases" / "v1.0.0").is_dir()
    assert read_env(root, "comms")["TELEGRAM_BOT_TOKEN"] == BOT
    key = read_env(root, "aivis")["PAY_KEY"]
    assert key != LITERAL and len(key) >= 32
    assert egress.hosts == ["api.github.com"]


def test_probe_DM_69_passport_without_a_required_option_is_refused_before_act(
    tmp_path: Path,
) -> None:
    """``options_required: [telegram]``, the passport without it: ``seams_check``
    refuses before the first ``act`` of a stack -- no env, no minted value, no
    release current of any stack. The pair: with it, green."""

    def required(data: dict[str, object]) -> None:
        _optional(data)
        data["options_required"] = ["telegram"]

    def box(tmp: Path, options: list[str], token: str):  # type: ignore[no-untyped-def]
        return planned(
            tmp,
            "core",
            comms=_comms(),
            asked={"comms": {"TELEGRAM_BOT_TOKEN": token, "MAILGUN_API_KEY": MAILGUN}},
            product_patch=required,
            options=options,
        )

    made, root = box(tmp_path / "off", ["pay"], LITERAL)
    services = {s.name: s for s in deferred(made, "services")}
    outcome = run_stacks([services["seams"], services["comms"]])
    [failed] = [r for r in outcome.steps if r.status == "failed"]
    assert (failed.stack, failed.name) == ("seams", "seams_check")
    assert failed.reason is not None
    assert failed.reason.code == "seams_check:option-required-off"
    assert failed.reason.params == {"options": ["telegram"]}
    assert not [r for r in outcome.steps if r.status == "ok" and r.stack != "seams"]
    for stack in ("comms", "payments", "aivis"):
        assert not (root / "opt" / stack / "env").exists(), stack
        assert not (root / "opt" / stack / "current").exists(), stack

    # the pair: telegram on -- seams_check is green
    made, root = box(tmp_path / "on", ["telegram"], BOT)
    services = {s.name: s for s in deferred(made, "services")}
    outcome = run_stacks([services["seams"]])
    assert outcome.code is ExitCode.OK, outcome.steps
