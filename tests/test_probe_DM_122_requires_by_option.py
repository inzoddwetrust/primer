"""Probe of DM-122: a service's ``requires`` whose variable is under ``when:
o`` is not asked of the product while ``o`` is off (contract 3 rule 38) --
comms takes the product's storage under ``when: llm``, and a product with no
storage stands beside it while ``llm`` is off. On, the seam is asked as
before. ``seam_needed`` is the one predicate of ``half_seams`` and of the
edges of ``seams_verify``, for a service's ``requires`` and for the
product's seams alike.
"""

from collections.abc import Iterator, Mapping, Sequence
from pathlib import Path

import pytest
from compose_support import SHA, LiveApp, health, log_line, observe_calls
from env_support import (
    COMMS_REPO,
    box,
    env_of,
    load,
    passport_data,
    product_data,
    read_env,
    render,
    run,
    service_data,
)
from services_support import deferred, planned

from pridem.events import Json
from pridem.report.codes import ExitCode
from pridem.runner import FakeCall, FakeRunner
from pridem.stacks import names as machine
from pridem.stacks.options import LITERAL
from pridem.stacks.schema import Product, Service
from pridem.stacks.seams import half_seams
from pridem.steps.compose import ComposeStack
from pridem.steps.env import SeamsCheck
from pridem.steps.services import SeamsVerify

STORAGE = "PRODUCT_STORAGE_ADDRESS"
DOMAINS = {"frontend": "a.example.org", "api": "api.example.org"}
OFFER = {"from": "domains.api", "path": "/storage"}


@pytest.fixture
def two_apps() -> Iterator[tuple[LiveApp, LiveApp]]:
    first, second = LiveApp(), LiveApp()
    try:
        yield first, second
    finally:
        first.close()
        second.close()


def _pair(
    tmp: Path,
    *,
    declared: bool,
    offer: Mapping[str, object] | None = None,
    comms_env: dict[str, object] | None = None,
    requires: Sequence[str] = (STORAGE,),
    product_env: dict[str, object] | None = None,
    ports: tuple[int, int] = (8000, 8000),
) -> tuple[Product, Service]:
    """A product that takes ``COMMS_API_URL`` from comms and gives ``STORAGE``
    only with ``offer``; comms takes ``STORAGE`` from the product under
    ``when: llm``. ``declared`` -- the product has ``llm`` among its options."""
    tmp.mkdir(parents=True, exist_ok=True)
    data = product_data(
        product_env or {"COMMS_API_URL": {"source": "seam", "from": "comms"}},
        dependencies={"comms": COMMS_REPO},
        provides={STORAGE: offer} if offer is not None else {},
        options=["llm"] if declared else (),
    )
    stacks = data["stacks"]
    assert isinstance(stacks, dict)
    stacks["aivis"]["app"].update({"port": ports[0], "health": "/health"})
    made = load(tmp, data)
    assert isinstance(made, Product)
    sdata = service_data(
        comms_env
        or {
            "COMMS_API_URL": {"source": "address"},
            STORAGE: {"source": "seam", "from": "product", "when": "llm"},
        },
        provides=["COMMS_API_URL"],
        requires=requires,
        options=["llm"],
    )
    sstacks = sdata["stacks"]
    assert isinstance(sstacks, dict)
    sstacks["comms"]["app"]["port"] = ports[1]
    comms = load(tmp, sdata)
    assert isinstance(comms, Service)
    return made, comms


def _observe(compose: ComposeStack, app: str) -> list[FakeCall]:
    """``observe_calls`` with the stack's own app in ``ps`` and ``logs``."""
    own = len(compose.product_argv())
    fixed = []
    for call in observe_calls(compose, logs=(log_line(compose.stack.name),)):
        argv = call.argv
        if len(argv) > own and argv[own] in ("ps", "logs") and argv[-1] == "app":
            argv = (*argv[:-1], app)
        fixed.append(FakeCall(argv, lines=call.lines))
    return fixed


def _verify(
    tmp: Path, made: Product, comms: Service, on: frozenset[str]
) -> tuple[SeamsVerify, list[FakeCall]]:
    root = tmp / "box"
    stacks = {
        "aivis": ComposeStack(
            made, "aivis", root / "a", "main", SHA, root, staged=True
        ),
        "comms": ComposeStack(
            comms, "comms", root / "c", "v1.0.0", SHA, root, staged=True
        ),
    }
    calls = [*_observe(stacks["aivis"], "app"), *_observe(stacks["comms"], "comms-app")]
    return SeamsVerify(made, {"comms": comms}, stacks, on), calls


def _live(
    apps: tuple[LiveApp, LiveApp],
    product: dict[str, Json],
    comms: dict[str, Json],
) -> None:
    apps[0].health = health(seams=product, service="aivis")
    apps[1].health = health(seams=comms, service="comms")


# --- the probe --------------------------------------------------------------------


@pytest.mark.parametrize(
    ("declared", "options"),
    [(True, []), (False, None)],
    ids=["llm-off-by-the-passport", "llm-not-the-product-s"],
)
def test_probe_DM_122_a_requires_under_an_option_off_is_not_asked_of_the_product(
    tmp_path: Path,
    two_apps: tuple[LiveApp, LiveApp],
    declared: bool,
    options: list[str] | None,
) -> None:
    """A product with no storage beside comms, which takes it under ``when:
    llm``: with ``llm`` off -- by the passport, or not among the product's
    options at all -- ``seams_check`` is green, comms' variable is the
    literal, and ``seams_verify`` builds no edge of it: comms, left with no
    seam to take, is not asked ``requires_satisfied`` (it says ``false``
    here) and the product is not asked to provide it. The pair: ``llm`` on,
    the same product is a half seam before any ``act``, and live the seam is
    an edge again."""
    ports = (two_apps[0].port, two_apps[1].port)
    made, comms = _pair(tmp_path, declared=declared, ports=ports)
    root, fetched = box(tmp_path, passport_data(domains=DOMAINS, options=options))
    steps = [
        SeamsCheck(made, {"comms": comms}, fetched),
        render(comms, root, fetched, product=made),
    ]
    with FakeRunner() as runner:
        outcome, _ = run(steps, runner)
    assert outcome.code is ExitCode.OK, outcome.steps
    assert read_env(root, "comms")[STORAGE] == LITERAL
    # live: comms is a provider only; its requires_satisfied is not read
    _live(
        two_apps,
        {"provides": [], "requires_satisfied": True},
        {"provides": ["COMMS_API_URL"], "requires_satisfied": False},
    )
    step, calls = _verify(tmp_path, made, comms, frozenset())
    with FakeRunner(*calls, *calls) as runner:  # check, then verify
        live, _ = run([step], runner)
    [record] = live.steps
    assert live.code is ExitCode.OK, record
    assert record.verify["seams"] == ["aivis.COMMS_API_URL <- comms"]
    # the pair: llm on -- the product without storage is a half seam
    on_made, on_comms = _pair(tmp_path / "on", declared=True, ports=ports)
    on_root, on_fetched = box(
        tmp_path / "on", passport_data(domains=DOMAINS, options=["llm"])
    )
    with FakeRunner() as runner:
        refused, _ = run(
            [
                SeamsCheck(on_made, {"comms": on_comms}, on_fetched),
                render(on_comms, on_root, on_fetched, product=on_made),
            ],
            runner,
        )
    [checked, after] = refused.steps
    assert checked.reason is not None
    assert checked.reason.code == "seams_check:half-seam"
    assert checked.reason.params["seams"] == [
        "comms.PRODUCT_STORAGE_ADDRESS: the product does not provide it"
    ]
    assert after.status == "skipped" and not env_of(on_root, "comms").exists()
    step, calls = _verify(tmp_path / "on", on_made, on_comms, frozenset({"llm"}))
    with FakeRunner(*calls) as runner:
        red, _ = run([step], runner)
    [record] = red.steps
    assert record.reason is not None
    assert record.reason.code == "seams_verify:provide-not-live"
    assert record.reason.params == {"stack": "aivis", "names": [STORAGE]}


# --- the rest ---------------------------------------------------------------------


def test_off_the_product_s_end_is_not_read_whatever_it_is(tmp_path: Path) -> None:
    """``llm`` off: a product that gives the name as a verb is no half seam
    either -- nothing of the product's end is read. On, the verb is one."""
    made, comms = _pair(tmp_path, declared=True, offer={"verb": "replay"})
    assert half_seams(made, {"comms": comms}, "full", on=frozenset()) == []
    assert half_seams(made, {"comms": comms}, "full", on=frozenset({"llm"})) == [
        "comms.PRODUCT_STORAGE_ADDRESS: the product provides a verb"
    ]
    given, comms = _pair(tmp_path / "given", declared=True, offer=OFFER)
    assert half_seams(given, {"comms": comms}, "full", on=frozenset({"llm"})) == []


def test_the_form_of_the_service_s_file_is_checked_whatever_the_options(
    tmp_path: Path,
) -> None:
    """A ``requires`` that names no seam of the service's ``env`` -- here a
    ``param`` under ``when: llm`` -- and a seam from the product left out of
    ``requires`` are the service's own form: half seams with ``llm`` off."""
    made, comms = _pair(
        tmp_path,
        declared=True,
        comms_env={
            "COMMS_API_URL": {"source": "address"},
            STORAGE: {"source": "param", "when": "llm"},
            "PRODUCT_OTHER_URL": {"source": "seam", "from": "product", "when": "llm"},
        },
    )
    assert half_seams(made, {"comms": comms}, "full", on=frozenset()) == [
        "comms.PRODUCT_STORAGE_ADDRESS: the product does not provide it",
        "comms.PRODUCT_STORAGE_ADDRESS: required, not a seam in env",
        "comms.PRODUCT_OTHER_URL: a seam not in requires",
    ]


def test_one_requires_off_and_one_on(
    tmp_path: Path, two_apps: tuple[LiveApp, LiveApp]
) -> None:
    """Two ``requires``, ``STORAGE`` under ``llm`` (off) and one with no
    option: only the second is an edge, so comms is a consumer and its
    ``requires_satisfied`` is read -- ``false`` is red."""
    made, comms = _pair(
        tmp_path,
        declared=True,
        offer=None,
        comms_env={
            "COMMS_API_URL": {"source": "address"},
            STORAGE: {"source": "seam", "from": "product", "when": "llm"},
            "PRODUCT_WEBHOOK_URL": {"source": "seam", "from": "product"},
        },
        requires=(STORAGE, "PRODUCT_WEBHOOK_URL"),
        ports=(two_apps[0].port, two_apps[1].port),
    )
    assert half_seams(made, {"comms": comms}, "full", on=frozenset()) == [
        "comms.PRODUCT_WEBHOOK_URL: the product does not provide it"
    ]
    for satisfied, code in ((True, None), (False, "seams_verify:requires-unsatisfied")):
        _live(
            two_apps,
            {"provides": ["PRODUCT_WEBHOOK_URL"], "requires_satisfied": True},
            {"provides": ["COMMS_API_URL"], "requires_satisfied": satisfied},
        )
        step, calls = _verify(tmp_path, made, comms, frozenset())
        with FakeRunner(*calls, *(calls if code is None else [])) as runner:
            outcome, _ = run([step], runner)  # check, then verify when green
        [record] = outcome.steps
        if code is None:
            assert outcome.code is ExitCode.OK, record
            assert record.verify["seams"] == [
                "aivis.COMMS_API_URL <- comms",
                "comms.PRODUCT_WEBHOOK_URL <- aivis",
            ]
        else:
            assert record.reason is not None and record.reason.code == code


def test_a_seam_of_the_product_under_an_option_off_is_no_live_edge(
    tmp_path: Path, two_apps: tuple[LiveApp, LiveApp]
) -> None:
    """The other direction, by the same predicate: the product's seam from
    comms under ``when: llm``, off -- comms is not asked to provide it live
    (its ``/health`` does not list it); on, it is, and missing is red."""
    made, comms = _pair(
        tmp_path,
        declared=True,
        product_env={
            "COMMS_API_URL": {"source": "seam", "from": "comms"},
            "COMMS_EVENTS_ADDRESS": {"source": "seam", "from": "comms", "when": "llm"},
        },
        comms_env={
            "COMMS_API_URL": {"source": "address"},
            "COMMS_EVENTS_ADDRESS": {"source": "address", "when": "llm"},
            STORAGE: {"source": "seam", "from": "product", "when": "llm"},
        },
        offer=OFFER,
        ports=(two_apps[0].port, two_apps[1].port),
    )
    _live(
        two_apps,
        {"provides": [STORAGE], "requires_satisfied": True},
        {"provides": ["COMMS_API_URL"], "requires_satisfied": True},
    )
    step, calls = _verify(tmp_path, made, comms, frozenset())
    with FakeRunner(*calls, *calls) as runner:
        outcome, _ = run([step], runner)
    [record] = outcome.steps
    assert outcome.code is ExitCode.OK, record
    assert record.verify["seams"] == ["aivis.COMMS_API_URL <- comms"]
    step, calls = _verify(tmp_path, made, comms, frozenset({"llm"}))
    with FakeRunner(*calls) as runner:
        red, _ = run([step], runner)
    [record] = red.steps
    assert record.reason is not None
    assert record.reason.code == "seams_verify:provide-not-live"
    assert record.reason.params == {"stack": "comms", "names": ["COMMS_EVENTS_ADDRESS"]}


def test_the_plan_gives_seams_verify_the_options_on(tmp_path: Path) -> None:
    """``seams_verify`` of the plan knows the options of the passport: none
    -- empty; ``telegram`` on -- that one."""

    def declare(data: dict[str, object]) -> None:
        data["options"] = ["telegram"]

    for options, wanted in ((None, frozenset[str]()), (["telegram"], {"telegram"})):
        made, _ = planned(
            tmp_path / str(options), "full", options=options, product_patch=declare
        )
        [step] = [
            step
            for stack in deferred(made, machine.PRODUCT)
            for step in stack.steps
            if isinstance(step, SeamsVerify)
        ]
        assert step.on == wanted
