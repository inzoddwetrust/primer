"""Seams (DM-14): the order of providers, half seams before ``act``, the plan's
memory after health. A service's ``provides`` is the value of its own ``env``
key of that name; the product's is a URL from the passport."""

from pathlib import Path

import pytest
from env_support import (
    COMMS_REPO,
    box,
    env_of,
    passport_data,
    product,
    read_env,
    render,
    run,
    service,
)

from pridem.report.codes import ExitCode
from pridem.runner import FakeRunner
from pridem.stacks.schema import Product, Service
from pridem.stacks.seams import (
    SeamMemory,
    half_seams,
    outside_edition,
    product_value,
    provider_order,
)
from pridem.steps.env import SeamsCheck

WEBHOOK = {"from": "domains.api", "path": "/internal/comms/webhook"}
DOMAINS = {"frontend": "a.example.org", "api": "api.example.org"}


def pair(tmp: Path, **change: object) -> tuple[Product, Service]:
    """A product and comms wired both ways; ``change`` breaks one end."""
    product_env: dict[str, object] = {
        "COMMS_API_URL": {"source": "seam", "from": "comms"}
    }
    comms_env: dict[str, object] = {
        "COMMS_API_URL": {"source": "address"},
        "PRODUCT_WEBHOOK_URL": {"source": "seam", "from": "product"},
    }
    provides: dict[str, object] = {"PRODUCT_WEBHOOK_URL": WEBHOOK}
    comms_provides = ["COMMS_API_URL"]
    requires = ["PRODUCT_WEBHOOK_URL"]
    match change.get("form"):
        case "not-provided":
            product_env["COMMS_TOKEN"] = {"source": "seam", "from": "comms"}
        case "not-offered":
            requires.append("PRODUCT_OTHER_URL")
            comms_env["PRODUCT_OTHER_URL"] = {"source": "seam", "from": "product"}
        case "a-verb":
            provides["PRODUCT_REPLAY"] = {"verb": "replay"}
            requires.append("PRODUCT_REPLAY")
            comms_env["PRODUCT_REPLAY"] = {"source": "seam", "from": "product"}
        case "not-required":
            requires.remove("PRODUCT_WEBHOOK_URL")
        case "not-wired":
            del comms_env["PRODUCT_WEBHOOK_URL"]
        case "provided-without-env":
            comms_provides.append("COMMS_SERVICE_TOKEN")
        case None:
            pass
        case other:
            raise AssertionError(other)
    made = product(
        tmp, product_env, dependencies={"comms": COMMS_REPO}, provides=provides
    )
    comms = service(tmp, comms_env, provides=comms_provides, requires=requires)
    return made, comms


# --- probes ---------------------------------------------------------------------


@pytest.mark.parametrize(
    ("form", "seam"),
    [
        ("not-provided", "aivis.COMMS_TOKEN: comms does not provide it"),
        ("not-offered", "comms.PRODUCT_OTHER_URL: the product does not provide it"),
        ("a-verb", "comms.PRODUCT_REPLAY: the product provides a verb"),
        ("not-required", "comms.PRODUCT_WEBHOOK_URL: a seam not in requires"),
        ("not-wired", "comms.PRODUCT_WEBHOOK_URL: required, not a seam in env"),
        (
            "provided-without-env",
            "comms.COMMS_SERVICE_TOKEN: provided without an env key",
        ),
    ],
)
def test_probe_DM_14_half_seam_refuses_before_act(
    tmp_path: Path, form: str, seam: str
) -> None:
    made, comms = pair(tmp_path, form=form)
    root, fetched = box(tmp_path, passport_data(domains=DOMAINS))
    steps = [SeamsCheck(made, {"comms": comms}, fetched), render(made, root, fetched)]

    with FakeRunner() as runner:
        outcome, _ = run(steps, runner)

    [checked, after] = outcome.steps
    assert checked.status == "failed" and checked.reason is not None
    assert checked.reason.code == "seams_check:half-seam"
    assert seam in checked.reason.params["seams"]  # type: ignore[operator]
    assert after.status == "skipped"
    assert not env_of(root, "aivis").exists()
    # the pair: the whole seam passes
    whole, comms = pair(tmp_path)
    assert half_seams(whole, {"comms": comms}, "full") == []


def test_probe_DM_14_seam_before_provider_health_refuses_plan(tmp_path: Path) -> None:
    made, comms = pair(tmp_path)
    root, fetched = box(tmp_path, passport_data(domains=DOMAINS))
    memory = SeamMemory()

    early, _ = run([render(made, root, fetched, memory=memory)], FakeRunner())

    [step] = early.steps
    assert step.reason is not None
    assert step.reason.code == "render_env:seam-before-health"
    assert step.reason.params == {"from": "comms", "names": ["COMMS_API_URL"]}
    assert not env_of(root, "aivis").exists()  # refused in check, before act
    # the pair: after the provider's health the same render is green
    provider = render(comms, root, fetched, product=made)
    assert run([provider], FakeRunner())[0].code is ExitCode.OK
    memory.healthy("comms", provider.provided())
    late, _ = run([render(made, root, fetched, memory=memory)], FakeRunner())
    assert late.code is ExitCode.OK, late.steps
    assert read_env(root, "aivis")["COMMS_API_URL"] == "http://comms-comms-app:8000"


# --- the rest -------------------------------------------------------------------


def test_address_is_the_alias_on_the_network_pridem(tmp_path: Path) -> None:
    _, comms = pair(tmp_path)
    made, _ = pair(tmp_path)
    root, fetched = box(tmp_path, passport_data(domains=DOMAINS))
    step = render(comms, root, fetched, product=made)
    assert run([step], FakeRunner())[0].code is ExitCode.OK
    assert step.provided() == {"COMMS_API_URL": "http://comms-comms-app:8000"}


def test_product_provides_a_url_from_the_passport(tmp_path: Path) -> None:
    made, comms = pair(tmp_path)
    root, fetched = box(tmp_path, passport_data(domains=DOMAINS))
    assert fetched.passport is not None
    url = "https://api.example.org/internal/comms/webhook"
    assert product_value(made, fetched.passport, "PRODUCT_WEBHOOK_URL") == url
    assert run([render(comms, root, fetched, product=made)], FakeRunner())[0].code is (
        ExitCode.OK
    )
    assert read_env(root, "comms")["PRODUCT_WEBHOOK_URL"] == url


def test_provider_order_is_the_edition_then_the_product(tmp_path: Path) -> None:
    deps = {
        "comms": COMMS_REPO,
        "payments": {"repo": "git@github.com:acme/payments.git", "version": ">=1,<2"},
        "meet": {
            "repo": "git@github.com:acme/meet.git",
            "version": ">=1,<2",
            "topology": "remote",
        },
    }
    editions = {
        "core": {"services": ["comms"]},
        "full": {"services": ["comms", "payments"]},
    }
    made = product(tmp_path, {}, dependencies=deps, editions=editions)
    assert provider_order(made, "full") == ["comms", "payments", "aivis"]
    assert provider_order(made, "core") == ["comms", "aivis"]


def test_seam_from_a_service_outside_the_edition_is_refused(tmp_path: Path) -> None:
    deps = {
        "comms": COMMS_REPO,
        "payments": {"repo": "git@github.com:acme/payments.git", "version": ">=1,<2"},
    }
    editions = {
        "core": {"services": ["comms"]},
        "full": {"services": ["comms", "payments"]},
    }
    env = {"PAYMENTS_API_URL": {"source": "seam", "from": "payments"}}
    made = product(tmp_path, env, dependencies=deps, editions=editions)
    assert outside_edition(made, "core") == ["aivis.PAYMENTS_API_URL: payments"]
    assert outside_edition(made, "full") == []
    root, fetched = box(tmp_path, passport_data(edition="core"))
    comms = service(tmp_path, {})
    outcome, _ = run([SeamsCheck(made, {"comms": comms}, fetched)], FakeRunner())
    [step] = outcome.steps
    assert step.reason is not None
    assert step.reason.code == "seams_check:seam-outside-edition"


def test_memory_answers_only_after_health() -> None:
    memory = SeamMemory()
    with pytest.raises(Exception, match="not healthy"):
        memory.values("comms", ["A"])
    memory.healthy("comms", {"A": "a"})
    assert memory.values("comms", ["A"]) == {"A": "a"}
    with pytest.raises(Exception, match="not healthy"):
        memory.values("comms", ["B"])
