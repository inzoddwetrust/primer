"""DM-79: a throwaway container of a product has no network (protocol 4.1).

The probe: ``derive`` of a product runs in its image with ``--network none``
(and with no capability, never pulling the image of this run); the pair: a
service's ``derive`` keeps the default network -- its way out -- with the same
two other flags. Both by the strict scenario: the command exactly, in order.
"""

from pathlib import Path

from env_support import (
    COMMS_REPO,
    IMAGE,
    STDOUT,
    box,
    derive,
    passport_data,
    product,
    read_env,
    render,
    run,
    service,
)

from pridem.report.codes import ExitCode
from pridem.runner import FakeCall, FakeRunner

ONE = "isolated-value-of-the-first-key-0001"
TWO = "isolated-value-of-the-second-key-002"
BOT_URL = "https://t.me/invented_bot_000000079"


def _product_derive(env_file: Path, *command: str, value: str) -> FakeCall:
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
            "--label",
            "pridem.stack=aivis",
            "--env-file",
            str(env_file),
            "--",
            IMAGE,
            *command,
        ),
        lines=((STDOUT, value),),
    )


def test_probe_DM_79_product_derive_has_no_network(tmp_path: Path) -> None:
    """Each ``derived`` key of a product -- two here, each its own container
    -- is derived with ``--network none``; the pair: comms' ``derive`` has no
    ``--network`` at all, and both drop every capability and never pull."""
    made = product(
        tmp_path,
        {
            "SECRET_KEY": {"source": "minted"},
            "FIRST_DERIVED": {"source": "derived", "run": "app derive one"},
            "SECOND_DERIVED": {"source": "derived", "run": "app derive two"},
        },
    )
    root, fetched = box(tmp_path, passport_data())
    env_file = root / "opt" / "aivis" / "env" / "derive.env"
    first = render(made, root, fetched)
    with FakeRunner(
        _product_derive(env_file, "app", "derive", "one", value=ONE),
        _product_derive(env_file, "app", "derive", "two", value=TWO),
    ) as runner:
        outcome, _ = run([first, derive(first, root)], runner)
    assert outcome.code is ExitCode.OK, outcome.steps
    held = read_env(root, "aivis")
    assert (held["FIRST_DERIVED"], held["SECOND_DERIVED"]) == (ONE, TWO)

    # the pair: a service keeps its way out
    other = tmp_path / "service"
    other.mkdir()
    owner = product(other, {}, dependencies={"comms": COMMS_REPO})
    comms = service(
        other,
        {
            "SECRET_KEY": {"source": "minted"},
            "TELEGRAM_BOT_URL": {"source": "derived", "run": "comms derive bot-url"},
        },
    )
    root, fetched = box(other, passport_data())
    env_file = root / "opt" / "comms" / "env" / "derive.env"
    argv = (
        "docker",
        "run",
        "--rm",
        "--cap-drop",
        "ALL",
        "--pull",
        "never",
        "--label",
        "pridem.stack=comms",
        "--env-file",
        str(env_file),
        "--",
        IMAGE,
        "comms",
        "derive",
        "bot-url",
    )
    assert "--network" not in argv
    first = render(comms, root, fetched, product=owner)
    with FakeRunner(FakeCall(argv, lines=((STDOUT, BOT_URL),))) as runner:
        outcome, _ = run([first, derive(first, root)], runner)
    assert outcome.code is ExitCode.OK, outcome.steps
    assert read_env(root, "comms")["TELEGRAM_BOT_URL"] == BOT_URL
