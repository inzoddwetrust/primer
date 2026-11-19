"""DM-23 (velo-dev 19.11): the networks of the box's pairs, made before any
stack.

``pair_networks`` makes every network of the box's pairs -- internal, labelled
with the provider, the point and the consumer -- in the stack
``pridem-points``, after the sources are read and before the services; both
sides of a pair declare it external. Every expected command is literal
(``par0`` 14.2).
"""

import json

import pytest
from env_support import context

from pridem.events import Code
from pridem.runner import FakeCall, FakeRunner, Stream
from pridem.stacks.seams import Pair
from pridem.steps.base import StepFailed
from pridem.steps.points import PairNetworks

STORAGE = Pair("velo-storage", "files", "storage", "comms", "PRODUCT_STORAGE_ADDRESS")
EVENTS = Pair("comms", "events", "comms-redis", "velo", "COMMS_EVENTS_ADDRESS")


def _inspect(pair: Pair, code: int = 0, line: str = "") -> FakeCall:
    argv = (
        "docker", "network", "inspect", "--format",
        "{{.Internal}} {{json .Labels}}", "--", pair.network,
    )  # fmt: skip
    lines = ((Stream.STDOUT, line),) if line else ()
    return FakeCall(argv, code=code, lines=lines)


def _labels(pair: Pair, **other: str) -> str:
    return json.dumps(
        {
            "pridem.stack": pair.provider,
            "pridem.point": f"{pair.provider}/{pair.endpoint}",
            "pridem.consumer": pair.consumer,
            **other,
        }
    )


def _create(pair: Pair) -> FakeCall:
    return FakeCall(
        (
            "docker", "network", "create", "--internal",
            "--label", f"pridem.stack={pair.provider}",
            "--label", f"pridem.point={pair.provider}/{pair.endpoint}",
            "--label", f"pridem.consumer={pair.consumer}",
            "--", pair.network,
        )
    )  # fmt: skip


def test_every_pair_of_the_box_gets_its_network_the_consumer_of_the_product_too() -> (
    None
):
    """velo-dev: comms, a service, takes ``velo-storage``, an entry of the
    product -- and the product takes a point of comms. Both networks are made,
    one after the other, internal and labelled; read back."""
    first, second = sorted([EVENTS, STORAGE], key=lambda p: p.network)
    calls = [
        _inspect(first, 1),
        _inspect(second, 1),
        _create(first),
        _create(second),
        _inspect(first, 0, f"true {_labels(first)}"),
        _inspect(second, 0, f"true {_labels(second)}"),
    ]
    step = PairNetworks([STORAGE, EVENTS])
    with FakeRunner(*calls) as runner:
        ctx = context(runner)
        check = step.check(ctx)
        assert check.needed
        step.act(ctx, check)
        fact = step.verify(ctx, check).fact
    assert fact == {"networks": sorted([STORAGE.network, EVENTS.network])}


def test_a_network_made_with_its_labels_is_taken_as_it_is() -> None:
    """A box where compose made the network before this step (velo-test): the
    same labels, internal -- nothing to do."""
    with FakeRunner(_inspect(STORAGE, 0, f"true {_labels(STORAGE)}")) as runner:
        assert not PairNetworks([STORAGE]).check(context(runner)).needed


@pytest.mark.parametrize(
    ("line", "refused"),
    [
        (
            f"false {_labels(STORAGE)}",
            Code("not-internal", {"network": STORAGE.network}),
        ),
        (
            f"true {_labels(STORAGE, **{'pridem.consumer': 'other'})}",
            Code(
                "labels",
                {
                    "network": STORAGE.network,
                    "labels": {
                        "pridem.stack": "velo-storage",
                        "pridem.point": "velo-storage/files",
                        "pridem.consumer": "other",
                    },
                },
            ),
        ),
    ],
    ids=["not-internal", "other-labels"],
)
def test_a_network_of_that_name_that_is_not_the_pairs_is_red(
    line: str, refused: Code
) -> None:
    with FakeRunner(_inspect(STORAGE, 0, line)) as runner:
        with pytest.raises(StepFailed) as error:
            PairNetworks([STORAGE]).check(context(runner))
    assert error.value.reason == refused


def test_a_box_without_pairs_runs_nothing() -> None:
    with FakeRunner() as runner:
        step = PairNetworks([])
        ctx = context(runner)
        check = step.check(ctx)
        assert not check.needed
        assert step.verify(ctx, check).fact == {"networks": []}


def test_two_consumers_of_one_point_are_two_networks() -> None:
    """One point, two consumers: two pairs, two networks -- each its own."""
    other = Pair("velo-storage", "files", "storage", "payments", "STORE")
    assert other.network != STORAGE.network
    first, second = sorted([other, STORAGE], key=lambda p: p.network)
    calls = [
        _inspect(first, 1),
        _inspect(second, 1),
        _create(first),
        _create(second),
    ]
    step = PairNetworks([STORAGE, other])
    with FakeRunner(*calls) as runner:
        ctx = context(runner)
        step.act(ctx, step.check(ctx))
