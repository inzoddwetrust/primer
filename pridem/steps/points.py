"""``pair_networks``: the networks of the pairs of the box, made before any
stack (DM-23, velo-dev 19.11).

A pair is a point and one stack that takes its address (protocol 4.4, DM-62):
its network joins the point's service and the consumer's services, nobody
else. It used to be made by compose on the provider's first command -- its
``up`` -- and a consumer that runs before its provider found none: comms, a
service, takes ``velo-storage``, an entry of the product, and the services'
ladders run first; comms' ``migrate`` (``compose run``) refused the external
network. So the machine makes every network of the box's pairs in one step,
after the sources are read and before the first stack: internal, labelled
``pridem.stack`` (the provider), ``pridem.point`` (``<provider>/<endpoint>``)
and ``pridem.consumer`` -- the labels ``up`` of the provider reads to take the
networks of pairs no more. Both sides declare it ``external`` in their
override (``steps.compose._pair_networks``).

``check`` inspects each: none -- ``create``; one that is not internal, or with
other labels -- red, never taken over. A network compose made on a box before
this step carries the same labels from the override of then, and is taken as
it is.
"""

import json
from collections.abc import Sequence
from typing import ClassVar

from pridem.events import Json, strings
from pridem.stacks.seams import Pair
from pridem.steps.base import (
    CheckResult,
    Mode,
    Step,
    StepContext,
    StepFailed,
    Verified,
    local_code,
)
from pridem.steps.compose import COMMAND_TIMEOUT_S, out

ALL_MODES: frozenset[Mode] = frozenset({"install", "deploy", "reinstall"})
INSPECT = "{{.Internal}} {{json .Labels}}"


def pair_labels(pair: Pair) -> dict[str, str]:
    """The labels of a pair's network: who provides, which point, who takes."""
    return {
        "pridem.stack": pair.provider,
        "pridem.point": f"{pair.provider}/{pair.endpoint}",
        "pridem.consumer": pair.consumer,
    }


class PairNetworks(Step):
    """Every network of the box's pairs, internal and labelled, before any
    stack."""

    name = "pair_networks"
    title = "Create the networks of the points"
    order = 1
    modes = ALL_MODES
    codes: ClassVar[dict[str, str]] = {
        "create": "create the networks of the points {networks}",
        "not-internal": "the network of a point {network} is not internal",
        "labels": "the network of a point {network} has other labels: {labels}",
        "missing": "the network of a point {network} is missing",
    }

    def __init__(self, pairs: Sequence[Pair]) -> None:
        by_name: dict[str, Pair] = {}
        for pair in pairs:
            by_name.setdefault(pair.network, pair)
        self.pairs = [by_name[name] for name in sorted(by_name)]

    def _seen(self, ctx: StepContext, pair: Pair) -> bool:
        """The pair's network is there, internal, with its labels; ``False``
        -- there is none. Another network of that name is red."""
        code, lines = out(
            ctx,
            ["docker", "network", "inspect", "--format", INSPECT, "--", pair.network],
            expect=(0, 1),
            timeout=COMMAND_TIMEOUT_S,
        )
        if code != 0:
            return False
        internal, _, given = " ".join(lines).partition(" ")
        if internal != "true":
            raise StepFailed("not-internal", {"network": pair.network})
        found = json.loads(given) if given.strip() else {}
        labels = found if isinstance(found, dict) else {}
        wanted = pair_labels(pair)
        if any(labels.get(key) != value for key, value in wanted.items()):
            shown: dict[str, Json] = {key: labels.get(key) for key in wanted}
            raise StepFailed("labels", {"network": pair.network, "labels": shown})
        return True

    def check(self, ctx: StepContext) -> CheckResult:
        missing = [pair.network for pair in self.pairs if not self._seen(ctx, pair)]
        if not missing:
            return CheckResult(False)
        networks = list[Json](missing)
        return CheckResult(
            True,
            local_code("create", {"networks": networks}),
            {"missing": networks},
        )

    def act(self, ctx: StepContext, check: CheckResult) -> None:
        missing = set(strings(check.data.get("missing")))
        for pair in self.pairs:
            if pair.network not in missing:
                continue
            labels = [
                word
                for key, value in pair_labels(pair).items()
                for word in ("--label", f"{key}={value}")
            ]
            out(
                ctx,
                [
                    "docker",
                    "network",
                    "create",
                    "--internal",
                    *labels,
                    "--",
                    pair.network,
                ],
                timeout=COMMAND_TIMEOUT_S,
            )

    def verify(self, ctx: StepContext, check: CheckResult) -> Verified:
        for pair in self.pairs:
            if not self._seen(ctx, pair):
                raise StepFailed("missing", {"network": pair.network})
        return Verified({"networks": [pair.network for pair in self.pairs]})
