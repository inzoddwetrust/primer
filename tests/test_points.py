"""Points (DM-62; protocol 4.4, contract 3 rule 22): a stack exposes a point,
a consumer takes its address ``<alias>:<port>``, and the machine joins the
pair on a network of its own -- not on ``pridem``, so a stack that did not
declare the point does not reach it."""

import json
from pathlib import Path

import pytest
from compose_support import stdout
from contract_support import yaml_problems
from passport_support import passport_example

from pridem.events import Json
from pridem.runner import FakeCall, FakeRunner
from pridem.stacks.env import point_address
from pridem.stacks.passport import PASSPORT
from pridem.stacks.schema import PRIMER_YAML, Product, Service
from pridem.stacks.seams import Pair, network_collisions, pairs, product_value
from pridem.steps.compose import NETWORK, ComposeStack, override_text
from pridem.steps.up import INSPECT_FORMAT, Up

REPORT = {"health": "/health", "ready": "/ready", "logs": "json", "junit": True}
APP = {"service": "app", "port": 8000, "health": "/health", "ready": "/ready"}
SHA = "0" * 40


def comms_data(**change: object) -> dict[str, object]:
    data: dict[str, object] = {
        "schema": 1,
        "name": "comms",
        "kind": "service",
        "stacks": {
            "comms": {
                "compose": "c.yml",
                "app": {**APP, "service": "comms-app"},
                "expose": {
                    "events": {
                        "service": "comms-redis",
                        "port": 6379,
                        "scheme": "redis",
                    }
                },
            }
        },
        "env": {
            "COMMS_EVENTS_ADDRESS": {"source": "address", "endpoint": "events"},
            "STORAGE": {"source": "seam", "from": "product"},
        },
        "provides": ["COMMS_EVENTS_ADDRESS"],
        "requires": ["STORAGE"],
        "report": REPORT,
    }
    data.update(change)
    return data


def velo_data(**change: object) -> dict[str, object]:
    data: dict[str, object] = {
        "schema": 1,
        "name": "velo",
        "kind": "product",
        "dependencies": {"comms": {"repo": "git@h:a/comms.git", "version": ">=1,<2"}},
        "stacks": {
            "velo": {"compose": "v.yml", "app": APP},
            "velo-storage": {
                "compose": "s.yml",
                "expose": {
                    "files": {"service": "store", "port": 9000, "scheme": "http"}
                },
            },
        },
        "env": {
            "COMMS_EVENTS_ADDRESS": {"source": "seam", "from": "comms"},
            "STORAGE_ADDRESS": {
                "source": "address",
                "stack": "velo-storage",
                "endpoint": "files",
            },
        },
        "provides": {"STORAGE": {"stack": "velo-storage", "endpoint": "files"}},
        "report": REPORT,
    }
    data.update(change)
    return data


def _load(data: dict[str, object]) -> Product | Service:
    return PRIMER_YAML.validate_python(data)


def _velo() -> Product:
    made = _load(velo_data())
    assert isinstance(made, Product)
    return made


def _comms() -> Service:
    made = _load(comms_data())
    assert isinstance(made, Service)
    return made


# --- the loader -------------------------------------------------------------------


def test_the_forms_of_a_point_load(tmp_path: Path) -> None:
    assert yaml_problems(tmp_path, velo_data()) == []
    assert yaml_problems(tmp_path, comms_data()) == []


@pytest.mark.parametrize("where", ["app", "route"])
def test_a_point_on_pridem_is_refused(tmp_path: Path, where: str) -> None:
    """``app`` and a service a route goes to are on ``pridem``: anyone reaches
    them -- a point there would be no point."""
    data = velo_data()
    stacks = data["stacks"]
    assert isinstance(stacks, dict)
    if where == "app":
        stacks["velo"] = {
            **stacks["velo"],
            "expose": {"x": {"service": "app", "port": 1, "scheme": "tcp"}},
        }
    else:
        data["host"] = {"domains": ["api"], "routes": {"api": {"to": "store:9000"}}}
    found = yaml_problems(tmp_path, data)
    assert any(code == "S.expose-app" for _, code in found), found


@pytest.mark.parametrize(
    "change",
    ["endpoint", "stack", "provides", "service-stack"],
)
def test_an_address_of_a_point_nobody_exposes_is_refused(
    tmp_path: Path, change: str
) -> None:
    if change == "service-stack":
        env = {"X": {"source": "address", "stack": "comms", "endpoint": "events"}}
        found = yaml_problems(tmp_path, comms_data(env=env, provides=[], requires=[]))
    else:
        data = velo_data()
        if change == "endpoint":
            data["env"] = {
                "A": {"source": "address", "stack": "velo-storage", "endpoint": "none"}
            }
        elif change == "stack":
            data["env"] = {
                "A": {"source": "address", "stack": "nowhere", "endpoint": "files"}
            }
        else:
            data["provides"] = {
                "STORAGE": {"stack": "velo-storage", "endpoint": "none"}
            }
        found = yaml_problems(tmp_path, data)
    assert any(code == "S.endpoint-unknown" for _, code in found), found


def test_a_point_s_alias_is_one_of_the_product_s_aliases(tmp_path: Path) -> None:
    """``a`` + ``b-c`` (a point) and ``a-b`` + ``c`` (an app): one name."""
    data = velo_data(name="a")
    data["stacks"] = {
        "a": {
            "compose": "a.yml",
            "app": APP,
            "expose": {"p": {"service": "b-c", "port": 1, "scheme": "tcp"}},
        },
        "a-b": {"compose": "b.yml", "app": {**APP, "service": "c"}},
    }
    data["env"], data["provides"] = {}, {}
    found = yaml_problems(tmp_path, data)
    assert any(code == "S.alias-collision" for _, code in found), found


# --- values and pairs -------------------------------------------------------------


def test_the_address_of_a_point_is_alias_and_port_without_a_scheme() -> None:
    velo, comms = _velo(), _comms()
    assert point_address(comms, "comms", "events") == "comms-comms-redis:6379"
    assert point_address(velo, "velo-storage", "files") == "velo-storage-store:9000"
    passport = PASSPORT.validate_python(passport_example())
    assert product_value(velo, passport, "STORAGE") == "velo-storage-store:9000"


def _pairs(on: frozenset[str] = frozenset()) -> list[Pair]:
    return pairs(_velo(), {"comms": _comms()}, None, on=on)


def test_the_pairs_of_the_box() -> None:
    """The product from comms, the app from its own store, comms from the
    product's store."""
    found = {(p.provider, p.endpoint, p.consumer, p.variable) for p in _pairs()}
    assert found == {
        ("comms", "events", "velo", "COMMS_EVENTS_ADDRESS"),
        ("velo-storage", "files", "velo", "STORAGE_ADDRESS"),
        ("velo-storage", "files", "comms", "STORAGE"),
    }


def test_a_point_has_one_alias_in_all_its_pairs() -> None:
    """Protocol 4.4: the product signs a link with the store's name, comms
    reaches the store by that very name."""
    store = [p for p in _pairs() if p.provider == "velo-storage"]
    assert len(store) == 2 and {p.alias for p in store} == {"velo-storage-store"}
    assert len({p.network for p in store}) == 2  # a network per pair


def test_a_variable_of_an_option_off_makes_no_pair() -> None:
    data = velo_data(options=["files"])
    env = data["env"]
    assert isinstance(env, dict)
    env["STORAGE_ADDRESS"] = {**env["STORAGE_ADDRESS"], "when": "files"}
    made = _load(data)
    assert isinstance(made, Product)
    off = pairs(made, {"comms": _comms()}, None, on=frozenset())
    assert "STORAGE_ADDRESS" not in {p.variable for p in off}
    on = pairs(made, {"comms": _comms()}, None, on=frozenset({"files"}))
    assert "STORAGE_ADDRESS" in {p.variable for p in on}


def test_two_pairs_with_one_network_name_are_found() -> None:
    class Same(Pair):
        @property
        def network(self) -> str:
            return "pridem-pt-00000000"

    one, two = Same("a", "p", "s", "x", "V"), Same("b", "p", "s", "x", "V")
    assert network_collisions([one, two]) == ["pridem-pt-00000000"]
    assert network_collisions([one, one]) == []


# --- the override: the probe --------------------------------------------------


def _compose(stack: Product | Service, entry: str, root: Path) -> ComposeStack:
    return ComposeStack(stack, entry, root / "release", "main", SHA, root)


def _override(
    cs: ComposeStack, services: dict[str, Json], points: list[Pair]
) -> dict[str, Json]:
    document: dict[str, Json] = {"services": services, "networks": {"default": {}}}
    loaded = json.loads(override_text(cs, document, proxy=False, points=points))
    assert isinstance(loaded, dict)
    return loaded


def _part(document: Json, *keys: str) -> dict[str, Json]:
    """``document[k1][k2]…`` as a mapping; a missing key -- empty."""
    for key in keys:
        assert isinstance(document, dict)
        document = document.get(key, {})
    assert isinstance(document, dict)
    return document


def test_probe_DM_62_only_the_declared_consumer_reaches_an_exposed_point(
    tmp_path: Path,
) -> None:
    """The point's service is on its pair's network under the one alias, not
    on ``pridem``; of the consumer, the service whose environment names the
    variable joins that network, the others do not; a stack that declared
    nothing has no service on it. The pair: the consumer's ``.env`` value is
    the point's address."""
    found = _pairs()
    comms_pair = next(p for p in found if p.provider == "comms")
    provider = _override(
        _compose(_comms(), "comms", tmp_path),
        {"comms-app": {"image": "x"}, "comms-redis": {"image": "r"}},
        found,
    )
    key = comms_pair.network.removeprefix("pridem-")
    redis = _part(provider, "services", "comms-redis", "networks")
    assert redis[key] == {"aliases": ["comms-comms-redis"]}
    assert NETWORK not in redis
    declared = _part(provider, "networks", key)
    assert declared["name"] == comms_pair.network and declared["internal"] is True
    assert _part(declared, "labels")["pridem.point"] == "comms/events"
    consumer = _override(
        _compose(_velo(), "velo", tmp_path),
        {
            "app": {
                "image": "x",
                "environment": {"E": "redis://${COMMS_EVENTS_ADDRESS:?}"},
            },
            "worker": {
                "image": "x",
                "environment": {"O": "${COMMS_EVENTS_ADDRESS_X:?}"},
            },
        },
        found,
    )
    assert key in _part(consumer, "services", "app", "networks")
    assert key not in _part(consumer, "services", "worker", "networks")
    external = {"name": comms_pair.network, "external": True}
    assert _part(consumer, "networks", key) == external
    bystander = _override(
        _compose(_velo(), "velo", tmp_path), {"app": {"image": "x"}}, []
    )
    assert not any(name.startswith("pt-") for name in _part(bystander, "networks"))
    # the pair: what the consumer is given is the point's address
    assert point_address(_comms(), "comms", "events") == "comms-comms-redis:6379"


# --- up of the provider takes its networks no more -------------------------------


def _up(tmp: Path, points: list[Pair]) -> Up:
    return Up(
        _comms(),
        "comms",
        release=tmp / "r",
        ref="v1",
        commit=SHA,
        root=tmp,
        points=points,
    )


LS = (
    "docker", "network", "ls", "--filter", "label=pridem.stack=comms",
    "--filter", "label=pridem.point", "--format", "{{.Name}}",
)  # fmt: skip


def test_a_network_of_a_pair_no_more_is_found_and_taken(tmp_path: Path) -> None:
    """A network of the provider's that is no pair of now and has no
    container: found by check, removed by act, read back by verify. The
    pair: one still holding a container stays -- its consumer leaves in this
    very run; a network of the current pair stays."""
    from env_support import context

    current = [p for p in _pairs() if p.provider == "comms"]
    now = current[0].network
    step = _up(tmp_path, current)
    calls = [
        FakeCall(
            LS,
            lines=stdout("pridem-pt-dead0000", "pridem-pt-held0000", now),
        ),
        FakeCall(
            (
                "docker",
                "network",
                "inspect",
                "--format",
                INSPECT_FORMAT,
                "pridem-pt-dead0000",
                "pridem-pt-held0000",
            ),
            lines=stdout("pridem-pt-dead0000 0", "pridem-pt-held0000 1"),
        ),
    ]
    with FakeRunner(*calls) as runner:
        assert step._gone_pairs(context(runner)) == ["pridem-pt-dead0000"]


def test_an_entry_without_points_looks_for_no_network(tmp_path: Path) -> None:
    data = comms_data()
    stacks = data["stacks"]
    assert isinstance(stacks, dict)
    stacks["comms"] = {k: v for k, v in stacks["comms"].items() if k != "expose"}
    data["env"] = {}
    data["provides"], data["requires"] = [], []
    made = _load(data)
    from env_support import context

    step = Up(
        made, "comms", release=tmp_path / "r", ref="v1", commit=SHA, root=tmp_path
    )
    with FakeRunner() as runner:  # no command at all
        assert step._gone_pairs(context(runner)) == []


def test_up_of_the_provider_finds_takes_and_reads_back(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The stack runs as it should, a network of a pair no more is there:
    ``check`` names it (``doctor`` sees it), ``act`` takes exactly it -- no
    ``compose up`` --, ``verify`` reads it back gone and counts it."""
    from env_support import context

    from pridem.steps.base import CheckResult

    step = _up(tmp_path, [])
    monkeypatch.setattr(step, "_check", lambda ctx, needed: CheckResult(False))
    monkeypatch.setattr(step, "_gone_pairs", lambda ctx: ["pridem-pt-dead0000"])
    with FakeRunner() as runner:
        found = step.check(context(runner))
    assert found.needed and found.would is not None
    assert found.would.code == "pair-networks"
    assert found.data == {"gone": ["pridem-pt-dead0000"], "up": False}
    with FakeRunner(
        FakeCall(("docker", "network", "rm", "pridem-pt-dead0000"))
    ) as runner:
        step.act(context(runner), found)
    monkeypatch.setattr(step, "_gone_pairs", lambda ctx: [])
    with FakeRunner() as runner:
        assert step._taken(context(runner), found) == {"pair_networks_removed": 1}
    monkeypatch.setattr(step, "_gone_pairs", lambda ctx: ["pridem-pt-dead0000"])
    with FakeRunner() as runner, pytest.raises(Exception, match="pair-networks-left"):
        step._taken(context(runner), found)
