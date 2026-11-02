"""Probe DM-55: the trust boundary of a stack's compose, before any build.

``forbidden`` reads what ``docker compose config --format json`` prints --
measured with compose v2.27.0: short and long volume forms come as ``{type,
source, target}`` with ``source`` absolute, anchors and ``extends`` resolved in
the service, a top-level ``x-`` key kept as it was, a port without a host part
as an entry without ``published``. The documents here are in that form; the
blank's is the measured output (``fixtures/compose/blank-config.json``, its
paths ``/r/...`` in the release). Since the FIX it is a list of what a stack
may use: every group of keys off the list has a red case, the keys on it a
green one; ``env_file`` is read from ``config --no-interpolate``.
"""

import json
import os
from pathlib import Path

import pytest
from compose_support import (
    APP_IMAGE,
    CONFIG,
    ENTRY,
    FRONT_IMAGE,
    REF,
    SHA,
    build_call,
    compose,
    config_call,
    image_call,
    in_release,
    raw_config_call,
    run,
)

from pridem.events import Code, Json
from pridem.report.codes import ExitCode
from pridem.runner import FakeRunner
from pridem.stacks.schema import PRIMER_YAML, Service
from pridem.steps.build import Build
from pridem.steps.compose import (
    BUILD_KEYS,
    SERVICE_KEYS,
    TOP_KEYS,
    TOP_NETWORK_KEYS,
    TOP_VOLUME_KEYS,
    VOLUME_KEYS,
    ComposeStack,
    env_files_out_of_release,
    forbidden,
)

BLANK = json.loads(
    (Path(__file__).parent / "fixtures" / "compose" / "blank-config.json").read_text()
)


def build(root: Path) -> Build:
    cs = compose(root)
    return Build(cs.stack, cs.entry, release=cs.release, ref=REF, commit=SHA, root=root)


def released(root: Path) -> ComposeStack:
    cs = compose(root)
    cs.release.mkdir(parents=True, exist_ok=True)
    return cs


def app(**body: Json) -> dict[str, Json]:
    """A compose document with one service ``app`` and ``postgres`` beside it."""
    return {
        "services": {
            "app": {"image": "app:1", **body},
            "postgres": {"image": "postgres:16"},
        }
    }


def comms(root: Path, ports: list[dict[str, object]]) -> ComposeStack:
    data = {
        "schema": 1,
        "name": "comms",
        "kind": "service",
        "stacks": {"comms": {"compose": "deploy/docker-compose.yml"}},
        "host": {"ports": ports},
        "report": {
            "health": "/health",
            "ready": "/ready",
            "logs": "json",
            "junit": True,
        },
    }
    stack = PRIMER_YAML.validate_python(data)
    assert isinstance(stack, Service)
    release = root / "comms-release"
    release.mkdir(parents=True, exist_ok=True)
    return ComposeStack(stack, "comms", release, "v1.0.0", SHA, root)


# --- probe ----------------------------------------------------------------------


def test_probe_DM_55_privileged_compose_is_red_before_build(tmp_path: Path) -> None:
    """A privileged service is red in ``check`` of ``build``: the strict
    scenario holds ``config`` alone -- nothing is built, no override written.
    The pair: the blank's compose, as ``config`` prints it, is clean and
    builds."""
    cs = released(tmp_path)
    document = in_release(BLANK, cs.release)
    planted = json.loads(json.dumps(document))
    planted["services"]["app"]["privileged"] = True
    with FakeRunner(raw_config_call(cs, planted), config_call(cs, planted)) as runner:
        outcome, _ = run([build(tmp_path)], runner)
    assert outcome.code is ExitCode.FAILED
    assert outcome.steps[0].reason == Code(
        "build:compose-forbidden", {"stack": ENTRY, "found": ["app: privileged"]}
    )
    assert not cs.override.exists()
    assert forbidden(cs, document) == []
    green = [
        raw_config_call(cs, BLANK),  # check: env_file
        config_call(cs, BLANK),  # check
        config_call(cs, BLANK),  # act
        build_call(cs),
        config_call(cs, BLANK),  # verify
        image_call(cs, "app", APP_IMAGE),
        image_call(cs, "frontend", FRONT_IMAGE),
    ]
    with FakeRunner(*green) as runner:
        outcome, _ = run([build(tmp_path)], runner)
    assert outcome.code is ExitCode.OK, outcome.steps


def test_doctor_names_a_forbidden_compose_too(tmp_path: Path) -> None:
    cs = released(tmp_path)
    document = app(cap_add=["NET_ADMIN"])
    calls = [raw_config_call(cs, document), config_call(cs, document)]
    with FakeRunner(*calls) as runner:
        outcome, _ = run([build(tmp_path)], runner, mode="doctor")
    [step] = outcome.steps
    assert step.reason == Code(
        "build:compose-forbidden", {"stack": ENTRY, "found": ["app: cap_add"]}
    )


# --- the list, key by key -------------------------------------------------------


def test_the_blank_uses_only_keys_of_the_list() -> None:
    """The keys ``config`` adds itself (``command``, ``entrypoint``, ``networks``;
    ``build.dockerfile``; ``volume: {}``) are on the lists: measured on the
    blank, whose every service, build and volume reads within them."""
    for name, body in BLANK["services"].items():
        assert set(body) <= SERVICE_KEYS, name
        assert set(body.get("build", {})) <= BUILD_KEYS, name
        for volume in body.get("volumes", []):
            assert set(volume) <= VOLUME_KEYS, name
    assert {"command", "entrypoint", "networks"} <= set(BLANK["services"]["app"])


def test_every_key_of_the_list_is_green(tmp_path: Path) -> None:
    cs = released(tmp_path)
    body: dict[str, Json] = {
        "image": "app:1",
        "build": {
            "context": str(cs.release),
            "dockerfile": "Dockerfile",
            "target": "runtime",
        },
        "environment": {"A": "1"},
        "volumes": [
            {"type": "volume", "source": "pgdata", "target": "/d", "volume": {}}
        ],
        "networks": {"default": None},
        "depends_on": {"postgres": {"condition": "service_healthy", "required": True}},
        "healthcheck": {"test": ["CMD", "true"]},
        "command": None,
        "entrypoint": None,
        "restart": "unless-stopped",
        "ports": [],
        "labels": {"a": "b"},
        "user": "1000",
        "working_dir": "/app",
    }
    assert set(body) == SERVICE_KEYS
    assert forbidden(cs, {"services": {"app": body}}) == []


SERVICE_OFF = [
    "privileged",
    "cap_add",
    "devices",
    "pid",
    "ipc",
    "uts",
    "network_mode",
    "userns_mode",
    "cgroup",
    "cgroup_parent",
    "security_opt",
    "volumes_from",
    "configs",
    "secrets",
    "tmpfs",
    "extra_hosts",
    "logging",
    "expose",
    "container_name",
    "sysctls",
    "ulimits",
    "init",
    "runtime",
    "platform",
]
BUILD_OFF = [
    "additional_contexts",
    "network",
    "entitlements",
    "ssh",
    "secrets",
    "extra_hosts",
    "privileged",
    "cache_from",
    "platforms",
    "tags",
]


@pytest.mark.parametrize("key", SERVICE_OFF)
def test_a_service_key_off_the_list_is_named(tmp_path: Path, key: str) -> None:
    assert forbidden(released(tmp_path), app(**{key: "x"})) == [f"app: {key}"]


@pytest.mark.parametrize("key", BUILD_OFF)
def test_a_build_key_off_the_list_is_named(tmp_path: Path, key: str) -> None:
    cs = released(tmp_path)
    build: dict[str, Json] = {"context": str(cs.release), "args": {"A": "1"}, key: "x"}
    assert forbidden(cs, app(build=build)) == [f"app: build.{key}"]


def test_a_volume_is_a_named_one_or_a_bind_with_nothing_more(tmp_path: Path) -> None:
    cs = released(tmp_path)
    inside = str(cs.release)
    cases: list[tuple[dict[str, Json], list[str]]] = [
        ({"type": "bind", "source": inside, "target": "/x", "read_only": True}, []),
        (
            {
                "type": "bind",
                "source": inside,
                "target": "/x",
                "bind": {"create_host_path": True},
            },
            [],
        ),
        ({"type": "tmpfs", "target": "/x"}, ["app: volumes type=tmpfs"]),
        (
            {"type": "image", "source": "img:1", "target": "/x"},
            ["app: volumes type=image"],
        ),
        (
            {
                "type": "bind",
                "source": inside,
                "target": "/x",
                "bind": {"propagation": "rshared"},
            },
            ["app: volumes.bind.propagation"],
        ),
        (
            {"type": "volume", "source": "v", "target": "/x", "consistency": "cached"},
            ["app: volumes.consistency"],
        ),
    ]
    for volume, found in cases:
        assert forbidden(cs, app(volumes=[volume])) == found, volume


def _bind(source: str | Path) -> dict[str, Json]:
    return {"type": "bind", "source": str(source), "target": "/x"}


def test_binds_stay_in_the_release(tmp_path: Path) -> None:
    cs = released(tmp_path)
    release = cs.release
    (release / "data").mkdir()
    (tmp_path / "outside").mkdir()
    os.symlink("/etc", release / "to-etc")
    os.symlink("/var/run/docker.sock", release / "sock")
    cases: list[tuple[dict[str, Json], list[str]]] = [
        (_bind(release / "data"), []),
        (_bind(release), []),
        ({"type": "volume", "source": "pgdata", "target": "/x"}, []),
        (_bind("/etc"), ["app: volumes=/etc"]),
        (_bind(tmp_path / "outside"), [f"app: volumes={tmp_path / 'outside'}"]),
        (_bind(release / "to-etc"), [f"app: volumes={release / 'to-etc'}"]),
        (_bind("/var/run/docker.sock"), ["app: volumes=docker.sock"]),
        (_bind("/run/docker.sock"), ["app: volumes=docker.sock"]),
        (_bind(release / "sock"), ["app: volumes=docker.sock"]),
    ]
    for volume, found in cases:
        assert forbidden(cs, app(volumes=[volume])) == found, volume


def test_a_build_reads_only_the_release(tmp_path: Path) -> None:
    cs = released(tmp_path)
    inside = str(cs.release / "backend")
    cases: list[tuple[dict[str, Json], list[str]]] = [
        ({"context": inside, "dockerfile": "Dockerfile"}, []),
        ({"context": inside}, []),
        ({"context": "/", "dockerfile": "Dockerfile"}, ["app: build.context=/"]),
        (
            {"context": inside, "dockerfile": "/etc/Dockerfile"},
            ["app: build.dockerfile=/etc/Dockerfile"],
        ),
        (
            {"context": inside, "dockerfile": "../../x"},
            ["app: build.dockerfile=../../x"],
        ),
    ]
    for given, found in cases:
        assert forbidden(cs, app(build=given)) == found, given


def test_a_product_publishes_no_port_of_the_host(tmp_path: Path) -> None:
    cs = released(tmp_path)
    published: dict[str, Json] = {
        "mode": "ingress",
        "target": 80,
        "published": "8080",
        "protocol": "tcp",
    }
    random: dict[str, Json] = {"mode": "ingress", "target": 5000, "protocol": "tcp"}
    local: dict[str, Json] = {**published, "host_ip": "127.0.0.1", "published": "9000"}
    assert forbidden(cs, app(ports=[published])) == ["app: ports=8080/tcp"]
    assert forbidden(cs, app(ports=[random])) == [
        "app: ports=5000/tcp on a random port"
    ]
    assert forbidden(cs, app(ports=[local])) == ["app: ports=9000/tcp"]


def test_a_service_publishes_only_what_host_ports_declares(tmp_path: Path) -> None:
    cs = comms(tmp_path, [{"proto": "udp", "port": 10000}])
    udp: dict[str, Json] = {
        "mode": "ingress",
        "target": 10000,
        "published": "10000",
        "protocol": "udp",
    }
    tcp: dict[str, Json] = {**udp, "protocol": "tcp"}
    other: dict[str, Json] = {**udp, "published": "10001", "target": 10001}
    assert forbidden(cs, app(ports=[udp])) == []
    assert forbidden(cs, app(ports=[tcp])) == ["app: ports=10000/tcp"]
    assert forbidden(cs, app(ports=[other])) == ["app: ports=10001/udp"]
    assert forbidden(comms(tmp_path / "none", []), app(ports=[udp])) == [
        "app: ports=10000/udp"
    ]


# --- the top level, as a list too (FIX 2) ---------------------------------------


def _top(**top: Json) -> dict[str, Json]:
    """``app()`` with these top-level keys beside its ``services``."""
    return {**app(), **top}


def test_every_top_level_key_of_the_list_is_green(tmp_path: Path) -> None:
    """What ``config`` prints for the live forms -- the blank's ``pgdata: {}``
    and its ``default`` network -- and every key of the three lists in the form
    it may have is green."""
    cs = released(tmp_path)
    inside = str(cs.release / "data")
    volume: dict[str, Json] = {
        "name": "blank_files",
        "driver": "local",
        "driver_opts": {"type": "none", "o": "bind", "device": inside},
    }
    network: dict[str, Json] = {"name": "blank_lan", "driver": "bridge", "ipam": {}}
    document = _top(
        name="blank",
        volumes={"files": volume, "pgdata": {"name": "blank_pgdata"}},
        networks={"lan": network, "default": {"name": "blank_default", "ipam": {}}},
    )
    assert set(document) == TOP_KEYS
    assert set(volume) == TOP_VOLUME_KEYS and set(network) == TOP_NETWORK_KEYS
    assert forbidden(cs, document) == []


@pytest.mark.parametrize("form", ["blank", "harness"])
def test_the_live_forms_are_green(tmp_path: Path, form: str) -> None:
    """The blank's ``config`` (``pgdata: {}`` -> ``blank_pgdata``, the
    ``default`` network with ``ipam: {}``) and the harness's ``CONFIG``
    (``default`` without ``ipam``) are green: their names are the ones
    ``config`` gives under the project ``blank``, so a wrong formula of the
    name turns both red, not only a foreign name."""
    cs = released(tmp_path)
    document = BLANK if form == "blank" else CONFIG
    assert forbidden(cs, in_release(document, cs.release)) == []


@pytest.mark.parametrize("key", ["configs", "secrets", "models", "include"])
def test_a_top_level_key_off_the_list_is_named(tmp_path: Path, key: str) -> None:
    """``x-`` keys are not read; every other key off the list is named --
    ``configs``/``secrets`` a second time, beside the service's own key, and a
    section a later ``config`` may print is stopped by the list."""
    cs = released(tmp_path)
    extra: dict[str, Json] = {
        key: {"c": {"file": str(cs.release)}},
        "x-anchor": {"a": 1},
    }
    document = _top(**extra)
    assert forbidden(cs, document) == [f"compose: {key}"]


@pytest.mark.parametrize(
    ("key", "value"),
    [("external", True), ("labels", {"pridem.stack": "other"}), ("driver_opts_x", 1)],
)
def test_a_top_level_volume_key_off_the_list_is_named(
    tmp_path: Path, key: str, value: Json
) -> None:
    cs = released(tmp_path)
    document = _top(volumes={"pgdata": {"name": "blank_pgdata", key: value}})
    assert forbidden(cs, document) == [f"volumes.pgdata: {key}"]


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("external", True),
        ("labels", {"a": "b"}),
        ("driver_opts", {"parent": "eth0"}),
        ("internal", True),
        ("attachable", True),
        ("enable_ipv6", True),
    ],
)
def test_a_top_level_network_key_off_the_list_is_named(
    tmp_path: Path, key: str, value: Json
) -> None:
    """``driver_opts`` of a network is off the list with or without a
    ``driver`` -- ``config`` keeps it either way."""
    cs = released(tmp_path)
    network: dict[str, Json] = {"name": "blank_lan", "ipam": {}, key: value}
    assert forbidden(cs, _top(networks={"lan": network})) == [f"networks.lan: {key}"]


def test_a_volume_driver_and_its_options_are_the_local_bind_of_the_release(
    tmp_path: Path,
) -> None:
    """``driver`` is none or ``local``; ``driver_opts`` exactly ``{type: none,
    o: bind, device}`` with the device in the release -- any other form is one
    finding with its reason. With the name and the external tests it replaces
    ``test_what_comes_from_the_top_level_is_the_stacks_own``: until FIX 2 the
    top level caught ``external`` and a device out of the release alone, so a
    plugin driver, an nfs or cifs mount and a device of the release under
    another type passed."""
    cs = released(tmp_path)
    inside, outside = str(cs.release / "data"), "/"
    opts = "driver_opts (not the options of a bind)"
    cases: list[tuple[dict[str, Json], list[str]]] = [
        ({}, []),
        ({"driver": "local"}, []),
        ({"driver": "some/plugin"}, ["driver=some/plugin"]),
        ({"driver_opts": {"type": "none", "o": "bind", "device": inside}}, []),
        (
            {"driver_opts": {"type": "none", "o": "bind", "device": outside}},
            [f"driver_opts (device={outside} not in the release)"],
        ),
        ({"driver": "local", "driver_opts": {"type": "nfs", "device": inside}}, [opts]),
        (
            {"driver_opts": {"type": "nfs", "o": "addr=10.0.0.1", "device": ":/x"}},
            [opts],
        ),
        (
            {"driver_opts": {"type": "cifs", "o": "username=u", "device": "//h/s"}},
            [opts],
        ),
        ({"driver_opts": {"type": "tmpfs", "device": "tmpfs"}}, [opts]),
        ({"driver_opts": {"type": "ext4", "device": inside}}, [opts]),
        ({"driver_opts": {"type": "none", "o": "rbind", "device": inside}}, [opts]),
        ({"driver_opts": {"type": "ext4", "o": "bind", "device": inside}}, [opts]),
        (
            {"driver_opts": {"type": "none", "o": "bind", "device": inside, "x": "1"}},
            [opts],
        ),
        ({"driver_opts": {}}, [opts]),
    ]
    for body, found in cases:
        document = _top(volumes={"data": {"name": "blank_data", **body}})
        assert forbidden(cs, document) == [f"volumes.data: {f}" for f in found], body


@pytest.mark.parametrize(
    ("body", "found"),
    [
        ({}, []),
        ({"driver": "bridge"}, []),
        ({"driver": "macvlan"}, ["driver=macvlan"]),
        ({"driver": "ipvlan"}, ["driver=ipvlan"]),
        ({"driver": "overlay"}, ["driver=overlay"]),
        ({"driver": "host"}, ["driver=host"]),
        ({"driver": "none"}, ["driver=none"]),
        ({"ipam": {}}, []),
        (
            {"ipam": {"driver": "default", "config": [{"subnet": "172.30.0.0/16"}]}},
            ["ipam"],
        ),
        ({"ipam": {"driver": "default"}}, ["ipam"]),
    ],
)
def test_a_network_driver_is_bridge_and_ipam_is_what_config_prints(
    tmp_path: Path, body: dict[str, Json], found: list[str]
) -> None:
    cs = released(tmp_path)
    document = _top(networks={"lan": {"name": "blank_lan", **body}})
    assert forbidden(cs, document) == [f"networks.lan: {f}" for f in found]


def test_a_name_is_the_one_config_gives_under_the_machines_project(
    tmp_path: Path,
) -> None:
    """``config`` names a volume or a network ``<project>_<key>`` itself, the
    project being the machine's ``-p`` (the stack's entry); another name takes
    another stack's object past ``-p`` and the labels gc goes by. An external
    object is named twice -- it is external, and its name is not its own."""
    cs = released(tmp_path)
    assert cs.project == ENTRY == "blank"
    document = _top(
        volumes={
            "own": {"name": "blank_own"},
            "data": {"name": "velo_data"},
            "theirs": {"name": "someone_else", "external": True},
        },
        networks={"default": {"name": "blank_default"}, "lan": {"name": "pridem"}},
    )
    assert forbidden(cs, document) == [
        "networks.lan: name=pridem",
        "volumes.data: name=velo_data",
        "volumes.theirs: external",
        "volumes.theirs: name=someone_else",
    ]


def test_the_dispatchers_macvlan_and_plugin_document_is_red(tmp_path: Path) -> None:
    """The hole of the top level as the dispatcher found it on ``cbf011d``: a
    ``macvlan`` network puts the container on the host's network past nginx
    and ``host.ports``, a volume of another driver passed -- ``[]`` then."""
    service: dict[str, Json] = {
        "image": "app:1",
        "networks": {"lan": None},
        "volumes": [
            {"type": "volume", "source": "remote", "target": "/d", "volume": {}}
        ],
    }
    document: dict[str, Json] = {
        "services": {"app": service},
        "networks": {"lan": {"driver": "macvlan", "driver_opts": {"parent": "eth0"}}},
        "volumes": {"remote": {"driver": "some/plugin"}},
    }
    assert forbidden(released(tmp_path), document) == [
        "networks.lan: driver=macvlan",
        "networks.lan: driver_opts",
        "volumes.remote: driver=some/plugin",
    ]


def test_an_env_file_is_read_from_the_release_only(tmp_path: Path) -> None:
    """``config`` inlines ``env_file``; ``config --no-interpolate`` still names
    it, absolute and with ``extends`` resolved (measured): a path out of the
    release, or one that still holds a variable, is named."""
    cs = released(tmp_path)
    inside = str(cs.release / "app.env")
    uninterpolated: dict[str, Json] = {
        "services": {
            "app": {"env_file": [{"path": inside, "required": True}]},
            "ext": {"env_file": [{"path": "/etc/environment", "required": True}]},
            "var": {"env_file": [{"path": f"{cs.release}/${{WHERE}}.env"}]},
            "postgres": {"image": "postgres:16"},
        }
    }
    assert env_files_out_of_release(cs, uninterpolated) == [
        "ext: env_file=/etc/environment",
        f"var: env_file={cs.release}/${{WHERE}}.env",
    ]
    assert env_files_out_of_release(cs, {"services": {"app": {"image": "a"}}}) == []


def test_build_names_an_env_file_out_of_the_release_before_anything(
    tmp_path: Path,
) -> None:
    cs = released(tmp_path)
    raw = json.loads(json.dumps(BLANK))
    raw["services"]["app"]["env_file"] = [{"path": "/root/.env", "required": True}]
    with FakeRunner(raw_config_call(cs, raw), config_call(cs, BLANK)) as runner:
        outcome, _ = run([build(tmp_path)], runner)
    assert outcome.steps[0].reason == Code(
        "build:compose-forbidden",
        {"stack": ENTRY, "found": ["app: env_file=/root/.env"]},
    )
    assert not cs.override.exists()


def test_a_package_goes_into_a_service_the_compose_has(tmp_path: Path) -> None:
    cs = released(tmp_path)
    assert forbidden(cs, app(), [("skin", "app")]) == []
    assert forbidden(cs, app(), [("skin", "frontend")]) == [
        "frontend: packages.skin.mount (no such service)"
    ]


def test_only_services_are_read_and_every_finding_is_named(tmp_path: Path) -> None:
    """A top-level ``x-`` key stays in the output of ``config`` (its anchor is
    already resolved in the service that used it): it is not a service. Two
    findings are two entries, sorted, across services."""
    cs = released(tmp_path)
    document = app(privileged=True, pid="host")
    document["x-common"] = {"privileged": True, "network_mode": "host"}
    services = document["services"]
    assert isinstance(services, dict)
    services["postgres"] = {"image": "postgres:16", "cap_add": ["SYS_PTRACE"]}
    assert forbidden(cs, document) == [
        "app: pid",
        "app: privileged",
        "postgres: cap_add",
    ]
    assert forbidden(cs, {"x-common": {"privileged": True}}) == []
