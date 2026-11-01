"""Probe DM-55: the trust boundary of a stack's compose, before any build.

``forbidden`` reads what ``docker compose config --format json`` prints --
measured with compose v2.27.0: short and long volume forms come as ``{type,
source, target}`` with ``source`` absolute, anchors and ``extends`` resolved in
the service, a top-level ``x-`` key kept as it was, a port without a host part
as an entry without ``published``. The documents here are in that form; the
blank's is the measured output (``fixtures/compose/blank-config.json``, its
paths ``/r/...`` in the release). Every key of the list has a red case and a
green form of the same key next to it.
"""

import json
import os
from pathlib import Path

import pytest
from compose_support import (
    APP_IMAGE,
    ENTRY,
    FRONT_IMAGE,
    REF,
    SHA,
    build_call,
    compose,
    config_call,
    image_call,
    in_release,
    run,
)

from pridem.events import Code, Json
from pridem.report.codes import ExitCode
from pridem.runner import FakeRunner
from pridem.stacks.schema import PRIMER_YAML, Service
from pridem.steps.build import Build
from pridem.steps.compose import ComposeStack, forbidden

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
    with FakeRunner(config_call(cs, planted)) as runner:
        outcome, _ = run([build(tmp_path)], runner)
    assert outcome.code is ExitCode.FAILED
    assert outcome.steps[0].reason == Code(
        "build:compose-forbidden", {"stack": ENTRY, "found": ["app: privileged"]}
    )
    assert not cs.override.exists()
    assert forbidden(cs, document) == []
    green = [
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
    with FakeRunner(config_call(cs, app(cap_add=["NET_ADMIN"]))) as runner:
        outcome, _ = run([build(tmp_path)], runner, mode="doctor")
    [step] = outcome.steps
    assert step.reason == Code(
        "build:compose-forbidden", {"stack": ENTRY, "found": ["app: cap_add=NET_ADMIN"]}
    )


# --- the list, key by key -------------------------------------------------------


@pytest.mark.parametrize(
    ("body", "found"),
    [
        ({"privileged": True}, ["app: privileged"]),
        ({"privileged": False}, []),
        (
            {"cap_add": ["SYS_ADMIN", "NET_RAW"]},
            ["app: cap_add=NET_RAW", "app: cap_add=SYS_ADMIN"],
        ),
        ({"cap_drop": ["ALL"]}, []),
        ({"devices": ["/dev/fuse:/dev/fuse"]}, ["app: devices=/dev/fuse:/dev/fuse"]),
        ({"pid": "host"}, ["app: pid=host"]),
        ({"ipc": "host"}, ["app: ipc=host"]),
        ({"ipc": "shareable"}, []),
        ({"network_mode": "host"}, ["app: network_mode=host"]),
        ({"network_mode": "service:postgres"}, []),
        ({"network_mode": "container:edge"}, ["app: network_mode=container:edge"]),
        ({"userns_mode": "host"}, ["app: userns_mode=host"]),
        ({"cgroup": "host"}, ["app: cgroup=host"]),
        ({"cgroup": "private"}, []),
        (
            {"security_opt": ["seccomp:unconfined"]},
            ["app: security_opt=seccomp:unconfined"],
        ),
        (
            {"security_opt": ["apparmor=unconfined"]},
            ["app: security_opt=apparmor=unconfined"],
        ),
        ({"security_opt": ["label:disable"]}, ["app: security_opt=label:disable"]),
        ({"security_opt": ["no-new-privileges:true"]}, []),
        ({"volumes_from": ["postgres"]}, []),
        ({"volumes_from": ["container:edge"]}, ["app: volumes_from=container:edge"]),
    ],
)
def test_each_key_of_the_host_is_named(
    tmp_path: Path, body: dict[str, Json], found: list[str]
) -> None:
    assert forbidden(released(tmp_path), app(**body)) == found


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
        ({"type": "tmpfs", "target": "/x"}, []),
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
    assert forbidden(cs, app(expose=["8000"])) == []  # not a port of the host


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


def test_what_a_service_mounts_from_the_top_level_stays_in_the_release(
    tmp_path: Path,
) -> None:
    cs = released(tmp_path)
    inside = str(cs.release / "conf")
    document = app()
    document["volumes"] = {
        "pgdata": {"name": "blank_pgdata"},
        "here": {
            "driver": "local",
            "driver_opts": {"type": "none", "o": "bind", "device": inside},
        },
        "root": {
            "driver": "local",
            "driver_opts": {"type": "none", "o": "bind", "device": "/"},
        },
    }
    document["configs"] = {"ok": {"file": inside}, "passwd": {"file": "/etc/passwd"}}
    document["secrets"] = {"ok": {"file": inside}, "key": {"file": "/root/key"}}
    assert forbidden(cs, document) == [
        "configs.passwd: file=/etc/passwd",
        "secrets.key: file=/root/key",
        "volumes.root: driver_opts.device=/",
    ]


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
        "app: pid=host",
        "app: privileged",
        "postgres: cap_add=SYS_PTRACE",
    ]
    assert forbidden(cs, {"x-common": {"privileged": True}}) == []
