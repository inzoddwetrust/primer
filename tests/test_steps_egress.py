"""DM-64: a product has no way out of the box but the machine's proxy, and the
proxy lets it reach exactly the hosts of its ``egress`` (protocol 4.1, 4.2).

What reaches the internet is measured on tier 3
(``test_probe_DM_64_product_reaches_only_its_egress_hosts``); here, its twin by
the renders -- the override that makes every network of a product internal and
the config of squid -- and the rest: the contract of ``egress``, the list agreed
with Primer, the refusal of ``build`` and ``pridem check``, and the step
``egress`` on a strict ``FakeRunner``, its proxy answering through a fake
``Answer``.
"""

import json
import socket
import threading
from collections.abc import Iterator, Mapping
from itertools import count
from pathlib import Path

import pytest
from compose_support import CONFIG, ENTRY, REF, SHA, blank, run, stdout
from env_support import context
from passport_support import passport_example
from test_probe_DM_57_check import _reason, _steps, _yaml, check, green_calls, repo

from pridem.events import Code, Json
from pridem.report.codes import ExitCode
from pridem.runner import FakeCall, FakeRunner, Stream
from pridem.stacks.egress import LISTING, listed, unlisted
from pridem.stacks.passport import PASSPORT
from pridem.stacks.schema import (
    PRIMER_YAML,
    PROXY_VARIABLES,
    Product,
    Service,
    _check,
    egress_hosts,
)
from pridem.steps.base import CheckResult, StepContext
from pridem.steps.build import Build
from pridem.steps.compose import (
    EGRESS_NETWORK,
    NETWORK,
    PROXY_ALIAS,
    PROXY_URL,
    ComposeStack,
    override_text,
)
from pridem.steps.egress import (
    CONTAINER_CONFIG,
    LABEL_FILTER,
    LOG_FORMAT,
    LOG_TAG,
    OUTSIDE,
    SENTINEL,
    SQUID_IMAGE,
    STATE_FORMAT,
    Egress,
    compose_file,
    compose_text,
    config_file,
    config_text,
    connect_status,
)
from pridem.steps.host import NETWORKS
from pridem.steps.passport import Fetched

PROXY = "c0ffee"
SQUID_ID = "sha256:" + "5" * 64
ADDRESS = "172.30.0.2"
ZOOM = ["zoom.us", "api.zoom.us"]


def product(egress: list[str], name: str = "blank") -> Product:
    """The blank of ``compose_support`` named ``name`` with ``egress``."""
    data = json.loads(blank().model_dump_json(by_alias=True, exclude_defaults=True))
    data.update({"name": name, "egress": egress})
    made = PRIMER_YAML.validate_python(data)
    assert isinstance(made, Product)
    return made


def problems(**change: object) -> list[tuple[str, str]]:
    """``(path, code)`` of every problem of the blank changed by ``change``."""
    data = json.loads(blank().model_dump_json(by_alias=True, exclude_defaults=True))
    data.update(change)
    _, problems_ = _check(data)
    return [(p.path, p.code) for p in problems_]


def at(value: object, *keys: str) -> object:
    """``value[keys[0]][keys[1]]...``, each level a dict."""
    for key in keys:
        assert isinstance(value, dict), key
        value = value[key]
    return value


def keys(value: object) -> list[str]:
    assert isinstance(value, dict)
    return [str(key) for key in value]


# --- the contract of egress -------------------------------------------------------


def test_egress_is_a_list_of_names_and_empty_by_default() -> None:
    assert blank().egress == []
    assert product(ZOOM).egress == ZOOM
    assert problems(egress=[]) == []
    assert problems(egress=["oauth.telegram.org", "a-b.example.org"]) == []


@pytest.mark.parametrize(
    "host",
    [
        "*.zoom.us",
        "zoom.us:443",
        "zoom.us/x",
        "https://zoom.us",
        "1.2.3.4",
        "::1",
        "[::1]",
        "Zoom.us",
        "zoom.us.",
        "zoom",
        "",
        "-zoom.us",
        "zoom-.us",
        "zo om.us",
        "a" * 64 + ".us",
    ],
)
def test_an_egress_host_that_is_not_a_name_is_refused(host: str) -> None:
    assert problems(egress=["zoom.us", host]) == [("egress[1]", "S.egress-host")]


def test_an_egress_host_named_twice_is_refused() -> None:
    assert problems(egress=["zoom.us", "api.zoom.us", "zoom.us"]) == [
        ("egress[2]", "S.egress-duplicate")
    ]


@pytest.mark.parametrize("key", PROXY_VARIABLES)
def test_a_key_of_env_named_as_the_proxy_is_refused(key: str) -> None:
    env = {key: {"source": "param"}, "LANGUAGE": {"source": "param"}}
    assert problems(env=env) == [(f"env.{key}", "S.egress-env")]


def test_a_service_has_no_egress() -> None:
    data = {
        "schema": 1,
        "name": "comms",
        "kind": "service",
        "stacks": {"comms": {"compose": "docker-compose.yml"}},
        "report": {"health": "/h", "ready": "/r", "logs": "json", "junit": True},
    }
    assert isinstance(PRIMER_YAML.validate_python(data), Service)  # the pair
    with pytest.raises(Exception, match="egress"):
        PRIMER_YAML.validate_python({**data, "egress": ["zoom.us"]})


# --- the list agreed with Primer --------------------------------------------------


def test_the_list_is_the_cards_first_edition() -> None:
    """Changed by DM-70: the blank's row is under its own name, ``primer-blank``
    (contract 3 rule 32)."""
    assert sorted((row.product, row.host) for row in LISTING) == [
        ("primer-blank", "api.github.com"),
        ("velo", "api.zoom.us"),
        ("velo", "chatgpt.com"),
        ("velo", "claude.ai"),
        ("velo", "oauth.telegram.org"),
        ("velo", "zoom.us"),
    ]
    for row in LISTING:  # every row is a host the contract takes
        assert problems(egress=[row.host]) == [], row


def test_unlisted_names_every_host_out_of_the_products_rows() -> None:
    velo = product(ZOOM, "velo")
    assert unlisted(velo) == []  # the pair: listed hosts pass
    assert unlisted(product(["zoom.us", "example.org", "pypi.org"], "velo")) == [
        "example.org",
        "pypi.org",
    ]
    # a row of another product admits nothing: api.github.com is the blank's
    assert unlisted(product(["api.github.com"], "velo")) == ["api.github.com"]
    assert unlisted(product(["zoom.us"], "blank")) == ["zoom.us"]
    # a product with no row at all
    assert unlisted(product(["zoom.us"], "aivis")) == ["zoom.us"]
    assert listed("aivis") == frozenset()
    assert unlisted(product([], "aivis")) == []


def test_build_refuses_an_unlisted_host_before_any_command(tmp_path: Path) -> None:
    """Changed by DM-70: the pair's listed host is admitted to the product named
    as its row, ``primer-blank`` (contract 3 rule 32)."""
    stack = product(["zoom.us"], "blank")
    step = Build(
        stack,
        ENTRY,
        release=tmp_path / "r",
        ref=REF,
        commit=SHA,
        root=tmp_path,
    )
    with FakeRunner() as runner:  # nothing runs
        outcome, _ = run([step], runner)
    assert outcome.steps[0].reason == Code(
        "build:egress-unlisted", {"product": "blank", "hosts": ["zoom.us"]}
    )
    assert not (tmp_path / "opt").exists()
    # the pair: a listed host passes on to compose -- the first command it runs;
    # the row is the blank's under its own name, primer-blank (DM-70)
    listed_ = product(["api.github.com"], "primer-blank")
    step = Build(
        listed_,
        ENTRY,
        release=tmp_path / "r",
        ref=REF,
        commit=SHA,
        root=tmp_path,
    )
    # (the strict runner names the unplanned command when the plan is over)
    with pytest.raises(AssertionError, match="'config'"), FakeRunner() as runner:
        run([step], runner)


def test_check_names_an_unlisted_host_by_the_same_function(tmp_path: Path) -> None:
    """Changed by DM-70: the product is named as the blank's row,
    ``primer-blank`` (contract 3 rule 32), so ``api.github.com`` is admitted."""
    root = repo(tmp_path)
    # the blank under its own name, primer-blank, whose row admits api.github.com
    # (DM-70): the hosts out of the row are named, the listed one is not
    egress = ["api.github.com", "github.com", "pypi.org"]
    _yaml(root, {"name": "primer-blank", "egress": egress})
    code, verdict, _ = check(root, green_calls(root))
    assert code == 1
    assert _reason(verdict, "blank/primer_yaml") == {
        "code": "primer_yaml:egress-unlisted",
        "product": "primer-blank",
        "hosts": ["github.com", "pypi.org"],
    }
    # the checks after it still ran: the compose was read and found clean
    assert _steps(verdict)["blank/compose"]["status"] == "ok"
    # the pair: a listed host is green, and the fact names it -- the row is the
    # blank's under its own name, primer-blank (DM-70)
    root = repo(tmp_path / "again")
    _yaml(root, {"name": "primer-blank", "egress": ["api.github.com"]})
    code, verdict, _ = check(root, green_calls(root))
    assert code == 0
    fact = _steps(verdict)["blank/primer_yaml"]["verify"]
    assert isinstance(fact, dict) and fact["egress"] == ["api.github.com"]


# --- the override ------------------------------------------------------------------


def rendered(
    stack: Product | Service, document: Mapping[str, Json] = CONFIG
) -> dict[str, Json]:
    cs = ComposeStack(stack, ENTRY, Path("/release"), REF, SHA, Path("/"), staged=True)
    proxy = isinstance(stack, Product) and bool(stack.egress)  # every host open
    loaded = json.loads(override_text(cs, document, proxy=proxy, references=document))
    assert isinstance(loaded, dict)
    return loaded


def test_without_egress_a_product_is_on_internal_networks_alone() -> None:
    found = rendered(product([]))
    networks = found["networks"]
    assert isinstance(networks, dict)
    assert networks["default"] == {
        "labels": {"pridem.stack": "blank"},
        "internal": True,
    }
    assert networks[NETWORK] == {"external": True}
    assert EGRESS_NETWORK not in networks
    services = found["services"]
    assert isinstance(services, dict)
    for name, body in services.items():
        assert isinstance(body, dict)
        assert "environment" not in body, name
        assert EGRESS_NETWORK not in keys(body.get("networks") or {}), name
    # the pair: app is still on pridem under its alias, nginx reaches it there
    assert at(services, "app", "networks") == {
        "default": None,
        NETWORK: {"aliases": ["blank-app"]},
    }


def test_with_egress_every_service_joins_the_proxy_and_gets_its_address() -> None:
    found = rendered(product(["api.github.com"]))
    services = found["services"]
    assert isinstance(services, dict)
    assert sorted(services) == ["app", "frontend", "postgres"]
    for name, body in services.items():  # a worker too, not only app
        assert isinstance(body, dict)
        assert body["environment"] == {
            "HTTPS_PROXY": PROXY_URL,
            "https_proxy": PROXY_URL,
        }, name
        networks = body["networks"]
        assert isinstance(networks, dict) and networks[EGRESS_NETWORK] is None, name
        assert "default" in networks, name  # its own network is kept
    assert at(services, "app", "networks", NETWORK) == {"aliases": ["blank-app"]}
    assert NETWORK not in keys(at(services, "postgres", "networks"))
    networks = found["networks"]
    assert isinstance(networks, dict)
    assert networks[EGRESS_NETWORK] == {"external": True}
    assert PROXY_URL == f"http://{PROXY_ALIAS}:3128"


def test_every_network_a_product_declares_is_internal() -> None:
    document = json.loads(json.dumps(CONFIG))
    document["networks"]["back"] = {"name": "blank_back"}
    document["networks"]["front"] = {"name": "blank_front", "internal": True}
    networks = rendered(product([]), document)["networks"]
    assert isinstance(networks, dict)
    assert networks["back"] == {"internal": True}
    assert networks["front"] == {"internal": True}
    assert networks["default"] == {
        "labels": {"pridem.stack": "blank"},
        "internal": True,
    }


def test_a_service_keeps_its_networks_and_its_way_out() -> None:
    service = PRIMER_YAML.validate_python(
        {
            "schema": 1,
            "name": "comms",
            "kind": "service",
            "stacks": {
                "blank": {
                    "compose": "docker-compose.yml",
                    "app": {
                        "service": "app",
                        "port": 8000,
                        "health": "/health",
                        "ready": "/ready",
                    },
                }
            },
            "report": {"health": "/h", "ready": "/r", "logs": "json", "junit": True},
        }
    )
    assert isinstance(service, Service)
    found = rendered(service)
    networks = found["networks"]
    assert isinstance(networks, dict)
    assert networks["default"] == {"labels": {"pridem.stack": "blank"}}
    assert EGRESS_NETWORK not in networks
    services = found["services"]
    assert isinstance(services, dict)
    assert all("environment" not in keys(body) for body in services.values())
    # the pair: its app is on pridem all the same
    assert NETWORK in keys(at(services, "app", "networks"))


# --- the config of squid -----------------------------------------------------------


def test_the_config_lets_through_connect_to_the_hosts_by_name_alone() -> None:
    lines = config_text(ZOOM).splitlines()
    assert "acl egress dstdomain -n zoom.us api.zoom.us" in lines
    assert not any(" ." in line for line in lines if "dstdomain" in line)
    access = [line for line in lines if line.startswith("http_access")]
    assert access == [
        "http_access deny !CONNECT",
        "http_access deny !SSL_ports",
        "http_access deny private",
        "http_access allow egress",
        "http_access deny all",
    ]
    assert "acl SSL_ports port 443" in lines
    private = next(line for line in lines if line.startswith("acl private dst"))
    for block in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8"):
        assert block in private.split()
    assert "cache deny all" in lines and "http_port 3128" in lines


PRIVATE_BLOCKS = (
    "0.0.0.0/8",
    "10.0.0.0/8",
    "100.64.0.0/10",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "172.16.0.0/12",
    "192.0.0.0/24",
    "192.168.0.0/16",
    "198.18.0.0/15",
    "224.0.0.0/4",
    "240.0.0.0/4",
    "::/128",
    "::1",
    "::ffff:0:0/96",
    "64:ff9b::/96",
    "fc00::/7",
    "fe80::/10",
    "ff00::/8",
)
"""Every range the proxy refuses, written out here and not read from
``PRIVATE``: a range dropped from the code is red (DM-79; the cloud's metadata
``169.254.0.0/16`` among them)."""


def test_the_proxy_refuses_every_private_range_once() -> None:
    """DM-79: ``acl private dst`` names each range of ``PRIVATE_BLOCKS``
    exactly once, nothing else -- the two lists are the same sets with no
    duplicate on either side."""
    lines = config_text(["zoom.us"]).splitlines()
    private = [line for line in lines if line.startswith("acl private dst")]
    assert len(private) == 1
    found = private[0].split()[3:]
    assert len(found) == len(set(found)) == len(PRIVATE_BLOCKS)
    assert set(found) == set(PRIVATE_BLOCKS)


def test_the_proxy_runs_confined(tmp_path: Path) -> None:
    """DM-79: squid runs as ``proxy`` from its first instruction and needs no
    capability: every one dropped, none given back, ``no-new-privileges``, a
    limit on processes; its log is the host's (no ``logging`` here)."""
    proxy = json.loads(compose_text(tmp_path))["services"]["proxy"]
    assert proxy["cap_drop"] == ["ALL"]
    assert "cap_add" not in proxy
    assert proxy["security_opt"] == ["no-new-privileges:true"]
    assert proxy["pids_limit"] == 256
    assert proxy["user"] == "proxy" and "logging" not in proxy


def test_the_proxy_compose_puts_it_on_its_network_and_a_way_out(tmp_path: Path) -> None:
    document = json.loads(compose_text(tmp_path))
    proxy = document["services"]["proxy"]
    assert proxy["image"] == SQUID_IMAGE and "@sha256:" in SQUID_IMAGE
    assert proxy["labels"] == {"pridem.stack": "egress"}
    assert proxy["networks"] == {
        EGRESS_NETWORK: {"aliases": [PROXY_ALIAS]},
        "default": None,
    }
    assert proxy["volumes"] == [f"{config_file(tmp_path)}:{CONTAINER_CONFIG}:ro"]
    # DM-45 FIX: squid as the image's user from the start -- the pipe of the
    # container's stdout is that user's, so squid opens its access log on it
    assert proxy["user"] == "proxy"
    assert proxy["entrypoint"] == ["/usr/sbin/squid"]
    assert proxy["command"] == ["-N", "-d", "1", "-f", CONTAINER_CONFIG]
    assert "ports" not in proxy  # nothing of the host
    assert document["networks"] == {
        EGRESS_NETWORK: {"external": True},
        "default": {"labels": {"pridem.stack": "egress"}},
    }


# --- the step ---------------------------------------------------------------------


class Proxy:
    """A fake ``Answer``: 403 for every host but ``allowed``, which get
    ``status``; records the hosts asked."""

    def __init__(self, allowed: list[str], status: int = 200) -> None:
        self.allowed = allowed
        self.status = status
        self.asked: list[str] = []
        self.silent: set[str] = set()

    def __call__(self, address: str, port: int, host: str) -> int | None:
        assert (address, port) == (ADDRESS, 3128)
        self.asked.append(host)
        if host in self.silent:
            return None
        return self.status if host in self.allowed else 403


def getent(host: str, *addresses: str, code: int = 0) -> FakeCall:
    """``getent ahosts`` in the proxy's container (DM-84): a line per address
    and socket type, as libc prints it."""
    lines = tuple(f"{a}      STREAM {host}" for a in addresses)
    return call(
        "docker", "exec", PROXY, "getent", "ahosts", host, code=code, lines=lines
    )


def call(*argv: str, code: int = 0, lines: tuple[str, ...] = ()) -> FakeCall:
    return FakeCall(argv, code=code, lines=stdout(*lines))


def ps(*ids: str, every: bool = False) -> FakeCall:
    args = ["docker", "ps", "-q", "--no-trunc", "--filter", LABEL_FILTER]
    if every:
        args.insert(2, "-a")
    return call(*args, lines=ids)


def image(running: str = SQUID_ID, pinned: str = SQUID_ID) -> list[FakeCall]:
    return [
        call("docker", "inspect", "-f", "{{.Image}}", PROXY, lines=(running,)),
        call(
            "docker", "image", "inspect", "-f", "{{.Id}}", SQUID_IMAGE, lines=(pinned,)
        ),
    ]


def seen(hosts: list[str]) -> FakeCall:
    return call(
        "docker",
        "exec",
        PROXY,
        "cat",
        CONTAINER_CONFIG,
        lines=tuple(config_text(hosts).splitlines()),
    )


def address(value: str = ADDRESS) -> FakeCall:
    networks = {
        OUTSIDE: {"IPAddress": value},
        EGRESS_NETWORK: {"IPAddress": "10.9.0.2"},
    }
    return call(
        "docker",
        "inspect",
        "-f",
        "{{json .NetworkSettings.Networks}}",
        PROXY,
        lines=(json.dumps(networks),),
    )


def up(root: Path, code: int = 0) -> FakeCall:
    return call(
        "docker",
        "compose",
        "-p",
        "pridem-egress",
        "-f",
        str(compose_file(root)),
        "up",
        "-d",
        "--force-recreate",
        "proxy",
        code=code,
    )


LOGGED = f"{LOG_TAG} host={SENTINEL} port=443 status=403 result=TCP_DENIED"
"""The access log's line of the refused sentinel (DM-45)."""


def logs(*lines: str) -> FakeCall:
    return call("docker", "logs", PROXY, lines=lines)


CRASHED: dict[str, Json] = {
    "status": "restarting",
    "exit_code": 1,
    "restarts": 7,
    "error": "",
}
"""The state docker reports of a squid that stops at its start (DM-45 FIX)."""
SQUID_SAYS = "FATAL: Cannot open '/dev/stdout' for writing."


def diagnosis(container: str = PROXY) -> list[FakeCall]:
    """What a refusal of the proxy reads (DM-45 FIX): its state, then the
    end of its log -- squid's own message on stderr."""
    return [
        call(
            "docker",
            "inspect",
            "-f",
            STATE_FORMAT,
            container,
            lines=(json.dumps(CRASHED),),
        ),
        FakeCall(
            ("docker", "logs", "--tail", "40", container),
            lines=((Stream.STDERR, SQUID_SAYS),),
        ),
    ]


DIAGNOSED: dict[str, Json] = {
    "container": PROXY,
    "state": CRASHED,
    "logs": [f"err: {SQUID_SAYS}"],
}


def verify_calls(hosts: list[str]) -> list[FakeCall]:
    """DM-45: verify reads the access log back last."""
    return [ps(PROXY), *image(), seen(hosts), address(), logs(LOGGED)]


FETCHED = Fetched(passport=PASSPORT.validate_python(passport_example()))
"""A passport with no option on: every host of these products is a plain
name, open whatever the options."""


def step(root: Path, hosts: list[str], proxy: Proxy, ready_s: float = 30) -> Egress:
    ticks = count()
    return Egress(
        product(hosts),
        fetched=FETCHED,
        root=root,
        answer=proxy,
        ready_s=ready_s,
        clock=lambda: float(next(ticks)),
        sleep=lambda _: None,
    )


def write(root: Path, hosts: list[str]) -> None:
    for path, text in (
        (config_file(root), config_text(hosts)),
        (compose_file(root), compose_text(root)),
    ):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)


def test_the_proxy_steps_in_after_migrate_and_before_up() -> None:
    """After the point of no return -- a failed migration leaves the old code on
    the old list -- and before ``up``: the new application starts with its proxy
    ready (the owner's decision on the gate of DM-64)."""
    from pridem.steps.migrate import Migrate
    from pridem.steps.up import Up

    assert Migrate.point_of_no_return
    assert Migrate.order < Egress.order < Up.order


def test_first_proxy_is_written_started_and_read_back(tmp_path: Path) -> None:
    proxy = Proxy(["api.github.com"], status=200)
    hosts = ["api.github.com"]
    with FakeRunner(up(tmp_path), *verify_calls(hosts)) as runner:
        outcome, _ = run([step(tmp_path, hosts, proxy)], runner)
    assert outcome.code is ExitCode.OK, outcome.steps
    assert outcome.steps[0].verify == {
        "hosts": hosts,
        "image": SQUID_IMAGE,
        "refused": {SENTINEL: 403},
        "allowed": {"api.github.com": 200},
        "log": LOGGED,  # DM-45: the refused sentinel in the proxy's own log
    }
    assert config_file(tmp_path).read_text() == config_text(hosts)
    assert oct(config_file(tmp_path).stat().st_mode & 0o777) == oct(0o644)
    assert proxy.asked == [SENTINEL, "api.github.com"]


def test_the_same_list_running_needs_no_act(tmp_path: Path) -> None:
    write(tmp_path, ZOOM)
    proxy = Proxy(ZOOM)
    # DM-81: check reads the config the proxy runs on too, as verify does
    script = [ps(PROXY), *image(), seen(ZOOM), *verify_calls(ZOOM)]  # no up
    with FakeRunner(*script) as runner:
        outcome, _ = run([step(tmp_path, ZOOM, proxy)], runner)
    assert outcome.code is ExitCode.OK, outcome.steps
    # every host of egress is asked, not the first alone
    assert proxy.asked == [SENTINEL, *ZOOM]


def test_a_proxy_on_a_config_of_its_own_is_recreated(tmp_path: Path) -> None:
    """DM-81: the files on disk are the rendered ones, the running proxy reads
    another config (its file was written again after it started, or by
    someone else): ``check`` reads what ``verify`` reads and acts -- never a
    red ``config-not-seen`` with nothing to do. The pair: a proxy whose
    ``exec`` fails (it restarts) is acted on too; the same config -- no act
    (``test_the_same_list_running_needs_no_act``)."""
    write(tmp_path, ZOOM)
    script = [ps(PROXY), *image(), seen(["claude.ai"]), up(tmp_path)]
    with FakeRunner(*script, *verify_calls(ZOOM)) as runner:
        outcome, _ = run([step(tmp_path, ZOOM, Proxy(ZOOM))], runner)
    assert outcome.code is ExitCode.OK, outcome.steps
    failing = call("docker", "exec", PROXY, "cat", CONTAINER_CONFIG, code=1)
    with FakeRunner(ps(PROXY), *image(), failing) as runner:
        check = step(tmp_path, ZOOM, Proxy(ZOOM)).check(context(runner))
    assert check.needed and check.would is not None
    assert check.would.code == "render"


def test_another_list_rewrites_and_recreates_the_proxy(tmp_path: Path) -> None:
    write(tmp_path, ["zoom.us"])
    proxy = Proxy(["claude.ai"])
    hosts = ["claude.ai"]
    with FakeRunner(up(tmp_path), *verify_calls(hosts)) as runner:
        outcome, _ = run([step(tmp_path, hosts, proxy)], runner)
    assert outcome.code is ExitCode.OK, outcome.steps
    assert "zoom.us" not in config_file(tmp_path).read_text()


def test_a_proxy_on_another_image_is_recreated(tmp_path: Path) -> None:
    write(tmp_path, ZOOM)
    script = [ps(PROXY), *image(running="sha256:" + "0" * 64), up(tmp_path)]
    with FakeRunner(*script, *verify_calls(ZOOM)) as runner:
        outcome, _ = run([step(tmp_path, ZOOM, Proxy(ZOOM))], runner)
    assert outcome.code is ExitCode.OK, outcome.steps


def test_a_stopped_proxy_is_started(tmp_path: Path) -> None:
    write(tmp_path, ZOOM)
    with FakeRunner(ps(), up(tmp_path), *verify_calls(ZOOM)) as runner:
        outcome, _ = run([step(tmp_path, ZOOM, Proxy(ZOOM))], runner)
    assert outcome.code is ExitCode.OK, outcome.steps


def test_a_run_cut_after_the_files_acts_again(tmp_path: Path) -> None:
    """``up`` failed after the files were written: red; the next run finds the
    files rendered but no proxy running, and acts."""
    hosts = ["zoom.us"]
    with FakeRunner(up(tmp_path, code=1)) as runner:
        outcome, _ = run([step(tmp_path, hosts, Proxy(hosts))], runner)
    assert outcome.code is not ExitCode.OK
    assert config_file(tmp_path).read_text() == config_text(hosts)
    with FakeRunner(ps(), up(tmp_path), *verify_calls(hosts)) as runner:
        outcome, _ = run([step(tmp_path, hosts, Proxy(hosts))], runner)
    assert outcome.code is ExitCode.OK, outcome.steps


def test_empty_egress_on_a_clean_box_is_no_proxy(tmp_path: Path) -> None:
    with FakeRunner(ps(every=True), ps(every=True)) as runner:
        outcome, _ = run([step(tmp_path, [], Proxy([]))], runner)
    assert outcome.code is ExitCode.OK
    assert outcome.steps[0].verify == {"hosts": [], "proxy": "absent"}
    assert not compose_file(tmp_path).exists()


def test_empty_egress_removes_the_proxy_a_release_left(tmp_path: Path) -> None:
    write(tmp_path, ZOOM)
    down = call(
        "docker",
        "compose",
        "-p",
        "pridem-egress",
        "-f",
        str(compose_file(tmp_path)),
        "down",
    )
    script = [ps(PROXY, every=True), down, ps(every=True)]
    with FakeRunner(*script) as runner:
        outcome, _ = run([step(tmp_path, [], Proxy([]))], runner)
    assert outcome.code is ExitCode.OK, outcome.steps
    assert not config_file(tmp_path).exists() and not compose_file(tmp_path).exists()


def test_a_proxy_left_without_its_file_goes_by_label(tmp_path: Path) -> None:
    script = [
        ps(PROXY, every=True),
        ps(PROXY, every=True),
        call("docker", "rm", "-f", PROXY),
        ps(every=True),
    ]
    with FakeRunner(*script) as runner:
        outcome, _ = run([step(tmp_path, [], Proxy([]))], runner)
    assert outcome.code is ExitCode.OK, outcome.steps


def test_a_proxy_still_there_after_removal_is_red(tmp_path: Path) -> None:
    write(tmp_path, ZOOM)
    down = call(
        "docker",
        "compose",
        "-p",
        "pridem-egress",
        "-f",
        str(compose_file(tmp_path)),
        "down",
    )
    with FakeRunner(ps(PROXY, every=True), down, ps(PROXY, every=True)) as runner:
        outcome, _ = run([step(tmp_path, [], Proxy([]))], runner)
    assert outcome.steps[0].reason == Code("egress:proxy-left", {"found": [PROXY]})


@pytest.mark.parametrize(
    ("change", "code"),
    [
        ("open", "egress:proxy-open"),
        ("refuses", "egress:host-refused"),
        ("silent", "egress:proxy-silent"),
        ("never-answers", "egress:proxy-silent"),
        ("image", "egress:image-wrong"),
        ("config", "egress:config-not-seen"),
        ("address", "egress:no-address"),
        ("none-running", "egress:not-running"),
    ],
)
def test_verify_reads_the_proxy_and_its_behaviour(
    tmp_path: Path, change: str, code: str
) -> None:
    """Changed by DM-84: a host of the list refused until ``ready_s`` is red
    with what the proxy's container resolves it to (``resolved``) beside
    docker's word."""
    hosts = list(ZOOM)
    proxy = Bounded(hosts)
    calls = verify_calls(hosts)[:-1]  # red before the log is read (DM-45)
    if change == "open":
        proxy.allowed = [*hosts, SENTINEL]
    elif change == "refuses":
        proxy.allowed = ["zoom.us"]  # api.zoom.us gets 403
    elif change == "silent":
        proxy.silent = {"api.zoom.us"}
    elif change == "never-answers":
        proxy.silent = {SENTINEL}
    elif change == "image":
        calls = [ps(PROXY), *image(running="sha256:" + "0" * 64)]
    elif change == "config":
        calls = [ps(PROXY), *image(), seen(["zoom.us"])]
    elif change == "address":
        calls = [ps(PROXY), *image(), seen(hosts), address("")]
    elif change == "none-running":
        calls = [ps(), ps(PROXY, every=True)]
    if change in ("refuses", "silent", "never-answers", "none-running"):
        calls += diagnosis()  # DM-45 FIX: the refusal carries docker's word
    if change == "refuses":
        calls.append(getent("api.zoom.us", "170.114.52.2"))
    with FakeRunner(up(tmp_path), *calls) as runner:
        outcome, _ = run([step(tmp_path, hosts, proxy, ready_s=3)], runner)
    reason = outcome.steps[0].reason
    assert reason is not None and reason.code == code, outcome.steps
    if change == "refuses":
        assert reason.params == {"hosts": ["api.zoom.us"]}
    if change in ("silent", "never-answers", "none-running"):
        assert outcome.steps[0].verify == DIAGNOSED, outcome.steps[0].verify
    if change == "refuses":  # DM-76 FIX, DM-84: docker's word and the address
        resolved = {"resolved": {"api.zoom.us": ["170.114.52.2"]}}
        assert outcome.steps[0].verify == {**DIAGNOSED, **resolved}


def test_a_host_with_no_answer_of_its_own_is_still_allowed(tmp_path: Path) -> None:
    """A 5xx -- the host itself did not answer -- is not a refusal: ``verify``
    reads the list, not the host's health."""
    proxy = Proxy(ZOOM, status=503)
    with FakeRunner(up(tmp_path), *verify_calls(ZOOM)) as runner:
        outcome, _ = run([step(tmp_path, ZOOM, proxy)], runner)
    assert outcome.code is ExitCode.OK, outcome.steps


def test_verify_waits_for_a_recreated_proxy_to_answer(tmp_path: Path) -> None:
    proxy = Proxy(ZOOM)
    answers = iter([None, None, 403])

    def slow(address_: str, port: int, host: str) -> int | None:
        if host == SENTINEL:
            return next(answers)
        return proxy(address_, port, host)

    egress = step(tmp_path, ZOOM, proxy, ready_s=10)
    egress.answer = slow
    with FakeRunner(up(tmp_path), *verify_calls(ZOOM)) as runner:
        outcome, _ = run([egress], runner)
    assert outcome.code is ExitCode.OK, outcome.steps


def test_drift_of_the_files_is_red_in_verify(tmp_path: Path) -> None:
    class Spoils(Egress):
        def act(self, ctx: StepContext, check: CheckResult) -> None:
            super().act(ctx, check)
            config_file(self.root).write_text("http_access allow all\n")

    egress = Spoils(product(ZOOM), fetched=FETCHED, root=tmp_path, answer=Proxy(ZOOM))
    with FakeRunner(up(tmp_path)) as runner:
        outcome, _ = run([egress], runner)
    assert outcome.steps[0].reason == Code(
        "egress:drift", {"files": [str(config_file(tmp_path))]}
    )


# --- connect_status: the real answer ---------------------------------------------


@pytest.fixture
def answering() -> Iterator[tuple[int, list[bytes]]]:
    """A server that reads one request and answers the next line of ``replies``."""
    server = socket.create_server(("127.0.0.1", 0))
    replies: list[bytes] = []
    received: list[bytes] = []

    def serve() -> None:
        while True:
            try:
                conn, _ = server.accept()
            except OSError:
                return
            with conn:
                received.append(conn.recv(1024))
                if replies:
                    conn.sendall(replies.pop(0))

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    try:
        yield server.getsockname()[1], replies
    finally:
        server.close()
        thread.join(timeout=2)
    assert all(r.startswith(b"CONNECT ") for r in received)


def test_connect_status_reads_the_status_of_the_answer(
    answering: tuple[int, list[bytes]],
) -> None:
    port, replies = answering
    replies += [
        b"HTTP/1.1 403 Forbidden\r\n\r\n",
        b"HTTP/1.1 200 Connection established\r\n\r\n",
        b"220 ready FTP\r\n",
        b"SMTP 220 ready\r\n",
    ]
    assert connect_status("127.0.0.1", port, "github.com") == 403
    assert connect_status("127.0.0.1", port, "api.github.com") == 200
    assert connect_status("127.0.0.1", port, "x.example") is None
    assert connect_status("127.0.0.1", port, "y.example") is None  # not HTTP


def test_connect_status_is_none_when_nothing_listens() -> None:
    server = socket.create_server(("127.0.0.1", 0))
    port = server.getsockname()[1]
    server.close()
    assert connect_status("127.0.0.1", port, "github.com") is None


# --- the twin of the probe by the renders ------------------------------------------


def test_product_reaches_only_its_egress_hosts_by_render() -> None:
    """Twin of ``test_probe_DM_64_product_reaches_only_its_egress_hosts``: every
    network a product's container is on is internal -- its own by the override,
    the machine's by ``ensure_network`` -- so its only way out is the proxy,
    which lets through the hosts of ``egress`` and refuses the rest. The pair:
    the host of ``egress`` is let through."""
    stack = product(["api.github.com"])
    found = rendered(stack)
    top = found["networks"]
    services = found["services"]
    assert isinstance(top, dict) and isinstance(services, dict)
    machine = set(NETWORKS)
    for name, body in services.items():
        assert isinstance(body, dict)
        for network in keys(body["networks"]):
            entry = top[network]
            assert isinstance(entry, dict)
            if network in machine:
                assert entry == {"external": True}, (name, network)
            else:
                assert entry.get("internal") is True, (name, network)
        assert at(body, "environment", "HTTPS_PROXY") == PROXY_URL
    lines = config_text(egress_hosts(stack)).splitlines()
    allow = [line for line in lines if line.startswith("acl egress ")]
    assert allow == ["acl egress dstdomain -n api.github.com"]  # the pair
    assert lines[-len(lines) :].count("http_access deny all") == 1
    assert "github.com" not in allow[0].split()[3:]


# --- DM-45: the proxy's access log ------------------------------------------------


def test_the_log_names_host_port_and_result_and_never_a_path() -> None:
    """squid logs to the container's stdout, one line a request, by codes of
    the domain and the port alone: no ``%ru`` (a request that is not CONNECT
    carries its path there), no ``none``; the pair: the format names the
    host, the port, the status and squid's result."""
    text = config_text(["api.github.com"])
    assert "access_log none" not in text
    assert f"logformat pridem {LOG_TAG} " in text
    assert "access_log stdio:/dev/stdout pridem" in text
    logformat = next(line for line in text.splitlines() if line.startswith("logformat"))
    assert "%ru" not in logformat and "%>ru" not in logformat and "%rp" not in logformat
    assert all(code in logformat for code in ("%>rd", "%>rP", "%>Hs", "%Ss"))


def test_verify_waits_for_the_log_line_and_is_red_without_it(tmp_path: Path) -> None:
    """The line of the refused sentinel may come late: ``verify`` reads the
    log again until ``ready_s``; a log that never has it is ``log-missing``,
    a line of another host or status is not it."""
    hosts = ["api.github.com"]
    write(tmp_path, hosts)
    other = f"{LOG_TAG} host=api.github.com port=443 status=200 result=TCP_TUNNEL"
    open_ = f"{LOG_TAG} host={SENTINEL} port=443 status=200 result=TCP_TUNNEL"
    read = [ps(PROXY), *image(), seen(hosts), address()]
    late = [*read, logs(), logs(other), logs(LOGGED)]
    with FakeRunner(ps(PROXY), *image(), seen(hosts), *late) as runner:
        outcome, _ = run([step(tmp_path, hosts, Proxy(hosts))], runner)
    assert outcome.code is ExitCode.OK, outcome.steps
    assert outcome.steps[0].verify["log"] == LOGGED
    never = [*read, logs(open_), *diagnosis()]
    with FakeRunner(ps(PROXY), *image(), seen(hosts), *never) as runner:
        outcome, _ = run([step(tmp_path, hosts, Proxy(hosts), ready_s=0)], runner)
    assert outcome.steps[0].reason == Code("egress:log-missing", {"host": SENTINEL})
    assert outcome.steps[0].verify == DIAGNOSED  # DM-45 FIX


# --- DM-45 FIX: a proxy that does not run says why ------------------------------


def test_a_proxy_whose_config_cannot_be_read_is_red_with_dockers_word(
    tmp_path: Path,
) -> None:
    """``docker exec`` of a restarting container fails: the step is red
    ``not-running`` -- not an error of the runner -- with the container's
    state, the end of its log and the exit code of ``exec`` in the fact; the
    lines reach the journal too."""
    hosts = list(ZOOM)
    exec_ = call("docker", "exec", PROXY, "cat", CONTAINER_CONFIG, code=1)
    calls = [ps(PROXY), *image(), exec_, *diagnosis()]
    with FakeRunner(up(tmp_path), *calls) as runner:
        outcome, sink = run([step(tmp_path, hosts, Proxy(hosts))], runner)
    record = outcome.steps[0]
    assert record.reason == Code("egress:not-running", {"count": 0})
    assert record.verify == {**DIAGNOSED, "exec_exit_code": 1}
    assert any(SQUID_SAYS in line.line for line in sink.lines())


def test_a_diagnosis_that_fails_names_its_exit_code(tmp_path: Path) -> None:
    """A container gone between the refusal and its diagnosis: the fact names
    the failed ``inspect`` and ``logs`` by their exit codes; the refusal is the
    proxy's, as before."""
    hosts = list(ZOOM)
    proxy = Proxy(hosts)
    proxy.silent = {SENTINEL}
    gone = [
        call("docker", "inspect", "-f", STATE_FORMAT, PROXY, code=1),
        call("docker", "logs", "--tail", "40", PROXY, code=1),
    ]
    calls = [ps(PROXY), *image(), seen(hosts), address(), *gone]
    with FakeRunner(up(tmp_path), *calls) as runner:
        outcome, _ = run([step(tmp_path, hosts, proxy, ready_s=1)], runner)
    record = outcome.steps[0]
    assert record.reason is not None and record.reason.code == "egress:proxy-silent"
    assert record.verify == {
        "container": PROXY,
        "state": {"inspect": 1},
        "logs": [],
        "logs_exit_code": 1,
    }


# --- DM-84: a fresh proxy's first answer comes before its DNS -------------------


ASKED_TO_THE_DEADLINE = 3
"""With ``ready_s=3`` and a clock that ticks once a reading: the probes of a
refused host of the list before the deadline -- exactly, so a deadline of
``>`` instead of ``>=`` is one probe more."""


class Bounded(Proxy):
    """A ``Proxy`` that fails the test past ``limit`` probes of one host -- a
    wait with no deadline ends as a red assertion, not a hang."""

    limit = 20

    def __call__(self, address: str, port: int, host: str) -> int | None:
        if self.asked.count(host) >= self.limit:
            raise AssertionError(f"{host} asked past any deadline")
        return super().__call__(address, port, host)


class Flaky(Proxy):
    """403 for ``host`` the first ``refusals`` times it is asked, then 200."""

    def __init__(self, allowed: list[str], host: str, refusals: int) -> None:
        super().__init__(allowed)
        self.host = host
        self.left = refusals

    def __call__(self, address: str, port: int, host: str) -> int | None:
        if host == self.host and self.left > 0:
            self.asked.append(host)
            self.left -= 1
            return 403
        return super().__call__(address, port, host)


def test_a_listed_host_refused_by_a_fresh_proxy_is_asked_again(tmp_path: Path) -> None:
    """DM-84: 403, 403, then 200 for a host of the list -- green; no probe
    after the 200; ``SENTINEL`` asked once."""
    proxy = Flaky(list(ZOOM), "api.zoom.us", 2)
    with FakeRunner(up(tmp_path), *verify_calls(ZOOM)) as runner:
        outcome, _ = run([step(tmp_path, ZOOM, proxy)], runner)
    assert outcome.code is ExitCode.OK, outcome.steps
    assert proxy.asked.count("api.zoom.us") == 3
    assert proxy.asked.count(SENTINEL) == 1


def test_a_listed_host_refused_until_the_deadline_is_red_with_its_address(
    tmp_path: Path,
) -> None:
    """Refused past ``ready_s`` (a private address stays private): red, with
    docker's word and the address the proxy's container resolves; none --
    ``none``; no getent in the image -- its exit code."""
    for answer, resolved in (
        (getent("api.zoom.us", "10.0.0.7"), ["10.0.0.7"]),
        (getent("api.zoom.us", code=2), "none"),
        (getent("api.zoom.us", code=127), {"getent": 127}),
    ):
        root = tmp_path / str(len(str(resolved)))
        root.mkdir()
        proxy = Bounded(["zoom.us"])
        calls = [*verify_calls(ZOOM)[:-1], *diagnosis(), answer]
        with FakeRunner(up(root), *calls) as runner:
            outcome, _ = run([step(root, ZOOM, proxy, ready_s=3)], runner)
        reason = outcome.steps[0].reason
        assert reason is not None and reason.code == "egress:host-refused"
        assert outcome.steps[0].verify == {
            **DIAGNOSED,
            "resolved": {"api.zoom.us": resolved},
        }
        assert proxy.asked.count("api.zoom.us") == ASKED_TO_THE_DEADLINE


def test_the_sentinel_is_never_asked_again(tmp_path: Path) -> None:
    """``SENTINEL`` must be refused: a 200 for it is ``proxy-open`` at once."""
    proxy = Proxy([*ZOOM, SENTINEL])
    calls = verify_calls(ZOOM)[:-1]
    with FakeRunner(up(tmp_path), *calls) as runner:
        outcome, _ = run([step(tmp_path, ZOOM, proxy)], runner)
    reason = outcome.steps[0].reason
    assert reason is not None and reason.code == "egress:proxy-open"
    assert proxy.asked.count(SENTINEL) == 1


def test_the_log_line_carries_the_address_and_no_path() -> None:
    assert LOG_FORMAT.endswith(" addr=%<a")
    assert "%ru" not in LOG_FORMAT and "%>rp" not in LOG_FORMAT


def test_a_silent_host_is_not_asked_again(tmp_path: Path) -> None:
    """Silence is ``proxy-silent`` at once: only a refusal is asked again."""
    proxy = Bounded(list(ZOOM))
    proxy.silent = {"api.zoom.us"}
    calls = [*verify_calls(ZOOM)[:-1], *diagnosis()]
    with FakeRunner(up(tmp_path), *calls) as runner:
        outcome, _ = run([step(tmp_path, ZOOM, proxy, ready_s=3)], runner)
    reason = outcome.steps[0].reason
    assert reason is not None and reason.code == "egress:proxy-silent"
    assert proxy.asked.count("api.zoom.us") == 1
