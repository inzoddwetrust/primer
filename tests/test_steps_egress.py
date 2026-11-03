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
from test_probe_DM_57_check import _reason, _steps, _yaml, check, green_calls, repo

from pridem.events import Code, Json
from pridem.report.codes import ExitCode
from pridem.runner import FakeCall, FakeRunner
from pridem.stacks.egress import LISTING, listed, unlisted
from pridem.stacks.schema import (
    PRIMER_YAML,
    PROXY_VARIABLES,
    Product,
    Service,
    _check,
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
    OUTSIDE,
    SENTINEL,
    SQUID_IMAGE,
    Egress,
    compose_file,
    compose_text,
    config_file,
    config_text,
    connect_status,
)
from pridem.steps.host import NETWORKS

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
    assert sorted((row.product, row.host) for row in LISTING) == [
        ("blank", "api.github.com"),
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
    stack = product(["zoom.us"], "blank")
    step = Build(
        stack, ENTRY, release=tmp_path / "r", ref=REF, commit=SHA, root=tmp_path
    )
    with FakeRunner() as runner:  # nothing runs
        outcome, _ = run([step], runner)
    assert outcome.steps[0].reason == Code(
        "build:egress-unlisted", {"product": "blank", "hosts": ["zoom.us"]}
    )
    assert not (tmp_path / "opt").exists()
    # the pair: a listed host passes on to compose -- the first command it runs
    listed_ = product(["api.github.com"], "blank")
    step = Build(
        listed_, ENTRY, release=tmp_path / "r", ref=REF, commit=SHA, root=tmp_path
    )
    # (the strict runner names the unplanned command when the plan is over)
    with pytest.raises(AssertionError, match="'config'"), FakeRunner() as runner:
        run([step], runner)


def test_check_names_an_unlisted_host_by_the_same_function(tmp_path: Path) -> None:
    root = repo(tmp_path)
    _yaml(root, {"egress": ["api.github.com", "github.com", "pypi.org"]})
    code, verdict, _ = check(root, green_calls(root))
    assert code == 1
    assert _reason(verdict, "blank/primer_yaml") == {
        "code": "primer_yaml:egress-unlisted",
        "product": "blank",
        "hosts": ["github.com", "pypi.org"],
    }
    # the checks after it still ran: the compose was read and found clean
    assert _steps(verdict)["blank/compose"]["status"] == "ok"
    # the pair: a listed host is green, and the fact names it
    root = repo(tmp_path / "again")
    _yaml(root, {"egress": ["api.github.com"]})
    code, verdict, _ = check(root, green_calls(root))
    assert code == 0
    fact = _steps(verdict)["blank/primer_yaml"]["verify"]
    assert isinstance(fact, dict) and fact["egress"] == ["api.github.com"]


# --- the override ------------------------------------------------------------------


def rendered(
    stack: Product | Service, document: Mapping[str, Json] = CONFIG
) -> dict[str, Json]:
    cs = ComposeStack(stack, ENTRY, Path("/release"), REF, SHA, Path("/"))
    loaded = json.loads(override_text(cs, document))
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


def verify_calls(hosts: list[str]) -> list[FakeCall]:
    return [ps(PROXY), *image(), seen(hosts), address()]


def step(root: Path, hosts: list[str], proxy: Proxy, ready_s: float = 30) -> Egress:
    ticks = count()
    return Egress(
        product(hosts),
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
    }
    assert config_file(tmp_path).read_text() == config_text(hosts)
    assert oct(config_file(tmp_path).stat().st_mode & 0o777) == oct(0o644)
    assert proxy.asked == [SENTINEL, "api.github.com"]


def test_the_same_list_running_needs_no_act(tmp_path: Path) -> None:
    write(tmp_path, ZOOM)
    proxy = Proxy(ZOOM)
    script = [ps(PROXY), *image(), *verify_calls(ZOOM)]  # no up
    with FakeRunner(*script) as runner:
        outcome, _ = run([step(tmp_path, ZOOM, proxy)], runner)
    assert outcome.code is ExitCode.OK, outcome.steps
    # every host of egress is asked, not the first alone
    assert proxy.asked == [SENTINEL, *ZOOM]


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
    hosts = list(ZOOM)
    proxy = Proxy(hosts)
    calls = verify_calls(hosts)
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
        calls = [ps()]
    with FakeRunner(up(tmp_path), *calls) as runner:
        outcome, _ = run([step(tmp_path, hosts, proxy, ready_s=3)], runner)
    reason = outcome.steps[0].reason
    assert reason is not None and reason.code == code, outcome.steps
    if change == "refuses":
        assert reason.params == {"hosts": ["api.zoom.us"]}


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

    egress = Spoils(product(ZOOM), root=tmp_path, answer=Proxy(ZOOM))
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
    lines = config_text(stack.egress).splitlines()
    allow = [line for line in lines if line.startswith("acl egress ")]
    assert allow == ["acl egress dstdomain -n api.github.com"]  # the pair
    assert lines[-len(lines) :].count("http_access deny all") == 1
    assert "github.com" not in allow[0].split()[3:]
