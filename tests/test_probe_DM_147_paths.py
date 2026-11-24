"""DM-147: a path of a route -- its own read timeout and no buffering for long
connections (long-poll of the agents, server-sent events of the run screen).

A path is a ``location`` of its own on the route's domain: ``/p/`` a prefix,
``/p`` an exact address; it is ``location /`` in all but its knobs. The loader
refuses a path that is not plain and normalized (``S.route-path``), one that
lies on what the machine closes (``R4.route-path-closed``) and any knob but
``read_timeout`` and ``buffering: false`` (``extra_forbidden``). A route
without paths renders as it did before them, byte for byte.
"""

import re
from collections.abc import Mapping
from pathlib import Path

import pytest
import yaml
from edge_support import DOMAINS, passport, product

from pridem.stacks.loader import ContractError
from pridem.stacks.routes import PREVIEW_PATH, render, targets
from pridem.stacks.schema import (
    MACHINE_PATHS,
    Product,
    Route,
    RoutePath,
    parse_primer_yaml,
    route_closed,
)
from pridem.steps.base import StepFailed

GOLDEN = Path(__file__).parent / "fixtures" / "nginx" / "no-paths-7e69082.conf"
"""``render`` of ``primer@7e69082`` -- before paths -- for the routes below, a
``test`` box and a ``preview`` one, one after the other."""
LINK = "preview-secret-of-the-test"
CSP = "default-src 'self'"
BASE = {"to": "app:8000", "max_body": "100M", "read_timeout": "300s"}
PATHS = {
    "/api/stream/": {"read_timeout": "3600s", "buffering": False},
    "/api/agent/poll": {"read_timeout": "900s"},
}


def routes(**api: object) -> dict[str, dict[str, object]]:
    return {"frontend": {"to": "frontend:80"}, "api": {**BASE, **api}}


def rendered(tmp: Path, made: Product, role: str = "test") -> str:
    _, fetched = passport(tmp, role=role)
    assert fetched.passport is not None
    return render(made, fetched.passport, LINK if role == "preview" else None)


def server_of(text: str, domain: str) -> str:
    [block] = [
        chunk for chunk in text.split("server {") if f"server_name {domain};" in chunk
    ]
    return block


def location(block: str, head: str) -> str:
    """The ``location`` that opens with ``head``, up to its closing brace."""
    found = re.findall(rf"^  {re.escape(head)} \{{\n.*?\n  \}}$", block, re.S | re.M)
    assert len(found) == 1, (head, found)
    return str(found[0])


def primer_text(paths: Mapping[str, object], to: str = "app:8000") -> str:
    data = {
        "schema": 1,
        "name": "blank",
        "kind": "product",
        "stacks": {
            "blank": {
                "compose": "docker-compose.yml",
                "app": {"service": "app", "port": 8000, "health": "/h", "ready": "/r"},
                "frontend": {"service": "frontend", "port": 80},
            }
        },
        "env": {},
        "host": {
            "domains": ["api"],
            "routes": {"api": {"to": to, "paths": paths}},
        },
        "report": {"health": "/h", "ready": "/r", "logs": "json", "junit": True},
    }
    return yaml.safe_dump(data)


def refused(paths: Mapping[str, object], to: str = "app:8000") -> list[tuple[str, str]]:
    """``(code, path in the file)`` of every problem the loader finds."""
    with pytest.raises(ContractError) as caught:
        parse_primer_yaml(primer_text(paths, to), "primer.yaml")
    return [(p.code, p.path) for p in caught.value.problems]


def loads(paths: Mapping[str, object], to: str = "app:8000") -> Route:
    made = parse_primer_yaml(primer_text(paths, to), "primer.yaml")
    assert made.host is not None
    return made.host.routes["api"]


# --- probes ---------------------------------------------------------------------


def test_probe_DM_147_a_path_gets_its_timeout_and_no_buffering_the_rest_as_before(
    tmp_path: Path,
) -> None:
    """The path's ``location`` has its own timeout and ``proxy_buffering off``,
    an exact path its own timeout and the buffering as it is; the pair:
    ``location /`` of the same route is the one rendered without paths, and so
    is the frontend's server."""
    text = rendered(tmp_path, product(routes=routes(paths=PATHS)))
    before = rendered(tmp_path, product(routes=routes()))
    api, was = server_of(text, DOMAINS["api"]), server_of(before, DOMAINS["api"])
    assert location(api, "location /api/stream/") == "\n".join(
        [
            "  location /api/stream/ {",
            "    set $upstream http://blank-app:8000;",
            "    proxy_pass $upstream;",
            "    proxy_http_version 1.1;",
            "    proxy_set_header Host $host;",
            "    proxy_set_header X-Real-IP $remote_addr;",
            "    proxy_set_header X-Forwarded-For $remote_addr;",
            "    proxy_set_header X-Forwarded-Proto https;",
            "    proxy_set_header X-Forwarded-Host $host;",
            "    proxy_set_header X-Forwarded-Port 443;",
            '    proxy_set_header X-Forwarded-Prefix "";',
            '    proxy_set_header Forwarded "";',
            "    proxy_read_timeout 3600s;",
            "    proxy_buffering off;",
            '    add_header Strict-Transport-Security "max-age=31536000; '
            'includeSubDomains" always;',
            '    add_header X-Content-Type-Options "nosniff" always;',
            "  }",
        ]
    )
    poll = location(api, "location = /api/agent/poll")
    assert "    proxy_read_timeout 900s;\n" in poll
    assert "proxy_buffering" not in poll and "proxy_pass $upstream;" in poll
    # the pair: the rest of the domain is as it was
    assert location(api, "location /") == location(was, "location /")
    assert "proxy_buffering" not in location(api, "location /")
    assert api.count("location ") == was.count("location ") + 2
    front = DOMAINS["frontend"]
    assert server_of(text, front) == server_of(before, front)


def test_probe_DM_147_an_unknown_knob_of_a_path_is_red_at_the_loader() -> None:
    """A knob a path does not have -- ``gzip``, or ``to``: the routing of paths
    is the frontend's (contract 3 rule 4) -- is red before any step; the pair:
    the same path with its two knobs loads."""
    where = "host.routes.api.paths./api/stream/"
    for knob, value in (("gzip", "off"), ("to", "app:8000"), ("max_body", "1M")):
        paths = {"/api/stream/": {"read_timeout": "60s", knob: value}}
        assert refused(paths) == [("extra_forbidden", f"{where}.{knob}")], knob
    route = loads({"/api/stream/": {"read_timeout": "60s", "buffering": False}})
    assert route.paths == {
        "/api/stream/": RoutePath(read_timeout="60s", buffering=False)
    }


# --- the form of a path (S.route-path) ------------------------------------------


@pytest.mark.parametrize(
    "path",
    [
        "api/stream/",  # relative
        "/",  # the whole domain: the route's own knobs
        "/a/../b",
        "/a/..",
        "/a/./b",
        "/.",
        "/a//b",
        "//a",
        "/a//",
        "/a b",
        "/a;b",
        "/a{b",
        "/a}b",
        '/a"b',
        "/a'b",
        "/a\nb",
        "/a$b",
        "/a?b",
        "/a#b",
    ],
)
def test_a_path_that_is_not_plain_and_normalized_is_refused(path: str) -> None:
    problems = refused({path: {"read_timeout": "60s"}})
    assert [code for code, _ in problems] == ["S.route-path"], problems


@pytest.mark.parametrize(
    "path", ["/a", "/a/", "/a/b.c~d_e-f/", "/a.b", "/..a/", "/a.."]
)
def test_a_plain_normalized_path_loads(path: str) -> None:
    assert list(loads({path: {"read_timeout": "60s"}}).paths) == [path]


def test_a_path_without_a_knob_or_with_buffering_on_is_refused() -> None:
    """No knob says nothing; ``buffering: true`` is every path's -- one way to
    say one thing. The pair: each knob alone loads."""
    assert [c for c, _ in refused({"/a/": {}})] == ["S.route-path"]
    assert [c for c, _ in refused({"/a/": {"buffering": True}})] == ["literal_error"]
    assert loads({"/a/": {"buffering": False}}).paths["/a/"].read_timeout is None
    assert loads({"/a/": {"read_timeout": "1h"}}).paths["/a/"].buffering is None


def test_a_path_timeout_has_the_form_of_the_route_s() -> None:
    assert [c for c, _ in refused({"/a/": {"read_timeout": "5 min"}})] == [
        "string_pattern_mismatch"
    ]


def test_empty_paths_are_no_paths(tmp_path: Path) -> None:
    """``paths: {}`` -- the route as it is without the key."""
    assert loads({}).paths == {}
    with_empty = rendered(tmp_path, product(routes=routes(paths={})))
    assert with_empty == rendered(tmp_path, product(routes=routes()))


# --- what the machine closes (R4.route-path-closed) -----------------------------


def test_a_path_on_what_the_machine_closes_is_refused() -> None:
    """``health`` and ``ready`` of the route's app, or under them, and anything
    under ``/__pridem/`` (the preview link) -- each refused, each part of the
    rule alone; the pair: a neighbour of each name loads."""
    for path in ("/h", "/h/", "/h/x", "/r", "/r/deep/", "/__pridem/", "/__pridem/x"):
        assert refused({path: {"read_timeout": "60s"}}) == [
            ("R4.route-path-closed", f"host.routes.api.paths.{path}")
        ], path
    for path in ("/hx", "/h2/", "/rr", "/__pridemx/", "/x/h/", "/x/__pridem/"):
        assert list(loads({path: {"read_timeout": "60s"}}).paths) == [path], path
    assert PREVIEW_PATH.startswith(f"{MACHINE_PATHS}/")


def test_a_route_to_the_frontend_closes_only_the_machine_s_paths() -> None:
    assert list(loads({"/h/": {"buffering": False}}, to="frontend:80").paths) == ["/h/"]
    assert refused({"/__pridem/a": {"buffering": False}}, to="frontend:80") == [
        ("R4.route-path-closed", "host.routes.api.paths./__pridem/a")
    ]


def test_the_loader_closes_what_the_rendering_closes() -> None:
    """``route_closed`` of the loader and ``Target.closed`` of ``routes`` are one
    answer for every route: two readings of the same ``to``."""
    stacks = {
        "blank": {
            "compose": "c.yml",
            "app": {"service": "app", "port": 8000, "health": "/h", "ready": "/r"},
            "frontend": {"service": "frontend", "port": 80},
        },
        "files": {
            "compose": "f.yml",
            "app": {"service": "files", "port": 9000, "health": "/z", "ready": "/z"},
        },
    }
    made = product(
        routes={
            "frontend": {"to": "frontend:80"},
            "api": {"to": "files:9000"},
        },
        stacks=stacks,
    )
    found = targets(made)
    assert made.host is not None
    for name, route in made.host.routes.items():
        assert route_closed(made, route) == found[name].closed, name
    assert found["api"].closed == ("/z",)


# --- the location of a path is location / in all but its knobs ------------------


def test_every_location_of_a_path_on_preview_asks_the_cookie(tmp_path: Path) -> None:
    """Without the check a path of a preview box is open without the link."""
    text = rendered(tmp_path, product(routes=routes(paths=PATHS)), role="preview")
    api = server_of(text, DOMAINS["api"])
    check = f'    if ($cookie_pridem_preview != "{LINK}") {{ return 404; }}\n'
    for head in ("location /api/stream/", "location = /api/agent/poll", "location /"):
        assert location(api, head).startswith(f"  {head} {{\n{check}"), head
    assert api.count(check) == 3


def test_every_location_of_a_path_carries_the_headers(tmp_path: Path) -> None:
    """``add_header`` in a location hides the server's: HSTS, nosniff, the CSP
    and noindex are in each path's location as in ``location /``; without a
    CSP there is none anywhere."""
    made = product(routes=routes(paths=PATHS), csp=CSP)
    api = server_of(rendered(tmp_path, made, role="preview"), DOMAINS["api"])
    lines = [
        'add_header Strict-Transport-Security "max-age=31536000; '
        'includeSubDomains" always;',
        'add_header X-Content-Type-Options "nosniff" always;',
        f'add_header Content-Security-Policy "{CSP}" always;',
        'add_header X-Robots-Tag "noindex, nofollow" always;',
    ]
    tail = "".join(f"    {line}\n" for line in lines) + "  }"
    for head in ("location /api/stream/", "location = /api/agent/poll", "location /"):
        assert location(api, head).endswith(tail), head
    plain = server_of(
        rendered(tmp_path, product(routes=routes(paths=PATHS))), DOMAINS["api"]
    )
    assert "Content-Security-Policy" not in plain and "X-Robots-Tag" not in plain


def test_a_path_without_its_own_timeout_takes_the_route_s(tmp_path: Path) -> None:
    """A location inherits no ``proxy_read_timeout`` from its sibling: a path
    with ``buffering: false`` alone repeats the route's; a route without one
    gives none -- nginx's own, as ``location /`` has."""
    only = {"/sse/": {"buffering": False}}
    api = server_of(
        rendered(tmp_path, product(routes=routes(paths=only))), DOMAINS["api"]
    )
    sse = location(api, "location /sse/")
    assert "    proxy_read_timeout 300s;\n    proxy_buffering off;\n" in sse
    bare = {"to": "app:8000", "paths": only}
    plain = rendered(
        tmp_path, product(routes={"frontend": {"to": "frontend:80"}, "api": bare})
    )
    sse = location(server_of(plain, DOMAINS["api"]), "location /sse/")
    assert "proxy_read_timeout" not in sse and "    proxy_buffering off;\n" in sse


def test_every_path_and_its_order_in_the_file(tmp_path: Path) -> None:
    """Each path its own location, in the file's order, after the closed ones
    and before ``location /``; a prefix and an exact address of one name, and
    a path under another, are each their own."""
    paths: dict[str, object] = {
        "/a/": {"read_timeout": "1s"},
        "/a": {"read_timeout": "2s"},
        "/a/b/": {"read_timeout": "3s"},
    }
    api = server_of(
        rendered(tmp_path, product(routes=routes(paths=paths))), DOMAINS["api"]
    )
    heads = re.findall(r"^  (location [^{]*?) \{", api, re.M)
    assert heads == [
        "location = /h",
        "location = /r",
        "location /a/",
        "location = /a",
        "location /a/b/",
        "location /",
    ]
    for head, timeout in (("location /a/", "1s"), ("location = /a", "2s")):
        assert f"proxy_read_timeout {timeout};" in location(api, head)
    assert "proxy_read_timeout 3s;" in location(api, "location /a/b/")


def test_the_rendering_refuses_a_path_that_reads_as_more_than_a_path(
    tmp_path: Path,
) -> None:
    """The second line (par0 14.4): a path that passed no loader -- a model
    built around it -- is refused before a line of it is written."""
    made = product(routes=routes(paths=PATHS))
    assert made.host is not None
    for bad in ("/a b", "/a;}", "/a\n}"):
        route = made.host.routes["api"].model_copy(
            update={"paths": {bad: RoutePath(read_timeout="1s")}}
        )
        host = made.host.model_copy(
            update={"routes": {**made.host.routes, "api": route}}
        )
        broken = made.model_copy(update={"host": host})
        with pytest.raises(StepFailed) as caught:
            rendered(tmp_path, broken)
        assert caught.value.args == ("path-unsafe",), bad
        assert caught.value.reason.params == {"route": "api", "path": bad}, bad


def test_a_route_without_paths_renders_as_before_them(tmp_path: Path) -> None:
    """Byte for byte the rendering of ``primer@7e69082`` (no paths yet): a box
    updated to this machine has no drift on routes without paths."""
    made = product(routes=routes(), csp=CSP)
    text = rendered(tmp_path / "t", made) + rendered(tmp_path / "p", made, "preview")
    assert text == GOLDEN.read_text(encoding="utf-8")
