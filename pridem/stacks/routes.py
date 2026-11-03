"""The host of a product as nginx sees it (TZ 7.3; contract 3 rules 4, 15).

``host.routes`` is the whole dictionary of the host: a route is named by a
domain of ``host.domains`` and has exactly ``to``, ``max_body``,
``read_timeout``; ``headers`` has exactly ``csp``. The loader refuses any other
key (``Strict`` models), so an unknown knob is red before a step runs.

``to: <service>:<port>`` names no stack: its target is the entry of ``stacks``
that declares that pair as its ``app`` or its ``frontend``. None -- the route
leads nowhere; two -- it is ambiguous; both are red before ``act``. The target
is reached at ``<entry>-<service>`` on the network ``pridem`` (``alias``):
two entries with an ``app`` service are two aliases.

``render`` writes the nginx config of the box from the routes, the passport's
domains and its role. What the machine always sets is not a knob: HTTP to
HTTPS with 301 and the ACME challenge on port 80; HSTS, ``X-Content-Type-
Options``, gzip on every route; a default server that answers no unknown
host. A ``preview`` box (contract 1 rule 10) also sets ``noindex`` on every
route and lets in only a browser that came by the link with the secret: the
link sets a cookie, a request without it is 404. The link's request carries
the secret in its query, so it is never in the access log: its location has
``access_log off`` on 443 and, for a link opened over http, on port 80, where
it is redirected to https.

``/health`` and ``/ready`` are not seen from outside (protocol 9.3): a route
to an ``app`` answers 404 itself on that app's ``health`` and ``ready`` paths,
before anything is proxied (``location =``); the machine reads them on the
network ``pridem``. A path that could read as more than a path in the config
(``path-unsafe``) is refused before it is rendered.

``normalized`` is the config as nginx would read it -- comments, empty lines
and runs of blanks are not drift; a domain, a header, an order is.
"""

import difflib
import re
from collections.abc import Sequence
from dataclasses import dataclass

from pridem.events import Json
from pridem.stacks.passport import Passport
from pridem.stacks.schema import Product, Route
from pridem.steps.base import StepFailed

CERT = "/etc/pridem/certs/fullchain.pem"
KEY = "/etc/pridem/certs/privkey.pem"
ACME_ROOT = "/var/www/acme"
PREVIEW_PATH = "/__pridem/preview"
PREVIEW_COOKIE = "pridem_preview"
HSTS = "max-age=31536000; includeSubDomains"
GZIP_TYPES = "text/css application/javascript application/json image/svg+xml text/plain"
_UNSAFE = re.compile(r'["$\\\n\r]')
_PATH = re.compile(r"/[A-Za-z0-9._~/-]*")
_COMMENT = re.compile(r"#.*$")
_BLANKS = re.compile(r"\s+")


@dataclass(frozen=True)
class Target:
    """Where a route goes: an entry of ``stacks``, its service and port."""

    entry: str
    service: str
    port: int
    closed: tuple[str, ...] = ()
    """Paths nginx answers 404 itself: ``health`` and ``ready`` of an ``app``."""

    @property
    def alias(self) -> str:
        return alias(self.entry, self.service)


def alias(entry: str, service: str) -> str:
    """The name of a stack's service on the network ``pridem`` (TZ 7.3)."""
    return f"{entry}-{service}"


def _declared(product: Product) -> list[Target]:
    found: list[Target] = []
    for entry, stage in product.stacks.items():
        if stage.app is not None:
            app = stage.app
            paths = tuple(dict.fromkeys((app.health, app.ready)))  # one if the same
            found.append(Target(entry, app.service, app.port, paths))
        if stage.frontend is not None:
            found.append(Target(entry, stage.frontend.service, stage.frontend.port))
    return found


def targets(product: Product) -> dict[str, Target]:
    """The target of every route of ``product``, by route (domain) name."""
    host = product.host
    routes: dict[str, Route] = dict(host.routes) if host is not None else {}
    declared = _declared(product)
    out: dict[str, Target] = {}
    for name, route in routes.items():
        service, _, port = route.to.rpartition(":")
        found = [t for t in declared if (t.service, t.port) == (service, int(port))]
        if not found:
            raise StepFailed("route-target-unknown", {"route": name, "to": route.to})
        if len(found) > 1:
            entries: list[Json] = [t.entry for t in found]
            raise StepFailed(
                "route-ambiguous", {"route": name, "to": route.to, "stacks": entries}
            )
        out[name] = found[0]
    return out


def routed_services(product: Product, entry: str) -> list[str]:
    """The services of ``entry`` some route goes to: they need an alias."""
    return sorted({t.service for t in targets(product).values() if t.entry == entry})


def _closed(name: str, target: Target) -> list[str]:
    """The ``location`` of every path of ``target`` nginx answers itself: a
    path is written into the config as it is, so one that could read as more
    than a path is refused."""
    lines: list[str] = []
    for path in target.closed:
        if not _PATH.fullmatch(path):
            raise StepFailed("path-unsafe", {"route": name, "path": path})
        lines.append(f"  location = {path} {{ return 404; }}")
    return lines


def _quoted(name: str, value: str) -> str:
    if _UNSAFE.search(value):
        raise StepFailed("header-unsafe", {"header": name})
    return f'"{value}"'


def _headers(product: Product, preview: bool) -> list[str]:
    lines = [
        f"add_header Strict-Transport-Security {_quoted('hsts', HSTS)} always;",
        'add_header X-Content-Type-Options "nosniff" always;',
    ]
    headers = product.host.headers if product.host is not None else None
    if headers is not None and headers.csp is not None:
        csp = _quoted("csp", headers.csp)
        lines.append(f"add_header Content-Security-Policy {csp} always;")
    if preview:
        lines.append('add_header X-Robots-Tag "noindex, nofollow" always;')
    return lines


def _server(
    name: str,
    domain: str,
    route: Route,
    target: Target,
    headers: list[str],
    secret: str | None,
) -> list[str]:
    # add_header in a location hides the server's: every location repeats them
    inner = [f"    {line}" for line in headers]
    lines = [
        "server {",
        "  listen 443 ssl;",
        f"  server_name {domain};",
        f"  ssl_certificate {CERT};",
        f"  ssl_certificate_key {KEY};",
        "  gzip on;",
        f"  gzip_types {GZIP_TYPES};",
        "  resolver 127.0.0.11 valid=10s ipv6=off;",
    ]
    if route.max_body is not None:
        lines.append(f"  client_max_body_size {route.max_body};")
    if secret is not None:
        cookie = f"{PREVIEW_COOKIE}={secret}; Path=/; Secure; HttpOnly; SameSite=Lax"
        lines += [
            f"  location = {PREVIEW_PATH} {{",
            "    access_log off;  # the query holds the preview secret",
            f'    if ($arg_k != "{secret}") {{ return 404; }}',
            f'    add_header Set-Cookie "{cookie}" always;',
            *inner,
            "    return 302 /;",
            "  }",
        ]
    # what the machine reads of the app it reads on the network pridem, never
    # here (protocol 9.3); an exact location wins over the prefix / in nginx
    lines += _closed(name, target)
    lines += ["  location / {"]
    if secret is not None:
        lines.append(
            f'    if ($cookie_{PREVIEW_COOKIE} != "{secret}") {{ return 404; }}'
        )
    lines += [
        f"    set $upstream http://{target.alias}:{target.port};",
        "    proxy_pass $upstream;",
        "    proxy_http_version 1.1;",
        "    proxy_set_header Host $host;",
        "    proxy_set_header X-Real-IP $remote_addr;",
        "    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;",
        "    proxy_set_header X-Forwarded-Proto https;",
    ]
    if route.read_timeout is not None:
        lines.append(f"    proxy_read_timeout {route.read_timeout};")
    lines += [*inner, "  }", "}"]
    return lines


def render(product: Product, passport: Passport, secret: str | None) -> str:
    """The nginx config of the box. ``secret`` -- the preview link's, on a
    ``preview`` box; ``None`` elsewhere."""
    preview = passport.server.role == "preview"
    if preview != (secret is not None):
        raise ValueError("the preview secret goes with the preview role")
    host = product.host
    routes: dict[str, Route] = dict(host.routes) if host is not None else {}
    found = targets(product)
    headers = _headers(product, preview)
    lines = [
        "# rendered by pridem from host.routes of primer.yaml; an edit here is drift",
        "server {",
        "  listen 80 default_server;",
        "  server_name _;",
        f"  location /.well-known/acme-challenge/ {{ root {ACME_ROOT}; }}",
    ]
    if preview:  # the link opened over http: its query holds the secret
        lines += [
            f"  location = {PREVIEW_PATH} {{ access_log off; "
            "return 301 https://$host$request_uri; }",
        ]
    lines += [
        "  location / { return 301 https://$host$request_uri; }",
        "}",
    ]
    if routes:
        lines += [
            "server {",
            "  listen 443 ssl default_server;",
            "  server_name _;",
            f"  ssl_certificate {CERT};",
            f"  ssl_certificate_key {KEY};",
            "  return 444;",
            "}",
        ]
    for name, route in routes.items():
        domain = passport.domains.get(name)
        if domain is None:
            raise StepFailed("domain-missing", {"route": name})
        lines += _server(name, domain, route, found[name], headers, secret)
    return "\n".join(lines) + "\n"


def normalized(text: str) -> list[str]:
    """The config without comments, empty lines and runs of blanks."""
    out: list[str] = []
    for line in text.splitlines():
        kept = _BLANKS.sub(" ", _COMMENT.sub("", line)).strip()
        if kept:
            out.append(kept)
    return out


def drift(live: str | None, rendered: str) -> list[str]:
    """Unified diff of the normalized texts; empty -- no drift."""
    before = normalized(live) if live is not None else []
    return [
        line.rstrip("\n")
        for line in difflib.unified_diff(
            before, normalized(rendered), "live", "rendered", lineterm="", n=1
        )
    ]


def domains(product: Product, passport: Passport) -> list[str]:
    """The domains the routes answer on, in route order."""
    host = product.host
    names: Sequence[str] = list(host.routes) if host is not None else []
    return [passport.domains[name] for name in names if name in passport.domains]
