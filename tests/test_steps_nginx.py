"""``nginx`` (DM-17): the config from ``host.routes``, aliases on the network
``pridem``, normalized drift, ``nginx -t`` aside before anything is in place,
the ``preview`` role on every route."""

import json
import re
from pathlib import Path

import pytest
import yaml
from compose_support import CONFIG
from edge_support import (
    DOMAINS,
    Mixed,
    exec_call,
    passport,
    product,
    ps_call,
    run,
    self_signed_pair,
)

from pridem.events import Secrets
from pridem.report.codes import ExitCode
from pridem.runner import FakeCall
from pridem.stacks.loader import ContractError
from pridem.stacks.routes import drift, normalized, render, targets
from pridem.stacks.schema import load_primer_yaml
from pridem.steps.base import StepFailed
from pridem.steps.compose import ComposeStack, override_text
from pridem.steps.edge import (
    NGINX_IMAGE,
    argv,
    candidate_dir,
    certs_dir,
    compose_file,
    compose_text,
    live_config,
    mode_of,
)
from pridem.steps.nginx import PREVIEW_SECRET, Nginx
from pridem.steps.passport import Fetched


def nginx_t(root: Path, code: int = 0) -> FakeCall:
    return FakeCall(
        (
            "docker",
            "run",
            "--rm",
            "--label",
            "pridem.stack=edge",
            "-v",
            f"{candidate_dir(root)}:/etc/nginx/conf.d:ro",
            "-v",
            f"{certs_dir(root)}:/etc/pridem/certs:ro",
            NGINX_IMAGE,
            "nginx",
            "-t",
        ),
        code=code,
    )


def step(
    root: Path, fetched: Fetched, secrets: Secrets | None = None, **made: object
) -> Nginx:
    return Nginx(
        product(**made),  # type: ignore[arg-type]
        fetched=fetched,
        secrets=Secrets(()) if secrets is None else secrets,
        root=root,
    )


def first_install(root: Path) -> list[FakeCall]:
    """check (no live config: no need to ask), act (test aside, start), verify."""
    return [
        nginx_t(root),
        ps_call(root, running=False),
        FakeCall(tuple(argv(root, "up", "-d", "nginx"))),
        ps_call(root, running=True),
        exec_call(root, "nginx", "-t"),
    ]


# --- probes ---------------------------------------------------------------------


def test_probe_DM_17_unknown_knob_is_red(tmp_path: Path) -> None:
    data = {
        "schema": 1,
        "name": "blank",
        "kind": "product",
        "stacks": {
            "blank": {
                "compose": "c.yml",
                "app": {"service": "app", "port": 8000, "health": "/h", "ready": "/r"},
            }
        },
        "env": {},
        "host": {
            "domains": ["api"],
            "routes": {"api": {"to": "app:8000", "gzip": "on"}},
        },
        "report": {"health": "/h", "ready": "/r", "logs": "json", "junit": True},
    }
    file = tmp_path / "primer.yaml"
    file.write_text(yaml.safe_dump(data))
    with pytest.raises(ContractError):
        load_primer_yaml(file)
    # the pair: every known knob is rendered
    _, fetched = passport(tmp_path)
    assert fetched.passport is not None
    made = product(
        routes={"api": {"to": "app:8000", "max_body": "100M", "read_timeout": "300s"}},
        csp="default-src 'self'",
    )
    text = render(made, fetched.passport, None)
    for line in (
        "client_max_body_size 100M;",
        "proxy_read_timeout 300s;",
        "add_header Content-Security-Policy \"default-src 'self'\" always;",
        "add_header Strict-Transport-Security"
        ' "max-age=31536000; includeSubDomains" always;',
        'add_header X-Content-Type-Options "nosniff" always;',
        "location / { return 301 https://$host$request_uri; }",
        "location /.well-known/acme-challenge/ { root /var/www/acme; }",
        "gzip on;",
    ):
        assert line in normalized(text), line


def test_probe_DM_17_route_targets_the_stack_alias_on_the_shared_network(
    tmp_path: Path,
) -> None:
    stacks = {
        "aivis": {
            "compose": "docker-compose.yml",
            "app": {"service": "app", "port": 8000, "health": "/h", "ready": "/r"},
            "frontend": {"service": "frontend", "port": 80},
        },
        "storage": {
            "compose": "storage.yml",
            "app": {"service": "app", "port": 9000, "health": "/h", "ready": "/r"},
        },
    }
    routes = {
        "frontend": {"to": "frontend:80"},
        "api": {"to": "app:8000"},
        "files": {"to": "app:9000"},
    }
    made = product(routes=routes, stacks=stacks)
    _, fetched = passport(tmp_path, domains={**DOMAINS, "files": "files.example.org"})
    assert fetched.passport is not None
    text = normalized(render(made, fetched.passport, None))
    assert "set $upstream http://aivis-app:8000;" in text
    assert (
        "set $upstream http://storage-app:9000;" in text
    )  # the same service, two stacks
    assert "set $upstream http://aivis-frontend:80;" in text
    # the override of each stack gives the alias the route goes to
    for entry, service, port in (("aivis", "frontend", 80), ("storage", "app", 9000)):
        cs = ComposeStack(made, entry, tmp_path, "main", "0" * 40, tmp_path)
        document = json.loads(json.dumps(CONFIG))
        document["services"] = {service: {"networks": {"default": None}}}
        rendered = json.loads(override_text(cs, document))
        assert rendered["services"][service]["networks"]["pridem"] == {
            "aliases": [f"{entry}-{service}"]
        }, (entry, port)


def test_probe_DM_17_comment_change_in_live_config_is_not_drift(tmp_path: Path) -> None:
    root, fetched = passport(tmp_path)
    nginx = step(root, fetched)
    assert fetched.passport is not None
    text = render(nginx.product, fetched.passport, None)
    commented = "# edited by hand\n\n" + text.replace(
        "  listen", "      listen  "
    ).replace("gzip on;", "gzip   on;   # on")
    assert drift(commented, text) == []
    live_config(root).parent.mkdir(parents=True)
    live_config(root).write_text(commented)
    compose_file(root).write_text(compose_text(root))
    with Mixed(
        ps_call(root, running=True),
        ps_call(root, running=True),
        exec_call(root, "nginx", "-t"),
    ) as runner:
        outcome, _ = run([nginx], runner)  # no test, no reload, no up
    assert outcome.code is ExitCode.OK, outcome.steps


def test_probe_DM_17_domain_change_is_drift(tmp_path: Path) -> None:
    root, fetched = passport(tmp_path)
    nginx = step(root, fetched)
    assert fetched.passport is not None
    text = render(nginx.product, fetched.passport, None)
    live_config(root).parent.mkdir(parents=True)
    live_config(root).write_text(
        text.replace("api.blank.example.org", "api.old.example.org")
    )
    compose_file(root).write_text(compose_text(root))
    with Mixed() as runner:  # the drift alone says act; nothing is asked
        outcome, _ = run([nginx], runner, mode="doctor")
    [item] = outcome.doctor_diff
    assert item.reason.code == "nginx:render"
    diff = item.reason.params["diff"]
    assert isinstance(diff, list)
    assert "-server_name api.old.example.org;" in diff
    assert "+server_name api.blank.example.org;" in diff


def test_probe_DM_17_nginx_t_red_prevents_reload(tmp_path: Path) -> None:
    root, fetched = passport(tmp_path)
    old = "# the config that serves now\n"
    live_config(root).parent.mkdir(parents=True)
    live_config(root).write_text(old)
    compose_file(root).write_text(compose_text(root))
    script = [nginx_t(root, code=1)]
    with Mixed(*script) as runner:  # no reload, no up after the red test
        outcome, _ = run([step(root, fetched)], runner)
    assert outcome.steps[0].reason is not None
    assert outcome.steps[0].reason.code == "nginx:config-invalid"
    assert live_config(root).read_text() == old  # the live file was never replaced
    assert not list(candidate_dir(root).iterdir())
    # the pair: green test -- the file is replaced, then the running nginx reloads
    script = [
        nginx_t(root),
        ps_call(root, running=True),
        exec_call(root, "nginx", "-s", "reload"),
        ps_call(root, running=True),
        exec_call(root, "nginx", "-t"),
    ]
    with Mixed(*script) as runner:
        outcome, _ = run([step(root, fetched)], runner)
    assert outcome.code is ExitCode.OK, outcome.steps
    assert live_config(root).read_text() != old
    assert mode_of(live_config(root)) == oct(0o600)


def test_probe_DM_17_preview_role_sets_noindex_on_every_route(tmp_path: Path) -> None:
    root, fetched = passport(tmp_path, role="preview")
    secrets = Secrets(())
    nginx = step(root, fetched, secrets)
    with Mixed(*first_install(root)) as runner:
        outcome, _ = run([nginx], runner)
    assert outcome.code is ExitCode.OK, outcome.steps
    secret = (root / PREVIEW_SECRET).read_text()
    assert mode_of(root / PREVIEW_SECRET) == oct(0o600)
    assert secrets.text(secret) == "[redacted]"
    text = live_config(root).read_text()
    blocks = re.findall(r"location / \{\n.*?\n  \}", text, re.S)
    assert len(blocks) == 2  # one per route
    for block in blocks:
        assert 'add_header X-Robots-Tag "noindex, nofollow" always;' in block
        assert f'if ($cookie_pridem_preview != "{secret}") {{ return 404; }}' in block
    assert text.count("location = /__pridem/preview {") == 2
    # the pair: test and prod have neither
    _, plain = passport(tmp_path / "t")
    assert plain.passport is not None
    other = render(nginx.product, plain.passport, None)
    assert "X-Robots-Tag" not in other and "pridem_preview" not in other


# --- the rest -------------------------------------------------------------------


def test_first_install_starts_nginx_with_the_compose_of_edge(tmp_path: Path) -> None:
    root, fetched = passport(tmp_path)
    with Mixed(*first_install(root)) as runner:
        outcome, _ = run([step(root, fetched)], runner)
    assert outcome.code is ExitCode.OK, outcome.steps
    assert outcome.steps[0].verify == {
        "config": str(live_config(root)),
        "routes": 2,
        "mode": oct(0o600),
        "preview": False,
    }
    document = json.loads(compose_file(root).read_text())
    nginx = document["services"]["nginx"]
    assert nginx["image"] == NGINX_IMAGE and "@sha256:" in nginx["image"]
    assert nginx["ports"] == ["80:80", "443:443"] and nginx["networks"] == ["pridem"]
    assert document["services"]["certbot"]["profiles"] == ["certbot"]


@pytest.mark.parametrize(
    ("routes", "code"),
    [
        ({"api": {"to": "app:9999"}}, "route-target-unknown"),
        ({"mail": {"to": "app:8000"}}, "domain-missing"),
    ],
)
def test_a_route_that_leads_nowhere_is_red_before_act(
    tmp_path: Path, routes: dict[str, dict[str, str]], code: str
) -> None:
    root, fetched = passport(tmp_path)
    with Mixed() as runner:  # nothing runs
        outcome, _ = run([step(root, fetched, routes=routes)], runner)
    assert outcome.steps[0].reason is not None
    assert outcome.steps[0].reason.code == f"nginx:{code}"


def test_a_route_declared_by_two_stacks_is_ambiguous() -> None:
    stacks = {
        "a": {
            "compose": "a.yml",
            "app": {"service": "app", "port": 8000, "health": "/h", "ready": "/r"},
        },
        "b": {
            "compose": "b.yml",
            "app": {"service": "app", "port": 8000, "health": "/h", "ready": "/r"},
        },
    }
    with pytest.raises(StepFailed) as failed:
        targets(product(routes={"api": {"to": "app:8000"}}, stacks=stacks))
    assert failed.value.reason.code == "route-ambiguous"


def test_a_header_value_nginx_would_read_otherwise_is_refused(tmp_path: Path) -> None:
    _, fetched = passport(tmp_path)
    assert fetched.passport is not None
    with pytest.raises(StepFailed) as failed:
        render(product(csp='default-src "self"'), fetched.passport, None)
    assert failed.value.reason.code == "header-unsafe"


def test_certificates_exist_before_the_test_aside(tmp_path: Path) -> None:
    """nginx -t reads the certificate: tls_files places it first (order 1)."""
    root, _ = passport(tmp_path)
    cert, key = self_signed_pair(tmp_path, list(DOMAINS.values()))
    assert "BEGIN CERTIFICATE" in cert and "PRIVATE KEY" in key
    assert Nginx.order > 1
