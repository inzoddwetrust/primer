"""State grid of primer.yaml (DM-3): fields, sources, rules, error layers, paths."""

from pathlib import Path

import pytest
from contract_support import example, node, yaml_messages, yaml_problems

from pridem.stacks.schema import Product, Service, load_primer_yaml

# --- the contract's examples -------------------------------------------------


def test_examples_load_and_are_not_empty() -> None:
    from contract_support import FIXTURES

    product = load_primer_yaml(FIXTURES / "product.yaml")
    service = load_primer_yaml(FIXTURES / "service.yaml")
    assert isinstance(product, Product)
    assert isinstance(service, Service)
    assert len(product.env) == 8
    assert set(product.dependencies) == {"comms", "payments", "meet"}
    assert len(product.packages["texts"].mount) == 2
    assert product.stacks["storage"].persistent is True
    assert product.stacks["storage"].app is None
    assert product.stacks["aivis"].persistent is False
    assert product.verbs["email-status"].roles is None
    assert service.update_window is not None
    assert service.provides == [
        "COMMS_API_URL",
        "COMMS_SERVICE_TOKEN",
        "TELEGRAM_BOT_URL",
    ]


# --- schema, kind, unknown keys, null -------------------------------------------


@pytest.mark.parametrize("value", [2, True, 1.0, "1"])
def test_schema_is_exactly_integer_one(tmp_path: Path, value: object) -> None:
    data = example("product.yaml")
    data["schema"] = value
    assert [path for path, _ in yaml_problems(tmp_path, data)] == ["schema"]


def test_schema_missing(tmp_path: Path) -> None:
    data = example("service.yaml")
    del data["schema"]
    assert yaml_problems(tmp_path, data) == [("schema", "missing")]


@pytest.mark.parametrize(
    ("kind", "code"), [("machine", "union_tag_invalid"), (None, "")]
)
def test_kind_other_or_missing(tmp_path: Path, kind: str | None, code: str) -> None:
    data = example("product.yaml")
    if kind is None:
        del data["kind"]
        expected = "union_tag_not_found"
    else:
        data["kind"] = kind
        expected = code
    assert yaml_problems(tmp_path, data) == [("", expected)]


@pytest.mark.parametrize(
    ("keys", "path"),
    [
        ((), "typo"),
        (("stacks", "aivis"), "stacks.aivis.typo"),
        (("stacks", "aivis", "app"), "stacks.aivis.app.typo"),
        (("env", "EDITION"), "env.EDITION.typo"),
        (("packages", "texts", "mount", 1), "packages.texts.mount[1].typo"),
        (("report",), "report.typo"),
    ],
)
def test_unknown_key_at_any_depth_names_the_path(
    tmp_path: Path, keys: tuple[str | int, ...], path: str
) -> None:
    data = example("product.yaml")
    node(data, *keys)["typo"] = "x"
    assert yaml_problems(tmp_path, data) == [(path, "extra_forbidden")]


def test_explicit_null_is_an_error_absence_is_not(tmp_path: Path) -> None:
    data = example("product.yaml")
    data["host"] = None
    assert yaml_problems(tmp_path, data) == [("", "null_forbidden")]
    assert "host" in yaml_messages(tmp_path, data)[0]
    del data["host"]
    assert yaml_problems(tmp_path, data) == []


def test_required_fields(tmp_path: Path) -> None:
    data = example("product.yaml")
    for key in ("name", "stacks", "report"):
        del data[key]
    assert yaml_problems(tmp_path, data) == [
        ("name", "missing"),
        ("stacks", "missing"),
        ("report", "missing"),
    ]


def test_stacks_need_at_least_one_and_compose(tmp_path: Path) -> None:
    data = example("product.yaml")
    data["stacks"] = {}
    assert yaml_problems(tmp_path, data) == [("stacks", "too_short")]
    data["stacks"] = {"x": {"persistent": True}}
    assert yaml_problems(tmp_path, data) == [("stacks.x.compose", "missing")]


# --- strict types (YAML 1.1 implicit typing) --------------------------------


@pytest.mark.parametrize(
    ("keys", "field", "value", "code"),
    [
        ((), "name", True, "string_type"),
        (("stacks", "aivis", "app"), "port", "8000", "int_type"),
        (("stacks", "aivis", "app"), "port", True, "int_type"),
        (("stacks", "storage"), "persistent", "yes", "bool_type"),
        (("dependencies", "comms"), "version", 3.0, "string_type"),
        (("report",), "junit", "true", "bool_type"),
    ],
)
def test_strict_types(
    tmp_path: Path, keys: tuple[str, ...], field: str, value: object, code: str
) -> None:
    data = example("product.yaml")
    node(data, *keys)[field] = value
    path = ".".join((*keys, field))
    assert yaml_problems(tmp_path, data) == [(path, code)]


# --- env sources -------------------------------------------------------------------


@pytest.mark.parametrize(
    ("entry", "found"),
    [
        ({"source": "derived"}, [("env.X.run", "missing")]),
        ({"source": "passport"}, [("env.X.key", "missing")]),
        ({"source": "seam"}, [("env.X.from", "missing")]),
        ({"source": "minted", "run": "x"}, [("env.X.run", "extra_forbidden")]),
        ({"source": "asked", "key": "x"}, [("env.X.key", "extra_forbidden")]),
        ({"source": "vault"}, [("env.X", "union_tag_invalid")]),
        ({"run": "x"}, [("env.X", "union_tag_not_found")]),
        ({"source": "asked", "value": "x"}, [("env.X", "R1.value")]),
        ({"source": "fixed"}, [("env.X", "R1.value")]),
        ({"source": "file", "path": "x"}, [("env.X", "R5.file-seam")]),
        (
            {"source": "passport", "key": "edition", "enum": "plans"},
            [("env.X.enum", "literal_error")],
        ),
    ],
)
def test_env_sources(
    tmp_path: Path, entry: dict[str, object], found: list[tuple[str, str]]
) -> None:
    data = example("product.yaml")
    node(data, "env")["X"] = entry
    assert yaml_problems(tmp_path, data) == found


@pytest.mark.parametrize("source", ["minted", "asked"])
def test_sources_without_fields(tmp_path: Path, source: str) -> None:
    data = example("service.yaml")
    node(data, "env")["X"] = {"source": source}
    assert yaml_problems(tmp_path, data) == []


def test_rule_1_and_5_messages_carry_the_rule(tmp_path: Path) -> None:
    data = example("product.yaml")
    node(data, "env")["A"] = {"source": "minted", "value": "x"}
    node(data, "env")["B"] = {"source": "file"}
    assert [m.split(":")[0] for m in yaml_messages(tmp_path, data)] == [
        "contract rule 1",
        "contract rule 5",
    ]


# --- dependencies ------------------------------------------------------------------


@pytest.mark.parametrize("version", ["3.0", "latest", "", " ", ">=3.0;<4"])
def test_dependency_range_must_parse(tmp_path: Path, version: str) -> None:
    data = example("product.yaml")
    node(data, "dependencies", "comms")["version"] = version
    assert yaml_problems(tmp_path, data) == [
        ("dependencies.comms.version", "value_error")
    ]


def test_dependency_topology_and_branch(tmp_path: Path) -> None:
    data = example("product.yaml")
    node(data, "dependencies", "comms")["topology"] = "local"
    node(data, "dependencies", "payments")["branch"] = "main"
    node(data, "dependencies", "meet")["ref"] = "main"
    assert yaml_problems(tmp_path, data) == [
        ("dependencies.comms.topology", "literal_error"),
        ("dependencies.payments", "R9.branch"),
        ("dependencies.meet.ref", "extra_forbidden"),
    ]


# --- editions ----------------------------------------------------------------------


def test_no_editions_is_valid(tmp_path: Path) -> None:
    data = example("product.yaml")
    del data["editions"]
    del node(data, "env")["EDITION"]
    assert yaml_problems(tmp_path, data) == []


def test_enum_editions_needs_editions(tmp_path: Path) -> None:
    data = example("product.yaml")
    del data["editions"]
    assert yaml_problems(tmp_path, data) == [("env.EDITION.enum", "R11.edition-enum")]


def test_edition_with_no_services_is_valid(tmp_path: Path) -> None:
    data = example("product.yaml")
    node(data, "editions")["core"] = {"services": []}
    assert yaml_problems(tmp_path, data) == []


# --- host --------------------------------------------------------------------------


def test_route_domain_outside_host_domains(tmp_path: Path) -> None:
    data = example("product.yaml")
    node(data, "host", "routes")["admin"] = {"to": "app:8000"}
    assert yaml_problems(tmp_path, data) == [("host.routes.admin", "R4.route-domain")]


@pytest.mark.parametrize(
    ("knob", "value"),
    [
        ("to", "app"),
        ("to", "app: 8000"),
        ("max_body", "100MB"),
        ("read_timeout", "5 min"),
    ],
)
def test_route_knob_formats(tmp_path: Path, knob: str, value: str) -> None:
    data = example("product.yaml")
    node(data, "host", "routes", "api")[knob] = value
    assert yaml_problems(tmp_path, data) == [
        (f"host.routes.api.{knob}", "string_pattern_mismatch")
    ]


def test_service_host_has_no_routes_and_takes_ports(tmp_path: Path) -> None:
    data = example("service.yaml")
    node(data, "host")["ports"] = [{"proto": "udp", "port": 10000}]
    assert yaml_problems(tmp_path, data) == []
    node(data, "host")["ports"] = [{"proto": "sctp", "port": 0}]
    node(data, "host")["routes"] = {}
    assert yaml_problems(tmp_path, data) == [
        ("host.ports[0].proto", "literal_error"),
        ("host.ports[0].port", "greater_than_equal"),
        ("host.routes", "extra_forbidden"),
    ]


# --- packages (rule 10) ---------------------------------------------------------


@pytest.mark.parametrize(
    ("mount", "found"),
    [
        ({"service": "frontend", "path": "/srv/skin"}, []),
        ({"service": "frontend", "from": "ui/dark", "path": "/srv/x"}, []),
        ({"dependency": "comms", "env": "DIR"}, []),
        ({"path": "/srv/x"}, [("m", "R10.mount")]),
        ({"service": "a", "dependency": "comms", "path": "/x", "env": "D"}, None),
        ({"service": "frontend"}, [("m", "R10.mount")]),
        ({"service": "frontend", "path": "srv/x"}, [("m.path", "R10.mount")]),
        ({"service": "frontend", "path": "/srv/../x"}, [("m.path", "R10.mount")]),
        ({"service": "frontend", "path": "/srv//x"}, [("m.path", "R10.mount")]),
        ({"service": "frontend", "path": "/srv/./x"}, [("m.path", "R10.mount")]),
        ({"service": "frontend", "path": "/srv/x/"}, [("m.path", "R10.mount")]),
        ({"service": "frontend", "path": "/x", "env": "D"}, [("m.env", "R10.mount")]),
        ({"dependency": "comms"}, [("m", "R10.mount")]),
        ({"dependency": "comms", "env": "D", "path": "/x"}, [("m.path", "R10.mount")]),
        (
            {"dependency": "comms", "env": "D", "from": "/abs"},
            [("m.from", "R10.mount")],
        ),
        (
            {"dependency": "comms", "env": "D", "from": "../up"},
            [("m.from", "R10.mount")],
        ),
        (
            {"dependency": "comms", "env": "D", "from": "a/../b"},
            [("m.from", "R10.mount")],
        ),
        ({"dependency": "comms", "env": "D", "from": ""}, [("m.from", "R10.mount")]),
    ],
)
def test_package_mount(
    tmp_path: Path, mount: dict[str, object], found: list[tuple[str, str]] | None
) -> None:
    data = example("product.yaml")
    node(data, "packages", "skin")["mount"] = [mount]
    got = yaml_problems(tmp_path, data)
    prefix = "packages.skin.mount[0]"
    if found is None:
        assert got and all(code == "R10.mount" for _, code in got)
        assert ("packages.skin.mount[0]", "R10.mount") in got
    else:
        assert got == [(path.replace("m", prefix, 1), code) for path, code in found]


def test_package_needs_a_mount(tmp_path: Path) -> None:
    data = example("product.yaml")
    node(data, "packages", "skin")["mount"] = []
    assert yaml_problems(tmp_path, data) == [("packages.skin.mount", "too_short")]


# --- seams (rule 13 and references) ----------------------------------------------


def test_product_seam_references(tmp_path: Path) -> None:
    data = example("product.yaml")
    node(data, "env")["A"] = {"source": "seam", "from": "billing"}
    node(data, "env")["B"] = {"source": "seam", "from": "product"}
    node(data, "env")["C"] = {"source": "seam", "from": "meet"}
    assert yaml_problems(tmp_path, data) == [
        ("env.A.from", "S.seam-from"),
        ("env.B.from", "S.seam-from"),
        ("env.C.from", "R13.remote-seam"),
    ]


def test_service_seam_is_wired_to_product_only(tmp_path: Path) -> None:
    data = example("service.yaml")
    node(data, "env")["PRODUCT_WEBHOOK_URL"] = {"source": "seam", "from": "payments"}
    assert yaml_problems(tmp_path, data) == [
        ("env.PRODUCT_WEBHOOK_URL.from", "S.seam-from")
    ]


# --- verbs, stacks ----------------------------------------------------------------


@pytest.mark.parametrize(
    ("roles", "found"),
    [
        (["test", "prod", "preview"], []),
        (["staging"], [("verbs.setrole.roles[0]", "literal_error")]),
        ([], [("verbs.setrole.roles", "too_short")]),
    ],
)
def test_verb_roles(
    tmp_path: Path, roles: list[str], found: list[tuple[str, str]]
) -> None:
    data = example("product.yaml")
    node(data, "verbs", "setrole")["roles"] = roles
    assert yaml_problems(tmp_path, data) == found


@pytest.mark.parametrize("compose", ["/opt/x/compose.yml", "../compose.yml", ""])
def test_compose_is_a_relative_repo_path(tmp_path: Path, compose: str) -> None:
    data = example("product.yaml")
    node(data, "stacks", "aivis")["compose"] = compose
    assert yaml_problems(tmp_path, data) == [("stacks.aivis.compose", "value_error")]


# --- error layers -----------------------------------------------------------------


def test_every_rule_violation_at_once(tmp_path: Path) -> None:
    data = example("product.yaml")
    node(data, "host", "routes")["admin"] = {"to": "app:8000"}
    node(data, "editions")["full"] = {"services": ["billing"]}
    node(data, "env")["C"] = {"source": "seam", "from": "meet"}
    assert yaml_problems(tmp_path, data) == [
        ("host.routes.admin", "R4.route-domain"),
        ("editions.full.services[0]", "R11.edition-services"),
        ("env.C.from", "R13.remote-seam"),
    ]


def test_field_errors_come_before_rules(tmp_path: Path) -> None:
    data = example("product.yaml")
    node(data, "host", "routes")["admin"] = {"to": "app:8000"}
    data["name"] = 5
    assert yaml_problems(tmp_path, data) == [("name", "string_type")]


def test_paths_carry_no_union_tags(tmp_path: Path) -> None:
    data = example("product.yaml")
    node(data, "env")["X"] = {"source": "derived"}
    node(data, "provides")["P"] = {"from": "domains.api"}
    found = yaml_problems(tmp_path, data)
    assert ("env.X.run", "missing") in found
    assert all(path.startswith(("env.", "provides.")) for path, _ in found)
    assert all("derived" not in path and "product" not in path for path, _ in found)
