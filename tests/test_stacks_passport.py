"""State grid of the passport, contract 1 v1.4: fields, rules 1, 4, 5, 9, 10."""

from collections.abc import Callable
from datetime import UTC, date, datetime
from pathlib import Path

import pytest
from passport_support import (
    Data,
    everything_printed,
    passport_example,
    passport_messages,
    passport_problems,
    rejection,
    section,
    write_passport,
)

from pridem.stacks.passport import load_passport

AT = datetime(2026, 11, 1, tzinfo=UTC)
CERT = "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"
KEY = "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n"


def _with_role(data: Data, role: str, ref: str) -> Data:
    section(data, "server")["role"] = role
    section(data, "product")["ref"] = ref
    if role == "preview":
        section(data, "server")["expires_at"] = AT
    return data


def test_example_loads_with_secrets_hidden(tmp_path: Path) -> None:
    passport = load_passport(write_passport(tmp_path, passport_example()))
    assert passport.server.role == "test"
    assert passport.asked["comms"]["TELEGRAM_BOT_TOKEN"].get_secret_value() == "…"
    assert "…" not in repr(passport.asked)
    assert set(passport.packages) == {"skin", "texts"}


# --- rule 4: product.ref by role ------------------------------------------------


@pytest.mark.parametrize(
    ("role", "ref", "found"),
    [
        ("test", "main", []),
        ("test", "feature/x", []),
        ("test", "v1.2", []),  # a legal branch name, not a release tag
        ("test", "v1.2.3", [("product.ref", "R4.ref-branch")]),
        ("test", "9a1c4e2", [("product.ref", "R4.ref-branch")]),
        ("test", "a..b", [("product.ref", "R4.ref-branch")]),
        ("test", "-x", [("product.ref", "R4.ref-branch")]),
        ("test", "x.lock", [("product.ref", "R4.ref-branch")]),
        ("test", "a b", [("product.ref", "R4.ref-branch")]),
        ("prod", "v1.2.3", []),
        ("prod", "main", [("product.ref", "R4.ref-tag")]),
        ("prod", "9a1c4e2", [("product.ref", "R4.ref-tag")]),
        ("prod", "v1.2", [("product.ref", "R4.ref-tag")]),
        ("prod", "v1.2.3-rc1", [("product.ref", "R4.ref-tag")]),
        ("preview", "v0.1.0", []),
        ("preview", "main", [("product.ref", "R4.ref-tag")]),
        ("preview", "9a1c4e2", [("product.ref", "R4.ref-tag")]),
        ("test", "", [("product.ref", "string_too_short")]),
        ("staging", "main", [("server.role", "literal_error")]),
    ],
)
def test_ref_by_role(
    tmp_path: Path, role: str, ref: str, found: list[tuple[str, str]]
) -> None:
    data = _with_role(passport_example(), role, ref)
    assert passport_problems(tmp_path, data) == found


def test_ref_message_names_the_rule(tmp_path: Path) -> None:
    data = _with_role(passport_example(), "prod", "main")
    assert passport_messages(tmp_path, data) == [
        "passport rule 4: on roles prod and preview product.ref is a release tag "
        "vX.Y.Z: role prod with ref 'main'"
    ]


# --- rule 10: expires_at exactly on preview ----------------------------------------


@pytest.mark.parametrize(
    ("role", "ref", "has", "found"),
    [
        ("preview", "v1.0.0", True, []),
        ("preview", "v1.0.0", False, [("server.expires_at", "R10.expires")]),
        ("test", "main", True, [("server.expires_at", "R10.expires")]),
        ("test", "main", False, []),
        ("prod", "v1.0.0", True, [("server.expires_at", "R10.expires")]),
        ("prod", "v1.0.0", False, []),
    ],
)
def test_expires_only_on_preview(
    tmp_path: Path, role: str, ref: str, has: bool, found: list[tuple[str, str]]
) -> None:
    data = passport_example()
    section(data, "server")["role"] = role
    section(data, "product")["ref"] = ref
    if has:
        section(data, "server")["expires_at"] = AT
    assert passport_problems(tmp_path, data) == found


@pytest.mark.parametrize(
    ("value", "code"),
    [
        (datetime(2026, 11, 1), "timezone_aware"),
        ("2026-11-01T00:00:00Z", "datetime_type"),  # quoted in YAML: a string
        (date(2026, 11, 1), "datetime_type"),
    ],
)
def test_expires_is_an_aware_timestamp(
    tmp_path: Path, value: object, code: str
) -> None:
    data = _with_role(passport_example(), "preview", "v1.0.0")
    section(data, "server")["expires_at"] = value
    assert passport_problems(tmp_path, data) == [("server.expires_at", code)]


# --- rule 5: tls exactly with ssl provided ---------------------------------------


@pytest.mark.parametrize("ssl", ["letsencrypt", "self-signed", "defer", "provided"])
@pytest.mark.parametrize("has_tls", [True, False])
def test_tls_iff_provided(tmp_path: Path, ssl: str, has_tls: bool) -> None:
    data = passport_example()
    section(data, "policies")["ssl"] = ssl
    if has_tls:
        section(data, "policies")["tls"] = {"cert": CERT, "key": KEY}
    expected = [] if (ssl == "provided") == has_tls else [("policies.tls", "R5.tls")]
    assert passport_problems(tmp_path, data) == expected


@pytest.mark.parametrize(
    ("tls", "found"),
    [
        ({"cert": "nope", "key": KEY}, [("policies.tls.cert", "value_error")]),
        (
            {"cert": KEY, "key": CERT},
            [("policies.tls.cert", "value_error"), ("policies.tls.key", "value_error")],
        ),
        ({"cert": CERT}, [("policies.tls.key", "missing")]),
        (
            {"cert": CERT, "key": KEY, "chain": CERT},
            [("policies.tls.chain", "extra_forbidden")],
        ),
    ],
)
def test_tls_shape(tmp_path: Path, tls: Data, found: list[tuple[str, str]]) -> None:
    data = passport_example()
    section(data, "policies").update(ssl="provided", tls=tls)
    assert passport_problems(tmp_path, data) == found


def test_unknown_ssl_mode(tmp_path: Path) -> None:
    data = passport_example()
    section(data, "policies")["ssl"] = "edge"
    assert passport_problems(tmp_path, data) == [("policies.ssl", "literal_error")]


# --- rule 1: names that never live in a passport -----------------------------------


@pytest.mark.parametrize(
    ("place", "key", "value", "found"),
    [
        ((), "minted", {"SECRET_KEY": "x"}, [("minted", "R1.minted")]),
        ((), "composition", {"comms": "3.0.0"}, [("composition", "R1.composition")]),
        ((), "lock", {}, [("lock", "R1.composition")]),
        ((), "dependencies", {}, [("dependencies", "R1.composition")]),
        ((), "ip", "1.2.3.4", [("ip", "R1.derived")]),
        (("server",), "ip", "1.2.3.4", [("server.ip", "R1.derived")]),
        (("product",), "commit", "9a1c4e2", [("product.commit", "R1.composition")]),
        (
            ("asked", "comms"),
            "minted",
            {"A": "b"},
            [("asked.comms.minted", "R1.minted")],
        ),
        (("asked", "comms"), "minted", "b", [("asked.comms.minted", "R1.minted")]),
        ((), "VITE_API_BASE_URL", "x", [("VITE_API_BASE_URL", "extra_forbidden")]),
        (("asked", "comms"), "SECRET_KEY", "x", []),  # composition, P1
    ],
)
def test_rule_1_names(
    tmp_path: Path,
    place: tuple[str, ...],
    key: str,
    value: object,
    found: list[tuple[str, str]],
) -> None:
    data = passport_example()
    section(data, *place)[key] = value
    assert passport_problems(tmp_path, data) == found


def test_rule_1_message(tmp_path: Path) -> None:
    data = passport_example()
    data["minted"] = {}
    assert passport_messages(tmp_path, data) == [
        "passport rule 1: minted secrets belong to their stack (env/minted.yaml), "
        "never to the passport: 'minted' is not a passport field"
    ]


def test_rule_1_reports_with_every_field_problem(tmp_path: Path) -> None:
    data = passport_example()
    data.update(minted={}, ip="1")
    section(data, "server")["role"] = "staging"
    assert passport_problems(tmp_path, data) == [
        ("minted", "R1.minted"),
        ("ip", "R1.derived"),
        ("server.role", "literal_error"),
    ]


# --- rule 9: packages pinned exactly -------------------------------------------


@pytest.mark.parametrize(
    "version", [">=1.4", "1.4", "v1.4.2", "", "01.4.2", "1.4.2rc1"]
)
def test_package_version_is_exact(tmp_path: Path, version: str) -> None:
    data = passport_example()
    section(data, "packages", "skin")["version"] = version
    assert passport_problems(tmp_path, data) == [
        ("packages.skin.version", "R9.package-version")
    ]
    assert passport_messages(tmp_path, data)[0].startswith("passport rule 9:")


def test_package_version_must_be_quoted(tmp_path: Path) -> None:
    data = passport_example()
    section(data, "packages", "skin")["version"] = 1.4
    assert passport_problems(tmp_path, data) == [
        ("packages.skin.version", "string_type")
    ]


def test_packages_may_be_empty(tmp_path: Path) -> None:
    data = passport_example()
    data["packages"] = {}
    assert passport_problems(tmp_path, data) == []


# --- fields ----------------------------------------------------------------------


Edit = Callable[[Data], object]


@pytest.mark.parametrize(
    ("edit", "found"),
    [
        (lambda d: d.pop("edition"), []),
        (lambda d: d.update(asked={}), []),
        (lambda d: d.update(domains={}), []),
        (
            lambda d: d.update(cloud={"provider": "x"}),
            [("cloud.provider", "extra_forbidden")],
        ),
        (lambda d: d.pop("cloud"), [("cloud", "missing")]),
        (lambda d: section(d, "policies").pop("gc"), [("policies.gc", "missing")]),
        (lambda d: section(d, "product").pop("ref"), [("product.ref", "missing")]),
        (lambda d: d.pop("server"), [("server", "missing")]),
        (lambda d: d.update(version=0), [("version", "greater_than_equal")]),
        (lambda d: d.update(version=True), [("version", "int_type")]),
        (lambda d: d.update(schema=True), [("schema", "int_type")]),
        (
            lambda d: section(d, "server").update(os="ubuntu-22.04"),
            [("server.os", "literal_error")],
        ),
        (
            lambda d: section(d, "server").update(name="Aivis_Test"),
            [("server.name", "string_pattern_mismatch")],
        ),
        (
            lambda d: section(d, "domains").update(api="https://api.x.one"),
            [("domains.api", "value_error")],
        ),
        (
            lambda d: section(d, "domains").update(api="localhost"),
            [("domains.api", "value_error")],
        ),
        (
            lambda d: section(d, "access").update(mode="pat"),
            [("access.mode", "literal_error")],
        ),
        (
            lambda d: section(d, "asked", "comms").update(X=5),
            [("asked.comms.X", "string_type")],
        ),
        (
            lambda d: section(d, "asked", "comms").update(X=""),
            [("asked.comms.X", "value_error")],
        ),
        (
            lambda d: section(d, "asked", "comms").update(X=None),
            [("asked.comms.X", "string_type")],
        ),
        (
            lambda d: section(d, "policies", "gc").update(builder_cache_budget="3GB"),
            [("policies.gc.builder_cache_budget", "string_pattern_mismatch")],
        ),
        (
            lambda d: section(d, "policies", "gc").update(keep_releases=0),
            [("policies.gc.keep_releases", "greater_than_equal")],
        ),
        (
            lambda d: section(d, "policies", "timers").update(gc="hourly"),
            [("policies.timers.gc", "literal_error")],
        ),
        (
            lambda d: section(d, "packages", "texts").update(subpath="../x"),
            [("packages.texts.subpath", "value_error")],
        ),
    ],
)
def test_fields(tmp_path: Path, edit: Edit, found: list[tuple[str, str]]) -> None:
    data = passport_example()
    edit(data)
    assert passport_problems(tmp_path, data) == found


# --- crossings ---------------------------------------------------------------


def test_rules_collect_every_violation(tmp_path: Path) -> None:
    data = passport_example()
    section(data, "server").update(role="prod", expires_at=AT)
    section(data, "policies")["ssl"] = "provided"
    assert passport_problems(tmp_path, data) == [
        ("product.ref", "R4.ref-tag"),
        ("policies.tls", "R5.tls"),
        ("server.expires_at", "R10.expires"),
    ]


def test_rules_wait_for_clean_fields(tmp_path: Path) -> None:
    data = passport_example()
    section(data, "server")["role"] = "prod"  # R4 would fire on 'main'
    section(data, "access")["mode"] = "pat"
    assert passport_problems(tmp_path, data) == [("access.mode", "literal_error")]


# --- secrets -----------------------------------------------------------------


MARKER = "LEAK-MARKER-9c1d"
PEM_MARKER = f"-----BEGIN CERTIFICATE-----\n{MARKER}\n-----END CERTIFICATE-----\n"


@pytest.mark.parametrize(
    "edit",
    [
        # value not a PEM block
        lambda d: section(d, "policies").update(
            ssl="provided", tls={"cert": MARKER, "key": MARKER}
        ),
        # tls where ssl is not provided (rule layer)
        lambda d: section(d, "policies").update(tls={"cert": PEM_MARKER, "key": KEY}),
        # null next to a secret
        lambda d: section(d, "asked", "comms").update(
            X=None, TELEGRAM_BOT_TOKEN=MARKER
        ),
        # a secret under an unknown key
        lambda d: d.update(stash={"TOKEN": MARKER}),
        # a secret under a rule-1 name
        lambda d: d.update(minted={"SECRET_KEY": MARKER}),
    ],
    ids=["not-pem", "tls-not-provided", "null-beside", "extra-key", "rule-1"],
)
def test_secret_never_printed(tmp_path: Path, edit: Edit) -> None:
    data = passport_example()
    edit(data)
    error = rejection(write_passport(tmp_path, data))
    assert error is not None and error.problems
    assert error.__cause__ is None
    assert error.__context__ is None
    assert MARKER not in everything_printed(error)


def test_secret_on_a_broken_yaml_line(tmp_path: Path) -> None:
    file = tmp_path / "passport.yaml"
    file.write_text(f'asked:\n  comms:\n    TELEGRAM_BOT_TOKEN: "{MARKER}\n')
    error = rejection(file)
    assert error is not None
    assert [p.code for p in error.problems] == ["Y.syntax"]
    assert MARKER not in everything_printed(error)


def test_secret_not_in_repr_or_json(tmp_path: Path) -> None:
    data = passport_example()
    section(data, "asked", "comms")["TELEGRAM_BOT_TOKEN"] = MARKER
    section(data, "policies").update(
        ssl="provided", tls={"cert": PEM_MARKER, "key": KEY}
    )
    passport = load_passport(write_passport(tmp_path, data))
    assert passport.asked["comms"]["TELEGRAM_BOT_TOKEN"].get_secret_value() == MARKER
    assert MARKER not in repr(passport)
    assert MARKER not in passport.model_dump_json()
