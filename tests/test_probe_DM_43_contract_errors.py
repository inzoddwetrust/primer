"""Probe DM-43: a rejected contract file is not quoted by its error.

A ``ValidationError`` carries the file's values as ``input_value``; a
``ContractError`` raised ``from`` it, or inside its ``except`` (implicit
``__context__``), prints them in a traceback. Rule texts may name a value that
is not secret (a range, a tag, a path) -- for the file's author that is the
whole diagnosis -- but the secret fields are quoted by nothing:
``env.*.value`` of ``primer.yaml`` (a value that must not be there at all),
``asked`` and ``policies.tls`` of the passport. Each secret field is probed
with an error in the field itself and with an error in a neighbouring field.

``primer.lock`` has no secret fields (contract 3 section 5: version, tag,
commit, resolved_at); its cases put the marker in values whose errors no rule
text quotes, so the only way to the output is the chain.
"""

import traceback
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

import pytest
import yaml
from contract_support import example, node
from passport_support import passport_example, section

from pridem.stacks.loader import ContractError
from pridem.stacks.lock import load_primer_lock
from pridem.stacks.passport import load_passport
from pridem.stacks.schema import load_primer_yaml

MARKER = "MK43-6d1e"
SECRET = f"{MARKER}-long-enough-secret"
CERT = f"-----BEGIN CERTIFICATE-----\n{MARKER}\n-----END CERTIFICATE-----\n"
KEY = f"-----BEGIN PRIVATE KEY-----\n{MARKER}\n-----END PRIVATE KEY-----\n"
LOCK_SECRET_FIELDS: tuple[str, ...] = ()

Data = dict[str, object]


@dataclass(frozen=True)
class Case:
    file: str
    load: Callable[[Path], object]
    data: Callable[[], Data]
    expected: tuple[tuple[str, str], ...]


def _yaml_value(neighbour: bool) -> Data:
    data = example("product.yaml")
    node(data, "env")["SECRET_KEY"] = {"source": "minted", "value": SECRET}
    if neighbour:
        node(data, "dependencies", "comms")["version"] = "not a range"
    return data


def _lock(field: str) -> Data:
    data = example("primer.lock")
    data[field] = MARKER
    return data


def _asked(value: str, neighbour: bool) -> Data:
    data = passport_example()
    section(data, "asked", "comms")["TELEGRAM_BOT_TOKEN"] = value
    if neighbour:
        section(data, "server")["role"] = "staging"
    return data


def _tls(cert: str, key: str, neighbour: str | None) -> Data:
    data = passport_example()
    policies = section(data, "policies")
    policies["ssl"] = "provided"
    policies["tls"] = {"cert": cert, "key": key}
    if neighbour == "field":
        section(data, "server")["role"] = "staging"
    elif neighbour == "rule":
        section(data, "server")["expires_at"] = datetime(2026, 11, 1, tzinfo=UTC)
    return data


CASES = {
    "yaml-env-value": Case(
        "primer.yaml",
        load_primer_yaml,
        lambda: _yaml_value(neighbour=False),
        (("env.SECRET_KEY", "R1.value"),),
    ),
    "yaml-env-value-neighbour": Case(
        "primer.yaml",
        load_primer_yaml,
        lambda: _yaml_value(neighbour=True),
        (("env.SECRET_KEY", "R1.value"), ("dependencies.comms.version", "value_error")),
    ),
    "lock-resolved-at": Case(
        "primer.lock",
        load_primer_lock,
        lambda: _lock("resolved_at"),
        (("resolved_at", "datetime_type"),),
    ),
    "lock-unknown-key": Case(
        "primer.lock",
        load_primer_lock,
        lambda: _lock("note"),
        (("note", "extra_forbidden"),),
    ),
    "passport-asked": Case(
        "passport.yaml",
        load_passport,
        lambda: _asked(MARKER, neighbour=False),
        (("asked.comms.TELEGRAM_BOT_TOKEN", "R12.secret-length"),),
    ),
    "passport-asked-neighbour": Case(
        "passport.yaml",
        load_passport,
        lambda: _asked(SECRET, neighbour=True),
        (("server.role", "literal_error"),),
    ),
    "passport-tls-cert": Case(
        "passport.yaml",
        load_passport,
        lambda: _tls(SECRET, KEY, neighbour=None),
        (("policies.tls.cert", "value_error"),),
    ),
    "passport-tls-key": Case(
        "passport.yaml",
        load_passport,
        lambda: _tls(CERT, SECRET, neighbour=None),
        (("policies.tls.key", "value_error"),),
    ),
    "passport-tls-neighbour-field": Case(
        "passport.yaml",
        load_passport,
        lambda: _tls(CERT, KEY, neighbour="field"),
        (("server.role", "literal_error"),),
    ),
    "passport-tls-neighbour-rule": Case(
        "passport.yaml",
        load_passport,
        lambda: _tls(CERT, KEY, neighbour="rule"),
        (("server.expires_at", "R10.expires"),),
    ),
}


@pytest.mark.parametrize("name", list(CASES))
def test_probe_DM_43_contract_errors_never_quote_the_file(
    tmp_path: Path, name: str
) -> None:
    case = CASES[name]
    file = tmp_path / case.file
    text = yaml.safe_dump(case.data(), sort_keys=False, allow_unicode=True)
    assert MARKER in text
    file.write_text(text)
    with pytest.raises(ContractError) as caught:
        case.load(file)
    error = caught.value

    assert error.__cause__ is None
    assert error.__context__ is None
    printed = str(error) + "".join(traceback.format_exception(error))
    assert MARKER not in printed

    for path, code in case.expected:
        assert f"{path}: [{code}]" in str(error), str(error)


def test_primer_lock_has_no_secret_fields() -> None:
    """Named, not assumed: the lock pins public releases (contract 3 section 5)."""
    assert LOCK_SECRET_FIELDS == ()
    assert set(example("primer.lock")) == {"schema", "resolved_at", "dependencies"}
    entries = node(example("primer.lock"), "dependencies")
    fields = {tuple(sorted(node(entries, name))) for name in entries}
    assert fields == {("commit", "tag", "version")}
