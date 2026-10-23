"""Probes DM-2: contract 1 v1.4 -- the passport as the machine reads it.

Each probe asserts the rule's own code and number and has its pair: the
contract's example passes and the checked section is not empty, so an emptied
check cannot stay green.
"""

from datetime import UTC, datetime
from pathlib import Path

from passport_support import (
    passport_example,
    passport_messages,
    passport_problems,
    section,
)

from pridem.stacks.passport import PASSPORT_SCHEMA, rendered_schema
from pridem.stacks.schema import SCHEMA_DIR

AT = datetime(2026, 11, 1, tzinfo=UTC)
CERT = "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"
KEY = "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n"


def test_probe_DM_2_prod_ref_must_be_tag(tmp_path: Path) -> None:
    for ref in ("main", "9a1c4e2", "v1.2"):
        data = passport_example()
        section(data, "server")["role"] = "prod"
        section(data, "product")["ref"] = ref
        assert passport_problems(tmp_path, data) == [("product.ref", "R4.ref-tag")], ref
        assert passport_messages(tmp_path, data)[0].startswith("passport rule 4:")

    tagged = passport_example()
    section(tagged, "server")["role"] = "prod"
    section(tagged, "product")["ref"] = "v1.2.3"
    assert passport_problems(tmp_path, tagged) == []

    pair = passport_example()
    assert passport_problems(tmp_path, pair) == []
    assert section(pair, "product")["ref"] == "main"


def test_probe_DM_2_minted_key_is_rejected(tmp_path: Path) -> None:
    top = passport_example()
    top["minted"] = {"SECRET_KEY": "x"}
    assert passport_problems(tmp_path, top) == [("minted", "R1.minted")]
    assert passport_messages(tmp_path, top)[0].startswith("passport rule 1:")

    asked = passport_example()
    section(asked, "asked", "comms")["minted"] = "x"
    assert passport_problems(tmp_path, asked) == [("asked.comms.minted", "R1.minted")]

    pair = passport_example()
    assert passport_problems(tmp_path, pair) == []
    assert section(pair, "asked", "comms")


def test_probe_DM_2_expires_only_for_preview(tmp_path: Path) -> None:
    preview = passport_example()
    section(preview, "server")["role"] = "preview"
    section(preview, "product")["ref"] = "v1.0.0"
    assert passport_problems(tmp_path, preview) == [
        ("server.expires_at", "R10.expires")
    ]
    assert passport_messages(tmp_path, preview)[0].startswith("passport rule 10:")
    section(preview, "server")["expires_at"] = AT
    assert passport_problems(tmp_path, preview) == []

    for role, ref in (("test", "main"), ("prod", "v1.0.0")):
        data = passport_example()
        section(data, "server").update(role=role, expires_at=AT)
        section(data, "product")["ref"] = ref
        assert passport_problems(tmp_path, data) == [
            ("server.expires_at", "R10.expires")
        ], role

    pair = passport_example()
    assert passport_problems(tmp_path, pair) == []
    assert "expires_at" not in section(pair, "server")


def test_probe_DM_2_tls_iff_ssl_provided(tmp_path: Path) -> None:
    provided = passport_example()
    section(provided, "policies")["ssl"] = "provided"
    assert passport_problems(tmp_path, provided) == [("policies.tls", "R5.tls")]
    assert passport_messages(tmp_path, provided)[0].startswith("passport rule 5:")
    section(provided, "policies")["tls"] = {"cert": CERT, "key": KEY}
    assert passport_problems(tmp_path, provided) == []

    other = passport_example()
    section(other, "policies")["tls"] = {"cert": CERT, "key": KEY}
    assert passport_problems(tmp_path, other) == [("policies.tls", "R5.tls")]

    pair = passport_example()
    assert passport_problems(tmp_path, pair) == []
    assert section(pair, "policies")["ssl"] == "letsencrypt"


def test_probe_DM_2_schema_export_matches_model() -> None:
    rendered = rendered_schema()
    on_disk = (SCHEMA_DIR / PASSPORT_SCHEMA).read_text(encoding="utf-8")
    assert rendered == on_disk, (
        f"{PASSPORT_SCHEMA} differs from the model; "
        "regenerate: python -m pridem.stacks.passport --export"
    )
    assert '"server"' in rendered and '"writeOnly": true' in rendered
