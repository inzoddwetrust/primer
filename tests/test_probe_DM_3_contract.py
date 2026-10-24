"""Probes DM-3: contract 3 (primer.yaml, primer.lock) as the machine reads it.

Each probe asserts the rule's own code and number, not just "an error": the
closed models reject an unknown key anyway, and a probe that accepted any error
would stay green after the rule itself was removed. Each probe has its pair:
the contract's example passes and is not empty.
"""

import json
from pathlib import Path

from contract_support import example, lock_problems, node, yaml_messages, yaml_problems

from pridem.stacks.lock import PRIMER_LOCK_SCHEMA, rendered_schema
from pridem.stacks.schema import PRIMER_YAML_SCHEMA, SCHEMA_DIR, rendered_schemas


def test_probe_DM_3_yaml_values_forbidden(tmp_path: Path) -> None:
    data = example("product.yaml")
    node(data, "env")["SECRET_KEY"] = {"source": "minted", "value": "s3cr3t"}
    node(data, "env")["DEBUG"] = {"source": "fixed", "value": "1"}
    assert yaml_problems(tmp_path, data) == [
        ("env.SECRET_KEY", "R1.value"),
        ("env.DEBUG", "R1.value"),
    ]
    assert all(
        message.startswith("contract rule 1:")
        for message in yaml_messages(tmp_path, data)
    )

    pair = example("product.yaml")
    assert yaml_problems(tmp_path, pair) == []
    assert node(pair, "env")


def test_probe_DM_3_service_branch_is_rejected(tmp_path: Path) -> None:
    data = example("product.yaml")
    node(data, "dependencies", "comms")["branch"] = "main"
    assert yaml_problems(tmp_path, data) == [("dependencies.comms", "R9.branch")]
    assert yaml_messages(tmp_path, data)[0].startswith("contract rule 9:")

    assert yaml_problems(tmp_path, example("product.yaml")) == []


def test_probe_DM_3_routes_unknown_knob_is_red(tmp_path: Path) -> None:
    data = example("product.yaml")
    preview_knob = "access_token"  # preview is applied by role, not a route knob
    node(data, "host", "routes", "api")[preview_knob] = "on"
    node(data, "host", "headers")["hsts"] = "max-age=1"
    assert yaml_problems(tmp_path, data) == [
        ("host.routes.api.access_token", "extra_forbidden"),
        ("host.headers.hsts", "extra_forbidden"),
    ]

    pair = example("product.yaml")
    assert yaml_problems(tmp_path, pair) == []
    assert node(pair, "host", "routes", "api")["max_body"] == "100M"


def test_probe_DM_3_lock_outside_range_is_red(tmp_path: Path) -> None:
    lock = example("primer.lock")
    node(lock, "dependencies", "comms").update(
        version="4.0.0", tag="v4.0.0", commit="b27c57c"
    )
    assert lock_problems(tmp_path, example("product.yaml"), lock) == [
        ("dependencies.comms.version", "R3.lock-range")
    ]

    assert (
        lock_problems(tmp_path, example("product.yaml"), example("primer.lock")) == []
    )


def test_probe_DM_3_edition_services_subset_of_dependencies(tmp_path: Path) -> None:
    data = example("product.yaml")
    node(data, "editions")["full"] = {"services": ["comms", "payments", "billing"]}
    assert yaml_problems(tmp_path, data) == [
        ("editions.full.services[2]", "R11.edition-services")
    ]

    pair = example("product.yaml")
    assert yaml_problems(tmp_path, pair) == []
    assert node(pair, "editions")


def test_probe_DM_3_remote_dependency_has_no_local_seam(tmp_path: Path) -> None:
    data = example("product.yaml")
    node(data, "env")["MEET_URL"] = {"source": "seam", "from": "meet"}
    assert yaml_problems(tmp_path, data) == [("env.MEET_URL.from", "R13.remote-seam")]

    pair = example("product.yaml")
    assert yaml_problems(tmp_path, pair) == []
    assert node(pair, "dependencies", "meet")["topology"] == "remote"


def test_probe_DM_3_schema_export_matches_model() -> None:
    """Both contract 3 schema files equal the export of the module that owns them.

    ``primer.yaml`` is exported by ``pridem.stacks.schema``, ``primer.lock`` by
    ``pridem.stacks.lock``. One exporter for both made ``schema`` import
    ``lock`` while ``lock`` imports ``schema``, a cycle the import fence of
    DM-34 rejects; the probe still checks both files, each with its own
    regeneration command.
    """
    yaml_rendered = rendered_schemas()
    assert sorted(yaml_rendered) == [PRIMER_YAML_SCHEMA] == ["primer-yaml.v1.json"]
    assert PRIMER_LOCK_SCHEMA == "primer-lock.v1.json"
    exports = [
        (PRIMER_YAML_SCHEMA, yaml_rendered[PRIMER_YAML_SCHEMA], "pridem.stacks.schema"),
        (PRIMER_LOCK_SCHEMA, rendered_schema(), "pridem.stacks.lock"),
    ]
    for name, text, owner in exports:
        on_disk = (SCHEMA_DIR / name).read_text(encoding="utf-8")
        assert on_disk == text, (
            f"{name} differs from the models; regenerate: python -m {owner} --export"
        )
        assert json.loads(on_disk)["$defs"]
