"""Probes DM-32: contract 3 v1.5 -- single-point pins and mount references.

Each probe asserts the rule's own code and number, not just "an error", and
has its pair: the contract's example passes and the checked section is not
empty, so an emptied rule layer cannot stay green.
"""

from pathlib import Path

from contract_support import example, node, yaml_messages, yaml_problems


def test_probe_DM_32_single_point_pin_is_rejected(tmp_path: Path) -> None:
    for version in ("==3.0.0", "===3.0.0", ">=3.0,==3.0.0"):
        data = example("product.yaml")
        node(data, "dependencies", "comms")["version"] = version
        assert yaml_problems(tmp_path, data) == [
            ("dependencies.comms.version", "R3.single-point")
        ], version
        assert yaml_messages(tmp_path, data)[0].startswith("contract rule 3:")

    pair = example("product.yaml")
    assert yaml_problems(tmp_path, pair) == []
    assert node(pair, "dependencies", "comms")["version"] == ">=3.0,<4"


def test_probe_DM_32_mount_dependency_must_be_declared(tmp_path: Path) -> None:
    data = example("product.yaml")
    node(data, "packages", "texts", "mount", 1)["dependency"] = "billing"
    assert yaml_problems(tmp_path, data) == [
        ("packages.texts.mount[1].dependency", "S.mount-dependency")
    ]

    pair = example("product.yaml")
    assert yaml_problems(tmp_path, pair) == []
    assert node(pair, "packages", "texts", "mount", 1)["dependency"] == "comms"
