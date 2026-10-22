"""Probes DM-33: contract 3 v1.6 -- half-open ranges, rule 3 for package contracts.

Each probe asserts the rule's own code and number and has its pair: the
contract's example passes and the checked section is not empty.
"""

from pathlib import Path

from contract_support import example, node, yaml_messages, yaml_problems


def test_probe_DM_33_upper_inclusive_is_rejected(tmp_path: Path) -> None:
    for version in ("<=3.0.0", ">=3.0.0,<=3.0.0", ">=3,<=4"):
        data = example("product.yaml")
        node(data, "dependencies", "comms")["version"] = version
        assert yaml_problems(tmp_path, data) == [
            ("dependencies.comms.version", "R3.single-point")
        ], version
        assert yaml_messages(tmp_path, data)[0].startswith("contract rule 3:")

    pair = example("product.yaml")
    assert yaml_problems(tmp_path, pair) == []
    assert node(pair, "dependencies", "comms")["version"] == ">=3.0,<4"


def test_probe_DM_33_package_contract_pin_is_rejected(tmp_path: Path) -> None:
    for contract in ("==1.0", "===1.0", "<=1.0"):
        data = example("product.yaml")
        node(data, "packages", "skin")["contract"] = contract
        assert yaml_problems(tmp_path, data) == [
            ("packages.skin.contract", "R3.single-point")
        ], contract
        assert yaml_messages(tmp_path, data)[0].startswith("contract rule 3:")

    pair = example("product.yaml")
    assert yaml_problems(tmp_path, pair) == []
    assert node(pair, "packages", "skin")["contract"] == ">=1,<2"
