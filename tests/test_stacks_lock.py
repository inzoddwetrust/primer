"""State grid of primer.lock (DM-3): entry form and the check against primer.yaml."""

from pathlib import Path

import pytest
from contract_support import example, lock_problems, node


def test_example_pair_is_green_and_pins_the_remote(tmp_path: Path) -> None:
    lock = example("primer.lock")
    assert lock_problems(tmp_path, example("product.yaml"), lock) == []
    assert set(node(lock, "dependencies")) == {"comms", "payments", "meet"}


def test_missing_and_extra_dependencies(tmp_path: Path) -> None:
    lock = example("primer.lock")
    del node(lock, "dependencies")["payments"]
    node(lock, "dependencies")["billing"] = {
        "version": "1.0.0",
        "tag": "v1.0.0",
        "commit": "abcdef0",
    }
    assert lock_problems(tmp_path, example("product.yaml"), lock) == [
        ("dependencies.payments", "R3.lock-set"),
        ("dependencies.billing", "R3.lock-set"),
    ]


def test_empty_lock_for_a_product_with_dependencies(tmp_path: Path) -> None:
    lock = example("primer.lock")
    lock["dependencies"] = {}
    assert [
        code for _, code in lock_problems(tmp_path, example("product.yaml"), lock)
    ] == ["R3.lock-set"] * 3


@pytest.mark.parametrize("tag", ["3.0.0", "v3.0", "v3.0.1", "V3.0.0"])
def test_tag_must_be_v_version(tmp_path: Path, tag: str) -> None:
    lock = example("primer.lock")
    node(lock, "dependencies", "comms")["tag"] = tag
    assert lock_problems(tmp_path, example("product.yaml"), lock) == [
        ("dependencies.comms.tag", "R3.lock-tag")
    ]


@pytest.mark.parametrize("commit", ["B27C57C", "b27c57", "a" * 41, "b27c57g"])
def test_commit_is_lowercase_hex_7_to_40(tmp_path: Path, commit: str) -> None:
    lock = example("primer.lock")
    node(lock, "dependencies", "comms")["commit"] = commit
    assert lock_problems(tmp_path, example("product.yaml"), lock) == [
        ("dependencies.comms.commit", "R3.lock-commit")
    ]


@pytest.mark.parametrize("commit", ["b27c57c", "a" * 40])
def test_commit_bounds_are_inclusive(tmp_path: Path, commit: str) -> None:
    lock = example("primer.lock")
    node(lock, "dependencies", "comms")["commit"] = commit
    assert lock_problems(tmp_path, example("product.yaml"), lock) == []


@pytest.mark.parametrize(
    ("version", "code"),
    [
        ("3.0", "string_pattern_mismatch"),
        ("3.0.0rc1", "string_pattern_mismatch"),
        (3.0, "string_type"),
    ],
)
def test_version_is_exactly_x_y_z(tmp_path: Path, version: object, code: str) -> None:
    lock = example("primer.lock")
    node(lock, "dependencies", "comms")["version"] = version
    assert lock_problems(tmp_path, example("product.yaml"), lock) == [
        ("dependencies.comms.version", code)
    ]


def test_resolved_at_is_a_yaml_timestamp_not_a_string(tmp_path: Path) -> None:
    lock = example("primer.lock")
    lock["resolved_at"] = "2026-10-22T10:00:00Z"
    assert lock_problems(tmp_path, example("product.yaml"), lock) == [
        ("resolved_at", "datetime_type")
    ]


def test_lock_rules_report_every_entry(tmp_path: Path) -> None:
    lock = example("primer.lock")
    node(lock, "dependencies", "comms")["tag"] = "v9.9.9"
    node(lock, "dependencies", "meet")["commit"] = "XYZ"
    assert lock_problems(tmp_path, example("product.yaml"), lock) == [
        ("dependencies.comms.tag", "R3.lock-tag"),
        ("dependencies.meet.commit", "R3.lock-commit"),
    ]
