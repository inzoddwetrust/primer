"""Probes DM-40: the form of a contract file is checked before it is parsed.

Contract 3 rule 16 and contract 1 rule 13: no anchors or aliases, collections
nested no deeper than 32; and a size limit read before anything else. The
probes replace ``yaml.compose`` with a function that fails, so a probe passes
only if the file is refused before composition; each has its pair, a file of
the allowed form that loads with the real ``compose``.
"""

from pathlib import Path

import pytest
import yaml

from pridem.stacks.loader import (
    MAX_BYTES,
    MAX_DEPTH,
    ContractError,
    Problem,
    load_yaml_mapping,
)


def _no_compose(monkeypatch: pytest.MonkeyPatch) -> None:
    def compose(*_: object, **__: object) -> None:
        raise AssertionError("yaml.compose was called")

    monkeypatch.setattr(yaml, "compose", compose)


def _refused(file: Path) -> list[Problem]:
    with pytest.raises(ContractError) as error:
        load_yaml_mapping(file)
    return list(error.value.problems)


def _bomb(levels: int, refs: int = 4) -> str:
    lines = ["l0: &l0 x"]
    for level in range(1, levels + 1):
        aliases = ", ".join([f"*l{level - 1}"] * refs)
        lines.append(f"l{level}: &l{level} [{aliases}]")
    return "\n".join(lines) + "\n"


def _nested(depth: int) -> str:
    """A root mapping holding ``depth - 1`` nested sequences: ``depth`` collections."""
    inner = depth - 1
    return "a: " + "[" * inner + "x" + "]" * inner + "\n"


def test_probe_DM_40_alias_bomb_is_refused_before_compose(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    file = tmp_path / "primer.yaml"
    file.write_text(_bomb(16))
    with monkeypatch.context() as patch:
        _no_compose(patch)
        found = _refused(file)
    # 17 anchors and 16 * 4 aliases, each named by its line
    assert len(found) == 17 + 16 * 4
    assert {problem.code for problem in found} == {"Y.alias"}

    pair = tmp_path / "pair.yaml"
    pair.write_text("l0: x\nl1: [x, x, x, x]\nl2: [[x, x], [x, x]]\n")
    assert load_yaml_mapping(pair) == {
        "l0": "x",
        "l1": ["x", "x", "x", "x"],
        "l2": [["x", "x"], ["x", "x"]],
    }


def test_probe_DM_40_deep_nesting_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    file = tmp_path / "primer.yaml"
    file.write_text(_nested(MAX_DEPTH + 1))
    with monkeypatch.context() as patch:
        _no_compose(patch)
        found = _refused(file)
    assert found == [
        Problem(
            "",
            "Y.depth",
            f"collections nested deeper than 32 at line 1, column {3 + MAX_DEPTH}",
        )
    ]

    pair = tmp_path / "pair.yaml"
    pair.write_text(_nested(MAX_DEPTH))
    value: object = load_yaml_mapping(pair)["a"]
    depth = 1
    while isinstance(value, list):
        [value] = value
        depth += 1
    assert (depth, value) == (MAX_DEPTH, "x")


def test_limits_are_the_contract_numbers() -> None:
    assert (MAX_BYTES, MAX_DEPTH) == (1024 * 1024, 32)


def test_anchor_without_alias_is_refused(tmp_path: Path) -> None:
    file = tmp_path / "primer.yaml"
    file.write_text("a: &unused 1\nb: &list [1]\nc: &map {k: 1}\n")
    found = _refused(file)
    assert [p.code for p in found] == ["Y.alias"] * 3
    assert all(p.message.startswith("anchor at line ") for p in found)
    assert all("unused" not in p.message for p in found), "anchor names are source"


def test_deep_nesting_counts_mappings_and_reports_once(tmp_path: Path) -> None:
    file = tmp_path / "primer.yaml"
    text = "".join(f"{'  ' * level}k{level}:\n" for level in range(MAX_DEPTH + 2))
    file.write_text(text + "  " * (MAX_DEPTH + 2) + "leaf: 1\n")
    assert [p.code for p in _refused(file)] == ["Y.depth"]


def test_sibling_collections_do_not_add_depth(tmp_path: Path) -> None:
    file = tmp_path / "primer.yaml"
    siblings = ", ".join(["[x]"] * (2 * MAX_DEPTH))
    file.write_text(f"a: [{siblings}]\nb: {{k: [x]}}\n")
    data = load_yaml_mapping(file)
    assert data["a"] == [["x"]] * (2 * MAX_DEPTH)


def test_file_at_the_size_limit_loads(tmp_path: Path) -> None:
    file = tmp_path / "primer.yaml"
    head, tail = b"a: ", b"\n"
    file.write_bytes(head + b"x" * (MAX_BYTES - len(head) - len(tail)) + tail)
    assert file.stat().st_size == MAX_BYTES
    assert len(str(load_yaml_mapping(file)["a"])) == MAX_BYTES - 4


def test_file_over_the_size_limit_is_refused_before_parsing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """One byte over the limit, and not YAML at all: only the size is reported."""
    file = tmp_path / "primer.yaml"
    file.write_bytes(b"a: [" + b"\xff" * MAX_BYTES)
    assert file.stat().st_size == MAX_BYTES + 4
    calls: list[str] = []
    real_parse = yaml.parse

    def parse(*args: object, **kwargs: object) -> object:
        calls.append("parse")
        return real_parse(*args, **kwargs)  # type: ignore[arg-type]

    with monkeypatch.context() as patch:
        _no_compose(patch)
        patch.setattr(yaml, "parse", parse)
        found = _refused(file)
    assert found == [Problem("", "Y.size", "file is larger than 1048576 bytes")]
    assert calls == []


def test_crlf_lines_keep_their_numbers(tmp_path: Path) -> None:
    file = tmp_path / "primer.yaml"
    file.write_bytes(b"a: 1\r\nb: [1, 2]\r\n")
    assert load_yaml_mapping(file) == {"a": 1, "b": [1, 2]}
    file.write_bytes(b"a: 1\r\nb: 2\r\na: 3\r\n")
    [problem] = _refused(file)
    assert (problem.code, problem.message) == (
        "Y.duplicate",
        "duplicate key 'a' at lines 1 and 3",
    )


def test_syntax_error_wins_over_form_problems(tmp_path: Path) -> None:
    """The event pass meets the syntax error; it is reported as before."""
    file = tmp_path / "primer.yaml"
    file.write_text("a: &x 1\nb: [unclosed\n")
    assert [p.code for p in _refused(file)] == ["Y.syntax"]
