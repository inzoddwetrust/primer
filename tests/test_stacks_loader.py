"""State grid of the contract-file loader (DM-3): file, YAML, duplicates, merge."""

import traceback
from pathlib import Path

import pytest

from pridem.stacks.loader import ContractError, Problem, load_yaml_mapping


def _problems(tmp_path: Path, text: str | bytes) -> list[Problem]:
    file = tmp_path / "primer.yaml"
    if isinstance(text, bytes):
        file.write_bytes(text)
    else:
        file.write_text(text)
    with pytest.raises(ContractError) as error:
        load_yaml_mapping(file)
    assert error.value.file == file
    return list(error.value.problems)


def test_missing_file(tmp_path: Path) -> None:
    with pytest.raises(ContractError) as error:
        load_yaml_mapping(tmp_path / "primer.yaml")
    assert [p.code for p in error.value.problems] == ["Y.missing"]


@pytest.mark.parametrize("text", ["", "\n", "# only a comment\n"])
def test_empty_file(tmp_path: Path, text: str) -> None:
    assert [p.code for p in _problems(tmp_path, text)] == ["Y.empty"]


def test_not_yaml_names_the_line(tmp_path: Path) -> None:
    [problem] = _problems(tmp_path, "a: 1\nb: [unclosed\n")
    assert problem.code == "Y.syntax"
    assert "line" in problem.message


def test_not_utf8(tmp_path: Path) -> None:
    assert [p.code for p in _problems(tmp_path, b"a: \xff\n")] == ["Y.syntax"]


@pytest.mark.parametrize("text", ["- a\n- b\n", "just a string\n", "42\n"])
def test_root_must_be_a_mapping(tmp_path: Path, text: str) -> None:
    assert [p.code for p in _problems(tmp_path, text)] == ["Y.root"]


def test_duplicate_keys_at_every_level_all_at_once(tmp_path: Path) -> None:
    text = (
        "schema: 1\n"  # line 1
        "env:\n"
        "  A: {source: minted}\n"  # line 3
        "  A: {source: asked}\n"  # line 4
        "list:\n"
        "  - {x: 1, x: 2}\n"  # line 6
        "schema: 1\n"  # line 7
    )
    found = _problems(tmp_path, text)
    assert [(p.path, p.code) for p in found] == [
        ("env.A", "Y.duplicate"),
        ("list[0].x", "Y.duplicate"),
        ("schema", "Y.duplicate"),
    ]
    assert "lines 3 and 4" in found[0].message
    assert "lines 1 and 7" in found[2].message


def test_merge_key_is_rejected(tmp_path: Path) -> None:
    text = "base: &b {k: 1}\nother:\n  <<: *b\n  k: 2\n"
    [problem] = _problems(tmp_path, text)
    assert (problem.path, problem.code) == ("other", "Y.merge")


def test_anchor_and_alias_without_merge_are_allowed(tmp_path: Path) -> None:
    file = tmp_path / "primer.yaml"
    file.write_text("base: &b {k: 1}\nother: *b\n")
    assert load_yaml_mapping(file) == {"base": {"k": 1}, "other": {"k": 1}}


def test_recursive_alias_does_not_hang(tmp_path: Path) -> None:
    file = tmp_path / "primer.yaml"
    file.write_text("a: &x [1, *x]\n")
    data = load_yaml_mapping(file)
    assert isinstance(data["a"], list)


def test_error_text_names_file_path_and_code(tmp_path: Path) -> None:
    file = tmp_path / "primer.yaml"
    file.write_text("a: 1\na: 2\n")
    with pytest.raises(ContractError) as error:
        load_yaml_mapping(file)
    assert str(file) in str(error.value)
    assert "a: [Y.duplicate]" in str(error.value)


MARKER = "LEAK-MARKER-5f3a"


@pytest.mark.parametrize(
    "text",
    [
        f'a:\n  T: "{MARKER}\n',  # unterminated quote
        f"a:\n  T: [{MARKER}\n",  # unclosed flow sequence
        f"a:\n  T: {MARKER}: x\n",  # mapping value where none is allowed
        f"a:\n  T: !!python/object:os.system {MARKER}\n",  # unknown tag
        f"a:\n  T: !!int {MARKER}\n",  # construction fails, ValueError
        f"a:\n  !!int {MARKER}: x\n",  # key construction fails in the walk
        f"a:\n  T: !!timestamp {MARKER}\n",  # construction fails, AttributeError
        f"a: !!omap [{MARKER}]\n",  # construction fails, ConstructorError
        "a:\n  T: 2026-13-45\n",  # implicit timestamp that is not a date
    ],
)
def test_yaml_error_never_quotes_the_source(tmp_path: Path, text: str) -> None:
    """A contract file may hold secrets: no snippet, no chained parser error.

    The problem names the line where the parser can tell it; the source text
    reaches neither the message nor a traceback.
    """
    file = tmp_path / "passport.yaml"
    file.write_text(text)
    with pytest.raises(ContractError) as caught:
        load_yaml_mapping(file)
    error = caught.value
    assert [p.code for p in error.problems] == ["Y.syntax"]
    assert error.problems[0].message
    assert error.__cause__ is None
    assert error.__context__ is None
    printed = str(error) + "".join(traceback.format_exception(error))
    assert MARKER not in printed


def test_yaml_error_names_line_and_column(tmp_path: Path) -> None:
    [problem] = _problems(tmp_path, "a: 1\nb: c: d\n")
    assert problem.message == (
        "not valid YAML at line 2, column 5: mapping values are not allowed here"
    )
