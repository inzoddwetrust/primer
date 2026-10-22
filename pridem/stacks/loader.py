"""Loading contract files: strict YAML and errors that name file, path and rule.

``yaml.safe_load`` silently keeps the last of two equal keys and lets a merge
key (``<<``) override fields; both hide a mistake in a contract file. The
loader walks the composed YAML graph first and reports every duplicate key
(with both lines) and every merge key, all at once; only then is the document
constructed. Anchors and aliases without merge are allowed.
"""

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

import yaml
from pydantic import ValidationError

MERGE_TAG = "tag:yaml.org,2002:merge"


@dataclass(frozen=True)
class Problem:
    """One violation: where in the file, which check, what is wrong."""

    path: str
    code: str
    message: str

    def __str__(self) -> str:
        return f"{self.path or '<root>'}: [{self.code}] {self.message}"


class ContractError(Exception):
    """A contract file was rejected; carries every problem found, not the first."""

    def __init__(self, file: Path, problems: Sequence[Problem]) -> None:
        self.file = file
        self.problems = tuple(problems)
        lines = "\n".join(f"  {problem}" for problem in self.problems)
        super().__init__(f"{file}: {len(self.problems)} problem(s)\n{lines}")


def render_path(loc: Iterable[int | str]) -> str:
    """Render a path as ``a.b[0].c``."""
    out = ""
    for segment in loc:
        if isinstance(segment, int):
            out += f"[{segment}]"
        else:
            out += f".{segment}" if out else segment
    return out


def _walk(
    node: yaml.Node, path: tuple[int | str, ...], seen: set[int], out: list[Problem]
) -> None:
    if id(node) in seen:
        return
    seen = seen | {id(node)}
    if isinstance(node, yaml.SequenceNode):
        for index, item in enumerate(node.value):
            _walk(item, (*path, index), seen, out)
    elif isinstance(node, yaml.MappingNode):
        first: dict[object, int] = {}
        constructor = yaml.SafeLoader("")
        for key_node, value_node in node.value:
            line = key_node.start_mark.line + 1
            if key_node.tag == MERGE_TAG:
                out.append(
                    Problem(
                        render_path(path),
                        "Y.merge",
                        f"merge key '<<' at line {line} is not allowed: "
                        "it silently overrides fields",
                    )
                )
                continue
            key = constructor.construct_object(key_node, deep=True)
            label = key if isinstance(key, int | str) else repr(key)
            hashable = repr(key) if isinstance(key, list | dict) else key
            if hashable in first:
                out.append(
                    Problem(
                        render_path((*path, label)),
                        "Y.duplicate",
                        f"duplicate key {key!r} at lines {first[hashable]} and {line}",
                    )
                )
            else:
                first[hashable] = line
            _walk(value_node, (*path, label), seen, out)


def load_yaml_mapping(file: Path) -> dict[str, object]:
    """Read ``file`` as one YAML mapping, rejecting duplicates and merge keys."""
    if not file.is_file():
        raise ContractError(file, [Problem("", "Y.missing", "file not found")])
    try:
        text = file.read_text(encoding="utf-8")
        node = yaml.compose(text, Loader=yaml.SafeLoader)
    except UnicodeDecodeError as error:
        raise ContractError(
            file, [Problem("", "Y.syntax", f"not UTF-8: {error}")]
        ) from error
    except yaml.YAMLError as error:
        raise ContractError(
            file, [Problem("", "Y.syntax", f"not valid YAML: {error}")]
        ) from error
    if node is None:
        raise ContractError(file, [Problem("", "Y.empty", "file is empty")])
    if not isinstance(node, yaml.MappingNode):
        raise ContractError(
            file, [Problem("", "Y.root", "top level must be a mapping")]
        )
    problems: list[Problem] = []
    _walk(node, (), set(), problems)
    if problems:
        raise ContractError(file, problems)
    data = yaml.safe_load(text)
    if not isinstance(data, dict):
        raise ContractError(
            file, [Problem("", "Y.root", "top level must be a mapping")]
        )
    return data


def _data_path(data: object, loc: tuple[int | str, ...], missing: bool) -> str:
    """Keep only the segments that exist in ``data``.

    pydantic puts union tags (``service``, ``derived``) and union member names
    into an error location; they are not in the file, so the path a person
    reads skips them. The last segment of a ``missing`` error is the absent
    key itself and is kept.
    """
    kept: list[int | str] = []
    node = data
    for index, segment in enumerate(loc):
        if isinstance(node, Mapping) and segment in node:
            kept.append(segment)
            node = node[segment]
        elif (
            isinstance(node, list)
            and isinstance(segment, int)
            and 0 <= segment < len(node)
        ):
            kept.append(segment)
            node = node[segment]
        elif missing and index == len(loc) - 1:
            kept.append(segment)
    return render_path(kept)


def field_problems(data: object, error: ValidationError) -> list[Problem]:
    """Turn a pydantic error into problems with file paths, every one of them."""
    return [
        Problem(
            _data_path(data, tuple(item["loc"]), item["type"] == "missing"),
            item["type"],
            item["msg"],
        )
        for item in error.errors(include_url=False)
    ]
