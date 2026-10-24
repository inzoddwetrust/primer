"""Loading contract files: strict YAML and errors that name file, path and rule.

A contract file may come from someone else's repository, so its form is checked
before it is parsed (contract 3 rule 16, contract 1 rule 13): a file larger
than ``MAX_BYTES`` is refused unread; then one pass over the parser's events --
which keep no tree and no recursion -- refuses every anchor and alias
(``Y.alias``) and nesting of collections deeper than ``MAX_DEPTH``
(``Y.depth``). Without anchors and aliases the composed graph is a tree, so no
node is shared and no cycle exists; ``yaml.compose`` runs only on a file that
passed.

``yaml.safe_load`` silently keeps the last of two equal keys and lets a merge
key (``<<``) override fields; both hide a mistake in a contract file. The
loader walks the composed tree and reports every duplicate key (with both
lines) and every merge key, all at once; only then is the document constructed.

A contract file may hold secrets (the passport does), so no problem quotes the
source: a YAML error is reported by line, column and the parser's own words,
never by pyyaml's snippet of the offending line, and ``ContractError`` is
raised outside ``except`` so no traceback prints the parser's exception.
"""

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

import yaml
from pydantic import ValidationError

MERGE_TAG = "tag:yaml.org,2002:merge"
MAX_BYTES = 1024 * 1024
MAX_DEPTH = 32


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


def _where(event: yaml.Event) -> str:
    mark = event.start_mark
    if mark is None:  # the stubs allow it; _yaml_error_text treats it the same way
        return "an unknown position"
    return f"line {mark.line + 1}, column {mark.column + 1}"


def _form_problems(text: str) -> list[Problem]:
    """Refuse anchors, aliases and deep nesting from the event stream.

    The parser keeps a state stack, not a recursion, and builds no nodes, so
    this pass is linear in the file. Every anchor and alias is reported; deep
    nesting once, where it first exceeds the limit. Names of anchors are
    source text and are not quoted.
    """
    out: list[Problem] = []
    depth = 0
    too_deep = False
    for event in yaml.parse(text, Loader=yaml.SafeLoader):
        if isinstance(event, yaml.AliasEvent):
            out.append(
                Problem(
                    "",
                    "Y.alias",
                    f"alias at {_where(event)}: anchors and aliases are not allowed",
                )
            )
        elif isinstance(event, yaml.NodeEvent) and event.anchor is not None:
            out.append(
                Problem(
                    "",
                    "Y.alias",
                    f"anchor at {_where(event)}: anchors and aliases are not allowed",
                )
            )
        if isinstance(event, yaml.CollectionStartEvent):
            depth += 1
            if depth > MAX_DEPTH and not too_deep:
                too_deep = True
                out.append(
                    Problem(
                        "",
                        "Y.depth",
                        f"collections nested deeper than {MAX_DEPTH} "
                        f"at {_where(event)}",
                    )
                )
        elif isinstance(event, yaml.CollectionEndEvent):
            depth -= 1
    return out


def _walk(node: yaml.Node, path: tuple[int | str, ...], out: list[Problem]) -> None:
    if isinstance(node, yaml.SequenceNode):
        for index, item in enumerate(node.value):
            _walk(item, (*path, index), out)
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
            _walk(value_node, (*path, label), out)


def _yaml_error_text(error: yaml.YAMLError) -> str:
    """The parser's words and position, without the snippet of the source line."""
    if isinstance(error, yaml.MarkedYAMLError):
        words = "; ".join(part for part in (error.context, error.problem) if part)
        mark = error.problem_mark or error.context_mark
        if mark is None:
            return f"not valid YAML: {words}"
        where = f"line {mark.line + 1}, column {mark.column + 1}"
        return f"not valid YAML at {where}: {words}"
    if isinstance(error, yaml.reader.ReaderError):
        return f"not valid YAML at position {error.position}: {error.reason}"
    return "not valid YAML"


def _read(file: Path) -> tuple[dict[str, object], list[Problem]]:
    """Parse ``file``; every failure is a problem, nothing is raised from here.

    Construction runs after the walk: an implicit scalar may still fail to
    construct (``2026-13-45`` is a timestamp by pattern and not a date), and
    so may a value under an explicit tag; such errors carry the value in their
    text, so only their type is reported.
    """
    with file.open("rb") as handle:
        raw = handle.read(MAX_BYTES + 1)
    if len(raw) > MAX_BYTES:
        return {}, [Problem("", "Y.size", f"file is larger than {MAX_BYTES} bytes")]
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        return {}, [Problem("", "Y.syntax", f"not UTF-8: {error}")]
    try:
        form = _form_problems(text)
        if form:
            return {}, form
        node = yaml.compose(text, Loader=yaml.SafeLoader)
    except yaml.YAMLError as error:
        return {}, [Problem("", "Y.syntax", _yaml_error_text(error))]
    if node is None:
        return {}, [Problem("", "Y.empty", "file is empty")]
    if not isinstance(node, yaml.MappingNode):
        return {}, [Problem("", "Y.root", "top level must be a mapping")]
    problems: list[Problem] = []
    try:
        _walk(node, (), problems)
        if problems:
            return {}, problems
        data = yaml.safe_load(text)
    except yaml.MarkedYAMLError as error:
        return {}, [Problem("", "Y.syntax", _yaml_error_text(error))]
    except (yaml.YAMLError, ValueError, TypeError, AttributeError) as error:
        return {}, [
            Problem(
                "",
                "Y.syntax",
                f"a value could not be constructed ({type(error).__name__})",
            )
        ]
    if not isinstance(data, dict):
        return {}, [Problem("", "Y.root", "top level must be a mapping")]
    return data, []


def load_yaml_mapping(file: Path) -> dict[str, object]:
    """Read ``file`` as one YAML mapping of the contract form, or raise."""
    if not file.is_file():
        raise ContractError(file, [Problem("", "Y.missing", "file not found")])
    data, problems = _read(file)
    if problems:
        raise ContractError(file, problems)
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
