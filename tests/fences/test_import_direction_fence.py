"""Fence: imports inside ``pridem/`` follow the layers of TZ section 7.2.

Layers, lowest first (``LAYERS``): leaves -> ``steps``, ``stacks`` -> ``plan`` ->
``cli``, ``agent``. A module may import a module of its own layer or of a lower
one; importing a higher layer is a violation reported with file, line and the
pair "who -> whom". ``steps`` cannot know ``agent`` because ``agent`` is above it.

The map names every module of ``pridem/`` (a package is its ``__init__.py``).
A module missing from the map, a map entry without a module, a module in two
layers and an import of a ``pridem`` name that is not a module are violations:
a new module joins the map in the delivery that adds it.

An edge is every import the AST holds, wherever it stands -- module level,
function, class, ``if TYPE_CHECKING:``, ``try`` -- in every form: ``import``,
``import as``, ``from ... import`` (a submodule through its package resolves to
the submodule, any other name to the package), relative imports, and constant
dynamic access: ``importlib.import_module("pridem.x")`` (with a constant
``package`` for a relative name), ``__import__("pridem.x")`` and
``sys.modules["pridem.x"]``. Direction is a property of the architecture, not of
run time, so a deferred import is an edge like any other. Every cycle over the
edges is a violation that lists each edge of it; imports inside one layer are
allowed but may not close a cycle.

Loading code by a computed name or from a string is forbidden in ``pridem/``
and ``tests/`` (the area of the ``subprocess`` fence), because it bypasses both
this fence and the ``subprocess`` one: ``importlib.import_module`` and
``__import__`` with a non-constant name, ``exec`` and ``eval``, ``runpy``,
``importlib.util.spec_from_file_location`` and ``exec_module``,
``sys.modules[...]`` with a non-constant key, and ``ctypes``.

Module aliases are tracked per file, without scopes, as in the ``subprocess``
fence. ``tests/`` is outside the layer map: tests may import any module.
"""

import ast
import shutil
from dataclasses import dataclass
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
PACKAGE = "pridem"
BANNED_AREA = ("pridem", "tests", "tier3")  # tier3: DM-16
MAP_PATH = "<layer map>"

Layers = tuple[tuple[str, tuple[str, ...]], ...]

LAYERS: Layers = (
    (
        "leaf",
        (
            "pridem",
            "pridem.contract",
            "pridem.events",
            "pridem.report",
            "pridem.report.catalog",
            "pridem.report.codes",
            "pridem.report.render",
            "pridem.report.schema",
            "pridem.runner",
            "pridem.state",
        ),
    ),
    (
        "domain",
        (
            "pridem.conformance",
            "pridem.stacks",
            "pridem.stacks.loader",
            "pridem.stacks.lock",
            "pridem.stacks.passport",
            "pridem.stacks.schema",
            "pridem.stacks.stack",
            "pridem.steps",
            "pridem.steps.base",
        ),
    ),
    ("plan", ("pridem.plan",)),
    (
        "verbs",
        (
            "pridem.verbs",
            "pridem.verbs.base",
            "pridem.verbs.status",
            "pridem.verbs.version",
        ),
    ),
    ("top", ("pridem.agent", "pridem.cli")),
)

IMPORT_FUNCTIONS = frozenset(
    {"importlib.import_module", "importlib.__import__", "builtins.__import__"}
)
STRING_EXECUTORS = frozenset({"builtins.exec", "builtins.eval"})
BANNED_MODULES = frozenset({"runpy", "ctypes"})
SPEC_LOADER = "importlib.util.spec_from_file_location"
SYS_MODULES = "sys.modules"


@dataclass(frozen=True, order=True)
class Hit:
    path: str
    line: int
    what: str


@dataclass(frozen=True, order=True)
class Edge:
    path: str
    line: int
    importer: str
    target: str


@dataclass(frozen=True)
class FenceReport:
    modules: int
    edges: tuple[Edge, ...]
    violations: tuple[Hit, ...]


def _module_name(relative: Path) -> str:
    parts = list(relative.with_suffix("").parts)
    if parts[-1] == "__init__":
        parts.pop()
    return ".".join(parts)


def _constant_str(node: ast.expr | None) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _argument(node: ast.Call, position: int, keyword: str) -> ast.expr | None:
    if len(node.args) > position:
        return node.args[position]
    for item in node.keywords:
        if item.arg == keyword:
            return item.value
    return None


def _banned_module(name: str) -> bool:
    return any(name == m or name.startswith(f"{m}.") for m in BANNED_MODULES)


def _in_package(name: str) -> bool:
    return name == PACKAGE or name.startswith(f"{PACKAGE}.")


class _Visitor(ast.NodeVisitor):
    """Collects ``pridem`` names a file imports and the banned loads it makes."""

    def __init__(self, path: str, name: str, is_package: bool) -> None:
        self.path = path
        self.package = name if is_package else name.rpartition(".")[0]
        # (line, imported module, names taken from it; empty for a plain import)
        self.imports: list[tuple[int, str, tuple[str, ...]]] = []
        self.unresolved: list[tuple[int, str]] = []
        self.banned: list[Hit] = []
        self.bound: dict[str, str] = {}

    def _ban(self, node: ast.stmt | ast.expr, what: str) -> None:
        self.banned.append(Hit(self.path, node.lineno, f"code loaded {what}"))

    def _qualified(self, node: ast.expr) -> str | None:
        if isinstance(node, ast.Name):
            return self.bound.get(node.id, f"builtins.{node.id}")
        if isinstance(node, ast.Attribute):
            head = self._qualified(node.value)
            return None if head is None else f"{head}.{node.attr}"
        return None

    def _relative(self, level: int, module: str | None) -> str | None:
        parts = self.package.split(".")
        if level > len(parts):
            return None
        base = ".".join(parts[: len(parts) - level + 1])
        return f"{base}.{module}" if module else base

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            if _banned_module(alias.name):
                self._ban(node, f"through {alias.name}")
            if _in_package(alias.name):
                self.imports.append((node.lineno, alias.name, ()))
            if alias.asname is not None:
                self.bound[alias.asname] = alias.name
            else:
                top = alias.name.split(".")[0]
                self.bound[top] = top
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        if node.level:
            module = self._relative(node.level, node.module)
            if module is None:
                self.unresolved.append((node.lineno, "." * node.level))
                return
        else:
            module = node.module or ""
        if _banned_module(module):
            self._ban(node, f"through {module}")
        if _in_package(module):
            names = tuple(alias.name for alias in node.names)
            self.imports.append((node.lineno, module, names))
        for alias in node.names:
            qualified = f"{module}.{alias.name}"
            if qualified == SPEC_LOADER:
                self._ban(node, f"through {SPEC_LOADER}")
            self.bound[alias.asname or alias.name] = qualified
        self.generic_visit(node)

    def _dynamic_import(self, node: ast.Call, function: str) -> None:
        name = _constant_str(_argument(node, 0, "name"))
        package_node = (
            _argument(node, 1, "package")
            if function.endswith("import_module")
            else None
        )
        package = _constant_str(package_node)
        if name is None or (package_node is not None and package is None):
            self._ban(node, f"by a computed name: {function}")
            return
        if _banned_module(name):
            self._ban(node, f"through {name}")
        if name.startswith("."):
            level = len(name) - len(name.lstrip("."))
            if package is None or not _in_package(package):
                return
            parts = package.split(".")
            if level > len(parts):
                self.unresolved.append((node.lineno, name))
                return
            base = ".".join(parts[: len(parts) - level + 1])
            rest = name[level:]
            name = f"{base}.{rest}" if rest else base
        if _in_package(name):
            self.imports.append((node.lineno, name, ()))

    def visit_Call(self, node: ast.Call) -> None:
        function = self._qualified(node.func) or ""
        if function in IMPORT_FUNCTIONS:
            self._dynamic_import(node, function)
        elif function in STRING_EXECUTORS:
            self._ban(node, f"from a string: {function.removeprefix('builtins.')}")
        elif function == f"{SYS_MODULES}.get":
            key = _constant_str(_argument(node, 0, "key"))
            if key is None:
                self._ban(node, f"by a computed name: {SYS_MODULES}.get")
            elif _in_package(key):
                self.imports.append((node.lineno, key, ()))
        self.generic_visit(node)

    def visit_Attribute(self, node: ast.Attribute) -> None:
        if node.attr == "exec_module":
            self._ban(node, "through exec_module")
        elif self._qualified(node) == SPEC_LOADER:
            self._ban(node, f"through {SPEC_LOADER}")
        self.generic_visit(node)

    def visit_Subscript(self, node: ast.Subscript) -> None:
        if self._qualified(node.value) == SYS_MODULES:
            key = _constant_str(node.slice)
            if key is None:
                self._ban(node, f"by a computed name: {SYS_MODULES}[...]")
            elif _in_package(key):
                self.imports.append((node.lineno, key, ()))
        self.generic_visit(node)


def _resolve(module: str, names: tuple[str, ...], known: set[str]) -> list[str]:
    """Targets of one import: a submodule through its package, else the package."""
    if not names:
        return [module]
    targets = [
        f"{module}.{name}" if f"{module}.{name}" in known else module for name in names
    ]
    return sorted(set(targets))


def _in_cycle(edges: list[Edge]) -> list[Edge]:
    """Edges that lie on a cycle: the target reaches back to the importer."""
    graph: dict[str, set[str]] = {}
    for edge in edges:
        graph.setdefault(edge.importer, set()).add(edge.target)
    reach: dict[str, set[str]] = {}
    for start in graph:
        seen = {start}
        stack = [start]
        while stack:
            for nxt in graph.get(stack.pop(), set()):
                if nxt not in seen:
                    seen.add(nxt)
                    stack.append(nxt)
        reach[start] = seen
    return [edge for edge in edges if edge.importer in reach.get(edge.target, set())]


def scan(root: Path, layers: Layers = LAYERS) -> FenceReport:
    """Check ``pridem/`` against ``layers``; the load ban covers ``tests/`` too."""
    package_files = sorted((root / PACKAGE).rglob("*.py"))
    modules = {
        _module_name(path.relative_to(root)): path.relative_to(root).as_posix()
        for path in package_files
    }
    known = set(modules)
    violations: list[Hit] = []

    rank: dict[str, int] = {}
    layer_of: dict[str, str] = {}
    for index, (layer, members) in enumerate(layers):
        for module in members:
            if module in rank:
                violations.append(
                    Hit(MAP_PATH, 0, f"{module} is in two layers of the map")
                )
            rank[module] = index
            layer_of[module] = layer
    for module in sorted(known - set(rank)):
        violations.append(Hit(modules[module], 0, f"{module} is not in the layer map"))
    for module in sorted(set(rank) - known):
        violations.append(
            Hit(MAP_PATH, 0, f"{module} is in the layer map but not in {PACKAGE}/")
        )

    edges: list[Edge] = []
    for path in package_files:
        relative = path.relative_to(root)
        name = _module_name(relative)
        visitor = _Visitor(relative.as_posix(), name, path.name == "__init__.py")
        visitor.visit(ast.parse(path.read_text(), filename=relative.as_posix()))
        violations.extend(visitor.banned)
        for line, target in visitor.unresolved:
            violations.append(
                Hit(visitor.path, line, f"{name} -> {target}: beyond the package")
            )
        for line, module, names in visitor.imports:
            for target in _resolve(module, names, known):
                if target not in known:
                    violations.append(
                        Hit(
                            visitor.path,
                            line,
                            f"{name} -> {target}: not a module of {PACKAGE}",
                        )
                    )
                    continue
                edges.append(Edge(visitor.path, line, name, target))

    for edge in edges:
        if edge.importer in rank and edge.target in rank:
            if rank[edge.target] > rank[edge.importer]:
                violations.append(
                    Hit(
                        edge.path,
                        edge.line,
                        f"{edge.importer} ({layer_of[edge.importer]}) -> "
                        f"{edge.target} ({layer_of[edge.target]}): "
                        "import against the layer direction",
                    )
                )
    for edge in _in_cycle(edges):
        violations.append(
            Hit(edge.path, edge.line, f"cycle: {edge.importer} -> {edge.target}")
        )

    for directory in BANNED_AREA:
        if directory == PACKAGE:
            continue
        for path in sorted((root / directory).rglob("*.py")):
            relative = path.relative_to(root)
            visitor = _Visitor(relative.as_posix(), "", False)
            visitor.visit(ast.parse(path.read_text(), filename=relative.as_posix()))
            violations.extend(visitor.banned)

    return FenceReport(len(modules), tuple(sorted(edges)), tuple(sorted(violations)))


def _layers_with(layer: str, module: str) -> Layers:
    return tuple(
        (name, (*members, module) if name == layer else members)
        for name, members in LAYERS
    )


def _copy_tree(root: Path) -> None:
    shutil.copytree(
        REPO / PACKAGE,
        root / PACKAGE,
        ignore=shutil.ignore_patterns("__pycache__"),
    )
    (root / "tests").mkdir()


def _append(root: Path, relative: str, source: str) -> int:
    """Append ``source`` to a file; return the line number of its first line."""
    path = root / relative
    text = path.read_text()
    path.write_text(text + source)
    return len(text.splitlines()) + 1


def test_probe_DM_34_import_against_direction_is_red(tmp_path: Path) -> None:
    _copy_tree(tmp_path)
    (tmp_path / "pridem" / "steps" / "planted.py").write_text(
        "from pridem.plan import run_plan\n"
    )
    planted = scan(tmp_path, _layers_with("domain", "pridem.steps.planted"))
    assert planted.violations == (
        Hit(
            "pridem/steps/planted.py",
            1,
            "pridem.steps.planted (domain) -> pridem.plan (plan): "
            "import against the layer direction",
        ),
    )

    tree = scan(REPO)
    assert tree.violations == (), "\n".join(map(str, tree.violations))
    layer_of = {module: layer for layer, members in LAYERS for module in members}
    seen = {layer_of[edge.importer] for edge in tree.edges}
    assert seen == {layer for layer, _ in LAYERS}, "a layer without an edge"


def test_probe_DM_34_module_outside_map_is_red(tmp_path: Path) -> None:
    _copy_tree(tmp_path)
    (tmp_path / "pridem" / "steps" / "planted.py").write_text("")
    planted = scan(tmp_path)
    assert planted.violations == (
        Hit(
            "pridem/steps/planted.py",
            0,
            "pridem.steps.planted is not in the layer map",
        ),
    )

    tree = scan(REPO)
    assert tree.modules == sum(len(members) for _, members in LAYERS)
    assert tree.violations == ()


def test_probe_DM_34_import_cycle_is_red(tmp_path: Path) -> None:
    _copy_tree(tmp_path)
    (tmp_path / "pridem" / "stacks" / "planted.py").write_text(
        "def load() -> None:\n    from pridem.stacks.loader import load_yaml_mapping\n"
    )
    line = _append(
        tmp_path, "pridem/stacks/loader.py", "from pridem.stacks.planted import load\n"
    )
    planted = scan(tmp_path, _layers_with("domain", "pridem.stacks.planted"))
    assert planted.violations == (
        Hit(
            "pridem/stacks/loader.py",
            line,
            "cycle: pridem.stacks.loader -> pridem.stacks.planted",
        ),
        Hit(
            "pridem/stacks/planted.py",
            2,
            "cycle: pridem.stacks.planted -> pridem.stacks.loader",
        ),
    )

    tree = scan(REPO)
    assert _in_cycle(list(tree.edges)) == []
    assert tree.violations == ()


BANNED_FORMS = [
    ("import importlib\nimportlib.import_module(name)\n", 2),
    ("import importlib as il\nil.import_module(name)\n", 2),
    ("from importlib import import_module\nimport_module(name)\n", 2),
    ("import importlib\nimportlib.import_module('.x', package)\n", 2),
    ("import importlib\nimportlib.import_module()\n", 2),
    ("__import__(name)\n", 1),
    ("import importlib\nimportlib.__import__(name)\n", 2),
    ("exec('import pridem.plan')\n", 1),
    ("eval(source)\n", 1),
    ("import builtins\nbuiltins.exec(code)\n", 2),
    ("from builtins import eval as ev\nev(source)\n", 2),
    ("import runpy\n", 1),
    ("from runpy import run_module\n", 1),
    ("import importlib\nimportlib.import_module('runpy')\n", 2),
    ("import importlib.util\nimportlib.util.spec_from_file_location('m', p)\n", 2),
    ("from importlib.util import spec_from_file_location\n", 1),
    ("loader.exec_module(module)\n", 1),
    ("import sys\nsys.modules[name]\n", 2),
    ("from sys import modules\nmodules[name]\n", 2),
    ("import sys\nsys.modules.get(name)\n", 2),
    ("import ctypes\n", 1),
    ("import ctypes.util\n", 1),
    ("from ctypes import CDLL\n", 1),
    ("__import__('ctypes')\n", 1),
]


@pytest.mark.parametrize("where", ["pridem/cli.py", "tests/planted.py"])
@pytest.mark.parametrize(("source", "line"), BANNED_FORMS)
def test_probe_DM_34_nonconstant_dynamic_import_is_red(
    tmp_path: Path, where: str, source: str, line: int
) -> None:
    _copy_tree(tmp_path)
    if where.startswith("tests/"):
        (tmp_path / where).write_text(source)
        first = 1
    else:
        first = _append(tmp_path, where, source)
    report = scan(tmp_path)
    assert [(hit.path, hit.line) for hit in report.violations] == [
        (where, first + line - 1)
    ], report.violations
    assert report.violations[0].what.startswith("code loaded ")

    pair = tmp_path / "pair"
    _copy_tree(pair)
    first = _append(
        pair,
        "pridem/cli.py",
        "import importlib\nimport sys\n"
        "importlib.import_module('pridem.plan')\nsys.modules['pridem.events']\n",
    )
    constant = scan(pair)
    assert constant.violations == ()
    assert Edge("pridem/cli.py", first + 2, "pridem.cli", "pridem.plan") in (
        constant.edges
    )
    assert Edge("pridem/cli.py", first + 3, "pridem.cli", "pridem.events") in (
        constant.edges
    )


MINI_LAYERS: Layers = (
    ("low", ("pridem", "pridem.low", "pridem.pkg", "pridem.pkg.deep")),
    ("high", ("pridem.high", "pridem.hpkg", "pridem.hpkg.mod")),
)


def _mini(root: Path, files: dict[str, str]) -> FenceReport:
    tree = {
        "pridem/__init__.py": "",
        "pridem/low.py": "",
        "pridem/pkg/__init__.py": "",
        "pridem/pkg/deep.py": "",
        "pridem/high.py": "",
        "pridem/hpkg/__init__.py": "",
        "pridem/hpkg/mod.py": "",
    }
    tree.update(files)
    for relative, source in tree.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(source)
    (root / "tests").mkdir(exist_ok=True)
    return scan(root, MINI_LAYERS)


# Each form in pridem/pkg/deep.py (layer low), importing upward.
UPWARD_FORMS = [
    ("import pridem.high\n", 1, "pridem.high"),
    ("import pridem.high as h\n", 1, "pridem.high"),
    ("import pridem.hpkg.mod\n", 1, "pridem.hpkg.mod"),
    ("from pridem.high import x\n", 1, "pridem.high"),
    ("from pridem import high\n", 1, "pridem.high"),
    ("from pridem.hpkg import mod\n", 1, "pridem.hpkg.mod"),
    ("from pridem.hpkg import attr\n", 1, "pridem.hpkg"),
    ("from pridem.hpkg import *\n", 1, "pridem.hpkg"),
    ("from .. import high\n", 1, "pridem.high"),
    ("from ..high import x\n", 1, "pridem.high"),
    ("from ..hpkg.mod import x\n", 1, "pridem.hpkg.mod"),
    ("def f() -> None:\n    import pridem.high\n", 2, "pridem.high"),
    ("class C:\n    from pridem.high import x\n", 2, "pridem.high"),
    (
        "from typing import TYPE_CHECKING\nif TYPE_CHECKING:\n"
        "    from pridem.high import x\n",
        3,
        "pridem.high",
    ),
    (
        "try:\n    import pridem.high\nexcept ImportError:\n    raise\n",
        2,
        "pridem.high",
    ),
    ("import importlib\nimportlib.import_module('pridem.high')\n", 2, "pridem.high"),
    (
        "from importlib import import_module as im\nim('pridem.high')\n",
        2,
        "pridem.high",
    ),
    (
        "import importlib\nimportlib.import_module('..high', 'pridem.pkg')\n",
        2,
        "pridem.high",
    ),
    (
        "import importlib\n"
        "importlib.import_module(name='.mod', package='pridem.hpkg')\n",
        2,
        "pridem.hpkg.mod",
    ),
    ("__import__('pridem.high')\n", 1, "pridem.high"),
    ("import sys\nsys.modules['pridem.high']\n", 2, "pridem.high"),
    ("import sys as s\ns.modules.get('pridem.high')\n", 2, "pridem.high"),
]


@pytest.mark.parametrize(("source", "line", "target"), UPWARD_FORMS)
def test_fence_reports_upward_form(
    tmp_path: Path, source: str, line: int, target: str
) -> None:
    report = _mini(tmp_path, {"pridem/pkg/deep.py": source})
    assert report.violations == (
        Hit(
            "pridem/pkg/deep.py",
            line,
            f"pridem.pkg.deep (low) -> {target} (high): "
            "import against the layer direction",
        ),
    )


# The same forms downward, from pridem/hpkg/mod.py (layer high): an edge, green.
DOWNWARD_FORMS = [
    ("import pridem.low\n", 1, "pridem.low"),
    ("import pridem.low as h\n", 1, "pridem.low"),
    ("import pridem.pkg.deep\n", 1, "pridem.pkg.deep"),
    ("from pridem.low import x\n", 1, "pridem.low"),
    ("from pridem import low\n", 1, "pridem.low"),
    ("from pridem import __version__\n", 1, "pridem"),
    ("from pridem.pkg import deep\n", 1, "pridem.pkg.deep"),
    ("from pridem.pkg import *\n", 1, "pridem.pkg"),
    ("from .. import low\n", 1, "pridem.low"),
    ("from ..pkg.deep import x\n", 1, "pridem.pkg.deep"),
    ("from . import x\n", 1, "pridem.hpkg"),
    ("def f() -> None:\n    import pridem.low\n", 2, "pridem.low"),
    (
        "from typing import TYPE_CHECKING\nif TYPE_CHECKING:\n    import pridem.low\n",
        3,
        "pridem.low",
    ),
    ("import importlib\nimportlib.import_module('pridem.low')\n", 2, "pridem.low"),
    ("__import__('pridem.low')\n", 1, "pridem.low"),
    ("import sys\nsys.modules['pridem.low']\n", 2, "pridem.low"),
]


@pytest.mark.parametrize(("source", "line", "target"), DOWNWARD_FORMS)
def test_fence_passes_downward_twin(
    tmp_path: Path, source: str, line: int, target: str
) -> None:
    report = _mini(tmp_path, {"pridem/hpkg/mod.py": source})
    assert report.violations == ()
    assert report.edges == (
        Edge("pridem/hpkg/mod.py", line, "pridem.hpkg.mod", target),
    )


CLEAN = [
    "import json\nimport importlib\nimportlib.import_module('json')\n",
    "import sys\nsys.modules['json']\nsys.modules.get('json')\n",
    "text = 'import pridem.high; exec(x); import ctypes'\n",
    "import os\nos.path.join('a', 'b')\n",
]


@pytest.mark.parametrize("source", CLEAN)
def test_fence_ignores_clean_twin(tmp_path: Path, source: str) -> None:
    report = _mini(tmp_path, {"pridem/low.py": source})
    assert report.violations == ()
    assert report.edges == ()


def test_fence_reports_every_upward_import_in_a_file(tmp_path: Path) -> None:
    report = _mini(
        tmp_path, {"pridem/low.py": "import pridem.high\nimport pridem.hpkg.mod\n"}
    )
    assert [hit.line for hit in report.violations] == [1, 2]


def test_fence_allows_imports_inside_a_layer(tmp_path: Path) -> None:
    report = _mini(tmp_path, {"pridem/pkg/deep.py": "import pridem.low\n"})
    assert report.violations == ()
    assert len(report.edges) == 1


def test_fence_reports_stale_map_entry(tmp_path: Path) -> None:
    _copy_tree(tmp_path)
    report = scan(tmp_path, _layers_with("domain", "pridem.steps.ghost"))
    assert report.violations == (
        Hit(MAP_PATH, 0, "pridem.steps.ghost is in the layer map but not in pridem/"),
    )


def test_fence_reports_module_in_two_layers(tmp_path: Path) -> None:
    _copy_tree(tmp_path)
    report = scan(tmp_path, _layers_with("top", "pridem.plan"))
    assert report.violations == (
        Hit(MAP_PATH, 0, "pridem.plan is in two layers of the map"),
    )


def test_fence_reports_import_of_a_missing_module(tmp_path: Path) -> None:
    report = _mini(tmp_path, {"pridem/high.py": "from pridem.nope import x\n"})
    assert report.violations == (
        Hit("pridem/high.py", 1, "pridem.high -> pridem.nope: not a module of pridem"),
    )


def test_fence_reports_relative_import_beyond_the_package(tmp_path: Path) -> None:
    report = _mini(tmp_path, {"pridem/pkg/deep.py": "from ... import x\n"})
    assert report.violations == (
        Hit("pridem/pkg/deep.py", 1, "pridem.pkg.deep -> ...: beyond the package"),
    )


def test_fence_reports_self_import_as_cycle(tmp_path: Path) -> None:
    report = _mini(tmp_path, {"pridem/low.py": "import pridem.low\n"})
    assert report.violations == (
        Hit("pridem/low.py", 1, "cycle: pridem.low -> pridem.low"),
    )


def test_fence_sees_the_tree(tmp_path: Path) -> None:
    """The tree has the deferred edge DM-34 had to break, now one way only."""
    tree = scan(REPO)
    pairs = {(edge.importer, edge.target) for edge in tree.edges}
    assert ("pridem.stacks.lock", "pridem.stacks.schema") in pairs
    assert ("pridem.stacks.schema", "pridem.stacks.lock") not in pairs
    # DM-16: the CLI goes through the verbs; the version comes from the root
    assert ("pridem.cli", "pridem.verbs") in pairs
    assert ("pridem.verbs.version", "pridem") in pairs

    empty = tmp_path / "empty"
    (empty / "pridem").mkdir(parents=True)
    (empty / "tests").mkdir()
    nothing = scan(empty)
    assert nothing.modules == 0
    assert len(nothing.violations) == sum(len(members) for _, members in LAYERS)
