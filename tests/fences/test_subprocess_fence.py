"""Fence: external commands start only in ``pridem/runner.py``.

The fence walks the AST of every ``*.py`` under ``pridem/`` and ``tests/`` and
reports, with file and line, every way of starting a process it knows:

- importing ``subprocess``, ``pty``, ``asyncio.subprocess`` or
  ``_posixsubprocess`` in any form (``import``, ``import as``, ``from ... import``);
- referring to ``os.system``, ``os.popen``, ``os.spawn*``, ``os.exec*``,
  ``os.posix_spawn``, ``os.posix_spawnp``, ``os.fork``, ``os.forkpty``,
  ``asyncio.create_subprocess_exec`` or ``asyncio.create_subprocess_shell``,
  called or not, through the module name, an alias or ``from ... import``;
- ``from os import *`` and ``from asyncio import *``, which hide what they bind;
- dynamic access with a constant string: ``getattr(os, "system")``, and getting
  a module by name -- ``__import__``, ``builtins.__import__``,
  ``importlib.__import__``, ``importlib.import_module``, ``sys.modules[...]``,
  ``sys.modules.get/pop/setdefault(...)``, through any alias or
  ``from ... import`` -- when the name is a forbidden module or a module whose
  names are forbidden (``os``, ``asyncio``): the fence cannot follow a module
  object once it is out of a name, so getting it is the violation.

``pridem/runner.py`` is the one allowed file: its hits are counted, not
reported, and the green test requires at least one, so a fence that sees
nothing cannot pass. ruff ``S`` does not replace this fence: it misses
``os.posix_spawn``, ``asyncio.create_subprocess_*`` and ``pty`` and every rule
can be silenced with ``noqa`` (measured on ruff 0.17.1).

Loading code by a computed name or from a string, and ``ctypes``, are forbidden
in ``pridem/`` and ``tests/`` by ``tests/fences/test_import_direction_fence.py``.

KNOWN CEILING: a module whose names are forbidden, reached past a tracked name.
1. Mechanics: the fence follows a module only through the names ``import`` binds
   and reads constant strings. Three forms reach ``os.system`` without that
   trace: ``getattr`` with a computed attribute name (``getattr(os, "sys" +
   "tem")``); a module object that leaves its name -- assigned (``m = os``),
   passed as an argument, stored in an attribute or a container, returned;
   attribute access through ``__dict__``, ``vars()``, ``__getattribute__`` or
   ``__builtins__``.
2. Status: acknowledged by design.
3. Task: none -- these are ordinary constructs that cannot be forbidden as a
   whole; the tree uses one of them harmlessly (``tests/test_probe_DM_7_state.py``
   passes ``os`` to ``monkeypatch.setattr`` for ``os.replace``).
4. Trigger: a file under ``pridem/`` or ``tests/`` uses one of these forms on
   ``os`` or ``asyncio`` to reach a name in ``FORBIDDEN_NAMES``.
5. Agreed fix: on the trigger, the fence reports that form itself as a
   violation outside ``runner.py``.
6. Rejected: forbidding the forms everywhere -- they are ordinary constructs
   (dispatcher answers to the DM-34 and DM-40 gates);
   ``multiprocessing`` and ``concurrent.futures.ProcessPoolExecutor`` are not
   fenced -- they start Python workers, not external commands (dispatcher
   answer to the DM-5 gate); a runtime audit hook (``sys.addaudithook`` on
   ``subprocess.Popen``/``os.system``) is rejected because it sees only the paths
   a test run happens to execute, while the fence must cover the whole tree.
"""

import ast
from dataclasses import dataclass
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
SCANNED_DIRS = ("pridem", "tests")
ALLOWED_FILE = "pridem/runner.py"

FORBIDDEN_MODULES = frozenset(
    {"subprocess", "pty", "asyncio.subprocess", "_posixsubprocess"}
)
FORBIDDEN_NAMES = {
    "os": frozenset(
        {"system", "popen", "posix_spawn", "posix_spawnp", "fork", "forkpty"}
    ),
    "asyncio": frozenset(
        {"create_subprocess_exec", "create_subprocess_shell", "subprocess"}
    ),
}
FORBIDDEN_PREFIXES = {"os": ("spawn", "exec")}
MODULE_GETTERS = frozenset(
    {"builtins.__import__", "importlib.__import__", "importlib.import_module"}
)
SYS_MODULES = "sys.modules"
SYS_MODULES_METHODS = frozenset({"get", "pop", "setdefault"})


@dataclass(frozen=True)
class Hit:
    path: str
    line: int
    what: str


@dataclass(frozen=True)
class FenceReport:
    scanned: int
    violations: tuple[Hit, ...]
    allowed: tuple[Hit, ...]


def _forbidden_module(name: str) -> bool:
    return any(name == m or name.startswith(f"{m}.") for m in FORBIDDEN_MODULES)


def _forbidden_name(module: str, name: str) -> bool:
    if name in FORBIDDEN_NAMES.get(module, frozenset()):
        return True
    return name.startswith(FORBIDDEN_PREFIXES.get(module, ()))


def _fenced_module(name: str) -> bool:
    """A module that may not be got by name: forbidden, or with forbidden names."""
    return _forbidden_module(name) or name in FORBIDDEN_NAMES


def _constant_str(node: ast.expr | None) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


class _Visitor(ast.NodeVisitor):
    """Collects hits; module aliases are tracked per file, without scopes."""

    def __init__(self, path: str) -> None:
        self.path = path
        self.hits: list[Hit] = []
        self.modules: dict[str, str] = {}
        self.bound: dict[str, str] = {}

    def _hit(self, node: ast.stmt | ast.expr, what: str) -> None:
        self.hits.append(Hit(self.path, node.lineno, what))

    def _qualified(self, node: ast.expr) -> str | None:
        """Dotted name of an expression; an unbound name is a builtin."""
        if isinstance(node, ast.Name):
            return self.bound.get(node.id, f"builtins.{node.id}")
        if isinstance(node, ast.Attribute):
            head = self._qualified(node.value)
            return None if head is None else f"{head}.{node.attr}"
        return None

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            if _forbidden_module(alias.name):
                self._hit(node, f"import {alias.name}")
            top = alias.name.split(".")[0]
            if alias.asname is not None:
                self.modules[alias.asname] = alias.name
                self.bound[alias.asname] = alias.name
            else:
                self.modules[top] = top
                self.bound[top] = top
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        module = node.module or ""
        if node.level == 0 and _forbidden_module(module):
            self._hit(node, f"from {module} import ...")
        elif node.level == 0:
            for alias in node.names:
                if alias.name == "*" and module in FORBIDDEN_NAMES:
                    self._hit(node, f"from {module} import *")
                elif _forbidden_name(module, alias.name):
                    self._hit(node, f"from {module} import {alias.name}")
                self.bound[alias.asname or alias.name] = f"{module}.{alias.name}"
        self.generic_visit(node)

    def visit_Attribute(self, node: ast.Attribute) -> None:
        if isinstance(node.value, ast.Name):
            module = self.modules.get(node.value.id)
            if module is not None and _forbidden_name(module, node.attr):
                self._hit(node, f"{module}.{node.attr}")
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        func = node.func
        qualified = self._qualified(func) or ""
        first = node.args[0] if node.args else None
        if qualified in MODULE_GETTERS:
            if first is None:
                first = next((k.value for k in node.keywords if k.arg == "name"), None)
            name = _constant_str(first)
            if name is not None and _fenced_module(name):
                self._hit(node, f"dynamic import of {name}")
        owner, _, method = qualified.rpartition(".")
        if owner == SYS_MODULES and method in SYS_MODULES_METHODS:
            key = _constant_str(first)
            if key is not None and _fenced_module(key):
                self._hit(node, f"sys.modules.{method}({key!r})")
        if (
            isinstance(func, ast.Name)
            and func.id == "getattr"
            and len(node.args) >= 2
            and isinstance(node.args[0], ast.Name)
        ):
            module = self.modules.get(node.args[0].id)
            attr = _constant_str(node.args[1])
            if (
                module is not None
                and attr is not None
                and _forbidden_name(module, attr)
            ):
                self._hit(node, f"getattr({module}, {attr!r})")
        self.generic_visit(node)

    def visit_Subscript(self, node: ast.Subscript) -> None:
        value = node.value
        key = _constant_str(node.slice)
        if (
            key is not None
            and _fenced_module(key)
            and self._qualified(value) == SYS_MODULES
        ):
            self._hit(node, f"sys.modules[{key!r}]")
        self.generic_visit(node)


def scan(root: Path) -> FenceReport:
    """Scan ``pridem/`` and ``tests/`` under ``root``."""
    files = sorted(
        path for directory in SCANNED_DIRS for path in (root / directory).rglob("*.py")
    )
    violations: list[Hit] = []
    allowed: list[Hit] = []
    for path in files:
        relative = path.relative_to(root).as_posix()
        visitor = _Visitor(relative)
        visitor.visit(ast.parse(path.read_text(), filename=relative))
        (allowed if relative == ALLOWED_FILE else violations).extend(visitor.hits)
    return FenceReport(len(files), tuple(violations), tuple(allowed))


def _plant(root: Path, source: str) -> FenceReport:
    (root / "pridem").mkdir(parents=True, exist_ok=True)
    (root / "tests").mkdir(parents=True, exist_ok=True)
    (root / "pridem" / "runner.py").write_text("import subprocess\n")
    (root / "pridem" / "planted.py").write_text(source)
    return scan(root)


def test_probe_DM_5_subprocess_fence(tmp_path: Path) -> None:
    planted = _plant(tmp_path, 'import os\n\nos.system("true")\n')
    assert planted.violations == (Hit("pridem/planted.py", 3, "os.system"),)

    tree = scan(REPO)
    assert tree.scanned > 0
    assert len(tree.allowed) >= 1, "the fence saw nothing in runner.py"
    assert tree.violations == (), "\n".join(map(str, tree.violations))


FORMS = [
    ("import subprocess\n", 1),
    ("import subprocess as sp\n", 1),
    ("from subprocess import run\n", 1),
    ("import pty\n", 1),
    ("import _posixsubprocess\n", 1),
    ("import asyncio.subprocess\n", 1),
    ("from asyncio import subprocess\n", 1),
    ("import os\nos.popen('x')\n", 2),
    ("import os\nos.spawnl(os.P_WAIT, '/bin/true', 'true')\n", 2),
    ("import os\nos.execv('/bin/true', ['true'])\n", 2),
    ("import os\nos.posix_spawn('/bin/true', ['true'], {})\n", 2),
    ("import os\nos.posix_spawnp('true', ['true'], {})\n", 2),
    ("import os\nos.fork()\n", 2),
    ("import os\nos.forkpty()\n", 2),
    ("import os\nf = os.system\n", 2),
    ("import os as o\no.system('x')\n", 2),
    ("from os import system\n", 1),
    ("from os import system as s\n", 1),
    ("from os import *\n", 1),
    ("from asyncio import *\n", 1),
    ("import asyncio\nasyncio.create_subprocess_exec('x')\n", 2),
    ("import asyncio\nasyncio.create_subprocess_shell('x')\n", 2),
    ("from asyncio import create_subprocess_exec\n", 1),
    ("__import__('subprocess')\n", 1),
    ("import importlib\nimportlib.import_module('subprocess')\n", 2),
    ("from importlib import import_module\nimport_module('pty')\n", 2),
    ("import os\ngetattr(os, 'system')('x')\n", 2),
    ("import sys\nsys.modules['subprocess']\n", 2),
]


@pytest.mark.parametrize(("source", "line"), FORMS)
def test_fence_reports_form(tmp_path: Path, source: str, line: int) -> None:
    report = _plant(tmp_path, source)
    assert [hit.line for hit in report.violations] == [line], report.violations
    assert len(report.allowed) == 1


CLEAN = [
    "import os\nos.environ.get('X')\n",
    "import os\nos.path.join('a', 'b')\nos.kill(1, 0)\n",
    "from os import path, environ\n",
    "import asyncio\nasyncio.run(None)\n",
    "import importlib\nimportlib.import_module('json')\n",
    "import os\ngetattr(os, 'environ')\n",
    "import sys\nsys.modules['json']\n",
    "text = 'import subprocess; os.system(1)'\n",
    "from pridem.runner import SubprocessRunner\n",
]


@pytest.mark.parametrize("source", CLEAN)
def test_fence_passes_clean_twin(tmp_path: Path, source: str) -> None:
    report = _plant(tmp_path, source)
    assert report.violations == ()
    assert report.scanned == 2


def test_fence_reports_every_hit_in_a_file(tmp_path: Path) -> None:
    report = _plant(tmp_path, "import os\nos.system('a')\nos.system('b')\n")
    assert [hit.line for hit in report.violations] == [2, 3]


GETTER_FORMS = [
    ("import builtins\nbuiltins.__import__({m!r})\n", 2),
    ("from builtins import __import__ as imp\nimp({m!r})\n", 2),
    ("__import__({m!r})\n", 1),
    ("import importlib\nimportlib.__import__({m!r})\n", 2),
    ("from importlib import __import__\n__import__({m!r})\n", 2),
    ("import importlib\nimportlib.import_module({m!r})\n", 2),
    ("import importlib as il\nil.import_module(name={m!r})\n", 2),
    ("from importlib import import_module\nimport_module({m!r})\n", 2),
    ("import sys\nsys.modules[{m!r}]\n", 2),
    ("import sys as s\ns.modules[{m!r}]\n", 2),
    ("from sys import modules\nmodules[{m!r}]\n", 2),
    ("import sys\nsys.modules.get({m!r})\n", 2),
    ("import sys\nsys.modules.get({m!r}).system('x')\n", 2),
    ("from sys import modules as mods\nmods.get({m!r})\n", 2),
    ("import sys\nsys.modules.pop({m!r})\n", 2),
    ("import sys\nsys.modules.setdefault({m!r}, None)\n", 2),
]


@pytest.mark.parametrize("module", ["subprocess", "os", "asyncio"])
@pytest.mark.parametrize(("form", "line"), GETTER_FORMS)
def test_probe_DM_40_builtins_import_is_red(
    tmp_path: Path, form: str, line: int, module: str
) -> None:
    """Getting a fenced module by a constant name is red; ``json`` is not."""
    planted = _plant(tmp_path / "planted", form.format(m=module))
    assert [hit.line for hit in planted.violations] == [line], planted.violations
    assert len(planted.allowed) == 1

    pair = _plant(tmp_path / "pair", form.format(m="json"))
    assert pair.violations == ()
    assert pair.scanned == 2

    tree = scan(REPO)
    assert len(tree.allowed) >= 1
    assert tree.violations == ()
