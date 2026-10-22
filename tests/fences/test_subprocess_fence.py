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
- dynamic access with a constant string: ``__import__("subprocess")``,
  ``importlib.import_module("subprocess")``, ``getattr(os, "system")``,
  ``sys.modules["subprocess"]``.

``pridem/runner.py`` is the one allowed file: its hits are counted, not
reported, and the green test requires at least one, so a fence that sees
nothing cannot pass. ruff ``S`` does not replace this fence: it misses
``os.posix_spawn``, ``asyncio.create_subprocess_*`` and ``pty`` and every rule
can be silenced with ``noqa`` (measured on ruff 0.17.1).

KNOWN CEILING: process start the fence cannot see.
1. Mechanics: the fence reads names and constant strings in the AST. A module
   or attribute name built at run time (``getattr(os, "sys" + "tem")``,
   ``importlib.import_module(name)``), a call through ``ctypes`` into libc
   ``system``/``execve``, or code loaded from outside ``pridem/`` and ``tests/``
   starts a process without a trace in the AST.
2. Status: acknowledged by design.
3. Task: none -- no code in the line builds module names at run time or uses
   ``ctypes``; the ceiling is a property of static analysis, not a backlog item.
4. Trigger: a file under ``pridem/`` or ``tests/`` imports ``ctypes`` or calls
   ``importlib.import_module``, ``__import__`` or ``getattr`` with a non-constant
   name argument.
5. Agreed fix: on the trigger, the fence reports that form itself (``ctypes``
   import, non-constant dynamic access) as a violation outside ``runner.py``.
6. Rejected: ``multiprocessing`` and ``concurrent.futures.ProcessPoolExecutor``
   are not fenced -- they start Python workers, not external commands (dispatcher
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


def _constant_str(node: ast.expr) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


class _Visitor(ast.NodeVisitor):
    """Collects hits; module aliases are tracked per file, without scopes."""

    def __init__(self, path: str) -> None:
        self.path = path
        self.hits: list[Hit] = []
        self.modules: dict[str, str] = {}
        self.import_module_names: set[str] = set()

    def _hit(self, node: ast.stmt | ast.expr, what: str) -> None:
        self.hits.append(Hit(self.path, node.lineno, what))

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            if _forbidden_module(alias.name):
                self._hit(node, f"import {alias.name}")
            top = alias.name.split(".")[0]
            if alias.asname is not None:
                self.modules[alias.asname] = alias.name
            else:
                self.modules[top] = top
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
                elif module == "importlib" and alias.name == "import_module":
                    self.import_module_names.add(alias.asname or alias.name)
        self.generic_visit(node)

    def visit_Attribute(self, node: ast.Attribute) -> None:
        if isinstance(node.value, ast.Name):
            module = self.modules.get(node.value.id)
            if module is not None and _forbidden_name(module, node.attr):
                self._hit(node, f"{module}.{node.attr}")
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        name = _constant_str(node.args[0]) if node.args else None
        func = node.func
        if name is not None and _forbidden_module(name):
            dynamic_import = (
                isinstance(func, ast.Name)
                and (func.id == "__import__" or func.id in self.import_module_names)
            ) or (
                isinstance(func, ast.Attribute)
                and func.attr == "import_module"
                and isinstance(func.value, ast.Name)
                and self.modules.get(func.value.id) == "importlib"
            )
            if dynamic_import:
                self._hit(node, f"dynamic import of {name}")
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
            and _forbidden_module(key)
            and isinstance(value, ast.Attribute)
            and value.attr == "modules"
            and isinstance(value.value, ast.Name)
            and self.modules.get(value.value.id) == "sys"
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
