"""Probe DM-1: the repository mypy config rejects an explicit ``Any``.

``mypy --strict`` alone accepts ``def f(x: Any) -> Any`` (measured on the pinned
mypy 2.4.0); the line's strictness comes from ``disallow_any_explicit``. The
probe runs mypy with the repository config on a module with an explicit ``Any``,
which must be red with ``[explicit-any]``, and on its twin without ``Any``, which
must be green, so a config that rejects everything does not pass either.
"""

import subprocess
import sys
from pathlib import Path

_CONFIG = Path(__file__).resolve().parent.parent / "pyproject.toml"

_WITH_ANY = """from typing import Any


def f(x: Any) -> Any:
    return x
"""

_WITHOUT_ANY = """def f(x: int) -> int:
    return x
"""


def _mypy(module: Path, cache_dir: Path) -> subprocess.CompletedProcess[str]:
    # runner appears in DM-5; this test pins tooling, not machine behaviour
    return subprocess.run(  # noqa: S603
        [
            sys.executable,
            "-m",
            "mypy",
            "--config-file",
            str(_CONFIG),
            "--cache-dir",
            str(cache_dir),
            str(module),
        ],
        capture_output=True,
        text=True,
        check=False,
    )


def test_probe_DM_1_explicit_any_is_red(tmp_path: Path) -> None:
    with_any = tmp_path / "with_any.py"
    with_any.write_text(_WITH_ANY)
    without_any = tmp_path / "without_any.py"
    without_any.write_text(_WITHOUT_ANY)
    cache_dir = tmp_path / "mypy_cache"

    red = _mypy(with_any, cache_dir)
    assert red.returncode == 1, red.stdout + red.stderr
    assert "[explicit-any]" in red.stdout, red.stdout + red.stderr

    green = _mypy(without_any, cache_dir)
    assert green.returncode == 0, green.stdout + green.stderr
