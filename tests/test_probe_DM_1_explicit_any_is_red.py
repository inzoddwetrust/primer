"""Probe DM-1: the repository mypy config rejects an explicit ``Any``.

``mypy --strict`` alone accepts ``def f(x: Any) -> Any`` (measured on the pinned
mypy 2.4.0); the line's strictness comes from ``disallow_any_explicit``. The
probe runs mypy through the runner with the repository config on a module with
an explicit ``Any``, which must exit with code 1 and report ``[explicit-any]``,
and on its twin without ``Any``, which must exit with code 0, so a config that
rejects everything does not pass either.
"""

import sys
from pathlib import Path

from pridem.runner import Stream, SubprocessRunner

_CONFIG = Path(__file__).resolve().parent.parent / "pyproject.toml"
_TIMEOUT_SECONDS = 120.0

_WITH_ANY = """from typing import Any


def f(x: Any) -> Any:
    return x
"""

_WITHOUT_ANY = """def f(x: int) -> int:
    return x
"""


def _mypy(module: Path, cache_dir: Path, expect: tuple[int, ...]) -> list[str]:
    stdout: list[str] = []

    def collect(stream: Stream, line: str) -> None:
        if stream is Stream.STDOUT:
            stdout.append(line)

    SubprocessRunner().run(
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
        expect=expect,
        timeout=_TIMEOUT_SECONDS,
        on_line=collect,
    )
    return stdout


def test_probe_DM_1_explicit_any_is_red(tmp_path: Path) -> None:
    with_any = tmp_path / "with_any.py"
    with_any.write_text(_WITH_ANY)
    without_any = tmp_path / "without_any.py"
    without_any.write_text(_WITHOUT_ANY)
    cache_dir = tmp_path / "mypy_cache"

    red = _mypy(with_any, cache_dir, expect=(1,))
    assert any("[explicit-any]" in line for line in red), "\n".join(red)

    _mypy(without_any, cache_dir, expect=(0,))
