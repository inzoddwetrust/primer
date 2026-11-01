"""The one way the machine writes a file of its own (TZ 7.3).

``atomic_write`` puts ``data`` at ``path``. A temporary file ``.<name>.tmp``
beside it is created with ``O_CREAT | O_EXCL`` and ``mode``, and
``fchmod``-ed to ``mode`` before its first byte: a umask only narrows the
mode ``os.open`` gives, ``fchmod`` sets the exact one, and no byte is ever on
disk under another mode. The data is written and fsynced; the temporary file
is renamed over ``path`` -- or, ``exclusive``, linked to it, where a name
already taken is ``FileExistsError`` and keeps what it holds -- and the
directory is fsynced, so the new name survives a power loss. On any failure
``path`` is as it was and the temporary file is gone.

``staged_write`` is the same write with a check between the fsync and the
rename: the body of its ``with`` gets the temporary file and refuses it by
raising, so a file is checked from the very bytes that become ``path``.

The temporary name is fixed, so a writer that died leaves one file at most:
it is removed before the next write, and ``O_EXCL`` refuses whatever appears
at that name in between -- a planted symlink is never written through. That
rests on one writer per path, which the box lock gives: every write of the
machine runs under it (par0 8). The directory is the caller's and is never
created here, so its mode stays the caller's choice.
"""

import os
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

TEMP_SUFFIX = ".tmp"


def temp_of(path: Path) -> Path:
    """The temporary file of a write to ``path``."""
    return path.with_name(f".{path.name}{TEMP_SUFFIX}")


def fsync_dir(directory: Path) -> None:
    """Make the names in ``directory`` durable."""
    fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


@contextmanager
def staged_write(
    path: Path, data: bytes | str, mode: int, *, exclusive: bool = False
) -> Iterator[Path]:
    """``data`` in the temporary file of ``path`` for the body to check; it
    becomes ``path`` when the body ends without raising."""
    raw = data.encode("utf-8") if isinstance(data, str) else data
    temp = temp_of(path)
    temp.unlink(missing_ok=True)  # left by a writer that died
    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    try:
        try:
            os.fchmod(fd, mode)
            view = memoryview(raw)
            while view:
                view = view[os.write(fd, view) :]
            os.fsync(fd)
        finally:
            os.close(fd)
        yield temp
        if exclusive:
            os.link(temp, path)
        else:
            os.replace(temp, path)
    finally:
        # after a failure the temp goes; after replace there is none, after
        # link the final name holds the data
        temp.unlink(missing_ok=True)
    fsync_dir(path.parent)


def atomic_write(
    path: Path, data: bytes | str, mode: int, *, exclusive: bool = False
) -> None:
    """``data`` to ``path`` with ``mode``: temp, fsync, rename (``exclusive``:
    link), fsync of the directory."""
    with staged_write(path, data, mode, exclusive=exclusive):
        pass
