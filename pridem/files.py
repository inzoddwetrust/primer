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

``write_set`` puts several files in place as one change: each is staged as
above, all are fsynced, then renamed in the caller's order with the directory
fsynced after each rename. ``commit_set`` does the same for temporary files a
command wrote (``openssl``, ``ssh-keygen``, ``age-keygen``): each is fsynced,
then renamed in order. A reader sees the old set or the new one, except
between two renames -- a crash there leaves the set torn, which is why the
order is the caller's (a key before its certificate, a public part before its
private key) and the caller's ``check`` must recognise a torn set (DM-80).

``private_dir`` makes a directory 0700, an existing one included: ``mkdir``
with ``exist_ok`` leaves an existing directory's mode as it is (DM-80).

The temporary name is fixed, so a writer that died leaves one file at most:
it is removed before the next write, and ``O_EXCL`` refuses whatever appears
at that name in between -- a planted symlink is never written through. That
rests on one writer per path, which the box lock gives: every write of the
machine runs under it (par0 8). A write never creates its directory: the
directory's mode is the caller's choice (``private_dir`` for a private one).
"""

import os
from collections.abc import Iterator, Sequence
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


class PathOutside(ValueError):
    """A path of a foreign tree that leaves it or goes through a symlink."""


def resolve_inside(root: Path, rel: str | Path) -> Path:
    """``root / rel`` where ``rel`` is relative, of names only (no ``..``), and
    no part from ``root`` down is a symlink (DM-78): a package, a release or
    the ops repository is someone else's tree, and a link in it -- out or even
    in -- would take the machine's read or write past what it checked. With
    the three, the path stays under ``root`` by construction. The path need
    not exist; what exists of it is checked. A refusal names no part of the
    path."""
    if Path(rel).is_absolute():
        raise PathOutside("an absolute path")
    target = Path(root)
    for part in Path(rel).parts:
        if part in ("", ".", ".."):
            raise PathOutside("a relative path of names only")
        target = target / part
        if target.is_symlink():
            raise PathOutside("a symlink in the path")
    return target


def _fsync_file(path: Path) -> None:
    fd = os.open(path, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def commit_set(pairs: Sequence[tuple[Path, Path]]) -> None:
    """Each ``(temporary, final)`` of ``pairs``: every temporary file fsynced
    first, then renamed over its final name in the given order, the directory
    fsynced after each rename. On a failure the temporary files left are
    removed; the finals already renamed stay -- the caller's order decides
    which partial set a crash can leave."""
    if not pairs:
        raise ValueError("commit_set: no files")
    try:
        for temp, _ in pairs:
            _fsync_file(temp)
        for temp, final in pairs:
            os.replace(temp, final)
            fsync_dir(final.parent)
    finally:
        for temp, _ in pairs:
            temp.unlink(missing_ok=True)


def write_set(items: Sequence[tuple[Path, bytes | str, int]]) -> None:
    """Each ``(path, data, mode)`` of ``items`` staged in its temporary file
    (as ``staged_write``), then all renamed in the given order by
    ``commit_set``: the files of one change, written as one."""
    if not items:
        raise ValueError("write_set: no files")
    pairs: list[tuple[Path, Path]] = []
    try:
        for path, data, mode in items:
            raw = data.encode("utf-8") if isinstance(data, str) else data
            temp = temp_of(path)
            temp.unlink(missing_ok=True)  # left by a writer that died
            fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
            pairs.append((temp, path))
            try:
                os.fchmod(fd, mode)
                view = memoryview(raw)
                while view:
                    view = view[os.write(fd, view) :]
                os.fsync(fd)
            finally:
                os.close(fd)
    except BaseException:
        for temp, _ in pairs:
            temp.unlink(missing_ok=True)
        raise
    commit_set(pairs)


def private_dir(path: Path) -> None:
    """``path`` a directory of mode 0700: made with its parents when missing,
    set to 0700 when it exists with another mode."""
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    if path.stat().st_mode & 0o777 != 0o700:
        path.chmod(0o700)
