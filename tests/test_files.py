"""``atomic_write`` and ``staged_write`` (DM-54): the one write of the machine.

Files are real, in ``tmp``. The order of the system calls -- the mode before the
first byte, fsync of the file before the rename, of the directory after it --
is read by watching ``os``; a power loss is not simulated, so durability itself
is the kernel's, the calls are the machine's.
"""

import os
import stat
from collections.abc import Callable
from pathlib import Path

import pytest

from pridem.files import atomic_write, staged_write, temp_of


def mode(path: Path) -> int:
    return stat.S_IMODE(path.lstat().st_mode)


def names(directory: Path) -> list[str]:
    return sorted(path.name for path in directory.iterdir())


class Watched:
    """The calls of one write, in order, with what the file held at ``fchmod``."""

    def __init__(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self.calls: list[str] = []
        self.size_at_fchmod: list[int] = []
        fsync, fchmod = os.fsync, os.fchmod
        replace, link = os.replace, os.link

        def watch_fsync(fd: int) -> None:
            kind = "dir" if stat.S_ISDIR(os.fstat(fd).st_mode) else "file"
            self.calls.append(f"fsync {kind}")
            fsync(fd)

        def watch_fchmod(fd: int, mode: int) -> None:
            self.calls.append(f"fchmod {oct(mode)}")
            self.size_at_fchmod.append(os.fstat(fd).st_size)
            fchmod(fd, mode)

        def watch_replace(src: str, dst: str) -> None:
            self.calls.append("replace")
            replace(src, dst)

        def watch_link(src: str, dst: str) -> None:
            self.calls.append("link")
            link(src, dst)

        monkeypatch.setattr(os, "fsync", watch_fsync)
        monkeypatch.setattr(os, "fchmod", watch_fchmod)
        monkeypatch.setattr(os, "replace", watch_replace)
        monkeypatch.setattr(os, "link", watch_link)


@pytest.mark.parametrize("wanted", [0o600, 0o644])
def test_a_new_file_gets_its_data_and_mode_in_order(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, wanted: int
) -> None:
    watched = Watched(monkeypatch)
    path = tmp_path / "state.json"
    atomic_write(path, '{"a": 1}\n', wanted)
    assert path.read_text() == '{"a": 1}\n' and mode(path) == wanted
    assert watched.calls == [
        f"fchmod {oct(wanted)}",
        "fsync file",
        "replace",
        "fsync dir",
    ]
    assert watched.size_at_fchmod == [0]  # no byte before the mode
    assert names(tmp_path) == ["state.json"]


@pytest.mark.parametrize(("before", "wanted"), [(0o644, 0o600), (0o600, 0o644)])
def test_an_existing_file_is_replaced_whole_with_the_mode_given(
    tmp_path: Path, before: int, wanted: int
) -> None:
    path = tmp_path / "unit"
    path.write_bytes(b"old and longer than the new one\n")
    path.chmod(before)
    inode = path.stat().st_ino
    atomic_write(path, b"new\n", wanted)
    assert path.read_bytes() == b"new\n" and mode(path) == wanted
    assert path.stat().st_ino != inode  # a new file took the name
    assert names(tmp_path) == ["unit"]


def test_a_umask_does_not_narrow_the_mode(tmp_path: Path) -> None:
    old = os.umask(0o077)
    try:
        atomic_write(tmp_path / "pridem-gc.timer", "[Timer]\n", 0o644)
    finally:
        os.umask(old)
    assert mode(tmp_path / "pridem-gc.timer") == 0o644


def test_an_empty_write_is_an_empty_file(tmp_path: Path) -> None:
    atomic_write(tmp_path / "empty", b"", 0o600)
    assert (tmp_path / "empty").read_bytes() == b"" and mode(
        tmp_path / "empty"
    ) == 0o600


def test_two_writes_in_a_row_leave_the_second(tmp_path: Path) -> None:
    path = tmp_path / "env"
    atomic_write(path, "A=1\n", 0o600)
    atomic_write(path, "A=2\n", 0o600)
    assert path.read_text() == "A=2\n" and names(tmp_path) == ["env"]


def test_a_failed_write_leaves_the_file_and_no_temp(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "passport.yaml"
    path.write_text("old\n")
    path.chmod(0o600)

    def full(fd: int, data: object) -> int:
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(os, "write", full)
    with pytest.raises(OSError, match="No space"):
        atomic_write(path, "new\n", 0o600)
    monkeypatch.undo()
    assert path.read_text() == "old\n" and mode(path) == 0o600
    assert names(tmp_path) == ["passport.yaml"]


@pytest.mark.parametrize("exclusive", [False, True])
def test_a_temp_left_by_a_dead_writer_does_not_block_the_next(
    tmp_path: Path, exclusive: bool
) -> None:
    path = tmp_path / "history.json"
    temp_of(path).write_text("half of a write")
    temp_of(path).chmod(0o644)
    atomic_write(path, "whole\n", 0o600, exclusive=exclusive)
    assert path.read_text() == "whole\n" and mode(path) == 0o600
    assert names(tmp_path) == ["history.json"]


def test_a_temp_planted_between_unlink_and_open_is_never_written_through(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``O_EXCL``: a symlink that appears at the temp's name after it was
    cleared is refused, and the file it points to keeps what it holds."""
    path = tmp_path / ".env"
    target = tmp_path / "elsewhere"
    target.write_text("someone else's\n")
    unlink = os.unlink

    def plant(name: str, *, dir_fd: int | None = None) -> None:
        unlink(name, dir_fd=dir_fd)
        if Path(name) == temp_of(path):
            os.symlink(target, name)

    temp_of(path).write_text("left")
    monkeypatch.setattr(os, "unlink", plant)
    with pytest.raises(FileExistsError):
        atomic_write(path, "SECRET=1\n", 0o600)
    monkeypatch.undo()
    assert target.read_text() == "someone else's\n"
    assert not path.exists()


def test_no_directory_is_an_error_and_nothing_is_created(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        atomic_write(tmp_path / "missing" / "file", "x", 0o600)
    assert names(tmp_path) == []


def test_exclusive_links_a_new_name(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    watched = Watched(monkeypatch)
    path = tmp_path / "2026-10-15T10:42:01Z-a3f9.json"
    atomic_write(path, "{}\n", 0o600, exclusive=True)
    assert path.read_text() == "{}\n" and path.stat().st_nlink == 1
    assert watched.calls == ["fchmod 0o600", "fsync file", "link", "fsync dir"]
    assert names(tmp_path) == [path.name]


def test_exclusive_refuses_a_name_taken_and_keeps_it(tmp_path: Path) -> None:
    path = tmp_path / "verdict.json"
    path.write_text("first\n")
    with pytest.raises(FileExistsError):
        atomic_write(path, "second\n", 0o600, exclusive=True)
    assert path.read_text() == "first\n" and names(tmp_path) == ["verdict.json"]


def test_exclusive_twice_keeps_the_first(tmp_path: Path) -> None:
    path = tmp_path / "verdict.json"
    atomic_write(path, "first\n", 0o600, exclusive=True)
    with pytest.raises(FileExistsError):
        atomic_write(path, "second\n", 0o600, exclusive=True)
    assert path.read_text() == "first\n"


def _staged(path: Path, check: Callable[[Path], None]) -> None:
    with staged_write(path, "server: box-1\n", 0o600) as temp:
        check(temp)


def test_staged_body_sees_the_bytes_that_become_the_file(tmp_path: Path) -> None:
    path = tmp_path / "passport.yaml"
    seen: list[tuple[str, int, bool]] = []

    def check(temp: Path) -> None:
        seen.append((temp.read_text(), mode(temp), path.exists()))

    _staged(path, check)
    assert seen == [("server: box-1\n", 0o600, False)]  # checked before the rename
    assert path.read_text() == "server: box-1\n" and names(tmp_path) == [path.name]


def test_staged_body_that_raises_leaves_the_file_and_no_temp(tmp_path: Path) -> None:
    path = tmp_path / "passport.yaml"
    path.write_text("server: box-0\n")

    def refuse(temp: Path) -> None:
        raise ValueError("not this server")

    with pytest.raises(ValueError, match="not this server"):
        _staged(path, refuse)
    assert path.read_text() == "server: box-0\n" and names(tmp_path) == [path.name]
