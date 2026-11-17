"""DM-110 (the owner's decision of 17.11): ``destroy``, ``destroy --all`` and
``reinstall`` take the server's name on any role -- ``--confirm`` (the
Panel), else asked at the terminal before the lock; checked under the lock
against the passport's copy read then; no terminal and no ``--confirm`` --
refused, nothing taken down."""

import io
from collections.abc import Callable
from pathlib import Path

import pytest
from data_support import blank_box

from pridem.cli import run
from pridem.state import Box
from pridem.verbs.base import ask_terminal

NAME = "box-1"
QUESTIONS: list[str] = []


class Refusing:
    """Every command refused: the plan runs and its verdict is written."""

    def run(self, argv, **kw):  # type: ignore[no-untyped-def]
        from pridem.runner import CommandNotStarted

        raise CommandNotStarted(tuple(argv), "refused by the test")


def _cli(
    tmp: Path, argv: list[str], ask: Callable[[str], str | None]
) -> tuple[int, str, list[Path]]:
    out, err = io.StringIO(), io.StringIO()
    root = tmp / "opt" / "pridem"
    code = run(
        argv, root=root, out=out, err=err, runner=Refusing(),
        fs_root=tmp, ask=ask,
    )  # fmt: skip
    history = (
        sorted((root / "history").iterdir()) if (root / "history").exists() else []
    )
    return code, err.getvalue(), history


def _never(question: str) -> str | None:
    raise AssertionError(f"asked: {question}")


def _answer(text: str | None) -> Callable[[str], str | None]:
    def ask(question: str) -> str | None:
        QUESTIONS.append(question)
        return text

    return ask


VERBS = [["destroy"], ["destroy", "--all"]]


@pytest.mark.parametrize("role", ["test", "preview", "prod"])
@pytest.mark.parametrize("verb", VERBS)
def test_the_server_s_name_goes_on_and_any_other_is_refused(
    tmp_path: Path, role: str, verb: list[str]
) -> None:
    """``--confirm`` of the box's name -- the run, a verdict, no question;
    another name -- refused under the lock, no verdict; nothing at all and
    no terminal -- refused before the lock, no verdict. On every role."""
    blank_box(tmp_path, role=role, name=NAME)
    code, err, history = _cli(tmp_path, [*verb, "--confirm", "box-2"], _never)
    assert (code, history) == (1, []) and "is not the server's name" in err
    code, err, history = _cli(tmp_path, verb, _answer(None))
    assert (code, history) == (1, []) and f"--confirm {NAME}, or answer" in err
    code, err, history = _cli(tmp_path, [*verb, "--confirm", NAME], _never)
    assert len(history) == 1, err


@pytest.mark.parametrize("verb", VERBS)
def test_the_terminal_is_asked_and_its_answer_is_checked_under_the_lock(
    tmp_path: Path, verb: list[str]
) -> None:
    blank_box(tmp_path, role="test", name=NAME)
    QUESTIONS.clear()
    code, err, history = _cli(tmp_path, verb, _answer("box-2"))
    assert (code, history) == (1, []) and "'box-2' is not the server's name" in err
    assert QUESTIONS == [f"Type the server's name to destroy {NAME}: "]
    code, err, history = _cli(tmp_path, verb, _answer(""))
    assert (code, history) == (1, []) and "not confirmed" in err
    code, err, history = _cli(tmp_path, verb, _answer(NAME))
    assert len(history) == 1, err


def test_reinstall_takes_the_name_on_any_role(tmp_path: Path) -> None:
    """D9: ``reinstall`` on ``test`` without the name -- refused; asked at the
    terminal; with it -- the run."""
    from passport_support import passport_example, section, write_passport

    blank_box(tmp_path, role="test", name=NAME)
    data = passport_example()
    section(data, "server")["role"] = "test"
    section(data, "server")["name"] = NAME
    file = write_passport(tmp_path, data)
    argv = ["reinstall", "--passport", str(file)]
    code, err, history = _cli(tmp_path, argv, _answer(None))
    assert (code, history) == (1, []) and f"--confirm {NAME}" in err
    QUESTIONS.clear()
    code, err, history = _cli(tmp_path, argv, _answer("nope"))
    assert (code, history) == (1, []) and "is not the server's name" in err
    assert QUESTIONS == [f"Type the server's name to reinstall {NAME}: "]
    code, err, history = _cli(tmp_path, [*argv, "--confirm", NAME], _never)
    assert len(history) == 1, err


def test_a_box_with_no_passport_is_refused(tmp_path: Path) -> None:
    Box(tmp_path / "opt" / "pridem").root.mkdir(parents=True)
    code, err, history = _cli(tmp_path, ["destroy", "--confirm", NAME], _never)
    assert (code, history) == (1, []) and "no passport to confirm against" in err
    code, err, history = _cli(tmp_path, ["destroy"], _never)
    assert (code, history) == (1, []) and "no passport to confirm against" in err


def test_the_name_is_checked_against_the_copy_read_under_the_lock(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """D3: the copy names ``box-1`` when the command starts and ``box-2`` once
    the lock is taken (the copy was replaced while it waited): ``--confirm
    box-1`` is refused -- the check reads the copy under the lock."""
    blank_box(tmp_path, role="test", name=NAME)
    real = Box.recover

    def recover(self: Box, *args, **kw):  # type: ignore[no-untyped-def]
        blank = tmp_path / "opt" / "pridem" / "passport.yaml"
        blank.write_text(blank.read_text().replace(f"name: {NAME}", "name: box-2"))
        return real(self, *args, **kw)

    monkeypatch.setattr(Box, "recover", recover)
    code, err, history = _cli(tmp_path, ["destroy", "--confirm", NAME], _never)
    assert (code, history) == (1, []) and "--confirm box-2" in err


def test_ctrl_c_and_a_closed_terminal_answer_nothing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``ask_terminal``: no terminal -- ``None``; Ctrl-C at the question --
    ``""`` (refused as not confirmed, no traceback); a line -- the line."""
    import sys

    class Tty(io.StringIO):
        def isatty(self) -> bool:
            return True

    class Interrupted(Tty):
        def readline(self, size: int | None = -1) -> str:  # type: ignore[override]
            raise KeyboardInterrupt

    monkeypatch.setattr(sys, "stderr", io.StringIO())
    monkeypatch.setattr(sys, "stdin", io.StringIO("box-1\n"))
    assert ask_terminal("? ") is None
    monkeypatch.setattr(sys, "stdin", Interrupted())
    assert ask_terminal("? ") == ""
    monkeypatch.setattr(sys, "stdin", Tty("box-1\n"))
    assert ask_terminal("? ") == "box-1"
