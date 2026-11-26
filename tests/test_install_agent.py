"""The sixth step of ``install.sh``, the agent (DM-143), on the stubs of
``test_install_output``: the installed ``pridem`` is a stub that keeps the
arguments of every call but ``version`` and the token it got in its
environment.

The one-time token comes in the environment alone: it reaches ``pridem
register`` through it, and no argument, no line of the screen, no line of the
install's log carries it.
"""

from pathlib import Path

from test_install_output import _install

TOKEN = "first-contact-token-0f9e8d7c6b5a"  # noqa: S105 -- a marker


def _box(tmp: Path, *files: str) -> Path:
    """The box before the command: ``files`` under ``/opt/pridem``."""
    home = tmp / "root" / "opt" / "pridem"
    for name in files:
        path = home / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("x\n")
    return home


def _calls(tmp: Path) -> list[str]:
    path = tmp / "calls"
    return path.read_text().splitlines() if path.exists() else []


def _tokens(tmp: Path) -> list[str]:
    path = tmp / "calls.env"
    return path.read_text().splitlines() if path.exists() else []


def test_no_token_installs_the_machine_and_says_why(tmp_path: Path) -> None:
    _box(tmp_path, "passport.yaml")
    code, screen, errors, _ = _install(tmp_path)
    assert code == 0, errors
    assert screen[-1] == (
        "6/6 agent: not registered -- no PRIDEM_REGISTER_TOKEN; "
        "the machine works without the Panel"
    )
    assert _calls(tmp_path) == []


def test_no_passport_copy_yet_registers_nothing_and_says_why(tmp_path: Path) -> None:
    """A bare box: the token waits for the product -- the same command again
    after ``pridem install``."""
    code, screen, errors, _ = _install(tmp_path, PRIDEM_REGISTER_TOKEN=TOKEN)
    assert code == 0, errors
    assert screen[-1] == (
        "6/6 agent: not registered -- no passport copy yet: pridem install, "
        "then this command again"
    )
    assert _calls(tmp_path) == []


def test_a_token_and_a_passport_register_then_run_the_service(tmp_path: Path) -> None:
    _box(tmp_path, "passport.yaml")
    code, screen, errors, _ = _install(
        tmp_path, PRIDEM_REGISTER_TOKEN=TOKEN, PRIDEM_PANEL="http://127.0.0.1:8080"
    )
    assert code == 0, errors
    assert _calls(tmp_path) == [
        "register --panel http://127.0.0.1:8080",
        "agent install",
    ]
    assert screen[-1] == "6/6 agent: registered; its service runs"


def test_without_a_panel_the_machine_s_own_is_asked(tmp_path: Path) -> None:
    _box(tmp_path, "passport.yaml")
    code, _, errors, _ = _install(tmp_path, PRIDEM_REGISTER_TOKEN=TOKEN)
    assert code == 0, errors
    assert _calls(tmp_path) == ["register", "agent install"]


def test_the_token_is_in_no_argument_no_screen_and_no_log(tmp_path: Path) -> None:
    """The fence of the marker; the pair -- ``pridem register`` got it in its
    environment."""
    _box(tmp_path, "passport.yaml")
    code, screen, errors, log = _install(tmp_path, PRIDEM_REGISTER_TOKEN=TOKEN)
    assert code == 0, errors
    assert f"token={TOKEN}" in _tokens(tmp_path)
    for text in (*_calls(tmp_path), *screen, *errors, log.read_text()):
        assert TOKEN not in text


def test_a_registration_refused_is_a_refusal_with_no_service(tmp_path: Path) -> None:
    """``pridem register`` red (a used token): ``install.sh`` refuses with the
    reason and the log's tail; the service is not installed."""
    _box(tmp_path, "passport.yaml")
    code, _, errors, log = _install(
        tmp_path, PRIDEM_REGISTER_TOKEN=TOKEN, REGISTER_EXIT="1"
    )
    assert code == 1
    assert errors[0] == "install.sh: the box is not registered: see above"
    assert "pridem: register says its own lines" in errors
    assert errors[-1] == f"Full log: {log}"
    assert _calls(tmp_path) == ["register"]


def test_a_box_registered_already_makes_sure_of_its_service(tmp_path: Path) -> None:
    """The same command again: no registration -- the token is not sent --
    and the service made sure of."""
    _box(tmp_path, "passport.yaml", "agent/registration.json")
    code, screen, errors, _ = _install(tmp_path, PRIDEM_REGISTER_TOKEN=TOKEN)
    assert code == 0, errors
    assert _calls(tmp_path) == ["agent install"]
    assert screen[-1] == "6/6 agent: registered already; its service runs"


def test_a_service_that_does_not_start_is_a_refusal(tmp_path: Path) -> None:
    _box(tmp_path, "passport.yaml")
    code, _, errors, _ = _install(
        tmp_path, PRIDEM_REGISTER_TOKEN=TOKEN, SERVICE_EXIT="1"
    )
    assert code == 1
    assert errors[0] == "install.sh: the agent's service did not start: see above"
    assert _calls(tmp_path) == ["register", "agent install"]
