"""``pridem agent install`` (DM-143): the agent's systemd service.

The unit file is real, under the test's root; ``systemctl`` follows a strict
script. The command runs through ``pridem.cli`` on a box registered by
``pridem register`` against the stand-in Panel of DM-139.
"""

import io
import json
from pathlib import Path

import pytest
from identity_support import FakePanel, box_root, register, with_passport

from pridem.cli import run
from pridem.events import Json
from pridem.runner import FakeCall, FakeRunner, Stream
from pridem.steps.agent_service import UNIT, unit_text
from pridem.steps.timers import UNIT_DIR

ANSWER = {"enabled": 0, "active": 0, "disabled": 1, "inactive": 3, "failed": 3}


def _is(question: str, state: str) -> FakeCall:
    return FakeCall(
        ("systemctl", question, UNIT),
        code=ANSWER.get(state, 3),
        lines=((Stream.STDOUT, state),),
    )


def _reload_needed(answer: str = "no") -> FakeCall:
    return FakeCall(
        ("systemctl", "show", "-p", "NeedDaemonReload", "--value", UNIT),
        lines=((Stream.STDOUT, answer),),
    )


def _started(reload: bool = True) -> list[FakeCall]:
    calls = [FakeCall(("systemctl", "daemon-reload"))] if reload else []
    return [
        *calls,
        FakeCall(("systemctl", "enable", UNIT)),
        FakeCall(("systemctl", "restart", UNIT)),
    ]


def _read_back(active: str = "active", enabled: str = "enabled") -> list[FakeCall]:
    return [_reload_needed(), _is("is-enabled", enabled), _is("is-active", active)]


@pytest.fixture
def fs_root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    with_passport(tmp_path)
    assert register(tmp_path, monkeypatch, FakePanel()).code == 0
    return tmp_path


def _install(fs_root: Path, *calls: FakeCall) -> tuple[int, dict[str, Json], str]:
    out, err = io.StringIO(), io.StringIO()
    with FakeRunner(*calls) as runner:
        code = run(
            ["--json", "agent", "install"],
            root=box_root(fs_root),
            out=out,
            err=err,
            runner=runner,
            fs_root=fs_root,
        )
    verdict: dict[str, Json] = json.loads(out.getvalue()) if out.getvalue() else {}
    return code, verdict, err.getvalue()


def _step(verdict: dict[str, Json]) -> dict[str, Json]:
    steps = verdict["steps"]
    assert isinstance(steps, list)
    [step] = [s for s in steps if isinstance(s, dict) and s["name"] == "agent_service"]
    return step


def _unit(fs_root: Path) -> Path:
    return fs_root / UNIT_DIR / UNIT


def test_the_unit_is_the_agent_as_root_restarted_and_started_on_boot() -> None:
    """The text, literally: what systemd runs, restarts and starts on boot."""
    assert unit_text() == (
        "[Unit]\n"
        "Description=pridem agent\n"
        "Wants=network-online.target\n"
        "After=network-online.target\n"
        "\n"
        "[Service]\n"
        "Type=simple\n"
        "ExecStart=/usr/local/bin/pridem agent\n"
        "Restart=always\n"
        "RestartSec=5\n"
        "User=root\n"
        "\n"
        "[Install]\n"
        "WantedBy=multi-user.target\n"
    )


def test_a_registered_box_gets_its_service_written_enabled_and_started(
    fs_root: Path,
) -> None:
    code, verdict, err = _install(fs_root, *_started(), *_read_back())
    assert code == 0, err
    assert verdict["verb"] == "agent install" and verdict["result"] == "green"
    assert _step(verdict)["verify"] == {
        "unit": UNIT,
        "path": str(_unit(fs_root)),
        "enabled": "enabled",
        "active": "active",
        "changed": True,
    }
    assert _unit(fs_root).read_text() == unit_text()
    assert _unit(fs_root).stat().st_mode & 0o777 == 0o644


def test_a_service_as_it_should_be_is_not_touched(fs_root: Path) -> None:
    """The repeat of the first contact: nothing written, reloaded or
    restarted -- the strict script has no such call."""
    _unit(fs_root).parent.mkdir(parents=True)
    _unit(fs_root).write_text(unit_text())
    code, verdict, err = _install(
        fs_root,
        _reload_needed(),
        _is("is-enabled", "enabled"),
        _is("is-active", "active"),
        *_read_back(),
    )
    assert code == 0, err
    fact = _step(verdict)["verify"]
    assert isinstance(fact, dict) and fact["changed"] is False


def test_a_service_that_stopped_is_started_again(fs_root: Path) -> None:
    _unit(fs_root).parent.mkdir(parents=True)
    _unit(fs_root).write_text(unit_text())
    code, _, err = _install(
        fs_root,
        _reload_needed(),
        _is("is-enabled", "enabled"),
        _is("is-active", "failed"),
        _reload_needed(),
        *_started(reload=False),
        *_read_back(),
    )
    assert code == 0, err


def test_a_text_systemd_has_not_loaded_is_reloaded(fs_root: Path) -> None:
    _unit(fs_root).parent.mkdir(parents=True)
    _unit(fs_root).write_text(unit_text())
    code, _, err = _install(
        fs_root,
        _reload_needed("yes"),
        _reload_needed("yes"),
        *_started(reload=True),
        *_read_back(),
    )
    assert code == 0, err


def test_an_older_text_is_written_again(fs_root: Path) -> None:
    _unit(fs_root).parent.mkdir(parents=True)
    _unit(fs_root).write_text(unit_text().replace("Restart=always", "Restart=no"))
    code, _, err = _install(fs_root, *_started(), *_read_back())
    assert code == 0, err
    assert _unit(fs_root).read_text() == unit_text()


@pytest.mark.parametrize(
    ("enabled", "active", "code"),
    [
        ("disabled", "active", "agent_service:not-enabled"),
        ("enabled", "activating", "agent_service:not-active"),
        ("enabled", "failed", "agent_service:not-active"),
    ],
)
def test_a_service_not_enabled_or_not_running_after_the_start_is_red(
    fs_root: Path, enabled: str, active: str, code: str
) -> None:
    exit_code, verdict, _ = _install(
        fs_root,
        *_started(),
        _reload_needed(),
        _is("is-enabled", enabled),
        *([_is("is-active", active)] if enabled == "enabled" else []),
    )
    assert exit_code == 1 and verdict["result"] == "red"
    reason = _step(verdict)["reason"]
    assert isinstance(reason, dict) and reason["code"] == code


def test_a_box_not_registered_gets_no_service(tmp_path: Path) -> None:
    """No call of systemd, no file: the agent would refuse to start."""
    code, verdict, _ = _install(tmp_path)
    assert code == 1
    reason = _step(verdict)["reason"]
    assert isinstance(reason, dict) and reason["code"] == "agent_service:not-registered"
    assert not _unit(tmp_path).exists()


@pytest.mark.parametrize(
    "argv",
    [["agent", "install", "now"], ["--timer", "agent", "install"],
     ["--command", "cmd-1", "agent", "install"], ["agent", "remove"]],
)  # fmt: skip
def test_agent_install_takes_nothing_else(fs_root: Path, argv: list[str]) -> None:
    out, err = io.StringIO(), io.StringIO()
    code = run(argv, root=box_root(fs_root), out=out, err=err, fs_root=fs_root)
    assert code == 1
    assert err.getvalue() == "pridem: agent takes no arguments and no flags\n"
