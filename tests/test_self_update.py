"""``pridem self-update`` beyond its probes (DM-163): the grid of the gate.

The machine in use is never removed; the release's repository is the
machine's own unless ``--from`` named the file; the schema of ``state.json``
both ways; the rest of a try a hard break left; a rollback; the agent's
service after the switch; ``--from`` only to a file or the loopback; the
agent ends after a green update it ran, not after a red one.
"""

import hashlib
import io
import json
import os
from pathlib import Path

import pytest
from agent_support import AgentPanel, Clock, PridemInProcess, held_so_far
from identity_support import FakePanel, box_root, register, with_passport
from self_update_support import (
    RELEASES,
    Releases,
    Spoil,
    install_machine,
    releases,
    tree,
)
from state_support import state
from test_probe_DM_135_protocol import STATE

from pridem.agent.client import PanelClient
from pridem.agent.service import Agent
from pridem.cli import run
from pridem.events import Json
from pridem.identity import key_path, read_registration
from pridem.report.box_snapshot import BoxSnapshot
from pridem.state import Box
from pridem.steps.agent_service import UNIT
from pridem.steps.timers import UNIT_DIR

FROM = "file:///srv/releases/{tag}/install.sh"


def _update(
    fs_root: Path, box: Releases, *argv: str, command: str | None = None
) -> tuple[int, dict[str, Json], str]:
    out, err = io.StringIO(), io.StringIO()
    head = ["--json", *(["--command", command] if command else []), "self-update"]
    code = run(
        [*head, *argv],
        root=fs_root / "opt" / "pridem",
        out=out,
        err=err,
        runner=box,
        fs_root=fs_root,
    )
    verdict: dict[str, Json] = json.loads(out.getvalue()) if out.getvalue() else {}
    return code, verdict, err.getvalue()


def _failed(verdict: dict[str, Json]) -> dict[str, Json]:
    steps = verdict["steps"]
    assert isinstance(steps, list)
    for step in steps:
        if isinstance(step, dict) and step["status"] == "failed":
            reason = step["reason"]
            assert isinstance(reason, dict)
            return reason
    raise AssertionError("no step failed")


def _home(tmp_path: Path, tag: str = "v0.1.11") -> Path:
    home = tmp_path / "opt" / "pridem"
    install_machine(home, tag)
    return home


# --- the machine in use ----------------------------------------------------------


def test_the_machine_in_use_is_never_removed(tmp_path: Path) -> None:
    """``current`` is ``versions/v0.1.12`` and does not say its version (a
    damaged install): ``self-update v0.1.12`` refuses -- it would build the
    machine in use away under itself. Its files stay byte for byte."""
    home = _home(tmp_path, "v0.1.12")
    pridem = home / "versions" / "v0.1.12" / "venv" / "bin" / "pridem"
    pridem.write_text("version=0.1.99\n")
    before = {p: p.read_bytes() for p in (home / "versions").rglob("*") if p.is_file()}
    box = Releases(releases("v0.1.12"))
    code, verdict, _ = _update(
        tmp_path, box, "v0.1.12", "--from", FROM.format(tag="v0.1.12")
    )
    assert code == 1
    assert _failed(verdict)["code"] == "release:current-differs"
    assert box.calls == [(str(pridem), "version")]  # refused at once
    after = {p: p.read_bytes() for p in (home / "versions").rglob("*") if p.is_file()}
    assert after == before
    assert tree(home) == ["v0.1.12", "current=v0.1.12"]


def test_the_rest_of_a_broken_try_is_built_again(tmp_path: Path) -> None:
    """A hard break left ``versions/v0.1.12`` half built, no one's: it is
    removed and built again, then switched to."""
    home = _home(tmp_path)
    (home / "versions" / "v0.1.12" / "venv").mkdir(parents=True)
    box = Releases(releases("v0.1.11", "v0.1.12"))
    code, _, err = _update(
        tmp_path, box, "v0.1.12", "--from", FROM.format(tag="v0.1.12")
    )
    assert code == 0, err
    assert (
        home / "current" / "venv" / "bin" / "pridem"
    ).read_text() == "version=0.1.12\n"


def test_a_wheel_of_the_same_prefix_and_another_tail_is_refused(
    tmp_path: Path,
) -> None:
    """DM-217: the pin ``WHEEL_SHA256`` shares the wheel's first 8 signs and
    has another tail -- refused before the switch, as a wheel other in whole
    is (``[wheel]`` of the probe): the whole digest is held, not a prefix. The
    pair: the pin of the wheel in whole installs (the probe of DM-163)."""
    home = _home(tmp_path)
    box = Releases(releases("v0.1.11", "v0.1.12", v0_1_12=Spoil(sha256_tail=True)))
    release = box.releases["v0.1.12"]
    digest = hashlib.sha256(release.wheel).hexdigest()
    pinned = release._pinned_sha256()  # noqa: SLF001 -- the pin the file carries
    assert pinned[:8] == digest[:8] and pinned != digest
    code, verdict, _ = _update(
        tmp_path, box, "v0.1.12", "--from", FROM.format(tag="v0.1.12")
    )
    assert code == 1
    reason = _failed(verdict)
    assert (reason["code"], reason["pin"], reason["pinned"], reason["found"]) == (
        "build:pin-differs", "sha256", pinned, digest,
    )  # fmt: skip
    assert tree(home) == ["v0.1.11", "current=v0.1.11"]


def test_a_lower_release_is_a_rollback(tmp_path: Path) -> None:
    home = _home(tmp_path, "v0.1.12")
    box = Releases(releases("v0.1.11", "v0.1.12"))
    code, _, err = _update(
        tmp_path, box, "v0.1.11", "--from", FROM.format(tag="v0.1.11")
    )
    assert code == 0, err
    assert tree(home) == ["v0.1.11", "v0.1.12", "current=v0.1.11"]


# --- the repository, --from --------------------------------------------------------


def test_without_from_the_release_is_the_machine_s_own(tmp_path: Path) -> None:
    """No ``--from``: ``install.sh`` from the machine's home, and its ``REPO``
    must be that home -- a file with a repository of its own is refused. The
    pair: with the home's repository it installs."""
    home = _home(tmp_path)
    foreign = Releases(releases("v0.1.11", "v0.1.12"), repo="file:///elsewhere")
    code, verdict, _ = _update(tmp_path, foreign, "v0.1.12")
    assert code == 1
    reason = _failed(verdict)
    assert (reason["code"], reason["pin"], reason["found"]) == (
        "release:pin-differs", "repo", "file:///elsewhere",
    )  # fmt: skip
    assert foreign.calls[0][-1] == f"{RELEASES}/releases/download/v0.1.12/install.sh"
    own = Releases(releases("v0.1.11", "v0.1.12"), repo=RELEASES)
    code, _, err = _update(tmp_path, own, "v0.1.12")
    assert code == 0, err
    assert tree(home)[-1] == "current=v0.1.12"


@pytest.mark.parametrize(
    "source",
    ["http://example.com/install.sh", "https://example.com/install.sh",
     "ftp://127.0.0.1/install.sh", "file://host/install.sh"],
)  # fmt: skip
def test_from_is_a_file_or_the_loopback(tmp_path: Path, source: str) -> None:
    _home(tmp_path)
    box = Releases(releases("v0.1.11"))
    code, _, err = _update(tmp_path, box, "v0.1.12", "--from", source)
    assert code == 1 and "invalid arguments" in err and box.calls == []


def test_a_tag_not_of_its_form_is_no_release(tmp_path: Path) -> None:
    _home(tmp_path)
    box = Releases(releases("v0.1.11"))
    code, verdict, _ = _update(tmp_path, box, "0.1.12", "--from", FROM.format(tag="0"))
    assert code == 1 and _failed(verdict)["code"] == "release:not-a-release"
    assert box.calls == []


# --- the schema ------------------------------------------------------------------


def test_a_release_of_another_schema_is_refused_before_the_switch(
    tmp_path: Path,
) -> None:
    """The release writes a schema of ``state.json`` other than the box's
    (``2`` on a box of ``1``): refused before the switch. The other way --
    the box ahead of the release -- is a rollback from a machine of a higher
    schema; the same comparison holds it (``box != release``)."""
    home = _home(tmp_path)
    box_of = Box(home)
    with box_of.lock("test"):
        box_of.write_state(state())
    box = Releases(releases("v0.1.11", "v0.1.12", v0_1_12=Spoil(schema=2)))
    code, verdict, _ = _update(
        tmp_path, box, "v0.1.12", "--from", FROM.format(tag="v0.1.12")
    )
    assert code == 1
    reason = _failed(verdict)
    assert (reason["code"], reason["box"], reason["release"]) == (
        "schema:schema-differs", 1, 2,
    )  # fmt: skip
    assert tree(home) == ["v0.1.11", "current=v0.1.11"]


def test_a_box_ahead_of_this_machine_runs_no_update(tmp_path: Path) -> None:
    """A ``state.json`` of schema 2 on a machine of schema 1: the machine
    refuses before any plan (``state-schema``, DM-191) -- nothing fetched,
    ``current`` as it was."""
    home = _home(tmp_path)
    box_of = Box(home)
    with box_of.lock("test"):
        box_of.write_state(state())
    written = json.loads((home / "state.json").read_text())
    (home / "state.json").write_text(json.dumps({**written, "schema": 2}))
    box = Releases(releases("v0.1.11", "v0.1.12"))
    code, _, err = _update(
        tmp_path, box, "v0.1.12", "--from", FROM.format(tag="v0.1.12")
    )
    assert code == 1 and "schema 2" in err, err
    assert box.calls == [] and tree(home) == ["v0.1.11", "current=v0.1.11"]


def test_the_same_schema_goes_on(tmp_path: Path) -> None:
    """The pair: a box of schema 1, a release of schema 1 -- installed."""
    home = _home(tmp_path)
    box_of = Box(home)
    with box_of.lock("test"):
        box_of.write_state(state())
    box = Releases(releases("v0.1.11", "v0.1.12"))
    code, _, err = _update(
        tmp_path, box, "v0.1.12", "--from", FROM.format(tag="v0.1.12")
    )
    assert code == 0, err


# --- the agent's service ------------------------------------------------------------


def _service(fs_root: Path) -> None:
    unit = fs_root / UNIT_DIR / UNIT
    unit.parent.mkdir(parents=True, exist_ok=True)
    unit.write_text("[Unit]\n")


def test_from_the_console_the_running_service_is_restarted(tmp_path: Path) -> None:
    _home(tmp_path)
    _service(tmp_path)
    box = Releases(releases("v0.1.11", "v0.1.12"), agent_active=True)
    code, _, err = _update(
        tmp_path, box, "v0.1.12", "--from", FROM.format(tag="v0.1.12")
    )
    assert code == 0, err
    assert box.restarted


def test_by_a_command_the_service_is_left_to_the_agent(tmp_path: Path) -> None:
    """Run as a command of the queue, the update never restarts the agent's
    service: that would take this very run down."""
    _home(tmp_path)
    _service(tmp_path)
    box = Releases(releases("v0.1.11", "v0.1.12"), agent_active=True)
    code, _, err = _update(
        tmp_path, box, "v0.1.12", "--from", FROM.format(tag="v0.1.12"), command="cmd-1"
    )
    assert code == 0, err
    assert not box.restarted
    assert not any(call[:2] == ("systemctl", "restart") for call in box.calls)


def test_no_service_running_is_not_restarted(tmp_path: Path) -> None:
    _home(tmp_path)
    _service(tmp_path)
    box = Releases(releases("v0.1.11", "v0.1.12"), agent_active=False)
    code, _, err = _update(
        tmp_path, box, "v0.1.12", "--from", FROM.format(tag="v0.1.12")
    )
    assert code == 0, err
    assert not box.restarted


# --- the agent ends after the update it ran -------------------------------------------


def _agent(
    fs_root: Path, monkeypatch: pytest.MonkeyPatch, spoil: Spoil
) -> tuple[Agent, AgentPanel]:
    with_passport(fs_root)
    assert register(fs_root, monkeypatch, FakePanel()).code == 0
    root = box_root(fs_root)
    install_machine(root, "v0.1.11")
    held_so_far(root)
    registration = read_registration(root)
    assert registration is not None
    clock = Clock()
    panel = AgentPanel(clock)
    panel.enrol(root)
    machine = PridemInProcess(
        fs_root, machine=Releases(releases("v0.1.11", "v0.1.12", v0_1_12=spoil))
    )
    agent = Agent(
        root=root,
        client=PanelClient(registration, key_path(root).read_bytes(), panel, clock),
        runner=machine,
        now=clock,
        pause=lambda seconds: True,
        say=lambda text: None,
        state=lambda: BoxSnapshot.model_validate(STATE),
        owner=os.geteuid(),
        heartbeat_s=registration.heartbeat_s,
        full_state_s=registration.full_state_s,
    )
    source: Json = FROM.format(tag="v0.1.12")
    panel.queue.append(
        {"verb": "self-update", "args": {"tag": "v0.1.12", "source": source}}
    )
    return agent, panel


def test_the_agent_ends_after_a_green_update_it_ran(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The verdict goes first -- sent by the code the agent has in memory --
    then the agent ends: its service starts the new machine."""
    agent, panel = _agent(tmp_path, monkeypatch, Spoil())
    agent.turn()
    [kept] = panel.verdicts.values()
    assert kept.verified and kept.envelope.verdict.verb == "self-update"
    assert kept.envelope.verdict.result == "green"
    assert agent.replaced.is_set()
    agent.serve(lambda: False)  # returns at once: the agent is over


def test_the_agent_goes_on_after_a_red_update(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    agent, panel = _agent(tmp_path, monkeypatch, Spoil(head="e" * 40))
    agent.turn()
    [kept] = panel.verdicts.values()
    assert kept.envelope.verdict.result == "red"
    assert not agent.replaced.is_set()
