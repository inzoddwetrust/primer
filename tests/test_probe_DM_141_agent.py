"""The probes of DM-141, part A: the agent of the box.

A box registered by ``pridem register`` (DM-139) and the Panel's side of the
agent (``agent_support.AgentPanel``: every request's signature checked by the
box's public half, the queue, the lines by ``seq``, the verdict by the
Panel's bytes). The machine runs in this process (``PridemInProcess``): its
journal and its verdict are real. The part B probe -- the console works and
no verdict is lost while the Panel is away -- is not here: part A does not
close it.
"""

import os
from pathlib import Path

import pytest
from agent_support import AgentPanel, Clock, PridemInProcess
from identity_support import FakePanel, box_root, register, with_passport
from test_probe_DM_135_protocol import STATE

from pridem.agent.client import PanelClient
from pridem.agent.service import Agent, journal_lines
from pridem.identity import key_path, read_registration
from pridem.report.box_snapshot import BoxSnapshot


def _agent(
    fs_root: Path, monkeypatch: pytest.MonkeyPatch
) -> tuple[Agent, AgentPanel, PridemInProcess, list[str]]:
    with_passport(fs_root)
    assert register(fs_root, monkeypatch, FakePanel()).code == 0
    root = box_root(fs_root)
    registration = read_registration(root)
    assert registration is not None
    clock = Clock()
    panel = AgentPanel(clock)
    panel.enrol(root)
    machine = PridemInProcess(fs_root)
    said: list[str] = []
    agent = Agent(
        root=root,
        client=PanelClient(registration, key_path(root).read_bytes(), panel, clock),
        runner=machine,
        now=clock,
        pause=lambda seconds: True,
        say=said.append,
        state=lambda: BoxSnapshot.model_validate(STATE),
        owner=os.geteuid(),
        heartbeat_s=registration.heartbeat_s,
        full_state_s=registration.full_state_s,
    )
    return agent, panel, machine, said


def test_probe_DM_141_a_command_runs_and_its_events_and_verdict_arrive(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A command of the queue runs as the console would run it, with its id;
    every line of its journal reaches the Panel by ``seq`` with no gap -- in
    as many batches as the run's ticks give, the verdict last; its verdict
    arrives, names the command, and its signature holds by the box's public
    half."""
    agent, panel, machine, said = _agent(tmp_path, monkeypatch)
    panel.queue.append({"verb": "status", "args": {}})
    agent.turn()
    assert machine.calls == [("pridem", "--json", "--command", "cmd-1", "status")]
    [run_id] = panel.verdicts
    kept = panel.verdicts[run_id]
    assert kept.verified and kept.envelope.verdict.command == "cmd-1"
    journal = box_root(tmp_path) / "journal" / f"{run_id}.jsonl"
    written = [line.model_dump(mode="json") for line in journal_lines(journal)]
    held = panel.lines[run_id]
    assert sorted(held) == list(range(1, len(written) + 1))
    assert [held[seq] for seq in sorted(held)] == written
    first, *lines, last = panel.requests
    assert first == ("GET", "/agent/v1/commands/next")
    assert last == ("POST", f"/agent/v1/runs/{run_id}/verdict")
    assert lines and set(lines) == {("POST", f"/agent/v1/runs/{run_id}/events")}
    assert panel.refusals == {} and said == []
    panel.assert_consumed()
    machine.assert_clean()


@pytest.mark.parametrize(
    ("given", "code"),
    [
        ({"verb": "teleport", "args": {}}, "verb-unknown"),
        ({"verb": "status", "args": {"unexpected": "x"}}, "args-refused"),
        ({"verb": "gc", "args": {"stack": "aivis"}}, "args-refused"),
    ],
    ids=["an unknown verb", "an extra argument", "an argument of no verb's"],
)
def test_probe_DM_141_an_unknown_verb_or_an_extra_argument_is_refused_before_a_run(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, given: dict[str, object], code: str
) -> None:
    """The agent refuses the command by its code before any run: the machine
    is not called, no run reaches the Panel. The pair: the next command, of
    the machine's form, runs."""
    agent, panel, machine, _ = _agent(tmp_path, monkeypatch)
    panel.queue.extend([given, {"verb": "status", "args": {}}])  # type: ignore[list-item]
    agent.turn()
    assert panel.refusals == {"cmd-1": code}
    assert machine.calls == [] and panel.lines == {} and panel.verdicts == {}
    agent.turn()
    assert machine.calls == [("pridem", "--json", "--command", "cmd-2", "status")]
    assert len(panel.verdicts) == 1
    panel.assert_consumed()
    machine.assert_clean()
