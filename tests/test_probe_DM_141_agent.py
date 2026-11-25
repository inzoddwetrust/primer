"""The probes of DM-141, part A: the agent of the box.

A box registered by ``pridem register`` (DM-139) and the Panel's side of the
agent (``agent_support.AgentPanel``: every request's signature checked by the
box's public half, the queue, the lines by ``seq``, the verdict by the
Panel's bytes). The machine runs in this process (``PridemInProcess``): its
journal and its verdict are real.

Changed by DM-141 part B (the same card): the agent sends what of
``history/`` the Panel does not hold before every long-poll, so the probes
of part A begin with the box's past held (``held_so_far``) -- the run of
``register`` that made the box. What the probes of part A hold is as it was.
"""

import os
from pathlib import Path

import pytest
from agent_support import AgentPanel, Clock, PridemInProcess, held_so_far
from identity_support import FakePanel, box_root, register, with_passport
from test_probe_DM_135_protocol import STATE

from pridem.agent.client import PanelClient
from pridem.agent.history import read_cursor
from pridem.agent.service import Agent, journal_lines
from pridem.identity import key_path, read_registration
from pridem.report.box_snapshot import BoxSnapshot
from pridem.state import Box
from pridem.steps.identity import Answer


def _agent(
    fs_root: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    register_first: bool = True,
    panel: AgentPanel | None = None,
) -> tuple[Agent, AgentPanel, PridemInProcess, list[str]]:
    root = box_root(fs_root)
    if register_first:
        with_passport(fs_root)
        assert register(fs_root, monkeypatch, FakePanel()).code == 0
        held_so_far(root)  # part B: the run of register is with the Panel already
    registration = read_registration(root)
    assert registration is not None
    if panel is None:
        panel = AgentPanel(Clock())
        panel.enrol(root)
    machine = PridemInProcess(fs_root)
    said: list[str] = []
    agent = Agent(
        root=root,
        client=PanelClient(
            registration, key_path(root).read_bytes(), panel, panel.clock
        ),
        runner=machine,
        now=panel.clock,
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


def test_probe_DM_141_the_console_works_and_no_verdict_is_lost_while_the_panel_is_away(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Part B. The Panel away: the console's ``pridem`` runs as ever, its
    verdict lands in ``history/``; the agent pauses longer each time. The
    Panel back: the verdict of the console's run reaches it -- its lines by
    ``seq`` with no gap, its signature holding. A new agent on the box sends
    none of it again: the cursor is on the box."""
    agent, panel, machine, said = _agent(tmp_path, monkeypatch)
    paused: list[float] = []

    def pause(seconds: float) -> bool:
        paused.append(seconds)
        return True

    agent.pause = pause
    panel.outages = ["refused", "refused", Answer(503, b"")]
    console = PridemInProcess(tmp_path)
    console.run(
        ["pridem", "--json", "status"], expect=(0,), timeout=60,
        on_line=lambda *line: None,
    )  # fmt: skip
    past = set(read_cursor(box_root(tmp_path)).held)
    [run_id] = set(Box(box_root(tmp_path)).history_ids()) - past
    agent.queue(lambda: run_id in panel.verdicts or len(paused) > 20)
    assert paused[:3] == [1, 2, 4]
    kept = panel.verdicts[run_id]
    assert kept.verified and kept.envelope.verdict.actor.via == "local"
    journal = box_root(tmp_path) / "journal" / f"{run_id}.jsonl"
    assert sorted(panel.lines[run_id]) == [line.seq for line in journal_lines(journal)]
    panel.requests.clear()
    again, _, _, _ = _agent(tmp_path, monkeypatch, register_first=False, panel=panel)
    again.turn()
    assert panel.requests == [("GET", "/agent/v1/commands/next")]
    panel.assert_consumed()
    console.assert_clean()
