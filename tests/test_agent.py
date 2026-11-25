"""The agent beyond its probes (DM-141, part A): the grid of the gate.

The base of the agent's paths; a command's verb and arguments turned into the
machine's command line and back; the agent's own refusals; a busy box; the
pauses of a Panel away and its refusals; the heartbeat, light and full; one
agent per box; ``pridem agent`` on the command line; the whole way through
``http.client`` to a Panel on the loopback; the run of a dead agent.

Which test holds which way: the transport in this process and the machine
in it (``PridemInProcess``) -- everything but the two below;
``test_a_command_through_http_client_on_the_loopback`` -- the real HTTP of
the agent, the machine still in process; a real process of ``pridem`` under
an agent -- tier 3 (``test_probe_DM_141_agent_on_the_runner``) and, for the
parent's death alone, ``test_the_run_dies_with_the_agent``.
"""

import io
import os
import signal
import sys
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest
from agent_support import (
    AgentPanel,
    Clock,
    PridemInProcess,
    refused,
)
from identity_support import FakePanel, box_root, register, with_passport
from test_probe_DM_135_protocol import STATE

from pridem import __version__
from pridem.agent import service
from pridem.agent.client import BaseMismatch, PanelClient, agent_base
from pridem.agent.command import NotArgv, argv_of, checked
from pridem.agent.service import (
    Agent,
    AgentRunning,
    Backoff,
    agent_lock,
    journal_lines,
    light_beat,
)
from pridem.cli import _arguments, run
from pridem.events import Json
from pridem.identity import Registration, key_path, read_registration
from pridem.protocol import Command
from pridem.report.box_snapshot import BoxSnapshot
from pridem.runner import RunnerError, SubprocessRunner
from pridem.state import Box
from pridem.steps.identity import Answer, HttpTransport
from pridem.verbs import VERBS

# --- the box and the agent ----------------------------------------------------------


@pytest.fixture
def fs_root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """A box registered in the Panel ``https://api.primer.team``."""
    with_passport(tmp_path)
    assert register(tmp_path, monkeypatch, FakePanel()).code == 0
    return tmp_path


class Pauses:
    """The agent's pauses, kept; a hook after each (the test's time)."""

    def __init__(self, clock: Clock, stop_after: int | None = None) -> None:
        self.clock = clock
        self.seen: list[float] = []
        self.stop_after = stop_after
        self.hook: list[object] = []

    def __call__(self, seconds: float) -> bool:
        self.seen.append(seconds)
        self.clock.move(seconds)
        for hook in self.hook:
            assert callable(hook)
            hook()
        return self.stop_after is None or len(self.seen) < self.stop_after


def _agent(
    fs_root: Path,
    panel: AgentPanel,
    machine: PridemInProcess,
    pauses: Pauses,
    said: list[str],
) -> Agent:
    root = box_root(fs_root)
    registration = read_registration(root)
    assert registration is not None
    panel.enrol(root)
    return Agent(
        root=root,
        client=PanelClient(
            registration, key_path(root).read_bytes(), panel, panel.clock
        ),
        runner=machine,
        now=panel.clock,
        pause=pauses,
        say=said.append,
        state=lambda: BoxSnapshot.model_validate(STATE),
        owner=os.geteuid(),
        heartbeat_s=registration.heartbeat_s,
        full_state_s=registration.full_state_s,
    )


@contextmanager
def _held(root: Path) -> Iterator[int]:
    """The box's lock held by a process a command left (DM-24): its pid,
    once its name is ``sleep``."""
    seen: list[str] = []
    box = Box(root)
    with box.lock("update 2026-11-25T10:00:00Z-a3f9 pid 7"):
        runner = SubprocessRunner()
        assert box.lock_fd is not None
        runner.hold(box.lock_fd)
        runner.run(
            ["sh", "-c", "setsid sleep 30 </dev/null >/dev/null 2>&1 & echo $!"],
            timeout=30,
            on_line=lambda s, line, c: seen.append(line),
        )
    pid = int(seen[0])
    try:
        end = time.monotonic() + 5
        while Path(f"/proc/{pid}/comm").read_text().strip() != "sleep":
            assert time.monotonic() < end
            time.sleep(0.01)
        yield pid
    finally:
        _gone(pid)


def _gone(pid: int) -> None:
    try:
        os.kill(pid, signal.SIGKILL)
    except ProcessLookupError:
        return
    end = time.monotonic() + 10
    while Path(f"/proc/{pid}").exists():
        state = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()[0]
        if state == "Z" or time.monotonic() > end:
            return
        time.sleep(0.02)


# --- the base of the agent's paths --------------------------------------------------


def _registration(panel: str, agent_url: str) -> Registration:
    return Registration(
        box_id="box-1",
        agent_url=agent_url,
        heartbeat_s=30,
        full_state_s=300,
        poll_s=60,
        panel=panel,
        registered_at="2026-11-25T12:00:00Z",
    )


def test_the_base_is_agent_url_for_a_panel_over_https() -> None:
    found = agent_base(
        _registration("https://api.primer.team", "https://api.primer.team/agent/v1/")
    )
    assert found == "https://api.primer.team/agent/v1/"


def test_a_port_agent_url_cannot_carry_is_a_refusal_naming_both() -> None:
    with pytest.raises(BaseMismatch) as caught:
        agent_base(
            _registration(
                "https://api.primer.team:8443", "https://api.primer.team/agent/v1/"
            )
        )
    assert str(caught.value) == (
        "the Panel https://api.primer.team:8443 and its agent_url "
        "https://api.primer.team/agent/v1/ are not one address"
    )


def test_the_loopback_s_base_is_its_own() -> None:
    found = agent_base(
        _registration("http://127.0.0.1:8080", "https://127.0.0.1/agent/v1/")
    )
    assert found == "http://127.0.0.1:8080/agent/v1/"


def test_the_agent_refuses_to_start_on_a_port_agent_url_has_not(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with_passport(tmp_path)
    ran = register(
        tmp_path, monkeypatch, FakePanel(), argv=("--panel", "https://panel.test:8443")
    )
    assert ran.code == 0, ran.err
    out, err = io.StringIO(), io.StringIO()
    code = run(["agent"], root=box_root(tmp_path), out=out, err=err, fs_root=tmp_path)
    assert code == 1
    assert err.getvalue() == (
        "pridem: agent: the Panel https://panel.test:8443 and its agent_url "
        "https://panel.test/agent/v1/ are not one address\n"
    )


# --- a command's arguments and its command line -------------------------------------

SAMPLES: dict[str, tuple[dict[str, Json], list[str]]] = {
    "status": ({}, []),
    "gc": ({}, []),
    "register": (
        {"panel": "https://api.primer.team"},
        ["--panel", "https://api.primer.team"],
    ),
    "ssl": ({"action": "renew"}, ["renew"]),
    "check": (
        {"path": "/srv/aivis", "packages": ["skin=/srv/skin"]},
        ["/srv/aivis", "skin=/srv/skin"],
    ),
    "install": (
        {"server": "velo-dev"},
        ["--server", "velo-dev"],
    ),
    "update": (
        {"tries": ["comms=4.2.0", "payments=1.0.3"]},
        ["--try", "comms=4.2.0", "--try", "payments=1.0.3"],
    ),
    "deploy": ({"ref": "9a1c4e2"}, ["9a1c4e2"]),
    "rollback": ({}, []),
    "doctor": ({}, []),
    "reinstall": (
        {"new_secrets": True, "confirm": "velo-dev"},
        ["--new-secrets", "--confirm", "velo-dev"],
    ),
    "destroy": (
        {"confirm": "velo-dev", "all": True},
        ["--confirm", "velo-dev", "--all"],
    ),
    "db": (
        {"action": "dump", "stack": "aivis"},
        ["dump", "aivis"],
    ),
    "backup": ({}, []),
    "seed": (
        {"stack": "aivis", "profile": "demo", "dry_run": True},
        ["aivis", "--profile", "demo", "--dry-run"],
    ),
    "verb": (
        {"name": "set-setting", "pairs": ["key=x", "value=привет"]},
        ["set-setting", "key=x", "value=привет"],
    ),
    "start": ({"stack": "aivis", "service": "app"}, ["aivis", "app"]),
    "stop": ({"stack": "aivis"}, ["aivis"]),
    "restart": ({"stack": "aivis", "service": "worker"}, ["aivis", "worker"]),
}
"""A command of each verb with a verdict: its arguments and, literally, the
command line the machine gets for them."""


def test_every_verb_with_a_verdict_has_a_sample() -> None:
    assert sorted(SAMPLES) == sorted(n for n, v in VERBS.items() if v.verdict)


@pytest.mark.parametrize("name", sorted(SAMPLES))
def test_a_command_s_arguments_go_on_the_command_line_and_back(name: str) -> None:
    """args -> argv (literal) -> the command line read by the CLI -> the
    verb's model equal to the model of the arguments."""
    verb = VERBS[name]
    args, line = SAMPLES[name]
    assert argv_of(verb, args) == line
    given, _ = _arguments(verb, line)
    assert given == args
    assert verb.args.model_validate(given) == verb.args.model_validate(args)


@pytest.mark.parametrize("name", sorted(n for n, v in VERBS.items() if v.verdict))
def test_every_kind_of_argument_of_every_verb_goes_and_comes_back(name: str) -> None:
    """Every positional, the rest, every option by its kind, all at once:
    the command line read back is the arguments."""
    verb = VERBS[name]
    args: dict[str, Json] = {}
    for number, positional in enumerate(verb.positionals):
        args[positional] = f"p{number}"
    if verb.rest is not None:
        args[verb.rest] = ["r1", "r2"]
    for flag, (key, kind) in verb.options.items():
        args[key] = (
            True if kind == "flag" else ["l1", "l2"] if kind == "list" else flag[2:]
        )
    given, _ = _arguments(verb, argv_of(verb, args))
    assert given == args


@pytest.mark.parametrize(
    ("name", "args"),
    [
        ("deploy", {"ref": "--json"}),
        ("deploy", {"ref": ["9a1c4e2"]}),
        ("destroy", {"all": "yes"}),
        ("update", {"tries": "comms=4.2.0"}),
        ("db", {"stack": "aivis"}),
        ("verb", {"pairs": ["x=1"]}),
        ("status", {"unexpected": "x"}),
        ("verb", {"name": "set", "pairs": ["--confirm"]}),
    ],
)
def test_what_the_command_line_cannot_carry_is_not_turned(
    name: str, args: dict[str, Json]
) -> None:
    with pytest.raises(NotArgv):
        argv_of(VERBS[name], args)


# --- the agent's own refusals -------------------------------------------------------

NOW = datetime(2026, 11, 25, 12, 0, 0, tzinfo=UTC)


def _command(verb: str, args: dict[str, Json], **more: str) -> Command:
    return Command.model_validate(
        {
            "id": "cmd-1",
            "verb": verb,
            "args": args,
            "expires_at": "2026-11-25T12:10:00Z",
            **more,
        }
    )


def test_the_verbs_refused_as_unknown_are_those_with_no_verdict_agent_and_none() -> (
    None
):
    """Literally: the five verbs a command cannot carry (``ssl status`` writes
    no verdict though ``ssl`` has one), ``agent`` and a verb of no one's.
    The pair: ``ssl renew`` passes."""
    refused_ones: list[tuple[str, dict[str, Json]]] = [
        ("state", {}),
        ("version", {}),
        ("report", {"run_id": "2026-11-25T10:00:00Z-a3f9"}),
        ("logs", {"stack": "aivis"}),
        ("ssl", {"action": "status"}),
        ("agent", {}),
        ("teleport", {}),
    ]
    for verb, args in refused_ones:
        assert checked(_command(verb, args), NOW) == "verb-unknown", verb
    found = checked(_command("ssl", {"action": "renew"}), NOW)
    assert not isinstance(found, str) and found[1] == ["renew"]


@pytest.mark.parametrize(
    ("verb", "args"),
    [
        ("deploy", {"unexpected": "x"}),
        ("deploy", {"ref": ["x"]}),
        ("deploy", {"ref": "--json"}),
        ("deploy", {"ref": 7}),
        ("deploy", {}),
        ("ssl", {"action": "explode"}),
    ],
    ids=["extra", "a list", "an option", "a number", "none", "not of the model"],
)
def test_arguments_the_verb_or_the_command_line_refuse_are_args_refused(
    verb: str, args: dict[str, Json]
) -> None:
    """The last two go on a command line well enough: the verb's own model
    refuses them -- a ``ref`` missing, an ``action`` of no list."""
    assert checked(_command(verb, args), NOW) == "args-refused"


def test_confirm_without_confirmed_at_is_confirmation_missing() -> None:
    args: dict[str, Json] = {"confirm": "velo-dev"}
    assert checked(_command("destroy", args), NOW) == "confirmation-missing"
    found = checked(_command("destroy", args, confirmed_at="2026-11-25T11:59:00Z"), NOW)
    assert not isinstance(found, str) and found[1] == ["--confirm", "velo-dev"]


def test_a_command_taken_after_its_term_is_expired() -> None:
    command = _command("status", {})
    at_term = datetime(2026, 11, 25, 12, 10, 0, tzinfo=UTC)
    assert not isinstance(checked(command, at_term), str)
    assert checked(command, at_term + timedelta(seconds=1)) == "expired"


# --- a busy box ---------------------------------------------------------------------


def test_a_busy_box_asks_for_no_command(fs_root: Path) -> None:
    """While a process holds the box's lock the agent does not ask the
    queue: it looks again in 5 s. The pair: the box free, it asks."""
    clock = Clock()
    panel, pauses = AgentPanel(clock), Pauses(clock)
    said: list[str] = []
    agent = _agent(fs_root, panel, PridemInProcess(fs_root), pauses, said)
    with _held(box_root(fs_root)):
        agent.turn()
        assert panel.requests == [] and pauses.seen == [5.0]
    agent.turn()
    assert panel.requests == [("GET", "/agent/v1/commands/next")]


def test_a_run_a_busy_box_refuses_runs_again_when_it_is_free(fs_root: Path) -> None:
    """The box got busy after the command was taken: the machine refuses the
    run before it (``box-busy``); the agent runs it again in 5 s, the box
    free by then, and the command runs once."""
    clock = Clock()
    panel, pauses = AgentPanel(clock), Pauses(clock)
    said: list[str] = []
    machine = PridemInProcess(fs_root)
    agent = _agent(fs_root, panel, machine, pauses, said)
    panel.queue.append({"verb": "status", "args": {}})
    with _held(box_root(fs_root)) as pid:
        pauses.hook.append(lambda: _gone(pid))
        command = agent.client.next_command()
        assert command is not None
        agent.handle(command)
    assert len(machine.calls) == 2 and pauses.seen == [5.0]
    assert len(panel.verdicts) == 1 and panel.refusals == {}
    machine.assert_clean()


def test_a_box_busy_until_the_term_refuses_the_command_expired(fs_root: Path) -> None:
    clock = Clock()
    panel, pauses = AgentPanel(clock), Pauses(clock)
    said: list[str] = []
    machine = PridemInProcess(fs_root)
    agent = _agent(fs_root, panel, machine, pauses, said)
    panel.queue.append({"verb": "status", "args": {}})
    pauses.hook.append(lambda: clock.move(600))  # past the term after a pause
    with _held(box_root(fs_root)):
        command = agent.client.next_command()
        assert command is not None
        agent.handle(command)
    assert panel.refusals == {"cmd-1": "expired"}
    assert len(machine.calls) == 2 and panel.verdicts == {}
    assert said[-1] == "command cmd-1: the box stayed busy: expired"


# --- the Panel away, its refusals ---------------------------------------------------


def test_the_pauses_double_up_to_five_minutes_with_no_end() -> None:
    seen: list[float] = []

    def pause(seconds: float) -> bool:
        seen.append(seconds)
        return True

    backoff = Backoff()
    for _ in range(12):
        backoff.wait(pause)
    assert seen == [1, 2, 4, 8, 16, 32, 64, 128, 256, 300, 300, 300]
    backoff.reset()
    backoff.wait(pause)
    assert seen[-1] == 1


def test_the_queue_waits_out_a_panel_away_and_its_refusals(fs_root: Path) -> None:
    """No answer, a 5xx, a refusal of the transport: the queue pauses
    longer each time, then takes the command when the Panel answers."""
    clock = Clock()
    panel, pauses = AgentPanel(clock), Pauses(clock, stop_after=4)
    said: list[str] = []
    machine = PridemInProcess(fs_root)
    agent = _agent(fs_root, panel, machine, pauses, said)
    panel.outages = ["refused", Answer(503, b""), refused("signature-bad")]
    panel.queue.append({"verb": "status", "args": {}})
    agent.queue(lambda: len(panel.verdicts) == 1)
    assert pauses.seen == [1, 2, 4]
    assert said[:3] == [
        "commands: the Panel did not answer (refused)",
        "commands: the Panel answered 503",
        "commands: refused: signature-bad",
    ]
    assert len(panel.verdicts) == 1
    panel.assert_consumed()


def test_a_verdict_waits_out_a_refusal_of_the_transport(fs_root: Path) -> None:
    clock = Clock()
    panel, pauses = AgentPanel(clock), Pauses(clock)
    said: list[str] = []
    machine = PridemInProcess(fs_root)
    agent = _agent(fs_root, panel, machine, pauses, said)
    run_id = _one_run(agent, panel)
    panel.verdicts.clear()
    panel.outages = [refused("clock-skew"), "timed-out"]
    agent._send_verdict(run_id)  # noqa: SLF001 -- the delivery alone
    assert pauses.seen == [1, 2] and run_id in panel.verdicts


def test_a_run_of_another_box_is_given_up(fs_root: Path) -> None:
    clock = Clock()
    panel, pauses = AgentPanel(clock), Pauses(clock, stop_after=3)
    said: list[str] = []
    machine = PridemInProcess(fs_root)
    agent = _agent(fs_root, panel, machine, pauses, said)
    run_id = _one_run(agent, panel)
    panel.verdicts.clear()
    panel.owners[run_id] = "box-of-someone"
    agent._send_verdict(run_id)  # noqa: SLF001
    assert pauses.seen == [] and panel.verdicts == {}
    assert said == [f"verdict {run_id}: refused: run-foreign"]


def test_the_lines_of_a_run_over_go_until_the_panel_holds_them_all(
    fs_root: Path,
) -> None:
    """The Panel holds nothing after a batch (its gap): the agent pauses and
    sends again from where it holds."""
    clock = Clock()
    panel, pauses = AgentPanel(clock), Pauses(clock)
    said: list[str] = []
    agent = _agent(fs_root, panel, PridemInProcess(fs_root), pauses, said)
    run_id = _one_run(agent, panel)
    panel.lines.clear()
    panel.verdicts.clear()
    path = box_root(fs_root) / "journal" / f"{run_id}.jsonl"
    panel.outages = [Answer(200, b'{"last_seq":0}')]
    agent.finish(path, 0)
    assert pauses.seen == [1]
    assert sorted(panel.lines[run_id]) == [line.seq for line in journal_lines(path)]
    assert said == [f"events {run_id}: the Panel holds up to seq 0"]


def test_the_lines_go_in_batches(
    fs_root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(service, "BATCH", 1)
    clock = Clock()
    panel, pauses = AgentPanel(clock), Pauses(clock)
    said: list[str] = []
    agent = _agent(fs_root, panel, PridemInProcess(fs_root), pauses, said)
    run_id = _one_run(agent, panel)
    events = [r for r in panel.requests if r[1].endswith("/events")]
    lines = journal_lines(box_root(fs_root) / "journal" / f"{run_id}.jsonl")
    assert len(events) >= len(lines) >= 2


def test_lines_the_panel_holds_are_not_sent_again(fs_root: Path) -> None:
    """A run over whose lines the Panel holds to the last: no line goes
    again -- the agent goes on from the Panel's answer, not from the first.
    The pair: from one before the last, one batch of one line."""
    clock = Clock()
    panel, pauses = AgentPanel(clock), Pauses(clock)
    said: list[str] = []
    agent = _agent(fs_root, panel, PridemInProcess(fs_root), pauses, said)
    run_id = _one_run(agent, panel)
    path = box_root(fs_root) / "journal" / f"{run_id}.jsonl"
    last = journal_lines(path)[-1].seq
    panel.requests.clear()
    panel.verdicts.clear()
    agent.finish(path, last)
    assert panel.requests == [("POST", f"/agent/v1/runs/{run_id}/verdict")]
    panel.requests.clear()
    agent.finish(path, last - 1)
    assert panel.requests == [
        ("POST", f"/agent/v1/runs/{run_id}/events"),
        ("POST", f"/agent/v1/runs/{run_id}/verdict"),
    ]
    assert panel.batches[-1] == (run_id, last, 1)


def test_a_run_makes_the_next_heartbeat_a_full_one(fs_root: Path) -> None:
    """TZ-2 5: the full form after every run. The pair: none before."""
    clock = Clock()
    panel, pauses = AgentPanel(clock), Pauses(clock)
    said: list[str] = []
    agent = _agent(fs_root, panel, PridemInProcess(fs_root), pauses, said)
    assert not agent.full_due.is_set()
    _one_run(agent, panel)
    assert agent.full_due.is_set()


def _one_run(agent: Agent, panel: AgentPanel) -> str:
    panel.queue.append({"verb": "status", "args": {}})
    agent.turn()
    [run_id] = panel.verdicts
    return run_id


# --- the heartbeat ------------------------------------------------------------------


def test_the_light_heartbeat_says_who_holds_the_box_and_the_runs(
    fs_root: Path,
) -> None:
    root = box_root(fs_root)
    (root / "journal").mkdir(exist_ok=True)
    (root / "journal" / "2026-11-25T10:00:00Z-dead.jsonl").write_text("")
    newest = max(p.stem for p in (root / "history").glob("*.json"))
    with _held(root) as pid:
        beat = light_beat(root, NOW)
    assert beat.model_dump(mode="json") == {
        "measured_at": "2026-11-25T12:00:00Z",
        "machine_version": __version__,
        "lock_open_by": [f"pid {pid} (sleep)"],
        "journals_without_verdict": ["2026-11-25T10:00:00Z-dead"],
        "last_run_id": newest,
    }


def test_the_heartbeat_is_full_first_after_a_run_and_by_its_interval(
    fs_root: Path,
) -> None:
    clock = Clock()
    panel = AgentPanel(clock)
    said: list[str] = []
    pauses = Pauses(clock, stop_after=4)
    agent = _agent(fs_root, panel, PridemInProcess(fs_root), pauses, said)
    pauses.hook.append(lambda: agent.full_due.set() if len(pauses.seen) == 2 else None)
    agent.beats(lambda: False)
    full = [beat.state is not None for beat in panel.beats]
    assert full == [True, False, True, False]
    assert pauses.seen == [30, 30, 30, 30]
    assert panel.beats[0].state == BoxSnapshot.model_validate(STATE)


# --- one agent, the command line ----------------------------------------------------


def test_a_second_agent_is_refused(fs_root: Path) -> None:
    root = box_root(fs_root)
    with agent_lock(root):
        with pytest.raises(AgentRunning), agent_lock(root):
            pass
        out, err = io.StringIO(), io.StringIO()
        assert run(["agent"], root=root, out=out, err=err, fs_root=fs_root) == 1
        assert err.getvalue() == "pridem: agent: another agent runs\n"
    with agent_lock(root):
        pass


@pytest.mark.parametrize(
    "argv",
    [["agent", "--json"], ["agent", "now"], ["--json", "agent"], ["--timer", "agent"],
     ["--command", "cmd-1", "agent"]],
)  # fmt: skip
def test_agent_takes_no_argument_and_no_flag(fs_root: Path, argv: list[str]) -> None:
    out, err = io.StringIO(), io.StringIO()
    assert run(argv, root=box_root(fs_root), out=out, err=err, fs_root=fs_root) == 1
    assert err.getvalue() == "pridem: agent takes no arguments and no flags\n"


def test_a_box_not_registered_runs_no_agent(tmp_path: Path) -> None:
    out, err = io.StringIO(), io.StringIO()
    root = tmp_path / "opt" / "pridem"
    assert run(["agent"], root=root, out=out, err=err, fs_root=tmp_path) == 1
    assert err.getvalue() == (
        "pridem: agent: the box is not registered -- pridem register first\n"
    )


def test_a_damaged_key_runs_no_agent(fs_root: Path) -> None:
    key_path(box_root(fs_root)).chmod(0o644)
    out, err = io.StringIO(), io.StringIO()
    code = run(["agent"], root=box_root(fs_root), out=out, err=err, fs_root=fs_root)
    assert code == 1
    assert err.getvalue() == "pridem: agent: the box's key cannot be read\n"


# --- the loopback -------------------------------------------------------------------


def test_a_command_through_http_client_on_the_loopback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The agent's HTTP the whole way: registered on the loopback, a command
    taken, its lines and its verdict through ``http.client``."""
    clock = Clock(datetime.now(UTC).replace(microsecond=0))
    panel = AgentPanel(clock)

    class Handler(BaseHTTPRequestHandler):
        def _any(self) -> None:
            body = self.rfile.read(int(self.headers.get("Content-Length") or 0))
            answer = panel.request(
                self.command, self.path, body, dict(self.headers.items()), 5
            )
            self.send_response(answer.status)
            self.send_header("Content-Length", str(len(answer.body)))
            self.end_headers()
            self.wfile.write(answer.body)

        do_GET = do_POST = _any  # noqa: N815

        def log_message(self, format: str, *args: object) -> None:  # noqa: A002
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    origin = f"http://127.0.0.1:{server.server_address[1]}"
    try:
        with_passport(tmp_path)
        assert register(tmp_path, monkeypatch, FakePanel(), argv=("--panel", origin),
                        now=lambda: clock()).code == 0  # fmt: skip
        root = box_root(tmp_path)
        registration = read_registration(root)
        assert registration is not None
        panel.enrol(root)
        machine = PridemInProcess(tmp_path)
        agent = Agent(
            root=root,
            client=PanelClient(
                registration, key_path(root).read_bytes(), HttpTransport(), clock
            ),
            runner=machine,
            now=clock,
            pause=lambda seconds: True,
            say=lambda text: None,
            state=lambda: BoxSnapshot.model_validate(STATE),
            owner=os.geteuid(),
            heartbeat_s=registration.heartbeat_s,
            full_state_s=registration.full_state_s,
        )
        assert agent.client.base == f"{origin}/agent/v1/"
        panel.queue.append({"verb": "status", "args": {}})
        agent.turn()
    finally:
        server.shutdown()
        server.server_close()
    [kept] = panel.verdicts.values()
    assert kept.verified and kept.envelope.verdict.command == "cmd-1"
    panel.assert_consumed()
    machine.assert_clean()


# --- the parent's death -------------------------------------------------------------

AGENT_LIKE = """
import sys, threading
from pridem.runner import RunnerError, SubprocessRunner
def work():
    SubprocessRunner().run(
        ["sh", "-c", "echo $$; exec sleep 30"], timeout=60,
        on_line=lambda s, line, c: print(line, flush=True))
threading.Thread(target=work).start()
"""


def test_the_run_dies_with_the_agent() -> None:
    """Measured (gate of DM-141): a process that runs a command from a
    thread of its own, as the agent does, is killed -- the command dies with
    it (``setpriv --pdeathsig KILL``). The pair: alive before the kill."""
    seen: list[str] = []
    box: list[BaseException] = []

    def agent() -> None:
        try:
            SubprocessRunner().run(
                [sys.executable, "-c", AGENT_LIKE],
                timeout=60,
                on_line=lambda s, line, c: seen.append(line),
            )
        except RunnerError as error:  # killed: the code is the kill's
            box.append(error)

    thread = threading.Thread(target=agent)
    thread.start()
    end = time.monotonic() + 15
    while not seen:
        assert time.monotonic() < end, "the command never started"
        time.sleep(0.02)
    child = int(seen[0])
    parent = int(Path(f"/proc/{child}/stat").read_text().rsplit(")", 1)[1].split()[1])
    assert Path(f"/proc/{child}").exists()
    os.kill(parent, signal.SIGKILL)
    while Path(f"/proc/{child}").exists():
        assert time.monotonic() < end, "the command outlived the agent"
        time.sleep(0.02)
    thread.join(15)
    assert not thread.is_alive() and len(box) == 1
