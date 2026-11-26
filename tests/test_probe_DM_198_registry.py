"""Probe of DM-198: the marks of the machine's registry of verbs are what the
verbs do.

``Verb`` says as data whether a run is destructive (``destructive``) and
whether it ends with a verdict (``verdict``, ``no_verdict``); the console, the
box's agent and the Panel read it there. The probe walks the registry: every
destructive run it names is refused without the server's name, every run it
says writes no verdict is refused ``--command`` -- and the cases here are
exactly those the registry names, so a mark added to it without its case is
red, and a mark taken off it lets its run through.

One box for all: the blank with a destructive verb of its own, a seed profile
with its resets, a dump on the box.
"""

import io
from datetime import UTC, datetime
from pathlib import Path

import yaml
from data_support import STACK
from test_dm110_confirm import Refusing
from test_verbs_data import _a_dump
from test_verbs_project import _box

from pridem.agent.command import checked
from pridem.cli import run as cli
from pridem.events import Json
from pridem.protocol import Command
from pridem.runner import FakeRunner
from pridem.state import Box
from pridem.verbs import VERBS

NAME = "box-1"
RUN_ID = "2026-11-25T10:00:00Z-a3f9"
NOW = datetime(2026, 11, 26, 12, 0, tzinfo=UTC)

Case = tuple[str, ...] | tuple[str, str, str | bool]


def _a_box(fs_root: Path) -> Path:
    """The box of the blank: the verbs of ``test_verbs_project`` (``set-setting``
    is destructive), the profile ``demo`` with ``reset`` and ``reset_only``,
    ``seeds_reset_all``, a dump of ``db dump``. Returns the dump."""
    _box(fs_root)
    release = (fs_root / "opt" / STACK / "current").resolve()
    primer = yaml.safe_load((release / "primer.yaml").read_text())
    primer["stacks"][STACK]["seeds"] = {
        "demo": {
            "run": "python -m app.seed demo",
            "when": "command",
            "reset": "python -m app.seed demo --reset",
            "reset_only": "python -m app.seed demo --reset-only",
        },
        "bootstrap": {"run": "python -m app.seed bootstrap", "when": "install"},
    }
    primer["stacks"][STACK]["seeds_reset_all"] = "python -m app.seed demo --reset-all"
    (release / "primer.yaml").write_text(yaml.safe_dump(primer, sort_keys=False))
    return _a_dump(fs_root)


def _destructive_runs(dump: Path) -> dict[Case, list[list[str]]]:
    """A command line for every destructive run the registry can name: a verb
    that always is, each value of an argument that makes one, a verb of the
    product that declares itself one."""
    seed = ["seed", STACK, "--profile", "demo"]
    return {
        ("destroy", "always"): [["destroy"], ["destroy", "--all"]],
        ("reinstall", "always"): [["reinstall"], ["reinstall", "--new-secrets"]],
        ("db", "action", "restore"): [["db", "restore", STACK, str(dump)]],
        ("db", "action", "reset"): [["db", "reset", STACK]],
        ("seed", "reset", True): [[*seed, "--reset"]],
        ("seed", "reset_only", True): [[*seed, "--reset-only"]],
        ("seed", "reset_all", True): [["seed", STACK, "--reset-all"]],
        ("verb", "declared"): [["verb", "set-setting", "key=k", "value=v"]],
    }


def _named_destructive() -> set[Case]:
    """The same, read off the registry."""
    found: set[Case] = set()
    for verb in VERBS.values():
        mark = verb.destructive
        if mark.always:
            found.add((verb.name, "always"))
        if mark.declared:
            found.add((verb.name, "declared"))
        for field, values in mark.when:
            found |= {(verb.name, field, value) for value in values}
    return found


NO_VERDICT_VERBS: dict[str, list[str]] = {
    "version": ["version"],
    "state": ["state"],
    "report": ["report", RUN_ID],
    "logs": ["logs", STACK],
}
NO_VERDICT_ACTIONS: dict[Case, tuple[list[str], str]] = {
    ("ssl", "action", "status"): (["ssl", "status"], "ssl status"),
    ("db", "action", "connect"): (["db", "connect", STACK], "db connect"),
}


def _history(fs_root: Path) -> list[str]:
    return Box(fs_root / "opt" / "pridem").history_ids()


def _run(fs_root: Path, argv: list[str], runner: object) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    code = cli(
        argv,
        root=fs_root / "opt" / "pridem",
        out=out,
        err=err,
        runner=runner,  # type: ignore[arg-type]
        fs_root=fs_root,
    )
    return code, out.getvalue(), err.getvalue()


def test_probe_DM_198_the_marks_of_the_registry_are_what_the_verbs_do(
    tmp_path: Path,
) -> None:
    """Destructive, by the registry: without ``--confirm`` (and no terminal)
    every such run is refused -- exit 1, the name asked for on stderr, no
    verdict, no command of the runner (its script is empty) -- and so it is
    with another server's name. The pair, for each: with the server's name it
    is not refused -- it goes on to its plan and a verdict is written.

    No verdict, by the registry: every verb that writes none, and every action
    that writes none of a verb that does (``ssl status``, ``db connect``), is
    refused ``--command`` before the lock by its words; the box's agent
    refuses the same as ``verb-unknown``. The pair: ``ssl renew`` and ``db
    dump`` with ``--command`` run, and their verdicts carry the command."""
    dump = _a_box(tmp_path)

    # --- destructive -----------------------------------------------------------
    runs = _destructive_runs(dump)
    assert set(runs) == _named_destructive()
    for case, lines in sorted(runs.items(), key=str):
        for argv in lines:
            for name in ([], ["--confirm", "box-2"]):  # none, and another's
                before = _history(tmp_path)
                with FakeRunner() as runner:  # nothing runs
                    code, out, err = _run(tmp_path, [*argv, *name], runner)
                assert (code, out) == (1, ""), (case, argv, name, err)
                assert "confirm" in err, (case, argv, name, err)
                assert _history(tmp_path) == before, (case, argv, name)
    # the pair: named, each goes on -- a verdict (every command of it refused)
    for case, lines in sorted(runs.items(), key=str):
        if case[0] in ("destroy", "reinstall"):
            continue  # they take the box down: named last, below
        for argv in lines:
            before = _history(tmp_path)
            code, _, err = _run(tmp_path, [*argv, "--confirm", NAME], Refusing())
            assert "confirm" not in err, (case, argv, err)
            assert len(_history(tmp_path)) == len(before) + 1, (case, argv, err)
    before = _history(tmp_path)
    code, _, err = _run(tmp_path, ["destroy", "--confirm", NAME], Refusing())
    assert "confirm" not in err and len(_history(tmp_path)) == len(before) + 1, err

    # --- no verdict ------------------------------------------------------------
    assert set(NO_VERDICT_VERBS) == {v.name for v in VERBS.values() if not v.verdict}
    named = {
        (verb.name, field, value)
        for verb in VERBS.values()
        for field, values in verb.no_verdict
        for value in values
    }
    assert set(NO_VERDICT_ACTIONS) == named
    silent = [(argv, argv[0]) for argv in NO_VERDICT_VERBS.values()]
    silent += list(NO_VERDICT_ACTIONS.values())
    for argv, words in silent:
        before = _history(tmp_path)
        with FakeRunner() as runner:
            code, out, err = _run(tmp_path, ["--command", "c1", *argv], runner)
        assert (code, out) == (1, ""), (argv, err)
        refusal = f"pridem: {words} writes no verdict: --command has nothing to carry"
        assert err.strip() == refusal, (argv, err)
        assert _history(tmp_path) == before, argv
    # the pair: the other action of the same verbs carries the command
    for argv in (["ssl", "renew"], ["db", "dump", STACK]):
        before = _history(tmp_path)
        code, _, err = _run(tmp_path, ["--json", "--command", "c1", *argv], Refusing())
        assert "writes no verdict" not in err, (argv, err)
        [new] = [r for r in _history(tmp_path) if r not in before]
        verdict = Box(tmp_path / "opt" / "pridem").read_verdict(new)
        assert verdict.command == "c1", (argv, verdict)

    # --- the agent reads the same mark ------------------------------------------
    queued: list[tuple[str, dict[str, Json]]] = [
        ("version", {}),
        ("state", {}),
        ("report", {"run_id": RUN_ID}),
        ("logs", {"stack": STACK}),
        ("ssl", {"action": "status"}),
        ("db", {"action": "connect", "stack": STACK}),
    ]
    assert {(v, a.get("action")) for v, a in queued} == {
        *((name, None) for name in NO_VERDICT_VERBS),
        *((verb, value) for verb, _, value in NO_VERDICT_ACTIONS),
    }
    for verb, args in queued:
        assert checked(_command(verb, args), NOW) == "verb-unknown", (verb, args)
    carried: list[tuple[str, dict[str, Json]]] = [
        ("ssl", {"action": "renew"}),
        ("db", {"action": "dump", "stack": STACK}),
    ]
    for verb, args in carried:
        found = checked(_command(verb, args), NOW)
        assert not isinstance(found, str), (verb, args, found)


def _command(verb: str, args: dict[str, Json]) -> Command:
    return Command.model_validate(
        {"id": "c1", "verb": verb, "args": args, "expires_at": "2026-11-26T13:00:00Z"}
    )
