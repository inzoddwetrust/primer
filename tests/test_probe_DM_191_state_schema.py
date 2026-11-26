"""DM-191 (REVIEW-0006 K11, B4): a machine of another release on the same box
does not destroy ``state.json``. Its stamp is read first, by a model that
ignores the fields it does not know: another schema -- every verb is refused
before a verdict (``state-schema``), the file stays byte for byte. A file that
is no JSON goes to quarantine only by a verb that writes the composition
(``install``, ``update``, ``deploy``, ``reinstall``, ``rollback``,
``destroy``); ``status`` and ``doctor`` are refused (``state-damaged``) and
the file stays; JSON not of the schema's form is quarantined by none. At
schema 1 the file carries no ``schema``: absent is 1 (the dispatcher's
decision on the gate -- a machine older than DM-191 put back on the box reads
the file as its own).
"""

import io
import json
from pathlib import Path

import pytest
from data_support import STACK, blank_box
from plan_support import Journal, ScriptedStep

from pridem.cli import run as cli
from pridem.plan import StackSteps
from pridem.runner import FakeRunner
from pridem.state import STATE, Box
from pridem.verbs import deploy as deploy_verbs
from pridem.verbs.run import Planned, Session

NAME = "tier1-box"
NEWER = "pridem: state-schema: state.json is of schema 2, this machine reads schema 1; nothing is changed\n"  # noqa: E501
DAMAGED = "pridem: state-damaged: state.json cannot be read; nothing is changed\n"


def _plan(session: Session, root: Path, wanted: object, preread: object) -> Planned:
    """One step, green, for the plan of any verb here: what is tested is
    before the plan."""
    step = ScriptedStep("done", 1, Journal(), modes=frozenset({"deploy", "install"}))
    return Planned([StackSteps(STACK, [step], root=True)])


def _box(fs_root: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    blank_box(fs_root, name=NAME)
    monkeypatch.setattr(deploy_verbs, "deploy_plan", _plan)
    return fs_root / "opt" / "pridem" / STATE


def _cli(
    fs_root: Path, argv: list[str], *, as_json: bool = True
) -> tuple[int, str, list[str]]:
    out, err = io.StringIO(), io.StringIO()
    box = Box(fs_root / "opt" / "pridem")
    before = set(box.history_ids())
    with FakeRunner() as runner:  # --json: no console state, no docker
        code = cli(
            ["--json", *argv] if as_json else argv,
            root=box.root,
            out=out,
            err=err,
            runner=runner,
            fs_root=fs_root,
        )
    added = [r for r in box.history_ids() if r not in before]
    return code, err.getvalue(), added


def _newer(path: Path) -> bytes:
    """``state.json`` as a newer machine writes it: schema 2 and a field this
    machine does not know."""
    data = json.loads(path.read_text(encoding="utf-8"))
    data.update({"schema": 2, "pulse": {"interval_s": 30}})
    content = json.dumps(data, indent=2).encode()
    path.write_bytes(content)
    return content


# --- probes ---------------------------------------------------------------------


def test_probe_DM_191_a_reading_verb_refuses_a_state_of_another_schema(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``status`` and ``doctor`` -- and ``update``, which writes -- on the
    ``state.json`` of a newer machine: refused before a verdict
    (``state-schema``, code 1); the file byte for byte, no
    ``state.json.damaged``, no verdict. The pair: the file this machine
    writes (no ``schema``, schema 1) -- ``status`` and ``doctor`` run."""
    state = _box(tmp_path, monkeypatch)
    written = state.read_bytes()
    assert "schema" not in json.loads(written)  # schema 1: absent
    for argv in (["status"], ["doctor"]):
        code, err, added = _cli(tmp_path, argv)
        assert code != 1 and len(added) == 1, (argv, err)  # it ran: a verdict
    content = _newer(state)
    for argv in (["status"], ["doctor"], ["update"]):
        code, err, added = _cli(tmp_path, argv)
        assert (code, err, added) == (1, NEWER, []), argv
        assert state.read_bytes() == content, argv
        assert not state.with_name(STATE + ".damaged").exists(), argv


def test_probe_DM_191_only_a_writing_verb_quarantines_what_is_not_json(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A ``state.json`` that is no JSON: ``status`` and ``doctor`` are refused
    (``state-damaged``), the file stays; ``update`` writes the composition --
    it quarantines it and says so (``incomplete state/quarantined``, code 2).
    The pair: JSON not of the schema's form -- ``update`` is refused too, no
    quarantine."""
    state = _box(tmp_path, monkeypatch)
    state.write_bytes(b"{")
    for argv in (["status"], ["doctor"]):
        code, err, added = _cli(tmp_path, argv)
        assert (code, err, added) == (1, DAMAGED, []), argv
        assert state.read_bytes() == b"{"
    code, err, added = _cli(tmp_path, ["update"])
    assert code == 2 and len(added) == 1, err
    assert not state.exists()
    assert state.with_name(STATE + ".damaged").read_bytes() == b"{"
    box = Box(tmp_path / "opt" / "pridem")
    found = box.read_verdict(added[0]).report.incomplete
    assert [i.model_dump() for i in found] == [{"what": "state", "code": "quarantined"}]
    # the pair: JSON, not of the form -- no quarantine by any verb
    other = tmp_path / "second"
    state = _box(other, monkeypatch)
    state.write_text('{"composition": "x"}', encoding="utf-8")
    for argv in (["update"], ["status"]):
        code, err, added = _cli(other, argv)
        assert (code, err, added) == (1, DAMAGED, []), argv
        assert state.read_text(encoding="utf-8") == '{"composition": "x"}'
        assert not state.with_name(STATE + ".damaged").exists()


# --- the rest -------------------------------------------------------------------


def test_the_stamp_of_another_machine_is_read_whatever_else_it_holds(
    tmp_path: Path,
) -> None:
    """The stamp ignores what it does not know: a newer file with a field this
    machine has never seen is ``StateSchema``, not damage. A stamp not of its
    form (``schema`` not a whole number of at least 1), or a file that is no
    object -- damage, left where it is."""
    from pridem.state import StateDamaged, StateSchema

    box = Box(tmp_path)
    path = tmp_path / STATE
    for content, error in (
        ('{"schema": 3, "anything": [1, 2]}', StateSchema),
        ('{"schema": 0}', StateDamaged),
        ('{"schema": "2"}', StateDamaged),
        ("[1, 2]", StateDamaged),
    ):
        path.write_text(content, encoding="utf-8")
        with box.lock("a"), pytest.raises(error):
            box.read_state()
        assert path.read_text(encoding="utf-8") == content
        assert not box.state_quarantined


def test_a_data_verb_outside_the_lock_refuses_another_schema(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``logs`` reads ``state.json`` without the lock (the stacks it names):
    another schema -- refused the same way, the file as it was."""
    state = _box(tmp_path, monkeypatch)
    content = _newer(state)
    code, err, _ = _cli(tmp_path, ["logs", STACK], as_json=False)
    assert (code, err) == (1, NEWER)
    assert state.read_bytes() == content
