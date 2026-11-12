"""The role and ``--confirm`` are read under the box lock (DM-24, pass 2).

A verb that refuses by the box's role or asks for the server's name reads the
passport's copy after it took the lock (``before`` of ``run_plan_verb``), not
before: here the copy turns ``prod`` between the start of the command and the
lock -- inside ``recover``, the first thing done under it -- and the verb
refuses by the copy it read then, with no journal and no verdict. The pair: the
copy stays ``test`` -- the verb goes on to its plan.
"""

import io
from pathlib import Path

import pytest
import yaml
from data_support import STACK, blank_box
from passport_support import passport_example, section, write_passport
from plan_support import Journal, ScriptedStep

from pridem.cli import run as cli
from pridem.events import Secrets
from pridem.plan import StackSteps
from pridem.runner import FakeRunner
from pridem.state import Box
from pridem.steps.passport import PASSPORT_COPY
from pridem.verbs import deploy as deploy_verbs
from pridem.verbs.run import Planned, Session

NAME = "tier1-box"


def _turns_prod(fs_root: Path, monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """Under the lock, before anything else, the copy becomes ``prod``."""
    order: list[str] = []
    real = Box.recover

    def recover(self: Box, secrets: Secrets, version: str, *rest: object) -> object:
        copy = fs_root / PASSPORT_COPY
        data = yaml.safe_load(copy.read_text(encoding="utf-8"))
        data["server"]["role"] = "prod"
        data["product"]["ref"] = "v1.0.0"  # passport rule 4
        copy.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
        order.append("recover")
        return real(self, secrets, version, *rest)  # type: ignore[arg-type]

    monkeypatch.setattr(Box, "recover", recover)
    return order


def _cli(fs_root: Path, argv: list[str]) -> tuple[int, str, list[str]]:
    out, err = io.StringIO(), io.StringIO()
    box = Box(fs_root / "opt" / "pridem")
    before = set(box.history_ids())
    with FakeRunner() as runner:
        code = cli(
            argv, root=box.root, out=out, err=err, runner=runner, fs_root=fs_root
        )
    added = [r for r in box.history_ids() if r not in before]
    return code, err.getvalue(), added


def _plan(session: Session, root: Path, wanted: object, preread: object) -> Planned:
    step = ScriptedStep("done", 1, Journal(), modes=frozenset({"reinstall"}))
    return Planned([StackSteps("aivis", [step], root=True)])


def _file(fs_root: Path) -> Path:
    data = passport_example()
    section(data, "server")["role"] = "test"
    section(data, "server")["name"] = NAME
    return write_passport(fs_root, data)


def test_reinstall_reads_the_role_under_the_lock(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``reinstall`` without ``--confirm``: the copy is ``test`` when the
    command starts and ``prod`` under the lock -- refused, naming the server,
    after ``recover``; no verdict."""
    blank_box(tmp_path, name=NAME)
    file = _file(tmp_path)
    monkeypatch.setattr(deploy_verbs, "deploy_plan", _plan)
    order = _turns_prod(tmp_path, monkeypatch)
    code, err, added = _cli(tmp_path, ["reinstall", "--passport", str(file)])
    assert (code, added, order) == (1, [], ["recover"])
    assert f"--confirm {NAME} to go on" in err


def test_reinstall_on_a_test_box_goes_on(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The pair: the copy stays ``test`` -- ``reinstall`` runs its plan."""
    blank_box(tmp_path, name=NAME)
    file = _file(tmp_path)
    monkeypatch.setattr(deploy_verbs, "deploy_plan", _plan)
    code, err, added = _cli(tmp_path, ["reinstall", "--passport", str(file)])
    assert code == 0, err
    assert len(added) == 1


def test_destroy_reads_the_role_under_the_lock(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    blank_box(tmp_path, name=NAME)
    order = _turns_prod(tmp_path, monkeypatch)
    code, err, added = _cli(tmp_path, ["destroy"])
    assert (code, added, order) == (1, [], ["recover"])
    assert f"destroy on prod: --confirm {NAME} to go on" in err


def test_db_reset_reads_the_role_under_the_lock(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``db reset`` runs on the role ``test`` only: ``test`` when the command
    starts, ``prod`` under the lock -- refused; no verdict."""
    blank_box(tmp_path, name=NAME)
    order = _turns_prod(tmp_path, monkeypatch)
    argv = ["db", "reset", STACK, "--confirm", NAME]
    code, err, added = _cli(tmp_path, argv)
    assert (code, added, order) == (1, [], ["recover"])
    assert "db reset: runs on the role test only" in err
