"""Probe DM-54: every verb that ends with a verdict first gives its verdict to
a run that ended without one (``recover``, contract 2 rule 4), then opens its
own journal.

The verbs are taken from ``VERBS`` -- each one whose ``verdict`` is true and
that works on a box (``box``, since DM-57) -- so a new verb joins the probe by
itself; ``ARGV`` names its command line, and a
verb with a verdict missing there is red. The fact is the box's ``history/``:
the dead run's red verdict and the verb's own; the order is that of ``recover``
and ``open_journal`` on the ``Box``.
"""

import io
from collections.abc import Mapping, Sequence
from pathlib import Path

import pytest
from data_support import blank_box
from history_support import NEW, OLD, release_box, released, run_of
from passport_support import passport_example, section, write_passport
from state_support import header, run_id

from pridem.cli import run
from pridem.events import Secrets
from pridem.report.catalog import ENGLISH, Catalog
from pridem.report.schema import Verdict
from pridem.runner import CommandNotStarted, FakeRunner, OnLine, Result
from pridem.state import Box, JournalHeader, JournalSink, Recovery
from pridem.verbs import VERBS

NO_SECRETS = Secrets(())
PASSPORT = "<passport>"
"""Stands for a passport file of a test box the test writes."""
ARGV = {
    "status": ["status"],
    "gc": ["gc"],
    "ssl": ["ssl", "renew"],
    "install": ["install", "--passport", PASSPORT],
    "update": ["update", "--passport", PASSPORT],
    "deploy": ["deploy", "main", "--passport", PASSPORT],
    "doctor": ["doctor", "--passport", PASSPORT],
    "reinstall": ["reinstall", "--passport", PASSPORT],
    "destroy": ["destroy"],
    "db": ["db", "dump", "blank"],
    "backup": ["backup"],
    "seed": ["seed", "--list"],
    "verb": ["verb", "count-settings"],
    "rollback": ["rollback", "--passport", PASSPORT],
}
"""The command line of each verb with a verdict."""
ON_A_BOX = {"db", "backup", "seed", "verb"}
"""DM-86: the data verbs refuse before the run without an entry the box runs
and the passport's copy; the probe gives them a box that runs the blank
(``data_support.blank_box``), and their steps' commands are refused here
(``Refusing``) -- the probe is about what comes before."""
ROLLBACK = {"rollback"}
"""DM-24: ``rollback`` refuses before its journal on a box with no previous
release (a refusal, not a command); the probe gives it a prod box with one
(``history_support.release_box``), and its plan's commands are refused here.
The box's two green verdicts are the setup's, not the verb's: they are left
out of what the probe reads."""
PLANS = {"install", "update", "deploy", "doctor", "reinstall", "destroy"}
"""DM-45: the verbs of the box's plan; their steps run commands, which a
runner refuses here (``Refusing``): the probe is about what comes before."""


class Refusing:
    """A runner that starts nothing: every command is ``not started``."""

    def run(
        self,
        argv: Sequence[str],
        *,
        expect: tuple[int, ...] = (0,),
        timeout: float,
        cwd: Path | None = None,
        env: Mapping[str, str] | None = None,
        on_line: OnLine,
    ) -> Result:
        raise CommandNotStarted(tuple(argv), "refused by the test")


WITH_VERDICT = sorted(name for name, verb in VERBS.items() if verb.verdict and verb.box)
"""The verbs of the box that end with a verdict. DM-57 added ``check``: a
verdict of a repository with no box -- no lock, no journal, nothing to recover
-- so the probe takes the verbs with a verdict that work on a box
(``Verb.box``), and its pair holds that ``check`` is the only one without."""


def test_the_probe_covers_the_verbs_with_a_verdict() -> None:
    """The pair of the probe: the verbs it runs are not an empty list,
    ``version`` (no verdict) is not among them, and the verbs without a box
    are exactly ``check`` -- a new verb does not leave ``recover`` by a flag.

    Changed by DM-86: ``db``, ``backup``, (pass 2) ``seed`` and (pass 3)
    ``verb`` are verbs with a verdict on a box; the list names them, and the
    probe runs them on a box with an entry. Changed by DM-24, on the
    dispatcher's word: ``rollback`` is a verb with a verdict on a box."""
    assert WITH_VERDICT == sorted(["gc", "ssl", "status", *PLANS, *ON_A_BOX, *ROLLBACK])
    assert "version" in VERBS and not VERBS["version"].verdict
    assert {name for name, verb in VERBS.items() if not verb.box} == {"check"}


@pytest.mark.parametrize("name", WITH_VERDICT)
def test_probe_DM_54_recover_runs_before_every_plan_verb(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, name: str
) -> None:
    root = tmp_path / "opt" / "pridem"
    box = Box(root)
    with box.lock("dying"):  # a run that died: a journal and no verdict
        box.open_journal(header(run_id(1)), NO_SECRETS).close()
    order: list[str] = []
    real_recover, real_open = Box.recover, Box.open_journal

    def recover(
        self: Box, secrets: Secrets, machine_version: str, catalog: Catalog = ENGLISH
    ) -> Recovery:
        order.append("recover")
        return real_recover(self, secrets, machine_version, catalog)

    def open_journal(
        self: Box, head: JournalHeader, secrets: Secrets, limit: int | None = None
    ) -> JournalSink:
        # DM-24, on the dispatcher's word: the journal takes the run's limit
        order.append(f"journal {head.verb}")
        return real_open(self, head, secrets, limit)

    monkeypatch.setattr(Box, "recover", recover)
    monkeypatch.setattr(Box, "open_journal", open_journal)
    out, err = io.StringIO(), io.StringIO()
    data = passport_example()
    section(data, "server")["role"] = "test"
    file = write_passport(tmp_path, data)
    argv = [str(file) if word == PASSPORT else word for word in ARGV[name]]
    if name == "verb":  # a box whose product has the verb (pass 3)
        from test_verbs_project import _box

        _box(tmp_path)
    elif name in ON_A_BOX:
        blank_box(tmp_path)
    seeded: set[str] = set()
    if name in ROLLBACK:  # a previous release to go back to (DM-24)
        release_box(tmp_path, "prod", NEW, released(1, OLD), released(2, NEW))
        seeded = {run_of(1), run_of(2)}
    if name in PLANS | ON_A_BOX | ROLLBACK:
        run(argv, root=root, out=out, err=err, runner=Refusing(), fs_root=tmp_path)
    else:
        with FakeRunner() as runner:  # no passport: the verbs' steps run nothing
            run(argv, root=root, out=out, err=err, runner=runner, fs_root=tmp_path)
    assert err.getvalue() == ""
    verdicts = {
        path.stem: Verdict.model_validate_json(path.read_text())
        for path in (root / "history").iterdir()
        if path.stem not in seeded
    }
    dead = verdicts.pop(run_id(1))
    assert (dead.verb, dead.result) == ("deploy", "red")
    assert dead.report.incomplete[0].code == "no-verdict"
    [own] = verdicts.values()
    assert own.verb == " ".join(ARGV[name][:2] if name in ("ssl", "db") else [name])
    assert order == ["recover", f"journal {own.verb}"]
