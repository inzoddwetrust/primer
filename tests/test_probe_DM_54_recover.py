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
from pathlib import Path

import pytest
from state_support import header, run_id

from pridem.cli import run
from pridem.events import Secrets
from pridem.report.catalog import ENGLISH, Catalog
from pridem.report.schema import Verdict
from pridem.runner import FakeRunner
from pridem.state import Box, JournalHeader, JournalSink, Recovery
from pridem.verbs import VERBS

NO_SECRETS = Secrets(())
ARGV = {"status": ["status"], "gc": ["gc"], "ssl": ["ssl", "renew"]}
"""The command line of each verb with a verdict."""
WITH_VERDICT = sorted(name for name, verb in VERBS.items() if verb.verdict and verb.box)
"""The verbs of the box that end with a verdict. DM-57 added ``check``: a
verdict of a repository with no box -- no lock, no journal, nothing to recover
-- so the probe takes the verbs with a verdict that work on a box
(``Verb.box``), and its pair holds that ``check`` is the only one without."""


def test_the_probe_covers_the_verbs_with_a_verdict() -> None:
    """The pair of the probe: the verbs it runs are not an empty list,
    ``version`` (no verdict) is not among them, and the verbs without a box
    are exactly ``check`` -- a new verb does not leave ``recover`` by a flag."""
    assert WITH_VERDICT == ["gc", "ssl", "status"]
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

    def open_journal(self: Box, head: JournalHeader, secrets: Secrets) -> JournalSink:
        order.append(f"journal {head.verb}")
        return real_open(self, head, secrets)

    monkeypatch.setattr(Box, "recover", recover)
    monkeypatch.setattr(Box, "open_journal", open_journal)
    out, err = io.StringIO(), io.StringIO()
    with FakeRunner() as runner:  # no passport: the verbs' steps run nothing
        run(ARGV[name], root=root, out=out, err=err, runner=runner, fs_root=tmp_path)
    assert err.getvalue() == ""
    verdicts = {
        path.stem: Verdict.model_validate_json(path.read_text())
        for path in (root / "history").iterdir()
    }
    dead = verdicts.pop(run_id(1))
    assert (dead.verb, dead.result) == ("deploy", "red")
    assert dead.report.incomplete[0].code == "no-verdict"
    [own] = verdicts.values()
    assert own.verb == " ".join(ARGV[name])
    assert order == ["recover", f"journal {own.verb}"]
