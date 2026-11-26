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
from pridem.runner import CommandNotStarted, FakeCall, FakeRunner, OnLine, Result
from pridem.state import Box, JournalHeader, JournalSink, Recovery
from pridem.steps.identity import Answer, PanelUnreachable
from pridem.steps.passport import PASSPORT_COPY
from pridem.verbs import VERBS
from pridem.verbs.register import TOKEN_ENV, make_register

NO_SECRETS = Secrets(())
PASSPORT = "<passport>"
NAMED = str(passport_example()["server"]["name"])  # type: ignore[index]
"""The server's name ``destroy`` and ``reinstall`` confirm on any role
(DM-110, on the dispatcher's word: the owner's decision of 17.11)."""
"""Stands for a passport file of a test box the test writes."""
ARGV = {
    "status": ["status"],
    "gc": ["gc"],
    "ssl": ["ssl", "renew"],
    "install": ["install", "--passport", PASSPORT],
    "update": ["update", "--passport", PASSPORT],
    "deploy": ["deploy", "main", "--passport", PASSPORT],
    "doctor": ["doctor", "--passport", PASSPORT],
    "reinstall": ["reinstall", "--passport", PASSPORT, "--confirm", NAMED],
    "destroy": ["destroy", "--confirm", NAMED],
    "db": ["db", "dump", "blank"],
    "backup": ["backup"],
    "seed": ["seed", "--list"],
    "verb": ["verb", "count-settings"],
    "rollback": ["rollback", "--passport", PASSPORT],
    "start": ["start"],
    "stop": ["stop"],
    "restart": ["restart"],
    "register": ["register"],
    "self-update": ["self-update", "v0.1.99"],
}
"""The command line of each verb with a verdict."""
ON_A_BOX = {"db", "backup", "seed", "verb", "start", "stop", "restart"}
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
SELF = {"self-update"}
"""DM-163: ``self-update`` fetches its release by the runner -- refused here,
the probe is about what comes before."""

IDENTITY = {"register"}
"""DM-139: ``register`` refuses before the lock without its token and the
passport's copy; the probe gives it both and a Panel that does not answer
(``Unreachable``) -- the probe is about what comes before."""


class Unreachable:
    """A way to the Panel that never reaches it: no network, no socket."""

    def post(self, url: str, body: bytes, headers: Mapping[str, str]) -> Answer:
        raise PanelUnreachable("refused")


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

    Changed by DM-86: ``db``, ``backup``, (pass 2) ``seed``, (pass 3)
    ``verb`` and (pass 4) ``start``, ``stop``, ``restart`` are verbs with a
    verdict on a box; the list names them, and the probe runs them on a box
    with an entry; ``logs`` reads with no verdict. Changed by DM-24, on the
    dispatcher's word: ``rollback`` is a verb with a verdict on a box.

    Changed by DM-136: ``state`` reads the box with no lock, no journal and
    no verdict -- a verb without a box, beside ``check``.

    Changed by DM-139, on the dispatcher's word 24.11: ``register`` is a verb
    with a verdict on a box.

    Changed by DM-163, on the dispatcher's word 26.11: ``self-update`` is a
    verb with a verdict on a box."""
    assert WITH_VERDICT == sorted(
        ["gc", "ssl", "status", *PLANS, *ON_A_BOX, *ROLLBACK, *IDENTITY, *SELF]
    )
    assert "version" in VERBS and not VERBS["version"].verdict
    assert {name for name, verb in VERBS.items() if not verb.box} == {
        "check",
        "state",
    }


STATE_ON_AN_EMPTY_BOX = (
    FakeCall(
        ("docker", "ps", "-a", "-q", "--no-trunc", "--filter", "label=pridem.stack")
    ),
    FakeCall(("docker", "system", "df", "--format", "json")),
)
"""What the state of a box without stacks asks docker (DM-136): no container,
and ``system df`` saying nothing -- the images are not measured."""


@pytest.mark.parametrize("name", WITH_VERDICT)
def test_probe_DM_54_recover_runs_before_every_plan_verb(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, name: str
) -> None:
    """Changed by DM-136, on the dispatcher's word of 24.11: ``status``
    prints the box's state after its verdict. It became false that
    ``status`` on a box without stacks runs no command: the strict script of
    ``status`` holds the commands of the state on an empty box, literally as
    docker gets them -- the containers by the machine's label and ``system
    df``. What the probe holds is as it was: ``recover`` runs before the
    plan."""
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
    elif name == "destroy":  # DM-110: the name is the passport's copy's
        copy = tmp_path / PASSPORT_COPY
        copy.parent.mkdir(parents=True, exist_ok=True)
        copy.write_text(file.read_text())
    elif name in IDENTITY:  # DM-139: a token, the passport's copy, no Panel
        monkeypatch.setenv(TOKEN_ENV, "a-one-time-token-of-the-panel")
        copy = tmp_path / PASSPORT_COPY
        copy.parent.mkdir(parents=True, exist_ok=True)
        copy.write_text(file.read_text())
        monkeypatch.setitem(VERBS, "register", make_register(transport=Unreachable))
    seeded: set[str] = set()
    if name in ROLLBACK:  # a previous release to go back to (DM-24)
        release_box(tmp_path, "prod", NEW, released(1, OLD), released(2, NEW))
        seeded = {run_of(1), run_of(2)}
    if name in PLANS | ON_A_BOX | ROLLBACK | SELF:
        run(argv, root=root, out=out, err=err, runner=Refusing(), fs_root=tmp_path)
    else:
        # no passport: the verbs' steps run nothing; status measures the
        # box's state after its verdict (DM-136)
        state = STATE_ON_AN_EMPTY_BOX if name == "status" else ()
        with FakeRunner(*state) as runner:
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
