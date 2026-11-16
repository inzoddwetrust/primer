"""The console for a person (DM-107; the form of velo's old install).

Literal lines: a step by its title, its fact in one sentence (``said``),
commits short, the reason in the catalog's words; a live line on a terminal
only, its ticker ended with the step, on an interrupted step and on
``close``; colors only on a terminal and never under ``NO_COLOR``; the block
of a key to add; the closing; ``status`` and ``logs``. The JSON of the
events and the verdict is not this file's: its tests are unchanged.
"""

import io
import json
import time
from datetime import UTC, datetime
from pathlib import Path

from data_support import blank_box
from history_support import deploy_verdict, sha
from pydantic import SecretStr
from test_verbs_admin import LOGS, _out
from test_verbs_project import _box

from pridem.events import (
    INTERNAL_STACKS,
    Code,
    ConsoleSink,
    KeyNeeded,
    RecipientNeeded,
    Secrets,
    StepFinished,
    StepRecord,
    StepStarted,
)
from pridem.report.catalog import ENGLISH
from pridem.report.render import closing, said_args
from pridem.runner import FakeCall, FakeRunner, Stream
from pridem.steps.base import Step
from pridem.steps.keys import keys_page

TEN = datetime(2026, 11, 16, 10, 0, 0)
SECRET = "s3cr3t-value-that-is-long-enough-0001"  # noqa: S105 -- a test value
CATALOG = {
    **ENGLISH,
    "@title.build": "Build images",
    "@title.preflight": "Check the server",
    "@said.build": "release {release}",
    "@said.preflight": "{os} with {token}",
}


class Terminal(io.StringIO):
    def isatty(self) -> bool:
        return True


def _console(stream: io.StringIO, **extra: object) -> ConsoleSink:
    return ConsoleSink(
        stream,
        Secrets((SecretStr(SECRET),)),
        CATALOG,
        now=lambda: TEN,
        **extra,  # type: ignore[arg-type]
    )


def _started(stack: str, name: str) -> StepStarted:
    return StepStarted("main", stack, name, 1, datetime.now(UTC))


def _finished(
    stack: str, name: str, status: str = "ok", **more: object
) -> StepFinished:
    if status == "ok" and "verify" not in more:
        more["verify"] = {"x": 1}
    record = StepRecord(stack, name, 1, status, duration_s=72.0, **more)  # type: ignore[arg-type]
    return StepFinished("main", record)


def test_a_step_is_its_title_its_time_and_its_fact_in_one_sentence() -> None:
    """Off a terminal: a line when a step begins, its line when it ends --
    the title, the stack only for a product's, the time in the catalog's
    words, the fact by ``said`` with the commit short; a machine stack's step
    by its title alone; a failed step with its reason."""
    out = io.StringIO()
    console = _console(out)
    console.emit(_started("velo", "build"))
    console.emit(_finished("velo", "build", verify={"release": sha("a")}))
    console.emit(
        _finished("pridem-host", "preflight", "failed", reason=Code("interrupted"))
    )
    assert out.getvalue().splitlines() == [
        "[10:00:00] → velo · Build images…",
        f"[10:00:00] ✓ velo · Build images · 1m12s · release {sha('a')[:7]}",
        "[10:00:00] ✗ Check the server · 1m12s — interrupted",
    ]


def test_a_secret_in_a_said_sentence_is_cleaned() -> None:
    """``said`` puts a fact's values in a sentence: they are cleaned first, as
    the journal's (contract 2 rule 2). The pair: the other value is seen."""
    out = io.StringIO()
    _console(out).emit(
        _finished(
            "pridem-host", "preflight", verify={"os": "ubuntu 24.04", "token": SECRET}
        )
    )
    printed = out.getvalue()
    assert SECRET not in printed and "ubuntu 24.04 with [redacted]" in printed


def test_the_live_line_is_a_terminal_s_and_ends_with_its_step() -> None:
    """On a terminal the running step is redrawn by a ticker; the ticker ends
    with the step (ok, and interrupted), and ``close`` ends one left -- no
    redraw after."""
    for status, reason in (("ok", None), ("failed", Code("interrupted"))):
        out = Terminal()
        console = _console(out, tick_s=0.01)
        console.emit(_started("velo", "build"))
        time.sleep(0.05)
        assert "\r\x1b[2K" in out.getvalue() and "Build images" in out.getvalue()
        console.emit(_finished("velo", "build", status, reason=reason))
        assert console._ticker is None
        size = len(out.getvalue())
        time.sleep(0.05)
        assert len(out.getvalue()) == size  # nothing drawn after the step
    out = Terminal()
    console = _console(out, tick_s=0.01)
    console.emit(_started("velo", "build"))
    console.close()
    size = len(out.getvalue())
    time.sleep(0.05)
    assert len(out.getvalue()) == size


def test_off_a_terminal_there_is_no_redraw_and_no_color() -> None:
    out = io.StringIO()
    console = _console(out)
    console.emit(_started("velo", "build"))
    console.emit(_finished("velo", "build"))
    assert "\r" not in out.getvalue() and "\x1b[" not in out.getvalue()
    assert console._ticker is None


def test_colors_on_a_terminal_and_never_under_no_color() -> None:
    painted = Terminal()
    _console(painted, environ={}).emit(_finished("velo", "build"))
    assert "\x1b[32m✓\x1b[0m" in painted.getvalue()
    for environ in ({"NO_COLOR": "1"}, {"TERM": "dumb"}):
        plain = Terminal()
        _console(plain, environ=environ).emit(_finished("velo", "build"))
        assert "\x1b[3" not in plain.getvalue(), environ


def test_a_key_to_add_is_a_block_with_its_page_its_rights_and_the_wait() -> None:
    """The key whole, where it goes, read-only in green words or write with its
    reason, that the box goes on by itself, and how long it waits."""
    out = io.StringIO()
    _console(out).notice(
        KeyNeeded(
            repo="git@github.com:VELO2026-app/velo.git",
            key="ssh-ed25519 AAAA velo",
            page=keys_page("git@github.com:VELO2026-app/velo.git"),
            write=False,
            why=None,
            wait_s=1800,
        )
    )
    printed = out.getvalue()
    assert (
        "Deploy key — add this key to git@github.com:VELO2026-app/velo.git" in printed
    )
    assert "\nssh-ed25519 AAAA velo\n" in printed
    assert "Go to: https://github.com/VELO2026-app/velo/settings/keys" in printed
    assert "READ-ONLY is enough: do NOT tick 'Allow write access'." in printed
    assert (
        "Waiting for access to git@github.com:VELO2026-app/velo.git, up to 30m00s"
        in printed
    )
    out = io.StringIO()
    _console(out).notice(
        KeyNeeded("x", "k", None, True, "the box pushes the generated types", 60)
    )
    assert (
        "IMPORTANT: tick 'Allow write access' — the box pushes the generated types."
        in (out.getvalue())
    )
    assert "Go to:" not in out.getvalue()


def test_the_keys_page_of_a_github_address() -> None:
    for address in (
        "git@github.com:aivis-one/comms.git",
        "ssh://git@github.com/aivis-one/comms.git",
        "https://github.com/aivis-one/comms",
    ):
        assert keys_page(address) == "https://github.com/aivis-one/comms/settings/keys"
    assert keys_page("git@gitlab.com:o/r.git") is None


def test_the_closing_green_and_red() -> None:
    """Green: done in, the versions short with a spaced arrow; red: the failed
    step and its reason, the log and what to run next; arguments as typed."""
    green = deploy_verdict(1, result="green", head=sha("a")).model_copy(
        update={
            "composition_before": {"pridem": "0.1.0", "velo": sha("b")},
            "composition_after": {"pridem": "0.1.0", "velo": sha("c")},
        }
    )
    lines = closing(green, ENGLISH)
    assert lines[2].startswith("deploy main: done in ") and lines[2].endswith(".")
    assert f"Versions: velo {sha('b')[:7]} → {sha('c')[:7]}" in lines
    red = deploy_verdict(2, head=sha("a"))
    lines = closing(red, ENGLISH)
    assert lines[2].startswith("deploy main: failed in ")
    assert " at build — command failed" in lines[2]
    assert lines[-2:] == [
        f"Full log: /opt/pridem/{red.log_ref}",
        f"Next: pridem report {red.run_id}",
    ]
    assert said_args({"confirm": "velo-dev", "all": True, "dry_run": False}) == (
        "--confirm velo-dev --all"
    )


def test_status_says_each_stack_running_or_not() -> None:
    """``status``: each stack of ``current``, its release short, and what
    compose says of it -- read outside the plan, the verdict's JSON as it was."""
    import tempfile

    root = Path(tempfile.mkdtemp())
    blank_box(root)
    listed = json.dumps([{"Name": "blank", "Status": "running(3)"}])
    ls = FakeCall(
        ("docker", "compose", "ls", "--all", "--format", "json"),
        lines=((Stream.STDOUT, listed),),
    )
    with FakeRunner(ls) as runner:
        code, out, _ = _out(root, ["status"], runner)
    assert code == 0
    assert "blank · 0e82be5 · running(3)" in out
    with FakeRunner(FakeCall(ls.argv, lines=((Stream.STDOUT, "[]"),))) as runner:
        _, out, _ = _out(root, ["status"], runner)
    assert "blank · 0e82be5 · not running" in out


def test_logs_merge_the_services_by_time_filter_and_tail_in_all(tmp_path: Path) -> None:
    """Three services' lines, out of order: the stamp is taken off before the
    filter by JSON fields, the lines are put in time order, ``--tail 2`` is
    two in all; a filter nothing matches says so."""
    cs = _box(tmp_path)
    lines = (
        (Stream.STDOUT, '2026-11-16T10:00:03.000000000Z {"level": "error", "n": 3}'),
        (Stream.STDOUT, '2026-11-16T10:00:01.000000000Z {"level": "error", "n": 1}'),
        (Stream.STDOUT, '2026-11-16T10:00:02.000000000Z {"level": "info", "n": 2}'),
        (Stream.STDOUT, '2026-11-16T10:00:04.000000000Z {"level": "error", "n": 4}'),
    )
    argv = tuple(cs.argv(*LOGS, "--tail", "2"))
    with FakeRunner(FakeCall(argv, lines=lines)) as runner:
        code, out, err = _out(
            tmp_path, ["logs", "blank", "level=error", "--tail", "2"], runner
        )
    assert code == 0, err
    assert [json.loads(line)["n"] for line in out.splitlines()] == [3, 4]
    with FakeRunner(FakeCall(tuple(cs.argv(*LOGS)), lines=lines)) as runner:
        _, out, err = _out(tmp_path, ["logs", "blank", "level=fatal"], runner)
    assert out == "" and "logs: no lines match level=fatal" in err


def _steps(base: type) -> list[type]:
    found: list[type] = []
    subs: list[type] = base.__subclasses__()
    for sub in subs:
        found.append(sub)
        found += _steps(sub)
    return found


def test_every_step_of_the_machine_has_a_title() -> None:
    import pridem.verbs  # noqa: F401 -- every verb: every step a plan has

    untitled = sorted(
        getattr(step, "name", step.__name__)
        for step in _steps(Step)
        if step.__module__.startswith("pridem.")
        and not getattr(step, "title", "")
        and isinstance(getattr(step, "name", None), str)
    )
    assert untitled == []
    assert "pridem-host" not in INTERNAL_STACKS  # machine stacks: by their prefix


def test_the_key_step_hands_the_console_its_block(tmp_path: Path) -> None:
    """The ceremony of a key (``deploy_key``): minted, not yet working -- the
    step tells the console the key whole, its page, read-only, and how long
    it waits; the journal keeps its lines as before. The pair: a key that
    works tells the console nothing."""
    from itertools import count

    from plan_support import ListSink
    from test_steps_keys import ADDRESS, PUBLIC, _KeygenRunner, keygen, lsremote

    from pridem.plan import Plan, StackSteps
    from pridem.steps.keys import DeployKey

    def plan(step: DeployKey, calls: list[FakeCall], got: list[object]) -> None:
        ticks = count()
        with _KeygenRunner(*calls) as runner:  # it writes the key files keygen would
            Plan(
                [StackSteps("pridem-sources", [step], root=True)],
                mode="install",
                role="test",
                runner=runner,
                sink=ListSink(),
                clock=lambda: float(next(ticks)),
                notice=got.append,
            ).run()

    got: list[object] = []
    clock = iter([0.0, 1.0, 2.0])
    step = DeployKey(
        ADDRESS, tmp_path, wait_s=100, clock=lambda: next(clock), sleep=lambda s: None
    )
    plan(
        step,
        [
            keygen(tmp_path),
            lsremote(tmp_path, 128),
            lsremote(tmp_path, 0),
            lsremote(tmp_path, 0),
        ],
        got,
    )
    assert got == [
        KeyNeeded(
            repo=ADDRESS,
            key=PUBLIC.strip(),
            page=keys_page(ADDRESS),
            write=False,
            why=None,
            wait_s=100,
        )
    ]
    again: list[object] = []
    plan(
        DeployKey(ADDRESS, tmp_path),
        [lsremote(tmp_path, 0), lsremote(tmp_path, 0)],
        again,
    )
    assert again == []


def test_the_box_s_age_key_is_a_block_once_and_a_sentence_after(tmp_path: Path) -> None:
    """DM-107 FIX: the box's public age key is what the owner adds to its
    passport's recipients (contract 1 section 3). Minted: a block -- the key
    and where it goes; every later run: no block, the key in the step's line
    (``said``), so a person sees it on each run (the probe of tier 3)."""
    from itertools import count

    from plan_support import ListSink
    from test_steps_passport import Recording

    from pridem.events import RecipientNeeded
    from pridem.plan import Plan, StackSteps
    from pridem.steps.passport import AgeKey

    root = tmp_path / "box"

    def once() -> tuple[list[object], str]:
        got: list[object] = []
        out = io.StringIO()
        ticks = count()
        plan = Plan(
            [StackSteps("pridem-passport", [AgeKey(root)], root=True)],
            mode="install",
            role="test",
            runner=Recording(),
            sink=ListSink(),
            clock=lambda: float(next(ticks)),
            notice=got.append,
        )
        console = ConsoleSink(out, Secrets(()), plan.catalog, now=lambda: TEN)
        outcome = plan.run()
        for record in outcome.steps:
            console.emit(StepFinished("main", record))
        return got, out.getvalue()

    got, printed = once()
    [notice] = got
    assert isinstance(notice, RecipientNeeded) and notice.key.startswith("age1")
    assert (notice.path, notice.wait_s) == (None, 0)
    assert f"public key {notice.key}" in printed
    again, printed = once()
    assert again == [] and f"public key {notice.key}" in printed


def test_the_recipient_block_says_where_the_key_goes() -> None:
    out = io.StringIO()
    _console(out).notice(RecipientNeeded("age1abc", "passports/velo-dev.yaml", 1800))
    printed = out.getvalue()
    assert "Passport key of this box — add it to the ops repository" in printed
    assert "\nage1abc\n" in printed
    assert (
        "Add it as a recipient of passports/velo-dev.yaml in the ops repository and "
        "encrypt the passport again (sops with age)."
    ) in printed
    assert (
        "Waiting for passports/velo-dev.yaml to be encrypted for this box, up to 30m00s"
        in printed
    )
    out = io.StringIO()
    _console(out).notice(RecipientNeeded("age1abc", None, 0))
    assert "this box's passport, passports/<server name>.yaml," in out.getvalue()
    assert "Waiting" not in out.getvalue()


def test_the_wait_for_the_passport_s_recipient_is_a_block(tmp_path: Path) -> None:
    """DM-107 FIX: ``fetch_passport`` waits for the owner to encrypt the
    passport for this box -- it tells the console the box's key, the passport's
    file and how long it waits, once; the pair: a box already a recipient
    tells nothing."""
    from itertools import count

    from plan_support import ListSink
    from test_steps_passport import (
        SERVER,
        Ops,
        Recording,
        box_key,
        encrypt,
        mint,
        ops_steps,
        passport,
    )

    from pridem.plan import Plan, StackSteps

    def run(steps: list[object], got: list[object]) -> None:
        ticks = count()
        Plan(
            [StackSteps("pridem-passport", steps, root=True)],  # type: ignore[arg-type]
            mode="install",
            role="test",
            runner=Recording(),
            sink=ListSink(),
            clock=lambda: float(next(ticks)),
            notice=got.append,
        ).run()

    root = tmp_path / "box"
    public = box_key(root)
    owner = mint(tmp_path / "owner.key")
    ops = Ops(tmp_path)
    ops.put(SERVER, encrypt(tmp_path, passport(), owner))

    def owner_adds_the_box(seconds: float) -> None:
        ops.put(SERVER, encrypt(tmp_path, passport(), owner, public))

    _, steps = ops_steps(root, ops, wait_s=100, sleep=owner_adds_the_box)
    got: list[object] = []
    run(list(steps), got)
    waited = [n for n in got if isinstance(n, RecipientNeeded) and n.wait_s]
    assert waited == [
        RecipientNeeded(key=public, path=f"passports/{SERVER}.yaml", wait_s=100)
    ]
    _, steps = ops_steps(root, ops)
    again: list[object] = []
    run(list(steps), again)
    assert [n for n in again if isinstance(n, RecipientNeeded) and n.wait_s] == []
