"""DM-118: what the passport lacks is asked at the terminal -- a secret
without the echo, checked by its schema at once, asked again with the reason
and never the value; the read stops on a counted signal and after its wait;
the live line pauses; ``doctor`` and a run with no terminal ask nobody."""

import ast
import io
import json
import os
import termios
from collections.abc import Callable, Iterator, Mapping
from pathlib import Path

import pytest

from pridem.events import Json
from pridem.interrupt import Interrupt, Interrupted
from pridem.verbs import asker
from pridem.verbs.asker import problem, read_answer, terminal_asker

SECRET: dict[str, Json] = {
    "type": "string",
    "format": "password",
    "writeOnly": True,
    "minLength": 16,
}
PLAIN: dict[str, Json] = {"type": "string", "enum": ["core", "pro"]}
PLANS = Path(__file__).resolve().parent.parent / "pridem" / "verbs" / "plans.py"


class _Pty:
    """A terminal: stdin is a pty's slave, the answer written to its master."""

    def __init__(self, answers: str = "") -> None:
        self.master, slave = os.openpty()
        self.stdin = io.TextIOWrapper(io.FileIO(slave, "r", closefd=True))
        if answers:
            os.write(self.master, answers.encode())

    def close(self) -> None:
        self.stdin.close()
        os.close(self.master)


Tty = Callable[[str], "_Pty"]


@pytest.fixture
def tty() -> Iterator[Tty]:
    made: list[_Pty] = []

    def make(answers: str) -> _Pty:
        made.append(_Pty(answers))
        return made[-1]

    yield make
    for pty in made:
        pty.close()


def _echo_seen(monkeypatch: pytest.MonkeyPatch) -> list[bool]:
    """Every ``tcsetattr``: whether it leaves the echo on."""
    seen: list[bool] = []
    real = termios.tcsetattr

    def record(fd: int, when: int, attrs: list[int | list[bytes | int]]) -> None:
        flags = attrs[3]
        seen.append(isinstance(flags, int) and bool(flags & termios.ECHO))
        real(fd, when, attrs)

    monkeypatch.setattr(termios, "tcsetattr", record)
    return seen


# --- the echo -----------------------------------------------------------------


def test_a_secret_is_read_with_the_echo_off_and_it_comes_back(
    tty: Tty, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Q2 (the main one): the echo goes off for the read of a secret and is
    put back after it. Q3, the pair: a plain field never touches it."""
    seen = _echo_seen(monkeypatch)
    pty = tty("x" * 16 + "\n")
    err = io.StringIO()
    answer = read_answer(
        "Value? ",
        hidden=True,
        interrupt=Interrupt(),
        wait_s=5,
        stdin=pty.stdin,
        stderr=err,
    )
    assert answer == "x" * 16
    assert seen and seen[0] is False and seen[-1] is True
    plain = tty("core\n")
    seen.clear()
    answer = read_answer(
        "Value? ",
        hidden=False,
        interrupt=Interrupt(),
        wait_s=5,
        stdin=plain.stdin,
        stderr=err,
    )
    assert answer == "core" and seen == []


# --- the check at once --------------------------------------------------------


def test_an_answer_the_schema_refuses_is_asked_again_with_the_reason_not_the_value(
    tty: Tty, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Q4: a secret of 6 characters -- the reason, asked again; the second
    answer is taken. Q5: the refused value is nowhere in what is printed."""
    pty = tty("short1\n" + "y" * 20 + "\n")
    err = io.StringIO()
    ask = terminal_asker(Interrupt(), wait_s=5, stdin=pty.stdin, stderr=err)
    assert ask("asked.comms.TELEGRAM_BOT_TOKEN", SECRET) == "y" * 20
    said = err.getvalue()
    assert "asked.comms.TELEGRAM_BOT_TOKEN: must be at least 16 characters" in said
    assert "short1" not in said and "y" * 20 not in said
    assert said.count("Value for asked.comms.TELEGRAM_BOT_TOKEN: ") == 2


def test_the_schema_s_choices_and_form_are_named() -> None:
    assert problem(PLAIN, "core") is None
    assert problem(PLAIN, "max") == "must be one of core, pro"
    assert problem({"pattern": "^[a-z]+$"}, "Abc") == "must match ^[a-z]+$"
    assert problem(SECRET, "z" * 16) is None


def test_an_empty_answer_is_none(tty: Tty) -> None:
    pty = tty("\n")
    ask = terminal_asker(Interrupt(), wait_s=5, stdin=pty.stdin, stderr=io.StringIO())
    assert ask("asked.comms.KEY", SECRET) == ""


# --- a signal, the wait -------------------------------------------------------


def test_a_counted_signal_stops_the_question(tty: Tty) -> None:
    """Q6: the machine's handler only counts a signal (DM-92); the read checks
    it between its waits -- ``Interrupted``, the echo put back."""
    import signal

    interrupt = Interrupt()
    interrupt.receive(signal.SIGINT)  # a signal came while the person thought
    pty = tty("")
    with pytest.raises(Interrupted):
        read_answer(
            "Value? ", hidden=True, interrupt=interrupt, wait_s=5,
            stdin=pty.stdin, stderr=io.StringIO(),
        )  # fmt: skip
    assert termios.tcgetattr(pty.stdin.fileno())[3] & termios.ECHO


def test_no_answer_within_the_wait_is_none(tty: Tty) -> None:
    """Q7: the lock holds every deploy -- after the wait, no answer."""
    pty = tty("")
    answer = read_answer(
        "Value? ", hidden=False, interrupt=Interrupt(), wait_s=0.6,
        stdin=pty.stdin, stderr=io.StringIO(),
    )  # fmt: skip
    assert answer == ""
    assert asker.ANSWER_WAIT_S == 600.0


# --- the live line ------------------------------------------------------------


def test_the_live_line_pauses_while_the_person_answers(
    tty: Tty, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Q8: the question is asked inside ``paused`` -- every console's live
    line stopped before, back after."""
    order: list[str] = []

    class Paused:
        def __enter__(self) -> None:
            order.append("pause")

        def __exit__(self, *rest: object) -> None:
            order.append("resume")

    monkeypatch.setattr(asker, "paused", Paused)
    real = asker.read_answer

    def read(*args: object, **kw: object) -> str:
        order.append("read")
        return real(*args, **kw)  # type: ignore[arg-type]

    monkeypatch.setattr(asker, "read_answer", read)
    pty = tty("core\n")
    ask = terminal_asker(Interrupt(), wait_s=5, stdin=pty.stdin, stderr=io.StringIO())
    assert ask("product.edition", PLAIN) == "core"
    assert order == ["pause", "read", "resume"]


def test_a_console_pauses_and_resumes_its_ticker() -> None:
    from pridem.events import CONSOLES, ConsoleSink, Secrets, paused

    console = ConsoleSink(io.StringIO(), Secrets(()), tty=True, environ={})
    assert console in CONSOLES
    console._live = ("pridem-host · preflight", 0.0)
    console.resume()
    assert console._ticker is not None
    with paused():
        assert console._ticker is None
    assert console._ticker is not None
    console._halt()


# --- who is asked -------------------------------------------------------------


def test_the_plan_hands_the_asker_to_every_step_that_asks() -> None:
    """Q1: ``passport_steps`` and every ``RenderEnv`` of ``deploy_plan`` get
    ``ask=wanted.ask`` -- the wire that was cut."""
    tree = ast.parse(PLANS.read_text(encoding="utf-8"))
    calls = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id in ("RenderEnv", "passport_steps")
    ]
    assert len(calls) == 3
    for call in calls:
        given = {kw.arg: ast.unparse(kw.value) for kw in call.keywords}
        assert given.get("ask") == "wanted.ask", ast.unparse(call)


@pytest.mark.parametrize(
    ("verb", "terminal", "asks"),
    [
        ("install", True, True),
        ("reinstall", True, True),
        ("update", True, True),
        ("rollback", True, True),
        ("doctor", True, False),
        ("install", False, False),
    ],
)
def test_the_terminal_is_asked_but_never_by_doctor_or_without_one(
    tmp_path: Path, verb: str, terminal: bool, asks: bool
) -> None:
    """Q9: ``doctor`` writes nothing and asks nobody; no terminal (the Panel)
    asks nobody either -- the steps then say what to add."""
    from pridem.verbs.base import Context
    from pridem.verbs.deploy import _asker

    ctx = Context(
        root=tmp_path, out=io.StringIO(), err=io.StringIO(), terminal=lambda: terminal
    )
    assert (_asker(ctx, verb) is not None) is asks


def test_an_answer_is_in_no_fact_of_the_verdict(tmp_path: Path) -> None:
    """Q10, the third channel (the journal and the console: the test of
    ``render_env`` in ``test_stacks_env``): the answer is in no fact."""
    from env_support import box, passport_data, render, run, service
    from env_support import product as product_of

    from pridem.events import Secrets
    from pridem.runner import FakeRunner

    answer = "tok-" + "a" * 28
    comms = service(tmp_path, {"TELEGRAM_BOT_TOKEN": {"source": "asked"}})
    made = product_of(tmp_path, {})
    root, fetched = box(tmp_path, passport_data(asked={}))

    def ask(field: str, schema: Mapping[str, Json]) -> str | None:
        return answer

    step = render(comms, root, fetched, product=made, ask=ask, secrets=Secrets(()))
    outcome, sink = run([step], FakeRunner())
    assert outcome.code.value == 0, outcome.steps
    assert answer not in json.dumps([s.verify for s in outcome.steps])
    assert answer not in json.dumps([s.reason for s in outcome.steps], default=str)


def test_without_anyone_to_ask_the_refusal_says_what_to_add() -> None:
    """The Panel: the codes and their fields as before; the text says where."""
    from pridem.report.catalog import ENGLISH, say, with_steps
    from pridem.steps.env import RenderEnv
    from pridem.steps.passport import FetchPassport

    catalog = with_steps(
        ENGLISH,
        [("render_env", RenderEnv.codes), ("fetch_passport", FetchPassport.codes)],
    )
    for step in ("render_env", "fetch_passport"):
        text = say(catalog, f"{step}:missing", fields=["asked.comms.LLM_KEY_SETS"])
        assert "asked.comms.LLM_KEY_SETS" in text
        assert "add them to the passport" in text
