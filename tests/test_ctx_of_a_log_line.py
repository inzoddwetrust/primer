"""FIX 3 of DM-55 (protocol 9.4): the ``ctx`` of a stack's log line.

Over ``FREE_LIMIT`` bytes of compact UTF-8 JSON the machine cuts it -- where it
writes a line of a command, one place (``Plan`` hands every whole line to
``events.cut_ctx``) -- and the secrets of the box are cleaned from it as from
the whole line, in the forms a JSON line writes them.
"""

import json
import sys
from pathlib import Path

import pytest
from deadline_support import deadline
from plan_support import NOW, Journal, ScriptedStep
from pydantic import SecretStr
from state_support import header, run_id

from pridem.events import (
    CUT_MARK,
    FREE_LIMIT,
    REDACTED,
    Json,
    Secrets,
    cut_ctx,
    free_size,
)
from pridem.plan import Plan, StackSteps
from pridem.runner import LINE_LIMIT, SubprocessRunner
from pridem.state import Box

BASE = {"ts": "2026-11-03T00:00:00Z", "level": "info", "msg": "job done"}


def _line(ctx: object) -> str:
    return json.dumps({**BASE, "ctx": ctx}, ensure_ascii=False, separators=(",", ":"))


def _ctx_of(size: int) -> dict[str, Json]:
    """A ``ctx`` of exactly ``size`` bytes of compact JSON."""
    frame = free_size({"x": ""})
    found: dict[str, Json] = {"x": "y" * (size - frame)}
    assert free_size(found) == size
    return found


def test_a_ctx_up_to_the_limit_is_kept_and_over_it_is_cut() -> None:
    at = _line(_ctx_of(FREE_LIMIT))
    assert cut_ctx(at) == at
    over = _line(_ctx_of(FREE_LIMIT + 1))
    cut = json.loads(cut_ctx(over))
    assert cut == {**BASE, "ctx": {CUT_MARK: FREE_LIMIT + 1}}


@pytest.mark.parametrize(
    "line",
    [
        "Started server process [1]",
        "",
        json.dumps({**BASE, "detail": "y" * (FREE_LIMIT * 2)}),  # no ctx
        json.dumps(["ctx", "y" * (FREE_LIMIT * 2)]),  # not an object
        "{not json " + "y" * FREE_LIMIT,
        "[" * 100_000 + "]" * 100_000,  # too deep for the parser: passes
    ],
)
def test_a_line_without_a_ctx_to_cut_passes_as_it_came(line: str) -> None:
    assert cut_ctx(line) == line


def test_a_ctx_of_any_kind_over_the_limit_is_cut() -> None:
    """The machine does not read ``ctx``: a string or a list over the limit is
    cut the same way; a leading blank does not hide a line."""
    kinds: list[Json] = ["y" * FREE_LIMIT, ["y" * FREE_LIMIT]]
    for ctx in kinds:
        assert json.loads(cut_ctx("  " + _line(ctx)))["ctx"] == {
            CUT_MARK: free_size(ctx)
        }


@pytest.mark.parametrize(
    "secret",
    [
        'pass"word-0123456789',  # a quote: escaped in any JSON
        "back\\slash-0123456789",  # a backslash
        'пароль"секрет-0123456789',  # non-ASCII and a quote
    ],
)
@pytest.mark.parametrize("ascii", [True, False])
def test_a_secret_in_ctx_is_cleaned_in_the_form_json_writes_it(
    secret: str, ascii: bool
) -> None:
    """A stack writes its line with ``\\uXXXX`` for non-ASCII or without: the
    secret is cleaned in both forms, from ``ctx`` as from the rest. Until FIX 3
    only the value as it is was cleaned -- escaped, it passed."""
    line = json.dumps(
        {**BASE, "msg": secret, "ctx": {"token": secret}}, ensure_ascii=ascii
    )
    assert secret not in line  # the line holds the escaped form only
    cleaned = Secrets([SecretStr(secret)]).text(line)
    escaped = json.dumps(secret, ensure_ascii=ascii)[1:-1]
    assert escaped not in cleaned and cleaned.count(REDACTED) == 2


def _through_the_plan(tmp_path: Path, script: str, secret: str) -> list[str]:
    """The log lines the journal got from one command a step ran."""
    box = Box(tmp_path)
    run = run_id(1)
    with box.lock("a"):
        sink = box.open_journal(header(run), Secrets([SecretStr(secret)]))
        step = ScriptedStep("up", 1, Journal(), act_argv=[sys.executable, "-c", script])
        plan = Plan(
            [StackSteps("aivis", [step], root=True)],
            mode="deploy",
            role="test",
            runner=SubprocessRunner(),
            sink=sink,
            clock=lambda: 0.0,
            now=lambda: NOW,
        )
        with deadline(30.0):
            plan.run()
        sink.close()
    rows = [
        json.loads(line)
        for line in (box.journals / f"{run}.jsonl").read_text().splitlines()
    ]
    return [str(row["line"]) for row in rows if row.get("event") == "log"]


def test_the_plan_cuts_ctx_and_the_journal_cleans_it(tmp_path: Path) -> None:
    """Runner -> plan -> journal: a line with a big ``ctx`` is cut there, a
    small one is kept with its secret cleaned. The pair: what is not cut is
    written as the stack wrote it."""
    planted = 'tok"en-0123456789abcdef'
    big = _line({"secret": planted, "pad": "y" * FREE_LIMIT})
    small = _line({"secret": planted, "job": "7"})
    script = f"import sys\nsys.stdout.write({big!r} + '\\n' + {small!r} + '\\n')\n"
    first, second = _through_the_plan(tmp_path, script, planted)
    assert json.loads(first) == {
        **BASE,
        "ctx": {CUT_MARK: free_size(json.loads(big)["ctx"])},
    }
    assert json.loads(second)["ctx"] == {"secret": REDACTED, "job": "7"}
    assert "tok" not in first + second


def test_the_last_piece_of_a_long_line_is_not_read_as_a_line(tmp_path: Path) -> None:
    """KNOWN CEILING of ``Plan._context``: a line over ``LINE_LIMIT`` arrives in
    pieces and passes as pieces -- its last piece is not a log line of its own,
    even when it reads as JSON with a big ``ctx``."""
    tail = _line({"pad": "y" * FREE_LIMIT})
    line = "." * LINE_LIMIT + tail
    script = f"import sys\nsys.stdout.write({line!r} + '\\n')\n"
    pieces = _through_the_plan(tmp_path, script, "q" * 20)
    assert "".join(pieces) == line  # the tail as the stack wrote it, not cut
