"""The marks of the registry of verbs as data (DM-198): their table, literally,
and their form against each verb's own arguments. What the verbs do by them is
the probe (``test_probe_DM_198_registry.py``)."""

import dataclasses
from pathlib import Path
from typing import get_args

import pytest
from data_support import STACK
from test_dm110_confirm import Refusing
from test_probe_DM_198_registry import _a_box, _history, _run

from pridem.runner import FakeRunner
from pridem.verbs import GROUPS, VERBS, Destructive, Group
from pridem.verbs import data as data_verbs
from pridem.verbs import deploy as deploy_verbs
from pridem.verbs.base import Values

NEVER = Destructive()
ALWAYS = Destructive(always=True)

MARKS: dict[str, tuple[str, bool, Destructive, Values]] = {
    # verb: its group, on a box, destructive, the values that write no verdict
    "version": ("server", True, NEVER, ()),
    "status": ("server", True, NEVER, ()),
    "state": ("server", True, NEVER, ()),
    "gc": ("host", True, NEVER, ()),
    "register": ("server", True, NEVER, ()),
    "ssl": ("host", True, NEVER, (("action", ("status",)),)),
    "check": ("deploy", False, NEVER, ()),
    "install": ("deploy", True, NEVER, ()),
    "update": ("deploy", True, NEVER, ()),
    "deploy": ("deploy", True, NEVER, ()),
    "rollback": ("deploy", True, NEVER, ()),
    "doctor": ("server", True, NEVER, ()),
    "reinstall": ("deploy", True, ALWAYS, ()),
    "destroy": ("deploy", True, ALWAYS, ()),
    "report": ("logs", True, NEVER, ()),
    "db": (
        "data",
        True,
        Destructive(when=(("action", ("restore", "reset")),)),
        (("action", ("connect",)),),
    ),
    "backup": ("data", True, NEVER, ()),
    "seed": (
        "data",
        True,
        Destructive(
            when=(("reset", (True,)), ("reset_only", (True,)), ("reset_all", (True,)))
        ),
        (),
    ),
    "verb": ("project", True, Destructive(declared=True), ()),
    "logs": ("logs", True, NEVER, ()),
    "start": ("server", True, NEVER, ()),
    "stop": ("server", True, NEVER, ()),
    "restart": ("server", True, NEVER, ()),
}


def test_the_marks_of_every_verb_literally() -> None:
    """The table of the gate, verb by verb, in the registry's order: 23 verbs,
    each with its group, whether it works on a box, its destructiveness and
    the values of an argument that write no verdict. A verb added to the
    registry is not here until its marks are named."""
    assert len(MARKS) == 23
    assert list(VERBS) == list(MARKS)
    for name, verb in VERBS.items():
        found = (verb.group, verb.on_box, verb.destructive, verb.no_verdict)
        assert found == MARKS[name], name


def test_the_groups_are_six_in_their_order_and_none_is_empty() -> None:
    assert GROUPS == ("server", "deploy", "data", "host", "logs", "project")
    assert set(get_args(Group)) == set(GROUPS)
    assert {verb.group for verb in VERBS.values()} == set(GROUPS)
    by_group = {
        group: [name for name, verb in VERBS.items() if verb.group == group]
        for group in GROUPS
    }
    assert by_group == {
        "server": [
            "version",
            "status",
            "state",
            "register",
            "doctor",
            "start",
            "stop",
            "restart",
        ],
        "deploy": [
            "check",
            "install",
            "update",
            "deploy",
            "rollback",
            "reinstall",
            "destroy",
        ],
        "data": ["db", "backup", "seed"],
        "host": ["gc", "ssl"],
        "logs": ["report", "logs"],
        "project": ["verb"],
    }


def _pairs() -> list[tuple[str, str, str, str | bool]]:
    """Every ``(verb, table, field, value)`` the registry names."""
    found: list[tuple[str, str, str, str | bool]] = []
    for name, verb in VERBS.items():
        for table, values in (
            ("when", verb.destructive.when),
            ("no_verdict", verb.no_verdict),
        ):
            for field, meant in values:
                found += [(name, table, field, value) for value in meant]
    return found


def test_every_value_a_mark_names_is_one_the_verb_s_arguments_take() -> None:
    """Twin SHORTAGE: a field of a mark is an argument of the verb's own model
    that its command line can give -- a positional or an option -- and each
    value is one the model takes for it (a word of its ``Literal``, ``True``
    of a flag). The pair: the pairs are there -- seven of them."""
    pairs = _pairs()
    assert len(pairs) == 7  # db: restore, reset, connect; seed: three; ssl: status
    for name, table, field, value in pairs:
        verb = VERBS[name]
        schema = verb.args.model_json_schema()["properties"]
        assert field in schema, (name, table, field)
        given = {option for option, _ in verb.options.values()}
        assert field in verb.positionals or field in given, (name, table, field)
        if isinstance(value, bool):
            assert schema[field]["type"] == "boolean" and value is True, (name, field)
            kinds = {arg: kind for arg, kind in verb.options.values()}
            assert kinds[field] == "flag", (name, field)
        else:
            assert value in schema[field]["enum"], (name, table, field, value)


def test_no_field_and_no_value_is_named_twice_in_a_mark() -> None:
    """Twin REPEAT: one row a field, one mention a value."""
    for name, verb in VERBS.items():
        for values in (verb.destructive.when, verb.no_verdict):
            fields = [field for field, _ in values]
            assert len(fields) == len(set(fields)), name
            for _, meant in values:
                assert meant and len(meant) == len(set(meant)), name


def test_a_mark_of_no_verdict_is_only_on_a_verb_that_writes_one() -> None:
    """Twin EMPTINESS: a verb with no verdict at all names no value -- there
    is nothing a value could take away; and no value is both destructive and
    without a verdict."""
    for name, verb in VERBS.items():
        if verb.no_verdict:
            assert verb.verdict, name
        silent = {(f, v) for f, vs in verb.no_verdict for v in vs}
        wiping = {(f, v) for f, vs in verb.destructive.when for v in vs}
        assert not silent & wiping, name


def test_confirm_is_an_option_of_exactly_the_verbs_with_a_destructive_mark() -> None:
    """One truth: a verb takes ``--confirm`` when its mark is anything but
    never, and no other verb does."""
    takes = {name for name, verb in VERBS.items() if "--confirm" in verb.options}
    marked = {name for name, verb in VERBS.items() if verb.destructive != NEVER}
    assert takes == marked == {"reinstall", "destroy", "db", "seed", "verb"}


def test_only_check_does_not_work_on_a_box() -> None:
    """``on_box`` is not ``box``: ``state`` takes no lock and reads a box."""
    assert [name for name, verb in VERBS.items() if not verb.on_box] == ["check"]
    assert VERBS["state"].on_box and not VERBS["state"].box


@pytest.mark.parametrize(
    ("verb", "args", "destroys"),
    [
        ("destroy", {}, True),
        ("destroy", {"all": True}, True),
        ("reinstall", {"new_secrets": True}, True),
        ("db", {"action": "restore"}, True),
        ("db", {"action": "reset"}, True),
        ("db", {"action": "dump"}, False),
        ("db", {"action": "migrate"}, False),
        ("db", {"action": "connect"}, False),
        ("db", {}, False),
        ("seed", {"reset": True}, True),
        ("seed", {"reset_only": True}, True),
        ("seed", {"reset_all": True}, True),
        ("seed", {"reset": False, "reset_only": False, "reset_all": False}, False),
        ("seed", {"dry_run": True}, False),
        ("seed", {"reset": 1}, False),  # a flag is True, not a number
        ("seed", {"reset": "True"}, False),
        ("db", {"action": "RESET"}, False),
        ("db", {"action": True}, False),
        ("verb", {"name": "set-setting"}, None),  # the product says
        ("verb", {"name": "set-setting", "confirm": "box-1"}, None),
        ("update", {}, False),
        ("status", {}, False),
    ],
)
def test_destroys_reads_the_mark_and_nothing_else(
    verb: str, args: dict[str, object], destroys: bool | None
) -> None:
    assert VERBS[verb].destroys(args) is destroys


@pytest.mark.parametrize(
    ("verb", "args", "words"),
    [
        ("state", {}, "state"),
        ("version", {}, "version"),
        ("logs", {"stack": "blank"}, "logs"),
        ("report", {"run_id": "r"}, "report"),
        ("ssl", {"action": "status"}, "ssl status"),
        ("ssl", {"action": "renew"}, None),
        ("ssl", {}, None),
        ("ssl", {"action": "STATUS"}, None),
        ("db", {"action": "connect", "stack": "blank"}, "db connect"),
        ("db", {"action": "dump", "stack": "blank"}, None),
        ("db", {"stack": "connect"}, None),  # the value of another field
        ("status", {}, None),
        ("check", {"path": "."}, None),
    ],
)
def test_without_verdict_says_the_run_by_its_words(
    verb: str, args: dict[str, object], words: str | None
) -> None:
    assert VERBS[verb].without_verdict(args) == words
    assert VERBS[verb].writes_verdict(args) is (words is None)


SEED_RESET = ["seed", STACK, "--profile", "demo", "--reset"]


@pytest.mark.parametrize(
    ("module", "constant", "argv"),
    [
        (deploy_verbs, "DESTROY", ["destroy"]),
        (deploy_verbs, "REINSTALL", ["reinstall"]),
        (data_verbs, "DB", ["db", "restore", STACK, "<dump>"]),
        (data_verbs, "DB", ["db", "reset", STACK]),
        (data_verbs, "SEED", SEED_RESET),
        (data_verbs, "SEED", [*SEED_RESET[:-1], "--reset-only"]),
        (data_verbs, "SEED", ["seed", STACK, "--reset-all"]),
        (data_verbs, "VERB", ["verb", "set-setting", "key=k", "value=v"]),
    ],
    ids=lambda value: " ".join(value) if isinstance(value, list) else None,
)
def test_a_verb_asks_the_server_s_name_by_its_mark_and_by_nothing_else(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, module: object, constant: str,
    argv: list[str],
) -> None:  # fmt: skip
    """One truth: the body of a verb decides by the mark of its own entry of
    the registry. With the mark as it is, the run without ``--confirm`` is
    refused and nothing is written; with the mark taken off that entry -- the
    same command line, the same box -- nobody asks for a name, and the run
    goes on to its plan and its verdict. A body that kept a rule of its own
    would refuse both."""
    dump = _a_box(tmp_path)
    argv = [str(dump) if word == "<dump>" else word for word in argv]
    before = _history(tmp_path)
    with FakeRunner() as runner:
        code, _, err = _run(tmp_path, argv, runner)
    assert code == 1 and "confirm" in err and _history(tmp_path) == before, err
    verb = getattr(module, constant)
    unmarked = dataclasses.replace(verb, destructive=Destructive())
    monkeypatch.setattr(module, constant, unmarked)
    monkeypatch.setitem(VERBS, verb.name, unmarked)
    monkeypatch.setitem(deploy_verbs._PLAN_VERBS, "reinstall", deploy_verbs.REINSTALL)
    code, _, err = _run(tmp_path, argv, Refusing())
    assert "confirm" not in err, err
    assert len(_history(tmp_path)) == len(before) + 1, err


@pytest.mark.parametrize(
    ("verb", "argv"), [("ssl", ["ssl", "status"]), ("db", ["db", "connect", STACK])]
)
def test_command_is_refused_by_the_mark_of_the_registry_and_by_nothing_else(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, verb: str, argv: list[str]
) -> None:
    """One truth for ``--command``: with the mark, the refusal before the
    lock; with ``no_verdict`` taken off the verb's entry, no branch of the
    verb's own says "writes no verdict" -- there is none left."""
    _a_box(tmp_path)
    with FakeRunner() as runner:
        code, _, err = _run(tmp_path, ["--command", "c1", *argv], runner)
    assert code == 1 and "writes no verdict" in err, err
    monkeypatch.setitem(VERBS, verb, dataclasses.replace(VERBS[verb], no_verdict=()))
    _, _, err = _run(tmp_path, ["--command", "c1", *argv], Refusing())
    assert "writes no verdict" not in err, err
