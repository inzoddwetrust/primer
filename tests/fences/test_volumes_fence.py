"""DM-106: the machine's argv keep volumes as they should, by every form.

- every ``docker rm`` carries ``-v``: a removed container takes its
  anonymous volumes (an image's ``VOLUME`` no compose path covers) with it --
  measured: a named volume is never among them;
- no ``down`` carries ``-v`` or ``--volumes``: compose then takes the named
  volumes too -- ``persistent`` among them (measured);
- no ``--renew-anon-volumes`` (``-V``) on ``up``: it leaves the old anonymous
  volume an orphan (measured).

A fence that cannot fail is no fence (par0 §9): every rule has its planted
case, and the clean forms beside them pass.
"""

import ast
from pathlib import Path

import pytest

PRIDEM = Path(__file__).resolve().parent.parent.parent / "pridem"


def _words(node: ast.AST) -> list[str] | None:
    """The string words of a list or tuple literal; ``None`` when it is none."""
    if not isinstance(node, (ast.List, ast.Tuple)):
        return None
    return [
        e.value
        for e in node.elts
        if isinstance(e, ast.Constant) and isinstance(e.value, str)
    ]


def _call_words(node: ast.Call) -> list[str]:
    return [
        a.value
        for a in node.args
        if isinstance(a, ast.Constant) and isinstance(a.value, str)
    ]


def hits(source: str) -> list[str]:
    """What breaks the rules in ``source``."""
    found: list[str] = []
    for node in ast.walk(ast.parse(source)):
        line = getattr(node, "lineno", 0)
        words = _words(node)
        if words is not None and words[:2] == ["docker", "rm"] and "-v" not in words:
            found.append(f"{line}: docker rm without -v")
        if isinstance(node, ast.Call):
            words = _call_words(node)
        if words is None:
            continue
        if "down" in words and ("-v" in words or "--volumes" in words):
            found.append(f"{line}: down with its volumes")
        if "--renew-anon-volumes" in words or ("up" in words and "-V" in words):
            found.append(f"{line}: up renewing anonymous volumes")
    return found


def test_the_machine_keeps_volumes_as_measured() -> None:
    """Every module of ``pridem/``: no hit. The pair: ``docker rm`` is there
    (``destroy``, ``egress``) and every one carries ``-v``."""
    found = {
        str(path.relative_to(PRIDEM)): hits(path.read_text(encoding="utf-8"))
        for path in sorted(PRIDEM.rglob("*.py"))
    }
    assert {k: v for k, v in found.items() if v} == {}
    removing = [
        path.name
        for path in PRIDEM.rglob("*.py")
        if '"docker", "rm", "-f", "-v"' in path.read_text(encoding="utf-8")
    ]
    assert sorted(removing) == ["destroy.py", "egress.py"]


@pytest.mark.parametrize(
    ("planted", "said"),
    [
        ('out(ctx, ["docker", "rm", "-f", *ids])', "docker rm without -v"),
        ('out(ctx, ("docker", "rm", "c1"))', "docker rm without -v"),
        ('out(ctx, argv(root, "down", "-v"))', "down with its volumes"),
        ('out(ctx, argv(root, "down", "--volumes"))', "down with its volumes"),
        ('out(ctx, compose.argv("down", "-v"))', "down with its volumes"),
        (
            'out(ctx, ["docker", "compose", "down", "--volumes"])',
            "down with its volumes",
        ),
        ('out(ctx, argv(root, "up", "-d", "--renew-anon-volumes"))', "up renewing"),
        ('out(ctx, argv(root, "up", "-d", "-V"))', "up renewing"),
    ],
)
def test_selftest_a_planted_form_is_caught(planted: str, said: str) -> None:
    found = hits(planted)
    assert found and said in found[0], (planted, found)


@pytest.mark.parametrize(
    "clean",
    [
        'out(ctx, ["docker", "rm", "-f", "-v", *ids])',
        'out(ctx, argv(root, "rm", "-s", "-f", "-v"))',
        'out(ctx, argv(root, "down"))',
        'out(ctx, ["docker", "volume", "rm", *gone])',
        'out(ctx, ["docker", "image", "rm", "-f", *images])',
        'out(ctx, ["docker", "network", "rm", *networks])',
        'out(ctx, argv(root, "up", "-d", "--force-recreate", "proxy"))',
    ],
)
def test_selftest_a_clean_form_passes(clean: str) -> None:
    """The rule's border: ``volume``, ``image``, ``network rm`` are not
    ``docker rm``; ``compose rm -v`` and a plain ``down`` keep named volumes."""
    assert hits(clean) == []
