"""The probes of DM-163: ``pridem self-update <tag>``.

The box is real under the test's root -- ``versions/``, ``current`` -- and its
commands are answered by ``self_update_support.Releases``: a release's
``install.sh`` with its pins, its tag in the repository, its clone, its wheel,
the venv built from it.
"""

import io
import json
import os
from pathlib import Path

import pytest
from self_update_support import (
    Releases,
    Spoil,
    install_machine,
    releases,
    tree,
)

from pridem.cli import run
from pridem.events import Json
from pridem.state import Box

FROM = "file:///srv/releases/{tag}/install.sh"


def _update(
    fs_root: Path, box: Releases, tag: str, *more: str
) -> tuple[int, dict[str, Json], str]:
    out, err = io.StringIO(), io.StringIO()
    code = run(
        ["--json", "self-update", tag, "--from", FROM.format(tag=tag), *more],
        root=fs_root / "opt" / "pridem",
        out=out,
        err=err,
        runner=box,
        fs_root=fs_root,
    )
    verdict: dict[str, Json] = json.loads(out.getvalue()) if out.getvalue() else {}
    return code, verdict, err.getvalue()


def _reason(verdict: dict[str, Json]) -> Json:
    steps = verdict["steps"]
    assert isinstance(steps, list)
    for step in steps:
        if isinstance(step, dict) and step["status"] == "failed":
            reason = step["reason"]
            assert isinstance(reason, dict)
            return {k: v for k, v in reason.items()}
    return None


@pytest.fixture
def root(tmp_path: Path) -> Path:
    home = tmp_path / "opt" / "pridem"
    install_machine(home, "v0.1.11")
    return home


def test_probe_DM_163_installs_a_release_with_its_pins(
    tmp_path: Path, root: Path
) -> None:
    """``v0.1.11`` -> ``v0.1.12``: built where ``install.sh`` builds, its
    six pins held, ``current`` turned to it; the machine says the new
    version. The old one stays for a rollback."""
    box = Releases(releases("v0.1.11", "v0.1.12"))
    code, verdict, err = _update(tmp_path, box, "v0.1.12")
    assert code == 0, err
    assert verdict["result"] == "green"
    assert tree(root) == ["v0.1.11", "v0.1.12", "current=v0.1.12"]
    pridem = root / "current" / "venv" / "bin" / "pridem"
    assert pridem.read_text() == "version=0.1.12\n"
    box.assert_clean()


@pytest.mark.parametrize(
    ("spoil", "code", "what"),
    [
        (Spoil(install_sh="missing"), "release:not-a-release", None),
        (Spoil(install_sh="no-pin"), "release:not-a-release", None),
        (Spoil(tag="v0.1.13"), "release:pin-differs", "tag"),
        (Spoil(commit="f" * 40), "release:pin-differs", "commit"),
        (Spoil(head="e" * 40), "build:pin-differs", "head"),
        (Spoil(wheel=b"another wheel"), "build:pin-differs", "sha256"),
        (Spoil(version="0.1.99"), "build:pin-differs", "version"),
    ],
    ids=["no release", "no pin", "tag", "commit of the tag", "clone", "wheel",
         "version built"],
)  # fmt: skip
def test_probe_DM_163_refuses_a_tag_or_a_pin_before_the_switch(
    tmp_path: Path, root: Path, spoil: Spoil, code: str, what: str | None
) -> None:
    """Each of the six checks, a defect planted in the release: refused by
    its code, ``current`` the old machine, nothing of the new one left."""
    box = Releases(releases("v0.1.11", "v0.1.12", v0_1_12=spoil))
    exit_code, verdict, _ = _update(tmp_path, box, "v0.1.12")
    assert exit_code == 1 and verdict["result"] == "red"
    reason = _reason(verdict)
    assert isinstance(reason, dict) and reason["code"] == code
    if what is not None:
        assert reason["pin"] == what
    assert tree(root) == ["v0.1.11", "current=v0.1.11"]
    box.assert_clean()


def test_probe_DM_163_the_same_version_is_nothing_to_do(
    tmp_path: Path, root: Path
) -> None:
    """``current`` is ``versions/v0.1.11`` and says it: green, nothing built,
    nothing fetched -- the only command, before and after, asks the machine
    in use its version."""
    box = Releases(releases("v0.1.11"))
    code, verdict, err = _update(tmp_path, box, "v0.1.11")
    assert code == 0, err
    assert verdict["result"] == "green"
    asked = {(str(root / where / "venv" / "bin" / "pridem"), "version")
             for where in ("versions/v0.1.11", "current")}  # fmt: skip
    assert box.calls and set(box.calls) <= asked
    assert tree(root) == ["v0.1.11", "current=v0.1.11"]


def test_probe_DM_163_a_break_leaves_the_old_machine_or_the_new_whole(
    tmp_path: Path, root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Before the point of no return -- the venv's install fails, or the
    switch's own ``rename`` is cut: the old machine whole, the build removed.
    After it -- the new one whole: ``current`` is one ``rename``, never a
    moment with no ``current``."""
    failing = Releases(releases("v0.1.11", "v0.1.12", v0_1_12=Spoil(pip_fails=True)))
    code, _, _ = _update(tmp_path, failing, "v0.1.12")
    assert code == 1 and tree(root) == ["v0.1.11", "current=v0.1.11"]

    def cut(source: object, target: object) -> None:
        raise OSError("cut")

    monkeypatch.setattr(os, "replace", cut)
    box = Releases(releases("v0.1.11", "v0.1.12"))
    code, _, _ = _update(tmp_path, box, "v0.1.12")
    assert code == 1
    assert tree(root) == ["v0.1.11", "current=v0.1.11"]
    assert not (root / "current.next").exists() or (root / "current.next").is_symlink()
    monkeypatch.undo()
    code, _, err = _update(
        tmp_path, Releases(releases("v0.1.11", "v0.1.12")), "v0.1.12"
    )
    assert code == 0, err
    assert tree(root) == ["v0.1.11", "v0.1.12", "current=v0.1.12"]


def test_probe_DM_163_runs_under_the_lock(tmp_path: Path, root: Path) -> None:
    """The box's lock held: refused as every verb is, nothing fetched."""
    box = Releases(releases("v0.1.11", "v0.1.12"))
    held = Box(root)
    with held.lock("update 2026-11-26T10:00:00Z-a3f9 pid 7"):
        out, err = io.StringIO(), io.StringIO()
        code = run(
            ["self-update", "v0.1.12", "--from", FROM.format(tag="v0.1.12")],
            root=root,
            out=out,
            err=err,
            runner=box,
            fs_root=tmp_path,
        )
    assert code == 1 and "busy" in err.getvalue()
    assert box.calls == []
    assert tree(root) == ["v0.1.11", "current=v0.1.11"]
