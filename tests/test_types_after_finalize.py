"""DM-63: the write key and the types, after ``finalize``.

The key that writes the types of a ``test`` box is ``DeployKey``'s ceremony on
its own pair and alias (``<alias>-write``), asked by a dry push; both steps
are the root stack's, after ``finalize``, and whatever they are refused is
left undone -- ``incomplete``, never red. Every expected command is literal
(``par0`` 14.2).
"""

from pathlib import Path

from env_support import passport_data  # noqa: F401 -- the box of services_support
from services_support import deferred, planned
from test_steps_keys import ADDRESS, PRIVATE, PUBLIC, run

from pridem.events import Code
from pridem.report.codes import ExitCode
from pridem.runner import FakeCall, Stream
from pridem.steps.git import KEYS, git_env, repo
from pridem.steps.keys import WriteKey, ssh_config_differs, write_ssh_config

COMMIT = "c" * 40
WRITE = "pridem-github.com-partner-x-velo-look-write"


def _dry(root: Path, code: int, *lines: tuple[Stream, str]) -> FakeCall:
    return FakeCall(
        (
            "git", "--git-dir", f"{root}/box.git", "push", "--dry-run",
            "--porcelain", f"{WRITE}:partner-x/velo-look.git",
            f"{COMMIT}:refs/pridem/write-check",
        ),
        code=code,
        lines=lines,
        env=git_env(root),
    )  # fmt: skip


def _write_key_in_place(root: Path) -> None:
    key = root / KEYS / WRITE
    key.parent.mkdir(parents=True, exist_ok=True)
    key.write_text(PRIVATE)
    key.with_name(key.name + ".pub").write_text(PUBLIC + "\n")
    key.chmod(0o600)
    write_ssh_config(root, [repo(ADDRESS, write=True)])
    assert ssh_config_differs(root, [repo(ADDRESS, write=True)]) == []


def _step(root: Path, *ticks: float) -> WriteKey:
    clock = iter(ticks)
    return WriteKey(
        ADDRESS,
        root,
        git_dir=root / "box.git",
        commit=COMMIT,
        wait_s=100,
        clock=lambda: next(clock),
        sleep=lambda _: None,
    )


def test_the_write_key_is_its_own_pair_and_alias(tmp_path: Path) -> None:
    """The read key and the write key of one address: two aliases, two files,
    two blocks of ``ssh_config``; the write key is asked by a dry push of a ref
    of the machine's own, never by a push of the branch."""
    assert repo(ADDRESS).alias == "pridem-github.com-partner-x-velo-look"
    assert repo(ADDRESS, write=True).alias == WRITE
    assert repo(ADDRESS, write=True).url() == f"{WRITE}:partner-x/velo-look.git"
    _write_key_in_place(tmp_path)
    config = (tmp_path / KEYS / "ssh_config").read_text()
    assert f"Host {WRITE}\n" in config
    assert f"  IdentityFile {tmp_path / KEYS / WRITE}\n" in config
    outcome, _ = run(tmp_path, _step(tmp_path, 0.0), [_dry(tmp_path, 0)] * 2)
    assert outcome.code is ExitCode.OK, outcome.steps
    assert outcome.steps[0].verify["alias"] == WRITE


def test_a_write_key_refused_is_left_undone(tmp_path: Path) -> None:
    """The key in place, the dry push refused until the wait ends: ``no-access``,
    left undone -- the release is out and running by then. ssh that reaches
    nothing: ``unreachable`` at once, left undone too."""
    _write_key_in_place(tmp_path)
    refused = _dry(tmp_path, 128, (Stream.STDERR, "ERROR: read only key"))
    outcome, _ = run(tmp_path, _step(tmp_path, 0.0, 101.0), [refused] * 3)
    assert outcome.code is ExitCode.INCOMPLETE, outcome.steps
    [left] = outcome.incomplete
    assert left.what == "write_key"
    assert left.reason.code == "write_key:no-access"
    lost = _dry(tmp_path, 128, (Stream.STDERR, "ssh: connect to host github.com"))
    outcome, _ = run(tmp_path, _step(tmp_path, 0.0), [lost])
    assert outcome.code is ExitCode.INCOMPLETE, outcome.steps
    assert [i.reason for i in outcome.incomplete] == [
        Code("write_key:unreachable", {"repo": ADDRESS})
    ]


def _without_types(data: dict[str, object]) -> None:
    """The product of the fixture without its ``types``, by new dicts: the
    fixture's are shared between tests."""
    stacks = data["stacks"]
    assert isinstance(stacks, dict)
    aivis = {key: value for key, value in stacks["aivis"].items() if key != "types"}
    data["stacks"] = {**stacks, "aivis": aivis}


def test_the_types_go_after_finalize_and_a_test_box_has_a_write_key(
    tmp_path: Path,
) -> None:
    """The root stack: ``final_check``, ``finalize``, then ``write_key`` and
    ``types`` -- a red deploy never reaches them. The pair: a product without
    ``types`` gets no write key."""
    made, _ = planned(tmp_path / "with", "core")  # the fixture declares types
    [root] = deferred(made, "finalize")
    assert [step.name for step in root.steps] == [
        "final_check",
        "finalize",
        "write_key",
        "types",
    ]
    made, _ = planned(tmp_path / "without", "core", product_patch=_without_types)
    [root] = deferred(made, "finalize")
    assert [step.name for step in root.steps] == ["final_check", "finalize", "types"]


def test_types_without_generate_are_refused_by_the_schema() -> None:
    """Contract 3 rule 23: no ``generate``, no ``types`` -- and ``openapi`` is
    a command. The pair: both commands, the section loads."""
    import pytest
    from pydantic import ValidationError

    from pridem.stacks.schema import Types

    whole = {
        "openapi": "python scripts/dump_openapi.py",
        "generate": "python scripts/gen.py <openapi> <out>",
        "out": "frontend/src/api/generated.ts",
        "commit_as": "bot",
    }
    assert Types.model_validate(whole).generate == whole["generate"]
    for missing in ("generate", "openapi"):
        with pytest.raises(ValidationError):
            Types.model_validate({k: v for k, v in whole.items() if k != missing})
