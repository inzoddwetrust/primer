"""Sources steps (DM-10) on real ``git``: local bare repositories in ``tmp_path``
reached by ``file://``, every git through ``SubprocessRunner``. The colour does
not depend on the machine's git configuration: the fixture's git runs with its
own identity, ``GIT_CONFIG_GLOBAL`` to the null device and no system config,
as the machine's git does.
"""

import os
from datetime import UTC, datetime
from itertools import count
from pathlib import Path

import pytest
import yaml
from contract_support import example
from plan_support import ListSink

from pridem.events import PlanOutcome
from pridem.plan import Plan, StackSteps
from pridem.report.codes import ExitCode
from pridem.runner import Stream, SubprocessRunner
from pridem.stacks.passport import Package
from pridem.steps.base import StepContext
from pridem.steps.git import git_env, run_git
from pridem.steps.sources import source_steps

ENV = {
    "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
    "HOME": "/nonexistent",
    "LANG": "C.UTF-8",
    "GIT_AUTHOR_NAME": "t",
    "GIT_AUTHOR_EMAIL": "t@example.org",
    "GIT_COMMITTER_NAME": "t",
    "GIT_COMMITTER_EMAIL": "t@example.org",
    "GIT_CONFIG_GLOBAL": os.devnull,
    "GIT_CONFIG_NOSYSTEM": "1",
}


def git(cwd: Path, *args: str) -> list[str]:
    out: list[str] = []

    def keep(stream: Stream, line: str, cut: bool) -> None:
        if stream is Stream.STDOUT:
            out.append(line)

    SubprocessRunner().run(
        ["git", "-C", str(cwd), *args], env=ENV, timeout=60, on_line=keep
    )
    return out


def remote(
    tmp: Path, name: str, files: dict[str, str], tags: tuple[str, ...] = ()
) -> Path:
    """A bare ``<name>.git`` with one commit of ``files`` on ``main`` and ``tags``."""
    work = tmp / "work" / name
    work.mkdir(parents=True)
    git(work, "init", "-q", "-b", "main")
    for path, text in files.items():
        (work / path).parent.mkdir(parents=True, exist_ok=True)
        (work / path).write_text(text)
    git(work, "add", "-A")
    git(work, "commit", "-q", "-m", "first")
    for tag in tags:
        git(work, "tag", tag)
    bare = tmp / f"{name}.git"
    git(tmp, "clone", "-q", "--bare", str(work), str(bare))
    return bare


def commit(
    tmp: Path, name: str, files: dict[str, str], tags: tuple[str, ...] = ()
) -> str:
    work = tmp / "work" / name
    for path, text in files.items():
        (work / path).write_text(text)
    git(work, "commit", "-q", "-am", "next")
    for tag in tags:
        git(work, "tag", "-f", tag)
    git(work, "push", "-q", "--force", "--tags", str(tmp / f"{name}.git"), "main")
    return git(work, "rev-parse", "HEAD")[0]


def product(tmp: Path, *, dependency: bool, packages: bool = False) -> str:
    data = example("product.yaml")
    data["dependencies"] = (
        {"comms": {"repo": f"file://{tmp}/comms.git", "version": ">=3.0,<4"}}
        if dependency
        else {}
    )
    data["editions"] = {"core": {"services": ["comms"] if dependency else []}}
    env = data["env"]
    assert isinstance(env, dict)
    data["env"] = {
        k: v
        for k, v in env.items()
        if not (isinstance(v, dict) and v.get("source") == "seam")
        or (dependency and isinstance(v, dict) and v.get("from") == "comms")
    }
    data.pop("provides", None)
    data.pop("replay", None)
    if packages:
        data["packages"] = {
            "skin": {
                "contract": ">=1,<2",
                "validate": "v <dir>",
                "mount": [{"service": "frontend", "path": "/srv/skin"}],
            }
        }
    else:
        data.pop("packages", None)
    return yaml.safe_dump(data, sort_keys=False)


def lock(commit_prefix: str, version: str = "3.0.0") -> str:
    return yaml.safe_dump(
        {
            "schema": 1,
            "resolved_at": datetime(2026, 10, 25, tzinfo=UTC),
            "dependencies": {
                "comms": {
                    "version": version,
                    "tag": f"v{version}",
                    "commit": commit_prefix,
                }
            },
        }
    )


def run(root: Path, steps: list, mode: str = "install") -> PlanOutcome:  # type: ignore[type-arg]
    ticks = count()
    return Plan(
        [StackSteps("sources", steps, root=True)],
        mode=mode,  # type: ignore[arg-type]
        role="test",
        runner=SubprocessRunner(),
        sink=ListSink(),
        clock=lambda: float(next(ticks)),
        now=lambda: datetime(2026, 10, 25, tzinfo=UTC),
    ).run()


def services_lock(
    tmp: Path, *, version: str = "3.0.0", prefix_len: int = 7
) -> tuple[str, str]:
    bare = remote(tmp, "comms", {"primer.yaml": "x: 1\n"}, tags=(f"v{version}",))
    head = git(bare, "rev-parse", f"v{version}^{{commit}}")[0]
    return head, lock(head[:prefix_len], version)


def test_probe_DM_10_lock_outside_range_is_red_before_clone(tmp_path: Path) -> None:
    head, _ = services_lock(tmp_path, version="4.0.0")
    remote(
        tmp_path,
        "aivis",
        {
            "primer.yaml": product(tmp_path, dependency=True),
            "primer.lock": lock(head[:7], "4.0.0"),
        },
    )
    root = tmp_path / "box"
    _, steps = source_steps(
        root,
        stack="aivis",
        address=f"file://{tmp_path}/aivis.git",
        ref="main",
        tag=False,
    )
    outcome = run(root, steps)
    assert outcome.code is ExitCode.FAILED
    by = {r.name: r for r in outcome.steps}
    assert by["check_lock"].reason is not None
    assert by["check_lock"].reason.code == "check_lock:lock-range"
    assert not (root / "opt" / "comms").exists()  # no service cloned
    # the pair: in range -- the service is cloned at its tag
    tmp2 = tmp_path / "pair"
    tmp2.mkdir()
    head, ok_lock = services_lock(tmp2)
    remote(
        tmp2,
        "aivis",
        {"primer.yaml": product(tmp2, dependency=True), "primer.lock": ok_lock},
    )
    root2 = tmp2 / "box"
    _, steps = source_steps(
        root2, stack="aivis", address=f"file://{tmp2}/aivis.git", ref="main", tag=False
    )
    assert run(root2, steps).code is ExitCode.OK
    assert (root2 / "opt" / "comms" / "releases" / "v3.0.0" / "primer.yaml").exists()


def test_lock_commit_is_a_prefix_of_the_tag_commit(tmp_path: Path) -> None:
    head, _ = services_lock(tmp_path)
    remote(
        tmp_path,
        "aivis",
        {
            "primer.yaml": product(tmp_path, dependency=True),
            "primer.lock": lock("deadbee"),
        },
    )
    root = tmp_path / "box"
    _, steps = source_steps(
        root,
        stack="aivis",
        address=f"file://{tmp_path}/aivis.git",
        ref="main",
        tag=False,
    )
    outcome = run(root, steps)
    reason = {r.name: r for r in outcome.steps}["check_lock"].reason
    assert reason is not None and reason.code == "check_lock:lock-commit"


def test_probe_DM_10_dirty_tree_is_discarded_and_recorded(tmp_path: Path) -> None:
    remote(
        tmp_path,
        "aivis",
        {"primer.yaml": product(tmp_path, dependency=False), "app.py": "a\n"},
    )
    root = tmp_path / "box"
    address = f"file://{tmp_path}/aivis.git"
    _, steps = source_steps(root, stack="aivis", address=address, ref="main", tag=False)
    assert run(root, steps).code is ExitCode.OK
    [release] = (root / "opt" / "aivis" / "releases").iterdir()
    (release / "app.py").write_text("changed\n")
    (release / "stray.txt").write_text("x\n")
    _, steps = source_steps(root, stack="aivis", address=address, ref="main", tag=False)
    outcome = run(root, steps)
    fetch = outcome.steps[0]
    assert fetch.status == "ok", fetch.reason
    assert fetch.verify["drift_discarded"] == ["app.py", "stray.txt"]
    assert (release / "app.py").read_text() == "a\n" and not (
        release / "stray.txt"
    ).exists()
    # the pair: a clean release -- no act, nothing discarded
    _, steps = source_steps(root, stack="aivis", address=address, ref="main", tag=False)
    again = run(root, steps).steps[0]
    assert again.verify["drift_discarded"] == []


def test_a_moved_tag_resets_the_release_to_the_target(tmp_path: Path) -> None:
    remote(
        tmp_path,
        "aivis",
        {"primer.yaml": product(tmp_path, dependency=False)},
        tags=("v1.0.0",),
    )
    root = tmp_path / "box"
    address = f"file://{tmp_path}/aivis.git"
    _, steps = source_steps(
        root, stack="aivis", address=address, ref="v1.0.0", tag=True
    )
    assert run(root, steps).code is ExitCode.OK
    moved = commit(
        tmp_path,
        "aivis",
        {"primer.yaml": product(tmp_path, dependency=False) + "# moved\n"},
        ("v1.0.0",),
    )
    _, steps = source_steps(
        root, stack="aivis", address=address, ref="v1.0.0", tag=True
    )
    fetch = run(root, steps).steps[0]
    assert fetch.verify["head"] == moved and "HEAD" in fetch.verify["drift_discarded"]  # type: ignore[operator]


def test_probe_DM_10_config_is_read_from_target_ref_not_worktree(
    tmp_path: Path,
) -> None:
    remote(tmp_path, "aivis", {"primer.yaml": product(tmp_path, dependency=False)})
    root = tmp_path / "box"
    address = f"file://{tmp_path}/aivis.git"
    resolved, steps = source_steps(
        root, stack="aivis", address=address, ref="main", tag=False
    )
    assert run(root, steps).code is ExitCode.OK
    [release] = (root / "opt" / "aivis" / "releases").iterdir()
    (release / "primer.yaml").write_text(
        "schema: 1\nname: worktree-lie\nkind: product\n"
    )
    resolved, steps = source_steps(
        root, stack="aivis", address=address, ref="main", tag=False
    )
    run(root, steps)
    assert resolved.product is not None and resolved.product.name == "aivis"
    # the pair: a new commit's name is read -- from git, the target commit
    text = product(tmp_path, dependency=False).replace(
        "name: aivis", "name: aivis-next"
    )
    commit(tmp_path, "aivis", {"primer.yaml": text})
    resolved, steps = source_steps(
        root, stack="aivis", address=address, ref="main", tag=False
    )
    run(root, steps)
    assert resolved.product is not None and resolved.product.name == "aivis-next"


def test_probe_DM_10_release_dir_is_inert(tmp_path: Path) -> None:
    """Nothing runs from releases/ and current is never touched."""
    remote(tmp_path, "aivis", {"primer.yaml": product(tmp_path, dependency=False)})
    root = tmp_path / "box"
    home = root / "opt" / "aivis"
    home.mkdir(parents=True)
    (home / "current").symlink_to("releases/older")
    _, steps = source_steps(
        root,
        stack="aivis",
        address=f"file://{tmp_path}/aivis.git",
        ref="main",
        tag=False,
    )
    outcome = run(root, steps)
    assert outcome.code is ExitCode.OK
    assert os.readlink(home / "current") == "releases/older"
    assert all(r.name != "up" for r in outcome.steps)
    # the pair: the release itself is there
    assert len(list((home / "releases").iterdir())) == 1


def test_probe_DM_10_missing_ref_is_red_before_act(tmp_path: Path) -> None:
    remote(tmp_path, "aivis", {"primer.yaml": product(tmp_path, dependency=False)})
    root = tmp_path / "box"
    address = f"file://{tmp_path}/aivis.git"
    _, steps = source_steps(
        root, stack="aivis", address=address, ref="v9.9.9", tag=True
    )
    outcome = run(root, steps)
    reason = outcome.steps[0].reason
    assert reason is not None and reason.code == "fetch_root:missing-ref"
    assert not (root / "opt" / "aivis").exists()  # nothing acted
    # the pair: an existing ref is fetched
    _, steps = source_steps(root, stack="aivis", address=address, ref="main", tag=False)
    assert run(root, steps).code is ExitCode.OK


def _package_repo(tmp: Path, contract: str) -> None:
    remote(
        tmp,
        "velo-look",
        {
            "theme/primer-package.yaml": f"schema: 1\ncontract: '{contract}'\n",
            "theme/tokens.json": "{}\n",
        },
        tags=("v1.4.2",),
    )


def test_probe_DM_10_package_is_cloned_by_tag_and_contract_checked(
    tmp_path: Path,
) -> None:
    _package_repo(tmp_path, "2.0")  # outside >=1,<2
    remote(
        tmp_path,
        "aivis",
        {"primer.yaml": product(tmp_path, dependency=False, packages=True)},
    )
    root = tmp_path / "box"
    package = Package(
        repo=f"file://{tmp_path}/velo-look.git", version="1.4.2", subpath="theme"
    )
    _, steps = source_steps(
        root,
        stack="aivis",
        address=f"file://{tmp_path}/aivis.git",
        ref="main",
        tag=False,
        packages={"skin": package},
    )
    outcome = run(root, steps)
    reason = {r.name: r for r in outcome.steps}["fetch_packages"].reason
    assert reason is not None and reason.code == "fetch_packages:contract"
    assert not (root / "opt" / "aivis" / "releases" / "velo-look@1.4.2").exists()
    # the pair: a package in range is cloned at v1.4.2
    tmp2 = tmp_path / "pair"
    tmp2.mkdir()
    _package_repo(tmp2, "1.3")
    remote(
        tmp2, "aivis", {"primer.yaml": product(tmp2, dependency=False, packages=True)}
    )
    root2 = tmp2 / "box"
    package = Package(
        repo=f"file://{tmp2}/velo-look.git", version="1.4.2", subpath="theme"
    )
    _, steps = source_steps(
        root2,
        stack="aivis",
        address=f"file://{tmp2}/aivis.git",
        ref="main",
        tag=False,
        packages={"skin": package},
    )
    outcome = run(root2, steps)
    assert outcome.code is ExitCode.OK, outcome.steps
    fact = {r.name: r for r in outcome.steps}["fetch_packages"].verify
    packages = fact["packages"]
    assert isinstance(packages, list) and len(packages) == 1
    entry = packages[0]
    assert isinstance(entry, dict)
    assert (entry["slot"], entry["contract"]) == ("skin", "1.3")
    assert entry["release"] == "velo-look@1.4.2"
    assert (
        root2
        / "opt"
        / "aivis"
        / "releases"
        / "velo-look@1.4.2"
        / "theme"
        / "tokens.json"
    ).exists()


def test_git_runs_with_its_own_environment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A planted GIT_DIR in the caller's environment never reaches the git."""
    remote(tmp_path, "aivis", {"primer.yaml": product(tmp_path, dependency=False)})
    decoy = tmp_path / "decoy.git"
    git(tmp_path, "init", "-q", "--bare", str(decoy))
    monkeypatch.setenv("GIT_DIR", str(decoy))
    env = git_env(tmp_path)
    assert "GIT_DIR" not in env and env["GIT_TERMINAL_PROMPT"] == "0"
    assert env["GIT_CONFIG_GLOBAL"] == os.devnull and env["GIT_CONFIG_NOSYSTEM"] == "1"
    root = tmp_path / "box"
    _, steps = source_steps(
        root,
        stack="aivis",
        address=f"file://{tmp_path}/aivis.git",
        ref="main",
        tag=False,
    )
    assert run(root, steps).code is ExitCode.OK


def test_git_show_joins_continued_pieces(tmp_path: Path) -> None:
    long = "a" * 70_000
    bare = remote(tmp_path, "big", {"f.txt": long + "\nb\n"})
    lines: list[str] = []
    ctx = StepContext(
        SubprocessRunner(),
        "install",
        "test",
        "big",
        lambda stream, line, cut: lines.append(line),
    )
    _, out = run_git(ctx, tmp_path, ["-C", str(bare), "show", "main:f.txt"])
    assert out == [long, "b"]


def test_primer_package_schema_file_is_the_model_export() -> None:
    from pridem.contract import SCHEMA_DIR
    from pridem.stacks.package import (
        PRIMER_PACKAGE_SCHEMA,
        parse_primer_package,
        rendered_schema,
    )

    on_disk = (SCHEMA_DIR / PRIMER_PACKAGE_SCHEMA).read_text(encoding="utf-8")
    assert on_disk == rendered_schema(), "python -m pridem.stacks.package --export"
    assert parse_primer_package("schema: 1\ncontract: '1.3'\n", "p").contract == "1.3"
    with pytest.raises(Exception, match="primer-package"):
        parse_primer_package(
            "schema: 1\ncontract: 1.3.0\nextra: x\n", "primer-package.yaml"
        )
