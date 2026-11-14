"""``types`` (DM-19, DM-63) on real git over ``file://``: the OpenAPI document and
the types made by the product's commands in a throwaway container of the
release's app, planted here (``Container``); one commit of one path on top of
the deployed commit on ``test``, a check elsewhere; after ``finalize``, every
refusal left undone (``incomplete``)."""

import os
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path

import pytest
from compose_support import ENTRY, REF
from env_support import context
from plan_support import ListSink

from pridem.events import Code, PlanOutcome
from pridem.plan import Plan, StackSteps
from pridem.report.codes import ExitCode
from pridem.runner import (
    FakeCall,
    FakeRunner,
    OnLine,
    Result,
    Stream,
    SubprocessRunner,
)
from pridem.stacks.schema import PRIMER_YAML, Product
from pridem.steps import types as types_module
from pridem.steps.base import Role, StepFailed
from pridem.steps.types import Types

OUT = "frontend/src/api/generated.ts"
OPENAPI = '{"openapi": "3.1.0", "paths": {}}'
RUN_ID = "2026-11-01T00:00:00Z-ab12"
GIT_ENV = {
    "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
    "HOME": "/nonexistent",
    "GIT_AUTHOR_NAME": "t",
    "GIT_AUTHOR_EMAIL": "t@example.org",
    "GIT_COMMITTER_NAME": "t",
    "GIT_COMMITTER_EMAIL": "t@example.org",
    "GIT_CONFIG_GLOBAL": os.devnull,
    "GIT_CONFIG_NOSYSTEM": "1",
}
TASKS = "--format=%(trailers:key=Task,valueonly,separator=%x2C)"
"""What ``stand`` (DM-24) reads of a commit, literally."""


def generated(document: str) -> bytes:
    """What the planted ``generate`` writes for ``document``."""
    return b"// generated from the app's OpenAPI\n" + document.encode() + b"\n"


def git(*args: str) -> list[str]:
    out: list[str] = []

    def keep(stream: Stream, line: str, cut: bool) -> None:
        if stream is Stream.STDOUT:
            out.append(line)

    SubprocessRunner().run(["git", *args], env=GIT_ENV, timeout=60, on_line=keep)
    return out


Generate = Callable[[Path, list[str]], int]
"""The planted ``generate``: the host directory mounted at ``/primer/types``
and the command's words -> its exit code."""


def writes(host: Path, words: list[str]) -> int:
    assert words == [
        "gen-types",
        "--in",
        "/primer/types/openapi.json",
        "--out=/primer/types/out",
    ], words
    document = (host / "openapi.json").read_text()
    (host / "out").write_bytes(generated(document))
    return 0


class Container(FakeRunner):
    """git runs for real; ``docker compose ... run`` of the app is the planted
    container: ``dump-openapi`` prints ``printed`` (exit ``code``), the other
    command runs ``generate`` on the mounted directory. Every docker argv is
    kept, literally."""

    def __init__(
        self,
        *calls: FakeCall,
        printed: Sequence[str] = (OPENAPI,),
        code: int = 0,
        generate: Generate = writes,
    ) -> None:
        super().__init__(*calls)
        self.printed = list(printed)
        self.code = code
        self.generate = generate
        self.docker: list[list[str]] = []

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
        if argv[0] == "git":
            return SubprocessRunner().run(
                argv, expect=expect, timeout=timeout, cwd=cwd, env=env, on_line=on_line
            )
        if "run" not in argv:
            return super().run(
                argv, expect=expect, timeout=timeout, cwd=cwd, env=env, on_line=on_line
            )
        self.docker.append(list(argv))
        words = list(argv[argv.index("app") + 1 :])
        if words == ["dump-openapi"]:
            for line in self.printed:
                on_line(Stream.STDOUT, line, False)
            return Result(tuple(argv), self.code)
        host, _, inside = argv[argv.index("-v") + 1].partition(":")
        assert inside == "/primer/types"
        return Result(tuple(argv), self.generate(Path(host), words))


def product() -> Product:
    made = PRIMER_YAML.validate_python(
        {
            "schema": 1,
            "name": "blank",
            "kind": "product",
            "stacks": {
                "blank": {
                    "compose": "docker-compose.yml",
                    "app": {
                        "service": "app",
                        "port": 8000,
                        "health": "/health",
                        "ready": "/ready",
                    },
                    "types": {
                        "openapi": "dump-openapi",
                        "generate": "gen-types --in <openapi> --out=<out>",
                        "out": OUT,
                        "commit_as": "blank-bot",
                    },
                }
            },
            "env": {},
            "report": {
                "health": "/health",
                "ready": "/ready",
                "logs": "json",
                "junit": True,
            },
        }
    )
    assert isinstance(made, Product)
    return made


def repos(
    tmp: Path, old: bytes = b"// old\n", message: str = "init"
) -> tuple[Path, Path, Path, str]:
    """The box's bare, the release worktree, the push address, the deployed
    commit -- whose message is ``message``."""
    work = tmp / "origin"
    (work / OUT).parent.mkdir(parents=True)
    (work / OUT).write_bytes(old)
    (work / "README").write_text("blank\n")
    git("-C", str(work), "init", "-q", "-b", REF)
    git("-C", str(work), "add", "-A")
    git("-C", str(work), "commit", "-q", "-m", message)
    remote = tmp / "remote.git"
    git("clone", "-q", "--bare", str(work), str(remote))
    bare = tmp / "box.git"
    git("clone", "-q", "--bare", str(remote), str(bare))
    release = tmp / "release"
    git("clone", "-q", str(remote), str(release))
    [commit] = git("-C", str(release), "rev-parse", "HEAD")
    return bare, release, remote, commit


def step_of(
    tmp: Path, release: Path, bare: Path, commit: str, push_to: str, role: Role
) -> Types:
    return Types(
        product(),
        ENTRY,
        release=release,
        ref=REF,
        commit=commit,
        role=role,
        branch=REF,
        run_id=RUN_ID,
        push_to=push_to,
        git_dir=bare,
        root=tmp,
        env=GIT_ENV,
    )


def types(
    tmp: Path, role: Role, *, old: bytes = b"// old\n", message: str = "init"
) -> tuple[Types, Path, str]:
    bare, release, remote, commit = repos(tmp, old, message)
    return step_of(tmp, release, bare, commit, f"file://{remote}", role), remote, commit


def run(step: Types, runner: FakeRunner, role: Role = "test") -> PlanOutcome:
    return Plan(
        [StackSteps("finalize", [step], root=True)],
        mode="install",
        role=role,
        runner=runner,
        sink=ListSink(),
    ).run()


def head(remote: Path) -> str:
    [found] = git("--git-dir", str(remote), "rev-parse", REF)
    return found


def left(outcome: PlanOutcome) -> list[Code]:
    assert outcome.code is ExitCode.INCOMPLETE, outcome.steps
    return [item.reason for item in outcome.incomplete]


# --- probes ---------------------------------------------------------------------


def test_probe_DM_63_types_are_made_by_the_products_command(tmp_path: Path) -> None:
    """The API of the release gives other types than its file: the product's
    ``openapi`` prints the document, its ``generate`` writes the types -- both
    in a throwaway container of the app on the deploy's files -- and one commit
    of ``out`` lands on top of the deployed commit, by the product's bot, with
    the deployed commit's ``Task`` and the machine's trailer. The pair: types
    that did not change -- no commit."""
    root = tmp_path / "changed"
    step, remote, deployed = types(root, "test", message="Add the API\n\nTask: DM-5")
    with Container() as runner:
        outcome = run(step, runner)
    assert outcome.code is ExitCode.OK, outcome.steps
    after = head(remote)
    assert outcome.steps[0].verify["commit"] == after
    assert git("--git-dir", str(remote), "rev-parse", f"{after}^") == [deployed]
    changed = git("--git-dir", str(remote), "show", "--name-only", "--format=", after)
    assert [line for line in changed if line] == [OUT]
    assert git("--git-dir", str(remote), "show", f"{after}:{OUT}") == (
        generated(OPENAPI).decode().splitlines()
    )
    assert git("--git-dir", str(remote), "log", "-1", "--format=%B", after) == [
        f"Regenerate {OUT}",
        "",
        "Task: DM-5",
        f"Primer-Machine: types {RUN_ID}",
        "",
    ]
    assert git("--git-dir", str(remote), "log", "-1", TASKS, after) == ["DM-5"]
    project = [
        "docker", "compose", "-p", "blank",
        "--env-file", f"{root}/opt/blank/env/next.env",
        "-f", f"{root}/release/docker-compose.yml",
        "-f", f"{root}/opt/blank/compose/blank.next.yml",
    ]  # fmt: skip
    host = f"{root}/opt/blank/types-run"
    assert runner.docker[:2] == [
        [*project, "run", "--rm", "--no-deps", "-T", "--", "app", "dump-openapi"],
        [
            *project, "run", "--rm", "--no-deps", "-T", "-v", f"{host}:/primer/types",
            "--", "app", "gen-types", "--in", "/primer/types/openapi.json",
            "--out=/primer/types/out",
        ],
    ]  # fmt: skip
    assert not Path(host).exists()

    # the pair: the same types -- nothing committed
    step, remote, deployed = types(tmp_path / "same", "test", old=generated(OPENAPI))
    with Container() as runner:
        outcome = run(step, runner)
    assert outcome.code is ExitCode.OK, outcome.steps
    assert outcome.steps[0].verify == {"types": "current", "path": OUT}
    assert head(remote) == deployed


def test_probe_DM_19_types_commit_only_on_test_and_only_types_out(
    tmp_path: Path,
) -> None:
    """Changed by DM-63, by the dispatcher's word before the change: the
    document is the product's ``openapi`` command and the types its
    ``generate`` (the owner's decision of 05.11), not HTTP and a
    ``Generator``; on prod a stale file is ``incomplete`` -- the step runs
    after ``finalize`` -- not red."""
    step, remote, _ = types(tmp_path, "test")
    before = head(remote)
    with Container() as runner:
        outcome = run(step, runner)
    assert outcome.code is ExitCode.OK, outcome.steps
    after = head(remote)
    assert after != before and outcome.steps[0].verify["commit"] == after
    changed = git("--git-dir", str(remote), "show", "--name-only", "--format=", after)
    assert [line for line in changed if line] == [OUT]  # exactly one path
    [author] = git("--git-dir", str(remote), "log", "-1", "--format=%an", after)
    assert author == "blank-bot"
    # the pair: on prod nothing is committed, a stale file is left undone
    step, remote, _ = types(tmp_path / "prod", "prod")
    before = head(remote)
    with Container() as runner:
        outcome = run(step, runner, "prod")
    assert left(outcome) == [Code("types:stale", {"path": OUT})]
    assert head(remote) == before


# --- the rest -------------------------------------------------------------------


def test_every_task_of_the_deployed_commit_and_none_more_is_carried(
    tmp_path: Path,
) -> None:
    """No ``Task`` on the deployed commit: none on the types commit -- the set
    ``stand`` reads is empty for both; two of them: both, one line each, in
    the one paragraph of trailers."""
    step, remote, _ = types(tmp_path / "none", "test")
    with Container() as runner:
        run(step, runner)
    assert git("--git-dir", str(remote), "log", "-1", TASKS, REF) == [""]
    step, remote, _ = types(
        tmp_path / "two", "test", message="Two\n\nTask: DM-5\nTask: DM-7"
    )
    with Container() as runner:
        run(step, runner)
    assert git("--git-dir", str(remote), "log", "-1", TASKS, REF) == ["DM-5,DM-7"]


def test_a_branch_moved_meanwhile_is_left_undone_never_forced(
    tmp_path: Path,
) -> None:
    """The remote's branch moved after the deployed commit: the types commit,
    made on the deployed one, is no fast-forward -- ``behind``, left undone;
    the remote keeps what it had."""
    step, remote, deployed = types(tmp_path, "test")
    work = tmp_path / "origin"
    (work / "README").write_text("moved\n")
    git("-C", str(work), "commit", "-q", "-am", "moved on")
    git("-C", str(work), "push", "-q", str(remote), f"{REF}:{REF}")
    moved = head(remote)
    with Container() as runner:
        outcome = run(step, runner)
    assert left(outcome) == [Code("types:behind", {"branch": REF})]
    assert head(remote) == moved != deployed


def test_the_types_commit_is_made_on_the_deployed_commit_not_the_branch(
    tmp_path: Path,
) -> None:
    """The box's bare repository already has a newer commit of the branch than
    the deployed one: the types commit's parent is the deployed commit."""
    bare, release, remote, deployed = repos(tmp_path)
    work = tmp_path / "origin"
    (work / "README").write_text("newer\n")
    git("-C", str(work), "commit", "-q", "-am", "newer")
    git("-C", str(work), "push", "-q", str(bare), f"{REF}:{REF}")
    step = step_of(tmp_path, release, bare, deployed, f"file://{remote}", "test")
    with Container() as runner:
        outcome = run(step, runner)
    assert outcome.code is ExitCode.OK, outcome.steps
    assert git("--git-dir", str(remote), "rev-parse", f"{REF}^") == [deployed]


@pytest.mark.parametrize(
    ("printed", "code", "refused"),
    [
        ((OPENAPI,), 3, Code("types:openapi-failed", {"exit": 3})),
        (("not json",), 0, Code("types:openapi-not-json")),
        (("[1, 2]",), 0, Code("types:openapi-not-json")),
        ((), 0, Code("types:openapi-not-json")),
    ],
    ids=["red", "not-json", "not-an-object", "empty"],
)
def test_an_openapi_command_that_gives_no_document_is_left_undone(
    tmp_path: Path, printed: tuple[str, ...], code: int, refused: Code
) -> None:
    step, remote, _ = types(tmp_path, "test")
    before = head(remote)
    with Container(printed=printed, code=code) as runner:
        outcome = run(step, runner)
    assert left(outcome) == [refused]
    assert head(remote) == before


def test_a_document_over_the_bound_is_not_read_whole(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(types_module, "OPENAPI_LIMIT", len(OPENAPI) - 1)
    step, _, _ = types(tmp_path, "test")
    with Container() as runner:
        outcome = run(step, runner)
    assert left(outcome) == [Code("types:openapi-too-big", {"limit": len(OPENAPI) - 1})]


def _red(host: Path, words: list[str]) -> int:
    return 2


def _nothing(host: Path, words: list[str]) -> int:
    return 0


def _link(host: Path, words: list[str]) -> int:
    (host / "out").symlink_to("/etc/passwd")
    return 0


@pytest.mark.parametrize(
    ("generate", "refused"),
    [
        (_red, Code("types:generate-failed", {"exit": 2})),
        (_nothing, None),
        (_link, Code("types:generate-unsafe", {"cause": "symlink"})),
    ],
    ids=["red", "wrote-nothing", "symlink"],
)
def test_a_generate_command_that_gives_no_types_is_left_undone(
    tmp_path: Path, generate: Generate, refused: Code | None
) -> None:
    step, remote, _ = types(tmp_path, "test")
    before = head(remote)
    with Container(generate=generate) as runner:
        outcome = run(step, runner)
    host = tmp_path / "opt" / "blank" / "types-run"
    expected = refused or Code("types:generate-missing", {"path": f"{host}/out"})
    assert left(outcome) == [expected]
    assert head(remote) == before and not host.exists()


def test_types_out_through_a_symlink_of_the_product_is_refused(
    tmp_path: Path,
) -> None:
    """DM-78: the deployed commit makes ``frontend/src`` a symlink out of the
    tree -- root's write of ``out`` would land there. ``types:path-outside``,
    left undone, and the place outside is untouched. The pair: the probe."""
    bare, release, remote, _ = repos(tmp_path)
    outside = tmp_path / "outside"
    outside.mkdir()
    work = tmp_path / "origin"
    git("-C", str(work), "rm", "-q", "-r", "frontend/src")
    (work / "frontend").mkdir(exist_ok=True)
    (work / "frontend" / "src").symlink_to(outside, target_is_directory=True)
    git("-C", str(work), "add", "-A")
    git("-C", str(work), "commit", "-q", "-m", "a symlinked src")
    git("-C", str(work), "push", "-q", str(bare), f"{REF}:{REF}")
    [commit] = git("-C", str(work), "rev-parse", "HEAD")
    step = step_of(tmp_path, release, bare, commit, f"file://{remote}", "test")
    with Container() as runner:
        outcome = run(step, runner)
    assert left(outcome) == [Code("types:path-outside", {"path": OUT})]
    assert list(outside.iterdir()) == []


REJECTED = ((Stream.STDOUT, f"!\tHEAD:refs/heads/{REF}\t[rejected] (fetch first)"),)
SSH = (
    (Stream.STDERR, "ssh: connect to host github.com port 22: Connection refused"),
    (Stream.STDERR, "fatal: Could not read from remote repository."),
)
READ_ONLY = (
    (Stream.STDERR, "ERROR: The key you are authenticating with is read only."),
    (Stream.STDERR, "fatal: Could not read from remote repository."),
)


@pytest.mark.parametrize(
    ("code", "lines", "refused"),
    [
        (1, REJECTED, Code("behind", {"branch": REF})),
        (128, SSH, Code("unreachable", {"repo": "git@github.com:acme/blank.git"})),
        (
            128,
            READ_ONLY,
            Code("write-refused", {"repo": "git@github.com:acme/blank.git"}),
        ),
    ],
    ids=["rejected", "ssh", "refused"],
)
def test_a_refused_push_says_why(
    tmp_path: Path,
    code: int,
    lines: tuple[tuple[Stream, str], ...],
    refused: Code,
) -> None:
    """The push goes through the write key's alias, ``--porcelain``, never
    ``--force`` (the argv is literal): a rejected ref is ``behind``, ssh's own
    failure ``unreachable``, any other refusal ``write-refused``."""
    step = step_of(
        tmp_path, tmp_path, tmp_path, "c" * 40, "git@github.com:acme/blank.git", "test"
    )
    push = (
        "git", "-C", "/w", "push", "--porcelain",
        "pridem-github.com-acme-blank-write:acme/blank.git",
        f"HEAD:refs/heads/{REF}",
    )  # fmt: skip
    with FakeRunner(FakeCall(push, code=code, lines=lines, env=GIT_ENV)) as runner:
        with pytest.raises(StepFailed) as error:
            step._push(context(runner), ["-C", "/w"], REF)
    assert error.value.reason == refused
