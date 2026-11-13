"""DM-63 FIX: each finding of the review is a test here, red on ``dcbb843``.

``.git`` in a path of ``primer.yaml``, a package or the passport (4.1), a tag
deployed on ``test`` (2.1), every refusal after ``finalize`` left undone
(2.2), a write key in place not waited for (3.1), what git normalizes (2.3), a
branch moved after the push (2.4), the write key's alias among the read keys
(2.5), ``check`` with no command of the product (5.1), the stdout of
``generate`` (6.1), ``types`` on one entry (6.2) and the paths ``generate``
names (9.1).
"""

import shutil
from collections.abc import Mapping, Sequence
from dataclasses import replace
from pathlib import Path

import pytest
from compose_support import REF
from env_support import context
from plan_support import ListSink
from pydantic import ValidationError
from test_steps_keys import ADDRESS, PRIVATE, PUBLIC
from test_steps_keys import run as run_key
from test_steps_types import (
    OPENAPI,
    OUT,
    Container,
    generated,
    git,
    head,
    left,
    repos,
    run,
    step_of,
    types,
)

from pridem.events import Code
from pridem.files import PathOutside, resolve_inside
from pridem.interrupt import Interrupted
from pridem.plan import Plan, StackSteps
from pridem.report.codes import ExitCode
from pridem.runner import (
    CommandTimedOut,
    FakeCall,
    FakeRunner,
    OnLine,
    Result,
    Stream,
)
from pridem.stacks.passport import Package as PassportPackage
from pridem.stacks.schema import PRIMER_YAML, Types, rule_problems
from pridem.steps.compose import _volume_problems
from pridem.steps.git import KEYS, collisions, git_env, repo
from pridem.steps.keys import WriteKey, write_ssh_config
from pridem.steps.types import Types as TypesStep

COMMANDS = {
    "openapi": "dump-openapi",
    "generate": "gen-types --in <openapi> --out=<out>",
    "commit_as": "bot",
}


# --- 4.1: .git in a path ----------------------------------------------------------


@pytest.mark.parametrize("out", [".git", "a/.GIT/b", ".Git/config"])
def test_a_path_through_git_is_refused_by_the_schema(out: str) -> None:
    with pytest.raises(ValidationError) as refused:
        Types.model_validate({**COMMANDS, "out": out})
    assert "S.git-path" in str(refused.value)


@pytest.mark.parametrize("out", [".github/x.ts", ".gitignore", "a/.gitkeep"])
def test_names_that_only_begin_with_git_are_other_names(out: str) -> None:
    assert Types.model_validate({**COMMANDS, "out": out}).out == out
    assert resolve_inside(Path("/r"), out) == Path("/r") / out


def _product_with(patch: Mapping[str, object]) -> dict[str, object]:
    return {
        "schema": 1,
        "name": "blank",
        "kind": "product",
        "stacks": {
            "blank": {
                "compose": "docker-compose.yml",
                "app": {"service": "app", "port": 8000, "health": "/h", "ready": "/r"},
                **patch,
            }
        },
        "env": {},
        "report": {"health": "/h", "ready": "/r", "logs": "json", "junit": True},
    }


def test_every_path_of_primer_yaml_and_the_passport_refuses_git() -> None:
    """Each of the six fields on its own: ``compose``, ``types.out`` (above),
    ``data``, the passport's ``subpath``, a package's ``mount.from`` and
    ``build.path``."""
    with pytest.raises(ValidationError, match="S.git-path"):
        PRIMER_YAML.validate_python(_product_with({"compose": ".git/compose.yml"}))
    data = _product_with({})
    data["dependencies"] = {
        "svc": {"repo": "git@github.com:a/svc.git", "version": ">=1", "data": {
            "profile": "x/.git"}},
    }  # fmt: skip
    with pytest.raises(ValidationError, match="S.git-path"):
        PRIMER_YAML.validate_python(data)
    with pytest.raises(ValidationError, match="S.git-path"):
        PassportPackage.model_validate(
            {"repo": "git@github.com:a/p.git", "version": "1.0.0", "subpath": ".git"}
        )
    for package in (
        {"contract": ">=1",
         "mount": [{"service": "app", "path": "/s", "from": ".git"}]},
        {"contract": ">=1", "apply": "build",
         "build": [{"service": "app", "path": "x/.git"}]},
    ):  # fmt: skip
        made = PRIMER_YAML.validate_python(
            {**_product_with({}), "packages": {"skin": package}}
        )
        codes = [problem.code for problem in rule_problems(made)]
        assert "S.git-path" in codes, (package, codes)


def test_the_second_line_refuses_git_in_the_steps(tmp_path: Path) -> None:
    """``resolve_inside`` (types, packages, the compose file, the ops path),
    ``_within`` (a bind or a context of compose)."""
    with pytest.raises(PathOutside):
        resolve_inside(tmp_path, ".git")
    with pytest.raises(PathOutside):
        resolve_inside(tmp_path, "a/.GIT/hooks")
    release = tmp_path / "release"
    (release / ".git").mkdir(parents=True)
    (release / ".github").mkdir()
    bind = {"type": "bind", "source": str(release / ".git"), "target": "/g"}
    assert _volume_problems(bind, release) == [f"volumes={release / '.git'}"]
    fine = {**bind, "source": str(release / ".github")}
    assert _volume_problems(fine, release) == []


def test_types_out_through_git_past_the_schema_writes_nothing(tmp_path: Path) -> None:
    """The step's own line: ``types.out`` of ``.git`` that came past the schema
    (built with ``model_construct``) -- ``path-outside``, left undone; the
    worktree's ``.git`` is never written, the remote untouched."""
    step, remote, _ = types(tmp_path, "test")
    step.types = Types.model_construct(
        openapi=COMMANDS["openapi"],
        generate=COMMANDS["generate"],
        commit_as=COMMANDS["commit_as"],
        out=".git",
    )
    before = head(remote)
    with Container() as runner:
        outcome = run(step, runner)
    assert left(outcome) == [Code("types:path-outside", {"path": ".git"})]
    assert head(remote) == before


def test_data_through_git_is_unsafe(tmp_path: Path) -> None:
    from test_steps_services import _copy

    step, _, item = _copy(tmp_path)
    (item.base / ".git").mkdir(exist_ok=True)
    step.items = [replace(item, source=item.base / ".git")]
    outcome = Plan(
        [StackSteps("x", [step], root=True)],
        mode="install",
        role="test",
        runner=FakeRunner(),
        sink=ListSink(),
    ).run()
    [record] = outcome.steps
    assert record.reason is not None
    assert record.reason.code == "data_copy:data-unsafe"


# --- 2.1: a tag on test -----------------------------------------------------------


def test_a_deployed_tag_is_no_branch_to_push_to(tmp_path: Path) -> None:
    bare, release, remote, commit = repos(tmp_path)
    git("--git-dir", str(remote), "tag", "v1", commit)
    step = step_of(tmp_path, release, bare, commit, f"file://{remote}", "test")
    step.branch = None
    with Container() as runner:
        outcome = run(step, runner)
    assert left(outcome) == [Code("types:not-a-branch", {"ref": REF})]
    assert git("--git-dir", str(remote), "branch", "--list", "v1") == []


# --- 2.2: every refusal after finalize is left undone -----------------------------


class Breaking(Container):
    """The planted container, with ``dump-openapi`` raising ``error`` or a git
    command (``fails``, by its first words) failing with exit 1."""

    def __init__(
        self,
        error: BaseException | None = None,
        fails: Sequence[str] = (),
    ) -> None:
        super().__init__()
        self.error = error
        self.fails = list(fails)

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
        if self.error is not None and argv[-1:] == ["dump-openapi"]:
            raise self.error
        if (
            self.fails
            and [w for w in argv if not w.startswith("/")][:4]
            == [
                "git",
                *self.fails,
            ][:4]
        ):
            if 1 in expect:
                return Result(tuple(argv), 1)
            from pridem.runner import CommandFailed

            raise CommandFailed(tuple(argv), 1, expect, ())
        return super().run(
            argv, expect=expect, timeout=timeout, cwd=cwd, env=env, on_line=on_line
        )


def test_a_command_that_times_out_is_left_undone(tmp_path: Path) -> None:
    step, _, _ = types(tmp_path, "test")
    with Breaking(error=CommandTimedOut(("docker",), 600.0, ())) as runner:
        outcome = run(step, runner)
    assert left(outcome) == [Code("types:failed", {"error": "CommandTimedOut"})]


def test_a_git_that_fails_and_a_clean_up_that_fails_are_left_undone(
    tmp_path: Path,
) -> None:
    """``git add`` of an ignored ``out`` fails: ``failed``, not red. A
    clean-up of the worktree that fails hides nothing: the push stands."""
    bare, release, remote, commit = repos(tmp_path / "ignored")
    work = tmp_path / "ignored" / "origin"
    (work / ".gitignore").write_text("frontend/src/api/\n")
    git("-C", str(work), "add", ".gitignore")
    git("-C", str(work), "commit", "-q", "-m", "ignore the types")
    git("-C", str(work), "push", "-q", str(bare), f"{REF}:{REF}")
    [commit] = git("-C", str(work), "rev-parse", "HEAD")
    step = step_of(tmp_path / "ignored", release, bare, commit, f"file://{remote}",
                   "test")  # fmt: skip
    with Container() as runner:
        outcome = run(step, runner)
    assert left(outcome) == [Code("types:failed", {"error": "CommandFailed"})]
    step, remote, _ = types(tmp_path / "clean", "test")
    with Breaking(fails=["--git-dir", "worktree", "remove"]) as runner:
        outcome = run(step, runner)
    assert outcome.code is ExitCode.OK, outcome.steps
    assert outcome.steps[0].verify["commit"] == head(remote)


def test_a_read_back_that_fails_is_left_undone(tmp_path: Path) -> None:
    step, remote, _ = types(tmp_path, "test")
    ctx = context(Container())
    check = step.check(ctx)
    step.act(ctx, check)
    shutil.rmtree(remote)  # ls-remote cannot read it any more
    verified = step.verify(ctx, check)
    assert verified.incomplete == Code("failed", {"error": "CommandFailed"})


def test_an_interrupt_goes_through(tmp_path: Path) -> None:
    step, _, _ = types(tmp_path, "test")
    with Breaking(error=Interrupted(15)) as runner:
        outcome = run(step, runner)
    assert outcome.interrupted and outcome.incomplete == ()


def test_a_write_key_that_cannot_be_minted_is_left_undone(tmp_path: Path) -> None:
    keygen = FakeCall(
        (
            "ssh-keygen", "-q", "-t", "ed25519", "-N", "",
            "-C", "pridem pridem-github.com-partner-x-velo-look-write",
            "-f",
            str(tmp_path / KEYS / ".pridem-github.com-partner-x-velo-look-write.tmp"),
        ),
        code=1,
    )  # fmt: skip
    step = WriteKey(ADDRESS, tmp_path, git_dir=tmp_path / "box.git", commit="c" * 40)
    outcome, _ = run_key(tmp_path, step, [keygen])
    assert outcome.code is ExitCode.INCOMPLETE, outcome.steps
    assert [i.reason for i in outcome.incomplete] == [
        Code("write_key:failed", {"error": "CommandFailed"})
    ]


# --- 3.1: a write key in place is not waited for ----------------------------------


def test_a_write_key_in_place_without_access_is_not_waited_for(
    tmp_path: Path,
) -> None:
    """The key is there from an earlier run, write access not given: three
    dry pushes -- check, act, the one look of the wait -- and ``no-access``,
    the clock never moving: no half an hour under the box's lock."""
    write = "pridem-github.com-partner-x-velo-look-write"
    key = tmp_path / KEYS / write
    key.parent.mkdir(parents=True)
    key.write_text(PRIVATE)
    key.with_name(key.name + ".pub").write_text(PUBLIC + "\n")
    key.chmod(0o600)
    write_ssh_config(tmp_path, [repo(ADDRESS, write=True)])
    dry = FakeCall(
        (
            "git", "--git-dir", f"{tmp_path}/box.git", "push", "--dry-run",
            "--porcelain", f"{write}:partner-x/velo-look.git",
            f"{'c' * 40}:refs/pridem/write-check",
        ),
        code=128,
        lines=((Stream.STDERR, "ERROR: read only"),),
        env=git_env(tmp_path),
    )  # fmt: skip
    step = WriteKey(
        ADDRESS,
        tmp_path,
        git_dir=tmp_path / "box.git",
        commit="c" * 40,
        clock=lambda: 0.0,
        sleep=lambda _: None,
    )
    outcome, _ = run_key(tmp_path, step, [dry] * 3)
    assert [i.reason.code for i in outcome.incomplete] == ["write_key:no-access"]


# --- 2.3, 2.4, 2.5 ----------------------------------------------------------------


def test_what_git_normalizes_is_no_commit(tmp_path: Path) -> None:
    """``* text=auto`` and a generator that writes CRLF: the bytes differ, git
    sees nothing to commit -- ``same-in-git``, not ``more-than-types []``."""
    bare, release, remote, _ = repos(tmp_path, old=generated(OPENAPI))
    work = tmp_path / "origin"
    (work / ".gitattributes").write_text("* text=auto\n")
    git("-C", str(work), "add", ".gitattributes")
    git("-C", str(work), "commit", "-q", "-m", "attributes")
    git("-C", str(work), "push", "-q", str(bare), f"{REF}:{REF}")
    [commit] = git("-C", str(work), "rev-parse", "HEAD")

    def crlf(host: Path, words: list[str]) -> int:
        text = generated((host / "openapi.json").read_text())
        (host / "out").write_bytes(text.replace(b"\n", b"\r\n"))
        return 0

    step = step_of(tmp_path, release, bare, commit, f"file://{remote}", "test")
    with Container(generate=crlf) as runner:
        outcome = run(step, runner)
    assert left(outcome) == [Code("types:same-in-git", {"path": OUT})]


def test_a_branch_moved_after_the_push_still_holds_it(tmp_path: Path) -> None:
    """Someone pushed on top of the types commit before ``verify``: it is in
    the branch -- ``committed`` with ``moved_on``. The pair: the branch reset
    without it -- ``not-pushed``."""
    step, remote, deployed = types(tmp_path / "on-top", "test")
    ctx = context(Container())
    check = step.check(ctx)
    step.act(ctx, check)
    other = tmp_path / "on-top" / "other"
    git("clone", "-q", str(remote), str(other))
    (other / "README").write_text("on top\n")
    git("-C", str(other), "commit", "-q", "-am", "on top")
    git("-C", str(other), "push", "-q", "origin", REF)
    fact = step.verify(ctx, check).fact
    assert fact["commit"] == step.pushed and fact["moved_on"] == head(remote)
    step, remote, deployed = types(tmp_path / "reset", "test")
    ctx = context(Container())
    check = step.check(ctx)
    step.act(ctx, check)
    git("--git-dir", str(remote), "update-ref", f"refs/heads/{REF}", deployed)
    assert step.verify(ctx, check).incomplete == Code("not-pushed", {"branch": REF})


def test_the_write_alias_of_a_among_the_read_keys_of_a_write(tmp_path: Path) -> None:
    clash = "pridem-github.com-acme-app-write"
    assert collisions(["git@github.com:acme/app-write.git"]) == []
    assert collisions(
        ["git@github.com:acme/app-write.git"], write=["git@github.com:acme/app.git"]
    ) == [clash]
    step = WriteKey(
        "git@github.com:acme/app.git",
        tmp_path,
        git_dir=tmp_path,
        commit="c" * 40,
        others=["git@github.com:acme/app-write.git"],
    )
    outcome, _ = run_key(tmp_path, step, [])
    assert [i.reason for i in outcome.incomplete] == [
        Code("write_key:alias-clash", {"aliases": [clash]})
    ]


# --- 5.1: check runs nothing of the product --------------------------------------


def test_check_runs_no_command_of_the_product_and_writes_nothing(
    tmp_path: Path,
) -> None:
    """The mark of the deployed commit: nothing to do, no docker at all. No
    mark: ``generate`` -- still no docker, no ``types-run``. ``act`` -- one
    ``openapi`` and one ``generate``; green -- the mark, the deployed commit
    in it."""
    step, _, deployed = types(tmp_path, "test")
    runner = Container()
    check = step.check(context(runner))
    assert check.needed and check.would is not None
    assert check.would.code == "generate" and runner.docker == []
    assert not (tmp_path / "opt" / "blank" / "types-run").exists()
    step.act(context(runner), check)
    assert len(runner.docker) == 2
    step.verify(context(runner), check)
    assert step.mark.read_text() == deployed + "\n"
    again = Container()
    assert not step.check(context(again)).needed and again.docker == []


def test_a_step_left_undone_writes_no_mark(tmp_path: Path) -> None:
    step, _, _ = types(tmp_path, "prod")
    with Container() as runner:
        outcome = run(step, runner, "prod")
    assert left(outcome) == [Code("types:stale", {"path": OUT})]
    assert not step.mark.exists()


# --- 6.1, 6.2, 9.1 ----------------------------------------------------------------


class Loud(Container):
    """``generate`` prints more than the bound to stdout."""

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
        if "gen-types" in argv:
            on_line(Stream.STDOUT, "x" * 200, False)
        return super().run(
            argv, expect=expect, timeout=timeout, cwd=cwd, env=env, on_line=on_line
        )


def test_the_stdout_of_generate_goes_to_the_journal_unbounded(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from pridem.steps import types as module

    monkeypatch.setattr(module, "OPENAPI_LIMIT", 150)  # over the types, under 200
    step, _, _ = types(tmp_path, "test")
    with Loud() as runner:
        outcome = run(step, runner)
    assert outcome.code is ExitCode.OK, outcome.steps


def test_types_on_two_entries_are_refused() -> None:
    data = _product_with({"types": {**COMMANDS, "out": "a.ts"}})
    stacks = data["stacks"]
    assert isinstance(stacks, dict)
    stacks["web"] = {**stacks["blank"], "types": {**COMMANDS, "out": "b.ts"}}
    del stacks["web"]["app"]
    made = PRIMER_YAML.validate_python(data)
    assert "S.types-one" in [problem.code for problem in rule_problems(made)]


@pytest.mark.parametrize("generate", ["gen --in <openapi>", "gen --out <out>", "gen"])
def test_generate_names_both_paths(generate: str) -> None:
    with pytest.raises(ValidationError, match="R23.generate"):
        Types.model_validate({**COMMANDS, "generate": generate, "out": "a.ts"})


def test_a_plan_deploying_a_tag_gives_types_no_branch(tmp_path: Path) -> None:
    """The plan's own wiring (2.1): ``deploy`` of a tag on test -- the product's
    ``fetch_root`` takes the tag -- gives ``types`` no branch. The pair: the
    branch ``main`` is the branch."""
    from services_support import (
        NO_SECRETS,
        TAG,
        deferred,
        passport_file,
        remotes,
        run_stacks,
    )

    from pridem.stacks.passport import load_passport
    from pridem.state import Box
    from pridem.steps.passport import Fetched
    from pridem.verbs.plans import Source, Wanted, deploy_plan
    from pridem.verbs.run import Session

    for ref, branch in ((TAG, None), ("main", "main")):
        tmp = tmp_path / ref
        tmp.mkdir()
        remotes(tmp, None, None, None)
        git("--git-dir", str(tmp / "aivis.git"), "tag", TAG, "main")
        file = passport_file(tmp, "core", None, None)
        root = tmp / "box"
        made = deploy_plan(
            Session(Box(root / "opt" / "pridem"), "r1", Fetched(), NO_SECRETS),
            root,
            Wanted(mode="deploy", source=Source(file=file), ref=ref),
            None,
        )
        assert made.fetched is not None
        made.fetched.passport = load_passport(file)
        for name in ("sources", "dependencies"):
            assert run_stacks(deferred(made, name)).code is ExitCode.OK
        [stack] = deferred(made, "finalize")
        [step] = [s for s in stack.steps if s.name == "types"]
        assert isinstance(step, TypesStep)
        assert step.branch == branch, ref


def test_a_file_the_box_would_not_write_is_left_undone(tmp_path: Path) -> None:
    """``OSError``: the stack's directory is a file -- ``types-run`` cannot be
    made. ``failed``, the class named; not red."""
    step, _, _ = types(tmp_path, "test")
    (tmp_path / "opt").mkdir()
    (tmp_path / "opt" / "blank").write_text("not a directory\n")
    with Container() as runner:
        outcome = run(step, runner)
    assert left(outcome) == [Code("types:failed", {"error": "NotADirectoryError"})]
