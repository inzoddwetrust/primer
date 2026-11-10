"""``types`` (DM-19) on real git over ``file://``: one commit of one path to the
box's branch on ``test``, a red check elsewhere, a red step without a
generator. The app's OpenAPI is served by a real local HTTP server."""

import json
import os
import threading
from collections.abc import Iterator, Mapping, Sequence
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest
from compose_support import ENTRY, REF, stdout
from plan_support import ListSink

from pridem.events import Code, PlanOutcome
from pridem.plan import Plan, StackSteps
from pridem.report.codes import ExitCode
from pridem.runner import FakeCall, FakeRunner, OnLine, Result, SubprocessRunner
from pridem.stacks.schema import PRIMER_YAML, Product
from pridem.steps.base import Role
from pridem.steps.compose import ComposeStack
from pridem.steps.types import Types

OUT = "frontend/src/api/generated.ts"
OPENAPI = b'{"openapi": "3.1.0", "paths": {}}'
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


def generate(document: bytes) -> bytes:
    return b"// generated from the app's OpenAPI\n" + document + b"\n"


@pytest.fixture
def openapi() -> Iterator[int]:
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802 -- the stdlib's name
            self.send_response(200 if self.path == "/openapi.json" else 404)
            self.end_headers()
            if self.path == "/openapi.json":
                self.wfile.write(OPENAPI)

        def log_message(self, format: str, *args: object) -> None:
            return

    server = HTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        yield server.server_address[1]
    finally:
        server.shutdown()
        server.server_close()


def git(*args: str) -> list[str]:
    out: list[str] = []
    SubprocessRunner().run(
        ["git", *args],
        env=GIT_ENV,
        timeout=60,
        on_line=lambda stream, line, cut: out.append(line),
    )
    return out


class RealGit(FakeRunner):
    """git runs for real; docker follows the script."""

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
        return super().run(
            argv, expect=expect, timeout=timeout, cwd=cwd, env=env, on_line=on_line
        )


def product(port: int) -> Product:
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
                        "port": port,
                        "health": "/health",
                        "ready": "/ready",
                    },
                    "types": {
                        "openapi": "/openapi.json",
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


def repos(tmp: Path, old: bytes = b"// old\n") -> tuple[Path, Path, Path, str]:
    """origin (work), the box's bare, the release worktree, the push address."""
    work = tmp / "origin"
    (work / OUT).parent.mkdir(parents=True)
    (work / OUT).write_bytes(old)
    (work / "README").write_text("blank\n")
    git("-C", str(work), "init", "-q", "-b", REF)
    git("-C", str(work), "add", "-A")
    git("-C", str(work), "commit", "-q", "-m", "init")
    remote = tmp / "remote.git"
    git("clone", "-q", "--bare", str(work), str(remote))
    bare = tmp / "box.git"
    git("clone", "-q", "--bare", str(remote), str(bare))
    release = tmp / "release"
    git("clone", "-q", str(remote), str(release))
    [commit] = git("-C", str(release), "rev-parse", "HEAD")
    return bare, release, remote, commit


def app_calls(port: int, cs: ComposeStack, times: int) -> list[FakeCall]:
    own = cs.product_argv()
    networks = json.dumps({"pridem": {"IPAddress": "127.0.0.1"}})
    one = [
        FakeCall((*own, "ps", "-q", "app"), lines=stdout("c0ffee")),
        FakeCall(
            ("docker", "inspect", "-f", "{{json .NetworkSettings.Networks}}", "c0ffee"),
            lines=stdout(networks),
        ),
    ]
    return one * times


def types(
    tmp: Path, port: int, role: Role, *, generator: bool = True
) -> tuple[Types, Path, ComposeStack]:
    bare, release, remote, commit = repos(tmp)
    made = product(port)
    step = Types(
        made,
        ENTRY,
        release=release,
        ref=REF,
        commit=commit,
        role=role,
        branch=REF,
        run_id="2026-11-01T00:00:00Z-ab12",
        push_to=f"file://{remote}",
        git_dir=bare,
        root=tmp,
        generator=generate if generator else None,
        env=GIT_ENV,
    )
    return (
        step,
        remote,
        ComposeStack(made, ENTRY, release, REF, commit, tmp, staged=True),
    )


def run(step: Types, runner: FakeRunner, role: Role = "test") -> PlanOutcome:
    return Plan(
        [StackSteps("types", [step], root=True)],
        mode="install",
        role=role,
        runner=runner,
        sink=ListSink(),
    ).run()


# --- probe ----------------------------------------------------------------------


def test_probe_DM_19_types_commit_only_on_test_and_only_types_out(
    tmp_path: Path, openapi: int
) -> None:
    step, remote, cs = types(tmp_path, openapi, "test")
    [before] = git("--git-dir", str(remote), "rev-parse", REF)
    with RealGit(*app_calls(openapi, cs, 2)) as runner:  # check, act
        outcome = run(step, runner)
    assert outcome.code is ExitCode.OK, outcome.steps
    [after] = git("--git-dir", str(remote), "rev-parse", REF)
    assert after != before and outcome.steps[0].verify["commit"] == after
    changed = git("--git-dir", str(remote), "show", "--name-only", "--format=", after)
    assert [line for line in changed if line] == [OUT]  # exactly one path
    body = git("--git-dir", str(remote), "log", "-1", "--format=%B", after)
    assert "Primer-Machine: types 2026-11-01T00:00:00Z-ab12" in body
    [author] = git("--git-dir", str(remote), "log", "-1", "--format=%an", after)
    assert author == "blank-bot"
    assert (
        git("--git-dir", str(remote), "show", f"{after}:{OUT}")
        == generate(OPENAPI).decode().splitlines()
    )
    # the pair: on prod nothing is committed, a stale file is red
    step, remote, cs = types(tmp_path / "prod", openapi, "prod")
    [before] = git("--git-dir", str(remote), "rev-parse", REF)
    with RealGit(*app_calls(openapi, cs, 1)) as runner:
        outcome = run(step, runner, "prod")
    assert outcome.steps[0].reason == Code("types:stale", {"path": OUT})
    assert git("--git-dir", str(remote), "rev-parse", REF) == [before]


# --- the rest -------------------------------------------------------------------


def test_without_a_generator_types_are_red_before_act(tmp_path: Path) -> None:
    step, remote, _ = types(tmp_path, 8000, "test", generator=False)
    [before] = git("--git-dir", str(remote), "rev-parse", REF)
    with RealGit() as runner:  # not even the app is asked
        outcome = run(step, runner)
    assert outcome.steps[0].reason == Code(
        "types:generator-unknown", {"stack": "blank"}
    )
    assert git("--git-dir", str(remote), "rev-parse", REF) == [before]


def test_the_same_types_need_no_commit(tmp_path: Path, openapi: int) -> None:
    bare, release, remote, commit = repos(tmp_path, old=generate(OPENAPI))
    made = product(openapi)
    step = Types(
        made,
        ENTRY,
        release=release,
        ref=REF,
        commit=commit,
        role="test",
        branch=REF,
        run_id="r",
        push_to=f"file://{remote}",
        git_dir=bare,
        root=tmp_path,
        generator=generate,
        env=GIT_ENV,
    )
    cs = ComposeStack(made, ENTRY, release, REF, commit, tmp_path, staged=True)
    with RealGit(*app_calls(openapi, cs, 1)) as runner:
        outcome = run(step, runner)
    assert outcome.steps[0].verify == {"types": "current", "path": OUT}


def test_types_out_through_a_symlink_of_the_product_is_refused(
    tmp_path: Path, openapi: int
) -> None:
    """DM-78: the product's branch makes ``frontend/src`` a symlink out of the
    tree -- root's write of ``out`` would land there. ``types:path-outside``,
    and the place outside is untouched. The pair: the probe above."""
    step, remote, cs = types(tmp_path, openapi, "test")
    outside = tmp_path / "outside"
    outside.mkdir()
    work = tmp_path / "origin"
    git("-C", str(work), "rm", "-q", "-r", "frontend/src")
    (work / "frontend").mkdir(exist_ok=True)
    (work / "frontend" / "src").symlink_to(outside, target_is_directory=True)
    git("-C", str(work), "add", "-A")
    git("-C", str(work), "commit", "-q", "-m", "a symlinked src")
    for bare in (remote, tmp_path / "box.git"):
        git("-C", str(work), "push", "-q", "--force", str(bare), f"{REF}:{REF}")
    with RealGit(*app_calls(openapi, cs, 2)) as runner:
        outcome = run(step, runner)
    assert outcome.steps[0].reason == Code("types:path-outside", {"path": OUT})
    assert list(outside.iterdir()) == []
