"""DM-124: alembic in the release's image with the app's environment; the cause
of a failed command -- up to three rows.

``alembic heads`` and ``alembic show`` run in a throwaway container of the
built image, no network, with the environment ``compose run <app>`` gives the
app -- read from ``config`` of the stack's files and given by a file of the
stack's ``env/``, 0600, there only while the command runs. Expected commands
are literal (``par0`` 14.2).
"""

import io
import json
import os
import stat
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path

import pytest
from compose_support import (
    APP_IMAGE,
    app_config_call,
    compose,
    image_call,
    stdout,
)
from env_support import context
from pydantic import SecretStr

from pridem.events import (
    Code,
    ConsoleSink,
    LogLine,
    Secrets,
    StepFinished,
    StepRecord,
    StepStarted,
)
from pridem.runner import CommandFailed, FakeCall, FakeRunner, OnLine, Result, Stream
from pridem.steps.base import StepFailed
from pridem.steps.compose import ComposeStack
from pridem.steps.migrate import Migrate


def _migrate(root: Path) -> Migrate:
    cs = compose(root)
    return Migrate(
        cs.stack, cs.entry, release=cs.release, ref=cs.ref, commit=cs.commit, root=root
    )


def _rendered_env(root: Path) -> None:
    """The deploy's ``next.env``, as ``render_env`` writes it."""
    (root / "opt" / "blank" / "env").mkdir(parents=True)
    (root / "opt" / "blank" / "env" / "next.env").write_text("")


def _heads_argv(root: Path, *args: str) -> tuple[str, ...]:
    return (
        "docker", "run", "--rm", "--network", "none",
        "--label", "pridem.stack=blank", "--label", "pridem.release=main",
        "--label", "pridem.commit=0e82be562d186afc933b8779d91dddcae4278cea",
        "--env-file", f"{root}/opt/blank/env/alembic.env",
        "--", APP_IMAGE, "python", "-m", "alembic", *args,
    )  # fmt: skip


class Looking(FakeRunner):
    """The strict script; at ``docker run`` it reads the env file the argv
    names -- its text and its mode -- as the container would."""

    def __init__(self, *calls: FakeCall) -> None:
        super().__init__(*calls)
        self.seen: list[tuple[str, int]] = []

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
        if tuple(argv[:2]) == ("docker", "run"):
            path = Path(argv[argv.index("--env-file") + 1])
            mode = stat.S_IMODE(os.stat(path).st_mode)
            self.seen.append((path.read_text(), mode))
        return super().run(
            argv, expect=expect, timeout=timeout, cwd=cwd, env=env, on_line=on_line
        )


def test_heads_runs_with_the_apps_environment_no_network(tmp_path: Path) -> None:
    """``alembic heads``: the app's environment from ``config`` of the stack's
    files with the machine's override, in a file 0600 while the command runs,
    no network; after it the file is gone."""
    cs = compose(tmp_path)
    _rendered_env(tmp_path)
    calls = [
        image_call(cs, "app", APP_IMAGE),
        app_config_call(cs),
        FakeCall(_heads_argv(tmp_path, "heads"), lines=stdout("0001 (head)")),
    ]
    with Looking(*calls) as runner:
        found, _ = _migrate(tmp_path)._heads(context(runner))
    assert found == ["0001"]
    assert runner.seen == [
        ("DATABASE_URL=postgresql://blank@postgres/blank\nLEVEL=1\n", 0o600)
    ]
    assert not (tmp_path / "opt" / "blank" / "env" / "alembic.env").exists()


def test_show_runs_with_the_apps_environment(tmp_path: Path) -> None:
    from pridem.steps.migrate import unknown_head

    cs = compose(tmp_path)
    _rendered_env(tmp_path)
    step = _migrate(tmp_path)
    calls = [
        image_call(cs, "app", APP_IMAGE),
        app_config_call(cs),
        FakeCall(_heads_argv(tmp_path, "show", "0001"), lines=stdout("Rev: 0001")),
    ]
    with Looking(*calls) as runner:
        with step._alembic(context(runner), "show", "0001") as argv:
            assert not unknown_head(context(runner), argv, "0001")
    assert len(runner.seen) == 1


def _config_with(cs: ComposeStack, environment: dict[str, object]) -> FakeCall:
    document = {"services": {"app": {"environment": environment}}}
    return FakeCall(
        tuple(cs.argv("config", "--format", "json")), lines=stdout(json.dumps(document))
    )


def test_a_key_without_a_value_is_not_written_and_a_multiline_one_is_refused(
    tmp_path: Path,
) -> None:
    cs = compose(tmp_path)
    _rendered_env(tmp_path)
    calls = [
        image_call(cs, "app", APP_IMAGE),
        _config_with(cs, {"EMPTY": None, "B": "x"}),
        FakeCall(_heads_argv(tmp_path, "heads"), lines=stdout("0001 (head)")),
    ]
    with Looking(*calls) as runner:
        _migrate(tmp_path)._heads(context(runner))
    assert runner.seen == [("B=x\n", 0o600)]
    calls = [
        image_call(cs, "app", APP_IMAGE),
        _config_with(cs, {"KEY": "a\nb"}),
    ]
    with Looking(*calls) as runner, pytest.raises(StepFailed) as refused:
        _migrate(tmp_path)._heads(context(runner))
    assert refused.value.reason == Code(
        "env-multiline", {"stack": "blank", "key": "KEY"}
    )
    assert runner.seen == []


def test_the_file_goes_when_the_command_fails(tmp_path: Path) -> None:
    cs = compose(tmp_path)
    _rendered_env(tmp_path)
    calls = [
        image_call(cs, "app", APP_IMAGE),
        app_config_call(cs),
        FakeCall(_heads_argv(tmp_path, "heads"), code=1),
    ]
    with Looking(*calls) as runner, pytest.raises(CommandFailed):
        _migrate(tmp_path)._heads(context(runner))
    assert not (tmp_path / "opt" / "blank" / "env" / "alembic.env").exists()


# --- the console: up to three rows ------------------------------------------------


def test_the_console_shows_the_last_three_lines_that_say_why() -> None:
    """comms' refusal: three lines, the reason a line above the last -- all
    three, a row each under the step's line, a secret in one cleaned; git's set
    phrases are no cause; the first of four is not shown."""
    secret = "pridem-planted-secret-124b"  # noqa: S105 -- planted
    out = io.StringIO()
    console = ConsoleSink(out, Secrets([SecretStr(secret)]))
    at = datetime(2026, 11, 19, tzinfo=UTC)
    console.emit(StepStarted("main", "comms", "stop_for_migrate", 1, at))
    for line in (
        "first line, not shown",
        "comms: startup refused -- the configuration is invalid.",
        f"DATABASE_URL is required. {secret}",
        "fatal: Could not read from remote repository.",
        "Fix the variables named above and start again.",
    ):
        console.emit(LogLine("main", "comms", "stop_for_migrate", Stream.STDERR, line))
    record = StepRecord(
        stack="comms",
        name="stop_for_migrate",
        order=1,
        status="failed",
        reason=Code("command-failed", {"argv": ["docker", "run"], "exit_code": 1}),
        started=at,
        duration_s=1.0,
        verify={},
    )
    console.emit(StepFinished("main", record))
    rows = out.getvalue().splitlines()
    assert rows[-3:] == [
        "           comms: startup refused -- the configuration is invalid.",
        "           DATABASE_URL is required. [redacted]",
        "           Fix the variables named above and start again.",
    ]
    assert secret not in out.getvalue() and "first line" not in out.getvalue()
