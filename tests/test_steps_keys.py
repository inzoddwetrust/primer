"""The deploy-key ceremony (DM-10) on a strict ``FakeRunner``: ssh and the wait
for the owner are not git's behaviour, so a scenario is enough. ``ssh-keygen``
is answered by a runner that also writes the pair it would write.
"""

import stat
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from itertools import count
from pathlib import Path

from plan_support import ListSink

from pridem.events import PlanOutcome
from pridem.plan import Plan, StackSteps
from pridem.report.codes import ExitCode
from pridem.runner import FakeCall, FakeRunner, OnLine, Result
from pridem.steps.git import KEYS, git_env, repo
from pridem.steps.keys import DeployKey

ADDRESS = "git@github.com:partner-x/velo-look.git"
PRIVATE = (
    "-----BEGIN OPENSSH PRIVATE KEY-----\n"
    "MARKER-PRIVATE-a7f3\n"
    "-----END OPENSSH PRIVATE KEY-----\n"
)
PUBLIC = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMARKERPUBLIC pridem"


class _KeygenRunner(FakeRunner):
    """``ssh-keygen`` also leaves the pair on disk, as the real one does."""

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
        result = super().run(
            argv, expect=expect, timeout=timeout, cwd=cwd, env=env, on_line=on_line
        )
        if argv[0] == "ssh-keygen":
            key = Path(argv[argv.index("-f") + 1])
            key.write_text(PRIVATE)
            key.with_name(key.name + ".pub").write_text(PUBLIC + "\n")
        return result


def lsremote(root: Path, code: int) -> FakeCall:
    found = repo(ADDRESS)
    return FakeCall(
        ("git", "ls-remote", "--heads", found.url()), code=code, env=git_env(root)
    )


def run(
    root: Path, step: DeployKey, calls: list[FakeCall]
) -> tuple[PlanOutcome, ListSink]:
    runner = _KeygenRunner(*calls)
    sink = ListSink()
    ticks = count()
    with runner:
        outcome = Plan(
            [StackSteps("sources", [step], root=True)],
            mode="install",
            role="test",
            runner=runner,
            sink=sink,
            clock=lambda: float(next(ticks)),
            now=lambda: datetime(2026, 10, 25, tzinfo=UTC),
        ).run()
    return outcome, sink


def keygen(root: Path) -> FakeCall:
    key = root / KEYS / repo(ADDRESS).alias
    argv = (
        "ssh-keygen",
        "-q",
        "-t",
        "ed25519",
        "-N",
        "",
        "-C",
        f"pridem {repo(ADDRESS).alias}",
        "-f",
        str(key),
    )
    return FakeCall(argv)


def test_ceremony_mints_waits_and_never_shows_the_private_part(tmp_path: Path) -> None:
    clock = iter([0.0, 1.0, 2.0])
    step = DeployKey(
        ADDRESS, tmp_path, wait_s=100, clock=lambda: next(clock), sleep=lambda s: None
    )
    calls = [
        keygen(tmp_path),
        lsremote(tmp_path, 128),
        lsremote(tmp_path, 0),
        lsremote(tmp_path, 0),
    ]
    outcome, sink = run(tmp_path, step, calls)
    assert outcome.code is ExitCode.OK, outcome.steps
    key = tmp_path / KEYS / repo(ADDRESS).alias
    assert stat.S_IMODE(key.stat().st_mode) == 0o600
    printed = "\n".join(str(event) for event in sink.events)
    assert PUBLIC in printed  # the owner sees the public part
    assert "MARKER-PRIVATE" not in printed and "MARKER-PRIVATE" not in str(outcome)
    config = (tmp_path / KEYS / "ssh_config").read_text()
    assert f"Host {repo(ADDRESS).alias}" in config and "IdentitiesOnly yes" in config
    assert "StrictHostKeyChecking accept-new" in config
    # the pair: the key in place with access -- no act at all
    outcome, _ = run(
        tmp_path,
        DeployKey(ADDRESS, tmp_path),
        [lsremote(tmp_path, 0), lsremote(tmp_path, 0)],
    )
    assert outcome.code is ExitCode.OK


def test_no_access_by_the_deadline_is_red_with_the_public_part_only(
    tmp_path: Path,
) -> None:
    clock = iter([0.0, 5.0, 11.0])
    step = DeployKey(
        ADDRESS, tmp_path, wait_s=10, clock=lambda: next(clock), sleep=lambda s: None
    )
    calls = [keygen(tmp_path), lsremote(tmp_path, 128), lsremote(tmp_path, 128)]
    outcome, _ = run(tmp_path, step, calls)
    reason = outcome.steps[0].reason
    assert reason is not None and reason.code == "deploy_key:no-access"
    assert reason.params["public_key"] == PUBLIC
    assert "MARKER-PRIVATE" not in str(reason.as_json())


def test_two_repositories_with_one_name_get_two_keys() -> None:
    first = repo("git@github.com:partner-x/velo-look.git")
    second = repo("git@github.com:partner-y/velo-look.git")
    assert first.name == second.name and first.alias != second.alias


def test_repositories_that_share_an_alias_are_red_before_act(tmp_path: Path) -> None:
    clash = "git@github.com:Partner-X/velo-look.git"  # the same alias after lower case
    step = DeployKey(ADDRESS, tmp_path, others=[clash])
    outcome, _ = run(tmp_path, step, [])
    reason = outcome.steps[0].reason
    assert reason is not None and reason.code == "deploy_key:alias-clash"
    assert not (tmp_path / KEYS).exists()


def test_a_file_repository_needs_no_key(tmp_path: Path) -> None:
    outcome, _ = run(tmp_path, DeployKey(f"file://{tmp_path}/x.git", tmp_path), [])
    assert outcome.code is ExitCode.OK
