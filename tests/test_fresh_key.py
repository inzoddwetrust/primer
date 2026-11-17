"""DM-111: a fresh key of GitHub -- steady access; the cause of a failed
command in the console.

A key minted in this run counts as working only after ``STEADY`` looks in a
row; a refusal of it by the next command to its repository is a wait again,
within the same deadline, pauses growing; a key of an earlier run is refused
at once, as before. The console says why a command failed: its last line that
is no git set phrase, cleaned as the journal is.
"""

import io
from dataclasses import replace
from datetime import UTC, datetime
from itertools import count
from pathlib import Path

import pytest
from env_support import context
from test_steps_keys import ADDRESS, keygen, lsremote, run

from pridem.events import (
    Code,
    ConsoleSink,
    KeyNeeded,
    LogLine,
    Secrets,
    StepFinished,
    StepRecord,
    StepStarted,
)
from pridem.report.codes import ExitCode
from pridem.runner import CommandFailed, FakeRunner, Stream
from pridem.steps import keys
from pridem.steps.base import StepContext
from pridem.steps.git import repo
from pridem.steps.keys import (
    PAUSES_S,
    STEADY_PAUSE_S,
    DeployKey,
    FreshKeys,
    wait_for_access,
)
from pridem.steps.sources import remote_target

REFUSED_TAIL = (
    (Stream.STDERR, "git@github.com: Permission denied (publickey)."),
    (Stream.STDERR, "fatal: Could not read from remote repository."),
    (Stream.STDERR, ""),
    (Stream.STDERR, "Please make sure you have the correct access rights"),
    (Stream.STDERR, "and the repository exists."),
)


# --- the policy -------------------------------------------------------------------


def test_steady_access_is_three_looks_in_a_row_fifteen_seconds_apart() -> None:
    """One look that answers is not enough; a refusal in the row starts it
    again; three in a row -- working, ``STEADY_PAUSE_S`` between them."""
    slept: list[float] = []
    given = iter([True, False, True, True, True])
    assert wait_for_access(
        context_of(), lambda: next(given), 1e9, lambda: 0.0, slept.append
    )
    assert slept == [STEADY_PAUSE_S, PAUSES_S[0], STEADY_PAUSE_S, STEADY_PAUSE_S]
    assert STEADY_PAUSE_S == 15.0


def test_pauses_grow_and_never_are_none() -> None:
    """Refused look after look: 10, 30, 60, then 60 s -- never a look without
    a pause; at the deadline, ``False``."""
    slept: list[float] = []
    ticks = count()
    assert not wait_for_access(
        context_of(), lambda: False, 5.0, lambda: float(next(ticks)), slept.append
    )
    assert slept == [10.0, 30.0, 60.0, 60.0, 60.0]
    assert all(pause > 0 for pause in slept)


def context_of() -> StepContext:
    return context(FakeRunner())


# --- the step of the key ----------------------------------------------------------


def test_a_key_that_answers_once_then_not_is_waited_for_again(tmp_path: Path) -> None:
    """Minted, taken once, refused by the next look (GitHub spreads it), then
    steady: green -- and in the run's fresh keys, with its deadline."""
    fresh = FreshKeys(tmp_path, clock=lambda: 0.0, sleep=lambda _: None)
    step = DeployKey(
        ADDRESS,
        tmp_path,
        wait_s=100,
        clock=lambda: 0.0,
        sleep=lambda _: None,
        fresh=fresh,
    )
    calls = [
        keygen(tmp_path),
        lsremote(tmp_path, 0),
        lsremote(tmp_path, 128),
        lsremote(tmp_path, 0),
        lsremote(tmp_path, 0),
        lsremote(tmp_path, 0),
        lsremote(tmp_path, 0),  # verify
    ]
    outcome, _ = run(tmp_path, step, calls)
    assert outcome.code is ExitCode.OK, outcome.steps
    assert fresh.deadline(repo(ADDRESS)) == 100.0


def test_a_key_never_taken_says_check_that_it_is_added(tmp_path: Path) -> None:
    ticks = count()
    step = DeployKey(
        ADDRESS,
        tmp_path,
        wait_s=3,
        clock=lambda: float(next(ticks)),
        sleep=lambda _: None,
    )
    outcome, _ = run(tmp_path, step, [keygen(tmp_path), *[lsremote(tmp_path, 128)] * 3])
    reason = outcome.steps[0].reason
    assert reason is not None and reason.code == "deploy_key:no-access"
    assert "check that the key is added to {repo}" in DeployKey.codes["no-access"]


# --- the next command to the repository -------------------------------------------


def _refused() -> CommandFailed:
    return CommandFailed(("git", "fetch"), 128, (0,), REFUSED_TAIL)


def test_a_fresh_key_refused_by_the_next_command_waits_and_tries_again(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``fetch`` refused with ``Permission denied (publickey)``, the key minted
    in this run: the key's block again (``again``), the wait, the command again
    -- green. The pair: a key of an earlier run -- the refusal as it is."""
    monkeypatch.setattr(keys, "has_access", lambda ctx, root, found: True)
    found = repo(ADDRESS)
    fresh = FreshKeys(tmp_path, clock=lambda: 0.0, sleep=lambda _: None)
    fresh.minted(found, "ssh-ed25519 AAAA", 1800.0)
    notices: list[object] = []
    ctx = replace(context_of(), notice=notices.append)
    calls = iter([_refused(), None])

    def fetch() -> str:
        error = next(calls)
        if error is not None:
            raise error
        return "fetched"

    assert fresh.retried(ctx, found, fetch) == "fetched"
    [notice] = notices
    assert isinstance(notice, KeyNeeded) and notice.again
    other = repo("git@github.com:acme/old.git")
    calls = iter([_refused(), None])
    with pytest.raises(CommandFailed):
        fresh.retried(ctx, other, fetch)


def test_the_deadline_is_the_keys_own_for_every_command(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The key's deadline is shared by the step and every command after it:
    a refusal after it is the failure as it is -- no new half an hour."""
    monkeypatch.setattr(keys, "has_access", lambda ctx, root, found: True)
    found = repo(ADDRESS)
    fresh = FreshKeys(tmp_path, clock=lambda: 2000.0, sleep=lambda _: None)
    fresh.minted(found, "ssh-ed25519 AAAA", 1800.0)

    def fetch() -> str:
        raise _refused()

    with pytest.raises(CommandFailed):
        fresh.retried(context_of(), found, fetch)


def test_a_failure_that_is_no_refusal_of_the_key_is_not_waited_for(
    tmp_path: Path,
) -> None:
    found = repo(ADDRESS)
    fresh = FreshKeys(tmp_path, clock=lambda: 0.0, sleep=lambda _: None)
    fresh.minted(found, "ssh-ed25519 AAAA", 1800.0)

    def fetch() -> str:
        raise CommandFailed(("git", "fetch"), 128, (0,), ((Stream.STDERR, "no"),))

    with pytest.raises(CommandFailed):
        fresh.retried(context_of(), found, fetch)


def test_ls_remote_of_a_fresh_key_goes_through_the_wait(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``remote_target`` -- ``check`` of the fetch steps -- as ``fetch``."""
    monkeypatch.setattr(keys, "has_access", lambda ctx, root, found: True)
    found = repo(ADDRESS)
    fresh = FreshKeys(tmp_path, clock=lambda: 0.0, sleep=lambda _: None)
    fresh.minted(found, "ssh-ed25519 AAAA", 1800.0)
    seen: list[int] = []

    def flaky(ctx, root, argv, **kw):  # type: ignore[no-untyped-def]
        seen.append(1)
        if len(seen) == 1:
            raise _refused()
        return 0, [f"{'a' * 40}\trefs/heads/main"]

    from pridem.steps import sources

    monkeypatch.setattr(sources, "run_git", flaky)
    target = remote_target(context_of(), tmp_path, found, "main", False, fresh)
    assert target is not None and target.commit == "a" * 40 and len(seen) == 2


# --- the console ------------------------------------------------------------------


def _console_of(lines: tuple[tuple[Stream, str], ...], secret: str) -> str:
    out = io.StringIO()
    console = ConsoleSink(out, _secrets(secret))
    at = datetime(2026, 11, 17, tzinfo=UTC)
    console.emit(StepStarted("main", "aivis", "fetch_root", 1, at))
    for stream, line in lines:
        console.emit(LogLine("main", "aivis", "fetch_root", stream, line))
    record = StepRecord(
        stack="aivis",
        name="fetch_root",
        order=1,
        status="failed",
        reason=Code("command-failed", {"argv": ["git", "fetch"], "exit_code": 128}),
        started=at,
        duration_s=1.0,
        verify={},
    )
    console.emit(StepFinished("main", record))
    return out.getvalue()


def _secrets(secret: str) -> Secrets:
    from pydantic import SecretStr

    return Secrets([SecretStr(secret)])


def test_the_console_says_why_a_command_failed_cleaned(tmp_path: Path) -> None:
    """The last line that says why -- ``Permission denied (publickey)``, not
    git's set phrases after it; a secret in it -- ``[redacted]``, the rest of
    the line there. The pair: nothing that says why -- no cause."""
    secret = "pridem-planted-secret-111a"  # noqa: S105 -- planted
    lines = (
        (Stream.STDOUT, "fetching"),
        (Stream.STDERR, f"git@github.com: Permission denied (publickey). {secret}"),
        *REFUSED_TAIL[1:],
    )
    printed = _console_of(lines, secret)
    assert "Permission denied (publickey). [redacted]" in printed
    assert secret not in printed and "and the repository exists." not in printed
    only_git = _console_of(REFUSED_TAIL[1:], secret)
    assert "Could not read" not in only_git
    stdout_only = _console_of(((Stream.STDOUT, "make: *** [x] Error 2"),), secret)
    assert "make: *** [x] Error 2" in stdout_only


def test_a_refusal_before_the_deadline_waits_only_up_to_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Refused at 1700 s of a key whose wait ends at 1800 s, the clock
    going 10 s a call: the wait again ends at 1800 s -- nine looks -- not
    half an hour after the refusal."""
    looks: list[int] = []

    def refused(ctx: StepContext, root: Path, found: object) -> bool:
        looks.append(1)
        return False

    monkeypatch.setattr(keys, "has_access", refused)
    found = repo(ADDRESS)
    ticks = count(1700.0, 10.0)
    fresh = FreshKeys(tmp_path, clock=lambda: next(ticks), sleep=lambda _: None)
    fresh.minted(found, "ssh-ed25519 AAAA", 1800.0)

    def fetch() -> str:
        raise _refused()

    with pytest.raises(CommandFailed):
        fresh.retried(context_of(), found, fetch)
    assert len(looks) == 9
