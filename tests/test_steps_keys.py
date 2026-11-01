"""The deploy-key ceremony (DM-10) on a strict ``FakeRunner``: ssh and the wait
for the owner are not git's behaviour, so a scenario is enough. ``ssh-keygen``
is answered by a runner that also writes the pair it would write. Addresses,
the machine's ``ssh_config`` and its copy of GitHub's host keys (DM-52).
"""

import base64
import hashlib
import stat
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from itertools import count
from pathlib import Path

import pytest
from plan_support import ListSink

from pridem.events import PlanOutcome
from pridem.plan import Plan, StackSteps
from pridem.report.codes import ExitCode
from pridem.runner import FakeCall, FakeRunner, OnLine, Result
from pridem.steps import keys as keys_module
from pridem.steps.git import KEYS, collisions, git_env, repo
from pridem.steps.keys import (
    GITHUB_HOST_KEYS,
    PINNED,
    DeployKey,
    drawn_ssh_config,
    pinned_known_hosts,
    ssh_config,
    write_ssh_config,
)

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
    # GitHub: its host keys are the machine's copy, never trusted on first use
    # (DM-52; until then this read accept-new for every host)
    assert "StrictHostKeyChecking yes" in config and "accept-new" not in config
    # the pair: the key in place with access -- no act at all
    outcome, _ = run(
        tmp_path,
        DeployKey(ADDRESS, tmp_path),
        [lsremote(tmp_path, 0), lsremote(tmp_path, 0)],
    )
    assert outcome.code is ExitCode.OK


@pytest.mark.parametrize("mode", [0o600, 0o640])
def test_key_mode_is_the_mode_of_the_key_on_disk(tmp_path: Path, mode: int) -> None:
    """DM-54: the fact ``key_mode`` is read from the key file, so a key found
    with another mode is named with it, not with the mode the step mints."""
    key = tmp_path / KEYS / repo(ADDRESS).alias
    key.parent.mkdir(parents=True)
    key.write_text(PRIVATE)
    key.with_name(key.name + ".pub").write_text(PUBLIC + "\n")
    key.chmod(mode)
    outcome, _ = run(
        tmp_path,
        DeployKey(ADDRESS, tmp_path),
        [lsremote(tmp_path, 0), lsremote(tmp_path, 0)],
    )
    assert outcome.code is ExitCode.OK, outcome.steps
    assert outcome.steps[0].verify["key_mode"] == oct(mode)


def _key_in_place(root: Path) -> Path:
    key = root / KEYS / repo(ADDRESS).alias
    key.parent.mkdir(parents=True, exist_ok=True)
    key.write_text(PRIVATE)
    key.with_name(key.name + ".pub").write_text(PUBLIC + "\n")
    key.chmod(0o600)
    return key


def _doctor(root: Path, calls: list[FakeCall]) -> PlanOutcome:
    with _KeygenRunner(*calls) as runner:
        return Plan(
            [StackSteps("sources", [DeployKey(ADDRESS, root)], root=True)],
            mode="doctor",
            role="test",
            runner=runner,
            sink=ListSink(),
        ).run()


def test_check_writes_nothing_act_draws_the_files(tmp_path: Path) -> None:
    """DM-55: ``check`` only compares the machine's ssh files with the drawn
    ones -- ``doctor`` writes nothing -- and ``act`` writes them; a key in place
    with access is not shown again. The pair: files as drawn, no act at all and
    the files untouched."""
    _key_in_place(tmp_path)
    config, pinned = tmp_path / KEYS / "ssh_config", tmp_path / KEYS / PINNED
    outcome = _doctor(tmp_path, [])  # files not drawn: no ls-remote either
    [item] = outcome.doctor_diff
    assert item.reason.code == "deploy_key:ssh-config"
    assert item.reason.params["files"] == [str(config), str(pinned)]
    assert not config.exists() and not pinned.exists()
    outcome, sink = run(
        tmp_path, DeployKey(ADDRESS, tmp_path), [lsremote(tmp_path, 0)] * 2
    )
    assert outcome.code is ExitCode.OK, outcome.steps
    assert config.read_text() == drawn_ssh_config(tmp_path, [repo(ADDRESS)])[config]
    assert pinned.read_text() == pinned_known_hosts()
    assert "deploy key for" not in "\n".join(str(event) for event in sink.events)
    before = [(p.stat().st_ino, p.stat().st_mtime_ns) for p in (config, pinned)]
    outcome = _doctor(tmp_path, [lsremote(tmp_path, 0)])
    assert outcome.doctor_diff == () and outcome.code is ExitCode.OK
    assert [(p.stat().st_ino, p.stat().st_mtime_ns) for p in (config, pinned)] == before


def test_verify_reads_the_ssh_files_back(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """DM-55: ``verify`` reads the files ``act`` wrote: a write that did not
    land is ``ssh-config-differs``, not a green step."""
    _key_in_place(tmp_path)
    monkeypatch.setattr(keys_module, "atomic_write", lambda *args, **kw: None)
    outcome, _ = run(tmp_path, DeployKey(ADDRESS, tmp_path), [lsremote(tmp_path, 0)])
    reason = outcome.steps[0].reason
    assert reason is not None and reason.code == "deploy_key:ssh-config-differs"
    assert reason.params == {"path": str(tmp_path / KEYS / "ssh_config")}


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


# --- DM-52: addresses without losses, GitHub's host keys pinned ----------------


def test_probe_DM_52_repo_keeps_port_and_user_and_refuses_https(
    tmp_path: Path,
) -> None:
    found = repo("ssh://deploy@example.com:2222/a/b.git")
    assert (found.user, found.port) == ("deploy", 2222)
    assert found.alias == "pridem-example.com-2222-a-b"
    assert found.url() == "ssh://pridem-example.com-2222-a-b/a/b.git"
    block = ssh_config(tmp_path, [found])
    assert "  User deploy\n" in block and "  Port 2222\n" in block
    assert "  BatchMode yes\n" in block
    # the pair: the scp form without a port -- User git, no Port
    plain = repo("git@example.com:a/b.git")
    assert (plain.user, plain.port) == ("git", None)
    block = ssh_config(tmp_path, [plain])
    assert "  User git\n" in block and "Port" not in block
    assert "  BatchMode yes\n" in block
    # https and http are refused, never turned into ssh
    for address, scheme in (
        ("https://github.com/a/b", "https"),
        ("HTTPS://github.com/a/b.git", "https"),
        ("http://example.com/a/b.git", "http"),
    ):
        with pytest.raises(ValueError) as error:
            repo(address)
        assert str(error.value) == f"{scheme} is not supported: add an ssh address"


@pytest.mark.parametrize(
    ("address", "user", "port", "path", "url"),
    [
        ("git@github.com:a/b.git", "git", None, "a/b", "pridem-github.com-a-b:a/b.git"),
        ("host:a/b", "git", None, "a/b", "pridem-host-a-b:a/b"),
        ("ssh://deploy@host/a/b.git", "deploy", None, "a/b", "ssh://pridem-host-a-b/a/b.git"),
        ("ssh://host/a/b", "git", None, "a/b", "ssh://pridem-host-a-b/a/b"),
        ("ssh://h:22/a/b/", "git", 22, "a/b", "ssh://pridem-h-22-a-b/a/b/"),
    ],
)  # fmt: skip
def test_every_ssh_form_keeps_its_user_port_and_path(
    address: str, user: str, port: int | None, path: str, url: str
) -> None:
    found = repo(address)
    assert (found.user, found.port, found.path, found.url()) == (user, port, path, url)


@pytest.mark.parametrize(
    "address",
    [
        "",
        "github.com",
        "@host:a/b",
        "host:",
        "host:/abs",
        "ssh://host:/a/b",
        "ssh://host:0/a/b",
        "ssh://host:70000/a/b",
        "ssh://[::1]/a/b",
        "ssh://host/",
        "ssh://host",
    ],
)
def test_not_an_address_is_refused(address: str) -> None:
    with pytest.raises(ValueError, match="not a repository address"):
        repo(address)


def test_a_file_repository_is_read_as_before() -> None:
    found = repo("file:///srv/x.git")
    assert (found.local, found.url(), found.user, found.port) == (
        True,
        "file:///srv/x.git",
        "",
        None,
    )


def test_one_path_on_two_ports_gets_two_keys() -> None:
    first = repo("ssh://git@host:2222/a/b.git")
    second = repo("ssh://git@host:2223/a/b.git")
    assert first.alias != second.alias
    assert collisions([first.address, second.address]) == []


def test_one_repository_by_two_users_is_a_clash() -> None:
    first, second = "ssh://git@host/a/b.git", "ssh://deploy@host/a/b.git"
    assert repo(first).alias == repo(second).alias
    assert collisions([first, second]) == [repo(first).alias]
    # the pair: two forms of one address by one user are one repository
    assert collisions([first, "git@host:a/b.git"]) == []


@pytest.mark.parametrize(
    "address",
    ["git@github.com:a/b.git", "ssh://git@github.com:22/a/b", "git@GitHub.com:a/b"],
)
def test_github_is_checked_against_the_machine_copy_only(
    tmp_path: Path, address: str
) -> None:
    block = ssh_config(tmp_path, [repo(address)])
    keys = tmp_path / KEYS
    assert "  StrictHostKeyChecking yes\n" in block
    assert f"  UserKnownHostsFile {keys / PINNED}\n" in block
    assert "  GlobalKnownHostsFile none\n" in block
    assert "accept-new" not in block


@pytest.mark.parametrize(
    "address", ["git@gitlab.com:a/b.git", "ssh://git@github.com:443/a/b"]
)
def test_other_hosts_are_accepted_on_first_use(tmp_path: Path, address: str) -> None:
    block = ssh_config(tmp_path, [repo(address)])
    assert "  StrictHostKeyChecking accept-new\n" in block
    assert f"  UserKnownHostsFile {tmp_path / KEYS / 'known_hosts'}\n" in block
    assert "GlobalKnownHostsFile" not in block


PUBLISHED_FINGERPRINTS = {
    "uNiVztksCsDhcc0u9e8BujQXVUpKZIDTMczCvj3tD2s",  # RSA
    "p2QAMXNIC1TJYWeIOttrVc98/R1BUFWu3/LiyKgUfQM",  # ECDSA
    "+DiY3wvvV6TuJJhbpZisF/zLDA0zPMSvHdkr4UvCOqU",  # Ed25519
}
"""The SHA256 fingerprints GitHub's page "GitHub's SSH key fingerprints" lists,
read on 2026-11-01 with the keys of ``GITHUB_HOST_KEYS`` (its DSA one, "closing
down", has no key line there and none here)."""


def _fingerprint(key: str) -> str:
    blob = base64.b64decode(key.split()[1])
    return base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip("=")


def test_the_pinned_keys_are_the_ones_github_publishes() -> None:
    """Both sides come from one reading of GitHub's publication (see
    ``GITHUB_HOST_KEYS``): its ``known_hosts`` lines in the code, its
    fingerprints here. Tier 3 measures them again against ``ssh-keyscan`` and
    ``api.github.com/meta``."""
    assert sorted(key.split()[0] for key in GITHUB_HOST_KEYS) == [
        "ecdsa-sha2-nistp256",
        "ssh-ed25519",
        "ssh-rsa",
    ]
    assert {_fingerprint(key) for key in GITHUB_HOST_KEYS} == PUBLISHED_FINGERPRINTS


def test_the_machine_copy_of_github_keys_is_written_with_the_config(
    tmp_path: Path,
) -> None:
    write_ssh_config(tmp_path, [repo("git@gitlab.com:a/b.git")])
    pinned = tmp_path / KEYS / PINNED
    assert not pinned.exists()  # no GitHub repository, no copy
    write_ssh_config(tmp_path, [repo(ADDRESS)])
    assert pinned.read_text() == "".join(f"github.com {k}\n" for k in GITHUB_HOST_KEYS)
    assert stat.S_IMODE(pinned.stat().st_mode) == 0o600
    pinned.write_text("github.com ssh-ed25519 AAAAforged\n")
    write_ssh_config(tmp_path, [repo(ADDRESS)])  # a changed copy is written again
    assert pinned.read_text() == pinned_known_hosts()


def test_a_block_is_drawn_again_and_the_others_are_kept(tmp_path: Path) -> None:
    other = repo("git@gitlab.com:x/y.git")
    write_ssh_config(tmp_path, [other, repo("ssh://git@host/a/b.git")])
    config = tmp_path / KEYS / "ssh_config"
    write_ssh_config(tmp_path, [repo("ssh://deploy@host/a/b.git")])
    text = config.read_text()
    assert text.count("Host pridem-host-a-b\n") == 1
    assert "  User deploy\n" in text and "  User git\n" in text  # gitlab kept
    assert text.count("Host ") == 2
    # the same repositories again: the file is not written
    inode, mtime = config.stat().st_ino, config.stat().st_mtime_ns
    write_ssh_config(tmp_path, [other, repo("ssh://deploy@host/a/b.git")])
    assert (config.stat().st_ino, config.stat().st_mtime_ns) == (inode, mtime)
    assert stat.S_IMODE(config.stat().st_mode) == 0o600
