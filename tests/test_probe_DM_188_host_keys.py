"""Probes of DM-188 (REVIEW-0006, S10), tier 1: GitHub's ssh on both of its
hosts -- ``github.com`` on 22 and ``ssh.github.com`` on 443 -- is checked
against the machine's own copy of GitHub's host keys; the ops repository on
any other host is refused before a key is minted, a file written or a command
run. On a strict ``FakeRunner``: a command the scenario does not name fails.
"""

from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from itertools import count
from pathlib import Path

import pytest
from plan_support import ListSink

from pridem.events import Code, PlanMode, PlanOutcome, Secrets
from pridem.files import temp_of
from pridem.plan import Plan, StackSteps
from pridem.report.codes import ExitCode
from pridem.runner import FakeCall, FakeRunner, OnLine, Result
from pridem.steps.base import Step
from pridem.steps.git import KEYS, git_env, repo
from pridem.steps.keys import (
    GITHUB_HOST_KEYS,
    PINNED,
    DeployKey,
    pinned_known_hosts,
    ssh_config,
    write_ssh_config,
)
from pridem.steps.passport import OpsSource, passport_steps

ON_443 = "ssh://git@ssh.github.com:443/primer/primer-ops.git"
PUBLIC = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDM188PUBLIC pridem"


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
            key.write_text("-----BEGIN OPENSSH PRIVATE KEY-----\nM188\n")
            key.with_name(key.name + ".pub").write_text(PUBLIC + "\n")
        return result


def _keygen(root: Path, address: str) -> FakeCall:
    alias = repo(address).alias
    key = temp_of(root / KEYS / alias)
    argv = ("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", f"pridem {alias}")
    return FakeCall((*argv, "-f", str(key)))


def _lsremote(root: Path, address: str) -> FakeCall:
    argv = ("git", "ls-remote", "--heads", repo(address).url())
    return FakeCall(argv, env=git_env(root))


def _run(
    root: Path, step: Step, calls: list[FakeCall], mode: PlanMode = "install"
) -> PlanOutcome:
    runner = _KeygenRunner(*calls)
    ticks = count()
    with runner:
        return Plan(
            [StackSteps("pridem-passport", [step], root=True)],
            mode=mode,
            role="test",
            runner=runner,
            sink=ListSink(),
            clock=lambda: float(next(ticks)),
            now=lambda: datetime(2026, 11, 25, tzinfo=UTC),
        ).run()


def _ops_key(root: Path, address: str) -> DeployKey:
    """The ``ops_key`` of the passport's ladder, with no real pause."""
    _, steps = passport_steps(
        root, secrets=Secrets(()), server="box-1", ops=OpsSource(address)
    )
    [key] = [step for step in steps if step.name == "ops_key"]
    assert isinstance(key, DeployKey)
    key.wait_s, key.clock, key.sleep = 100, lambda: 0.0, lambda s: None
    return key


def _key(root: Path, address: str) -> DeployKey:
    """A product's key, with no real pause."""
    return DeployKey(address, root, wait_s=100, clock=lambda: 0.0, sleep=lambda s: None)


def _ceremony(root: Path, address: str) -> list[FakeCall]:
    """A key minted and seen steady (three looks), then ``verify``'s look."""
    return [_keygen(root, address), *[_lsremote(root, address)] * 4]


def test_probe_DM_188_ssh_github_on_443_is_held_to_the_machine_copy(
    tmp_path: Path,
) -> None:
    """``ssh.github.com`` on port 443 is checked against ``known_hosts.github``
    and nothing else, and the copy holds every GitHub key under the name ssh
    looks up on that port, ``[ssh.github.com]:443``. A copy of the old form
    (``github.com`` alone) is drawn again. The pair: ``github.com`` on 22 is
    still held to the copy; ``ssh.github.com`` on 22 and ``github.com`` on 443
    are not GitHub's ssh as the machine knows it -- first use, as any host."""
    keys = tmp_path / KEYS
    for address in (ON_443, "ssh://git@SSH.GitHub.com:443/primer/primer-ops"):
        block = ssh_config(tmp_path, [repo(address)])
        assert "  Port 443\n" in block
        assert "  StrictHostKeyChecking yes\n" in block
        assert f"  UserKnownHostsFile {keys / PINNED}\n" in block
        assert "  GlobalKnownHostsFile none\n" in block
        assert "accept-new" not in block
    write_ssh_config(tmp_path, [repo(ON_443)])  # no github.com repository at all
    lines = (keys / PINNED).read_text().splitlines()
    for key in GITHUB_HOST_KEYS:
        assert f"[ssh.github.com]:443 {key}" in lines
        assert f"github.com {key}" in lines
    assert len(lines) == 2 * len(GITHUB_HOST_KEYS)
    # the ceremony on 443: the key minted, its fact names the copy
    outcome = _run(tmp_path, _key(tmp_path, ON_443), _ceremony(tmp_path, ON_443))
    assert outcome.code is ExitCode.OK, outcome.steps
    assert outcome.steps[0].verify["host_keys"] == PINNED
    # a copy of the old form: doctor names it, install draws it again, no wait
    (keys / PINNED).write_text(
        "".join(f"github.com {key}\n" for key in GITHUB_HOST_KEYS)
    )
    doctor = _run(tmp_path, _key(tmp_path, ON_443), [], mode="doctor")
    [item] = doctor.doctor_diff
    assert item.reason.code == "deploy_key:ssh-config"
    assert item.reason.params["files"] == [str(keys / PINNED)]
    look = _lsremote(tmp_path, ON_443)
    again = _run(tmp_path, _key(tmp_path, ON_443), [look, look])
    assert again.code is ExitCode.OK, again.steps
    assert (keys / PINNED).read_text() == pinned_known_hosts()
    # the pair: github.com on its port is held to the copy as before
    assert "StrictHostKeyChecking yes" in ssh_config(
        tmp_path, [repo("git@github.com:primer/primer-ops.git")]
    )
    for other in (
        "ssh://git@ssh.github.com/primer/primer-ops",
        "ssh://git@ssh.github.com:22/primer/primer-ops",
        "ssh://git@github.com:443/primer/primer-ops",
    ):
        block = ssh_config(tmp_path, [repo(other)])
        assert "  StrictHostKeyChecking accept-new\n" in block, other
        assert f"  UserKnownHostsFile {keys / 'known_hosts'}\n" in block, other


@pytest.mark.parametrize(
    "address",
    [
        "git@gitlab.com:primer/primer-ops.git",
        "ssh://git@ops.example:2222/primer/primer-ops",
        "ssh://git@ssh.github.com:22/primer/primer-ops",
        "ssh://git@github.com:443/primer/primer-ops",
    ],
)
def test_probe_DM_188_ops_host_off_github_is_refused_before_any_key(
    tmp_path: Path, address: str
) -> None:
    """The ops repository on a host whose key the machine does not keep is
    ``ops_key:host-unpinned`` in ``check`` -- in ``doctor`` and in
    ``install`` -- with an empty scenario: no ``ssh-keygen``, no
    ``ls-remote``, nothing under ``keys/``. No key comes from the passport:
    it is needed before the passport is read (the gate of DM-188). The pair:
    the ops repository on ``github.com`` and on ``ssh.github.com:443`` goes
    on to its key, the box's own ``file://`` needs none, and a product's
    repository on that same other host still goes to its key (DM-188 closes
    the ops host only)."""
    refused = Code("ops_key:host-unpinned", {"repo": address})
    for mode in ("doctor", "install"):
        outcome = _run(tmp_path, _ops_key(tmp_path, address), [], mode=mode)
        assert outcome.code is ExitCode.FAILED, outcome.steps
        assert outcome.steps[0].status == "failed"
        assert outcome.steps[0].reason == refused
        assert not (tmp_path / KEYS).exists()
    # the pair: GitHub's ssh on either host -- the ceremony
    for good in ("git@github.com:primer/primer-ops.git", ON_443):
        root = tmp_path / repo(good).alias
        outcome = _run(root, _ops_key(root, good), _ceremony(root, good))
        assert outcome.code is ExitCode.OK, outcome.steps
        assert outcome.steps[0].verify["host_keys"] == PINNED
    local = tmp_path / "local"
    outcome = _run(local, _ops_key(local, "file:///srv/primer-ops.git"), [])
    assert outcome.code is ExitCode.OK, outcome.steps
    product = tmp_path / "product"
    outcome = _run(product, _key(product, address), _ceremony(product, address))
    assert outcome.code is ExitCode.OK, outcome.steps
    assert outcome.steps[0].verify["host_keys"] == "accept-new"
