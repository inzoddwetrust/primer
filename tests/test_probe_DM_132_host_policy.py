"""DM-132: the machine prepares the server -- ``policies.host`` of the
passport (swap, memory, the login by password), nothing to restore past an
empty database, and the refusal of ``destroy`` with a dash.

Files are real, under ``tmp`` as the box's root; every command follows a
strict script: a ``swapoff``, an ``fallocate`` or a second ``mkswap`` nobody
planned is a failure.
"""

import os
from collections.abc import Iterator, Mapping, Sequence
from itertools import count
from pathlib import Path

import pytest
from compose_support import (
    APP_IMAGE,
    HEAD,
    LiveApp,
    alembic_call,
    compose,
    heads_call,
    image_call,
    live,
    migrate_call,
    observe_calls,
    stdout,
)
from compose_support import run as run_entry
from env_support import box, passport_data
from plan_support import Journal, ListSink, ScriptedStep
from pydantic import ValidationError
from report_support import build

from pridem.events import Code, PlanOutcome
from pridem.plan import Plan, StackSteps
from pridem.report.codes import ExitCode
from pridem.runner import FakeCall, FakeRunner
from pridem.stacks import names as machine
from pridem.stacks.passport import HostPolicy
from pridem.steps.base import Step
from pridem.steps.host_policy import (
    AS_ROOT,
    DROP_IN,
    DROP_IN_TEXT,
    FSTAB,
    MIN_MEMORY_GIB,
    MIN_RAM_GIB,
    SSHD,
    SWAPFILE,
    SWAPON,
    Memory,
    PasswordLogin,
    Swap,
    host_policy_steps,
)
from pridem.steps.migrate import Migrate
from pridem.steps.passport import Fetched
from pridem.verbs.base import Refused
from pridem.verbs.deploy import _named

GIB = 2**30
HAND = "/swapfile"
FSTAB_TEXT = "UUID=abc / ext4 defaults 0 1\n"


def fetched_with(tmp: Path, host: Mapping[str, str] | None) -> tuple[Path, Fetched]:
    data = passport_data()
    policies = data["policies"]
    assert isinstance(policies, dict)
    if host is not None:
        policies["host"] = dict(host)
    return box(tmp, data)


def run(
    steps: Sequence[Step], runner: FakeRunner, mode: str = "install"
) -> PlanOutcome:
    ticks = count()
    return Plan(
        [StackSteps(machine.HOST_POLICY, steps, root=True)],
        mode=mode,  # type: ignore[arg-type]
        role="test",
        runner=runner,
        sink=ListSink(),
        clock=lambda: float(next(ticks)),
    ).run()


def swapon(*rows: tuple[str, str, int]) -> FakeCall:
    """``swapon --show`` with ``rows`` of ``(path, type, bytes)``."""
    return FakeCall(SWAPON, lines=stdout(*(f"{p} {t} {n}" for p, t, n in rows)))


def fstab(root: Path, text: str = FSTAB_TEXT) -> Path:
    file = root / FSTAB
    file.parent.mkdir(parents=True, exist_ok=True)
    file.write_text(text, encoding="utf-8")
    return file


def swap(root: Path, fetched: Fetched, free: float = 0) -> Swap:
    return Swap(fetched=fetched, root=root, min_free_gib=free)


# --- probes ---------------------------------------------------------------------


def test_probe_DM_132_swap_is_made_once_and_a_hand_made_one_is_kept(
    tmp_path: Path,
) -> None:
    """A box with no swap gets the machine's own file of the passport's size:
    made, switched on, one line in ``/etc/fstab``; the repeat does nothing.
    The pair: a box whose hand-made ``/swapfile`` is on -- smaller than the
    passport's -- is not touched: no file, no line, no ``swapoff``, the
    shortage named."""
    root, fetched = fetched_with(tmp_path / "a", {"swap": "1M"})
    table = fstab(root)
    mine = str(root / SWAPFILE)
    made = [
        swapon(),
        FakeCall(("mkswap", mine)),
        FakeCall(("swapon", mine)),
        swapon((mine, "file", 2**20 - 4096)),
    ]
    with FakeRunner(*made) as runner:
        outcome = run([swap(root, fetched)], runner)
    assert outcome.code is ExitCode.OK, outcome.steps
    assert (root / SWAPFILE).stat().st_size == 2**20
    assert (root / SWAPFILE).stat().st_mode & 0o777 == 0o600
    assert table.read_text() == f"{FSTAB_TEXT}{mine} none swap sw 0 0\n"
    assert outcome.steps[0].verify["wanted"] == "1M"
    again = [swapon((mine, "file", 2**20 - 4096))] * 2
    with FakeRunner(*again) as runner:
        outcome = run([swap(root, fetched)], runner)
    assert outcome.code is ExitCode.OK
    assert table.read_text().count(mine) == 1
    # the pair: a hand-made swap on, smaller than the passport's -- kept
    root, fetched = fetched_with(tmp_path / "b", {"swap": "4G"})
    hand = f"{HAND} none swap sw 0 0\n"
    table = fstab(root, FSTAB_TEXT + hand)
    with FakeRunner(*[swapon((HAND, "file", 2 * GIB))] * 2) as runner:
        outcome = run([swap(root, fetched)], runner)
    assert outcome.code is ExitCode.OK, outcome.steps
    assert not (root / SWAPFILE).exists()
    assert table.read_text() == FSTAB_TEXT + hand
    fact = outcome.steps[0].verify
    assert fact["short_by_gib"] == 2.0 and fact["swap_gib"] == 2.0


def meminfo(root: Path, ram_gib: float, swap_gib: float) -> None:
    file = root / "proc" / "meminfo"
    file.parent.mkdir(parents=True, exist_ok=True)
    kb = int(ram_gib * GIB / 1024), int(swap_gib * GIB / 1024)
    file.write_text(
        f"MemTotal:       {kb[0]} kB\nMemFree:         1000 kB\n"
        f"SwapTotal:      {kb[1]} kB\nSwapFree:       {kb[1]} kB\n",
        encoding="utf-8",
    )


def test_probe_DM_132_memory_with_swap_is_refused_below_the_floor(
    tmp_path: Path,
) -> None:
    """velo-dev's RAM without swap is refused with the numbers; with its swap
    of 4 GB it passes. Swap does not stand in for RAM: 2 GiB of RAM with any
    swap is refused."""
    meminfo(tmp_path, 3.8, 0)
    with FakeRunner() as runner:
        outcome = run([Memory(tmp_path)], runner)
    assert outcome.steps[0].reason == Code(
        "memory:memory-low",
        {
            "ram_gib": 3.8,
            "swap_gib": 0.0,
            "total_gib": 3.8,
            "min_gib": MIN_MEMORY_GIB,
            "min_ram_gib": MIN_RAM_GIB,
        },
    )
    meminfo(tmp_path, 3.8, 4)
    with FakeRunner() as runner:
        outcome = run([Memory(tmp_path)], runner)
    assert outcome.code is ExitCode.OK
    assert outcome.steps[0].verify == {
        "ram_gib": 3.8,
        "swap_gib": 4.0,
        "total_gib": 7.8,
    }
    meminfo(tmp_path, 2, 8)
    with FakeRunner() as runner:
        outcome = run([Memory(tmp_path)], runner)
    assert outcome.steps[0].reason is not None
    assert outcome.steps[0].reason.code == "memory:memory-low"


# --- password login -------------------------------------------------------------

KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAM root@x"


def sshd_box(
    tmp: Path, host: Mapping[str, str] | None, *, key: str | None = KEY
) -> tuple[Path, Fetched, Path]:
    root, fetched = fetched_with(tmp, host)
    (root / SSHD).parent.mkdir(parents=True, exist_ok=True)
    (root / SSHD).write_text("", encoding="utf-8")
    keys = root / "root" / ".ssh" / "authorized_keys"
    keys.parent.mkdir(parents=True, mode=0o700)
    (root / "root").chmod(0o700)
    if key is not None:
        keys.write_text(key + "\n" if key else "", encoding="utf-8")
        keys.chmod(0o600)
    return root, fetched, keys


def effective(login: str = "yes", kbd: str = "no", **more: str) -> FakeCall:
    """``sshd -T`` for root; ``login`` -- its ``passwordauthentication``."""
    lines = {
        "PasswordAuthentication": login,
        "KbdInteractiveAuthentication": kbd,
        "PermitRootLogin": "prohibit-password",
        "PubkeyAuthentication": "yes",
        "AuthorizedKeysFile": ".ssh/authorized_keys .ssh/authorized_keys2",
        "StrictModes": "yes",
    }
    lines.update(more)
    return FakeCall(
        ("sshd", "-T", *AS_ROOT), lines=stdout(*(f"{k} {v}" for k, v in lines.items()))
    )


def keygen(keys: Path, ok: bool = True) -> FakeCall:
    said = "256 SHA256:abc root@x (ED25519)" if ok else "is not a public key file."
    return FakeCall(("ssh-keygen", "-l", "-f", str(keys)), code=0 if ok else 255,
                    lines=stdout(said))  # fmt: skip


def close_calls(keys: Path, *, active: bool = True) -> list[FakeCall]:
    reload = [FakeCall(("systemctl", "reload", "ssh"))] if active else []
    return [
        effective(),
        keygen(keys),
        FakeCall(("sshd", "-t")),
        FakeCall(("systemctl", "is-active", "--quiet", "ssh"), code=0 if active else 3),
        *reload,
        effective(login="no"),
    ]


def login(root: Path, fetched: Fetched) -> PasswordLogin:
    return PasswordLogin(fetched=fetched, root=root, root_uid=os.getuid())


def test_probe_DM_132_password_login_closes_only_when_asked_and_with_a_root_key(
    tmp_path: Path,
) -> None:
    """Asked (``closed``) and root has a key -- the machine's file, checked by
    ``sshd -t``, ``ssh`` reloaded, closed as sshd reads it. The pair: no field
    and the same key -- nothing is written, the fact says ``open``."""
    root, fetched, keys = sshd_box(tmp_path / "a", {"password_login": "closed"})
    with FakeRunner(*close_calls(keys)) as runner:
        outcome = run([login(root, fetched)], runner)
    assert outcome.code is ExitCode.OK, outcome.steps
    assert (root / DROP_IN).read_text() == DROP_IN_TEXT
    assert outcome.steps[0].verify == {"password": "closed"}
    root, fetched, keys = sshd_box(tmp_path / "b", None)
    with FakeRunner(effective()) as runner:
        outcome = run([login(root, fetched)], runner)
    assert outcome.code is ExitCode.OK
    assert not (root / DROP_IN).exists()
    assert outcome.steps[0].verify == {"password": "open"}


@pytest.mark.parametrize(
    ("key", "more", "why", "keygen_ok"),
    [
        (None, {}, "no-key", None),
        ("", {}, "key-unreadable", False),
        ("# a comment", {}, "key-unreadable", False),
        (KEY, {"PermitRootLogin": "no"}, "root-login-off", None),
        (KEY, {"PubkeyAuthentication": "no"}, "pubkey-off", None),
    ],
)
def test_asked_and_no_key_root_can_use_stays_open_and_incomplete(
    tmp_path: Path,
    key: str | None,
    more: dict[str, str],
    why: str,
    keygen_ok: bool | None,
) -> None:
    """The owner asked to close and the machine could not: not green -- exit
    2, the why named; nothing written."""
    root, fetched, keys = sshd_box(tmp_path, {"password_login": "closed"}, key=key)
    calls = [effective(**more)]
    if keygen_ok is not None:
        calls.append(keygen(keys, keygen_ok))
    calls.append(effective(**more))
    with FakeRunner(*calls) as runner:
        outcome = run([login(root, fetched)], runner)
    assert outcome.code is ExitCode.INCOMPLETE, outcome.steps
    assert outcome.steps[0].verify == {"password": "open", "why": why}
    assert not (root / DROP_IN).exists()


def test_keys_others_can_write_are_no_key(tmp_path: Path) -> None:
    """StrictModes: a key file the group may write is refused by sshd -- the
    machine does not close on it; the pair: ``StrictModes no`` -- it does."""
    root, fetched, keys = sshd_box(tmp_path / "a", {"password_login": "closed"})
    keys.chmod(0o620)
    calls = [effective(), keygen(keys), effective()]
    with FakeRunner(*calls) as runner:
        outcome = run([login(root, fetched)], runner)
    assert outcome.steps[0].verify == {"password": "open", "why": "strict-modes"}
    calls = [effective(StrictModes="no"), keygen(keys), FakeCall(("sshd", "-t")),
             FakeCall(("systemctl", "is-active", "--quiet", "ssh"), code=3),
             effective(login="no")]  # fmt: skip
    with FakeRunner(*calls) as runner:
        outcome = run([login(root, fetched)], runner)
    assert outcome.code is ExitCode.OK, outcome.steps


def test_a_config_sshd_refuses_takes_the_file_away(tmp_path: Path) -> None:
    root, fetched, keys = sshd_box(tmp_path, {"password_login": "closed"})
    calls = [effective(), keygen(keys), FakeCall(("sshd", "-t"), code=255)]
    with FakeRunner(*calls) as runner:
        outcome = run([login(root, fetched)], runner)
    assert outcome.steps[0].reason is not None
    assert outcome.steps[0].reason.code == "password_login:config-invalid"
    assert not (root / DROP_IN).exists()


def test_a_value_read_before_the_include_wins_and_is_red(tmp_path: Path) -> None:
    """``PasswordAuthentication yes`` in ``sshd_config`` above its ``Include``:
    the machine's file is written and sshd still says yes -- red, named."""
    root, fetched, keys = sshd_box(tmp_path, {"password_login": "closed"})
    calls = [*close_calls(keys, active=False)[:-1], effective(login="yes")]
    with FakeRunner(*calls) as runner:
        outcome = run([login(root, fetched)], runner)
    assert outcome.steps[0].reason is not None
    assert outcome.steps[0].reason.code == "password_login:still-open"


def test_keyboard_interactive_is_a_password_too(tmp_path: Path) -> None:
    """``passwordauthentication no`` with ``kbdinteractiveauthentication yes``
    is a login by password through PAM: open, and closed by the machine."""
    root, fetched, keys = sshd_box(tmp_path, {"password_login": "closed"})
    calls = [effective(login="no", kbd="yes"), *close_calls(keys)[1:]]
    with FakeRunner(*calls) as runner:
        outcome = run([login(root, fetched)], runner)
    assert outcome.code is ExitCode.OK, outcome.steps


def test_already_closed_or_no_sshd_writes_nothing(tmp_path: Path) -> None:
    root, fetched, _ = sshd_box(tmp_path / "a", {"password_login": "closed"})
    with FakeRunner(effective(login="no"), effective(login="no")) as runner:
        outcome = run([login(root, fetched)], runner)
    assert outcome.code is ExitCode.OK and not (root / DROP_IN).exists()
    root, fetched = fetched_with(tmp_path / "b", {"password_login": "closed"})
    with FakeRunner() as runner:
        outcome = run([login(root, fetched)], runner)
    assert outcome.steps[0].verify == {"password": "no sshd"}


def test_doctor_names_the_close_and_writes_nothing(tmp_path: Path) -> None:
    root, fetched, keys = sshd_box(tmp_path, {"password_login": "closed"})
    with FakeRunner(effective(), keygen(keys)) as runner:
        outcome = run([login(root, fetched)], runner, mode="doctor")
    assert [item.reason.code for item in outcome.doctor_diff] == [
        "password_login:close"
    ]
    assert not (root / DROP_IN).exists()


# --- swap: the rest of the grid -------------------------------------------------


def test_no_field_makes_no_swap(tmp_path: Path) -> None:
    root, fetched = fetched_with(tmp_path, None)
    fstab(root)
    with FakeRunner(swapon(), swapon()) as runner:
        outcome = run([swap(root, fetched)], runner)
    assert outcome.code is ExitCode.OK
    assert outcome.steps[0].verify == {"swaps": [], "swap_gib": 0.0, "wanted": "none"}
    assert not (root / SWAPFILE).exists()


def test_a_partition_or_two_swaps_count_and_are_kept(tmp_path: Path) -> None:
    root, fetched = fetched_with(tmp_path, {"swap": "4G"})
    fstab(root, FSTAB_TEXT + "/dev/sdb2 none swap sw 0 0\n/swapfile none swap sw 0 0\n")
    rows = (("/dev/sdb2", "partition", 2 * GIB), (HAND, "file", 2 * GIB))
    with FakeRunner(swapon(*rows), swapon(*rows)) as runner:
        outcome = run([swap(root, fetched)], runner)
    assert outcome.code is ExitCode.OK
    assert outcome.steps[0].verify["swap_gib"] == 4.0
    assert "short_by_gib" not in outcome.steps[0].verify


def test_a_hand_made_swap_not_in_fstab_is_incomplete_and_kept(tmp_path: Path) -> None:
    """Gone after a reboot: exit 2 names it; its fstab is not the machine's."""
    root, fetched = fetched_with(tmp_path, {"swap": "4G"})
    table = fstab(root)
    with FakeRunner(*[swapon((HAND, "file", 4 * GIB))] * 2) as runner:
        outcome = run([swap(root, fetched)], runner)
    assert outcome.code is ExitCode.INCOMPLETE
    assert table.read_text() == FSTAB_TEXT
    [left] = outcome.incomplete
    assert left.reason == Code("swap:foreign-not-in-fstab", {"paths": [HAND]})


def test_without_any_field_the_stack_only_says_what_it_sees(tmp_path: Path) -> None:
    """DM-132 FIX (tier 3: every install of the blank ended at exit 2 -- the
    runner's swap, switched on by its hoster's agent, is in no ``fstab``): no
    ``policies.host`` -- the swap not in ``fstab`` and an ``sshd -T`` that
    refuses are facts, nothing is left undone. The pair: with the field the
    same swap is incomplete (``test_a_hand_made_swap_not_in_fstab_is_…``)."""
    root, fetched = fetched_with(tmp_path, None)
    table = fstab(root)
    (root / SSHD).parent.mkdir(parents=True, exist_ok=True)
    (root / SSHD).write_text("", encoding="utf-8")
    meminfo(root, 15.3, 3)
    runner_swap = ("/mnt/swapfile", "file", 3 * GIB)
    refused = FakeCall(("sshd", "-T", *AS_ROOT), code=255)
    with FakeRunner(swapon(runner_swap), swapon(runner_swap), refused) as runner:
        outcome = run(host_policy_steps(root, fetched=fetched), runner)
    assert outcome.code is ExitCode.OK, (outcome.steps, outcome.incomplete)
    assert outcome.incomplete == ()
    facts = {step.name: step.verify for step in outcome.steps}
    assert facts["swap"]["not_in_fstab"] == ["/mnt/swapfile"]
    assert facts["swap"]["wanted"] == "none"
    assert facts["password_login"] == {"password": "unread"}
    assert table.read_text() == FSTAB_TEXT and not (root / SWAPFILE).exists()


def test_the_machine_s_swap_on_without_its_line_gets_it(tmp_path: Path) -> None:
    """An ``act`` cut after ``swapon``: the line is written, no second file."""
    root, fetched = fetched_with(tmp_path, {"swap": "1M"})
    table = fstab(root)
    mine = str(root / SWAPFILE)
    with FakeRunner(*[swapon((mine, "file", 2**20))] * 2) as runner:
        outcome = run([swap(root, fetched)], runner)
    assert outcome.code is ExitCode.OK
    assert table.read_text() == f"{FSTAB_TEXT}{mine} none swap sw 0 0\n"


def test_the_machine_s_file_off_is_made_again_whole(tmp_path: Path) -> None:
    """An ``act`` cut before ``swapon``, its line already written: the file is
    made again, the line stays one."""
    root, fetched = fetched_with(tmp_path, {"swap": "1M"})
    own = root / SWAPFILE
    table = fstab(root, f"{FSTAB_TEXT}{own} none swap sw 0 0\n")
    own.parent.mkdir(parents=True, exist_ok=True)
    own.write_bytes(b"half")
    mine = str(own)
    calls = [swapon(), FakeCall(("mkswap", mine)), FakeCall(("swapon", mine)),
             swapon((mine, "file", 2**20))]  # fmt: skip
    with FakeRunner(*calls) as runner:
        outcome = run([swap(root, fetched)], runner)
    assert outcome.code is ExitCode.OK
    assert own.stat().st_size == 2**20
    assert table.read_text().count(mine) == 1


def test_no_room_beside_the_swap_is_red_before_the_file(tmp_path: Path) -> None:
    root, fetched = fetched_with(tmp_path, {"swap": "1M"})
    fstab(root)
    with FakeRunner(swapon()) as runner:
        outcome = run([swap(root, fetched, free=10**9)], runner)
    assert outcome.steps[0].reason is not None
    assert outcome.steps[0].reason.code == "swap:disk-low"
    assert not (root / SWAPFILE).exists()
    assert (root / FSTAB).read_text() == FSTAB_TEXT


def test_the_room_counts_the_swap_itself(tmp_path: Path) -> None:
    """The floor of the disk alone is there; with the swap beside it, not."""
    root, fetched = fetched_with(tmp_path, {"swap": "64M"})
    fstab(root)
    disk = os.statvfs(tmp_path)
    free_gib = disk.f_bavail * disk.f_frsize / GIB
    with FakeRunner(swapon()) as runner:
        outcome = run([swap(root, fetched, free=free_gib - 0.01)], runner)
    assert outcome.steps[0].reason is not None
    assert outcome.steps[0].reason.code == "swap:disk-low"


def test_a_swap_not_on_after_swapon_is_red(tmp_path: Path) -> None:
    """``verify`` reads ``swapon --show``, not the exit of ``swapon``."""
    root, fetched = fetched_with(tmp_path, {"swap": "1M"})
    fstab(root)
    mine = str(root / SWAPFILE)
    calls = [swapon(), FakeCall(("mkswap", mine)), FakeCall(("swapon", mine)), swapon()]
    with FakeRunner(*calls) as runner:
        outcome = run([swap(root, fetched)], runner)
    assert outcome.steps[0].reason == Code("swap:not-on", {"path": mine})


def test_the_machine_s_file_is_read_before_cloud_init_s() -> None:
    """sshd takes the first value it reads: the machine's file sorts before
    ``50-cloud-init.conf`` of Ubuntu's cloud images."""
    assert sorted([DROP_IN.name, "50-cloud-init.conf"])[0] == DROP_IN.name


def test_doctor_names_the_swap_and_makes_nothing(tmp_path: Path) -> None:
    root, fetched = fetched_with(tmp_path, {"swap": "1M"})
    fstab(root)
    with FakeRunner(swapon()) as runner:
        outcome = run([swap(root, fetched)], runner, mode="doctor")
    assert [item.reason.code for item in outcome.doctor_diff] == ["swap:make"]
    assert not (root / SWAPFILE).exists()


# --- the passport ---------------------------------------------------------------


def test_the_passport_takes_a_size_and_closed_only() -> None:
    assert HostPolicy.model_validate({"swap": "4G", "password_login": "closed"})
    for bad in ({"swap": "0"}, {"swap": "4GB"}, {"password_login": "open"},
                {"swap": 4}, {"other": "x"}):  # fmt: skip
        with pytest.raises(ValidationError):
            HostPolicy.model_validate(bad)


# --- the stack ------------------------------------------------------------------


def test_the_ladder_of_policies_host(tmp_path: Path) -> None:
    """Swap first, memory after it -- the swap it made counts -- and the login
    last."""
    names = [s.name for s in host_policy_steps(tmp_path, fetched=Fetched())]
    assert names == ["swap", "memory", "password_login"]


def test_memory_without_meminfo_is_red(tmp_path: Path) -> None:
    with FakeRunner() as runner:
        outcome = run([Memory(tmp_path)], runner)
    assert outcome.steps[0].reason == Code("memory:meminfo-unreadable")


def test_memory_on_its_floor_passes(tmp_path: Path) -> None:
    meminfo(tmp_path, MIN_RAM_GIB, MIN_MEMORY_GIB - MIN_RAM_GIB)
    with FakeRunner() as runner:
        outcome = run([Memory(tmp_path)], runner)
    assert outcome.code is ExitCode.OK, outcome.steps


# --- nothing to restore past an empty database ----------------------------------


@pytest.fixture
def app() -> Iterator[LiveApp]:
    yield from live()


def _migrate(root: Path, port: int) -> Migrate:
    cs = compose(root, port)
    return Migrate(
        cs.stack, cs.entry, release=cs.release, ref=cs.ref, commit=cs.commit, root=root
    )


def test_probe_DM_132_a_first_install_past_migrate_has_nothing_to_restore(
    tmp_path: Path, app: LiveApp
) -> None:
    """No app answers and ``alembic current`` reads no revision: a red step
    after the migration says ``restore/empty``. The pair: the database had a
    revision -- ``restore/needed``, as before."""
    cs = compose(tmp_path, app.port)

    def first(*current: str) -> list[FakeCall]:
        return [
            image_call(cs, "app", APP_IMAGE),
            *heads_call(cs, APP_IMAGE, f"{HEAD} (head)"),
            *observe_calls(cs, running=False),
            alembic_call(cs, "current", *current, deps=True),
            migrate_call(cs),
            alembic_call(cs, "current", f"{HEAD} (head)", deps=True),
        ]

    red_after = ScriptedStep("up", 13, Journal(), fact={})
    with FakeRunner(*first()) as runner:
        outcome, _ = run_entry([_migrate(tmp_path, app.port), red_after], runner)
    assert outcome.needs_restore and outcome.restore_empty
    report = build(outcome).report
    assert [i.model_dump() for i in report.incomplete] == [
        {"what": "restore", "code": "empty"}
    ]
    with FakeRunner(*first("0000")) as runner:
        outcome, _ = run_entry([_migrate(tmp_path, app.port), red_after], runner)
    assert outcome.needs_restore and not outcome.restore_empty
    report = build(outcome).report
    assert [i.model_dump() for i in report.incomplete] == [
        {"what": "restore", "code": "needed"}
    ]


def test_one_crossing_with_data_is_a_restore(tmp_path: Path) -> None:
    """Two points crossed, one of them over data (``destroy`` of
    ``reinstall``, or a second entry with a database) -- ``needed``."""
    journal = Journal()
    steps = [
        ScriptedStep("a", 1, journal, point_of_no_return=True, crossed_data=False),
        ScriptedStep("b", 2, journal, point_of_no_return=True),
        ScriptedStep("c", 3, journal, fact={}),
    ]
    with FakeRunner() as runner:
        outcome = run(steps, runner)
    assert outcome.needs_restore and not outcome.restore_empty


# --- the refusal of destroy -----------------------------------------------------


def test_probe_DM_132_destroy_refusal_reads_with_a_dash(tmp_path: Path) -> None:
    """The words a person reads: a dash, not two hyphens (rules 5)."""
    _, fetched = fetched_with(tmp_path, None)
    with pytest.raises(Refused) as caught:
        _named("destroy", "box-2", fetched.passport)
    name = fetched.passport.server.name if fetched.passport else ""
    assert str(caught.value) == (
        f"destroy: 'box-2' is not the server's name — --confirm {name}"
    )
