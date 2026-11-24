"""DM-190, delivery B: the edges of a run, each a code instead of an exception.

E3 a journal that failed a write; E4 ``unreachable`` in every step that goes
to a repository by a key; E5 a host key that is not the machine's; E8 an old
verdict and a journal with a damaged header in ``report``; E9 a manifest not
in UTF-8 and a verdict with no journal; E10 a rejected passport copy and a
run that replaces it; E12 what dpkg left half done. E14 and E15 are in
``test_steps_egress.py`` and ``test_verbs_admin.py``.
"""

import io
import json
from pathlib import Path

import pytest
from data_support import blank_box
from test_steps_host import AUDIT, BUILDX, active, box, call, dpkg
from test_steps_host import run as run_host
from test_steps_keys import ADDRESS

from pridem.events import Code, LogLine, Secrets, StepStarted
from pridem.report.catalog import ENGLISH, text
from pridem.runner import FakeCall, FakeRunner, Stream
from pridem.stacks.loader import ContractError
from pridem.state import Box, JournalHeader, read_journal
from pridem.steps.base import StepContext, StepFailed
from pridem.steps.git import git_env, repo
from pridem.steps.host import HOST_PACKAGES, ProvisionHost, apt_env
from pridem.steps.keys import DeployKey, has_access
from pridem.steps.passport import PASSPORT_COPY, FetchPassport
from pridem.steps.sources import CheckLock, FetchPackages, FetchRoot, FetchServices
from pridem.verbs.base import Context
from pridem.verbs.check import _manifest
from pridem.verbs.run import read_copy


def _header(run_id: str = "2026-11-25T10:00:00Z-a3f9") -> JournalHeader:
    return JournalHeader.model_validate(
        {
            "run_id": run_id,
            "verb": "update",
            "mode": "deploy",
            "args": {},
            "actor": {"type": "engineer", "via": "local"},
            "started": "2026-11-25T10:00:00Z",
            "composition_before": {"pridem": "0.1.9"},
        }
    )


# --- E3 ---------------------------------------------------------------------------


def test_a_journal_that_failed_a_write_writes_nothing_more(tmp_path: Path) -> None:
    """A full disk tears a line: the sink writes nothing after it -- the torn
    line stays the last, the reader drops it, no ``seq`` is written twice."""
    from datetime import UTC, datetime

    box_ = Box(tmp_path)
    with box_.lock("test"):
        sink = box_.open_journal(_header(), Secrets(()))
        sink.emit(StepStarted("main", "blank", "a", 1, datetime.now(UTC)))
        real = sink._handle.write
        torn = {"done": False}

        def full(data: str) -> int:
            if not torn["done"]:
                torn["done"] = True
                real(data[: len(data) // 2])
                raise OSError(28, "No space left on device")
            return real(data)

        sink._handle.write = full  # type: ignore[method-assign]
        with pytest.raises(OSError):
            sink.emit(LogLine("main", "blank", "a", Stream.STDOUT, "x" * 64))
        with pytest.raises(OSError):  # nothing more, not even a later line
            sink.emit(LogLine("main", "blank", "a", Stream.STDOUT, "after"))
        with pytest.raises(OSError):
            sink.close()
    path = box_.journals / "2026-11-25T10:00:00Z-a3f9.jsonl"
    lines = path.read_text().splitlines()
    seqs = [json.loads(line)["seq"] for line in lines[:-1]]
    assert seqs == list(range(1, len(seqs) + 1))
    assert "after" not in path.read_text()
    found = read_journal(path)
    assert found.torn and found.damaged_at is None


# --- E4, E5 -----------------------------------------------------------------------


@pytest.mark.parametrize(
    "step",
    [DeployKey, FetchRoot, CheckLock, FetchServices, FetchPackages, FetchPassport],
)
def test_every_step_that_goes_to_a_repository_by_a_key_has_its_codes(
    step: type,
) -> None:
    """``by_key`` waits for a fresh key in each of these steps, and
    ``has_access`` can say ``unreachable`` or ``host-key-mismatch`` there:
    both are codes of the step (E4)."""
    codes = step.codes  # type: ignore[attr-defined]
    assert {"unreachable", "host-key-mismatch"} <= set(codes)


def test_a_host_key_not_the_machines_is_refused_at_once(tmp_path: Path) -> None:
    """``Host key verification failed`` is no key to wait for: refused at once
    with its code, never 1800 s under the lock (E5). The pair: the server's
    own refusal of the key is still a ``False`` to wait on."""
    found = repo(ADDRESS)
    argv = ("git", "ls-remote", "--heads", found.url())
    mismatch = FakeCall(
        argv,
        code=128,
        lines=((Stream.STDERR, "Host key verification failed."),),
        env=git_env(tmp_path),
    )
    with FakeRunner(mismatch) as runner:
        ctx = StepContext(runner, "install", "test", "blank", lambda *_: None)
        with pytest.raises(StepFailed) as refused:
            has_access(ctx, tmp_path, found)
    assert refused.value.reason == Code("host-key-mismatch", {"repo": ADDRESS})
    denied = FakeCall(
        argv,
        code=128,
        lines=((Stream.STDERR, "git@github.com: Permission denied (publickey)."),),
        env=git_env(tmp_path),
    )
    with FakeRunner(denied) as runner:
        ctx = StepContext(runner, "install", "test", "blank", lambda *_: None)
        assert has_access(ctx, tmp_path, found) is False


# --- E8 ---------------------------------------------------------------------------


def test_an_old_verdicts_code_whose_words_need_more_is_said_as_it_is() -> None:
    """A code whose words now name a value the old verdict does not have:
    said by ``@unknown``, never a ``KeyError`` (E8)."""
    said = text(ENGLISH, "command-failed", {"argv": ["x"]})
    assert "command-failed" in said and "argv" in said


def test_report_of_a_journal_with_a_damaged_header_prints_the_verdict(
    tmp_path: Path,
) -> None:
    """``report`` of a run whose journal's header is damaged: the verdict
    with no lines -- never ``JournalDamaged`` out of the command (E8)."""
    from pridem.cli import run

    blank_box(tmp_path)
    home = tmp_path / "opt" / "pridem"
    out, err = io.StringIO(), io.StringIO()
    with FakeRunner() as runner:
        run(["--json", "status"], root=home, out=out, err=err, runner=runner,
            fs_root=tmp_path)  # fmt: skip
    run_id = json.loads(out.getvalue())["run_id"]
    (home / "journal" / f"{run_id}.jsonl").write_text("{not json\n")
    out, err = io.StringIO(), io.StringIO()
    code = run(["report", run_id], root=home, out=out, err=err,
               runner=FakeRunner(), fs_root=tmp_path)  # fmt: skip
    assert code == 0, err.getvalue()
    assert run_id in out.getvalue() or "status" in out.getvalue()


# --- E9 ---------------------------------------------------------------------------


def test_a_manifest_not_in_utf8_is_refused_by_its_code(tmp_path: Path) -> None:
    manifest = tmp_path / "primer-package.yaml"
    manifest.write_bytes(b"name: \xff\xfe\n")
    with pytest.raises(StepFailed) as refused:
        _manifest("skin", manifest)
    assert refused.value.reason == Code(
        "manifest-unreadable", {"slot": "skin", "cause": "not-utf-8"}
    )


def test_a_red_verdict_with_no_journal_names_no_log() -> None:
    """``pridem check`` writes no journal: its red verdict names no
    ``/opt/pridem/None`` (E9)."""
    from pridem.report.render import closing
    from pridem.report.schema import Verdict

    verdict = Verdict.model_validate(
        {
            "schema": 1,
            "run_id": "2026-11-25T10:00:00Z-a3f9",
            "verb": "check",
            "args": {},
            "actor": {"type": "engineer", "via": "local"},
            "started": "2026-11-25T10:00:00Z",
            "finished": "2026-11-25T10:00:01Z",
            "exit_code": 1,
            "result": "red",
            "composition_before": {"pridem": "0.1.9"},
            "composition_after": {"pridem": "0.1.9"},
            "steps": [],
            "report": {"failures": [], "incomplete": []},
        }
    )
    said = "\n".join(closing(verdict, ENGLISH))
    assert "None" not in said and "Full log" not in said


# --- E10 --------------------------------------------------------------------------


def test_a_rejected_copy_is_no_obstacle_to_a_run_that_replaces_it(
    tmp_path: Path,
) -> None:
    """A copy the loader rejects stops every command -- but one given a new
    passport, which is what replaces it (E10). The pair: without a new
    passport it is refused as before."""
    blank_box(tmp_path)
    (tmp_path / PASSPORT_COPY).write_text("schema: 1\nnot: a passport\n")
    ctx = Context(
        root=tmp_path / "opt" / "pridem",
        out=io.StringIO(),
        err=io.StringIO(),
        runner=FakeRunner(),
        fs_root=tmp_path,
    )
    assert read_copy(ctx, replaced=True).passport is None
    with pytest.raises(ContractError):
        read_copy(ctx)


# --- E12 --------------------------------------------------------------------------


def test_what_dpkg_left_half_done_is_configured_first(tmp_path: Path) -> None:
    """Every package there, and ``dpkg --audit`` says packages are half done:
    ``check`` asks ``configure``, ``act`` runs ``dpkg --configure -a`` and no
    ``apt-get``, ``verify`` reads the audit empty. The pair: the audit still
    says so -- ``dpkg-unconfigured``."""
    root = box(tmp_path)
    packages = [dpkg(p) for p in HOST_PACKAGES]
    half = call("dpkg", "--audit", lines=("The following packages are only half",))
    tail = [
        active("docker", True),
        call("docker", "version", "--format", "{{.Server.Version}}", lines=("27.5.1",)),
        BUILDX,
    ]
    configure = FakeCall(("dpkg", "--configure", "-a"), env=apt_env())
    outcome = run_host(
        [ProvisionHost(root)], [*packages, half, configure, *packages, AUDIT, *tail]
    )
    assert outcome.code.value == 0, outcome.steps
    red = run_host([ProvisionHost(root)], [*packages, half, configure, *packages, half])
    assert red.steps[0].reason == Code("provision_host:dpkg-unconfigured")
