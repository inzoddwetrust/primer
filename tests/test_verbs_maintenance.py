"""The verbs ``gc`` and ``ssl renew`` (DM-20) behind the CLI: one step as the
whole plan, under the box lock, a journal and one verdict; ``--timer`` makes
the machine the actor. The file system root is the test's directory
(``fs_root``), the box root ``<fs_root>/opt/pridem``.
"""

import io
import json
from pathlib import Path

from edge_support import DOMAINS, Mixed, passport, self_signed_pair
from env_support import box as passport_box
from env_support import passport_data

from pridem.cli import run
from pridem.report.schema import Verdict
from pridem.runner import FakeCall, FakeRunner, Runner, Stream
from pridem.state import Box
from pridem.steps.passport import PASSPORT_COPY
from pridem.steps.ssl import cert_path, key_path

DF = ("docker", "system", "df", "--format", "{{json .}}")
CONTAINERS = ("docker", "container", "ls", "--all", "--quiet", "--no-trunc")
IMAGES = (
    "docker",
    "image",
    "ls",
    "--quiet",
    "--no-trunc",
    "--filter",
    "label=pridem.commit",
)


def df() -> FakeCall:
    row = {"Type": "Local Volumes", "TotalCount": "2", "Size": "1MB", "Active": "1"}
    return FakeCall(DF, lines=((Stream.STDOUT, json.dumps(row)),))


def empty_gc() -> list[FakeCall]:
    return [df(), FakeCall(CONTAINERS), FakeCall(IMAGES), df()]


def cli(argv: list[str], fs_root: Path, runner: Runner) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    code = run(
        argv,
        root=fs_root / "opt" / "pridem",
        out=out,
        err=err,
        runner=runner,
        fs_root=fs_root,
    )
    return code, out.getvalue(), err.getvalue()


def verdicts(fs_root: Path) -> list[Verdict]:
    history = fs_root / "opt" / "pridem" / "history"
    return [
        Verdict.model_validate_json(path.read_text(encoding="utf-8"))
        for path in sorted(history.glob("*.json"))
    ]


def test_gc_writes_one_verdict_and_its_journal(tmp_path: Path) -> None:
    root, fetched = passport_box(tmp_path, passport_data())
    with FakeRunner(*empty_gc()) as runner:
        code, out, err = cli(["gc"], root, runner)
    assert (code, err) == (0, "")
    [verdict] = verdicts(root)
    assert (verdict.verb, verdict.result, verdict.args) == ("gc", "green", {})
    assert (verdict.actor.type, verdict.actor.via) == ("engineer", "local")
    assert fetched.passport is not None
    assert verdict.passport_version == fetched.passport.version
    assert [(s.stack, s.name, s.phase) for s in verdict.steps] == [
        ("box", "gc", "main")
    ]
    assert out.startswith("gc → green · ")
    journal = root / "opt" / "pridem" / verdict.log_ref
    header = json.loads(journal.read_text(encoding="utf-8").splitlines()[0])
    assert (header["verb"], header["mode"]) == ("gc", "gc")


def test_a_timer_makes_the_machine_the_actor(tmp_path: Path) -> None:
    root, _ = passport_box(tmp_path, passport_data())
    with FakeRunner(*empty_gc()) as runner:
        code, out, _ = cli(["--timer", "--json", "gc"], root, runner)
    assert code == 0
    printed = Verdict.model_validate_json(out)
    assert (printed.actor.type, printed.actor.via) == ("machine", "timer")
    assert verdicts(root) == [printed]


def test_timer_is_refused_for_verbs_no_timer_runs(tmp_path: Path) -> None:
    root, _ = passport_box(tmp_path, passport_data())
    for argv in (["--timer", "version"], ["--timer", "status"]):
        with FakeRunner() as runner:
            code, out, err = cli(argv, root, runner)
        assert (code, out) == (1, ""), argv
        assert "--timer does not apply" in err
    assert not (root / "opt" / "pridem" / "history").exists()


def test_a_busy_box_refuses_gc_and_renew_before_anything_runs(tmp_path: Path) -> None:
    root, _ = passport_box(tmp_path, passport_data())
    box = Box(root / "opt" / "pridem")
    with box.lock("deploy"):  # the same flock as another process would hold
        for argv in (["gc"], ["ssl", "renew"]):
            with FakeRunner() as runner:  # nothing runs
                code, out, err = cli(argv, root, runner)
            assert (code, out) == (1, "")
            assert "the box is busy" in err and "deploy" in err
    assert verdicts(root) == []
    # the pair: the lock released, gc runs and writes its verdict
    with FakeRunner(*empty_gc()) as runner:
        assert cli(["gc"], root, runner)[0] == 0
    assert [v.verb for v in verdicts(root)] == ["gc"]


def test_gc_without_a_passport_is_red_with_its_code(tmp_path: Path) -> None:
    root, _ = passport_box(tmp_path, passport_data())
    (root / PASSPORT_COPY).unlink()
    with FakeRunner() as runner:
        code, _, _ = cli(["gc"], root, runner)
    assert code == 1
    [verdict] = verdicts(root)
    [step] = verdict.steps
    assert step.reason is not None and step.reason.code == "gc:no-passport"
    assert "passport_version" not in verdict.model_dump_json()


def test_ssl_renew_on_a_self_signed_box(tmp_path: Path) -> None:
    root, _ = passport(tmp_path, ssl="self-signed")
    cert, key = self_signed_pair(tmp_path, list(DOMAINS.values()))
    cert_path(root).parent.mkdir(parents=True)
    cert_path(root).write_text(cert)
    key_path(root).write_text(key)
    key_path(root).chmod(0o600)
    with Mixed() as runner:
        code, out, err = cli(["--timer", "ssl", "renew"], root, runner)
    assert (code, err) == (0, "")
    assert out.startswith("ssl renew → green · ")
    [verdict] = verdicts(root)
    assert (verdict.verb, verdict.actor.via) == ("ssl renew", "timer")
    [step] = verdict.steps
    assert (step.stack, step.name) == ("edge", "ssl_renew")
    assert step.verify is not None and step.verify["mode"] == "self-signed"


def test_ssl_takes_renew_and_nothing_else(tmp_path: Path) -> None:
    root, _ = passport_box(tmp_path, passport_data())
    for argv in (["ssl"], ["ssl", "issue"], ["ssl", "renew", "now"]):
        with FakeRunner() as runner:
            code, out, err = cli(argv, root, runner)
        assert (code, out) == (1, ""), argv
        assert err.startswith("pridem: ssl"), err
    assert not (root / "opt" / "pridem" / "history").exists()
