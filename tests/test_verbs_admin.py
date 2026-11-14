"""DM-86, pass 4: ``logs``, ``start|stop|restart``, ``destroy --all``,
``db connect`` and its logs in ``gc``; ``Runner.interactive``."""

import json
import os
import sys
import textwrap
from collections.abc import Sequence
from itertools import count
from pathlib import Path

import pytest
import yaml
from data_support import STACK, blank_box
from plan_support import ListSink
from test_verbs_data import (
    Copying,
    _cli,
    _service,
    _verdict,
    compose,
    config_call,
    lines,
    running_call,
)
from test_verbs_project import MINTED, _box

from pridem.plan import Plan, StackSteps
from pridem.report.codes import ExitCode
from pridem.runner import FakeCall, FakeRunner
from pridem.state import Box
from pridem.steps.compose import ComposeStack
from pridem.steps.gc import CONNECT_DIR, CONNECT_KEEP_DAYS, Gc
from pridem.steps.passport import Fetched

LOGS = ("logs", "--no-color", "--no-log-prefix")
RECORDS = [
    json.dumps({"level": "error", "status": 500, "event": "a", "msg": "boom"}),
    json.dumps({"level": "error", "status": 404, "event": "b"}),
    json.dumps({"level": "info", "status": 500, "event": "c"}),
    json.dumps({"level": "info", "event": "d"}),
    json.dumps({"level": "error", "event": "f"}),  # no status: not printed
    "plain text, not JSON",
    json.dumps({"level": "error", "status": 500, "event": "e", "token": MINTED}),
    "[1, 2]",
]


def _logs(cs: ComposeStack, *extra: str, service: str | None = None) -> FakeCall:
    named = () if service is None else (service,)
    return FakeCall(
        tuple(cs.argv(*LOGS, *extra, operands=named)), lines=lines(*RECORDS)
    )


def _out(fs_root: Path, argv: list[str], runner: FakeRunner) -> tuple[int, str, str]:
    """A verb with no verdict: ``--json`` changes nothing in what it prints."""
    import io

    from pridem.cli import run

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


# --- logs --------------------------------------------------------------------


def test_probe_DM_22_logs_filter_by_json_fields(tmp_path: Path) -> None:
    """``logs blank level=error status=500``: the JSON lines where both fields
    hold -- a number compared by its JSON text -- and none other; a line
    without a field, a line that is no JSON object, are not printed and are
    counted; the box's secret in a printed line is cleaned out (contract 2
    rule 2: the console of the machine). No verdict: nothing in ``history/``."""
    cs = _box(tmp_path)
    with FakeRunner(_logs(cs)) as runner:
        code, out, err = _out(
            tmp_path, ["logs", STACK, "level=error", "status=500"], runner
        )
    assert code == 0, err
    printed = out.splitlines()
    assert [json.loads(line)["event"] for line in printed] == ["a", "e"]
    assert MINTED not in out
    assert "6 line(s) not matching" in err
    assert not (tmp_path / "opt" / "pridem" / "history").exists() or not list(
        (tmp_path / "opt" / "pridem" / "history").iterdir()
    )


def test_logs_without_a_filter_print_every_line_and_take_the_service_and_follow(
    tmp_path: Path,
) -> None:
    """No filter: every line, JSON or not, the secret cleaned. A first word
    without ``=`` is the service; ``-f`` and ``--tail`` go to compose."""
    cs = _box(tmp_path)
    with FakeRunner(_logs(cs, "-f", "--tail", "50", service="app")) as runner:
        code, out, err = _out(
            tmp_path, ["logs", STACK, "app", "-f", "--tail", "50"], runner
        )
    assert code == 0, err
    assert len(out.splitlines()) == len(RECORDS)
    assert "plain text, not JSON" in out and MINTED not in out
    assert "not matching" not in err


@pytest.mark.parametrize(
    ("argv", "said"),
    [
        (["logs", "ghost"], "runs no entry ghost"),
        (["logs", STACK, "=x"], "is not <field>=<value>"),
        (["logs", STACK, "app", "level"], "is not <field>=<value>"),
        (["logs", STACK, "--tail", "x"], "a number of lines"),
    ],
)
def test_logs_refuses_before_the_run(
    tmp_path: Path, argv: list[str], said: str
) -> None:
    _box(tmp_path)
    with FakeRunner() as runner:
        code, out, err = _out(tmp_path, argv, runner)
    assert (code, out) == (1, "") and said in err


# --- start, stop, restart ------------------------------------------------------------


def _two_entries(tmp_path: Path) -> tuple[ComposeStack, ComposeStack]:
    """The blank and the service ``comms`` on the box."""
    blank_box(tmp_path)
    _service(tmp_path, "comms", with_database=True)
    release = (tmp_path / "opt" / "comms" / "current").resolve()
    from pridem.stacks.schema import load_primer_yaml

    made = load_primer_yaml(release / "primer.yaml")
    comms = ComposeStack(made, "comms", release, release.name, release.name, tmp_path)
    return compose(tmp_path), comms


COMMS_CONFIG = {"services": {"app": {"image": "a"}}}
BLANK = ("app", "frontend", "postgres")


def _action_calls(
    cs: ComposeStack, action: str, services: Sequence[str], document: object
) -> list[FakeCall]:
    up = action != "stop"
    return [
        config_call(cs, document),  # type: ignore[arg-type]
        FakeCall(tuple(cs.argv(action, operands=services))),
        *(running_call(cs, s, *(["c"] if up else [])) for s in services),
    ]


@pytest.mark.parametrize("action", ["start", "restart", "stop"])
def test_services_go_up_before_the_product_and_down_after_it(
    tmp_path: Path, action: str
) -> None:
    """``start`` and ``restart``: the service, then the product; ``stop``: the
    product, then the service -- each read back (running, or not)."""
    blank, comms = _two_entries(tmp_path)
    from test_verbs_data import CONFIG

    first = _action_calls(comms, action, ["app"], COMMS_CONFIG)
    second = _action_calls(blank, action, BLANK, CONFIG)
    script = [*second, *first] if action == "stop" else [*first, *second]
    with FakeRunner(*script) as runner:
        code, out, _ = _cli(tmp_path, [action], runner)
    verdict = _verdict(out)
    assert code == 0, verdict.steps
    order = [s.stack for s in verdict.steps]
    assert order == (["blank", "comms"] if action == "stop" else ["comms", "blank"])
    assert {s.name for s in verdict.steps} == {f"service_{action}"}
    up = [] if action == "stop" else ["app", "frontend", "postgres"]
    assert verdict.steps[order.index("blank")].verify == {
        "stack": "blank",
        "services": list(BLANK),
        "running": up,
    }


@pytest.mark.parametrize(("action", "ids"), [("stop", ["c"]), ("start", [])])
def test_a_service_in_the_wrong_state_after_the_action_is_red(
    tmp_path: Path, action: str, ids: list[str]
) -> None:
    blank_box(tmp_path)
    cs = compose(tmp_path)
    script = [
        FakeCall(tuple(cs.argv(action, operands=("app",)))),
        running_call(cs, "app", *ids),
    ]
    with FakeRunner(*script) as runner:
        code, out, _ = _cli(tmp_path, [action, STACK, "app"], runner)
    reason = _verdict(out).steps[0].reason
    assert code == 1 and reason is not None
    assert reason.code == f"service_{action}:failed"


def test_the_jobs_of_an_entry_are_not_started(tmp_path: Path) -> None:
    """A job does not live between deploys: ``start`` leaves it out."""
    blank_box(tmp_path)
    release = (tmp_path / "opt" / STACK / "current").resolve()
    primer = yaml.safe_load((release / "primer.yaml").read_text())
    primer["stacks"][STACK]["jobs"] = {"init": {"service": "init"}}
    (release / "primer.yaml").write_text(yaml.safe_dump(primer, sort_keys=False))
    cs = compose(tmp_path)
    from test_verbs_data import CONFIG

    document = json.loads(json.dumps(CONFIG))
    document["services"]["init"] = {"image": "j"}
    with FakeRunner(*_action_calls(cs, "start", BLANK, document)) as runner:
        code, out, _ = _cli(tmp_path, ["start", STACK], runner)
    assert code == 0, _verdict(out).steps


@pytest.mark.parametrize(
    ("argv", "said"),
    [(["stop", "ghost"], "runs no entry ghost")],
)
def test_start_stop_restart_refuse_an_unknown_entry(
    tmp_path: Path, argv: list[str], said: str
) -> None:
    blank_box(tmp_path)
    with FakeRunner() as runner:
        code, out, err = _cli(tmp_path, argv, runner)
    assert (code, out) == (1, "") and said in err


# --- destroy --all -------------------------------------------------------------------


@pytest.mark.parametrize("role", ["test", "preview", "prod"])
def test_probe_DM_22_destroy_all_requires_server_name(
    tmp_path: Path, role: str
) -> None:
    """``--all`` wipes people's files: the server's name on any role, checked
    under the lock (DM-24) -- without it or with another, refused: nothing ran
    (an empty script), no journal. The pair at the step level: the persistent
    volume is named to ``docker volume rm`` (below)."""
    blank_box(tmp_path, role=role, name="box-1")
    journal = tmp_path / "opt" / "pridem" / "journal"
    for confirm in ([], ["--confirm", "box-2"]):
        with FakeRunner() as runner:
            code, out, err = _cli(tmp_path, ["destroy", "--all", *confirm], runner)
        assert (code, out) == (1, ""), err
        assert "--confirm box-1" in err
        assert not journal.exists() or not list(journal.iterdir())


def test_destroy_all_wipes_the_persistent_volume_its_record_and_minted(
    tmp_path: Path,
) -> None:
    """At the step level: the volume of the persistent entry is named to
    ``docker volume rm`` with the others, ``kept-volumes.json`` goes, the fact
    names it wiped; ``remove_files`` takes ``minted.yaml`` too. The pair --
    ``destroy`` without ``--all`` -- is the probe of pass 3, the volume kept."""
    from test_steps_destroy import box_with_release, docker, listed

    from pridem.steps.destroy import KEPT, destroy_steps

    root, box = box_with_release(tmp_path, {"storage"})
    (box.root / KEPT).write_text(
        json.dumps({"schema": 1, "volumes": {"files": "storage"}})
    )
    minted = root / "opt" / "aivis" / "env" / "minted.yaml"
    minted.parent.mkdir(parents=True, exist_ok=True)
    minted.write_text("SECRET_KEY: " + "s" * 43 + "\n")
    seen = listed(("c1",), ("pridem",), ("files\tstorage", "db\taivis"), ("sha256:1",))
    script = [
        docker(),
        *seen,
        docker(),
        *seen,
        FakeCall(("docker", "rm", "-f", "c1")),
        FakeCall(("docker", "volume", "rm", "db", "files")),
        FakeCall(("docker", "network", "rm", "pridem")),
        FakeCall(("docker", "image", "rm", "-f", "sha256:1")),
        *listed(),
    ]
    ticks = count()
    with box.lock("destroy"), FakeRunner(*script) as runner:
        outcome = Plan(
            [
                StackSteps(
                    "destroy",
                    destroy_steps(root, box=box, everything=True)[:2],
                    root=True,
                )
            ],
            mode="destroy",
            role="test",
            runner=runner,
            sink=ListSink(),
            clock=lambda: float(next(ticks)),
        ).run()
    assert outcome.code is ExitCode.OK, outcome.steps
    assert outcome.steps[0].verify == {
        "containers": 0,
        "networks": 0,
        "images": 0,
        "kept_volumes": [],
        "wiped_volumes": ["files"],
    }
    assert not (box.root / KEPT).exists()
    assert not minted.exists()
    assert (
        outcome.steps[1].verify is not None and outcome.steps[1].verify["all"] is True
    )


# --- db connect ----------------------------------------------------------------------


def _connect_calls(
    cs: ComposeStack, kept: Path | None, code: int = 0
) -> list[FakeCall]:
    from test_verbs_data import CONFIG

    inside = "/tmp/pridem-connect-STAMP.log"  # noqa: S108 -- in the container
    session = cs.argv(
        "exec", "-T", "-e", "PGOPTIONS=-c default_transaction_read_only=on",
        operands=("postgres", "psql", "-U", "blank", "-d", "blank", "-L", inside),
    )  # fmt: skip
    calls = [
        FakeCall(
            tuple(cs.product_argv("config", "--format", "json")),
            lines=lines(json.dumps(CONFIG)),
        ),
        running_call(cs, "postgres", "c-pg"),
        FakeCall(tuple(session), code=code),
    ]
    if kept is not None:
        calls += [
            FakeCall(
                tuple(
                    cs.argv(
                        "cp",
                        operands=(
                            f"postgres:{inside}",
                            str(kept),
                        ),
                    )
                )
            ),
            FakeCall(
                tuple(
                    cs.argv(
                        "exec",
                        "-T",
                        operands=(
                            "postgres",
                            "rm",
                            "-f",
                            inside,
                        ),
                    )
                )
            ),
        ]
    return calls


class _Stamped(Copying):
    """The script names the session's time ``STAMP``: the real time is put in
    its place as the calls arrive."""

    def __init__(self, *calls: FakeCall, stamp: str) -> None:
        self.stamp = stamp
        fixed = [
            FakeCall(
                tuple(a.replace("STAMP", stamp) for a in c.argv),
                lines=c.lines,
                code=c.code,
            )
            for c in calls
        ]
        super().__init__(*fixed, content=b"SELECT 1;\n")


def _freeze(monkeypatch: pytest.MonkeyPatch) -> str:
    from datetime import UTC, datetime

    import pridem.verbs.data as data

    class Frozen(datetime):
        @classmethod
        def now(cls, tz: object = None) -> "Frozen":
            return cls(2026, 11, 13, 12, 0, 0, tzinfo=UTC)

    monkeypatch.setattr(data, "datetime", Frozen)
    return "20261113T120000Z"


@pytest.mark.parametrize("role", ["test", "prod"])
def test_db_connect_reads_only_and_keeps_its_log_on_the_box(
    tmp_path: Path, role: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The session -- ``-T`` (no terminal here), every transaction read-only,
    ``psql -L`` -- on the caller's terminal; its log taken to
    ``/opt/pridem/connect/<time>-<entry>.log`` (0600, the directory 0700).
    On ``prod`` the server is named first: without it, refused, nothing ran."""
    stamp = _freeze(monkeypatch)
    blank_box(tmp_path, role=role, name="box-1")
    cs = compose(tmp_path)
    home = tmp_path / "opt" / "pridem" / CONNECT_DIR
    kept = home / f"{stamp}-{STACK}.log"
    argv = ["db", "connect", STACK, *(["--confirm", "box-1"] if role == "prod" else [])]
    if role == "prod":
        with FakeRunner() as runner:
            code, out, err = _out(tmp_path, ["db", "connect", STACK], runner)
        assert (code, out) == (1, "") and "--confirm box-1" in err
    with _Stamped(*_connect_calls(cs, kept), stamp=stamp) as runner:
        code, out, err = _out(tmp_path, argv, runner)
    assert code == 0, err
    assert kept.read_bytes() == b"SELECT 1;\n"
    assert kept.stat().st_mode & 0o777 == 0o600
    assert home.stat().st_mode & 0o777 == 0o700
    assert str(kept) in err


def test_db_connect_of_a_stopped_database_is_refused_before_the_session(
    tmp_path: Path,
) -> None:
    from test_verbs_data import CONFIG

    blank_box(tmp_path)
    cs = compose(tmp_path)
    calls = [
        FakeCall(
            tuple(cs.product_argv("config", "--format", "json")),
            lines=lines(json.dumps(CONFIG)),
        ),
        running_call(cs, "postgres"),
    ]
    with FakeRunner(*calls) as runner:
        code, out, err = _out(tmp_path, ["db", "connect", STACK], runner)
    assert (code, out) == (1, "") and "does not run" in err


def test_a_session_whose_log_is_not_taken_ends_with_1(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    stamp = _freeze(monkeypatch)
    blank_box(tmp_path)
    cs = compose(tmp_path)
    kept = tmp_path / "opt" / "pridem" / CONNECT_DIR / f"{stamp}-{STACK}.log"
    calls = _connect_calls(cs, kept)
    calls[3] = FakeCall(calls[3].argv, code=1)  # the copy fails
    with FakeRunner(
        *[
            FakeCall(
                tuple(a.replace("STAMP", stamp) for a in c.argv),
                lines=c.lines,
                code=c.code,
            )
            for c in calls[:4]
        ]
    ) as runner:
        code, out, err = _out(tmp_path, ["db", "connect", STACK], runner)
    assert code == 1 and "was not kept" in err


# --- gc of the sessions' logs --------------------------------------------------------


def test_gc_takes_the_logs_of_sessions_older_than_their_term(tmp_path: Path) -> None:
    """``CONNECT_KEEP_DAYS``: a session's log holds the results of queries --
    on prod, people's data. Older -- to go; younger -- kept."""
    box = Box(tmp_path / "opt" / "pridem")
    home = box.root / CONNECT_DIR
    home.mkdir(parents=True)
    now = 2_000_000_000.0
    old, young = home / "old.log", home / "young.log"
    for path, age_days in (
        (old, CONNECT_KEEP_DAYS + 1),
        (young, CONNECT_KEEP_DAYS - 1),
    ):
        path.write_text("x")
        at = now - age_days * 86400
        os.utime(path, (at, at))
    gc = Gc(box=box, run_id="r1", fetched=Fetched(), root=tmp_path, now=lambda: now)
    assert gc._old_sessions() == [old]
    assert CONNECT_KEEP_DAYS == 30


# --- the interactive runner ----------------------------------------------------------


CHILD = textwrap.dedent(
    """
    import signal, sys, time
    got = []
    signal.signal(signal.SIGINT, lambda s, f: got.append(s))
    t = time.time()
    while time.time() - t < 1.5:
        time.sleep(0.05)
    print("child got", len(got), flush=True)
    sys.exit(3)
    """
)
HARNESS = textwrap.dedent(
    """
    import os, signal, sys, threading
    from pridem.runner import SubprocessRunner
    timer = threading.Timer(0.5, lambda: os.killpg(os.getpgrp(), signal.SIGINT))
    timer.start()
    code = SubprocessRunner().interactive([sys.executable, "-c", sys.argv[1]])
    print("caller alive, code", code, flush=True)
    """
)


def test_ctrl_c_in_a_session_reaches_the_command_and_not_the_caller() -> None:
    """Measured before the code (gate): the terminal's Ctrl-C is SIGINT to its
    foreground group. ``interactive`` keeps the command in the caller's group
    -- it gets the signal -- and the caller ignores it while the command runs
    -- it lives on to keep the session's log. The harness is started by the
    machine's own runner, in a session and group of its own, standing for the
    terminal (the fence: commands start in ``runner.py`` alone)."""
    from pridem.runner import Stream, SubprocessRunner

    said: list[str] = []

    def keep(stream: Stream, line: str, cut: bool) -> None:
        said.append(line)

    SubprocessRunner().run(
        [sys.executable, "-c", HARNESS, CHILD],
        timeout=30,
        env={**os.environ},
        on_line=keep,
    )
    assert "child got 1" in said, said
    assert "caller alive, code 3" in said, said
