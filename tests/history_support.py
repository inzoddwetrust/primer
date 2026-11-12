"""Verdicts of deploys in ``history/`` for the stand and the roll-back (DM-24)."""

from pathlib import Path

import yaml
from passport_support import passport_example, section, write_passport
from report_support import example, load

from pridem.events import Json, Secrets
from pridem.plan import Stack
from pridem.report.schema import Verdict
from pridem.runner import FakeCall, Stream
from pridem.stacks.passport import load_passport
from pridem.state import Box
from pridem.steps.git import git_env
from pridem.steps.passport import PASSPORT_COPY, Fetched
from pridem.verbs.plans import Source, Wanted, deploy_plan
from pridem.verbs.run import Session

OLD, NEW = "v1.0.0", "v2.0.0"
"""A previous release and the current one on prod (tags)."""
STACK = "aivis"
"""The product of ``passport_support.passport_example``: its repository's name."""
ADDRESS = "git@github.com:aivis-one/aivis.git"


def sha(digit: str) -> str:
    return digit * 40


def run_of(n: int) -> str:
    return f"2026-11-11T10:{n // 60:02d}:{n % 60:02d}Z-a3f9"


def deploy_verdict(
    n: int,
    *,
    verb: str = "deploy",
    result: str = "red",
    head: str | None = None,
    release: str | None = None,
    refused: dict[str, Json] | None = None,
) -> Verdict:
    """A verdict of ``verb``: ``fetch_root`` of ``head`` when given, a failed
    ``build`` when red, ``finalize`` putting ``release`` in ``current`` when
    green, ``stand`` failed by ``refused`` when given."""
    data = example()
    run = run_of(n)
    data["run_id"] = run
    data["log_ref"] = f"journal/{run}.jsonl"
    data["verb"] = verb
    data["args"] = {"ref": "main"} if verb == "deploy" else {}
    data.pop("junit")
    steps: list[Json] = []
    if head is not None:
        steps.append(
            {
                "stack": "sources",
                "name": "fetch_root",
                "phase": "main",
                "order": 2,
                "status": "ok",
                "verify": {
                    "stack": STACK,
                    "drift_discarded": [],
                    "head": head,
                    "release": release or head,
                    "config": STACK,
                },
            }
        )
    if refused is not None:
        steps.append(
            {
                "stack": "sources",
                "name": "stand",
                "phase": "main",
                "order": 2,
                "status": "failed",
                "reason": refused,
            }
        )
    elif result == "red":
        steps.append(
            {
                "stack": STACK,
                "name": "build",
                "phase": "main",
                "order": 7,
                "status": "failed",
                "reason": {
                    "code": "command-failed",
                    "argv": ["docker"],
                    "exit_code": 1,
                },
            }
        )
    exit_code = {"green": 0, "red": 1, "incomplete": 2}[result]
    if result in ("green", "incomplete"):
        current = release or head or sha("0")
        steps.append(
            {
                "stack": "finalize",
                "name": "finalize",
                "phase": "main",
                "order": 2,
                "status": "ok",
                "verify": {"current": {STACK: current}},
            }
        )
    if result == "incomplete":
        report = data["report"]
        assert isinstance(report, dict)
        report["incomplete"] = [{"what": "ssl", "code": "ssl:deferred"}]
    data["steps"] = steps
    data["exit_code"] = exit_code
    data["result"] = result
    return load(data)


def history(root: Path, *verdicts: Verdict) -> Box:
    """A box at ``root`` whose ``history/`` holds ``verdicts``."""
    box = Box(root)
    with box.lock("setup"):
        for verdict in verdicts:
            box.write_verdict(verdict)
    return box


def log_call(fs_root: Path, commit: str, *tasks: str, code: int = 0) -> FakeCall:
    """``git log`` of the ``Task`` trailers of ``commit`` in the bare repository."""
    bare = fs_root / "opt" / STACK / "git"
    argv = (
        "git",
        "-C",
        str(bare),
        "log",
        "-1",
        "--format=%(trailers:key=Task,valueonly,separator=%x2C)",
        commit,
        "--",
    )
    lines = () if code else ((Stream.STDOUT, ",".join(tasks)),)
    return FakeCall(argv, code=code, lines=lines, env=git_env(fs_root))


def deploy_verbs_box(fs_root: Path, verb: str, role: str) -> Stack:
    """The ``sources`` stack of the plan of ``verb`` on a box of ``role``, its
    passport read (the plan's ``fetched``)."""
    data = passport_example()
    section(data, "server")["role"] = role
    if role != "test":  # passport rule 4: a release tag there
        section(data, "product")["ref"] = "v1.0.0"
    file = write_passport(fs_root, data)
    box = Box(fs_root / "opt" / "pridem")
    mode = verb if verb in ("install", "reinstall", "doctor") else "deploy"
    wanted = Wanted(mode=mode, source=Source(file=file))
    session = Session(box, run_of(0), Fetched(), Secrets(()))
    planned = deploy_plan(session, fs_root, wanted, None)
    assert planned.fetched is not None
    planned.fetched.passport = load_passport(file)
    [sources] = [s for s in planned.stacks if s.name == "sources"]
    return sources


def released(n: int, release: str) -> Verdict:
    """A green deploy whose ``finalize`` put ``release`` in ``current``."""
    return deploy_verdict(n, result="green", head=sha(str(n)), release=release)


def release_box(fs_root: Path, role: str, current: str, *verdicts: Verdict) -> Path:
    """A box of ``role``: the passport's copy (and the same as a file, the
    passport's source, which it returns), ``/opt/aivis/current`` ->
    ``releases/<current>``, ``history/`` of ``verdicts``. On prod the passport
    names ``NEW``."""
    data = passport_example()
    section(data, "server")["role"] = role
    if role == "prod":
        section(data, "product")["ref"] = NEW
    copy = fs_root / PASSPORT_COPY
    copy.parent.mkdir(parents=True, exist_ok=True)
    copy.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
    copy.chmod(0o600)
    release = fs_root / "opt" / STACK / "releases" / current
    release.mkdir(parents=True)
    (fs_root / "opt" / STACK / "current").symlink_to(release)
    history(fs_root / "opt" / "pridem", *verdicts)
    return write_passport(fs_root, data)
