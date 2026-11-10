"""DM-81: data copied before it is seen, sources that say why, reads with bounds.

Each test is one row of the grid of the card's gate: the copy of a service's
data (special files, drift, a red validate again), ``gc`` of the copies, the
release's drift and a dead run's ``.tmp``, ``git show`` on a damaged
repository, ``finalize`` on a new passport, conformance reading a long line,
a big or slow body and the application's own names, the OpenAPI read with a
bound, ssh that reaches nothing, and the release bound read-only.
"""

import json
import os
import shutil
import socket
import sys
import threading
from collections.abc import Callable, Iterator, Mapping
from http.server import BaseHTTPRequestHandler, HTTPServer
from itertools import count
from pathlib import Path

import pytest
from compose_support import image_call, run
from env_support import context
from plan_support import Journal, ScriptedStep, plan
from test_probe_DM_81_data import _validate
from test_steps_finalize import finalize, tail
from test_steps_keys import ADDRESS, _key_in_place, lsremote
from test_steps_keys import run as run_key
from test_steps_services import IMAGE, _copy, _hashes, _item
from test_steps_sources import git, product, remote
from test_steps_sources import run as run_sources
from test_steps_types import OPENAPI, app_calls, openapi, types  # noqa: F401
from test_steps_types import run as run_types

from pridem.conformance import stack as conformance
from pridem.conformance.stack import (
    BODY_LIMIT,
    LINE_LIMIT_JOINED,
    BodyTooBig,
    Problem,
    check_health,
    check_logs,
    http_get,
    shown,
)
from pridem.events import Json
from pridem.report.codes import ExitCode
from pridem.runner import FakeCall, FakeRunner, Stream, SubprocessRunner
from pridem.state import Box, BoxState
from pridem.steps import types as types_module
from pridem.steps.base import CheckResult, StepContext, StepFailed
from pridem.steps.compose import ComposeStack, override_text
from pridem.steps.finalize import FinalCheck
from pridem.steps.gc import _copies_gone
from pridem.steps.git import git_env, repo
from pridem.steps.keys import DeployKey
from pridem.steps.services import tree
from pridem.steps.sources import Checkout, RepoDamaged, source_steps

# --- data_copy --------------------------------------------------------------------


def test_a_fifo_or_a_socket_in_the_data_is_refused_unopened(tmp_path: Path) -> None:
    """A FIFO would hang ``tree`` and ``copytree`` forever (opening one waits
    for a writer); a socket cannot be copied. Each is ``data-special`` before
    anything is copied or opened. The pair: the same data without it -- the
    check asks for a copy."""
    step, _, item = _copy(tmp_path)
    os.mkfifo(item.source / "pipe")
    outcome, _ = run([step], FakeRunner())
    [record] = outcome.steps
    assert record.reason is not None
    assert record.reason.code == "data_copy:data-special"
    assert record.reason.params["paths"] == ["pipe"]
    assert not item.home.exists()
    (item.source / "pipe").unlink()
    with socket.socket(socket.AF_UNIX) as bound:
        bound.bind(str(item.source / "sock"))
        outcome, _ = run([step], FakeRunner())
    [record] = outcome.steps
    assert record.reason is not None and record.reason.params["paths"] == ["sock"]
    (item.source / "sock").unlink()
    check = step.check(context(FakeRunner()))
    assert check.needed and check.would is not None and check.would.code == "copy"


def test_tree_reads_files_by_their_digest_and_names_a_fifo_special(
    tmp_path: Path,
) -> None:
    (tmp_path / "f").write_bytes(b"x" * 100_000)
    (tmp_path / "d").mkdir()
    (tmp_path / "l").symlink_to("f")
    os.mkfifo(tmp_path / "p")
    found = {name: (kind, value) for name, kind, value in tree(tmp_path)}
    assert found["f"][0] == "file" and len(found["f"][1]) == 64
    assert found["d"] == ("dir", "")
    assert found["l"] == ("link", "f")
    assert found["p"] == ("special", "")


def test_a_copy_that_drifted_is_red(tmp_path: Path) -> None:
    """The machine writes a copy only through ``.tmp`` and a rename to a name
    not taken: a copy that holds other files than its name says, or that is
    no directory, is a foreign hand -- ``copy-drift``, never overwritten. A
    FIFO planted in the copy is read as ``special``, never opened. The pair:
    the copy as it was copied -- no drift."""
    step, compose, item = _copy(tmp_path)
    target = item.target
    shutil.copytree(item.source, target)
    with FakeRunner(*_hashes(compose, "a" * 64)) as runner:
        assert not step.check(context(runner)).needed

    def edit() -> None:
        (target / "kinds.yaml").write_text("kinds: [b]\n")

    def fifo() -> None:
        os.mkfifo(target / "pipe")

    def file() -> None:
        shutil.rmtree(target)
        target.write_text("x")

    def link() -> None:
        shutil.rmtree(target)
        target.symlink_to(item.source)

    planted: list[tuple[str, Callable[[], None]]] = [
        ("edit", edit),
        ("fifo", fifo),
        ("file", file),
        ("link", link),
    ]
    for name, plant in planted:
        if target.is_dir() and not target.is_symlink():
            shutil.rmtree(target)
        elif os.path.lexists(target):
            target.unlink()
        shutil.copytree(item.source, target)
        plant()
        outcome, _ = run([step], FakeRunner())
        [record] = outcome.steps
        assert record.reason is not None, name
        assert record.reason.code == "data_copy:copy-drift", name
        assert record.reason.params["path"] == str(target), name


def test_a_red_validate_is_validated_again_on_the_next_run(tmp_path: Path) -> None:
    """The copy a red ``validate`` left is there, and so is the deploy's
    override that binds it; the service is off that configuration, so the next
    run's ``data_copy`` validates again, never green on a copy no one
    validated. The pair: the service on that configuration -- the copy was
    validated (it is what runs), nothing to do.

    Changed by DM-89: no text is handed from ``build`` any more and nothing
    is put in place here (``finalize`` does it); with the service on the
    configuration there is nothing at all to do, not an ``override`` to
    place."""
    step, compose, item = _copy(tmp_path)
    script = [image_call(compose, "comms-app", IMAGE), _validate(compose, item, 1)]
    with FakeRunner(*script) as runner:
        outcome, _ = run([step], runner)
    assert outcome.code is ExitCode.FAILED
    assert item.target.is_dir()
    with FakeRunner(*_hashes(compose, "b" * 64)) as runner:
        check = step.check(context(runner))
    assert check.needed and check.data == {"validate": True}
    with FakeRunner(*_hashes(compose, "a" * 64)) as runner:
        check = step.check(context(runner))
    assert not check.needed


def test_every_kind_new_is_copied_not_the_first_alone(tmp_path: Path) -> None:
    """Two kinds of data, the first already copied: the second is copied too
    (``act`` with nothing to validate); each copy holds its own source."""
    step, _, item = _copy(tmp_path)
    other = _item(tmp_path, "texts")
    other.source.mkdir(parents=True)
    (other.source / "ui.yaml").write_text("ui: {}\n")
    shutil.copytree(item.source, item.target)
    step.items = [item, other]
    assert step._changed() == [other]
    step.act(context(FakeRunner()), CheckResult(False))
    assert (other.target / "ui.yaml").read_text() == "ui: {}\n"
    assert step._changed() == []


# --- gc of the copies -------------------------------------------------------------


def _copies(release: Path, *names: str) -> list[Path]:
    made = []
    for age, name in enumerate(names):
        path = release / name
        path.mkdir(parents=True)
        os.utime(path, (1000 + age, 1000 + age))
        made.append(path)
    return made


def test_gc_removes_a_copy_neither_mounted_nor_the_newest_of_its_kind(
    tmp_path: Path,
) -> None:
    release = tmp_path / "data" / "blank@v1"
    old, mounted, newest = _copies(
        release, "profile@0000000000000001", "profile@0000000000000002",
        "profile@0000000000000003",
    )  # fmt: skip
    [texts] = _copies(release, "texts@0000000000000004")
    (release / "profile@0000000000000005.tmp").mkdir()
    assert _copies_gone(release, [mounted]) == [old]
    # each part: a mounted one stays, the newest stays, another kind's newest
    assert mounted.exists() and newest.exists() and texts.exists()
    assert _copies_gone(release, [old, mounted]) == []
    assert _copies_gone(release, []) == [mounted, old]


# --- sources ----------------------------------------------------------------------


def _fetched(tmp: Path) -> tuple[Path, Path]:
    remote(
        tmp,
        "aivis",
        {
            "primer.yaml": product(tmp, dependency=False),
            ".gitignore": ".env\n",
            "app.py": "a\n",
        },
    )
    root = tmp / "box"
    address = f"file://{tmp}/aivis.git"
    _, steps = source_steps(root, stack="aivis", address=address, ref="main", tag=False)
    assert run_sources(root, steps).code is ExitCode.OK
    [release] = (root / "opt" / "aivis" / "releases").iterdir()
    return root, release


def _again(tmp: Path, root: Path) -> Mapping[str, Json]:
    address = f"file://{tmp}/aivis.git"
    _, steps = source_steps(root, stack="aivis", address=address, ref="main", tag=False)
    outcome = run_sources(root, steps)
    fetch = outcome.steps[0]
    assert fetch.status == "ok", fetch.reason
    return fetch.verify


def test_an_ignored_file_and_a_nested_repository_are_drift(tmp_path: Path) -> None:
    """A ``.env`` the release ignores is read by compose all the same: it is
    drift, discarded; so is a repository planted in the release, which only
    ``clean -ffdx`` removes. The pair: the clean release again -- nothing."""
    root, release = _fetched(tmp_path)
    (release / ".env").write_text("SECRET=planted\n")
    nested = release / "nested"
    nested.mkdir()
    git(nested, "init", "-q")
    (nested / "n.txt").write_text("n\n")
    assert _again(tmp_path, root)["drift_discarded"] == [".env", "nested/"]
    assert not (release / ".env").exists() and not nested.exists()
    assert _again(tmp_path, root)["drift_discarded"] == []


def test_a_tmp_a_dead_run_left_does_not_block_the_release(tmp_path: Path) -> None:
    """``worktree add`` died: its ``.tmp`` is a plain directory, a worktree
    still locked ``initializing``, or that worktree with its directory gone.
    Each is taken off and the release made. The pair: none -- made all the
    same (``test_probe_DM_10_dirty_tree_is_discarded_and_recorded``)."""
    root, release = _fetched(tmp_path)
    bare = root / "opt" / "aivis" / "git"
    commit = git(bare, "rev-parse", "main")[0]
    temp = release.with_name(release.name + ".tmp")
    for form in ("plain", "locked", "locked-gone"):
        shutil.rmtree(release)
        git(bare, "worktree", "prune")
        if form == "plain":
            temp.mkdir()
            (temp / "junk").write_text("j\n")
        else:
            git(bare, "worktree", "add", "-q", "--detach", str(temp), commit)
            git(bare, "worktree", "lock", "--reason", "initializing", str(temp))
            if form == "locked-gone":
                shutil.rmtree(temp)
        verify = _again(tmp_path, root)
        assert verify["head"] == commit, form
        assert (release / "app.py").is_file() and not os.path.lexists(temp), form


def _damaged(tmp: Path) -> tuple[Checkout, str, Path]:
    bare = remote(tmp, "d", {"primer.yaml": "a: 1\n", "sub/f.txt": "f\n"})
    commit = git(bare, "rev-parse", "main")[0]
    checkout = Checkout(tmp, "d", repo(f"file://{bare}"), bare=bare)
    return checkout, commit, bare


def _object(bare: Path, name: str) -> Path:
    found = git(bare, "rev-parse", name)[0]
    return bare / "objects" / found[:2] / found[2:]


def _ctx() -> StepContext:
    return StepContext(SubprocessRunner(), "install", "test", "d", lambda *_: None)


def test_show_tells_no_file_from_a_damaged_repository(tmp_path: Path) -> None:
    """``git show`` is 128 for both; ``ls-tree`` answers 0 with nothing when
    the commit has no such file, 128 when its tree is broken, and lists a file
    whose blob is gone -- then ``show`` 128 is damage."""
    checkout, commit, bare = _damaged(tmp_path)
    assert checkout.show(_ctx(), commit, "primer.yaml") == "a: 1\n"
    assert checkout.show(_ctx(), commit, "primer.lock") is None
    _object(bare, f"{commit}:sub/f.txt").unlink()
    with pytest.raises(RepoDamaged) as blob:
        checkout.show(_ctx(), commit, "sub/f.txt")
    assert blob.value.path == "sub/f.txt"
    _object(bare, f"{commit}:sub").unlink()
    with pytest.raises(RepoDamaged):
        checkout.show(_ctx(), commit, "sub/f.txt")
    _object(bare, f"{commit}^{{tree}}").unlink()
    with pytest.raises(RepoDamaged):
        checkout.show(_ctx(), commit, "primer.lock")


def test_a_damaged_repository_is_repo_damaged_not_no_primer_yaml(
    tmp_path: Path,
) -> None:
    root, release = _fetched(tmp_path)
    bare = root / "opt" / "aivis" / "git"
    commit = git(bare, "rev-parse", "main")[0]
    _object(bare, f"{commit}:primer.yaml").unlink()
    address = f"file://{tmp_path}/aivis.git"
    _, steps = source_steps(root, stack="aivis", address=address, ref="main", tag=False)
    reason = run_sources(root, steps).steps[0].reason
    assert reason is not None and reason.code == "fetch_root:repo-damaged"
    assert reason.params == {"ref": "main", "path": "primer.yaml"}


# --- finalize ---------------------------------------------------------------------


def test_a_new_passport_on_the_same_releases_is_written(tmp_path: Path) -> None:
    """The releases are the same, the passport is new: ``finalize`` writes
    ``state.json`` and ``verify`` reads the version and the ops commit back.
    Each part alone: an older version, another ops commit."""
    box = Box(tmp_path / "pridem")
    step, _ = finalize(tmp_path, box)
    passport = step.fetched.passport
    assert passport is not None
    journal = Journal()
    green = ScriptedStep("up", 12, journal, fact={"up": "ok"})
    with box.lock("t"):
        assert plan(tail(green, FinalCheck(), step), "install")[0].run().code is (
            ExitCode.OK
        )
        written = box.read_state()
        assert written is not None
        ctx = context(FakeRunner())
        assert not step.check(ctx).needed
        older = written.model_copy(update={"passport_version": passport.version - 1})
        box.write_state(BoxState.model_validate(older.model_dump()))
        assert step.check(ctx).needed
        with pytest.raises(StepFailed) as stale:
            step.verify(ctx, step.check(ctx))
        assert stale.value.reason.code == "state-passport"
        box.write_state(written)
        step.fetched.ops_commit = "a" * 40
        assert step.check(ctx).needed
        step.act(ctx, step.check(ctx))
        fact = step.verify(ctx, step.check(ctx)).fact
        state = box.read_state()
    assert state is not None and state.ops_commit == "a" * 40
    assert fact["passport_version"] == passport.version


# --- conformance ------------------------------------------------------------------


def _printing(expression: str) -> tuple[list[str], frozenset[int]]:
    ctx = StepContext(SubprocessRunner(), "install", "test", "c", lambda *_: None)
    script = f"import sys; sys.stdout.write({expression})"
    return conformance._read(ctx, [sys.executable, "-c", script])


def test_a_long_log_line_is_joined_and_one_over_the_bound_is_named() -> None:
    """The runner gives a line over 64 KiB in pieces: each piece alone was
    ``log-not-json``. Joined back it is the line; over ``LINE_LIMIT_JOINED``
    it is ``log-too-long`` and never parsed."""
    line = '{"msg": "' + "x" * 100_000 + '"}'
    lines, long = _printing(f"{line!r} + '\\nnext\\n'")
    assert lines == [line, "next"] and long == frozenset()
    lines, long = _printing(f"'y' * {LINE_LIMIT_JOINED + 70_000} + '\\nok\\n'")
    assert long == {1} and lines[1] == "ok" and len(lines[0]) <= LINE_LIMIT_JOINED
    problems = check_logs(lines, stack_name="blank", long_lines=long)
    assert problems[0] == Problem(
        "log-too-long", {"line": 1, "limit": LINE_LIMIT_JOINED}
    )


@pytest.fixture
def body() -> Iterator[tuple[int, list[bytes]]]:
    sent: list[bytes] = [b""]

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802 -- the stdlib's name
            self.send_response(200)
            self.end_headers()
            self.wfile.write(sent[0])

        def log_message(self, format: str, *args: object) -> None:
            return

    server = HTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        yield server.server_address[1], sent
    finally:
        server.shutdown()
        server.server_close()


def test_get_reads_within_its_bound_and_its_deadline(
    body: tuple[int, list[bytes]],
) -> None:
    port, sent = body
    sent[0] = b"x" * BODY_LIMIT
    assert http_get("127.0.0.1", port, "/", limit=BODY_LIMIT) == (200, sent[0])
    sent[0] = b"x" * (BODY_LIMIT + 1)
    with pytest.raises(BodyTooBig) as over:
        http_get("127.0.0.1", port, "/", limit=BODY_LIMIT)
    assert (over.value.status, over.value.limit) == (200, BODY_LIMIT)
    # a body still coming at the deadline is nothing answered
    ticks = count(step=100)
    late = http_get(
        "127.0.0.1", port, "/", limit=BODY_LIMIT, clock=lambda: float(next(ticks))
    )
    assert late is None
    assert check_health(None, migrate=False, stack_name="b", too_big=True) == [
        Problem("health-too-big", {"limit": BODY_LIMIT})
    ]


def test_values_of_the_application_are_cut_in_problems() -> None:
    long = "s" * 500
    assert shown(long) == "s" * 64 + "...+436"
    assert shown("short") == "short"
    assert shown(["n"] * 10) == ["n"] * 8 + ["...+2"]
    assert shown({"a": 1}) == "<object>" and shown(7) == "<number>"
    document = {**conformance._GOOD_HEALTH, "service": long, long: 1}
    problems = check_health(
        json.dumps(document).encode(), migrate=True, stack_name="blank"
    )
    assert Problem("health-service", {"service": shown(long), "stack": "blank"}) in (
        problems
    )
    assert Problem("health-field", {"field": shown(long), "problem": "extra"}) in (
        problems
    )
    degraded = {
        **conformance._GOOD_HEALTH,
        "status": "degraded",
        "checks": {f"c{i}": "error" for i in range(10)},
    }
    [problem] = [
        p
        for p in check_health(
            json.dumps(degraded).encode(), migrate=True, stack_name="blank"
        )
        if p.code == "health-degraded"
    ]
    checks = problem.params["checks"]
    assert isinstance(checks, list) and len(checks) == 9 and checks[-1] == "...+2"
    line = conformance._GOOD_LOG.replace('"service": "blank"', '"service": {"x": 1}')
    extra = conformance._GOOD_LOG[:-1] + f', "{long}": 1}}'
    found = check_logs([line, extra], stack_name="blank")
    assert found[0].params["service"] == "<object>"
    assert found[1].params["extra"] == [shown(long)]


def test_types_refuses_an_openapi_over_its_bound(
    tmp_path: Path,
    openapi: int,  # noqa: F811 -- the fixture of test_steps_types
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The OpenAPI document is read with a bound too (the class of reads of
    conformance): over it -- ``openapi-too-big``, never read whole."""
    monkeypatch.setattr(types_module, "OPENAPI_LIMIT", len(OPENAPI) - 1)
    step, _, cs = types(tmp_path, openapi, "test")
    with FakeRunner(*app_calls(openapi, cs, 1)) as runner:
        outcome = run_types(step, runner)
    reason = outcome.steps[0].reason
    assert reason is not None and reason.code == "types:openapi-too-big"
    assert reason.params["limit"] == len(OPENAPI) - 1


# --- keys -------------------------------------------------------------------------


def _ssh_failed(root: Path, line: str) -> FakeCall:
    found = repo(ADDRESS)
    return FakeCall(
        ("git", "ls-remote", "--heads", found.url()),
        code=128,
        lines=(
            (Stream.STDERR, line),
            (Stream.STDERR, "fatal: Could not read from remote repository."),
        ),
        env=git_env(root),
    )


def _key_step(root: Path, *ticks: float) -> DeployKey:
    clock = iter(ticks)
    return DeployKey(
        ADDRESS, root, wait_s=100, clock=lambda: next(clock), sleep=lambda _: None
    )


def test_ssh_that_reaches_nothing_is_unreachable_at_once(tmp_path: Path) -> None:
    """``ls-remote`` is 128 whether the server refused the key or ssh never
    reached it; ssh's own line says which. Not reached -- ``unreachable`` at
    once, in ``check`` and on any poll of the wait, never 30 minutes and a
    false ``no-access``. The pair: the server's refusal is waited for."""
    _key_in_place(tmp_path)
    lost = "ssh: connect to host github.com port 22: Connection refused"
    refused = _ssh_failed(tmp_path, "git@github.com: Permission denied (publickey).")
    calls = [lsremote(tmp_path, 0), lsremote(tmp_path, 0)]  # act, verify
    outcome, _ = run_key(tmp_path, _key_step(tmp_path, 0.0, 1.0), calls)
    assert outcome.code is ExitCode.OK  # files drawn, key works
    for script in (
        [_ssh_failed(tmp_path, lost)],  # check
        [refused, refused, _ssh_failed(tmp_path, lost)],  # a poll of the wait
    ):
        step = _key_step(tmp_path, 0.0, 1.0, 2.0, 3.0)
        outcome, _ = run_key(tmp_path, step, script)
        reason = outcome.steps[0].reason
        assert reason is not None and reason.code == "deploy_key:unreachable"
        assert reason.params == {"repo": ADDRESS}
    step = _key_step(tmp_path, 0.0, 101.0)
    outcome, _ = run_key(tmp_path, step, [refused, refused, refused])
    reason = outcome.steps[0].reason
    assert reason is not None and reason.code == "deploy_key:no-access"


# --- the release bound read-only --------------------------------------------------


def test_the_override_binds_the_release_read_only(tmp_path: Path) -> None:
    """A bind of the release, and a named volume bound to it, are declared
    again ``read_only`` in the override: no container writes the release it
    runs from (its compose, ``Dockerfile`` and context are what ``forbidden``
    read). The pair: a bind already read-only and a plain named volume are
    left as they are."""
    from test_steps_services import _product

    made = _product(tmp_path)
    release = tmp_path / "rel"
    release.mkdir()
    compose = ComposeStack(
        made, "aivis", release, "main", "c" * 40, tmp_path, staged=True
    )
    rw: dict[str, Json] = {
        "type": "bind",
        "source": str(release / "src"),
        "target": "/app",
    }
    ro: dict[str, Json] = {**rw, "target": "/ro", "read_only": True}
    named: dict[str, Json] = {
        "type": "volume",
        "source": "files",
        "target": "/files",
        "volume": {},
    }
    plain: dict[str, Json] = {**named, "source": "db", "target": "/db"}
    bound: dict[str, Json] = {
        "driver_opts": {"type": "none", "o": "bind", "device": str(release)}
    }
    document: dict[str, Json] = {
        "services": {"app": {"volumes": [rw, ro, named, plain]}},
        "volumes": {"files": bound, "db": {}},
    }
    text = override_text(compose, document, proxy=False, references={})
    volumes = json.loads(text)["services"]["app"]["volumes"]
    assert volumes == [{**rw, "read_only": True}, {**named, "read_only": True}]
