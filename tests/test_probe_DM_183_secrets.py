"""The probes of DM-183: every run cleans every secret of the box; the
types' ``generate`` sees no environment of the app.

Markers of no real form of a key stand for the secrets: ``asked`` of the
passport, ``minted`` of the stack, ``derived`` in its env file. A command
prints them; the journal, the verdict, ``report --llm`` and the console hold
none -- and a marker that is no secret is there, so the probe is not empty.
"""

import io
import json
from dataclasses import replace
from pathlib import Path

import pytest
import yaml
from data_support import STACK, blank_box
from passport_support import section
from pydantic import SecretStr
from test_probe_DM_54_recover import Refusing
from test_steps_types import OPENAPI, Container, generated, head, run, types
from test_verbs_data import head_call, running_call
from test_verbs_project import MINTED, SET, _box, _exec
from test_verbs_seeds_and_reset import MIGRATE, migrate_check

from pridem.cli import run as cli
from pridem.events import Secrets
from pridem.runner import FakeCall, FakeRunner, Runner, Stream
from pridem.steps.passport import PASSPORT_COPY
from pridem.verbs.base import Context
from pridem.verbs.run import box_secrets

ASKED = "marker-asked-0123456789abcdef"
DERIVED = "marker-derived-0123456789abcdef"
PLAIN = "marker-plain-0123456789abcdef"


def _secrets_on_the_box(root: Path) -> None:
    """An ``asked`` marker in the passport copy; a ``derived`` key of the
    blank's release with its marker in the stack's env file. ``minted`` --
    ``MINTED`` of the fixture."""
    copy = root / PASSPORT_COPY
    data = yaml.safe_load(copy.read_text())
    asked = section(data, "asked")
    held = asked.get(STACK)
    asked[STACK] = {**(held if isinstance(held, dict) else {}), "MARKER_ASKED": ASKED}
    copy.write_text(yaml.safe_dump(data, sort_keys=False))
    release = (root / "opt" / STACK / "current").resolve()
    primer = yaml.safe_load((release / "primer.yaml").read_text())
    primer["env"]["MARKER_DERIVED"] = {"source": "derived", "run": "app derive x"}
    (release / "primer.yaml").write_text(yaml.safe_dump(primer, sort_keys=False))
    env = root / "opt" / STACK / "env" / ".env"
    env.parent.mkdir(parents=True, exist_ok=True)
    env.write_text(f"MARKER_DERIVED='{DERIVED}'\n", encoding="utf-8")
    env.chmod(0o600)


def _printing(call: FakeCall) -> FakeCall:
    """``call`` printing every marker, on both streams."""
    lines = tuple(
        (stream, f"value {marker}")
        for marker in (MINTED, ASKED, DERIVED, PLAIN)
        for stream in (Stream.STDOUT, Stream.STDERR)
    )
    return replace(call, lines=lines)


def _cli(root: Path, argv: list[str], runner: Runner) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    home = root / "opt" / "pridem"
    code = cli(argv, root=home, out=out, err=err, runner=runner, fs_root=root)
    return code, out.getvalue(), err.getvalue()


def _everything(root: Path, out: str, err: str) -> str:
    """The verdict, its journal, ``history/`` and ``report --llm`` of it, the
    console."""
    verdict = json.loads(out)
    home = root / "opt" / "pridem"
    journal = (home / str(verdict["log_ref"])).read_text()
    history = (home / "history" / f"{verdict['run_id']}.json").read_text()
    run_id = str(verdict["run_id"])
    _, report, _ = _cli(root, ["report", run_id, "--llm"], FakeRunner())
    return "\n".join([out, err, journal, history, report])


def _no_secret(text: str) -> None:
    for marker in (MINTED, ASKED, DERIVED):
        assert marker not in text, marker
    assert PLAIN in text  # the pair: what is no secret is there


def _broken_minted(root: Path) -> None:
    minted = root / "opt" / STACK / "env" / "minted.yaml"
    minted.write_text(":: not yaml")
    minted.chmod(0o600)


# --- probes -----------------------------------------------------------------------


@pytest.mark.parametrize("verb", ["verb", "db migrate"])
def test_probe_DM_183_a_command_plan_cleans_every_secret_of_the_box(
    tmp_path: Path, verb: str
) -> None:
    """``verb`` and ``db migrate`` -- plans with no passport step of their
    own: the command prints ``asked``, ``minted`` and ``derived`` of the box;
    the journal, the verdict, ``report --llm`` and the console hold none.
    The pair: a marker that is no secret is in each."""
    cs = _box(tmp_path)
    _secrets_on_the_box(tmp_path)
    if verb == "verb":
        calls = [
            running_call(cs, "app", "c-app"),
            _printing(_exec(cs, "app", *SET, "k", "v")),
        ]
        argv = ["--json", "verb", "set-setting", "key=k", "value=v"]
        argv += ["--confirm", "box-1"]
    else:
        run_argv = tuple(cs.argv("run", "--rm", operands=("app", *MIGRATE)))
        calls = [
            *migrate_check(cs, "0001"),
            _printing(FakeCall(run_argv)),
            head_call(cs, "0002"),
        ]
        argv = ["--json", "db", "migrate", STACK]
    with FakeRunner(*calls) as runner:
        code, out, err = _cli(tmp_path, argv, runner)
    assert code == 0, err
    _no_secret(_everything(tmp_path, out, err))


def test_probe_DM_183_types_generate_has_no_env_of_the_app(tmp_path: Path) -> None:
    """``generate`` is ``docker run`` of the release's app image with no
    network and no env file: a command that writes its environment writes
    none of the app's. A document of ``openapi`` -- which runs with the
    app's environment -- holding a known secret is refused before anything
    is written: ``secret-in-openapi``, no ``generate``, the value never named.
    The pair: the clean document is generated and committed."""
    step, _, _ = types(tmp_path / "leak", "test")
    step.secrets = Secrets([SecretStr(ASKED)])
    leaking = json.dumps({"openapi": "3.1.0", "info": {"title": ASKED}})
    with Container(printed=[leaking]) as runner:
        outcome = run(step, runner)
    [left] = [item.reason for item in outcome.incomplete]
    assert left.code == "types:secret-in-openapi", left
    assert ASKED not in json.dumps(left.as_json())
    assert [argv[:2] for argv in runner.docker] == [["docker", "compose"]]
    step, remote, deployed = types(tmp_path / "clean", "test")
    step.secrets = Secrets([SecretStr(ASKED)])
    with Container(printed=[OPENAPI]) as runner:
        outcome = run(step, runner)
    assert outcome.incomplete == (), outcome.incomplete
    assert head(remote) != deployed  # committed
    [generate] = [argv for argv in runner.docker if argv[:2] == ["docker", "run"]]
    assert "--env-file" not in generate
    assert generate[generate.index("--network") + 1] == "none"


# --- around the probes ------------------------------------------------------------


def test_generated_types_with_a_secret_are_not_committed(tmp_path: Path) -> None:
    """``generate`` writes a known secret into ``out`` (a value baked into
    the image, say): ``secret-in-out``, nothing committed."""
    step, remote, deployed = types(tmp_path, "test")
    step.secrets = Secrets([SecretStr(ASKED)])

    def leaking(host: Path, words: list[str]) -> int:
        (host / "out").write_bytes(generated(ASKED))
        return 0

    with Container(generate=leaking) as runner:
        outcome = run(step, runner)
    [left] = [item.reason for item in outcome.incomplete]
    assert left.code == "types:secret-in-out", left
    assert head(remote) == deployed


@pytest.mark.parametrize("verb", ["destroy", "status"])
def test_a_run_that_mends_the_box_goes_on_and_says_what_it_could_not_read(
    tmp_path: Path, verb: str
) -> None:
    """A broken ``minted.yaml``: ``destroy`` and ``status`` -- ways a box is
    mended or taken off -- go on to their verdict, and their journal says the
    stack's secrets were not read, naming the file, never a value. The pair
    is the next test: ``db migrate`` is refused."""
    _box(tmp_path)
    _broken_minted(tmp_path)
    argv = ["--json", verb]
    if verb == "destroy":
        argv += ["--confirm", "box-1"]
    # docker refuses every command: the run goes on to its verdict all the same
    _, out, err = _cli(tmp_path, argv, Refusing())
    assert out, err  # a verdict: not refused before the run
    verdict = json.loads(out)
    home = tmp_path / "opt" / "pridem"
    lines = [
        json.loads(line)
        for line in (home / str(verdict["log_ref"])).read_text().splitlines()
    ]
    notices = [line["notice"] for line in lines if line["event"] == "notice"]
    assert {"kind": "secrets_unread", "stack": STACK, "why": "minted"} in notices


def test_a_run_with_secrets_it_cannot_read_is_refused(tmp_path: Path) -> None:
    """Every other run with a stack whose secrets cannot be read is refused
    before its journal: it could print a value it does not know to clean."""
    _box(tmp_path)
    _broken_minted(tmp_path)
    with FakeRunner() as runner:
        code, out, err = _cli(tmp_path, ["--json", "db", "migrate", STACK], runner)
    assert (code, out) == (1, "")
    assert f"the secrets of {STACK} cannot be read (minted)" in err
    assert not list((tmp_path / "opt" / "pridem" / "journal").glob("*.jsonl"))


def test_a_fresh_box_has_no_secrets_of_stacks(tmp_path: Path) -> None:
    """Twin EMPTINESS: no stack with the machine's mark -- nothing to read,
    no refusal."""
    blank_box(tmp_path)
    ctx = Context(
        root=tmp_path / "opt" / "pridem",
        out=io.StringIO(),
        err=io.StringIO(),
        runner=FakeRunner(),
        fs_root=tmp_path,
    )
    found = box_secrets(ctx, None)
    assert found.values == [] and found.unread == []
