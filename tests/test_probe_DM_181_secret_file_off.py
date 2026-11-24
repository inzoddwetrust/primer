"""DM-181 (REVIEW-0006 B1): a secret file under an option that is off.

The key of a secret file is never a line of the env file (DM-145); under an
option that is off it has no file, no bind, no value -- and no literal.
``render_env`` read the literal of every key of the option back from the env
file and failed on the file's key (``KeyError``) in each of the three ways
``read_back`` is reached: ``render_env``'s ``verify``, its ``check`` on an
unchanged file (a repeat, ``doctor``), ``derive_env``'s ``verify``.
"""

from pathlib import Path

from env_support import (
    box,
    load,
    passport_data,
    product_data,
    read_env,
    render,
    run,
)

from pridem.runner import FakeRunner
from pridem.stacks.env import DERIVED_PLACEHOLDER, resolve
from pridem.stacks.options import LITERAL
from pridem.stacks.schema import Product
from pridem.stacks.seams import SeamMemory

PATH = "/run/primer/probe.key"
VALUE = "pridem-planted-option-file-181\nits second line\n"
FILE = {"source": "asked", "when": "meet", "file": {"path": PATH}}
BOTH = {"PROBE_URL": {"source": "param", "when": "meet"}, "AGE_KEY": FILE}


def _stack(tmp: Path, env: dict[str, object]) -> Product:
    tmp.mkdir(parents=True, exist_ok=True)
    made = load(tmp, product_data(env, options=["meet"]))
    assert isinstance(made, Product)
    return made


def _never(field: str, schema: object) -> str:
    raise AssertionError(f"asked {field}: an option off asks nothing")


def test_probe_DM_181_a_secret_file_under_an_option_off_renders_green(
    tmp_path: Path,
) -> None:
    """Off: green, the env key of the option the literal, the file's key no
    line of the env file and no value. The pair: on -- the value of the env
    key, the file's value for its file, still no line."""
    stack = _stack(tmp_path / "s", BOTH)
    root, fetched = box(tmp_path / "off", passport_data())
    outcome, _ = run([render(stack, root, fetched, ask=_never)], FakeRunner())
    assert outcome.steps[0].reason is None, outcome.steps
    env = read_env(root, "aivis")
    assert env["PROBE_URL"] == LITERAL and "AGE_KEY" not in env
    assert fetched.passport is not None
    resolved = resolve(stack, stack, fetched.passport, {}, SeamMemory())
    assert resolved.files == {}
    # the pair: the option on
    data = passport_data(
        options=["meet"],
        params={"aivis": {"PROBE_URL": "https://probe.example.org"}},
        asked={"aivis": {"AGE_KEY": VALUE}},
    )
    root, fetched = box(tmp_path / "on", data)
    outcome, _ = run([render(stack, root, fetched)], FakeRunner())
    assert outcome.steps[0].reason is None, outcome.steps
    env = read_env(root, "aivis")
    assert env["PROBE_URL"] == "https://probe.example.org" and "AGE_KEY" not in env
    assert fetched.passport is not None
    resolved = resolve(stack, stack, fetched.passport, {}, SeamMemory())
    assert resolved.files == {"AGE_KEY": VALUE}


def test_a_repeat_and_doctor_read_the_file_back_green(tmp_path: Path) -> None:
    """``check`` on an unchanged file reads it back (DM-59 FIX): the second
    install and ``doctor`` -- green, nothing to do."""
    stack = _stack(tmp_path / "s", BOTH)
    root, fetched = box(tmp_path, passport_data())
    run([render(stack, root, fetched, ask=_never)], FakeRunner())
    for mode in ("install", "doctor"):
        outcome, _ = run(
            [render(stack, root, fetched, ask=_never)], FakeRunner(), mode=mode
        )
        assert outcome.code.value == 0, (mode, outcome)
        assert outcome.doctor_diff == (), mode


def test_derive_env_reads_the_file_back_green(tmp_path: Path) -> None:
    """``derive_env``'s ``verify`` begins with ``read_back`` and nothing
    waiting -- the whole env file after ``derive``; called here as it calls
    it, before its compose check (DM-182), which runs compose: a stack with a
    ``derived`` key beside the option's file."""
    env = {**BOTH, "BOT_URL": {"source": "derived", "run": "x"}}
    stack = _stack(tmp_path / "s", env)
    root, fetched = box(tmp_path, passport_data())
    step = render(stack, root, fetched, ask=_never)
    run([step], FakeRunner())
    file = root / "opt" / "aivis" / "env" / "next.env"
    on_disk = file.read_text()
    derived = on_disk.replace(  # what derive_env's act leaves in the file
        f"BOT_URL='{DERIVED_PLACEHOLDER}'", f"BOT_URL='{'d' * 40}'"
    )
    assert derived != on_disk
    file.write_text(derived)
    verified = step.read_back(waiting=())
    assert verified.fact["keys"] == 2, verified.fact  # PROBE_URL, BOT_URL
    assert step.rendered["PROBE_URL"] == LITERAL and "AGE_KEY" not in step.rendered


def test_an_option_with_only_a_file(tmp_path: Path) -> None:
    """Nothing of the option in the env file: the flag alone, green."""
    env = {"AGE_KEY": FILE, "MEET": {"source": "passport", "key": "options.meet"}}
    stack = _stack(tmp_path / "s", env)
    root, fetched = box(tmp_path, passport_data())
    outcome, _ = run([render(stack, root, fetched, ask=_never)], FakeRunner())
    assert outcome.steps[0].reason is None, outcome.steps
    assert read_env(root, "aivis") == {"MEET": "false"}


def test_the_literal_on_the_file_s_key_passes_and_a_value_is_refused(
    tmp_path: Path,
) -> None:
    """The passport of a box whose option is off may carry the literal on the
    file's key (contract 3 rule 39); a value there is ``option-value``."""
    stack = _stack(tmp_path / "s", BOTH)
    literal = passport_data(asked={"aivis": {"AGE_KEY": LITERAL}})
    root, fetched = box(tmp_path / "a", literal)
    outcome, _ = run([render(stack, root, fetched, ask=_never)], FakeRunner())
    assert outcome.steps[0].reason is None, outcome.steps
    root, fetched = box(
        tmp_path / "b", passport_data(asked={"aivis": {"AGE_KEY": VALUE}})
    )
    outcome, _ = run([render(stack, root, fetched, ask=_never)], FakeRunner())
    reason = outcome.steps[0].reason
    assert reason is not None and reason.code == "render_env:option-value", reason
