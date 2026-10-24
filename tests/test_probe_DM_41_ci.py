"""Probes DM-41: CI runs on the versions boxes get, with actions pinned by SHA.

Every job that sets up Python installs, in this order: the runtime from
``wheels/`` by ``requirements.lock`` with hashes and no index; the package
without dependencies; the dev tools constrained to the runtime just installed
(``pip freeze --exclude-editable`` into a file, then ``-c`` that file). Every
``uses:`` of every workflow is ``owner/repo@<40 hex>``.

Two checks back the recipe where it matters: the wheels in ``wheels/`` are
exactly the lock's (name, version, sha256) -- an extra wheel installs nothing
and so passes ``pip``, but not this test -- and the runtime this very
``pytest`` imports has the lock's versions.

Each check is a function of the text it reads, so each test plants a defect
it must catch next to the tree it must pass.
"""

import hashlib
import re
import shlex
import shutil
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parents[1]
WORKFLOWS = REPO / ".github" / "workflows"
CI = WORKFLOWS / "ci.yml"
LOCK = REPO / "requirements.lock"
WHEELS = REPO / "wheels"

PINNED = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_./-]+@[0-9a-f]{40}")
LOCK_ENTRY = re.compile(r"^([A-Za-z0-9_.-]+)==(\S+)")
LOCK_HASH = re.compile(r"--hash=sha256:([0-9a-f]{64})")

Command = tuple[int, list[str]]

RUNTIME_COMMENT = "      # Runtime exactly as boxes get it"
PACKAGE_STEP = "      - run: python -m pip install --no-deps -e .\n"
DEV_BLOCK = (
    "      - run: |\n"
    '          python -m pip freeze --exclude-editable > "$RUNNER_TEMP/runtime.txt"\n'
    '          python -m pip install -c "$RUNNER_TEMP/runtime.txt" -e ".[dev]"\n'
)


def _normalized(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _has(tokens: list[str], *pair: str) -> bool:
    return any(tokens[i : i + len(pair)] == list(pair) for i in range(len(tokens)))


def _steps(document: object) -> dict[str, list[dict[str, object]]]:
    assert isinstance(document, dict)
    jobs = document.get("jobs")
    assert isinstance(jobs, dict)
    out: dict[str, list[dict[str, object]]] = {}
    for name, job in jobs.items():
        assert isinstance(job, dict)
        steps = job.get("steps", [])
        assert isinstance(steps, list)
        out[str(name)] = [step for step in steps if isinstance(step, dict)]
    return out


def _commands(steps: list[dict[str, object]]) -> list[Command]:
    """Every shell line of the job's ``run`` steps, numbered in order."""
    out: list[Command] = []
    for step in steps:
        run = step.get("run")
        if isinstance(run, str):
            for line in run.splitlines():
                if line.strip() and not line.lstrip().startswith("#"):
                    out.append((len(out), shlex.split(line)))
    return out


def ci_problems(text: str) -> list[str]:
    """What keeps the CI of ``text`` from testing the locked runtime."""
    problems: list[str] = []
    jobs = {
        name: steps
        for name, steps in _steps(yaml.safe_load(text)).items()
        if any(
            str(step.get("uses", "")).startswith("actions/setup-python@")
            for step in steps
        )
    }
    if not jobs:
        return ["no job sets up Python"]
    for name, steps in jobs.items():
        runtime = package = freeze = dev = None
        frozen: str | None = None
        for index, tokens in _commands(steps):
            if _has(tokens, "pip", "freeze", "--exclude-editable", ">"):
                freeze, frozen = index, tokens[tokens.index(">") + 1]
                continue
            if not _has(tokens, "pip", "install"):
                continue
            if (
                "--no-index" in tokens
                and _has(tokens, "--find-links", "wheels/")
                and "--require-hashes" in tokens
                and _has(tokens, "-r", "requirements.lock")
            ):
                runtime = index
            elif "--no-deps" in tokens and _has(tokens, "-e", "."):
                package = index
            elif _has(tokens, "-e", ".[dev]") and frozen and _has(tokens, "-c", frozen):
                dev = index
            else:
                problems.append(
                    f"{name}: pip install outside the recipe: {shlex.join(tokens)}"
                )
        order = [runtime, package, freeze, dev]
        labels = [
            "runtime from the lock",
            "package",
            "runtime freeze",
            "constrained dev",
        ]
        for label, at in zip(labels, order, strict=True):
            if at is None:
                problems.append(f"{name}: no {label} step")
        present = [at for at in order if at is not None]
        if present != sorted(present):
            problems.append(f"{name}: recipe steps out of order")
    return problems


def _uses(node: object) -> list[str]:
    if isinstance(node, dict):
        found = [str(v) for k, v in node.items() if k == "uses"]
        return found + [u for v in node.values() for u in _uses(v)]
    if isinstance(node, list):
        return [u for item in node for u in _uses(item)]
    return []


def unpinned(text: str) -> tuple[int, list[str]]:
    """(number of ``uses:``, those not pinned by a 40-character SHA)."""
    found = _uses(yaml.safe_load(text))
    return len(found), [use for use in found if not PINNED.fullmatch(use)]


def lock_entries(text: str) -> dict[str, tuple[str, set[str]]]:
    """Normalized name -> (version, sha256 hashes) of ``requirements.lock``."""
    out: dict[str, tuple[str, set[str]]] = {}
    current: str | None = None
    for line in text.splitlines():
        entry = LOCK_ENTRY.match(line)
        if entry:
            current = _normalized(entry.group(1))
            out[current] = (entry.group(2), set())
        hashed = LOCK_HASH.search(line)
        if hashed and current is not None:
            out[current][1].add(hashed.group(1))
    return out


def wheel_problems(wheels: Path, lock_text: str) -> list[str]:
    """Differences between the wheels and the lock in (name, version, sha256)."""
    locked = lock_entries(lock_text)
    problems: list[str] = []
    seen: set[str] = set()
    for wheel in sorted(wheels.glob("*.whl")):
        name, ver = wheel.name.split("-")[:2]
        key = _normalized(name)
        seen.add(key)
        if key not in locked:
            problems.append(f"{wheel.name}: not in the lock")
            continue
        if ver != locked[key][0]:
            problems.append(f"{wheel.name}: the lock pins {locked[key][0]}")
        digest = hashlib.sha256(wheel.read_bytes()).hexdigest()
        if digest not in locked[key][1]:
            problems.append(f"{wheel.name}: sha256 is not the lock's")
    for key in sorted(set(locked) - seen):
        problems.append(f"{key}: locked, no wheel")
    return problems


def runtime_problems(lock_text: str) -> list[str]:
    """Locked packages whose installed version differs from the lock."""
    problems: list[str] = []
    for name, (locked, _) in sorted(lock_entries(lock_text).items()):
        try:
            installed = version(name)
        except PackageNotFoundError:
            problems.append(f"{name}: not installed")
            continue
        if installed != locked:
            problems.append(f"{name}: installed {installed}, locked {locked}")
    return problems


def test_probe_DM_41_ci_runs_on_locked_versions() -> None:
    text = CI.read_text()
    assert ci_problems(text) == []
    assert len(_steps(yaml.safe_load(text))) >= 3

    plants = {
        "no hashes": text.replace(" --require-hashes", "", 1),
        "index": text.replace(" --no-index", "", 1),
        "dev unconstrained": text.replace(' -c "$RUNNER_TEMP/runtime.txt"', "", 1),
        "dev first": text.replace(DEV_BLOCK, "", 1).replace(
            RUNTIME_COMMENT, DEV_BLOCK + RUNTIME_COMMENT, 1
        ),
        "old recipe": re.sub(
            r"      # Runtime exactly.*?runtime.txt\" -e \"\.\[dev\]\"\n",
            '      - run: python -m pip install -e ".[dev]"\n',
            text,
            count=1,
            flags=re.S,
        ),
        "package last": text.replace(PACKAGE_STEP, "", 1).replace(
            DEV_BLOCK, DEV_BLOCK + PACKAGE_STEP, 1
        ),
    }
    for label, planted in plants.items():
        assert planted != text, label
        assert ci_problems(planted), label


def test_probe_DM_41_ci_actions_pinned_by_sha() -> None:
    files = sorted([*WORKFLOWS.glob("*.yml"), *WORKFLOWS.glob("*.yaml")])
    assert files
    total = 0
    for file in files:
        count, bad = unpinned(file.read_text())
        assert bad == [], f"{file.name}: {bad}"
        total += count
    assert total > 0, "no uses: seen"

    text = CI.read_text()
    sha = re.search(r"actions/checkout@([0-9a-f]{40})", text)
    assert sha is not None
    for planted in (
        text.replace(f"actions/checkout@{sha.group(1)}", "actions/checkout@v7", 1),
        text.replace(
            f"actions/checkout@{sha.group(1)}",
            f"actions/checkout@{sha.group(1)[:39]}",
            1,
        ),
        text.replace(
            f"actions/checkout@{sha.group(1)}",
            f"actions/checkout@{sha.group(1).upper()}",
            1,
        ),
    ):
        assert planted != text
        assert len(unpinned(planted)[1]) == 1


def test_wheels_equal_the_lock(tmp_path: Path) -> None:
    lock = LOCK.read_text()
    assert wheel_problems(WHEELS, lock) == []
    assert len(lock_entries(lock)) == len(list(WHEELS.glob("*.whl"))) > 0

    extra = tmp_path / "extra"
    shutil.copytree(WHEELS, extra)
    (extra / "left_over-1.0-py3-none-any.whl").write_bytes(b"x")
    assert wheel_problems(extra, lock) == [
        "left_over-1.0-py3-none-any.whl: not in the lock"
    ]

    changed = tmp_path / "changed"
    shutil.copytree(WHEELS, changed)
    [target] = changed.glob("click-*.whl")
    target.write_bytes(target.read_bytes() + b"\0")
    assert wheel_problems(changed, lock) == [f"{target.name}: sha256 is not the lock's"]

    missing = tmp_path / "missing"
    shutil.copytree(WHEELS, missing)
    [gone] = missing.glob("click-*.whl")
    gone.unlink()
    assert wheel_problems(missing, lock) == ["click: locked, no wheel"]


def test_installed_runtime_equals_the_lock() -> None:
    lock = LOCK.read_text()
    assert runtime_problems(lock) == []
    assert len(lock_entries(lock)) > 0

    planted = re.sub(r"^click==\S+", "click==0.0.1", lock, count=1, flags=re.M)
    assert planted != lock
    assert runtime_problems(planted) == [
        f"click: installed {version('click')}, locked 0.0.1"
    ]
