"""Probes DM-41: CI runs on the versions boxes get, with actions pinned by SHA.

Every ``pip install`` of every workflow is one of four, each by a lock with
hashes or with no dependencies: the runtime from ``wheels/`` by
``requirements.lock`` with no index; the package itself without dependencies;
the dev tools by ``requirements-dev.lock``; the build backend by
``requirements-build.lock``. A job that installs the dev tools does it after
the runtime and the package, and no step that installs is conditional (an
``if:`` would leave the job without it). Every ``uses:`` of every workflow is
``owner/repo@<40 hex>``.

DM-82, by the dispatcher's word before the edit: the dev tools come by their
lock with hashes, not from the index constrained by ``pip freeze``; the check
covers every job that installs packages, ``tier3.yml`` included, not only the
jobs that set up Python. No step that holds a secret or the job token comes
before the last install of its job.

Checks back the recipe where it matters: the wheels in ``wheels/`` are
exactly the lock's (name, version, sha256) -- an extra wheel installs nothing
and so passes ``pip``, but not this test -- the runtime this very ``pytest``
imports has the lock's versions, and ``requirements-dev.lock`` has every dev
pin of ``pyproject.toml`` and the runtime of ``requirements.lock`` at its
versions, with its wheels' hashes, so installing it moves nothing.

Each check is a function of the text it reads, so each test plants a defect
it must catch next to the tree it must pass.
"""

import hashlib
import json
import re
import shlex
import shutil
import tomllib
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parents[1]
WORKFLOWS = REPO / ".github" / "workflows"
CI = WORKFLOWS / "ci.yml"
LOCK = REPO / "requirements.lock"
DEV_LOCK = REPO / "requirements-dev.lock"
TOOLS_LOCK = REPO / "requirements-tools.lock"
PYPROJECT = REPO / "pyproject.toml"
WHEELS = REPO / "wheels"

PINNED = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_./-]+@[0-9a-f]{40}")
LOCK_ENTRY = re.compile(r"^([A-Za-z0-9_.-]+)==(\S+)")
LOCK_HASH = re.compile(r"--hash=sha256:([0-9a-f]{64})")

Command = tuple[int, list[str]]

RUNTIME_COMMENT = "      # Runtime exactly as boxes get it"
PACKAGE_STEP = "      - run: python -m pip install --no-deps -e .\n"
DEV_STEP = (
    "      - run: python -m pip install --require-hashes -r requirements-dev.lock\n"
)
# What gives a step a secret or the job token.
HOLDS_SECRET = re.compile(r"\$\{\{[^}]*\b(secrets|github\.token)\b")


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


def _pip_installs(run: str) -> list[tuple[str, list[str]]]:
    """Each ``pip install`` command line of a ``run`` text, continuation lines
    joined, comments left out, with its tokens; other lines are not split."""
    out: list[tuple[str, list[str]]] = []
    for line in run.replace("\\\n", " ").splitlines():
        if line.lstrip().startswith("#") or not re.search(r"\bpip\s+install\b", line):
            continue
        tokens = shlex.split(line)
        if _has(tokens, "pip", "install"):
            out.append((line.strip(), tokens))
    return out


def _file(tokens: list[str], flag: str, name: str) -> bool:
    """``flag <path>`` in ``tokens`` where the path is the repository's ``name``
    -- relative, or under ``$GITHUB_WORKSPACE``."""
    return any(
        tokens[i] == flag and tokens[i + 1] in (name, f"$GITHUB_WORKSPACE/{name}")
        for i in range(len(tokens) - 1)
    )


def _install_kind(tokens: list[str]) -> str | None:
    """Which of the four installs ``tokens`` is; None -- none of them."""
    hashed = "--require-hashes" in tokens
    if (
        hashed
        and "--no-index" in tokens
        and (
            _file(tokens, "--find-links", "wheels/")
            or _file(tokens, "--find-links", "wheels")
        )
        and _file(tokens, "-r", "requirements.lock")
    ):
        return "runtime"
    if "--no-deps" in tokens and (
        _has(tokens, "-e", ".") or _has(tokens, "-e", "$GITHUB_WORKSPACE")
    ):
        return "package"
    if hashed and _file(tokens, "-r", "requirements-dev.lock"):
        return "dev"
    if hashed and _file(tokens, "-r", "requirements-build.lock"):
        return "build"
    return None


def ci_problems(text: str) -> list[str]:
    """What keeps the workflow ``text`` from installing only locked packages."""
    problems: list[str] = []
    jobs = _steps(yaml.safe_load(text))
    installing = 0
    for name, steps in jobs.items():
        found: dict[str, int] = {}
        index = 0
        for step in steps:
            run = step.get("run")
            if not isinstance(run, str):
                continue
            for line, tokens in _pip_installs(run):
                index += 1
                if "if" in step:
                    problems.append(f"{name}: a conditional install: {line.strip()}")
                kind = _install_kind(tokens)
                if kind is None:
                    problems.append(
                        f"{name}: pip install outside the recipe: {shlex.join(tokens)}"
                    )
                else:
                    found.setdefault(kind, index)
        if found:
            installing += 1
        if "dev" in found:
            if "runtime" not in found or "package" not in found:
                problems.append(
                    f"{name}: dev tools without the runtime and the package"
                )
            elif not found["runtime"] < found["package"] < found["dev"]:
                problems.append(f"{name}: recipe steps out of order")
    if not installing:
        problems.append("no job installs packages")
    return problems


def secret_problems(text: str) -> list[str]:
    """Steps that hold a secret or the job token before the last install of
    their job: whatever the install brings would run beside it."""
    problems: list[str] = []
    for name, steps in _steps(yaml.safe_load(text)).items():
        installs = [
            i
            for i, step in enumerate(steps)
            if isinstance(step.get("run"), str) and _pip_installs(str(step["run"]))
        ]
        if not installs:
            continue
        for i, step in enumerate(steps[: max(installs) + 1]):
            if HOLDS_SECRET.search(json.dumps(step)):
                problems.append(f"{name}: step {i} holds a secret before an install")
    return problems


def _hashes_of(text: str) -> dict[str, tuple[str, set[str]]]:
    return lock_entries(text)


def dev_lock_problems(
    pyproject: str, runtime_lock: str, dev_lock: str, wheels: Path
) -> list[str]:
    """What keeps ``requirements-dev.lock`` from pinning the dev tools of
    ``pyproject.toml`` without moving the runtime."""
    problems: list[str] = []
    dev = _hashes_of(dev_lock)
    for name, (_, hashes) in sorted(dev.items()):
        if not hashes:
            problems.append(f"{name}: no hash in the dev lock")
    declared = tomllib.loads(pyproject)["project"]["optional-dependencies"]["dev"]
    for requirement in declared:
        name, _, wanted = requirement.partition("==")
        key = _normalized(name)
        if not wanted:
            problems.append(f"{requirement}: a dev tool not pinned == in pyproject")
        elif key not in dev:
            problems.append(f"{key}: in pyproject, not in the dev lock")
        elif dev[key][0] != wanted:
            problems.append(
                f"{key}: pyproject pins {wanted}, the dev lock {dev[key][0]}"
            )
    runtime = lock_entries(runtime_lock)
    shipped = {
        _normalized(wheel.name.split("-")[0]): hashlib.sha256(
            wheel.read_bytes()
        ).hexdigest()
        for wheel in wheels.glob("*.whl")
    }
    for key, (locked, _) in sorted(runtime.items()):
        if key not in dev:
            problems.append(f"{key}: in requirements.lock, not in the dev lock")
            continue
        if dev[key][0] != locked:
            problems.append(
                f"{key}: the dev lock moves the runtime {locked} -> {dev[key][0]}"
            )
        if shipped.get(key) not in dev[key][1]:
            problems.append(f"{key}: the wheel's sha256 is not in the dev lock")
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
    files = {f.name: f.read_text() for f in sorted(WORKFLOWS.glob("*.yml"))}
    # the pair: all three workflows install packages, and each passes
    assert sorted(files) == ["ci.yml", "release.yml", "tier3.yml"]
    for name, workflow in files.items():
        assert ci_problems(workflow) == [], name
    text = CI.read_text()
    assert len(_steps(yaml.safe_load(text))) >= 3

    plants = {
        "no hashes": text.replace(" --require-hashes", "", 1),
        "index": text.replace(" --no-index", "", 1),
        "dev from the index": text.replace(
            DEV_STEP, '      - run: python -m pip install -e ".[dev]"\n', 1
        ),
        "dev constrained, not hashed": text.replace(
            DEV_STEP,
            DEV_STEP.replace(
                "--require-hashes -r requirements-dev.lock",
                '-c "$RUNNER_TEMP/runtime.txt" -e ".[dev]"',
            ),
            1,
        ),
        "dev first": text.replace(DEV_STEP, "", 1).replace(
            RUNTIME_COMMENT, DEV_STEP + RUNTIME_COMMENT, 1
        ),
        "package last": text.replace(PACKAGE_STEP, "", 1).replace(
            DEV_STEP, DEV_STEP + PACKAGE_STEP, 1
        ),
        "a conditional install": text.replace(
            DEV_STEP,
            DEV_STEP.replace(
                "      - run:", "      - if: github.ref == 'x'\n        run:"
            ),
            1,
        ),
    }
    tier3 = files["tier3.yml"]
    plants["tier3 dev from the index"] = tier3.replace(
        '-m pip install --require-hashes -r "$GITHUB_WORKSPACE/requirements-dev.lock"',
        '-m pip install -e "$GITHUB_WORKSPACE[dev]"',
    )
    plants["release build unhashed"] = files["release.yml"].replace(
        "pip install --require-hashes -r requirements-build.lock",
        "pip install flit_core",
    )
    for label, planted in plants.items():
        assert planted not in files.values(), label
        assert ci_problems(planted), label


def test_no_secret_before_the_last_install() -> None:
    files = {f.name: f.read_text() for f in sorted(WORKFLOWS.glob("*.yml"))}
    for name, workflow in files.items():
        assert secret_problems(workflow) == [], name
    tier3 = files["tier3.yml"]
    assert HOLDS_SECRET.search(tier3)  # the pair: tier 3 has secrets to see
    document = yaml.safe_load(tier3)
    steps = document["jobs"]["box"]["steps"]
    [venv] = [s for s in steps if str(s.get("name", "")).startswith("the probes' venv")]
    [key] = [s for s in steps if str(s.get("name", "")).startswith("the deploy key")]
    steps.remove(venv)
    steps.insert(steps.index(key) + 1, venv)
    planted = yaml.safe_dump(document, sort_keys=False)
    assert secret_problems(planted) == ["box: step 4 holds a secret before an install"]


def test_the_dev_lock_pins_the_dev_tools_and_the_runtime() -> None:
    pyproject, runtime, dev = (
        PYPROJECT.read_text(),
        LOCK.read_text(),
        DEV_LOCK.read_text(),
    )
    assert dev_lock_problems(pyproject, runtime, dev, WHEELS) == []
    assert len(lock_entries(dev)) > len(lock_entries(runtime)) > 0
    tools = lock_entries(TOOLS_LOCK.read_text())
    assert "pip-tools" in tools
    assert all(hashes for _, hashes in tools.values())

    click = lock_entries(runtime)["click"][0]
    pytest_pin = re.search(r'"pytest==([^"]+)"', pyproject)
    assert pytest_pin is not None
    [wheel] = WHEELS.glob("click-*.whl")
    wheel_hash = hashlib.sha256(wheel.read_bytes()).hexdigest()
    plants = {
        "runtime moved": (
            pyproject,
            dev.replace(f"click=={click} ", "click==0.0.1 ", 1),
            "click: the dev lock moves the runtime",
        ),
        "wheel hash missing": (
            pyproject,
            dev.replace(f"--hash=sha256:{wheel_hash}", "--hash=sha256:" + "0" * 64, 1),
            "click: the wheel's sha256 is not in the dev lock",
        ),
        "dev tool moved": (
            pyproject.replace(f'"pytest=={pytest_pin.group(1)}"', '"pytest==0.0.1"', 1),
            dev,
            "pytest: pyproject pins 0.0.1",
        ),
        "dev tool unpinned": (
            pyproject.replace(f'"pytest=={pytest_pin.group(1)}"', '"pytest"', 1),
            dev,
            "pytest: a dev tool not pinned == in pyproject",
        ),
        "a runtime package left out": (
            pyproject,
            re.sub(r"^click==.*?(?=^\S)", "", dev, count=1, flags=re.M | re.S),
            "click: in requirements.lock, not in the dev lock",
        ),
    }
    for label, (project, lock, words) in plants.items():
        assert (project, lock) != (pyproject, dev), label
        found = dev_lock_problems(project, runtime, lock, WHEELS)
        assert any(words in problem for problem in found), (label, found)


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


def checkout_problems(text: str) -> tuple[int, list[str]]:
    """(number of ``actions/checkout``, those that keep the job token in
    ``.git/config``: without ``persist-credentials: false``)."""
    count, problems = 0, []
    for name, steps in _steps(yaml.safe_load(text)).items():
        for step in steps:
            if not str(step.get("uses", "")).startswith("actions/checkout@"):
                continue
            count += 1
            given = step.get("with")
            if (
                not isinstance(given, dict)
                or given.get("persist-credentials") is not False
            ):
                problems.append(f"{name}: checkout keeps the job token")
    return count, problems


def test_no_checkout_keeps_the_job_token() -> None:
    """DM-82: every checkout of every workflow leaves the token out of
    ``.git/config``, where every later step could read it."""
    total = 0
    for file in sorted(WORKFLOWS.glob("*.yml")):
        count, problems = checkout_problems(file.read_text())
        assert problems == [], file.name
        total += count
    assert total == 7  # the pair: ci 4, release 2, tier3 1
    text = CI.read_text()
    flag = "          persist-credentials: false\n"
    planted = {
        "dropped": text.replace(flag, "", 1),
        "true": text.replace(flag, "          persist-credentials: true\n", 1),
        "a string": text.replace(flag, '          persist-credentials: "false"\n', 1),
    }
    for label, defect in planted.items():
        assert defect != text, label
        assert len(checkout_problems(defect)[1]) == 1, label


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
