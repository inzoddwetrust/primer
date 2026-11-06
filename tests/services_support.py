"""A product with services on ``file://`` remotes, and the machine's own plan
of it, for the tests of DM-46.

The product ``aivis`` has two co-located services -- ``comms`` in every
edition, ``payments`` in ``full`` only -- and a remote one, ``meet``. Each is a
bare repository with one commit tagged ``v1.0.0`` and a valid ``primer.yaml``;
the product's lock pins them. ``stacks_of`` runs the plan's deferred stacks
``sources`` and ``dependencies`` with real git and makes ``services`` and the
product's, as ``deploy_plan`` does on a box.
"""

import os
import shutil
from collections.abc import Sequence
from datetime import UTC, datetime
from itertools import count
from pathlib import Path

import yaml
from contract_support import example
from passport_support import passport_example, section, write_passport
from plan_support import ListSink

from pridem.events import PlanOutcome, Secrets
from pridem.plan import Deferred, Plan, StackSteps
from pridem.runner import Stream, SubprocessRunner
from pridem.stacks.passport import load_passport
from pridem.state import Box
from pridem.steps.passport import Fetched
from pridem.verbs.plans import Source, Wanted, deploy_plan
from pridem.verbs.run import Planned, Session

TAG = "v1.0.0"
NO_SECRETS = Secrets(())


ENV = {
    "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
    "HOME": "/nonexistent",
    "LANG": "C.UTF-8",
    "GIT_AUTHOR_NAME": "t",
    "GIT_AUTHOR_EMAIL": "t@example.org",
    "GIT_COMMITTER_NAME": "t",
    "GIT_COMMITTER_EMAIL": "t@example.org",
    "GIT_CONFIG_GLOBAL": os.devnull,
    "GIT_CONFIG_NOSYSTEM": "1",
}


def git(cwd: Path, *args: str) -> list[str]:
    out: list[str] = []

    def keep(stream: Stream, line: str, cut: bool) -> None:
        if stream is Stream.STDOUT:
            out.append(line)

    SubprocessRunner().run(
        ["git", "-C", str(cwd), *args], env=ENV, timeout=60, on_line=keep
    )
    return out


def remote(tmp: Path, name: str, files: dict[str, str], tag: str | None = TAG) -> str:
    """A bare ``<name>.git`` with one commit of ``files``; its commit."""
    work = tmp / "work" / name
    work.mkdir(parents=True)
    git(work, "init", "-q", "-b", "main")
    for path, text in files.items():
        (work / path).parent.mkdir(parents=True, exist_ok=True)
        (work / path).write_text(text)
    git(work, "add", "-A")
    git(work, "commit", "-q", "-m", "first")
    if tag is not None:
        git(work, "tag", tag)
    git(tmp, "clone", "-q", "--bare", str(work), str(tmp / f"{name}.git"))
    return git(work, "rev-parse", "HEAD")[0]


def comms_data() -> dict[str, object]:
    """``comms`` of contract 3, its seams whole, taking the product's profile."""
    data = example("service.yaml")
    env = data["env"]
    assert isinstance(env, dict)
    env["COMMS_API_URL"] = {"source": "address"}
    env["COMMS_SERVICE_TOKEN"] = {"source": "minted"}
    data["accepts"] = {
        "profile": {"validate": "comms validate --profile <dir>", "env": "PROFILE_DIR"}
    }
    return data


def payments_data() -> dict[str, object]:
    """A second service: no seams of its own."""
    data = example("service.yaml")
    data.update(
        {
            "name": "payments",
            "stacks": {
                "payments": {
                    "compose": "docker-compose.yml",
                    "app": {
                        "service": "api",
                        "port": 8000,
                        "health": "/health",
                        "ready": "/ready",
                    },
                    "migrate": "alembic upgrade head",
                }
            },
            "env": {"POSTGRES_PASSWORD": {"source": "minted"}},
            "provides": [],
            "requires": [],
        }
    )
    data.pop("update_window", None)
    data.pop("host", None)
    return data


def product_data(
    tmp: Path,
    *,
    comms_data: bool = True,
    extra_env: dict[str, object] | None = None,
) -> dict[str, object]:
    """``aivis`` of contract 3 with its services on ``file://``; without
    ``comms_data`` it gives comms no data (a comms that accepts none)."""
    more_env = dict(extra_env or {})
    data = example("product.yaml")
    data["dependencies"] = {
        "comms": {
            "repo": f"file://{tmp}/comms.git",
            "version": ">=1.0,<2",
            **({"data": {"profile": "comms-profile"}} if comms_data else {}),
        },
        "payments": {"repo": f"file://{tmp}/payments.git", "version": ">=1.0,<2"},
        "meet": {
            "repo": f"file://{tmp}/meet.git",
            "version": ">=1.0,<2",
            "topology": "remote",
        },
    }
    data["editions"] = {
        "core": {"services": ["comms", "meet"]},
        "full": {"services": ["comms", "payments", "meet"]},
    }
    env = data["env"]
    assert isinstance(env, dict)
    env.pop("PAYMENTS_API_URL")  # payments is outside core: no seam from it
    env["MEET_URL"] = {"source": "param"}
    env.update(more_env)
    data.pop("packages")
    return data


def remotes(
    tmp: Path,
    comms: dict[str, object] | None = None,
    product_env: dict[str, object] | None = None,
) -> None:
    """The three services and the product, the lock pinning ``v1.0.0``;
    ``comms`` -- another ``primer.yaml`` of comms, taking no data."""
    given = comms_data() if comms is None else comms
    heads = {
        "comms": remote(tmp, "comms", {"primer.yaml": yaml.safe_dump(given)}),
        "payments": remote(
            tmp, "payments", {"primer.yaml": yaml.safe_dump(payments_data())}
        ),
        "meet": remote(tmp, "meet", {"README": "meet\n"}),
    }
    lock = {
        "schema": 1,
        "resolved_at": datetime(2026, 11, 5, tzinfo=UTC),
        "dependencies": {
            name: {"version": "1.0.0", "tag": TAG, "commit": head[:7]}
            for name, head in heads.items()
        },
    }
    remote(
        tmp,
        "aivis",
        {
            "primer.yaml": yaml.safe_dump(
                product_data(tmp, comms_data=comms is None, extra_env=product_env)
            ),
            "primer.lock": yaml.safe_dump(lock),
            "comms-profile/kinds.yaml": "kinds: []\n",
        },
        tag=None,
    )


def passport_file(
    tmp: Path, edition: str, asked: dict[str, dict[str, str]] | None = None
) -> Path:
    data = passport_example()
    if asked is not None:
        data["asked"] = asked
    data["edition"] = edition
    data["packages"] = {}
    section(data, "product").update({"repo": f"file://{tmp}/aivis.git", "ref": "main"})
    params = section(data, "params")
    params["aivis"] = {"MEET_URL": "https://meet.example.org", "SUPPORT_LANGUAGE": "ru"}
    (tmp / "p").mkdir(exist_ok=True)
    return write_passport(tmp / "p", data)


def run_stacks(stacks: Sequence[StackSteps]) -> PlanOutcome:
    ticks = count()
    return Plan(
        [
            *(StackSteps(s.name, s.steps) for s in stacks),
            StackSteps("root", [], root=True),
        ],
        mode="install",
        role="test",
        runner=SubprocessRunner(),
        sink=ListSink(),
        clock=lambda: float(next(ticks)),
        now=lambda: datetime(2026, 11, 5, tzinfo=UTC),
    ).run()


def deferred(planned: Planned, name: str) -> list[StackSteps]:
    [found] = [s for s in planned.stacks if isinstance(s, Deferred) and s.name == name]
    made = found.build()
    assert made is not None, f"{name} is not known yet"
    return list(made)


def planned(
    tmp: Path,
    edition: str,
    *,
    gone: Sequence[str] = (),
    comms: dict[str, object] | None = None,
    asked: dict[str, dict[str, str]] | None = None,
    product_env: dict[str, object] | None = None,
    again: bool = False,
) -> tuple[Planned, Path]:
    """The plan of ``install`` on a box at ``tmp/box``, its sources and
    dependencies run -- the services' ladders and the product's then known;
    ``gone`` -- remotes removed first: a command that asks one fails."""
    if not again:  # ``again``: a second plan on the same box and remotes
        remotes(tmp, comms, product_env)
    for name in gone:
        shutil.rmtree(tmp / f"{name}.git")
    root = tmp / "box"
    file = passport_file(tmp, edition, asked)
    box = Box(root / "opt" / "pridem")
    made = deploy_plan(
        Session(box, "r1", Fetched(), NO_SECRETS),
        root,
        Wanted(mode="install", source=Source(file=file)),
        None,
    )
    assert made.fetched is not None
    made.fetched.passport = load_passport(file)
    for name in ("sources", "dependencies"):
        outcome = run_stacks(deferred(made, name))
        assert outcome.code.value == 0, outcome.steps
    return made, root
