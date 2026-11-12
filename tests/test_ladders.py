"""Every ladder of every deploy verb is made whole and is valid (DM-24 FIX).

The plan checks its stacks -- one root, unique names, and in each stack unique
step names and orders -- when it is made (``plan.ladder``), and each part of a
deferred stack, by the same check, when the run reaches it. A step with an
order its stack already holds was red only on a box, at the first ``update``
(tier 3, DM-24: ``stand`` and ``fetch_root`` both at 2). Here the real
``deploy_plan`` of each verb and role has every deferred stack made, as the run
makes it once the steps before it read the passport and the target -- the
blank's ``primer.yaml`` as the product -- and each part is checked as the run
checks it.
"""

from pathlib import Path

import pytest
from compose_support import blank
from passport_support import passport_example, section, write_passport
from plan_support import ListSink

from pridem.events import Secrets
from pridem.plan import Plan, StackSteps, ladder
from pridem.runner import FakeRunner
from pridem.stacks.passport import load_passport
from pridem.state import Box
from pridem.steps.passport import Fetched
from pridem.steps.sources import FetchRoot, Target
from pridem.verbs.plans import Source, Wanted, deploy_plan
from pridem.verbs.run import Session

COMMIT = "0e82be562d186afc933b8779d91dddcae4278cea"

CASES = [
    ("update", "test", False),
    ("deploy", "test", False),
    ("install", "test", False),
    ("reinstall", "test", False),
    ("doctor", "test", False),
    ("update", "prod", False),
    ("install", "prod", False),
    ("rollback", "prod", True),
]
"""Verb, role, and whether it is the plan of ``rollback`` (mode ``deploy``)."""


def _made(
    fs_root: Path, verb: str, role: str, rollback: bool
) -> tuple[Plan, list[StackSteps]]:
    """The plan of ``verb`` on a box of ``role``, every deferred stack made;
    the stacks made, in the ladder's order."""
    data = passport_example()
    section(data, "server")["role"] = role
    if role != "test":  # passport rule 4: a release tag there
        section(data, "product")["ref"] = "v1.0.0"
    data["edition"] = "core"  # the blank's own edition
    file = write_passport(fs_root, data)
    mode = verb if verb in ("install", "reinstall", "doctor") else "deploy"
    wanted = Wanted(mode=mode, source=Source(file=file), rollback=rollback)
    box = Box(fs_root / "opt" / "pridem")
    session = Session(box, "2026-11-12T10:00:00Z-a3f9", Fetched(), Secrets(()))
    planned = deploy_plan(session, fs_root, wanted, None)
    assert planned.fetched is not None
    planned.fetched.passport = load_passport(file)  # what fetch_passport read
    plan = Plan(  # whole stacks and finally: validated as a run makes its plan
        planned.stacks,
        mode="doctor" if verb == "doctor" else mode,  # type: ignore[arg-type]
        role=role,  # type: ignore[arg-type]
        runner=FakeRunner(),
        sink=ListSink(),
        finally_=planned.finally_,
    )
    stacks: list[StackSteps] = []
    for stack in planned.stacks:
        if isinstance(stack, StackSteps):
            stacks.append(stack)
            continue
        built = stack.build()
        assert built, f"{stack.name} is not made once {stack.after} has read"
        for part in built:  # a deferred part: validated as the run reaches it
            ladder([StackSteps(part.name, list(part.steps), root=True)])
        stacks += built
        if stack.name == "sources":  # what fetch_root reads: the target
            [fetch] = [s for s in built[0].steps if isinstance(s, FetchRoot)]
            fetch.target = Target("main", role == "test", COMMIT)
            fetch.resolved.product = blank()
            fetch.resolved.releases[fetch.stack] = fs_root / "release"
    return plan, stacks


@pytest.mark.parametrize(("verb", "role", "rollback"), CASES)
def test_every_ladder_of_every_verb_is_made_whole(
    tmp_path: Path, verb: str, role: str, rollback: bool
) -> None:
    """``Plan`` takes the whole ladder: no stack holds two steps of one order
    or one name. The pair -- the ladder is the whole one: the product's
    entries, ``finalize`` at the end, ``stand`` where it stands, and
    ``rollback`` only in the plan of ``rollback``."""
    plan, stacks = _made(tmp_path, verb, role, rollback)
    assert plan is not None
    names = [stack.name for stack in stacks]
    assert {"sources", "dependencies", "blank", "finalize"} <= set(names), names
    assert names[-1] == "finalize"
    assert ("rollback" in names) is rollback
    [sources] = [stack for stack in stacks if stack.name == "sources"]
    stands = verb in ("update", "deploy") and role == "test"
    assert ("stand" in [step.name for step in sources.steps]) is stands
