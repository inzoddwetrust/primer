"""Probes DM-6: the step frame and the plan."""

import pytest
from plan_support import Journal, ScriptedStep, plan, red

from pridem.events import Code, StepRecord
from pridem.plan import StackSteps
from pridem.report.codes import ExitCode


def _ladder(journal: Journal) -> list[StackSteps]:
    return [
        StackSteps("comms", [ScriptedStep("migrate", 1, journal)]),
        StackSteps("aivis", [ScriptedStep("build", 1, journal)], root=True),
    ]


def test_probe_DM_6_doctor_calls_no_act() -> None:
    journal = Journal()
    doctor, _ = plan(_ladder(journal), "doctor")
    outcome = doctor.run()
    assert journal == ["comms/migrate:check", "aivis/build:check"]
    assert [(d.stack, d.name) for d in outcome.doctor_diff] == [
        ("comms", "migrate"),
        ("aivis", "build"),
    ]
    assert outcome.code is ExitCode.INCOMPLETE

    # Pair: deploy over the same ladder does call act.
    journal.clear()
    deploy, _ = plan(_ladder(journal), "deploy")
    assert deploy.run().code is ExitCode.OK
    assert [entry for entry in journal if entry.endswith(":act")] == [
        "comms/migrate:act",
        "aivis/build:act",
    ]


def test_probe_DM_6_red_verify_skips_rest_exit_1() -> None:
    """DM-42 (contract 2 v1.6): reasons and incomplete entries are codes with
    parameters, not phrases; the data changed form only, each assertion keeps
    its strength.
    """
    journal = Journal()
    stacks = [
        StackSteps(
            "aivis",
            [
                ScriptedStep("sources", 1, journal),
                red("build", 2, journal),
                ScriptedStep("up", 3, journal),
                ScriptedStep("health", 4, journal),
            ],
            root=True,
        )
    ]
    outcome = plan(stacks)[0].run()
    assert [(r.name, r.status) for r in outcome.steps] == [
        ("sources", "ok"),
        ("build", "failed"),
        ("up", "skipped"),
        ("health", "skipped"),
    ]
    assert outcome.steps[1].verify == {"seen": "x"}
    # DM-42 (contract 2 v1.6): the reason is a code with parameters
    after = Code("after-failure", {"phase": "main", "stack": "aivis", "name": "build"})
    assert all(r.reason == after for r in outcome.steps[2:])
    assert "aivis/up:check" not in journal
    assert outcome.code is ExitCode.FAILED

    # Pair: the same ladder without the red step is green and runs everything.
    journal.clear()
    green = [
        StackSteps(
            "aivis",
            [ScriptedStep(n, i, journal) for i, n in enumerate(["a", "b", "c"], 1)],
            root=True,
        )
    ]
    result = plan(green)[0].run()
    assert result.code is ExitCode.OK
    assert [r.status for r in result.steps] == ["ok", "ok", "ok"]


def _with_point(journal: Journal, failing: str) -> list[StackSteps]:
    steps = [
        red("build", 1, journal)
        if failing == "before"
        else ScriptedStep("build", 1, journal),
        red("migrate", 2, journal, point_of_no_return=True)
        if failing == "at"
        else ScriptedStep(
            "migrate",
            2,
            journal,
            point_of_no_return=True,
            act_raises=RuntimeError("migration broke halfway")
            if failing == "act"
            else None,
        ),
        red("up", 3, journal) if failing == "after" else ScriptedStep("up", 3, journal),
    ]
    return [StackSteps("aivis", steps, root=True)]


def _restore(journal: Journal) -> list[StackSteps]:
    return [StackSteps("aivis", [ScriptedStep("up_old", 1, journal)])]


def _finally(journal: Journal) -> list[StackSteps]:
    return [StackSteps("aivis", [ScriptedStep("gc", 1, journal)])]


def test_probe_DM_6_red_before_point_of_no_return_restores_old() -> None:
    journal = Journal()
    run, _ = plan(
        _with_point(journal, "before"),
        restore=_restore(journal),
        finally_=_finally(journal),
    )
    outcome = run.run()
    assert [r.name for r in outcome.restore] == ["up_old"]
    assert outcome.restore[0].status == "ok"
    assert outcome.needs_restore is False
    assert outcome.code is ExitCode.FAILED
    assert "aivis/migrate:act" not in journal
    assert journal.index("aivis/up_old:act") < journal.index("aivis/gc:act")

    # Pair: a green plan does not touch the old composition.
    journal.clear()
    green, _ = plan(
        _with_point(journal, "none"),
        restore=_restore(journal),
        finally_=_finally(journal),
    )
    assert green.run().restore == ()
    assert "aivis/up_old:check" not in journal


@pytest.mark.parametrize("failing", ["act", "at", "after"])
def test_probe_DM_6_red_after_point_of_no_return_needs_restore(failing: str) -> None:
    journal = Journal()
    run, _ = plan(
        _with_point(journal, failing),
        restore=_restore(journal),
        finally_=_finally(journal),
    )
    outcome = run.run()
    assert outcome.needs_restore is True
    assert outcome.restore == ()
    assert "aivis/up_old:check" not in journal
    assert [r.name for r in outcome.finally_] == ["gc"]
    assert outcome.code is ExitCode.FAILED


def test_probe_DM_6_ladder_orders_providers_before_product() -> None:
    journal = Journal()
    stacks = [
        StackSteps("aivis", [ScriptedStep("up", 1, journal)], root=True),
        StackSteps("payments", [ScriptedStep("up", 1, journal)]),
        StackSteps(
            "comms",
            [ScriptedStep("up", 2, journal), ScriptedStep("migrate", 1, journal)],
        ),
    ]
    outcome = plan(stacks)[0].run()
    assert [(r.stack, r.name, r.order) for r in outcome.steps] == [
        ("payments", "up", 1),
        ("comms", "migrate", 1),
        ("comms", "up", 2),
        ("aivis", "up", 1),
    ]

    # A box of a shared remote service: the root is a service, no product.
    meet = plan([StackSteps("velo-meet", [ScriptedStep("up", 1, journal)], root=True)])[
        0
    ]
    assert [r.stack for r in meet.run().steps] == ["velo-meet"]

    no_root = [StackSteps("aivis", [ScriptedStep("up", 1, journal)])]
    two_roots = [
        StackSteps("aivis", [ScriptedStep("up", 1, journal)], root=True),
        StackSteps("comms", [ScriptedStep("up", 1, journal)], root=True),
    ]
    for bad in (no_root, two_roots):
        with pytest.raises(ValueError, match="exactly one root"):
            plan(bad)


def test_probe_DM_6_finally_runs_on_red() -> None:
    journal = Journal()
    stacks = [StackSteps("aivis", [red("build", 1, journal)], root=True)]
    outcome = plan(stacks, finally_=_finally(journal))[0].run()
    assert outcome.code is ExitCode.FAILED
    assert [(r.name, r.status) for r in outcome.finally_] == [("gc", "ok")]
    assert "aivis/gc:verify" in journal

    # Pair: finally runs on green too.
    journal.clear()
    green = [StackSteps("aivis", [ScriptedStep("build", 1, journal)], root=True)]
    assert [
        r.name for r in plan(green, finally_=_finally(journal))[0].run().finally_
    ] == ["gc"]


def test_probe_DM_6_step_without_verify_fact_is_invalid() -> None:
    """DM-42 (contract 2 v1.6): reasons and incomplete entries are codes with
    parameters, not phrases; the data changed form only, each assertion keeps
    its strength.
    """
    journal = Journal()
    stacks = [
        StackSteps(
            "aivis",
            [
                ScriptedStep("build", 1, journal, fact={}),
                ScriptedStep("up", 2, journal),
            ],
            root=True,
        )
    ]
    outcome = plan(stacks)[0].run()
    assert [(r.name, r.status, r.reason) for r in outcome.steps] == [
        ("build", "failed", Code("no-fact")),  # DM-42: codes, not phrases (v1.6)
        (
            "up",
            "skipped",
            Code("after-failure", {"phase": "main", "stack": "aivis", "name": "build"}),
        ),
    ]
    assert outcome.code is ExitCode.FAILED
    with pytest.raises(ValueError, match="non-empty verify fact"):
        StepRecord("aivis", "build", 1, "ok", verify={})

    # Pair: a step that reads back a fact is ok and carries it.
    journal.clear()
    ok = [
        StackSteps(
            "aivis",
            [ScriptedStep("build", 1, journal, fact={"image_id": "sha256:1"})],
            root=True,
        )
    ]
    assert plan(ok)[0].run().steps[0].verify == {"image_id": "sha256:1"}
