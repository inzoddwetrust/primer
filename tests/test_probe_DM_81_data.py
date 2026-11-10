"""Probe of DM-81: the data of a service is validated before the service sees it.

The product's data a service takes (form D) is copied to a directory of its
own, named by what it holds, and validated there by the service's new image;
the override that binds it into the service is put in place only after a
green ``validate``. Data the service refuses never reaches the running
service: the copy it mounts and the override are as they were, the step is
red. The pair: data it takes is in place after the check, the copy the
service mounted before still there for the container that runs on it.
"""

from pathlib import Path

from compose_support import image_call, run
from test_steps_services import IMAGE, _copy

from pridem.report.codes import ExitCode
from pridem.runner import FakeCall, FakeRunner
from pridem.steps.compose import ComposeStack, write_override
from pridem.steps.services import DataCopy, DataItem

OLD = "the override that binds the copy the service runs on\n"
NEW = "the override build rendered: it binds the new copy\n"


def _validate(compose: ComposeStack, item: DataItem, code: int) -> FakeCall:
    labels = [
        word
        for key, value in compose.release_labels().items()
        for word in ("--label", f"{key}={value}")
    ]
    return FakeCall(
        (
            "docker",
            "run",
            "--rm",
            "--network",
            "none",
            "--cap-drop",
            "ALL",
            "--pull",
            "never",
            *labels,
            "--mount",  # never -v: it splits at a colon (DM-86 FIX)
            f"type=bind,source={item.target},target={item.container},readonly",
            "-e",
            "PROFILE_DIR=/primer/data/profile",
            IMAGE,
            "comms",
            "validate",
            "--profile",
            "/primer/data/profile",
        ),
        code=code,
    )


def _box(tmp: Path) -> tuple[DataCopy, ComposeStack, DataItem, Path]:
    """A service running on its old copy, its override on disk; ``build`` of
    this run rendered a new override for new data (the candidate)."""
    tmp.mkdir()
    step, compose, item = _copy(tmp)
    mounted = item.home / "profile@00000000deadbeef"
    mounted.mkdir(parents=True)
    (mounted / "kinds.yaml").write_text("kinds: [old]\n")
    write_override(compose, OLD)
    write_override(compose.candidate(), NEW)
    step.handoff.texts[compose.entry] = NEW
    return step, compose, item, mounted


def test_probe_DM_81_data_validated_before_the_service_sees_it(tmp_path: Path) -> None:
    step, compose, item, mounted = _box(tmp_path / "refused")
    script = [image_call(compose, "comms-app", IMAGE), _validate(compose, item, 3)]
    with FakeRunner(*script) as runner:
        outcome, _ = run([step], runner)
    assert outcome.code is ExitCode.FAILED, outcome.steps
    [record] = outcome.steps
    assert record.reason is not None
    assert record.reason.code == "data_copy:validate-failed"
    # the running service does not see the refused data: its override and the
    # copy it mounts are as they were; the refused copy is bound by nothing
    assert compose.override.read_text() == OLD
    assert not compose.candidate().override.exists()
    assert (mounted / "kinds.yaml").read_text() == "kinds: [old]\n"
    assert str(item.target) not in compose.override.read_text()

    # the pair: data the service takes -- the new override, after validate
    step, compose, item, mounted = _box(tmp_path / "taken")
    script = [image_call(compose, "comms-app", IMAGE), _validate(compose, item, 0)]
    with FakeRunner(*script) as runner:
        outcome, _ = run([step], runner)
    assert outcome.code is ExitCode.OK, outcome.steps
    assert compose.override.read_text() == NEW
    assert (item.target / "kinds.yaml").read_text() == "kinds: [a]\n"
    assert item.target != mounted
    assert (mounted / "kinds.yaml").read_text() == "kinds: [old]\n"
    assert outcome.steps[0].verify["data"] == {"profile": str(item.target)}
