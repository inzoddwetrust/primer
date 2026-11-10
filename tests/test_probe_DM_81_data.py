"""Probe of DM-81: the data of a service is validated before the service sees it.

The product's data a service takes (form D) is copied to a directory of its
own, named by what it holds, and validated there by the service's new image;
the override that binds it into the service goes in place only at the end of
a green plan. Data the service refuses never reaches the running service: the
copy it mounts and the override are as they were, the step is red. The pair:
data it takes is copied and validated, the copy the service mounted before
still there for the container that runs on it.

Changed by DM-89, on the dispatcher's word before the change: the override
goes in place in ``finalize`` with ``current`` and ``.env``, not in
``data_copy``. The deploy's override (``<entry>.next.yml``) binds the new
copy; the running release's (``<entry>.yml``) is untouched by the step, red
or green.
"""

from dataclasses import replace
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
    this run rendered a new override for new data (the deploy's)."""
    tmp.mkdir()
    step, compose, item = _copy(tmp)
    mounted = item.home / "profile@00000000deadbeef"
    mounted.mkdir(parents=True)
    (mounted / "kinds.yaml").write_text("kinds: [old]\n")
    write_override(replace(compose, staged=False), OLD)
    write_override(compose, NEW)
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
    running = replace(compose, staged=False)
    assert running.override.read_text() == OLD
    assert (mounted / "kinds.yaml").read_text() == "kinds: [old]\n"
    assert str(item.target) not in running.override.read_text()

    # the pair: data the service takes -- the new override, after validate
    step, compose, item, mounted = _box(tmp_path / "taken")
    script = [image_call(compose, "comms-app", IMAGE), _validate(compose, item, 0)]
    with FakeRunner(*script) as runner:
        outcome, _ = run([step], runner)
    assert outcome.code is ExitCode.OK, outcome.steps
    assert replace(compose, staged=False).override.read_text() == OLD  # finalize's
    assert compose.override.read_text() == NEW
    assert (item.target / "kinds.yaml").read_text() == "kinds: [a]\n"
    assert item.target != mounted
    assert (mounted / "kinds.yaml").read_text() == "kinds: [old]\n"
    assert outcome.steps[0].verify["data"] == {"profile": str(item.target)}
