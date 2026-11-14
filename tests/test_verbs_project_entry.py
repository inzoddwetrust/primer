"""DM-86, pass 4b: a verb in a service of another entry of the product
(``entry``), a verb on a job of an entry (a one-off container), and a seam
whose value is a service's ``asked``."""

import copy
import json
from pathlib import Path

import pytest
import yaml
from data_support import SHA, STACK
from test_verbs_data import (
    CONFIG,
    _cli,
    _verdict,
    compose,
    config_call,
    git_call,
    lines,
    running_call,
)
from test_verbs_project import _box

from pridem.events import Json
from pridem.runner import FakeCall, FakeRunner
from pridem.stacks.schema import PRIMER_YAML, Product, load_primer_yaml, rule_problems
from pridem.steps.compose import ComposeStack, forbidden

FILES = "files"
FILES_CONFIG: dict[str, Json] = {
    "services": {
        "files": {"image": "postgres:16-alpine@sha256:x"},
        "files-list": {"image": "postgres:16-alpine@sha256:x"},
    }
}
BUILT_IMAGE = f"{STACK}-init:{SHA[:12]}"
VERBS: dict[str, Json] = {
    "files-ls": {
        "run": "ls -1 /srv/files",
        "entry": FILES,
        "service": "files-list",
    },
    "files-ping": {"run": "true", "entry": FILES, "service": "files"},
    "init-again": {"run": "python -m app.seed bootstrap", "service": "init"},
}


def _two_entry_box(tmp_path: Path) -> tuple[ComposeStack, ComposeStack]:
    """The blank's box with a second entry ``files`` (a running service and a
    job from a registry) and the blank's own job ``init`` built from its
    code; the verbs of ``VERBS``."""
    _box(tmp_path, verbs={})
    release = (tmp_path / "opt" / STACK / "current").resolve()
    primer = yaml.safe_load((release / "primer.yaml").read_text())
    primer["verbs"] = VERBS
    primer["stacks"][FILES] = {
        "compose": "files-compose.yml",
        "persistent": True,
        "jobs": {"list": {"service": "files-list"}},
    }
    primer["stacks"][STACK]["jobs"] = {"init": {"service": "init"}}
    (release / "primer.yaml").write_text(yaml.safe_dump(primer, sort_keys=False))
    (release / "files-compose.yml").write_text(yaml.safe_dump(FILES_CONFIG))
    made = load_primer_yaml(release / "primer.yaml")
    files = ComposeStack(made, FILES, release, release.name, release.name, tmp_path)
    return compose(tmp_path), files


def _oneoff(cs: ComposeStack, service: str, *argv: str, code: int = 0) -> FakeCall:
    """The command as docker gets it (par0 14.2)."""
    return FakeCall(
        tuple(
            cs.argv(
                "run",
                "--rm",
                "--no-deps",
                operands=(
                    service,
                    *argv,
                ),
            )
        ),
        code=code,
    )


# --- running service / job, own entry / another ------------------------------------


def test_a_verb_on_a_job_of_another_entry_from_a_registry_runs_one_off(
    tmp_path: Path,
) -> None:
    """``files-ls``: the job ``files-list`` of the entry ``files`` -- a one-off
    container of that entry's compose, no image check (the image is a
    registry's: the strict script has no ``image inspect``), no
    ``service-down`` (a job does not run between deploys). The fact names the
    entry and that it was one-off."""
    _, files = _two_entry_box(tmp_path)
    calls = [
        config_call(files, FILES_CONFIG),
        _oneoff(files, "files-list", "ls", "-1", "/srv/files"),
    ]
    with FakeRunner(*calls) as runner:
        code, out, _ = _cli(tmp_path, ["verb", "files-ls"], runner)
    verdict = _verdict(out)
    assert code == 0, verdict.steps
    assert verdict.steps[0].verify == {
        "verb": "files-ls",
        "service": "files-list",
        "exit_code": 0,
        "entry": FILES,
        "oneoff": True,
    }


def test_a_verb_on_a_running_service_of_another_entry_execs_in_it(
    tmp_path: Path,
) -> None:
    """``files-ping``: the running service ``files`` of the entry ``files`` --
    ``exec`` in that entry's compose after ``service-down`` is read."""
    _, files = _two_entry_box(tmp_path)
    calls = [
        running_call(files, "files", "c-files"),
        FakeCall(
            tuple(
                files.argv(
                    "exec",
                    "-T",
                    operands=(
                        "files",
                        "true",
                    ),
                )
            )
        ),
    ]
    with FakeRunner(*calls) as runner:
        code, out, _ = _cli(tmp_path, ["verb", "files-ping"], runner)
    verdict = _verdict(out)
    assert code == 0, verdict.steps
    assert verdict.steps[0].verify == {
        "verb": "files-ping",
        "service": "files",
        "exit_code": 0,
        "entry": FILES,
    }


def _built(document: dict[str, Json] | None = None) -> dict[str, Json]:
    found = copy.deepcopy(CONFIG if document is None else document)
    services = found["services"]
    assert isinstance(services, dict)
    services["init"] = {"build": {"context": "/r/backend"}, "image": BUILT_IMAGE}
    return found


def _inspect(commit: str) -> FakeCall:
    label = '{{index .Config.Labels "pridem.commit"}}'
    return FakeCall(
        ("docker", "image", "inspect", "-f", label, "--", BUILT_IMAGE),
        lines=lines(commit),
    )


def test_a_verb_on_a_built_job_checks_its_image_then_runs_one_off(
    tmp_path: Path,
) -> None:
    """``init-again``: the job ``init`` of the product's own entry, built from
    the product's code -- its image's commit against the release's before the
    one-off container; the fact names no entry (its own) and that it was
    one-off."""
    cs, _ = _two_entry_box(tmp_path)
    calls = [
        config_call(cs, _built()),
        _inspect(SHA),
        git_call(cs),
        _oneoff(cs, "init", "python", "-m", "app.seed", "bootstrap"),
    ]
    with FakeRunner(*calls) as runner:
        code, out, _ = _cli(tmp_path, ["verb", "init-again"], runner)
    verdict = _verdict(out)
    assert code == 0, verdict.steps
    assert verdict.steps[0].verify == {
        "verb": "init-again",
        "service": "init",
        "exit_code": 0,
        "oneoff": True,
    }


@pytest.mark.parametrize(
    ("image_commit", "release_commit"),
    [("1" * 40, SHA), (SHA, "2" * 40)],
    ids=["image-of-another-commit", "release-of-another-commit"],
)
def test_a_built_job_of_another_commit_is_refused_before_it_runs(
    tmp_path: Path, image_commit: str, release_commit: str
) -> None:
    cs, _ = _two_entry_box(tmp_path)
    calls = [
        config_call(cs, _built()),
        _inspect(image_commit),
        git_call(cs, release_commit),
    ]
    with FakeRunner(*calls) as runner:
        code, out, _ = _cli(tmp_path, ["verb", "init-again"], runner)
    reason = _verdict(out).steps[0].reason
    assert code == 1 and reason is not None
    assert reason.code == "project_verb:image-not-current"


def test_a_built_job_with_no_label_is_refused(tmp_path: Path) -> None:
    cs, _ = _two_entry_box(tmp_path)
    with FakeRunner(config_call(cs, _built()), _inspect("<no value>")) as runner:
        code, out, _ = _cli(tmp_path, ["verb", "init-again"], runner)
    reason = _verdict(out).steps[0].reason
    assert code == 1 and reason is not None
    assert reason.code == "project_verb:image-unread"


def test_a_red_job_is_red_with_its_command(tmp_path: Path) -> None:
    _, files = _two_entry_box(tmp_path)
    calls = [
        config_call(files, FILES_CONFIG),
        _oneoff(files, "files-list", "ls", "-1", "/srv/files", code=1),
    ]
    with FakeRunner(*calls) as runner:
        code, out, _ = _cli(tmp_path, ["verb", "files-ls"], runner)
    reason = _verdict(out).steps[0].reason
    assert code == 1 and reason is not None and reason.code == "command-failed"


# --- the loader and compose --------------------------------------------------------


def _product(verbs: dict[str, Json], **entries: Json) -> dict[str, Json]:
    return {
        "schema": 1,
        "name": STACK,
        "kind": "product",
        "stacks": {
            STACK: {
                "compose": "docker-compose.yml",
                "app": {"service": "app", "port": 8000, "health": "/h", "ready": "/r"},
            },
            **entries,
        },
        "env": {},
        "verbs": verbs,
        "report": {"health": "/h", "ready": "/r", "logs": "json", "junit": True},
    }


def test_a_verb_s_entry_is_an_entry_of_the_same_product() -> None:
    """``S.verb-entry``: an entry the product does not have -- refused. The
    pair: its own second entry, and no entry at all."""
    files: dict[str, Json] = {
        "compose": "f.yml",
        "jobs": {"l": {"service": "files-list"}},
    }
    foreign = _product({"v": {"run": "x", "entry": "velo-storage", "service": "s"}})
    assert [p.code for p in rule_problems(PRIMER_YAML.validate_python(foreign))] == [
        "S.verb-entry"
    ]
    fine = _product(
        {"v": {"run": "x", "entry": FILES, "service": "files-list"}}, files=files
    )
    assert rule_problems(PRIMER_YAML.validate_python(fine)) == []
    own = _product({"v": {"run": "x"}})
    assert rule_problems(PRIMER_YAML.validate_python(own)) == []


def test_a_verb_on_an_entry_without_an_app_names_its_service() -> None:
    files: dict[str, Json] = {"compose": "f.yml"}
    raw = _product({"v": {"run": "x", "entry": FILES}}, files=files)
    assert [p.code for p in rule_problems(PRIMER_YAML.validate_python(raw))] == [
        "S.verb-service"
    ]


def test_a_verb_s_service_is_looked_for_in_the_compose_of_its_entry(
    tmp_path: Path,
) -> None:
    """The finding ``verbs.<n>: no service <s>`` is the verb's entry's: in the
    compose of ``files`` -- named when the service is missing there, not in
    the compose of the product's own entry, which has none of it."""
    from compose_support import HEALTHCHECK

    files: dict[str, Json] = {
        "compose": "f.yml",
        "jobs": {"l": {"service": "files-list"}},
    }
    made = PRIMER_YAML.validate_python(
        _product(
            {"v": {"run": "x", "entry": FILES, "service": "files-list"}}, files=files
        )
    )
    assert isinstance(made, Product)
    healthy: dict[str, Json] = {"image": "a@sha256:x", "healthcheck": HEALTHCHECK}
    own = ComposeStack(made, STACK, tmp_path / "r", "main", SHA, tmp_path)
    other = ComposeStack(made, FILES, tmp_path / "r", "main", SHA, tmp_path)
    own.release.mkdir()
    assert forbidden(own, {"services": {"app": healthy}}) == []
    assert forbidden(other, {"services": {"files": healthy}}) == [
        "jobs.l: no service files-list",  # the job of the entry is missing too
        "verbs.v: no service files-list",
    ]
    job: dict[str, Json] = {"image": "j@sha256:x"}
    assert forbidden(other, {"services": {"files": healthy, "files-list": job}}) == []


# --- a seam whose value is a service's asked ---------------------------------------


def test_a_service_gives_its_asked_value_by_a_seam(tmp_path: Path) -> None:
    """Pass 4b: the provider's ``provides`` names a key of source ``asked``
    -- its value is the passport's, it goes to the seam memory after health,
    and the product's ``.env`` gets it; the value is a secret of the run (the
    journal's text is cleaned of it). The live check is tier 3's."""
    from env_support import box, passport_data, printed, read_env, render, run, service

    from pridem.stacks.seams import SeamMemory

    token = "bot-" + "t" * 28
    comms = service(
        tmp_path, {"COMMS_BOT_TOKEN": {"source": "asked"}}, provides=["COMMS_BOT_TOKEN"]
    )
    from env_support import COMMS_REPO
    from env_support import product as product_of

    made = product_of(
        tmp_path,
        {"COMMS_BOT_TOKEN": {"source": "seam", "from": "comms"}},
        dependencies={"comms": COMMS_REPO},
    )
    root, fetched = box(
        tmp_path, passport_data(asked={"comms": {"COMMS_BOT_TOKEN": token}})
    )
    memory = SeamMemory()
    provider = render(comms, root, fetched, product=made)
    outcome, sink = run([provider], FakeRunner())
    assert outcome.code.value == 0, outcome.steps
    assert provider.provided() == {"COMMS_BOT_TOKEN": token}
    memory.healthy("comms", provider.provided())
    late, sink = run([render(made, root, fetched, memory=memory)], FakeRunner())
    assert late.code.value == 0, late.steps
    assert read_env(root, made.name)["COMMS_BOT_TOKEN"] == token
    assert token not in printed(sink)
    assert token not in json.dumps([s.verify for s in late.steps])
