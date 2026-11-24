"""The probes of DM-182: the compose check reads what compose would execute.

Each probe hands the real ``docker compose`` of the boxes (``docker-compose-v2``
of noble-updates, installed by ``ci.yml``) a file that goes around the check
as it was, shows with compose itself what compose would run, then runs the
machine's check -- ``executable`` and ``checked``, the one function of
``build``, ``pridem check`` and ``derive_env`` -- on the same files. With no
compose the probes fail: a probe that skips holds nothing.
"""

import copy
from pathlib import Path

import pytest
from compose_support import compose
from pydantic import ValidationError

from pridem.events import Json
from pridem.runner import FakeRunner, Stream, SubprocessRunner
from pridem.stacks.env import safe
from pridem.steps.base import StepContext, StepFailed
from pridem.steps.compose import ComposeStack, checked, executable

APP = """\
  app:
    image: busybox
    healthcheck: { test: ["CMD", "true"] }
    environment:
      A: ${A:?}
"""

PRIVILEGED = """\
  hidden:
    image: busybox
    privileged: true
    healthcheck: { test: ["CMD", "true"] }
    profiles: [never]
"""


def _stdout(argv: list[str]) -> list[str]:
    """What a real command prints, by the machine's runner (no subprocess of
    the test's own: the fence of DM-5)."""
    lines: list[str] = []

    def keep(stream: Stream, line: str, cut: bool) -> None:
        if stream is Stream.STDOUT:
            lines.append(line)

    SubprocessRunner().run(argv, timeout=60, on_line=keep)
    return lines


@pytest.fixture(scope="module", autouse=True)
def compose_version() -> str:
    """The version of compose the probes run, printed for the log of CI."""
    [version] = _stdout(["docker", "compose", "version", "--short"])
    print(f"docker compose {version}")
    return version


def _box(tmp: Path, document: str, env: str) -> ComposeStack:
    cs = compose(tmp)
    cs.compose_file.parent.mkdir(parents=True, exist_ok=True)
    cs.compose_file.write_text(document, encoding="utf-8")
    cs.env_file.parent.mkdir(parents=True, exist_ok=True)
    cs.env_file.write_text(env, encoding="utf-8")
    cs.env_file.chmod(0o600)
    return cs


def _compose(cs: ComposeStack, *args: str) -> list[str]:
    """What compose itself says of the files: the evidence of the way round."""
    head = ["docker", "compose", "-p", cs.project, "--env-file", str(cs.env_file)]
    lines = _stdout([*head, "-f", str(cs.compose_file), *args])
    return " ".join(lines).split()


def _found(cs: ComposeStack) -> list[str]:
    """The machine's check of the files, by the real compose."""
    ctx = StepContext(SubprocessRunner(), "install", "test", cs.entry, lambda *_: None)
    try:
        refused = checked(cs, executable(ctx, cs))
    except StepFailed as failed:  # unfolded, before compose reads the file
        refused = (failed.reason.code, dict(failed.reason.params))
    assert refused is not None, "the check let it through"
    code, params = refused
    assert code == "compose-forbidden", refused
    found = params["found"]
    assert isinstance(found, list)
    return [str(item) for item in found]


def test_probe_DM_182_S1_compose_reads_the_env_file_as_the_machine_wrote_it(
    tmp_path: Path,
) -> None:
    """A value that ends in a backslash escapes its closing quote: compose
    reads the lines after it otherwise than the machine -- the next value
    hands compose ``COMPOSE_PROFILES`` and a privileged service behind a
    profile is started with no ``--profile``. The machine never writes such a
    value (``env-unsafe``), and the check reads the file as compose does:
    every key read otherwise and the setting of compose are named."""
    env = "A='a\\'\nB=' COMPOSE_PROFILES=never #'\n"
    cs = _box(tmp_path, f"services:\n{APP}{PRIVILEGED}", env)
    assert "hidden" in _compose(cs, "config", "--services")  # compose runs it
    found = _found(cs)
    assert "env: A read otherwise" in found and "env: B read otherwise" in found
    assert "env: COMPOSE_PROFILES" in found
    with pytest.raises(StepFailed) as refused:
        safe("A", "a\\")
    assert refused.value.reason.code == "env-unsafe"
    safe("A", "a\\b")  # the pair: a backslash inside is read as itself


def test_probe_DM_182_S2_a_service_behind_a_profile_is_checked(tmp_path: Path) -> None:
    """A privileged service behind a profile: ``config`` without
    ``--profile`` does not show it, and ``compose run`` or
    ``COMPOSE_PROFILES`` would start it. The check reads every profile and
    names it. The pair: the same file without it is not refused for it."""
    cs = _box(tmp_path, f"services:\n{APP}{PRIVILEGED}", "A='x'\n")
    assert "hidden" not in _compose(cs, "config", "--services")
    assert "hidden" in _compose(cs, "--profile", "*", "config", "--services")
    assert "hidden: privileged" in _found(cs)
    other = tmp_path / "pair"
    other.mkdir()
    clean = _box(other, f"services:\n{APP}", "A='x'\n")
    ctx = StepContext(SubprocessRunner(), "install", "test", "blank", lambda *_: None)
    refused = checked(clean, executable(ctx, clean))
    assert refused is None or not [f for f in refused[1]["found"] if "hidden" in str(f)]  # type: ignore[union-attr]


def test_probe_DM_182_S3_a_derived_value_is_checked_after_derive_env(
    tmp_path: Path,
) -> None:
    """A value stands in the source of a bind: with the placeholder ``build``
    checks, the source is a path in the release -- green; with the value
    ``derive_env`` writes, it is the root of the host. The same check on the
    final ``next.env`` names it -- ``derive_env.verify`` runs it."""
    document = (
        "services:\n"
        "  app:\n"
        "    image: busybox\n"
        '    healthcheck: { test: ["CMD", "true"] }\n'
        "    volumes:\n"
        "      - type: bind\n"
        "        source: ${A:?}\n"
        "        target: /host\n"
    )
    cs = _box(tmp_path, document, "A='<derived>'\n")
    ctx = StepContext(SubprocessRunner(), "install", "test", "blank", lambda *_: None)
    assert checked(cs, executable(ctx, cs)) is None  # what build sees: green
    cs.env_file.write_text("A='/'\n", encoding="utf-8")
    assert '"source":"/"' in "".join(_compose(cs, "config", "--format", "json"))
    found = _found(cs)
    assert [f for f in found if f.startswith("app: volumes")], found


def test_probe_DM_182_S4_a_second_document_is_refused(tmp_path: Path) -> None:
    """A file of two YAML documents: compose merges them -- the second's
    privileged service runs -- the machine read the first alone. Refused
    before compose reads the file: ``compose: documents``; a tag of compose
    -- ``compose: unreadable``."""
    running = PRIVILEGED.replace("    profiles: [never]\n", "")
    second = f"services:\n{APP}---\nservices:\n{running}"
    cs = _box(tmp_path, second, "A='x'\n")
    assert "hidden" in _compose(cs, "config", "--services")
    assert _found(cs) == ["compose: documents"]
    tagged = tmp_path / "tagged"
    tagged.mkdir()
    reset = f"services:\n{APP}    ports: !reset []\n"
    cs = _box(tagged, reset, "A='x'\n")
    _compose(cs, "config", "--services")  # compose reads the tag
    assert _found(cs) == ["compose: unreadable"]


def test_probe_DM_182_S16_an_alias_on_a_shared_network_is_reserved(
    tmp_path: Path,
) -> None:
    """A service gives itself the alias of the machine's proxy on a network:
    a DNS name on it, as a name is. The alias is reserved; an address of the
    network is not the service's to choose."""
    document = (
        f"services:\n{APP}"
        "    networks:\n"
        "      default:\n"
        "        aliases: [pridem-egress-proxy]\n"
        "        ipv4_address: 172.30.0.9\n"
        "networks:\n"
        "  default:\n"
        "    ipam: { config: [{ subnet: 172.30.0.0/24 }] }\n"
    )
    cs = _box(tmp_path, document, "A='x'\n")
    assert "pridem-egress-proxy" in " ".join(_compose(cs, "config"))
    found = _found(cs)
    assert "app: alias pridem-egress-proxy reserved" in found
    assert "app: networks.default.ipv4_address" in found


# --- the schema's paths (S17) and an entry taken (B27) --------------------------


@pytest.mark.parametrize(
    "path",
    ["/run/${KEY}/key", "/run/$KEY", "//etc/key", "/run//key", "/run/-x/key",
     "/run/./key", "/run/../etc/key", "/run/key/", "run/key", "/"],
)  # fmt: skip
def test_a_path_compose_would_read_otherwise_is_refused(path: str) -> None:
    """A path of the schema the machine writes into its override: compose
    interpolates ``$`` there, ``//`` is a root of its own -- the loader
    refuses both forms, a secret file's as well as a package's mount. The
    pair: a dot first is a name (``.config``), taken."""
    from test_secret_files import _product

    from pridem.stacks.schema import container_path

    assert not container_path(path)
    with pytest.raises(ValidationError, match="S.secret-file"):
        _product({"path": path})
    assert container_path("/home/app/.config/key")
    assert _product({"path": "/home/app/.config/key"}).env["AGE_KEY"] is not None


def test_a_mount_path_compose_would_interpolate_is_refused(tmp_path: Path) -> None:
    """``mount.path`` with ``$`` -- ``R10.mount``; the pair: a plain path."""
    from contract_support import example, node, yaml_problems

    data = example("product.yaml")
    mount = {"service": "frontend", "path": "/srv/${X}"}
    node(data, "packages", "skin")["mount"] = [mount]
    assert yaml_problems(tmp_path, data) == [
        ("packages.skin.mount[0].path", "R10.mount")
    ]
    mount["path"] = "/srv/x"
    (tmp_path / "pair").mkdir()
    assert yaml_problems(tmp_path / "pair", data) == []


def test_an_entry_of_a_service_named_as_another_stacks_is_refused(
    tmp_path: Path,
) -> None:
    """A service with an entry the product has: one compose project
    (``-p <entry>``) for two stacks -- ``fetch_services:entry-taken`` before
    its worktree. The pair: its own entries alone are read."""
    from services_support import comms_data
    from test_steps_services import _sources

    data = comms_data()
    stacks = data["stacks"]
    assert isinstance(stacks, dict)
    stacks["aivis"] = copy.deepcopy(stacks["comms"])  # no YAML alias
    assert _sources(tmp_path / "a", data)[:1] == ["fetch_services:entry-taken"]
    assert not (tmp_path / "a" / "box" / "opt" / "comms" / "releases").exists()
    assert _sources(tmp_path / "b", comms_data()) == []


# --- the places of the one check ------------------------------------------------

HIDDEN: dict[str, Json] = {
    "image": "busybox",
    "privileged": True,
    "healthcheck": {"test": ["CMD", "true"]},
    "profiles": ["never"],
}
"""A privileged service behind a profile, as ``config --profile "*"`` prints
it."""


def test_build_refuses_what_compose_would_execute(tmp_path: Path) -> None:
    """``build`` reads the executable representation: the privileged service
    behind a profile is in it, and ``build`` is red ``compose-forbidden``
    before anything is built. The pair is every green build of the tests."""
    from compose_support import (
        CONFIG,
        config_call,
        executable_calls,
        raw_config_call,
        run,
    )
    from test_steps_build import steps

    cs = compose(tmp_path)
    services = CONFIG["services"]
    assert isinstance(services, dict)
    every: dict[str, Json] = {**CONFIG, "services": {**services, "hidden": HIDDEN}}
    script = [raw_config_call(cs), config_call(cs), *executable_calls(cs, every)]
    with FakeRunner(*script) as runner:
        outcome, _ = run([steps(tmp_path)[0]], runner)
    reason = outcome.steps[0].reason
    assert reason is not None and reason.code == "build:compose-forbidden"
    assert "hidden: privileged" in reason.params["found"]  # type: ignore[operator]


def test_derive_env_refuses_what_compose_would_execute(tmp_path: Path) -> None:
    """``derive_env.verify`` checks every entry of the stack on the values it
    derived: the executable representation names a privileged service --
    ``derive_env:compose-forbidden``, before the seams go anywhere."""
    from env_support import STDOUT, checked_calls
    from env_support import run as run_env
    from test_stacks_env import DERIVED, Reading, comms_box, derive_call, passes

    made, comms, root, fetched = comms_box(tmp_path, derived=True)
    env_file = root / "opt" / "comms" / "env" / "derive.env"
    bad: dict[str, Json] = {"name": "comms", "services": {"hidden": HIDDEN}}
    with Reading(
        derive_call(env_file, lines=[(STDOUT, DERIVED)]),
        *checked_calls(root, checked=bad),
    ) as runner:
        outcome, _ = run_env(passes(comms, root, fetched, made), runner)
    reason = outcome.steps[1].reason
    assert reason is not None and reason.code == "derive_env:compose-forbidden"
    assert "hidden: privileged" in reason.params["found"]  # type: ignore[operator]


def test_derive_env_checks_every_entry_of_its_stack(tmp_path: Path) -> None:
    """The stack's ``next.env`` is every entry's: ``derive_env`` checks the
    compose of each -- the second entry, not the one ``derive`` ran in, names
    a privileged service and the step is red. The pair is the test above: one
    entry, the same refusal."""
    from env_support import (
        COMMS_REPO,
        STDOUT,
        box,
        checked_calls,
        derive,
        load,
        product,
        render,
        service_data,
    )
    from env_support import run as run_env
    from test_stacks_env import (
        DERIVED,
        Reading,
        comms_env,
        comms_passport,
        derive_call,
    )

    made = product(tmp_path, {}, dependencies={"comms": COMMS_REPO})
    data = service_data(comms_env(derived=True))
    stacks = data["stacks"]
    assert isinstance(stacks, dict)
    stacks["comms-worker"] = {"compose": "deploy/worker-compose.yml"}
    comms = load(tmp_path, data)
    root, fetched = box(tmp_path, comms_passport())
    env_file = root / "opt" / "comms" / "env" / "derive.env"
    bad: dict[str, Json] = {"name": "comms-worker", "services": {"hidden": HIDDEN}}
    first = render(comms, root, fetched, product=made)
    with Reading(
        derive_call(env_file, lines=[(STDOUT, DERIVED)]),
        *checked_calls(root),
        *checked_calls(
            root, checked=bad, entry="comms-worker", compose="deploy/worker-compose.yml"
        ),
    ) as runner:
        outcome, _ = run_env([first, derive(first, root)], runner)
    reason = outcome.steps[1].reason
    assert reason is not None and reason.code == "derive_env:compose-forbidden"
    assert reason.params["stack"] == "comms-worker"
