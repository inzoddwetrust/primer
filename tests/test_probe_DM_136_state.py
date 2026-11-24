"""The probes of DM-136: the state of a box, one form for the console and the
Panel, read with no lock and nothing written.

The box of these tests is the blank of ``tests/fixtures/check`` with the
machine's mark, a second entry ``files`` (``persistent``) and a service
``comms``; docker, ``openssl`` and ``compose config --services`` are a strict
script; ``/proc/meminfo`` is a file under the test's root.
"""

import io
import json
from collections.abc import Iterator, Sequence
from pathlib import Path

import pytest
import yaml
from data_support import SHA, STACK, blank_box
from test_box_held import _gone, _leave
from test_probe_DM_54_recover import Refusing

from pridem.cli import run
from pridem.report.box_snapshot import BOX_STATE_SCHEMA, BoxSnapshot, rendered_schema
from pridem.runner import FakeCall, FakeRunner, Runner, Stream
from pridem.stacks.schema import load_primer_yaml
from pridem.state import Box
from pridem.steps.compose import ComposeStack
from pridem.steps.passport import PASSPORT_COPY
from pridem.steps.ssl import CERT_ARGS
from pridem.verbs.state import _covered

SERVICE = "comms"
SERVICE_TAG = "v3.0.0"
FILES = "files"
CERT_END = "2026-12-25T10:00:00Z"
RENEWS = "2026-11-25T10:00:00Z"
GIB = 2**30
DOMAINS = ("api-test.aivis.one", "mail-test.aivis.one", "test.aivis.one")
"""The domains of the passport of the tests (``tests/fixtures/passport``)."""


def out(*lines: str) -> tuple[tuple[Stream, str], ...]:
    return tuple((Stream.STDOUT, line) for line in lines)


def _box(root: Path, *, ssl: str = "letsencrypt") -> None:
    """The box of the probes: the blank with its mark, a second entry
    ``files`` (``persistent``), a service ``comms`` with its mark, the
    passport copy in mode ``ssl``, a certificate, ``/proc/meminfo``."""
    blank_box(root)
    home = root / "opt" / STACK
    (home / ".pridem").write_text(f"{STACK}\n")
    release = home / "releases" / SHA / "primer.yaml"
    made = yaml.safe_load(release.read_text())
    made["stacks"][FILES] = {"compose": "files-compose.yml", "persistent": True}
    release.write_text(yaml.safe_dump(made, sort_keys=False))
    service = root / "opt" / SERVICE
    (service / "releases" / SERVICE_TAG).mkdir(parents=True)
    (service / ".pridem").write_text(f"{SERVICE}\n")
    (service / "releases" / SERVICE_TAG / "primer.yaml").write_text(
        Path("tests/fixtures/primer/service.yaml").read_text()
    )
    (service / "current").symlink_to(service / "releases" / SERVICE_TAG)
    copy = root / PASSPORT_COPY
    passport = yaml.safe_load(copy.read_text())
    passport["policies"]["ssl"] = ssl
    if ssl == "provided":
        pem = "-----BEGIN {0}-----\n" + "A" * 64 + "\n-----END {0}-----\n"
        passport["policies"]["tls"] = {
            "cert": pem.format("CERTIFICATE"),
            "key": pem.format("PRIVATE KEY"),
        }
    copy.write_text(yaml.safe_dump(passport, sort_keys=False))
    certs = root / "opt" / "pridem" / "edge" / "certs"
    certs.mkdir(parents=True, exist_ok=True)
    (certs / "fullchain.pem").write_text("a certificate\n")
    proc = root / "proc"
    proc.mkdir(exist_ok=True)
    (proc / "meminfo").write_text(
        "MemTotal:        4000000 kB\nMemFree:          100000 kB\n"
        "MemAvailable:    1000000 kB\nSwapTotal:       2000000 kB\n"
        "SwapFree:        1500000 kB\n"
    )
    (root / "var" / "lib" / "docker").mkdir(parents=True, exist_ok=True)


def _compose(root: Path, stack: str, entry: str) -> ComposeStack:
    release = (root / "opt" / stack / "current").resolve()
    made = load_primer_yaml(release / "primer.yaml")
    return ComposeStack(made, entry, release, release.name, release.name, root)


def _container(
    cid: str,
    stack: str,
    service: str,
    status: str,
    health: str | None,
    *,
    oneoff: bool = False,
) -> dict[str, object]:
    state: dict[str, object] = {"Status": status}
    if health is not None:
        state["Health"] = {"Status": health}
    labels = {"pridem.stack": stack, "com.docker.compose.service": service}
    if oneoff:  # a container of compose run: a seed, a test, a verb
        labels["com.docker.compose.oneoff"] = "True"
    return {"Id": cid, "Config": {"Labels": labels}, "State": state}


CONTAINERS = [
    _container("c1", STACK, "app", "running", "healthy"),
    _container("c2", STACK, "frontend", "running", "unhealthy"),
    _container("c3", STACK, "postgres", "exited", None),
    _container("c4", FILES, "files", "running", None),
    _container("c5", SERVICE, "comms-app", "running", "starting"),
    _container("c6", "pridem-edge", "nginx", "running", "healthy"),
    _container("c7", STACK, "app", "running", None, oneoff=True),
]
"""``frontend`` unhealthy, ``postgres`` stopped, ``files`` with no
healthcheck; the blank's ``redis`` has no container at all (``absent``);
``c7`` is a one-off container of ``app`` (``compose run``) -- not a service."""

PS = ("docker", "ps", "-a", "-q", "--no-trunc", "--filter", "label=pridem.stack")
DF = ("docker", "system", "df", "--format", "json")
DF_LINES = out(
    '{"Type":"Images","TotalCount":"7","Size":"3.2GB","Reclaimable":"1.1GB (34%)"}',
    '{"Type":"Build Cache","TotalCount":"3","Size":"10MB","Reclaimable":"10MB"}',
)


def _openssl(root: Path, *names: str) -> FakeCall:
    cert = root / "opt" / "pridem" / "edge" / "certs" / "fullchain.pem"
    return FakeCall(
        ("openssl", "x509", "-in", str(cert), *CERT_ARGS),
        lines=out(
            "notAfter=Dec 25 10:00:00 2026 GMT",
            "issuer=CN = pridem",
            "subject=CN = pridem",
            "X509v3 Subject Alternative Name: ",
            "    " + ", ".join(f"DNS:{name}" for name in names),
        ),
    )


def _script(root: Path, *, certificate: Sequence[str] | None = None) -> list[FakeCall]:
    """Every command of the state of ``_box``, in the order it asks them."""
    calls = [
        FakeCall(PS, lines=out(*(str(c["Id"]) for c in CONTAINERS))),
        FakeCall(
            ("docker", "inspect", "--", *(str(c["Id"]) for c in CONTAINERS)),
            lines=out(json.dumps(CONTAINERS)),
        ),
        FakeCall(
            tuple(_compose(root, STACK, STACK).argv("config", "--services")),
            lines=out("app", "frontend", "postgres", "redis"),
        ),
        FakeCall(
            tuple(_compose(root, STACK, FILES).argv("config", "--services")),
            lines=out("files"),
        ),
        FakeCall(
            tuple(_compose(root, SERVICE, SERVICE).argv("config", "--services")),
            lines=out("comms-app"),
        ),
        FakeCall(DF, lines=DF_LINES),
    ]
    names = DOMAINS if certificate is None else certificate
    calls.append(_openssl(root, *names))
    return calls


def _cli(root: Path, argv: list[str], runner: Runner) -> tuple[int, str, str]:
    o, e = io.StringIO(), io.StringIO()
    code = run(
        argv, root=root / "opt" / "pridem", out=o, err=e, runner=runner, fs_root=root
    )
    return code, o.getvalue(), e.getvalue()


def _written(root: Path) -> dict[str, bytes]:
    """Every file of the machine's home but the passport copy, by its path:
    ``history/``, ``journal/``, the lock, ``state.json``."""
    home = root / "opt" / "pridem"
    return {
        str(p.relative_to(home)): p.read_bytes()
        for p in sorted(home.rglob("*"))
        if p.is_file() and p.name != "passport.yaml"
    }


@pytest.fixture
def held(tmp_path: Path) -> Iterator[int]:
    """Another process holds the box's lock, as a run does: a command under
    the lock left a process with its descriptor (``test_box_held``). Its pid."""
    _box(tmp_path)
    pid = _leave(Box(tmp_path / "opt" / "pridem"))
    yield pid
    _gone(pid)


# --- probes -----------------------------------------------------------------------


def test_probe_DM_136_state_with_the_lock_held_writes_nothing(
    tmp_path: Path, held: int
) -> None:
    """Another process holds the box's lock: ``state --json`` answers, exit
    0, and ``history/``, ``journal/``, the lock's file and ``state.json`` are
    byte for byte what they were. The pair: the state is there and full --
    the machine, the process holding the lock, every stack, the resources.
    (``status`` on the same box is refused: it takes the lock.)"""
    before = _written(tmp_path)
    with FakeRunner(*_script(tmp_path)) as runner:
        code, printed, err = _cli(tmp_path, ["--json", "state"], runner)
    assert (code, err) == (0, ""), err
    assert _written(tmp_path) == before
    state = BoxSnapshot.model_validate_json(printed)
    [holder] = state.lock_open_by
    assert holder.startswith(f"pid {held} ("), holder
    assert state.machine.version and isinstance(state.stacks, list)
    assert [s.stack for s in state.stacks] == [STACK, SERVICE]
    assert state.resources.memory.model_dump() == {
        "total_bytes": 4000000 * 1024,
        "available_bytes": 1000000 * 1024,
    }
    with FakeRunner() as runner:
        code, _, err = _cli(tmp_path, ["status"], runner)
    assert code == 1 and "busy" in err


def test_probe_DM_136_every_entry_of_the_product_is_in_the_state(
    tmp_path: Path,
) -> None:
    """Every entry of every stack -- the product's own, its ``persistent``
    entry, the service -- with every service of its compose by its
    container: healthy, unhealthy, starting, stopped, without a healthcheck,
    and ``absent`` for a service with no container. The machine's own edge
    by its label."""
    _box(tmp_path)
    with FakeRunner(*_script(tmp_path)) as runner:
        code, printed, _ = _cli(tmp_path, ["--json", "state"], runner)
    assert code == 0
    found = json.loads(printed)
    stacks = {s["stack"]: s for s in found["stacks"]}
    assert stacks[STACK]["release"] == SHA
    entries = {e["entry"]: e for e in stacks[STACK]["entries"]}
    assert entries[STACK]["persistent"] is False
    assert entries[FILES]["persistent"] is True
    assert entries[STACK]["services"] == [
        {"service": "app", "state": "running", "health": "healthy"},
        {"service": "frontend", "state": "running", "health": "unhealthy"},
        {"service": "postgres", "state": "exited", "health": "none"},
        {"service": "redis", "state": "absent", "health": "none"},
    ]
    assert entries[FILES]["services"] == [
        {"service": "files", "state": "running", "health": "none"}
    ]
    [comms] = stacks[SERVICE]["entries"]
    assert comms["services"] == [
        {"service": "comms-app", "state": "running", "health": "starting"}
    ]
    edge = {s["stack"]: s["services"] for s in found["machine_stacks"]}
    assert edge["pridem-edge"] == [
        {"service": "nginx", "state": "running", "health": "healthy"}
    ]
    assert edge["pridem-egress"] == []


def test_probe_DM_136_ssl_status_says_the_end_of_each_domain(tmp_path: Path) -> None:
    """``ssl status`` in the console: the mode, the end of the one
    certificate, from when the machine renews it -- 30 days before its end
    -- and each domain of the passport with the end it is served with, or
    that the certificate does not name it. The pair: ``provided`` -- the
    passport brings the next one, no date of the machine."""
    _box(tmp_path)
    cert = _openssl(tmp_path, "test.aivis.one")
    with FakeRunner(cert) as runner:
        code, printed, _ = _cli(tmp_path, ["ssl", "status"], runner)
    assert code == 0
    assert printed.splitlines() == [
        f"ssl letsencrypt — ends {CERT_END}, renews from {RENEWS}",
        "  api-test.aivis.one — not in the certificate",
        "  mail-test.aivis.one — not in the certificate",
        f"  test.aivis.one — ends {CERT_END}",
    ]
    other = tmp_path / "provided"
    other.mkdir()
    _box(other, ssl="provided")
    cert = _openssl(other, "*.aivis.one")
    with FakeRunner(cert) as runner:
        code, printed, _ = _cli(other, ["--json", "ssl", "status"], runner)
    assert code == 0
    part = json.loads(printed)
    assert part["mode"] == "provided" and part["expires"] == CERT_END
    assert part["renews_from"] == {"unmeasured": "renewed-by-passport"}
    # the wildcard of a provided certificate covers each domain of one label
    assert [d["covered"] for d in part["domains"]] == [True, True, True]


# --- around the probes ------------------------------------------------------------


def test_ssl_status_takes_no_lock_and_writes_nothing(tmp_path: Path, held: int) -> None:
    """``ssl status`` with the lock held by another process: it answers and
    nothing of the machine's home changed. The pair: its part ``ssl`` is
    there and full."""
    before = _written(tmp_path)
    cert = _openssl(tmp_path, *DOMAINS)
    with FakeRunner(cert) as runner:  # nothing of docker: the part ssl alone
        code, printed, err = _cli(tmp_path, ["--json", "ssl", "status"], runner)
    assert (code, err) == (0, ""), err
    assert _written(tmp_path) == before
    part = json.loads(printed)
    assert part["expires"] == CERT_END and part["renews_from"] == RENEWS
    assert part["domains"] == [
        {"domain": domain, "covered": True} for domain in DOMAINS
    ]


def test_status_with_docker_gone_keeps_its_code_and_its_verdict(
    tmp_path: Path,
) -> None:
    """A fresh box before its install: docker does not answer. ``status`` is
    green, its verdict as without the state -- no step, ``{pridem}`` -- and
    the state after it says ``docker-unreachable``, never a fall of the verb.
    The pair: ``status --json`` prints the verdict alone."""
    root = tmp_path / "opt" / "pridem"
    code, printed, err = _cli(tmp_path, ["status"], Refusing())
    assert (code, err) == (0, ""), err
    [verdict] = [json.loads(p.read_text()) for p in (root / "history").iterdir()]
    assert (verdict["result"], verdict["steps"]) == ("green", [])
    assert "images — not measured (docker-unreachable)" in printed
    assert "status: done in " in printed
    code, printed, _ = _cli(tmp_path, ["--json", "status"], Refusing())
    assert code == 0 and json.loads(printed)["verb"] == "status"


def test_no_value_of_asked_is_in_the_state(tmp_path: Path) -> None:
    """The passport copy holds secrets: only its version, ``policies.ssl``
    and ``domains`` are read -- no value of ``asked`` or ``tls`` is printed,
    in the console or in ``--json``."""
    _box(tmp_path)
    copy = yaml.safe_load((tmp_path / PASSPORT_COPY).read_text())
    secrets = [str(v) for stack in copy["asked"].values() for v in stack.values()]
    assert secrets
    for argv in (["--json", "state"], ["state"]):
        with FakeRunner(*_script(tmp_path)) as runner:
            code, printed, _ = _cli(tmp_path, argv, runner)
        assert code == 0
        assert not [s for s in secrets if s in printed]


def test_the_disks_are_measured(tmp_path: Path) -> None:
    """``/`` and docker's directory by ``statvfs`` of the box's file system:
    the total as the kernel says it, a free part under it."""
    import os

    _box(tmp_path)
    with FakeRunner(*_script(tmp_path)) as runner:
        _, printed, _ = _cli(tmp_path, ["--json", "state"], runner)
    disks = json.loads(printed)["resources"]["disk"]
    assert [d["path"] for d in disks] == ["/", "/var/lib/docker"]
    seen = os.statvfs(tmp_path)
    for disk in disks:
        space = disk["space"]
        assert space["total_bytes"] == seen.f_blocks * seen.f_frsize
        assert 0 < space["free_bytes"] <= space["total_bytes"]


def test_journals_without_a_verdict_are_named(tmp_path: Path) -> None:
    """A journal with no verdict is named -- a run going on or one that died:
    the files cannot tell -- and one with its verdict is not."""
    _box(tmp_path)
    home = tmp_path / "opt" / "pridem"
    (home / "journal").mkdir(exist_ok=True)
    (home / "history").mkdir(exist_ok=True)
    for run_id in ("2026-11-24T00:00:00Z-aaaa", "2026-11-24T00:00:01Z-bbbb"):
        (home / "journal" / f"{run_id}.jsonl").write_text("{}\n")
    (home / "history" / "2026-11-24T00:00:00Z-aaaa.json").write_text("{}")
    with FakeRunner(*_script(tmp_path)) as runner:
        _, printed, _ = _cli(tmp_path, ["--json", "state"], runner)
    found = json.loads(printed)
    assert found["journals_without_verdict"] == ["2026-11-24T00:00:01Z-bbbb"]


def test_what_is_not_measured_says_why(tmp_path: Path) -> None:
    """Twin SHORTAGE: no ``/proc/meminfo``, no docker's directory, docker's
    answer not docker's (a status it has no word for), no certificate --
    each part says why, none takes a value it did not measure."""
    _box(tmp_path)
    (tmp_path / "proc" / "meminfo").unlink()
    (tmp_path / "var" / "lib" / "docker").rmdir()
    (tmp_path / "opt" / "pridem" / "edge" / "certs" / "fullchain.pem").unlink()
    odd = [_container("c1", STACK, "app", "sleeping", None)]
    calls = [
        FakeCall(PS, lines=out("c1")),
        FakeCall(("docker", "inspect", "--", "c1"), lines=out(json.dumps(odd))),
        FakeCall(DF, lines=out("not json")),
    ]
    with FakeRunner(*calls) as runner:
        code, printed, _ = _cli(tmp_path, ["--json", "state"], runner)
    assert code == 0
    found = json.loads(printed)
    assert found["resources"]["memory"] == {"unmeasured": "meminfo-unreadable"}
    assert found["resources"]["swap"] == {"unmeasured": "meminfo-unreadable"}
    assert found["resources"]["disk"][1] == {
        "path": "/var/lib/docker",
        "space": {"unmeasured": "path-missing"},
    }
    assert found["resources"]["images"] == {"unmeasured": "docker-unreachable"}
    entries = {s["stack"]: s["entries"] for s in found["stacks"]}
    assert entries[STACK][0]["services"] == {"unmeasured": "docker-unreachable"}
    assert found["machine_stacks"] == {"unmeasured": "docker-unreachable"}
    assert found["ssl"] == {"unmeasured": "no-certificate"}


def test_a_fresh_box_has_no_stacks_and_no_passport(tmp_path: Path) -> None:
    """Twin EMPTINESS: the machine and nothing else -- no stack, no passport;
    docker answers with nothing."""
    with FakeRunner(FakeCall(PS), FakeCall(DF, lines=DF_LINES)) as runner:
        code, printed, _ = _cli(tmp_path, ["--json", "state"], runner)
    assert code == 0
    found = json.loads(printed)
    assert found["stacks"] == [] and found["passport"] == {"unmeasured": "no-passport"}
    assert found["ssl"] == {"unmeasured": "no-passport"}
    assert found["resources"]["images"] == {
        "count": 7,
        "bytes": 3_200_000_000,
        "reclaimable_bytes": 1_100_000_000,
    }


def test_a_stack_after_destroy_has_no_current(tmp_path: Path) -> None:
    """``destroy`` leaves the mark with ``minted.yaml``: the stack is named,
    its release and entries are not measured -- ``no-current``."""
    _box(tmp_path)
    calls = [
        call
        for call in _script(tmp_path)
        if "--services" not in call.argv or SERVICE in str(call.argv)
    ]
    (tmp_path / "opt" / STACK / "current").unlink()
    with FakeRunner(*calls) as runner:
        _, printed, _ = _cli(tmp_path, ["--json", "state"], runner)
    stacks = {s["stack"]: s for s in json.loads(printed)["stacks"]}
    assert stacks[STACK]["release"] == {"unmeasured": "no-current"}
    assert stacks[STACK]["entries"] == {"unmeasured": "no-current"}


def test_a_damaged_state_json_is_not_read(tmp_path: Path) -> None:
    """``state.json`` is a record, not a ground: damaged, the state is whole
    and the file is where it was."""
    _box(tmp_path)
    state = tmp_path / "opt" / "pridem" / "state.json"
    state.write_text("{not json")
    with FakeRunner(*_script(tmp_path)) as runner:
        code, printed, _ = _cli(tmp_path, ["--json", "state"], runner)
    assert code == 0 and state.read_text() == "{not json"
    assert len(json.loads(printed)["stacks"]) == 2


@pytest.mark.parametrize(
    ("domain", "names", "covered"),
    [
        ("a.preview.x", ["*.preview.x"], True),
        ("preview.x", ["*.preview.x"], False),
        ("a.b.preview.x", ["*.preview.x"], False),
        ("x.one", ["x.one"], True),
        ("y.one", ["x.one"], False),
    ],
)
def test_a_wildcard_covers_one_label(
    domain: str, names: list[str], covered: bool
) -> None:
    assert _covered(domain, names) is covered


def test_the_console_names_each_part(tmp_path: Path) -> None:
    """``state`` in the console: each stack and entry with its services,
    the disks, memory, swap, images, SSL."""
    _box(tmp_path)
    with FakeRunner(*_script(tmp_path)) as runner:
        code, printed, _ = _cli(tmp_path, ["state"], runner)
    assert code == 0
    lines = printed.splitlines()
    assert f"{STACK} · {SHA}" in lines
    assert (
        f"  {STACK} — app running (healthy), frontend running (unhealthy), "
        "postgres exited, redis absent"
    ) in lines
    assert f"  {FILES} — files running" in lines
    assert "memory — 1.0 GB free of 4.1 GB" in lines
    assert "swap — 1.5 GB free of 2.0 GB" in lines
    assert "images — 7, 3.2 GB, 1.1 GB reclaimable" in lines
    assert f"ssl letsencrypt — ends {CERT_END}, renews from {RENEWS}" in lines


def test_the_schema_on_disk_is_the_export_of_the_model() -> None:
    on_disk = (Path("contract/schema") / BOX_STATE_SCHEMA).read_text(encoding="utf-8")
    assert on_disk == rendered_schema(), "python -m pridem.report.box_snapshot --export"
