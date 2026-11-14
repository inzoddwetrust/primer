"""DM-93 (R2-2 of review 0002): input of a product or a package is never an
option of docker; the build context is written to inside itself; the names
of the machine are no stack's; a directory the machine did not mark is not
marked; the edge says what the client said of it; ``pg_restore`` is one
transaction."""

from pathlib import Path

import pytest
from data_support import STACK
from edge_support import DOMAINS, passport, product
from test_steps_nginx import _server_of
from test_verbs_data import compose

from pridem.events import Json
from pridem.runner import FakeCall, FakeRunner
from pridem.stacks.routes import render
from pridem.stacks.schema import PRIMER_YAML, RESERVED_NAMES, rule_problems
from pridem.steps.base import StepFailed
from pridem.steps.packages import PackagePlace, write_context
from pridem.steps.sources import MARKER, NotOurs, mark, marked

# --- R2-S2, S17: -- before the operands -------------------------------------------


def test_compose_puts_its_operands_after_a_double_dash(tmp_path: Path) -> None:
    """The literal argv, not one built by the same helper (DM-86 lesson): a
    service named ``-x`` comes after ``--`` -- an operand, never an option;
    with no operands there is no ``--``."""
    from data_support import blank_box

    blank_box(tmp_path)
    cs = compose(tmp_path)
    head = [
        "docker", "compose", "-p", STACK, "--env-file", str(cs.env_file),
        "-f", str(cs.compose_file), "-f", str(cs.override),
    ]  # fmt: skip
    assert cs.argv("logs", "--tail", "5", operands=("-x",)) == [
        *head, "logs", "--tail", "5", "--", "-x",
    ]  # fmt: skip
    assert cs.argv("ps", "-q") == [*head, "ps", "-q"]


def test_an_image_named_like_an_option_is_an_operand_of_docker_run(
    tmp_path: Path,
) -> None:
    """``pg_restore --list`` runs the database's image the product's compose
    names: ``--privileged`` there is the image, after ``--`` -- the literal
    argv docker gets."""
    from env_support import context

    from pridem.steps.data import _toc

    dump = tmp_path / "x.dump"
    dump.write_bytes(b"PGDMP")
    argv = (
        "docker", "run", "--rm", "--network", "none", "--cap-drop", "ALL",
        "--pull", "never", "--mount",
        f"type=bind,source={dump},target=/primer/db.dump,readonly",
        "--", "--privileged", "pg_restore", "--list", "/primer/db.dump",
    )  # fmt: skip
    with FakeRunner(FakeCall(argv, lines=())) as runner:
        assert _toc(context(runner), dump, "--privileged") == 0


def test_logs_of_a_service_named_like_an_option(tmp_path: Path) -> None:
    """The operator's ``logs blank -x``: ``-x`` is the service, after ``--``."""
    from test_verbs_admin import _out
    from test_verbs_project import _box

    cs = _box(tmp_path)
    argv = tuple(cs.argv("logs", "--no-color", "--no-log-prefix", operands=("-x",)))
    assert argv[-2:] == ("--", "-x")
    with FakeRunner(FakeCall(argv, lines=())) as runner:
        code, _, err = _out(tmp_path, ["logs", STACK, "-x"], runner)
    assert code == 0, err


# --- R2-S3: the build context through a symlink -----------------------------------


@pytest.mark.parametrize("where", ["first", "middle"])
def test_a_place_through_a_symlink_of_the_context_is_refused(
    tmp_path: Path, where: str
) -> None:
    """The copy of the context keeps its symlinks as links; ``place.path``
    through one would write where it leads. Refused as ``path-outside`` on
    the copy written to -- nothing outside is touched, no copy left."""
    outside = tmp_path / "outside"
    outside.mkdir()
    source = tmp_path / "context"
    source.mkdir()
    if where == "first":
        (source / "skin").symlink_to(outside)
        path = "skin/css"
    else:
        (source / "a").mkdir()
        (source / "a" / "skin").symlink_to(outside)
        path = "a/skin/css"
    package = tmp_path / "package"
    package.mkdir()
    (package / "theme.css").write_text("x")
    place = PackagePlace(
        slot="skin", release="v1", service="frontend", source=package, path=path
    )
    target = tmp_path / "built" / "context"
    with pytest.raises(StepFailed) as raised:
        write_context(source, target, [place])
    assert raised.value.reason.code == "path-outside"
    assert list(outside.iterdir()) == []
    assert not target.exists()
    assert not target.with_name("context.tmp").exists()


def test_a_place_inside_the_context_is_written(tmp_path: Path) -> None:
    """The pair: no symlink on the way -- the package is in place."""
    source = tmp_path / "context"
    (source / "skin").mkdir(parents=True)
    package = tmp_path / "package"
    package.mkdir()
    (package / "theme.css").write_text("x")
    place = PackagePlace(
        slot="skin", release="v1", service="frontend", source=package, path="skin/css"
    )
    target = tmp_path / "built" / "context"
    write_context(source, target, [place])
    assert (target / "skin" / "css" / "theme.css").read_text() == "x"


# --- R2-S6, S16, B27: the names of the machine ------------------------------------


def _product(name: str = "aivis", **change: Json) -> dict[str, Json]:
    raw: dict[str, Json] = {
        "schema": 1,
        "name": name,
        "kind": "product",
        "stacks": {
            name: {
                "compose": "docker-compose.yml",
                "app": {"service": "app", "port": 8000, "health": "/h", "ready": "/r"},
            }
        },
        "env": {},
        "report": {"health": "/h", "ready": "/r", "logs": "json", "junit": True},
    }
    raw.update(change)
    return raw


REPO = "git@github.com:acme/x.git"


def _codes(raw: dict[str, Json]) -> list[str]:
    return [p.code for p in rule_problems(PRIMER_YAML.validate_python(raw))]


@pytest.mark.parametrize("name", ["pridem", "pridem-edge", "pridem-egress", "pridem-x"])
def test_a_product_named_as_the_machine_is_refused(name: str) -> None:
    """``/opt/pridem`` is the box; ``pridem-edge`` and ``pridem-egress`` the
    machine's compose projects; ``pridem-`` a prefix of the machine's."""
    assert "S.name-reserved" in _codes(_product(name))


def test_a_dependency_named_product_or_pridem_is_refused() -> None:
    """B27: a dependency ``product`` -- the word a service's seam names its
    product by; S6: ``pridem`` -- ``destroy`` would take the box's keys."""
    for name in ("product", "pridem"):
        raw = _product(dependencies={name: {"repo": REPO, "version": ">=1,<2"}})
        assert "S.name-reserved" in _codes(raw), name


@pytest.mark.parametrize("entry", ["pridem-egress", "edge", "sources", "finalize"])
def test_an_entry_named_as_the_machine_or_its_plans_is_refused(entry: str) -> None:
    """S16 and the plans' stacks: the verdict keys a step by ``(stack,
    name)`` -- an entry ``edge`` would mix its facts with the edge's."""
    raw = _product()
    stacks = raw["stacks"]
    assert isinstance(stacks, dict)
    stacks[entry] = {"compose": "other.yml"}
    assert "S.name-reserved" in _codes(raw)


def test_an_ordinary_name_is_taken() -> None:
    assert "S.name-reserved" not in _codes(_product("velo"))


def test_the_reserved_names_hold_every_stack_of_the_machine_s_plans(
    tmp_path: Path,
) -> None:
    """The list is one constant; the plans are built from code. Every stack a
    plan of the machine names -- deploy (with rollback), its ``finally``,
    destroy, gc, ssl, the data verbs -- is in it: a new stack of a plan turns
    this red until the list has it."""
    from pridem.events import Secrets
    from pridem.state import Box
    from pridem.steps.destroy import STACK as DESTROY_STACK
    from pridem.steps.gc import GC_STACK
    from pridem.steps.passport import Fetched
    from pridem.steps.stand import ROLLBACK_CHECK
    from pridem.verbs.plans import Source, Wanted, deploy_plan
    from pridem.verbs.run import Session
    from pridem.verbs.ssl import SSL_STACK

    box = Box(tmp_path / "opt" / "pridem")
    names: set[str] = set()
    for mode, back in (("install", False), ("reinstall", False), ("deploy", True)):
        wanted = Wanted(mode=mode, source=Source(file=tmp_path / "x"), rollback=back)
        planned = deploy_plan(
            Session(box, "r1", Fetched(), Secrets(())), tmp_path, wanted, None
        )
        names |= {stack.name for stack in [*planned.stacks, *planned.finally_]}
    names |= {DESTROY_STACK, GC_STACK, SSL_STACK, ROLLBACK_CHECK, "backup", "seed"}
    assert names <= RESERVED_NAMES, sorted(names - RESERVED_NAMES)


# --- the mark of /opt/<stack> ------------------------------------------------------


def test_a_directory_with_files_and_no_mark_is_not_marked(tmp_path: Path) -> None:
    """``/opt/pridem`` of the box, a deploy before the machine: files, no
    mark -- not the machine's; a mark would hand it to ``destroy``."""
    home = tmp_path / "opt" / "aivis"
    home.mkdir(parents=True)
    (home / "docker-compose.yml").write_text("services: {}\n")
    with pytest.raises(NotOurs):
        mark(home, "aivis")
    assert not (home / MARKER).exists()


def test_a_new_or_empty_directory_is_marked_and_a_marked_one_is_left(
    tmp_path: Path,
) -> None:
    new = tmp_path / "opt" / "aivis"
    mark(new, "aivis")
    assert (new / MARKER).read_text() == "aivis\n"
    (new / "releases").mkdir()
    mark(new, "aivis")  # its own mark: nothing to do, files or not
    empty = tmp_path / "opt" / "comms"
    empty.mkdir()
    mark(empty, "comms")
    assert (empty / MARKER).is_file()


def test_destroy_and_gc_take_no_directory_without_the_mark(tmp_path: Path) -> None:
    """``/opt/pridem`` and a directory without a mark are none of the
    machine's stacks; a marked one is."""
    root = tmp_path
    (root / "opt" / "pridem" / "keys").mkdir(parents=True)
    (root / "opt" / "legacy" / "releases").mkdir(parents=True)
    mark(root / "opt" / "aivis", "aivis")
    mine, astray = marked(root)
    assert [p.name for p in mine] == ["aivis"] and astray == []


@pytest.mark.parametrize("left", ["a deploy's file", "current without a mark"])
def test_fetch_into_a_directory_that_is_not_the_machine_s_is_red(
    tmp_path: Path, left: str
) -> None:
    """``fetch_root``: ``/opt/<product>`` holds files of a deploy before the
    machine, no mark -- ``fetch_root:not-ours`` before the checkout writes
    anything there."""
    from test_steps_sources import product as product_yaml
    from test_steps_sources import remote, run

    from pridem.steps.sources import source_steps

    remote(tmp_path, "aivis", {"primer.yaml": product_yaml(tmp_path, dependency=False)})
    root = tmp_path / "box"
    home = root / "opt" / "aivis"
    home.mkdir(parents=True)
    if left == "a deploy's file":
        (home / "old-deploy.sh").write_text("#!/bin/sh\n")
    else:  # the box of the probe DM-10 before DM-93: current, no mark
        (home / "current").symlink_to("releases/older")
    _, steps = source_steps(
        root,
        stack="aivis",
        address=f"file://{tmp_path}/aivis.git",
        ref="main",
        tag=False,
    )
    outcome = run(root, steps)
    failed = [s for s in outcome.steps if s.reason is not None]
    assert failed and failed[0].reason is not None
    assert failed[0].reason.code == "fetch_root:not-ours"
    assert not (home / MARKER).exists() and not (home / "git").exists()


# --- R2-S11: the headers of the edge -----------------------------------------------


def test_the_edge_says_the_forwarded_host_and_port_and_drops_the_rest(
    tmp_path: Path,
) -> None:
    """What a client sends as ``X-Forwarded-Host``, ``-Port``, ``-Prefix`` or
    ``Forwarded`` is the edge's to say: its host, port 443, and no prefix or
    ``Forwarded`` at all (an empty value nginx does not pass). Every proxied
    location, every route. ``Upgrade`` and ``Connection`` are not touched."""
    _, fetched = passport(tmp_path, role="test")
    assert fetched.passport is not None
    text = render(product(), fetched.passport, None)
    proxied = text.count("proxy_pass $upstream;")
    for domain in (DOMAINS["api"], DOMAINS["frontend"]):
        server = _server_of(text, domain)
        assert server.count("proxy_set_header X-Forwarded-Host $host;") == 1
        assert server.count("proxy_set_header X-Forwarded-Port 443;") == 1
        assert server.count('proxy_set_header X-Forwarded-Prefix "";') == 1
        assert server.count('proxy_set_header Forwarded "";') == 1
    assert text.count("X-Forwarded-Host") == proxied
    assert "Upgrade" not in text and "Connection" not in text
