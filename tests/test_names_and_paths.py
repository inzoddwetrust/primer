"""DM-78: names and paths stay inside -- the form of a name and of a key of
``env`` in the model, the keys docker, compose and the machine read for
themselves, ``resolve_inside`` against symlinks of a foreign tree, aliases."""

import json
import os
from pathlib import Path

import pytest
from contract_support import yaml_problems
from env_support import product_data
from passport_support import passport_example
from test_steps_frontend import made, packages, run, skin_box, skin_product

from pridem.events import Code
from pridem.files import PathOutside, resolve_inside
from pridem.runner import FakeRunner
from pridem.stacks.passport import PASSPORT
from pridem.steps.base import StepFailed
from pridem.steps.packages import package_mounts
from pridem.steps.tests import JUNIT_LIMIT, _take_junit


def _codes(found: list[tuple[str, str]]) -> list[str]:
    return [code for _, code in found]


# --- the probe --------------------------------------------------------------------


def test_probe_DM_78_names_and_paths_stay_inside(tmp_path: Path) -> None:
    """A stack named ``../x`` and an entry of ``stacks`` with a newline: the
    loader refuses both before any command. A ``subpath`` of a package that
    is a symlink out of it: ``path-outside`` before any copy or mount -- no
    command at all. The pair: plain names and the package as it is."""
    data = product_data({})
    data["name"] = "../x"
    assert ("name", "S.name") in yaml_problems(tmp_path, data)
    data = product_data({})
    entry = data["stacks"]["aivis"]  # type: ignore[index]
    data["stacks"] = {"aivis\nserver { }": entry}
    assert "S.name" in _codes(yaml_problems(tmp_path, data))
    # the package: subpath is a symlink out of it
    stack = made(tmp_path, skin_product("css"))
    root, fetched, package = skin_box(tmp_path)
    (tmp_path / "elsewhere").mkdir()
    (package / "texts").symlink_to(tmp_path / "elsewhere", target_is_directory=True)
    passport = fetched.passport
    assert passport is not None
    skin = passport.packages["skin"].model_copy(update={"subpath": "texts"})
    fetched.passport = passport.model_copy(update={"packages": {"skin": skin}})
    with pytest.raises(StepFailed) as refused:
        package_mounts(stack, "blank", fetched.passport, root)
    assert refused.value.reason == Code(
        "path-outside", {"slot": "skin", "from": "texts"}
    )
    with FakeRunner() as runner:  # the step: not a command run
        outcome = run([packages(root, fetched, stack)], runner)
    assert outcome.steps[0].reason == Code(
        "packages:path-outside", {"slot": "skin", "from": "texts"}
    )
    # the pair
    assert yaml_problems(tmp_path, product_data({})) == []
    fetched.passport = passport
    assert package_mounts(stack, "blank", passport, root)


# --- names ------------------------------------------------------------------------


GOOD_NAMES = ["primer-blank", "primer-blank-service", "velo", "velo-storage", "comms"]


@pytest.mark.parametrize("name", GOOD_NAMES)
def test_the_names_of_the_line_pass(tmp_path: Path, name: str) -> None:
    data = product_data({})
    data["name"] = name
    assert yaml_problems(tmp_path, data) == []


@pytest.mark.parametrize(
    "name",
    [
        "../x",
        "x/..",
        "..",
        "a.b",
        "a/b",
        "a b",
        "a\nb",
        "a;b",
        "a{",
        "имя",
        "A",
        "",
        "-a",
        "a" * 64,
    ],
    ids=[
        "dotdot-head",
        "dotdot-tail",
        "dotdot",
        "dot",
        "slash",
        "space",
        "newline",
        "semicolon",
        "brace",
        "cyrillic",
        "upper",
        "empty",
        "dash-first",
        "long",
    ],
)
def test_a_name_out_of_form_is_refused(tmp_path: Path, name: str) -> None:
    data = product_data({})
    data["name"] = name
    assert ("name", "S.name") in yaml_problems(tmp_path, data)
    data = product_data(
        {}, dependencies={name: {"repo": "git@h:a/b.git", "version": ">=1,<2"}}
    )
    assert "S.name" in _codes(yaml_problems(tmp_path, data))


def test_the_longest_name_passes(tmp_path: Path) -> None:
    data = product_data({})
    data["name"] = "a" * 63
    assert yaml_problems(tmp_path, data) == []


# --- keys of env ------------------------------------------------------------------


@pytest.mark.parametrize(
    "key",
    ["A'B", 'A"B', "A=B", "A\nB", "1A", "A-B", ""],
    ids=["quote", "dquote", "equals", "newline", "digit-first", "dash", "empty"],
)
def test_a_key_of_env_out_of_form_is_refused(tmp_path: Path, key: str) -> None:
    data = product_data({key: {"source": "minted"}})
    assert "S.env-key" in _codes(yaml_problems(tmp_path, data))


@pytest.mark.parametrize(
    "key",
    [
        "PATH",
        "HOME",
        "HOSTNAME",
        "LD_PRELOAD",
        "LD_LIBRARY_PATH",
        "PYTHONPATH",
        "PYTHONHOME",
        "PYTHONSTARTUP",
        "COMPOSE_PROJECT_NAME",
        "DOCKER_HOST",
        "BUILDKIT_PROGRESS",
        "PRIMER_RELEASE",
    ],
)
def test_a_key_the_machine_or_docker_reads_is_reserved(
    tmp_path: Path, key: str
) -> None:
    data = product_data({key: {"source": "minted"}})
    assert yaml_problems(tmp_path, data) == [(f"env.{key}", "S.env-reserved")]


def test_a_key_near_a_reserved_one_passes(tmp_path: Path) -> None:
    """Exact names and the prefixes alone: ``MY_PATH``, ``COMPOSER``, ``HOME_URL``."""
    env = {key: {"source": "minted"} for key in ("MY_PATH", "COMPOSER", "HOME_URL")}
    assert yaml_problems(tmp_path, product_data(env)) == []


# --- aliases ----------------------------------------------------------------------


def test_two_entries_giving_one_alias_are_refused(tmp_path: Path) -> None:
    """``a-b`` + ``c`` and ``a`` + ``b-c``: one name ``a-b-c`` on ``pridem``."""
    data = product_data({})
    app = {"service": "b-c", "port": 8000, "health": "/h", "ready": "/r"}
    other = {"compose": "x.yml", "app": {**app, "service": "c"}}
    data["stacks"] = {"a": {"compose": "c.yml", "app": app}, "a-b": other}
    data["name"] = "a"
    assert ("stacks.a-b", "S.alias-collision") in yaml_problems(tmp_path, data)
    other["app"] = {**app, "service": "d"}  # the pair
    assert "S.alias-collision" not in _codes(yaml_problems(tmp_path, data))


# --- the passport ---------------------------------------------------------------


@pytest.mark.parametrize(
    "repo", ["git@github.com:a/...git", "git@github.com:a/X.git", "git@h:a/.git"]
)
def test_a_repository_named_out_of_form_is_refused(repo: str) -> None:
    data = passport_example()
    data["product"] = {**data["product"], "repo": repo}  # type: ignore[dict-item]
    with pytest.raises(Exception, match="R18.repo-name"):
        PASSPORT.validate_python(data)


def test_a_package_repository_is_named_the_same_way() -> None:
    data = passport_example()
    data["packages"] = {"skin": {"repo": "git@github.com:p/...git", "version": "1.0.0"}}
    with pytest.raises(Exception, match="R18.repo-name"):
        PASSPORT.validate_python(data)
    data["packages"] = {
        "skin": {"repo": "git@github.com:p/velo-look.git", "version": "1.0.0"}
    }
    assert (
        PASSPORT.validate_python(data).packages["skin"].repo.endswith("velo-look.git")
    )


# --- resolve_inside ---------------------------------------------------------------


def test_resolve_inside_takes_a_plain_path(tmp_path: Path) -> None:
    (tmp_path / "a" / "b").mkdir(parents=True)
    assert resolve_inside(tmp_path, "a/b") == tmp_path / "a" / "b"
    assert resolve_inside(tmp_path, "a/none") == tmp_path / "a" / "none"


@pytest.mark.parametrize("case", ["out", "in", "middle", "absolute", "dotdot"])
def test_resolve_inside_refuses_a_symlink_or_a_way_out(
    tmp_path: Path, case: str
) -> None:
    tree = tmp_path / "tree"
    (tree / "real").mkdir(parents=True)
    (tmp_path / "out").mkdir()
    rel = "link"
    if case == "out":
        (tree / "link").symlink_to(tmp_path / "out")
    elif case == "in":  # a link to its own tree: refused all the same
        (tree / "link").symlink_to(tree / "real")
    elif case == "middle":
        (tree / "link").symlink_to(tree / "real")
        rel = "link/file"
    elif case == "absolute":
        rel = "/etc"
    else:
        rel = "real/../../out"
    with pytest.raises(PathOutside):
        resolve_inside(tree, rel)


# --- junit -----------------------------------------------------------------------


def test_junit_written_by_the_container_is_taken_only_as_a_plain_file(
    tmp_path: Path,
) -> None:
    kept = tmp_path / "kept.xml"
    plain = tmp_path / "plain.xml"
    plain.write_text("<testsuite/>")
    _take_junit(plain, kept)
    assert kept.read_text() == "<testsuite/>"
    secret = tmp_path / "secret"
    secret.write_text("root's")
    cases = {
        "symlink": tmp_path / "link.xml",
        "not-a-file": tmp_path / "dir.xml",
        "too-big": tmp_path / "big.xml",
    }
    cases["symlink"].symlink_to(secret)
    cases["not-a-file"].mkdir()
    cases["too-big"].write_bytes(b"a" * (JUNIT_LIMIT + 1))
    fifo = tmp_path / "fifo.xml"
    os.mkfifo(fifo)
    for cause, path in [*cases.items(), ("not-a-file", fifo)]:
        with pytest.raises(StepFailed) as refused:
            _take_junit(path, tmp_path / "out.xml")
        assert refused.value.reason.params == {"path": str(path), "cause": cause}
    exact = tmp_path / "exact.xml"
    exact.write_bytes(b"a" * JUNIT_LIMIT)
    _take_junit(exact, kept)
    assert len(kept.read_bytes()) == JUNIT_LIMIT
    assert json.dumps(str(kept))


# --- compose: what config unfolds, aliases ----------------------------------------


@pytest.mark.parametrize(
    ("text", "found"),
    [
        ("include: [x.yml]\nservices: {}\n", ["compose: include"]),
        (
            "services:\n  app: {extends: {file: x.yml, service: y}}\n",
            ["app: extends"],
        ),
        ("services:\n  app: {env_file: ../../etc/shadow}\n", ["app: env_file"]),
        ("services:\n  app: {image: x}\n", []),
    ],
    ids=["include", "extends", "env_file", "plain"],
)
def test_what_config_would_unfold_is_refused_before_it_runs(
    tmp_path: Path, text: str, found: list[str]
) -> None:
    """``config`` unfolds ``include`` and ``extends`` out of its document and
    reads ``env_file`` off the host (measured, compose 2.40.3): the file is
    read before ``config`` is called -- no command when it is refused."""
    from test_steps_build_mode import compose, made, velo_data

    from pridem.steps.compose import config, unfolded

    stack = made(velo_data())
    cs = compose(tmp_path, stack, "velo")
    path = cs.compose_file
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    assert unfolded(cs) == found
    if found:
        from env_support import context

        with FakeRunner() as runner, pytest.raises(StepFailed) as refused:
            config(context(runner), cs)
        assert refused.value.reason.code == "compose-forbidden"


def test_a_compose_file_that_is_a_symlink_is_refused(tmp_path: Path) -> None:
    from test_steps_build_mode import compose, made, velo_data

    from pridem.steps.compose import unfolded

    cs = compose(tmp_path, made(velo_data()), "velo")
    cs.compose_file.parent.mkdir(parents=True, exist_ok=True)
    (tmp_path / "host.yml").write_text("services: {}\n")
    cs.compose_file.symlink_to(tmp_path / "host.yml")
    assert unfolded(cs) == ["compose: symlink"]


def test_a_service_whose_alias_is_another_entry_s_alias_is_reserved(
    tmp_path: Path,
) -> None:
    """``velo`` + ``storage-app`` is ``velo-storage`` + ``app`` on ``pridem``:
    the alias, whole (DM-78). The bare name of the service is a DNS name too
    -- that half stays (``test_names_the_machine_gives_are_reserved``)."""
    from test_steps_build_mode import compose, made, velo_data

    from pridem.steps.compose import forbidden

    data = velo_data()
    stacks = data["stacks"]
    assert isinstance(stacks, dict)
    app = {"service": "app", "port": 8000, "health": "/h", "ready": "/r"}
    stacks["velo-storage"] = {**stacks["velo-storage"], "app": app}
    stack = made(data)
    cs = compose(tmp_path, stack, "velo")
    (tmp_path / "release").mkdir(exist_ok=True)
    body = {"image": "x@sha256:x", "healthcheck": {"test": ["CMD", "true"]}}
    document: dict[str, object] = {"services": {"storage-app": body, "web": body}}
    assert forbidden(cs, document) == ["storage-app: name reserved"]  # type: ignore[arg-type]
