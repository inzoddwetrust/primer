"""``pridem check <directory> [<slot>=<directory> ...]``: a repository of a
project checked by the machine, for the project's CI (protocol 10.1; contract
3 section 6).

It checks what the machine checks on a box, by the same functions, and writes
nothing -- no journal, no ``history/``, no file -- with no box, no docker
daemon and no network. One step each, in this order (``CHECKS``):

- ``primer_yaml`` -- ``primer.yaml`` by the machine's loader (``invalid``: every
  problem with its path and rule; the paths of an ``app`` are plain ones), then
  the hosts of a product's ``egress`` against the list agreed with Primer by
  ``unlisted``, the function ``build`` refuses by (``egress-unlisted``, every
  such host named; the checks after it still run);
- ``primer_lock`` -- ``primer.lock`` by the machine's loader and ``check_lock``
  (``lock-missing``, ``lock-range``); its tags and commits the box checks over
  the network, so the fact says they are not checked;
- ``compose`` -- per stack, ``docker compose config`` of its file (the binary
  alone, no daemon): ``config --no-interpolate`` gives ``env_file`` and the
  variables as written (``env_files``, ``variables``), and when no variable is
  wrong, ``config`` with a stand-in value (``STAND_IN``) for every key of
  ``env`` -- in the environment of compose alone, its ``.env`` off, nothing
  written -- gives what ``refusal`` refuses: the codes and parameters of
  ``build`` on the box, from one dictionary, with the places of the packages
  against the compose of every stack (``package_places``: a service of
  another stack is that stack's; one in none is a finding of each). The
  product's ``config`` is read without the machine's override: the machine's
  ``PRIMER_EDITION`` is not a ``build.args`` of the product. No compose --
  ``incomplete compose:not-found``, exit 2;
- ``packages`` -- the ``primer-package.yaml`` of every package directory given
  (``<slot>=<directory>``) by ``package_contract``; none given -- the step is
  skipped and says which slots were not checked.

The verdict has the form of contract 2: no journal, so no ``log_ref``; both
compositions are ``{pridem}``; the actor is the machine. It is printed --
the ladder and the summary line, or the object with ``--json`` -- never
stored. A directory that is not one, a ``<slot>=<directory>`` that is not of
that form or names no slot of ``packages``, is refused before anything runs:
exit 1, a message, no verdict.
"""

import secrets as token
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from pridem import __version__
from pridem.contract import Strict
from pridem.events import (
    Code,
    ConsoleSink,
    Fact,
    Incomplete,
    Json,
    PlanOutcome,
    Secrets,
    StepFinished,
    StepRecord,
    after_failure,
)
from pridem.report.catalog import ENGLISH, with_steps
from pridem.report.codes import ExitCode
from pridem.report.render import render_json, summary_line
from pridem.report.schema import build_verdict
from pridem.runner import CommandFailed, CommandNotStarted, Stream
from pridem.stacks.egress import UNLISTED, unlisted
from pridem.stacks.loader import ContractError
from pridem.stacks.lock import check_lock, load_primer_lock
from pridem.stacks.package import PACKAGE_FILE
from pridem.stacks.schema import Product, Service, load_primer_yaml
from pridem.steps.base import StepContext, StepFailed
from pridem.steps.compose import (
    REFUSAL_CODES,
    ComposeStack,
    config,
    env_files,
    package_places,
    refusal,
    variables,
)
from pridem.steps.sources import PACKAGE_CODES, package_contract
from pridem.verbs.base import Context, Refused, Verb

ACTOR = {"type": "machine", "via": "local"}
NO_SECRETS = Secrets(())  # a repository holds no value: nothing to clean
STAND_IN = "1"
"""The value ``config`` gets for every key of ``env``: a string, a path in the
repository and a port alike. A value is the passport's, never the
repository's, so what it would be is not checked here."""
TIMEOUT_S = 120

Stack = Product | Service

CODES: dict[str, dict[str, str]] = {
    "primer_yaml": {
        "no-primer-yaml": "{file} is missing",
        "invalid": "{file} breaks its contract: {problems}",
        "egress-unlisted": UNLISTED,
    },
    "primer_lock": {
        "lock-missing": "primer.lock is missing and the product has dependencies",
        "lock-range": "primer.lock breaks primer.yaml: {problems}",
        "invalid": "{file} breaks its contract: {problems}",
    },
    "compose": {
        **REFUSAL_CODES,
        "no-compose": "{file} of {stack} is missing",
        "config-failed": "docker compose config of {stack} exits {exit_code}",
        "not-found": "docker compose is not found: the compose files are not checked",
    },
    "packages": {
        **PACKAGE_CODES,
        "not-given": "no package directory was given: {slots} not checked",
    },
}


class CheckArgs(Strict):
    path: str
    packages: list[str] = []


@dataclass
class Checked:
    """What the checks of one repository found, step by step."""

    root: Path
    given: Mapping[str, Path]
    ctx: StepContext
    stack: Stack | None = None
    steps: list[StepRecord] = field(default_factory=list)
    incomplete: list[Incomplete] = field(default_factory=list)


def _record(stack: str, name: str, order: int, run: Callable[[], Fact]) -> StepRecord:
    """One check as a step: its fact, or its code when it raised one."""
    try:
        fact = run()
    except StepFailed as failed:
        return StepRecord(
            stack,
            name,
            order,
            "failed",
            Code(f"{name}:{failed.reason.code}", dict(failed.reason.params)),
        )
    return StepRecord(stack, name, order, "ok", verify=fact)


def _problems(error: ContractError) -> list[Json]:
    return [str(problem) for problem in error.problems]


def _primer_yaml(checked: Checked) -> None:
    file = checked.root / "primer.yaml"

    def run() -> Fact:
        if not file.exists():
            raise StepFailed("no-primer-yaml", {"file": "primer.yaml"})
        try:
            checked.stack = load_primer_yaml(file)
        except ContractError as error:
            raise StepFailed(
                "invalid", {"file": "primer.yaml", "problems": _problems(error)}
            ) from None
        stack = checked.stack
        if isinstance(stack, Product) and (hosts := unlisted(stack)):
            raise StepFailed(
                "egress-unlisted", {"product": stack.name, "hosts": list[Json](hosts)}
            )
        fact: dict[str, Json] = {
            "kind": stack.kind,
            "name": stack.name,
            "stacks": list[Json](stack.stacks),
        }
        if isinstance(stack, Product):
            fact["egress"] = list[Json](stack.egress)
        return fact

    checked.steps.append(_record(checked.root.name, "primer_yaml", 1, run))


def _primer_lock(checked: Checked, stack: Stack) -> None:
    file = checked.root / "primer.lock"

    def run() -> Fact:
        dependencies = list(stack.dependencies) if isinstance(stack, Product) else []
        if not dependencies:
            return {"dependencies": [], "lock": "not needed"}
        if not file.exists():
            raise StepFailed("lock-missing")
        try:
            lock = load_primer_lock(file)
        except ContractError as error:
            raise StepFailed(
                "invalid", {"file": "primer.lock", "problems": _problems(error)}
            ) from None
        problems = check_lock(stack, lock) if isinstance(stack, Product) else []
        if problems:
            raise StepFailed("lock-range", {"problems": [str(p) for p in problems]})
        return {
            "dependencies": list[Json](dependencies),
            "tags": "not checked: the box checks them over the network",
        }

    checked.steps.append(_record(stack.name, "primer_lock", 2, run))


def _compose_found(ctx: StepContext) -> bool:
    """Whether ``docker compose`` answers here (the binary; no daemon)."""
    try:
        ctx.runner.run(
            ["docker", "compose", "version"], timeout=TIMEOUT_S, on_line=_drop
        )
    except (CommandNotStarted, CommandFailed):
        return False
    return True


def _drop(stream: Stream, line: str, cut: bool) -> None:
    """The version compose prints is not the verdict's."""


@dataclass
class Read:
    """What ``config`` gave of one entry's compose: its findings so far, and
    its document when every variable was right; or the code it failed by."""

    file: str
    raw: dict[str, Json] = field(default_factory=dict)
    document: dict[str, Json] | None = None
    found: list[str] = field(default_factory=list)
    failed: StepFailed | None = None


def _read(checked: Checked, stack: Stack, entry: str) -> Read:
    compose = ComposeStack(stack, entry, checked.root, "check", "", checked.root)
    file = stack.stacks[entry].compose
    read = Read(file)
    if not compose.compose_file.exists():
        read.failed = StepFailed("no-compose", {"file": file, "stack": entry})
        return read
    stand_ins = dict.fromkeys(stack.env, STAND_IN)
    try:
        read.raw = config(checked.ctx, compose, interpolate=False, values=stand_ins)
        wrong = variables(read.raw, stack.env)
        read.found = [*env_files(read.raw), *wrong]
        if not wrong:  # config stops at the first one, and names it as text
            read.document = config(checked.ctx, compose, values=stand_ins)
    except CommandFailed as failed:
        read.failed = StepFailed(
            "config-failed", {"stack": entry, "exit_code": failed.code}
        )
    return read


def _composes(checked: Checked, stack: Stack) -> None:
    """The compose of every entry: read first, all of them -- where a package
    goes is checked against them all (``package_places``) -- then refused by
    the function ``build`` refuses by."""
    reads = {entry: _read(checked, stack, entry) for entry in stack.stacks}
    documents = {e: r.document for e, r in reads.items() if r.document is not None}
    places: list[str] = []
    if len(documents) == len(reads):  # an entry unread could hold any service
        places = package_places(stack, documents)
    for entry, read in reads.items():
        compose = ComposeStack(stack, entry, checked.root, "check", "", checked.root)

        def run(read: Read = read, compose: ComposeStack = compose) -> Fact:
            if read.failed is not None:
                raise read.failed
            document = {} if read.document is None else read.document
            also = [*read.found, *(places if read.document is not None else [])]
            refused = refusal(compose, document, read.raw, also)
            if refused is not None:
                raise StepFailed(*refused)
            return {
                "file": read.file,
                "services": list[Json](sorted(_services(read.raw))),
            }

        checked.steps.append(_record(entry, "compose", 3, run))


def _services(document: Mapping[str, Json]) -> list[str]:
    services = document.get("services")
    return list(services) if isinstance(services, dict) else []


def _packages(checked: Checked, stack: Stack) -> None:
    slots = sorted(stack.packages) if isinstance(stack, Product) else []
    absent = [slot for slot in slots if slot not in checked.given]

    def run() -> Fact:
        found: list[Json] = []
        if isinstance(stack, Product):  # a service declares no packages
            for slot, directory in sorted(checked.given.items()):
                manifest = directory / PACKAGE_FILE
                text = (
                    manifest.read_text(encoding="utf-8") if manifest.exists() else None
                )
                contract = package_contract(
                    stack, slot, text, PACKAGE_FILE, str(directory)
                )
                found.append({"slot": slot, "contract": contract})
        return {"slots": found}

    if slots and not checked.given:
        reason = Code("packages:not-given", {"slots": list[Json](absent)})
        checked.steps.append(StepRecord(stack.name, "packages", 4, "skipped", reason))
        return
    record = _record(stack.name, "packages", 4, run)
    if record.status == "ok" and absent:  # some given, some not: say which
        record = StepRecord(
            stack.name,
            "packages",
            4,
            "ok",
            verify={**record.verify, "not_checked": list[Json](absent)},
        )
    checked.steps.append(record)


CHECKS: tuple[Callable[[Checked, Stack], None], ...] = (_primer_lock,)
"""The checks after ``primer.yaml`` that need nothing but it; ``compose`` and
``packages`` follow. A next check of a repository is one more function."""


def _run_checks(checked: Checked) -> None:
    _primer_yaml(checked)
    stack = checked.stack
    declared = set(stack.packages) if isinstance(stack, Product) else set()
    unknown = sorted(set(checked.given) - declared)
    if stack is not None and unknown:  # before anything else runs
        raise Refused(f"check: no slot {unknown} in packages of primer.yaml")
    if stack is None:
        failed = checked.steps[0]
        skip = after_failure("main", failed.stack, failed.name)
        for order, name in ((2, "primer_lock"), (3, "compose"), (4, "packages")):
            checked.steps.append(StepRecord(failed.stack, name, order, "skipped", skip))
        return
    for check in CHECKS:
        check(checked, stack)
    if _compose_found(checked.ctx):
        _composes(checked, stack)
    else:
        reason = Code("compose:not-found")
        checked.incomplete.append(Incomplete("compose", reason))
        for entry in stack.stacks:
            checked.steps.append(StepRecord(entry, "compose", 3, "skipped", reason))
    _packages(checked, stack)


def _given(pairs: Sequence[str]) -> dict[str, Path]:
    """``<slot>=<directory>`` pairs, by form; the slots are checked against
    ``packages`` once ``primer.yaml`` is read."""
    given: dict[str, Path] = {}
    for pair in pairs:
        slot, sign, directory = pair.partition("=")
        if not sign or not slot or not directory:
            raise Refused(f"check: {pair!r} is not <slot>=<directory>")
        path = Path(directory)
        if not path.is_dir():
            raise Refused(f"check: the package directory {directory!r} is not one")
        given[slot] = path
    return given


def _run(args: Strict, ctx: Context) -> int:
    if not isinstance(args, CheckArgs):
        raise TypeError("check takes CheckArgs")
    if not Path(args.path).is_dir():
        raise Refused(f"check: {args.path!r} is not a directory")
    # by its absolute path: the verdict names its first step by the
    # directory's name, which "." and ".." do not have
    root = Path(args.path).resolve()
    given = _given(args.packages)
    started = datetime.now(UTC).replace(microsecond=0)
    step_ctx = StepContext(ctx.runner, "deploy", "test", root.name, _drop)
    checked = Checked(root, given, step_ctx)
    _run_checks(checked)
    failed = any(record.status == "failed" for record in checked.steps)
    code = (
        ExitCode.FAILED
        if failed
        else ExitCode.INCOMPLETE
        if checked.incomplete
        else ExitCode.OK
    )
    catalog = with_steps(ENGLISH, CODES.items())
    composition = {"pridem": __version__}
    verdict = build_verdict(
        PlanOutcome(
            "check", code, tuple(checked.steps), incomplete=tuple(checked.incomplete)
        ),
        run_id=f"{started:%Y-%m-%dT%H:%M:%SZ}-{token.token_hex(2)}",
        verb="check",
        args={
            "path": args.path,
            **({"packages": list[Json](args.packages)} if args.packages else {}),
        },
        actor=ACTOR,
        started=started,
        finished=datetime.now(UTC).replace(microsecond=0),
        passport_version=None,
        composition_before=composition,
        composition_after=composition,
        secrets=NO_SECRETS,
        catalog=catalog,
        journal=False,
    )
    if ctx.json:
        ctx.out.write(render_json(verdict) + "\n")
    else:
        console = ConsoleSink(ctx.out, NO_SECRETS, catalog)
        for record in checked.steps:
            console.emit(StepFinished("main", record))
        ctx.out.write(summary_line(verdict, catalog) + "\n")
    return int(verdict.exit_code)


CHECK = Verb(
    "check", CheckArgs, _run, positionals=("path",), rest="packages", box=False
)
