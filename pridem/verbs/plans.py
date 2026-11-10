"""The plans of the box's verbs, made by the machine (TZ 7.1, 7.3; protocol 6).

One function makes the plan of ``install``, ``update``, ``deploy``,
``reinstall`` and ``doctor`` (``deploy_plan``), one that of ``destroy``
(``destroy_plan``). The order is protocol 6's, the same for every product;
``primer.yaml`` has no steps of its own.

    host -> passport -> [destroy: reinstall] -> timers -> sources ->
    dependencies -> services -> <the product's entries> -> types -> edge ->
    frontend -> finalize
    finally: stopped (what stop_for_migrate stopped, when migrate never
    acted), host (timers back), gc

What a stack needs and when it is known:

- ``host``, ``passport``, ``timers`` -- known before the run;
- ``sources`` -- deferred: the repository and ref are the passport's, read by
  ``fetch_passport`` (``deploy <ref>`` gives the ref; on a test box it is a tag
  if the remote has one, else a branch; on prod and preview a tag); the
  product repository's deploy key first (``deploy_key``), then ``fetch_root``
  and ``fetch_packages``;
- ``dependencies`` -- deferred on ``fetch_root``: the deploy key of every
  dependency the edition uses (a stack named as the dependency), then
  ``check_lock`` and ``fetch_services`` -- a service the edition leaves out is
  never asked of its remote;
- ``services`` -- deferred on ``fetch_services``, which read their
  ``primer.yaml``: ``seams_check`` first, before any ``act`` of a stack; then
  each co-located service of the edition in the order of ``installed``, one
  stack per entry, the ladder ``render_env -> build -> [derive_env] ->
  data_copy -> stop_for_migrate -> migrate -> up`` (``steps/services.py``);
- the product -- deferred: its ``primer.yaml@target``, read by ``fetch_root``.
  One stack per entry of ``stacks``: the entry named as the product first, with
  ``render_env`` at its head and ``egress`` before its ``up``; then the other
  entries; ``tests`` and ``migrate`` where the entry declares them, each
  ``migrate`` after its ``stop_for_migrate`` (DM-22); then
  ``seams_verify``, every seam read from the live providers;
- ``derive_env`` -- on the own entry of a stack (service or product) with a
  ``derived`` value, right after its ``build``: ``derive`` runs in the ``app``
  image ``build`` found or made in this run, before anything starts a
  container of the stack (``steps/env.py``);
- ``types``, ``edge``, ``frontend``, ``finalize`` -- deferred on the product.

Where the passport comes from (contract 1 section 3): ``--passport <file>``,
or ``--ops <url> --server <name>``; without either, from the box -- the
address its ops repository was fetched from (``pridem.address`` in the bare
repository's git config) and ``server.name`` of the copy, or the copy itself on
a box installed from a file.

The directory of the product on the box, ``/opt/<name>``, is named from its
repository (``<name>.git``): ``primer.yaml`` is read from git, after the
repository is fetched there -- and its ``name`` is that name, or ``fetch_root``
refuses it (``name-mismatch``): the env and the override are under
``/opt/<name>`` of ``primer.yaml``, and one product has one directory.

The point of no return of a plan is the first ``migrate`` that acts -- a
service's, when its head changes, before the product's tests (see the KNOWN
CEILING at ``services``).
"""

import configparser
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path

from pridem import __version__
from pridem.plan import Deferred, Stack, StackSteps
from pridem.stacks.env import own_entry
from pridem.stacks.options import switched_on
from pridem.stacks.passport import Passport
from pridem.stacks.schema import Derived, Product, Service
from pridem.stacks.seams import Pair, SeamMemory, installed, pairs
from pridem.steps.base import Step
from pridem.steps.build import Build
from pridem.steps.compose import ComposeStack, OverrideHandoff
from pridem.steps.destroy import STACK as DESTROY_STACK
from pridem.steps.destroy import destroy_steps
from pridem.steps.egress import Egress
from pridem.steps.env import DeriveEnv, RenderEnv, SeamsCheck
from pridem.steps.finalize import FinalCheck, Finalize
from pridem.steps.frontend import Frontend
from pridem.steps.gc import GC_STACK, gc_steps
from pridem.steps.git import repo
from pridem.steps.host import host_steps
from pridem.steps.keys import DeployKey
from pridem.steps.migrate import Migrate, StartStopped, StopForMigrate, Stopped
from pridem.steps.nginx import Nginx
from pridem.steps.packages import Packages
from pridem.steps.passport import (
    OPS_STACK,
    PASSPORT_COPY,
    Fetched,
    OpsSource,
    passport_steps,
)
from pridem.steps.services import (
    DataCopy,
    DataItem,
    SeamsVerify,
    data_items,
)
from pridem.steps.sources import (
    ADDRESS_KEY,
    CheckLock,
    FetchPackages,
    FetchRoot,
    FetchServices,
    Resolved,
    source_steps,
)
from pridem.steps.ssl import Ssl, TlsFiles
from pridem.steps.tests import TestReport, Tests
from pridem.steps.timers import timer_steps
from pridem.steps.types import Types
from pridem.steps.up import Up
from pridem.verbs.base import Refused
from pridem.verbs.run import Planned, Session

PRODUCT = "product"
"""The stack of the step ``ladder`` while the product's entries are unknown."""


@dataclass(frozen=True)
class Source:
    """Where the passport comes from: a file, or the ops repository and the
    server's name in it."""

    file: Path | None = None
    ops: str | None = None
    server: str | None = None


def ops_address(fs_root: Path) -> str | None:
    """The address the box's ops repository was fetched from, if it was."""
    config = fs_root / "opt" / OPS_STACK / "git" / "config"
    if not config.is_file():
        return None
    parser = configparser.ConfigParser(interpolation=None, strict=False)
    try:
        parser.read_string(config.read_text(encoding="utf-8"))
    except configparser.Error:
        return None
    section, _, key = ADDRESS_KEY.partition(".")
    return parser.get(section, key, fallback=None) or None


def source_of(
    fs_root: Path,
    copy: Fetched,
    *,
    file: Path | None,
    ops: str | None,
    server: str | None,
) -> Source:
    """The passport's source: as given, else the box's own; ``Refused`` when
    neither says where."""
    if file is not None and (ops is not None or server is not None):
        raise Refused("--passport and --ops/--server: one source, not both")
    if file is not None:
        return Source(file=file)
    if (ops is None) != (server is None):
        raise Refused("--ops and --server go together")
    if ops is not None:
        return Source(ops=ops, server=server)
    address = ops_address(fs_root)
    if address is not None and copy.passport is not None:
        return Source(ops=address, server=copy.passport.server.name)
    if copy.passport is not None:
        return Source(file=fs_root / PASSPORT_COPY)
    raise Refused(
        "where is the passport? --passport <file>, or --ops <url> --server <name>"
    )


@dataclass
class _Known:
    """What the deferred stacks read from the steps before them."""

    resolved: Resolved | None = None
    fetch_root: FetchRoot | None = None
    dependencies: list[Step] = field(default_factory=list)
    """``check_lock`` and ``fetch_services``: made with ``sources``, run after
    the dependencies' keys."""
    product: Product | None = None
    memory: SeamMemory = field(default_factory=SeamMemory)
    handoff: OverrideHandoff = field(default_factory=OverrideHandoff)
    stopped: Stopped = field(default_factory=Stopped)
    """What ``stop_for_migrate`` stopped; ``start_stopped`` reads it (DM-22)."""


@dataclass(frozen=True)
class Wanted:
    """What the verb asks of the plan."""

    mode: str
    """``install``, ``deploy`` (``update``, ``deploy``), ``reinstall``, ``doctor``."""
    source: Source
    ref: str | None = None
    """``deploy <ref>``; ``None`` -- the passport's."""
    tries: Mapping[str, str] = field(default_factory=dict)
    new_secrets: bool = False


def _derives(stack: Product | Service) -> bool:
    """The stack has a ``derived`` value: its own entry gets ``derive_env``."""
    return any(isinstance(var, Derived) for var in stack.env.values())


def _passport(fetched: Fetched) -> Passport | None:
    return fetched.passport


def _domains(passport: Passport | None) -> list[str]:
    """The domains ``preflight`` resolves: only where a certificate is issued
    by DNS (``letsencrypt``); a stand of ``self-signed`` has no DNS."""
    if passport is None or passport.policies.ssl != "letsencrypt":
        return []
    return sorted(set(passport.domains.values()))


def deploy_plan(
    session: Session, fs_root: Path, wanted: Wanted, preread: Passport | None
) -> Planned:
    """The plan of ``install``, ``update``, ``deploy``, ``reinstall``, ``doctor``."""
    root, box, secrets = fs_root, session.box, session.secrets
    report = TestReport()
    known = _Known()
    host, final = host_steps(root, domains=_domains(preread))
    source = wanted.source
    fetched, first = passport_steps(
        root,
        secrets=secrets,
        server=source.server,
        ops=OpsSource(source.ops) if source.ops is not None else None,
        file=source.file,
    )

    def sources() -> Sequence[StackSteps] | None:
        passport = _passport(fetched)
        if passport is None:
            return None
        role = passport.server.role
        ref = wanted.ref if wanted.ref is not None else passport.product.ref
        tag: bool | None = role != "test"
        if wanted.ref is not None and role == "test":
            tag = None  # a tag of that name, else a branch
        edition = passport.edition

        def chosen(product: Product) -> list[str]:
            return installed(product, edition, on=switched_on(passport))

        resolved, steps = source_steps(
            root,
            stack=repo(passport.product.repo).name,
            address=passport.product.repo,
            ref=ref,
            tag=tag,
            packages=passport.packages,
            tries=wanted.tries,
            chosen=chosen,
        )
        known.resolved = resolved
        known.fetch_root = next(s for s in steps if isinstance(s, FetchRoot))
        known.dependencies = [
            s for s in steps if isinstance(s, CheckLock | FetchServices)
        ]
        own = [s for s in steps if isinstance(s, FetchRoot | FetchPackages)]
        key = DeployKey(passport.product.repo, root)  # none for file://
        return [StackSteps("sources", [key, *own])]

    def dependencies() -> Sequence[StackSteps] | None:
        """The keys of the dependencies the edition uses, the lock, the services."""
        resolved, passport = known.resolved, _passport(fetched)
        product = None if resolved is None else resolved.product
        if product is None or passport is None or not known.dependencies:
            return None
        edition = passport.edition
        used = installed(product, edition, on=switched_on(passport))
        addresses = [
            passport.product.repo,
            *(d.repo for d in product.dependencies.values()),
        ]
        made: list[StackSteps] = []
        for name in [n for n in product.dependencies if n in used]:
            address = product.dependencies[name].repo
            others = [a for a in addresses if a != address]
            made.append(StackSteps(name, [DeployKey(address, root, others=others)]))
        made.append(StackSteps("dependencies", list(known.dependencies)))
        return made

    def services() -> Sequence[StackSteps] | None:
        """``seams_check`` and the ladder of each service."""
        found = target()
        passport = _passport(fetched)
        resolved = known.resolved
        if found is None or passport is None or resolved is None:
            return None
        product, release, _, _ = found
        here = installed(product, passport.edition, on=switched_on(passport))
        if any(name not in resolved.services for name in here):
            return None
        fetch = known.fetch_root
        if fetch is None or fetch.target is None:
            return None
        made: list[StackSteps] = [
            StackSteps(
                "seams",
                [SeamsCheck(product, resolved.services, fetched, root)],
            )
        ]
        # KNOWN CEILING (DM-46): a service migrates before the product's tests.
        # 1. Mechanism: the product's render_env takes the seams of the live
        #    services, and its build reads that env; so each service runs
        #    render_env -> build -> [derive_env] -> data_copy ->
        #    stop_for_migrate -> migrate -> up
        #    before the product's build and tests (TZ 6.2, protocol 4.5). Red
        #    tests of the product after a service's migrate that acted are
        #    past the point of no return: "restore needed".
        # 2. Status: acknowledged by design.
        # 3. Task: none -- tests run on the role test only, where a restore is
        #    cheap; no card yet.
        # 4. Trigger: red tests of the product after a service's migrate acted
        #    on a test box (the verdict: migrate of a service ok and acted,
        #    tests of the product failed).
        # 5. Agreed fix: on update, while the service already runs, build and
        #    test the product on the seams' previous values before the
        #    service's migrate.
        # 6. Rejected: the product's build and tests first -- its env needs the
        #    live service's seams; placeholders in env -- a build on values
        #    that are not the instance's.
        for name in here:
            service = resolved.services[name]
            made += _service_stacks(
                service,
                release=resolved.releases[name],
                tag=resolved.lock.dependencies[name].tag if resolved.lock else "",
                commit=resolved.commits[name],
                items=data_items(
                    product,
                    service,
                    release_dir=release,
                    release=fetch.target.release,
                    passport=passport,
                    root=root,
                ),
                product=product,
            )
        return made

    def _service_stacks(
        service: Service,
        *,
        release: Path,
        tag: str,
        commit: str,
        items: Sequence[DataItem],
        product: Product,
    ) -> list[StackSteps]:
        """One stack per entry of a service: its ladder (``steps/services.py``)."""
        render = RenderEnv(
            service,
            product=product,
            fetched=fetched,
            secrets=secrets,
            memory=known.memory,
            root=root,
        )
        first = own_entry(service)
        names = [first, *(n for n in service.stacks if n != first)]
        made: list[StackSteps] = []
        for index, entry in enumerate(names):
            stage = service.stacks[entry]
            mine = items if index == 0 else ()
            build = Build(
                service,
                entry,
                release=release,
                ref=tag,
                commit=commit,
                root=root,
                handoff=known.handoff,
                fetched=fetched,
                data=mine,
                points=points(product),
            )
            steps: list[Step] = [render] if index == 0 else []
            steps.append(build)
            if index == 0 and _derives(service):
                steps.append(DeriveEnv(render, build))
            steps += [
                DataCopy(
                    service,
                    entry,
                    release=release,
                    ref=tag,
                    commit=commit,
                    items=mine,
                    handoff=known.handoff,
                    root=root,
                ),
            ]
            if stage.migrate is not None and stage.app is not None:
                migrate = Migrate(
                    service,
                    entry,
                    release=release,
                    ref=tag,
                    commit=commit,
                    root=root,
                    fetched=fetched,
                )
                steps += [StopForMigrate(migrate, known.stopped), migrate]
            steps.append(
                Up(
                    service,
                    entry,
                    release=release,
                    ref=tag,
                    commit=commit,
                    root=root,
                    memory=known.memory,
                    render=render,
                    fetched=fetched,
                    points=points(product),
                )
            )
            made.append(StackSteps(entry, steps))
        return made

    def points(product: Product) -> list[Pair]:
        """The pairs of the box (DM-62): each ``build`` puts its side of them
        into its override."""
        passport, resolved = _passport(fetched), known.resolved
        if passport is None or resolved is None:
            return []
        on = switched_on(passport)
        return pairs(product, resolved.services, passport.edition, on=on)

    def target() -> tuple[Product, Path, str, str] | None:
        """The product, its release, ref and commit, once ``fetch_root`` read
        them."""
        resolved, fetch = known.resolved, known.fetch_root
        if resolved is None or fetch is None or fetch.target is None:
            return None
        product = resolved.product
        release = resolved.releases.get(fetch.stack)
        if product is None or release is None:
            return None
        known.product = product
        return product, release, fetch.target.ref, fetch.target.commit

    def entries() -> Sequence[StackSteps] | None:
        found = target()
        if found is None:
            return None
        product, release, ref, commit = found
        render = RenderEnv(
            product,
            product=product,
            fetched=fetched,
            secrets=secrets,
            memory=known.memory,
            root=root,
        )
        first = own_entry(product)
        names = [first, *(n for n in product.stacks if n != first)]
        made: list[StackSteps] = []
        for index, entry in enumerate(names):
            stage = product.stacks[entry]
            build = Build(
                product,
                entry,
                release=release,
                ref=ref,
                commit=commit,
                root=root,
                handoff=known.handoff,
                fetched=fetched,
                points=points(product),
            )
            steps: list[Step] = []
            if index == 0:
                steps.append(render)
            steps.append(build)
            if index == 0 and _derives(product):
                steps.append(DeriveEnv(render, build))
            steps += [
                Packages(
                    product,
                    entry,
                    release=release,
                    ref=ref,
                    commit=commit,
                    root=root,
                    fetched=fetched,
                    handoff=known.handoff,
                ),
            ]
            if stage.test is not None and stage.app is not None:
                steps.append(
                    Tests(
                        product,
                        entry,
                        release=release,
                        ref=ref,
                        commit=commit,
                        root=root,
                        report=report,
                        secrets=secrets,
                        fetched=fetched,
                    )
                )
            if stage.migrate is not None and stage.app is not None:
                migrate = Migrate(
                    product,
                    entry,
                    release=release,
                    ref=ref,
                    commit=commit,
                    root=root,
                    fetched=fetched,
                )
                steps += [StopForMigrate(migrate, known.stopped), migrate]
            if index == 0:
                steps.append(Egress(product, fetched=fetched, root=root))
            steps.append(
                Up(
                    product,
                    entry,
                    release=release,
                    ref=ref,
                    commit=commit,
                    root=root,
                    memory=known.memory,
                    render=render,
                    fetched=fetched,
                    points=points(product),
                )
            )
            made.append(StackSteps(entry, steps))
        made.append(StackSteps("seams", [_seams_verify(product, release, ref, commit)]))
        return made

    def _seams_verify(
        product: Product, release: Path, ref: str, commit: str
    ) -> SeamsVerify:
        """Every seam of the box, read from the live product and services."""
        resolved = known.resolved
        passport = _passport(fetched)
        edition = None if passport is None else passport.edition
        on = frozenset[str]() if passport is None else switched_on(passport)
        stacks = {
            product.name: ComposeStack(
                product, own_entry(product), release, ref, commit, root, staged_env=True
            )
        }
        services: dict[str, Service] = {}
        if resolved is not None:
            lock = resolved.lock
            for name in installed(product, edition, on=on):
                service = services[name] = resolved.services[name]
                stacks[name] = ComposeStack(
                    service,
                    own_entry(service),
                    resolved.releases[name],
                    lock.dependencies[name].tag if lock else "",
                    resolved.commits[name],
                    root,
                    staged_env=True,
                )
        return SeamsVerify(product, services, stacks)

    def types() -> Sequence[StackSteps] | None:
        found = target()
        passport = _passport(fetched)
        if found is None or passport is None or known.fetch_root is None:
            return None
        product, release, ref, commit = found
        declared = [name for name, stage in product.stacks.items() if stage.types]
        entry = declared[0] if declared else own_entry(product)
        made: list[Step] = [
            Types(
                product,
                entry,
                release=release,
                ref=ref,
                commit=commit,
                role=passport.server.role,
                branch=ref,
                run_id=session.run_id,
                push_to=passport.product.repo,
                git_dir=known.fetch_root.checkout.bare,
                root=root,
            )
        ]
        return [StackSteps("types", made)]

    def edge() -> Sequence[StackSteps] | None:
        found = target()
        if found is None:
            return None
        product = found[0]
        return [
            StackSteps(
                "edge",
                [
                    TlsFiles(product, fetched=fetched, root=root),
                    Nginx(product, fetched=fetched, secrets=secrets, root=root),
                    Ssl(product, fetched=fetched, secrets=secrets, root=root),
                ],
            )
        ]

    def frontend() -> Sequence[StackSteps] | None:
        found = target()
        if found is None:
            return None
        return [
            StackSteps("frontend", [Frontend(found[0], fetched=fetched, root=root)])
        ]

    def finalize() -> Sequence[StackSteps] | None:
        found = target()
        if found is None or known.fetch_root is None or known.fetch_root.target is None:
            return None
        product, release, _, _ = found
        resolved, passport = known.resolved, _passport(fetched)
        edition = None if passport is None else passport.edition
        on = frozenset[str]() if passport is None else switched_on(passport)
        releases = {known.fetch_root.stack: release}
        composition = {known.fetch_root.stack: known.fetch_root.target.release}
        for name in installed(product, edition, on=on):
            if resolved is not None and name in resolved.releases:
                releases[name] = resolved.releases[name]
                composition[name] = resolved.releases[name].name
        composition["pridem"] = __version__
        return [
            StackSteps(
                "finalize",
                [
                    FinalCheck(),
                    Finalize(
                        releases=releases,
                        composition=composition,
                        box=box,
                        fetched=fetched,
                        root=root,
                    ),
                ],
                root=True,
            )
        ]

    stacks: list[Stack] = [StackSteps("host", host), StackSteps("passport", first)]
    if wanted.mode == "reinstall":
        stacks.append(
            StackSteps(
                DESTROY_STACK,
                destroy_steps(root, box=box, new_secrets=wanted.new_secrets),
            )
        )
    stacks += [
        StackSteps("timers", timer_steps(root, fetched=fetched)),
        Deferred("sources", sources, after="fetch_passport"),
        Deferred("dependencies", dependencies, after="fetch_root"),
        Deferred("services", services, after="fetch_services"),
        Deferred(PRODUCT, entries, after="fetch_root"),
        Deferred("types", types, after="fetch_root"),
        Deferred("edge", edge, after="fetch_root"),
        Deferred("frontend", frontend, after="fetch_root"),
        Deferred("finalize", finalize, after="fetch_root", root=True),
    ]
    finally_ = [
        StackSteps("stopped", [StartStopped(known.stopped)]),
        StackSteps("host", final),
        StackSteps(
            GC_STACK, gc_steps(root, box=box, run_id=session.run_id, fetched=fetched)
        ),
    ]
    return Planned(stacks, finally_, fetched, report)


def destroy_plan(session: Session, fs_root: Path) -> Planned:
    """The plan of ``destroy``: the ladder of ``pridem/steps/destroy.py``."""
    steps = destroy_steps(fs_root, box=session.box)
    return Planned([StackSteps(DESTROY_STACK, steps, root=True)])
