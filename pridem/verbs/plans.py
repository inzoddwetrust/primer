"""The plans of the box's verbs, made by the machine (TZ 7.1, 7.3; protocol 6).

One function makes the plan of ``install``, ``update``, ``deploy``,
``reinstall`` and ``doctor`` (``deploy_plan``), one that of ``destroy``
(``destroy_plan``). The order is protocol 6's, the same for every product;
``primer.yaml`` has no steps of its own.

    host -> passport -> [destroy: reinstall] -> timers -> sources ->
    <the product's entries> -> types -> edge -> frontend -> finalize
    finally: host (timers back), gc

What a stack needs and when it is known:

- ``host``, ``passport``, ``timers`` -- known before the run;
- ``sources`` -- deferred: the repository and ref are the passport's, read by
  ``fetch_passport`` (``deploy <ref>`` gives the ref; on a test box it is a tag
  if the remote has one, else a branch; on prod and preview a tag); the
  product repository's deploy key first (``deploy_key``; the services' keys
  join with the services, DM-46);
- the product -- deferred: its ``primer.yaml@target``, read by ``fetch_root``.
  One stack per entry of ``stacks``: the entry named as the product first, with
  ``seams_check`` and ``render_env`` at its head and ``egress`` before its
  ``up``; then the other entries; ``tests`` and ``migrate`` where the entry
  declares them. The services of the product (``dependencies``) join here as
  their own stacks, before the product's (DM-46);
- ``types``, ``edge``, ``frontend``, ``finalize`` -- deferred on the product.

Where the passport comes from (contract 1 section 3): ``--passport <file>``,
or ``--ops <url> --server <name>``; without either, from the box -- the
address its ops repository was fetched from (``pridem.address`` in the bare
repository's git config) and ``server.name`` of the copy, or the copy itself on
a box installed from a file.

The directory of the product on the box, ``/opt/<name>``, is named from its
repository (``<name>.git``): ``primer.yaml`` is read from git, after the
repository is fetched there.
"""

import configparser
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path

from pridem import __version__
from pridem.plan import Deferred, Stack, StackSteps
from pridem.stacks.passport import Passport
from pridem.stacks.schema import Product
from pridem.stacks.seams import SeamMemory
from pridem.steps.base import Step
from pridem.steps.build import Build
from pridem.steps.compose import OverrideHandoff
from pridem.steps.destroy import STACK as DESTROY_STACK
from pridem.steps.destroy import destroy_steps
from pridem.steps.egress import Egress
from pridem.steps.env import RenderEnv, SeamsCheck
from pridem.steps.finalize import FinalCheck, Finalize
from pridem.steps.frontend import Frontend
from pridem.steps.gc import GC_STACK, gc_steps
from pridem.steps.git import repo
from pridem.steps.host import host_steps
from pridem.steps.keys import DeployKey
from pridem.steps.migrate import Migrate
from pridem.steps.nginx import Nginx
from pridem.steps.packages import Packages
from pridem.steps.passport import (
    OPS_STACK,
    PASSPORT_COPY,
    Fetched,
    OpsSource,
    passport_steps,
)
from pridem.steps.sources import ADDRESS_KEY, FetchRoot, Resolved, source_steps
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
    product: Product | None = None
    memory: SeamMemory = field(default_factory=SeamMemory)
    handoff: OverrideHandoff = field(default_factory=OverrideHandoff)


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


def _first(product: Product) -> str:
    """The product's own entry: the one named as the product, else the first."""
    return (
        product.name if product.name in product.stacks else next(iter(product.stacks))
    )


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
        resolved, steps = source_steps(
            root,
            stack=repo(passport.product.repo).name,
            address=passport.product.repo,
            ref=ref,
            tag=tag,
            packages=passport.packages,
            tries=wanted.tries,
        )
        known.resolved = resolved
        known.fetch_root = next(s for s in steps if isinstance(s, FetchRoot))
        key = DeployKey(passport.product.repo, root)  # none for file://
        return [StackSteps("sources", [key, *steps])]

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
        names = [_first(product), *(n for n in product.stacks if n != _first(product))]
        made: list[StackSteps] = []
        for index, entry in enumerate(names):
            stage = product.stacks[entry]
            steps: list[Step] = []
            if index == 0:
                steps += [SeamsCheck(product, {}, fetched), render]
            steps += [
                Build(
                    product,
                    entry,
                    release=release,
                    ref=ref,
                    commit=commit,
                    root=root,
                    handoff=known.handoff,
                    fetched=fetched,
                ),
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
                steps.append(
                    Migrate(
                        product,
                        entry,
                        release=release,
                        ref=ref,
                        commit=commit,
                        root=root,
                        fetched=fetched,
                    )
                )
            if index == 0:
                steps.append(Egress(product, root=root))
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
                )
            )
            made.append(StackSteps(entry, steps))
        return made

    def types() -> Sequence[StackSteps] | None:
        found = target()
        passport = _passport(fetched)
        if found is None or passport is None or known.fetch_root is None:
            return None
        product, release, ref, commit = found
        declared = [name for name, stage in product.stacks.items() if stage.types]
        entry = declared[0] if declared else _first(product)
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
        composition = {
            known.fetch_root.stack: known.fetch_root.target.release,
            "pridem": __version__,
        }
        return [
            StackSteps(
                "finalize",
                [
                    FinalCheck(),
                    Finalize(
                        releases={known.fetch_root.stack: release},
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
        Deferred(PRODUCT, entries, after="fetch_root"),
        Deferred("types", types, after="fetch_root"),
        Deferred("edge", edge, after="fetch_root"),
        Deferred("frontend", frontend, after="fetch_root"),
        Deferred("finalize", finalize, after="fetch_root", root=True),
    ]
    finally_ = [
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
