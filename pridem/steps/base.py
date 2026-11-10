"""The step: ``check -> act -> verify``.

``check`` reads the box and says whether ``act`` is needed and what it would do;
whatever ``act`` and ``verify`` need from it travels in the returned
``CheckResult``, never in ``self``. ``act`` changes the box. ``verify`` reads
the result back and returns a non-empty fact; a step whose ``verify`` returns
no fact is failed, not ok -- there is no ``act`` without a ``verify`` that
reads the fact back. A step reports a contradiction it read back by raising
``StepFailed`` with the fact it saw, and something left undone by returning
``Verified(fact, incomplete=...)``.

What a step says is a code with parameters, never a phrase (contract 2 v1.6):
``StepFailed``, ``CheckResult`` and ``Verified.incomplete`` take a code the
step declares in ``codes`` (code -> catalog template); the plan prefixes the
step name, ``<step>:<code>``, and the verdict is not built for a code without
a text.
"""

import re
import time
from abc import ABC, abstractmethod
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import ClassVar, Literal

from pridem.events import Code, Fact, Json
from pridem.interrupt import Interrupt
from pridem.report.codes import LOCAL_CODE
from pridem.runner import OnLine, Runner

Mode = Literal["install", "deploy", "reinstall", "destroy", "gc", "renew", "command"]
"""The plans a step can belong to: the three of a deploy, ``destroy``, the
one-step plans of the verbs ``gc`` and ``ssl renew``, and ``command`` -- the
plans of the data verbs (``db``, ``backup``; DM-86)."""
Role = Literal["test", "prod", "preview"]
MODES: frozenset[Mode] = frozenset(
    {"install", "deploy", "reinstall", "destroy", "gc", "renew", "command"}
)

NO_NETWORK = ("--network", "none")
"""A throwaway container of a product with no network at all (protocol 4.1:
a product has no way out); a service's keeps its way out."""
THROWAWAY = ("--cap-drop", "ALL")
"""Every throwaway container of DM-79 (``derive``, ``validate`` of a package
and of a service's data) runs with no capability."""
NO_PULL = ("--pull", "never")
"""On an image this run built or found by its key: never one of a registry."""


def local_code(code: str, params: Mapping[str, Json] | None = None) -> Code:
    """A code as a step says it, before the plan prefixes the step name."""
    if not re.fullmatch(LOCAL_CODE, code):
        raise ValueError(f"a step code is {LOCAL_CODE}: {code!r}")
    return Code(code, dict(params or {}))


@dataclass(frozen=True)
class CheckResult:
    """What ``check`` found: is ``act`` needed, the code of what it would do,
    data for later."""

    needed: bool
    would: Code | None = None
    data: Mapping[str, Json] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.needed and self.would is None:
            raise ValueError("a needed act must say, by a code, what it would do")


@dataclass(frozen=True)
class Verified:
    """The fact ``verify`` read back, and what was left undone, if anything."""

    fact: Fact
    incomplete: Code | None = None


class StepFailed(Exception):
    """``verify`` read back a fact that contradicts what the step promised."""

    def __init__(
        self,
        code: str,
        params: Mapping[str, Json] | None = None,
        fact: Fact | None = None,
    ) -> None:
        self.reason = local_code(code, params)
        super().__init__(code)
        self.fact: Fact = dict(fact or {})


@dataclass(frozen=True)
class StepContext:
    """What a step may use: the runner, an ``on_line`` bound to this step and
    the command's interrupt -- a step that waits asks it (``check``,
    ``sleep``) whether a signal stops the wait."""

    runner: Runner
    mode: Mode
    role: Role
    stack: str
    on_line: OnLine
    interrupt: Interrupt = field(default_factory=Interrupt)


class Step(ABC):
    """A named, idempotent step of a plan.

    ``order`` is the phase number of the step within its stack (contract 2);
    ``modes`` -- the plans it belongs to, never empty; ``point_of_no_return`` --
    the start of its ``act`` makes the plan irreversible; ``roles`` -- the
    roles it runs on, ``None`` for all; ``final_check`` -- the plan's final
    check (TZ 7.3): the plan itself calls ``verify`` of every green step of the
    run again in its place, and the step's own methods are never called;
    ``rechecked`` -- the final check calls this step's ``verify`` again: a step
    whose ``act`` a later step undoes by design (``stop_for_migrate``, whose
    stopped services ``up`` brings back) is ``False`` -- its fact stays in the
    verdict as it was read (DM-22 FIX).
    """

    name: str
    order: int
    modes: frozenset[Mode]
    codes: ClassVar[Mapping[str, str]] = {}
    """The step's own codes -> their catalog templates (English)."""
    point_of_no_return: bool = False
    roles: frozenset[Role] | None = None
    final_check: bool = False
    rechecked: bool = True

    @abstractmethod
    def check(self, ctx: StepContext) -> CheckResult:
        """Read the box; never change it."""

    @abstractmethod
    def act(self, ctx: StepContext, check: CheckResult) -> None:
        """Change the box as ``check`` said."""

    @abstractmethod
    def verify(self, ctx: StepContext, check: CheckResult) -> Verified:
        """Read the result back; return a non-empty fact."""


@dataclass(frozen=True)
class Waiting:
    """How a step waits for a state it reads back: until ``deadline_s`` after
    the first look, ``poll_s`` between looks, by ``clock`` and ``sleep``."""

    deadline_s: float
    poll_s: float
    clock: Callable[[], float] = time.monotonic
    sleep: Callable[[float], None] = time.sleep


def wait_until(ctx: StepContext, ready: Callable[[], bool], waiting: Waiting) -> bool:
    """Look with ``ready`` until it is true or the deadline passes; whether it
    became true. A signal ends the wait between two looks (DM-45). One helper
    for every ``verify`` that waits for a service to come up (DM-80)."""
    deadline = waiting.clock() + waiting.deadline_s
    while not ready():
        if waiting.clock() >= deadline:
            return False
        ctx.interrupt.check()
        waiting.sleep(waiting.poll_s)
        ctx.interrupt.check()
    return True
