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
from abc import ABC, abstractmethod
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import ClassVar, Literal

from pridem.events import Code, Fact, Json
from pridem.report.codes import LOCAL_CODE
from pridem.runner import OnLine, Runner

Mode = Literal["install", "deploy", "reinstall"]
Role = Literal["test", "prod", "preview"]
MODES: frozenset[Mode] = frozenset({"install", "deploy", "reinstall"})


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
    """What a step may use: the runner and an ``on_line`` bound to this step."""

    runner: Runner
    mode: Mode
    role: Role
    stack: str
    on_line: OnLine


class Step(ABC):
    """A named, idempotent step of a plan.

    ``order`` is the phase number of the step within its stack (contract 2);
    ``modes`` -- the plans it belongs to, never empty; ``point_of_no_return`` --
    the start of its ``act`` makes the plan irreversible; ``roles`` -- the
    roles it runs on, ``None`` for all.
    """

    name: str
    order: int
    modes: frozenset[Mode]
    codes: ClassVar[Mapping[str, str]] = {}
    """The step's own codes -> their catalog templates (English)."""
    point_of_no_return: bool = False
    roles: frozenset[Role] | None = None

    @abstractmethod
    def check(self, ctx: StepContext) -> CheckResult:
        """Read the box; never change it."""

    @abstractmethod
    def act(self, ctx: StepContext, check: CheckResult) -> None:
        """Change the box as ``check`` said."""

    @abstractmethod
    def verify(self, ctx: StepContext, check: CheckResult) -> Verified:
        """Read the result back; return a non-empty fact."""
