"""The interrupt of a command: SIGINT, SIGTERM, SIGHUP and SIGQUIT set a flag,
they raise nothing.

``Interrupt.install`` puts its own handler on these signals for the time
of a command and gives the previous handlers back after it. The handler only
counts the signal (``received``); no exception lands in the middle of the
plan's code. Who reads the flag:

- the plan, between steps and between stacks: a signal received since the
  phase began stops the ladder (``main``, ``restore``, ``doctor``);
- the runner, while a command runs, and the waits of steps (``sleep``,
  ``check``): ``stops`` -- a signal received since the plan began watching the
  current step (``watch``), outside a shield. The runner stops the command's
  group and raises ``Interrupted``; the step fails with ``interrupted``.

``finally`` runs under ``shield``: the first signal of the command is only
counted (the plan writes it to the journal), so the clean-up goes on; every
signal after it -- a person pressing Ctrl-C again -- stops the step of
``finally`` that runs then, and only it: the steps after it still run
(DM-24). A process killed outright (SIGKILL) runs no handler: the runner's
``pdeathsig`` and the box lock held by the command's processes cover that
case.
"""

import signal
import time
from collections.abc import Iterator
from contextlib import contextmanager
from types import FrameType

SIGNALS = (signal.SIGINT, signal.SIGTERM, signal.SIGHUP, signal.SIGQUIT)
"""The signals that interrupt a command: a terminal's Ctrl-C and Ctrl-\\,
``kill``, systemd stopping a unit, and the terminal going away -- an ssh session
dropped -- which by default kills the process with no ``finally`` and no
verdict (measured, DM-92)."""

ESCALATION = 2
"""The signal of a command that stops a step of ``finally``: every one from
the second on."""

SLICE_S = 0.1
"""The longest a wait sleeps before it looks at the flag again."""


class Interrupted(BaseException):
    """A command or a wait of a step stopped by a signal: the step is
    ``interrupted``.

    A ``BaseException``, as ``KeyboardInterrupt`` is: a step's ``except
    Exception`` around a command does not turn it into an ordinary failure.
    """


class Interrupt:
    """The signals a command received, and whether they stop what runs now."""

    def __init__(self) -> None:
        self.received: list[int] = []
        """Signal numbers, in the order they came."""
        self._watched = 0
        self._shielded = False

    @property
    def count(self) -> int:
        """How many signals came so far."""
        return len(self.received)

    def receive(self, signum: int) -> None:
        """Count one signal; the handler's whole work."""
        self.received.append(signum)

    def watch(self) -> None:
        """From now on a new signal stops what runs (a step of ``main``,
        ``restore`` or ``doctor`` begins)."""
        self._watched = self.count

    @contextmanager
    def shield(self) -> Iterator[None]:
        """Inside, only a signal after the command's first stops what runs
        (``finally``): the first is counted and the clean-up goes on."""
        before = self._shielded
        self._shielded = True
        try:
            yield
        finally:
            self._shielded = before

    def stops(self) -> bool:
        """A signal came since ``watch`` -- under a shield, one that is not
        the command's first."""
        if self._shielded and self.count < ESCALATION:
            return False
        return self.count > self._watched

    def check(self) -> None:
        """Raise ``Interrupted`` when ``stops``."""
        if self.stops():
            raise Interrupted

    def sleep(self, seconds: float) -> None:
        """Sleep ``seconds`` in slices of ``SLICE_S``; ``Interrupted`` as soon
        as a signal stops the wait."""
        end = time.monotonic() + seconds
        while True:
            self.check()
            left = end - time.monotonic()
            if left <= 0:
                return
            time.sleep(min(left, SLICE_S))

    def _handler(self, signum: int, frame: FrameType | None) -> None:
        self.receive(signum)

    @contextmanager
    def install(self) -> Iterator[None]:
        """The handler on ``SIGNALS`` inside; the previous ones after."""
        previous = {sig: signal.signal(sig, self._handler) for sig in SIGNALS}
        try:
            yield
        finally:
            for sig, handler in previous.items():
                signal.signal(sig, handler)
