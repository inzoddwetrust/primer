"""A test that would hang turns red by an assertion within its own deadline.

``deadline(seconds)`` arms ``ITIMER_REAL``; when it fires, the handler raises
``AssertionError`` in the main thread. A blocking ``waitpid`` or ``flock`` is
interrupted, not retried: PEP 475 retries a system call only when the handler
returns. Without it, a broken kill or lock shows up as the CI job timeout.
"""

import signal
import time
from collections.abc import Iterator
from contextlib import contextmanager
from types import FrameType


@contextmanager
def deadline(seconds: float) -> Iterator[None]:
    started = time.monotonic()

    def expired(signum: int, frame: FrameType | None) -> None:
        elapsed = time.monotonic() - started
        raise AssertionError(f"did not finish within {seconds} s ({elapsed:.1f} s)")

    previous = signal.signal(signal.SIGALRM, expired)
    signal.setitimer(signal.ITIMER_REAL, seconds)
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)
