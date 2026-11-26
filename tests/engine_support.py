"""The build cache as the Engine API gives it to ``gc`` (DM-207), for tests
whose docker follows a script: ``steps.engine.build_cache`` replaced by a
script of its own -- strict, as ``FakeRunner`` is -- or by a cache that stays
as it is, for a test that is not about the cache. The reader itself is
tested on a real unix socket (``test_steps_engine.py``).
"""

from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from pathlib import Path
from unittest import mock

from pridem.steps import engine
from pridem.steps.engine import CacheRecord

GB = 1000**3


def cache(whole: int, own: int | None = None, *, count: int = 5) -> list[CacheRecord]:
    """``count`` records of ``whole`` bytes, ``own`` of them no image's (by
    default all): one record neither in use nor shared, one shared with the
    images, the others in use and empty."""
    own = whole if own is None else own
    assert 0 <= own <= whole and count >= 2
    return [
        CacheRecord(own, in_use=False, shared=False),
        CacheRecord(whole - own, in_use=False, shared=True),
        *(CacheRecord(0, in_use=True, shared=False) for _ in range(count - 2)),
    ]


CALM = cache(1 * GB)
"""A cache under every budget of the tests' passports but the planted ones."""


class Engine:
    """The reads of the build cache by a strict script: each read takes the
    next measurement; a read the script does not hold fails where it is made,
    and ``done`` fails on a measurement nobody read."""

    def __init__(self, *measures: Sequence[CacheRecord]) -> None:
        self._left = list(measures)
        self.reads = 0

    def __call__(self, root: Path) -> list[CacheRecord]:
        self.reads += 1
        if not self._left:
            raise AssertionError(f"read {self.reads} of the build cache is unplanned")
        return list(self._left.pop(0))

    def done(self) -> None:
        assert not self._left, f"{len(self._left)} measurements of the cache unread"


@contextmanager
def engine_says(*measures: Sequence[CacheRecord]) -> Iterator[Engine]:
    """The Engine API answers by the script ``measures``, read to its end."""
    script = Engine(*measures)
    with mock.patch.object(engine, "build_cache", script):
        yield script
    script.done()


@contextmanager
def engine_steady(measure: Sequence[CacheRecord] = CALM) -> Iterator[None]:
    """The Engine API answers ``measure`` whenever it is asked."""
    with mock.patch.object(engine, "build_cache", lambda root: list(measure)):
        yield


@contextmanager
def engine_raises(error: Exception) -> Iterator[None]:
    """The Engine API cannot be read: every read raises ``error``."""

    def refuse(root: Path) -> list[CacheRecord]:
        raise error

    with mock.patch.object(engine, "build_cache", refuse):
        yield
