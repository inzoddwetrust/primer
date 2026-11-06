"""Fixtures of every tier 3 test file.

The blank's service (DM-59). Every edition of ``primer-blank`` at its pin
installs ``primer-blank-service``, and its ``primer.yaml`` names the
service's ``file://`` mirror: any plan that reads the blank's lock --
``check_lock`` of the whole install and of the ssh probe of DM-10 alike --
asks that mirror for the pinned tag. The mirror is made once, before the
first test of the session: cloned over https (the service is public), each
pinned tag's commit checked, as the blank's ``primer.lock`` pins it.
"""

import shutil
from collections.abc import Iterator
from pathlib import Path

import pytest

from pridem.runner import Stream, SubprocessRunner

SERVICE = "primer-blank-service"
SERVICE_REPO = f"https://github.com/inzoddwetrust/{SERVICE}.git"
SERVICE_PINS = {"v1.0.0": "883e3ce4568a5f379737af13c6e2ee21d2810421"}
SERVICE_MIRROR = Path(f"/srv/tier3/{SERVICE}.git")


def _stdout(argv: list[str], timeout: float) -> list[str]:
    out: list[str] = []

    def keep(stream: Stream, line: str, cut: bool) -> None:
        if stream is Stream.STDOUT:
            out.append(line)

    SubprocessRunner().run(argv, timeout=timeout, on_line=keep)
    return out


@pytest.fixture(scope="session", autouse=True)
def service_mirror() -> Iterator[Path]:
    """The service's mirror at ``/srv/tier3``, its pins checked."""
    SERVICE_MIRROR.parent.mkdir(parents=True, exist_ok=True)
    if SERVICE_MIRROR.exists():
        shutil.rmtree(SERVICE_MIRROR)
    _stdout(["git", "clone", "-q", "--mirror", SERVICE_REPO, str(SERVICE_MIRROR)], 300)
    for tag, pin in SERVICE_PINS.items():
        commit = f"{tag}^{{commit}}"
        git = ["git", "--git-dir", str(SERVICE_MIRROR), "rev-parse", commit]
        [found] = _stdout(git, 60)
        assert found == pin, f"{SERVICE} {tag} names {found}, pinned {pin}"
    yield SERVICE_MIRROR
