"""Probe DM-88: a command run with no ``env`` gets the home of the running user.

``pridem check`` runs in a product's CI as the runner's user, not root. With
``DOCKER_CONFIG=/root/.docker``, which that user cannot read, docker loses every
plugin, the system's ``compose`` too, and the check is ``not-found``. The
clean environment of the runner takes ``HOME`` from ``passwd`` for the running
uid and puts ``DOCKER_CONFIG`` at ``$HOME/.docker``; root -- every run on a
box, from the timer or ssh -- gets ``/root`` as before. Neither ``HOME`` nor
``DOCKER_CONFIG`` of the process reaches the command.

The user is a uid with an entry made here (``getuid`` and ``getpwuid`` stood
in for that uid alone), so the probe is the same as root in the sandbox and as
the runner's user on tier 1; the command is a real child process that prints
its whole environment.
"""

import json
import os
import pwd
import sys
from pathlib import Path

import pytest

from pridem.runner import Stream, SubprocessRunner

TIMEOUT = 30.0
UID = 4343

CONSTANT = {
    "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    "LANG": "C.UTF-8",
    "LC_ALL": "C.UTF-8",
}


def seen() -> dict[str, str]:
    """The whole environment of a command run with no ``env``."""
    lines: list[str] = []

    def keep(stream: Stream, line: str, continued: bool) -> None:
        if stream is Stream.STDOUT:
            lines.append(line)

    SubprocessRunner().run(
        [sys.executable, "-c", "import json, os; print(json.dumps(dict(os.environ)))"],
        timeout=TIMEOUT,
        on_line=keep,
    )
    environment: dict[str, str] = json.loads(lines[0])
    return environment


def test_probe_DM_88_no_env_is_the_home_of_the_user(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A user who is not root: their ``HOME`` from ``passwd`` and
    ``$HOME/.docker``, whatever ``HOME`` and ``DOCKER_CONFIG`` the process has,
    and no ``/root`` anywhere. The pair -- root: ``/root`` and
    ``/root/.docker``."""
    home = str(tmp_path / "home" / "runner")
    real = pwd.getpwuid

    def entry(uid: int) -> pwd.struct_passwd:
        if uid == UID:
            return pwd.struct_passwd(("runner", "x", UID, UID, "", home, "/bin/sh"))
        return real(uid)

    monkeypatch.setattr(pwd, "getpwuid", entry)
    monkeypatch.setenv("HOME", "/home/somebody")
    monkeypatch.setenv("DOCKER_CONFIG", "/home/somebody/.docker-elsewhere")

    monkeypatch.setattr(os, "getuid", lambda: UID)
    user = seen()
    assert user == {**CONSTANT, "HOME": home, "DOCKER_CONFIG": f"{home}/.docker"}
    assert not any("/root" in value for value in user.values())

    monkeypatch.setattr(os, "getuid", lambda: 0)
    root = seen()
    assert root == {**CONSTANT, "HOME": "/root", "DOCKER_CONFIG": "/root/.docker"}
