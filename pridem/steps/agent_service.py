"""``agent_service``: the agent of the box as a systemd service (DM-143).

One unit in ``/etc/systemd/system``, ``pridem-agent.service``: ``pridem
agent`` (``pridem/agent/service.py``) as root -- the machine is root's, like
every file of the box -- restarted by systemd whenever it ends
(``Restart=always``, ``RestartSec``), started on boot (``WantedBy=
multi-user.target``) after the network is up (``Wants`` and ``After``
``network-online.target``: ``After`` alone orders, it does not pull the target
in). One agent per box is the agent's own ``flock`` (DM-141), not the unit.

A box that is not registered gets no service: the agent refuses to start
without ``agent/registration.json`` and ``Restart=always`` would turn that
refusal round and round. ``check`` refuses first (``not-registered``), before
a file is written or systemd asked.

``check`` compares the file with its render, asks systemd whether it still
holds an older text (``NeedDaemonReload``: a run that died between the write
and the reload leaves the file right and systemd wrong), whether the unit is
enabled and whether it runs. ``act`` writes the file when it differs
(``atomic_write``, 0644), reloads systemd when the file changed or systemd
holds an older text, enables the unit and restarts it -- so a changed text is
the one that runs. ``verify`` reads all four back. Nothing else of systemd is
touched; the timers are ``steps/timers.py``'s.
"""

from pathlib import Path
from typing import ClassVar

from pridem.events import Json
from pridem.files import atomic_write
from pridem.identity import RegistrationDamaged, read_registration
from pridem.steps.base import (
    CheckResult,
    Mode,
    Step,
    StepContext,
    StepFailed,
    Verified,
    local_code,
)
from pridem.steps.compose import out
from pridem.steps.timers import PRIDEM, UNIT_DIR

UNIT = "pridem-agent.service"
RESTART_S = 5
"""How long systemd waits before it starts the agent again."""
MODES: frozenset[Mode] = frozenset({"command"})


def unit_text() -> str:
    """The text of ``pridem-agent.service``."""
    return (
        "[Unit]\n"
        "Description=pridem agent\n"
        "Wants=network-online.target\n"
        "After=network-online.target\n"
        "\n"
        "[Service]\n"
        "Type=simple\n"
        f"ExecStart={PRIDEM} agent\n"
        "Restart=always\n"
        f"RestartSec={RESTART_S}\n"
        "User=root\n"
        "\n"
        "[Install]\n"
        "WantedBy=multi-user.target\n"
    )


def _answer(ctx: StepContext, question: str) -> str:
    """``systemctl is-enabled|is-active pridem-agent.service``: what systemd
    answers (``not-found`` and the like for a unit it does not have)."""
    _, lines = out(
        ctx, ["systemctl", question, UNIT], expect=(0, 1, 3, 4), passed_on=False
    )
    return lines[0].strip() if lines else ""


def _stale(ctx: StepContext) -> bool:
    """systemd holds an older text of the unit than the file."""
    _, lines = out(
        ctx,
        ["systemctl", "show", "-p", "NeedDaemonReload", "--value", UNIT],
        passed_on=False,
    )
    return bool(lines) and lines[0].strip() == "yes"


class AgentService(Step):
    """The agent's systemd service: written, loaded, enabled, running."""

    name = "agent_service"
    title = "The agent's service"
    said = "{unit} {active}"
    order = 1
    modes = MODES
    codes: ClassVar[dict[str, str]] = {
        "install": "write, enable and start {unit}",
        "not-registered": (
            "the box is not registered: the agent would refuse to start -- "
            "pridem register first"
        ),
        "not-loaded": "systemd holds an older text of {unit} after daemon-reload",
        "not-enabled": "{unit} is {state}, not enabled",
        "not-active": "{unit} is {state}, not active",
    }

    def __init__(self, root: Path, fs_root: Path) -> None:
        self.root = root
        self.path = fs_root / UNIT_DIR / UNIT

    def _registered(self) -> None:
        try:
            registration = read_registration(self.root)
        except RegistrationDamaged:
            registration = None
        if registration is None:
            raise StepFailed("not-registered")

    def _differs(self) -> bool:
        try:
            return self.path.read_text(encoding="utf-8") != unit_text()
        except OSError:
            return True

    def check(self, ctx: StepContext) -> CheckResult:
        self._registered()
        if (
            self._differs()
            or _stale(ctx)
            or _answer(ctx, "is-enabled") != "enabled"
            or _answer(ctx, "is-active") != "active"
        ):
            return CheckResult(True, local_code("install", {"unit": UNIT}))
        return CheckResult(False)

    def act(self, ctx: StepContext, check: CheckResult) -> None:
        written = self._differs()
        if written:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            atomic_write(self.path, unit_text(), 0o644)
        if written or _stale(ctx):
            out(ctx, ["systemctl", "daemon-reload"])
        out(ctx, ["systemctl", "enable", UNIT])
        out(ctx, ["systemctl", "restart", UNIT])

    def verify(self, ctx: StepContext, check: CheckResult) -> Verified:
        if self._differs() or _stale(ctx):
            raise StepFailed("not-loaded", {"unit": UNIT})
        enabled = _answer(ctx, "is-enabled")
        if enabled != "enabled":
            raise StepFailed("not-enabled", {"unit": UNIT, "state": enabled})
        active = _answer(ctx, "is-active")
        if active != "active":
            raise StepFailed("not-active", {"unit": UNIT, "state": active})
        fact: dict[str, Json] = {
            "unit": UNIT,
            "path": str(self.path),
            "enabled": enabled,
            "active": active,
            "changed": check.needed,
        }
        return Verified(fact)
