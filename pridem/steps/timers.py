"""``timers``: the box's own timers, systemd units the machine writes (TZ 7.3).

Two pairs in ``/etc/systemd/system``, a oneshot service and its timer each:

- ``pridem-gc`` -- ``pridem --timer gc`` on ``policies.timers.gc``;
- ``pridem-ssl-renew`` -- ``pridem --timer ssl renew`` daily, started up to
  ``RENEW_DELAY`` later at random (``RandomizedDelaySec``), so boxes do not
  all ask Let's Encrypt at midnight: the passport has no field for it, and
  certbot renews only what is due.

Both commands take the box lock like any other: a timer that fires during a run
is refused (exit 1, no verdict) and tries again on its next day -- ``gc`` already
ran in that run's ``finally``, and a certificate is renewed 30 days before it
ends. ``Persistent=true`` runs a day missed while the box was off.

``check`` compares each file with its render and asks systemd whether each timer
is enabled and active. ``act`` writes what differs (``atomic_write``, 0644),
reloads systemd when a file changed, enables the timers and restarts them, so a
changed calendar is the one that runs. ``verify`` reads back the files, then
``is-enabled`` and ``is-active`` of each timer. Other timers of the host are
never touched.
"""

from pathlib import Path
from typing import ClassVar

from pridem.events import Json
from pridem.files import atomic_write
from pridem.stacks.passport import Passport
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
from pridem.steps.passport import NO_PASSPORT, Fetched

UNIT_DIR = Path("etc/systemd/system")
PRIDEM = "/usr/local/bin/pridem"
"""The link ``install.sh`` makes to the installed machine."""
RENEW_CALENDAR = "daily"
"""When the renewal timer runs: a constant of the machine, not a passport field."""
RENEW_DELAY = "1h"
"""The renewal timer's random delay; ``gc`` has none: its load is the box's own."""
DELAYS = {"pridem-ssl-renew.timer": RENEW_DELAY}
TIMER_MODES: frozenset[Mode] = frozenset({"install", "deploy", "reinstall"})


def _service(verb: str) -> str:
    return (
        "[Unit]\n"
        f"Description=pridem {verb}\n"
        "\n"
        "[Service]\n"
        "Type=oneshot\n"
        f"ExecStart={PRIDEM} --timer {verb}\n"
    )


def _timer(verb: str, calendar: str, delay: str | None) -> str:
    spread = f"RandomizedDelaySec={delay}\n" if delay is not None else ""
    return (
        "[Unit]\n"
        f"Description=pridem {verb}, {calendar}\n"
        "\n"
        "[Timer]\n"
        f"OnCalendar={calendar}\n"
        f"{spread}"
        "Persistent=true\n"
        "\n"
        "[Install]\n"
        "WantedBy=timers.target\n"
    )


def units(passport: Passport) -> dict[str, tuple[str, str]]:
    """``<timer unit> -> (verb, calendar)`` of the box."""
    return {
        "pridem-gc.timer": ("gc", passport.policies.timers.gc),
        "pridem-ssl-renew.timer": ("ssl renew", RENEW_CALENDAR),
    }


def unit_files(passport: Passport) -> dict[str, str]:
    """Every unit file name -> its text."""
    files: dict[str, str] = {}
    for timer, (verb, calendar) in units(passport).items():
        files[timer.removesuffix(".timer") + ".service"] = _service(verb)
        files[timer] = _timer(verb, calendar, DELAYS.get(timer))
    return files


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    atomic_write(path, text, 0o644)


def _state(ctx: StepContext, question: str, timer: str) -> str:
    """``systemctl is-enabled|is-active <timer>``: what systemd answers."""
    _, lines = out(
        ctx, ["systemctl", question, timer], expect=(0, 1, 3, 4), passed_on=False
    )
    return lines[0].strip() if lines else ""


class Timers(Step):
    """The ``gc`` and renewal timers, enabled and active."""

    name = "timers"
    order = 1
    modes = TIMER_MODES
    codes: ClassVar[dict[str, str]] = {
        **NO_PASSPORT,
        "install": "write {files} and start the timers {timers}",
        "unit-differs": "{path} is not what the machine writes",
        "not-enabled": "{timer} is {state}, not enabled",
        "not-active": "{timer} is {state}, not active",
    }

    def __init__(self, *, fetched: Fetched, root: Path = Path("/")) -> None:
        self.fetched = fetched
        self.root = root

    def _passport(self) -> Passport:
        if self.fetched.passport is None:
            raise StepFailed("no-passport")
        return self.fetched.passport

    def _path(self, name: str) -> Path:
        return self.root / UNIT_DIR / name

    def _differs(self) -> list[str]:
        return [
            name
            for name, text in sorted(unit_files(self._passport()).items())
            if not self._path(name).is_file()
            or self._path(name).read_text(encoding="utf-8") != text
        ]

    def check(self, ctx: StepContext) -> CheckResult:
        files = self._differs()
        stopped = [
            timer
            for timer in sorted(units(self._passport()))
            if _state(ctx, "is-enabled", timer) != "enabled"
            or _state(ctx, "is-active", timer) != "active"
        ]
        if not files and not stopped:
            return CheckResult(False)
        params: dict[str, Json] = {
            "files": list[Json](files),
            "timers": list[Json](sorted(units(self._passport()))),
        }
        return CheckResult(True, local_code("install", params))

    def act(self, ctx: StepContext, check: CheckResult) -> None:
        texts = unit_files(self._passport())
        changed = self._differs()
        for name in changed:
            _write(self._path(name), texts[name])
        if changed:
            out(ctx, ["systemctl", "daemon-reload"])
        timers = sorted(units(self._passport()))
        out(ctx, ["systemctl", "enable", *timers])
        out(ctx, ["systemctl", "restart", *timers])

    def verify(self, ctx: StepContext, check: CheckResult) -> Verified:
        for name in self._differs():
            raise StepFailed("unit-differs", {"path": str(self._path(name))})
        facts: list[Json] = []
        for timer, (verb, calendar) in sorted(units(self._passport()).items()):
            enabled = _state(ctx, "is-enabled", timer)
            if enabled != "enabled":
                raise StepFailed("not-enabled", {"timer": timer, "state": enabled})
            active = _state(ctx, "is-active", timer)
            if active != "active":
                raise StepFailed("not-active", {"timer": timer, "state": active})
            facts.append(
                {"timer": timer, "runs": f"pridem {verb}", "on_calendar": calendar}
            )
        return Verified({"timers": facts})


def timer_steps(root: Path, *, fetched: Fetched) -> list[Step]:
    """The ``timers`` ladder a plan builder puts right after the passport's."""
    return [Timers(fetched=fetched, root=root)]
