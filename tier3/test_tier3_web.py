"""Tier 3 probe (DM-17): the blank's routes answer by ``Host`` on localhost.

After ``test_tier3_up.py`` (pytest takes a directory's files by name) the
blank runs, its ``app`` and ``frontend`` on the network ``pridem`` under
``blank-app`` and ``blank-frontend``. One plan in the machine's venv:
``fetch_passport`` from a file (``ssl: self-signed``), then the stack ``edge``
-- ``tls_files``, ``nginx``, ``ssl``. Then ``curl`` from the runner:
``https://localhost/`` with the frontend's ``Host`` and ``/health`` with the
api's answer 200 with HSTS and ``X-Content-Type-Options``; ``http://`` is a 301
to ``https://``; a ``Host`` no route has gets no page.

Last, the probe prints ``RepoDigests`` and the version of ``CERTBOT_TAG``
without asserting on them: the digest the machine pins certbot by is taken
from this print (KNOWN CEILING on ``CERTBOT_IMAGE``).
"""

import warnings
from pathlib import Path

from test_tier3_render_env import API, PYTHON, _blank, _passport

from pridem.report.schema import Verdict
from pridem.runner import CommandTimedOut, Stream, SubprocessRunner
from pridem.steps.edge import CERTBOT_TAG

FRONTEND = "tier3-env.test"
PLAN = """
import sys
from datetime import UTC, datetime
from pathlib import Path
from secrets import token_hex
from pridem import __version__
from pridem.events import ConsoleSink, Secrets
from pridem.plan import Plan, StackSteps
from pridem.report.catalog import ENGLISH, with_steps
from pridem.report.schema import build_verdict
from pridem.runner import SubprocessRunner
from pridem.stacks.schema import load_primer_yaml
from pridem.state import Box
from pridem.steps.nginx import Nginx
from pridem.steps.passport import passport_steps
from pridem.steps.ssl import Ssl, TlsFiles

root, checkout, passport = Path("/"), Path(sys.argv[1]), Path(sys.argv[2])
blank = load_primer_yaml(checkout / "primer.yaml")
box, secrets = Box(Path("/opt/pridem")), Secrets(())
fetched, first = passport_steps(root, secrets=secrets, server=None, file=passport)
edge = [
    TlsFiles(blank, fetched=fetched, root=root),
    Nginx(blank, fetched=fetched, secrets=secrets, root=root),
    Ssl(blank, fetched=fetched, secrets=secrets, root=root),
]
with box.lock("tier3-web"):
    started = datetime.now(UTC).replace(microsecond=0)
    outcome = Plan(
        [StackSteps("passport", first), StackSteps("edge", edge, root=True)],
        mode="install", role="test", runner=SubprocessRunner(),
        sink=ConsoleSink(sys.stdout, secrets),
    ).run()
    every = [*first, *edge]
    verdict = build_verdict(
        outcome, run_id=f"{started:%Y-%m-%dT%H:%M:%SZ}-{token_hex(2)}",
        verb="install", args={}, actor={"type": "machine", "via": "local"},
        started=started, finished=datetime.now(UTC).replace(microsecond=0),
        passport_version=fetched.passport.version if fetched.passport else None,
        composition_before={"pridem": __version__},
        composition_after={"pridem": __version__}, secrets=secrets,
        catalog=with_steps(ENGLISH, [(step.name, step.codes) for step in every]),
    )
    box.write_verdict(verdict)
print("VERDICT " + verdict.model_dump_json())
sys.exit(int(verdict.exit_code))
"""


def _run(
    argv: list[str], timeout: float = 120, expect: tuple[int, ...] = (0,)
) -> list[str]:
    lines: list[str] = []

    def keep(stream: Stream, line: str, cut: bool) -> None:
        lines.append(line)

    try:
        SubprocessRunner().run(argv, expect=expect, timeout=timeout, on_line=keep)
    except CommandTimedOut:
        raise AssertionError("\n".join(lines)) from None
    return lines


def _curl(tmp: Path, url: str, host: str, *extra: str) -> tuple[str, str]:
    """``(status, headers)`` of one request; ``000`` -- no answer."""
    headers = tmp / "headers.txt"
    headers.unlink(missing_ok=True)
    lines = _run(
        [
            "curl",
            "-k",
            "-sS",
            "--max-time",
            "10",
            "-H",
            f"Host: {host}",
            "-D",
            str(headers),
            "-o",
            str(tmp / "body"),
            "-w",
            "%{http_code} %{redirect_url}",
            *extra,
            url,
        ],
        expect=(0, 52, 35, 56),
    )
    text = headers.read_text(encoding="latin-1") if headers.exists() else ""
    return (lines[-1] if lines else "000"), text.lower()


def test_tier3_blank_routes_answer_by_host(tmp_path: Path) -> None:
    checkout = _blank(tmp_path)
    passport = _passport(tmp_path)

    lines = _run(
        [PYTHON, "-c", PLAN, str(checkout), str(passport)],
        timeout=600,
        expect=(0, 1, 2),
    )

    printed = "\n".join(lines)
    [line] = [x for x in lines if x.startswith("VERDICT ")]
    verdict = Verdict.model_validate_json(line.removeprefix("VERDICT "))
    assert verdict.result == "green", printed

    front, front_headers = _curl(tmp_path, "https://localhost/", FRONTEND)
    assert front.startswith("200"), (front, printed)
    assert "strict-transport-security: max-age=31536000" in front_headers
    assert "x-content-type-options: nosniff" in front_headers
    api, _ = _curl(tmp_path, "https://localhost/health", API)
    assert api.startswith("200"), (api, printed)
    plain, _ = _curl(tmp_path, "http://localhost/", FRONTEND)
    assert plain == f"301 https://{FRONTEND}/", plain
    # the pair: a Host no route has gets no page
    stranger, _ = _curl(tmp_path, "https://localhost/", "nobody.example.org")
    assert not stranger.startswith("200"), stranger

    # the digest certbot is to be pinned by: printed, not asserted
    _run(["docker", "pull", "-q", CERTBOT_TAG], timeout=300)
    digests = _run(
        ["docker", "image", "inspect", "-f", "{{json .RepoDigests}}", CERTBOT_TAG]
    )
    version = _run(["docker", "run", "--rm", CERTBOT_TAG, "--version"], timeout=120)
    # a warning, so the run's summary shows it whatever pytest captures
    warnings.warn(
        f"CERTBOT {CERTBOT_TAG} digests={digests} version={version}", stacklevel=1
    )
