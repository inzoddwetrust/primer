"""``tls_files`` and ``ssl`` (DM-17): the four modes of ``policies.ssl``.
``openssl`` runs for real; docker and the network follow a strict script."""

import json
import re
from pathlib import Path

from edge_support import (
    DOMAINS,
    NOW,
    Mixed,
    exec_call,
    issued_pair,
    passport,
    product,
    run,
    self_signed_pair,
    stdout,
)

from pridem.events import Code, Secrets
from pridem.report.codes import ExitCode
from pridem.runner import FakeCall
from pridem.steps.base import Step
from pridem.steps.edge import (
    CERTBOT_IMAGE,
    argv,
    compose_text,
    letsencrypt_dir,
    mode_of,
)
from pridem.steps.passport import Fetched
from pridem.steps.ssl import Ssl, TlsFiles, cert_path, key_path

NAMES = list(DOMAINS.values())


def ladder(root: Path, fetched: Fetched, secrets: Secrets | None = None) -> list[Step]:
    made = product()
    return [
        TlsFiles(made, fetched=fetched, root=root, now=NOW),
        Ssl(made, fetched=fetched, secrets=secrets or Secrets(()), root=root, now=NOW),
    ]


# --- probes ---------------------------------------------------------------------


def test_probe_DM_17_defer_gives_exit_2_with_incomplete_ssl(tmp_path: Path) -> None:
    root, fetched = passport(tmp_path, ssl="defer")
    with Mixed() as runner:  # openssl only: no certbot, no docker
        outcome, _ = run(ladder(root, fetched), runner)
    assert outcome.code is ExitCode.INCOMPLETE
    [entry] = outcome.incomplete
    assert (entry.what, entry.reason) == ("ssl", Code("ssl:deferred"))
    assert outcome.steps[1].verify["self_signed"] is True
    assert mode_of(key_path(root)) == oct(0o600)
    # the pair: self-signed is the same certificate and exit 0
    root, fetched = passport(tmp_path / "s", ssl="self-signed")
    with Mixed() as runner:
        outcome, _ = run(ladder(root, fetched), runner)
    assert outcome.code is ExitCode.OK and outcome.incomplete == ()


def test_probe_DM_17_provided_cert_installed_without_certbot_call(
    tmp_path: Path,
) -> None:
    cert, key = self_signed_pair(tmp_path, ["*.preview.example.org", *NAMES])
    root, fetched = passport(tmp_path, role="preview", ssl="provided", tls=(cert, key))
    runner = Mixed()
    with runner:  # no docker at all: certbot is never called
        outcome, sink = run(ladder(root, fetched), runner)
    assert outcome.code is ExitCode.OK, outcome.steps
    assert cert_path(root).read_text() == cert and key_path(root).read_text() == key
    assert mode_of(key_path(root)) == oct(0o600)
    assert not [a for a in runner.argvs if a[0] != "openssl"]
    body = "".join(line for line in key.splitlines() if "-----" not in line)
    pieces = {body[i : i + 16] for i in range(len(body) - 15)}
    words = [word for a in runner.argvs for word in a]
    printed = "\n".join(e.line for e in sink.lines())
    assert not [w for w in words if any(piece in w for piece in pieces)]
    assert not [piece for piece in pieces if piece in printed]
    # the pair: letsencrypt does call certbot (pinned, DNS green)
    root, fetched = passport(tmp_path / "le", ssl="letsencrypt")
    issued_cert, issued_key = issued_pair(tmp_path, NAMES)
    live = letsencrypt_dir(root) / "live" / "pridem"
    live.mkdir(parents=True)
    (live / "fullchain.pem").write_text(issued_cert)
    (live / "privkey.pem").write_text(issued_key)
    calls = [*_dns_green(), *_issue(root)]
    runner = Mixed(*calls)
    with runner:
        outcome, _ = run(ladder(root, fetched), runner)
    assert outcome.code is ExitCode.OK, outcome.steps
    assert any("certonly" in a for a in runner.argvs)
    assert outcome.steps[1].verify["self_signed"] is False


# --- letsencrypt ----------------------------------------------------------------


def _dns_green(ip: str = "203.0.113.7") -> list[FakeCall]:
    calls = [
        FakeCall(("curl", "-fsS", "--max-time", "10", url), lines=stdout(ip))
        for url in ("https://api.ipify.org", "https://checkip.amazonaws.com")
    ]
    for name in NAMES:
        calls.append(
            FakeCall(("getent", "ahostsv4", name), lines=stdout(f"{ip} STREAM {name}"))
        )
    return calls


def _issue(root: Path) -> list[FakeCall]:
    words = [w for name in NAMES for w in ("-d", name)]
    return [
        FakeCall(
            tuple(
                argv(
                    root,
                    "run",
                    "--rm",
                    "certbot",
                    "certonly",
                    "--webroot",
                    "-w",
                    "/var/www/acme",
                    "--cert-name",
                    "pridem",
                    "--non-interactive",
                    "--agree-tos",
                    "--register-unsafely-without-email",
                    "--keep-until-expiring",
                    "--expand",
                    *words,
                )
            )
        ),
        exec_call(root, "nginx", "-t"),
        exec_call(root, "nginx", "-s", "reload"),
    ]


def test_letsencrypt_with_dns_elsewhere_is_red_before_certbot(tmp_path: Path) -> None:
    root, fetched = passport(tmp_path, ssl="letsencrypt")
    calls = _dns_green()
    calls[-1] = FakeCall(
        ("getent", "ahostsv4", NAMES[-1]), lines=stdout("198.51.100.1 x")
    )
    with Mixed(*calls) as runner:  # certbot is not in the script
        outcome, _ = run(ladder(root, fetched), runner)
    assert outcome.steps[1].reason == Code(
        "ssl:dns-not-ready", {"domains": [NAMES[-1]]}
    )


# --- files ----------------------------------------------------------------------


def test_a_key_that_is_not_0600_is_refused_not_remoded(tmp_path: Path) -> None:
    root, fetched = passport(tmp_path)
    with Mixed() as runner:
        run(ladder(root, fetched), runner)
    key_path(root).chmod(0o644)
    with Mixed() as runner:
        outcome, _ = run(ladder(root, fetched), runner)
    assert outcome.steps[0].reason is not None
    assert outcome.steps[0].reason.code == "tls_files:key-mode"
    assert mode_of(key_path(root)) == oct(0o644)


def test_a_fresh_self_signed_pair_is_kept_an_expiring_one_is_made_again(
    tmp_path: Path,
) -> None:
    root, fetched = passport(tmp_path)
    with Mixed() as runner:
        run(ladder(root, fetched), runner)
    first = cert_path(root).read_text()
    runner = Mixed()
    with runner:
        run(ladder(root, fetched), runner)
    assert cert_path(root).read_text() == first
    assert not [a for a in runner.argvs if "req" in a]
    cert, key = self_signed_pair(tmp_path, NAMES, days=10)
    cert_path(root).write_text(cert)
    key_path(root).write_text(key)
    with Mixed() as runner:
        outcome, _ = run(ladder(root, fetched), runner)
    assert outcome.code is ExitCode.OK
    assert cert_path(root).read_text() not in (first, cert)


def test_status_reports_expiry_and_key_mode(tmp_path: Path) -> None:
    root, fetched = passport(tmp_path)
    with Mixed() as runner:
        outcome, _ = run(ladder(root, fetched), runner)
    fact = outcome.steps[1].verify
    assert fact["mode"] == "self-signed"
    assert str(fact["cert_expires"]).endswith("Z")
    assert fact["domains"] == sorted(NAMES)


# --- DM-49: certbot pinned by digest -------------------------------------------

READ_BY_TIER_3 = "bc93cb710b413e6b456d622f9b0133b3e109c0a78c2ed9976af43d209b0a1805"
"""The digest tier 3 printed on ``main@c5931be`` (DM-50): the only source."""


def test_probe_DM_49_certbot_image_is_pinned_by_digest(tmp_path: Path) -> None:
    assert re.fullmatch(
        r"certbot/certbot:v\d+\.\d+\.\d+@sha256:[0-9a-f]{64}", CERTBOT_IMAGE
    )
    assert CERTBOT_IMAGE.endswith(f"@sha256:{READ_BY_TIER_3}")
    # the edge's compose runs certbot from that image, nothing else
    document = json.loads(compose_text(tmp_path))
    assert document["services"]["certbot"]["image"] == CERTBOT_IMAGE
    # the pair: letsencrypt with DNS on the box calls certbot -- no stand-in image
    root, fetched = passport(tmp_path / "le", ssl="letsencrypt")
    issued_cert, issued_key = issued_pair(tmp_path, NAMES)
    live = letsencrypt_dir(root) / "live" / "pridem"
    live.mkdir(parents=True)
    (live / "fullchain.pem").write_text(issued_cert)
    (live / "privkey.pem").write_text(issued_key)
    runner = Mixed(*_dns_green(), *_issue(root))
    with runner:
        outcome, _ = run(ladder(root, fetched), runner)
    assert outcome.code is ExitCode.OK, outcome.steps
    assert any("certonly" in argv for argv in runner.argvs)
