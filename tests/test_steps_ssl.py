"""``tls_files`` and ``ssl`` (DM-17), ``ssl_renew`` (DM-20): the four modes of
``policies.ssl``. ``openssl`` runs for real; docker and the network follow a
strict script."""

import json
import os
import re
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
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

from pridem.events import Code, Secrets, strings
from pridem.interrupt import Interrupt
from pridem.report.codes import ExitCode
from pridem.runner import FakeCall, SubprocessRunner
from pridem.steps.base import CheckResult, Step, StepContext, StepFailed
from pridem.steps.edge import (
    CERTBOT_IMAGE,
    argv,
    compose_text,
    letsencrypt_dir,
    mode_of,
    write_file,
)
from pridem.steps.passport import Fetched
from pridem.steps.ssl import Ssl, SslRenew, TlsFiles, cert_path, key_path

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


def test_the_certificate_is_0644_and_its_key_0600(tmp_path: Path) -> None:
    """DM-54: ``write_file`` of edge writes the mode each file is given -- the
    certificate world-readable, its key private -- not one mode for both."""
    cert, key = self_signed_pair(tmp_path, [*NAMES])
    root, fetched = passport(tmp_path, ssl="provided", tls=(cert, key))
    with Mixed() as runner:
        outcome, _ = run(ladder(root, fetched), runner)
    assert outcome.code is ExitCode.OK, outcome.steps
    assert (mode_of(cert_path(root)), mode_of(key_path(root))) == (
        oct(0o644),
        oct(0o600),
    )


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


# --- DM-20: ssl renew, the plan of the verb and of its timer -------------------


def _placed(root: Path, cert: str, key: str) -> None:
    cert_path(root).parent.mkdir(parents=True, exist_ok=True)
    cert_path(root).write_text(cert)
    key_path(root).write_text(key)
    key_path(root).chmod(0o600)


def test_ssl_renew_in_letsencrypt_runs_certbot_copies_and_reloads(
    tmp_path: Path,
) -> None:
    root, fetched = passport(tmp_path, ssl="letsencrypt")
    issued_cert, issued_key = issued_pair(tmp_path, NAMES)
    _placed(root, *self_signed_pair(tmp_path, NAMES))
    live = letsencrypt_dir(root) / "live" / "pridem"
    live.mkdir(parents=True)
    (live / "fullchain.pem").write_text(issued_cert)
    (live / "privkey.pem").write_text(issued_key)
    renew = argv(root, "run", "--rm", "certbot", "renew", "--webroot", "-w",
                  "/var/www/acme")  # fmt: skip
    secrets = Secrets(())
    with Mixed(
        FakeCall(tuple(renew)),
        exec_call(root, "nginx", "-t"),
        exec_call(root, "nginx", "-s", "reload"),
    ) as runner:
        outcome, _ = run(
            [SslRenew(fetched=fetched, secrets=secrets, root=root)],
            runner,
            mode="renew",
        )
    assert outcome.code is ExitCode.OK, outcome.steps
    assert cert_path(root).read_text() == issued_cert
    verify = outcome.steps[0].verify
    assert (verify["mode"], verify["self_signed"], verify["key_mode"]) == (
        "letsencrypt",
        False,
        oct(0o600),
    )


def test_ssl_renew_outside_letsencrypt_never_calls_certbot(tmp_path: Path) -> None:
    for mode in ("self-signed", "defer"):
        root, fetched = passport(tmp_path / mode, ssl=mode)
        cert, key = self_signed_pair(tmp_path, NAMES)
        _placed(root, cert, key)
        with Mixed() as runner:  # openssl only: no docker, no certbot
            outcome, _ = run(
                [SslRenew(fetched=fetched, secrets=Secrets(()), root=root)],
                runner,
                mode="renew",
            )
        assert outcome.code is ExitCode.OK, outcome.steps
        assert not [a for a in runner.argvs if a[0] != "openssl"]
        verify = outcome.steps[0].verify
        assert (verify["mode"], verify["self_signed"]) == (mode, True)
        assert cert_path(root).read_text() == cert  # nothing replaced


def test_ssl_renew_without_a_passport_refuses(tmp_path: Path) -> None:
    with Mixed() as runner:
        outcome, _ = run(
            [SslRenew(fetched=Fetched(), secrets=Secrets(()), root=tmp_path)],
            runner,
            mode="renew",
        )
    assert outcome.steps[0].reason == Code("ssl_renew:no-passport")


# --- DM-53: a fresh certificate asks nothing outside the box -------------------


def test_a_fresh_certificate_asks_no_echo_service_and_no_dns(tmp_path: Path) -> None:
    root, fetched = passport(tmp_path, ssl="letsencrypt")
    _placed(root, *issued_pair(tmp_path, NAMES))
    step = Ssl(product(), fetched=fetched, secrets=Secrets(()), root=root, now=NOW)
    with Mixed() as runner:  # openssl only: no curl, no getent, no docker
        outcome, _ = run([step], runner, mode="deploy")
    assert outcome.code is ExitCode.OK, outcome.steps
    assert {argv[0] for argv in runner.argvs} == {"openssl"}
    # the pair: a self-signed one under letsencrypt asks the echo services first
    root, fetched = passport(tmp_path / "self", ssl="letsencrypt")
    _placed(root, *self_signed_pair(tmp_path, NAMES))
    step = Ssl(product(), fetched=fetched, secrets=Secrets(()), root=root, now=NOW)
    runner = Mixed()  # nothing scripted: the first outside call is refused
    outcome, _ = run([step], runner, mode="deploy")
    assert outcome.code is ExitCode.FAILED
    outside = [argv for argv in runner.argvs if argv[0] != "openssl"]
    assert outside and outside[0][0] == "curl"


# --- DM-80: the end of the certificate, a torn pair, renew without an issue ----


def _renew(root: Path, fetched: Fetched, now: datetime | None = None) -> SslRenew:
    return SslRenew(fetched=fetched, secrets=Secrets(()), root=root, now=now)


def _ends(root: Path) -> datetime:
    found: list[str] = []
    SubprocessRunner().run(
        ["openssl", "x509", "-in", str(cert_path(root)), "-noout", "-enddate"],
        timeout=30,
        on_line=lambda stream, line, cut: found.append(line),
    )
    text = found[0].partition("=")[2]
    return datetime.strptime(" ".join(text.split()), "%b %d %H:%M:%S %Y %Z").replace(
        tzinfo=UTC
    )


def test_probe_DM_80_expired_certificate_is_red_on_renew(tmp_path: Path) -> None:
    """``ssl renew`` judges the end of what nginx serves, in a mode where it
    cannot renew it (``provided``): past its end -- red by ``expired``; the
    pair: the same certificate before its end is green."""
    cert, key = self_signed_pair(tmp_path, NAMES)
    root, fetched = passport(tmp_path, ssl="provided", tls=(cert, key))
    _placed(root, cert, key)
    ends = _ends(root)
    with Mixed() as runner:  # openssl only: provided renews nothing
        outcome, _ = run(
            [_renew(root, fetched, ends + timedelta(seconds=1))], runner, mode="renew"
        )
    assert outcome.steps[0].reason == Code(
        "ssl_renew:expired", {"cert_expires": ends.strftime("%Y-%m-%dT%H:%M:%SZ")}
    )
    with Mixed() as runner:
        outcome, _ = run([_renew(root, fetched, NOW)], runner, mode="renew")
    assert outcome.code is ExitCode.OK, outcome.steps
    assert outcome.steps[0].verify["renew_due"] is False


def test_a_week_left_is_red_and_a_month_is_a_fact(tmp_path: Path) -> None:
    """Under 7 days -- ``expiring``; under 30 -- ``renew_due``; the bounds."""
    cert, key = self_signed_pair(tmp_path, NAMES)
    root, fetched = passport(tmp_path, ssl="provided", tls=(cert, key))
    _placed(root, cert, key)
    ends = _ends(root)
    cases = {
        timedelta(days=7) - timedelta(seconds=1): "expiring",
        timedelta(days=7): True,
        timedelta(days=30) - timedelta(seconds=1): True,
        timedelta(days=30): False,
        timedelta(seconds=1): "expiring",
        timedelta(0): "expired",
    }
    for left, judged in cases.items():
        with Mixed() as runner:
            outcome, _ = run([_renew(root, fetched, ends - left)], runner, mode="renew")
        step = outcome.steps[0]
        if isinstance(judged, str):
            assert step.reason is not None and step.reason.code == (
                f"ssl_renew:{judged}"
            ), (left, step)
        else:
            assert step.verify["renew_due"] is judged, (left, step)


def test_renew_signs_a_self_signed_pair_again_when_it_is_due(tmp_path: Path) -> None:
    """A box without deploys keeps its self-signed certificate fresh: due for
    renewal -- signed again over the names it has, nginx reloaded."""
    for mode in ("self-signed", "defer"):
        root, fetched = passport(tmp_path / mode, ssl=mode)
        cert, key = self_signed_pair(tmp_path, NAMES, days=20)
        _placed(root, cert, key)
        with Mixed(
            exec_call(root, "nginx", "-t"), exec_call(root, "nginx", "-s", "reload")
        ) as runner:
            outcome, _ = run([_renew(root, fetched)], runner, mode="renew")
        assert outcome.code is ExitCode.OK, outcome.steps
        assert cert_path(root).read_text() != cert
        verify = outcome.steps[0].verify
        assert sorted(strings(verify["domains"])) == sorted(NAMES)
        assert verify["renew_due"] is False


def test_renew_before_the_issue_calls_no_certbot_and_is_incomplete(
    tmp_path: Path,
) -> None:
    """``letsencrypt`` before certbot issued (``dns-not-ready``): nothing to
    renew -- no certbot, no ``FileNotFoundError``; the placeholder is read
    back and the result says the certificate is not issued yet."""
    root, fetched = passport(tmp_path, ssl="letsencrypt")
    _placed(root, *self_signed_pair(tmp_path, NAMES))
    with Mixed() as runner:  # openssl only
        outcome, _ = run([_renew(root, fetched)], runner, mode="renew")
    assert outcome.code is ExitCode.INCOMPLETE, outcome.steps
    [entry] = outcome.incomplete
    assert (entry.what, entry.reason) == ("ssl_renew", Code("ssl_renew:not-issued"))
    assert not [a for a in runner.argvs if a[0] != "openssl"]


def test_renew_with_nothing_new_copies_nothing_and_reloads_nothing(
    tmp_path: Path,
) -> None:
    root, fetched = passport(tmp_path, ssl="letsencrypt")
    issued_cert, issued_key = issued_pair(tmp_path, NAMES)
    _placed(root, issued_cert, issued_key)
    live = letsencrypt_dir(root) / "live" / "pridem"
    live.mkdir(parents=True)
    (live / "fullchain.pem").write_text(issued_cert)
    (live / "privkey.pem").write_text(issued_key)
    before = cert_path(root).stat().st_mtime_ns
    renew = argv(root, "run", "--rm", "certbot", "renew", "--webroot", "-w",
                  "/var/www/acme")  # fmt: skip
    with Mixed(FakeCall(tuple(renew))) as runner:  # no nginx -t, no reload
        outcome, _ = run([_renew(root, fetched)], runner, mode="renew")
    assert outcome.code is ExitCode.OK, outcome.steps
    assert cert_path(root).stat().st_mtime_ns == before


def test_a_torn_pair_is_placed_again_and_never_green(tmp_path: Path) -> None:
    """A crash between the two renames leaves a certificate of another key:
    ``check`` places the pair again; ``verify`` refuses a pair still torn."""
    root, fetched = passport(tmp_path, ssl="self-signed")
    for name in ("a", "b"):
        (tmp_path / name).mkdir()
    cert, _ = self_signed_pair(tmp_path / "a", NAMES)
    _, other_key = self_signed_pair(tmp_path / "b", NAMES)
    _placed(root, cert, other_key)
    with Mixed() as runner:
        outcome, _ = run(ladder(root, fetched), runner)
    assert outcome.code is ExitCode.OK, outcome.steps
    assert cert_path(root).read_text() != cert  # signed again, a whole pair
    # verify of every step that places the pair refuses a torn one
    _placed(root, cert, other_key)
    made = product()
    for step in (
        TlsFiles(made, fetched=fetched, root=root, now=NOW),
        Ssl(made, fetched=fetched, secrets=Secrets(()), root=root, now=NOW),
        _renew(root, fetched, NOW),
    ):
        with Mixed() as runner:
            ctx = StepContext(
                runner, "install", "test", "x", lambda *_: None, Interrupt()
            )
            try:
                step.verify(ctx, CheckResult(False))
            except StepFailed as failed:
                assert failed.args == ("pair-mismatch",), step.name
            else:
                raise AssertionError(f"{step.name}: a torn pair passed verify")


def test_the_key_is_renamed_before_the_certificate(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The order of the pair's two renames: the key, then the certificate."""
    renamed: list[str] = []
    real = os.replace

    def spy(src: object, dst: object) -> None:
        renamed.append(Path(str(dst)).name)
        real(src, dst)  # type: ignore[arg-type]

    monkeypatch.setattr(os, "replace", spy)
    cert, key = self_signed_pair(tmp_path, NAMES)
    root, fetched = passport(tmp_path, ssl="provided", tls=(cert, key))
    with Mixed() as runner:
        outcome, _ = run(ladder(root, fetched), runner)
    assert outcome.code is ExitCode.OK, outcome.steps
    assert [n for n in renamed if n.endswith(".pem")] == [
        "privkey.pem",
        "fullchain.pem",
    ]


def test_renew_signs_a_torn_pair_again_even_when_fresh(tmp_path: Path) -> None:
    """The renewal timer repairs what a crash between the two renames left: a
    fresh certificate of another key is signed again as a whole pair."""
    root, fetched = passport(tmp_path, ssl="self-signed")
    for name in ("a", "b"):
        (tmp_path / name).mkdir()
    cert, _ = self_signed_pair(tmp_path / "a", NAMES)
    _, other_key = self_signed_pair(tmp_path / "b", NAMES)
    _placed(root, cert, other_key)
    with Mixed(
        exec_call(root, "nginx", "-t"), exec_call(root, "nginx", "-s", "reload")
    ) as runner:
        outcome, _ = run([_renew(root, fetched)], runner, mode="renew")
    assert outcome.code is ExitCode.OK, outcome.steps
    assert cert_path(root).read_text() != cert


def test_a_certs_directory_found_wider_is_made_0700(tmp_path: Path) -> None:
    """DM-80: ``mkdir`` with ``exist_ok`` left an existing directory's mode;
    the pair's directory is 0700 whatever it was found as -- for a signed pair
    and for a pair written from the passport alike."""
    root, fetched = passport(tmp_path / "s", ssl="self-signed")
    cert_path(root).parent.mkdir(parents=True)
    cert_path(root).parent.chmod(0o755)
    with Mixed() as runner:
        outcome, _ = run(ladder(root, fetched), runner)
    assert outcome.code is ExitCode.OK, outcome.steps
    assert mode_of(cert_path(root).parent) == oct(0o700)
    cert, key = self_signed_pair(tmp_path, NAMES)
    root, fetched = passport(tmp_path / "p", ssl="provided", tls=(cert, key))
    cert_path(root).parent.mkdir(parents=True)
    cert_path(root).parent.chmod(0o755)
    with Mixed() as runner:
        outcome, _ = run(ladder(root, fetched), runner)
    assert outcome.code is ExitCode.OK, outcome.steps
    assert mode_of(cert_path(root).parent) == oct(0o700)


def test_every_file_of_the_edge_goes_into_a_0700_directory(tmp_path: Path) -> None:
    """DM-80: ``write_file`` of the edge (nginx configuration, compose, proxy)
    makes its directory 0700 even when it was found wider."""
    directory = tmp_path / "opt" / "pridem" / "edge" / "nginx"
    directory.mkdir(parents=True)
    directory.chmod(0o755)
    write_file(directory / "live.conf", b"server {}\n", 0o600)
    assert mode_of(directory) == oct(0o700)


def test_install_judges_the_end_in_tls_files_and_in_ssl(tmp_path: Path) -> None:
    """DM-80: one ``expiry`` for the three steps: the steps of ``install``
    refuse a certificate with under a week left, as ``ssl renew`` does."""
    cert, key = self_signed_pair(tmp_path, NAMES)
    root, fetched = passport(tmp_path, ssl="provided", tls=(cert, key))
    _placed(root, cert, key)
    ends = _ends(root)
    made = product()
    soon = ends - timedelta(days=1)
    for step in (
        TlsFiles(made, fetched=fetched, root=root, now=soon),
        Ssl(made, fetched=fetched, secrets=Secrets(()), root=root, now=soon),
    ):
        with Mixed() as runner:
            ctx = StepContext(
                runner, "install", "test", "x", lambda *_: None, Interrupt()
            )
            with pytest.raises(StepFailed) as failed:
                step.verify(ctx, CheckResult(False))
        assert failed.value.reason.code == "expiring", step.name
