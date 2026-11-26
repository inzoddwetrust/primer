"""DM-185 (REVIEW-0006 K4: B6, B7, B8, B29, B30), tier 1: what nginx serves is
read back and is the file; a reload that failed is done again by the next
run; ``ssl renew`` signs again only the machine's own self-signed pair;
``letsencrypt`` in its last week does not stop a deploy; a bad pair of the
passport is refused before anything is written; a long domain signs; a box
with no pair renews nothing. ``openssl`` runs for real, docker follows a
strict script, nginx is ``Edge`` (TLS on localhost, the pair it loaded last).

The probe of ``letsencrypt`` is here, on tier 1, not on tier 3: on the runner
the box's domains do not resolve to it, and ``ssl`` stops at
``dns-not-ready`` before certbot -- the path cannot be walked there.
"""

from datetime import timedelta
from pathlib import Path

import pytest
from edge_support import (
    CA_NAME,
    DOMAINS,
    Edge,
    Mixed,
    exec_call,
    issued_pair,
    passport,
    product,
    run,
    self_signed_pair,
)
from test_steps_ssl import NAMES, _dns_green, _ends, _issue, _placed, ladder

from pridem.events import Code, Secrets, strings
from pridem.interrupt import Interrupt
from pridem.report.codes import ExitCode
from pridem.runner import FakeCall
from pridem.steps import ssl as ssl_steps
from pridem.steps.base import CheckResult, StepContext, StepFailed
from pridem.steps.edge import argv, letsencrypt_dir
from pridem.steps.ssl import (
    SslRenew,
    TlsFiles,
    cert_path,
    file_fingerprint,
    key_path,
    served_once,
    signs_itself,
)

RELOAD = ("nginx", "-s", "reload")
STAMP = "%Y-%m-%dT%H:%M:%SZ"


def _reload(root: Path, *, red: bool = False) -> list[FakeCall]:
    if red:
        return [exec_call(root, "nginx", "-t", code=1)]
    return [exec_call(root, "nginx", "-t"), exec_call(root, *RELOAD)]


def _renew(root: Path, fetched: object, edge: Edge) -> SslRenew:
    return SslRenew(
        fetched=fetched,  # type: ignore[arg-type]
        secrets=Secrets(()),
        root=root,
        port=edge.port,
    )


def _live(root: Path, cert: str, key: str) -> None:
    live = letsencrypt_dir(root) / "live" / "pridem"
    live.mkdir(parents=True)
    (live / "fullchain.pem").write_text(cert)
    (live / "privkey.pem").write_text(key)


def _ctx(runner: Mixed) -> StepContext:
    return StepContext(runner, "install", "test", "x", lambda *_: None, Interrupt())


def _pair(tmp: Path, name: str, **days: int) -> tuple[str, str]:
    (tmp / name).mkdir()
    return self_signed_pair(tmp / name, NAMES, **days)


# --- probes ---------------------------------------------------------------------


def test_probe_DM_185_letsencrypt_in_its_last_week_does_not_block_a_deploy(
    tmp_path: Path,
) -> None:
    """B8: a certificate Let's Encrypt issued, five days left: ``tls_files``
    does not refuse it -- it says ``days_left`` and ``renew_due`` -- so
    ``ssl`` comes and renews it: certbot, the new pair copied, nginx reloaded
    and serving it; the deploy is green. The pair: a ``provided`` one in its
    last week is left undone (``tls_files:expiring``, exit 2), not red; past
    its end -- red."""
    root, fetched = passport(tmp_path, ssl="letsencrypt")
    (tmp_path / "old").mkdir()
    (tmp_path / "new").mkdir()
    _placed(root, *issued_pair(tmp_path / "old", NAMES, days=5))
    _live(root, *issued_pair(tmp_path / "new", NAMES))
    with Edge(root) as edge:
        edge.up()
        calls = [*_dns_green(), *_issue(root)]
        with Mixed(*calls, edge=edge) as runner:
            outcome, _ = run(ladder(root, fetched, edge=edge, clock=None), runner)
        assert outcome.code is ExitCode.OK, outcome.steps
        files, _, issued = outcome.steps
        assert files.verify["days_left"] in (4, 5) and files.verify["renew_due"] is True
        assert files.verify["self_signed"] is False
        assert issued.verify["renew_due"] is False
        assert (
            issued.verify["served"] == file_fingerprint(root) != files.verify["served"]
        )
    # the pair: provided -- its last week is undone, past its end is red
    cert, key = _pair(tmp_path, "provided", days=3)
    root, fetched = passport(tmp_path / "p", ssl="provided", tls=(cert, key))
    _placed(root, cert, key)
    ends = _ends(root)
    with Edge(root) as edge, Mixed() as runner:
        edge.up()
        files_step = TlsFiles(product(), fetched=fetched, root=root, port=edge.port)
        undone = files_step.verify(_ctx(runner), CheckResult(False)).incomplete
        assert undone is not None and undone.code == "expiring"
        late = TlsFiles(
            product(),
            fetched=fetched,
            root=root,
            port=edge.port,
            now=ends + timedelta(seconds=1),
        )
        with pytest.raises(StepFailed) as failed:
            late.verify(_ctx(runner), CheckResult(False))
    assert failed.value.reason == Code(
        "expired", {"cert_expires": ends.strftime(STAMP)}
    )


def test_probe_DM_185_a_bad_provided_pair_leaves_the_working_one(
    tmp_path: Path,
) -> None:
    """B29: the passport's certificate is not of its key -- ``tls_files`` and
    ``ssl renew`` refuse it in ``check``: no command at all, the pair on disk
    and what nginx serves as they were. The pair: a whole pair of the
    passport is placed, nginx reloaded, and serves it."""
    working = _pair(tmp_path, "a")
    other = _pair(tmp_path, "b")
    bad = (other[0], working[1])
    root, fetched = passport(tmp_path, ssl="provided", tls=bad)
    _placed(root, *working)
    with Edge(root) as edge:
        edge.up()
        served = served_once(NAMES[0], edge.port)
        for steps, mode, code in (
            (
                ladder(root, fetched, edge=edge),
                "doctor",  # refused in check: doctor says it too
                "tls_files:provided-pair-mismatch",
            ),
            (
                ladder(root, fetched, edge=edge),
                "install",
                "tls_files:provided-pair-mismatch",
            ),
            (
                [_renew(root, fetched, edge)],
                "renew",
                "ssl_renew:provided-pair-mismatch",
            ),
        ):
            runner = Mixed()
            with runner:
                outcome, _ = run(steps, runner, mode=mode)
            assert outcome.steps[0].reason == Code(code), outcome.steps
            assert runner.argvs == []  # refused before any command
            assert (cert_path(root).read_text(), key_path(root).read_text()) == working
            assert served_once(NAMES[0], edge.port) == served
    # the pair: the passport's whole pair is placed and served
    root, fetched = passport(tmp_path / "good", ssl="provided", tls=other)
    _placed(root, *working)
    with Edge(root) as edge:
        edge.up()
        with Mixed(*_reload(root), edge=edge) as runner:
            outcome, _ = run(ladder(root, fetched, edge=edge), runner)
        assert outcome.code is ExitCode.OK, outcome.steps
        assert cert_path(root).read_text() == other[0]
        assert served_once(NAMES[0], edge.port) == file_fingerprint(root)


# --- B6: what nginx serves is the file -------------------------------------------


def test_a_pair_placed_without_a_reload_is_reloaded(tmp_path: Path) -> None:
    """Files of another pair under a running nginx (placed, never reloaded):
    ``check`` sees nginx serve another certificate (``serve``), ``act``
    reloads it, ``verify`` reads the file served. A second run has nothing to
    do."""
    root, fetched = passport(tmp_path)
    _placed(root, *_pair(tmp_path, "a"))
    with Edge(root) as edge:
        edge.up()
        before = served_once(NAMES[0], edge.port)
        _placed(root, *_pair(tmp_path, "b"))
        with Mixed(*_reload(root), edge=edge) as runner:
            outcome, _ = run(ladder(root, fetched, edge=edge), runner)
        assert outcome.code is ExitCode.OK, outcome.steps
        files = outcome.steps[0]
        assert files.verify["served"] == file_fingerprint(root) != before
        assert edge.reloads == 1
        with Mixed() as runner:  # nothing scripted: nothing to reload
            again, _ = run(ladder(root, fetched, edge=edge), runner)
        assert again.code is ExitCode.OK, again.steps


def test_a_provided_pair_placed_without_a_reload_is_reloaded(tmp_path: Path) -> None:
    """``provided``: the passport's pair is on disk, as the passport says,
    and nginx still serves the one before (``tls_files`` of an older machine
    placed it and never reloaded -- B6): ``check`` -- ``serve``; the reload;
    the passport's served."""
    old, new = _pair(tmp_path, "a"), _pair(tmp_path, "b")
    root, fetched = passport(tmp_path, ssl="provided", tls=new)
    _placed(root, *old)
    with Edge(root) as edge:
        edge.up()
        _placed(root, *new)
        with Mixed(*_reload(root), edge=edge) as runner:
            outcome, _ = run(ladder(root, fetched, edge=edge), runner)
        assert outcome.code is ExitCode.OK, outcome.steps
        assert edge.reloads == 1
        assert outcome.steps[0].verify["served"] == file_fingerprint(root)


def test_a_reload_that_failed_is_done_again_by_the_next_run(tmp_path: Path) -> None:
    """Rr2 of the gate: one reload in ``act``; red (``nginx -t``) -- the step
    is red and nginx serves the old pair; the next run's ``check`` sees it
    and reloads. ``ssl renew`` alike."""
    root, fetched = passport(tmp_path)
    _placed(root, *_pair(tmp_path, "a"))
    with Edge(root) as edge:
        edge.up()
        old = served_once(NAMES[0], edge.port)
        _placed(root, *_pair(tmp_path, "b"))
        with Mixed(*_reload(root, red=True), edge=edge) as runner:
            red, _ = run(ladder(root, fetched, edge=edge), runner)
        assert red.steps[0].reason == Code(
            "tls_files:config-invalid", {"where": "running nginx"}
        )
        assert served_once(NAMES[0], edge.port) == old
        with Mixed(*_reload(root), edge=edge) as runner:
            outcome, _ = run([_renew(root, fetched, edge)], runner, mode="renew")
        assert outcome.code is ExitCode.OK, outcome.steps
        assert outcome.steps[0].verify["served"] == file_fingerprint(root) != old


def test_served_waits_out_the_old_workers(tmp_path: Path) -> None:
    """After a reload the old workers still answer a few handshakes with the
    old pair (measured on nginx): ``verify`` waits for ``SERVED_STEADY`` in a
    row of the file's -- green, not a flapping red."""
    root, fetched = passport(tmp_path)
    _placed(root, *_pair(tmp_path, "a"))
    with Edge(root, lag=3) as edge:
        edge.up()
        _placed(root, *_pair(tmp_path, "b"))
        with Mixed(*_reload(root), edge=edge) as runner:
            outcome, _ = run(ladder(root, fetched, edge=edge), runner)
        assert outcome.code is ExitCode.OK, outcome.steps
        assert outcome.steps[0].verify["served"] == file_fingerprint(root)


def test_nginx_serving_another_pair_is_not_served(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``verify`` of a step whose nginx keeps another certificate, and of
    ``ssl`` with nginx not answering at all: ``not-served`` with both
    fingerprints, never green. ``tls_files`` with nginx not up yet -- the
    fact ``served: none``, the step that starts nginx reads the pair."""
    monkeypatch.setattr(ssl_steps, "SERVED_WAIT_S", 0.5)
    root, fetched = passport(tmp_path)
    _placed(root, *_pair(tmp_path, "a"))
    made = product()
    with Edge(root) as edge, Mixed() as runner:
        files = TlsFiles(made, fetched=fetched, root=root, now=None, port=edge.port)
        assert files.verify(_ctx(runner), CheckResult(False)).fact["served"] == "none"
        edge.up()
        served = served_once(NAMES[0], edge.port)
        _placed(root, *_pair(tmp_path, "b"))
        for step in (
            files,
            ssl_steps.Ssl(
                made, fetched=fetched, secrets=Secrets(()), root=root, port=edge.port
            ),
            _renew(root, fetched, edge),
        ):
            with pytest.raises(StepFailed) as failed:
                step.verify(_ctx(runner), CheckResult(False))
            assert failed.value.reason == Code(
                "not-served", {"served": served, "file": file_fingerprint(root)}
            ), step.name
        down = ssl_steps.Ssl(
            made, fetched=fetched, secrets=Secrets(()), root=root, port=edge.port
        )
        edge.context = None  # nginx answers nothing
        with pytest.raises(StepFailed) as failed:
            down.verify(_ctx(runner), CheckResult(False))
    assert failed.value.reason == Code(
        "not-served", {"served": "none", "file": file_fingerprint(root)}
    )


# --- B7: ssl renew signs again only its own self-signed pair ---------------------


def test_renew_never_signs_over_a_certificate_a_ca_issued(tmp_path: Path) -> None:
    """A CA's certificate due for renewal with no certbot lineage: left as it
    is -- in ``letsencrypt`` ``no-lineage`` (exit 2), in ``self-signed`` green;
    also when its issuer and subject read the same (it does not sign itself).
    The pair: the machine's own self-signed pair due is signed again."""
    for mode, subject, outcome_code in (
        ("letsencrypt", None, ExitCode.INCOMPLETE),
        ("self-signed", CA_NAME, ExitCode.OK),
    ):
        here = tmp_path / mode
        here.mkdir()
        root, fetched = passport(here, ssl=mode)
        cert, key = issued_pair(here, NAMES, days=10, subject=subject)
        _placed(root, cert, key)
        assert signs_itself(cert_path(root)) is False
        with Edge(root) as edge, Mixed() as runner:  # openssl only: nothing signed
            edge.up()
            outcome, _ = run([_renew(root, fetched, edge)], runner, mode="renew")
        assert outcome.code is outcome_code, outcome.steps
        assert cert_path(root).read_text() == cert
        assert not [a for a in runner.argvs if "req" in a]
        assert outcome.steps[0].verify["self_signed"] is False
        if mode == "letsencrypt":
            [entry] = outcome.incomplete
            ends = _ends(root).strftime(STAMP)
            assert entry.reason == Code("ssl_renew:no-lineage", {"cert_expires": ends})
    # the pair: its own self-signed pair, due -- signed again
    root, fetched = passport(tmp_path / "own", ssl="self-signed")
    cert, key = _pair(tmp_path, "own-pair", days=10)
    _placed(root, cert, key)
    assert signs_itself(cert_path(root)) is True
    with Edge(root) as edge, Mixed(*_reload(root), edge=edge) as runner:
        edge.up()
        outcome, _ = run([_renew(root, fetched, edge)], runner, mode="renew")
    assert outcome.code is ExitCode.OK, outcome.steps
    assert cert_path(root).read_text() != cert


# --- B30: a long domain; a box with no pair -------------------------------------


def test_a_domain_longer_than_a_cn_signs(tmp_path: Path) -> None:
    """The first domain is 72 characters; a CN holds 64: the self-signed pair
    names ``pridem`` in its CN and every domain in its SAN."""
    long = "a" * 60 + ".example.org"
    names = {"frontend": long, "api": DOMAINS["api"]}
    root, fetched = passport(tmp_path, domains=names)
    with Edge(root) as edge, Mixed() as runner:
        outcome, _ = run(ladder(root, fetched, edge=edge), runner)
    assert outcome.code is ExitCode.OK, outcome.steps
    [req] = [a for a in runner.argvs if "req" in a]
    assert req[req.index("-subj") + 1] == "/CN=pridem"
    assert sorted(strings(outcome.steps[0].verify["domains"])) == sorted(names.values())


def test_renew_on_a_box_with_no_pair_renews_nothing(tmp_path: Path) -> None:
    """No pair on the box (a product with no domains): ``ssl renew`` green,
    ``placed: false``, no command -- not red every night."""
    root, fetched = passport(tmp_path)
    with Edge(root) as edge, Mixed() as runner:
        outcome, _ = run([_renew(root, fetched, edge)], runner, mode="renew")
    assert outcome.code is ExitCode.OK, outcome.steps
    assert outcome.steps[0].verify == {"mode": "self-signed", "placed": False}
    assert runner.argvs == []


def test_a_self_signed_certificate_is_one_that_its_own_key_verifies(
    tmp_path: Path,
) -> None:
    """``signs_itself``: the machine's pair -- yes; a CA's leaf -- no; a CA's
    leaf whose subject is the CA's name -- no, though issuer and subject read
    the same; a file that is no certificate -- no."""
    cert, _ = _pair(tmp_path, "own")
    (tmp_path / "x").mkdir()
    leaf, _ = issued_pair(tmp_path / "x", NAMES)
    (tmp_path / "y").mkdir()
    odd, _ = issued_pair(tmp_path / "y", NAMES, subject=CA_NAME)
    found = {}
    for name, text in (("own", cert), ("leaf", leaf), ("odd", odd), ("junk", "x")):
        path = tmp_path / f"{name}.pem"
        path.write_text(text)
        found[name] = signs_itself(path)
    assert found == {"own": True, "leaf": False, "odd": False, "junk": False}


def test_renew_in_letsencrypt_reloads_when_nginx_serves_another(
    tmp_path: Path,
) -> None:
    """``ssl renew`` with nothing new from certbot, but nginx serving another
    pair than the file (a reload that failed after the last renewal): it
    reloads -- the copy alone no longer decides."""
    root, fetched = passport(tmp_path, ssl="letsencrypt")
    (tmp_path / "old").mkdir()
    (tmp_path / "new").mkdir()
    old = issued_pair(tmp_path / "old", NAMES)
    new = issued_pair(tmp_path / "new", NAMES)
    _placed(root, *old)
    _live(root, *new)
    with Edge(root) as edge:
        edge.up()
        _placed(root, *new)  # copied by the last renewal, never reloaded
        renew = argv(root, "run", "--rm", "certbot", "renew", "--webroot", "-w",
                     "/var/www/acme")  # fmt: skip
        with Mixed(FakeCall(tuple(renew)), *_reload(root), edge=edge) as runner:
            outcome, _ = run([_renew(root, fetched, edge)], runner, mode="renew")
        assert outcome.code is ExitCode.OK, outcome.steps
        assert outcome.steps[0].verify["served"] == file_fingerprint(root)


def test_nginx_not_answering_is_no_reason_to_reload(tmp_path: Path) -> None:
    """A fresh pair on disk and nginx not up (the first install, before the
    ``nginx`` step): ``tls_files`` has nothing to do -- nothing served is no
    other certificate. The pair: nginx up on another pair -- ``serve``."""
    root, fetched = passport(tmp_path)
    _placed(root, *_pair(tmp_path, "a"))
    made = product()
    with Edge(root) as edge, Mixed() as runner:
        files = TlsFiles(made, fetched=fetched, root=root, now=None, port=edge.port)
        assert files.check(_ctx(runner)).needed is False
        edge.up()
        _placed(root, *_pair(tmp_path, "b"))
        found = files.check(_ctx(runner))
    assert found.needed and found.would is not None
    assert found.would.code == "serve"
