"""TLS of the box in the four modes of ``policies.ssl`` (contract 1 rule 5;
TZ 7.3, 8).

nginx always reads ``/opt/pridem/edge/certs/{fullchain,privkey}.pem`` (the key
0600, the directory 0700); where the pair comes from is the mode:

- ``provided`` -- the passport's ``policies.tls`` (the preview wildcard),
  written by the machine; certbot is never called;
- ``self-signed`` -- ``openssl req -x509`` over every domain of the routes; the
  key is written by openssl into its file, never through an argv or a pipe;
- ``defer`` -- the same self-signed pair, and the step ``ssl`` stays undone:
  ``incomplete {what: ssl, code: ssl:deferred}``, exit code 2; ``ssl issue``
  later;
- ``letsencrypt`` -- a self-signed pair first (nginx cannot start without
  one), then ``ssl`` runs certbot by HTTP-01 through the shared webroot, only
  when every domain resolves to the box (contract 1 rule 6), and copies what
  certbot made into the certs directory; ``nginx -t`` and reload follow.

``tls_files`` (order 1, before ``nginx``) places the pair; ``ssl`` (order 3,
after ``nginx``) issues and reports ``cert_expires``. A key found with another
mode than 0600 is refused, never re-moded. ``renew`` and ``status`` are what
the verb ``ssl renew|status`` and the renewal timer (DM-20) call; ``renew`` runs
under ``Box.lock`` like every command of a box. ``ssl_renew`` -- the whole plan
of ``ssl renew`` -- calls certbot only in ``letsencrypt`` and only when certbot
issued a certificate (``live/pridem``); the pair certbot holds is copied, and
nginx reloaded, only when it differs from the pair nginx reads. A self-signed
pair (``self-signed``, ``defer``, ``letsencrypt`` before its issue) due for
renewal is signed again over the names it has (DM-80).

The pair is written as one change (``write_set``, ``commit_set``): the key
first, then the certificate. A crash between the two renames, or nginx
restarting right then, sees a torn pair -- so every step that places the pair
checks it: the public key of the certificate is the key's (``pair_matches``),
or the pair is placed again; ``verify`` refuses a torn pair (DM-80).

Every step that reads the certificate back judges its end by ``expiry``: past
-- ``expired``; under ``EXPIRING_BEFORE`` -- ``expiring``: renewal starts
``RENEW_BEFORE`` ahead, so a week left means it failed for three weeks; under
``RENEW_BEFORE`` -- the fact ``renew_due``, not a refusal (DM-80). Where the
certificate comes from decides who may refuse it (DM-185): ``tls_files`` does
not refuse a certificate a CA issued in ``letsencrypt`` -- ``ssl`` after it
renews it, and a red ``tls_files`` would stop the deploy before ``ssl`` could;
a ``provided`` one in its last week is left undone (``incomplete``), not red:
the passport renews it.

What nginx serves is a fact, not the file (DM-185, REVIEW-0006 B6): ``served``
is the SHA-256 of the DER nginx gives a handshake on 443 for the box's first
name, read from the host by Python's ``ssl`` with no verification; the file's
is the SHA-256 of the DER of the first certificate of ``fullchain.pem``. After
a reload the old workers still answer for a moment -- measured: the old and the
new certificate alternate for about 0.1 s -- so ``served`` is
``SERVED_STEADY`` handshakes in a row ``SERVED_PAUSE_S`` apart, within
``SERVED_WAIT_S``, or ``not-served``. Every step that places the pair reloads
nginx once when nginx answers; a reload that failed is done again by the
``check`` of the next run, which sees nginx serve another certificate than the
file (``serve``).

A certificate *signs itself* when its signature verifies with its own public
key (``signs_itself``): the machine's own self-signed pair. ``issuer ==
subject`` can hold for a certificate a CA issued (measured), so it decides
nothing. ``ssl renew`` signs again only a pair that signs itself; a CA's
certificate with no certbot lineage is left as it is (``no-lineage``,
REVIEW-0006 B7). The fact ``self_signed`` is that same test.

A pair of the passport (``provided``) is checked before anything is written:
the public key of its certificate is its key's, in the process -- the key goes
to no argv and no file; not -- ``provided-pair-mismatch``, the pair on disk as
it was (REVIEW-0006 B29). The self-signed pair names the box in its SAN only:
its CN is ``SELF_SIGNED_CN``, a domain may be longer than the 64 characters a
CN holds (REVIEW-0006 B30).
"""

import hashlib
import re
import socket
import ssl
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import ClassVar

from cryptography import x509
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from pydantic import SecretStr

from pridem.events import Code, Json, Secrets, strings
from pridem.files import commit_set, private_dir, temp_of, write_set
from pridem.stacks.passport import Passport
from pridem.stacks.routes import domains
from pridem.stacks.schema import Product
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
from pridem.steps.edge import (
    argv,
    certs_dir,
    letsencrypt_dir,
    mode_of,
)
from pridem.steps.host import dns_table
from pridem.steps.passport import NO_PASSPORT, Fetched

ALL_MODES: frozenset[Mode] = frozenset({"install", "deploy", "reinstall"})
RENEW_MODES: frozenset[Mode] = frozenset({"renew"})
RENEW_BEFORE = timedelta(days=30)
EXPIRING_BEFORE = timedelta(days=7)
SELF_SIGNED_DAYS = 90
CERT_NAME = "pridem"
CERTBOT_TIMEOUT_S = 600
SELF_SIGNED_CN = "pridem"
"""The CN of the machine's self-signed pair: a CN holds 64 characters, a
domain may be longer; the names are in the SAN (REVIEW-0006 B30)."""
EDGE_PORT = 443
"""Where nginx serves TLS on the box -- the port of the edge's compose."""
SERVED_STEADY = 10
"""Handshakes in a row that must give one certificate: after a reload the
old workers still answer for a moment (DM-185, measured)."""
SERVED_PAUSE_S = 0.1
SERVED_WAIT_S = 30.0
HANDSHAKE_TIMEOUT_S = 5.0
_PEM_CERT = re.compile(
    r"-----BEGIN CERTIFICATE-----.+?-----END CERTIFICATE-----", re.DOTALL
)


def cert_path(root: Path) -> Path:
    return certs_dir(root) / "fullchain.pem"


def key_path(root: Path) -> Path:
    return certs_dir(root) / "privkey.pem"


def _passport(fetched: Fetched) -> Passport:
    if fetched.passport is None:
        raise StepFailed("no-passport")
    return fetched.passport


def key_mode(root: Path, code: str = "key-mode") -> None:
    key = key_path(root)
    if key.exists() and mode_of(key) != oct(0o600):
        raise StepFailed(code, {"path": str(key), "mode": mode_of(key)})


def cert_facts(ctx: StepContext, root: Path) -> dict[str, Json]:
    """What the certificate says of itself: expiry, its domains, and whether
    it signs itself (``signs_itself``, DM-185)."""
    _, lines = out(
        ctx,
        [
            "openssl",
            "x509",
            "-in",
            str(cert_path(root)),
            *CERT_ARGS,
        ],
        passed_on=False,
    )
    return {**read_cert(lines), "self_signed": signs_itself(cert_path(root))}


CERT_ARGS = ("-noout", "-enddate", "-issuer", "-subject", "-ext", "subjectAltName")
"""What ``openssl x509`` prints of a certificate for ``read_cert``."""


def read_cert(lines: list[str]) -> dict[str, Json]:
    """What ``openssl x509 <CERT_ARGS>`` printed: the end and the domains
    (``state`` reads it too, DM-136). Whether the certificate signs itself is
    no text it prints: ``signs_itself`` (DM-185).
    ``KeyError`` or ``ValueError`` -- not what ``openssl`` prints."""
    fields: dict[str, str] = {}
    names: list[Json] = []
    for line in lines:
        key, sep, value = line.partition("=")
        if sep and key == "notAfter":
            fields[key] = value.strip()
        for part in line.split(","):
            part = part.strip()
            if part.startswith("DNS:"):
                names.append(part.removeprefix("DNS:"))
    ends = datetime.strptime(
        " ".join(fields["notAfter"].split()), "%b %d %H:%M:%S %Y %Z"
    ).replace(tzinfo=UTC)
    return {
        "cert_expires": ends.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "domains": sorted(names, key=str),
    }


def pair_matches(ctx: StepContext, root: Path) -> bool:
    """The certificate's public key is the key's: the pair is not torn."""
    _, cert = out(
        ctx,
        ["openssl", "x509", "-in", str(cert_path(root)), "-noout", "-pubkey"],
        passed_on=False,
    )
    _, key = out(
        ctx, ["openssl", "pkey", "-in", str(key_path(root)), "-pubout"], passed_on=False
    )
    return cert == key


def signs_itself(path: Path) -> bool:
    """The certificate at ``path`` verifies with its own public key: a
    self-signed one, the machine's (DM-185). A certificate a CA issued does
    not, whatever its names say -- ``issuer == subject`` can hold for one."""
    try:
        cert = x509.load_pem_x509_certificate(path.read_bytes())
        cert.verify_directly_issued_by(cert)
    except (OSError, ValueError, TypeError, InvalidSignature):
        return False
    return True


def cert_names(path: Path) -> list[str]:
    """The DNS names of the certificate's SAN, read in the process; none when
    it has none or cannot be read."""
    try:
        cert = x509.load_pem_x509_certificate(path.read_bytes())
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
    except (OSError, ValueError, x509.ExtensionNotFound):
        return []
    return [str(name) for name in san.value.get_values_for_type(x509.DNSName)]


def _fingerprint(der: bytes) -> str:
    return hashlib.sha256(der).hexdigest()


def file_fingerprint(root: Path) -> str:
    """SHA-256 of the DER of the first certificate of ``fullchain.pem`` -- the
    one nginx gives a handshake; ``unreadable`` when there is none."""
    text = cert_path(root).read_bytes().decode("ascii", errors="replace")
    found = _PEM_CERT.search(text)
    if found is None:
        return "unreadable"
    try:
        return _fingerprint(ssl.PEM_cert_to_DER_cert(found.group(0)))
    except ValueError:
        return "unreadable"


def served_once(name: str, port: int) -> str | None:
    """SHA-256 of the DER nginx gives one handshake on ``port`` of the host for
    the name ``name`` (SNI), read with no verification; ``None`` -- nobody
    answers TLS there."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection(("127.0.0.1", port), HANDSHAKE_TIMEOUT_S) as raw:
            with context.wrap_socket(raw, server_hostname=name) as tls:
                der = tls.getpeercert(binary_form=True)
    except OSError:  # refused, reset, timed out, a TLS alert (ssl.SSLError)
        return None
    return None if der is None else _fingerprint(der)


def served_steady(ctx: StepContext, name: str, port: int, want: str) -> str | None:
    """``want`` once ``SERVED_STEADY`` handshakes in a row give it,
    ``SERVED_PAUSE_S`` apart. A reload leaves the old workers answering for a
    moment: the old and the new certificate alternate first (DM-185,
    measured), so only a row counts. At ``SERVED_WAIT_S`` with no such row --
    the last certificate seen that is not ``want`` (the old workers'), or
    ``None`` when nothing else answered: never ``want``, whichever answered
    last (DM-185 FIX: the last handshake of an alternation decided it)."""
    deadline = time.monotonic() + SERVED_WAIT_S
    row = 0
    other: str | None = None
    while True:
        seen = served_once(name, port)
        if seen == want:
            row += 1
            if row >= SERVED_STEADY:
                return want
        else:
            row = 0
            if seen is not None:
                other = seen
        if time.monotonic() >= deadline:
            return other
        ctx.interrupt.sleep(SERVED_PAUSE_S)


def served_fact(
    ctx: StepContext, root: Path, name: str, port: int, *, required: bool
) -> str:
    """The fact ``served``: the fingerprint nginx serves, steadily the file's,
    or ``not-served``. Not ``required`` and nobody answers -- ``none``: nginx
    is not up yet, and the step that brings it up reads the pair."""
    file = file_fingerprint(root)
    if not required and served_once(name, port) is None:
        return "none"
    seen = served_steady(ctx, name, port, file)
    if seen != file:
        raise StepFailed("not-served", {"served": seen or "none", "file": file})
    return file


def serving(root: Path, name: str, port: int) -> CheckResult:
    """``check``'s look at what nginx serves: another certificate than the
    file -- ``serve`` (a reload, again if the last one failed); nobody
    answering or the file's -- nothing to do."""
    file = file_fingerprint(root)
    seen = served_once(name, port)
    if seen is None or seen == file:
        return CheckResult(False)
    params: dict[str, Json] = {"served": seen, "file": file}
    return CheckResult(True, local_code("serve", params), {"act": "serve"})


def one_key(cert: bytes, key: bytes) -> bool:
    """The public key of the certificate is the key's: in the process, the key
    in no argv and no file (REVIEW-0006 B29)."""
    form = (serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    try:
        public = x509.load_pem_x509_certificate(cert).public_key()
        private = serialization.load_pem_private_key(key, password=None)
    except (ValueError, TypeError, UnsupportedAlgorithm):
        return False
    return public.public_bytes(*form) == private.public_key().public_bytes(*form)


def provided_pair(passport: Passport) -> tuple[bytes, bytes]:
    """The passport's pair (``ssl: provided``), checked before anything is
    written: not of one key -- ``provided-pair-mismatch``, nothing placed."""
    tls = passport.policies.tls
    if tls is None:
        raise RuntimeError("ssl: provided comes with policies.tls (rule 5)")
    cert = tls.cert.get_secret_value().encode("ascii")
    key = tls.key.get_secret_value().encode("ascii")
    if not one_key(cert, key):
        raise StepFailed("provided-pair-mismatch")
    return cert, key


def remaining(facts: dict[str, Json], now: datetime) -> dict[str, Json]:
    """``days_left`` and ``renew_due``, judging nothing."""
    left = _ends(facts) - now
    return {"days_left": left.days, "renew_due": left < RENEW_BEFORE}


def _ends(facts: dict[str, Json]) -> datetime:
    return datetime.strptime(str(facts["cert_expires"]), "%Y-%m-%dT%H:%M:%SZ").replace(
        tzinfo=UTC
    )


def expiry(facts: dict[str, Json], now: datetime) -> dict[str, Json]:
    """The certificate's end judged: ``expired``, ``expiring`` or the facts
    ``days_left`` and ``renew_due``."""
    left = _ends(facts) - now
    if left <= timedelta(0):
        raise StepFailed("expired", {"cert_expires": facts["cert_expires"]})
    days = left.days
    if left < EXPIRING_BEFORE:
        raise StepFailed(
            "expiring", {"cert_expires": facts["cert_expires"], "days_left": days}
        )
    return {"days_left": days, "renew_due": left < RENEW_BEFORE}


def _fresh(facts: dict[str, Json], wanted: list[str], now: datetime) -> bool:
    expires = datetime.strptime(str(facts["cert_expires"]), "%Y-%m-%dT%H:%M:%SZ")
    covered = set(wanted) <= set(strings(facts["domains"]))
    return covered and expires.replace(tzinfo=UTC) - now > RENEW_BEFORE


def self_sign(ctx: StepContext, root: Path, names: list[str]) -> None:
    """A self-signed pair over ``names``; openssl writes the key into its file."""
    certs = certs_dir(root)
    private_dir(certs)
    key_temp, cert_temp = temp_of(key_path(root)), temp_of(cert_path(root))
    try:
        key_temp.unlink(missing_ok=True)  # left by a run that died
        cert_temp.unlink(missing_ok=True)
        out(
            ctx,
            [
                "openssl",
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-keyout",
                str(key_temp),
                "-out",
                str(cert_temp),
                "-days",
                str(SELF_SIGNED_DAYS),
                "-subj",
                f"/CN={SELF_SIGNED_CN}",
                "-addext",
                "subjectAltName=" + ",".join(f"DNS:{n}" for n in names),
            ],
        )
        key_temp.chmod(0o600)
        commit_set([(key_temp, key_path(root)), (cert_temp, cert_path(root))])
    finally:
        key_temp.unlink(missing_ok=True)
        cert_temp.unlink(missing_ok=True)


def reload_nginx(ctx: StepContext, root: Path) -> None:
    """``nginx -t`` in the running nginx, then reload; red -- no reload."""
    code, _ = out(ctx, argv(root, "exec", "-T", "nginx", "nginx", "-t"), expect=(0, 1))
    if code != 0:
        raise StepFailed("config-invalid", {"where": "running nginx"})
    out(ctx, argv(root, "exec", "-T", "nginx", "nginx", "-s", "reload"))


def _live(root: Path) -> Path:
    return letsencrypt_dir(root) / "live" / CERT_NAME


def issued(root: Path) -> bool:
    """certbot holds a certificate of the box (``live/pridem``)."""
    live = _live(root)
    return (live / "fullchain.pem").exists() and (live / "privkey.pem").exists()


def place_pair(root: Path, cert: bytes, key: bytes) -> None:
    """The pair nginx reads, as one change: the key, then the certificate."""
    private_dir(certs_dir(root))
    write_set([(key_path(root), key, 0o600), (cert_path(root), cert, 0o644)])


def _issued_pair(root: Path, secrets: Secrets) -> tuple[bytes, bytes]:
    live = _live(root)
    path = live / "privkey.pem"
    key = path.read_bytes()
    try:
        text = key.decode("ascii")
    except UnicodeDecodeError:  # a PEM is ASCII: the key is damaged (DM-77)
        raise StepFailed("key-damaged", {"path": str(path)}) from None
    secrets.add([SecretStr(text.strip())])
    return (live / "fullchain.pem").read_bytes(), key


def _placed(root: Path) -> tuple[bytes, bytes] | None:
    if not cert_path(root).exists() or not key_path(root).exists():
        return None
    return cert_path(root).read_bytes(), key_path(root).read_bytes()


def _copy_issued(root: Path, secrets: Secrets) -> bool:
    """certbot's pair to nginx's, when it differs; whether it did."""
    pair = _issued_pair(root, secrets)
    if _placed(root) == pair:
        return False
    place_pair(root, *pair)
    return True


def issue(ctx: StepContext, root: Path, names: list[str], secrets: Secrets) -> None:
    """certbot HTTP-01 through the shared webroot; the pair copied; reload."""
    out(
        ctx,
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
            CERT_NAME,
            "--non-interactive",
            "--agree-tos",
            "--register-unsafely-without-email",
            "--keep-until-expiring",
            "--expand",
            *[word for name in names for word in ("-d", name)],
        ),
        timeout=CERTBOT_TIMEOUT_S,
    )
    _copy_issued(root, secrets)
    reload_nginx(ctx, root)


def renew(ctx: StepContext, root: Path, secrets: Secrets) -> bool:
    """``ssl renew`` of an issued certificate: certbot renews what is due; the
    pair is copied only when certbot's pair is new -- whether it was (the
    caller reloads nginx then, and when nginx serves another than the file)."""
    out(
        ctx,
        argv(
            root, "run", "--rm", "certbot", "renew", "--webroot", "-w", "/var/www/acme"
        ),
        timeout=CERTBOT_TIMEOUT_S,
    )
    return _copy_issued(root, secrets)


def status(ctx: StepContext, root: Path) -> dict[str, Json]:
    """``ssl status``: what nginx serves -- expiry, issuer, domains, key mode."""
    key_mode(root)
    return {**cert_facts(ctx, root), "key_mode": mode_of(key_path(root))}


SERVE_CODES: dict[str, str] = {
    "serve": "reload nginx: it serves {served}, the file is {file}",
    "not-served": "nginx serves {served}, the file is {file}",
}
PAIR_CODES: dict[str, str] = {
    "provided-pair-mismatch": "the passport's certificate is not of the passport's "
    "key; the pair on disk is left",
}


class TlsFiles(Step):
    """The certificate pair nginx reads, from the mode of ``policies.ssl``;
    nginx reloaded when it serves another (DM-185)."""

    name = "tls_files"
    title = "Place the certificate files"
    order = 1
    modes = ALL_MODES
    codes: ClassVar[dict[str, str]] = {
        **NO_PASSPORT,
        **SERVE_CODES,
        **PAIR_CODES,
        "place": "place the {mode} certificate for {domains}",
        "key-mode": "the TLS key {path} is {mode}, not 0o600; it is left as it is",
        "provided-differs": "the certificate on disk is not the passport's",
        "pair-mismatch": "the TLS certificate is not of the TLS key beside it",
        "expired": "the certificate expired at {cert_expires}",
        "expiring": "the certificate ends at {cert_expires}, in {days_left} days",
        "config-invalid": "nginx -t is red in {where}; nothing reloaded",
    }

    def __init__(
        self,
        product: Product,
        *,
        fetched: Fetched,
        root: Path = Path("/"),
        now: datetime | None = None,
        port: int = EDGE_PORT,
    ) -> None:
        self.product = product
        self.fetched = fetched
        self.root = root
        self.now = now
        self.port = port

    def _names(self) -> list[str]:
        return domains(self.product, _passport(self.fetched))

    def _now(self) -> datetime:
        return self.now if self.now is not None else datetime.now(UTC)

    def check(self, ctx: StepContext) -> CheckResult:
        key_mode(self.root)
        names = self._names()
        if not names:
            return CheckResult(False)
        mode = _passport(self.fetched).policies.ssl
        # the passport's pair is one key's before anything is placed (B29)
        given = provided_pair(_passport(self.fetched)) if mode == "provided" else None
        params: dict[str, Json] = {"mode": mode, "domains": list[Json](names)}
        needed = CheckResult(True, local_code("place", params), {"act": "place"})
        if not cert_path(self.root).exists() or not key_path(self.root).exists():
            return needed
        if given is not None:
            if _placed(self.root) != given:
                return needed
            return serving(self.root, names[0], self.port)
        if not pair_matches(ctx, self.root):
            return needed  # torn by a crash between the two renames
        facts = cert_facts(ctx, self.root)
        kept = mode == "letsencrypt" and not facts["self_signed"]  # issued: ssl's
        if kept or _fresh(facts, names, self._now()):
            return serving(self.root, names[0], self.port)
        return needed

    def act(self, ctx: StepContext, check: CheckResult) -> None:
        passport = _passport(self.fetched)
        if check.data.get("act") != "serve":
            if passport.policies.ssl == "provided":
                place_pair(self.root, *provided_pair(passport))
            else:
                self_sign(ctx, self.root, self._names())
        if served_once(self._names()[0], self.port) is not None:
            reload_nginx(ctx, self.root)  # nginx runs: it reads the pair now

    def verify(self, ctx: StepContext, check: CheckResult) -> Verified:
        names = self._names()
        mode = _passport(self.fetched).policies.ssl
        if not names:
            return Verified({"mode": mode, "domains": []})
        key_mode(self.root)
        if mode == "provided":
            if _placed(self.root) != provided_pair(_passport(self.fetched)):
                raise StepFailed("provided-differs")
        if not pair_matches(ctx, self.root):
            raise StepFailed("pair-mismatch")
        facts = cert_facts(ctx, self.root)
        now = self._now()
        fact: dict[str, Json] = {"mode": mode, **facts}
        undone: Code | None = None
        if mode == "letsencrypt" and not facts["self_signed"]:
            fact.update(remaining(facts, now))  # ssl, next, renews it (B8)
        elif mode == "provided":
            left = _ends(facts) - now
            if left <= timedelta(0):
                expiry(facts, now)  # expired: red
            fact.update(remaining(facts, now))
            if left < EXPIRING_BEFORE:  # the passport renews it: undone, not red
                undone = Code(
                    "expiring",
                    {"cert_expires": facts["cert_expires"], "days_left": left.days},
                )
        else:
            fact.update(expiry(facts, now))
        fact["key_mode"] = oct(0o600)
        fact["served"] = served_fact(
            ctx, self.root, names[0], self.port, required=False
        )
        return Verified(fact, incomplete=undone)


class Ssl(Step):
    """The certificate of the mode: issued, deferred, or as placed; served by
    nginx as the file is (DM-185)."""

    name = "ssl"
    title = "Issue the TLS certificate"
    said = "{mode}, {days_left} days left"
    order = 3
    modes = ALL_MODES
    codes: ClassVar[dict[str, str]] = {
        **NO_PASSPORT,
        **SERVE_CODES,
        "issue": "issue a Let's Encrypt certificate for {domains}",
        "deferred": "the certificate is self-signed until ssl issue",
        "dns-not-ready": "domains do not resolve to this box: {domains}",
        "not-issued": "the certificate is still self-signed after certbot",
        "expired": "the certificate expired at {cert_expires}",
        "expiring": "the certificate ends at {cert_expires}, in {days_left} days",
        "pair-mismatch": "the TLS certificate is not of the TLS key beside it",
        "key-mode": "the TLS key {path} is {mode}, not 0o600; it is left as it is",
        "key-damaged": "the key certbot wrote at {path} is not a PEM of ASCII",
        "config-invalid": "nginx -t is red in {where}; nothing reloaded",
    }

    def __init__(
        self,
        product: Product,
        *,
        fetched: Fetched,
        secrets: Secrets,
        root: Path = Path("/"),
        now: datetime | None = None,
        port: int = EDGE_PORT,
    ) -> None:
        self.product = product
        self.fetched = fetched
        self.secrets = secrets
        self.root = root
        self.now = now
        self.port = port
        self.precheck: str | None = None
        """``ok`` -- DNS was checked before issuing; ``skipped`` -- no public IP
        known to check it by (DM-92); ``None`` -- nothing was issued."""

    def _names(self) -> list[str]:
        return domains(self.product, _passport(self.fetched))

    def _now(self) -> datetime:
        return self.now if self.now is not None else datetime.now(UTC)

    def check(self, ctx: StepContext) -> CheckResult:
        names = self._names()
        if _passport(self.fetched).policies.ssl != "letsencrypt" or not names:
            return CheckResult(False)
        # a fresh certificate needs nothing from outside: the echo services
        # and DNS are asked only when there is something to issue
        facts = cert_facts(ctx, self.root)
        if not facts["self_signed"] and _fresh(facts, names, self._now()):
            return CheckResult(False)
        ip, _, wrong = dns_table(ctx, names)
        if wrong:
            raise StepFailed("dns-not-ready", {"domains": list[Json](wrong)})
        # no public IP known: no precheck -- Let's Encrypt checks it (DM-92)
        self.precheck = "ok" if ip is not None else "skipped"
        return CheckResult(True, local_code("issue", {"domains": list[Json](names)}))

    def act(self, ctx: StepContext, check: CheckResult) -> None:
        issue(ctx, self.root, self._names(), self.secrets)

    def verify(self, ctx: StepContext, check: CheckResult) -> Verified:
        mode = _passport(self.fetched).policies.ssl
        names = self._names()
        if not names:
            return Verified({"mode": mode, "domains": []})
        key_mode(self.root)
        if not pair_matches(ctx, self.root):
            raise StepFailed("pair-mismatch")
        facts = cert_facts(ctx, self.root)
        judged = expiry(facts, self._now())
        if mode == "letsencrypt" and facts["self_signed"]:
            raise StepFailed("not-issued")
        fact: dict[str, Json] = {"mode": mode, **facts, **judged}
        if self.precheck is not None:
            fact["precheck"] = self.precheck
        # nginx is up after its step: it serves the file, steadily
        fact["served"] = served_fact(ctx, self.root, names[0], self.port, required=True)
        if mode == "defer":
            return Verified(fact, incomplete=Code("deferred"))
        return Verified(fact)


class SslRenew(Step):
    """``ssl renew``: certbot renews an issued certificate that is due; a
    self-signed pair due for renewal is signed again -- one that signs itself,
    never a CA's (B7); a torn pair is placed again; nginx reloaded when it
    serves another than the file; every mode reads back what nginx serves and
    judges its end. No pair on the box -- nothing to renew (B30)."""

    name = "ssl_renew"
    title = "Renew the certificate"
    order = 1
    modes = RENEW_MODES
    codes: ClassVar[dict[str, str]] = {
        **NO_PASSPORT,
        **SERVE_CODES,
        **PAIR_CODES,
        "renew": "renew the Let's Encrypt certificate if it is due",
        "sign": "sign the self-signed certificate again for {domains}",
        "place": "place the passport's certificate again",
        "key-mode": "the TLS key {path} is {mode}, not 0o600; it is left as it is",
        "key-damaged": "the key certbot wrote at {path} is not a PEM of ASCII",
        "config-invalid": "nginx -t is red in {where}; nothing reloaded",
        "pair-mismatch": "the TLS certificate is not of the TLS key beside it",
        "expired": "the certificate expired at {cert_expires}",
        "expiring": "the certificate ends at {cert_expires}, in {days_left} days",
        "not-issued": "no Let's Encrypt certificate yet: ssl issue when DNS is ready",
        "no-lineage": "a CA's certificate with no certbot lineage, ending at "
        "{cert_expires}: ssl issue renews it",
    }

    def __init__(
        self,
        *,
        fetched: Fetched,
        secrets: Secrets,
        root: Path = Path("/"),
        now: datetime | None = None,
        port: int = EDGE_PORT,
    ) -> None:
        self.fetched = fetched
        self.secrets = secrets
        self.root = root
        self.now = now
        self.port = port

    def _now(self) -> datetime:
        return self.now if self.now is not None else datetime.now(UTC)

    def _placed(self) -> bool:
        return cert_path(self.root).exists() or key_path(self.root).exists()

    def check(self, ctx: StepContext) -> CheckResult:
        key_mode(self.root)
        if not self._placed():
            return CheckResult(False)  # nothing placed: nothing to renew (B30)
        mode = _passport(self.fetched).policies.ssl
        if mode == "letsencrypt" and issued(self.root):
            return CheckResult(True, local_code("renew"), {"act": "renew"})
        if mode == "provided":
            given = provided_pair(_passport(self.fetched))  # before writing (B29)
            if _placed(self.root) != given:
                return CheckResult(True, local_code("place"), {"act": "place"})
            return self._serving()
        # the machine's self-signed pair -- self-signed, defer, letsencrypt
        # before its issue -- or a pair the machine did not sign (B7)
        facts = cert_facts(ctx, self.root)
        names = strings(facts["domains"])
        if not facts["self_signed"]:
            return self._serving()  # a CA's: never signed over
        if pair_matches(ctx, self.root) and _fresh(facts, names, self._now()):
            return self._serving()
        params: dict[str, Json] = {"domains": list[Json](names)}
        return CheckResult(True, local_code("sign", params), {"act": "sign", **params})

    def _name(self) -> str | None:
        """The name nginx is asked for: the certificate's first."""
        names = cert_names(cert_path(self.root))
        return names[0] if names else None

    def _serving(self) -> CheckResult:
        name = self._name()
        if name is None:
            return CheckResult(False)
        return serving(self.root, name, self.port)

    def act(self, ctx: StepContext, check: CheckResult) -> None:
        what = check.data.get("act")
        if what == "renew":
            copied = renew(ctx, self.root, self.secrets)
            name = self._name()
            stale = name is not None and serving(self.root, name, self.port).needed
            if copied or stale:
                reload_nginx(ctx, self.root)
            return
        if what == "place":
            place_pair(self.root, *provided_pair(_passport(self.fetched)))
        elif what == "sign":
            self_sign(ctx, self.root, strings(check.data.get("domains")))
        reload_nginx(ctx, self.root)

    def verify(self, ctx: StepContext, check: CheckResult) -> Verified:
        mode = _passport(self.fetched).policies.ssl
        if not self._placed():
            return Verified({"mode": mode, "placed": False})
        key_mode(self.root)
        if not pair_matches(ctx, self.root):
            raise StepFailed("pair-mismatch")
        found = status(ctx, self.root)
        judged = expiry(found, self._now())
        fact: dict[str, Json] = {"mode": mode, **found, **judged}
        name = self._name()
        if name is not None:
            fact["served"] = served_fact(ctx, self.root, name, self.port, required=True)
        if mode == "letsencrypt" and not issued(self.root):
            if not found["self_signed"]:  # a CA's, no lineage: left as it is (B7)
                params = {"cert_expires": found["cert_expires"]}
                return Verified(fact, incomplete=Code("no-lineage", params))
            return Verified(fact, incomplete=Code("not-issued"))
        return Verified(fact)
