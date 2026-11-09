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
``RENEW_BEFORE`` -- the fact ``renew_due``, not a refusal (DM-80).
"""

from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import ClassVar

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
    """What the certificate says of itself: expiry, issuer, its domains."""
    _, lines = out(
        ctx,
        [
            "openssl",
            "x509",
            "-in",
            str(cert_path(root)),
            "-noout",
            "-enddate",
            "-issuer",
            "-subject",
            "-ext",
            "subjectAltName",
        ],
        passed_on=False,
    )
    fields: dict[str, str] = {}
    names: list[Json] = []
    for line in lines:
        key, sep, value = line.partition("=")
        if sep and key in ("notAfter", "issuer", "subject"):
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
        "self_signed": fields.get("issuer") == fields.get("subject"),
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
                f"/CN={names[0]}",
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


def renew(ctx: StepContext, root: Path, secrets: Secrets) -> None:
    """``ssl renew`` of an issued certificate: certbot renews what is due; the
    pair is copied and nginx reloaded only when certbot's pair is new."""
    out(
        ctx,
        argv(
            root, "run", "--rm", "certbot", "renew", "--webroot", "-w", "/var/www/acme"
        ),
        timeout=CERTBOT_TIMEOUT_S,
    )
    if _copy_issued(root, secrets):
        reload_nginx(ctx, root)


def status(ctx: StepContext, root: Path) -> dict[str, Json]:
    """``ssl status``: what nginx serves -- expiry, issuer, domains, key mode."""
    key_mode(root)
    return {**cert_facts(ctx, root), "key_mode": mode_of(key_path(root))}


class TlsFiles(Step):
    """The certificate pair nginx reads, from the mode of ``policies.ssl``."""

    name = "tls_files"
    order = 1
    modes = ALL_MODES
    codes: ClassVar[dict[str, str]] = {
        **NO_PASSPORT,
        "place": "place the {mode} certificate for {domains}",
        "key-mode": "the TLS key {path} is {mode}, not 0o600; it is left as it is",
        "provided-differs": "the certificate on disk is not the passport's",
        "pair-mismatch": "the TLS certificate is not of the TLS key beside it",
        "expired": "the certificate expired at {cert_expires}",
        "expiring": "the certificate ends at {cert_expires}, in {days_left} days",
    }

    def __init__(
        self,
        product: Product,
        *,
        fetched: Fetched,
        root: Path = Path("/"),
        now: datetime | None = None,
    ) -> None:
        self.product = product
        self.fetched = fetched
        self.root = root
        self.now = now

    def _names(self) -> list[str]:
        return domains(self.product, _passport(self.fetched))

    def _now(self) -> datetime:
        return self.now if self.now is not None else datetime.now(UTC)

    def _provided(self) -> tuple[bytes, bytes]:
        tls = _passport(self.fetched).policies.tls
        if tls is None:
            raise RuntimeError("ssl: provided comes with policies.tls (rule 5)")
        return (
            tls.cert.get_secret_value().encode("ascii"),
            tls.key.get_secret_value().encode("ascii"),
        )

    def check(self, ctx: StepContext) -> CheckResult:
        key_mode(self.root)
        names = self._names()
        if not names:
            return CheckResult(False)
        mode = _passport(self.fetched).policies.ssl
        params: dict[str, Json] = {"mode": mode, "domains": list[Json](names)}
        needed = CheckResult(True, local_code("place", params))
        if not cert_path(self.root).exists() or not key_path(self.root).exists():
            return needed
        if mode == "provided":
            cert, key = self._provided()
            same = (
                cert_path(self.root).read_bytes() == cert
                and key_path(self.root).read_bytes() == key
            )
            return CheckResult(False) if same else needed
        if not pair_matches(ctx, self.root):
            return needed  # torn by a crash between the two renames
        facts = cert_facts(ctx, self.root)
        if mode == "letsencrypt" and not facts["self_signed"]:
            return CheckResult(False)  # issued: ssl keeps it
        return CheckResult(False) if _fresh(facts, names, self._now()) else needed

    def act(self, ctx: StepContext, check: CheckResult) -> None:
        if _passport(self.fetched).policies.ssl == "provided":
            place_pair(self.root, *self._provided())
            return
        self_sign(ctx, self.root, self._names())

    def verify(self, ctx: StepContext, check: CheckResult) -> Verified:
        names = self._names()
        mode = _passport(self.fetched).policies.ssl
        if not names:
            return Verified({"mode": mode, "domains": []})
        key_mode(self.root)
        if mode == "provided":
            cert, key = self._provided()
            if (
                cert_path(self.root).read_bytes(),
                key_path(self.root).read_bytes(),
            ) != (
                cert,
                key,
            ):
                raise StepFailed("provided-differs")
        if not pair_matches(ctx, self.root):
            raise StepFailed("pair-mismatch")
        facts = cert_facts(ctx, self.root)
        judged = expiry(facts, self._now())
        return Verified({"mode": mode, **facts, **judged, "key_mode": oct(0o600)})


class Ssl(Step):
    """The certificate of the mode: issued, deferred, or as placed."""

    name = "ssl"
    order = 3
    modes = ALL_MODES
    codes: ClassVar[dict[str, str]] = {
        **NO_PASSPORT,
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
    ) -> None:
        self.product = product
        self.fetched = fetched
        self.secrets = secrets
        self.root = root
        self.now = now

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
        _, _, wrong = dns_table(ctx, names)
        if wrong:
            raise StepFailed("dns-not-ready", {"domains": list[Json](wrong)})
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
        if mode == "defer":
            return Verified(fact, incomplete=Code("deferred"))
        return Verified(fact)


class SslRenew(Step):
    """``ssl renew``: certbot renews an issued certificate that is due; a
    self-signed pair due for renewal is signed again; a torn pair is placed
    again; every mode reads back what nginx serves and judges its end."""

    name = "ssl_renew"
    order = 1
    modes = RENEW_MODES
    codes: ClassVar[dict[str, str]] = {
        **NO_PASSPORT,
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
    }

    def __init__(
        self,
        *,
        fetched: Fetched,
        secrets: Secrets,
        root: Path = Path("/"),
        now: datetime | None = None,
    ) -> None:
        self.fetched = fetched
        self.secrets = secrets
        self.root = root
        self.now = now

    def _now(self) -> datetime:
        return self.now if self.now is not None else datetime.now(UTC)

    def check(self, ctx: StepContext) -> CheckResult:
        key_mode(self.root)
        mode = _passport(self.fetched).policies.ssl
        if mode == "letsencrypt" and issued(self.root):
            return CheckResult(True, local_code("renew"))
        if mode == "provided":
            tls = _passport(self.fetched).policies.tls
            if tls is None:
                raise RuntimeError("ssl: provided comes with policies.tls (rule 5)")
            given = (
                tls.cert.get_secret_value().encode("ascii"),
                tls.key.get_secret_value().encode("ascii"),
            )
            if _placed(self.root) == given:
                return CheckResult(False)
            return CheckResult(True, local_code("place"))
        # a self-signed pair: self-signed, defer, letsencrypt before its issue
        facts = cert_facts(ctx, self.root)
        names = strings(facts["domains"])
        if pair_matches(ctx, self.root) and _fresh(facts, names, self._now()):
            return CheckResult(False)
        params: dict[str, Json] = {"domains": list[Json](names)}
        return CheckResult(True, local_code("sign", params), params)

    def act(self, ctx: StepContext, check: CheckResult) -> None:
        mode = _passport(self.fetched).policies.ssl
        if mode == "letsencrypt" and issued(self.root):
            renew(ctx, self.root, self.secrets)
            return
        if mode == "provided":
            tls = _passport(self.fetched).policies.tls
            if tls is None:
                raise RuntimeError("ssl: provided comes with policies.tls (rule 5)")
            place_pair(
                self.root,
                tls.cert.get_secret_value().encode("ascii"),
                tls.key.get_secret_value().encode("ascii"),
            )
        else:
            self_sign(ctx, self.root, strings(check.data.get("domains")))
        reload_nginx(ctx, self.root)

    def verify(self, ctx: StepContext, check: CheckResult) -> Verified:
        mode = _passport(self.fetched).policies.ssl
        key_mode(self.root)
        if not pair_matches(ctx, self.root):
            raise StepFailed("pair-mismatch")
        found = status(ctx, self.root)
        judged = expiry(found, self._now())
        fact: dict[str, Json] = {"mode": mode, **found, **judged}
        if mode == "letsencrypt" and not issued(self.root):
            return Verified(fact, incomplete=Code("not-issued"))
        return Verified(fact)
