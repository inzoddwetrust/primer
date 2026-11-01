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
of ``ssl renew`` -- calls certbot only in ``letsencrypt``: in the other modes no
certbot certificate exists to renew, and the step reads back ``status``.
"""

from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import ClassVar

from pydantic import SecretStr

from pridem.events import Code, Json, Secrets
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
    write_file,
)
from pridem.steps.host import dns_table
from pridem.steps.passport import NO_PASSPORT, Fetched

ALL_MODES: frozenset[Mode] = frozenset({"install", "deploy", "reinstall"})
RENEW_MODES: frozenset[Mode] = frozenset({"renew"})
RENEW_BEFORE = timedelta(days=30)
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


def _fresh(facts: dict[str, Json], wanted: list[str], now: datetime) -> bool:
    expires = datetime.strptime(str(facts["cert_expires"]), "%Y-%m-%dT%H:%M:%SZ")
    covered = set(wanted) <= {str(name) for name in facts["domains"]}  # type: ignore[union-attr]
    return covered and expires.replace(tzinfo=UTC) - now > RENEW_BEFORE


def self_sign(ctx: StepContext, root: Path, names: list[str]) -> None:
    """A self-signed pair over ``names``; openssl writes the key into its file."""
    certs = certs_dir(root)
    certs.mkdir(mode=0o700, parents=True, exist_ok=True)
    key_temp, cert_temp = certs / "privkey.pem.tmp", certs / "fullchain.pem.tmp"
    try:
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
        cert_temp.replace(cert_path(root))
        key_temp.replace(key_path(root))
    finally:
        key_temp.unlink(missing_ok=True)
        cert_temp.unlink(missing_ok=True)


def reload_nginx(ctx: StepContext, root: Path) -> None:
    """``nginx -t`` in the running nginx, then reload; red -- no reload."""
    code, _ = out(ctx, argv(root, "exec", "-T", "nginx", "nginx", "-t"), expect=(0, 1))
    if code != 0:
        raise StepFailed("config-invalid", {"where": "running nginx"})
    out(ctx, argv(root, "exec", "-T", "nginx", "nginx", "-s", "reload"))


def _copy_issued(root: Path, secrets: Secrets) -> None:
    live = letsencrypt_dir(root) / "live" / CERT_NAME
    key = (live / "privkey.pem").read_bytes()
    secrets.add([SecretStr(key.decode("ascii").strip())])
    write_file(cert_path(root), (live / "fullchain.pem").read_bytes(), 0o644)
    write_file(key_path(root), key, 0o600)


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


def renew(ctx: StepContext, root: Path, secrets: Secrets) -> dict[str, Json]:
    """``ssl renew``: certbot renews what is due, the pair is copied, reload."""
    out(
        ctx,
        argv(
            root, "run", "--rm", "certbot", "renew", "--webroot", "-w", "/var/www/acme"
        ),
        timeout=CERTBOT_TIMEOUT_S,
    )
    _copy_issued(root, secrets)
    reload_nginx(ctx, root)
    return status(ctx, root)


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
        facts = cert_facts(ctx, self.root)
        if mode == "letsencrypt" and not facts["self_signed"]:
            return CheckResult(False)  # issued: ssl keeps it
        return CheckResult(False) if _fresh(facts, names, self._now()) else needed

    def act(self, ctx: StepContext, check: CheckResult) -> None:
        if _passport(self.fetched).policies.ssl == "provided":
            cert, key = self._provided()
            write_file(cert_path(self.root), cert, 0o644)
            write_file(key_path(self.root), key, 0o600)
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
        facts = cert_facts(ctx, self.root)
        return Verified({"mode": mode, **facts, "key_mode": oct(0o600)})


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
        "key-mode": "the TLS key {path} is {mode}, not 0o600; it is left as it is",
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
        _, _, wrong = dns_table(ctx, names)
        if wrong:
            raise StepFailed("dns-not-ready", {"domains": list[Json](wrong)})
        facts = cert_facts(ctx, self.root)
        if not facts["self_signed"] and _fresh(facts, names, self._now()):
            return CheckResult(False)
        return CheckResult(True, local_code("issue", {"domains": list[Json](names)}))

    def act(self, ctx: StepContext, check: CheckResult) -> None:
        issue(ctx, self.root, self._names(), self.secrets)

    def verify(self, ctx: StepContext, check: CheckResult) -> Verified:
        mode = _passport(self.fetched).policies.ssl
        names = self._names()
        if not names:
            return Verified({"mode": mode, "domains": []})
        key_mode(self.root)
        facts = cert_facts(ctx, self.root)
        ends = datetime.strptime(str(facts["cert_expires"]), "%Y-%m-%dT%H:%M:%SZ")
        if ends.replace(tzinfo=UTC) <= self._now():
            raise StepFailed("expired", {"cert_expires": facts["cert_expires"]})
        if mode == "letsencrypt" and facts["self_signed"]:
            raise StepFailed("not-issued")
        fact: dict[str, Json] = {"mode": mode, **facts}
        if mode == "defer":
            return Verified(fact, incomplete=Code("deferred"))
        return Verified(fact)


class SslRenew(Step):
    """``ssl renew``: certbot renews what is due in ``letsencrypt``; every mode
    reads back what nginx serves."""

    name = "ssl_renew"
    order = 1
    modes = RENEW_MODES
    codes: ClassVar[dict[str, str]] = {
        **NO_PASSPORT,
        "renew": "renew the Let's Encrypt certificate if it is due",
        "key-mode": "the TLS key {path} is {mode}, not 0o600; it is left as it is",
        "config-invalid": "nginx -t is red in {where}; nothing reloaded",
    }

    def __init__(
        self, *, fetched: Fetched, secrets: Secrets, root: Path = Path("/")
    ) -> None:
        self.fetched = fetched
        self.secrets = secrets
        self.root = root

    def check(self, ctx: StepContext) -> CheckResult:
        if _passport(self.fetched).policies.ssl != "letsencrypt":
            return CheckResult(False)
        return CheckResult(True, local_code("renew"))

    def act(self, ctx: StepContext, check: CheckResult) -> None:
        renew(ctx, self.root, self.secrets)

    def verify(self, ctx: StepContext, check: CheckResult) -> Verified:
        mode = _passport(self.fetched).policies.ssl
        return Verified({"mode": mode, **status(ctx, self.root)})
