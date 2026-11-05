"""A product with routes, passports by role and SSL mode, and a runner whose
``openssl`` is real while ``docker`` and the network follow a strict script
(DM-17)."""

import json
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from itertools import count
from pathlib import Path

from env_support import box, passport_data
from plan_support import ListSink

from pridem.events import PlanOutcome
from pridem.plan import Plan, StackSteps
from pridem.runner import FakeCall, FakeRunner, OnLine, Result, Stream, SubprocessRunner
from pridem.stacks.schema import PRIMER_YAML, Product
from pridem.steps.base import Step
from pridem.steps.edge import NGINX_IMAGE, argv
from pridem.steps.nginx import HASH_LABEL, INSPECT
from pridem.steps.passport import Fetched

DOMAINS = {"frontend": "blank.example.org", "api": "api.blank.example.org"}
NOW = datetime(2026, 11, 1, tzinfo=UTC)
CONTAINER = "edge0"


def product(
    *,
    routes: Mapping[str, Mapping[str, object]] | None = None,
    csp: str | None = None,
    stacks: Mapping[str, object] | None = None,
) -> Product:
    host: dict[str, object] = {
        "domains": list(DOMAINS),
        "routes": dict(
            routes
            if routes is not None
            else {
                "frontend": {"to": "frontend:80"},
                "api": {"to": "app:8000", "max_body": "1M"},
            }
        ),
    }
    if csp is not None:
        host["headers"] = {"csp": csp}
    made = PRIMER_YAML.validate_python(
        {
            "schema": 1,
            "name": "blank",
            "kind": "product",
            "stacks": dict(
                stacks
                if stacks is not None
                else {
                    "blank": {
                        "compose": "docker-compose.yml",
                        "app": {
                            "service": "app",
                            "port": 8000,
                            "health": "/h",
                            "ready": "/r",
                        },
                        "frontend": {"service": "frontend", "port": 80},
                    }
                }
            ),
            "env": {},
            "host": host,
            "report": {"health": "/h", "ready": "/r", "logs": "json", "junit": True},
        }
    )
    assert isinstance(made, Product)
    return made


def passport(
    tmp: Path,
    *,
    role: str = "test",
    ssl: str = "self-signed",
    tls: tuple[str, str] | None = None,
    domains: Mapping[str, str] = DOMAINS,
) -> tuple[Path, Fetched]:
    data = passport_data(domains=domains)
    server = data["server"]
    assert isinstance(server, dict)
    server["role"] = role
    if role == "preview":
        server["expires_at"] = datetime(2026, 12, 1, tzinfo=UTC)
        product_part = data["product"]
        assert isinstance(product_part, dict)
        product_part["ref"] = "v1.0.0"
    policies = data["policies"]
    assert isinstance(policies, dict)
    policies["ssl"] = ssl
    if tls is not None:
        policies["tls"] = {"cert": tls[0], "key": tls[1]}
    return box(tmp, data)


def openssl(*args: str) -> None:
    SubprocessRunner().run(
        ["openssl", *args], timeout=60, on_line=lambda stream, line, cut: None
    )


def self_signed_pair(
    tmp: Path, names: Sequence[str], days: int = 90
) -> tuple[str, str]:
    key, cert = tmp / "pair.key", tmp / "pair.crt"
    openssl(
        "req",
        "-x509",
        "-newkey",
        "rsa:2048",
        "-nodes",
        "-keyout",
        str(key),
        "-out",
        str(cert),
        "-days",
        str(days),
        "-subj",
        f"/CN={names[0]}",
        "-addext",
        "subjectAltName=" + ",".join(f"DNS:{n}" for n in names),
    )
    return cert.read_text(), key.read_text()


def issued_pair(tmp: Path, names: Sequence[str]) -> tuple[str, str]:
    """A leaf signed by a throwaway CA: what certbot leaves, issuer != subject."""
    ca_key, ca_crt = tmp / "ca.key", tmp / "ca.crt"
    openssl(
        "req",
        "-x509",
        "-newkey",
        "rsa:2048",
        "-nodes",
        "-keyout",
        str(ca_key),
        "-out",
        str(ca_crt),
        "-days",
        "30",
        "-subj",
        "/CN=Invented Test CA",
    )
    key, csr, crt, ext = (
        tmp / "leaf.key",
        tmp / "leaf.csr",
        tmp / "leaf.crt",
        tmp / "leaf.ext",
    )
    openssl(
        "req",
        "-newkey",
        "rsa:2048",
        "-nodes",
        "-keyout",
        str(key),
        "-out",
        str(csr),
        "-subj",
        f"/CN={names[0]}",
    )
    ext.write_text("subjectAltName=" + ",".join(f"DNS:{n}" for n in names) + "\n")
    openssl(
        "x509",
        "-req",
        "-in",
        str(csr),
        "-CA",
        str(ca_crt),
        "-CAkey",
        str(ca_key),
        "-CAcreateserial",
        "-out",
        str(crt),
        "-days",
        "80",
        "-extfile",
        str(ext),
    )
    return crt.read_text(), key.read_text()


class Mixed(FakeRunner):
    """``openssl`` runs for real; every other command follows the script."""

    def __init__(self, *calls: FakeCall) -> None:
        super().__init__(*calls)
        self.argvs: list[tuple[str, ...]] = []
        self._real = SubprocessRunner()

    def run(
        self,
        argv: Sequence[str],
        *,
        expect: tuple[int, ...] = (0,),
        timeout: float,
        cwd: Path | None = None,
        env: Mapping[str, str] | None = None,
        on_line: OnLine,
    ) -> Result:
        self.argvs.append(tuple(argv))
        if argv[0] == "openssl":
            return self._real.run(
                argv, expect=expect, timeout=timeout, cwd=cwd, env=env, on_line=on_line
            )
        return super().run(
            argv, expect=expect, timeout=timeout, cwd=cwd, env=env, on_line=on_line
        )


def stdout(*lines: str) -> tuple[tuple[Stream, str], ...]:
    return tuple((Stream.STDOUT, line) for line in lines)


def ps_call(root: Path, running: bool) -> FakeCall:
    return FakeCall(
        tuple(argv(root, "ps", "-q", "nginx")),
        lines=stdout(CONTAINER) if running else (),
    )


EDGE_HASH = "e" * 64
"""``config --hash nginx`` of the edge's compose file (scripted)."""


def hash_call(root: Path, value: str = EDGE_HASH) -> FakeCall:
    return FakeCall(
        tuple(argv(root, "config", "--hash", "nginx")), lines=stdout(f"nginx {value}")
    )


def inspect_call(
    image: str = NGINX_IMAGE,
    networks: Sequence[str] = ("pridem", "pridem-edge_default"),
    found: str = EDGE_HASH,
) -> FakeCall:
    """``docker inspect`` of the nginx container: image, labels, networks."""
    document = {
        "image": image,
        "labels": {HASH_LABEL: found},
        "networks": {name: {} for name in networks},
    }
    return FakeCall(
        ("docker", "inspect", "--format", INSPECT, CONTAINER),
        lines=stdout(json.dumps(document)),
    )


def container_calls(root: Path, **seen: object) -> list[FakeCall]:
    """What nginx reads of its container (DM-45): inspect, then the hash."""
    return [inspect_call(**seen), hash_call(root)]  # type: ignore[arg-type]


def exec_call(root: Path, *command: str, code: int = 0) -> FakeCall:
    return FakeCall(tuple(argv(root, "exec", "-T", "nginx", *command)), code=code)


def run(
    steps: Sequence[Step], runner: FakeRunner, *, mode: str = "install"
) -> tuple[PlanOutcome, ListSink]:
    ticks = count()
    sink = ListSink()
    outcome = Plan(
        [StackSteps("edge", steps, root=True)],
        mode=mode,  # type: ignore[arg-type]
        role="test",
        runner=runner,
        sink=sink,
        clock=lambda: float(next(ticks)),
        now=lambda: NOW,
    ).run()
    return outcome, sink
