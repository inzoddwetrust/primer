"""The machine's own stack ``edge``: nginx and certbot (TZ 7.3).

The compose project ``pridem-edge`` from the machine's file
``/opt/pridem/edge/compose.yml``: nginx runs on the network ``pridem``, holds
the host's ports 80 and 443 (no application has a port of its own), reads its
config from ``/opt/pridem/edge/nginx`` and the certificate from
``/opt/pridem/edge/certs``; the ACME webroot is the volume ``acme`` it shares
with certbot. certbot never runs as a service: ``run --rm`` when a
certificate is issued or renewed, writing to ``/opt/pridem/edge/letsencrypt``.
Every object carries ``pridem.stack=edge``. Images are pinned by digest.
"""

import json
import os
from pathlib import Path

from pridem.events import Json
from pridem.steps.compose import NETWORK

PROJECT = "pridem-edge"
STACK_LABEL = {"pridem.stack": "edge"}

NGINX_IMAGE = (
    "nginx:1.30.6-alpine@sha256:"
    "47928bf67eb62a1863cb08d9ecb52d3e704304ba614eaee17884204677702951"
)
"""The nginx the blank's frontend is built from: pulled on every tier 3 run."""

CERTBOT_IMAGE = (
    "certbot/certbot:v5.9.0@sha256:"
    "bc93cb710b413e6b456d622f9b0133b3e109c0a78c2ed9976af43d209b0a1805"
)
"""certbot, pinned by the digest tier 3 read (DM-49): ``RepoDigests`` of
``certbot/certbot:latest`` pulled on the run of ``main@c5931be``, whose
``--version`` said ``certbot 5.9.0`` -- the tag named here. docker pulls by the
digest; the tag is for people. Tier 3 checks on every run that this tag names
this digest (``tier3/test_tier3_whole_install.py``)."""


def home(root: Path) -> Path:
    return root / "opt" / "pridem" / "edge"


def compose_file(root: Path) -> Path:
    return home(root) / "compose.yml"


def nginx_dir(root: Path) -> Path:
    return home(root) / "nginx"


def live_config(root: Path) -> Path:
    return nginx_dir(root) / "pridem.conf"


def candidate_dir(root: Path) -> Path:
    return home(root) / "nginx-candidate"


def certs_dir(root: Path) -> Path:
    return home(root) / "certs"


def letsencrypt_dir(root: Path) -> Path:
    return home(root) / "letsencrypt"


def argv(root: Path, *args: str) -> list[str]:
    return ["docker", "compose", "-p", PROJECT, "-f", str(compose_file(root)), *args]


def compose_text(root: Path) -> str:
    """The edge compose file: nginx, certbot (run only), the webroot volume."""
    labels: dict[str, Json] = dict[str, Json](STACK_LABEL)
    document: dict[str, Json] = {
        "services": {
            "nginx": {
                "image": NGINX_IMAGE,
                "restart": "unless-stopped",
                "ports": ["80:80", "443:443"],
                "networks": [NETWORK],
                "labels": labels,
                "volumes": [
                    f"{nginx_dir(root)}:/etc/nginx/conf.d:ro",
                    f"{certs_dir(root)}:/etc/pridem/certs:ro",
                    "acme:/var/www/acme:ro",
                ],
            },
            "certbot": {
                "image": CERTBOT_IMAGE,
                "profiles": ["certbot"],
                "labels": labels,
                "volumes": [
                    "acme:/var/www/acme",
                    f"{letsencrypt_dir(root)}:/etc/letsencrypt",
                ],
            },
        },
        "volumes": {"acme": {"labels": labels}},
        "networks": {NETWORK: {"external": True}},
    }
    return json.dumps(document, indent=2, sort_keys=True) + "\n"


def write_file(path: Path, data: bytes, mode: int) -> None:
    """``data`` to ``path`` with ``mode`` from the first byte: temp, fsync,
    rename; the directory 0700."""
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    temp = path.with_name(path.name + ".tmp")
    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp, path)
    finally:
        temp.unlink(missing_ok=True)


def mode_of(path: Path) -> str:
    return oct(path.stat().st_mode & 0o777)
