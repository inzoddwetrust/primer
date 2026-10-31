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

CERTBOT_IMAGE = "certbot/certbot"
"""KNOWN CEILING (DM-17).

1. Mechanics: images run by digest only (TZ 7.3); certbot's digest has not been
   seen by anyone on this line -- the sandbox has no docker and no registry --
   so the constant names no digest, and ``ssl`` in ``letsencrypt`` mode is red
   ``ssl:certbot-unpinned`` before ``act``: no certbot runs unpinned.
   ``self-signed``, ``defer`` and ``provided`` never run certbot.
2. Status: acknowledged by design.
3. Task: a delivery after DM-17, before DM-23, pins it.
4. Trigger: tier 3 prints ``RepoDigests`` and ``--version`` of
   ``CERTBOT_TAG`` (``tier3/test_tier3_web.py``).
5. Agreed fix: ``CERTBOT_IMAGE = "certbot/certbot:<tag>@sha256:<digest>"`` with
   the value taken from that print.
6. Rejected: a tag without a digest -- a tag moves, the image under it is not
   the one the line has seen.
"""

CERTBOT_TAG = "certbot/certbot:latest"
"""What tier 3 reads the digest and version of (KNOWN CEILING above, point 4):
the pin names the version it found, never this tag."""


def pinned(image: str) -> bool:
    return "@sha256:" in image


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
