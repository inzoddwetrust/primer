"""DM-146: the way out of the Panel.

The Panel, as a product (``primer-panel``), reaches ``ssh.github.com`` -- git
to ``primer-ops`` over ssh on port 443 -- through the machine's proxy, and
nothing else: a host not in its rows, a row of another product, port 22, an
address of a private range stay closed as before (protocol 4.1, 4.2). The
proxy's config is compared literally (``par0`` 14.2).
"""

import pytest
from compose_support import blank

from pridem.stacks.egress import listed, unlisted
from pridem.stacks.schema import PRIMER_YAML, Product
from pridem.steps.compose import PROXY_PORT
from pridem.steps.egress import PRIVATE, config_text


def _product(name: str, *hosts: str) -> Product:
    data = blank().model_dump(by_alias=True, exclude_none=True)
    data["name"] = name
    data["egress"] = list(hosts)
    made = PRIMER_YAML.validate_python(data)
    assert isinstance(made, Product)
    return made


def test_probe_DM_146_the_panel_reaches_its_host_not_another() -> None:
    """``ssh.github.com`` is a row of ``primer-panel``: its ``egress`` passes,
    and the proxy rendered for it lets ``CONNECT`` through to that name on
    443 alone. The pair: ``github.com`` of the Panel and ``ssh.github.com`` of
    another product are refused before any build.

    Changed by DM-188 (S11), the dispatcher's word on its gate: squid does not
    resolve a name before it checks the list -- ``deny !egress`` is the first
    rule of ``http_access``, the order is a literal still."""
    assert listed("primer-panel") == frozenset({"ssh.github.com"})
    assert unlisted(_product("primer-panel", "ssh.github.com")) == []
    assert unlisted(_product("primer-panel", "github.com")) == ["github.com"]
    for other in ("primer-blank", "velo"):
        assert unlisted(_product(other, "ssh.github.com")) == ["ssh.github.com"]
    text = config_text(sorted(listed("primer-panel"))).splitlines()
    assert text[1:12] == [
        f"http_port {PROXY_PORT}",
        "acl SSL_ports port 443",
        "acl CONNECT method CONNECT",
        f"acl private dst {' '.join(PRIVATE)}",
        "acl egress dstdomain -n ssh.github.com",
        "http_access deny !egress",
        "http_access deny !CONNECT",
        "http_access deny !SSL_ports",
        "http_access deny private",
        "http_access allow egress",
        "http_access deny all",
    ]


@pytest.mark.parametrize("host", ["api.telegram.org", "api.github.com", "github.com"])
def test_the_panel_has_no_other_row(host: str) -> None:
    """Telegram is comms'; the page of a key is a link in a browser (DM-159):
    no row for them (the owner's word, 24.11)."""
    assert unlisted(_product("primer-panel", host)) == [host]
