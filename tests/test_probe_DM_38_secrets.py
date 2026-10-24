"""Probe DM-38: a known secret is cleaned whole, without edge whitespace and line
by line when a line is at least 16 characters (contract 2 v1.4 rule 2).
"""

import pytest
from pydantic import SecretStr

from pridem.contract import SECRET_MIN_LENGTH
from pridem.events import REDACTED, Secrets

BODY = [
    "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7VJTUt9Us8cKj",
    "MvOYz8wHkiXCSf4GLNYF2r0sZXKJ6bA8LS7bOFhXR1FD1Fk2hT9ThbL5bjKtfV3m",
    "AB==",
]
PEM = (
    "-----BEGIN PRIVATE KEY-----\n" + "\n".join(BODY) + "\n-----END PRIVATE KEY-----\n"
)
YAML_BLOCK = "a-secret-value-1234\n"
PADDED = "   padded-secret-value-77   "


def _clean(secret: str, text: str) -> str:
    return Secrets([SecretStr(secret)]).text(text)


@pytest.mark.parametrize(
    ("secret", "text", "cleaned"),
    [
        (PEM, f"key line: {BODY[1]}", f"key line: {REDACTED}"),
        (PEM.replace("\n", "\r\n"), f"key line: {BODY[0]}", f"key line: {REDACTED}"),
        (YAML_BLOCK, "token=a-secret-value-1234 sent", f"token={REDACTED} sent"),
        (PADDED, "pw=padded-secret-value-77;", f"pw={REDACTED};"),
    ],
    ids=["pem-line", "pem-crlf-line", "yaml-block", "padded"],
)
def test_probe_DM_38_multiline_secret_lines_are_redacted(
    secret: str, text: str, cleaned: str
) -> None:
    assert _clean(secret, text) == cleaned
    # the whole secret is one [redacted], no pieces of its lines left
    assert _clean(secret, f"<{secret}>") == f"<{REDACTED}>"
    # pair: what is not a form of the secret stays
    assert _clean(secret, "nothing secret here, AB== and short") == (
        "nothing secret here, AB== and short"
    )


@pytest.mark.parametrize("form", ["strip", "line"])
def test_derived_forms_start_at_16_characters(form: str) -> None:
    """15 -- left alone, 16 -- cleaned; for the stripped form and for a line."""
    fifteen = "x" * (SECRET_MIN_LENGTH - 1)
    sixteen = "y" * SECRET_MIN_LENGTH
    if form == "strip":
        short, long = f" {fifteen} ", f" {sixteen} "
    else:
        short = f"{fifteen}\n{'z' * 40}"
        long = f"{sixteen}\n{'z' * 40}"
    assert _clean(short, f"[{fifteen}]") == f"[{fifteen}]"
    assert _clean(long, f"[{sixteen}]") == f"[{REDACTED}]"


def test_whole_secret_is_cleaned_at_any_length() -> None:
    assert _clean("abc", "x-abc-y") == f"x-{REDACTED}-y"


def test_forms_shared_by_two_secrets_are_one_form() -> None:
    line = "s" * 20
    secrets = Secrets([SecretStr(f"{line}\nfirst-tail-000000"), SecretStr(line)])
    assert secrets.text(f"a {line} b") == f"a {REDACTED} b"
