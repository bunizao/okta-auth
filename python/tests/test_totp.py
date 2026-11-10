"""Ports tests/totp.test.ts. Test names are the TypeScript case names in snake_case."""

import pytest

from okta_auth import totp

# RFC 6238 Appendix B, SHA-1 rows. The seed is ASCII "12345678901234567890";
# the RFC prints 8 digits, and a 6-digit code is the last 6 of them.
RFC_SEED = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
RFC_VECTORS = [
    (59, "94287082"),
    (1111111109, "07081804"),
    (1111111111, "14050471"),
    (1234567890, "89005924"),
    (2000000000, "69279037"),
    (20000000000, "65353130"),
]


@pytest.mark.parametrize(("seconds", "eight_digits"), RFC_VECTORS)
def test_matches_rfc_6238_at_t(seconds: int, eight_digits: str) -> None:
    assert totp(RFC_SEED, seconds) == eight_digits[-6:]


def test_accepts_secrets_as_authenticator_apps_show_them() -> None:
    spaced = "gezd gnbv gy3t qojq gezd gnbv gy3t qojq"
    assert totp(spaced, 59) == "287082"
    assert totp(f"{RFC_SEED}====", 59) == "287082"


def test_rejects_a_malformed_secret_without_echoing_it() -> None:
    with pytest.raises(ValueError, match=r"^TOTP secret is not valid base32$"):
        totp("not-base32!", 0)


def test_rejects_incomplete_and_noncanonical_base32_without_echoing_it() -> None:
    for secret in ("A", "AAA", "AAAAAA", "MZ", "M=Y", "MY=A", "===="):
        with pytest.raises(ValueError, match=r"^TOTP secret is not valid base32$"):
            totp(secret, 0)
