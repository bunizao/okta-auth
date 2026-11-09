"""Ports tests/globalprotect.test.ts. Test names are the TypeScript case names in snake_case."""

from __future__ import annotations

import asyncio
import traceback
from collections.abc import Callable
from datetime import datetime, timezone
from typing import Any
from urllib.parse import parse_qs

import pytest

from fake_sso import (
    GP,
    GP_COOKIE,
    OKTA,
    PASSWORD,
    SAML_RESPONSE,
    STATE_TOKEN,
    TOTP_SECRET,
    USERNAME,
    FakeOptions,
    FakeSso,
    RecordedRequest,
    fake_sso,
)
from okta_auth import GlobalProtectResult, OktaSignInError, sign_in_globalprotect

NOW = datetime(2026, 11, 2, 3, 4, 5, tzinfo=timezone.utc).timestamp()


def now() -> float:
    return NOW


def setup(**fake_options: Any) -> tuple[FakeSso, Callable[..., GlobalProtectResult]]:
    fake = fake_sso(FakeOptions(now=now, **{"enrollments": ["google_otp"], **fake_options}))

    def run(**extra: Any) -> GlobalProtectResult:
        options: dict[str, Any] = {
            "server": GP,
            "username": USERNAME,
            "password": PASSWORD,
            "totp_secret": TOTP_SECRET,
            "transport": fake.transport,
            "now": now,
            **extra,
        }
        return asyncio.run(sign_in_globalprotect(**options))

    return fake, run


def prelogins(requests: list[RecordedRequest]) -> list[str]:
    return [r.url.path for r in requests if r.url.path.endswith("/prelogin.esp")]


def form(body: str) -> dict[str, str]:
    return {name: values[0] for name, values in parse_qs(body).items()}


def rejection(run: Callable[[], object]) -> OktaSignInError:
    with pytest.raises(OktaSignInError) as info:
        run()
    return info.value


def expect_no_secrets(error: BaseException) -> None:
    text = f"{error} {''.join(traceback.format_exception(error))}"
    for secret in [
        PASSWORD,
        TOTP_SECRET,
        STATE_TOKEN,
        "02.id.abc",
        GP_COOKIE,
        SAML_RESPONSE,
        "gprequest",
        "gp-anon",
    ]:
        assert secret not in text


def test_signs_in_through_the_gateway_with_a_redirect_binding_and_returns_the_prelogin_cookie() -> (
    None
):
    fake, run = setup()
    result = run()

    assert result == GlobalProtectResult(
        interface="gateway",
        user=USERNAME,
        cookie_name="prelogin-cookie",
        cookie=GP_COOKIE,
        device_token="dt-1",
    )
    assert prelogins(fake.requests) == ["/ssl-vpn/prelogin.esp"]

    prelogin = fake.requests[0]
    assert prelogin.method == "POST"
    assert prelogin.headers.get("user-agent") == "PAN GlobalProtect"
    assert form(prelogin.body).get("clientos") == "Mac"


def test_follows_a_post_binding_to_okta_and_reads_the_result_from_an_html_comment() -> None:
    fake, run = setup(gp_binding="POST", gp_result_in="comment")
    result = run(device_token="dt-9")

    assert result.cookie == GP_COOKIE
    assert result.device_token == "dt-9"
    saml_request = next(r for r in fake.requests if r.url.host == OKTA)
    assert saml_request.method == "POST"
    assert form(saml_request.body).get("SAMLRequest") == "gprequest"
    # The SAMLRequest sits in the body here, yet the first Okta request still carries the device token.
    assert saml_request.cookies.get("DT") == "dt-9"


def test_falls_back_to_the_portal_when_the_gateway_does_not_offer_saml() -> None:
    fake, run = setup(gp_saml=["portal"])
    result = run()

    assert prelogins(fake.requests) == ["/ssl-vpn/prelogin.esp", "/global-protect/prelogin.esp"]
    assert result.interface == "portal"
    # The portal also sends prelogin-cookie, set to the literal "empty".
    assert result.cookie_name == "portal-userauthcookie"
    assert result.cookie == GP_COOKIE


def test_asks_only_the_interface_it_is_told_to() -> None:
    fake, run = setup(gp_saml=["gateway"])
    error = rejection(lambda: run(interface="portal"))

    assert error.code == "unexpected_step"
    assert prelogins(fake.requests) == ["/global-protect/prelogin.esp"]


def test_sends_nothing_to_okta_when_neither_interface_offers_saml() -> None:
    fake, run = setup(gp_saml=[])
    error = rejection(run)

    assert error.code == "unexpected_step"
    assert f"{GP}/global-protect/prelogin.esp" in str(error)
    assert not any(r.url.host == OKTA for r in fake.requests)
    expect_no_secrets(error)


def test_sends_the_password_only_to_okta_and_the_saml_response_only_to_the_acs() -> None:
    fake, run = setup()
    run()

    for request in fake.requests:
        if PASSWORD in request.body:
            assert request.url.host == OKTA
        if "SAMLResponse" in request.body:
            assert request.url.host == GP
        if request.url.host == GP:
            assert "DT" not in request.cookies


def test_skips_idx_when_okta_already_has_a_session() -> None:
    fake, run = setup(okta_session=True)
    result = run()

    assert not any(r.url.path.startswith("/idp/idx/") for r in fake.requests)
    assert result.cookie == GP_COOKIE


def test_reports_handoff_failed_when_the_acs_rejects_the_saml_response() -> None:
    _, run = setup(sp_rejects=True)
    error = rejection(run)

    assert error.code == "handoff_failed"
    assert f"{GP}/SAML20/SP/ACS" in str(error)
    expect_no_secrets(error)


def test_rejects_bad_input_before_any_request() -> None:
    fake, run = setup()
    with pytest.raises(ValueError):
        run(server="https://vpn.example.edu")
    with pytest.raises(ValueError):
        run(server="vpn.example.edu/path")
    with pytest.raises(ValueError):
        run(totp_secret="not base32!")
    assert fake.requests == []


def test_rejects_malformed_base32_before_any_request() -> None:
    fake, run = setup()
    for secret in ("A", "AAA", "AAAAAA", "MZ", "M=Y"):
        with pytest.raises(ValueError):
            run(totp_secret=secret)
    assert fake.requests == []


def test_reports_which_interface_it_asks() -> None:
    steps: list[str] = []
    _, run = setup(gp_saml=["portal"], okta_session=True)
    run(progress=steps.append)

    assert steps == [
        f"Asking the gateway at {GP} for SAML sign-in",
        f"Asking the portal at {GP} for SAML sign-in",
        f"{OKTA} already has a session",
        f"Posting the SAML response to {GP}",
    ]
