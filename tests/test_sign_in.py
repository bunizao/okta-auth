"""Ports tests/sign-in.test.ts. Test names are the TypeScript case names in snake_case."""

from __future__ import annotations

import asyncio
import json
import logging
import traceback
from collections.abc import Callable
from datetime import datetime, timezone
from typing import Any
from urllib.parse import parse_qs

import httpx
import pytest

from fake_sso import (
    OKTA,
    ONTRACK,
    ONTRACK_APP,
    ONTRACK_AUTH_TOKEN,
    ONTRACK_LANDING,
    PASSWORD,
    SP,
    STATE_TOKEN,
    TARGET,
    TOTP_SECRET,
    USERNAME,
    FakeOptions,
    FakeSso,
    RecordedRequest,
    fake_sso,
    idx_json,
)
from okta_auth import OktaSignInError, SignInResult, sign_in

NOW = datetime(2026, 11, 2, 3, 4, 5, tzinfo=timezone.utc).timestamp()


def now() -> float:
    return NOW


def setup(
    fake_options: dict[str, Any] | None = None, **sign_in_options: Any
) -> tuple[FakeSso, Callable[..., SignInResult]]:
    fake = fake_sso(FakeOptions(now=now, **(fake_options or {})))

    def run(**extra: Any) -> SignInResult:
        options: dict[str, Any] = {
            "url": TARGET,
            "username": USERNAME,
            "password": PASSWORD,
            "totp_secret": TOTP_SECRET,
            "transport": fake.transport,
            "now": now,
            **sign_in_options,
            **extra,
        }
        return asyncio.run(sign_in(**options))

    return fake, run


def idx_calls(requests: list[RecordedRequest]) -> list[RecordedRequest]:
    return [request for request in requests if request.url.path.startswith("/idp/idx/")]


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
        "ssp-1",
        "j-1",
        "dt-1",
        "SAMLRequest=request",
        ONTRACK_AUTH_TOKEN,
        "okta-session",
    ]:
        assert secret not in text


def test_signs_in_identifier_first_password_then_google_otp_over_push_then_saml() -> None:
    fake, run = setup()
    result = run()

    assert [(c.name, c.value, c.domain) for c in result.cookies] == [
        ("MoodleSession", "authed", SP),
        ("MDL_SSP_SessID", "ssp-1", SP),
    ]
    assert result.device_token == "dt-1"

    steps = [(request.url.path, json.loads(request.body)) for request in idx_calls(fake.requests)]
    assert [path for path, _ in steps] == [
        "/idp/idx/introspect",
        "/idp/idx/identify",
        "/idp/idx/challenge/answer",
        "/idp/idx/challenge",
        "/idp/idx/challenge/answer",
    ]
    # Identifier first: the identify form had no credentials field, so none went.
    assert steps[1][1] == {"identifier": USERNAME, "stateHandle": STATE_TOKEN}
    assert steps[2][1] == {"credentials": {"passcode": PASSWORD}, "stateHandle": STATE_TOKEN}
    # Okta Verify (push only) was listed first; Google Authenticator was chosen.
    assert steps[3][1] == {
        "authenticator": {"id": "aut-google", "methodType": "otp"},
        "stateHandle": STATE_TOKEN,
    }
    passcode = steps[4][1]["credentials"]["passcode"]
    assert len(passcode) == 6 and passcode.isdigit()


def test_sends_the_password_with_the_identifier_when_the_identify_form_asks_for_it() -> None:
    fake, run = setup({"password_on_identify": True, "enrollments": ["google_otp"]})
    run()

    identify = next(r for r in idx_calls(fake.requests) if r.url.path == "/idp/idx/identify")
    assert json.loads(identify.body) == {
        "identifier": USERNAME,
        "credentials": {"passcode": PASSWORD},
        "stateHandle": STATE_TOKEN,
    }


def test_answers_okta_verify_with_a_totp_code_in_the_field_okta_names() -> None:
    fake, run = setup({"enrollments": ["okta_verify"]})
    run()

    select, answer = idx_calls(fake.requests)[-2:]
    assert json.loads(select.body)["authenticator"] == {"id": "aut-verify", "methodType": "totp"}
    code = json.loads(answer.body)["credentials"]["totp"]
    assert len(code) == 6 and code.isdigit()


def test_switches_away_from_a_pre_selected_okta_verify_to_google_authenticator() -> None:
    fake, run = setup({"enrollments": ["okta_verify", "google_otp"], "preselect": "okta_verify"})
    run()

    select, answer = idx_calls(fake.requests)[-2:]
    assert select.url.path == "/idp/idx/challenge"
    assert json.loads(select.body)["authenticator"] == {"id": "aut-google", "methodType": "otp"}
    code = json.loads(answer.body)["credentials"]["passcode"]
    assert len(code) == 6 and code.isdigit()


def test_answers_a_pre_selected_google_authenticator_challenge_directly() -> None:
    fake, run = setup({"enrollments": ["okta_verify", "google_otp"], "preselect": "google_otp"})
    run()

    assert not any(r.url.path == "/idp/idx/challenge" for r in idx_calls(fake.requests))


def test_round_trips_the_device_token_so_okta_sees_the_same_device() -> None:
    fake, run = setup()
    first = run()
    assert first.device_token == "dt-1"

    fake.requests.clear()
    second = run(device_token=first.device_token)
    assert second.device_token == "dt-1"

    # The very first request to Okta already carries it.
    okta_requests = [r for r in fake.requests if r.url.host == OKTA]
    assert "SAMLRequest" in okta_requests[0].url.params
    assert okta_requests[0].cookies.get("DT") == "dt-1"
    assert all(r.cookies.get("DT") == "dt-1" for r in okta_requests)


def test_never_sends_one_host_s_cookies_to_another_host() -> None:
    fake, run = setup()
    result = run()

    okta_cookies = {"DT", "JSESSIONID", "sid"}
    sp_cookies = {"MoodleSession", "MDL_SSP_SessID"}
    for request in fake.requests:
        names = set(request.cookies)
        if request.url.host == OKTA:
            assert not names & sp_cookies
        if request.url.host == SP:
            assert not names & okta_cookies
    assert all(cookie.domain == SP for cookie in result.cookies)


def test_stops_after_one_wrong_password_with_credentials_rejected() -> None:
    fake, run = setup(password="wrong password")
    error = rejection(run)

    assert error.code == "credentials_rejected"
    assert "incorrectPassword" in str(error)
    attempts = [r for r in idx_calls(fake.requests) if r.url.path == "/idp/idx/challenge/answer"]
    assert len(attempts) == 1
    assert not any(r.url.path == "/login/token/redirect" for r in fake.requests)
    expect_no_secrets(error)


def test_reports_a_wrong_one_time_code_as_passcode_rejected() -> None:
    _, run = setup({"totp_secret": "KRSXG5CTMVRXEZLUKN2XAZLSKNSWG4TFOQ"})
    error = rejection(run)

    assert error.code == "passcode_rejected"
    assert "api.authn.otp.invalid" in str(error)
    expect_no_secrets(error)


def test_refuses_push_only_enrollment_with_mfa_unsupported() -> None:
    fake, run = setup({"enrollments": ["okta_verify_push"]})
    error = rejection(run)

    assert error.code == "mfa_unsupported"
    assert "okta_verify (push)" in str(error)
    assert not any(r.url.path == "/idp/idx/challenge" for r in idx_calls(fake.requests))


def test_skips_idx_when_okta_already_has_a_session() -> None:
    fake, run = setup({"okta_session": True})
    result = run()

    assert idx_calls(fake.requests) == []
    assert next(c.value for c in result.cookies if c.name == "MoodleSession") == "authed"


def test_returns_where_the_saml_post_landed() -> None:
    _, run = setup()
    assert run().landing_url == f"https://{SP}/my/"


def test_starts_at_an_okta_app_link_and_returns_the_app_s_landing_url_and_cookies() -> None:
    fake, run = setup()
    result = run(url=ONTRACK_APP)

    assert result.landing_url == ONTRACK_LANDING
    assert [(c.name, c.domain) for c in result.cookies] == [("doubtfire", ONTRACK)]
    assert len(idx_calls(fake.requests)) == 5
    assert not any(r.url.host == SP for r in fake.requests)


def test_sends_the_device_token_to_okta_on_an_okta_app_link() -> None:
    fake, run = setup()
    run(url=ONTRACK_APP, device_token="dt-known")

    assert all(r.cookies.get("DT") == "dt-known" for r in idx_calls(fake.requests))
    assert all("DT" not in r.cookies for r in fake.requests if r.url.host == ONTRACK)


def test_reports_handoff_failed_when_the_app_behind_an_okta_app_link_refuses_the_saml_post() -> (
    None
):
    _, run = setup({"sp_rejects": True})
    error = rejection(lambda: run(url=ONTRACK_APP))

    assert error.code == "handoff_failed"
    assert ONTRACK in str(error)
    expect_no_secrets(error)


def test_returns_okta_s_session_cookies_without_the_device_token() -> None:
    _, run = setup()
    result = run()

    assert [(c.name, c.domain) for c in result.okta_session] == [
        ("JSESSIONID", OKTA),
        ("sid", OKTA),
    ]


def test_reuses_an_okta_session_to_sign_in_to_a_second_app_without_mfa() -> None:
    fake, run = setup()
    first = run()
    answered = len(idx_calls(fake.requests))
    second = run(url=ONTRACK_APP, okta_session=first.okta_session)

    assert len(idx_calls(fake.requests)) == answered
    assert second.landing_url == ONTRACK_LANDING
    assert [r for r in fake.requests if r.url.host != OKTA and "sid" in r.cookies] == []


def test_reports_handoff_failed_when_the_service_provider_rejects_the_saml_response() -> None:
    _, run = setup({"sp_rejects": True})
    error = rejection(run)

    assert error.code == "handoff_failed"
    assert OKTA in str(error)
    expect_no_secrets(error)


def test_gives_up_after_eight_idx_steps() -> None:
    fake, run = setup()
    skip = {
        "name": "skip",
        "href": f"https://{OKTA}/idp/idx/skip",
        "value": [{"name": "stateHandle", "value": STATE_TOKEN}],
    }
    fake.set_override(
        lambda request: (
            idx_json({"stateHandle": STATE_TOKEN, "remediation": {"value": [skip]}})
            if request.url.path in ("/idp/idx/introspect", "/idp/idx/skip")
            else None
        )
    )
    error = rejection(run)

    assert error.code == "unexpected_step"
    assert len([r for r in idx_calls(fake.requests) if r.url.path == "/idp/idx/skip"]) == 8


def test_names_unknown_remediation_forms_without_their_values() -> None:
    fake, run = setup()
    unknown = {
        "name": "enroll-profile",
        "href": "x",
        "value": [{"name": "stateHandle", "value": STATE_TOKEN}],
    }
    fake.set_override(
        lambda request: (
            idx_json({"stateHandle": STATE_TOKEN, "remediation": {"value": [unknown]}})
            if request.url.path == "/idp/idx/introspect"
            else None
        )
    )
    error = rejection(run)

    assert error.code == "unexpected_step"
    assert "enroll-profile" in str(error)
    expect_no_secrets(error)


def test_maps_http_failures_to_http_n_and_timeouts_to_network() -> None:
    down, run_down = setup()
    down.set_override(
        lambda request: httpx.Response(503, text="busy") if request.url.host == OKTA else None
    )
    assert rejection(run_down).code == "http_503"

    slow, run_slow = setup()

    def time_out(request: RecordedRequest) -> httpx.Response | None:
        if request.url.host == OKTA:
            # httpx's message carries the full URL, query string included.
            raise httpx.ReadTimeout(f"timed out reading {request.url}")
        return None

    slow.set_override(time_out)
    error = rejection(run_slow)
    assert error.code == "network"
    assert "timed out" in str(error)
    expect_no_secrets(error)


def test_rejects_bad_input_before_any_request() -> None:
    fake, run = setup()
    with pytest.raises(ValueError):
        run(url="http://learning.example.edu/")
    with pytest.raises(ValueError):
        run(totp_secret="not base32!")
    assert fake.requests == []


def test_rejects_malformed_base32_before_any_request() -> None:
    fake, run = setup()
    for secret in ("A", "AAA", "AAAAAA", "MZ", "M=Y"):
        with pytest.raises(ValueError):
            run(totp_secret=secret)
    assert fake.requests == []


def test_rejects_a_same_host_login_page_after_the_saml_post() -> None:
    _, run = setup({"sp_rejects": True, "sp_login_page": True})
    assert rejection(run).code == "handoff_failed"


def test_rejects_an_unfinished_redirect_after_the_saml_post() -> None:
    fake, run = setup()
    fake.set_override(
        lambda request: (
            httpx.Response(302)
            if str(request.url) == TARGET and request.cookies.get("MoodleSession") == "authed"
            else None
        )
    )
    assert rejection(run).code == "handoff_failed"


def test_preserves_saml_posts_across_same_origin_307_and_308_redirects() -> None:
    for status in (307, 308):
        fake, run = setup({"acs_redirect": status})
        result = run()
        assert next(c.value for c in result.cookies if c.name == "MoodleSession") == "authed"
        acs = next(r for r in fake.requests if r.url.path == "/canonical-acs")
        assert acs.method == "POST"
        assert "SAMLResponse" in parse_qs(acs.body)
        assert acs.headers.get("content-type") == "application/x-www-form-urlencoded"
        assert acs.cookies.get("acs-route") == "canonical"


@pytest.mark.parametrize("status", [307, 308])
def test_refuses_to_replay_saml_posts_across_origins(status: int) -> None:
    fake, run = setup()
    fake.set_override(
        lambda request: (
            httpx.Response(status, headers={"location": f"https://{SP}:8443/acs?token=private"})
            if "saml2-acs.php" in request.url.path
            else None
        )
    )
    error = rejection(run)
    assert error.code == "unexpected_step"
    assert "private" not in str(error)
    assert not any(r.url.port == 8443 for r in fake.requests)


@pytest.mark.parametrize("path", ["/login/index.php", "/idp/idx/introspect"])
@pytest.mark.parametrize("error_type", [httpx.ReadError, httpx.ReadTimeout])
def test_maps_interrupted_page_and_idx_response_bodies_to_network(
    path: str, error_type: type[httpx.HTTPError]
) -> None:
    class BrokenBody(httpx.AsyncByteStream):
        async def __aiter__(self):
            yield b"partial body"
            raise error_type(f"{PASSWORD} {STATE_TOKEN}")

    fake, run = setup()
    fake.set_override(
        lambda request: (
            httpx.Response(200, stream=BrokenBody()) if request.url.path == path else None
        )
    )
    error = rejection(run)
    assert error.code == "network"
    expect_no_secrets(error)
    assert len([r for r in fake.requests if r.url.path == path]) == 1


@pytest.mark.parametrize("body", ["not json", "null", "[]", '"text"'])
def test_reports_invalid_successful_idx_responses_as_unexpected_step(body: str) -> None:
    fake, run = setup()
    fake.set_override(
        lambda request: (
            httpx.Response(200, text=body) if request.url.path == "/idp/idx/introspect" else None
        )
    )
    assert rejection(run).code == "unexpected_step"


def test_keeps_request_urls_out_of_logs_even_at_debug(caplog: pytest.LogCaptureFixture) -> None:
    # Python only: httpx logs full URLs (stateToken, SAMLRequest) at INFO.
    caplog.set_level(logging.DEBUG)
    _, run = setup()
    run()

    for secret in [PASSWORD, TOTP_SECRET, STATE_TOKEN, "stateToken=", "SAMLRequest="]:
        assert secret not in caplog.text


def test_reports_each_step_by_host_without_secrets() -> None:
    steps: list[str] = []
    _, run = setup()
    run(progress=steps.append)

    assert steps == [
        f"Opening {SP}",
        f"Signing in at {OKTA}",
        "Sending the username",
        "Sending the password",
        "Choosing the TOTP authenticator",
        "Sending a TOTP code",
        f"Posting the SAML response to {SP}",
        f"Checking that {SP} is signed in",
    ]
    for secret in [USERNAME, PASSWORD, TOTP_SECRET, STATE_TOKEN, "?"]:
        assert not any(secret in step for step in steps)
