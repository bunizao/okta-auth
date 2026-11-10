"""Ports tests/okta-variants.test.ts. Test names are the TypeScript case names in snake_case.

Okta orgs and apps configured differently from the default fake: other SAML
bindings, OIDC apps, and sign-on policies that add steps."""

from __future__ import annotations

import asyncio
import json
from collections.abc import Callable
from datetime import datetime, timezone
from typing import Any
from urllib.parse import parse_qs, quote

import httpx
import pytest

from fake_sso import (
    OKTA,
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
APP_PATH = "/app/example_moodle/exk1/sso/saml"
STATE_HANDLE = {
    "name": "stateHandle",
    "required": True,
    "value": STATE_TOKEN,
    "visible": False,
    "mutable": False,
}


def now() -> float:
    return NOW


def setup(**fake_options: Any) -> tuple[FakeSso, Callable[..., SignInResult]]:
    fake = fake_sso(FakeOptions(now=now, **fake_options))

    def run(**extra: Any) -> SignInResult:
        return asyncio.run(
            sign_in(
                url=TARGET,
                username=USERNAME,
                password=PASSWORD,
                totp_secret=TOTP_SECRET,
                transport=fake.transport,
                now=now,
                **extra,
            )
        )

    return fake, run


def rejection(run: Callable[..., SignInResult], **extra: Any) -> OktaSignInError:
    with pytest.raises(OktaSignInError) as caught:
        run(**extra)
    return caught.value


def idx(request: RecordedRequest, path: str) -> bool:
    return (
        request.method == "POST"
        and request.url.host == OKTA
        and request.url.path == f"/idp/idx/{path}"
    )


def body(request: RecordedRequest) -> dict[str, Any]:
    parsed: dict[str, Any] = json.loads(request.body)
    return parsed


def passcode(request: RecordedRequest) -> Any:
    return (body(request).get("credentials") or {}).get("passcode")


def idx_state(remediation: list[dict[str, Any]], **extra: Any) -> httpx.Response:
    return idx_json(
        {
            "version": "1.0.0",
            "stateHandle": STATE_TOKEN,
            "remediation": {"type": "array", "value": remediation},
            **extra,
        }
    )


def form(name: str, path: str, value: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    return {
        "name": name,
        "href": f"https://{OKTA}/idp/idx/{path}",
        "method": "POST",
        "value": [*(value or []), STATE_HANDLE],
    }


def redirect(location: str, cookies: list[str] | None = None) -> httpx.Response:
    headers = [("location", location)] + [("set-cookie", c) for c in cookies or []]
    return httpx.Response(302, headers=headers)


def html(text: str, cookies: list[str] | None = None) -> httpx.Response:
    headers = [("content-type", "text/html")] + [("set-cookie", c) for c in cookies or []]
    return httpx.Response(200, headers=headers, text=text)


def replay(fake: FakeSso, request: RecordedRequest, path: str, payload: Any) -> httpx.Response:
    """What the fake Okta would have answered to `payload` at `path`."""
    return fake.transport.handle_request(
        httpx.Request(
            "POST",
            f"https://{OKTA}/idp/idx/{path}",
            headers=request.headers,
            content=json.dumps(payload).encode(),
        )
    )


def answer_password(fake: FakeSso, request: RecordedRequest) -> httpx.Response:
    return replay(
        fake,
        request,
        "challenge/answer",
        {"credentials": {"passcode": PASSWORD}, "stateHandle": STATE_TOKEN},
    )


# service providers


def test_follows_a_saml_request_the_service_provider_posts_to_okta() -> None:
    fake, run = setup()

    def route(request: RecordedRequest) -> httpx.Response | None:
        url = request.url
        if (
            request.method == "GET"
            and url.host == SP
            and url.path == "/login/index.php"
            and request.cookies.get("MoodleSession") != "authed"
        ):
            return html(
                f'<form method="post" action="https://{OKTA}{APP_PATH}">'
                '<input type="hidden" name="SAMLRequest" value="request">'
                f'<input type="hidden" name="RelayState" value="https://{SP}/my/"></form>',
                [
                    "MoodleSession=anon; Path=/; Secure; HttpOnly",
                    "MDL_SSP_SessID=ssp-1; Path=/; Secure; HttpOnly",
                ],
            )
        if request.method == "POST" and url.host == OKTA and url.path == APP_PATH:
            if parse_qs(request.body).get("SAMLRequest") != ["request"]:
                return httpx.Response(400, text="bad")
            return html(
                "<script>var stateToken = '02.id.abc\\x2Ddef';</script>",
                ["DT=dt-1; Path=/; Secure; HttpOnly"],
            )
        return None

    fake.set_override(route)
    result = run(device_token="dt-old")

    assert "MoodleSession" in [cookie.name for cookie in result.cookies]
    # Okta is known from the form's action, so it sees the device token from the first request.
    post = next(r for r in fake.requests if r.method == "POST" and r.url.path == APP_PATH)
    assert post.cookies.get("DT") == "dt-old"
    assert "sid" in [cookie.name for cookie in result.okta_session]


def test_signs_in_to_an_oidc_app_that_okta_returns_to_with_a_redirect() -> None:
    fake, run = setup()
    callback = f"https://{SP}/auth/oidc/callback"

    def route(request: RecordedRequest) -> httpx.Response | None:
        url, cookies = request.url, request.cookies
        if (
            url.host == SP
            and url.path == "/login/index.php"
            and cookies.get("MoodleSession") != "authed"
        ):
            return redirect(
                f"https://{OKTA}/oauth2/v1/authorize?client_id=moodle"
                f"&redirect_uri={quote(callback, safe='')}&state=s1"
            )
        if request.method == "GET" and url.host == OKTA and url.path == "/oauth2/v1/authorize":
            if cookies.get("sid") == "okta-session":
                return redirect(f"{callback}?code=c1&state=s1")
            return html("<script>var stateToken = '02.id.abc\\x2Ddef';</script>")
        if request.method == "GET" and url.host == OKTA and url.path == "/login/token/redirect":
            return redirect(
                f"{callback}?code=c1&state=s1", ["sid=okta-session; Path=/; Secure; HttpOnly"]
            )
        if url.host == SP and url.path == "/auth/oidc/callback":
            if url.params.get("code") != "c1":
                return httpx.Response(400, text="bad code")
            return redirect(f"https://{SP}/my/", ["MoodleSession=authed; Path=/; Secure; HttpOnly"])
        return None

    fake.set_override(route)
    result = run()

    session = {cookie.name: cookie.value for cookie in result.cookies}
    assert session.get("MoodleSession") == "authed"
    assert httpx.URL(result.landing_url).path == "/my/"
    assert "sid" in [cookie.name for cookie in result.okta_session]

    # With that Okta session, a second sign-in goes straight through.
    again = run(okta_session=result.okta_session)
    assert {c.name: c.value for c in again.cookies}.get("MoodleSession") == "authed"


def test_still_reports_a_url_that_never_leads_to_okta() -> None:
    fake, run = setup()
    fake.set_override(
        lambda request: html("<p>Public page</p>") if request.url.host == SP else None
    )
    error = rejection(run)

    assert error.code == "unexpected_step"
    assert not any(request.url.host == OKTA for request in fake.requests)


# sign-on policies


def test_skips_a_password_expiry_warning() -> None:
    fake, run = setup()
    warned = False

    def route(request: RecordedRequest) -> httpx.Response | None:
        nonlocal warned
        if idx(request, "challenge/answer") and not warned and passcode(request) == PASSWORD:
            warned = True
            return idx_state(
                [
                    form(
                        "reenroll-authenticator-warning",
                        "challenge/answer",
                        [{"name": "credentials"}],
                    ),
                    form("skip", "skip"),
                ]
            )
        if idx(request, "skip"):
            return answer_password(fake, request)
        return None

    fake.set_override(route)
    run()
    assert warned


def test_explains_an_expired_password_instead_of_answering_it() -> None:
    fake, run = setup()
    fake.set_override(
        lambda request: (
            idx_state(
                [form("reenroll-authenticator", "challenge/answer", [{"name": "credentials"}])]
            )
            if idx(request, "challenge/answer") and passcode(request) == PASSWORD
            else None
        )
    )
    error = rejection(run)

    assert error.code == "unexpected_step"
    assert "password has expired" in str(error).lower()
    assert PASSWORD not in str(error)


def test_explains_a_required_authenticator_enrollment() -> None:
    fake, run = setup()
    fake.set_override(
        lambda request: (
            idx_state(
                [
                    form(
                        "select-authenticator-enroll",
                        "credential/enroll",
                        [{"name": "authenticator", "options": []}],
                    )
                ]
            )
            if idx(request, "challenge/answer") and passcode(request) == PASSWORD
            else None
        )
    )
    error = rejection(run)

    assert error.code == "unexpected_step"
    assert "set up" in str(error).lower()


def test_skips_an_optional_authenticator_enrollment() -> None:
    fake, run = setup()
    offered = False

    def route(request: RecordedRequest) -> httpx.Response | None:
        nonlocal offered
        if idx(request, "challenge/answer") and not offered and passcode(request) == PASSWORD:
            offered = True
            return idx_state(
                [
                    form(
                        "select-authenticator-enroll",
                        "credential/enroll",
                        [{"name": "authenticator", "options": []}],
                    ),
                    form("skip", "skip"),
                ]
            )
        if idx(request, "skip"):
            return answer_password(fake, request)
        return None

    fake.set_override(route)
    run()
    assert offered


def _option(label: str, authenticator_id: str, related: str, method: str | None) -> dict[str, Any]:
    fields: list[dict[str, Any]] = [{"name": "id", "value": authenticator_id}]
    if method:
        fields.append({"name": "methodType", "value": method})
    return {"label": label, "value": {"form": {"value": fields}}, "relatesTo": related}


def test_chooses_the_password_from_select_authenticator_then_the_totp_authenticator() -> None:
    fake, run = setup()

    # identify -> choose among password and Google Authenticator -> password -> TOTP.
    def route(request: RecordedRequest) -> httpx.Response | None:
        if idx(request, "identify"):
            return idx_state(
                [
                    form(
                        "select-authenticator-authenticate",
                        "challenge",
                        [
                            {
                                "name": "authenticator",
                                "options": [
                                    _option(
                                        "Google", "aut-google", "$.authenticators.value[0]", "otp"
                                    ),
                                    _option(
                                        "Password",
                                        "aut-password",
                                        "$.authenticators.value[1]",
                                        "password",
                                    ),
                                ],
                            }
                        ],
                    )
                ],
                authenticators={
                    "value": [
                        {"key": "google_otp", "id": "aut-google"},
                        {"key": "okta_password", "id": "aut-password"},
                    ]
                },
            )
        if idx(request, "challenge") and body(request)["authenticator"].get("id") == "aut-password":
            return _password_challenge()
        return None

    fake.set_override(route)
    run()

    chosen = [body(r)["authenticator"]["id"] for r in fake.requests if idx(r, "challenge")]
    assert chosen == ["aut-password", "aut-google"]


def _password_challenge() -> httpx.Response:
    return idx_state(
        [
            {
                **form(
                    "challenge-authenticator",
                    "challenge/answer",
                    [{"name": "credentials", "form": {"value": [{"name": "passcode"}]}}],
                ),
                "relatesTo": ["$.currentAuthenticatorEnrollment"],
            }
        ],
        currentAuthenticatorEnrollment={"value": {"key": "okta_password", "id": "aut-password"}},
    )


def test_asks_okta_verify_for_a_totp_code_when_okta_asks_how_to_verify() -> None:
    fake, run = setup(enrollments=["okta_verify"])

    def route(request: RecordedRequest) -> httpx.Response | None:
        if idx(request, "challenge") and "methodType" not in body(request)["authenticator"]:
            return idx_state(
                [
                    form(
                        "authenticator-verification-data",
                        "challenge",
                        [
                            {
                                "name": "authenticator",
                                "form": {
                                    "value": [
                                        {"name": "id", "value": "aut-verify"},
                                        {
                                            "name": "methodType",
                                            "options": [{"value": "push"}, {"value": "totp"}],
                                        },
                                    ]
                                },
                            }
                        ],
                    )
                ]
            )
        if idx(request, "challenge/answer") and passcode(request) == PASSWORD:
            # Okta Verify offered without a method type in select-authenticator.
            return idx_state(
                [
                    form(
                        "select-authenticator-authenticate",
                        "challenge",
                        [
                            {
                                "name": "authenticator",
                                "options": [
                                    _option(
                                        "Okta Verify",
                                        "aut-verify",
                                        "$.authenticatorEnrollments.value[0]",
                                        None,
                                    )
                                ],
                            }
                        ],
                    )
                ],
                authenticatorEnrollments={"value": [{"key": "okta_verify", "id": "aut-verify"}]},
            )
        return None

    fake.set_override(route)
    run()

    methods = [body(r)["authenticator"] for r in fake.requests if idx(r, "challenge")]
    assert methods == [{"id": "aut-verify"}, {"id": "aut-verify", "methodType": "totp"}]


def test_answers_a_totp_challenge_before_the_password_when_okta_asks_for_it_first() -> None:
    fake, run = setup(enrollments=["google_otp"])
    answered_code = False

    def route(request: RecordedRequest) -> httpx.Response | None:
        nonlocal answered_code
        if idx(request, "identify"):
            # Authenticator-first: Okta goes straight to Google Authenticator.
            return replay(
                fake,
                request,
                "challenge",
                {"authenticator": {"id": "aut-google"}, "stateHandle": STATE_TOKEN},
            )
        if idx(request, "challenge/answer") and not answered_code and passcode(request) != PASSWORD:
            answered_code = True
            return _password_challenge()
        if idx(request, "challenge/answer") and answered_code and passcode(request) == PASSWORD:
            return idx_json(
                {
                    "stateHandle": STATE_TOKEN,
                    "success": {
                        "name": "success-redirect",
                        "href": f"https://{OKTA}/login/token/redirect?stateToken={STATE_TOKEN}",
                    },
                }
            )
        return None

    fake.set_override(route)
    run()
    assert answered_code


def test_reports_a_locked_account_as_credentials_rejected_without_retrying() -> None:
    fake, run = setup(password_on_identify=True)
    locked = {
        "version": "1.0.0",
        "stateHandle": STATE_TOKEN,
        "messages": {
            "value": [{"class": "ERROR", "i18n": {"key": "errors.E0000119"}, "message": "locked"}]
        },
    }
    fake.set_override(
        lambda request: httpx.Response(403, json=locked) if idx(request, "identify") else None
    )
    error = rejection(run)

    assert error.code == "credentials_rejected"
    assert len([r for r in fake.requests if idx(r, "identify")]) == 1


def test_reports_oktas_rate_limit_as_http_429_not_as_rejected_credentials() -> None:
    fake, run = setup()
    limited = {
        "messages": {"value": [{"class": "ERROR", "i18n": {"key": "E0000047"}, "message": "rate"}]}
    }
    fake.set_override(
        lambda request: httpx.Response(429, json=limited) if idx(request, "identify") else None
    )
    assert rejection(run).code == "http_429"


def test_names_an_external_identity_provider_routing_rule() -> None:
    fake, run = setup()
    redirect_idp = {
        "name": "redirect-idp",
        "type": "SAML2",
        "href": "https://idp.example.org/sso",
        "method": "GET",
    }
    fake.set_override(
        lambda request: idx_state([redirect_idp]) if idx(request, "introspect") else None
    )
    error = rejection(run)

    assert error.code == "unexpected_step"
    assert "redirect-idp" in str(error)


def test_ignores_fastpass_and_other_forms_okta_offers_next_to_identify() -> None:
    fake, run = setup()
    inner = False

    def route(request: RecordedRequest) -> httpx.Response | None:
        nonlocal inner
        if not idx(request, "introspect") or inner:
            return None
        inner = True
        state = json.loads(replay(fake, request, "introspect", body(request)).content)
        state["remediation"]["value"][:0] = [
            {
                "name": "launch-authenticator",
                "href": "https://127.0.0.1:8769/challenge",
                "method": "GET",
            },
            {
                "name": "select-enroll-profile",
                "href": f"https://{OKTA}/idp/idx/enroll",
                "value": [STATE_HANDLE],
            },
            {
                "name": "unlock-account",
                "href": f"https://{OKTA}/idp/idx/unlock-account",
                "value": [STATE_HANDLE],
            },
        ]
        return idx_json(state)

    fake.set_override(route)
    run()
    assert not any(request.url.host == "127.0.0.1" for request in fake.requests)
