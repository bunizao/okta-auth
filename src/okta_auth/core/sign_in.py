from __future__ import annotations

import json
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlencode

import httpx

from .client import Client, Page
from .cookies import Cookie
from .errors import OktaSignInError, where
from .html import read_saml_form, read_state_token
from .idx import Credentials, IdxState, Sends, error_keys, next_step
from .totp import base32_decode


@dataclass
class SignInResult:
    # Cookies the target site set, and only those.
    cookies: list[Cookie]
    # Okta's DT cookie. Store it and pass it back next time.
    device_token: str | None


MAX_IDX_STEPS = 8
IDX_CONTENT_TYPE = "application/ion+json; okta-version=1.0.0"


async def sign_in(
    *,
    url: str,
    username: str,
    password: str,
    totp_secret: str | None = None,
    device_token: str | None = None,
    transport: httpx.AsyncBaseTransport | None = None,
    now: Callable[[], float] = time.time,
) -> SignInResult:
    """Signs in to a SAML service provider through Okta Identity Engine with plain
    HTTP: no browser. Raises OktaSignInError; see its codes for what's retryable.

    url: a page on the target site that sends signed-out visitors to Okta,
        e.g. https://learning.monash.edu/login/index.php
    totp_secret: base32 secret of a Google Authenticator (or Okta Verify TOTP) enrollment.
    device_token: the `device_token` from an earlier sign-in. Okta keys "new device"
        checks and sign-on emails to it.
    transport: an httpx transport, for tests.
    now: seconds since the epoch. Drives TOTP codes and cookie expiry.
    """
    target = _https_url(url)
    # Fail on a malformed secret before anything reaches Okta.
    if totp_secret is not None:
        base32_decode(totp_secret)

    credentials = Credentials(username, password, totp_secret)
    async with Client(transport, now, device_token) as client:
        acs = await hand_off(client, await client.follow(target), credentials, now)

        # Signed in means the page that sent us to Okta no longer does.
        check = await client.follow(target)
        if check.url.host != target.host or check.status >= 400:
            raise OktaSignInError(
                "handoff_failed",
                f"{where(target)} is still not signed in after the SAML post "
                f"({where(acs.url)} answered {acs.status}; {where(target)} now leads to "
                f"{where(check.url)}, {check.status})",
            )

        return SignInResult(
            cookies=client.jar.list(target.host),
            device_token=device_token_of(client, device_token),
        )


async def hand_off(
    client: Client, page: Page, credentials: Credentials, now: Callable[[], float]
) -> Page:
    """Takes Okta's first page through sign-in (unless Okta already has a session and
    answers with the SAML form) and posts the SAMLResponse to the service
    provider's ACS. Returns the ACS's answer, redirects followed."""
    if page.status >= 400:
        raise http_error(page.status, page.url)

    if not read_saml_form(page.body):
        state_token = read_state_token(page.body, page.url)
        client.use_idp(page.url.host)
        page = await _authenticate(client, _origin(page.url), state_token, credentials, now)

    form = read_saml_form(page.body)
    if not form:
        raise OktaSignInError(
            "unexpected_step", f"Okta finished without a SAML form at {where(page.url)}"
        )
    return await client.follow(
        page.url.join(form.action),
        method="POST",
        headers={"content-type": "application/x-www-form-urlencoded"},
        body=urlencode(form.fields),
    )


def device_token_of(client: Client, previous: str | None) -> str | None:
    """Okta's DT cookie after this sign-in, or the one the caller passed in."""
    current = client.jar.get(client.idp_host, "DT") if client.idp_host else None
    return current.value if current else previous


async def _authenticate(
    client: Client,
    origin: httpx.URL,
    state_token: str,
    credentials: Credentials,
    now: Callable[[], float],
) -> Page:
    """Walks the IDX remediations until Okta reports success, then follows Okta's
    success link to the page carrying the SAML form."""
    state = await _post(
        client, origin.join("/idp/idx/introspect"), {"stateToken": state_token}, None
    )
    steps = 0
    while True:
        success = state.get("success")
        if isinstance(success, dict) and success.get("href"):
            return await client.follow(_okta_url(str(success["href"]), origin))
        if steps == MAX_IDX_STEPS:
            raise OktaSignInError(
                "unexpected_step", f"Okta still wants more after {MAX_IDX_STEPS} steps"
            )
        step = next_step(state, credentials, now())
        state = await _post(client, _okta_url(step.href, origin), step.body, step.sends)
        steps += 1


async def _post(client: Client, url: httpx.URL, body: dict[str, Any], sends: Sends) -> IdxState:
    response = await client.send(
        url,
        method="POST",
        headers={"accept": IDX_CONTENT_TYPE, "content-type": IDX_CONTENT_TYPE},
        body=json.dumps(body),
    )
    try:
        data = response.json()
    except ValueError:
        data = None
    state: IdxState | None = data if isinstance(data, dict) else None

    keys = error_keys(state) if state is not None else []
    if response.is_success and state is not None and not keys:
        return state
    if state is None:
        if not response.is_success:
            raise http_error(response.status_code, url)
        raise OktaSignInError("unexpected_step", f"{where(url)} returned an invalid IDX response")
    if response.status_code == 429 or response.status_code >= 500:
        raise http_error(response.status_code, url)

    reason = f" ({', '.join(keys)})" if keys else ""
    if sends in ("identifier", "password"):
        rejected = "username or password" if sends == "password" else "username"
        raise OktaSignInError(
            "credentials_rejected",
            f"Okta rejected the {rejected}{reason}. "
            "Not retried: repeated attempts can lock the account.",
        )
    if sends == "passcode":
        raise OktaSignInError("passcode_rejected", f"Okta rejected the one-time code{reason}")
    if not response.is_success:
        raise http_error(response.status_code, url, reason)
    raise OktaSignInError("unexpected_step", f"Okta reported an error at {where(url)}{reason}")


def _okta_url(href: str, origin: httpx.URL) -> httpx.URL:
    """Credentials only ever go to the Okta host that served the sign-in page."""
    try:
        url = origin.join(href)
    except httpx.InvalidURL:
        url = None
    if url is None or _origin(url) != origin:
        host = url.host if url is not None else "an invalid URL"
        raise OktaSignInError("unexpected_step", f"Okta pointed a form at another host ({host})")
    return url


def http_error(status: int, url: httpx.URL, detail: str = "") -> OktaSignInError:
    return OktaSignInError(f"http_{status}", f"{where(url)} answered HTTP {status}{detail}")


def _origin(url: httpx.URL) -> httpx.URL:
    return httpx.URL(scheme=url.scheme, host=url.host, port=url.port, path="/")


def _https_url(url: str) -> httpx.URL:
    try:
        parsed = httpx.URL(url)
    except httpx.InvalidURL:
        raise ValueError("url is not a valid URL") from None
    if parsed.scheme != "https" or not parsed.host:
        raise ValueError("url must be https")
    return parsed
