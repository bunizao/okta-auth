from __future__ import annotations

import base64
import binascii
import re
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Literal
from urllib.parse import urlencode

import httpx

from .client import Client, Page
from .errors import OktaSignInError, where
from .html import decode_entities, read_saml_form
from .idx import Credentials
from .sign_in import (
    Progress,
    device_token_of,
    hand_off,
    http_error,
    keeping_device_token,
    quiet,
)
from .totp import base32_decode

GlobalProtectInterface = Literal["gateway", "portal"]


@dataclass
class GlobalProtectResult:
    # The interface whose prelogin started the sign-in. With `cookie_name` it makes
    # OpenConnect's --usergroup, e.g. gateway:prelogin-cookie.
    interface: GlobalProtectInterface
    # The user name the ACS reported; OpenConnect's --user.
    user: str
    # "prelogin-cookie" or "portal-userauthcookie".
    cookie_name: str
    # One-time: OpenConnect reads it as the password (--passwd-on-stdin).
    cookie: str
    device_token: str | None


PRELOGIN_PATHS: dict[GlobalProtectInterface, str] = {
    "gateway": "/ssl-vpn/prelogin.esp",
    "portal": "/global-protect/prelogin.esp",
}

# What the GlobalProtect client sends; some portals answer other clients differently.
PRELOGIN_FIELDS = {
    "tmp": "tmp",
    "kerberos-support": "yes",
    "ipv6-support": "yes",
    "clientVer": "4100",
    "clientos": "Mac",
}

COOKIE_NAMES = ("prelogin-cookie", "portal-userauthcookie")
RESULT_FIELDS = ("saml-auth-status", "saml-username", *COOKIE_NAMES)


@dataclass
class _SamlStart:
    interface: GlobalProtectInterface
    method: str
    # A URL for the REDIRECT binding, an auto-submitting HTML form for POST.
    request: str


async def sign_in_globalprotect(
    *,
    server: str,
    username: str,
    password: str,
    interface: GlobalProtectInterface | None = None,
    totp_secret: str | None = None,
    totp_code: Callable[[], Awaitable[str]] | None = None,
    device_token: str | None = None,
    transport: httpx.AsyncBaseTransport | None = None,
    now: Callable[[], float] = time.time,
    progress: Progress = quiet,
) -> GlobalProtectResult:
    """Signs in to a GlobalProtect portal or gateway that uses Okta SAML, with plain
    HTTP, and returns the cookie OpenConnect connects with:

      openconnect --protocol=gp --user=<user> --usergroup=<interface>:<cookie_name> \\
        --passwd-on-stdin <server>   # and <cookie> on stdin

    server: the portal or gateway host, e.g. vpn.gp.monash.edu
    interface: whose prelogin to ask. Default: the gateway's, then the portal's if
        the gateway doesn't offer SAML.

    Raises OktaSignInError like sign_in does; `handoff_failed` here means the ACS
    answered without a cookie.
    """
    base = _server_url(server)
    if totp_secret is not None:
        base32_decode(totp_secret)

    credentials = Credentials(username, password, totp_secret, totp_code)
    async with (
        Client(transport, now, device_token) as client,
        keeping_device_token(client, device_token),
    ):
        interfaces: list[GlobalProtectInterface] = (
            [interface] if interface else ["gateway", "portal"]
        )
        start = await _prelogin(client, base, interfaces, progress)
        acs = await hand_off(client, await _open_okta(client, start), credentials, now, progress)
        user, cookie_name, cookie = _read_result(acs)
        return GlobalProtectResult(
            interface=start.interface,
            user=user,
            cookie_name=cookie_name,
            cookie=cookie,
            device_token=device_token_of(client, device_token),
        )


async def _prelogin(
    client: Client,
    base: httpx.URL,
    interfaces: list[GlobalProtectInterface],
    progress: Progress,
) -> _SamlStart:
    """Asks each interface's prelogin in turn and returns the first SAML request.
    Nothing reaches Okta until one offers SAML."""
    asked: list[httpx.URL] = []
    for name in interfaces:
        url = base.join(PRELOGIN_PATHS[name])
        asked.append(url)
        progress(f"Asking the {name} at {base.host} for SAML sign-in")
        page = await client.follow(
            url,
            method="POST",
            headers={
                "user-agent": "PAN GlobalProtect",
                "content-type": "application/x-www-form-urlencoded",
            },
            body=urlencode(PRELOGIN_FIELDS),
        )
        if page.status == 429 or page.status >= 500:
            raise http_error(page.status, page.url)

        method = _xml_text(page.body, "saml-auth-method")
        request = _xml_text(page.body, "saml-request")
        if _xml_text(page.body, "status") == "Success" and method and request:
            return _SamlStart(interface=name, method=method, request=_decode_base64(request, url))
    raise OktaSignInError(
        "unexpected_step", f"{' and '.join(where(url) for url in asked)} did not offer SAML sign-in"
    )


async def _open_okta(client: Client, start: _SamlStart) -> Page:
    """Delivers the SAML request to Okta and returns Okta's first page."""
    if start.method == "REDIRECT":
        return await client.follow(_absolute_url(start.request))
    if start.method != "POST":
        raise OktaSignInError("unexpected_step", "GlobalProtect asked for an unknown SAML binding")

    form = read_saml_form(start.request, "SAMLRequest")
    if not form:
        raise OktaSignInError(
            "unexpected_step", "GlobalProtect's SAML request has no SAMLRequest form"
        )
    url = _absolute_url(form.action)
    # The SAMLRequest travels in the body, so Client.send can't spot Okta itself.
    client.use_idp(url.host)
    return await client.follow(
        url,
        method="POST",
        headers={"content-type": "application/x-www-form-urlencoded"},
        body=urlencode(form.fields),
    )


def _read_result(acs: Page) -> tuple[str, str, str]:
    """The ACS reports in response headers, or in an HTML comment of <tag>value</tag>
    pairs on older versions. An unused cookie field holds the literal "empty".
    Returns (user, cookie_name, cookie)."""
    comments = "".join(re.findall(r"<!--([\s\S]*?)-->", acs.body))
    values: dict[str, str] = {}
    for name in RESULT_FIELDS:
        value = acs.headers.get(name)
        if value is None:
            value = _xml_text(comments, name)
        if value and value != "empty":
            values[name] = value

    status = values.get("saml-auth-status")
    cookie_name = next((name for name in COOKIE_NAMES if values.get(name)), None)
    user = values.get("saml-username")
    if status in (None, "1") and cookie_name and user:
        return user, cookie_name, values[cookie_name]
    shown = status if status is not None and re.fullmatch(r"-?[0-9]+", status) else "missing"
    raise OktaSignInError(
        "handoff_failed",
        f"{where(acs.url)} returned no GlobalProtect cookie after the SAML post "
        f"(HTTP {acs.status}, saml-auth-status {shown})",
    )


def _xml_text(xml: str, tag: str) -> str | None:
    match = re.search(f"<{re.escape(tag)}>([^<]*)</{re.escape(tag)}>", xml, re.IGNORECASE)
    return decode_entities(match.group(1).strip()) if match else None


def _decode_base64(text: str, source: httpx.URL) -> str:
    try:
        return base64.b64decode("".join(text.split()), validate=True).decode("utf-8")
    except (binascii.Error, UnicodeDecodeError):
        raise OktaSignInError(
            "unexpected_step", f"{where(source)} sent a SAML request that is not base64 text"
        ) from None


def _absolute_url(text: str) -> httpx.URL:
    try:
        url = httpx.URL(text)
    except httpx.InvalidURL:
        url = None
    if url is None or not url.is_absolute_url:
        raise OktaSignInError(
            "unexpected_step", "GlobalProtect's SAML request points at no absolute URL"
        )
    return url


def _server_url(server: str) -> httpx.URL:
    try:
        base = httpx.URL(f"https://{server}/")
    except httpx.InvalidURL:
        base = None
    if base is None or base.netloc.decode("ascii") != server.lower():
        raise ValueError("server must be a host name such as vpn.example.edu")
    return base
