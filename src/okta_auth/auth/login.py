"""Sign in and check sessions over plain HTTP, storing results in the session store.

The protocol lives in okta_auth.core; this module connects it to the local
session and device-token files for the CLI, the MCP server and the adapter.
"""

from __future__ import annotations

import time
from typing import Any

import httpx

from okta_auth.auth import session_store
from okta_auth.core import OktaSignInError, sign_in
from okta_auth.core.client import Client


async def perform_login(
    url: str,
    username: str,
    password: str,
    totp_secret: str | None = None,
    *,
    transport: httpx.AsyncBaseTransport | None = None,
) -> dict[str, Any]:
    """Sign in through Okta and store the target site's cookies.

    Never retries. Returns {success, domain_key, message, url}, plus `error_code`
    (an OktaSignInError code, or None for bad input) on failure. Do not retry
    automatically after `credentials_rejected`: Okta locks the account after a
    few attempts.
    """
    try:
        result = await sign_in(
            url=url,
            username=username,
            password=password,
            totp_secret=totp_secret,
            device_token=session_store.read_device_token(url),
            transport=transport,
        )
    except OktaSignInError as error:
        return _login_failure(url, f"{error.code}: {error}", error.code)
    except ValueError as error:
        return _login_failure(url, str(error), None)

    session_store.save_device_token(url, result.device_token)
    domain_key = session_store.save_session(url, result.cookies)
    return {
        "success": True,
        "domain_key": domain_key,
        "message": f"Session saved for {domain_key}",
        "url": url,
    }


async def verify_session(
    url: str,
    *,
    transport: httpx.AsyncBaseTransport | None = None,
) -> dict[str, Any]:
    """Check whether the stored cookies still sign in to the URL's site.

    Signed in means the URL no longer sends us to another host (Okta), the same
    check sign_in finishes with. Returns {valid, domain_key, message, url}.
    """
    if not session_store.get_session_path(url):
        return {
            "valid": False,
            "domain_key": None,
            "message": "No stored session found for this URL",
            "url": url,
        }

    domain_key = session_store._domain_key(url)
    try:
        target = httpx.URL(url)
        async with Client(transport, time.time) as client:
            for cookie in session_store.load_cookies(url):
                client.jar.set(cookie)
            page = await client.follow(target)
    except OktaSignInError as error:
        message = f"Session check failed: {error.code}: {error}"
        return {"valid": False, "domain_key": domain_key, "message": message, "url": url}
    except httpx.InvalidURL:
        message = "Session check failed: not a valid URL"
        return {"valid": False, "domain_key": domain_key, "message": message, "url": url}

    active = page.url.host == target.host and page.status < 400
    return {
        "valid": active,
        "domain_key": domain_key,
        "message": "Session is active" if active else "Session expired or invalid",
        "url": url,
    }


def _login_failure(url: str, reason: str, code: str | None) -> dict[str, Any]:
    return {
        "success": False,
        "domain_key": None,
        "message": f"Login failed: {reason}",
        "url": url,
        "error_code": code,
    }
