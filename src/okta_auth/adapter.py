"""Local adapter API for reusing okta-auth sessions from other CLIs."""

from __future__ import annotations

import asyncio
import json
from typing import Any
from urllib.parse import urlparse

from okta_auth.auth.login import perform_login, verify_session
from okta_auth.auth.session_store import get_session_path
from okta_auth.runtime_credentials import resolve_runtime_credentials
from okta_auth.settings import AppSettings


class OktaAdapterError(RuntimeError):
    """Raised when okta-auth cannot provide a usable session."""


def get_cookies(url: str, *, target_domain_only: bool = True) -> list[dict[str, Any]]:
    """Return cookies stored for a URL from okta-auth's session store."""
    session_path = get_session_path(url)
    if not session_path:
        return []

    try:
        with open(session_path, "r", encoding="utf-8") as file:
            data = json.load(file)
    except (OSError, json.JSONDecodeError) as exc:
        raise OktaAdapterError(f"Failed to read stored okta-auth session: {exc}") from exc

    cookies = data.get("cookies")
    if not isinstance(cookies, list):
        return []

    if not target_domain_only:
        return [cookie for cookie in cookies if isinstance(cookie, dict)]

    host = _target_host(url)
    return [
        cookie
        for cookie in cookies
        if isinstance(cookie, dict) and _domain_matches_host(cookie.get("domain"), host)
    ]


def get_cookie_value(url: str, cookie_name: str, *, target_domain_only: bool = True) -> str | None:
    """Return a single cookie value from the stored okta-auth session."""
    host = _target_host(url)
    preferred: str | None = None

    for cookie in get_cookies(url, target_domain_only=target_domain_only):
        if cookie.get("name") != cookie_name:
            continue

        value = cookie.get("value")
        if not isinstance(value, str) or not value:
            continue

        cookie_domain = cookie.get("domain")
        if preferred is None:
            preferred = value
        if _is_exact_host_match(cookie_domain, host):
            return value

    return preferred


def ensure_login(
    url: str,
    *,
    headed: bool = False,
    timeout_ms: int = 60000,
) -> dict[str, Any]:
    """Ensure a valid okta-auth session exists for the URL."""
    if get_session_path(url):
        status = asyncio.run(verify_session(url=url, timeout_ms=min(timeout_ms, 30000)))
        if status.get("valid"):
            return {
                "success": True,
                "domain_key": status.get("domain_key"),
                "message": "Session already active",
                "url": url,
                "performed_login": False,
            }

    username, password, totp_secret, app_settings = _resolve_credentials()
    if not username or not password:
        raise OktaAdapterError(_missing_credentials_message(app_settings))

    result = asyncio.run(
        perform_login(
            url=url,
            username=username,
            password=password,
            totp_secret=totp_secret,
            headed=headed,
            timeout_ms=timeout_ms,
        )
    )
    if not result.get("success"):
        raise OktaAdapterError(str(result.get("message") or "okta-auth login failed"))

    payload = dict(result)
    payload["performed_login"] = True
    return payload


def _resolve_credentials() -> tuple[str | None, str | None, str | None, AppSettings]:
    username, password, totp_secret, app_settings = resolve_runtime_credentials()
    return (
        username,
        password,
        totp_secret,
        app_settings,
    )


def _missing_credentials_message(app_settings: AppSettings) -> str:
    provider_hint = "run `okta config`."
    if app_settings.credential_provider == "op" and app_settings.op_env_file:
        provider_hint = (
            "run `op run --env-file="
            f"{app_settings.op_env_file} -- <your command>` so OKTA_* variables are available."
        )

    return (
        "okta-auth could not resolve credentials. Set OKTA_USERNAME / OKTA_PASSWORD, "
        f"or {provider_hint}"
    )


def _target_host(url: str) -> str:
    parsed = urlparse(url)
    return (parsed.hostname or parsed.netloc or url).lower()


def _domain_matches_host(cookie_domain: object, host: str) -> bool:
    if not isinstance(cookie_domain, str):
        return False

    normalized = cookie_domain.lstrip(".").lower()
    return normalized == host or host.endswith(f".{normalized}")


def _is_exact_host_match(cookie_domain: object, host: str) -> bool:
    if not isinstance(cookie_domain, str):
        return False
    return cookie_domain.lstrip(".").lower() == host
