"""okta_auth — MCP server for Okta SSO authentication with persistent session management.

Provides tools for AI agents to sign in through Okta over plain HTTP, persist the
target site's cookies, and verify session validity. Sessions are stored per-domain
in ~/.okta-auth/sessions/.
"""

import json
from typing import Optional

from mcp.server.fastmcp import FastMCP
from mcp.types import ToolAnnotations

from okta_auth.auth import session_store
from okta_auth.auth.login import perform_login, verify_session
from okta_auth.credential_store import StoredCredentials
from okta_auth.credential_store import load_credentials as load_stored_credentials
from okta_auth.runtime_credentials import resolve_credentials
from okta_auth.settings import load_settings, uses_keyring

mcp = FastMCP("okta_auth")


# ── Tools ─────────────────────────────────────────────────────────────────────


@mcp.tool(
    name="okta_login",
    annotations=ToolAnnotations(
        title="Okta SSO Login",
        readOnlyHint=False,
        destructiveHint=False,
        idempotentHint=True,
        openWorldHint=True,
    ),
)
async def okta_login(
    url: str,
    username: Optional[str] = None,
    password: Optional[str] = None,
    totp_secret: Optional[str] = None,
) -> str:
    """Authenticate to a website via Okta SSO and persist the session.

    Signs in over plain HTTP (no browser): follows the URL to Okta, answers Okta
    Identity Engine with the password and a TOTP code if configured, posts the SAML
    response back, and saves the site's cookies. Sessions are stored per-domain in
    ~/.okta-auth/sessions/. Only TOTP second factors work; push, SMS and email don't.

    Never retry automatically when error_code is "credentials_rejected": Okta locks
    the account after a few failed attempts. Ask the user to fix the credentials.

    Credentials are resolved in order: explicit parameter → environment variable
    → OS keyring when the local provider is set to `keyring`. When the provider
    is set to `op`, launch the server through `op run` so the environment is
    populated at process start.

    Args:
        url: Target URL to authenticate against (e.g., 'https://portal.company.com').
        username: Okta username or email. Falls back to OKTA_USERNAME or stored keyring data.
        password: Okta password. Falls back to OKTA_PASSWORD or stored keyring data.
        totp_secret: Base32 TOTP secret for automated MFA. Falls back to OKTA_TOTP_SECRET or stored keyring data.

    Returns:
        JSON: {"success": bool, "domain_key": str|null, "message": str, "url": str}
        On failure also "error_code": credentials_rejected, passcode_rejected,
        mfa_unsupported, unexpected_step, handoff_failed, network, http_<n>, or null.
    """
    app_settings = load_settings()
    stored_credentials = (
        load_stored_credentials() if uses_keyring(app_settings) else StoredCredentials()
    )
    credentials = resolve_credentials(
        explicit_username=username,
        explicit_password=password,
        explicit_totp_secret=totp_secret,
        app_settings=app_settings,
        stored_credentials=stored_credentials,
    )
    resolved_username, resolved_password = credentials.username, credentials.password

    if not resolved_username or not resolved_password:
        provider_hint = "run `okta config`."
        if app_settings.credential_provider == "op" and app_settings.op_env_file:
            provider_hint = (
                "run `op run --env-file="
                f"{app_settings.op_env_file} -- uvx --from okta-auth-cli okta-auth`."
            )
        return json.dumps(
            {
                "success": False,
                "domain_key": None,
                "message": (
                    "username and password are required. Pass them as arguments, set "
                    f"OKTA_USERNAME / OKTA_PASSWORD, or {provider_hint}"
                ),
                "url": url,
            },
            indent=2,
        )

    result = await perform_login(
        url=url,
        username=resolved_username,
        password=resolved_password,
        totp_secret=credentials.totp_secret,
        totp_code=credentials.totp_code(),
    )
    return json.dumps(result, indent=2)


@mcp.tool(
    name="okta_check_session",
    annotations=ToolAnnotations(
        title="Check Okta Session Validity",
        readOnlyHint=True,
        destructiveHint=False,
        idempotentHint=True,
        openWorldHint=True,
    ),
)
async def okta_check_session(url: str) -> str:
    """Verify if a stored session for a URL is still valid.

    Requests the URL with live stored cookies and checks for a successful
    response on the same host without a login form.

    Args:
        url: URL to verify session against. Must match the URL used during login.

    Returns:
        JSON: {"valid": bool, "domain_key": str|null, "message": str, "url": str}
    """
    result = await verify_session(url=url)
    return json.dumps(result, indent=2)


@mcp.tool(
    name="okta_list_sessions",
    annotations=ToolAnnotations(
        title="List Stored Sessions",
        readOnlyHint=True,
        destructiveHint=False,
        idempotentHint=True,
        openWorldHint=False,
    ),
)
async def okta_list_sessions() -> str:
    """List all stored authentication sessions.

    Returns metadata for every saved session including the domain, when it was
    saved, and cookie/origin counts. Does NOT verify if sessions are still valid —
    use okta_check_session for that.

    Returns:
        JSON: {"count": int, "sessions": [{url, domain_key, saved_at_iso, cookie_count, origin_count}]}
    """
    sessions = session_store.list_sessions()
    return json.dumps({"count": len(sessions), "sessions": sessions}, indent=2)


@mcp.tool(
    name="okta_delete_session",
    annotations=ToolAnnotations(
        title="Delete Stored Session",
        readOnlyHint=False,
        destructiveHint=True,
        idempotentHint=True,
        openWorldHint=False,
    ),
)
async def okta_delete_session(url: str) -> str:
    """Delete a stored session for a given URL.

    Removes the session file and metadata from ~/.okta-auth/sessions/.
    The agent will need to re-authenticate to access the service again.

    Args:
        url: URL whose stored session should be deleted.

    Returns:
        JSON: {"deleted": bool, "message": str, "url": str}
    """
    deleted = session_store.delete_session(url)
    msg = "Session deleted" if deleted else "No session found for this URL"
    return json.dumps({"deleted": deleted, "message": msg, "url": url}, indent=2)


@mcp.tool(
    name="okta_get_cookies",
    annotations=ToolAnnotations(
        title="Get Session Cookies",
        readOnlyHint=True,
        destructiveHint=False,
        idempotentHint=True,
        openWorldHint=False,
    ),
)
async def okta_get_cookies(
    url: str,
    domain_filter: Optional[str] = None,
) -> str:
    """Retrieve cookies from a stored session.

    Returns the raw cookie data from a stored session. Useful for making
    authenticated HTTP requests.

    Args:
        url: URL whose stored session cookies to retrieve.
        domain_filter: Optional domain substring to filter cookies (e.g., 'okta.com').

    Returns:
        JSON: {"count": int, "cookies": [{name, value, domain, path, ...}], "url": str}
        Error: {"error": str, "url": str}
    """
    session_path = session_store.get_session_path(url)
    if not session_path:
        return json.dumps(
            {
                "error": "No stored session found for this URL",
                "url": url,
            },
            indent=2,
        )

    try:
        with open(session_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as exc:
        return json.dumps(
            {
                "error": f"Failed to read session file: {exc}",
                "url": url,
            },
            indent=2,
        )

    cookies = data.get("cookies", [])
    if domain_filter:
        cookies = [c for c in cookies if domain_filter.lower() in c.get("domain", "").lower()]

    return json.dumps(
        {
            "count": len(cookies),
            "cookies": cookies,
            "url": url,
        },
        indent=2,
    )


def main():
    mcp.run()


if __name__ == "__main__":
    main()
