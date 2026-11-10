"""`okta export` hands the raw password and TOTP secret to a program that signs in
by itself, such as a Worker:

    okta export --dangerously-print-password-and-totp-secret | npx wrangler secret bulk

The flag names what it does, and a terminal never gets the output."""

from __future__ import annotations

import json

from okta_auth.runtime_credentials import RuntimeCredentials

EXPORT_FLAG = "dangerously-print-password-and-totp-secret"


def export_refusal(confirmed: bool, stdout_is_tty: bool) -> str | None:
    """Why export won't run, or None when it may."""
    if not confirmed:
        return (
            "export prints your Okta password and TOTP secret. To hand them to a program "
            "you trust, pipe them there:\n"
            f"  okta export --{EXPORT_FLAG} | npx wrangler secret bulk"
        )
    if stdout_is_tty:
        return (
            "refusing to print your password and TOTP secret to a terminal; "
            "pipe the output into the program that needs it"
        )
    return None


def export_json(credentials: RuntimeCredentials) -> str | None:
    """The variable names a Worker reads, as one JSON object (what `wrangler secret
    bulk` takes). The same output as the TypeScript CLI's."""
    if not credentials.username or not credentials.password:
        return None
    values = {"OKTA_USERNAME": credentials.username, "OKTA_PASSWORD": credentials.password}
    if credentials.totp_secret:
        values["OKTA_TOTP_SECRET"] = credentials.totp_secret
    return json.dumps(values, separators=(",", ":"))
