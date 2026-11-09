from __future__ import annotations

import httpx

# Codes, as in the TypeScript reference:
#   credentials_rejected  Okta refused the username or password. Never retry
#                         automatically: each attempt counts towards Okta's lockout limit.
#   passcode_rejected     Okta refused the one-time code (wrong secret, clock skew, or a reused code).
#   mfa_unsupported       Okta wants an authenticator this package can't answer (push, SMS, email...).
#   unexpected_step       Okta asked for something this package doesn't know how to answer.
#   handoff_failed        Okta signed in, but the target site is still not signed in afterwards.
#   network               The request timed out or never got an answer.
#   http_<n>              A server answered with HTTP status <n>.


class OktaSignInError(Exception):
    """A sign-in failure with a stable `code`.

    Messages name hosts, paths, IDX form names and Okta i18n keys only. They never
    carry passwords, one-time codes, the TOTP secret, state tokens or cookie values.
    """

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


def where(url: httpx.URL) -> str:
    """Host and path only: query strings carry SAMLRequest, state tokens and the like."""
    return f"{url.host}{url.path}"
