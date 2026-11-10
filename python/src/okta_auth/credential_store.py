"""Secure local credential storage backed by the OS keyring."""

from __future__ import annotations

from dataclasses import dataclass

import keyring
from keyring.errors import KeyringError, NoKeyringError, PasswordDeleteError

SERVICE_NAME = "okta-auth"
_PROBE_ACCOUNT = "__probe__"
_USERNAME_ACCOUNT = "username"
_PASSWORD_ACCOUNT = "password"
_TOTP_ACCOUNT = "totp_secret"


class CredentialStoreError(RuntimeError):
    """Raised when the OS keyring cannot be used safely."""


@dataclass
class StoredCredentials:
    username: str | None = None
    password: str | None = None
    totp_secret: str | None = None


def get_store_status() -> dict[str, object]:
    """Return availability and non-sensitive keyring metadata."""
    try:
        keyring.get_password(SERVICE_NAME, _PROBE_ACCOUNT)
    except (NoKeyringError, KeyringError) as exc:
        return {
            "available": False,
            "backend": keyring.get_keyring().__class__.__name__,
            "error": str(exc),
        }

    stored = load_credentials()
    return {
        "available": True,
        "backend": keyring.get_keyring().__class__.__name__,
        "error": None,
        "username": stored.username,
        "password_stored": bool(stored.password),
        "totp_secret_stored": bool(stored.totp_secret),
    }


def load_credentials() -> StoredCredentials:
    """Load credentials from the OS keyring when available."""
    try:
        return StoredCredentials(
            username=keyring.get_password(SERVICE_NAME, _USERNAME_ACCOUNT),
            password=keyring.get_password(SERVICE_NAME, _PASSWORD_ACCOUNT),
            totp_secret=keyring.get_password(SERVICE_NAME, _TOTP_ACCOUNT),
        )
    except (NoKeyringError, KeyringError):
        return StoredCredentials()


def save_credentials(username: str, password: str, totp_secret: str | None) -> None:
    """Persist credentials in the OS keyring."""
    _require_store()
    try:
        keyring.set_password(SERVICE_NAME, _USERNAME_ACCOUNT, username)
        keyring.set_password(SERVICE_NAME, _PASSWORD_ACCOUNT, password)
        if totp_secret:
            keyring.set_password(SERVICE_NAME, _TOTP_ACCOUNT, totp_secret)
        else:
            _delete_password(_TOTP_ACCOUNT)
    except KeyringError as exc:
        raise CredentialStoreError(f"Failed to save credentials to the OS keyring: {exc}") from exc


def clear_credentials() -> None:
    """Delete all stored credentials from the OS keyring."""
    _require_store()
    try:
        _delete_password(_USERNAME_ACCOUNT)
        _delete_password(_PASSWORD_ACCOUNT)
        _delete_password(_TOTP_ACCOUNT)
    except KeyringError as exc:
        raise CredentialStoreError(
            f"Failed to clear credentials from the OS keyring: {exc}"
        ) from exc


def _require_store() -> None:
    status = get_store_status()
    if status["available"]:
        return
    raise CredentialStoreError(
        f"OS keyring is unavailable: {status['error']}. "
        "Install or unlock a supported secure credential backend before running `okta config`."
    )


def _delete_password(account: str) -> None:
    try:
        keyring.delete_password(SERVICE_NAME, account)
    except PasswordDeleteError:
        pass
