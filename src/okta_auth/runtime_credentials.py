"""Runtime credential resolution shared by the CLI, adapter, and MCP server."""

from __future__ import annotations

import asyncio
import os
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from pathlib import Path

from okta_auth import onepassword
from okta_auth.credential_store import StoredCredentials
from okta_auth.credential_store import load_credentials as load_stored_credentials
from okta_auth.settings import AppSettings, load_settings, uses_keyring

_OP_REFERENCE_PREFIX = "op://"
_CREDENTIAL_ENV_NAMES = (
    "OKTA_USERNAME",
    "OKTA_PASSWORD",
    "OKTA_TOTP_SECRET",
)


@dataclass
class RuntimeCredentials:
    username: str | None
    password: str | None
    totp_secret: str | None
    # A 1Password reference to the TOTP field. Sign-in asks 1Password for the
    # current code through it, so the secret itself stays in 1Password.
    totp_ref: str | None
    settings: AppSettings

    def totp_code(
        self, progress: Callable[[str], None] | None = None
    ) -> Callable[[], Awaitable[str]] | None:
        """The sign-in callback for a TOTP field in 1Password, or None."""
        ref = self.totp_ref
        if ref is None:
            return None

        async def code() -> str:
            if progress:
                progress("Asking 1Password for a TOTP code")
            return await asyncio.to_thread(onepassword.read_totp_code, ref)

        return code


def resolve_credentials(
    *,
    explicit_username: str | None = None,
    explicit_password: str | None = None,
    explicit_totp_secret: str | None = None,
    app_settings: AppSettings | None = None,
    stored_credentials: StoredCredentials | None = None,
    progress: Callable[[str], None] | None = None,
    read_totp_secret: bool = False,
) -> RuntimeCredentials:
    """Resolve credentials from CLI args, env, 1Password refs, or keyring.

    Any value may be an op:// reference; they're all read with one `op inject`,
    which can wait for approval in the 1Password app, so `progress` hears about
    it before it starts and about why it failed. A TOTP reference is read only
    with `read_totp_secret` (for `export`); otherwise sign-in asks 1Password for
    codes through `totp_code`."""
    current_settings = app_settings or load_settings()
    current_credentials = stored_credentials
    if current_credentials is None:
        current_credentials = (
            load_stored_credentials() if uses_keyring(current_settings) else StoredCredentials()
        )
    op_reference_values = _load_op_reference_values(current_settings)

    def pick(*candidates: str | None) -> str | None:
        return next((candidate for candidate in candidates if candidate), None)

    values: dict[str, str | None] = {
        "username": pick(
            explicit_username,
            os.environ.get("OKTA_USERNAME"),
            op_reference_values.get("OKTA_USERNAME"),
            current_credentials.username,
        ),
        "password": pick(
            explicit_password,
            os.environ.get("OKTA_PASSWORD"),
            op_reference_values.get("OKTA_PASSWORD"),
            current_credentials.password,
        ),
        "TOTP secret": pick(
            explicit_totp_secret,
            os.environ.get("OKTA_TOTP_SECRET"),
            op_reference_values.get("OKTA_TOTP_SECRET"),
            current_credentials.totp_secret,
        ),
    }
    to_read = [
        label
        for label, value in values.items()
        if value and onepassword.is_op_ref(value) and (label != "TOTP secret" or read_totp_secret)
    ]
    if to_read:
        what = to_read[0] if len(to_read) == 1 else f"{', '.join(to_read[:-1])} and {to_read[-1]}"
        if progress:
            progress(f"Reading the {what} from 1Password (approve it there if asked)")
        try:
            read = onepassword.read_refs([values[label] or "" for label in to_read])
            values.update(zip(to_read, read, strict=True))
        except onepassword.OpError as error:
            if progress:
                progress(f"Could not read the {what} from 1Password: {error}")
            values.update((label, None) for label in to_read)

    totp_value = values["TOTP secret"]
    totp_ref = totp_value if totp_value and onepassword.is_op_ref(totp_value) else None
    return RuntimeCredentials(
        username=values["username"] or None,
        password=values["password"] or None,
        totp_secret=onepassword.totp_secret_of(totp_value) if totp_value and not totp_ref else None,
        totp_ref=totp_ref,
        settings=current_settings,
    )


def resolve_runtime_credentials(
    *,
    explicit_username: str | None = None,
    explicit_password: str | None = None,
    explicit_totp_secret: str | None = None,
    app_settings: AppSettings | None = None,
    stored_credentials: StoredCredentials | None = None,
    progress: Callable[[str], None] | None = None,
) -> tuple[str | None, str | None, str | None, AppSettings]:
    """resolve_credentials with the TOTP secret itself read, as a tuple."""
    credentials = resolve_credentials(
        explicit_username=explicit_username,
        explicit_password=explicit_password,
        explicit_totp_secret=explicit_totp_secret,
        app_settings=app_settings,
        stored_credentials=stored_credentials,
        progress=progress,
        read_totp_secret=True,
    )
    return (
        credentials.username,
        credentials.password,
        credentials.totp_secret,
        credentials.settings,
    )


def _load_op_reference_values(app_settings: AppSettings) -> dict[str, str]:
    if app_settings.credential_provider != "op":
        return {}

    values = _load_op_env_file(app_settings.op_env_file)
    if app_settings.op_vault and app_settings.op_item:
        values.setdefault(
            "OKTA_USERNAME",
            _build_op_reference(
                app_settings.op_vault,
                app_settings.op_item,
                app_settings.op_username_field,
            ),
        )
        values.setdefault(
            "OKTA_PASSWORD",
            _build_op_reference(
                app_settings.op_vault,
                app_settings.op_item,
                app_settings.op_password_field,
            ),
        )
        if app_settings.op_totp_secret_field:
            values.setdefault(
                "OKTA_TOTP_SECRET",
                _build_op_reference(
                    app_settings.op_vault,
                    app_settings.op_item,
                    app_settings.op_totp_secret_field,
                ),
            )
    return values


def _load_op_env_file(path: str | None) -> dict[str, str]:
    if not path:
        return {}

    env_path = Path(path).expanduser()
    if not env_path.exists():
        return {}

    values: dict[str, str] = {}
    try:
        with open(env_path, "r", encoding="utf-8") as file:
            for raw_line in file:
                line = raw_line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, raw_value = line.split("=", 1)
                normalized_key = key.removeprefix("export ").strip()
                if normalized_key not in _CREDENTIAL_ENV_NAMES:
                    continue
                values[normalized_key] = _strip_optional_quotes(raw_value.strip())
    except OSError:
        return {}

    return values


def _strip_optional_quotes(value: str) -> str:
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'"}:
        return value[1:-1]
    return value


def _build_op_reference(vault: str, item: str, field: str) -> str:
    return f"{_OP_REFERENCE_PREFIX}{vault}/{item}/{field}"
