"""Runtime credential resolution shared by the CLI, adapter, and MCP server."""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

from okta_auth.credential_store import StoredCredentials
from okta_auth.credential_store import load_credentials as load_stored_credentials
from okta_auth.settings import AppSettings, load_settings, uses_keyring

_OP_REFERENCE_PREFIX = "op://"
_CREDENTIAL_ENV_NAMES = (
    "OKTA_USERNAME",
    "OKTA_PASSWORD",
    "OKTA_TOTP_SECRET",
)


def resolve_runtime_credentials(
    *,
    explicit_username: str | None = None,
    explicit_password: str | None = None,
    explicit_totp_secret: str | None = None,
    app_settings: AppSettings | None = None,
    stored_credentials: StoredCredentials | None = None,
) -> tuple[str | None, str | None, str | None, AppSettings]:
    """Resolve runtime credentials from CLI args, env, 1Password refs, or keyring."""
    current_settings = app_settings or load_settings()
    current_credentials = stored_credentials
    if current_credentials is None:
        current_credentials = (
            load_stored_credentials() if uses_keyring(current_settings) else StoredCredentials()
        )

    op_reference_values = _load_op_reference_values(current_settings)
    op_cache: dict[str, str | None] = {}

    username = _resolve_value(
        explicit_username,
        os.environ.get("OKTA_USERNAME"),
        op_reference_values.get("OKTA_USERNAME"),
        current_credentials.username,
        op_cache=op_cache,
    )
    password = _resolve_value(
        explicit_password,
        os.environ.get("OKTA_PASSWORD"),
        op_reference_values.get("OKTA_PASSWORD"),
        current_credentials.password,
        op_cache=op_cache,
    )
    totp_secret = _resolve_value(
        explicit_totp_secret,
        os.environ.get("OKTA_TOTP_SECRET"),
        op_reference_values.get("OKTA_TOTP_SECRET"),
        current_credentials.totp_secret,
        op_cache=op_cache,
    )

    return username, password, totp_secret, current_settings


def _resolve_value(
    *candidates: str | None,
    op_cache: dict[str, str | None],
) -> str | None:
    for candidate in candidates:
        if not candidate:
            continue
        return _maybe_resolve_op_reference(candidate, op_cache)
    return None


def _maybe_resolve_op_reference(
    value: str,
    op_cache: dict[str, str | None],
) -> str | None:
    if not value.startswith(_OP_REFERENCE_PREFIX):
        return value

    if value not in op_cache:
        op_cache[value] = _read_op_reference(value)
    return op_cache[value]


def _read_op_reference(reference: str) -> str | None:
    op_path = shutil.which("op")
    if not op_path:
        return None

    try:
        result = subprocess.run(
            [op_path, "read", reference],
            check=True,
            capture_output=True,
            text=True,
            timeout=10,
        )
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
        return None

    return _trim_trailing_newline(result.stdout)


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


def _trim_trailing_newline(value: str) -> str:
    if value.endswith("\r\n"):
        return value[:-2]
    if value.endswith("\n"):
        return value[:-1]
    return value
