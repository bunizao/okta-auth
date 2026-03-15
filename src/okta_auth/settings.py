"""Non-secret local settings for the CLI."""

from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass
from pathlib import Path

from okta_auth.auth.session_store import DATA_DIR

CONFIG_PATH = DATA_DIR / "config.json"
DEFAULT_OP_ENV_PATH = DATA_DIR / "op.env"
DEFAULT_PROVIDER = "keyring"
PROVIDERS = {"keyring", "op"}


@dataclass
class AppSettings:
    default_url: str | None = None
    credential_provider: str = DEFAULT_PROVIDER
    op_vault: str | None = None
    op_item: str | None = None
    op_username_field: str = "username"
    op_password_field: str = "password"
    op_totp_secret_field: str | None = "totp_secret"
    op_env_file: str | None = str(DEFAULT_OP_ENV_PATH)


def load_settings() -> AppSettings:
    """Load settings from disk. Invalid files are ignored."""
    if not CONFIG_PATH.exists():
        return AppSettings()

    try:
        with open(CONFIG_PATH, "r", encoding="utf-8") as file:
            data = json.load(file)
    except (OSError, json.JSONDecodeError):
        return AppSettings()

    default_url = data.get("default_url")
    if isinstance(default_url, str):
        default_url = default_url.strip() or None
    else:
        default_url = None

    credential_provider = data.get("credential_provider")
    if credential_provider not in PROVIDERS:
        credential_provider = DEFAULT_PROVIDER

    op_totp_secret_field = data.get("op_totp_secret_field")
    if isinstance(op_totp_secret_field, str):
        op_totp_secret_field = op_totp_secret_field.strip() or None
    else:
        op_totp_secret_field = "totp_secret"

    return AppSettings(
        default_url=default_url,
        credential_provider=credential_provider,
        op_vault=_normalize_string(data.get("op_vault")),
        op_item=_normalize_string(data.get("op_item")),
        op_username_field=_normalize_string(data.get("op_username_field")) or "username",
        op_password_field=_normalize_string(data.get("op_password_field")) or "password",
        op_totp_secret_field=op_totp_secret_field,
        op_env_file=_normalize_string(data.get("op_env_file")) or str(DEFAULT_OP_ENV_PATH),
    )


def save_settings(settings: AppSettings) -> Path:
    """Persist non-secret settings under ~/.okta-auth."""
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    with open(CONFIG_PATH, "w", encoding="utf-8") as file:
        json.dump(asdict(settings), file, indent=2)

    try:
        os.chmod(CONFIG_PATH, 0o600)
    except OSError:
        pass

    return CONFIG_PATH


def clear_settings() -> None:
    """Delete the local settings file when present."""
    if CONFIG_PATH.exists():
        CONFIG_PATH.unlink()


def describe_settings() -> dict[str, object]:
    """Return non-sensitive settings metadata."""
    settings = load_settings()
    return {
        "config_exists": CONFIG_PATH.exists(),
        "config_path": str(CONFIG_PATH),
        "default_url": settings.default_url,
        "credential_provider": settings.credential_provider,
        "op_vault": settings.op_vault,
        "op_item": settings.op_item,
        "op_username_field": settings.op_username_field,
        "op_password_field": settings.op_password_field,
        "op_totp_secret_field": settings.op_totp_secret_field,
        "op_env_file": settings.op_env_file,
        "op_env_file_exists": _op_env_path(settings).exists(),
    }


def write_op_env_file(app_settings: AppSettings) -> Path:
    """Write an op-compatible env file containing 1Password secret references."""
    if not app_settings.op_vault or not app_settings.op_item:
        raise ValueError("1Password vault and item are required.")

    env_path = _op_env_path(app_settings)
    env_path.parent.mkdir(parents=True, exist_ok=True)

    lines = [
        f"OKTA_USERNAME={_op_ref(app_settings.op_vault, app_settings.op_item, app_settings.op_username_field)}",
        f"OKTA_PASSWORD={_op_ref(app_settings.op_vault, app_settings.op_item, app_settings.op_password_field)}",
    ]
    if app_settings.op_totp_secret_field:
        lines.append(
            "OKTA_TOTP_SECRET="
            f"{_op_ref(app_settings.op_vault, app_settings.op_item, app_settings.op_totp_secret_field)}"
        )

    with open(env_path, "w", encoding="utf-8") as file:
        file.write("\n".join(lines) + "\n")

    try:
        os.chmod(env_path, 0o600)
    except OSError:
        pass

    return env_path


def clear_op_env_file(app_settings: AppSettings | None = None) -> None:
    """Delete the generated op env file when present."""
    env_path = _op_env_path(app_settings or load_settings())
    if env_path.exists():
        env_path.unlink()


def uses_keyring(app_settings: AppSettings | None = None) -> bool:
    """Return True when the selected provider is the local OS keyring."""
    current = app_settings or load_settings()
    return current.credential_provider == "keyring"


def _normalize_string(value: object) -> str | None:
    if isinstance(value, str):
        return value.strip() or None
    return None


def _op_env_path(app_settings: AppSettings) -> Path:
    raw_path = app_settings.op_env_file or str(DEFAULT_OP_ENV_PATH)
    return Path(raw_path).expanduser()


def _op_ref(vault: str, item: str, field: str) -> str:
    return f"op://{vault}/{item}/{field}"
