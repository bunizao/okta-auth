"""Interactive terminal wizard for configuring local credentials."""

from __future__ import annotations

import shutil
import sys
from dataclasses import dataclass
from getpass import getpass
from typing import Callable
from urllib.parse import urlparse

from okta_auth import credential_store, settings

InputFunc = Callable[[str], str]
SecretInputFunc = Callable[[str], str]
PrintFunc = Callable[..., None]


@dataclass
class WizardState:
    credential_provider: str
    default_url: str | None
    username: str | None
    password: str | None
    totp_secret: str | None
    password_stored: bool
    totp_secret_stored: bool
    keyring_backend: str
    keyring_available: bool
    keyring_error: str | None
    op_vault: str | None
    op_item: str | None
    op_username_field: str
    op_password_field: str
    op_totp_secret_field: str | None
    op_env_file: str


class ConfigWizard:
    """Small step-based TUI wizard for selecting a credential provider."""

    def __init__(
        self,
        *,
        provider: str | None = None,
        input_func: InputFunc = input,
        secret_input_func: SecretInputFunc = getpass,
        print_func: PrintFunc = print,
        stdin: object = sys.stdin,
        stdout: object = sys.stdout,
    ) -> None:
        self._provider = provider
        self._input = input_func
        self._secret_input = secret_input_func
        self._print = print_func
        self._stdin = stdin
        self._stdout = stdout

    def run(self) -> int:
        """Collect configuration interactively and save it."""
        if not self._is_tty():
            print("`okta config` requires an interactive terminal.", file=sys.stderr)
            return 1

        status = credential_store.get_store_status()
        state = self._load_state(status)
        self._show_step(
            1,
            7,
            "Welcome",
            [
                "Choose where Okta credentials should come from.",
                "Keyring stores secrets in the OS credential manager.",
                "1Password stores only op:// references in ~/.okta-auth/op.env.",
                "Only the default portal URL is written to ~/.okta-auth/config.json.",
            ],
        )
        self._input("Press Enter to continue...")

        state.credential_provider = self._prompt_provider(state.credential_provider)
        state.default_url = self._prompt_default_url(state.default_url)

        if state.credential_provider == "keyring":
            if not state.keyring_available:
                print(
                    "OS keyring is unavailable. Use `okta config --provider op` or install "
                    f"a supported secure backend. Details: {state.keyring_error}",
                    file=sys.stderr,
                )
                return 1
            state.username = self._prompt_username(state.username)
            state.password = self._prompt_password(state.password_stored)
            state.totp_secret = self._prompt_totp_secret(
                state.totp_secret, state.totp_secret_stored
            )
            self._show_keyring_review(state)
        else:
            state.op_vault = self._prompt_required_value(
                step=4,
                title="1Password Vault",
                current=state.op_vault,
                prompt="Vault name: ",
                help_text="The vault that contains your Okta login item.",
            )
            state.op_item = self._prompt_required_value(
                step=5,
                title="1Password Item",
                current=state.op_item,
                prompt="Item title: ",
                help_text="The login item title used by op:// references.",
            )
            self._prompt_op_fields(state)
            self._show_op_review(state)

        confirm = self._input("Save this configuration? [Y/n]: ").strip().lower()
        if confirm not in {"", "y", "yes"}:
            self._print("Configuration was not changed.")
            return 1

        try:
            self._save(state)
        except (credential_store.CredentialStoreError, ValueError) as exc:
            print(str(exc), file=sys.stderr)
            return 1
        return 0

    def _is_tty(self) -> bool:
        return bool(getattr(self._stdin, "isatty", lambda: False)()) and bool(
            getattr(self._stdout, "isatty", lambda: False)()
        )

    def _load_state(self, status: dict[str, object]) -> WizardState:
        stored = credential_store.load_credentials()
        app_settings = settings.load_settings()
        return WizardState(
            credential_provider=self._provider or app_settings.credential_provider,
            default_url=app_settings.default_url,
            username=stored.username,
            password=stored.password,
            totp_secret=stored.totp_secret,
            password_stored=bool(stored.password),
            totp_secret_stored=bool(stored.totp_secret),
            keyring_backend=str(status.get("backend") or "unknown"),
            keyring_available=bool(status.get("available")),
            keyring_error=_normalize(status.get("error")),
            op_vault=app_settings.op_vault,
            op_item=app_settings.op_item,
            op_username_field=app_settings.op_username_field,
            op_password_field=app_settings.op_password_field,
            op_totp_secret_field=app_settings.op_totp_secret_field,
            op_env_file=app_settings.op_env_file or str(settings.DEFAULT_OP_ENV_PATH),
        )

    def _prompt_provider(self, current: str) -> str:
        if self._provider:
            return self._provider

        self._show_step(
            2,
            7,
            "Provider",
            [
                f"Current provider: {current}",
                "1. keyring: store secrets in the local OS credential manager",
                "2. op: generate an op.env file with 1Password secret references",
            ],
        )
        while True:
            entered = self._input("Provider [1/2, default current]: ").strip().lower()
            if not entered:
                return current
            if entered in {"1", "keyring"}:
                return "keyring"
            if entered in {"2", "op"}:
                return "op"
            self._print("Enter `1`, `2`, `keyring`, or `op`.")

    def _prompt_default_url(self, current: str | None) -> str | None:
        self._show_step(
            3,
            7,
            "Default URL",
            [
                f"Current default URL: {current or '(not set)'}",
                "This value is optional and is used by `okta` when no URL argument is passed.",
                "Enter a full http(s) URL or type `none` to clear it.",
            ],
        )
        while True:
            entered = self._input("Default portal URL: ").strip()
            if not entered:
                return current
            if entered.lower() == "none":
                return None
            if _is_valid_url(entered):
                return entered
            self._print("Enter a full URL like https://portal.company.com.")

    def _prompt_username(self, current: str | None) -> str:
        self._show_step(
            4,
            7,
            "Username",
            [
                f"Current username: {current or '(not set)'}",
                "The username is stored in the OS keyring with your password.",
            ],
        )
        while True:
            entered = self._input("Okta username or email: ").strip()
            if entered:
                return entered
            if current:
                return current
            self._print("Username is required.")

    def _prompt_password(self, password_stored: bool) -> str:
        self._show_step(
            5,
            7,
            "Password",
            [
                f"Current password: {'stored' if password_stored else '(not set)'}",
                "The password is always written to the OS keyring, never to a local file.",
            ],
        )
        while True:
            entered = self._secret_input("Okta password: ").strip()
            if entered:
                return entered
            if password_stored:
                stored = credential_store.load_credentials()
                if stored.password:
                    return stored.password
            self._print("Password is required.")

    def _prompt_totp_secret(self, current: str | None, totp_secret_stored: bool) -> str | None:
        self._show_step(
            6,
            7,
            "TOTP",
            [
                f"Current TOTP secret: {'stored' if totp_secret_stored else '(not set)'}",
                "This field is optional. Leave it blank to keep the current value.",
                "Type `none` to remove the stored TOTP secret.",
            ],
        )
        entered = self._input("TOTP secret: ").strip()
        if not entered:
            return current
        if entered.lower() == "none":
            return None
        return entered.replace(" ", "").upper()

    def _prompt_required_value(
        self,
        *,
        step: int,
        title: str,
        current: str | None,
        prompt: str,
        help_text: str,
    ) -> str:
        self._show_step(
            step,
            7,
            title,
            [
                f"Current value: {current or '(not set)'}",
                help_text,
            ],
        )
        while True:
            entered = self._input(prompt).strip()
            if entered:
                return entered
            if current:
                return current
            self._print("This value is required.")

    def _prompt_op_fields(self, state: WizardState) -> None:
        self._show_step(
            6,
            7,
            "1Password Fields",
            [
                "These are the field names used inside the selected 1Password item.",
                "Leave blank to keep the current value.",
                "Type `none` for the TOTP field if the item does not store one.",
            ],
        )
        state.op_username_field = self._prompt_with_default(
            "Username field", state.op_username_field or "username"
        )
        state.op_password_field = self._prompt_with_default(
            "Password field", state.op_password_field or "password"
        )
        totp_field = self._input(f"TOTP field [{state.op_totp_secret_field or 'none'}]: ").strip()
        if totp_field.lower() == "none":
            state.op_totp_secret_field = None
        elif totp_field:
            state.op_totp_secret_field = totp_field

    def _prompt_with_default(self, label: str, current: str) -> str:
        entered = self._input(f"{label} [{current}]: ").strip()
        return entered or current

    def _show_keyring_review(self, state: WizardState) -> None:
        self._show_step(
            7,
            7,
            "Review",
            [
                f"Provider: {state.credential_provider}",
                f"Default URL: {state.default_url or '(not set)'}",
                f"Username: {state.username or '(not set)'}",
                "Password: stored in OS keyring",
                f"TOTP secret: {'stored' if state.totp_secret else '(not set)'}",
                f"Keyring backend: {state.keyring_backend}",
            ],
        )

    def _show_op_review(self, state: WizardState) -> None:
        self._show_step(
            7,
            7,
            "Review",
            [
                f"Provider: {state.credential_provider}",
                f"Default URL: {state.default_url or '(not set)'}",
                f"Vault: {state.op_vault}",
                f"Item: {state.op_item}",
                f"Username field: {state.op_username_field}",
                f"Password field: {state.op_password_field}",
                f"TOTP field: {state.op_totp_secret_field or '(not used)'}",
                f"op env file: {state.op_env_file}",
                f"`op` installed: {'yes' if shutil.which('op') else 'no'}",
            ],
        )

    def _save(self, state: WizardState) -> None:
        if state.credential_provider == "keyring":
            credential_store.save_credentials(
                username=state.username or "",
                password=state.password or "",
                totp_secret=state.totp_secret,
            )
            settings.clear_op_env_file()
            saved_settings = settings.AppSettings(
                default_url=state.default_url,
                credential_provider="keyring",
            )
            settings_path = settings.save_settings(saved_settings)
            self._print("")
            self._print("Configuration saved.")
            self._print(f"Provider: keyring ({state.keyring_backend})")
            self._print(f"Settings: {settings_path}")
            return

        has_existing_keyring_credentials = bool(
            state.username or state.password_stored or state.totp_secret_stored
        )
        if has_existing_keyring_credentials:
            if not state.keyring_available:
                raise credential_store.CredentialStoreError(
                    "Cannot switch to the 1Password provider because existing OS keyring "
                    "credentials could not be verified or removed."
                )
            try:
                credential_store.clear_credentials()
            except credential_store.CredentialStoreError as exc:
                raise credential_store.CredentialStoreError(
                    "Failed to remove existing OS keyring credentials before switching to "
                    f"the 1Password provider: {exc}"
                ) from exc

        saved_settings = settings.AppSettings(
            default_url=state.default_url,
            credential_provider="op",
            op_vault=state.op_vault,
            op_item=state.op_item,
            op_username_field=state.op_username_field,
            op_password_field=state.op_password_field,
            op_totp_secret_field=state.op_totp_secret_field,
            op_env_file=state.op_env_file,
        )
        env_path = settings.write_op_env_file(saved_settings)
        settings_path = settings.save_settings(saved_settings)
        self._print("")
        self._print("Configuration saved.")
        self._print(f"Provider: op (1Password CLI references in {env_path})")
        self._print(f"Settings: {settings_path}")
        self._print(f"Run CLI with: op run --env-file={env_path} -- okta")
        self._print(
            f"Run MCP with: op run --env-file={env_path} -- uvx --from okta-auth-cli okta-auth"
        )

    def _show_step(self, step: int, total: int, title: str, lines: list[str]) -> None:
        self._print("")
        self._print("=" * 64)
        self._print(f"Okta Config Wizard [{step}/{total}] - {title}")
        self._print("=" * 64)
        for line in lines:
            self._print(line)


def _is_valid_url(value: str) -> bool:
    parsed = urlparse(value)
    return parsed.scheme in {"http", "https"} and bool(parsed.netloc)


def _normalize(value: object) -> str | None:
    if isinstance(value, str):
        return value
    return None
