"""Interactive CLI for Okta login and session management."""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from getpass import getpass
from typing import Any, Sequence

from okta_auth.auth import session_store
from okta_auth.auth.login import perform_login, verify_session
from okta_auth.config_wizard import ConfigWizard
from okta_auth.credential_store import (
    CredentialStoreError,
    StoredCredentials,
    clear_credentials,
    get_store_status,
)
from okta_auth.credential_store import load_credentials as load_stored_credentials
from okta_auth.settings import (
    clear_op_env_file,
    clear_settings,
    describe_settings,
    load_settings,
    uses_keyring,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="okta",
        description="Interactive Okta CLI for login and local session management.",
    )
    subparsers = parser.add_subparsers(dest="command")

    login_parser = subparsers.add_parser(
        "login",
        help="Authenticate to a URL and save the session locally.",
    )
    login_parser.add_argument("url", nargs="?", help="Target URL to authenticate against.")
    login_parser.add_argument("--username", help="Okta username or email.")
    login_parser.add_argument("--password", help="Okta password.")
    login_parser.add_argument("--totp-secret", help="Base32 TOTP secret for MFA.")
    login_parser.add_argument(
        "--headed",
        action="store_true",
        help="Show the browser window during login. Default is headless.",
    )
    login_parser.add_argument("--timeout-ms", type=int, default=60000, help="Page timeout in ms.")
    login_parser.add_argument("--json", action="store_true", help="Print raw JSON output.")

    check_parser = subparsers.add_parser(
        "check",
        help="Verify whether a stored session is still valid.",
    )
    check_parser.add_argument("url", help="URL to verify.")
    check_parser.add_argument("--timeout-ms", type=int, default=30000, help="Page timeout in ms.")
    check_parser.add_argument("--json", action="store_true", help="Print raw JSON output.")

    list_parser = subparsers.add_parser("list", help="List saved sessions.")
    list_parser.add_argument("--json", action="store_true", help="Print raw JSON output.")

    delete_parser = subparsers.add_parser("delete", help="Delete a stored session.")
    delete_parser.add_argument("url", help="URL whose session should be deleted.")
    delete_parser.add_argument("--json", action="store_true", help="Print raw JSON output.")

    cookies_parser = subparsers.add_parser("cookies", help="Show cookies from a stored session.")
    cookies_parser.add_argument("url", help="URL whose session cookies should be shown.")
    cookies_parser.add_argument("--domain", help="Optional domain substring filter.")
    cookies_parser.add_argument("--json", action="store_true", help="Print raw JSON output.")

    config_parser = subparsers.add_parser(
        "config",
        help="Open the interactive credential wizard or inspect stored configuration.",
    )
    config_parser.add_argument(
        "--provider",
        choices=["keyring", "op"],
        help="Force the wizard to configure a specific credential provider.",
    )
    config_parser.add_argument("--show", action="store_true", help="Show stored config status.")
    config_parser.add_argument("--reset", action="store_true", help="Delete stored credentials.")
    config_parser.add_argument("--yes", action="store_true", help="Skip the reset confirmation.")
    config_parser.add_argument("--json", action="store_true", help="Print raw JSON output.")

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    raw_args = list(sys.argv[1:] if argv is None else argv)
    parser = build_parser()

    if raw_args and raw_args[0] in {"-h", "--help"}:
        parser.print_help()
        return 0

    if not raw_args or raw_args[0] not in {"login", "check", "list", "delete", "cookies", "config"}:
        raw_args.insert(0, "login")

    args = parser.parse_args(raw_args)
    return asyncio.run(run_cli(args))


async def run_cli(args: argparse.Namespace) -> int:
    if args.command == "login":
        return await _run_login(args)
    if args.command == "check":
        return await _run_check(args)
    if args.command == "list":
        return _run_list(args)
    if args.command == "delete":
        return _run_delete(args)
    if args.command == "cookies":
        return _run_cookies(args)
    if args.command == "config":
        return _run_config(args)
    raise AssertionError(f"Unsupported command: {args.command}")


async def _run_login(args: argparse.Namespace) -> int:
    stored_settings = load_settings()
    stored_credentials = (
        load_stored_credentials() if uses_keyring(stored_settings) else StoredCredentials()
    )
    url = _require_value(args.url or stored_settings.default_url, "Target URL", secret=False)
    username = _resolve_login_value(
        args.username,
        "OKTA_USERNAME",
        stored_credentials.username,
        "Username",
    )
    password = _resolve_login_value(
        args.password,
        "OKTA_PASSWORD",
        stored_credentials.password,
        "Password",
        secret=True,
    )
    totp_secret = _resolve_optional_value(
        args.totp_secret,
        "OKTA_TOTP_SECRET",
        stored_credentials.totp_secret,
        "TOTP secret",
    )

    result = await perform_login(
        url=url,
        username=username,
        password=password,
        totp_secret=totp_secret,
        headed=args.headed,
        timeout_ms=args.timeout_ms,
    )
    return _print_result(
        result,
        use_json=args.json,
        success_key="success",
        success_text=_format_login_message(result),
        failure_text=result["message"],
    )


async def _run_check(args: argparse.Namespace) -> int:
    result = await verify_session(
        url=args.url,
        timeout_ms=args.timeout_ms,
    )
    return _print_result(
        result,
        use_json=args.json,
        success_key="valid",
        success_text=_format_check_message(result),
        failure_text=result["message"],
    )


def _run_list(args: argparse.Namespace) -> int:
    sessions = session_store.list_sessions()
    payload = {"count": len(sessions), "sessions": sessions}
    if args.json:
        print(json.dumps(payload, indent=2))
        return 0

    if not sessions:
        print("No saved sessions.")
        return 0

    print(f"Saved sessions: {len(sessions)}")
    for session in sessions:
        print(
            f"- {session['domain_key']} | {session['url']} | "
            f"saved {session['saved_at_iso']} | "
            f"cookies {session['cookie_count']} | origins {session['origin_count']}"
        )
    return 0


def _run_delete(args: argparse.Namespace) -> int:
    deleted = session_store.delete_session(args.url)
    payload = {
        "deleted": deleted,
        "message": "Session deleted" if deleted else "No session found for this URL",
        "url": args.url,
    }
    return _print_result(
        payload,
        use_json=args.json,
        success_key="deleted",
        success_text=payload["message"],
        failure_text=payload["message"],
    )


def _run_cookies(args: argparse.Namespace) -> int:
    session_path = session_store.get_session_path(args.url)
    if not session_path:
        payload = {"error": "No stored session found for this URL", "url": args.url}
        print(json.dumps(payload, indent=2) if args.json else payload["error"], file=sys.stderr)
        return 1

    with open(session_path, "r", encoding="utf-8") as file:
        data = json.load(file)

    cookies = data.get("cookies", [])
    if args.domain:
        cookies = [
            cookie for cookie in cookies if args.domain.lower() in cookie.get("domain", "").lower()
        ]

    payload = {"count": len(cookies), "cookies": cookies, "url": args.url}
    if args.json:
        print(json.dumps(payload, indent=2))
        return 0

    print(f"Cookies: {len(cookies)}")
    for cookie in cookies:
        print(f"- {cookie.get('name')} @ {cookie.get('domain')}{cookie.get('path', '/')}")
    return 0


def _run_config(args: argparse.Namespace) -> int:
    if args.show:
        return _show_config_status(use_json=args.json)
    if args.reset:
        return _reset_config(args)
    if args.json:
        print(json.dumps({"error": "--json is only supported with --show or --reset"}, indent=2))
        return 1
    return ConfigWizard(provider=args.provider).run()


def _require_value(value: str | None, label: str, *, secret: bool) -> str:
    if value:
        return value
    if not sys.stdin.isatty():
        raise SystemExit(f"{label} is required in non-interactive mode.")

    while True:
        entered = getpass(f"{label}: ") if secret else input(f"{label}: ").strip()
        if entered:
            return entered
        print(f"{label} is required.", file=sys.stderr)


def _resolve_login_value(
    explicit_value: str | None,
    env_name: str,
    stored_value: str | None,
    label: str,
    *,
    secret: bool = False,
) -> str:
    return _require_value(
        explicit_value or os.environ.get(env_name) or stored_value,
        label,
        secret=secret,
    )


def _resolve_optional_value(
    explicit_value: str | None,
    env_name: str,
    stored_value: str | None,
    label: str,
) -> str | None:
    value = explicit_value or os.environ.get(env_name) or stored_value
    if value:
        return value
    if not sys.stdin.isatty():
        return None

    entered = input(f"{label} (optional): ").strip()
    return entered or None


def _format_login_message(result: dict[str, Any]) -> str:
    session_path = session_store.get_session_path(result["url"])
    message = result["message"]
    if session_path:
        return (
            f"{message}\n"
            f"Sensitive session data is stored locally under: {session_store.SESSIONS_DIR}\n"
            f"Session file: {session_path}"
        )
    return message


def _format_check_message(result: dict[str, Any]) -> str:
    return f"{result['message']} ({result['domain_key']})"


def _show_config_status(*, use_json: bool) -> int:
    credential_status = get_store_status()
    settings_status = describe_settings()
    payload = {
        "credential_provider": settings_status["credential_provider"],
        "keyring_available": credential_status["available"],
        "keyring_backend": credential_status["backend"],
        "keyring_error": credential_status["error"],
        "username": credential_status.get("username"),
        "password_stored": credential_status.get("password_stored", False),
        "totp_secret_stored": credential_status.get("totp_secret_stored", False),
        "default_url": settings_status["default_url"],
        "config_path": settings_status["config_path"],
        "op_vault": settings_status["op_vault"],
        "op_item": settings_status["op_item"],
        "op_env_file": settings_status["op_env_file"],
        "op_env_file_exists": settings_status["op_env_file_exists"],
    }

    if use_json:
        print(json.dumps(payload, indent=2))
        return 0

    print(f"Credential provider: {payload['credential_provider']}")
    print(f"Keyring available: {'yes' if payload['keyring_available'] else 'no'}")
    print(f"Keyring backend: {payload['keyring_backend']}")
    if payload["keyring_error"]:
        print(f"Keyring error: {payload['keyring_error']}")
    print(f"Username: {payload['username'] or '(not set)'}")
    print(f"Password stored: {'yes' if payload['password_stored'] else 'no'}")
    print(f"TOTP secret stored: {'yes' if payload['totp_secret_stored'] else 'no'}")
    print(f"Default URL: {payload['default_url'] or '(not set)'}")
    if payload["credential_provider"] == "op":
        print(f"1Password vault: {payload['op_vault'] or '(not set)'}")
        print(f"1Password item: {payload['op_item'] or '(not set)'}")
        print(f"op env file: {payload['op_env_file'] or '(not set)'}")
        print(f"op env file exists: {'yes' if payload['op_env_file_exists'] else 'no'}")
    print(f"Settings file: {payload['config_path']}")
    return 0


def _reset_config(args: argparse.Namespace) -> int:
    if not args.yes:
        if not sys.stdin.isatty():
            print("--reset requires --yes in non-interactive mode.", file=sys.stderr)
            return 1

        confirmed = input("Delete stored credentials and local settings? [y/N]: ").strip().lower()
        if confirmed not in {"y", "yes"}:
            message = "Reset cancelled."
            if args.json:
                print(json.dumps({"deleted": False, "message": message}, indent=2))
            else:
                print(message)
            return 1

    keyring_error = None
    try:
        clear_credentials()
    except CredentialStoreError as exc:
        keyring_error = str(exc)

    clear_op_env_file(load_settings())
    clear_settings()
    message = "Stored credentials and local settings deleted."
    if keyring_error:
        message = f"{message} Keyring cleanup skipped: {keyring_error}"
    payload = {"deleted": True, "message": message}
    if args.json:
        print(json.dumps(payload, indent=2))
    else:
        print(payload["message"])
    return 0


def _print_result(
    payload: dict[str, Any],
    *,
    use_json: bool,
    success_key: str,
    success_text: str,
    failure_text: str,
) -> int:
    success = bool(payload.get(success_key))
    if use_json:
        print(json.dumps(payload, indent=2))
    else:
        stream = sys.stdout if success else sys.stderr
        print(success_text if success else failure_text, file=stream)
    return 0 if success else 1


if __name__ == "__main__":
    raise SystemExit(main())
