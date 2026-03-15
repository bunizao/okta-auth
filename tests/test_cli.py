import json
from pathlib import Path

from okta_auth import cli
from okta_auth.credential_store import CredentialStoreError, StoredCredentials
from okta_auth.settings import AppSettings


def test_okta_defaults_to_login(monkeypatch, capsys) -> None:
    async def fake_perform_login(**kwargs):
        assert kwargs["url"] == "https://portal.example.com"
        assert kwargs["username"] == "user@example.com"
        assert kwargs["password"] == "secret"
        assert kwargs["totp_secret"] is None
        assert kwargs["headed"] is False
        return {
            "success": True,
            "domain_key": "portal.example.com",
            "message": "Session saved for portal.example.com",
            "url": "https://portal.example.com",
        }

    monkeypatch.setattr(cli, "perform_login", fake_perform_login)
    monkeypatch.setattr(cli.session_store, "get_session_path", lambda url: "/tmp/session.json")
    monkeypatch.setattr(cli.session_store, "SESSIONS_DIR", Path("/tmp/sessions"))

    exit_code = cli.main(
        [
            "https://portal.example.com",
            "--username",
            "user@example.com",
            "--password",
            "secret",
        ]
    )

    assert exit_code == 0
    output = capsys.readouterr().out
    assert "Session saved for portal.example.com" in output
    assert "Sensitive session data is stored locally under: /tmp/sessions" in output
    assert "Session file: /tmp/session.json" in output


def test_okta_login_can_enable_headed_mode(monkeypatch) -> None:
    async def fake_perform_login(**kwargs):
        assert kwargs["headed"] is True
        return {
            "success": True,
            "domain_key": "portal.example.com",
            "message": "Session saved for portal.example.com",
            "url": "https://portal.example.com",
        }

    monkeypatch.setattr(cli, "perform_login", fake_perform_login)
    monkeypatch.setattr(cli.session_store, "get_session_path", lambda url: None)

    exit_code = cli.main(
        [
            "https://portal.example.com",
            "--username",
            "user@example.com",
            "--password",
            "secret",
            "--headed",
        ]
    )

    assert exit_code == 0


def test_okta_defaults_to_stored_config(monkeypatch) -> None:
    async def fake_perform_login(**kwargs):
        assert kwargs["url"] == "https://portal.example.com"
        assert kwargs["username"] == "user@example.com"
        assert kwargs["password"] == "secret"
        assert kwargs["totp_secret"] == "JBSWY3DPEHPK3PXP"
        return {
            "success": True,
            "domain_key": "portal.example.com",
            "message": "Session saved for portal.example.com",
            "url": "https://portal.example.com",
        }

    monkeypatch.setattr(cli, "perform_login", fake_perform_login)
    monkeypatch.setattr(
        cli,
        "load_settings",
        lambda: AppSettings(
            default_url="https://portal.example.com",
            credential_provider="keyring",
        ),
    )
    monkeypatch.setattr(
        cli,
        "load_stored_credentials",
        lambda: StoredCredentials(
            username="user@example.com",
            password="secret",
            totp_secret="JBSWY3DPEHPK3PXP",
        ),
    )
    monkeypatch.setattr(cli.session_store, "get_session_path", lambda url: None)

    exit_code = cli.main([])

    assert exit_code == 0


def test_okta_config_show_json(monkeypatch, capsys) -> None:
    monkeypatch.setattr(
        cli,
        "get_store_status",
        lambda: {
            "available": True,
            "backend": "FakeKeyring",
            "error": None,
            "username": "user@example.com",
            "password_stored": True,
            "totp_secret_stored": False,
        },
    )
    monkeypatch.setattr(
        cli,
        "describe_settings",
        lambda: {
            "config_exists": True,
            "config_path": "/tmp/config.json",
            "default_url": "https://portal.example.com",
            "credential_provider": "op",
            "op_vault": "Personal",
            "op_item": "Okta MCP",
            "op_username_field": "username",
            "op_password_field": "password",
            "op_totp_secret_field": "totp_secret",
            "op_env_file": "/tmp/op.env",
            "op_env_file_exists": True,
        },
    )

    exit_code = cli.main(["config", "--show", "--json"])

    assert exit_code == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["keyring_available"] is True
    assert payload["keyring_backend"] == "FakeKeyring"
    assert payload["default_url"] == "https://portal.example.com"
    assert payload["credential_provider"] == "op"
    assert payload["op_env_file"] == "/tmp/op.env"


def test_okta_config_reset_reports_failure_when_keyring_cleanup_fails(monkeypatch, capsys) -> None:
    monkeypatch.setattr(
        cli,
        "load_settings",
        lambda: AppSettings(
            credential_provider="keyring",
            op_env_file="/tmp/op.env",
        ),
    )
    monkeypatch.setattr(
        cli,
        "get_store_status",
        lambda: {
            "available": True,
            "backend": "FakeKeyring",
            "error": None,
            "username": "user@example.com",
            "password_stored": True,
            "totp_secret_stored": False,
        },
    )
    monkeypatch.setattr(
        cli,
        "clear_credentials",
        lambda: (_ for _ in ()).throw(CredentialStoreError("keyring locked")),
    )
    clear_calls = []
    monkeypatch.setattr(
        cli, "clear_op_env_file", lambda app_settings: clear_calls.append(app_settings)
    )
    monkeypatch.setattr(cli, "clear_settings", lambda: clear_calls.append("settings"))

    exit_code = cli.main(["config", "--reset", "--yes", "--json"])

    assert exit_code == 1
    payload = json.loads(capsys.readouterr().out)
    assert payload["deleted"] is False
    assert "keyring locked" in payload["message"]
    assert len(clear_calls) == 2


def test_okta_ignores_keyring_when_provider_is_op(monkeypatch) -> None:
    async def fake_perform_login(**kwargs):
        assert kwargs["url"] == "https://portal.example.com"
        assert kwargs["username"] == "env-user@example.com"
        assert kwargs["password"] == "env-secret"
        assert kwargs["totp_secret"] == "ENVTOTP"
        return {
            "success": True,
            "domain_key": "portal.example.com",
            "message": "Session saved for portal.example.com",
            "url": "https://portal.example.com",
        }

    monkeypatch.setattr(cli, "perform_login", fake_perform_login)
    monkeypatch.setattr(
        cli,
        "load_settings",
        lambda: AppSettings(
            default_url="https://portal.example.com",
            credential_provider="op",
            op_env_file="/tmp/op.env",
        ),
    )
    monkeypatch.setattr(
        cli,
        "load_stored_credentials",
        lambda: StoredCredentials(
            username="keyring-user@example.com",
            password="keyring-secret",
            totp_secret="KEYRINGTOTP",
        ),
    )
    monkeypatch.setattr(cli.session_store, "get_session_path", lambda url: None)
    monkeypatch.setenv("OKTA_USERNAME", "env-user@example.com")
    monkeypatch.setenv("OKTA_PASSWORD", "env-secret")
    monkeypatch.setenv("OKTA_TOTP_SECRET", "ENVTOTP")

    exit_code = cli.main([])

    assert exit_code == 0


def test_okta_check_json(monkeypatch, capsys) -> None:
    async def fake_verify_session(**kwargs):
        assert kwargs["url"] == "https://portal.example.com"
        return {
            "valid": True,
            "domain_key": "portal.example.com",
            "message": "Session is active",
            "url": "https://portal.example.com",
        }

    monkeypatch.setattr(cli, "verify_session", fake_verify_session)

    exit_code = cli.main(["check", "https://portal.example.com", "--json"])

    assert exit_code == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["valid"] is True
    assert payload["domain_key"] == "portal.example.com"
