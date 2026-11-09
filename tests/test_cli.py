import io
import json
import subprocess
from pathlib import Path

from okta_auth import GlobalProtectResult, cli, runtime_credentials
from okta_auth.credential_store import CredentialStoreError, StoredCredentials
from okta_auth.settings import AppSettings


def test_okta_defaults_to_login(monkeypatch, capsys) -> None:
    async def fake_perform_login(**kwargs):
        assert kwargs["url"] == "https://portal.example.com"
        assert kwargs["username"] == "user@example.com"
        assert kwargs["password"] == "secret"
        assert kwargs["totp_secret"] is None
        return {
            "success": True,
            "domain_key": "portal.example.com",
            "message": "Session saved for portal.example.com",
            "url": "https://portal.example.com",
        }

    monkeypatch.setattr(cli, "perform_login", fake_perform_login)
    monkeypatch.setattr(cli.session_store, "get_session_path", lambda url: "/tmp/session.json")
    monkeypatch.setattr(cli.session_store, "SESSIONS_DIR", Path("/tmp/sessions"))
    monkeypatch.setattr(cli, "load_settings", lambda: AppSettings())
    monkeypatch.setattr(cli, "load_stored_credentials", lambda: StoredCredentials())

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


def test_okta_login_ignores_browser_options_from_before_0_3(monkeypatch, capsys) -> None:
    async def fake_perform_login(**kwargs):
        assert set(kwargs) == {"url", "username", "password", "totp_secret", "progress"}
        return {
            "success": True,
            "domain_key": "portal.example.com",
            "message": "Session saved for portal.example.com",
            "url": "https://portal.example.com",
        }

    monkeypatch.setattr(cli, "perform_login", fake_perform_login)
    monkeypatch.setattr(cli.session_store, "get_session_path", lambda url: None)
    monkeypatch.setattr(cli, "load_settings", lambda: AppSettings())
    monkeypatch.setattr(cli, "load_stored_credentials", lambda: StoredCredentials())

    exit_code = cli.main(
        [
            "https://portal.example.com",
            "--username",
            "user@example.com",
            "--password",
            "secret",
            "--headed",
            "--timeout-ms",
            "1000",
            "--settle-ms",
            "2500",
        ]
    )

    assert exit_code == 0
    errors = capsys.readouterr().err
    for flag in ["--headed", "--timeout-ms", "--settle-ms"]:
        assert f"{flag} is ignored since 0.3.0" in errors


def test_okta_login_exits_77_when_okta_rejects_the_credentials(monkeypatch, capsys) -> None:
    async def fake_perform_login(**kwargs):
        return {
            "success": False,
            "domain_key": None,
            "message": "Login failed: credentials_rejected: Okta rejected the username or password",
            "url": kwargs["url"],
            "error_code": "credentials_rejected",
        }

    monkeypatch.setattr(cli, "perform_login", fake_perform_login)
    monkeypatch.setattr(cli, "load_settings", lambda: AppSettings())
    monkeypatch.setattr(cli, "load_stored_credentials", lambda: StoredCredentials())

    exit_code = cli.main(
        ["https://portal.example.com", "--username", "user@example.com", "--password", "x"]
    )

    assert exit_code == 77
    assert "credentials_rejected" in capsys.readouterr().err


def test_okta_globalprotect_prints_the_openconnect_cookie_as_json(
    monkeypatch, capsys, tmp_path
) -> None:
    async def fake_sign_in_globalprotect(**kwargs):
        assert kwargs["server"] == "vpn.example.edu"
        assert kwargs["interface"] == "portal"
        assert kwargs["device_token"] is None
        return GlobalProtectResult(
            interface="portal",
            user="user@example.com",
            cookie_name="portal-userauthcookie",
            cookie="gp-cookie",
            device_token="dt-1",
        )

    monkeypatch.setattr(cli, "sign_in_globalprotect", fake_sign_in_globalprotect)
    monkeypatch.setattr(cli.session_store, "SESSIONS_DIR", tmp_path / "sessions")
    monkeypatch.setattr(cli, "load_settings", lambda: AppSettings())
    monkeypatch.setattr(cli, "load_stored_credentials", lambda: StoredCredentials())

    exit_code = cli.main(
        [
            "globalprotect",
            "vpn.example.edu",
            "--interface",
            "portal",
            "--username",
            "user@example.com",
            "--password",
            "secret",
        ]
    )

    assert exit_code == 0
    assert json.loads(capsys.readouterr().out) == {
        "server": "vpn.example.edu",
        "interface": "portal",
        "user": "user@example.com",
        "cookieName": "portal-userauthcookie",
        "cookie": "gp-cookie",
    }
    assert cli.session_store.read_device_token("https://vpn.example.edu/") == "dt-1"


def test_okta_globalprotect_keeps_interactive_prompts_out_of_json(
    monkeypatch, capsys, tmp_path
) -> None:
    async def fake_sign_in_globalprotect(**kwargs):
        assert kwargs["username"] == "user@example.com"
        assert kwargs["password"] == "secret"
        assert kwargs["totp_secret"] is None
        return GlobalProtectResult(
            "gateway", "user@example.com", "prelogin-cookie", "gp-cookie", None
        )

    stdin = io.StringIO("\nuser@example.com\n\n")
    monkeypatch.setattr(stdin, "isatty", lambda: True)
    monkeypatch.setattr(cli.sys, "stdin", stdin)
    monkeypatch.setattr(cli, "sign_in_globalprotect", fake_sign_in_globalprotect)
    monkeypatch.setattr(cli.session_store, "SESSIONS_DIR", tmp_path / "sessions")
    monkeypatch.setattr(cli, "load_settings", lambda: AppSettings())
    monkeypatch.setattr(cli, "load_stored_credentials", lambda: StoredCredentials())
    for name in ["OKTA_USERNAME", "OKTA_PASSWORD", "OKTA_TOTP_SECRET"]:
        monkeypatch.delenv(name, raising=False)

    exit_code = cli.main(["globalprotect", "vpn.example.edu", "--password", "secret"])

    assert exit_code == 0
    output = capsys.readouterr()
    assert json.loads(output.out)["cookie"] == "gp-cookie"
    assert "Username: " in output.err
    assert "Username is required." in output.err
    assert "TOTP secret (optional): " in output.err


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


def test_okta_list_handles_legacy_session_metadata(monkeypatch, capsys, tmp_path) -> None:
    sessions_dir = tmp_path / "sessions"
    monkeypatch.setattr(cli.session_store, "SESSIONS_DIR", sessions_dir)
    sessions_dir.mkdir(parents=True)

    (sessions_dir / "portal.example.com.json").write_text(
        json.dumps(
            {
                "cookies": [{"name": "sid"}, {"name": "csrf"}],
                "origins": [{"origin": "https://portal.example.com"}],
            }
        ),
        encoding="utf-8",
    )
    (sessions_dir / "portal.example.com.meta.json").write_text(
        json.dumps(
            {
                "url": "https://portal.example.com/student",
                "domain_key": "portal.example.com",
                "saved_at": 1,
                "saved_at_iso": "1970-01-01T00:00:01Z",
            }
        ),
        encoding="utf-8",
    )

    exit_code = cli.main(["list"])

    assert exit_code == 0
    output = capsys.readouterr().out
    assert "Saved sessions: 1" in output
    assert "cookies 2 | origins 1" in output


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


def test_okta_resolves_op_references_from_environment(monkeypatch) -> None:
    async def fake_perform_login(**kwargs):
        assert kwargs["url"] == "https://portal.example.com"
        assert kwargs["username"] == "resolved-user@example.com"
        assert kwargs["password"] == "resolved-secret"
        assert kwargs["totp_secret"] == "RESOLVEDTOTP"
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
        ),
    )
    monkeypatch.setattr(cli.session_store, "get_session_path", lambda url: None)
    monkeypatch.setenv("OKTA_USERNAME", "op://Private/Okta/username")
    monkeypatch.setenv("OKTA_PASSWORD", "op://Private/Okta/password")
    monkeypatch.setenv("OKTA_TOTP_SECRET", "op://Private/Okta/totp_secret")
    monkeypatch.setattr(runtime_credentials.shutil, "which", lambda command: "/usr/local/bin/op")

    def fake_run(cmd, *, check, capture_output, text, timeout):
        mapping = {
            "op://Private/Okta/username": "resolved-user@example.com\n",
            "op://Private/Okta/password": "resolved-secret\n",
            "op://Private/Okta/totp_secret": "RESOLVEDTOTP\n",
        }
        assert cmd[:2] == ["/usr/local/bin/op", "read"]
        assert check is True
        assert capture_output is True
        assert text is True
        assert timeout == 20
        return subprocess.CompletedProcess(cmd, 0, stdout=mapping[cmd[2]], stderr="")

    monkeypatch.setattr(runtime_credentials.subprocess, "run", fake_run)

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


def test_okta_says_when_it_waits_on_1password_and_why_a_read_failed(monkeypatch, capsys) -> None:
    async def fake_perform_login(**kwargs):
        assert kwargs["totp_secret"] is None
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
        lambda: AppSettings(default_url="https://portal.example.com", credential_provider="op"),
    )
    monkeypatch.setattr(cli.session_store, "get_session_path", lambda url: None)
    monkeypatch.setenv("OKTA_USERNAME", "op://Private/Okta/username")
    monkeypatch.setenv("OKTA_PASSWORD", "op://Private/Okta/password")
    monkeypatch.setenv("OKTA_TOTP_SECRET", "op://Private/Okta/totp_secret")
    monkeypatch.setattr(runtime_credentials.shutil, "which", lambda command: "/usr/local/bin/op")

    def fake_run(cmd, **kwargs):
        if cmd[2].endswith("totp_secret"):
            raise subprocess.CalledProcessError(1, cmd, output="", stderr="op: dismissed")
        return subprocess.CompletedProcess(cmd, 0, stdout="resolved-secret\n", stderr="")

    monkeypatch.setattr(runtime_credentials.subprocess, "run", fake_run)

    assert cli.main([]) == 0
    errors = capsys.readouterr().err
    for label in ["username", "password", "TOTP secret"]:
        assert f"okta: Reading the {label} from 1Password" in errors
    assert "Could not read the TOTP secret from 1Password: op read exited with status 1" in errors
    assert "resolved-secret" not in errors
    assert "dismissed" not in errors
