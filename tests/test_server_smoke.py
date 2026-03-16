import asyncio
import json
import subprocess

from okta_auth import runtime_credentials, server
from okta_auth.credential_store import StoredCredentials
from okta_auth.settings import AppSettings


def test_server_exports_tools() -> None:
    expected = [
        "okta_login",
        "okta_check_session",
        "okta_list_sessions",
        "okta_delete_session",
        "okta_get_cookies",
        "main",
    ]
    for name in expected:
        assert hasattr(server, name)


def test_okta_login_uses_stored_credentials(monkeypatch) -> None:
    async def fake_perform_login(**kwargs):
        assert kwargs["username"] == "user@example.com"
        assert kwargs["password"] == "secret"
        assert kwargs["totp_secret"] == "JBSWY3DPEHPK3PXP"
        return {"success": True, "url": kwargs["url"], "message": "ok", "domain_key": "example.com"}

    monkeypatch.setattr(server, "perform_login", fake_perform_login)
    monkeypatch.setattr(server, "load_settings", lambda: AppSettings(credential_provider="keyring"))
    monkeypatch.setattr(
        server,
        "load_stored_credentials",
        lambda: StoredCredentials(
            username="user@example.com",
            password="secret",
            totp_secret="JBSWY3DPEHPK3PXP",
        ),
    )

    payload = json.loads(asyncio.run(server.okta_login(url="https://portal.example.com")))

    assert payload["success"] is True


def test_okta_login_with_op_provider_reports_env_file(monkeypatch) -> None:
    monkeypatch.setattr(
        server,
        "load_settings",
        lambda: AppSettings(credential_provider="op", op_env_file="/tmp/op.env"),
    )
    monkeypatch.setattr(server, "load_stored_credentials", lambda: StoredCredentials())

    payload = json.loads(asyncio.run(server.okta_login(url="https://portal.example.com")))

    assert payload["success"] is False
    assert "op run --env-file=/tmp/op.env" in payload["message"]


def test_okta_login_resolves_op_env_file(monkeypatch, tmp_path) -> None:
    env_path = tmp_path / "op.env"
    env_path.write_text(
        "\n".join(
            [
                "OKTA_USERNAME=op://Private/Okta/username",
                "OKTA_PASSWORD=op://Private/Okta/password",
                "",
            ]
        ),
        encoding="utf-8",
    )

    async def fake_perform_login(**kwargs):
        assert kwargs["username"] == "user@example.com"
        assert kwargs["password"] == "secret"
        assert kwargs["totp_secret"] is None
        return {"success": True, "url": kwargs["url"], "message": "ok", "domain_key": "example.com"}

    monkeypatch.setattr(server, "perform_login", fake_perform_login)
    monkeypatch.setattr(
        server,
        "load_settings",
        lambda: AppSettings(credential_provider="op", op_env_file=str(env_path)),
    )
    monkeypatch.setattr(runtime_credentials.shutil, "which", lambda command: "/usr/local/bin/op")

    def fake_run(cmd, *, check, capture_output, text, timeout):
        mapping = {
            "op://Private/Okta/username": "user@example.com\n",
            "op://Private/Okta/password": "secret\n",
        }
        assert cmd[:2] == ["/usr/local/bin/op", "read"]
        return subprocess.CompletedProcess(cmd, 0, stdout=mapping[cmd[2]], stderr="")

    monkeypatch.setattr(runtime_credentials.subprocess, "run", fake_run)

    payload = json.loads(asyncio.run(server.okta_login(url="https://portal.example.com")))

    assert payload["success"] is True
