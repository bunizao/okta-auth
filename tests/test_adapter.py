import json
import subprocess

import pytest

from okta_auth import adapter, runtime_credentials
from okta_auth.credential_store import StoredCredentials
from okta_auth.settings import AppSettings


def test_get_cookie_value_prefers_exact_target_domain(monkeypatch, tmp_path) -> None:
    session_path = tmp_path / "session.json"
    session_path.write_text(
        json.dumps(
            {
                "cookies": [
                    {
                        "name": "MoodleSession",
                        "value": "parent",
                        "domain": ".example.edu",
                        "path": "/",
                    },
                    {
                        "name": "MoodleSession",
                        "value": "exact",
                        "domain": "school.example.edu",
                        "path": "/",
                    },
                ]
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(adapter, "get_session_path", lambda _url: str(session_path))

    assert adapter.get_cookie_value("https://school.example.edu", "MoodleSession") == "exact"


def test_ensure_login_reuses_active_session(monkeypatch) -> None:
    monkeypatch.setattr(adapter, "get_session_path", lambda _url: "/tmp/session.json")

    async def fake_verify_session(**_kwargs):
        return {
            "valid": True,
            "domain_key": "school.example.edu",
            "message": "Session is active",
            "url": "https://school.example.edu",
        }

    monkeypatch.setattr(adapter, "verify_session", fake_verify_session)

    called = {"perform_login": False}

    async def fake_perform_login(**_kwargs):
        called["perform_login"] = True
        return {"success": True}

    monkeypatch.setattr(adapter, "perform_login", fake_perform_login)

    result = adapter.ensure_login("https://school.example.edu")

    assert result["success"] is True
    assert result["performed_login"] is False
    assert called["perform_login"] is False


def test_ensure_login_uses_stored_credentials(monkeypatch) -> None:
    monkeypatch.setattr(adapter, "get_session_path", lambda _url: None)
    monkeypatch.setattr(
        runtime_credentials, "load_settings", lambda: AppSettings(credential_provider="keyring")
    )
    monkeypatch.setattr(
        runtime_credentials,
        "load_stored_credentials",
        lambda: StoredCredentials(
            username="user@example.com",
            password="secret",
            totp_secret="JBSWY3DPEHPK3PXP",
        ),
    )

    async def fake_perform_login(**kwargs):
        assert kwargs["username"] == "user@example.com"
        assert kwargs["password"] == "secret"
        assert kwargs["totp_secret"] == "JBSWY3DPEHPK3PXP"
        return {
            "success": True,
            "domain_key": "school.example.edu",
            "message": "Session saved",
            "url": kwargs["url"],
        }

    monkeypatch.setattr(adapter, "perform_login", fake_perform_login)

    result = adapter.ensure_login("https://school.example.edu")

    assert result["performed_login"] is True


def test_ensure_login_reports_missing_credentials(monkeypatch) -> None:
    monkeypatch.setattr(adapter, "get_session_path", lambda _url: None)
    monkeypatch.setattr(
        runtime_credentials,
        "load_settings",
        lambda: AppSettings(credential_provider="op", op_env_file="/tmp/op.env"),
    )
    monkeypatch.setattr(runtime_credentials, "load_stored_credentials", lambda: StoredCredentials())

    with pytest.raises(adapter.OktaAdapterError) as exc:
        adapter.ensure_login("https://school.example.edu")

    assert "op run --env-file=/tmp/op.env" in str(exc.value)


def test_ensure_login_resolves_op_env_file(monkeypatch, tmp_path) -> None:
    env_path = tmp_path / "op.env"
    env_path.write_text(
        "\n".join(
            [
                "OKTA_USERNAME=op://Private/Okta/username",
                "OKTA_PASSWORD=op://Private/Okta/password",
                "OKTA_TOTP_SECRET=op://Private/Okta/totp_secret",
                "",
            ]
        ),
        encoding="utf-8",
    )

    monkeypatch.setattr(adapter, "get_session_path", lambda _url: None)
    monkeypatch.delenv("OKTA_USERNAME", raising=False)
    monkeypatch.delenv("OKTA_PASSWORD", raising=False)
    monkeypatch.delenv("OKTA_TOTP_SECRET", raising=False)
    monkeypatch.setattr(
        runtime_credentials,
        "load_settings",
        lambda: AppSettings(credential_provider="op", op_env_file=str(env_path)),
    )
    monkeypatch.setattr(runtime_credentials.shutil, "which", lambda command: "/usr/local/bin/op")

    def fake_run(cmd, *, check, capture_output, text, timeout):
        mapping = {
            "op://Private/Okta/username": "user@example.com\n",
            "op://Private/Okta/password": "secret\n",
            "op://Private/Okta/totp_secret": "JBSWY3DPEHPK3PXP\n",
        }
        assert cmd[:2] == ["/usr/local/bin/op", "read"]
        return subprocess.CompletedProcess(cmd, 0, stdout=mapping[cmd[2]], stderr="")

    monkeypatch.setattr(runtime_credentials.subprocess, "run", fake_run)

    async def fake_perform_login(**kwargs):
        assert kwargs["username"] == "user@example.com"
        assert kwargs["password"] == "secret"
        assert kwargs["totp_secret"] == "JBSWY3DPEHPK3PXP"
        return {
            "success": True,
            "domain_key": "school.example.edu",
            "message": "Session saved",
            "url": kwargs["url"],
        }

    monkeypatch.setattr(adapter, "perform_login", fake_perform_login)

    result = adapter.ensure_login("https://school.example.edu")

    assert result["performed_login"] is True
