"""perform_login and verify_session against the fake SSO, with a temporary store."""

import asyncio
import json
import stat
import time

import httpx
import pytest

from fake_sso import OKTA, PASSWORD, SP, TARGET, USERNAME, FakeOptions, fake_sso
from okta_auth.auth import login, session_store
from okta_auth.core import Cookie


@pytest.fixture(autouse=True)
def store(tmp_path, monkeypatch):
    monkeypatch.setattr(session_store, "SESSIONS_DIR", tmp_path / "sessions")
    return tmp_path


def test_perform_login_saves_only_the_target_cookies_and_the_device_token(store) -> None:
    # An existing Okta session keeps the clock out of it: no TOTP step.
    fake = fake_sso(FakeOptions(now=time.time, okta_session=True))

    result = asyncio.run(login.perform_login(TARGET, USERNAME, PASSWORD, transport=fake.transport))

    assert result == {
        "success": True,
        "domain_key": SP,
        "message": f"Session saved for {SP}",
        "url": TARGET,
    }
    session_file = store / "sessions" / f"{SP}.json"
    saved = json.loads(session_file.read_text())
    assert {(c["name"], c["domain"], c["expires"]) for c in saved["cookies"]} == {
        ("MoodleSession", SP, -1),
        ("MDL_SSP_SessID", SP, -1),
    }
    assert stat.S_IMODE(session_file.stat().st_mode) == 0o600
    device_tokens = store / "device-tokens.json"
    assert json.loads(device_tokens.read_text()) == {SP: "dt-1"}
    assert stat.S_IMODE(device_tokens.stat().st_mode) == 0o600

    # The next sign-in presents the same device to Okta.
    fake.requests.clear()
    asyncio.run(login.perform_login(TARGET, USERNAME, PASSWORD, transport=fake.transport))
    assert all(r.cookies.get("DT") == "dt-1" for r in fake.requests if r.url.host == OKTA)


def test_perform_login_reports_rejected_credentials_by_code_without_saving(store) -> None:
    fake = fake_sso(FakeOptions(now=time.time))

    result = asyncio.run(
        login.perform_login(TARGET, USERNAME, "wrong password", transport=fake.transport)
    )

    assert result["success"] is False
    assert result["error_code"] == "credentials_rejected"
    assert "wrong password" not in result["message"]
    assert not (store / "sessions" / f"{SP}.json").exists()


def test_perform_login_reports_bad_input_without_a_code() -> None:
    result = asyncio.run(login.perform_login("http://portal.example.com", USERNAME, PASSWORD))

    assert result["success"] is False
    assert result["error_code"] is None
    assert "https" in result["message"]


def test_verify_session_sends_only_the_target_cookies_from_a_playwright_file(store) -> None:
    fake = fake_sso(FakeOptions(now=time.time))
    session_store.ensure_sessions_dir()
    (store / "sessions" / f"{SP}.json").write_text(
        json.dumps(
            {
                "cookies": [
                    {"name": "MoodleSession", "value": "authed", "domain": SP, "expires": -1},
                    {"name": "DT", "value": "dt-1", "domain": f".{OKTA}", "expires": -1},
                ],
                "origins": [],
            }
        )
    )

    result = asyncio.run(login.verify_session(TARGET, transport=fake.transport))

    assert result["valid"] is True
    assert [r.cookies for r in fake.requests] == [{"MoodleSession": "authed"}]


def test_verify_session_reports_a_session_okta_no_longer_honours(store) -> None:
    fake = fake_sso(FakeOptions(now=time.time))
    session_store.save_session(TARGET, [])

    result = asyncio.run(login.verify_session(TARGET, transport=fake.transport))

    assert result["valid"] is False
    assert result["message"] == "Session expired or invalid"


def test_verify_session_reports_a_missing_session() -> None:
    result = asyncio.run(login.verify_session(TARGET))

    assert result["valid"] is False
    assert result["domain_key"] is None


def test_verify_session_rejects_an_empty_cookie_store_without_sending_requests() -> None:
    fake = fake_sso(FakeOptions(now=time.time))
    session_store.save_session(TARGET, [])

    result = asyncio.run(login.verify_session(TARGET, transport=fake.transport))

    assert result["valid"] is False
    assert fake.requests == []


def test_verify_session_rejects_a_same_host_login_page() -> None:
    session_store.save_session(TARGET, [Cookie("MoodleSession", "anon", SP)])
    requests = []

    def login_page(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(
            200, text='<form><input name="username"><input type="password"></form>'
        )

    result = asyncio.run(login.verify_session(TARGET, transport=httpx.MockTransport(login_page)))

    assert result["valid"] is False
    assert len(requests) == 1


def test_verify_session_rejects_an_unresolved_redirect() -> None:
    session_store.save_session(TARGET, [Cookie("MoodleSession", "anon", SP)])
    transport = httpx.MockTransport(lambda request: httpx.Response(302))

    result = asyncio.run(login.verify_session(TARGET, transport=transport))

    assert result["valid"] is False
