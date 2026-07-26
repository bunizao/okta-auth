import asyncio

from playwright.async_api import TimeoutError as PlaywrightTimeoutError

from okta_auth.auth import login


def test_perform_login_saves_after_the_settle_budget_expires(monkeypatch) -> None:
    events = []

    class FakePage:
        async def goto(self, url, timeout):
            events.append(("goto", url, timeout))

        async def wait_for_load_state(self, state, timeout):
            events.append(("settle", state, timeout))
            raise PlaywrightTimeoutError("still loading")

    class FakeContext:
        async def new_page(self):
            return FakePage()

        async def storage_state(self, path):
            events.append(("storage_state", path))

    class FakeBrowserController:
        def __init__(self, config):
            self.context = FakeContext()

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, traceback):
            return None

    async def fake_auto_login(page, credentials):
        events.append(("auto_login", credentials.username))
        return True

    def fake_save_session(url, path):
        events.append(("save_session", url, path))
        return "portal.example.com"

    monkeypatch.setattr(login, "BrowserController", FakeBrowserController)
    monkeypatch.setattr(login, "auto_login", fake_auto_login)
    monkeypatch.setattr(login, "is_browser_channel_available", lambda channel: False)
    monkeypatch.setattr(login.session_store, "save_session", fake_save_session)

    result = asyncio.run(
        login.perform_login(
            url="https://portal.example.com",
            username="user@example.com",
            password="secret",
            settle_ms=2500,
        )
    )

    assert result["success"] is True
    assert events[2] == ("settle", "networkidle", 2500)
    assert events[3][0] == "storage_state"
    assert events[4][0] == "save_session"
