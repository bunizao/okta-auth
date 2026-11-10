import json
import stat
from pathlib import Path

from okta_auth.auth import session_store
from okta_auth.core import Cookie


def _write_storage_state(
    path: Path, cookies: list | None = None, origins: list | None = None
) -> None:
    payload = {
        "cookies": cookies or [],
        "origins": origins or [],
    }
    path.write_text(json.dumps(payload), encoding="utf-8")


def test_save_get_list_delete_session(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(session_store, "SESSIONS_DIR", tmp_path / "sessions")

    url = "https://portal.example.com/student"
    key = session_store.save_session(
        url, [Cookie(name="sid", value="abc", domain="portal.example.com")]
    )

    stored_path = session_store.get_session_path(url)
    assert stored_path is not None
    assert key == "portal.example.com"
    assert session_store.is_session_effective(url)

    sessions = session_store.list_sessions()
    assert len(sessions) == 1
    assert sessions[0]["domain_key"] == key
    assert sessions[0]["cookie_count"] == 1

    assert session_store.delete_session(url)
    assert session_store.get_session_path(url) is None
    assert not session_store.list_sessions()


def test_is_session_effective_handles_bad_json(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(session_store, "SESSIONS_DIR", tmp_path / "sessions")
    session_store.ensure_sessions_dir()

    broken = session_store.SESSIONS_DIR / "portal.example.com.json"
    broken.write_text("{bad json", encoding="utf-8")

    assert session_store.is_session_effective("https://portal.example.com") is False


def test_ensure_sessions_dir_migrates_legacy_sessions(tmp_path, monkeypatch) -> None:
    new_data_dir = tmp_path / ".okta-auth"
    legacy_data_dir = tmp_path / ".okta-auth-mcp"
    new_sessions_dir = new_data_dir / "sessions"
    legacy_sessions_dir = legacy_data_dir / "sessions"

    monkeypatch.setattr(session_store, "DATA_DIR", new_data_dir)
    monkeypatch.setattr(session_store, "LEGACY_DATA_DIR", legacy_data_dir)
    monkeypatch.setattr(session_store, "SESSIONS_DIR", new_sessions_dir)
    monkeypatch.setattr(session_store, "LEGACY_SESSIONS_DIR", legacy_sessions_dir)

    legacy_sessions_dir.mkdir(parents=True)
    stored = legacy_sessions_dir / "portal.example.com.json"
    stored.write_text('{"cookies":[{"name":"sid"}],"origins":[]}', encoding="utf-8")

    ensured = session_store.ensure_sessions_dir()

    assert ensured == new_sessions_dir
    assert (new_sessions_dir / "portal.example.com.json").exists()
    assert not stored.exists()


def test_list_sessions_backfills_missing_counts_from_storage_state(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(session_store, "SESSIONS_DIR", tmp_path / "sessions")
    session_store.ensure_sessions_dir()

    key = "portal.example.com"
    (session_store.SESSIONS_DIR / f"{key}.json").write_text(
        json.dumps(
            {
                "cookies": [{"name": "sid"}, {"name": "csrf"}],
                "origins": [{"origin": "https://portal.example.com"}],
            }
        ),
        encoding="utf-8",
    )
    (session_store.SESSIONS_DIR / f"{key}.meta.json").write_text(
        json.dumps(
            {
                "url": "https://portal.example.com/student",
                "domain_key": key,
                "saved_at": 1,
                "saved_at_iso": "1970-01-01T00:00:01Z",
            }
        ),
        encoding="utf-8",
    )

    sessions = session_store.list_sessions()

    assert len(sessions) == 1
    assert sessions[0]["cookie_count"] == 2
    assert sessions[0]["origin_count"] == 1


def test_saves_sessions_readable_only_by_the_user(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(session_store, "SESSIONS_DIR", tmp_path / "sessions")

    session_store.save_session("https://portal.example.com/", [])

    for path in [
        session_store.SESSIONS_DIR / "portal.example.com.json",
        session_store.SESSIONS_DIR / "portal.example.com.meta.json",
    ]:
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert stat.S_IMODE(session_store.SESSIONS_DIR.stat().st_mode) == 0o700


def test_load_cookies_keeps_only_live_target_cookies(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(session_store, "SESSIONS_DIR", tmp_path / "sessions")
    session_store.ensure_sessions_dir()
    _write_storage_state(
        session_store.SESSIONS_DIR / "portal.example.com.json",
        cookies=[
            {"name": "session", "value": "a", "domain": "portal.example.com", "expires": -1},
            {"name": "old", "value": "b", "domain": "portal.example.com", "expires": 1},
            {"name": "DT", "value": "c", "domain": "example.okta.com", "expires": -1},
        ],
    )

    cookies = session_store.load_cookies("https://portal.example.com/student")

    assert [(c.name, c.domain, c.expires) for c in cookies] == [
        ("session", "portal.example.com", None)
    ]


def test_deleting_a_session_keeps_the_device_token(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(session_store, "SESSIONS_DIR", tmp_path / "sessions")
    url = "https://portal.example.com/student"
    session_store.save_session(url, [])
    session_store.save_device_token(url, "dt-1")

    assert session_store.delete_session(url)
    assert session_store.read_device_token(url) == "dt-1"
    assert json.loads((tmp_path / "device-tokens.json").read_text()) == {
        "portal.example.com": "dt-1"
    }


def test_saves_an_okta_app_link_s_session_under_the_site_it_landed_on() -> None:
    app_link = "https://example.okta.com/app/example_ontrack/exk3/sso/saml"
    url_a = "https://learning.example.edu/login/index.php"
    doubtfire = Cookie(name="doubtfire", value="x", domain="ontrack.example.edu")
    moodle = Cookie(name="MoodleSession", value="x", domain="learning.example.edu")

    landing = "https://ontrack.example.edu/sign_in"
    assert (
        session_store.session_url(app_link, [doubtfire], landing) == "https://ontrack.example.edu/"
    )
    assert session_store.session_url(url_a, [moodle], url_a) == url_a
    assert session_store.session_url(app_link, [], app_link) == app_link


def test_keeps_the_port_of_an_okta_app_link_s_landing_site_in_the_session_key() -> None:
    app_link = "https://example.okta.com/app/example_ontrack/exk3/sso/saml"
    doubtfire = Cookie(name="doubtfire", value="x", domain="ontrack.example.edu")
    url = session_store.session_url(
        app_link, [doubtfire], "https://ontrack.example.edu:8443/sign_in"
    )
    assert url == "https://ontrack.example.edu:8443/"

    session_store.save_session(url, [doubtfire])
    assert [c.name for c in session_store.load_cookies("https://ontrack.example.edu:8443/api")] == [
        "doubtfire"
    ]
