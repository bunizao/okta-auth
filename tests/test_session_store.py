import json
from pathlib import Path

from okta_auth.auth import session_store


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

    source = tmp_path / "state.json"
    _write_storage_state(source, cookies=[{"name": "sid", "value": "abc"}])

    url = "https://portal.example.com/student"
    key = session_store.save_session(url, str(source))

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
