"""Keeps every test away from the real ~/.okta-auth."""

from __future__ import annotations

import pytest

from okta_auth import settings
from okta_auth.auth import session_store


@pytest.fixture(autouse=True)
def isolated_store(
    tmp_path_factory: pytest.TempPathFactory, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = tmp_path_factory.mktemp("home")
    data_dir = home / ".okta-auth"
    legacy_dir = home / ".okta-auth-mcp"
    monkeypatch.setattr(session_store, "DATA_DIR", data_dir)
    monkeypatch.setattr(session_store, "LEGACY_DATA_DIR", legacy_dir)
    monkeypatch.setattr(session_store, "SESSIONS_DIR", data_dir / "sessions")
    monkeypatch.setattr(session_store, "LEGACY_SESSIONS_DIR", legacy_dir / "sessions")
    monkeypatch.setattr(settings, "CONFIG_PATH", data_dir / "config.json")
    monkeypatch.setattr(settings, "DEFAULT_OP_ENV_PATH", data_dir / "op.env")
    monkeypatch.setenv("HOME", str(home))
