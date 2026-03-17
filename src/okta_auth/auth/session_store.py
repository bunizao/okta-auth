"""Per-domain session storage and validation.

Sessions are stored as Playwright storage_state JSON files under
~/.okta-auth/sessions/{domain_hash}.json with a companion metadata file.
"""

from __future__ import annotations

import json
import shutil
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

DATA_DIR = Path.home() / ".okta-auth"
LEGACY_DATA_DIR = Path.home() / ".okta-auth-mcp"
SESSIONS_DIR = DATA_DIR / "sessions"
LEGACY_SESSIONS_DIR = LEGACY_DATA_DIR / "sessions"


def _domain_key(url: str) -> str:
    """Derive a filesystem-safe key from a URL's domain."""
    from urllib.parse import urlparse

    host = urlparse(url).netloc.lower()
    if not host:
        host = url.lower()
    return host.replace(":", "_").replace("/", "_")


def _session_path(domain_key: str) -> Path:
    return SESSIONS_DIR / f"{domain_key}.json"


def _meta_path(domain_key: str) -> Path:
    return SESSIONS_DIR / f"{domain_key}.meta.json"


def _migrate_legacy_sessions_dir() -> None:
    if SESSIONS_DIR.exists() or not LEGACY_SESSIONS_DIR.exists():
        return

    DATA_DIR.mkdir(parents=True, exist_ok=True)
    shutil.move(str(LEGACY_SESSIONS_DIR), str(SESSIONS_DIR))


def ensure_sessions_dir() -> Path:
    _migrate_legacy_sessions_dir()
    SESSIONS_DIR.mkdir(parents=True, exist_ok=True)
    return SESSIONS_DIR


def save_session(url: str, storage_state_path: str) -> str:
    """Copy a Playwright storage_state file into the session store.

    Returns the domain key used for retrieval.
    """
    ensure_sessions_dir()
    key = _domain_key(url)

    # Copy storage state
    with open(storage_state_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    with open(_session_path(key), "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)

    # Write metadata
    meta = {
        "url": url,
        "domain_key": key,
        "saved_at": time.time(),
        "saved_at_iso": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "cookie_count": len(data.get("cookies", [])),
        "origin_count": len(data.get("origins", [])),
    }
    with open(_meta_path(key), "w", encoding="utf-8") as f:
        json.dump(meta, f, indent=2)

    return key


def get_session_path(url: str) -> Optional[str]:
    """Return the storage_state file path for a domain, or None if not found."""
    ensure_sessions_dir()
    key = _domain_key(url)
    path = _session_path(key)
    if path.exists():
        return str(path)
    return None


def is_session_effective(url: str) -> bool:
    """Return True if a stored session for the given URL has cookies or origins."""
    path = get_session_path(url)
    if not path:
        return False
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        cookies = data.get("cookies") or []
        origins = data.get("origins") or []
        return bool(cookies or origins)
    except Exception:
        return False


def list_sessions() -> List[Dict[str, Any]]:
    """List all stored sessions with metadata."""
    ensure_sessions_dir()
    sessions = []
    for meta_file in sorted(SESSIONS_DIR.glob("*.meta.json")):
        try:
            with open(meta_file, "r", encoding="utf-8") as f:
                meta = json.load(f)
            session_file = _session_path(meta["domain_key"])
            if "cookie_count" not in meta or "origin_count" not in meta:
                with open(session_file, "r", encoding="utf-8") as f:
                    session_data = json.load(f)
                meta["cookie_count"] = len(session_data.get("cookies", []))
                meta["origin_count"] = len(session_data.get("origins", []))
            meta["session_file_exists"] = session_file.exists()
            sessions.append(meta)
        except Exception:
            continue
    return sessions


def delete_session(url: str) -> bool:
    """Delete a stored session. Returns True if anything was deleted."""
    ensure_sessions_dir()
    key = _domain_key(url)
    deleted = False
    for path in (_session_path(key), _meta_path(key)):
        if path.exists():
            path.unlink()
            deleted = True
    return deleted
