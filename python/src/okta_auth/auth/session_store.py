"""Per-domain session storage.

Sessions are stored as Playwright-style storage_state JSON files under
~/.okta-auth/sessions/{host}.json with a companion metadata file, readable only by
the user. Releases before 0.3.0 wrote them with Playwright; the format is unchanged.
Okta device tokens live apart in ~/.okta-auth/device-tokens.json, so deleting a
session doesn't make Okta see a new device.
"""

from __future__ import annotations

import json
import os
import shutil
import time
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from okta_auth.core import Cookie

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
    SESSIONS_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    return SESSIONS_DIR


def save_session(url: str, cookies: List[Cookie]) -> str:
    """Store the cookies a sign-in returned. Returns the domain key used for retrieval."""
    ensure_sessions_dir()
    key = _domain_key(url)

    data = {"cookies": [_storage_state_cookie(cookie) for cookie in cookies], "origins": []}
    _write_secret(_session_path(key), data)

    meta = {
        "url": url,
        "domain_key": key,
        "saved_at": time.time(),
        "saved_at_iso": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "cookie_count": len(data["cookies"]),
        "origin_count": 0,
    }
    _write_secret(_meta_path(key), meta)

    return key


def session_url(url: str, cookies: List[Cookie]) -> str:
    """The URL a signed-in session is saved under. An Okta app link signs in to the
    site the SAML post landed on, so the cookies belong to that site, not to Okta."""
    site = cookies[0].domain if cookies else None
    return f"https://{site}/" if site and site != urlparse(url).hostname else url


def load_cookies(url: str) -> List[Cookie]:
    """The stored cookies the URL's own host set and that are still live.

    Older Playwright files hold every host's cookies, Okta's included; only the
    target's are returned. A non-positive `expires` marks a session cookie.
    """
    path = get_session_path(url)
    if not path:
        return []
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, ValueError):
        return []

    host = (urlparse(url).hostname or "").lower()
    now = time.time()
    cookies = []
    for item in data.get("cookies") or []:
        if not isinstance(item, dict) or str(item.get("domain", "")).lstrip(".").lower() != host:
            continue
        expires = item.get("expires")
        expires = expires if isinstance(expires, (int, float)) and expires > 0 else None
        if expires is not None and expires <= now:
            continue
        cookies.append(
            Cookie(
                name=str(item.get("name", "")),
                value=str(item.get("value", "")),
                domain=host,
                path=str(item.get("path") or "/"),
                expires=int(expires) if expires is not None else None,
                secure=bool(item.get("secure")),
                http_only=bool(item.get("httpOnly")),
            )
        )
    return cookies


def read_device_token(url: str) -> Optional[str]:
    """Okta's device token from the last sign-in that started at this URL's host."""
    token = _read_device_tokens().get(_host(url))
    return token if isinstance(token, str) else None


def save_device_token(url: str, token: Optional[str]) -> None:
    if not token:
        return
    tokens = _read_device_tokens()
    if tokens.get(_host(url)) == token:
        return
    tokens[_host(url)] = token
    _write_secret(_device_tokens_path(), tokens)


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


def _host(url: str) -> str:
    return urlparse(url).netloc.lower()


def _device_tokens_path() -> Path:
    # ~/.okta-auth/device-tokens.json, the file the TypeScript CLI uses too. Derived
    # from SESSIONS_DIR so that redirecting the sessions also redirects this.
    return SESSIONS_DIR.parent / "device-tokens.json"


def _read_device_tokens() -> Dict[str, Any]:
    try:
        with open(_device_tokens_path(), "r", encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def _storage_state_cookie(cookie: Cookie) -> Dict[str, Any]:
    return {
        "name": cookie.name,
        "value": cookie.value,
        "domain": cookie.domain,
        "path": cookie.path,
        # Playwright's marker for a session cookie.
        "expires": cookie.expires if cookie.expires is not None else -1,
        "httpOnly": cookie.http_only,
        "secure": cookie.secure,
    }


def _write_secret(path: Path, data: Any) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    # os.open's mode only applies to new files.
    os.chmod(path, 0o600)
