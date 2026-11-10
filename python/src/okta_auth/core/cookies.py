from __future__ import annotations

import builtins
import math
import re
from collections.abc import Callable
from dataclasses import dataclass
from email.utils import parsedate_to_datetime

import httpx


@dataclass
class Cookie:
    name: str
    value: str
    # Always the exact host that set the cookie. See CookieJar.
    domain: str
    path: str = "/"
    # Seconds since the epoch. None for session cookies.
    expires: int | None = None
    secure: bool = False
    http_only: bool = False


class CookieJar:
    """A cookie jar that is stricter than a browser on purpose: every cookie belongs
    to the exact host that set it, and the Domain attribute is ignored. A sign-in
    hops between the target site and Okta, and neither should ever see the
    other's cookies."""

    def __init__(self, now: Callable[[], float]) -> None:
        self._now = now
        self._hosts: dict[str, dict[tuple[str, str], Cookie]] = {}

    def store(self, url: httpx.URL, headers: httpx.Headers) -> None:
        for line in headers.get_list("set-cookie"):
            cookie = parse_set_cookie(line, url, self._now())
            if cookie:
                self.set(cookie)

    def set(self, cookie: Cookie) -> None:
        cookies = self._hosts.setdefault(cookie.domain, {})
        key = (cookie.name, cookie.path)
        if self._is_expired(cookie):
            cookies.pop(key, None)
        else:
            cookies[key] = cookie

    def get(self, host: str, name: str, path: str = "/") -> Cookie | None:
        cookie = self._hosts.get(host, {}).get((name, path))
        return cookie if cookie and not self._is_expired(cookie) else None

    def list(self, host: str) -> builtins.list[Cookie]:
        return [c for c in self._hosts.get(host, {}).values() if not self._is_expired(c)]

    def header(self, url: httpx.URL) -> str | None:
        path = url.raw_path.split(b"?", 1)[0].decode("ascii")
        cookies = [
            cookie
            for cookie in self.list(url.host)
            if path == cookie.path
            or path.startswith(cookie.path if cookie.path.endswith("/") else f"{cookie.path}/")
        ]
        cookies.sort(key=lambda cookie: len(cookie.path), reverse=True)
        pairs = [f"{cookie.name}={cookie.value}" for cookie in cookies]
        return "; ".join(pairs) if pairs else None

    def _is_expired(self, cookie: Cookie) -> bool:
        return cookie.expires is not None and cookie.expires <= self._now()


def parse_set_cookie(line: str, url: httpx.URL, now: float) -> Cookie | None:
    pair, *attributes = line.split(";")
    equals = pair.find("=")
    if equals <= 0:
        return None

    path = url.raw_path.split(b"?", 1)[0].decode("ascii")
    cookie = Cookie(
        name=pair[:equals].strip(),
        value=pair[equals + 1 :].strip(),
        domain=url.host,
        path=path.rsplit("/", 1)[0] or "/",
    )
    max_age: int | None = None
    for attribute in attributes:
        raw_key, _, value = attribute.partition("=")
        key = raw_key.strip().lower()
        value = value.strip()
        if key == "path" and value.startswith("/"):
            cookie.path = value
        elif key == "secure":
            cookie.secure = True
        elif key == "httponly":
            cookie.http_only = True
        elif key == "max-age" and re.fullmatch(r"-?[0-9]+", value):
            max_age = int(value)
        elif key == "expires":
            try:
                cookie.expires = math.floor(parsedate_to_datetime(value).timestamp())
            except (TypeError, ValueError):
                pass
    # Max-Age wins over Expires (RFC 6265 §5.3).
    if max_age is not None:
        cookie.expires = math.floor(now) + max_age
    return cookie
