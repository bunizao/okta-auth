"""Ports tests/cookies.test.ts. Test names are the TypeScript case names in snake_case."""

import httpx

from okta_auth.core.cookies import CookieJar

URL = httpx.URL("https://sp.example/app/acs")


def test_keeps_same_name_cookies_on_different_paths() -> None:
    jar = CookieJar(lambda: 1800000000)
    jar.store(URL, httpx.Headers({"set-cookie": "session=root; Path=/; Secure"}))
    jar.store(URL, httpx.Headers({"set-cookie": "session=app; Path=/app; Secure"}))

    assert len(jar.list(URL.host)) == 2
    assert jar.header(URL) == "session=app; session=root"
    assert jar.header(httpx.URL("https://sp.example/other")) == "session=root"
    assert jar.header(httpx.URL("https://sp.example/application")) == "session=root"
    assert jar.header(httpx.URL("https://other.example/app")) is None


def test_deletes_only_the_cookie_with_the_matching_path() -> None:
    jar = CookieJar(lambda: 1800000000)
    jar.store(URL, httpx.Headers({"set-cookie": "session=root; Path=/"}))
    jar.store(URL, httpx.Headers({"set-cookie": "session=app; Path=/app"}))
    jar.store(URL, httpx.Headers({"set-cookie": "session=gone; Path=/app; Max-Age=0"}))

    assert jar.header(URL) == "session=root"


def test_defaults_missing_or_invalid_cookie_paths_to_the_request_directory() -> None:
    for attribute in ("", "; Path=", "; Path=invalid"):
        jar = CookieJar(lambda: 1800000000)
        jar.store(URL, httpx.Headers({"set-cookie": f"session=app{attribute}"}))
        assert jar.list(URL.host)[0].path == "/app"
        assert jar.header(httpx.URL("https://sp.example/app")) == "session=app"
        assert jar.header(httpx.URL("https://sp.example/")) is None
    jar = CookieJar(lambda: 1800000000)
    jar.store(httpx.URL("https://sp.example/login"), httpx.Headers({"set-cookie": "session=root"}))
    assert jar.header(URL) == "session=root"


def test_matches_trailing_slash_cookie_paths_without_matching_their_parent() -> None:
    jar = CookieJar(lambda: 1800000000)
    jar.store(URL, httpx.Headers({"set-cookie": "session=app; Path=/app/"}))
    assert jar.header(httpx.URL("https://sp.example/app")) is None
    assert jar.header(URL) == "session=app"
