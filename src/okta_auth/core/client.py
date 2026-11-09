from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from http.cookiejar import CookieJar as StdlibCookieJar
from http.cookiejar import DefaultCookiePolicy

import httpx

from .cookies import Cookie, CookieJar
from .errors import OktaSignInError, where


@dataclass
class Page:
    url: httpx.URL
    status: int
    headers: httpx.Headers
    body: str


MAX_REDIRECTS = 10
TIMEOUT_SECONDS = 15.0
USER_AGENT = "okta-auth-cli (+https://github.com/bunizao/okta-auth)"


class Client:
    """One sign-in's worth of HTTP: a host-scoped cookie jar, manual redirects, a
    timeout per request, and HTTPS only."""

    def __init__(
        self,
        transport: httpx.AsyncBaseTransport | None,
        now: Callable[[], float],
        device_token: str | None = None,
    ) -> None:
        self.jar = CookieJar(now)
        # The Okta host, once known. It is the only host that gets the device token.
        self.idp_host: str | None = None
        self._device_token = device_token
        self._http = httpx.AsyncClient(
            transport=transport,
            follow_redirects=False,
            timeout=TIMEOUT_SECONDS,
            # httpx's own jar honours the Domain attribute; ours doesn't. Make
            # httpx's refuse everything so only ours is ever in play.
            cookies=httpx.Cookies(StdlibCookieJar(DefaultCookiePolicy(allowed_domains=[]))),
        )

    async def __aenter__(self) -> Client:
        return self

    async def __aexit__(self, *_: object) -> None:
        await self._http.aclose()

    def use_idp(self, host: str) -> None:
        if self.idp_host:
            return
        self.idp_host = host
        if self._device_token:
            self.jar.set(
                Cookie(
                    name="DT",
                    value=self._device_token,
                    domain=host,
                    path="/",
                    secure=True,
                    http_only=True,
                )
            )

    async def send(
        self,
        url: httpx.URL,
        *,
        method: str = "GET",
        headers: Mapping[str, str] | None = None,
        body: str | None = None,
    ) -> httpx.Response:
        if url.scheme != "https":
            raise OktaSignInError(
                "unexpected_step", f"refusing a plain-HTTP request to {where(url)}"
            )
        # The service provider hands its AuthnRequest to the identity provider, so
        # the host that receives SAMLRequest is Okta. Knowing that before the first
        # request lets Okta see the device token from the start.
        if "SAMLRequest" in url.params:
            self.use_idp(url.host)

        request_headers = httpx.Headers(headers)
        if "user-agent" not in request_headers:
            request_headers["user-agent"] = USER_AGENT
        cookie = self.jar.header(url)
        if cookie:
            request_headers["cookie"] = cookie

        # Built by hand rather than with client.build_request, which would merge
        # httpx's cookie jar into the request.
        request = httpx.Request(
            method,
            url,
            headers=request_headers,
            content=body.encode() if body is not None else None,
        )
        try:
            response = await self._http.send(request)
        except httpx.TimeoutException:
            # `from None`: httpx's own message may carry the full URL, query included.
            raise OktaSignInError("network", f"request to {where(url)} timed out") from None
        except httpx.HTTPError:
            raise OktaSignInError("network", f"request to {where(url)} failed") from None
        self.jar.store(url, response.headers)
        return response

    async def follow(
        self,
        url: httpx.URL,
        *,
        method: str = "GET",
        headers: Mapping[str, str] | None = None,
        body: str | None = None,
    ) -> Page:
        """Preserves POSTs on same-origin 307/308 redirects, but never replays a SAML
        response to a different origin. Ordinary form redirects switch to GET."""
        for _ in range(MAX_REDIRECTS + 1):
            response = await self.send(url, method=method, headers=headers, body=body)
            location = response.headers.get("location")
            if response.status_code in (301, 302, 303, 307, 308) and location:
                try:
                    next_url = url.join(location)
                except httpx.InvalidURL:
                    raise OktaSignInError(
                        "unexpected_step", f"{where(url)} redirected to an invalid URL"
                    ) from None
                preserve = response.status_code in (307, 308)
                same_origin = (url.scheme, url.host, url.port) == (
                    next_url.scheme,
                    next_url.host,
                    next_url.port,
                )
                if preserve and not same_origin and method.upper() not in ("GET", "HEAD"):
                    raise OktaSignInError(
                        "unexpected_step",
                        f"refusing to replay a form to another origin ({where(next_url)})",
                    )
                url = next_url
                if not preserve:
                    method, headers, body = "GET", None, None
                continue
            return Page(
                url=url, status=response.status_code, headers=response.headers, body=response.text
            )
        raise OktaSignInError(
            "unexpected_step", f"more than {MAX_REDIRECTS} redirects, last at {where(url)}"
        )
