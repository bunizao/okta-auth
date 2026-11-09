"""A scripted Okta Identity Engine org (example.okta.com), a Moodle-like SAML
service provider (learning.example.edu) and a GlobalProtect portal
(vpn.example.edu), served through an httpx.MockTransport.

A port of tests/fake-sso.ts in the TypeScript reference. Keep the two in step.
"""

from __future__ import annotations

import base64
import json
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, Literal
from urllib.parse import parse_qs, quote

import httpx

from okta_auth.core.totp import totp

SP = "learning.example.edu"
OKTA = "example.okta.com"
TARGET = f"https://{SP}/login/index.php"
USERNAME = "student@example.edu"
PASSWORD = "correct horse battery staple"
TOTP_SECRET = "JBSWY3DPEHPK3PXP"
STATE_TOKEN = "02.id.abc-def"
SAML_RESPONSE = "PHNhbWw+"
GP = "vpn.example.edu"
GP_COOKIE = "gp-cookie-1"

RELAY_STATE = f"https://{SP}/my/"
IDX = "application/ion+json; okta-version=1.0.0"
APP_PATH = "/app/example_moodle/exk1/sso/saml"
ACS_PATH = f"/auth/saml2/sp/saml2-acs.php/{SP}"
GP_APP_PATH = "/app/example_gp/exk2/sso/saml"
GP_ACS_PATH = "/SAML20/SP/ACS"
GP_RELAY_STATE = "gp-relay"
PRELOGIN_PATHS = {"gateway": "/ssl-vpn/prelogin.esp", "portal": "/global-protect/prelogin.esp"}

GpInterface = Literal["gateway", "portal"]
Enrollment = Literal["google_otp", "okta_verify", "okta_verify_push"]


@dataclass
class FakeOptions:
    now: Callable[[], float]
    # The secret Okta holds for the user's TOTP enrollment.
    totp_secret: str | None = None
    # Second factors besides the password, in the order Okta lists them.
    enrollments: list[Enrollment] = field(
        default_factory=lambda: ["okta_verify_push", "google_otp"]
    )
    # Okta asks for the password on the identify form instead of a later step.
    password_on_identify: bool = False
    # After the password, Okta challenges this enrollment straight away (the one
    # used last time) and offers the rest through select-authenticator.
    preselect: Enrollment | None = None
    # Okta already has a session for every request (say, a browser's cookies).
    okta_session: bool = False
    # The SP (or the GlobalProtect ACS) refuses the SAML response.
    sp_rejects: bool = False
    # How GlobalProtect prelogin hands over the SAMLRequest.
    gp_binding: Literal["REDIRECT", "POST"] = "REDIRECT"
    # GlobalProtect interfaces whose prelogin offers SAML; the rest answer Error.
    gp_saml: list[GpInterface] = field(default_factory=lambda: ["gateway", "portal"])
    # Where the GlobalProtect ACS reports the result.
    gp_result_in: Literal["headers", "comment"] = "headers"


@dataclass
class RecordedRequest:
    method: str
    url: httpx.URL
    cookies: dict[str, str]
    headers: httpx.Headers
    body: str


ENROLLMENTS: dict[str, dict[str, Any]] = {
    "google_otp": {
        "key": "google_otp",
        "id": "aut-google",
        "methodType": {"name": "methodType", "required": False, "value": "otp", "mutable": False},
    },
    "okta_verify": {
        "key": "okta_verify",
        "id": "aut-verify",
        "methodType": {
            "name": "methodType",
            "type": "string",
            "options": [
                {"label": "Enter a code", "value": "totp"},
                {"label": "Get a push notification", "value": "push"},
            ],
        },
    },
    "okta_verify_push": {
        "key": "okta_verify",
        "id": "aut-verify",
        "methodType": {
            "name": "methodType",
            "type": "string",
            "options": [{"label": "Get a push notification", "value": "push"}],
        },
    },
}

Override = Callable[[RecordedRequest], "httpx.Response | None"]


class FakeSso:
    def __init__(self, options: FakeOptions) -> None:
        self.options = options
        self.requests: list[RecordedRequest] = []
        self.transport = httpx.MockTransport(self._handle)
        self._issued_devices = 0
        self._challenged: Enrollment | None = None
        # The Okta app the current sign-in is for, so the success link returns to it.
        self._app_path = APP_PATH
        # The GlobalProtect interface whose prelogin started the sign-in.
        self._gp_interface: GpInterface | None = None
        # Lets a test replace any route.
        self._override: Override | None = None

    def set_override(self, route: Override | None) -> None:
        self._override = route

    def _handle(self, raw: httpx.Request) -> httpx.Response:
        request = RecordedRequest(
            method=raw.method,
            url=raw.url,
            cookies=_parse_cookies(raw.headers.get("cookie")),
            headers=raw.headers,
            body=raw.content.decode(),
        )
        self.requests.append(request)
        routed = self._override(request) if self._override else None
        if routed:
            return routed
        if request.url.host == SP:
            return self._service_provider(request)
        if request.url.host == OKTA:
            return self._okta(request)
        if request.url.host == GP:
            return self._global_protect(request)
        return httpx.Response(502, text="unknown host")

    def _service_provider(self, request: RecordedRequest) -> httpx.Response:
        method, url, cookies = request.method, request.url, request.cookies
        signed_in = cookies.get("MoodleSession") == "authed"
        if method == "GET" and url.path in ("/login/index.php", "/my/"):
            if signed_in:
                return _html("<p>You are logged in</p>")
            location = f"https://{OKTA}{APP_PATH}?SAMLRequest=request&RelayState={quote(RELAY_STATE, safe='')}"
            return _redirect(
                location,
                [
                    "MoodleSession=anon; Path=/; Secure; HttpOnly",
                    "MDL_SSP_SessID=ssp-1; Path=/; Secure; HttpOnly",
                ],
            )
        if method == "POST" and url.path == ACS_PATH:
            form = _form(request.body)
            accepted = (
                not self.options.sp_rejects
                and form.get("SAMLResponse") == SAML_RESPONSE
                and form.get("RelayState") == RELAY_STATE
                and cookies.get("MDL_SSP_SessID") == "ssp-1"
            )
            if not accepted:
                return _redirect(f"https://{SP}/login/index.php")
            return _redirect(RELAY_STATE, ["MoodleSession=authed; Path=/; Secure; HttpOnly"])
        return httpx.Response(404, text="not found")

    def _okta(self, request: RecordedRequest) -> httpx.Response:
        method, url, cookies = request.method, request.url, request.cookies
        cookie_lines: list[str] = []
        if "DT" not in cookies:
            self._issued_devices += 1
            cookie_lines.append(
                f"DT=dt-{self._issued_devices}; Path=/; Max-Age=157680000; Secure; HttpOnly"
            )
        if "JSESSIONID" not in cookies:
            cookie_lines.append("JSESSIONID=j-1; Path=/; Secure; HttpOnly")
        has_session = self.options.okta_session or cookies.get("sid") == "okta-session"

        if (method == "GET" and url.path == APP_PATH) or url.path == GP_APP_PATH:
            if url.path == GP_APP_PATH and method == "POST":
                if _form(request.body).get("SAMLRequest") != "gprequest":
                    return httpx.Response(400, text="bad request")
            self._app_path = url.path
            if has_session:
                page = gp_saml_form_page() if self._app_path == GP_APP_PATH else saml_form_page()
                return _html(page, cookie_lines)
            return _html("<script>var stateToken = '02.id.abc\\x2Ddef';</script>", cookie_lines)
        if method == "GET" and url.path == "/login/token/redirect":
            return _redirect(
                f"https://{OKTA}{self._app_path}",
                [*cookie_lines, "sid=okta-session; Path=/; Secure; HttpOnly"],
            )
        if method != "POST" or not url.path.startswith("/idp/idx/"):
            return httpx.Response(404, text="not found")
        if request.headers.get("accept") != IDX or request.headers.get("content-type") != IDX:
            return httpx.Response(406, text="not acceptable")

        body = json.loads(request.body)
        handle = body.get("stateToken") or body.get("stateHandle")
        if handle != STATE_TOKEN:
            return _json(401, {"messages": _error_messages("idx.session.expired")})
        credentials = body.get("credentials") or {}
        authenticator = body.get("authenticator") or {}

        if url.path == "/idp/idx/introspect":
            self._challenged = None
            return _json(200, _identify_state(self.options.password_on_identify))
        if url.path == "/idp/idx/identify":
            if body.get("identifier") != USERNAME:
                return _json(400, {"messages": _error_messages("idx.unknown.user")})
            if not self.options.password_on_identify:
                return _json(200, _password_state())
            if credentials.get("passcode") != PASSWORD:
                return _json(401, _password_state("incorrectPassword"))
            return _json(200, self._after_password())
        if url.path == "/idp/idx/challenge":
            chosen = next(
                (
                    e
                    for e in self.options.enrollments
                    if ENROLLMENTS[e]["id"] == authenticator.get("id")
                ),
                None,
            )
            if not chosen:
                return _json(400, {"messages": _error_messages("unknown.authenticator")})
            if chosen.startswith("okta_verify") and authenticator.get("methodType") != "totp":
                return _json(400, {"messages": _error_messages("push.not.expected")})
            self._challenged = chosen
            return _json(200, _otp_state(chosen))
        if url.path == "/idp/idx/challenge/answer":
            if not self._challenged:
                if credentials.get("passcode") != PASSWORD:
                    return _json(401, _password_state("incorrectPassword"))
                return _json(200, self._after_password())
            name = "passcode" if self._challenged == "google_otp" else "totp"
            expected = totp(self.options.totp_secret or TOTP_SECRET, self.options.now())
            if credentials.get(name) != expected:
                return _json(400, _otp_state(self._challenged, "api.authn.otp.invalid"))
            return _json(
                200,
                {
                    "stateHandle": STATE_TOKEN,
                    "success": {
                        "name": "success-redirect",
                        "href": f"https://{OKTA}/login/token/redirect?stateToken={STATE_TOKEN}",
                    },
                },
            )
        return httpx.Response(404, text="not found")

    def _global_protect(self, request: RecordedRequest) -> httpx.Response:
        method, url = request.method, request.url
        prelogin = next((name for name, path in PRELOGIN_PATHS.items() if path == url.path), None)
        if method == "POST" and prelogin:
            if request.headers.get("user-agent") != "PAN GlobalProtect":
                return httpx.Response(403, text="forbidden")
            if prelogin not in self.options.gp_saml:
                return _xml(
                    "<prelogin-response><status>Error</status>"
                    "<msg>Gateway is not configured</msg></prelogin-response>"
                )
            self._gp_interface = prelogin  # type: ignore[assignment]
            binding = self.options.gp_binding
            saml_request = (
                f"https://{OKTA}{GP_APP_PATH}?SAMLRequest=gprequest&RelayState={GP_RELAY_STATE}"
                if binding == "REDIRECT"
                else f'<html><body><form id="myform" method="POST" action="https://{OKTA}{GP_APP_PATH}">'
                '<input type="hidden" name="SAMLRequest" value="gprequest" />'
                f'<input type="hidden" name="RelayState" value="{GP_RELAY_STATE}" /></form></body></html>'
            )
            encoded = base64.b64encode(saml_request.encode()).decode()
            return _xml(
                "<prelogin-response><status>Success</status><msg></msg>"
                f"<saml-auth-method>{binding}</saml-auth-method><saml-request>{encoded}</saml-request>"
                "<region>AU</region></prelogin-response>",
                ["PHPSESSID=gp-anon; Path=/; Secure; HttpOnly"],
            )
        if method == "POST" and url.path == GP_ACS_PATH:
            form = _form(request.body)
            accepted = (
                not self.options.sp_rejects
                and form.get("SAMLResponse") == SAML_RESPONSE
                and form.get("RelayState") == GP_RELAY_STATE
            )
            portal = self._gp_interface == "portal"
            fields = (
                [
                    ("saml-auth-status", "1"),
                    ("saml-username", USERNAME),
                    ("portal-userauthcookie", GP_COOKIE)
                    if portal
                    else ("prelogin-cookie", GP_COOKIE),
                    ("prelogin-cookie", "empty") if portal else ("portal-userauthcookie", "empty"),
                ]
                if accepted
                else [("saml-auth-status", "-1")]
            )
            if self.options.gp_result_in == "comment":
                comment = "".join(f"<{name}>{value}</{name}>" for name, value in fields)
                return _html(f"<html><!-- {comment} --><body>Login Successful!</body></html>")
            return httpx.Response(
                200, headers=fields, text="<html><body>Login Successful!</body></html>"
            )
        return httpx.Response(404, text="not found")

    def _after_password(self) -> dict[str, Any]:
        select = _select_state(self.options.enrollments)
        if not self.options.preselect:
            return select
        self._challenged = self.options.preselect
        challenge = _otp_state(self.options.preselect)
        return {
            **select,
            **challenge,
            "remediation": {
                "type": "array",
                "value": [*challenge["remediation"]["value"], *select["remediation"]["value"]],
            },
        }


def fake_sso(options: FakeOptions) -> FakeSso:
    return FakeSso(options)


def saml_form_page() -> str:
    def entities(text: str) -> str:
        return re.sub(r"[:/+]", lambda m: f"&#x{ord(m.group(0)):x};", text)

    return f"""<html><body onload="document.forms[0].submit()">
<form id="appForm" action="{entities(f"https://{SP}{ACS_PATH}")}" method="POST">
<input name="SAMLResponse" type="hidden" value="{entities(SAML_RESPONSE)}"/>
<input name="RelayState" type="hidden" value="{entities(RELAY_STATE)}"/>
</form></body></html>"""


def gp_saml_form_page() -> str:
    """What Okta posts to the GlobalProtect ACS."""
    return f"""<html><body onload="document.forms[0].submit()">
<form id="appForm" action="https&#x3a;&#x2f;&#x2f;{GP}{GP_ACS_PATH}" method="POST">
<input name="SAMLResponse" type="hidden" value="{SAML_RESPONSE.replace("+", "&#x2b;", 1)}"/>
<input name="RelayState" type="hidden" value="{GP_RELAY_STATE}"/>
</form></body></html>"""


_STATE_HANDLE_FIELD = {
    "name": "stateHandle",
    "required": True,
    "value": STATE_TOKEN,
    "visible": False,
    "mutable": False,
}


def _idx_href(path: str) -> str:
    return f"https://{OKTA}/idp/idx/{path}"


def _credentials_field(name: str, error: str | None = None) -> dict[str, Any]:
    secret: dict[str, Any] = {"name": name, "label": "Code", "secret": True}
    if error:
        secret["messages"] = _error_messages(error)
    return {"name": "credentials", "type": "object", "required": True, "form": {"value": [secret]}}


def _identify_state(with_password: bool) -> dict[str, Any]:
    return {
        "version": "1.0.0",
        "stateHandle": STATE_TOKEN,
        "remediation": {
            "type": "array",
            "value": [
                {
                    "rel": ["create-form"],
                    "name": "identify",
                    "href": _idx_href("identify"),
                    "method": "POST",
                    "value": [
                        {"name": "identifier", "label": "Username", "required": True},
                        *([_credentials_field("passcode")] if with_password else []),
                        {"name": "rememberMe", "type": "boolean", "label": "Keep me signed in"},
                        _STATE_HANDLE_FIELD,
                    ],
                },
                {
                    "name": "redirect-idp",
                    "type": "MTLS",
                    "href": f"https://{OKTA}/sso/idps/mtls",
                    "method": "GET",
                },
            ],
        },
    }


def _password_state(error: str | None = None) -> dict[str, Any]:
    return {
        "version": "1.0.0",
        "stateHandle": STATE_TOKEN,
        "remediation": {
            "type": "array",
            "value": [
                {
                    "name": "challenge-authenticator",
                    "relatesTo": ["$.currentAuthenticatorEnrollment"],
                    "href": _idx_href("challenge/answer"),
                    "method": "POST",
                    "value": [_credentials_field("passcode", error), _STATE_HANDLE_FIELD],
                }
            ],
        },
        "currentAuthenticatorEnrollment": {
            "type": "object",
            "value": {
                "type": "password",
                "key": "okta_password",
                "id": "aut-password",
                "displayName": "Password",
            },
        },
    }


def _select_state(enrollments: list[Enrollment]) -> dict[str, Any]:
    return {
        "version": "1.0.0",
        "stateHandle": STATE_TOKEN,
        "remediation": {
            "type": "array",
            "value": [
                {
                    "name": "select-authenticator-authenticate",
                    "href": _idx_href("challenge"),
                    "method": "POST",
                    "value": [
                        {
                            "name": "authenticator",
                            "type": "object",
                            # Labels are deliberately unhelpful: the key comes from relatesTo.
                            "options": [
                                {
                                    "label": f"Option {index + 1}",
                                    "value": {
                                        "form": {
                                            "value": [
                                                {
                                                    "name": "id",
                                                    "required": True,
                                                    "value": ENROLLMENTS[name]["id"],
                                                    "mutable": False,
                                                },
                                                ENROLLMENTS[name]["methodType"],
                                            ]
                                        }
                                    },
                                    "relatesTo": f"$.authenticatorEnrollments.value[{index}]",
                                }
                                for index, name in enumerate(enrollments)
                            ],
                        },
                        _STATE_HANDLE_FIELD,
                    ],
                }
            ],
        },
        "authenticatorEnrollments": {
            "type": "array",
            "value": [
                {"key": ENROLLMENTS[name]["key"], "id": ENROLLMENTS[name]["id"], "type": "app"}
                for name in enrollments
            ],
        },
    }


def _otp_state(enrollment: Enrollment, error: str | None = None) -> dict[str, Any]:
    return {
        "version": "1.0.0",
        "stateHandle": STATE_TOKEN,
        "remediation": {
            "type": "array",
            "value": [
                {
                    "name": "challenge-authenticator",
                    "relatesTo": ["$.currentAuthenticatorEnrollment"],
                    "href": _idx_href("challenge/answer"),
                    "method": "POST",
                    "value": [
                        _credentials_field(
                            "passcode" if enrollment == "google_otp" else "totp", error
                        ),
                        _STATE_HANDLE_FIELD,
                    ],
                }
            ],
        },
        "currentAuthenticatorEnrollment": {
            "type": "object",
            "value": {
                "type": "app",
                "key": ENROLLMENTS[enrollment]["key"],
                "id": ENROLLMENTS[enrollment]["id"],
            },
        },
    }


def _error_messages(key: str) -> dict[str, Any]:
    return {
        "type": "array",
        "value": [{"message": f"Error {key}", "i18n": {"key": key}, "class": "ERROR"}],
    }


def _parse_cookies(header: str | None) -> dict[str, str]:
    cookies: dict[str, str] = {}
    for pair in header.split("; ") if header else []:
        name, equals, value = pair.partition("=")
        if equals and name:
            cookies[name] = value
    return cookies


def _form(body: str) -> dict[str, str]:
    return {name: values[0] for name, values in parse_qs(body).items()}


def _headers(content_type: str | None, cookies: list[str]) -> list[tuple[str, str]]:
    headers = [("content-type", content_type)] if content_type else []
    return headers + [("set-cookie", cookie) for cookie in cookies]


def _html(body: str, cookies: list[str] | None = None) -> httpx.Response:
    return httpx.Response(200, headers=_headers("text/html", cookies or []), text=body)


def _redirect(location: str, cookies: list[str] | None = None) -> httpx.Response:
    return httpx.Response(303, headers=[("location", location), *_headers(None, cookies or [])])


def _xml(body: str, cookies: list[str] | None = None) -> httpx.Response:
    return httpx.Response(200, headers=_headers("application/xml", cookies or []), text=body)


def _json(status: int, body: Any) -> httpx.Response:
    return httpx.Response(status, headers={"content-type": IDX}, content=json.dumps(body).encode())


def idx_json(body: Any) -> httpx.Response:
    """For overrides: an IDX answer, like Response.json in the TypeScript tests."""
    return _json(200, body)
